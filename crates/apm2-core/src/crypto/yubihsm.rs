//! `YubiHSM` provider implementation for T1 validator keys.
//!
//! This module provides an HSM provider implementation for `YubiHSM` devices.
//! The actual `YubiHSM` SDK integration requires the `yubihsm` feature flag.
//!
//! # Implementation Status
//!
//! This module provides the **interface and mock implementation** for `YubiHSM`
//! integration. The full hardware integration is a work in progress and
//! requires:
//!
//! 1. Adding the `yubihsm` crate as a dependency (not currently included)
//! 2. A running yubihsm-connector daemon
//! 3. Physical `YubiHSM` hardware or a hardware emulator
//!
//! The current implementation allows:
//! - Testing the HSM integration logic without hardware
//! - Validating the API design and error handling
//! - Development and CI testing with mock keys
//!
//! # Feature Flag and Mock Implementation
//!
//! This provider has two modes of operation:
//!
//! - **With `yubihsm` feature enabled**: Would connect to real `YubiHSM`
//!   hardware via the yubihsm-connector daemon. Private keys never leave the
//!   HSM boundary. **(SDK integration pending)**
//!
//! - **Without `yubihsm` feature (default)**: A mock implementation is provided
//!   for development and testing. Keys are stored in memory and do NOT provide
//!   hardware security guarantees. This mode allows testing HSM integration
//!   logic without requiring actual hardware.
//!
//! The trait abstraction ([`super::hsm::HsmProvider`]) allows easy swapping
//! between mock and real implementations at compile time via the feature flag.
//!
//! To enable real `YubiHSM` support (once SDK integration is complete):
//!
//! ```toml
//! [dependencies]
//! apm2-core = { version = "0.3", features = ["yubihsm"] }
//! ```
//!
//! # Security Properties
//!
//! When using real `YubiHSM` hardware (with the `yubihsm` feature enabled):
//! - Private keys are generated within the HSM and never leave it
//! - All signing operations are performed by the HSM hardware
//! - Key material is protected by tamper-evident hardware
//! - Audit logging captures all key operations
//!
//! **Warning**: The mock implementation (without the `yubihsm` feature) stores
//! keys in process memory and should NOT be used in production environments
//! requiring HSM-level security.
//!
//! # Connection
//!
//! The `YubiHSM` provider connects via the yubihsm-connector daemon, which must
//! be running and accessible via USB or network. The connector URL is
//! typically:
//! - Local USB: `http://127.0.0.1:12345`
//! - Network: `http://<connector-host>:12345`
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::crypto::hsm::{HsmConfig, HsmProvider};
//! use apm2_core::crypto::yubihsm::YubiHsmProvider;
//! use secrecy::SecretString;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = HsmConfig::yubihsm(
//!     "http://127.0.0.1:12345".to_string(),
//!     1,  // auth key ID
//!     SecretString::from("password"),
//! );
//!
//! let hsm = YubiHsmProvider::new(config)?;
//! hsm.connect().await?;
//!
//! // Generate a validator key
//! let key_id = hsm.generate_key("validator-1").await?;
//!
//! // Sign a message
//! let signature = hsm.sign(&key_id, b"message").await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use super::hsm::{
    BoxFuture, HSM_PUBLIC_KEY_SIZE, HsmConfig, HsmError, HsmProvider, HsmProviderType, HsmResult,
    MAX_KEY_ID_LEN,
};
use super::sign::Signature;

/// Default `YubiHSM` authentication key ID.
const DEFAULT_AUTH_KEY_ID: u16 = 1;

/// Default `YubiHSM` domain.
const DEFAULT_DOMAIN: u16 = 1;

/// Maximum number of keys that can be stored in the HSM.
///
/// This is limited by the 16-bit object ID space (0 is reserved, so max is
/// `u16::MAX`).
const MAX_HSM_KEYS: usize = u16::MAX as usize;

/// Mapping from string key IDs to `YubiHSM` object IDs.
///
/// `YubiHSM` uses 16-bit object IDs, so we maintain a mapping from our
/// string-based key IDs to the HSM's numeric IDs.
///
/// Note: Some fields and methods are only used with the `yubihsm` feature or
/// in tests. The `allow(dead_code)` attributes suppress warnings for the mock
/// implementation.
#[derive(Debug, Default)]
#[allow(dead_code)]
struct KeyIdMapping {
    /// Map from string key ID to HSM object ID.
    id_to_object: HashMap<String, u16>,
    /// Next available object ID (starting from 1, reserving 0).
    next_object_id: u16,
}

#[allow(dead_code)]
impl KeyIdMapping {
    fn new() -> Self {
        Self {
            id_to_object: HashMap::new(),
            next_object_id: 1,
        }
    }

    fn get(&self, key_id: &str) -> Option<u16> {
        self.id_to_object.get(key_id).copied()
    }

    /// Inserts a new key ID and returns the assigned object ID.
    ///
    /// # Errors
    ///
    /// Returns `HsmError::CapacityExceeded` if the maximum number of keys
    /// (`MAX_HSM_KEYS`) has been reached.
    fn insert(&mut self, key_id: String) -> HsmResult<u16> {
        // Check if we've reached the maximum capacity
        if self.id_to_object.len() >= MAX_HSM_KEYS {
            return Err(HsmError::CapacityExceeded);
        }

        let object_id = self.next_object_id;

        // Use checked_add to detect overflow; if overflow would occur,
        // we've exhausted the ID space
        self.next_object_id = self
            .next_object_id
            .checked_add(1)
            .ok_or(HsmError::CapacityExceeded)?;

        self.id_to_object.insert(key_id, object_id);
        Ok(object_id)
    }

    fn remove(&mut self, key_id: &str) -> Option<u16> {
        self.id_to_object.remove(key_id)
    }

    fn contains(&self, key_id: &str) -> bool {
        self.id_to_object.contains_key(key_id)
    }

    fn keys(&self) -> Vec<String> {
        self.id_to_object.keys().cloned().collect()
    }
}

/// `YubiHSM` provider for T1 validator keys.
///
/// This provider implements the `HsmProvider` trait using `YubiHSM` hardware.
/// When the yubihsm feature is enabled, it connects to a real `YubiHSM` device.
/// Without the feature, it operates as a stub that returns configuration
/// errors.
///
/// # Connection Lifecycle
///
/// 1. Create provider with configuration
/// 2. Call `connect()` to establish session with `YubiHSM`
/// 3. Perform key operations (generate, sign, rotate, etc.)
/// 4. Call `disconnect()` when done
///
/// # Thread Safety
///
/// The provider is thread-safe and can be shared across multiple async tasks.
/// Internal state is protected by appropriate synchronization primitives.
pub struct YubiHsmProvider {
    /// Provider configuration.
    config: HsmConfig,

    /// Connection state.
    connected: AtomicBool,

    /// Key ID to HSM object ID mapping.
    key_mapping: RwLock<KeyIdMapping>,

    /// Key version tracking for rotation.
    key_versions: RwLock<HashMap<String, u32>>,

    /// Mock public keys for testing (when yubihsm feature is disabled).
    #[cfg(not(feature = "yubihsm"))]
    mock_public_keys: RwLock<HashMap<String, [u8; HSM_PUBLIC_KEY_SIZE]>>,

    /// Mock signers for testing (when yubihsm feature is disabled).
    #[cfg(not(feature = "yubihsm"))]
    mock_signers: RwLock<HashMap<String, super::sign::Signer>>,
}

impl YubiHsmProvider {
    /// Creates a new `YubiHSM` provider with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid (e.g., missing
    /// connector URL or authentication credentials).
    pub fn new(config: HsmConfig) -> HsmResult<Self> {
        // Validate configuration
        if config.provider_type != HsmProviderType::YubiHsm {
            return Err(HsmError::InvalidConfiguration {
                message: format!(
                    "expected `YubiHSM` provider type, got {:?}",
                    config.provider_type
                ),
            });
        }

        if config.yubihsm_connector_url.is_none() {
            return Err(HsmError::InvalidConfiguration {
                message: "`YubiHSM` connector URL is required".to_string(),
            });
        }

        if config.yubihsm_auth_key_password.is_none() {
            return Err(HsmError::InvalidConfiguration {
                message: "`YubiHSM` authentication key password is required".to_string(),
            });
        }

        Ok(Self {
            config,
            connected: AtomicBool::new(false),
            key_mapping: RwLock::new(KeyIdMapping::new()),
            key_versions: RwLock::new(HashMap::new()),
            #[cfg(not(feature = "yubihsm"))]
            mock_public_keys: RwLock::new(HashMap::new()),
            #[cfg(not(feature = "yubihsm"))]
            mock_signers: RwLock::new(HashMap::new()),
        })
    }

    /// Returns the connector URL.
    #[must_use]
    pub fn connector_url(&self) -> Option<&str> {
        self.config.yubihsm_connector_url.as_deref()
    }

    /// Returns the authentication key ID.
    #[must_use]
    pub fn auth_key_id(&self) -> u16 {
        self.config
            .yubihsm_auth_key_id
            .unwrap_or(DEFAULT_AUTH_KEY_ID)
    }

    /// Returns the domain.
    #[must_use]
    pub fn domain(&self) -> u16 {
        self.config.yubihsm_domain.unwrap_or(DEFAULT_DOMAIN)
    }

    /// Validates a key ID.
    fn validate_key_id(key_id: &str) -> HsmResult<()> {
        if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
            return Err(HsmError::InvalidKeyId {
                key_id: key_id.to_string(),
            });
        }

        if key_id.starts_with('-') {
            return Err(HsmError::InvalidKeyId {
                key_id: key_id.to_string(),
            });
        }

        if !key_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(HsmError::InvalidKeyId {
                key_id: key_id.to_string(),
            });
        }

        Ok(())
    }

    /// Ensures the provider is connected.
    fn ensure_connected(&self) -> HsmResult<()> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(HsmError::NotConnected);
        }
        Ok(())
    }
}

// Allow clippy lints in this impl because conditional compilation blocks
// require:
// - needless_return: explicit returns to ensure both cfg branches compile
//   correctly
// - readonly_write_lock: lock types that work for both cfg branches
// - unused_variables: parameters like `message` are only used in the mock
//   branch
// - unused_mut: mutability needed only in the mock branch for write locks
#[allow(
    clippy::needless_return,
    clippy::readonly_write_lock,
    unused_variables,
    unused_mut
)]
impl HsmProvider for YubiHsmProvider {
    fn generate_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<String>> {
        Box::pin(async move {
            self.ensure_connected()?;
            Self::validate_key_id(key_id)?;

            let mut mapping = self.key_mapping.write().unwrap();
            if mapping.contains(key_id) {
                return Err(HsmError::KeyAlreadyExists {
                    key_id: key_id.to_string(),
                });
            }

            // In a real implementation, this would call:
            // client.generate_asymmetric_key(object_id, label, domain, capabilities,
            // algorithm)

            #[cfg(feature = "yubihsm")]
            {
                // Real `YubiHSM` implementation would go here
                // This is a placeholder for the actual SDK calls
                return Err(HsmError::InternalError {
                    message: "`YubiHSM` SDK integration not yet implemented".to_string(),
                });
            }

            #[cfg(not(feature = "yubihsm"))]
            {
                // Mock implementation for testing without actual HSM
                let _object_id = mapping.insert(key_id.to_string())?;

                // Generate a mock key for testing
                let signer = super::sign::Signer::generate();
                let public_key = signer.public_key_bytes();

                self.mock_public_keys
                    .write()
                    .unwrap()
                    .insert(key_id.to_string(), public_key);
                self.mock_signers
                    .write()
                    .unwrap()
                    .insert(key_id.to_string(), signer);

                let mut versions = self.key_versions.write().unwrap();
                versions.insert(key_id.to_string(), 1);

                Ok(key_id.to_string())
            }
        })
    }

    fn sign<'a>(
        &'a self,
        key_id: &'a str,
        message: &'a [u8],
    ) -> BoxFuture<'a, HsmResult<Signature>> {
        Box::pin(async move {
            self.ensure_connected()?;
            Self::validate_key_id(key_id)?;

            let mapping = self.key_mapping.read().unwrap();
            if !mapping.contains(key_id) {
                return Err(HsmError::KeyNotFound {
                    key_id: key_id.to_string(),
                });
            }

            #[cfg(feature = "yubihsm")]
            {
                // Real `YubiHSM` implementation would go here
                // client.sign_ed25519(object_id, message)
                return Err(HsmError::InternalError {
                    message: "`YubiHSM` SDK integration not yet implemented".to_string(),
                });
            }

            #[cfg(not(feature = "yubihsm"))]
            {
                let signers = self.mock_signers.read().unwrap();
                let signer = signers.get(key_id).ok_or_else(|| HsmError::KeyNotFound {
                    key_id: key_id.to_string(),
                })?;
                Ok(signer.sign(message))
            }
        })
    }

    fn public_key<'a>(
        &'a self,
        key_id: &'a str,
    ) -> BoxFuture<'a, HsmResult<[u8; HSM_PUBLIC_KEY_SIZE]>> {
        Box::pin(async move {
            self.ensure_connected()?;
            Self::validate_key_id(key_id)?;

            let mapping = self.key_mapping.read().unwrap();
            if !mapping.contains(key_id) {
                return Err(HsmError::KeyNotFound {
                    key_id: key_id.to_string(),
                });
            }

            #[cfg(feature = "yubihsm")]
            {
                // Real `YubiHSM` implementation would go here
                // client.get_public_key(object_id)
                return Err(HsmError::InternalError {
                    message: "`YubiHSM` SDK integration not yet implemented".to_string(),
                });
            }

            #[cfg(not(feature = "yubihsm"))]
            {
                let public_keys = self.mock_public_keys.read().unwrap();
                public_keys
                    .get(key_id)
                    .copied()
                    .ok_or_else(|| HsmError::KeyNotFound {
                        key_id: key_id.to_string(),
                    })
            }
        })
    }

    fn rotate_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<String>> {
        Box::pin(async move {
            self.ensure_connected()?;
            Self::validate_key_id(key_id)?;

            // Acquire write locks upfront to prevent TOCTOU race conditions:
            // version derivation and insertion must be atomic.
            let mut mapping = self.key_mapping.write().unwrap();
            let mut versions = self.key_versions.write().unwrap();

            // Check that old key exists
            if !mapping.contains(key_id) {
                return Err(HsmError::KeyNotFound {
                    key_id: key_id.to_string(),
                });
            }

            // Derive next version under the write lock
            let base_id = key_id.split("-v").next().unwrap_or(key_id);
            let max_version = versions
                .iter()
                .filter_map(|(id, ver)| {
                    let id_base = id.split("-v").next().unwrap_or(id);
                    if id_base == base_id { Some(*ver) } else { None }
                })
                .max()
                .unwrap_or(0);
            let version = max_version + 1;

            let new_key_id = format!("{base_id}-v{version}");

            Self::validate_key_id(&new_key_id)?;

            // Generate new key
            #[cfg(feature = "yubihsm")]
            {
                return Err(HsmError::InternalError {
                    message: "`YubiHSM` SDK integration not yet implemented".to_string(),
                });
            }

            #[cfg(not(feature = "yubihsm"))]
            {
                let _object_id = mapping.insert(new_key_id.clone())?;

                let signer = super::sign::Signer::generate();
                let public_key = signer.public_key_bytes();

                self.mock_public_keys
                    .write()
                    .unwrap()
                    .insert(new_key_id.clone(), public_key);
                self.mock_signers
                    .write()
                    .unwrap()
                    .insert(new_key_id.clone(), signer);

                versions.insert(new_key_id.clone(), version);

                Ok(new_key_id)
            }
        })
    }

    fn delete_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<()>> {
        Box::pin(async move {
            self.ensure_connected()?;
            Self::validate_key_id(key_id)?;

            let mut mapping = self.key_mapping.write().unwrap();
            if !mapping.contains(key_id) {
                return Err(HsmError::KeyNotFound {
                    key_id: key_id.to_string(),
                });
            }

            #[cfg(feature = "yubihsm")]
            {
                // Real `YubiHSM` implementation would go here
                // client.delete_object(object_id, ObjectType::AsymmetricKey)
                return Err(HsmError::InternalError {
                    message: "`YubiHSM` SDK integration not yet implemented".to_string(),
                });
            }

            #[cfg(not(feature = "yubihsm"))]
            {
                mapping.remove(key_id);
                self.mock_public_keys.write().unwrap().remove(key_id);
                self.mock_signers.write().unwrap().remove(key_id);
                self.key_versions.write().unwrap().remove(key_id);
                Ok(())
            }
        })
    }

    fn key_exists<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<bool>> {
        Box::pin(async move {
            self.ensure_connected()?;
            Self::validate_key_id(key_id)?;

            let mapping = self.key_mapping.read().unwrap();
            Ok(mapping.contains(key_id))
        })
    }

    fn list_keys(&self) -> BoxFuture<'_, HsmResult<Vec<String>>> {
        Box::pin(async move {
            self.ensure_connected()?;
            let mapping = self.key_mapping.read().unwrap();
            Ok(mapping.keys())
        })
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    fn provider_type(&self) -> HsmProviderType {
        HsmProviderType::YubiHsm
    }

    fn connect(&self) -> BoxFuture<'_, HsmResult<()>> {
        Box::pin(async move {
            #[cfg(feature = "yubihsm")]
            {
                // Real `YubiHSM` connection would go here:
                // 1. Create connector to yubihsm-connector URL
                // 2. Create credentials from auth key ID and password
                // 3. Establish authenticated session
                // 4. Store client for subsequent operations
                return Err(HsmError::InternalError {
                    message: "`YubiHSM` SDK integration not yet implemented".to_string(),
                });
            }

            #[cfg(not(feature = "yubihsm"))]
            {
                // Mock connection for testing
                self.connected.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
    }

    fn disconnect(&self) -> BoxFuture<'_, HsmResult<()>> {
        Box::pin(async move {
            #[cfg(feature = "yubihsm")]
            {
                // Close `YubiHSM` session
                return Err(HsmError::InternalError {
                    message: "`YubiHSM` SDK integration not yet implemented".to_string(),
                });
            }

            #[cfg(not(feature = "yubihsm"))]
            {
                self.connected.store(false, Ordering::SeqCst);
                Ok(())
            }
        })
    }
}

#[cfg(test)]
mod unit_tests {
    use secrecy::SecretString;

    use super::*;

    fn test_config() -> HsmConfig {
        HsmConfig::yubihsm(
            "http://127.0.0.1:12345".to_string(),
            1,
            SecretString::from("password"),
        )
    }

    #[test]
    fn tck_00192_yubihsm_create_provider() {
        let config = test_config();
        let provider = YubiHsmProvider::new(config).unwrap();

        assert_eq!(provider.provider_type(), HsmProviderType::YubiHsm);
        assert!(!provider.is_connected());
        assert_eq!(provider.connector_url(), Some("http://127.0.0.1:12345"));
        assert_eq!(provider.auth_key_id(), 1);
        assert_eq!(provider.domain(), 1);
    }

    #[test]
    fn tck_00192_yubihsm_invalid_config_wrong_type() {
        let config = HsmConfig::software();
        let result = YubiHsmProvider::new(config);
        assert!(matches!(result, Err(HsmError::InvalidConfiguration { .. })));
    }

    #[test]
    fn tck_00192_yubihsm_invalid_config_no_url() {
        let mut config = test_config();
        config.yubihsm_connector_url = None;
        let result = YubiHsmProvider::new(config);
        assert!(matches!(result, Err(HsmError::InvalidConfiguration { .. })));
    }

    #[test]
    fn tck_00192_yubihsm_invalid_config_no_password() {
        let mut config = test_config();
        config.yubihsm_auth_key_password = None;
        let result = YubiHsmProvider::new(config);
        assert!(matches!(result, Err(HsmError::InvalidConfiguration { .. })));
    }

    #[tokio::test]
    async fn tck_00192_yubihsm_not_connected_error() {
        let config = test_config();
        let provider = YubiHsmProvider::new(config).unwrap();

        // Operations should fail when not connected
        let result = provider.generate_key("validator-1").await;
        assert!(matches!(result, Err(HsmError::NotConnected)));

        let result = provider.sign("validator-1", b"message").await;
        assert!(matches!(result, Err(HsmError::NotConnected)));

        let result = provider.public_key("validator-1").await;
        assert!(matches!(result, Err(HsmError::NotConnected)));
    }

    #[tokio::test]
    #[cfg(not(feature = "yubihsm"))]
    async fn tck_00192_yubihsm_mock_operations() {
        use ed25519_dalek::Verifier as _;

        let config = test_config();
        let provider = YubiHsmProvider::new(config).unwrap();

        // Connect (mock)
        provider.connect().await.unwrap();
        assert!(provider.is_connected());

        // Generate key
        let key_id = provider.generate_key("validator-1").await.unwrap();
        assert_eq!(key_id, "validator-1");

        // Key should exist
        assert!(provider.key_exists("validator-1").await.unwrap());

        // Get public key
        let public_key = provider.public_key("validator-1").await.unwrap();
        assert_eq!(public_key.len(), HSM_PUBLIC_KEY_SIZE);

        // Sign
        let signature = provider.sign("validator-1", b"message").await.unwrap();
        assert_eq!(signature.to_bytes().len(), 64);

        // Verify signature
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
        assert!(verifying_key.verify(b"message", &signature).is_ok());

        // Disconnect
        provider.disconnect().await.unwrap();
        assert!(!provider.is_connected());
    }

    #[tokio::test]
    #[cfg(not(feature = "yubihsm"))]
    async fn tck_00192_yubihsm_mock_key_rotation() {
        let config = test_config();
        let provider = YubiHsmProvider::new(config).unwrap();
        provider.connect().await.unwrap();

        // Generate initial key
        provider.generate_key("validator-1").await.unwrap();
        let old_public_key = provider.public_key("validator-1").await.unwrap();

        // Rotate key
        let new_key_id = provider.rotate_key("validator-1").await.unwrap();
        assert_eq!(new_key_id, "validator-1-v2");

        // New key should have different public key
        let new_public_key = provider.public_key(&new_key_id).await.unwrap();
        assert_ne!(old_public_key, new_public_key);

        // Both keys should exist
        assert!(provider.key_exists("validator-1").await.unwrap());
        assert!(provider.key_exists("validator-1-v2").await.unwrap());
    }

    #[tokio::test]
    #[cfg(not(feature = "yubihsm"))]
    async fn tck_00192_yubihsm_mock_delete_key() {
        let config = test_config();
        let provider = YubiHsmProvider::new(config).unwrap();
        provider.connect().await.unwrap();

        provider.generate_key("validator-1").await.unwrap();
        assert!(provider.key_exists("validator-1").await.unwrap());

        provider.delete_key("validator-1").await.unwrap();
        assert!(!provider.key_exists("validator-1").await.unwrap());
    }

    #[tokio::test]
    #[cfg(not(feature = "yubihsm"))]
    async fn tck_00192_yubihsm_mock_list_keys() {
        let config = test_config();
        let provider = YubiHsmProvider::new(config).unwrap();
        provider.connect().await.unwrap();

        provider.generate_key("validator-1").await.unwrap();
        provider.generate_key("validator-2").await.unwrap();

        let mut keys = provider.list_keys().await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["validator-1", "validator-2"]);
    }

    #[tokio::test]
    #[cfg(not(feature = "yubihsm"))]
    async fn tck_00192_yubihsm_mock_duplicate_key_error() {
        let config = test_config();
        let provider = YubiHsmProvider::new(config).unwrap();
        provider.connect().await.unwrap();

        provider.generate_key("validator-1").await.unwrap();

        let result = provider.generate_key("validator-1").await;
        assert!(matches!(result, Err(HsmError::KeyAlreadyExists { .. })));
    }

    #[tokio::test]
    #[cfg(not(feature = "yubihsm"))]
    async fn tck_00192_yubihsm_mock_key_not_found() {
        let config = test_config();
        let provider = YubiHsmProvider::new(config).unwrap();
        provider.connect().await.unwrap();

        let result = provider.public_key("nonexistent").await;
        assert!(matches!(result, Err(HsmError::KeyNotFound { .. })));

        let result = provider.sign("nonexistent", b"message").await;
        assert!(matches!(result, Err(HsmError::KeyNotFound { .. })));

        let result = provider.rotate_key("nonexistent").await;
        assert!(matches!(result, Err(HsmError::KeyNotFound { .. })));

        let result = provider.delete_key("nonexistent").await;
        assert!(matches!(result, Err(HsmError::KeyNotFound { .. })));
    }

    #[test]
    fn tck_00192_yubihsm_key_id_validation() {
        assert!(YubiHsmProvider::validate_key_id("validator-1").is_ok());
        assert!(YubiHsmProvider::validate_key_id("validator_1").is_ok());
        assert!(YubiHsmProvider::validate_key_id("").is_err());
        assert!(YubiHsmProvider::validate_key_id("-invalid").is_err());
        assert!(YubiHsmProvider::validate_key_id("invalid.key").is_err());
    }

    #[test]
    fn tck_00192_key_id_mapping() {
        let mut mapping = KeyIdMapping::new();

        let id1 = mapping.insert("key-1".to_string()).unwrap();
        assert_eq!(id1, 1);

        let id2 = mapping.insert("key-2".to_string()).unwrap();
        assert_eq!(id2, 2);

        // Access internal map directly for testing (get method only available with
        // yubihsm feature)
        assert_eq!(mapping.id_to_object.get("key-1"), Some(&1));
        assert_eq!(mapping.id_to_object.get("key-2"), Some(&2));
        assert_eq!(mapping.id_to_object.get("nonexistent"), None);

        assert!(mapping.contains("key-1"));
        assert!(!mapping.contains("nonexistent"));

        let removed = mapping.remove("key-1");
        assert_eq!(removed, Some(1));
        assert!(!mapping.contains("key-1"));
    }

    #[test]
    fn tck_00192_key_id_mapping_capacity_exceeded() {
        let mut mapping = KeyIdMapping::new();

        // Fill up the mapping to near capacity to test overflow handling
        // We can't actually insert u16::MAX keys in a test, but we can verify
        // the error type is correct by manipulating next_object_id

        // Set to MAX - 1 so we can insert one more key
        mapping.next_object_id = u16::MAX - 1;

        // Insert at MAX - 1 should succeed (next_object_id becomes MAX)
        let result = mapping.insert("key-penultimate".to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), u16::MAX - 1);

        // Insert at MAX should fail because we can't increment past MAX
        // (the increment happens before insertion to ensure we have a valid
        // next ID available)
        let result = mapping.insert("key-max".to_string());
        assert!(
            matches!(result, Err(HsmError::CapacityExceeded)),
            "expected CapacityExceeded at u16::MAX, got {result:?}"
        );
    }
}
