//! Hardware Security Module (HSM) integration for T1 validator keys.
//!
//! This module provides a trait abstraction for HSM key storage and operations.
//! Keys managed by an HSM never leave the secure hardware boundary; all signing
//! operations are performed via the HSM API.
//!
//! # Trust Hierarchy
//!
//! HSM integration is designed for T1 validator keys in the four-tier trust
//! hierarchy:
//!
//! - **T0 (Root)**: Offline ceremony keys (not managed by this module)
//! - **T1 (Validator)**: HSM-managed keys for consensus signing
//! - **T2 (Holon)**: Software keys via `KeyManager`
//! - **T3 (Session)**: Ephemeral keys
//!
//! # Providers
//!
//! The following providers are available:
//!
//! - [`SoftwareHsmProvider`]: In-memory fallback for development and testing
//! - [`YubiHsmProvider`]: Reference implementation for `YubiHSM` devices
//!   (requires yubihsm feature flag)
//!
//! # Security Properties
//!
//! - **Key Isolation**: Private keys never leave HSM boundary
//! - **Bounded Timeouts**: All HSM operations have configurable timeouts
//! - **Connection Resilience**: Automatic reconnection with backoff
//! - **Secure Deletion**: Key material zeroized on deletion
//!
//! # Example
//!
//! ```rust,no_run
//! use apm2_core::crypto::hsm::{HsmConfig, HsmProvider, SoftwareHsmProvider};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a software HSM provider for development
//! let config = HsmConfig::software();
//! let hsm = SoftwareHsmProvider::new(config);
//!
//! // Generate a validator key
//! let key_id = hsm.generate_key("validator-1").await?;
//!
//! // Sign a message (key never leaves HSM)
//! let message = b"consensus proposal hash";
//! let signature = hsm.sign(&key_id, message).await?;
//!
//! // Retrieve public key for verification
//! let public_key = hsm.public_key(&key_id).await?;
//!
//! // Rotate key when needed
//! let new_key_id = hsm.rotate_key(&key_id).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::RwLock;
use std::time::Duration;

use thiserror::Error;

use super::sign::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE, Signature, Signer};

/// A boxed future for async HSM trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Default timeout for HSM operations (5 seconds).
pub const DEFAULT_HSM_TIMEOUT_MS: u64 = 5000;

/// Maximum key ID length.
pub const MAX_KEY_ID_LEN: usize = 128;

/// Size of an Ed25519 public key in bytes.
pub const HSM_PUBLIC_KEY_SIZE: usize = PUBLIC_KEY_SIZE;

/// Size of an Ed25519 signature in bytes.
pub const HSM_SIGNATURE_SIZE: usize = SIGNATURE_SIZE;

/// Errors that can occur during HSM operations.
#[derive(Debug, Error)]
pub enum HsmError {
    /// HSM connection failed.
    #[error("HSM connection failed: {message}")]
    ConnectionFailed {
        /// Description of the connection failure.
        message: String,
    },

    /// HSM connection timeout.
    #[error("HSM operation timed out after {timeout_ms}ms")]
    Timeout {
        /// The timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// HSM not connected.
    #[error("HSM not connected")]
    NotConnected,

    /// Key not found in HSM.
    #[error("key not found in HSM: {key_id}")]
    KeyNotFound {
        /// The key ID that was not found.
        key_id: String,
    },

    /// Key already exists in HSM.
    #[error("key already exists in HSM: {key_id}")]
    KeyAlreadyExists {
        /// The key ID that already exists.
        key_id: String,
    },

    /// Invalid key ID format.
    #[error(
        "invalid key ID: {key_id} (must be alphanumeric with hyphens/underscores, 1-{} chars)",
        MAX_KEY_ID_LEN
    )]
    InvalidKeyId {
        /// The invalid key ID.
        key_id: String,
    },

    /// HSM authentication failed.
    #[error("HSM authentication failed: {message}")]
    AuthenticationFailed {
        /// Description of the authentication failure.
        message: String,
    },

    /// HSM internal error.
    #[error("HSM internal error: {message}")]
    InternalError {
        /// Description of the internal error.
        message: String,
    },

    /// Signing operation failed.
    #[error("signing failed: {message}")]
    SigningFailed {
        /// Description of the signing failure.
        message: String,
    },

    /// Key rotation failed.
    #[error("key rotation failed: {message}")]
    RotationFailed {
        /// Description of the rotation failure.
        message: String,
    },

    /// HSM capacity exceeded.
    #[error("HSM key capacity exceeded")]
    CapacityExceeded,

    /// Invalid HSM configuration.
    #[error("invalid HSM configuration: {message}")]
    InvalidConfiguration {
        /// Description of the configuration error.
        message: String,
    },
}

/// Result type for HSM operations.
pub type HsmResult<T> = Result<T, HsmError>;

/// HSM provider type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmProviderType {
    /// Software-based provider for development and testing.
    Software,
    /// `YubiHSM` hardware provider.
    YubiHsm,
    /// AWS `CloudHSM` provider (future).
    AwsCloudHsm,
}

impl std::fmt::Display for HsmProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Software => write!(f, "Software"),
            Self::YubiHsm => write!(f, "`YubiHSM`"),
            Self::AwsCloudHsm => write!(f, "AWS CloudHSM"),
        }
    }
}

/// Configuration for HSM providers.
#[derive(Debug, Clone)]
pub struct HsmConfig {
    /// The type of HSM provider to use.
    pub provider_type: HsmProviderType,

    /// Timeout for HSM operations in milliseconds.
    pub timeout_ms: u64,

    /// Number of retry attempts for failed operations.
    pub retry_attempts: u32,

    /// Delay between retry attempts in milliseconds.
    pub retry_delay_ms: u64,

    /// `YubiHSM`-specific: Connector URL (e.g., `http://127.0.0.1:12345`).
    pub yubihsm_connector_url: Option<String>,

    /// `YubiHSM`-specific: Authentication key ID (default: 1).
    pub yubihsm_auth_key_id: Option<u16>,

    /// `YubiHSM`-specific: Authentication key password.
    pub yubihsm_auth_key_password: Option<String>,

    /// `YubiHSM`-specific: Domain to use for key operations (default: 1).
    pub yubihsm_domain: Option<u16>,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self::software()
    }
}

impl HsmConfig {
    /// Creates a configuration for the software HSM provider.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: initializes Option<String>
    pub fn software() -> Self {
        Self {
            provider_type: HsmProviderType::Software,
            timeout_ms: DEFAULT_HSM_TIMEOUT_MS,
            retry_attempts: 3,
            retry_delay_ms: 100,
            yubihsm_connector_url: None,
            yubihsm_auth_key_id: None,
            yubihsm_auth_key_password: None,
            yubihsm_domain: None,
        }
    }

    /// Creates a configuration for `YubiHSM` provider.
    ///
    /// # Arguments
    ///
    /// * `connector_url` - URL of the `YubiHSM` connector (e.g., `http://127.0.0.1:12345`)
    /// * `auth_key_id` - Authentication key ID
    /// * `auth_key_password` - Authentication key password
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: takes String parameters
    pub fn yubihsm(connector_url: String, auth_key_id: u16, auth_key_password: String) -> Self {
        Self {
            provider_type: HsmProviderType::YubiHsm,
            timeout_ms: DEFAULT_HSM_TIMEOUT_MS,
            retry_attempts: 3,
            retry_delay_ms: 100,
            yubihsm_connector_url: Some(connector_url),
            yubihsm_auth_key_id: Some(auth_key_id),
            yubihsm_auth_key_password: Some(auth_key_password),
            yubihsm_domain: Some(1),
        }
    }

    /// Sets the operation timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Sets the retry configuration.
    #[must_use]
    pub const fn with_retries(mut self, attempts: u32, delay_ms: u64) -> Self {
        self.retry_attempts = attempts;
        self.retry_delay_ms = delay_ms;
        self
    }

    /// Sets the `YubiHSM` domain.
    #[must_use]
    pub const fn with_yubihsm_domain(mut self, domain: u16) -> Self {
        self.yubihsm_domain = Some(domain);
        self
    }

    /// Returns the timeout as a Duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// Trait for HSM providers supporting validator key operations.
///
/// This trait abstracts over different HSM implementations, providing a uniform
/// interface for key generation, signing, and rotation. All implementations
/// must ensure that private key material never leaves the HSM boundary.
///
/// # Async Methods
///
/// HSM operations are inherently asynchronous due to potential network latency
/// and hardware communication delays. All methods return boxed futures for
/// compatibility with async runtimes.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow concurrent access from
/// multiple validator threads.
pub trait HsmProvider: Send + Sync {
    /// Generates a new Ed25519 key pair in the HSM.
    ///
    /// The key is generated entirely within the HSM; the private key never
    /// leaves the secure boundary.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key (1-128 alphanumeric chars)
    ///
    /// # Returns
    ///
    /// The key ID on success, or an error if generation fails.
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyAlreadyExists`]: Key with this ID already exists
    /// - [`HsmError::InvalidKeyId`]: Key ID format is invalid
    /// - [`HsmError::CapacityExceeded`]: HSM key storage is full
    /// - [`HsmError::Timeout`]: Operation timed out
    /// - [`HsmError::NotConnected`]: HSM is not connected
    fn generate_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<String>>;

    /// Signs a message using the specified key.
    ///
    /// The signing operation is performed entirely within the HSM; the private
    /// key never leaves the secure boundary.
    ///
    /// # Arguments
    ///
    /// * `key_id` - ID of the key to use for signing
    /// * `message` - Message bytes to sign
    ///
    /// # Returns
    ///
    /// The Ed25519 signature (64 bytes) on success.
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyNotFound`]: Key with this ID does not exist
    /// - [`HsmError::SigningFailed`]: Signing operation failed
    /// - [`HsmError::Timeout`]: Operation timed out
    /// - [`HsmError::NotConnected`]: HSM is not connected
    fn sign<'a>(
        &'a self,
        key_id: &'a str,
        message: &'a [u8],
    ) -> BoxFuture<'a, HsmResult<Signature>>;

    /// Retrieves the public key for the specified key.
    ///
    /// # Arguments
    ///
    /// * `key_id` - ID of the key
    ///
    /// # Returns
    ///
    /// The Ed25519 public key (32 bytes) on success.
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyNotFound`]: Key with this ID does not exist
    /// - [`HsmError::Timeout`]: Operation timed out
    /// - [`HsmError::NotConnected`]: HSM is not connected
    fn public_key<'a>(
        &'a self,
        key_id: &'a str,
    ) -> BoxFuture<'a, HsmResult<[u8; HSM_PUBLIC_KEY_SIZE]>>;

    /// Rotates a key by generating a new key and optionally deleting the old
    /// one.
    ///
    /// Key rotation creates a new key with a derived ID (e.g.,
    /// "validator-1-v2") and optionally removes the old key. The new key ID
    /// is returned.
    ///
    /// # Arguments
    ///
    /// * `key_id` - ID of the current key to rotate
    ///
    /// # Returns
    ///
    /// The new key ID on success.
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyNotFound`]: Key with this ID does not exist
    /// - [`HsmError::RotationFailed`]: Key rotation failed
    /// - [`HsmError::Timeout`]: Operation timed out
    /// - [`HsmError::NotConnected`]: HSM is not connected
    fn rotate_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<String>>;

    /// Deletes a key from the HSM.
    ///
    /// This operation is irreversible. The key material is securely zeroized.
    ///
    /// # Arguments
    ///
    /// * `key_id` - ID of the key to delete
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyNotFound`]: Key with this ID does not exist
    /// - [`HsmError::Timeout`]: Operation timed out
    /// - [`HsmError::NotConnected`]: HSM is not connected
    fn delete_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<()>>;

    /// Checks if a key exists in the HSM.
    ///
    /// # Arguments
    ///
    /// * `key_id` - ID of the key to check
    ///
    /// # Returns
    ///
    /// `true` if the key exists, `false` otherwise.
    fn key_exists<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<bool>>;

    /// Lists all key IDs in the HSM.
    ///
    /// # Returns
    ///
    /// Vector of key IDs.
    fn list_keys(&self) -> BoxFuture<'_, HsmResult<Vec<String>>>;

    /// Returns whether the HSM is connected and operational.
    fn is_connected(&self) -> bool;

    /// Returns the provider type.
    fn provider_type(&self) -> HsmProviderType;

    /// Connects to the HSM (if not already connected).
    ///
    /// For software providers, this is a no-op. For hardware providers, this
    /// establishes the connection to the HSM device.
    fn connect(&self) -> BoxFuture<'_, HsmResult<()>>;

    /// Disconnects from the HSM.
    ///
    /// For software providers, this is a no-op. For hardware providers, this
    /// closes the connection to the HSM device.
    fn disconnect(&self) -> BoxFuture<'_, HsmResult<()>>;
}

/// Validates a key ID.
///
/// Valid key IDs:
/// - Are 1-128 characters long
/// - Contain only alphanumeric characters, hyphens, and underscores
/// - Do not start with a hyphen
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

/// Internal key storage for software HSM provider.
struct SoftwareKeyEntry {
    /// The signing key (stored in memory for software provider).
    signer: Signer,
    /// Key version (for rotation tracking).
    version: u32,
}

/// Software-based HSM provider for development and testing.
///
/// This provider stores keys in memory and performs all cryptographic
/// operations in software. It is suitable for development and testing but
/// should NOT be used in production environments where HSM protection is
/// required.
///
/// # Security Warning
///
/// The software provider does NOT provide the security guarantees of a hardware
/// HSM. Private keys are stored in process memory and may be vulnerable to:
/// - Memory dumping attacks
/// - Side-channel attacks
/// - Process introspection
///
/// Use a hardware HSM provider (e.g., `YubiHsmProvider`) for production.
pub struct SoftwareHsmProvider {
    /// Configuration for the provider (stored for future use in retry logic).
    #[allow(dead_code)]
    config: HsmConfig,
    /// In-memory key storage.
    keys: RwLock<HashMap<String, SoftwareKeyEntry>>,
    /// Connection state (always true for software provider).
    connected: std::sync::atomic::AtomicBool,
}

impl SoftwareHsmProvider {
    /// Creates a new software HSM provider.
    #[must_use]
    pub fn new(config: HsmConfig) -> Self {
        Self {
            config,
            keys: RwLock::new(HashMap::new()),
            connected: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Creates a new software HSM provider with default configuration.
    #[must_use]
    pub fn default_provider() -> Self {
        Self::new(HsmConfig::software())
    }

    /// Returns the next version number for a key rotation.
    fn next_version(&self, key_id: &str) -> u32 {
        // Extract base key ID and find highest version
        let base_id = key_id.split("-v").next().unwrap_or(key_id);
        let keys = self.keys.read().unwrap();

        let max_version = keys
            .iter()
            .filter_map(|(id, entry)| {
                let id_base = id.split("-v").next().unwrap_or(id);
                if id_base == base_id {
                    Some(entry.version)
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(0);

        max_version + 1
    }
}

impl HsmProvider for SoftwareHsmProvider {
    fn generate_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<String>> {
        Box::pin(async move {
            validate_key_id(key_id)?;

            let mut keys = self.keys.write().unwrap();

            if keys.contains_key(key_id) {
                return Err(HsmError::KeyAlreadyExists {
                    key_id: key_id.to_string(),
                });
            }

            let signer = Signer::generate();
            keys.insert(key_id.to_string(), SoftwareKeyEntry { signer, version: 1 });

            Ok(key_id.to_string())
        })
    }

    fn sign<'a>(
        &'a self,
        key_id: &'a str,
        message: &'a [u8],
    ) -> BoxFuture<'a, HsmResult<Signature>> {
        Box::pin(async move {
            validate_key_id(key_id)?;

            let keys = self.keys.read().unwrap();
            let entry = keys.get(key_id).ok_or_else(|| HsmError::KeyNotFound {
                key_id: key_id.to_string(),
            })?;

            Ok(entry.signer.sign(message))
        })
    }

    fn public_key<'a>(
        &'a self,
        key_id: &'a str,
    ) -> BoxFuture<'a, HsmResult<[u8; HSM_PUBLIC_KEY_SIZE]>> {
        Box::pin(async move {
            validate_key_id(key_id)?;

            let keys = self.keys.read().unwrap();
            let entry = keys.get(key_id).ok_or_else(|| HsmError::KeyNotFound {
                key_id: key_id.to_string(),
            })?;

            Ok(entry.signer.public_key_bytes())
        })
    }

    fn rotate_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<String>> {
        Box::pin(async move {
            validate_key_id(key_id)?;

            // Check that old key exists
            {
                let keys = self.keys.read().unwrap();
                if !keys.contains_key(key_id) {
                    return Err(HsmError::KeyNotFound {
                        key_id: key_id.to_string(),
                    });
                }
            }

            // Generate new key ID with version
            let version = self.next_version(key_id);
            let base_id = key_id.split("-v").next().unwrap_or(key_id);
            let new_key_id = format!("{base_id}-v{version}");

            // Validate new key ID
            validate_key_id(&new_key_id)?;

            // Generate and store new key
            let mut keys = self.keys.write().unwrap();
            let signer = Signer::generate();
            keys.insert(new_key_id.clone(), SoftwareKeyEntry { signer, version });

            Ok(new_key_id)
        })
    }

    fn delete_key<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<()>> {
        Box::pin(async move {
            validate_key_id(key_id)?;

            let mut keys = self.keys.write().unwrap();
            if keys.remove(key_id).is_none() {
                return Err(HsmError::KeyNotFound {
                    key_id: key_id.to_string(),
                });
            }

            Ok(())
        })
    }

    fn key_exists<'a>(&'a self, key_id: &'a str) -> BoxFuture<'a, HsmResult<bool>> {
        Box::pin(async move {
            validate_key_id(key_id)?;

            let keys = self.keys.read().unwrap();
            Ok(keys.contains_key(key_id))
        })
    }

    fn list_keys(&self) -> BoxFuture<'_, HsmResult<Vec<String>>> {
        Box::pin(async move {
            let keys = self.keys.read().unwrap();
            Ok(keys.keys().cloned().collect())
        })
    }

    fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn provider_type(&self) -> HsmProviderType {
        HsmProviderType::Software
    }

    fn connect(&self) -> BoxFuture<'_, HsmResult<()>> {
        Box::pin(async move {
            self.connected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }

    fn disconnect(&self) -> BoxFuture<'_, HsmResult<()>> {
        Box::pin(async move {
            self.connected
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

/// Creates an HSM provider based on configuration.
///
/// This factory function creates the appropriate HSM provider based on the
/// configuration. For `HsmProviderType::YubiHsm`, the yubihsm feature must
/// be enabled at compile time.
///
/// # Errors
///
/// Returns an error if the requested provider type is not available or if
/// configuration is invalid.
pub fn create_hsm_provider(config: HsmConfig) -> HsmResult<Box<dyn HsmProvider>> {
    match config.provider_type {
        HsmProviderType::Software => Ok(Box::new(SoftwareHsmProvider::new(config))),
        HsmProviderType::YubiHsm => {
            #[cfg(feature = "yubihsm")]
            {
                use super::yubihsm::YubiHsmProvider;
                Ok(Box::new(YubiHsmProvider::new(config)?))
            }
            #[cfg(not(feature = "yubihsm"))]
            {
                Err(HsmError::InvalidConfiguration {
                    message: "`YubiHSM` support requires the 'yubihsm' feature flag".to_string(),
                })
            }
        },
        HsmProviderType::AwsCloudHsm => Err(HsmError::InvalidConfiguration {
            message: "AWS CloudHSM support is not yet implemented".to_string(),
        }),
    }
}

/// Key information returned from HSM queries.
#[derive(Debug, Clone)]
pub struct HsmKeyInfo {
    /// The key ID.
    pub key_id: String,
    /// The public key bytes.
    pub public_key: [u8; HSM_PUBLIC_KEY_SIZE],
    /// Key version (for rotation tracking).
    pub version: u32,
}

#[cfg(test)]
mod unit_tests {
    use ed25519_dalek::Verifier as _;

    use super::*;

    // ========== Key ID Validation Tests ==========

    #[test]
    fn tck_00192_valid_key_ids() {
        assert!(validate_key_id("validator-1").is_ok());
        assert!(validate_key_id("validator_1").is_ok());
        assert!(validate_key_id("VALIDATOR-1").is_ok());
        assert!(validate_key_id("v1").is_ok());
        assert!(validate_key_id("a").is_ok());
        assert!(validate_key_id("123").is_ok());
        assert!(validate_key_id("validator-1-v2").is_ok());
    }

    #[test]
    fn tck_00192_invalid_key_ids() {
        // Empty
        assert!(matches!(
            validate_key_id(""),
            Err(HsmError::InvalidKeyId { .. })
        ));

        // Too long
        let long_id = "a".repeat(MAX_KEY_ID_LEN + 1);
        assert!(matches!(
            validate_key_id(&long_id),
            Err(HsmError::InvalidKeyId { .. })
        ));

        // Invalid characters
        assert!(matches!(
            validate_key_id("validator.1"),
            Err(HsmError::InvalidKeyId { .. })
        ));
        assert!(matches!(
            validate_key_id("validator/1"),
            Err(HsmError::InvalidKeyId { .. })
        ));
        assert!(matches!(
            validate_key_id("validator 1"),
            Err(HsmError::InvalidKeyId { .. })
        ));
        assert!(matches!(
            validate_key_id("../escape"),
            Err(HsmError::InvalidKeyId { .. })
        ));

        // Starts with hyphen
        assert!(matches!(
            validate_key_id("-validator"),
            Err(HsmError::InvalidKeyId { .. })
        ));
    }

    #[test]
    fn tck_00192_max_length_key_id() {
        let max_id = "a".repeat(MAX_KEY_ID_LEN);
        assert!(validate_key_id(&max_id).is_ok());
    }

    // ========== HsmConfig Tests ==========

    #[test]
    fn tck_00192_software_config() {
        let config = HsmConfig::software();
        assert_eq!(config.provider_type, HsmProviderType::Software);
        assert_eq!(config.timeout_ms, DEFAULT_HSM_TIMEOUT_MS);
        assert!(config.yubihsm_connector_url.is_none());
    }

    #[test]
    fn tck_00192_yubihsm_config() {
        let config = HsmConfig::yubihsm(
            "http://127.0.0.1:12345".to_string(),
            1,
            "password".to_string(),
        );
        assert_eq!(config.provider_type, HsmProviderType::YubiHsm);
        assert_eq!(
            config.yubihsm_connector_url,
            Some("http://127.0.0.1:12345".to_string())
        );
        assert_eq!(config.yubihsm_auth_key_id, Some(1));
    }

    #[test]
    fn tck_00192_config_with_timeout() {
        let config = HsmConfig::software().with_timeout(10000);
        assert_eq!(config.timeout_ms, 10000);
        assert_eq!(config.timeout(), Duration::from_millis(10000));
    }

    #[test]
    fn tck_00192_config_with_retries() {
        let config = HsmConfig::software().with_retries(5, 200);
        assert_eq!(config.retry_attempts, 5);
        assert_eq!(config.retry_delay_ms, 200);
    }

    // ========== SoftwareHsmProvider Tests ==========

    #[tokio::test]
    async fn tck_00192_software_generate_key() {
        let hsm = SoftwareHsmProvider::default_provider();

        let key_id = hsm.generate_key("validator-1").await.unwrap();
        assert_eq!(key_id, "validator-1");

        // Key should exist
        assert!(hsm.key_exists("validator-1").await.unwrap());

        // Public key should be retrievable
        let public_key = hsm.public_key("validator-1").await.unwrap();
        assert_eq!(public_key.len(), HSM_PUBLIC_KEY_SIZE);
    }

    #[tokio::test]
    async fn tck_00192_software_duplicate_key_error() {
        let hsm = SoftwareHsmProvider::default_provider();

        hsm.generate_key("validator-1").await.unwrap();

        let result = hsm.generate_key("validator-1").await;
        assert!(matches!(result, Err(HsmError::KeyAlreadyExists { .. })));
    }

    #[tokio::test]
    async fn tck_00192_software_key_not_found() {
        let hsm = SoftwareHsmProvider::default_provider();

        let result = hsm.public_key("nonexistent").await;
        assert!(matches!(result, Err(HsmError::KeyNotFound { .. })));
    }

    #[tokio::test]
    async fn tck_00192_software_sign_and_verify() {
        let hsm = SoftwareHsmProvider::default_provider();

        hsm.generate_key("validator-1").await.unwrap();

        let message = b"consensus proposal hash";
        let signature = hsm.sign("validator-1", message).await.unwrap();

        // Verify signature with public key
        let public_key_bytes = hsm.public_key("validator-1").await.unwrap();
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).unwrap();

        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[tokio::test]
    async fn tck_00192_software_key_rotation() {
        let hsm = SoftwareHsmProvider::default_provider();

        // Generate initial key
        hsm.generate_key("validator-1").await.unwrap();
        let old_public_key = hsm.public_key("validator-1").await.unwrap();

        // Rotate key
        let new_key_id = hsm.rotate_key("validator-1").await.unwrap();
        assert_eq!(new_key_id, "validator-1-v2");

        // New key should exist with different public key
        let new_public_key = hsm.public_key(&new_key_id).await.unwrap();
        assert_ne!(old_public_key, new_public_key);

        // Old key should still exist
        assert!(hsm.key_exists("validator-1").await.unwrap());
    }

    #[tokio::test]
    async fn tck_00192_software_multiple_rotations() {
        let hsm = SoftwareHsmProvider::default_provider();

        hsm.generate_key("validator-1").await.unwrap();

        let key_v2 = hsm.rotate_key("validator-1").await.unwrap();
        assert_eq!(key_v2, "validator-1-v2");

        let key_v3 = hsm.rotate_key(&key_v2).await.unwrap();
        assert_eq!(key_v3, "validator-1-v3");

        let key_v4 = hsm.rotate_key(&key_v3).await.unwrap();
        assert_eq!(key_v4, "validator-1-v4");
    }

    #[tokio::test]
    async fn tck_00192_software_delete_key() {
        let hsm = SoftwareHsmProvider::default_provider();

        hsm.generate_key("validator-1").await.unwrap();
        assert!(hsm.key_exists("validator-1").await.unwrap());

        hsm.delete_key("validator-1").await.unwrap();
        assert!(!hsm.key_exists("validator-1").await.unwrap());
    }

    #[tokio::test]
    async fn tck_00192_software_delete_nonexistent() {
        let hsm = SoftwareHsmProvider::default_provider();

        let result = hsm.delete_key("nonexistent").await;
        assert!(matches!(result, Err(HsmError::KeyNotFound { .. })));
    }

    #[tokio::test]
    async fn tck_00192_software_list_keys() {
        let hsm = SoftwareHsmProvider::default_provider();

        hsm.generate_key("validator-1").await.unwrap();
        hsm.generate_key("validator-2").await.unwrap();
        hsm.generate_key("validator-3").await.unwrap();

        let mut keys = hsm.list_keys().await.unwrap();
        keys.sort();

        assert_eq!(keys, vec!["validator-1", "validator-2", "validator-3"]);
    }

    #[tokio::test]
    async fn tck_00192_software_connection_state() {
        let hsm = SoftwareHsmProvider::default_provider();

        assert!(hsm.is_connected());
        assert_eq!(hsm.provider_type(), HsmProviderType::Software);

        hsm.disconnect().await.unwrap();
        assert!(!hsm.is_connected());

        hsm.connect().await.unwrap();
        assert!(hsm.is_connected());
    }

    #[tokio::test]
    async fn tck_00192_software_sign_nonexistent_key() {
        let hsm = SoftwareHsmProvider::default_provider();

        let result = hsm.sign("nonexistent", b"message").await;
        assert!(matches!(result, Err(HsmError::KeyNotFound { .. })));
    }

    #[tokio::test]
    async fn tck_00192_software_rotate_nonexistent_key() {
        let hsm = SoftwareHsmProvider::default_provider();

        let result = hsm.rotate_key("nonexistent").await;
        assert!(matches!(result, Err(HsmError::KeyNotFound { .. })));
    }

    // ========== Factory Function Tests ==========

    #[test]
    fn tck_00192_create_software_provider() {
        let config = HsmConfig::software();
        let provider = create_hsm_provider(config).unwrap();
        assert_eq!(provider.provider_type(), HsmProviderType::Software);
    }

    #[test]
    #[cfg(not(feature = "yubihsm"))]
    fn tck_00192_create_yubihsm_provider_without_feature() {
        let config = HsmConfig::yubihsm(
            "http://127.0.0.1:12345".to_string(),
            1,
            "password".to_string(),
        );

        let result = create_hsm_provider(config);
        assert!(matches!(result, Err(HsmError::InvalidConfiguration { .. })));
    }

    #[test]
    fn tck_00192_create_cloudhsm_provider_not_implemented() {
        let config = HsmConfig {
            provider_type: HsmProviderType::AwsCloudHsm,
            ..HsmConfig::default()
        };
        let result = create_hsm_provider(config);
        assert!(matches!(result, Err(HsmError::InvalidConfiguration { .. })));
    }

    // ========== HsmProviderType Display Tests ==========

    #[test]
    fn tck_00192_provider_type_display() {
        assert_eq!(format!("{}", HsmProviderType::Software), "Software");
        assert_eq!(format!("{}", HsmProviderType::YubiHsm), "`YubiHSM`");
        assert_eq!(format!("{}", HsmProviderType::AwsCloudHsm), "AWS CloudHSM");
    }

    // ========== Thread Safety Test ==========

    #[tokio::test]
    async fn tck_00192_software_concurrent_operations() {
        use std::sync::Arc;

        let hsm = Arc::new(SoftwareHsmProvider::default_provider());

        // Generate keys concurrently
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let hsm = Arc::clone(&hsm);
                tokio::spawn(async move {
                    let key_id = format!("validator-{i}");
                    hsm.generate_key(&key_id).await
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // All keys should exist
        let keys = hsm.list_keys().await.unwrap();
        assert_eq!(keys.len(), 10);

        // Sign concurrently
        let sign_handles: Vec<_> = (0..10)
            .map(|i| {
                let hsm = Arc::clone(&hsm);
                tokio::spawn(async move {
                    let key_id = format!("validator-{i}");
                    let message = format!("message-{i}");
                    hsm.sign(&key_id, message.as_bytes()).await
                })
            })
            .collect();

        for handle in sign_handles {
            handle.await.unwrap().unwrap();
        }
    }
}
