//! OS keychain integration for receipt signing keys.
//!
//! This module implements secure storage and retrieval of Ed25519 signing
//! keys using the OS-native keychain per AD-KEY-001.
//!
//! # Architecture
//!
//! ```text
//! SigningKeyStore (trait)
//!     |-- store_key(key_id, key_bytes, version)
//!     |-- load_key(key_id) -> SigningKey + version
//!     |-- delete_key(key_id)
//!     |-- list_keys() -> Vec<KeyInfo>
//!     `-- key_exists(key_id) -> bool
//!
//! OsKeychain (impl SigningKeyStore)
//!     |-- Uses `keyring` crate for Secret Service (Linux) / Keychain (macOS)
//!     `-- Persists key metadata to ~/.apm2/keychain_manifest.json
//!
//! InMemoryKeyStore (impl SigningKeyStore)
//!     `-- For testing without OS keychain
//! ```
//!
//! # Security Model
//!
//! Per AD-KEY-001:
//! - Keys are stored in OS keychain, never in plaintext files
//! - Key versioning enables rotation without breaking verification
//! - 90-day rotation schedule (enforced by caller)
//! - Old keys preserved for verification (1 year)
//!
//! # Persistence
//!
//! The `OsKeychain` implementation maintains a manifest file at
//! `~/.apm2/keychain_manifest.json` that tracks key metadata (IDs, versions,
//! timestamps). This ensures:
//! - `list_keys()` returns all keys even after daemon restart
//! - `MAX_STORED_KEYS` limit is enforced across restarts
//! - The manifest only contains metadata, never secret key material
//!
//! # Contract References
//!
//! - AD-KEY-001: Key lifecycle management
//! - CTR-1303: Bounded collections
//! - CTR-2003: Fail-closed security defaults

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::RwLock;

use secrecy::zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::signer::{KeyId, ReceiptSigner, SignerError};

// =============================================================================
// Constants
// =============================================================================

/// Service name for keychain entries.
pub const KEYCHAIN_SERVICE_NAME: &str = "apm2-receipt-signing";

/// Service name for GitHub tokens (TCK-00262).
///
/// Uses a dedicated service name to avoid collisions with signing keys.
pub const GITHUB_KEYCHAIN_SERVICE: &str = "apm2-github-tokens";

/// Service name for SSH agent socket path (TCK-00263).
///
/// Uses a dedicated service name to avoid collisions with signing keys and
/// GitHub tokens.
pub const SSH_KEYCHAIN_SERVICE: &str = "apm2-ssh-agent";

/// Maximum number of keys to store (CTR-1303).
pub const MAX_STORED_KEYS: usize = 100;

/// Maximum number of GitHub tokens to store (CTR-1303, TCK-00262).
///
/// This bounds the in-memory token store to prevent memory exhaustion attacks.
pub const MAX_STORED_TOKENS: usize = 100;

/// Maximum size for a single GitHub token in bytes (CTR-1303, TCK-00262).
///
/// GitHub tokens are typically under 100 bytes. 4KB is generous while
/// preventing unbounded allocation from malicious input.
pub const MAX_TOKEN_SIZE: usize = 4096;

/// Maximum length for `SSH_AUTH_SOCK` path (CTR-1303, TCK-00263).
///
/// Unix socket paths are limited to 108 bytes on most systems
/// (`UNIX_PATH_MAX`). We use 256 to be generous while preventing unbounded
/// allocation.
pub const MAX_SSH_AUTH_SOCK_LEN: usize = 256;

/// Key data version for serialization compatibility.
const KEY_DATA_VERSION: u8 = 1;

/// Manifest file name for persistent key tracking.
const MANIFEST_FILE_NAME: &str = "keychain_manifest.json";

/// Directory name under home for apm2 state.
const APM2_DIR_NAME: &str = ".apm2";

// =============================================================================
// Helper Functions (internal)
// =============================================================================

/// Gets the current Unix timestamp, failing closed on system time errors.
///
/// Per CTR-2003, if the system time is before the Unix epoch (which should
/// never happen in practice on modern systems), we return an error rather
/// than silently using a fallback value.
fn current_timestamp() -> Result<u64, KeychainError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| KeychainError::Manifest(format!("system time is before Unix epoch: {e}")))
}

// =============================================================================
// KeychainError
// =============================================================================

/// Errors that can occur during keychain operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeychainError {
    /// Key not found in keychain.
    #[error("key not found: {key_id}")]
    NotFound {
        /// The key ID that was not found.
        key_id: String,
    },

    /// Key already exists in keychain.
    #[error("key already exists: {key_id}")]
    AlreadyExists {
        /// The key ID that already exists.
        key_id: String,
    },

    /// Keychain operation failed.
    #[error("keychain error: {0}")]
    Keychain(String),

    /// Invalid key data format.
    #[error("invalid key data: {0}")]
    InvalidData(String),

    /// Maximum key limit exceeded.
    #[error("maximum key limit exceeded ({max} keys)")]
    LimitExceeded {
        /// Maximum number of keys.
        max: usize,
    },

    /// Key ID validation failed.
    #[error("key ID error: {0}")]
    KeyId(#[from] SignerError),

    /// Lock poisoned.
    #[error("internal lock poisoned")]
    LockPoisoned,

    /// Manifest file operation failed.
    #[error("manifest error: {0}")]
    Manifest(String),

    /// Home directory not found.
    #[error("could not determine home directory")]
    NoHomeDirectory,

    /// Token exceeds maximum size (CTR-1303, TCK-00262).
    #[error("token too large: {size} bytes (max {max})")]
    TokenTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Token store is full (CTR-1303, TCK-00262).
    #[error("token store full: maximum {max} tokens")]
    StoreFull {
        /// Maximum number of tokens.
        max: usize,
    },

    /// `SSH_AUTH_SOCK` path too long (CTR-1303, TCK-00263).
    #[error("SSH_AUTH_SOCK path too long: {len} bytes (max {max})")]
    SshAuthSockTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// SSH agent not available (TCK-00263).
    #[error("SSH agent not available")]
    SshAgentNotAvailable,
}

// =============================================================================
// KeyInfo
// =============================================================================

/// Metadata about a stored key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Unique identifier for the key.
    pub key_id: KeyId,
    /// Version number for rotation tracking.
    pub version: u32,
    /// Timestamp when the key was created (Unix epoch seconds).
    pub created_at: u64,
}

// =============================================================================
// SigningKeyStore Trait
// =============================================================================

/// Trait for signing key storage backends.
///
/// This trait abstracts the key storage mechanism to allow:
/// - OS keychain storage for production
/// - In-memory storage for testing
pub trait SigningKeyStore: Send + Sync {
    /// Stores a signing key in the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `key_bytes` - 32-byte Ed25519 signing key seed
    /// * `version` - Version number for rotation tracking
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key already exists
    /// - Maximum key limit exceeded
    /// - Keychain operation fails
    fn store_key(
        &self,
        key_id: &KeyId,
        key_bytes: &[u8; 32],
        version: u32,
    ) -> Result<(), KeychainError>;

    /// Loads a signing key from the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key not found
    /// - Key data is corrupted
    /// - Keychain operation fails
    fn load_key(&self, key_id: &KeyId) -> Result<ReceiptSigner, KeychainError>;

    /// Deletes a signing key from the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    ///
    /// # Errors
    ///
    /// Returns an error if the keychain operation fails.
    /// Returns Ok(()) if key doesn't exist (idempotent delete).
    fn delete_key(&self, key_id: &KeyId) -> Result<(), KeychainError>;

    /// Lists all keys in the keystore.
    ///
    /// # Errors
    ///
    /// Returns an error if the keychain operation fails.
    fn list_keys(&self) -> Result<Vec<KeyInfo>, KeychainError>;

    /// Checks if a key exists in the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    fn key_exists(&self, key_id: &KeyId) -> Result<bool, KeychainError>;

    /// Updates the version of an existing key.
    ///
    /// This is used during key rotation to update the version number
    /// while preserving the same key bytes.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `new_version` - New version number
    ///
    /// # Errors
    ///
    /// Returns an error if the key doesn't exist or the operation fails.
    fn update_version(&self, key_id: &KeyId, new_version: u32) -> Result<(), KeychainError>;
}

// =============================================================================
// GitHubCredentialStore Trait (TCK-00262)
// =============================================================================

/// Trait for GitHub credential storage backends.
///
/// This trait abstracts the storage of GitHub installation access tokens
/// to allow for OS keychain storage in production and in-memory storage
/// for testing. Per RFC-0017 TB-003, credentials are held by the daemon
/// only and never exposed to session processes.
///
/// # Security
///
/// - Tokens are stored in the OS keychain, protected at rest
/// - Sessions never see raw credentials (broker-mediated access)
/// - Uses a dedicated service name (`GITHUB_KEYCHAIN_SERVICE`) to avoid
///   collisions with signing keys
pub trait GitHubCredentialStore: Send + Sync {
    /// Stores a GitHub token for an installation.
    ///
    /// # Arguments
    ///
    /// * `installation_id` - GitHub installation ID (unique identifier)
    /// * `token` - The access token to store
    ///
    /// # Errors
    ///
    /// Returns an error if the keychain operation fails.
    fn store_token(&self, installation_id: &str, token: &str) -> Result<(), KeychainError>;

    /// Retrieves a GitHub token for an installation.
    ///
    /// # Arguments
    ///
    /// * `installation_id` - GitHub installation ID
    ///
    /// # Errors
    ///
    /// Returns `KeychainError::NotFound` if the token is not found,
    /// or another error if the operation fails.
    fn get_token(&self, installation_id: &str) -> Result<String, KeychainError>;

    /// Deletes a GitHub token.
    ///
    /// # Arguments
    ///
    /// * `installation_id` - GitHub installation ID
    ///
    /// # Errors
    ///
    /// Returns an error if the keychain operation fails.
    /// Returns `Ok(())` if the token doesn't exist (idempotent delete).
    fn delete_token(&self, installation_id: &str) -> Result<(), KeychainError>;
}

// =============================================================================
// SshCredentialStore Trait (TCK-00263)
// =============================================================================

/// Trait for SSH credential storage backends.
///
/// This trait abstracts the storage of SSH agent socket paths to allow for
/// broker-mediated SSH operations. Per RFC-0017 TB-003, credentials are held
/// by the daemon only and never exposed to session processes.
///
/// # Security
///
/// - The `SSH_AUTH_SOCK` path is stored in the daemon scope only
/// - Sessions never see the `SSH_AUTH_SOCK` environment variable
/// - All SSH operations are mediated through the broker
/// - The broker sets `SSH_AUTH_SOCK` in subprocess environment for git
///   operations
///
/// # Architecture
///
/// The daemon manages SSH agent access:
/// 1. Daemon holds `SSH_AUTH_SOCK` reference (from environment or internal
///    agent)
/// 2. Git tool requests go through broker
/// 3. Broker executes git commands with `SSH_AUTH_SOCK` set in subprocess env
/// 4. Session process has NO access to `SSH_AUTH_SOCK` or private keys
pub trait SshCredentialStore: Send + Sync {
    /// Stores the `SSH_AUTH_SOCK` path for broker-mediated operations.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier for the session
    /// * `auth_sock_path` - Path to the SSH agent socket
    ///
    /// # Errors
    ///
    /// Returns an error if the path is too long or storage fails.
    fn store_ssh_auth_sock(
        &self,
        session_id: &str,
        auth_sock_path: &str,
    ) -> Result<(), KeychainError>;

    /// Retrieves the `SSH_AUTH_SOCK` path for a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier for the session
    ///
    /// # Errors
    ///
    /// Returns `KeychainError::NotFound` if no path is stored for the session,
    /// or another error if the operation fails.
    fn get_ssh_auth_sock(&self, session_id: &str) -> Result<String, KeychainError>;

    /// Clears the `SSH_AUTH_SOCK` path for a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier for the session
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Returns `Ok(())` if no path was stored (idempotent clear).
    fn clear_ssh_auth_sock(&self, session_id: &str) -> Result<(), KeychainError>;

    /// Checks if SSH agent is available for broker-mediated operations.
    ///
    /// This is typically determined by checking if `SSH_AUTH_SOCK` is set in
    /// the daemon's environment and the socket exists.
    fn is_ssh_agent_available(&self) -> bool;

    /// Gets the daemon's `SSH_AUTH_SOCK` path if available.
    ///
    /// Returns the `SSH_AUTH_SOCK` path from the daemon's environment for use
    /// in broker-mediated operations. This is the path the broker will set
    /// in subprocess environment for git SSH operations.
    fn get_daemon_ssh_auth_sock(&self) -> Option<String>;
}

// =============================================================================
// KeyManifest
// =============================================================================

/// Persistent manifest tracking all stored keys.
///
/// This manifest is stored at `~/.apm2/keychain_manifest.json` and contains
/// only metadata (no secret key material). It ensures `list_keys()` and
/// `MAX_STORED_KEYS` enforcement work correctly across daemon restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct KeyManifest {
    /// Map from key ID string to metadata.
    keys: HashMap<String, KeyInfo>,
}

impl KeyManifest {
    /// Gets the path to the manifest file.
    ///
    /// Returns `~/.apm2/keychain_manifest.json` or `None` if the home
    /// directory cannot be determined.
    fn path() -> Option<PathBuf> {
        directories::BaseDirs::new()
            .map(|dirs| dirs.home_dir().join(APM2_DIR_NAME).join(MANIFEST_FILE_NAME))
    }

    /// Loads the manifest from disk.
    ///
    /// Returns an empty manifest if the file doesn't exist. Fails closed
    /// on parse errors per CTR-2003.
    fn load() -> Result<Self, KeychainError> {
        let path = Self::path().ok_or(KeychainError::NoHomeDirectory)?;

        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content)
                .map_err(|e| KeychainError::Manifest(format!("failed to parse manifest: {e}"))),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // File doesn't exist yet - return empty manifest
                Ok(Self::default())
            },
            Err(e) => Err(KeychainError::Manifest(format!(
                "failed to read manifest: {e}"
            ))),
        }
    }

    /// Saves the manifest to disk.
    ///
    /// Creates the parent directory if it doesn't exist.
    fn save(&self) -> Result<(), KeychainError> {
        let path = Self::path().ok_or(KeychainError::NoHomeDirectory)?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                KeychainError::Manifest(format!("failed to create manifest directory: {e}"))
            })?;
        }

        let content = serde_json::to_string_pretty(&self)
            .map_err(|e| KeychainError::Manifest(format!("failed to serialize manifest: {e}")))?;

        fs::write(&path, content)
            .map_err(|e| KeychainError::Manifest(format!("failed to write manifest: {e}")))?;

        Ok(())
    }
}

// =============================================================================
// OsKeychain
// =============================================================================

/// OS keychain-backed signing key store.
///
/// Uses the `keyring` crate to store keys in the OS-native keychain:
/// - Linux: Secret Service API (GNOME Keyring, KDE Wallet)
/// - macOS: Keychain
/// - Windows: Credential Manager
///
/// Key metadata is persisted to `~/.apm2/keychain_manifest.json` to ensure
/// `list_keys()` returns all keys and `MAX_STORED_KEYS` is enforced across
/// daemon restarts.
pub struct OsKeychain {
    /// Service name for keychain entries.
    service_name: String,
    /// Cache of key metadata (key IDs and versions only, not secrets).
    /// This cache is populated from the manifest on initialization.
    metadata_cache: RwLock<HashMap<String, KeyInfo>>,
    /// Path to manifest file (None to use default path).
    manifest_path: Option<PathBuf>,
}

impl OsKeychain {
    /// Creates a new OS keychain store.
    ///
    /// Loads existing key metadata from the manifest file if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest exists but cannot be read or parsed.
    pub fn new() -> Result<Self, KeychainError> {
        Self::with_service_name(KEYCHAIN_SERVICE_NAME)
    }

    /// Creates a new OS keychain store with a custom service name.
    ///
    /// Loads existing key metadata from the manifest file if it exists.
    ///
    /// # Arguments
    ///
    /// * `service_name` - Custom service name for keychain entries
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest exists but cannot be read or parsed.
    pub fn with_service_name(service_name: impl Into<String>) -> Result<Self, KeychainError> {
        let manifest = KeyManifest::load()?;
        Ok(Self {
            service_name: service_name.into(),
            metadata_cache: RwLock::new(manifest.keys),
            manifest_path: None,
        })
    }

    /// Creates a new OS keychain store with a custom manifest path.
    ///
    /// This is primarily for testing to avoid using the global manifest file.
    ///
    /// # Arguments
    ///
    /// * `service_name` - Custom service name for keychain entries
    /// * `manifest_path` - Path to the manifest file
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest exists but cannot be read or parsed.
    pub fn with_manifest_path(
        service_name: impl Into<String>,
        manifest_path: PathBuf,
    ) -> Result<Self, KeychainError> {
        let manifest = Self::load_manifest_from_path(&manifest_path)?;
        Ok(Self {
            service_name: service_name.into(),
            metadata_cache: RwLock::new(manifest.keys),
            manifest_path: Some(manifest_path),
        })
    }

    /// Loads manifest from a specific path.
    fn load_manifest_from_path(path: &PathBuf) -> Result<KeyManifest, KeychainError> {
        match fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content)
                .map_err(|e| KeychainError::Manifest(format!("failed to parse manifest: {e}"))),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(KeyManifest::default()),
            Err(e) => Err(KeychainError::Manifest(format!(
                "failed to read manifest: {e}"
            ))),
        }
    }

    /// Saves the current cache to the manifest file.
    fn save_manifest(&self, cache: &HashMap<String, KeyInfo>) -> Result<(), KeychainError> {
        let manifest = KeyManifest {
            keys: cache.clone(),
        };

        if let Some(ref path) = self.manifest_path {
            // Use custom path
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    KeychainError::Manifest(format!("failed to create manifest directory: {e}"))
                })?;
            }

            let content = serde_json::to_string_pretty(&manifest).map_err(|e| {
                KeychainError::Manifest(format!("failed to serialize manifest: {e}"))
            })?;

            fs::write(path, content)
                .map_err(|e| KeychainError::Manifest(format!("failed to write manifest: {e}")))?;

            Ok(())
        } else {
            // Use default path
            manifest.save()
        }
    }

    /// Gets the keyring entry for a key.
    fn entry(&self, key_id: &KeyId) -> Result<keyring::Entry, KeychainError> {
        keyring::Entry::new(&self.service_name, key_id.as_str())
            .map_err(|e| KeychainError::Keychain(e.to_string()))
    }

    /// Serializes key data for storage.
    fn serialize_key_data(key_bytes: &[u8; 32], version: u32, created_at: u64) -> String {
        // Simple format: version:created_at:hex_key
        // Version prefix allows future format changes
        format!(
            "{}:{}:{}:{}",
            KEY_DATA_VERSION,
            version,
            created_at,
            hex::encode(key_bytes)
        )
    }

    /// Deserializes key data from storage.
    fn deserialize_key_data(data: &str) -> Result<(Zeroizing<[u8; 32]>, u32, u64), KeychainError> {
        let parts: Vec<&str> = data.split(':').collect();
        if parts.len() != 4 {
            return Err(KeychainError::InvalidData(
                "expected 4 colon-separated parts".to_string(),
            ));
        }

        let data_version: u8 = parts[0]
            .parse()
            .map_err(|_| KeychainError::InvalidData("invalid data version".to_string()))?;
        if data_version != KEY_DATA_VERSION {
            return Err(KeychainError::InvalidData(format!(
                "unsupported data version: {data_version}"
            )));
        }

        let version: u32 = parts[1]
            .parse()
            .map_err(|_| KeychainError::InvalidData("invalid key version".to_string()))?;

        let created_at: u64 = parts[2]
            .parse()
            .map_err(|_| KeychainError::InvalidData("invalid timestamp".to_string()))?;

        let key_bytes = hex::decode(parts[3])
            .map_err(|_| KeychainError::InvalidData("invalid hex key".to_string()))?;

        if key_bytes.len() != 32 {
            return Err(KeychainError::InvalidData(format!(
                "expected 32 key bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        Ok((Zeroizing::new(arr), version, created_at))
    }
}

impl SigningKeyStore for OsKeychain {
    fn store_key(
        &self,
        key_id: &KeyId,
        key_bytes: &[u8; 32],
        version: u32,
    ) -> Result<(), KeychainError> {
        // Check if key already exists
        if self.key_exists(key_id)? {
            return Err(KeychainError::AlreadyExists {
                key_id: key_id.as_str().to_string(),
            });
        }

        // Check limit (CTR-1303) - this now works across restarts because
        // the cache is populated from the manifest on initialization
        {
            let cache = self
                .metadata_cache
                .read()
                .map_err(|_| KeychainError::LockPoisoned)?;
            if cache.len() >= MAX_STORED_KEYS {
                return Err(KeychainError::LimitExceeded {
                    max: MAX_STORED_KEYS,
                });
            }
        }

        // Get current timestamp (fail closed per CTR-2003)
        let created_at = current_timestamp()?;

        // Serialize and store in OS keychain
        let data = Self::serialize_key_data(key_bytes, version, created_at);
        let entry = self.entry(key_id)?;
        entry
            .set_password(&data)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        // Update cache and persist manifest
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        cache.insert(
            key_id.as_str().to_string(),
            KeyInfo {
                key_id: key_id.clone(),
                version,
                created_at,
            },
        );

        // Persist manifest to ensure keys survive restart
        self.save_manifest(&cache)?;

        Ok(())
    }

    fn load_key(&self, key_id: &KeyId) -> Result<ReceiptSigner, KeychainError> {
        let entry = self.entry(key_id)?;
        let data = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeychainError::NotFound {
                key_id: key_id.as_str().to_string(),
            },
            _ => KeychainError::Keychain(e.to_string()),
        })?;

        let (key_bytes, version, created_at) = Self::deserialize_key_data(&data)?;

        // Create signer from bytes
        let signer = ReceiptSigner::from_bytes(&*key_bytes, key_id.clone(), version)
            .map_err(KeychainError::KeyId)?;

        // Update cache (no need to persist manifest on load - it's already there
        // or will be persisted on next mutation)
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        cache.insert(
            key_id.as_str().to_string(),
            KeyInfo {
                key_id: key_id.clone(),
                version,
                created_at,
            },
        );

        Ok(signer)
    }

    fn delete_key(&self, key_id: &KeyId) -> Result<(), KeychainError> {
        let entry = self.entry(key_id)?;

        // Attempt to delete from OS keychain, ignore NotFound (idempotent)
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {},
            Err(e) => return Err(KeychainError::Keychain(e.to_string())),
        }

        // Remove from cache and persist manifest
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        cache.remove(key_id.as_str());

        // Persist manifest to ensure deletion survives restart
        self.save_manifest(&cache)?;

        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<KeyInfo>, KeychainError> {
        // Because the cache is loaded from the manifest on initialization,
        // this now returns all keys even after daemon restart
        let cache = self
            .metadata_cache
            .read()
            .map_err(|_| KeychainError::LockPoisoned)?;
        Ok(cache.values().cloned().collect())
    }

    fn key_exists(&self, key_id: &KeyId) -> Result<bool, KeychainError> {
        // Check cache first
        {
            let cache = self
                .metadata_cache
                .read()
                .map_err(|_| KeychainError::LockPoisoned)?;
            if cache.contains_key(key_id.as_str()) {
                return Ok(true);
            }
        }

        // Try to load from keychain
        let entry = self.entry(key_id)?;
        match entry.get_password() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KeychainError::Keychain(e.to_string())),
        }
    }

    fn update_version(&self, key_id: &KeyId, new_version: u32) -> Result<(), KeychainError> {
        // Load existing key from OS keychain
        let entry = self.entry(key_id)?;
        let data = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeychainError::NotFound {
                key_id: key_id.as_str().to_string(),
            },
            _ => KeychainError::Keychain(e.to_string()),
        })?;

        let (key_bytes, _old_version, created_at) = Self::deserialize_key_data(&data)?;

        // Store with new version in OS keychain
        let new_data = Self::serialize_key_data(&key_bytes, new_version, created_at);
        entry
            .set_password(&new_data)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        // Update cache and persist manifest
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        if let Some(info) = cache.get_mut(key_id.as_str()) {
            info.version = new_version;
        }

        // Persist manifest to ensure version update survives restart
        self.save_manifest(&cache)?;

        Ok(())
    }
}

impl GitHubCredentialStore for OsKeychain {
    fn store_token(&self, installation_id: &str, token: &str) -> Result<(), KeychainError> {
        // Use a dedicated service name for GitHub tokens to avoid collision
        // with signing keys
        let entry = keyring::Entry::new(GITHUB_KEYCHAIN_SERVICE, installation_id)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        entry
            .set_password(token)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        Ok(())
    }

    fn get_token(&self, installation_id: &str) -> Result<String, KeychainError> {
        let entry = keyring::Entry::new(GITHUB_KEYCHAIN_SERVICE, installation_id)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeychainError::NotFound {
                key_id: installation_id.to_string(),
            },
            _ => KeychainError::Keychain(e.to_string()),
        })
    }

    fn delete_token(&self, installation_id: &str) -> Result<(), KeychainError> {
        let entry = keyring::Entry::new(GITHUB_KEYCHAIN_SERVICE, installation_id)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        // Idempotent delete: ignore NotFound errors
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(KeychainError::Keychain(e.to_string())),
        }
    }
}

impl SshCredentialStore for OsKeychain {
    fn store_ssh_auth_sock(
        &self,
        session_id: &str,
        auth_sock_path: &str,
    ) -> Result<(), KeychainError> {
        // CTR-1303, TCK-00263: Enforce path length limit
        if auth_sock_path.len() > MAX_SSH_AUTH_SOCK_LEN {
            return Err(KeychainError::SshAuthSockTooLong {
                len: auth_sock_path.len(),
                max: MAX_SSH_AUTH_SOCK_LEN,
            });
        }

        // Use a dedicated service name for SSH auth sockets
        let entry = keyring::Entry::new(SSH_KEYCHAIN_SERVICE, session_id)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        entry
            .set_password(auth_sock_path)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        Ok(())
    }

    fn get_ssh_auth_sock(&self, session_id: &str) -> Result<String, KeychainError> {
        let entry = keyring::Entry::new(SSH_KEYCHAIN_SERVICE, session_id)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeychainError::NotFound {
                key_id: session_id.to_string(),
            },
            _ => KeychainError::Keychain(e.to_string()),
        })
    }

    fn clear_ssh_auth_sock(&self, session_id: &str) -> Result<(), KeychainError> {
        let entry = keyring::Entry::new(SSH_KEYCHAIN_SERVICE, session_id)
            .map_err(|e| KeychainError::Keychain(e.to_string()))?;

        // Idempotent delete: ignore NotFound errors
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(KeychainError::Keychain(e.to_string())),
        }
    }

    fn is_ssh_agent_available(&self) -> bool {
        self.get_daemon_ssh_auth_sock()
            .is_some_and(|path| std::path::Path::new(&path).exists())
    }

    fn get_daemon_ssh_auth_sock(&self) -> Option<String> {
        std::env::var("SSH_AUTH_SOCK").ok()
    }
}

// =============================================================================
// InMemoryKeyStore
// =============================================================================

/// Entry stored in the in-memory key store.
type InMemoryKeyEntry = (Zeroizing<[u8; 32]>, KeyInfo);

/// In-memory signing key store for testing.
///
/// This implementation does not persist keys and is intended for unit tests
/// that should not interact with the real OS keychain.
pub struct InMemoryKeyStore {
    /// Storage for key data.
    keys: RwLock<HashMap<String, InMemoryKeyEntry>>,
}

impl InMemoryKeyStore {
    /// Creates a new in-memory key store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningKeyStore for InMemoryKeyStore {
    fn store_key(
        &self,
        key_id: &KeyId,
        key_bytes: &[u8; 32],
        version: u32,
    ) -> Result<(), KeychainError> {
        let mut keys = self.keys.write().map_err(|_| KeychainError::LockPoisoned)?;

        if keys.contains_key(key_id.as_str()) {
            return Err(KeychainError::AlreadyExists {
                key_id: key_id.as_str().to_string(),
            });
        }

        if keys.len() >= MAX_STORED_KEYS {
            return Err(KeychainError::LimitExceeded {
                max: MAX_STORED_KEYS,
            });
        }

        // For testing, use current_timestamp helper which fails closed per CTR-2003.
        // In practice, system time before Unix epoch is impossible on modern systems.
        let created_at = current_timestamp()?;

        let info = KeyInfo {
            key_id: key_id.clone(),
            version,
            created_at,
        };

        keys.insert(
            key_id.as_str().to_string(),
            (Zeroizing::new(*key_bytes), info),
        );
        Ok(())
    }

    fn load_key(&self, key_id: &KeyId) -> Result<ReceiptSigner, KeychainError> {
        let keys = self.keys.read().map_err(|_| KeychainError::LockPoisoned)?;

        let (key_bytes, info) =
            keys.get(key_id.as_str())
                .ok_or_else(|| KeychainError::NotFound {
                    key_id: key_id.as_str().to_string(),
                })?;

        ReceiptSigner::from_bytes(&**key_bytes, key_id.clone(), info.version)
            .map_err(KeychainError::KeyId)
    }

    fn delete_key(&self, key_id: &KeyId) -> Result<(), KeychainError> {
        let mut keys = self.keys.write().map_err(|_| KeychainError::LockPoisoned)?;
        keys.remove(key_id.as_str());
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<KeyInfo>, KeychainError> {
        let keys = self.keys.read().map_err(|_| KeychainError::LockPoisoned)?;
        Ok(keys.values().map(|(_, info)| info.clone()).collect())
    }

    fn key_exists(&self, key_id: &KeyId) -> Result<bool, KeychainError> {
        let keys = self.keys.read().map_err(|_| KeychainError::LockPoisoned)?;
        Ok(keys.contains_key(key_id.as_str()))
    }

    fn update_version(&self, key_id: &KeyId, new_version: u32) -> Result<(), KeychainError> {
        let mut keys = self.keys.write().map_err(|_| KeychainError::LockPoisoned)?;

        let (_, info) = keys
            .get_mut(key_id.as_str())
            .ok_or_else(|| KeychainError::NotFound {
                key_id: key_id.as_str().to_string(),
            })?;

        info.version = new_version;
        Ok(())
    }
}

// =============================================================================
// InMemoryGitHubCredentialStore (TCK-00262)
//
// NOTE: This is a TEST-ONLY implementation (marked with #[cfg(test)]).
// Per TCK-00262 security review, in-memory credential stores must not be
// available in production builds. Production code MUST use OsKeychain.
// =============================================================================

/// In-memory GitHub credential store for testing.
///
/// This implementation does not persist tokens and is intended for unit tests
/// that should not interact with the real OS keychain.
///
/// # Security
///
/// This is a **test-only** implementation, enforced via `#[cfg(test)]`.
/// Production code should use `OsKeychain` which stores credentials in the
/// OS-native keychain. The `#[cfg(test)]` attribute ensures this type cannot
/// be accidentally used in production builds.
///
/// Per CTR-1303, this store enforces:
/// - Maximum token size (`MAX_TOKEN_SIZE` = 4096 bytes)
/// - Maximum store capacity (`MAX_STORED_TOKENS` = 100 entries)
#[cfg(test)]
pub struct InMemoryGitHubCredentialStore {
    /// Storage for tokens (`installation_id` -> token).
    tokens: RwLock<HashMap<String, String>>,
}

#[cfg(test)]
impl InMemoryGitHubCredentialStore {
    /// Creates a new in-memory GitHub credential store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
impl Default for InMemoryGitHubCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl GitHubCredentialStore for InMemoryGitHubCredentialStore {
    fn store_token(&self, installation_id: &str, token: &str) -> Result<(), KeychainError> {
        // CTR-1303, TCK-00262: Enforce token size limit to prevent DoS
        if token.len() > MAX_TOKEN_SIZE {
            return Err(KeychainError::TokenTooLarge {
                size: token.len(),
                max: MAX_TOKEN_SIZE,
            });
        }

        let mut tokens = self
            .tokens
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;

        // CTR-1303, TCK-00262: Enforce store capacity limit to prevent memory
        // exhaustion Note: We check if the key already exists to allow
        // overwrites without counting against the limit (common pattern for
        // token refresh)
        if !tokens.contains_key(installation_id) && tokens.len() >= MAX_STORED_TOKENS {
            return Err(KeychainError::StoreFull {
                max: MAX_STORED_TOKENS,
            });
        }

        tokens.insert(installation_id.to_string(), token.to_string());
        Ok(())
    }

    fn get_token(&self, installation_id: &str) -> Result<String, KeychainError> {
        let tokens = self
            .tokens
            .read()
            .map_err(|_| KeychainError::LockPoisoned)?;
        tokens
            .get(installation_id)
            .cloned()
            .ok_or_else(|| KeychainError::NotFound {
                key_id: installation_id.to_string(),
            })
    }

    fn delete_token(&self, installation_id: &str) -> Result<(), KeychainError> {
        let mut tokens = self
            .tokens
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        tokens.remove(installation_id);
        Ok(())
    }
}

// =============================================================================
// InMemorySshCredentialStore (TCK-00263)
//
// NOTE: This is a TEST-ONLY implementation (marked with #[cfg(test)]).
// Per TCK-00263 security review, in-memory credential stores must not be
// available in production builds. Production code MUST use OsKeychain.
// =============================================================================

/// In-memory SSH credential store for testing.
///
/// This implementation does not persist `SSH_AUTH_SOCK` paths and is intended
/// for unit tests that should not interact with the real OS keychain.
///
/// # Security
///
/// This is a **test-only** implementation, enforced via `#[cfg(test)]`.
/// Production code should use `OsKeychain` which stores credentials securely.
/// The `#[cfg(test)]` attribute ensures this type cannot be accidentally used
/// in production builds.
///
/// Per CTR-1303, this store enforces:
/// - Maximum path length (`MAX_SSH_AUTH_SOCK_LEN` = 256 bytes)
#[cfg(test)]
pub struct InMemorySshCredentialStore {
    /// Storage for `SSH_AUTH_SOCK` paths (`session_id` -> path).
    paths: RwLock<HashMap<String, String>>,
    /// Mock daemon `SSH_AUTH_SOCK` path (for testing agent availability).
    daemon_auth_sock: RwLock<Option<String>>,
}

#[cfg(test)]
impl InMemorySshCredentialStore {
    /// Creates a new in-memory SSH credential store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: RwLock::new(HashMap::new()),
            daemon_auth_sock: RwLock::new(None),
        }
    }

    /// Creates a new in-memory SSH credential store with a mock daemon
    /// `SSH_AUTH_SOCK`.
    ///
    /// This is useful for testing SSH agent availability.
    #[must_use]
    pub fn with_daemon_auth_sock(auth_sock: String) -> Self {
        Self {
            paths: RwLock::new(HashMap::new()),
            daemon_auth_sock: RwLock::new(Some(auth_sock)),
        }
    }

    /// Sets the mock daemon `SSH_AUTH_SOCK` path.
    pub fn set_daemon_auth_sock(&self, auth_sock: Option<String>) {
        if let Ok(mut guard) = self.daemon_auth_sock.write() {
            *guard = auth_sock;
        }
    }
}

#[cfg(test)]
impl Default for InMemorySshCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl SshCredentialStore for InMemorySshCredentialStore {
    fn store_ssh_auth_sock(
        &self,
        session_id: &str,
        auth_sock_path: &str,
    ) -> Result<(), KeychainError> {
        // CTR-1303, TCK-00263: Enforce path length limit
        if auth_sock_path.len() > MAX_SSH_AUTH_SOCK_LEN {
            return Err(KeychainError::SshAuthSockTooLong {
                len: auth_sock_path.len(),
                max: MAX_SSH_AUTH_SOCK_LEN,
            });
        }

        let mut paths = self
            .paths
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        paths.insert(session_id.to_string(), auth_sock_path.to_string());
        Ok(())
    }

    fn get_ssh_auth_sock(&self, session_id: &str) -> Result<String, KeychainError> {
        let paths = self.paths.read().map_err(|_| KeychainError::LockPoisoned)?;
        paths
            .get(session_id)
            .cloned()
            .ok_or_else(|| KeychainError::NotFound {
                key_id: session_id.to_string(),
            })
    }

    fn clear_ssh_auth_sock(&self, session_id: &str) -> Result<(), KeychainError> {
        let mut paths = self
            .paths
            .write()
            .map_err(|_| KeychainError::LockPoisoned)?;
        paths.remove(session_id);
        Ok(())
    }

    fn is_ssh_agent_available(&self) -> bool {
        self.daemon_auth_sock
            .read()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn get_daemon_ssh_auth_sock(&self) -> Option<String> {
        self.daemon_auth_sock
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generates a new signing key and stores it in the keystore.
///
/// # Arguments
///
/// * `store` - The key store to use
/// * `key_id` - Unique identifier for the key
/// * `version` - Version number for rotation tracking
///
/// # Errors
///
/// Returns an error if key generation or storage fails.
pub fn generate_and_store_key(
    store: &impl SigningKeyStore,
    key_id: &KeyId,
    version: u32,
) -> Result<ReceiptSigner, KeychainError> {
    // Generate a new signer
    let receipt_signer =
        ReceiptSigner::generate(key_id.clone(), version).map_err(KeychainError::KeyId)?;

    // Store the key bytes
    let key_bytes = receipt_signer.signing_key_bytes();
    store.store_key(key_id, &key_bytes, version)?;

    Ok(receipt_signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_store_key_roundtrip() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("test-key").unwrap();
        let key_bytes = [0x42u8; 32];

        // Store key
        store.store_key(&key_id, &key_bytes, 1).unwrap();

        // Load key
        let signer = store.load_key(&key_id).unwrap();
        assert_eq!(signer.key_id().as_str(), "test-key");
        assert_eq!(signer.key_version(), 1);
    }

    #[test]
    fn test_in_memory_key_already_exists() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("test-key").unwrap();
        let key_bytes = [0x42u8; 32];

        store.store_key(&key_id, &key_bytes, 1).unwrap();

        // Try to store again
        let result = store.store_key(&key_id, &key_bytes, 2);
        assert!(matches!(result, Err(KeychainError::AlreadyExists { .. })));
    }

    #[test]
    fn test_in_memory_key_not_found() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("nonexistent").unwrap();

        let result = store.load_key(&key_id);
        assert!(matches!(result, Err(KeychainError::NotFound { .. })));
    }

    #[test]
    fn test_in_memory_delete_key() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("test-key").unwrap();
        let key_bytes = [0x42u8; 32];

        store.store_key(&key_id, &key_bytes, 1).unwrap();
        assert!(store.key_exists(&key_id).unwrap());

        store.delete_key(&key_id).unwrap();
        assert!(!store.key_exists(&key_id).unwrap());
    }

    #[test]
    fn test_in_memory_delete_nonexistent_is_ok() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("nonexistent").unwrap();

        // Delete should be idempotent
        assert!(store.delete_key(&key_id).is_ok());
    }

    #[test]
    fn test_in_memory_list_keys() {
        let store = InMemoryKeyStore::new();

        // Empty list
        assert!(store.list_keys().unwrap().is_empty());

        // Add some keys
        store
            .store_key(&KeyId::new("key-1").unwrap(), &[0x01u8; 32], 1)
            .unwrap();
        store
            .store_key(&KeyId::new("key-2").unwrap(), &[0x02u8; 32], 2)
            .unwrap();

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_in_memory_update_version() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("test-key").unwrap();
        let key_bytes = [0x42u8; 32];

        store.store_key(&key_id, &key_bytes, 1).unwrap();

        // Update version
        store.update_version(&key_id, 2).unwrap();

        // Verify version was updated
        let signer = store.load_key(&key_id).unwrap();
        assert_eq!(signer.key_version(), 2);
    }

    #[test]
    fn test_generate_and_store_key() {
        let store = InMemoryKeyStore::new();
        let key_id = KeyId::new("generated-key").unwrap();

        let receipt_signer = generate_and_store_key(&store, &key_id, 1).unwrap();
        assert_eq!(receipt_signer.key_id().as_str(), "generated-key");
        assert_eq!(receipt_signer.key_version(), 1);

        // Verify it was stored
        assert!(store.key_exists(&key_id).unwrap());

        // Verify we can load it
        let loaded = store.load_key(&key_id).unwrap();
        assert_eq!(loaded.public_key_bytes(), receipt_signer.public_key_bytes());
    }

    #[test]
    fn test_serialize_deserialize_key_data() {
        let key_bytes = [0x42u8; 32];
        let version = 3;
        let created_at = 1_704_067_200;

        let data = OsKeychain::serialize_key_data(&key_bytes, version, created_at);
        let (loaded_bytes, loaded_version, loaded_created_at) =
            OsKeychain::deserialize_key_data(&data).unwrap();

        assert_eq!(&*loaded_bytes, &key_bytes);
        assert_eq!(loaded_version, version);
        assert_eq!(loaded_created_at, created_at);
    }

    #[test]
    fn test_deserialize_invalid_data() {
        // Missing parts
        assert!(OsKeychain::deserialize_key_data("1:2:3").is_err());

        // Invalid version
        assert!(OsKeychain::deserialize_key_data("99:1:0:00").is_err());

        // Invalid hex
        assert!(OsKeychain::deserialize_key_data("1:1:0:not-hex").is_err());

        // Wrong key length
        assert!(OsKeychain::deserialize_key_data("1:1:0:00112233").is_err());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test only, i is bounded by MAX_STORED_KEYS
    fn test_key_limit_enforced() {
        let store = InMemoryKeyStore::new();

        // Store up to the limit
        for i in 0..MAX_STORED_KEYS {
            let key_id = KeyId::new(format!("key-{i}")).unwrap();
            store.store_key(&key_id, &[i as u8; 32], 1).unwrap();
        }

        // One more should fail
        let key_id = KeyId::new("key-overflow").unwrap();
        let result = store.store_key(&key_id, &[0xff; 32], 1);
        assert!(matches!(result, Err(KeychainError::LimitExceeded { .. })));
    }

    // =========================================================================
    // Manifest Persistence Tests
    // =========================================================================

    #[test]
    fn test_manifest_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("test_manifest.json");

        // Create a keychain with custom manifest path
        let keychain = OsKeychain::with_manifest_path("test-service", manifest_path).unwrap();

        // Initially empty
        assert!(keychain.list_keys().unwrap().is_empty());

        // Note: We can't actually test store_key without a real keyring
        // backend, but we can test manifest serialization directly
    }

    #[test]
    fn test_manifest_serialization() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        // Create and save a manifest with test data
        let mut manifest = KeyManifest::default();
        let key_id = KeyId::new("test-key").unwrap();
        manifest.keys.insert(
            "test-key".to_string(),
            KeyInfo {
                key_id,
                version: 1,
                created_at: 1_704_067_200,
            },
        );

        // Write manifest to file
        let content = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(&manifest_path, &content).unwrap();

        // Load it back
        let loaded = OsKeychain::load_manifest_from_path(&manifest_path).unwrap();

        assert_eq!(loaded.keys.len(), 1);
        let loaded_info = loaded.keys.get("test-key").unwrap();
        assert_eq!(loaded_info.key_id.as_str(), "test-key");
        assert_eq!(loaded_info.version, 1);
        assert_eq!(loaded_info.created_at, 1_704_067_200);
    }

    #[test]
    fn test_manifest_missing_file_returns_empty() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("nonexistent.json");

        // Loading a non-existent manifest should return empty, not error
        let manifest = OsKeychain::load_manifest_from_path(&manifest_path).unwrap();
        assert!(manifest.keys.is_empty());
    }

    #[test]
    fn test_manifest_corrupt_file_returns_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("corrupt.json");

        // Write invalid JSON
        fs::write(&manifest_path, "not valid json {{{").unwrap();

        // Loading corrupt manifest should fail closed (CTR-2003)
        let result = OsKeychain::load_manifest_from_path(&manifest_path);
        assert!(matches!(result, Err(KeychainError::Manifest(_))));
    }

    #[test]
    fn test_key_info_serialization() {
        // Test that KeyInfo round-trips through JSON correctly
        let key_id = KeyId::new("test-key-123").unwrap();
        let info = KeyInfo {
            key_id,
            version: 42,
            created_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&info).unwrap();
        let loaded: KeyInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.key_id.as_str(), "test-key-123");
        assert_eq!(loaded.version, 42);
        assert_eq!(loaded.created_at, 1_700_000_000);
    }

    #[test]
    fn test_current_timestamp_succeeds() {
        // Should succeed on any modern system
        let ts = current_timestamp().unwrap();
        // Timestamp should be after 2024-01-01 (1704067200)
        assert!(ts > 1_704_067_200);
    }

    // =========================================================================
    // InMemoryGitHubCredentialStore Tests (TCK-00262)
    // =========================================================================

    #[test]
    fn test_in_memory_github_store_roundtrip() {
        let store = InMemoryGitHubCredentialStore::new();
        let installation_id = "123456";
        let token = "ghs_test_token_value";

        // Store token
        store.store_token(installation_id, token).unwrap();

        // Retrieve token
        let retrieved = store.get_token(installation_id).unwrap();
        assert_eq!(retrieved, token);
    }

    #[test]
    fn test_in_memory_github_store_not_found() {
        let store = InMemoryGitHubCredentialStore::new();

        let result = store.get_token("nonexistent");
        assert!(matches!(result, Err(KeychainError::NotFound { .. })));
    }

    #[test]
    fn test_in_memory_github_store_delete() {
        let store = InMemoryGitHubCredentialStore::new();
        let installation_id = "123456";

        // Store and then delete
        store.store_token(installation_id, "token").unwrap();
        store.delete_token(installation_id).unwrap();

        // Should not be found
        let result = store.get_token(installation_id);
        assert!(matches!(result, Err(KeychainError::NotFound { .. })));
    }

    #[test]
    fn test_in_memory_github_store_delete_idempotent() {
        let store = InMemoryGitHubCredentialStore::new();

        // Delete nonexistent token should succeed (idempotent)
        assert!(store.delete_token("nonexistent").is_ok());
    }

    #[test]
    fn test_in_memory_github_store_overwrite() {
        let store = InMemoryGitHubCredentialStore::new();
        let installation_id = "123456";

        // Store and overwrite
        store.store_token(installation_id, "token1").unwrap();
        store.store_token(installation_id, "token2").unwrap();

        // Should get latest token
        let retrieved = store.get_token(installation_id).unwrap();
        assert_eq!(retrieved, "token2");
    }

    // =========================================================================
    // Security Bounds Tests (TCK-00262)
    // =========================================================================

    #[test]
    fn test_in_memory_github_store_token_too_large() {
        let store = InMemoryGitHubCredentialStore::new();
        let large_token = "x".repeat(MAX_TOKEN_SIZE + 1);

        let result = store.store_token("installation-1", &large_token);
        assert!(matches!(
            result,
            Err(KeychainError::TokenTooLarge { size, max })
            if size == MAX_TOKEN_SIZE + 1 && max == MAX_TOKEN_SIZE
        ));
    }

    #[test]
    fn test_in_memory_github_store_token_at_limit() {
        let store = InMemoryGitHubCredentialStore::new();
        let max_token = "x".repeat(MAX_TOKEN_SIZE);

        // Should succeed at exactly the limit
        store.store_token("installation-1", &max_token).unwrap();
        let retrieved = store.get_token("installation-1").unwrap();
        assert_eq!(retrieved.len(), MAX_TOKEN_SIZE);
    }

    #[test]
    fn test_in_memory_github_store_capacity_limit() {
        let store = InMemoryGitHubCredentialStore::new();

        // Fill up to the limit
        for i in 0..MAX_STORED_TOKENS {
            store
                .store_token(&format!("installation-{i}"), "token")
                .unwrap();
        }

        // One more should fail
        let result = store.store_token("installation-overflow", "token");
        assert!(matches!(
            result,
            Err(KeychainError::StoreFull { max }) if max == MAX_STORED_TOKENS
        ));
    }

    #[test]
    fn test_in_memory_github_store_overwrite_at_capacity() {
        let store = InMemoryGitHubCredentialStore::new();

        // Fill up to the limit
        for i in 0..MAX_STORED_TOKENS {
            store
                .store_token(&format!("installation-{i}"), "token-v1")
                .unwrap();
        }

        // Overwriting an existing key should still work
        store.store_token("installation-0", "token-v2").unwrap();
        let retrieved = store.get_token("installation-0").unwrap();
        assert_eq!(retrieved, "token-v2");
    }

    // =========================================================================
    // InMemorySshCredentialStore Tests (TCK-00263)
    // =========================================================================

    #[test]
    fn test_in_memory_ssh_store_roundtrip() {
        let store = InMemorySshCredentialStore::new();
        let session_id = "session-123";
        let auth_sock_path = "/tmp/ssh-agent/agent.123";

        // Store path
        store
            .store_ssh_auth_sock(session_id, auth_sock_path)
            .unwrap();

        // Retrieve path
        let retrieved = store.get_ssh_auth_sock(session_id).unwrap();
        assert_eq!(retrieved, auth_sock_path);
    }

    #[test]
    fn test_in_memory_ssh_store_not_found() {
        let store = InMemorySshCredentialStore::new();

        let result = store.get_ssh_auth_sock("nonexistent");
        assert!(matches!(result, Err(KeychainError::NotFound { .. })));
    }

    #[test]
    fn test_in_memory_ssh_store_clear() {
        let store = InMemorySshCredentialStore::new();
        let session_id = "session-123";

        // Store and then clear
        store
            .store_ssh_auth_sock(session_id, "/tmp/agent.sock")
            .unwrap();
        store.clear_ssh_auth_sock(session_id).unwrap();

        // Should not be found
        let result = store.get_ssh_auth_sock(session_id);
        assert!(matches!(result, Err(KeychainError::NotFound { .. })));
    }

    #[test]
    fn test_in_memory_ssh_store_clear_idempotent() {
        let store = InMemorySshCredentialStore::new();

        // Clear nonexistent path should succeed (idempotent)
        assert!(store.clear_ssh_auth_sock("nonexistent").is_ok());
    }

    #[test]
    fn test_in_memory_ssh_store_overwrite() {
        let store = InMemorySshCredentialStore::new();
        let session_id = "session-123";

        // Store and overwrite
        store
            .store_ssh_auth_sock(session_id, "/tmp/agent1.sock")
            .unwrap();
        store
            .store_ssh_auth_sock(session_id, "/tmp/agent2.sock")
            .unwrap();

        // Should get latest path
        let retrieved = store.get_ssh_auth_sock(session_id).unwrap();
        assert_eq!(retrieved, "/tmp/agent2.sock");
    }

    #[test]
    fn test_in_memory_ssh_store_path_too_long() {
        let store = InMemorySshCredentialStore::new();
        let long_path = "/tmp/".to_owned() + &"x".repeat(MAX_SSH_AUTH_SOCK_LEN);

        let result = store.store_ssh_auth_sock("session-1", &long_path);
        assert!(matches!(
            result,
            Err(KeychainError::SshAuthSockTooLong { .. })
        ));
    }

    #[test]
    fn test_in_memory_ssh_store_path_at_limit() {
        let store = InMemorySshCredentialStore::new();
        let max_path = "x".repeat(MAX_SSH_AUTH_SOCK_LEN);

        // Should succeed at exactly the limit
        store.store_ssh_auth_sock("session-1", &max_path).unwrap();
        let retrieved = store.get_ssh_auth_sock("session-1").unwrap();
        assert_eq!(retrieved.len(), MAX_SSH_AUTH_SOCK_LEN);
    }

    #[test]
    fn test_in_memory_ssh_store_agent_not_available_by_default() {
        let store = InMemorySshCredentialStore::new();

        // By default, no daemon auth sock is set
        assert!(!store.is_ssh_agent_available());
        assert!(store.get_daemon_ssh_auth_sock().is_none());
    }

    #[test]
    fn test_in_memory_ssh_store_agent_available() {
        let store =
            InMemorySshCredentialStore::with_daemon_auth_sock("/tmp/ssh-agent.sock".to_string());

        assert!(store.is_ssh_agent_available());
        assert_eq!(
            store.get_daemon_ssh_auth_sock(),
            Some("/tmp/ssh-agent.sock".to_string())
        );
    }

    #[test]
    fn test_in_memory_ssh_store_set_daemon_auth_sock() {
        let store = InMemorySshCredentialStore::new();

        // Initially not available
        assert!(!store.is_ssh_agent_available());

        // Set daemon auth sock
        store.set_daemon_auth_sock(Some("/run/user/1000/ssh-agent.sock".to_string()));
        assert!(store.is_ssh_agent_available());
        assert_eq!(
            store.get_daemon_ssh_auth_sock(),
            Some("/run/user/1000/ssh-agent.sock".to_string())
        );

        // Clear daemon auth sock
        store.set_daemon_auth_sock(None);
        assert!(!store.is_ssh_agent_available());
        assert!(store.get_daemon_ssh_auth_sock().is_none());
    }

    #[test]
    fn test_in_memory_ssh_store_multiple_sessions() {
        let store = InMemorySshCredentialStore::new();

        // Store paths for multiple sessions
        store
            .store_ssh_auth_sock("session-1", "/tmp/agent1.sock")
            .unwrap();
        store
            .store_ssh_auth_sock("session-2", "/tmp/agent2.sock")
            .unwrap();
        store
            .store_ssh_auth_sock("session-3", "/tmp/agent3.sock")
            .unwrap();

        // Verify each session has its own path
        assert_eq!(
            store.get_ssh_auth_sock("session-1").unwrap(),
            "/tmp/agent1.sock"
        );
        assert_eq!(
            store.get_ssh_auth_sock("session-2").unwrap(),
            "/tmp/agent2.sock"
        );
        assert_eq!(
            store.get_ssh_auth_sock("session-3").unwrap(),
            "/tmp/agent3.sock"
        );

        // Clear one session, others should remain
        store.clear_ssh_auth_sock("session-2").unwrap();
        assert!(store.get_ssh_auth_sock("session-1").is_ok());
        assert!(store.get_ssh_auth_sock("session-2").is_err());
        assert!(store.get_ssh_auth_sock("session-3").is_ok());
    }
}
