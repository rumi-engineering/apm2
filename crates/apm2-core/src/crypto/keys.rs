//! Key management for secure storage of signing keys.
//!
//! Mutex poisoning indicates a panic in another thread, which is unrecoverable.

#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use ed25519_dalek::SigningKey;
use thiserror::Error;
use zeroize::Zeroizing;

use super::sign::{PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};

/// Errors that can occur during key management operations.
#[derive(Debug, Error)]
pub enum KeyManagerError {
    /// I/O error during key file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Key not found in storage.
    #[error("key not found: {actor_id}")]
    KeyNotFound {
        /// The actor ID whose key was not found.
        actor_id: String,
    },

    /// Key already exists for actor.
    #[error("key already exists for actor: {actor_id}")]
    KeyAlreadyExists {
        /// The actor ID that already has a key.
        actor_id: String,
    },

    /// Invalid key format in storage.
    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Insecure file permissions detected.
    #[error("insecure permissions on key file: {path}")]
    InsecurePermissions {
        /// The path with insecure permissions.
        path: String,
    },

    /// Invalid actor ID (contains unsafe characters).
    #[error(
        "invalid actor ID: {actor_id} (must be alphanumeric with hyphens/underscores, 1-128 chars)"
    )]
    InvalidActorId {
        /// The invalid actor ID.
        actor_id: String,
    },
}

/// A stored keypair with metadata.
#[derive(Clone)]
pub struct StoredKeypair {
    /// The actor ID this keypair belongs to.
    pub actor_id: String,

    /// The signing key (secret key).
    signing_key: SigningKey,

    /// The public key bytes.
    pub public_key: [u8; PUBLIC_KEY_SIZE],
}

impl StoredKeypair {
    /// Creates a new stored keypair from a signing key.
    fn new(actor_id: impl Into<String>, signing_key: SigningKey) -> Self {
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            actor_id: actor_id.into(),
            signing_key,
            public_key,
        }
    }

    /// Returns the signing key.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Returns the secret key bytes in a zeroizing container.
    #[must_use]
    pub fn secret_key_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }
}

/// Manager for storing and retrieving signing keys.
///
/// Keys can be stored in memory (for testing) or on disk with secure
/// file permissions (0600).
pub struct KeyManager {
    storage: KeyStorage,
}

enum KeyStorage {
    /// In-memory storage for testing.
    Memory(RwLock<HashMap<String, StoredKeypair>>),

    /// File-based storage with secure permissions.
    File { keys_dir: PathBuf },
}

/// Maximum length for actor IDs.
const MAX_ACTOR_ID_LEN: usize = 128;

/// Validates an actor ID to prevent path traversal and other attacks.
///
/// Valid actor IDs:
/// - Are 1-128 characters long
/// - Contain only alphanumeric characters, hyphens, and underscores
/// - Do not start with a hyphen
fn validate_actor_id(actor_id: &str) -> Result<(), KeyManagerError> {
    if actor_id.is_empty() || actor_id.len() > MAX_ACTOR_ID_LEN {
        return Err(KeyManagerError::InvalidActorId {
            actor_id: actor_id.to_string(),
        });
    }

    // Must not start with a hyphen (could be confused with command flags)
    if actor_id.starts_with('-') {
        return Err(KeyManagerError::InvalidActorId {
            actor_id: actor_id.to_string(),
        });
    }

    // Only allow alphanumeric, hyphens, and underscores
    if !actor_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(KeyManagerError::InvalidActorId {
            actor_id: actor_id.to_string(),
        });
    }

    Ok(())
}

impl KeyManager {
    /// Creates an in-memory key manager for testing.
    ///
    /// Keys stored in memory are not persisted and will be lost when
    /// the manager is dropped.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            storage: KeyStorage::Memory(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a file-based key manager.
    ///
    /// Keys are stored in the specified directory with 0600 permissions.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn new(keys_dir: impl AsRef<Path>) -> Result<Self, KeyManagerError> {
        let keys_dir = keys_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist, with secure permissions set atomically
        if !keys_dir.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&keys_dir)?;
        }

        // Verify directory permissions
        let metadata = fs::metadata(&keys_dir)?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyManagerError::InsecurePermissions {
                path: keys_dir.display().to_string(),
            });
        }

        Ok(Self {
            storage: KeyStorage::File { keys_dir },
        })
    }

    /// Generates a new keypair for an actor.
    ///
    /// # Errors
    ///
    /// Returns an error if a key already exists for the actor,
    /// if the actor ID is invalid, or if the key cannot be stored.
    pub fn generate_keypair(&self, actor_id: &str) -> Result<SigningKey, KeyManagerError> {
        validate_actor_id(actor_id)?;

        // Check if key already exists
        if self.get_keypair(actor_id).is_ok() {
            return Err(KeyManagerError::KeyAlreadyExists {
                actor_id: actor_id.to_string(),
            });
        }

        // Generate new keypair
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        // Store the keypair
        self.store_keypair(actor_id, &signing_key)?;

        Ok(signing_key)
    }

    /// Stores a keypair for an actor.
    ///
    /// # Errors
    ///
    /// Returns an error if the actor ID is invalid, a key already exists,
    /// or the key cannot be stored.
    pub fn store_keypair(
        &self,
        actor_id: &str,
        signing_key: &SigningKey,
    ) -> Result<(), KeyManagerError> {
        validate_actor_id(actor_id)?;

        let keypair = StoredKeypair::new(actor_id, signing_key.clone());

        match &self.storage {
            KeyStorage::Memory(map) => {
                let mut map = map.write().unwrap();
                // Consistent with file storage: don't allow overwrites
                if map.contains_key(actor_id) {
                    return Err(KeyManagerError::KeyAlreadyExists {
                        actor_id: actor_id.to_string(),
                    });
                }
                map.insert(actor_id.to_string(), keypair);
            },
            KeyStorage::File { keys_dir } => {
                let key_path = keys_dir.join(format!("{actor_id}.key"));

                // Write key file with atomic operations
                let secret_bytes = keypair.secret_key_bytes();

                // Create file with restricted permissions
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&key_path)?;

                file.write_all(&*secret_bytes)?;
                file.sync_all()?;

                // Verify permissions were set correctly
                let metadata = fs::metadata(&key_path)?;
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    // Remove the file and return error
                    let _ = fs::remove_file(&key_path);
                    return Err(KeyManagerError::InsecurePermissions {
                        path: key_path.display().to_string(),
                    });
                }
            },
        }

        Ok(())
    }

    /// Retrieves a keypair for an actor.
    ///
    /// # Errors
    ///
    /// Returns an error if the actor ID is invalid, key is not found,
    /// or the key cannot be read.
    pub fn get_keypair(&self, actor_id: &str) -> Result<StoredKeypair, KeyManagerError> {
        validate_actor_id(actor_id)?;

        match &self.storage {
            KeyStorage::Memory(map) => {
                let map = map.read().unwrap();
                map.get(actor_id)
                    .cloned()
                    .ok_or_else(|| KeyManagerError::KeyNotFound {
                        actor_id: actor_id.to_string(),
                    })
            },
            KeyStorage::File { keys_dir } => {
                let key_path = keys_dir.join(format!("{actor_id}.key"));

                if !key_path.exists() {
                    return Err(KeyManagerError::KeyNotFound {
                        actor_id: actor_id.to_string(),
                    });
                }

                // Verify permissions before reading
                let metadata = fs::metadata(&key_path)?;
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(KeyManagerError::InsecurePermissions {
                        path: key_path.display().to_string(),
                    });
                }

                // Read key file
                let mut file = File::open(&key_path)?;
                let mut secret_bytes = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
                file.read_exact(&mut *secret_bytes)?;

                let signing_key = SigningKey::from_bytes(&secret_bytes);

                Ok(StoredKeypair::new(actor_id, signing_key))
            },
        }
    }

    /// Deletes a keypair for an actor.
    ///
    /// # Errors
    ///
    /// Returns an error if the actor ID is invalid, key is not found,
    /// or the key cannot be deleted.
    pub fn delete_keypair(&self, actor_id: &str) -> Result<(), KeyManagerError> {
        validate_actor_id(actor_id)?;

        match &self.storage {
            KeyStorage::Memory(map) => {
                let mut map = map.write().unwrap();
                if map.remove(actor_id).is_none() {
                    return Err(KeyManagerError::KeyNotFound {
                        actor_id: actor_id.to_string(),
                    });
                }
            },
            KeyStorage::File { keys_dir } => {
                let key_path = keys_dir.join(format!("{actor_id}.key"));

                if !key_path.exists() {
                    return Err(KeyManagerError::KeyNotFound {
                        actor_id: actor_id.to_string(),
                    });
                }

                fs::remove_file(&key_path)?;
            },
        }

        Ok(())
    }

    /// Lists all actor IDs with stored keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the key directory cannot be read.
    pub fn list_actors(&self) -> Result<Vec<String>, KeyManagerError> {
        match &self.storage {
            KeyStorage::Memory(map) => {
                let map = map.read().unwrap();
                Ok(map.keys().cloned().collect())
            },
            KeyStorage::File { keys_dir } => {
                let mut actors = Vec::new();

                for entry in fs::read_dir(keys_dir)? {
                    let entry = entry?;
                    let path = entry.path();

                    if path.extension().is_some_and(|ext| ext == "key") {
                        if let Some(stem) = path.file_stem() {
                            actors.push(stem.to_string_lossy().into_owned());
                        }
                    }
                }

                Ok(actors)
            },
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_in_memory_generate() {
        let manager = KeyManager::in_memory();

        let signing_key = manager.generate_keypair("actor-1").unwrap();

        // Should be able to retrieve
        let stored = manager.get_keypair("actor-1").unwrap();
        assert_eq!(stored.actor_id, "actor-1");
        assert_eq!(stored.signing_key().to_bytes(), signing_key.to_bytes());
    }

    #[test]
    fn test_in_memory_duplicate_error() {
        let manager = KeyManager::in_memory();

        manager.generate_keypair("actor-1").unwrap();

        // Duplicate should error
        let result = manager.generate_keypair("actor-1");
        assert!(matches!(
            result,
            Err(KeyManagerError::KeyAlreadyExists { .. })
        ));
    }

    #[test]
    fn test_in_memory_not_found() {
        let manager = KeyManager::in_memory();

        let result = manager.get_keypair("nonexistent");
        assert!(matches!(result, Err(KeyManagerError::KeyNotFound { .. })));
    }

    #[test]
    fn test_in_memory_delete() {
        let manager = KeyManager::in_memory();

        manager.generate_keypair("actor-1").unwrap();
        manager.delete_keypair("actor-1").unwrap();

        let result = manager.get_keypair("actor-1");
        assert!(matches!(result, Err(KeyManagerError::KeyNotFound { .. })));
    }

    #[test]
    fn test_in_memory_list_actors() {
        let manager = KeyManager::in_memory();

        manager.generate_keypair("actor-a").unwrap();
        manager.generate_keypair("actor-b").unwrap();
        manager.generate_keypair("actor-c").unwrap();

        let mut actors = manager.list_actors().unwrap();
        actors.sort();

        assert_eq!(actors, vec!["actor-a", "actor-b", "actor-c"]);
    }

    #[test]
    fn test_file_storage() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path().join("keys")).unwrap();

        let signing_key = manager.generate_keypair("actor-1").unwrap();

        // Should be able to retrieve
        let stored = manager.get_keypair("actor-1").unwrap();
        assert_eq!(stored.actor_id, "actor-1");
        assert_eq!(stored.signing_key().to_bytes(), signing_key.to_bytes());
    }

    #[test]
    fn test_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let keys_dir = temp_dir.path().join("keys");
        let manager = KeyManager::new(&keys_dir).unwrap();

        manager.generate_keypair("actor-1").unwrap();

        // Verify key file permissions
        let key_path = keys_dir.join("actor-1.key");
        let metadata = fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode();

        // Should be 0600 (owner read/write only)
        assert_eq!(mode & 0o777, 0o600, "Key file should have 0600 permissions");
    }

    #[test]
    fn test_file_list_actors() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path().join("keys")).unwrap();

        manager.generate_keypair("actor-a").unwrap();
        manager.generate_keypair("actor-b").unwrap();

        let mut actors = manager.list_actors().unwrap();
        actors.sort();

        assert_eq!(actors, vec!["actor-a", "actor-b"]);
    }

    #[test]
    fn test_file_delete() {
        let temp_dir = TempDir::new().unwrap();
        let keys_dir = temp_dir.path().join("keys");
        let manager = KeyManager::new(&keys_dir).unwrap();

        manager.generate_keypair("actor-1").unwrap();

        let key_path = keys_dir.join("actor-1.key");
        assert!(key_path.exists());

        manager.delete_keypair("actor-1").unwrap();
        assert!(!key_path.exists());
    }

    // ========== Actor ID Validation Tests ==========

    #[test]
    fn test_valid_actor_ids() {
        let manager = KeyManager::in_memory();

        // Valid IDs should work
        assert!(manager.generate_keypair("actor1").is_ok());
        assert!(manager.generate_keypair("actor-2").is_ok());
        assert!(manager.generate_keypair("actor_3").is_ok());
        assert!(manager.generate_keypair("Actor_4").is_ok());
        assert!(manager.generate_keypair("ACTOR-5").is_ok());
        assert!(manager.generate_keypair("a").is_ok());
        assert!(manager.generate_keypair("123").is_ok());
    }

    #[test]
    fn test_path_traversal_rejected() {
        let manager = KeyManager::in_memory();

        // Path traversal attempts should be rejected
        assert!(matches!(
            manager.generate_keypair("../escape"),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
        assert!(matches!(
            manager.generate_keypair(".."),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
        assert!(matches!(
            manager.generate_keypair("foo/bar"),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
        assert!(matches!(
            manager.generate_keypair("foo\\bar"),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
    }

    #[test]
    fn test_invalid_actor_id_characters() {
        let manager = KeyManager::in_memory();

        // Special characters should be rejected
        assert!(matches!(
            manager.generate_keypair("actor.id"),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
        assert!(matches!(
            manager.generate_keypair("actor id"),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
        assert!(matches!(
            manager.generate_keypair("actor@id"),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
        assert!(matches!(
            manager.generate_keypair("actor:id"),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
    }

    #[test]
    fn test_empty_actor_id_rejected() {
        let manager = KeyManager::in_memory();

        assert!(matches!(
            manager.generate_keypair(""),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
    }

    #[test]
    fn test_hyphen_start_rejected() {
        let manager = KeyManager::in_memory();

        // Leading hyphen rejected (could be confused with command flags)
        assert!(matches!(
            manager.generate_keypair("-actor"),
            Err(KeyManagerError::InvalidActorId { .. })
        ));
    }

    #[test]
    fn test_too_long_actor_id_rejected() {
        let manager = KeyManager::in_memory();

        // ID longer than 128 characters should be rejected
        let long_id = "a".repeat(129);
        assert!(matches!(
            manager.generate_keypair(&long_id),
            Err(KeyManagerError::InvalidActorId { .. })
        ));

        // Exactly 128 should work
        let max_id = "a".repeat(128);
        assert!(manager.generate_keypair(&max_id).is_ok());
    }

    #[test]
    fn test_in_memory_store_overwrite_rejected() {
        let manager = KeyManager::in_memory();

        // First store should work
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        manager.store_keypair("actor-1", &signing_key).unwrap();

        // Second store with same ID should fail
        let signing_key2 = SigningKey::generate(&mut rand::thread_rng());
        let result = manager.store_keypair("actor-1", &signing_key2);
        assert!(matches!(
            result,
            Err(KeyManagerError::KeyAlreadyExists { .. })
        ));

        // Original key should be unchanged
        let stored = manager.get_keypair("actor-1").unwrap();
        assert_eq!(stored.signing_key().to_bytes(), signing_key.to_bytes());
    }
}
