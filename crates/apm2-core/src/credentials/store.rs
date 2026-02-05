//! Secure credential storage using OS keyring.
//!
//! Secrets are stored in the OS keyring. A secondary JSON index file persists
//! profile metadata (IDs, provider, label, timestamps) so that `list()` can
//! enumerate credentials after a daemon restart without requiring the keyring
//! to support enumeration.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::profile::{AuthMethod, CredentialProfile, ProfileId, Provider};

/// Default filename for the credential index.
const INDEX_FILENAME: &str = "credential_index.json";

/// A single entry in the on-disk credential index (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexEntry {
    /// Profile ID.
    profile_id: String,
    /// Provider name.
    provider: String,
    /// Human-readable label.
    label: Option<String>,
    /// Auth method type string (e.g. `api_key`, `oauth`, `session_token`).
    auth_method: String,
    /// ISO-8601 creation timestamp.
    created_at: String,
    /// ISO-8601 last-updated timestamp.
    updated_at: String,
}

/// Credential store backed by OS keyring.
pub struct CredentialStore {
    /// Service name for keyring entries.
    service_name: String,

    /// In-memory cache of profiles (metadata only, secrets stay in keyring).
    cache: RwLock<HashMap<ProfileId, CredentialProfile>>,

    /// Path to the on-disk credential index file.
    index_path: Option<PathBuf>,
}

impl CredentialStore {
    /// Create a new credential store.
    ///
    /// On construction the store attempts to load a persisted index from
    /// `$XDG_DATA_HOME/apm2/credential_index.json` (or the platform equivalent)
    /// so that `list()` returns previously stored profiles even after a daemon
    /// restart.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        let service_name = service_name.into();
        let index_path = Self::default_index_path();
        let cache = Self::load_index(&service_name, index_path.as_deref());
        Self {
            service_name,
            cache: RwLock::new(cache),
            index_path,
        }
    }

    /// Create a credential store with an explicit index path (useful for
    /// testing).
    #[must_use]
    pub fn with_index_path(
        service_name: impl Into<String>,
        index_path: impl Into<PathBuf>,
    ) -> Self {
        let service_name = service_name.into();
        let index_path = Some(index_path.into());
        let cache = Self::load_index(&service_name, index_path.as_deref());
        Self {
            service_name,
            cache: RwLock::new(cache),
            index_path,
        }
    }

    /// Returns the default index file path using XDG data directory
    /// conventions.
    fn default_index_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("com", "apm2", "apm2")
            .map(|dirs| dirs.data_dir().join(INDEX_FILENAME))
    }

    /// Load the credential index from disk and reconstruct in-memory cache
    /// entries by fetching each profile's secret from the keyring.
    fn load_index(
        service_name: &str,
        index_path: Option<&std::path::Path>,
    ) -> HashMap<ProfileId, CredentialProfile> {
        let mut cache = HashMap::new();

        let path = match index_path {
            Some(p) if p.exists() => p,
            _ => return cache,
        };

        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read credential index");
                return cache;
            },
        };

        let entries: Vec<IndexEntry> = match serde_json::from_str(&data) {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to parse credential index; starting with empty cache"
                );
                return cache;
            },
        };

        for entry in entries {
            let profile_id = ProfileId::new(&entry.profile_id);

            // Try to load the secret from the keyring to fully reconstruct the
            // profile.  If the keyring entry is missing (e.g. user manually
            // deleted it), we skip that profile and will prune it from the
            // index on the next write.
            let Ok(secret_data) =
                keyring::Entry::new(service_name, &entry.profile_id).and_then(|e| e.get_password())
            else {
                warn!(
                    profile_id = %entry.profile_id,
                    "keyring entry missing; skipping profile"
                );
                continue;
            };

            let auth = match Self::deserialize_auth(&secret_data) {
                Ok(auth) => auth,
                Err(e) => {
                    warn!(
                        profile_id = %entry.profile_id,
                        error = %e,
                        "failed to deserialize keyring secret; skipping profile"
                    );
                    continue;
                },
            };

            let provider: Provider = entry.provider.parse().unwrap_or(Provider::Custom);

            let mut profile = CredentialProfile::new(profile_id.clone(), provider, auth);
            profile.label.clone_from(&entry.label);

            // Restore timestamps from the index.
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&entry.created_at) {
                profile.created_at = dt.with_timezone(&chrono::Utc);
            }
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&entry.updated_at) {
                profile.updated_at = dt.with_timezone(&chrono::Utc);
            }

            cache.insert(profile_id, profile);
        }

        cache
    }

    /// Persist the current cache to the index file.
    fn persist_index(&self, cache: &HashMap<ProfileId, CredentialProfile>) {
        let Some(path) = &self.index_path else {
            return;
        };

        let entries: Vec<IndexEntry> = cache
            .values()
            .map(|p| IndexEntry {
                profile_id: p.id.as_str().to_string(),
                provider: p.provider.to_string(),
                label: p.label.clone(),
                auth_method: p.auth.method_type().to_string(),
                created_at: p.created_at.to_rfc3339(),
                updated_at: p.updated_at.to_rfc3339(),
            })
            .collect();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(
                    path = %parent.display(),
                    error = %e,
                    "failed to create credential index directory"
                );
                return;
            }
        }

        match serde_json::to_string_pretty(&entries) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to write credential index"
                    );
                }
            },
            Err(e) => {
                warn!(error = %e, "failed to serialize credential index");
            },
        }
    }

    /// Get the keyring entry for a profile.
    fn keyring_entry(&self, profile_id: &ProfileId) -> keyring::Result<keyring::Entry> {
        keyring::Entry::new(&self.service_name, profile_id.as_str())
    }

    /// Store a credential profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be stored in the keyring.
    pub fn store(&self, profile: CredentialProfile) -> Result<(), CredentialStoreError> {
        // Serialize the secret part of the credentials
        let secret_data = Self::serialize_auth(&profile.auth)?;

        // Store in OS keyring
        let entry = self
            .keyring_entry(&profile.id)
            .map_err(|e| CredentialStoreError::Keyring(e.to_string()))?;

        entry
            .set_password(&secret_data)
            .map_err(|e| CredentialStoreError::Keyring(e.to_string()))?;

        // Update cache and persist index
        let mut cache = self
            .cache
            .write()
            .map_err(|_| CredentialStoreError::LockPoisoned)?;
        cache.insert(profile.id.clone(), profile);
        self.persist_index(&cache);

        Ok(())
    }

    /// Retrieve a credential profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile is not found or cannot be retrieved.
    pub fn get(&self, profile_id: &ProfileId) -> Result<CredentialProfile, CredentialStoreError> {
        // Check cache first
        {
            let cache = self
                .cache
                .read()
                .map_err(|_| CredentialStoreError::LockPoisoned)?;
            if let Some(profile) = cache.get(profile_id) {
                return Ok(profile.clone());
            }
        }

        // Try to load from keyring
        let entry = self
            .keyring_entry(profile_id)
            .map_err(|e| CredentialStoreError::Keyring(e.to_string()))?;

        let secret_data = entry
            .get_password()
            .map_err(|_e| CredentialStoreError::NotFound(profile_id.to_string()))?;

        // Deserialize and reconstruct profile
        let auth = Self::deserialize_auth(&secret_data)?;

        // For now, we reconstruct a minimal profile
        // In a full implementation, we'd store metadata separately
        let profile = CredentialProfile::new(profile_id.clone(), Provider::Custom, auth);

        // Update cache
        let mut cache = self
            .cache
            .write()
            .map_err(|_| CredentialStoreError::LockPoisoned)?;
        cache.insert(profile_id.clone(), profile.clone());

        Ok(profile)
    }

    /// Remove a credential profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be removed.
    pub fn remove(&self, profile_id: &ProfileId) -> Result<(), CredentialStoreError> {
        // Remove from keyring
        let entry = self
            .keyring_entry(profile_id)
            .map_err(|e| CredentialStoreError::Keyring(e.to_string()))?;

        entry
            .delete_credential()
            .map_err(|e| CredentialStoreError::Keyring(e.to_string()))?;

        // Remove from cache and persist index
        let mut cache = self
            .cache
            .write()
            .map_err(|_| CredentialStoreError::LockPoisoned)?;
        cache.remove(profile_id);
        self.persist_index(&cache);

        Ok(())
    }

    /// List all stored profile IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache cannot be read.
    pub fn list(&self) -> Result<Vec<ProfileId>, CredentialStoreError> {
        let cache = self
            .cache
            .read()
            .map_err(|_| CredentialStoreError::LockPoisoned)?;
        Ok(cache.keys().cloned().collect())
    }

    /// Check if a profile exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache cannot be read.
    pub fn exists(&self, profile_id: &ProfileId) -> Result<bool, CredentialStoreError> {
        let cache = self
            .cache
            .read()
            .map_err(|_| CredentialStoreError::LockPoisoned)?;
        Ok(cache.contains_key(profile_id))
    }

    /// Serialize authentication data to JSON.
    fn serialize_auth(auth: &AuthMethod) -> Result<String, CredentialStoreError> {
        // Simple JSON serialization for now
        // In production, consider encryption at rest
        use secrecy::ExposeSecret;

        let json = match auth {
            AuthMethod::OAuth {
                access_token,
                refresh_token,
                expires_at,
                scopes,
            } => {
                serde_json::json!({
                    "type": "oauth",
                    "access_token": access_token.expose_secret(),
                    "refresh_token": refresh_token.as_ref().map(secrecy::ExposeSecret::expose_secret),
                    "expires_at": expires_at,
                    "scopes": scopes,
                })
            },
            AuthMethod::SessionToken {
                token,
                cookie_jar,
                expires_at,
            } => {
                serde_json::json!({
                    "type": "session_token",
                    "token": token.expose_secret(),
                    "cookie_jar": cookie_jar,
                    "expires_at": expires_at,
                })
            },
            AuthMethod::ApiKey { key } => {
                serde_json::json!({
                    "type": "api_key",
                    "key": key.expose_secret(),
                })
            },
        };

        serde_json::to_string(&json).map_err(|e| CredentialStoreError::Serialization(e.to_string()))
    }

    /// Deserialize authentication data from JSON.
    fn deserialize_auth(data: &str) -> Result<AuthMethod, CredentialStoreError> {
        let json: serde_json::Value = serde_json::from_str(data)
            .map_err(|e| CredentialStoreError::Serialization(e.to_string()))?;

        let auth_type = json["type"]
            .as_str()
            .ok_or_else(|| CredentialStoreError::Serialization("missing type field".to_string()))?;

        match auth_type {
            "oauth" => {
                let access_token = json["access_token"].as_str().ok_or_else(|| {
                    CredentialStoreError::Serialization("missing access_token".to_string())
                })?;
                let refresh_token = json["refresh_token"]
                    .as_str()
                    .map(|s| SecretString::from(s.to_string()));
                let expires_at = json["expires_at"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc));
                let scopes = json["scopes"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(AuthMethod::OAuth {
                    access_token: SecretString::from(access_token.to_string()),
                    refresh_token,
                    expires_at,
                    scopes,
                })
            },
            "session_token" => {
                let token = json["token"].as_str().ok_or_else(|| {
                    CredentialStoreError::Serialization("missing token".to_string())
                })?;
                let cookie_jar = json["cookie_jar"].as_str().map(std::path::PathBuf::from);
                let expires_at = json["expires_at"]
                    .as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc));

                Ok(AuthMethod::SessionToken {
                    token: SecretString::from(token.to_string()),
                    cookie_jar,
                    expires_at,
                })
            },
            "api_key" => {
                let key = json["key"].as_str().ok_or_else(|| {
                    CredentialStoreError::Serialization("missing key".to_string())
                })?;

                Ok(AuthMethod::ApiKey {
                    key: SecretString::from(key.to_string()),
                })
            },
            _ => Err(CredentialStoreError::Serialization(format!(
                "unknown auth type: {auth_type}"
            ))),
        }
    }
}

/// Errors from the credential store.
#[derive(Debug, thiserror::Error)]
pub enum CredentialStoreError {
    /// Profile not found.
    #[error("credential profile not found: {0}")]
    NotFound(String),

    /// Keyring error.
    #[error("keyring error: {0}")]
    Keyring(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Lock poisoned.
    #[error("internal lock poisoned")]
    LockPoisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Keyring tests require a running secrets service
    // These tests use mock data and don't interact with the real keyring

    #[test]
    fn test_serialize_api_key() {
        let auth = AuthMethod::ApiKey {
            key: SecretString::from("test-key".to_string()),
        };

        let serialized = CredentialStore::serialize_auth(&auth).unwrap();
        assert!(serialized.contains("api_key"));
        assert!(serialized.contains("test-key"));
    }

    #[test]
    fn test_roundtrip_api_key() {
        let auth = AuthMethod::ApiKey {
            key: SecretString::from("test-key-123".to_string()),
        };

        let serialized = CredentialStore::serialize_auth(&auth).unwrap();
        let deserialized = CredentialStore::deserialize_auth(&serialized).unwrap();

        match deserialized {
            AuthMethod::ApiKey { key } => {
                use secrecy::ExposeSecret;
                assert_eq!(key.expose_secret(), "test-key-123");
            },
            _ => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn test_index_entry_roundtrip() {
        let entries = vec![
            IndexEntry {
                profile_id: "test-profile".to_string(),
                provider: "claude".to_string(),
                label: Some("My Claude Key".to_string()),
                auth_method: "api_key".to_string(),
                created_at: "2025-01-01T00:00:00+00:00".to_string(),
                updated_at: "2025-01-01T00:00:00+00:00".to_string(),
            },
            IndexEntry {
                profile_id: "openai-prod".to_string(),
                provider: "openai".to_string(),
                label: None,
                auth_method: "oauth".to_string(),
                created_at: "2025-06-15T12:30:00+00:00".to_string(),
                updated_at: "2025-06-15T12:30:00+00:00".to_string(),
            },
        ];

        let json = serde_json::to_string_pretty(&entries).unwrap();
        let parsed: Vec<IndexEntry> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].profile_id, "test-profile");
        assert_eq!(parsed[0].provider, "claude");
        assert_eq!(parsed[0].label.as_deref(), Some("My Claude Key"));
        assert_eq!(parsed[1].profile_id, "openai-prod");
        assert!(parsed[1].label.is_none());
    }

    #[test]
    fn test_persist_and_load_index() {
        let dir = tempfile::tempdir().unwrap();
        let index_path = dir.path().join("credential_index.json");

        // Write an index to disk
        let entries = vec![IndexEntry {
            profile_id: "my-key".to_string(),
            provider: "custom".to_string(),
            label: Some("Test".to_string()),
            auth_method: "api_key".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        }];
        let json = serde_json::to_string_pretty(&entries).unwrap();
        std::fs::write(&index_path, &json).unwrap();

        // load_index will try to fetch from keyring and skip entries where the
        // keyring entry is missing. In test environments without a secrets
        // service the cache will be empty, which is correct -- the test
        // verifies that the index file is read without panicking.
        let cache = CredentialStore::load_index("test-service", Some(&index_path));
        // The profile will be skipped because we have no keyring in tests.
        // This is the expected behaviour: stale index entries are pruned.
        assert!(
            cache.is_empty(),
            "cache should be empty when keyring is unavailable"
        );
    }

    #[test]
    fn test_load_index_missing_file() {
        let cache = CredentialStore::load_index(
            "test-service",
            Some(std::path::Path::new("/nonexistent/path.json")),
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn test_load_index_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let index_path = dir.path().join("credential_index.json");
        std::fs::write(&index_path, "NOT VALID JSON").unwrap();

        let cache = CredentialStore::load_index("test-service", Some(&index_path));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_load_index_no_path() {
        let cache = CredentialStore::load_index("test-service", None);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_persist_index_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested_path = dir
            .path()
            .join("sub")
            .join("dir")
            .join("credential_index.json");

        let store = CredentialStore {
            service_name: "test".to_string(),
            cache: RwLock::new(HashMap::new()),
            index_path: Some(nested_path.clone()),
        };

        let cache = HashMap::new();
        store.persist_index(&cache);

        // The file should exist (even if empty array)
        assert!(nested_path.exists());
        let contents = std::fs::read_to_string(&nested_path).unwrap();
        let parsed: Vec<IndexEntry> = serde_json::from_str(&contents).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_persist_index_with_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let index_path = dir.path().join("credential_index.json");

        let store = CredentialStore {
            service_name: "test".to_string(),
            cache: RwLock::new(HashMap::new()),
            index_path: Some(index_path.clone()),
        };

        let mut cache = HashMap::new();
        let profile = CredentialProfile::new(
            ProfileId::new("test-id"),
            Provider::Claude,
            AuthMethod::ApiKey {
                key: SecretString::from("secret".to_string()),
            },
        )
        .with_label("My Key");
        cache.insert(ProfileId::new("test-id"), profile);

        store.persist_index(&cache);

        let contents = std::fs::read_to_string(&index_path).unwrap();
        let parsed: Vec<IndexEntry> = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].profile_id, "test-id");
        assert_eq!(parsed[0].provider, "claude");
        assert_eq!(parsed[0].label.as_deref(), Some("My Key"));
        assert_eq!(parsed[0].auth_method, "api_key");

        // Verify that no secrets leaked into the index
        assert!(!contents.contains("secret"));
    }
}
