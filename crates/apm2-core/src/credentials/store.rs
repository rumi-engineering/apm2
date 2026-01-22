//! Secure credential storage using OS keyring.

use std::collections::HashMap;
use std::sync::RwLock;

use secrecy::SecretString;

use super::profile::{AuthMethod, CredentialProfile, ProfileId, Provider};

/// Credential store backed by OS keyring.
pub struct CredentialStore {
    /// Service name for keyring entries.
    service_name: String,

    /// In-memory cache of profiles (metadata only, secrets stay in keyring).
    cache: RwLock<HashMap<ProfileId, CredentialProfile>>,
}

impl CredentialStore {
    /// Create a new credential store.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            cache: RwLock::new(HashMap::new()),
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

        // Update cache
        let mut cache = self
            .cache
            .write()
            .map_err(|_| CredentialStoreError::LockPoisoned)?;
        cache.insert(profile.id.clone(), profile);

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

        // Remove from cache
        let mut cache = self
            .cache
            .write()
            .map_err(|_| CredentialStoreError::LockPoisoned)?;
        cache.remove(profile_id);

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
}
