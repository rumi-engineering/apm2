//! Credential profile definitions.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Unique identifier for a credential profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId(String);

impl ProfileId {
    /// Create a new profile ID from a string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID as a string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ProfileId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ProfileId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// AI provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// Anthropic Claude.
    Claude,
    /// Google Gemini.
    Gemini,
    /// `OpenAI` (GPT, Codex).
    OpenAI,
    /// Custom/other provider.
    Custom,
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Claude => write!(f, "claude"),
            Self::Gemini => write!(f, "gemini"),
            Self::OpenAI => write!(f, "openai"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for Provider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "claude" | "anthropic" => Ok(Self::Claude),
            "gemini" | "google" => Ok(Self::Gemini),
            "openai" | "gpt" | "codex" => Ok(Self::OpenAI),
            "custom" | "other" => Ok(Self::Custom),
            _ => Err(format!("unknown provider: {s}")),
        }
    }
}

/// Authentication method and credentials.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// OAuth 2.0 authentication.
    OAuth {
        /// Access token.
        access_token: SecretString,
        /// Refresh token (if available).
        refresh_token: Option<SecretString>,
        /// Token expiration time.
        expires_at: Option<DateTime<Utc>>,
        /// OAuth scopes.
        scopes: Vec<String>,
    },

    /// Session token authentication (e.g., Claude Code).
    SessionToken {
        /// Session token value.
        token: SecretString,
        /// Path to cookie jar file (if browser-based).
        cookie_jar: Option<PathBuf>,
        /// Session expiration time.
        expires_at: Option<DateTime<Utc>>,
    },

    /// API key authentication.
    ApiKey {
        /// API key value.
        key: SecretString,
    },
}

impl AuthMethod {
    /// Check if credentials are expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let expires_at = match self {
            Self::OAuth { expires_at, .. } | Self::SessionToken { expires_at, .. } => *expires_at,
            Self::ApiKey { .. } => return false,
        };

        expires_at.is_some_and(|exp| Utc::now() >= exp)
    }

    /// Check if credentials will expire within the given duration.
    #[must_use]
    pub fn expires_within(&self, duration: chrono::Duration) -> bool {
        let expires_at = match self {
            Self::OAuth { expires_at, .. } | Self::SessionToken { expires_at, .. } => *expires_at,
            Self::ApiKey { .. } => return false,
        };

        expires_at.is_some_and(|exp| Utc::now() + duration >= exp)
    }

    /// Get the auth method type as a string.
    #[must_use]
    pub const fn method_type(&self) -> &'static str {
        match self {
            Self::OAuth { .. } => "oauth",
            Self::SessionToken { .. } => "session_token",
            Self::ApiKey { .. } => "api_key",
        }
    }
}

/// Complete credential profile.
#[derive(Debug, Clone)]
pub struct CredentialProfile {
    /// Unique identifier.
    pub id: ProfileId,

    /// AI provider.
    pub provider: Provider,

    /// Human-readable label.
    pub label: Option<String>,

    /// Authentication method and credentials.
    pub auth: AuthMethod,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last modification timestamp.
    pub updated_at: DateTime<Utc>,

    /// Last used timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl CredentialProfile {
    /// Create a new credential profile.
    #[must_use]
    pub fn new(id: impl Into<ProfileId>, provider: Provider, auth: AuthMethod) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            provider,
            label: None,
            auth,
            created_at: now,
            updated_at: now,
            last_used_at: None,
        }
    }

    /// Set a human-readable label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Check if credentials are expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.auth.is_expired()
    }

    /// Mark the profile as recently used.
    pub fn mark_used(&mut self) {
        self.last_used_at = Some(Utc::now());
    }
}

/// Serializable representation of a credential profile (without secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProfileMetadata {
    /// Profile ID.
    pub id: String,
    /// Provider name.
    pub provider: String,
    /// Human-readable label.
    pub label: Option<String>,
    /// Auth method type.
    pub auth_method: String,
    /// Expiration time (if applicable).
    pub expires_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last used timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<&CredentialProfile> for CredentialProfileMetadata {
    fn from(profile: &CredentialProfile) -> Self {
        let expires_at = match &profile.auth {
            AuthMethod::OAuth { expires_at, .. } | AuthMethod::SessionToken { expires_at, .. } => {
                *expires_at
            },
            AuthMethod::ApiKey { .. } => None,
        };

        Self {
            id: profile.id.as_str().to_string(),
            provider: profile.provider.to_string(),
            label: profile.label.clone(),
            auth_method: profile.auth.method_type().to_string(),
            expires_at,
            created_at: profile.created_at,
            last_used_at: profile.last_used_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_from_str() {
        assert_eq!("claude".parse::<Provider>().unwrap(), Provider::Claude);
        assert_eq!("anthropic".parse::<Provider>().unwrap(), Provider::Claude);
        assert_eq!("gemini".parse::<Provider>().unwrap(), Provider::Gemini);
        assert_eq!("openai".parse::<Provider>().unwrap(), Provider::OpenAI);
    }

    #[test]
    fn test_auth_method_expiry() {
        let expired = AuthMethod::OAuth {
            access_token: SecretString::from("token".to_string()),
            refresh_token: None,
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            scopes: vec![],
        };
        assert!(expired.is_expired());

        let valid = AuthMethod::ApiKey {
            key: SecretString::from("key".to_string()),
        };
        assert!(!valid.is_expired());
    }
}
