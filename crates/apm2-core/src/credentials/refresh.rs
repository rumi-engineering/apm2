#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Token refresh functionality.
//!
//! Handles automatic refresh of OAuth tokens and session tokens before expiry.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for automatic token refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshConfig {
    /// Whether automatic refresh is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Refresh tokens this duration before expiry.
    #[serde(default = "default_refresh_before")]
    #[serde(with = "humantime_serde")]
    pub refresh_before_expiry: Duration,

    /// Maximum number of refresh attempts.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Delay between refresh attempts on failure.
    #[serde(default = "default_retry_delay")]
    #[serde(with = "humantime_serde")]
    pub retry_delay: Duration,

    /// OAuth token endpoint URL (if using OAuth).
    #[serde(default)]
    pub token_endpoint: Option<String>,
}

const fn default_true() -> bool {
    true
}

const fn default_refresh_before() -> Duration {
    Duration::from_secs(5 * 60) // 5 minutes
}

const fn default_max_attempts() -> u32 {
    3
}

const fn default_retry_delay() -> Duration {
    Duration::from_secs(30)
}

impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_before_expiry: default_refresh_before(),
            max_attempts: default_max_attempts(),
            retry_delay: default_retry_delay(),
            token_endpoint: None,
        }
    }
}

/// State of a token refresh operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshState {
    /// No refresh needed.
    NotNeeded,
    /// Refresh is scheduled.
    Scheduled {
        /// When the refresh will occur.
        at: DateTime<Utc>,
    },
    /// Refresh is in progress.
    InProgress {
        /// Attempt number (1-based).
        attempt: u32,
    },
    /// Refresh completed successfully.
    Completed {
        /// New expiration time.
        new_expiry: DateTime<Utc>,
    },
    /// Refresh failed.
    Failed {
        /// Error message.
        error: String,
        /// Number of failed attempts.
        attempts: u32,
    },
}

impl std::fmt::Display for RefreshState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotNeeded => write!(f, "not needed"),
            Self::Scheduled { at } => write!(f, "scheduled for {at}"),
            Self::InProgress { attempt } => write!(f, "in progress (attempt {attempt})"),
            Self::Completed { new_expiry } => write!(f, "completed (expires {new_expiry})"),
            Self::Failed { error, attempts } => {
                write!(f, "failed after {attempts} attempts: {error}")
            },
        }
    }
}

/// Manages token refresh for a credential profile.
#[derive(Debug)]
pub struct RefreshManager {
    /// Refresh configuration.
    config: RefreshConfig,

    /// Current refresh state.
    state: RefreshState,

    /// Last successful refresh time.
    last_refresh: Option<DateTime<Utc>>,

    /// Number of consecutive failures.
    consecutive_failures: u32,
}

impl RefreshManager {
    /// Create a new refresh manager.
    #[must_use]
    pub const fn new(config: RefreshConfig) -> Self {
        Self {
            config,
            state: RefreshState::NotNeeded,
            last_refresh: None,
            consecutive_failures: 0,
        }
    }

    /// Get the current refresh state.
    #[must_use]
    pub const fn state(&self) -> &RefreshState {
        &self.state
    }

    /// Check if a refresh is needed based on expiration time.
    #[must_use]
    pub fn needs_refresh(&self, expires_at: Option<DateTime<Utc>>) -> bool {
        if !self.config.enabled {
            return false;
        }

        let Some(expiry) = expires_at else {
            return false;
        };

        let refresh_at = expiry
            - chrono::Duration::from_std(self.config.refresh_before_expiry)
                .unwrap_or(chrono::Duration::zero());

        Utc::now() >= refresh_at
    }

    /// Schedule a refresh for the given expiration time.
    pub fn schedule(&mut self, expires_at: DateTime<Utc>) {
        let refresh_at = expires_at
            - chrono::Duration::from_std(self.config.refresh_before_expiry)
                .unwrap_or(chrono::Duration::zero());

        self.state = RefreshState::Scheduled { at: refresh_at };
    }

    /// Begin a refresh attempt.
    pub fn begin_refresh(&mut self) {
        let attempt = match &self.state {
            RefreshState::InProgress { attempt } => attempt + 1,
            RefreshState::Failed { attempts, .. } => attempts + 1,
            _ => 1,
        };

        self.state = RefreshState::InProgress { attempt };
    }

    /// Mark the refresh as completed.
    pub fn complete(&mut self, new_expiry: DateTime<Utc>) {
        self.state = RefreshState::Completed { new_expiry };
        self.last_refresh = Some(Utc::now());
        self.consecutive_failures = 0;
    }

    /// Mark the refresh as failed.
    pub fn fail(&mut self, error: String) {
        let attempts = match &self.state {
            RefreshState::InProgress { attempt } => *attempt,
            RefreshState::Failed { attempts, .. } => *attempts,
            _ => 1,
        };

        self.consecutive_failures += 1;
        self.state = RefreshState::Failed { error, attempts };
    }

    /// Check if more refresh attempts are allowed.
    #[must_use]
    pub const fn can_retry(&self) -> bool {
        match &self.state {
            RefreshState::Failed { attempts, .. } => *attempts < self.config.max_attempts,
            _ => true,
        }
    }

    /// Get the delay before the next retry.
    #[must_use]
    pub const fn retry_delay(&self) -> Duration {
        self.config.retry_delay
    }

    /// Reset the manager state.
    pub fn reset(&mut self) {
        self.state = RefreshState::NotNeeded;
        self.consecutive_failures = 0;
    }

    /// Get the last successful refresh time.
    #[must_use]
    pub const fn last_refresh(&self) -> Option<DateTime<Utc>> {
        self.last_refresh
    }
}

/// Token refresh errors.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// No refresh token available.
    #[error("no refresh token available")]
    NoRefreshToken,

    /// Token endpoint not configured.
    #[error("token endpoint not configured")]
    NoTokenEndpoint,

    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    HttpFailed(String),

    /// Invalid response from token endpoint.
    #[error("invalid token response: {0}")]
    InvalidResponse(String),

    /// Max retries exceeded.
    #[error("max refresh attempts exceeded")]
    MaxRetriesExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_refresh() {
        let config = RefreshConfig {
            enabled: true,
            refresh_before_expiry: Duration::from_secs(300), // 5 minutes
            ..Default::default()
        };
        let manager = RefreshManager::new(config);

        // Token expiring in 1 minute - needs refresh
        let soon = Utc::now() + chrono::Duration::minutes(1);
        assert!(manager.needs_refresh(Some(soon)));

        // Token expiring in 10 minutes - doesn't need refresh yet
        let later = Utc::now() + chrono::Duration::minutes(10);
        assert!(!manager.needs_refresh(Some(later)));

        // No expiration - doesn't need refresh
        assert!(!manager.needs_refresh(None));
    }

    #[test]
    fn test_refresh_state_machine() {
        let mut manager = RefreshManager::new(RefreshConfig::default());

        assert_eq!(*manager.state(), RefreshState::NotNeeded);

        let expiry = Utc::now() + chrono::Duration::hours(1);
        manager.schedule(expiry);
        assert!(matches!(manager.state(), RefreshState::Scheduled { .. }));

        manager.begin_refresh();
        assert!(matches!(
            manager.state(),
            RefreshState::InProgress { attempt: 1 }
        ));

        let new_expiry = Utc::now() + chrono::Duration::hours(2);
        manager.complete(new_expiry);
        assert!(matches!(manager.state(), RefreshState::Completed { .. }));
    }

    #[test]
    fn test_retry_logic() {
        let config = RefreshConfig {
            max_attempts: 3,
            ..Default::default()
        };
        let mut manager = RefreshManager::new(config);

        manager.begin_refresh();
        manager.fail("error 1".to_string());
        assert!(manager.can_retry());

        manager.begin_refresh();
        manager.fail("error 2".to_string());
        assert!(manager.can_retry());

        manager.begin_refresh();
        manager.fail("error 3".to_string());
        assert!(!manager.can_retry());
    }
}

mod humantime_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&humantime::format_duration(*duration).to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}
