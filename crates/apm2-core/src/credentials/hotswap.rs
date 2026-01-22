//! Credential hot-swapping functionality.
//!
//! NOTE: This module contains scaffolding for future credential hot-swap
//! support. Currently unused pending research into CLI-specific credential
//! rotation mechanisms.

#![allow(dead_code)] // Scaffolding for future hot-swap feature

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for hot-swapping credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotSwapConfig {
    /// Signal to send to notify the process of credential change.
    #[serde(default = "default_signal")]
    pub signal: String,

    /// Whether to re-inject environment variables.
    #[serde(default = "default_true")]
    pub env_injection: bool,

    /// Path to config file to update.
    #[serde(default)]
    pub config_file_path: Option<PathBuf>,

    /// Duration to wait for the process to drain current requests.
    #[serde(default = "default_graceful_drain")]
    #[serde(with = "humantime_serde")]
    pub graceful_drain: Duration,

    /// Whether to validate credentials before applying.
    #[serde(default = "default_true")]
    pub validate_before_swap: bool,

    /// Rollback to previous credentials on failure.
    #[serde(default = "default_true")]
    pub rollback_on_failure: bool,
}

fn default_signal() -> String {
    "SIGHUP".to_string()
}

const fn default_true() -> bool {
    true
}

const fn default_graceful_drain() -> Duration {
    Duration::from_secs(5)
}

impl Default for HotSwapConfig {
    fn default() -> Self {
        Self {
            signal: default_signal(),
            env_injection: true,
            config_file_path: None,
            graceful_drain: default_graceful_drain(),
            validate_before_swap: true,
            rollback_on_failure: true,
        }
    }
}

/// Hot-swap operation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotSwapState {
    /// Idle, no swap in progress.
    Idle,
    /// Validating new credentials.
    Validating,
    /// Draining current requests.
    Draining,
    /// Applying new credentials.
    Applying,
    /// Swap completed successfully.
    Completed,
    /// Swap failed, rolling back.
    RollingBack,
    /// Swap failed.
    Failed(String),
}

impl std::fmt::Display for HotSwapState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Validating => write!(f, "validating"),
            Self::Draining => write!(f, "draining"),
            Self::Applying => write!(f, "applying"),
            Self::Completed => write!(f, "completed"),
            Self::RollingBack => write!(f, "rolling_back"),
            Self::Failed(reason) => write!(f, "failed: {reason}"),
        }
    }
}

/// Manages hot-swap operations for a process.
#[derive(Debug)]
pub struct HotSwapManager {
    /// Configuration for hot-swap operations.
    config: HotSwapConfig,

    /// Current state of the hot-swap operation.
    state: HotSwapState,

    /// Previous credential profile ID (for rollback).
    previous_profile: Option<String>,
}

impl HotSwapManager {
    /// Create a new hot-swap manager.
    #[must_use]
    pub const fn new(config: HotSwapConfig) -> Self {
        Self {
            config,
            state: HotSwapState::Idle,
            previous_profile: None,
        }
    }

    /// Get the current hot-swap state.
    #[must_use]
    pub const fn state(&self) -> &HotSwapState {
        &self.state
    }

    /// Check if a hot-swap is in progress.
    #[must_use]
    pub const fn is_in_progress(&self) -> bool {
        !matches!(
            self.state,
            HotSwapState::Idle | HotSwapState::Completed | HotSwapState::Failed(_)
        )
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &HotSwapConfig {
        &self.config
    }

    /// Start a hot-swap operation.
    ///
    /// # Errors
    ///
    /// Returns an error if a swap is already in progress.
    pub fn start_swap(&mut self, current_profile: String) -> Result<(), HotSwapError> {
        if self.is_in_progress() {
            return Err(HotSwapError::AlreadyInProgress);
        }

        self.previous_profile = Some(current_profile);
        self.state = HotSwapState::Validating;
        Ok(())
    }

    /// Advance to the draining state.
    pub fn begin_drain(&mut self) {
        if self.state == HotSwapState::Validating {
            self.state = HotSwapState::Draining;
        }
    }

    /// Advance to the applying state.
    pub fn begin_apply(&mut self) {
        if self.state == HotSwapState::Draining {
            self.state = HotSwapState::Applying;
        }
    }

    /// Mark the swap as completed.
    pub fn complete(&mut self) {
        self.state = HotSwapState::Completed;
        self.previous_profile = None;
    }

    /// Mark the swap as failed and begin rollback if configured.
    pub fn fail(&mut self, reason: String) {
        if self.config.rollback_on_failure && self.previous_profile.is_some() {
            self.state = HotSwapState::RollingBack;
        } else {
            self.state = HotSwapState::Failed(reason);
        }
    }

    /// Complete the rollback.
    pub fn complete_rollback(&mut self, success: bool) {
        if success {
            self.state = HotSwapState::Idle;
        } else {
            self.state = HotSwapState::Failed("rollback failed".to_string());
        }
        self.previous_profile = None;
    }

    /// Reset the manager to idle state.
    pub fn reset(&mut self) {
        self.state = HotSwapState::Idle;
        self.previous_profile = None;
    }

    /// Get the previous profile ID (for rollback).
    #[must_use]
    pub fn previous_profile(&self) -> Option<&str> {
        self.previous_profile.as_deref()
    }
}

/// Hot-swap errors.
#[derive(Debug, thiserror::Error)]
pub enum HotSwapError {
    /// A hot-swap is already in progress.
    #[error("hot-swap already in progress")]
    AlreadyInProgress,

    /// No hot-swap in progress to complete.
    #[error("no hot-swap in progress")]
    NotInProgress,

    /// Signal delivery failed.
    #[error("failed to send signal: {0}")]
    SignalFailed(String),

    /// Config file update failed.
    #[error("failed to update config file: {0}")]
    ConfigUpdateFailed(String),

    /// Credential validation failed.
    #[error("credential validation failed: {0}")]
    ValidationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_swap_state_machine() {
        let mut manager = HotSwapManager::new(HotSwapConfig::default());

        assert!(!manager.is_in_progress());
        assert_eq!(*manager.state(), HotSwapState::Idle);

        manager.start_swap("old-profile".to_string()).unwrap();
        assert!(manager.is_in_progress());
        assert_eq!(*manager.state(), HotSwapState::Validating);

        manager.begin_drain();
        assert_eq!(*manager.state(), HotSwapState::Draining);

        manager.begin_apply();
        assert_eq!(*manager.state(), HotSwapState::Applying);

        manager.complete();
        assert!(!manager.is_in_progress());
        assert_eq!(*manager.state(), HotSwapState::Completed);
    }

    #[test]
    fn test_hot_swap_prevents_concurrent() {
        let mut manager = HotSwapManager::new(HotSwapConfig::default());

        manager.start_swap("profile-1".to_string()).unwrap();
        let result = manager.start_swap("profile-2".to_string());

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HotSwapError::AlreadyInProgress
        ));
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
