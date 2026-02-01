#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Restart policy module.
//!
//! Defines restart behavior including backoff strategies and circuit breakers.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Restart configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartConfig {
    /// Maximum number of restarts within the restart window.
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,

    /// Time window for counting restarts.
    #[serde(default = "default_restart_window")]
    #[serde(with = "humantime_serde")]
    pub restart_window: Duration,

    /// Minimum uptime before a restart is considered successful.
    #[serde(default = "default_min_uptime")]
    #[serde(with = "humantime_serde")]
    pub min_uptime: Duration,

    /// Backoff configuration.
    #[serde(default)]
    pub backoff: BackoffConfig,

    /// Whether to restart on successful exit (exit code 0).
    #[serde(default)]
    pub restart_on_success: bool,
}

const fn default_max_restarts() -> u32 {
    5
}

const fn default_restart_window() -> Duration {
    Duration::from_secs(60)
}

const fn default_min_uptime() -> Duration {
    Duration::from_secs(30)
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: default_max_restarts(),
            restart_window: default_restart_window(),
            min_uptime: default_min_uptime(),
            backoff: BackoffConfig::default(),
            restart_on_success: false,
        }
    }
}

/// Backoff configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackoffConfig {
    /// Fixed delay between restarts.
    Fixed {
        /// Delay duration.
        #[serde(with = "humantime_serde")]
        delay: Duration,
    },

    /// Exponential backoff.
    Exponential {
        /// Initial delay.
        #[serde(with = "humantime_serde")]
        initial_delay: Duration,

        /// Maximum delay.
        #[serde(with = "humantime_serde")]
        max_delay: Duration,

        /// Multiplier for each retry (default: 2.0).
        #[serde(default = "default_multiplier")]
        multiplier: f64,
    },

    /// Linear backoff.
    Linear {
        /// Initial delay.
        #[serde(with = "humantime_serde")]
        initial_delay: Duration,

        /// Increment per retry.
        #[serde(with = "humantime_serde")]
        increment: Duration,

        /// Maximum delay.
        #[serde(with = "humantime_serde")]
        max_delay: Duration,
    },
}

const fn default_multiplier() -> f64 {
    2.0
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self::Exponential {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(300),
            multiplier: 2.0,
        }
    }
}

impl BackoffConfig {
    /// Calculate the delay for a given attempt number (1-based).
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        match self {
            Self::Fixed { delay } => *delay,
            Self::Exponential {
                initial_delay,
                max_delay,
                multiplier,
            } => {
                #[allow(clippy::cast_possible_wrap)] // attempt count won't exceed i32
                let delay_secs =
                    initial_delay.as_secs_f64() * multiplier.powi((attempt - 1) as i32);
                let delay = Duration::from_secs_f64(delay_secs);
                delay.min(*max_delay)
            },
            Self::Linear {
                initial_delay,
                increment,
                max_delay,
            } => {
                let delay = *initial_delay + *increment * (attempt - 1);
                delay.min(*max_delay)
            },
        }
    }
}

/// Restart history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartEntry {
    /// Time of the restart.
    pub timestamp: DateTime<Utc>,

    /// Exit code of the previous run (if available).
    pub exit_code: Option<i32>,

    /// Uptime of the previous run.
    pub uptime: Duration,

    /// Restart delay applied.
    pub delay: Duration,
}

/// Manages restart decisions and history.
#[derive(Debug)]
pub struct RestartManager {
    /// Restart configuration.
    config: RestartConfig,

    /// Restart history (within the restart window).
    history: Vec<RestartEntry>,

    /// Current backoff attempt counter.
    backoff_attempt: u32,

    /// Whether the circuit breaker is open (preventing restarts).
    circuit_open: bool,

    /// Time when the circuit breaker opened.
    circuit_opened_at: Option<DateTime<Utc>>,
}

impl RestartManager {
    /// Create a new restart manager.
    #[must_use]
    pub const fn new(config: RestartConfig) -> Self {
        Self {
            config,
            history: Vec::new(),
            backoff_attempt: 0,
            circuit_open: false,
            circuit_opened_at: None,
        }
    }

    /// Check if a restart should be allowed.
    #[must_use]
    pub fn should_restart(&self, exit_code: Option<i32>) -> bool {
        // Check circuit breaker
        if self.circuit_open {
            return false;
        }

        // Check if we restart on success
        if exit_code == Some(0) && !self.config.restart_on_success {
            return false;
        }

        // Check restart count within window
        let now = Utc::now();
        let window_start =
            now - chrono::Duration::from_std(self.config.restart_window).unwrap_or_default();

        let recent_restarts = self
            .history
            .iter()
            .filter(|entry| entry.timestamp >= window_start)
            .count();

        recent_restarts < self.config.max_restarts as usize
    }

    /// Record a restart and get the delay before restarting.
    pub fn record_restart(&mut self, exit_code: Option<i32>, uptime: Duration) -> Duration {
        self.backoff_attempt += 1;
        let delay = self.config.backoff.delay_for_attempt(self.backoff_attempt);

        let entry = RestartEntry {
            timestamp: Utc::now(),
            exit_code,
            uptime,
            delay,
        };

        self.history.push(entry);
        self.prune_history();

        // Check if we should open the circuit breaker
        self.check_circuit_breaker();

        delay
    }

    /// Record a successful run (uptime exceeded `min_uptime`).
    pub const fn record_success(&mut self) {
        // Reset backoff on successful run
        self.backoff_attempt = 0;
        self.circuit_open = false;
        self.circuit_opened_at = None;
    }

    /// Check if the circuit breaker should open.
    fn check_circuit_breaker(&mut self) {
        let now = Utc::now();
        let window_start =
            now - chrono::Duration::from_std(self.config.restart_window).unwrap_or_default();

        let recent_restarts = self
            .history
            .iter()
            .filter(|entry| entry.timestamp >= window_start)
            .count();

        if recent_restarts >= self.config.max_restarts as usize {
            self.circuit_open = true;
            self.circuit_opened_at = Some(now);
        }
    }

    /// Remove old entries from history.
    fn prune_history(&mut self) {
        let now = Utc::now();
        let window_start =
            now - chrono::Duration::from_std(self.config.restart_window).unwrap_or_default();

        self.history.retain(|entry| entry.timestamp >= window_start);
    }

    /// Get the number of restarts within the window.
    #[must_use]
    pub fn restart_count(&self) -> usize {
        let now = Utc::now();
        let window_start =
            now - chrono::Duration::from_std(self.config.restart_window).unwrap_or_default();

        self.history
            .iter()
            .filter(|entry| entry.timestamp >= window_start)
            .count()
    }

    /// Check if the circuit breaker is open.
    #[must_use]
    pub const fn is_circuit_open(&self) -> bool {
        self.circuit_open
    }

    /// Reset the manager state.
    pub fn reset(&mut self) {
        self.history.clear();
        self.backoff_attempt = 0;
        self.circuit_open = false;
        self.circuit_opened_at = None;
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &RestartConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff() {
        let config = BackoffConfig::Exponential {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 2.0,
        };

        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(config.delay_for_attempt(4), Duration::from_secs(8));

        // Should cap at max_delay
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(60));
    }

    #[test]
    fn test_linear_backoff() {
        let config = BackoffConfig::Linear {
            initial_delay: Duration::from_secs(1),
            increment: Duration::from_secs(2),
            max_delay: Duration::from_secs(10),
        };

        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(3));
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(5));
        assert_eq!(config.delay_for_attempt(5), Duration::from_secs(9));

        // Should cap at max_delay
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(10));
    }

    #[test]
    fn test_restart_manager() {
        let config = RestartConfig {
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };
        let mut manager = RestartManager::new(config);

        // Should allow restarts initially
        assert!(manager.should_restart(Some(1)));

        // Record some restarts
        manager.record_restart(Some(1), Duration::from_secs(5));
        assert!(manager.should_restart(Some(1)));

        manager.record_restart(Some(1), Duration::from_secs(5));
        assert!(manager.should_restart(Some(1)));

        manager.record_restart(Some(1), Duration::from_secs(5));
        // Should not allow restart after max_restarts
        assert!(!manager.should_restart(Some(1)));
        assert!(manager.is_circuit_open());
    }

    #[test]
    fn test_restart_on_success() {
        let config = RestartConfig {
            restart_on_success: false,
            ..Default::default()
        };
        let manager = RestartManager::new(config);

        // Should not restart on exit code 0
        assert!(!manager.should_restart(Some(0)));
        // Should restart on non-zero exit code
        assert!(manager.should_restart(Some(1)));
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
