//! Health check module.
//!
//! Provides health check mechanisms for monitoring process health.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Type of health check.
    #[serde(flatten)]
    pub check_type: HealthCheckType,

    /// Interval between health checks.
    #[serde(default = "default_interval")]
    #[serde(with = "humantime_serde")]
    pub interval: Duration,

    /// Timeout for health check.
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    /// Number of consecutive failures before marking unhealthy.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of consecutive successes before marking healthy.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,

    /// Initial delay before starting health checks.
    #[serde(default = "default_initial_delay")]
    #[serde(with = "humantime_serde")]
    pub initial_delay: Duration,
}

const fn default_interval() -> Duration {
    Duration::from_secs(30)
}

const fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

const fn default_unhealthy_threshold() -> u32 {
    3
}

const fn default_healthy_threshold() -> u32 {
    1
}

const fn default_initial_delay() -> Duration {
    Duration::from_secs(0)
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            check_type: HealthCheckType::None,
            interval: default_interval(),
            timeout: default_timeout(),
            unhealthy_threshold: default_unhealthy_threshold(),
            healthy_threshold: default_healthy_threshold(),
            initial_delay: default_initial_delay(),
        }
    }
}

/// Type of health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[derive(Default)]
pub enum HealthCheckType {
    /// No health check.
    #[default]
    None,

    /// HTTP GET health check.
    Http {
        /// URL to check.
        url: String,

        /// Expected status codes (defaults to 200).
        #[serde(default)]
        expected_status: Vec<u16>,

        /// Expected response body substring.
        #[serde(default)]
        expected_body: Option<String>,
    },

    /// TCP connection health check.
    Tcp {
        /// Host to connect to.
        host: String,

        /// Port to connect to.
        port: u16,
    },

    /// Script-based health check.
    Script {
        /// Path to the script.
        path: PathBuf,

        /// Arguments to pass to the script.
        #[serde(default)]
        args: Vec<String>,
    },

    /// Process liveness check (just checks if PID exists).
    Liveness,
}

/// Result of a health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Whether the check passed.
    pub healthy: bool,

    /// Time of the check.
    pub timestamp: DateTime<Utc>,

    /// Duration of the check.
    pub duration: Duration,

    /// Error message if unhealthy.
    pub error: Option<String>,

    /// Additional details.
    pub details: Option<String>,
}

impl HealthCheckResult {
    /// Create a successful health check result.
    #[must_use]
    pub fn healthy(duration: Duration) -> Self {
        Self {
            healthy: true,
            timestamp: Utc::now(),
            duration,
            error: None,
            details: None,
        }
    }

    /// Create a failed health check result.
    #[must_use]
    pub fn unhealthy(duration: Duration, error: impl Into<String>) -> Self {
        Self {
            healthy: false,
            timestamp: Utc::now(),
            duration,
            error: Some(error.into()),
            details: None,
        }
    }

    /// Add details to the result.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Health status derived from health check history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Health checks not configured or not yet run.
    Unknown,
    /// Process is healthy.
    Healthy,
    /// Process is unhealthy.
    Unhealthy,
    /// Health check is in progress.
    Checking,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Healthy => write!(f, "healthy"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Checking => write!(f, "checking"),
        }
    }
}

/// Manages health check state for a process.
#[derive(Debug)]
pub struct HealthChecker {
    /// Health check configuration.
    config: HealthCheckConfig,

    /// Current health status.
    status: HealthStatus,

    /// Recent health check results.
    history: Vec<HealthCheckResult>,

    /// Consecutive successful checks.
    consecutive_success: u32,

    /// Consecutive failed checks.
    consecutive_failure: u32,

    /// Time of last health check.
    last_check: Option<DateTime<Utc>>,
}

impl HealthChecker {
    /// Create a new health checker.
    #[must_use]
    pub const fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            status: HealthStatus::Unknown,
            history: Vec::new(),
            consecutive_success: 0,
            consecutive_failure: 0,
            last_check: None,
        }
    }

    /// Get the current health status.
    #[must_use]
    pub const fn status(&self) -> HealthStatus {
        self.status
    }

    /// Record a health check result and update status.
    pub fn record_result(&mut self, result: HealthCheckResult) {
        let was_healthy = result.healthy;
        self.last_check = Some(result.timestamp);
        self.history.push(result);

        // Keep only recent history
        if self.history.len() > 100 {
            self.history.remove(0);
        }

        if was_healthy {
            self.consecutive_success += 1;
            self.consecutive_failure = 0;

            if self.consecutive_success >= self.config.healthy_threshold {
                self.status = HealthStatus::Healthy;
            }
        } else {
            self.consecutive_failure += 1;
            self.consecutive_success = 0;

            if self.consecutive_failure >= self.config.unhealthy_threshold {
                self.status = HealthStatus::Unhealthy;
            }
        }
    }

    /// Check if a health check is due.
    #[must_use]
    pub fn is_check_due(&self) -> bool {
        let Some(last_check) = self.last_check else {
            return true;
        };

        let next_check = last_check
            + chrono::Duration::from_std(self.config.interval).unwrap_or(chrono::Duration::zero());

        Utc::now() >= next_check
    }

    /// Get the health check configuration.
    #[must_use]
    pub const fn config(&self) -> &HealthCheckConfig {
        &self.config
    }

    /// Get recent health check history.
    #[must_use]
    pub fn history(&self) -> &[HealthCheckResult] {
        &self.history
    }

    /// Reset the health checker state.
    pub fn reset(&mut self) {
        self.status = HealthStatus::Unknown;
        self.history.clear();
        self.consecutive_success = 0;
        self.consecutive_failure = 0;
        self.last_check = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_transitions() {
        let config = HealthCheckConfig {
            unhealthy_threshold: 2,
            healthy_threshold: 2,
            ..Default::default()
        };
        let mut checker = HealthChecker::new(config);

        assert_eq!(checker.status(), HealthStatus::Unknown);

        // One success isn't enough
        checker.record_result(HealthCheckResult::healthy(Duration::from_millis(10)));
        assert_eq!(checker.status(), HealthStatus::Unknown);

        // Two successes -> healthy
        checker.record_result(HealthCheckResult::healthy(Duration::from_millis(10)));
        assert_eq!(checker.status(), HealthStatus::Healthy);

        // One failure isn't enough
        checker.record_result(HealthCheckResult::unhealthy(
            Duration::from_millis(10),
            "error",
        ));
        assert_eq!(checker.status(), HealthStatus::Healthy);

        // Two failures -> unhealthy
        checker.record_result(HealthCheckResult::unhealthy(
            Duration::from_millis(10),
            "error",
        ));
        assert_eq!(checker.status(), HealthStatus::Unhealthy);
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
