//! Graceful shutdown module.
//!
//! Handles coordinated shutdown of processes with proper signal handling.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Shutdown configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    /// Timeout for graceful shutdown before force kill.
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    /// Signal to send for graceful shutdown.
    #[serde(default = "default_signal")]
    pub signal: String,

    /// Delay before sending SIGKILL after timeout.
    #[serde(default = "default_kill_delay")]
    #[serde(with = "humantime_serde")]
    pub kill_delay: Duration,

    /// Whether to send SIGKILL if graceful shutdown times out.
    #[serde(default = "default_force_kill")]
    pub force_kill: bool,

    /// Commands to run before shutdown (cleanup scripts).
    #[serde(default)]
    pub pre_shutdown_commands: Vec<String>,
}

const fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_signal() -> String {
    "SIGTERM".to_string()
}

const fn default_kill_delay() -> Duration {
    Duration::from_secs(5)
}

const fn default_force_kill() -> bool {
    true
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            timeout: default_timeout(),
            signal: default_signal(),
            kill_delay: default_kill_delay(),
            force_kill: true,
            pre_shutdown_commands: Vec::new(),
        }
    }
}

/// Shutdown state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownState {
    /// Not shutting down.
    Running,
    /// Pre-shutdown commands are running.
    PreShutdown,
    /// Graceful shutdown signal sent, waiting for process to exit.
    GracefulShutdown,
    /// Graceful shutdown timed out, force kill pending.
    ForceKillPending,
    /// Process has exited.
    Completed,
}

impl std::fmt::Display for ShutdownState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::PreShutdown => write!(f, "pre_shutdown"),
            Self::GracefulShutdown => write!(f, "graceful_shutdown"),
            Self::ForceKillPending => write!(f, "force_kill_pending"),
            Self::Completed => write!(f, "completed"),
        }
    }
}

/// Manages the shutdown process for a single process.
#[derive(Debug)]
pub struct ShutdownManager {
    /// Shutdown configuration.
    config: ShutdownConfig,

    /// Current shutdown state.
    state: ShutdownState,

    /// Time when shutdown was initiated.
    shutdown_started_at: Option<std::time::Instant>,

    /// Time when graceful shutdown signal was sent.
    graceful_signal_sent_at: Option<std::time::Instant>,
}

impl ShutdownManager {
    /// Create a new shutdown manager.
    #[must_use]
    pub const fn new(config: ShutdownConfig) -> Self {
        Self {
            config,
            state: ShutdownState::Running,
            shutdown_started_at: None,
            graceful_signal_sent_at: None,
        }
    }

    /// Get the current shutdown state.
    #[must_use]
    pub const fn state(&self) -> ShutdownState {
        self.state
    }

    /// Check if shutdown is in progress.
    #[must_use]
    pub const fn is_shutting_down(&self) -> bool {
        !matches!(
            self.state,
            ShutdownState::Running | ShutdownState::Completed
        )
    }

    /// Initiate shutdown.
    pub fn initiate(&mut self) {
        if self.state == ShutdownState::Running {
            self.shutdown_started_at = Some(std::time::Instant::now());
            if self.config.pre_shutdown_commands.is_empty() {
                self.state = ShutdownState::GracefulShutdown;
            } else {
                self.state = ShutdownState::PreShutdown;
            }
        }
    }

    /// Mark pre-shutdown commands as complete.
    pub fn pre_shutdown_complete(&mut self) {
        if self.state == ShutdownState::PreShutdown {
            self.state = ShutdownState::GracefulShutdown;
            self.graceful_signal_sent_at = Some(std::time::Instant::now());
        }
    }

    /// Check if graceful shutdown has timed out.
    #[must_use]
    pub fn has_timed_out(&self) -> bool {
        if self.state != ShutdownState::GracefulShutdown {
            return false;
        }

        self.graceful_signal_sent_at
            .is_some_and(|sent_at| sent_at.elapsed() >= self.config.timeout)
    }

    /// Transition to force kill state.
    pub fn initiate_force_kill(&mut self) {
        if self.state == ShutdownState::GracefulShutdown && self.config.force_kill {
            self.state = ShutdownState::ForceKillPending;
        }
    }

    /// Mark shutdown as complete.
    pub const fn complete(&mut self) {
        self.state = ShutdownState::Completed;
    }

    /// Reset the manager to running state.
    pub const fn reset(&mut self) {
        self.state = ShutdownState::Running;
        self.shutdown_started_at = None;
        self.graceful_signal_sent_at = None;
    }

    /// Get the configured signal for graceful shutdown.
    #[must_use]
    pub fn signal(&self) -> &str {
        &self.config.signal
    }

    /// Get the pre-shutdown commands.
    #[must_use]
    pub fn pre_shutdown_commands(&self) -> &[String] {
        &self.config.pre_shutdown_commands
    }

    /// Get the timeout duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Get the kill delay duration.
    #[must_use]
    pub const fn kill_delay(&self) -> Duration {
        self.config.kill_delay
    }

    /// Check if force kill is enabled.
    #[must_use]
    pub const fn force_kill_enabled(&self) -> bool {
        self.config.force_kill
    }

    /// Get the shutdown configuration.
    #[must_use]
    pub const fn config(&self) -> &ShutdownConfig {
        &self.config
    }

    /// Get elapsed time since shutdown was initiated.
    #[must_use]
    pub fn elapsed(&self) -> Option<Duration> {
        self.shutdown_started_at.map(|t| t.elapsed())
    }
}

/// Parse a signal name to the corresponding nix signal.
///
/// # Errors
///
/// Returns an error if the signal name is not recognized.
pub fn parse_signal(name: &str) -> Result<nix::sys::signal::Signal, ShutdownError> {
    use nix::sys::signal::Signal;

    let name = name.to_uppercase();
    let name = name.strip_prefix("SIG").unwrap_or(&name);

    match name {
        "TERM" => Ok(Signal::SIGTERM),
        "INT" => Ok(Signal::SIGINT),
        "QUIT" => Ok(Signal::SIGQUIT),
        "KILL" => Ok(Signal::SIGKILL),
        "HUP" => Ok(Signal::SIGHUP),
        "USR1" => Ok(Signal::SIGUSR1),
        "USR2" => Ok(Signal::SIGUSR2),
        _ => Err(ShutdownError::InvalidSignal(name.to_string())),
    }
}

/// Shutdown errors.
#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    /// Invalid signal name.
    #[error("invalid signal name: {0}")]
    InvalidSignal(String),

    /// Failed to send signal.
    #[error("failed to send signal: {0}")]
    SignalFailed(String),

    /// Pre-shutdown command failed.
    #[error("pre-shutdown command failed: {0}")]
    PreShutdownFailed(String),

    /// Shutdown timed out.
    #[error("shutdown timed out after {0:?}")]
    Timeout(Duration),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_state_transitions() {
        let config = ShutdownConfig {
            pre_shutdown_commands: vec!["cleanup.sh".to_string()],
            ..Default::default()
        };
        let mut manager = ShutdownManager::new(config);

        assert_eq!(manager.state(), ShutdownState::Running);
        assert!(!manager.is_shutting_down());

        manager.initiate();
        assert_eq!(manager.state(), ShutdownState::PreShutdown);
        assert!(manager.is_shutting_down());

        manager.pre_shutdown_complete();
        assert_eq!(manager.state(), ShutdownState::GracefulShutdown);

        manager.complete();
        assert_eq!(manager.state(), ShutdownState::Completed);
        assert!(!manager.is_shutting_down());
    }

    #[test]
    fn test_shutdown_without_pre_commands() {
        let config = ShutdownConfig::default();
        let mut manager = ShutdownManager::new(config);

        manager.initiate();
        // Should skip PreShutdown and go directly to GracefulShutdown
        assert_eq!(manager.state(), ShutdownState::GracefulShutdown);
    }

    #[test]
    fn test_parse_signal() {
        use nix::sys::signal::Signal;

        assert_eq!(parse_signal("SIGTERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("sigterm").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("SIGHUP").unwrap(), Signal::SIGHUP);
        assert!(parse_signal("INVALID").is_err());
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
