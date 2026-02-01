#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Process management module.
//!
//! This module provides types and functions for spawning, monitoring,
//! and controlling child processes.

pub mod runner;
pub mod spawner;

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::credentials::CredentialConfig;
use crate::health::HealthCheckConfig;
use crate::log::LogConfig;
use crate::restart::RestartConfig;
use crate::shutdown::ShutdownConfig;

/// Unique identifier for a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(Uuid);

impl ProcessId {
    /// Create a new random process ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ProcessId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ProcessId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Process specification - defines what to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSpec {
    /// Unique identifier.
    pub id: ProcessId,

    /// Human-readable name.
    pub name: String,

    /// Command to execute.
    pub command: String,

    /// Command arguments.
    pub args: Vec<String>,

    /// Working directory.
    pub cwd: Option<PathBuf>,

    /// Environment variables.
    pub env: HashMap<String, String>,

    /// Number of instances to run.
    pub instances: u32,

    /// Restart configuration.
    pub restart: RestartConfig,

    /// Health check configuration.
    pub health: Option<HealthCheckConfig>,

    /// Log configuration.
    pub log: LogConfig,

    /// Shutdown configuration.
    pub shutdown: ShutdownConfig,

    /// Credential binding configuration.
    pub credentials: Option<CredentialConfig>,
}

impl ProcessSpec {
    /// Create a new builder for `ProcessSpec`.
    #[must_use]
    pub fn builder() -> ProcessSpecBuilder {
        ProcessSpecBuilder::default()
    }
}

/// Builder for `ProcessSpec`.
#[derive(Debug, Default)]
pub struct ProcessSpecBuilder {
    name: Option<String>,
    command: Option<String>,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: HashMap<String, String>,
    instances: u32,
    restart: RestartConfig,
    health: Option<HealthCheckConfig>,
    log: LogConfig,
    shutdown: ShutdownConfig,
    credentials: Option<CredentialConfig>,
}

impl ProcessSpecBuilder {
    /// Set the process name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the command to execute.
    #[must_use]
    pub fn command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Set command arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Set the working directory.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Add an environment variable.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set the number of instances.
    #[must_use]
    pub const fn instances(mut self, instances: u32) -> Self {
        self.instances = instances;
        self
    }

    /// Set the restart configuration.
    #[must_use]
    pub const fn restart(mut self, restart: RestartConfig) -> Self {
        self.restart = restart;
        self
    }

    /// Set the health check configuration.
    #[must_use]
    pub fn health(mut self, health: HealthCheckConfig) -> Self {
        self.health = Some(health);
        self
    }

    /// Set the log configuration.
    #[must_use]
    pub fn log(mut self, log: LogConfig) -> Self {
        self.log = log;
        self
    }

    /// Set the shutdown configuration.
    #[must_use]
    pub fn shutdown(mut self, shutdown: ShutdownConfig) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// Set the credential binding.
    #[must_use]
    pub fn credentials(mut self, credentials: CredentialConfig) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Build the `ProcessSpec`.
    ///
    /// # Panics
    ///
    /// Panics if `name` or `command` is not set.
    #[must_use]
    pub fn build(self) -> ProcessSpec {
        ProcessSpec {
            id: ProcessId::new(),
            name: self.name.expect("name is required"),
            command: self.command.expect("command is required"),
            args: self.args,
            cwd: self.cwd,
            env: self.env,
            instances: if self.instances == 0 {
                1
            } else {
                self.instances
            },
            restart: self.restart,
            health: self.health,
            log: self.log,
            shutdown: self.shutdown,
            credentials: self.credentials,
        }
    }
}

/// Process state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is starting up.
    Starting,

    /// Process is running normally.
    Running,

    /// Process is running but failing health checks.
    Unhealthy,

    /// Process is being stopped gracefully.
    Stopping,

    /// Process has stopped (graceful exit).
    Stopped {
        /// Exit code if available.
        exit_code: Option<i32>,
    },

    /// Process has crashed unexpectedly.
    Crashed {
        /// Exit code if available.
        exit_code: Option<i32>,
    },

    /// Process was terminated by signal.
    Terminated,
}

impl ProcessState {
    /// Returns `true` if the process is in a running state.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Unhealthy)
    }

    /// Returns `true` if the process has exited (stopped, crashed, or
    /// terminated).
    #[must_use]
    pub const fn has_exited(&self) -> bool {
        matches!(
            self,
            Self::Stopped { .. } | Self::Crashed { .. } | Self::Terminated
        )
    }
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped { exit_code } => {
                if let Some(code) = exit_code {
                    write!(f, "stopped (exit code: {code})")
                } else {
                    write!(f, "stopped")
                }
            },
            Self::Crashed { exit_code } => {
                if let Some(code) = exit_code {
                    write!(f, "crashed (exit code: {code})")
                } else {
                    write!(f, "crashed")
                }
            },
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

/// Handle to a running process instance.
#[derive(Debug)]
pub struct ProcessHandle {
    /// Process specification.
    pub spec: ProcessSpec,

    /// Instance index (0-based).
    pub instance: u32,

    /// Current state.
    pub state: ProcessState,

    /// OS process ID (if running).
    pub pid: Option<u32>,

    /// Time when the process started.
    pub started_at: Option<DateTime<Utc>>,

    /// Number of restarts.
    pub restart_count: u32,

    /// Time of last restart.
    pub last_restart: Option<DateTime<Utc>>,

    /// CPU usage percentage (0-100).
    pub cpu_percent: Option<f32>,

    /// Memory usage in bytes.
    pub memory_bytes: Option<u64>,
}

impl ProcessHandle {
    /// Create a new process handle.
    ///
    /// The handle starts in `Stopped` state until the process is actually
    /// started.
    #[must_use]
    pub const fn new(spec: ProcessSpec, instance: u32) -> Self {
        Self {
            spec,
            instance,
            state: ProcessState::Stopped { exit_code: None },
            pid: None,
            started_at: None,
            restart_count: 0,
            last_restart: None,
            cpu_percent: None,
            memory_bytes: None,
        }
    }

    /// Get the display name for this instance.
    #[must_use]
    pub fn display_name(&self) -> String {
        if self.spec.instances > 1 {
            format!("{}-{}", self.spec.name, self.instance)
        } else {
            self.spec.name.clone()
        }
    }

    /// Get uptime in seconds if the process is running.
    #[must_use]
    pub fn uptime_secs(&self) -> Option<i64> {
        self.started_at.map(|started| {
            let now = Utc::now();
            (now - started).num_seconds()
        })
    }
}

/// Error types for process operations.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// Failed to spawn process.
    #[error("failed to spawn process: {0}")]
    SpawnFailed(String),

    /// Process not found.
    #[error("process not found: {0}")]
    NotFound(String),

    /// Process already exists.
    #[error("process already exists: {0}")]
    AlreadyExists(String),

    /// Invalid process state for operation.
    #[error("invalid state for operation: {0}")]
    InvalidState(String),

    /// Signal delivery failed.
    #[error("failed to send signal: {0}")]
    SignalFailed(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_spec_builder() {
        let spec = ProcessSpec::builder()
            .name("test-process")
            .command("echo")
            .args(["hello", "world"])
            .cwd("/tmp")
            .env("FOO", "bar")
            .instances(2)
            .build();

        assert_eq!(spec.name, "test-process");
        assert_eq!(spec.command, "echo");
        assert_eq!(spec.args, vec!["hello", "world"]);
        assert_eq!(spec.cwd, Some(PathBuf::from("/tmp")));
        assert_eq!(spec.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(spec.instances, 2);
    }

    #[test]
    fn test_process_state_display() {
        assert_eq!(ProcessState::Running.to_string(), "running");
        assert_eq!(
            ProcessState::Crashed { exit_code: Some(1) }.to_string(),
            "crashed (exit code: 1)"
        );
    }

    #[test]
    fn test_process_state_predicates() {
        assert!(ProcessState::Running.is_running());
        assert!(!ProcessState::Running.has_exited());

        assert!(!ProcessState::Stopped { exit_code: Some(0) }.is_running());
        assert!(ProcessState::Stopped { exit_code: Some(0) }.has_exited());
    }
}
