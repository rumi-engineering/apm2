//! Configuration parsing and management.
//!
//! This module handles parsing of ecosystem configuration files (TOML/JSON)
//! that define processes, credentials, and daemon settings.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::credentials::CredentialConfig;
use crate::health::HealthCheckConfig;
use crate::log::LogConfig;
use crate::restart::RestartConfig;
use crate::shutdown::ShutdownConfig;

/// Top-level ecosystem configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EcosystemConfig {
    /// Daemon configuration.
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// Credential profiles.
    #[serde(default)]
    pub credentials: Vec<CredentialProfileConfig>,

    /// Process definitions.
    #[serde(default)]
    pub processes: Vec<ProcessConfig>,
}

impl EcosystemConfig {
    /// Load configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::from_toml(&content)
    }

    /// Parse configuration from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML is invalid.
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(ConfigError::Parse)
    }

    /// Serialize configuration to TOML.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(ConfigError::Serialize)
    }
}

/// Daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to the PID file.
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,

    /// Path to the Unix socket.
    #[serde(default = "default_socket")]
    pub socket: PathBuf,

    /// Log directory.
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,

    /// State file path.
    #[serde(default = "default_state_file")]
    pub state_file: PathBuf,

    /// Audit configuration.
    #[serde(default)]
    pub audit: AuditConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: default_pid_file(),
            socket: default_socket(),
            log_dir: default_log_dir(),
            state_file: default_state_file(),
            audit: AuditConfig::default(),
        }
    }
}

/// Audit configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditConfig {
    /// Maximum days to retain audit events.
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,

    /// Maximum size of audit log in bytes.
    #[serde(default = "default_audit_max_size_bytes")]
    pub max_size_bytes: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            retention_days: default_audit_retention_days(),
            max_size_bytes: default_audit_max_size_bytes(),
        }
    }
}

const fn default_audit_retention_days() -> u32 {
    30 // 30 days
}

const fn default_audit_max_size_bytes() -> u64 {
    1024 * 1024 * 1024 // 1 GB
}

fn default_pid_file() -> PathBuf {
    PathBuf::from("/var/run/apm2/apm2.pid")
}

fn default_socket() -> PathBuf {
    // Per RFC-0013 AD-DAEMON-002: ${XDG_RUNTIME_DIR}/apm2/apm2d.sock
    // Falls back to /tmp/apm2/apm2d.sock if XDG_RUNTIME_DIR is not set
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| PathBuf::from("/tmp/apm2/apm2d.sock"),
        |runtime_dir| PathBuf::from(runtime_dir).join("apm2").join("apm2d.sock"),
    )
}

fn default_log_dir() -> PathBuf {
    PathBuf::from("/var/log/apm2")
}

fn default_state_file() -> PathBuf {
    PathBuf::from("/var/lib/apm2/state.json")
}

/// Credential profile configuration (in ecosystem file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProfileConfig {
    /// Unique identifier for this profile.
    pub id: String,

    /// AI provider (claude, gemini, openai, etc.).
    pub provider: String,

    /// Authentication method.
    pub auth_method: String,

    /// Refresh token before expiry duration.
    #[serde(default)]
    pub refresh_before_expiry: Option<String>,
}

/// Process configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    /// Process name (must be unique).
    pub name: String,

    /// Command to execute.
    pub command: String,

    /// Command arguments.
    #[serde(default)]
    pub args: Vec<String>,

    /// Working directory.
    #[serde(default)]
    pub cwd: Option<PathBuf>,

    /// Environment variables.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Number of instances to run.
    #[serde(default = "default_instances")]
    pub instances: u32,

    /// Restart configuration.
    #[serde(default)]
    pub restart: RestartConfig,

    /// Health check configuration.
    #[serde(default)]
    pub health: Option<HealthCheckConfig>,

    /// Log configuration.
    #[serde(default)]
    pub log: LogConfig,

    /// Shutdown configuration.
    #[serde(default)]
    pub shutdown: ShutdownConfig,

    /// Credential binding configuration.
    #[serde(default)]
    pub credentials: Option<CredentialConfig>,
}

const fn default_instances() -> u32 {
    1
}

/// Configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// I/O error reading configuration file.
    #[error("failed to read configuration file: {0}")]
    Io(#[from] std::io::Error),

    /// TOML parsing error.
    #[error("failed to parse configuration: {0}")]
    Parse(#[from] toml::de::Error),

    /// TOML serialization error.
    #[error("failed to serialize configuration: {0}")]
    Serialize(#[from] toml::ser::Error),

    /// Validation error.
    #[error("configuration validation failed: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let config = EcosystemConfig::from_toml(toml).unwrap();
        assert_eq!(config.processes.len(), 1);
        assert_eq!(config.processes[0].name, "test");
        assert_eq!(config.processes[0].command, "echo");
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
            [daemon]
            pid_file = "/tmp/apm2.pid"
            socket = "/tmp/apm2.sock"

            [daemon.audit]
            retention_days = 90
            max_size_bytes = 536870912

            [[credentials]]
            id = "claude-work"
            provider = "claude"
            auth_method = "session_token"

            [[processes]]
            name = "claude-code"
            command = "claude"
            args = ["--session", "project"]
            instances = 2

            [processes.restart]
            max_restarts = 5

            [processes.credentials]
            profile = "claude-work"
            hot_swap = true
        "#;

        let config = EcosystemConfig::from_toml(toml).unwrap();
        assert_eq!(config.daemon.pid_file, PathBuf::from("/tmp/apm2.pid"));
        assert_eq!(config.daemon.audit.retention_days, 90);
        assert_eq!(config.daemon.audit.max_size_bytes, 536_870_912);
        assert_eq!(config.credentials.len(), 1);
        assert_eq!(config.processes[0].instances, 2);
    }
}
