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
    /// Returns an error if:
    /// - The TOML is invalid
    /// - The legacy `socket` key is present in `[daemon]` section (DD-009)
    /// - The `operator_socket` or `session_socket` fields are missing
    ///   (TCK-00280)
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        // First, check for legacy `socket` key in daemon config (DD-009 fail-closed
        // validation) Parse as raw TOML value to detect if `daemon.socket` was
        // explicitly set
        if let Ok(raw) = content.parse::<toml::Table>() {
            if let Some(daemon) = raw.get("daemon") {
                if let Some(daemon_table) = daemon.as_table() {
                    if daemon_table.contains_key("socket") {
                        return Err(ConfigError::Validation(
                            "DD-009: legacy 'socket' key is no longer supported in [daemon] section. \
                             Use 'operator_socket' and 'session_socket' instead for dual-socket \
                             privilege separation."
                                .to_string(),
                        ));
                    }
                }
            }
        }
        // Parse the config - operator_socket and session_socket are now required fields
        // and serde will fail if they are missing when [daemon] section is present
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

    /// Path to the operator socket (mode 0600, privileged operations).
    ///
    /// Added in TCK-00249 for dual-socket privilege separation.
    /// Required field - config validation fails if not provided.
    pub operator_socket: PathBuf,

    /// Path to the session socket (mode 0660, session-scoped operations).
    ///
    /// Added in TCK-00249 for dual-socket privilege separation.
    /// Required field - config validation fails if not provided.
    pub session_socket: PathBuf,

    /// Log directory.
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,

    /// State file path.
    #[serde(default = "default_state_file")]
    pub state_file: PathBuf,

    /// Audit configuration.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Projection worker configuration (TCK-00322).
    ///
    /// Controls the projection worker that posts review results to GitHub.
    #[serde(default)]
    pub projection: ProjectionConfig,

    /// Path to durable content-addressed storage (CAS) directory (TCK-00383).
    ///
    /// When provided alongside a ledger database, the daemon uses
    /// `with_persistence_and_cas()` to wire the session dispatcher with
    /// a `ToolBroker`, `DurableCas`, ledger event emitter, and holonic clock.
    /// Without this, the session dispatcher uses stubs and all session-scoped
    /// operations (tool execution, event emission, evidence publishing) fail
    /// closed with "unavailable" errors.
    ///
    /// The directory is created with mode 0700 if it does not exist.
    #[serde(default)]
    pub cas_path: Option<PathBuf>,

    /// Divergence watchdog configuration (TCK-00393).
    ///
    /// Controls the background watchdog that polls the external trunk HEAD
    /// and compares it against the ledger's `MergeReceipt` HEAD. When
    /// divergence is detected, a `DefectRecorded` event and
    /// `InterventionFreeze` are emitted to halt admissions.
    #[serde(default)]
    pub divergence_watchdog: DivergenceWatchdogSection,
}

/// Projection worker configuration (TCK-00322).
///
/// Controls the projection worker that posts review results to GitHub.
/// Disabled by default; enable by setting `enabled = true` and providing
/// GitHub API credentials.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionConfig {
    /// Whether projection is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// GitHub API base URL (default: `https://api.github.com`).
    #[serde(default = "default_github_api_url")]
    pub github_api_url: String,

    /// Repository owner (e.g., "rumi-engineering").
    #[serde(default)]
    pub github_owner: String,

    /// Repository name (e.g., "apm2").
    #[serde(default)]
    pub github_repo: String,

    /// GitHub API token (stored as environment variable reference).
    ///
    /// For security, this should reference an environment variable,
    /// e.g., `$GITHUB_TOKEN` or use a credential profile.
    ///
    /// **Required when `enabled = true`**: Missing token is a fatal error
    /// to prevent fail-open security issues (TCK-00322 security review).
    #[serde(default)]
    pub github_token_env: Option<String>,

    /// Poll interval in seconds for ledger tailer.
    #[serde(default = "default_projection_poll_interval")]
    pub poll_interval_secs: u64,

    /// Batch size for processing ledger events.
    #[serde(default = "default_projection_batch_size")]
    pub batch_size: usize,

    /// Path to persistent signer key file for projection receipts.
    ///
    /// TCK-00322 BLOCKER FIX: The projection worker requires a persistent
    /// signing key to ensure receipt signatures remain valid across daemon
    /// restarts. If not specified, defaults to
    /// `{state_file_dir}/projection_signer.key`.
    ///
    /// The key file contains the 32-byte Ed25519 secret key. It is created
    /// automatically with mode 0600 if it does not exist.
    #[serde(default)]
    pub signer_key_file: Option<PathBuf>,
}

fn default_github_api_url() -> String {
    "https://api.github.com".to_string()
}

const fn default_projection_poll_interval() -> u64 {
    1
}

const fn default_projection_batch_size() -> usize {
    100
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: default_pid_file(),
            operator_socket: default_operator_socket(),
            session_socket: default_session_socket(),
            log_dir: default_log_dir(),
            state_file: default_state_file(),
            audit: AuditConfig::default(),
            projection: ProjectionConfig::default(),
            cas_path: None,
            divergence_watchdog: DivergenceWatchdogSection::default(),
        }
    }
}

/// Divergence watchdog configuration (TCK-00393).
///
/// Controls the background task that polls the external trunk HEAD and
/// compares it against the ledger's `MergeReceipt` HEAD. When divergence
/// is detected, a `DefectRecorded` event and `InterventionFreeze` are
/// emitted to halt new admissions until adjudication.
///
/// Disabled by default; enable by setting `enabled = true` and providing
/// the GitHub repository coordinates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DivergenceWatchdogSection {
    /// Whether the divergence watchdog is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// GitHub repository owner (e.g., "rumi-engineering").
    #[serde(default)]
    pub github_owner: String,

    /// GitHub repository name (e.g., "apm2").
    #[serde(default)]
    pub github_repo: String,

    /// Trunk branch name to monitor (default: "main").
    #[serde(default = "default_trunk_branch")]
    pub trunk_branch: String,

    /// GitHub API base URL (default: `https://api.github.com`).
    #[serde(default = "default_github_api_url")]
    pub github_api_url: String,

    /// Environment variable name containing the GitHub API token.
    ///
    /// For security, the token itself is NOT stored in the config file.
    /// Instead, provide the name of an environment variable that holds
    /// the token (e.g., `$GITHUB_TOKEN`).
    #[serde(default)]
    pub github_token_env: Option<String>,

    /// Poll interval in seconds for divergence checks.
    /// Default: 30 seconds. Minimum: 1 second. Maximum: 3600 seconds.
    #[serde(default = "default_divergence_poll_interval")]
    pub poll_interval_secs: u64,
}

impl DivergenceWatchdogSection {
    /// Validate startup prerequisites for the divergence watchdog.
    ///
    /// TCK-00408: When the watchdog is enabled, a ledger database is mandatory.
    /// The watchdog is a security control; allowing it to be enabled without
    /// its required ledger database would silently disable divergence
    /// detection, violating fail-closed posture.
    ///
    /// `has_ledger_db` indicates whether a ledger database path was configured.
    ///
    /// Returns `Ok(())` when:
    /// - The watchdog is disabled (no validation needed), or
    /// - The watchdog is enabled AND a ledger database is configured.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` when the watchdog is enabled but no ledger
    /// database is configured.
    pub fn validate_startup_prerequisites(&self, has_ledger_db: bool) -> Result<(), String> {
        if self.enabled && !has_ledger_db {
            return Err(
                "divergence_watchdog.enabled=true but no --ledger-db configured. \
                 Divergence watchdog requires a ledger database. \
                 Either provide --ledger-db or disable the watchdog."
                    .to_string(),
            );
        }
        Ok(())
    }
}

impl Default for DivergenceWatchdogSection {
    fn default() -> Self {
        Self {
            enabled: false,
            github_owner: String::new(),
            github_repo: String::new(),
            trunk_branch: default_trunk_branch(),
            github_api_url: default_github_api_url(),
            github_token_env: None,
            poll_interval_secs: default_divergence_poll_interval(),
        }
    }
}

fn default_trunk_branch() -> String {
    "main".to_string()
}

const fn default_divergence_poll_interval() -> u64 {
    30
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

fn default_operator_socket() -> PathBuf {
    // Per TCK-00249: ${XDG_RUNTIME_DIR}/apm2/operator.sock
    // Falls back to /tmp/apm2/operator.sock if XDG_RUNTIME_DIR is not set
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| PathBuf::from("/tmp/apm2/operator.sock"),
        |runtime_dir| {
            PathBuf::from(runtime_dir)
                .join("apm2")
                .join("operator.sock")
        },
    )
}

fn default_session_socket() -> PathBuf {
    // Per TCK-00249: ${XDG_RUNTIME_DIR}/apm2/session.sock
    // Falls back to /tmp/apm2/session.sock if XDG_RUNTIME_DIR is not set
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| PathBuf::from("/tmp/apm2/session.sock"),
        |runtime_dir| PathBuf::from(runtime_dir).join("apm2").join("session.sock"),
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
            operator_socket = "/tmp/apm2/operator.sock"
            session_socket = "/tmp/apm2/session.sock"

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
        assert_eq!(
            config.daemon.operator_socket,
            PathBuf::from("/tmp/apm2/operator.sock")
        );
        assert_eq!(
            config.daemon.session_socket,
            PathBuf::from("/tmp/apm2/session.sock")
        );
        assert_eq!(config.daemon.audit.retention_days, 90);
        assert_eq!(config.daemon.audit.max_size_bytes, 536_870_912);
        assert_eq!(config.credentials.len(), 1);
        assert_eq!(config.processes[0].instances, 2);
    }

    /// UT-00280-01: Test that DD-009 rejects legacy socket configuration
    /// (fail-closed).
    #[test]
    fn config_reject_legacy_socket() {
        let toml = r#"
            [daemon]
            pid_file = "/tmp/apm2.pid"
            socket = "/tmp/apm2.sock"

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let result = EcosystemConfig::from_toml(toml);
        assert!(result.is_err(), "Should reject legacy socket key");

        let err = result.unwrap_err();
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("DD-009"), "Error should mention DD-009: {msg}");
                assert!(
                    msg.contains("socket"),
                    "Error should mention legacy socket: {msg}"
                );
            },
            _ => panic!("Expected ConfigError::Validation, got {err:?}"),
        }
    }

    /// Test that configs without daemon.socket are accepted.
    #[test]
    fn test_config_without_legacy_socket_accepted() {
        let toml = r#"
            [daemon]
            pid_file = "/tmp/apm2.pid"
            operator_socket = "/tmp/apm2/operator.sock"
            session_socket = "/tmp/apm2/session.sock"

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let config = EcosystemConfig::from_toml(toml).unwrap();
        assert_eq!(config.processes.len(), 1);
    }

    /// UT-00280-02: Test that daemon config requires `operator_socket`
    /// (TCK-00280).
    #[test]
    fn config_requires_operator_socket() {
        let toml = r#"
            [daemon]
            pid_file = "/tmp/apm2.pid"
            session_socket = "/tmp/apm2/session.sock"

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let result = EcosystemConfig::from_toml(toml);
        assert!(
            result.is_err(),
            "Should require operator_socket when daemon section present"
        );
    }

    /// UT-00280-03: Test that daemon config requires `session_socket`
    /// (TCK-00280).
    #[test]
    fn config_requires_session_socket() {
        let toml = r#"
            [daemon]
            pid_file = "/tmp/apm2.pid"
            operator_socket = "/tmp/apm2/operator.sock"

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let result = EcosystemConfig::from_toml(toml);
        assert!(
            result.is_err(),
            "Should require session_socket when daemon section present"
        );
    }

    /// UT-00280-04: Test that both sockets are required when daemon section is
    /// present.
    #[test]
    fn config_requires_both_sockets() {
        let toml = r#"
            [daemon]
            pid_file = "/tmp/apm2.pid"

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let result = EcosystemConfig::from_toml(toml);
        assert!(
            result.is_err(),
            "Should require both sockets when daemon section present"
        );
    }
}
