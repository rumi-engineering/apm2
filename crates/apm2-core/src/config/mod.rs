//! Configuration parsing and management.
//!
//! This module handles parsing of ecosystem configuration files (TOML/JSON)
//! that define processes, credentials, and daemon settings.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::credentials::CredentialConfig;
use crate::fac::{
    CLAUDE_CODE_PROFILE_ID, CODEX_CLI_PROFILE_ID, GEMINI_CLI_PROFILE_ID, LOCAL_INFERENCE_PROFILE_ID,
};
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
        let config: Self = toml::from_str(content).map_err(ConfigError::Parse)?;
        config
            .daemon
            .adapter_rotation
            .validate()
            .map_err(ConfigError::Validation)?;
        // TCK-00507: Validate projection sink profiles at startup.
        // Invalid trusted signer keys must prevent daemon start, not
        // silently produce DENY at runtime.
        config
            .daemon
            .projection
            .validate_sink_profiles()
            .map_err(ConfigError::Validation)?;
        Ok(config)
    }

    /// Serialize configuration to TOML.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(ConfigError::Serialize)
    }

    /// Build a default config with environment-based auto-detection.
    ///
    /// TCK-00595: Enables config-less startup for the CLI layer. When no
    /// `ecosystem.toml` exists, this method constructs a usable config by:
    ///
    /// 1. Using XDG-standard default paths for all daemon paths.
    /// 2. Auto-detecting GitHub owner/repo from `git remote get-url origin`.
    /// 3. Using `$GITHUB_TOKEN` (or `$GH_TOKEN`) for projection auth, with
    ///    fallback to systemd credentials and APM2 credential files.
    ///
    /// The projection worker is enabled only when both the GitHub token
    /// and owner/repo are successfully detected. Otherwise, the config
    /// defaults to projection-disabled.
    ///
    /// **This is for the short-lived CLI only.** The long-lived daemon
    /// must NOT use auto-detection from CWD (see MAJOR-1 in daemon/main.rs).
    ///
    /// # Security
    ///
    /// This calls `detect_github_owner_repo_from_cwd()` which executes a
    /// PATH-resolved `git` binary. This is acceptable for the CLI context
    /// (runs with user privileges), but the daemon MUST use explicit config.
    /// See security review finding f-686-security-*.
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Detect GitHub owner/repo from CWD git remote
        let github_coords = crate::github::detect_github_owner_repo_from_cwd();

        // Check for GitHub token via unified resolution chain (TCK-00595 MAJOR FIX):
        // env vars -> $CREDENTIALS_DIRECTORY/gh-token ->
        // $APM2_HOME/private/creds/gh-token
        let github_token_env = if resolve_github_token("GITHUB_TOKEN").is_some() {
            Some("GITHUB_TOKEN".to_string())
        } else if resolve_github_token("GH_TOKEN").is_some() {
            Some("GH_TOKEN".to_string())
        } else {
            None
        };

        // Enable projection only when we have both coordinates and a token
        if let (Some((owner, repo)), Some(token_env)) = (&github_coords, &github_token_env) {
            config.daemon.projection.enabled = true;
            config.daemon.projection.github_owner.clone_from(owner);
            config.daemon.projection.github_repo.clone_from(repo);
            config.daemon.projection.github_token_env = Some(format!("${token_env}"));
        }

        config
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

    /// Path to the daemon ledger database.
    ///
    /// Defaults to `$APM2_DATA_DIR/ledger.db` (or XDG equivalent) when not
    /// specified in config.
    #[serde(default = "default_ledger_db")]
    pub ledger_db: Option<PathBuf>,

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

    /// Adapter profile rotation policy (TCK-00400).
    ///
    /// Defines weighted profile selection and rate-limit backoff behavior for
    /// `SpawnEpisode` when no explicit `adapter_profile_hash` is provided.
    #[serde(default)]
    pub adapter_rotation: AdapterRotationConfig,
}

/// Adapter profile rotation configuration (TCK-00400).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterRotationConfig {
    /// Selection strategy.
    #[serde(default)]
    pub strategy: AdapterRotationStrategyConfig,

    /// Rate-limit backoff window in seconds.
    #[serde(default = "default_adapter_rotation_backoff_secs")]
    pub rate_limit_backoff_secs: u64,

    /// Profile entries with weights and enable flags.
    #[serde(default = "default_adapter_rotation_profiles")]
    pub profiles: Vec<AdapterRotationProfileConfig>,
}

impl AdapterRotationConfig {
    /// Validate weight configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns an error string when the profile list is empty, contains
    /// duplicates, or has no enabled profile with positive weight.
    pub fn validate(&self) -> Result<(), String> {
        if self.profiles.is_empty() {
            return Err("daemon.adapter_rotation.profiles cannot be empty".to_string());
        }

        let mut seen = std::collections::BTreeSet::new();
        let mut enabled_count: usize = 0;
        let mut enabled_positive_weight_count: usize = 0;

        for profile in &self.profiles {
            if profile.profile_id.trim().is_empty() {
                return Err("daemon.adapter_rotation profile_id cannot be empty".to_string());
            }
            if !seen.insert(profile.profile_id.clone()) {
                return Err(format!(
                    "daemon.adapter_rotation has duplicate profile_id '{}'",
                    profile.profile_id
                ));
            }
            if profile.enabled {
                enabled_count += 1;
                if profile.weight > 0 {
                    enabled_positive_weight_count += 1;
                }
            }
        }

        if enabled_count == 0 {
            return Err(
                "daemon.adapter_rotation must have at least one enabled profile".to_string(),
            );
        }
        if enabled_positive_weight_count == 0 {
            return Err(
                "daemon.adapter_rotation must have at least one enabled profile with weight > 0"
                    .to_string(),
            );
        }

        Ok(())
    }
}

impl Default for AdapterRotationConfig {
    fn default() -> Self {
        Self {
            strategy: AdapterRotationStrategyConfig::default(),
            rate_limit_backoff_secs: default_adapter_rotation_backoff_secs(),
            profiles: default_adapter_rotation_profiles(),
        }
    }
}

const fn default_adapter_rotation_backoff_secs() -> u64 {
    300
}

fn default_adapter_rotation_profiles() -> Vec<AdapterRotationProfileConfig> {
    vec![
        AdapterRotationProfileConfig {
            profile_id: CLAUDE_CODE_PROFILE_ID.to_string(),
            weight: 100,
            enabled: true,
            fallback_priority: 0,
        },
        AdapterRotationProfileConfig {
            profile_id: GEMINI_CLI_PROFILE_ID.to_string(),
            weight: 0,
            enabled: false,
            fallback_priority: 1,
        },
        AdapterRotationProfileConfig {
            profile_id: CODEX_CLI_PROFILE_ID.to_string(),
            weight: 0,
            enabled: false,
            fallback_priority: 2,
        },
        AdapterRotationProfileConfig {
            profile_id: LOCAL_INFERENCE_PROFILE_ID.to_string(),
            weight: 0,
            enabled: false,
            fallback_priority: 3,
        },
    ]
}

/// Adapter rotation selection strategy (TCK-00400).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdapterRotationStrategyConfig {
    /// Deterministic weighted random.
    #[default]
    WeightedRandom,
    /// Deterministic round-robin.
    RoundRobin,
}

/// Configured weight for one adapter profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterRotationProfileConfig {
    /// Builtin profile ID.
    pub profile_id: String,
    /// Selection weight.
    pub weight: u32,
    /// Whether this profile is eligible.
    #[serde(default)]
    pub enabled: bool,
    /// Lower number has higher fallback priority.
    #[serde(default)]
    pub fallback_priority: u32,
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

    /// Repository owner (e.g., "guardian-intelligence").
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

    /// Per-sink continuity profiles for economics gate input assembly
    /// (TCK-00507).
    ///
    /// Maps sink identifiers to their continuity parameters. Each sink
    /// profile declares outage/replay windows, churn/partition tolerance,
    /// and trusted signer keys that feed into the economics gate evaluator.
    ///
    /// Trusted signer keys are validated at config parse time (startup).
    /// Invalid hex encoding, wrong key length, or empty signer lists
    /// cause a startup-fatal validation error to prevent fail-open
    /// behavior at runtime.
    #[serde(default)]
    pub sinks: HashMap<String, ProjectionSinkProfileConfig>,
}

/// Maximum number of configured projection sinks (denial-of-service bound).
pub const MAX_PROJECTION_SINKS: usize = 64;

/// Maximum number of trusted signers per sink profile (denial-of-service
/// bound).
pub const MAX_TRUSTED_SIGNERS_PER_SINK: usize = 32;

/// Maximum length of a sink identifier string (references economics
/// domain constant for consistency).
pub const MAX_SINK_ID_CONFIG_LENGTH: usize =
    crate::economics::projection_continuity::MAX_SINK_ID_LENGTH;

/// Per-sink continuity profile configuration (TCK-00507).
///
/// Defines the continuity parameters for a single projection sink.
/// These values map directly to economics module input types
/// ([`crate::economics::ProjectionContinuityWindowV1`] fields) without
/// lossy conversion.
///
/// # TOML Example
///
/// ```toml
/// [daemon.projection.sinks.github-primary]
/// outage_window_ticks = 3600000000
/// replay_window_ticks = 7200000000
/// churn_tolerance = 3
/// partition_tolerance = 2
/// trusted_signers = [
///     "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
/// ]
/// ```
///
/// # Security
///
/// `trusted_signers` entries are hex-encoded Ed25519 public keys (32 bytes
/// = 64 hex chars). Validation is performed eagerly at config parse time:
/// - Odd-length hex strings are rejected.
/// - Non-hex characters are rejected.
/// - Keys that are not exactly 32 bytes after decoding are rejected.
/// - An empty `trusted_signers` list is rejected.
///
/// Invalid keys prevent daemon startup rather than silently producing
/// DENY verdicts at runtime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSinkProfileConfig {
    /// Outage window duration in HTF ticks.
    ///
    /// Maps to `ProjectionContinuityWindowV1` outage window span.
    pub outage_window_ticks: u64,

    /// Replay window duration in HTF ticks.
    ///
    /// Maps to `ProjectionContinuityWindowV1` replay window span.
    pub replay_window_ticks: u64,

    /// Maximum number of sink identity churn events tolerated within the
    /// outage window before continuity is denied.
    pub churn_tolerance: u32,

    /// Maximum number of network partition events tolerated within the
    /// outage window before continuity is denied.
    pub partition_tolerance: u32,

    /// Hex-encoded Ed25519 public keys of trusted signers for this sink.
    ///
    /// Each entry must be exactly 64 hex characters (32 bytes).
    /// Validated at config parse time -- invalid entries prevent daemon
    /// startup.
    pub trusted_signers: Vec<String>,
}

impl ProjectionConfig {
    /// Validates all configured sink profiles at startup (TCK-00507).
    ///
    /// Enforces:
    /// - Sink count within [`MAX_PROJECTION_SINKS`].
    /// - Sink ID is non-empty and within [`MAX_SINK_ID_CONFIG_LENGTH`].
    /// - Each sink has at least one trusted signer.
    /// - Trusted signer count within [`MAX_TRUSTED_SIGNERS_PER_SINK`].
    /// - Each trusted signer is valid hex encoding of exactly 32 bytes.
    /// - Outage/replay window ticks are non-zero.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first validation failure.
    /// Invalid keys prevent daemon startup (fail-closed).
    pub fn validate_sink_profiles(&self) -> Result<(), String> {
        let sink_count = self.sinks.len();
        // TCK-00502 MAJOR fix: enforce minimum 2 sinks at startup to match
        // the economics gate runtime requirement (REQ-0009 multi-sink
        // continuity requires >= 2 distinct sinks). A single-sink config
        // passes startup validation but is deterministically denied at
        // runtime by DENY_SINK_SNAPSHOT_INSUFFICIENT_SINKS, making the
        // deployment non-functional. Fail fast at startup instead.
        //
        // Zero sinks (no projection configured) is valid — the economics
        // gate simply has no sinks to evaluate.
        if sink_count == 1 {
            return Err(format!(
                "daemon.projection.sinks: at least 2 sinks required for multi-sink \
                 continuity (REQ-0009) when projection is configured, got {sink_count}; \
                 either add a second sink or remove projection configuration",
            ));
        }
        if sink_count > MAX_PROJECTION_SINKS {
            return Err(format!(
                "daemon.projection.sinks: too many sinks ({sink_count} > {MAX_PROJECTION_SINKS})",
            ));
        }
        for (sink_id, profile) in &self.sinks {
            if sink_id.is_empty() || sink_id.len() > MAX_SINK_ID_CONFIG_LENGTH {
                return Err(format!(
                    "daemon.projection.sinks: sink_id '{sink_id}' is empty or exceeds {MAX_SINK_ID_CONFIG_LENGTH} chars",
                ));
            }
            if profile.outage_window_ticks == 0 {
                return Err(format!(
                    "daemon.projection.sinks.{sink_id}: outage_window_ticks must be > 0",
                ));
            }
            if profile.replay_window_ticks == 0 {
                return Err(format!(
                    "daemon.projection.sinks.{sink_id}: replay_window_ticks must be > 0",
                ));
            }
            if profile.trusted_signers.is_empty() {
                return Err(format!(
                    "daemon.projection.sinks.{sink_id}: trusted_signers must not be empty",
                ));
            }
            let signer_count = profile.trusted_signers.len();
            if signer_count > MAX_TRUSTED_SIGNERS_PER_SINK {
                return Err(format!(
                    "daemon.projection.sinks.{sink_id}: too many trusted_signers ({signer_count} > {MAX_TRUSTED_SIGNERS_PER_SINK})",
                ));
            }
            for (i, hex_key) in profile.trusted_signers.iter().enumerate() {
                validate_trusted_signer_hex(sink_id, i, hex_key)?;
            }
        }
        Ok(())
    }
}

/// Validates a single hex-encoded Ed25519 public key at config parse time.
///
/// # Errors
///
/// Returns descriptive error for:
/// - Odd-length hex strings
/// - Non-hex characters
/// - Decoded key not exactly 32 bytes
fn validate_trusted_signer_hex(sink_id: &str, index: usize, hex_key: &str) -> Result<(), String> {
    // Check for odd length before attempting decode (specific error).
    let hex_len = hex_key.len();
    if hex_len % 2 != 0 {
        return Err(format!(
            "daemon.projection.sinks.{sink_id}: trusted_signers[{index}] \
             has odd-length hex ({hex_len} chars)",
        ));
    }
    let bytes = hex::decode(hex_key).map_err(|e| {
        format!(
            "daemon.projection.sinks.{sink_id}: trusted_signers[{index}] \
             invalid hex: {e}",
        )
    })?;
    let byte_len = bytes.len();
    if byte_len != 32 {
        return Err(format!(
            "daemon.projection.sinks.{sink_id}: trusted_signers[{index}] \
             decoded to {byte_len} bytes, expected 32",
        ));
    }
    // Validate the key is a valid Ed25519 point (not just any 32 bytes).
    // This catches keys that decode to valid-length bytes but are not
    // valid curve points.
    let key_bytes: [u8; 32] = bytes.try_into().expect("length checked above");
    ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
        format!(
            "daemon.projection.sinks.{sink_id}: trusted_signers[{index}] \
             not a valid Ed25519 public key: {e}",
        )
    })?;
    Ok(())
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
            ledger_db: default_ledger_db(),
            audit: AuditConfig::default(),
            projection: ProjectionConfig::default(),
            cas_path: None,
            divergence_watchdog: DivergenceWatchdogSection::default(),
            adapter_rotation: AdapterRotationConfig::default(),
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

    /// GitHub repository owner (e.g., "guardian-intelligence").
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

/// Returns the default APM2 data directory.
///
/// Resolution order:
/// 1. `APM2_DATA_DIR`
/// 2. platform data dir from `directories::ProjectDirs`
/// 3. `HOME` with fallback to `.local/share/apm2`
///
/// # Panics
/// This function panics if none of the above resolution methods produce a
/// directory path.
#[must_use]
pub fn default_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("APM2_DATA_DIR") {
        return PathBuf::from(dir);
    }
    directories::ProjectDirs::from("com", "apm2", "apm2")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| PathBuf::from(home).join(".local/share/apm2"))
        })
        .expect("cannot determine data directory: set APM2_DATA_DIR or HOME")
}

fn default_pid_file() -> PathBuf {
    // Use XDG_RUNTIME_DIR for PID file (ephemeral runtime data)
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| default_data_dir().join("apm2.pid"),
        |runtime_dir| PathBuf::from(runtime_dir).join("apm2").join("apm2.pid"),
    )
}

fn default_operator_socket() -> PathBuf {
    // Per TCK-00249: ${XDG_RUNTIME_DIR}/apm2/operator.sock
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| default_data_dir().join("operator.sock"),
        |runtime_dir| {
            PathBuf::from(runtime_dir)
                .join("apm2")
                .join("operator.sock")
        },
    )
}

fn default_session_socket() -> PathBuf {
    // Per TCK-00249: ${XDG_RUNTIME_DIR}/apm2/session.sock
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| default_data_dir().join("session.sock"),
        |runtime_dir| PathBuf::from(runtime_dir).join("apm2").join("session.sock"),
    )
}

fn default_log_dir() -> PathBuf {
    default_data_dir().join("logs")
}

fn default_state_file() -> PathBuf {
    default_data_dir().join("state.json")
}

#[allow(clippy::unnecessary_wraps)]
fn default_ledger_db() -> Option<PathBuf> {
    Some(default_data_dir().join("ledger.db"))
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

/// Maximum credential file size (4 KiB). Any file larger than this is
/// rejected to prevent unbounded memory allocation from attacker-controlled
/// file content (SECURITY BLOCKER fix).
const MAX_CREDENTIAL_FILE_SIZE: u64 = 4096;

/// Resolve a GitHub token value from available sources (TCK-00595 MAJOR FIX).
///
/// Resolution order:
/// 1. Environment variable named by `env_var_name` (e.g., `GITHUB_TOKEN`).
/// 2. Systemd credential directory: `$CREDENTIALS_DIRECTORY/gh-token`. This is
///    where `LoadCredential=gh-token:...` in the unit file places the token
///    when running under systemd.
/// 3. APM2 credential file: `$APM2_HOME/private/creds/gh-token` (direct file
///    fallback for non-systemd environments).
///
/// Returns the token as a `SecretString`, or `None` if no source provides a
/// value. The caller must use `.expose_secret()` to access the raw token.
///
/// # Security
///
/// - Credential files are opened with `O_NOFOLLOW` on Unix to prevent
///   symlink-based credential exfiltration attacks.
/// - File size is bounded to 4 KiB (`MAX_CREDENTIAL_FILE_SIZE`) to prevent
///   unbounded deserialization / memory exhaustion.
#[must_use]
pub fn resolve_github_token(env_var_name: &str) -> Option<secrecy::SecretString> {
    // 1. Standard env var
    if let Ok(val) = std::env::var(env_var_name) {
        if !val.is_empty() {
            return Some(secrecy::SecretString::from(val));
        }
    }

    // 2. Systemd credential directory ($CREDENTIALS_DIRECTORY/gh-token)
    if let Ok(cred_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let cred_path = std::path::Path::new(&cred_dir).join("gh-token");
        if let Some(secret) = read_credential_file_bounded(&cred_path) {
            return Some(secret);
        }
    }

    // 3. APM2 credential file fallback ($APM2_HOME/private/creds/gh-token)
    if let Some(apm2_home) = crate::github::resolve_apm2_home() {
        let cred_path = apm2_home.join("private/creds/gh-token");
        if let Some(secret) = read_credential_file_bounded(&cred_path) {
            return Some(secret);
        }
    }

    None
}

/// Read a credential file with bounded size and symlink protection.
///
/// Returns `None` if the file does not exist, is too large, is a symlink
/// (on Unix), or contains only whitespace.
fn read_credential_file_bounded(path: &std::path::Path) -> Option<secrecy::SecretString> {
    use std::io::Read;

    // Open with O_NOFOLLOW on Unix to reject symlinks
    let mut file = open_nofollow(path).ok()?;

    // Check file size before reading to prevent unbounded allocation
    let metadata = file.metadata().ok()?;
    if metadata.len() > MAX_CREDENTIAL_FILE_SIZE {
        return None;
    }

    // Safe: we verified metadata.len() <= MAX_CREDENTIAL_FILE_SIZE (4096) above,
    // which always fits in usize on any supported platform (>= 16-bit).
    let len: usize = usize::try_from(metadata.len()).ok()?;
    let mut contents = String::with_capacity(len);
    file.read_to_string(&mut contents).ok()?;

    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(secrecy::SecretString::from(trimmed.to_string()))
}

/// Open a file for reading, rejecting symlinks on Unix via `O_NOFOLLOW`.
#[cfg(unix)]
fn open_nofollow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Open a file for reading (non-Unix fallback — no symlink guard available).
#[cfg(not(unix))]
fn open_nofollow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
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
        assert_eq!(
            config.daemon.ledger_db,
            Some(default_data_dir().join("ledger.db"))
        );
        assert_eq!(config.daemon.audit.retention_days, 90);
        assert_eq!(config.daemon.audit.max_size_bytes, 536_870_912);
        assert_eq!(config.credentials.len(), 1);
        assert_eq!(config.processes[0].instances, 2);
    }

    #[test]
    fn test_parse_daemon_ledger_db_from_toml() {
        let toml = r#"
            [daemon]
            operator_socket = "/tmp/apm2/operator.sock"
            session_socket = "/tmp/apm2/session.sock"
            ledger_db = "/tmp/apm2/custom-ledger.db"

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let config = EcosystemConfig::from_toml(toml).expect("config should parse");
        assert_eq!(
            config.daemon.ledger_db,
            Some(PathBuf::from("/tmp/apm2/custom-ledger.db"))
        );
    }

    #[test]
    fn test_daemon_default_sets_ledger_db() {
        let config = EcosystemConfig::default();
        assert_eq!(
            config.daemon.ledger_db,
            Some(default_data_dir().join("ledger.db"))
        );
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

    #[test]
    fn test_default_adapter_rotation_config() {
        let config = EcosystemConfig::default();
        let rotation = &config.daemon.adapter_rotation;

        assert_eq!(
            rotation.strategy,
            AdapterRotationStrategyConfig::WeightedRandom
        );
        assert_eq!(rotation.rate_limit_backoff_secs, 300);
        assert_eq!(rotation.profiles.len(), 4);
        assert_eq!(rotation.profiles[0].profile_id, CLAUDE_CODE_PROFILE_ID);
        assert_eq!(rotation.profiles[0].weight, 100);
        assert!(rotation.profiles[0].enabled);
        assert!(rotation.validate().is_ok());
    }

    #[test]
    fn test_parse_adapter_rotation_section() {
        let toml = r#"
            [daemon]
            operator_socket = "/tmp/apm2/operator.sock"
            session_socket = "/tmp/apm2/session.sock"

            [daemon.adapter_rotation]
            strategy = "weighted_random"
            rate_limit_backoff_secs = 900

            [[daemon.adapter_rotation.profiles]]
            profile_id = "claude-code-v1"
            weight = 70
            enabled = true
            fallback_priority = 0

            [[daemon.adapter_rotation.profiles]]
            profile_id = "gemini-cli-v1"
            weight = 30
            enabled = true
            fallback_priority = 1

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let config = EcosystemConfig::from_toml(toml).expect("config should parse");
        assert_eq!(config.daemon.adapter_rotation.rate_limit_backoff_secs, 900);
        assert_eq!(
            config.daemon.adapter_rotation.strategy,
            AdapterRotationStrategyConfig::WeightedRandom
        );
        assert_eq!(config.daemon.adapter_rotation.profiles.len(), 2);
    }

    #[test]
    fn test_adapter_rotation_requires_enabled_profiles() {
        let toml = r#"
            [daemon]
            operator_socket = "/tmp/apm2/operator.sock"
            session_socket = "/tmp/apm2/session.sock"

            [daemon.adapter_rotation]
            strategy = "weighted_random"
            rate_limit_backoff_secs = 300

            [[daemon.adapter_rotation.profiles]]
            profile_id = "claude-code-v1"
            weight = 100
            enabled = false
            fallback_priority = 0

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let err = EcosystemConfig::from_toml(toml).expect_err("config should fail validation");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    /// TCK-00502 MAJOR fix: validates that `validate_sink_profiles()` rejects
    /// a single-sink configuration at startup, matching the economics gate
    /// runtime requirement of >= 2 distinct sinks (REQ-0009).
    #[test]
    fn test_validate_sink_profiles_rejects_single_sink() {
        let mut projection = ProjectionConfig::default();
        projection.sinks.insert(
            "sink-1".to_string(),
            ProjectionSinkProfileConfig {
                outage_window_ticks: 100,
                replay_window_ticks: 50,
                churn_tolerance: 3,
                partition_tolerance: 2,
                trusted_signers: vec![
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                ],
            },
        );

        let result = projection.validate_sink_profiles();
        assert!(
            result.is_err(),
            "single-sink config must be rejected at startup"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("at least 2 sinks"),
            "error must mention minimum sink count: {err}"
        );
    }

    /// TCK-00502: validates that `validate_sink_profiles()` accepts a
    /// two-sink configuration.
    #[test]
    fn test_validate_sink_profiles_accepts_two_sinks() {
        let mut projection = ProjectionConfig::default();
        let profile = ProjectionSinkProfileConfig {
            outage_window_ticks: 100,
            replay_window_ticks: 50,
            churn_tolerance: 3,
            partition_tolerance: 2,
            trusted_signers: vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ],
        };
        projection
            .sinks
            .insert("sink-1".to_string(), profile.clone());
        projection.sinks.insert("sink-2".to_string(), profile);

        let result = projection.validate_sink_profiles();
        assert!(
            result.is_ok(),
            "two-sink config must be accepted: {result:?}"
        );
    }

    /// TCK-00502: validates that empty sinks configuration is accepted
    /// (no projection configured is a valid deployment).
    #[test]
    fn test_validate_sink_profiles_accepts_empty_sinks() {
        let projection = ProjectionConfig::default();
        let result = projection.validate_sink_profiles();
        assert!(
            result.is_ok(),
            "empty sinks config must be accepted (no projection): {result:?}"
        );
    }

    /// TCK-00595: `from_env()` produces a valid default config with XDG paths.
    #[test]
    fn test_from_env_produces_defaults() {
        // from_env() should never panic regardless of environment state.
        let config = EcosystemConfig::from_env();
        // Operator and session sockets should be non-empty paths
        assert!(
            !config.daemon.operator_socket.as_os_str().is_empty(),
            "operator_socket must have a default path"
        );
        assert!(
            !config.daemon.session_socket.as_os_str().is_empty(),
            "session_socket must have a default path"
        );
    }

    /// TCK-00595 MAJOR FIX: `resolve_github_token` does not panic when
    /// called with any env var name, including ones that do not exist.
    #[test]
    fn test_resolve_github_token_no_panic_on_missing_var() {
        // Env var that does not exist — function should return None or
        // fall through to credential file checks without panicking.
        let result = resolve_github_token("APM2_TEST_TOKEN_NONEXISTENT_VAR_12345");
        // We cannot guarantee None because $CREDENTIALS_DIRECTORY or
        // $APM2_HOME/private/creds/gh-token might exist in the test env.
        // The key assertion is: no panic.
        let _ = result;
    }

    /// TCK-00595 MAJOR FIX: `resolve_github_token` returns the env var
    /// value when the env var is set (tested via a known-set variable).
    #[test]
    fn test_resolve_github_token_reads_env_var() {
        // PATH is always set on any unix system — use it as a proxy to
        // verify the env var reading path works (not a real token, just
        // verifying the function reads env vars correctly).
        let result = resolve_github_token("PATH");
        assert!(
            result.is_some(),
            "resolve_github_token should return Some for a set env var"
        );
    }

    /// TCK-00595 SECURITY BLOCKER FIX: `resolve_github_token` returns
    /// `SecretString` so tokens are not leaked via Debug/Display.
    #[test]
    fn test_resolve_github_token_returns_secret_string() {
        use secrecy::ExposeSecret;
        // Use PATH as a known-set env var.
        let result = resolve_github_token("PATH");
        if let Some(secret) = result {
            // Verify we can expose the secret and it's non-empty.
            let exposed = secret.expose_secret();
            assert!(!exposed.is_empty());
            // Verify Debug does NOT leak the secret value.
            let debug_str = format!("{secret:?}");
            assert!(
                !debug_str.contains(exposed),
                "SecretString Debug must redact the secret value"
            );
        }
    }

    /// TCK-00595 SECURITY BLOCKER FIX: `read_credential_file_bounded`
    /// rejects files larger than `MAX_CREDENTIAL_FILE_SIZE`.
    #[test]
    fn test_read_credential_file_bounded_rejects_oversize() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let file_path = dir.path().join("oversize-cred");
        // Write a file that exceeds the 4 KiB bound.
        #[allow(clippy::cast_possible_truncation)]
        // MAX_CREDENTIAL_FILE_SIZE is 4096, fits in usize
        let oversize = "x".repeat((super::MAX_CREDENTIAL_FILE_SIZE + 1) as usize);
        std::fs::write(&file_path, &oversize).expect("write oversize file");
        assert!(
            super::read_credential_file_bounded(&file_path).is_none(),
            "read_credential_file_bounded must reject files > MAX_CREDENTIAL_FILE_SIZE"
        );
    }

    /// TCK-00595 SECURITY BLOCKER FIX: `read_credential_file_bounded`
    /// rejects symlinks (on Unix, via `O_NOFOLLOW`).
    #[cfg(unix)]
    #[test]
    fn test_read_credential_file_bounded_rejects_symlinks() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let real_file = dir.path().join("real-cred");
        std::fs::write(&real_file, "secret-token").expect("write real file");
        let symlink_path = dir.path().join("symlink-cred");
        std::os::unix::fs::symlink(&real_file, &symlink_path).expect("create symlink");
        assert!(
            super::read_credential_file_bounded(&symlink_path).is_none(),
            "read_credential_file_bounded must reject symlinks"
        );
    }

    /// TCK-00595 SECURITY FIX: `read_credential_file_bounded` reads valid
    /// credential files that are within the size bound.
    #[test]
    fn test_read_credential_file_bounded_reads_valid_file() {
        use secrecy::ExposeSecret;
        let dir = tempfile::tempdir().expect("create temp dir");
        let file_path = dir.path().join("valid-cred");
        std::fs::write(&file_path, "  my-secret-token  \n").expect("write valid file");
        let result = super::read_credential_file_bounded(&file_path);
        assert!(result.is_some(), "should read valid credential file");
        assert_eq!(
            result.unwrap().expose_secret(),
            "my-secret-token",
            "should trim whitespace from credential file"
        );
    }
}
