// AGENT-AUTHORED
//! Agent adapter profile types for FAC v0 heterogeneous agent integration.
//!
//! This module implements the `AgentAdapterProfileV1` structure used to define
//! how third-party coding agents (Claude Code, Gemini CLI, Codex CLI) are
//! integrated under holonic boundary discipline.
//!
//! # Overview
//!
//! Per RFC-0019 Addendum (`11_agent_adapter_profiles.md`), the agent process is
//! treated as an untrusted black-box proposer. The kernel is the only actuator:
//! all tools are executed kernel-side under policy, budgets, and durable ledger
//! events.
//!
//! `AgentAdapterProfileV1` is a CAS-addressed artifact. Profile selection is
//! explicit by hash; **ambient defaults are forbidden**.
//!
//! # Security Properties
//!
//! - **CAS Storage**: Profile is stored in CAS and referenced by hash
//! - **No Ambient Defaults**: Profiles must be explicitly selected by hash
//! - **Boundary Discipline**: Agent output is advisory; ledger is authoritative
//!
//! # Example
//!
//! ```rust
//! use std::collections::BTreeMap;
//!
//! use apm2_core::fac::{
//!     AdapterMode, AgentAdapterProfileV1, BudgetDefaults, EvidencePolicy, HealthChecks,
//!     InputMode, OutputMode, VersionProbe,
//! };
//!
//! let profile = AgentAdapterProfileV1::builder()
//!     .profile_id("claude-code-v1")
//!     .adapter_mode(AdapterMode::BlackBox)
//!     .command("/usr/bin/claude")
//!     .args_template(vec!["-p".to_string()])
//!     .env_template(vec![("CLAUDE_NO_TOOLS".to_string(), "1".to_string())])
//!     .cwd("/workspace")
//!     .requires_pty(false)
//!     .input_mode(InputMode::Stdin)
//!     .output_mode(OutputMode::Raw)
//!     .permission_mode_map(BTreeMap::new())
//!     .capability_map(BTreeMap::new())
//!     .version_probe(VersionProbe::new(
//!         "claude --version",
//!         r"claude (\d+\.\d+\.\d+)",
//!     ))
//!     .health_checks(HealthChecks::default())
//!     .budget_defaults(BudgetDefaults::default())
//!     .evidence_policy(EvidencePolicy::default())
//!     .build()
//!     .expect("valid profile");
//!
//! assert!(profile.validate().is_ok());
//! let cas_hash = profile.compute_cas_hash().expect("hash computation");
//! ```

use std::collections::BTreeMap;
use std::str::FromStr;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence::{CasError, ContentAddressedStore};
use crate::htf::Canonicalizable;

// =============================================================================
// Schema Constants and Limits
// =============================================================================

/// Agent Adapter Profile V1 schema identifier.
pub const AGENT_ADAPTER_PROFILE_V1_SCHEMA: &str = "apm2.agent_adapter_profile.v1";

/// Maximum length for `profile_id` field.
pub const MAX_PROFILE_ID_LENGTH: usize = 256;

/// Maximum length for `command` field.
pub const MAX_COMMAND_LENGTH: usize = 4096;

/// Maximum number of arguments in `args_template`.
pub const MAX_ARGS_COUNT: usize = 256;

/// Maximum length for each argument in `args_template`.
pub const MAX_ARG_LENGTH: usize = 4096;

/// Maximum number of environment variables in `env_template`.
pub const MAX_ENV_COUNT: usize = 128;

/// Maximum length for environment variable keys.
pub const MAX_ENV_KEY_LENGTH: usize = 256;

/// Maximum length for environment variable values.
pub const MAX_ENV_VALUE_LENGTH: usize = 4096;

/// Maximum length for `cwd` field.
pub const MAX_CWD_LENGTH: usize = 4096;

/// Maximum number of permission mode mappings.
pub const MAX_PERMISSION_MODE_MAP_COUNT: usize = 64;

/// Maximum length for permission mode map keys.
pub const MAX_PERMISSION_MODE_KEY_LENGTH: usize = 256;

/// Maximum number of flags per permission mode.
pub const MAX_PERMISSION_MODE_FLAGS_COUNT: usize = 32;

/// Maximum length for each permission mode flag.
pub const MAX_PERMISSION_MODE_FLAG_LENGTH: usize = 256;

/// Maximum number of capability mappings.
pub const MAX_CAPABILITY_MAP_COUNT: usize = 128;

/// Maximum length for capability map keys.
pub const MAX_CAPABILITY_MAP_KEY_LENGTH: usize = 256;

/// Maximum length for capability map values.
pub const MAX_CAPABILITY_MAP_VALUE_LENGTH: usize = 256;

/// Maximum length for version probe command.
pub const MAX_VERSION_PROBE_COMMAND_LENGTH: usize = 4096;

/// Maximum length for version probe regex.
pub const MAX_VERSION_PROBE_REGEX_LENGTH: usize = 1024;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during agent adapter profile operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AgentAdapterProfileError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Invalid schema identifier.
    #[error("invalid schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema.
        expected: String,
        /// Actual schema.
        actual: String,
    },

    /// Invalid adapter mode.
    #[error("invalid adapter mode: {0}")]
    InvalidAdapterMode(String),

    /// Invalid input mode.
    #[error("invalid input mode: {0}")]
    InvalidInputMode(String),

    /// Invalid output mode.
    #[error("invalid output mode: {0}")]
    InvalidOutputMode(String),

    /// Collection field exceeds maximum count.
    #[error("collection field '{field}' exceeds maximum count ({count} > {max})")]
    CollectionTooLarge {
        /// The field name.
        field: &'static str,
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Invalid regex in version probe.
    #[error("invalid regex in version probe: {0}")]
    InvalidRegex(String),

    /// Invalid path.
    #[error("invalid path in field '{field}': {reason}")]
    InvalidPath {
        /// The field name containing the invalid path.
        field: &'static str,
        /// The reason why the path is invalid.
        reason: String,
    },

    /// Invalid tool bridge config.
    #[error("invalid tool bridge config: {0}")]
    InvalidToolBridge(String),

    /// CAS error.
    #[error("CAS error: {0}")]
    CasError(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),
}

impl From<CasError> for AgentAdapterProfileError {
    fn from(e: CasError) -> Self {
        Self::CasError(e.to_string())
    }
}

// =============================================================================
// Enums
// =============================================================================

/// Adapter mode defining how the agent process communicates with the kernel.
///
/// Per RFC-0019 Addendum, the adapter mode determines the tool bridging option:
/// - `BlackBox`: Option C - Black-box ledger-mediated driver (default for FAC
///   v0)
/// - `StructuredOutput`: Option B - Structured output parsing (JSONL /
///   stream-json)
/// - `McpBridge`: Option A - MCP bridge
/// - `HookedVendor`: Vendor-specific hooked integration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterMode {
    /// Black-box ledger-mediated driver (default for FAC v0).
    ///
    /// Agent is run with native tools disabled/restricted. Agent emits a
    /// minimal, bounded `ToolIntent` grammar. Kernel validates, policy-checks,
    /// and executes tools; results are injected back as `ToolResult` envelopes.
    BlackBox,

    /// Structured output parsing (JSONL / stream-json).
    ///
    /// Allowed only when vendor output format is stable and version-pinned.
    /// Agent runs in vendor structured mode. Adapter parses tool request events
    /// from stdout.
    StructuredOutput,

    /// MCP bridge.
    ///
    /// Kernel exposes MCP tool schemas. Agent connects via MCP client
    /// configuration. Allowed but not preferred for v0.
    McpBridge,

    /// Vendor-specific hooked integration.
    ///
    /// For agents with native hook APIs that can be intercepted.
    HookedVendor,
}

impl std::fmt::Display for AdapterMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlackBox => write!(f, "black_box"),
            Self::StructuredOutput => write!(f, "structured_output"),
            Self::McpBridge => write!(f, "mcp_bridge"),
            Self::HookedVendor => write!(f, "hooked_vendor"),
        }
    }
}

impl FromStr for AdapterMode {
    type Err = AgentAdapterProfileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "black_box" => Ok(Self::BlackBox),
            "structured_output" => Ok(Self::StructuredOutput),
            "mcp_bridge" => Ok(Self::McpBridge),
            "hooked_vendor" => Ok(Self::HookedVendor),
            _ => Err(AgentAdapterProfileError::InvalidAdapterMode(s.to_string())),
        }
    }
}

/// Input mode defining how prompts/requests are delivered to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputMode {
    /// Input is passed as a command-line argument.
    Arg,
    /// Input is passed via stdin.
    Stdin,
    /// Input is passed via a file path argument.
    File,
    /// Input is streamed as JSON via stdin.
    StreamJson,
}

impl std::fmt::Display for InputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Arg => write!(f, "arg"),
            Self::Stdin => write!(f, "stdin"),
            Self::File => write!(f, "file"),
            Self::StreamJson => write!(f, "stream_json"),
        }
    }
}

impl FromStr for InputMode {
    type Err = AgentAdapterProfileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "arg" => Ok(Self::Arg),
            "stdin" => Ok(Self::Stdin),
            "file" => Ok(Self::File),
            "stream_json" => Ok(Self::StreamJson),
            _ => Err(AgentAdapterProfileError::InvalidInputMode(s.to_string())),
        }
    }
}

/// Output mode defining how the agent's responses are captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    /// Raw text output.
    Raw,
    /// Single JSON object output.
    Json,
    /// JSON Lines (newline-delimited JSON) output.
    Jsonl,
    /// Streaming JSON output.
    StreamJson,
}

impl std::fmt::Display for OutputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw => write!(f, "raw"),
            Self::Json => write!(f, "json"),
            Self::Jsonl => write!(f, "jsonl"),
            Self::StreamJson => write!(f, "stream_json"),
        }
    }
}

impl FromStr for OutputMode {
    type Err = AgentAdapterProfileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raw" => Ok(Self::Raw),
            "json" => Ok(Self::Json),
            "jsonl" => Ok(Self::Jsonl),
            "stream_json" => Ok(Self::StreamJson),
            _ => Err(AgentAdapterProfileError::InvalidOutputMode(s.to_string())),
        }
    }
}

// =============================================================================
// Sub-structs
// =============================================================================

/// Configuration for tool bridging between agent and kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBridgeConfig {
    /// Whether tool bridging is enabled.
    pub enabled: bool,

    /// The tool intent protocol version (e.g., "TI1" for `ToolIntentV1`).
    pub protocol_version: String,

    /// Nonce prefix for tool intent framing.
    pub nonce_prefix: String,

    /// Maximum size of tool arguments in bytes.
    pub max_args_size: usize,

    /// Maximum size of tool results in bytes.
    pub max_result_size: usize,

    /// Timeout for tool execution in milliseconds.
    pub tool_timeout_ms: u64,
}

impl ToolBridgeConfig {
    /// Validates the tool bridge configuration.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails (e.g. zero timeout).
    pub fn validate(&self) -> Result<(), AgentAdapterProfileError> {
        if self.tool_timeout_ms == 0 {
            return Err(AgentAdapterProfileError::InvalidToolBridge(
                "tool_timeout_ms must be non-zero".to_string(),
            ));
        }
        if self.max_args_size == 0 {
            return Err(AgentAdapterProfileError::InvalidToolBridge(
                "max_args_size must be non-zero".to_string(),
            ));
        }
        if self.max_result_size == 0 {
            return Err(AgentAdapterProfileError::InvalidToolBridge(
                "max_result_size must be non-zero".to_string(),
            ));
        }
        if self.max_args_size > 100 * 1024 * 1024 {
            // 100MB limit
            return Err(AgentAdapterProfileError::InvalidToolBridge(
                "max_args_size exceeds safety limit (100MB)".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for ToolBridgeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protocol_version: "TI1".to_string(),
            nonce_prefix: String::new(),
            max_args_size: 1024 * 1024,   // 1 MB
            max_result_size: 1024 * 1024, // 1 MB
            tool_timeout_ms: 60_000,      // 60 seconds
        }
    }
}

/// Version probe configuration for detecting agent CLI version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionProbe {
    /// Command to run to get version (e.g., "claude --version").
    pub command: String,

    /// Regex to extract version from command output.
    pub regex: String,
}

impl VersionProbe {
    /// Creates a new version probe configuration.
    #[must_use]
    pub fn new(command: impl Into<String>, regex: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            regex: regex.into(),
        }
    }

    /// Validates the version probe configuration.
    ///
    /// # Errors
    ///
    /// Returns error if command or regex exceeds maximum length, or regex is
    /// invalid.
    pub fn validate(&self) -> Result<(), AgentAdapterProfileError> {
        if self.command.is_empty() {
            return Err(AgentAdapterProfileError::MissingField(
                "version_probe.command",
            ));
        }
        if self.command.len() > MAX_VERSION_PROBE_COMMAND_LENGTH {
            return Err(AgentAdapterProfileError::StringTooLong {
                field: "version_probe.command",
                len: self.command.len(),
                max: MAX_VERSION_PROBE_COMMAND_LENGTH,
            });
        }
        if self.regex.is_empty() {
            return Err(AgentAdapterProfileError::MissingField(
                "version_probe.regex",
            ));
        }
        if self.regex.len() > MAX_VERSION_PROBE_REGEX_LENGTH {
            return Err(AgentAdapterProfileError::StringTooLong {
                field: "version_probe.regex",
                len: self.regex.len(),
                max: MAX_VERSION_PROBE_REGEX_LENGTH,
            });
        }

        // Compile regex to validate syntax
        Regex::new(&self.regex)
            .map_err(|e| AgentAdapterProfileError::InvalidRegex(e.to_string()))?;

        Ok(())
    }
}

/// Health check configuration for agent process monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthChecks {
    /// Startup timeout in milliseconds.
    pub startup_timeout_ms: u64,

    /// Heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: u64,

    /// Heartbeat timeout in milliseconds.
    pub heartbeat_timeout_ms: u64,

    /// Stall detection threshold in milliseconds (no output).
    pub stall_threshold_ms: u64,

    /// Maximum consecutive stalls before termination.
    pub max_stalls: u32,
}

impl Default for HealthChecks {
    fn default() -> Self {
        Self {
            startup_timeout_ms: 30_000,   // 30 seconds
            heartbeat_interval_ms: 5_000, // 5 seconds
            heartbeat_timeout_ms: 15_000, // 15 seconds
            stall_threshold_ms: 120_000,  // 2 minutes
            max_stalls: 3,
        }
    }
}

/// Budget defaults for agent execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetDefaults {
    /// Maximum number of tool calls per episode.
    pub max_tool_calls: u32,

    /// Maximum tokens (input + output) per episode.
    pub max_tokens: u64,

    /// Maximum wall clock time per episode in milliseconds.
    pub max_wall_clock_ms: u64,

    /// Maximum evidence size per episode in bytes.
    pub max_evidence_bytes: u64,
}

impl Default for BudgetDefaults {
    fn default() -> Self {
        Self {
            max_tool_calls: 100,
            max_tokens: 1_000_000,
            max_wall_clock_ms: 3_600_000,          // 1 hour
            max_evidence_bytes: 100 * 1024 * 1024, // 100 MB
        }
    }
}

/// Evidence policy controlling what is recorded vs discarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct EvidencePolicy {
    /// Whether to record full agent output.
    pub record_full_output: bool,

    /// Whether to record tool request/response pairs.
    pub record_tool_traces: bool,

    /// Whether to record timing information.
    pub record_timing: bool,

    /// Whether to record token usage.
    pub record_token_usage: bool,

    /// Maximum output size to record in bytes (truncate if exceeded).
    pub max_recorded_output_bytes: u64,

    /// Whether to redact sensitive patterns from recorded output.
    pub redact_sensitive: bool,
}

impl Default for EvidencePolicy {
    fn default() -> Self {
        Self {
            record_full_output: true,
            record_tool_traces: true,
            record_timing: true,
            record_token_usage: true,
            max_recorded_output_bytes: 10 * 1024 * 1024, // 10 MB
            redact_sensitive: true,
        }
    }
}

// =============================================================================
// AgentAdapterProfileV1
// =============================================================================

/// Agent Adapter Profile V1.
///
/// Defines how a third-party coding agent is integrated with the APM2 kernel
/// under holonic boundary discipline. This profile is stored in CAS and
/// selected by hash; ambient defaults are forbidden.
///
/// # Security Properties
///
/// - **Boundary Discipline**: Agent process is untrusted black-box proposer
/// - **Kernel Authority**: All tools are executed kernel-side under policy
/// - **CAS Binding**: Profile is content-addressed for integrity
/// - **No Ambient Defaults**: Must be explicitly selected by hash
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAdapterProfileV1 {
    /// Schema identifier (always `apm2.agent_adapter_profile.v1`).
    pub schema: String,

    /// Stable profile identifier (e.g., "claude-code-v1").
    pub profile_id: String,

    /// Adapter mode defining tool bridging option.
    pub adapter_mode: AdapterMode,

    /// Executable command path.
    pub command: String,

    /// Ordered argument template.
    pub args_template: Vec<String>,

    /// Ordered environment variable template (key-value pairs).
    /// Uses Vec for deterministic serialization order.
    pub env_template: Vec<(String, String)>,

    /// Working directory for the agent process.
    pub cwd: String,

    /// Whether the agent requires a PTY.
    pub requires_pty: bool,

    /// Input mode for delivering prompts.
    pub input_mode: InputMode,

    /// Output mode for capturing responses.
    pub output_mode: OutputMode,

    /// Policy tiers to CLI flags mapping.
    /// Uses `BTreeMap` for ordered serialization.
    pub permission_mode_map: BTreeMap<String, Vec<String>>,

    /// Optional tool bridging configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_bridge: Option<ToolBridgeConfig>,

    /// External tool intents to kernel tool classes mapping.
    /// Uses `BTreeMap` for ordered serialization.
    pub capability_map: BTreeMap<String, String>,

    /// Version probe configuration.
    pub version_probe: VersionProbe,

    /// Health check configuration.
    pub health_checks: HealthChecks,

    /// Budget defaults for execution.
    pub budget_defaults: BudgetDefaults,

    /// Evidence policy for recording.
    pub evidence_policy: EvidencePolicy,
}

impl AgentAdapterProfileV1 {
    /// Creates a new builder for `AgentAdapterProfileV1`.
    #[must_use]
    pub fn builder() -> AgentAdapterProfileV1Builder {
        AgentAdapterProfileV1Builder::default()
    }

    /// Validates the agent adapter profile.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails:
    /// - Schema identifier is invalid
    /// - Required fields are empty
    /// - String fields exceed maximum length
    /// - Collection fields exceed maximum count
    /// - Path traversal in paths
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), AgentAdapterProfileError> {
        // Validate schema
        if self.schema != AGENT_ADAPTER_PROFILE_V1_SCHEMA {
            return Err(AgentAdapterProfileError::InvalidSchema {
                expected: AGENT_ADAPTER_PROFILE_V1_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        // Validate profile_id
        if self.profile_id.is_empty() {
            return Err(AgentAdapterProfileError::MissingField("profile_id"));
        }
        if self.profile_id.len() > MAX_PROFILE_ID_LENGTH {
            return Err(AgentAdapterProfileError::StringTooLong {
                field: "profile_id",
                len: self.profile_id.len(),
                max: MAX_PROFILE_ID_LENGTH,
            });
        }

        // Validate command
        if self.command.is_empty() {
            return Err(AgentAdapterProfileError::MissingField("command"));
        }
        if self.command.len() > MAX_COMMAND_LENGTH {
            return Err(AgentAdapterProfileError::StringTooLong {
                field: "command",
                len: self.command.len(),
                max: MAX_COMMAND_LENGTH,
            });
        }
        // Path Traversal Check for command
        if self.command.contains("..") {
            return Err(AgentAdapterProfileError::InvalidPath {
                field: "command",
                reason: "path traversal sequences not allowed".to_string(),
            });
        }

        // Validate args_template
        if self.args_template.len() > MAX_ARGS_COUNT {
            return Err(AgentAdapterProfileError::CollectionTooLarge {
                field: "args_template",
                count: self.args_template.len(),
                max: MAX_ARGS_COUNT,
            });
        }
        for (i, arg) in self.args_template.iter().enumerate() {
            if arg.len() > MAX_ARG_LENGTH {
                return Err(AgentAdapterProfileError::StringTooLong {
                    field: "args_template",
                    len: arg.len(),
                    max: MAX_ARG_LENGTH,
                });
            }
            // Empty args are allowed (for positional placeholders)
            let _ = i; // Suppress unused warning
        }

        // Validate env_template
        if self.env_template.len() > MAX_ENV_COUNT {
            return Err(AgentAdapterProfileError::CollectionTooLarge {
                field: "env_template",
                count: self.env_template.len(),
                max: MAX_ENV_COUNT,
            });
        }
        for (key, value) in &self.env_template {
            if key.len() > MAX_ENV_KEY_LENGTH {
                return Err(AgentAdapterProfileError::StringTooLong {
                    field: "env_template.key",
                    len: key.len(),
                    max: MAX_ENV_KEY_LENGTH,
                });
            }
            if value.len() > MAX_ENV_VALUE_LENGTH {
                return Err(AgentAdapterProfileError::StringTooLong {
                    field: "env_template.value",
                    len: value.len(),
                    max: MAX_ENV_VALUE_LENGTH,
                });
            }
            // Syntax check: alphanumeric + underscore
            if !key.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Err(AgentAdapterProfileError::InvalidPath {
                    field: "env_template.key",
                    reason: format!("invalid env key syntax: {key}"),
                });
            }
        }

        // Validate cwd
        if self.cwd.is_empty() {
            return Err(AgentAdapterProfileError::MissingField("cwd"));
        }
        if self.cwd.len() > MAX_CWD_LENGTH {
            return Err(AgentAdapterProfileError::StringTooLong {
                field: "cwd",
                len: self.cwd.len(),
                max: MAX_CWD_LENGTH,
            });
        }
        // Path Traversal Check for cwd
        if self.cwd.contains("..") {
            return Err(AgentAdapterProfileError::InvalidPath {
                field: "cwd",
                reason: "path traversal sequences not allowed".to_string(),
            });
        }

        // Validate permission_mode_map
        if self.permission_mode_map.len() > MAX_PERMISSION_MODE_MAP_COUNT {
            return Err(AgentAdapterProfileError::CollectionTooLarge {
                field: "permission_mode_map",
                count: self.permission_mode_map.len(),
                max: MAX_PERMISSION_MODE_MAP_COUNT,
            });
        }
        for (key, flags) in &self.permission_mode_map {
            if key.len() > MAX_PERMISSION_MODE_KEY_LENGTH {
                return Err(AgentAdapterProfileError::StringTooLong {
                    field: "permission_mode_map.key",
                    len: key.len(),
                    max: MAX_PERMISSION_MODE_KEY_LENGTH,
                });
            }
            if flags.len() > MAX_PERMISSION_MODE_FLAGS_COUNT {
                return Err(AgentAdapterProfileError::CollectionTooLarge {
                    field: "permission_mode_map.flags",
                    count: flags.len(),
                    max: MAX_PERMISSION_MODE_FLAGS_COUNT,
                });
            }
            for flag in flags {
                if flag.len() > MAX_PERMISSION_MODE_FLAG_LENGTH {
                    return Err(AgentAdapterProfileError::StringTooLong {
                        field: "permission_mode_map.flag",
                        len: flag.len(),
                        max: MAX_PERMISSION_MODE_FLAG_LENGTH,
                    });
                }
            }
        }

        // Validate capability_map
        if self.capability_map.len() > MAX_CAPABILITY_MAP_COUNT {
            return Err(AgentAdapterProfileError::CollectionTooLarge {
                field: "capability_map",
                count: self.capability_map.len(),
                max: MAX_CAPABILITY_MAP_COUNT,
            });
        }
        for (key, value) in &self.capability_map {
            if key.len() > MAX_CAPABILITY_MAP_KEY_LENGTH {
                return Err(AgentAdapterProfileError::StringTooLong {
                    field: "capability_map.key",
                    len: key.len(),
                    max: MAX_CAPABILITY_MAP_KEY_LENGTH,
                });
            }
            if value.len() > MAX_CAPABILITY_MAP_VALUE_LENGTH {
                return Err(AgentAdapterProfileError::StringTooLong {
                    field: "capability_map.value",
                    len: value.len(),
                    max: MAX_CAPABILITY_MAP_VALUE_LENGTH,
                });
            }
        }

        // Validate version_probe
        self.version_probe.validate()?;

        // Validate tool_bridge if present
        if let Some(tb) = &self.tool_bridge {
            tb.validate()?;
        }

        Ok(())
    }

    /// Computes the CAS hash of this profile.
    ///
    /// Uses RFC 8785 canonical JSON serialization via the `Canonicalizable`
    /// trait to ensure deterministic hashing.
    ///
    /// # Errors
    ///
    /// Returns error if canonicalization fails.
    pub fn compute_cas_hash(&self) -> Result<[u8; 32], AgentAdapterProfileError> {
        self.canonical_bytes()
            .map(|bytes| *blake3::hash(&bytes).as_bytes())
            .map_err(|e| {
                AgentAdapterProfileError::SerializationError(format!(
                    "canonicalization failed: {e}"
                ))
            })
    }

    /// Stores this profile in CAS and returns its hash.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails or CAS storage fails.
    pub fn store_in_cas(
        &self,
        cas: &dyn ContentAddressedStore,
    ) -> Result<[u8; 32], AgentAdapterProfileError> {
        // Validate before storing
        self.validate()?;

        // Canonicalize
        let bytes = self.canonical_bytes().map_err(|e| {
            AgentAdapterProfileError::SerializationError(format!("canonicalization failed: {e}"))
        })?;

        // Store in CAS
        let result = cas.store(&bytes)?;

        Ok(result.hash)
    }

    /// Loads a profile from CAS by hash.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Content is not found in CAS
    /// - Content cannot be deserialized
    /// - Loaded profile fails validation
    pub fn load_from_cas(
        cas: &dyn ContentAddressedStore,
        hash: &[u8; 32],
    ) -> Result<Self, AgentAdapterProfileError> {
        // Retrieve from CAS
        let bytes = cas.retrieve(hash)?;

        // Deserialize
        let profile: Self = serde_json::from_slice(&bytes).map_err(|e| {
            AgentAdapterProfileError::SerializationError(format!("deserialization failed: {e}"))
        })?;

        // Validate loaded profile
        profile.validate()?;

        // Verify hash matches
        let computed_hash = profile.compute_cas_hash()?;
        if computed_hash != *hash {
            return Err(AgentAdapterProfileError::CasError(format!(
                "hash mismatch: expected {}, got {}",
                hex::encode(hash),
                hex::encode(computed_hash)
            )));
        }

        Ok(profile)
    }
}

// =============================================================================
// AgentAdapterProfileV1Builder
// =============================================================================

/// Builder for constructing an `AgentAdapterProfileV1`.
#[derive(Debug, Default)]
pub struct AgentAdapterProfileV1Builder {
    profile_id: Option<String>,
    adapter_mode: Option<AdapterMode>,
    command: Option<String>,
    args_template: Option<Vec<String>>,
    env_template: Option<Vec<(String, String)>>,
    cwd: Option<String>,
    requires_pty: Option<bool>,
    input_mode: Option<InputMode>,
    output_mode: Option<OutputMode>,
    permission_mode_map: Option<BTreeMap<String, Vec<String>>>,
    tool_bridge: Option<ToolBridgeConfig>,
    capability_map: Option<BTreeMap<String, String>>,
    version_probe: Option<VersionProbe>,
    health_checks: Option<HealthChecks>,
    budget_defaults: Option<BudgetDefaults>,
    evidence_policy: Option<EvidencePolicy>,
}

#[allow(clippy::missing_const_for_fn)] // Builder methods take `mut self` and can't be const
impl AgentAdapterProfileV1Builder {
    /// Sets the profile ID.
    #[must_use]
    pub fn profile_id(mut self, id: impl Into<String>) -> Self {
        self.profile_id = Some(id.into());
        self
    }

    /// Sets the adapter mode.
    #[must_use]
    pub fn adapter_mode(mut self, mode: AdapterMode) -> Self {
        self.adapter_mode = Some(mode);
        self
    }

    /// Sets the command.
    #[must_use]
    pub fn command(mut self, cmd: impl Into<String>) -> Self {
        self.command = Some(cmd.into());
        self
    }

    /// Sets the args template.
    #[must_use]
    pub fn args_template(mut self, args: Vec<String>) -> Self {
        self.args_template = Some(args);
        self
    }

    /// Sets the env template.
    #[must_use]
    pub fn env_template(mut self, env: Vec<(String, String)>) -> Self {
        self.env_template = Some(env);
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets whether a PTY is required.
    #[must_use]
    pub fn requires_pty(mut self, requires: bool) -> Self {
        self.requires_pty = Some(requires);
        self
    }

    /// Sets the input mode.
    #[must_use]
    pub fn input_mode(mut self, mode: InputMode) -> Self {
        self.input_mode = Some(mode);
        self
    }

    /// Sets the output mode.
    #[must_use]
    pub fn output_mode(mut self, mode: OutputMode) -> Self {
        self.output_mode = Some(mode);
        self
    }

    /// Sets the permission mode map.
    #[must_use]
    pub fn permission_mode_map(mut self, map: BTreeMap<String, Vec<String>>) -> Self {
        self.permission_mode_map = Some(map);
        self
    }

    /// Sets the tool bridge configuration.
    #[must_use]
    pub fn tool_bridge(mut self, config: ToolBridgeConfig) -> Self {
        self.tool_bridge = Some(config);
        self
    }

    /// Sets the capability map.
    #[must_use]
    pub fn capability_map(mut self, map: BTreeMap<String, String>) -> Self {
        self.capability_map = Some(map);
        self
    }

    /// Sets the version probe.
    #[must_use]
    pub fn version_probe(mut self, probe: VersionProbe) -> Self {
        self.version_probe = Some(probe);
        self
    }

    /// Sets the health checks.
    #[must_use]
    pub fn health_checks(mut self, checks: HealthChecks) -> Self {
        self.health_checks = Some(checks);
        self
    }

    /// Sets the budget defaults.
    #[must_use]
    pub fn budget_defaults(mut self, defaults: BudgetDefaults) -> Self {
        self.budget_defaults = Some(defaults);
        self
    }

    /// Sets the evidence policy.
    #[must_use]
    pub fn evidence_policy(mut self, policy: EvidencePolicy) -> Self {
        self.evidence_policy = Some(policy);
        self
    }

    /// Builds the `AgentAdapterProfileV1`.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build(self) -> Result<AgentAdapterProfileV1, AgentAdapterProfileError> {
        let profile = AgentAdapterProfileV1 {
            schema: AGENT_ADAPTER_PROFILE_V1_SCHEMA.to_string(),
            profile_id: self
                .profile_id
                .ok_or(AgentAdapterProfileError::MissingField("profile_id"))?,
            adapter_mode: self
                .adapter_mode
                .ok_or(AgentAdapterProfileError::MissingField("adapter_mode"))?,
            command: self
                .command
                .ok_or(AgentAdapterProfileError::MissingField("command"))?,
            args_template: self.args_template.unwrap_or_default(),
            env_template: self.env_template.unwrap_or_default(),
            cwd: self
                .cwd
                .ok_or(AgentAdapterProfileError::MissingField("cwd"))?,
            requires_pty: self.requires_pty.unwrap_or(false),
            input_mode: self
                .input_mode
                .ok_or(AgentAdapterProfileError::MissingField("input_mode"))?,
            output_mode: self
                .output_mode
                .ok_or(AgentAdapterProfileError::MissingField("output_mode"))?,
            permission_mode_map: self.permission_mode_map.unwrap_or_default(),
            tool_bridge: self.tool_bridge,
            capability_map: self.capability_map.unwrap_or_default(),
            version_probe: self
                .version_probe
                .ok_or(AgentAdapterProfileError::MissingField("version_probe"))?,
            health_checks: self.health_checks.unwrap_or_default(),
            budget_defaults: self.budget_defaults.unwrap_or_default(),
            evidence_policy: self.evidence_policy.unwrap_or_default(),
        };

        profile.validate()?;
        Ok(profile)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::MemoryCas;

    fn create_valid_profile() -> AgentAdapterProfileV1 {
        AgentAdapterProfileV1::builder()
            .profile_id("claude-code-v1")
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/claude")
            .args_template(vec!["-p".to_string()])
            .env_template(vec![("CLAUDE_NO_TOOLS".to_string(), "1".to_string())])
            .cwd("/workspace")
            .requires_pty(false)
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .permission_mode_map(BTreeMap::new())
            .capability_map(BTreeMap::new())
            .version_probe(VersionProbe::new(
                "claude --version",
                r"claude (\d+\.\d+\.\d+)",
            ))
            .health_checks(HealthChecks::default())
            .budget_defaults(BudgetDefaults::default())
            .evidence_policy(EvidencePolicy::default())
            .build()
            .expect("valid profile")
    }

    #[test]
    fn test_profile_builder_valid() {
        let profile = create_valid_profile();
        assert_eq!(profile.schema, AGENT_ADAPTER_PROFILE_V1_SCHEMA);
        assert_eq!(profile.profile_id, "claude-code-v1");
        assert_eq!(profile.adapter_mode, AdapterMode::BlackBox);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_profile_builder_missing_fields() {
        // Missing profile_id
        let result = AgentAdapterProfileV1::builder()
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/claude")
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .version_probe(VersionProbe::new("claude --version", r"v(\d+)"))
            .build();
        assert!(matches!(
            result,
            Err(AgentAdapterProfileError::MissingField("profile_id"))
        ));

        // Missing command
        let result = AgentAdapterProfileV1::builder()
            .profile_id("test")
            .adapter_mode(AdapterMode::BlackBox)
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .version_probe(VersionProbe::new("claude --version", r"v(\d+)"))
            .build();
        assert!(matches!(
            result,
            Err(AgentAdapterProfileError::MissingField("command"))
        ));
    }

    #[test]
    fn test_profile_validation_string_too_long() {
        let long_id = "x".repeat(MAX_PROFILE_ID_LENGTH + 1);
        let result = AgentAdapterProfileV1::builder()
            .profile_id(long_id)
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/claude")
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .version_probe(VersionProbe::new("claude --version", r"v(\d+)"))
            .build();
        assert!(matches!(
            result,
            Err(AgentAdapterProfileError::StringTooLong {
                field: "profile_id",
                ..
            })
        ));
    }

    #[test]
    fn test_profile_validation_collection_too_large() {
        let many_args: Vec<String> = (0..=MAX_ARGS_COUNT).map(|i| format!("arg{i}")).collect();
        let result = AgentAdapterProfileV1::builder()
            .profile_id("test")
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/claude")
            .args_template(many_args)
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .version_probe(VersionProbe::new("claude --version", r"v(\d+)"))
            .build();
        assert!(matches!(
            result,
            Err(AgentAdapterProfileError::CollectionTooLarge {
                field: "args_template",
                ..
            })
        ));
    }

    #[test]
    fn test_profile_cas_hash_deterministic() {
        let profile1 = create_valid_profile();
        let profile2 = create_valid_profile();

        assert_eq!(
            profile1.compute_cas_hash().unwrap(),
            profile2.compute_cas_hash().unwrap()
        );
    }

    #[test]
    fn test_profile_cas_hash_differs_on_change() {
        let profile1 = create_valid_profile();
        let profile2 = AgentAdapterProfileV1::builder()
            .profile_id("claude-code-v2") // Different profile_id
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/claude")
            .args_template(vec!["-p".to_string()])
            .env_template(vec![("CLAUDE_NO_TOOLS".to_string(), "1".to_string())])
            .cwd("/workspace")
            .requires_pty(false)
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .permission_mode_map(BTreeMap::new())
            .capability_map(BTreeMap::new())
            .version_probe(VersionProbe::new(
                "claude --version",
                r"claude (\d+\.\d+\.\d+)",
            ))
            .health_checks(HealthChecks::default())
            .budget_defaults(BudgetDefaults::default())
            .evidence_policy(EvidencePolicy::default())
            .build()
            .expect("valid profile");

        assert_ne!(
            profile1.compute_cas_hash().unwrap(),
            profile2.compute_cas_hash().unwrap()
        );
    }

    #[test]
    fn test_profile_cas_roundtrip() {
        let cas = MemoryCas::new();
        let profile = create_valid_profile();

        // Store
        let hash = profile.store_in_cas(&cas).expect("store should succeed");

        // Load
        let loaded =
            AgentAdapterProfileV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(profile, loaded);
    }

    #[test]
    fn test_profile_cas_not_found() {
        let cas = MemoryCas::new();
        let fake_hash = [0x42u8; 32];

        let result = AgentAdapterProfileV1::load_from_cas(&cas, &fake_hash);
        assert!(matches!(result, Err(AgentAdapterProfileError::CasError(_))));
    }

    #[test]
    fn test_adapter_mode_display() {
        assert_eq!(AdapterMode::BlackBox.to_string(), "black_box");
        assert_eq!(
            AdapterMode::StructuredOutput.to_string(),
            "structured_output"
        );
        assert_eq!(AdapterMode::McpBridge.to_string(), "mcp_bridge");
        assert_eq!(AdapterMode::HookedVendor.to_string(), "hooked_vendor");
    }

    #[test]
    fn test_adapter_mode_from_str() {
        assert_eq!(
            "black_box".parse::<AdapterMode>().unwrap(),
            AdapterMode::BlackBox
        );
        assert_eq!(
            "structured_output".parse::<AdapterMode>().unwrap(),
            AdapterMode::StructuredOutput
        );
        assert_eq!(
            "mcp_bridge".parse::<AdapterMode>().unwrap(),
            AdapterMode::McpBridge
        );
        assert_eq!(
            "hooked_vendor".parse::<AdapterMode>().unwrap(),
            AdapterMode::HookedVendor
        );
        assert!("invalid".parse::<AdapterMode>().is_err());
    }

    #[test]
    fn test_input_mode_display() {
        assert_eq!(InputMode::Arg.to_string(), "arg");
        assert_eq!(InputMode::Stdin.to_string(), "stdin");
        assert_eq!(InputMode::File.to_string(), "file");
        assert_eq!(InputMode::StreamJson.to_string(), "stream_json");
    }

    #[test]
    fn test_output_mode_display() {
        assert_eq!(OutputMode::Raw.to_string(), "raw");
        assert_eq!(OutputMode::Json.to_string(), "json");
        assert_eq!(OutputMode::Jsonl.to_string(), "jsonl");
        assert_eq!(OutputMode::StreamJson.to_string(), "stream_json");
    }

    #[test]
    fn test_version_probe_validation() {
        // Valid
        let probe = VersionProbe::new("claude --version", r"v(\d+)");
        assert!(probe.validate().is_ok());

        // Empty command
        let probe = VersionProbe::new("", r"v(\d+)");
        assert!(matches!(
            probe.validate(),
            Err(AgentAdapterProfileError::MissingField(
                "version_probe.command"
            ))
        ));

        // Empty regex
        let probe = VersionProbe::new("claude --version", "");
        assert!(matches!(
            probe.validate(),
            Err(AgentAdapterProfileError::MissingField(
                "version_probe.regex"
            ))
        ));

        // Command too long
        let long_cmd = "x".repeat(MAX_VERSION_PROBE_COMMAND_LENGTH + 1);
        let probe = VersionProbe::new(long_cmd, r"v(\d+)");
        assert!(matches!(
            probe.validate(),
            Err(AgentAdapterProfileError::StringTooLong {
                field: "version_probe.command",
                ..
            })
        ));

        // Invalid regex
        let probe = VersionProbe::new("claude --version", r"v(\d+");
        assert!(matches!(
            probe.validate(),
            Err(AgentAdapterProfileError::InvalidRegex(_))
        ));
    }

    #[test]
    fn test_defaults() {
        let health = HealthChecks::default();
        assert_eq!(health.startup_timeout_ms, 30_000);
        assert_eq!(health.max_stalls, 3);

        let budget = BudgetDefaults::default();
        assert_eq!(budget.max_tool_calls, 100);
        assert_eq!(budget.max_tokens, 1_000_000);

        let evidence = EvidencePolicy::default();
        assert!(evidence.record_full_output);
        assert!(evidence.redact_sensitive);

        let tool_bridge = ToolBridgeConfig::default();
        assert!(tool_bridge.enabled);
        assert_eq!(tool_bridge.protocol_version, "TI1");
    }

    #[test]
    fn test_profile_with_tool_bridge() {
        let profile = AgentAdapterProfileV1::builder()
            .profile_id("claude-code-v1")
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/claude")
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .tool_bridge(ToolBridgeConfig {
                enabled: true,
                protocol_version: "TI1".to_string(),
                nonce_prefix: "test".to_string(),
                max_args_size: 2048,
                max_result_size: 2048,
                tool_timeout_ms: 30_000,
            })
            .version_probe(VersionProbe::new(
                "claude --version",
                r"claude (\d+\.\d+\.\d+)",
            ))
            .build()
            .expect("valid profile");

        assert!(profile.tool_bridge.is_some());
        let tool_bridge = profile.tool_bridge.unwrap();
        assert_eq!(tool_bridge.nonce_prefix, "test");
    }

    #[test]
    fn test_profile_serialization() {
        let profile = create_valid_profile();

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&profile).expect("serialize should succeed");

        // Deserialize back
        let deserialized: AgentAdapterProfileV1 =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(profile, deserialized);
    }

    #[test]
    fn test_profile_with_permission_mode_map() {
        let mut permission_map = BTreeMap::new();
        permission_map.insert(
            "read_only".to_string(),
            vec!["--no-write".to_string(), "--safe-mode".to_string()],
        );
        permission_map.insert("full_access".to_string(), vec!["--allow-write".to_string()]);

        let profile = AgentAdapterProfileV1::builder()
            .profile_id("test-profile")
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/agent")
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .permission_mode_map(permission_map.clone())
            .version_probe(VersionProbe::new("agent --version", r"v(\d+)"))
            .build()
            .expect("valid profile");

        assert_eq!(profile.permission_mode_map.len(), 2);
        assert_eq!(
            profile.permission_mode_map.get("read_only"),
            Some(&vec!["--no-write".to_string(), "--safe-mode".to_string()])
        );
    }

    #[test]
    fn test_profile_with_capability_map() {
        let mut capability_map = BTreeMap::new();
        capability_map.insert("read_file".to_string(), "kernel.fs.read".to_string());
        capability_map.insert("write_file".to_string(), "kernel.fs.write".to_string());
        capability_map.insert("exec_command".to_string(), "kernel.shell.exec".to_string());

        let profile = AgentAdapterProfileV1::builder()
            .profile_id("test-profile")
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/agent")
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .capability_map(capability_map.clone())
            .version_probe(VersionProbe::new("agent --version", r"v(\d+)"))
            .build()
            .expect("valid profile");

        assert_eq!(profile.capability_map.len(), 3);
        assert_eq!(
            profile.capability_map.get("read_file"),
            Some(&"kernel.fs.read".to_string())
        );
    }

    #[test]
    fn test_path_traversal() {
        let result = AgentAdapterProfileV1::builder()
            .profile_id("test")
            .adapter_mode(AdapterMode::BlackBox)
            .command("../claude")
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .version_probe(VersionProbe::new("claude", "v1"))
            .build();
        assert!(matches!(
            result,
            Err(AgentAdapterProfileError::InvalidPath {
                field: "command",
                ..
            })
        ));
    }

    #[test]
    fn test_from_str_impls() {
        assert_eq!(InputMode::from_str("arg").unwrap(), InputMode::Arg);
        assert_eq!(OutputMode::from_str("raw").unwrap(), OutputMode::Raw);
        assert!(InputMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_deny_unknown_fields() {
        let json = r#"{
            "schema": "apm2.agent_adapter_profile.v1",
            "profile_id": "test",
            "adapter_mode": "black_box",
            "command": "cmd",
            "args_template": [],
            "env_template": [],
            "cwd": "/tmp",
            "requires_pty": false,
            "input_mode": "stdin",
            "output_mode": "raw",
            "permission_mode_map": {},
            "capability_map": {},
            "version_probe": { "command": "cmd", "regex": "v1" },
            "health_checks": { "startup_timeout_ms": 1, "heartbeat_interval_ms": 1, "heartbeat_timeout_ms": 1, "stall_threshold_ms": 1, "max_stalls": 1 },
            "budget_defaults": { "max_tool_calls": 1, "max_tokens": 1, "max_wall_clock_ms": 1, "max_evidence_bytes": 1 },
            "evidence_policy": { "record_full_output": true, "record_tool_traces": true, "record_timing": true, "record_token_usage": true, "max_recorded_output_bytes": 1, "redact_sensitive": true },
            "extra_field": "fail"
        }"#;

        let result: Result<AgentAdapterProfileV1, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown field `extra_field`"));
    }
}
