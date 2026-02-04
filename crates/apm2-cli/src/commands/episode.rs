//! Episode management CLI commands.
//!
//! This module implements the `apm2 episode` subcommands for managing
//! bounded execution episodes per RFC-0013 and TCK-00174.
//!
//! # Commands
//!
//! - `apm2 episode create --envelope <path>` - Create an episode from envelope
//! - `apm2 episode start <episode_id>` - Start a created episode
//! - `apm2 episode stop <episode_id> [--reason]` - Stop a running episode
//! - `apm2 episode status <episode_id>` - Show episode status
//! - `apm2 episode list [--state]` - List episodes
//! - `apm2 episode spawn --work-id <id> --role <role>` - Spawn episode via
//!   protocol (TCK-00288)
//! - `apm2 episode session-status --session-token <token>` - Session-scoped
//!   status (TCK-00288)
//!
//! # JSON Output
//!
//! All commands support `--json` flag for machine-readable output.
//!
//! # Exit Codes (RFC-0018)
//!
//! - 0: Success
//! - 10: Validation error
//! - 11: Permission denied
//! - 12: Not found
//! - 20: Daemon unavailable
//! - 21: Protocol error
//! - 22: Policy deny
//!
//! # Contract References
//!
//! - AD-DAEMON-002: UDS transport with length-prefixed framing
//! - AD-EPISODE-001: Immutable episode envelope
//! - AD-EPISODE-002: Episode state machine
//! - DD-009: Protocol-based IPC (TCK-00288)

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use apm2_daemon::protocol::WorkRole;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::client::daemon::ErrorCode;
use crate::client::protocol::{OperatorClient, ProtocolClientError};
use crate::exit_codes::{codes as hef_exit_codes, map_protocol_error};

/// Maximum envelope file size (10 MiB).
///
/// Per CTR-1603, this limit prevents denial-of-service attacks via memory
/// exhaustion from large file inputs.
pub const MAX_ENVELOPE_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Exit codes for episode commands.
pub mod exit_codes {
    /// Success exit code.
    pub const SUCCESS: u8 = 0;
    /// General error exit code.
    pub const ERROR: u8 = 1;
    /// Episode not found exit code.
    ///
    /// Reserved for future protocol support (TCK-00288).
    #[allow(dead_code)]
    pub const NOT_FOUND: u8 = 2;
}

/// Episode command group.
#[derive(Debug, Args)]
pub struct EpisodeCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
    pub json: bool,

    #[command(subcommand)]
    pub subcommand: EpisodeSubcommand,
}

/// Episode subcommands.
#[derive(Debug, Subcommand)]
pub enum EpisodeSubcommand {
    /// Create an episode from an envelope YAML file.
    ///
    /// The envelope defines immutable episode configuration including:
    /// - Budget (tokens, tool calls, time limits)
    /// - Stop conditions
    /// - Risk tier and determinism class
    /// - Capability manifest
    ///
    /// Returns the created episode ID on success.
    Create(CreateArgs),

    /// Start a created episode.
    ///
    /// Transitions an episode from CREATED to RUNNING state.
    /// Requires the daemon to spawn the harness process.
    Start(StartArgs),

    /// Stop a running episode.
    ///
    /// Transitions an episode from RUNNING to TERMINATED state.
    /// Optionally specify a reason for the stop.
    Stop(StopArgs),

    /// Show episode status and details.
    ///
    /// Displays the current state, budget remaining, and telemetry summary.
    Status(StatusArgs),

    /// List episodes with optional state filter.
    ///
    /// Shows all episodes or filters by state (created, running, terminated,
    /// quarantined).
    List(ListArgs),

    /// Spawn an episode for work execution (TCK-00288).
    ///
    /// Uses protocol-based IPC via `OperatorClient::spawn_episode`.
    /// Returns session ID and token for subsequent session-scoped operations.
    Spawn(SpawnArgs),

    /// Query session-scoped episode status (TCK-00288).
    ///
    /// Uses session socket with session token for authentication.
    /// Returns current session state and telemetry summary.
    SessionStatus(SessionStatusArgs),
}

/// Arguments for `apm2 episode create`.
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Path to the envelope YAML file.
    ///
    /// The envelope defines the immutable configuration for the episode.
    #[arg(long, required = true)]
    pub envelope: PathBuf,
}

/// Arguments for `apm2 episode start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Episode ID to start.
    pub episode_id: String,

    /// Lease ID authorizing execution (optional, daemon may generate).
    #[arg(long)]
    pub lease_id: Option<String>,
}

/// Stop reason for episode termination.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum StopReason {
    /// Normal completion.
    #[default]
    Success,
    /// User requested cancellation.
    Cancelled,
    /// Episode failed.
    Failure,
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Failure => write!(f, "failure"),
        }
    }
}

/// Arguments for `apm2 episode stop`.
#[derive(Debug, Args)]
pub struct StopArgs {
    /// Episode ID to stop.
    pub episode_id: String,

    /// Reason for stopping the episode.
    #[arg(long, value_enum, default_value = "success")]
    pub reason: StopReason,

    /// Custom reason message.
    #[arg(long)]
    pub message: Option<String>,
}

/// Arguments for `apm2 episode status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Episode ID to query.
    pub episode_id: String,
}

/// Episode state filter for list command.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum StateFilter {
    /// Show all episodes.
    #[default]
    All,
    /// Show only created (not yet started) episodes.
    Created,
    /// Show only running episodes.
    Running,
    /// Show only terminated episodes.
    Terminated,
    /// Show only quarantined episodes.
    Quarantined,
}

impl std::fmt::Display for StateFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Created => write!(f, "created"),
            Self::Running => write!(f, "running"),
            Self::Terminated => write!(f, "terminated"),
            Self::Quarantined => write!(f, "quarantined"),
        }
    }
}

/// Arguments for `apm2 episode list`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Filter by episode state.
    #[arg(long, value_enum, default_value = "all")]
    pub state: StateFilter,

    /// Maximum number of episodes to return.
    #[arg(long, default_value = "100")]
    pub limit: u32,
}

/// Role for spawning episodes (TCK-00288).
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum SpawnRoleArg {
    /// Implementer role (default).
    #[default]
    Implementer,
    /// Gate executor role.
    GateExecutor,
    /// Reviewer role.
    Reviewer,
    /// Coordinator role.
    Coordinator,
}

impl From<SpawnRoleArg> for WorkRole {
    fn from(arg: SpawnRoleArg) -> Self {
        match arg {
            SpawnRoleArg::Implementer => Self::Implementer,
            SpawnRoleArg::GateExecutor => Self::GateExecutor,
            SpawnRoleArg::Reviewer => Self::Reviewer,
            SpawnRoleArg::Coordinator => Self::Coordinator,
        }
    }
}

impl std::fmt::Display for SpawnRoleArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Implementer => write!(f, "implementer"),
            Self::GateExecutor => write!(f, "gate_executor"),
            Self::Reviewer => write!(f, "reviewer"),
            Self::Coordinator => write!(f, "coordinator"),
        }
    }
}

/// Arguments for `apm2 episode spawn` (TCK-00288).
#[derive(Debug, Args)]
pub struct SpawnArgs {
    /// Work identifier from a prior `ClaimWork`.
    #[arg(long, required = true)]
    pub work_id: String,

    /// Role for this episode.
    #[arg(long, value_enum, default_value = "implementer")]
    pub role: SpawnRoleArg,

    /// Lease ID (required for `GATE_EXECUTOR` role).
    #[arg(long)]
    pub lease_id: Option<String>,

    /// Workspace root directory for this episode (TCK-00319).
    ///
    /// All file operations will be confined to this directory.
    /// Must be an absolute path to an existing directory.
    #[arg(long, required = true)]
    pub workspace_root: String,
}

/// Arguments for `apm2 episode session-status` (TCK-00288).
#[derive(Debug, Args)]
pub struct SessionStatusArgs {
    /// Session token for authentication.
    ///
    /// Obtained from `apm2 episode spawn` response.
    ///
    /// **Security (CWE-214)**: Prefer setting the `APM2_SESSION_TOKEN`
    /// environment variable instead of using this flag. CLI arguments
    /// are visible in process listings on multi-user systems.
    #[arg(long, env = "APM2_SESSION_TOKEN")]
    pub session_token: Option<String>,
}

// ============================================================================
// Response Types for JSON output
// ============================================================================
//
// Note: CreateResponse, StartResponse, StopResponse, StatusResponse, and
// ListResponse are for deprecated commands but retained for future protocol
// support.

/// Response for episode create command.
///
/// Reserved for future protocol support (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct CreateResponse {
    /// Created episode ID.
    pub episode_id: String,
    /// Envelope hash (BLAKE3).
    pub envelope_hash: String,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
}

/// Response for episode start command.
///
/// Reserved for future protocol support (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct StartResponse {
    /// Episode ID.
    pub episode_id: String,
    /// Session ID for the running episode.
    pub session_id: String,
    /// Lease ID.
    pub lease_id: String,
    /// Start timestamp (RFC 3339).
    pub started_at: String,
}

/// Response for episode stop command.
///
/// Reserved for future protocol support (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct StopResponse {
    /// Episode ID.
    pub episode_id: String,
    /// Termination class.
    pub termination_class: String,
    /// Stop timestamp (RFC 3339).
    pub stopped_at: String,
}

/// Response for episode status command.
///
/// Reserved for future protocol support (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct StatusResponse {
    /// Episode ID.
    pub episode_id: String,
    /// Current state (Created, Running, Terminated, Quarantined).
    pub state: String,
    /// Envelope hash.
    pub envelope_hash: String,
    /// Creation timestamp.
    pub created_at: String,
    /// Start timestamp (if started).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Session ID (if running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Lease ID (if running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// Termination timestamp (if terminated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminated_at: Option<String>,
    /// Termination class (if terminated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub termination_class: Option<String>,
    /// Budget summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetSummary>,
}

/// Budget summary for status response.
///
/// Reserved for future protocol support (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct BudgetSummary {
    /// Tokens used / total.
    pub tokens: String,
    /// Tool calls used / total.
    pub tool_calls: String,
    /// Wall time used / total (ms).
    pub wall_ms: String,
}

/// Episode summary for list command.
///
/// Reserved for future protocol support (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct EpisodeSummary {
    /// Episode ID.
    pub episode_id: String,
    /// Current state.
    pub state: String,
    /// Creation timestamp.
    pub created_at: String,
    /// Session ID (if running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Response for episode list command.
///
/// Reserved for future protocol support (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ListResponse {
    /// List of episodes.
    pub episodes: Vec<EpisodeSummary>,
    /// Total count (may be more than returned due to limit).
    pub total: u32,
}

/// Error response for JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}

/// Response for episode spawn command (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnResponse {
    /// Session identifier for IPC communication.
    pub session_id: String,
    /// Blake3 hash of the capability manifest (hex-encoded).
    pub capability_manifest_hash: String,
    /// Whether the context pack is sealed.
    pub context_pack_sealed: bool,
    /// Ephemeral handle for session identification.
    pub ephemeral_handle: String,
    /// Session token for authenticating session-scoped IPC requests.
    pub session_token: String,
}

/// Response for session-scoped episode status (TCK-00288).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStatusResponse {
    /// Session identifier.
    pub session_id: String,
    /// Current session state.
    pub state: String,
    /// Episode ID (if associated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub episode_id: Option<String>,
    /// Telemetry summary (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<TelemetrySummary>,
}

/// Telemetry summary for session status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySummary {
    /// Total tool calls executed.
    pub tool_calls: u32,
    /// Total events emitted.
    pub events_emitted: u32,
    /// Session duration in milliseconds.
    pub duration_ms: u64,
}

// ============================================================================
// Command execution
// ============================================================================

/// Runs the episode command, returning an appropriate exit code.
///
/// # Exit Codes (RFC-0018)
///
/// - 0: Success
/// - 10: Validation error
/// - 11: Permission denied
/// - 12: Not found
/// - 20: Daemon unavailable
/// - 21: Protocol error
/// - 22: Policy deny
#[allow(clippy::too_many_lines)] // Command dispatch is inherently verbose
pub fn run_episode(
    cmd: &EpisodeCommand,
    operator_socket: &std::path::Path,
    session_socket: &std::path::Path,
) -> u8 {
    let json_output = cmd.json;

    match &cmd.subcommand {
        EpisodeSubcommand::Create(args) => run_create(args, operator_socket, json_output),
        EpisodeSubcommand::Start(args) => run_start(args, operator_socket, json_output),
        EpisodeSubcommand::Stop(args) => run_stop(args, operator_socket, json_output),
        EpisodeSubcommand::Status(args) => run_status(args, operator_socket, json_output),
        EpisodeSubcommand::List(args) => run_list(args, operator_socket, json_output),
        EpisodeSubcommand::Spawn(args) => run_spawn(args, operator_socket, json_output),
        EpisodeSubcommand::SessionStatus(args) => {
            run_session_status(args, session_socket, json_output)
        },
    }
}

/// Execute the create command.
///
/// # Deprecation Notice (TCK-00288)
///
/// This command is deprecated. Use `apm2 episode spawn` instead, which combines
/// create+start in a single protocol operation.
fn run_create(args: &CreateArgs, _socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Read envelope content with TOCTOU-safe bounded reading (CTR-1603, RSK-1501).
    // Opens file handle first, uses .take(limit) pattern to enforce size limit.
    let envelope_content = match read_bounded_file(&args.envelope, MAX_ENVELOPE_FILE_SIZE) {
        Ok(content) => content,
        Err((code, message)) => {
            return output_error(json_output, &code, &message, exit_codes::ERROR);
        },
    };

    // Validate YAML can be parsed (local validation before daemon call)
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(&envelope_content) {
        return output_error(
            json_output,
            "invalid_yaml",
            &format!("Failed to parse envelope YAML: {e}"),
            exit_codes::ERROR,
        );
    }

    // TCK-00288: This command requires protocol support not yet available.
    // The DD-009 protocol uses SpawnEpisode which combines create+start.
    // Guide users to the new workflow.
    output_error(
        json_output,
        "deprecated_command",
        "The 'episode create' command is deprecated. Use 'apm2 episode spawn' instead, \
         which combines create+start via the protocol-based IPC (DD-009).",
        hef_exit_codes::PROTOCOL_ERROR,
    )
}

/// Execute the start command.
///
/// # Deprecation Notice (TCK-00288)
///
/// This command is deprecated. Use `apm2 episode spawn` instead, which combines
/// create+start in a single protocol operation.
fn run_start(args: &StartArgs, _socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Validate episode ID format
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_id",
            "Episode ID cannot be empty",
            hef_exit_codes::VALIDATION_ERROR,
        );
    }

    if !args.episode_id.starts_with("ep-") {
        return output_error(
            json_output,
            "invalid_id",
            "Episode ID must start with 'ep-'",
            hef_exit_codes::VALIDATION_ERROR,
        );
    }

    // TCK-00288: This command requires protocol support not yet available.
    // The DD-009 protocol uses SpawnEpisode which combines create+start.
    // Guide users to the new workflow.
    output_error(
        json_output,
        "deprecated_command",
        "The 'episode start' command is deprecated. Use 'apm2 episode spawn' instead, \
         which combines create+start via the protocol-based IPC (DD-009).",
        hef_exit_codes::PROTOCOL_ERROR,
    )
}

/// Execute the stop command.
///
/// # Deprecation Notice (TCK-00288)
///
/// This command is deprecated. Episode termination is handled automatically
/// when a session closes or the daemon shuts down.
fn run_stop(args: &StopArgs, _socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Validate episode ID format
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_id",
            "Episode ID cannot be empty",
            hef_exit_codes::VALIDATION_ERROR,
        );
    }

    // TCK-00288: This command requires protocol support not yet available.
    // Episode termination is handled via session close or daemon shutdown.
    output_error(
        json_output,
        "deprecated_command",
        "The 'episode stop' command is deprecated. Episode termination is handled \
         automatically when the session closes or the daemon shuts down (DD-009).",
        hef_exit_codes::PROTOCOL_ERROR,
    )
}

/// Execute the status command.
///
/// # Deprecation Notice (TCK-00288)
///
/// This command is deprecated. Use `apm2 episode session-status` for
/// session-scoped status queries via the protocol-based IPC.
fn run_status(args: &StatusArgs, _socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Validate episode ID format
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_id",
            "Episode ID cannot be empty",
            hef_exit_codes::VALIDATION_ERROR,
        );
    }

    // TCK-00288: This command requires protocol support not yet available.
    // Use session-status for session-scoped status queries.
    output_error(
        json_output,
        "deprecated_command",
        "The 'episode status' command is deprecated. Use 'apm2 episode session-status' \
         for session-scoped status queries via the protocol-based IPC (DD-009).",
        hef_exit_codes::PROTOCOL_ERROR,
    )
}

/// Execute the list command.
///
/// # Deprecation Notice (TCK-00288)
///
/// This command is deprecated. Episode listing is not available in the
/// protocol-based IPC. Use telemetry or ledger queries for episode tracking.
fn run_list(args: &ListArgs, _socket_path: &std::path::Path, json_output: bool) -> u8 {
    // TCK-00288: This command requires protocol support not yet available.
    // Episode listing is not part of the DD-009 minimal agent command set.
    let _ = args; // Acknowledge args to avoid unused warning
    output_error(
        json_output,
        "deprecated_command",
        "The 'episode list' command is deprecated. Episode listing is not available \
         in the protocol-based IPC (DD-009). Use telemetry or ledger queries instead.",
        hef_exit_codes::PROTOCOL_ERROR,
    )
}

/// Execute the spawn command (TCK-00288).
///
/// Uses `OperatorClient::spawn_episode` for protocol-based IPC.
fn run_spawn(args: &SpawnArgs, socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Validate work ID
    if args.work_id.is_empty() {
        return output_error(
            json_output,
            "invalid_work_id",
            "Work ID cannot be empty",
            exit_codes::ERROR,
        );
    }

    // Validate GATE_EXECUTOR requires lease_id
    if matches!(args.role, SpawnRoleArg::GateExecutor) && args.lease_id.is_none() {
        return output_error(
            json_output,
            "missing_lease_id",
            "GATE_EXECUTOR role requires --lease-id",
            exit_codes::ERROR,
        );
    }

    // Build async runtime
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return output_error(
                json_output,
                "runtime_error",
                &format!("Failed to build tokio runtime: {e}"),
                exit_codes::ERROR,
            );
        },
    };

    // Execute spawn via protocol client
    let result = rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path).await?;
        client
            .spawn_episode(
                &args.work_id,
                args.role.into(),
                args.lease_id.as_deref(),
                &args.workspace_root,
            )
            .await
    });

    match result {
        Ok(response) => {
            let spawn_response = SpawnResponse {
                session_id: response.session_id,
                capability_manifest_hash: hex::encode(&response.capability_manifest_hash),
                context_pack_sealed: response.context_pack_sealed,
                ephemeral_handle: response.ephemeral_handle,
                session_token: response.session_token,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&spawn_response)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Episode spawned successfully");
                println!("  Session ID:           {}", spawn_response.session_id);
                println!(
                    "  Capability Manifest:  {}",
                    spawn_response.capability_manifest_hash
                );
                println!(
                    "  Context Pack Sealed:  {}",
                    spawn_response.context_pack_sealed
                );
                println!(
                    "  Ephemeral Handle:     {}",
                    spawn_response.ephemeral_handle
                );
                println!("  Session Token:        {}", spawn_response.session_token);
            }

            exit_codes::SUCCESS
        },
        Err(e) => handle_protocol_error(json_output, &e),
    }
}

/// Execute the session-status command (TCK-00288).
///
/// Uses `SessionClient` for session-scoped operations via session.sock.
fn run_session_status(
    args: &SessionStatusArgs,
    _socket_path: &std::path::Path,
    json_output: bool,
) -> u8 {
    // Resolve session token (CWE-214 mitigation: prefer env var over CLI arg)
    let session_token = match &args.session_token {
        Some(token) if !token.is_empty() => token.clone(),
        _ => {
            return output_error(
                json_output,
                "missing_session_token",
                "Session token is required. Set APM2_SESSION_TOKEN environment variable \
                 (preferred) or use --session-token flag.",
                hef_exit_codes::VALIDATION_ERROR,
            );
        },
    };

    // TODO(TCK-00288): Implement session status query via SessionClient.
    // The protocol layer does not yet have a QuerySessionStatus message.
    // For now, return a stub response.
    //
    // Future implementation would:
    // 1. Connect to session_socket via SessionClient
    // 2. Send a SessionStatusRequest with the session_token
    // 3. Receive SessionStatusResponse with state and telemetry

    // Parse session token to extract session_id (best effort)
    let session_id = session_token
        .split('.')
        .next()
        .unwrap_or("unknown")
        .to_string();

    let response = SessionStatusResponse {
        session_id,
        state: "PENDING_PROTOCOL_SUPPORT".to_string(),
        episode_id: None,
        telemetry: None,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Session Status");
        println!("  Session ID:  {}", response.session_id);
        println!("  State:       {}", response.state);
        println!();
        println!("Note: Session status query requires protocol support (pending).");
    }

    exit_codes::SUCCESS
}

// ============================================================================
// Helper functions
// ============================================================================

/// Output an error in the appropriate format.
fn output_error(json_output: bool, code: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let error = ErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
        };
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&error).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        eprintln!("Error: {message}");
    }
    exit_code
}

/// Truncate a string to a maximum length.
///
/// Reserved for future protocol support (TCK-00288).
#[allow(dead_code)]
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

/// Handles daemon client errors and returns appropriate exit code.
///
/// Maps daemon errors to exit codes:
/// - `DaemonNotRunning` -> ERROR (1)
/// - `EpisodeNotFound` -> `NOT_FOUND` (2)
/// - Other errors -> ERROR (1)
///
/// Reserved for future protocol support (TCK-00288).
#[allow(dead_code)]
fn handle_daemon_error(json_output: bool, error: &crate::client::daemon::DaemonClientError) -> u8 {
    use crate::client::daemon::DaemonClientError;
    match error {
        DaemonClientError::DaemonNotRunning => output_error(
            json_output,
            "daemon_not_running",
            "Daemon is not running. Start with: apm2 daemon",
            exit_codes::ERROR,
        ),
        DaemonClientError::DaemonError { code, message } => {
            let exit_code = match code {
                ErrorCode::EpisodeNotFound => exit_codes::NOT_FOUND,
                _ => exit_codes::ERROR,
            };
            let code_str = format!("{code:?}").to_lowercase();
            output_error(json_output, &code_str, message, exit_code)
        },
        DaemonClientError::ConnectionFailed(msg) => output_error(
            json_output,
            "connection_failed",
            &format!("Failed to connect to daemon: {msg}"),
            exit_codes::ERROR,
        ),
        DaemonClientError::IoError(e) => output_error(
            json_output,
            "io_error",
            &format!("I/O error communicating with daemon: {e}"),
            exit_codes::ERROR,
        ),
        DaemonClientError::FrameTooLarge { size, max } => output_error(
            json_output,
            "frame_too_large",
            &format!("Response frame too large: {size} bytes (max: {max})"),
            exit_codes::ERROR,
        ),
        DaemonClientError::SerdeError(msg) => output_error(
            json_output,
            "serde_error",
            &format!("Protocol error: {msg}"),
            exit_codes::ERROR,
        ),
        DaemonClientError::UnexpectedResponse(msg) => output_error(
            json_output,
            "unexpected_response",
            &format!("Unexpected daemon response: {msg}"),
            exit_codes::ERROR,
        ),
        DaemonClientError::ProtocolMigrationRequired => output_error(
            json_output,
            "protocol_migration_required",
            "CLI requires protobuf migration (DD-009). Legacy JSON IPC has been removed.",
            exit_codes::ERROR,
        ),
    }
}

/// Handles protocol client errors and returns appropriate exit code (RFC-0018).
fn handle_protocol_error(json_output: bool, error: &ProtocolClientError) -> u8 {
    let exit_code = map_protocol_error(error);
    let (code, message) = match error {
        ProtocolClientError::DaemonNotRunning => (
            "daemon_not_running".to_string(),
            "Daemon is not running. Start with: apm2 daemon".to_string(),
        ),
        ProtocolClientError::ConnectionFailed(msg) => (
            "connection_failed".to_string(),
            format!("Failed to connect to daemon: {msg}"),
        ),
        ProtocolClientError::HandshakeFailed(msg) => (
            "handshake_failed".to_string(),
            format!("Protocol handshake failed: {msg}"),
        ),
        ProtocolClientError::VersionMismatch { client, server } => (
            "version_mismatch".to_string(),
            format!("Protocol version mismatch: client {client}, server {server}"),
        ),
        ProtocolClientError::DaemonError { code, message } => (code.clone(), message.clone()),
        ProtocolClientError::IoError(e) => ("io_error".to_string(), format!("I/O error: {e}")),
        ProtocolClientError::ProtocolError(e) => {
            ("protocol_error".to_string(), format!("Protocol error: {e}"))
        },
        ProtocolClientError::DecodeError(msg) => {
            ("decode_error".to_string(), format!("Decode error: {msg}"))
        },
        ProtocolClientError::UnexpectedResponse(msg) => (
            "unexpected_response".to_string(),
            format!("Unexpected response: {msg}"),
        ),
        ProtocolClientError::Timeout => ("timeout".to_string(), "Operation timed out".to_string()),
        ProtocolClientError::FrameTooLarge { size, max } => (
            "frame_too_large".to_string(),
            format!("Frame too large: {size} bytes (max: {max})"),
        ),
    };
    output_error(json_output, &code, &message, exit_code)
}

/// Reads a file with bounded size to prevent TOCTOU and denial-of-service
/// attacks.
///
/// Opens the file handle first, then uses `.take(limit)` to enforce the
/// size limit. This is TOCTOU-safe because we read from the handle we
/// opened, not from a separate open operation.
///
/// Per CTR-1603 (Bounded Reads) and RSK-1501 (TOCTOU Canonicalization).
fn read_bounded_file(path: &std::path::Path, max_size: u64) -> Result<String, (String, String)> {
    let file = File::open(path).map_err(|e| {
        (
            "io_error".to_string(),
            format!("Failed to open file '{}': {e}", path.display()),
        )
    })?;

    // Use take() to limit reads - TOCTOU-safe as we read from the same handle
    let mut reader = BufReader::new(file.take(max_size + 1));
    let mut content = String::new();

    reader.read_to_string(&mut content).map_err(|e| {
        (
            "io_error".to_string(),
            format!("Failed to read file '{}': {e}", path.display()),
        )
    })?;

    // Check if we hit the limit (read more than max_size)
    if content.len() as u64 > max_size {
        return Err((
            "file_too_large".to_string(),
            format!(
                "File '{}' exceeds maximum size of {max_size} bytes",
                path.display()
            ),
        ));
    }

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stop_reason_display() {
        assert_eq!(StopReason::Success.to_string(), "success");
        assert_eq!(StopReason::Cancelled.to_string(), "cancelled");
        assert_eq!(StopReason::Failure.to_string(), "failure");
    }

    #[test]
    fn test_state_filter_display() {
        assert_eq!(StateFilter::All.to_string(), "all");
        assert_eq!(StateFilter::Created.to_string(), "created");
        assert_eq!(StateFilter::Running.to_string(), "running");
        assert_eq!(StateFilter::Terminated.to_string(), "terminated");
        assert_eq!(StateFilter::Quarantined.to_string(), "quarantined");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("hi", 2), "hi");
    }

    #[test]
    fn test_create_response_serialization() {
        let response = CreateResponse {
            episode_id: "ep-abc123".to_string(),
            envelope_hash: "deadbeef".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: CreateResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.episode_id, "ep-abc123");
    }

    #[test]
    fn test_status_response_serialization() {
        let response = StatusResponse {
            episode_id: "ep-test".to_string(),
            state: "Running".to_string(),
            envelope_hash: "abc".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            started_at: Some("2024-01-01T00:00:01Z".to_string()),
            session_id: Some("session-1".to_string()),
            lease_id: Some("lease-1".to_string()),
            terminated_at: None,
            termination_class: None,
            budget: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Running"));
        assert!(!json.contains("terminated_at")); // Should be skipped
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_create_response_rejects_unknown_fields() {
        let json = r#"{
            "episode_id": "ep-1",
            "envelope_hash": "abc",
            "created_at": "2024-01-01T00:00:00Z",
            "malicious": "value"
        }"#;

        let result: Result<CreateResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "CreateResponse should reject unknown fields"
        );
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ErrorResponse {
            code: "not_found".to_string(),
            message: "Episode not found".to_string(),
        };

        let json = serde_json::to_string_pretty(&error).unwrap();
        assert!(json.contains("not_found"));
    }

    // =========================================================================
    // TOCTOU-safe file reading tests (UT-00202-01)
    // =========================================================================

    #[test]
    fn test_read_bounded_file_success() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.yaml");
        std::fs::write(&file_path, "test content").unwrap();

        let result = read_bounded_file(&file_path, 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test content");
    }

    #[test]
    fn test_read_bounded_file_exceeds_limit() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("large.yaml");
        // Write 1001 bytes to a file with a 1000 byte limit
        std::fs::write(&file_path, "x".repeat(1001)).unwrap();

        let result = read_bounded_file(&file_path, 1000);
        assert!(result.is_err());
        let (code, message) = result.unwrap_err();
        assert_eq!(code, "file_too_large");
        assert!(message.contains("exceeds maximum size"));
    }

    #[test]
    fn test_read_bounded_file_not_found() {
        let result = read_bounded_file(std::path::Path::new("/nonexistent/file.yaml"), 1000);
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, "io_error");
    }

    #[test]
    fn test_read_bounded_file_exact_limit() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("exact.yaml");
        // Write exactly 1000 bytes (should pass)
        std::fs::write(&file_path, "x".repeat(1000)).unwrap();

        let result = read_bounded_file(&file_path, 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1000);
    }

    /// SECURITY TEST: Verify TOCTOU-safe file reading pattern.
    /// This test verifies the pattern, not actual race conditions.
    #[test]
    fn test_episode_create_toctou_safe() {
        // The read_bounded_file function:
        // 1. Opens the file handle first
        // 2. Uses .take(limit) on the handle
        // 3. Reads from the same handle
        // This is TOCTOU-safe because there's no separate stat/read operations.

        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("envelope.yaml");
        let content = "actor_id: test\nrisk_tier: 1";
        std::fs::write(&file_path, content).unwrap();

        let result = read_bounded_file(&file_path, MAX_ENVELOPE_FILE_SIZE);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), content);
    }
}
