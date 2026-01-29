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
//!
//! # JSON Output
//!
//! All commands support `--json` flag for machine-readable output.
//!
//! # Exit Codes
//!
//! - 0: Success
//! - 1: Error (daemon connection, validation, etc.)
//! - 2: Episode not found
//!
//! # Contract References
//!
//! - AD-DAEMON-002: UDS transport with length-prefixed framing
//! - AD-EPISODE-001: Immutable episode envelope
//! - AD-EPISODE-002: Episode state machine

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use apm2_core::ipc::ErrorCode;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::client::daemon::{DaemonClient, DaemonClientError};

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

// ============================================================================
// Response Types for JSON output
// ============================================================================

/// Response for episode create command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateResponse {
    /// Created episode ID.
    pub episode_id: String,
    /// Envelope hash (BLAKE3).
    pub envelope_hash: String,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
}

/// Response for episode start command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopResponse {
    /// Episode ID.
    pub episode_id: String,
    /// Termination class.
    pub termination_class: String,
    /// Stop timestamp (RFC 3339).
    pub stopped_at: String,
}

/// Response for episode status command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSummary {
    /// Tokens used / total.
    pub tokens: String,
    /// Tool calls used / total.
    pub tool_calls: String,
    /// Wall time used / total (ms).
    pub wall_ms: String,
}

/// Episode summary for list command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

// ============================================================================
// Command execution
// ============================================================================

/// Runs the episode command, returning an appropriate exit code.
///
/// # Exit Codes
///
/// - 0: Success
/// - 1: General error
/// - 2: Episode not found
#[allow(clippy::too_many_lines)] // Command dispatch is inherently verbose
pub fn run_episode(cmd: &EpisodeCommand, socket_path: &std::path::Path) -> u8 {
    let json_output = cmd.json;

    match &cmd.subcommand {
        EpisodeSubcommand::Create(args) => run_create(args, socket_path, json_output),
        EpisodeSubcommand::Start(args) => run_start(args, socket_path, json_output),
        EpisodeSubcommand::Stop(args) => run_stop(args, socket_path, json_output),
        EpisodeSubcommand::Status(args) => run_status(args, socket_path, json_output),
        EpisodeSubcommand::List(args) => run_list(args, socket_path, json_output),
    }
}

/// Execute the create command.
fn run_create(args: &CreateArgs, socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Read envelope content with TOCTOU-safe bounded reading (CTR-1603, RSK-1501).
    // Opens file handle first, uses .take(limit) pattern to enforce size limit.
    let envelope_content = match read_bounded_file(&args.envelope, MAX_ENVELOPE_FILE_SIZE) {
        Ok(content) => content,
        Err((code, message)) => {
            return output_error(json_output, &code, &message, exit_codes::ERROR);
        },
    };

    // Validate YAML can be parsed (local validation before daemon call)
    let envelope_value: serde_yaml::Value = match serde_yaml::from_str(&envelope_content) {
        Ok(v) => v,
        Err(e) => {
            return output_error(
                json_output,
                "invalid_yaml",
                &format!("Failed to parse envelope YAML: {e}"),
                exit_codes::ERROR,
            );
        },
    };

    // Compute envelope hash (BLAKE3) for daemon request
    let envelope_hash = blake3::hash(envelope_content.as_bytes());
    let envelope_hash_hex = hex::encode(envelope_hash.as_bytes());

    // Send CreateEpisode request to daemon (episode ID is daemon-generated)
    let client = DaemonClient::new(socket_path);

    let daemon_response = match client.create_episode(&envelope_content, &envelope_hash_hex) {
        Ok(resp) => resp,
        Err(e) => {
            return handle_daemon_error(json_output, &e);
        },
    };

    // Build response from daemon-provided data
    let response = CreateResponse {
        episode_id: daemon_response.episode_id,
        envelope_hash: daemon_response.envelope_hash,
        created_at: daemon_response.created_at,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Episode created successfully");
        println!("  Episode ID:    {}", response.episode_id);
        println!("  Envelope Hash: {}", response.envelope_hash);
        println!("  Created At:    {}", response.created_at);

        // Print envelope summary if we can extract it
        if let Some(actor_id) = envelope_value.get("actor_id").and_then(|v| v.as_str()) {
            println!("  Actor ID:      {actor_id}");
        }
        if let Some(risk_tier) = envelope_value
            .get("risk_tier")
            .and_then(serde_yaml::Value::as_u64)
        {
            println!("  Risk Tier:     {risk_tier}");
        }
    }

    exit_codes::SUCCESS
}

/// Execute the start command.
fn run_start(args: &StartArgs, socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Validate episode ID format
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_id",
            "Episode ID cannot be empty",
            exit_codes::ERROR,
        );
    }

    if !args.episode_id.starts_with("ep-") {
        return output_error(
            json_output,
            "invalid_id",
            "Episode ID must start with 'ep-'",
            exit_codes::ERROR,
        );
    }

    // Send StartEpisode request to daemon
    let client = DaemonClient::new(socket_path);

    let daemon_response = match client.start_episode(&args.episode_id, args.lease_id.as_deref()) {
        Ok(resp) => resp,
        Err(e) => {
            return handle_daemon_error(json_output, &e);
        },
    };

    // Build response from daemon-provided data
    let response = StartResponse {
        episode_id: daemon_response.episode_id,
        session_id: daemon_response.session_id,
        lease_id: daemon_response.lease_id,
        started_at: daemon_response.started_at,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Episode started successfully");
        println!("  Episode ID:  {}", response.episode_id);
        println!("  Session ID:  {}", response.session_id);
        println!("  Lease ID:    {}", response.lease_id);
        println!("  Started At:  {}", response.started_at);
    }

    exit_codes::SUCCESS
}

/// Execute the stop command.
fn run_stop(args: &StopArgs, socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Validate episode ID format
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_id",
            "Episode ID cannot be empty",
            exit_codes::ERROR,
        );
    }

    // Send StopEpisode request to daemon
    let client = DaemonClient::new(socket_path);
    let reason_str = args.reason.to_string();

    let daemon_response =
        match client.stop_episode(&args.episode_id, &reason_str, args.message.as_deref()) {
            Ok(resp) => resp,
            Err(e) => {
                return handle_daemon_error(json_output, &e);
            },
        };

    // Build response from daemon-provided data
    let response = StopResponse {
        episode_id: daemon_response.episode_id,
        termination_class: daemon_response.termination_class,
        stopped_at: daemon_response.stopped_at,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Episode stopped successfully");
        println!("  Episode ID:         {}", response.episode_id);
        println!("  Termination Class:  {}", response.termination_class);
        println!("  Stopped At:         {}", response.stopped_at);
        if let Some(msg) = &args.message {
            println!("  Message:            {msg}");
        }
    }

    exit_codes::SUCCESS
}

/// Execute the status command.
fn run_status(args: &StatusArgs, socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Validate episode ID format
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_id",
            "Episode ID cannot be empty",
            exit_codes::ERROR,
        );
    }

    // Send GetEpisodeStatus request to daemon
    let client = DaemonClient::new(socket_path);

    let daemon_response = match client.get_episode_status(&args.episode_id) {
        Ok(resp) => resp,
        Err(e) => {
            return handle_daemon_error(json_output, &e);
        },
    };

    // Build response from daemon-provided data
    let response = StatusResponse {
        episode_id: daemon_response.episode_id,
        state: daemon_response.state,
        envelope_hash: daemon_response.envelope_hash,
        created_at: daemon_response.created_at,
        started_at: daemon_response.started_at,
        session_id: daemon_response.session_id,
        lease_id: daemon_response.lease_id,
        terminated_at: daemon_response.terminated_at,
        termination_class: daemon_response.termination_class,
        budget: daemon_response.budget.map(|b| BudgetSummary {
            tokens: b.tokens,
            tool_calls: b.tool_calls,
            wall_ms: b.wall_ms,
        }),
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Episode Status");
        println!("  Episode ID:    {}", response.episode_id);
        println!("  State:         {}", response.state);
        println!("  Envelope Hash: {}", response.envelope_hash);
        println!("  Created At:    {}", response.created_at);
        if let Some(started) = &response.started_at {
            println!("  Started At:    {started}");
        }
        if let Some(session) = &response.session_id {
            println!("  Session ID:    {session}");
        }
        if let Some(lease) = &response.lease_id {
            println!("  Lease ID:      {lease}");
        }
        if let Some(budget) = &response.budget {
            println!();
            println!("Budget:");
            println!("  Tokens:     {}", budget.tokens);
            println!("  Tool Calls: {}", budget.tool_calls);
            println!("  Wall Time:  {}", budget.wall_ms);
        }
    }

    exit_codes::SUCCESS
}

/// Execute the list command.
fn run_list(args: &ListArgs, socket_path: &std::path::Path, json_output: bool) -> u8 {
    // Send ListEpisodes request to daemon
    let client = DaemonClient::new(socket_path);

    // Convert state filter to string for daemon
    let state_filter = match args.state {
        StateFilter::All => None,
        StateFilter::Created => Some("created"),
        StateFilter::Running => Some("running"),
        StateFilter::Terminated => Some("terminated"),
        StateFilter::Quarantined => Some("quarantined"),
    };

    let daemon_response = match client.list_episodes(state_filter, args.limit) {
        Ok(resp) => resp,
        Err(e) => {
            return handle_daemon_error(json_output, &e);
        },
    };

    // Build response from daemon-provided data
    let response = ListResponse {
        episodes: daemon_response
            .episodes
            .into_iter()
            .map(|ep| EpisodeSummary {
                episode_id: ep.episode_id,
                state: ep.state,
                created_at: ep.created_at,
                session_id: ep.session_id,
            })
            .collect(),
        total: daemon_response.total,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else if response.episodes.is_empty() {
        println!("No episodes found (filter: {})", args.state);
    } else {
        println!(
            "{:<40} {:<12} {:<25} {:<20}",
            "EPISODE ID", "STATE", "CREATED AT", "SESSION ID"
        );
        println!("{}", "-".repeat(97));
        for ep in &response.episodes {
            println!(
                "{:<40} {:<12} {:<25} {:<20}",
                truncate(&ep.episode_id, 40),
                ep.state,
                ep.created_at,
                ep.session_id.as_deref().unwrap_or("-"),
            );
        }
        println!();
        println!("Total: {} episodes", response.total);
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
fn handle_daemon_error(json_output: bool, error: &DaemonClientError) -> u8 {
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
    }
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
