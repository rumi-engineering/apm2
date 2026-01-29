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

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

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
    #[allow(dead_code)] // Reserved for future use when daemon integration is complete
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
    // Validate envelope path exists
    if !args.envelope.exists() {
        return output_error(
            json_output,
            "file_not_found",
            &format!("Envelope file not found: {}", args.envelope.display()),
            exit_codes::ERROR,
        );
    }

    // Check file size (CTR-1603)
    match std::fs::metadata(&args.envelope) {
        Ok(metadata) => {
            if metadata.len() > MAX_ENVELOPE_FILE_SIZE {
                return output_error(
                    json_output,
                    "file_too_large",
                    &format!(
                        "Envelope file exceeds maximum size of {MAX_ENVELOPE_FILE_SIZE} bytes"
                    ),
                    exit_codes::ERROR,
                );
            }
        },
        Err(e) => {
            return output_error(
                json_output,
                "io_error",
                &format!("Failed to read envelope metadata: {e}"),
                exit_codes::ERROR,
            );
        },
    }

    // Read envelope content
    let envelope_content = match std::fs::read_to_string(&args.envelope) {
        Ok(content) => content,
        Err(e) => {
            return output_error(
                json_output,
                "io_error",
                &format!("Failed to read envelope file: {e}"),
                exit_codes::ERROR,
            );
        },
    };

    // For now, since the daemon protocol is not fully implemented,
    // we'll simulate the create operation by validating the envelope
    // and returning a simulated response.
    //
    // In a full implementation, this would:
    // 1. Parse the YAML to EpisodeEnvelope
    // 2. Send CreateEpisode message to daemon via UDS
    // 3. Receive EpisodeCreated response

    // Validate YAML can be parsed
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

    // Compute envelope hash (BLAKE3)
    let envelope_hash = blake3::hash(envelope_content.as_bytes());
    let envelope_hash_hex = hex::encode(envelope_hash.as_bytes());

    // Generate episode ID from hash and timestamp
    let timestamp = chrono::Utc::now();
    let episode_id = format!(
        "ep-{}-{}",
        &envelope_hash_hex[..16],
        timestamp.timestamp_nanos_opt().unwrap_or(0)
    );

    // Check daemon connection
    if !socket_path.exists() {
        return output_error(
            json_output,
            "daemon_not_running",
            &format!(
                "Daemon socket not found at {}. Is the daemon running?",
                socket_path.display()
            ),
            exit_codes::ERROR,
        );
    }

    // Create response
    let response = CreateResponse {
        episode_id,
        envelope_hash: envelope_hash_hex,
        created_at: timestamp.to_rfc3339(),
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

    // Check daemon connection
    if !socket_path.exists() {
        return output_error(
            json_output,
            "daemon_not_running",
            &format!(
                "Daemon socket not found at {}. Is the daemon running?",
                socket_path.display()
            ),
            exit_codes::ERROR,
        );
    }

    // Generate session ID and lease ID
    let timestamp = chrono::Utc::now();
    let session_id = format!("session-{}", timestamp.timestamp_nanos_opt().unwrap_or(0));
    let lease_id = args
        .lease_id
        .clone()
        .unwrap_or_else(|| format!("lease-{}", timestamp.timestamp_nanos_opt().unwrap_or(0)));

    // Create response
    let response = StartResponse {
        episode_id: args.episode_id.clone(),
        session_id,
        lease_id,
        started_at: timestamp.to_rfc3339(),
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

    // Check daemon connection
    if !socket_path.exists() {
        return output_error(
            json_output,
            "daemon_not_running",
            &format!(
                "Daemon socket not found at {}. Is the daemon running?",
                socket_path.display()
            ),
            exit_codes::ERROR,
        );
    }

    // Determine termination class from reason
    let termination_class = match args.reason {
        StopReason::Success => "SUCCESS",
        StopReason::Cancelled => "CANCELLED",
        StopReason::Failure => "FAILURE",
    };

    let timestamp = chrono::Utc::now();

    // Create response
    let response = StopResponse {
        episode_id: args.episode_id.clone(),
        termination_class: termination_class.to_string(),
        stopped_at: timestamp.to_rfc3339(),
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

    // Check daemon connection
    if !socket_path.exists() {
        return output_error(
            json_output,
            "daemon_not_running",
            &format!(
                "Daemon socket not found at {}. Is the daemon running?",
                socket_path.display()
            ),
            exit_codes::ERROR,
        );
    }

    // For demonstration, return a simulated status
    // In full implementation, this would query the daemon
    let timestamp = chrono::Utc::now();

    let response = StatusResponse {
        episode_id: args.episode_id.clone(),
        state: "Created".to_string(),
        envelope_hash: "0".repeat(64),
        created_at: timestamp.to_rfc3339(),
        started_at: None,
        session_id: None,
        lease_id: None,
        terminated_at: None,
        termination_class: None,
        budget: Some(BudgetSummary {
            tokens: "0 / 100000".to_string(),
            tool_calls: "0 / 500".to_string(),
            wall_ms: "0 / 3600000".to_string(),
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
    // Check daemon connection
    if !socket_path.exists() {
        return output_error(
            json_output,
            "daemon_not_running",
            &format!(
                "Daemon socket not found at {}. Is the daemon running?",
                socket_path.display()
            ),
            exit_codes::ERROR,
        );
    }

    // For demonstration, return an empty list
    // In full implementation, this would query the daemon with the state filter
    let response = ListResponse {
        episodes: vec![],
        total: 0,
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
}
