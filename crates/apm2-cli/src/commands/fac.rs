//! FAC (Forge Admission Cycle) productivity CLI commands.
//!
//! This module implements the `apm2 fac` subcommands for ledger/CAS-oriented
//! debugging and productivity per TCK-00333 and RFC-0019.
//!
//! # Commands
//!
//! - `apm2 fac work status <work_id>` - Show work status from ledger
//! - `apm2 fac episode inspect <episode_id>` - Show episode details and tool log index
//! - `apm2 fac receipt show <receipt_hash>` - Show receipt from CAS
//! - `apm2 fac context rebuild <role> <episode_id>` - Rebuild role-scoped context
//! - `apm2 fac resume <work_id>` - Show crash-only resume helpers from ledger anchor
//!
//! # Design
//!
//! These commands operate directly on ledger and CAS files, enabling debugging
//! without requiring a running daemon. This supports crash-only recovery and
//! deterministic context rebuild for FAC v0.
//!
//! # Exit Codes (RFC-0018)
//!
//! - 0: Success
//! - 10: Validation error
//! - 12: Not found
//! - 1: Generic error
//!
//! # Contract References
//!
//! - TCK-00333: FAC productivity CLI/scripts (ledger/CAS oriented debug UX)
//! - RFC-0019: FAC v0 requirements

use std::path::{Path, PathBuf};

use apm2_core::fac::{ToolLogIndexV1, TOOL_LOG_INDEX_V1_SCHEMA};
use apm2_core::ledger::{EventRecord, Ledger, LedgerError};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of events to scan when searching for work/episode data.
const MAX_SCAN_EVENTS: u64 = 10_000;

/// Default ledger path relative to data directory.
const DEFAULT_LEDGER_FILENAME: &str = "ledger.db";

/// Default CAS path relative to data directory.
const DEFAULT_CAS_DIRNAME: &str = "cas";

// =============================================================================
// Command Types
// =============================================================================

/// FAC command group.
#[derive(Debug, Args)]
pub struct FacCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
    pub json: bool,

    /// Path to ledger database (defaults to `$APM2_DATA_DIR/ledger.db`).
    #[arg(long)]
    pub ledger_path: Option<PathBuf>,

    /// Path to CAS directory (defaults to `$APM2_DATA_DIR/cas`).
    #[arg(long)]
    pub cas_path: Option<PathBuf>,

    #[command(subcommand)]
    pub subcommand: FacSubcommand,
}

/// FAC subcommands.
#[derive(Debug, Subcommand)]
pub enum FacSubcommand {
    /// Show work status from ledger.
    ///
    /// Displays the current status of a work item including claims, episodes,
    /// and latest receipt hashes. Operates directly on ledger without daemon.
    Work(WorkArgs),

    /// Inspect episode details and tool log index.
    ///
    /// Shows episode metadata and tool execution summary from ledger events.
    /// Allows inspecting tool log index entries without raw log parsing.
    Episode(EpisodeArgs),

    /// Show receipt from CAS.
    ///
    /// Retrieves and displays a receipt artifact from content-addressed storage
    /// by its hash. Supports gate receipts, review receipts, and summary receipts.
    Receipt(ReceiptArgs),

    /// Rebuild role-scoped context deterministically.
    ///
    /// Reconstructs the context pack for a role+episode combination from
    /// ledger events and CAS artifacts. Useful for debugging and replay.
    Context(ContextArgs),

    /// Show crash-only resume helpers from ledger anchor.
    ///
    /// Analyzes ledger to determine restart point for interrupted work.
    /// Returns the last committed anchor and pending operations.
    Resume(ResumeArgs),
}

/// Arguments for `apm2 fac work`.
#[derive(Debug, Args)]
pub struct WorkArgs {
    #[command(subcommand)]
    pub subcommand: WorkSubcommand,
}

/// Work subcommands.
#[derive(Debug, Subcommand)]
pub enum WorkSubcommand {
    /// Show work status from ledger.
    Status(WorkStatusArgs),
}

/// Arguments for `apm2 fac work status`.
#[derive(Debug, Args)]
pub struct WorkStatusArgs {
    /// Work identifier to query.
    pub work_id: String,
}

/// Arguments for `apm2 fac episode`.
#[derive(Debug, Args)]
pub struct EpisodeArgs {
    #[command(subcommand)]
    pub subcommand: EpisodeSubcommand,
}

/// Episode subcommands.
#[derive(Debug, Subcommand)]
pub enum EpisodeSubcommand {
    /// Inspect episode details and tool log index.
    Inspect(EpisodeInspectArgs),
}

/// Arguments for `apm2 fac episode inspect`.
#[derive(Debug, Args)]
pub struct EpisodeInspectArgs {
    /// Episode identifier to inspect.
    pub episode_id: String,

    /// Show full tool log index (default: summary only).
    #[arg(long)]
    pub full: bool,
}

/// Arguments for `apm2 fac receipt`.
#[derive(Debug, Args)]
pub struct ReceiptArgs {
    #[command(subcommand)]
    pub subcommand: ReceiptSubcommand,
}

/// Receipt subcommands.
#[derive(Debug, Subcommand)]
pub enum ReceiptSubcommand {
    /// Show receipt from CAS.
    Show(ReceiptShowArgs),
}

/// Arguments for `apm2 fac receipt show`.
#[derive(Debug, Args)]
pub struct ReceiptShowArgs {
    /// Receipt hash (hex-encoded BLAKE3).
    pub receipt_hash: String,
}

/// Arguments for `apm2 fac context`.
#[derive(Debug, Args)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub subcommand: ContextSubcommand,
}

/// Context subcommands.
#[derive(Debug, Subcommand)]
pub enum ContextSubcommand {
    /// Rebuild role-scoped context deterministically.
    Rebuild(ContextRebuildArgs),
}

/// Arguments for `apm2 fac context rebuild`.
#[derive(Debug, Args)]
pub struct ContextRebuildArgs {
    /// Role for context rebuild (implementer, reviewer, etc.).
    pub role: String,

    /// Episode identifier.
    pub episode_id: String,

    /// Output directory for rebuilt context.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,
}

/// Arguments for `apm2 fac resume`.
#[derive(Debug, Args)]
pub struct ResumeArgs {
    /// Work identifier to analyze for resume point.
    pub work_id: String,
}

// =============================================================================
// Response Types
// =============================================================================

/// Response for work status command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkStatusResponse {
    /// Work identifier.
    pub work_id: String,
    /// Current work status inferred from ledger.
    pub status: String,
    /// Actor who claimed this work (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    /// Role of the actor (if claimed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Latest episode ID associated with this work.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_episode_id: Option<String>,
    /// Latest receipt hash (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_receipt_hash: Option<String>,
    /// Number of events found for this work.
    pub event_count: u64,
    /// Ledger sequence ID of the latest event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_seq_id: Option<u64>,
}

/// Response for episode inspect command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeInspectResponse {
    /// Episode identifier.
    pub episode_id: String,
    /// Episode status inferred from ledger.
    pub status: String,
    /// Associated work ID (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_id: Option<String>,
    /// Actor ID (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    /// Role (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Tool log index summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_log_summary: Option<ToolLogSummary>,
    /// Full tool log index (if --full flag).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_log_index: Option<ToolLogIndexV1>,
    /// Number of events found for this episode.
    pub event_count: u64,
}

/// Summary of tool log index.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLogSummary {
    /// Total tool executions.
    pub total_executions: u64,
    /// Successful executions.
    pub successful_executions: u64,
    /// Failed executions.
    pub failed_executions: u64,
    /// Total tokens consumed.
    pub total_tokens: u64,
    /// Total I/O bytes.
    pub total_bytes_io: u64,
    /// Total wall time in milliseconds.
    pub total_wall_ms: u64,
}

/// Response for receipt show command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptShowResponse {
    /// Receipt hash (hex-encoded).
    pub hash: String,
    /// Receipt type (`gate_receipt`, `review_receipt`, `summary_receipt`, etc.).
    pub receipt_type: String,
    /// Receipt size in bytes.
    pub size_bytes: u64,
    /// Receipt content (JSON parsed if possible).
    pub content: serde_json::Value,
}

/// Response for context rebuild command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRebuildResponse {
    /// Role used for rebuild.
    pub role: String,
    /// Episode ID.
    pub episode_id: String,
    /// Output directory path.
    pub output_dir: String,
    /// Context pack hash (hex-encoded).
    pub context_pack_hash: String,
    /// Number of artifacts retrieved from CAS.
    pub artifacts_retrieved: u64,
    /// Whether rebuild was deterministic (matched expected hash).
    pub deterministic: bool,
}

/// Response for resume command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeResponse {
    /// Work identifier.
    pub work_id: String,
    /// Last committed anchor sequence ID.
    pub last_anchor_seq_id: u64,
    /// Last committed anchor event type.
    pub last_anchor_event_type: String,
    /// Recommended restart action.
    pub restart_action: String,
    /// Pending operations (if any).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending_operations: Vec<String>,
    /// Last episode ID (if work was in progress).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_episode_id: Option<String>,
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

// =============================================================================
// Command Execution
// =============================================================================

/// Runs the FAC command, returning an appropriate exit code.
pub fn run_fac(cmd: &FacCommand) -> u8 {
    let json_output = cmd.json;
    let ledger_path = resolve_ledger_path(cmd.ledger_path.as_deref());
    let cas_path = resolve_cas_path(cmd.cas_path.as_deref());

    match &cmd.subcommand {
        FacSubcommand::Work(args) => match &args.subcommand {
            WorkSubcommand::Status(status_args) => {
                run_work_status(status_args, &ledger_path, json_output)
            },
        },
        FacSubcommand::Episode(args) => match &args.subcommand {
            EpisodeSubcommand::Inspect(inspect_args) => {
                run_episode_inspect(inspect_args, &ledger_path, &cas_path, json_output)
            },
        },
        FacSubcommand::Receipt(args) => match &args.subcommand {
            ReceiptSubcommand::Show(show_args) => {
                run_receipt_show(show_args, &cas_path, json_output)
            },
        },
        FacSubcommand::Context(args) => match &args.subcommand {
            ContextSubcommand::Rebuild(rebuild_args) => {
                run_context_rebuild(rebuild_args, &ledger_path, &cas_path, json_output)
            },
        },
        FacSubcommand::Resume(args) => run_resume(args, &ledger_path, json_output),
    }
}

/// Resolves the ledger path from explicit path, env var, or default.
fn resolve_ledger_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }

    if let Ok(data_dir) = std::env::var("APM2_DATA_DIR") {
        return PathBuf::from(data_dir).join(DEFAULT_LEDGER_FILENAME);
    }

    // Default to XDG data directory
    directories::ProjectDirs::from("com", "apm2", "apm2").map_or_else(
        || PathBuf::from("/var/lib/apm2").join(DEFAULT_LEDGER_FILENAME),
        |dirs| dirs.data_dir().join(DEFAULT_LEDGER_FILENAME),
    )
}

/// Resolves the CAS path from explicit path, env var, or default.
fn resolve_cas_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }

    if let Ok(data_dir) = std::env::var("APM2_DATA_DIR") {
        return PathBuf::from(data_dir).join(DEFAULT_CAS_DIRNAME);
    }

    // Default to XDG data directory
    directories::ProjectDirs::from("com", "apm2", "apm2").map_or_else(
        || PathBuf::from("/var/lib/apm2").join(DEFAULT_CAS_DIRNAME),
        |dirs| dirs.data_dir().join(DEFAULT_CAS_DIRNAME),
    )
}

/// Opens the ledger at the given path.
fn open_ledger(path: &Path) -> Result<Ledger, LedgerError> {
    if !path.exists() {
        return Err(LedgerError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Ledger not found at: {}", path.display()),
        )));
    }
    Ledger::open(path)
}

// =============================================================================
// Work Status Command
// =============================================================================

/// Execute the work status command.
fn run_work_status(args: &WorkStatusArgs, ledger_path: &Path, json_output: bool) -> u8 {
    // Validate work ID
    if args.work_id.is_empty() {
        return output_error(
            json_output,
            "invalid_work_id",
            "Work ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Open ledger
    let ledger = match open_ledger(ledger_path) {
        Ok(l) => l,
        Err(e) => {
            return output_error(
                json_output,
                "ledger_error",
                &format!("Failed to open ledger: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Scan ledger for work-related events
    let mut response = WorkStatusResponse {
        work_id: args.work_id.clone(),
        status: "UNKNOWN".to_string(),
        actor_id: None,
        role: None,
        latest_episode_id: None,
        latest_receipt_hash: None,
        event_count: 0,
        latest_seq_id: None,
    };

    let mut cursor = 1u64;
    let batch_size = 1000u64;

    loop {
        let events = match ledger.read_from(cursor, batch_size) {
            Ok(events) => events,
            Err(e) => {
                return output_error(
                    json_output,
                    "ledger_error",
                    &format!("Failed to read ledger: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };

        if events.is_empty() {
            break;
        }

        for event in &events {
            if let Some(work_info) = extract_work_info(event, &args.work_id) {
                response.event_count += 1;
                response.latest_seq_id = event.seq_id;

                // Update status based on event type
                match event.event_type.as_str() {
                    "work_claimed" => {
                        response.status = "CLAIMED".to_string();
                        response.actor_id = work_info.actor_id;
                        response.role = work_info.role;
                    },
                    "episode_spawned" => {
                        response.status = "IN_PROGRESS".to_string();
                        response.latest_episode_id = work_info.episode_id;
                    },
                    "session_terminated" => {
                        response.status = "COMPLETED".to_string();
                    },
                    "gate_receipt" | "review_receipt" | "merge_receipt" => {
                        if let Some(hash) = event.event_hash.as_ref() {
                            response.latest_receipt_hash = Some(hex::encode(hash));
                        }
                    },
                    _ => {},
                }
            }
        }

        cursor = events.last().map_or(cursor, |e| e.seq_id.unwrap_or(0) + 1);

        // Safety limit
        if cursor > MAX_SCAN_EVENTS {
            break;
        }
    }

    if response.event_count == 0 {
        return output_error(
            json_output,
            "not_found",
            &format!("No events found for work_id: {}", args.work_id),
            exit_codes::NOT_FOUND,
        );
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Work Status");
        println!("  Work ID:            {}", response.work_id);
        println!("  Status:             {}", response.status);
        if let Some(actor) = &response.actor_id {
            println!("  Actor ID:           {actor}");
        }
        if let Some(role) = &response.role {
            println!("  Role:               {role}");
        }
        if let Some(episode) = &response.latest_episode_id {
            println!("  Latest Episode:     {episode}");
        }
        if let Some(receipt) = &response.latest_receipt_hash {
            println!("  Latest Receipt:     {receipt}");
        }
        println!("  Events Found:       {}", response.event_count);
        if let Some(seq_id) = response.latest_seq_id {
            println!("  Latest Seq ID:      {seq_id}");
        }
    }

    exit_codes::SUCCESS
}

/// Extracted work information from an event.
struct WorkInfo {
    actor_id: Option<String>,
    role: Option<String>,
    episode_id: Option<String>,
}

/// Extracts work-related information from an event if it matches the `work_id`.
fn extract_work_info(event: &EventRecord, work_id: &str) -> Option<WorkInfo> {
    // Try to parse payload as JSON and check for work_id field
    let payload: serde_json::Value = match serde_json::from_slice(&event.payload) {
        Ok(v) => v,
        Err(_) => return None,
    };

    // Check if this event is for the requested work_id
    let event_work_id = payload.get("work_id").and_then(|v| v.as_str())?;
    if event_work_id != work_id {
        return None;
    }

    Some(WorkInfo {
        actor_id: payload
            .get("actor_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        role: payload
            .get("role")
            .and_then(|v| v.as_str())
            .map(String::from),
        episode_id: payload
            .get("episode_id")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

// =============================================================================
// Episode Inspect Command
// =============================================================================

/// Execute the episode inspect command.
fn run_episode_inspect(
    args: &EpisodeInspectArgs,
    ledger_path: &Path,
    cas_path: &Path,
    json_output: bool,
) -> u8 {
    // Validate episode ID
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_episode_id",
            "Episode ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Open ledger
    let ledger = match open_ledger(ledger_path) {
        Ok(l) => l,
        Err(e) => {
            return output_error(
                json_output,
                "ledger_error",
                &format!("Failed to open ledger: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Scan ledger for episode-related events
    let mut response = EpisodeInspectResponse {
        episode_id: args.episode_id.clone(),
        status: "UNKNOWN".to_string(),
        work_id: None,
        actor_id: None,
        role: None,
        tool_log_summary: None,
        tool_log_index: None,
        event_count: 0,
    };

    let mut tool_log_index_hash: Option<Vec<u8>> = None;
    let mut cursor = 1u64;
    let batch_size = 1000u64;

    loop {
        let events = match ledger.read_from(cursor, batch_size) {
            Ok(events) => events,
            Err(e) => {
                return output_error(
                    json_output,
                    "ledger_error",
                    &format!("Failed to read ledger: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };

        if events.is_empty() {
            break;
        }

        for event in &events {
            if let Some(episode_info) = extract_episode_info(event, &args.episode_id) {
                response.event_count += 1;

                // Update status based on event type
                match event.event_type.as_str() {
                    "episode_spawned" => {
                        response.status = "SPAWNED".to_string();
                        response.work_id = episode_info.work_id;
                        response.actor_id = Some(event.actor_id.clone());
                        response.role = episode_info.role;
                    },
                    "tool_executed" | "tool_decided" => {
                        response.status = "RUNNING".to_string();
                    },
                    "session_terminated" => {
                        response.status = "TERMINATED".to_string();
                        tool_log_index_hash = episode_info.tool_log_index_hash;
                    },
                    _ => {},
                }
            }
        }

        cursor = events.last().map_or(cursor, |e| e.seq_id.unwrap_or(0) + 1);

        // Safety limit
        if cursor > MAX_SCAN_EVENTS {
            break;
        }
    }

    if response.event_count == 0 {
        return output_error(
            json_output,
            "not_found",
            &format!("No events found for episode_id: {}", args.episode_id),
            exit_codes::NOT_FOUND,
        );
    }

    // Try to load tool log index from CAS if we have a hash
    if let Some(hash) = tool_log_index_hash {
        if let Some(index) = load_tool_log_index_from_cas(cas_path, &hash) {
            response.tool_log_summary = Some(ToolLogSummary {
                total_executions: index.counts.total_executions,
                successful_executions: index.counts.successful_executions,
                failed_executions: index.counts.failed_executions,
                total_tokens: index.counts.total_tokens,
                total_bytes_io: index.counts.total_bytes_io,
                total_wall_ms: index.counts.total_wall_ms,
            });

            if args.full {
                response.tool_log_index = Some(index);
            }
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Episode Details");
        println!("  Episode ID:         {}", response.episode_id);
        println!("  Status:             {}", response.status);
        if let Some(work_id) = &response.work_id {
            println!("  Work ID:            {work_id}");
        }
        if let Some(actor) = &response.actor_id {
            println!("  Actor ID:           {actor}");
        }
        if let Some(role) = &response.role {
            println!("  Role:               {role}");
        }
        println!("  Events Found:       {}", response.event_count);

        if let Some(summary) = &response.tool_log_summary {
            println!();
            println!("Tool Log Summary");
            println!("  Total Executions:   {}", summary.total_executions);
            println!(
                "  Successful:         {}",
                summary.successful_executions
            );
            println!("  Failed:             {}", summary.failed_executions);
            println!("  Total Tokens:       {}", summary.total_tokens);
            println!("  Total I/O Bytes:    {}", summary.total_bytes_io);
            println!("  Total Wall Time:    {} ms", summary.total_wall_ms);
        }

        if args.full {
            if let Some(index) = &response.tool_log_index {
                println!();
                println!("Tool Log Index (full)");
                println!(
                    "  Schema:             {}",
                    index.schema
                );
                println!(
                    "  Receipt Count:      {}",
                    index.tool_execution_receipt_hashes.len()
                );
                println!("  First Sequence:     {}", index.first_sequence);
                println!("  Is Final Chunk:     {}", index.is_final_chunk);

                if !index.tool_execution_receipt_hashes.is_empty() {
                    println!();
                    println!("Receipt Hashes:");
                    for (i, hash) in index.tool_execution_receipt_hashes.iter().enumerate() {
                        println!("  [{i}] {hash}");
                    }
                }
            }
        }
    }

    exit_codes::SUCCESS
}

/// Extracted episode information from an event.
struct EpisodeInfo {
    work_id: Option<String>,
    role: Option<String>,
    tool_log_index_hash: Option<Vec<u8>>,
}

/// Extracts episode-related information from an event if it matches the `episode_id`.
fn extract_episode_info(event: &EventRecord, episode_id: &str) -> Option<EpisodeInfo> {
    // Check session_id first (episodes often use session_id == episode_id)
    if event.session_id == episode_id {
        let payload: serde_json::Value = serde_json::from_slice(&event.payload).ok()?;
        return Some(EpisodeInfo {
            work_id: payload
                .get("work_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            role: payload
                .get("role")
                .and_then(|v| v.as_str())
                .map(String::from),
            tool_log_index_hash: payload
                .get("tool_log_index_hash")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok()),
        });
    }

    // Try payload check for episode_id field
    let payload: serde_json::Value = serde_json::from_slice(&event.payload).ok()?;
    let event_episode_id = payload.get("episode_id").and_then(|v| v.as_str())?;
    if event_episode_id != episode_id {
        return None;
    }

    Some(EpisodeInfo {
        work_id: payload
            .get("work_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        role: payload
            .get("role")
            .and_then(|v| v.as_str())
            .map(String::from),
        tool_log_index_hash: payload
            .get("tool_log_index_hash")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok()),
    })
}

/// Loads a tool log index from CAS by hash.
fn load_tool_log_index_from_cas(cas_path: &Path, hash: &[u8]) -> Option<ToolLogIndexV1> {
    let hex_hash = hex::encode(hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    let file_path = cas_path.join("objects").join(prefix).join(suffix);

    let content = std::fs::read(&file_path).ok()?;

    // Verify hash
    let computed_hash = blake3::hash(&content);
    if computed_hash.as_bytes() != hash {
        return None;
    }

    // Parse as JSON
    let index: ToolLogIndexV1 = serde_json::from_slice(&content).ok()?;

    // Validate schema
    if index.schema != TOOL_LOG_INDEX_V1_SCHEMA {
        return None;
    }

    Some(index)
}

// =============================================================================
// Receipt Show Command
// =============================================================================

/// Execute the receipt show command.
fn run_receipt_show(args: &ReceiptShowArgs, cas_path: &Path, json_output: bool) -> u8 {
    // Validate receipt hash
    if args.receipt_hash.is_empty() {
        return output_error(
            json_output,
            "invalid_hash",
            "Receipt hash cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Parse hex hash
    let hash_bytes = match hex::decode(&args.receipt_hash) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(bytes) => {
            return output_error(
                json_output,
                "invalid_hash",
                &format!("Receipt hash must be 32 bytes, got {}", bytes.len()),
                exit_codes::VALIDATION_ERROR,
            );
        },
        Err(e) => {
            return output_error(
                json_output,
                "invalid_hash",
                &format!("Invalid hex encoding: {e}"),
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

    // Load from CAS
    let (prefix, suffix) = args.receipt_hash.split_at(4);
    let file_path = cas_path.join("objects").join(prefix).join(suffix);

    let content = match std::fs::read(&file_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return output_error(
                json_output,
                "not_found",
                &format!("Receipt not found in CAS: {}", args.receipt_hash),
                exit_codes::NOT_FOUND,
            );
        },
        Err(e) => {
            return output_error(
                json_output,
                "io_error",
                &format!("Failed to read CAS: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Verify hash
    let computed_hash = blake3::hash(&content);
    if computed_hash.as_bytes() != hash_bytes.as_slice() {
        return output_error(
            json_output,
            "hash_mismatch",
            "CAS content hash mismatch (possible corruption)",
            exit_codes::GENERIC_ERROR,
        );
    }

    // Try to parse as JSON and detect receipt type
    let (receipt_type, parsed_content) =
        serde_json::from_slice::<serde_json::Value>(&content).map_or_else(
            |_| {
                (
                    "binary".to_string(),
                    serde_json::Value::String(format!("<binary data, {} bytes>", content.len())),
                )
            },
            |json| {
                let receipt_type = detect_receipt_type(&json);
                (receipt_type, json)
            },
        );

    let response = ReceiptShowResponse {
        hash: args.receipt_hash.clone(),
        receipt_type,
        size_bytes: content.len() as u64,
        content: parsed_content,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Receipt Details");
        println!("  Hash:               {}", response.hash);
        println!("  Type:               {}", response.receipt_type);
        println!("  Size:               {} bytes", response.size_bytes);
        println!();
        println!("Content:");
        println!(
            "{}",
            serde_json::to_string_pretty(&response.content).unwrap_or_else(|_| "{}".to_string())
        );
    }

    exit_codes::SUCCESS
}

/// Detects the receipt type from JSON content.
fn detect_receipt_type(json: &serde_json::Value) -> String {
    // Check for schema field
    if let Some(schema) = json.get("schema").and_then(|v| v.as_str()) {
        if schema.contains("gate_receipt") {
            return "gate_receipt".to_string();
        }
        if schema.contains("review_receipt") || schema.contains("review_artifact") {
            return "review_receipt".to_string();
        }
        if schema.contains("summary_receipt") {
            return "summary_receipt".to_string();
        }
        if schema.contains("tool_log_index") {
            return "tool_log_index".to_string();
        }
        if schema.contains("tool_execution_receipt") {
            return "tool_execution_receipt".to_string();
        }
        if schema.contains("merge_receipt") {
            return "merge_receipt".to_string();
        }
        if schema.contains("projection") {
            return "projection_receipt".to_string();
        }
        return schema.to_string();
    }

    // Check for type-specific fields
    if json.get("verdict").is_some() && json.get("gate_id").is_some() {
        return "gate_receipt".to_string();
    }
    if json.get("review_verdict").is_some() {
        return "review_receipt".to_string();
    }
    if json.get("outcome").is_some() && json.get("summary_text").is_some() {
        return "summary_receipt".to_string();
    }

    "unknown".to_string()
}

// =============================================================================
// Context Rebuild Command
// =============================================================================

/// Execute the context rebuild command.
fn run_context_rebuild(
    args: &ContextRebuildArgs,
    ledger_path: &Path,
    cas_path: &Path,
    json_output: bool,
) -> u8 {
    // Validate inputs
    if args.role.is_empty() {
        return output_error(
            json_output,
            "invalid_role",
            "Role cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }
    if args.episode_id.is_empty() {
        return output_error(
            json_output,
            "invalid_episode_id",
            "Episode ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Determine output directory
    let output_dir = args.output_dir.clone().unwrap_or_else(|| {
        std::env::temp_dir()
            .join("apm2-context-rebuild")
            .join(&args.episode_id)
    });

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        return output_error(
            json_output,
            "io_error",
            &format!("Failed to create output directory: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    // Open ledger
    let ledger = match open_ledger(ledger_path) {
        Ok(l) => l,
        Err(e) => {
            return output_error(
                json_output,
                "ledger_error",
                &format!("Failed to open ledger: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Find episode spawn event to get context pack hash
    let mut context_pack_hash: Option<Vec<u8>> = None;
    let mut artifacts_retrieved = 0u64;
    let mut cursor = 1u64;
    let batch_size = 1000u64;

    loop {
        let events = match ledger.read_from(cursor, batch_size) {
            Ok(events) => events,
            Err(e) => {
                return output_error(
                    json_output,
                    "ledger_error",
                    &format!("Failed to read ledger: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };

        if events.is_empty() {
            break;
        }

        for event in &events {
            if event.event_type == "episode_spawned" {
                if let Some(info) = extract_episode_info(event, &args.episode_id) {
                    // Check role matches
                    if info.role.as_deref() == Some(args.role.as_str()) {
                        // Extract context pack hash from payload
                        if let Ok(payload) =
                            serde_json::from_slice::<serde_json::Value>(&event.payload)
                        {
                            context_pack_hash = payload
                                .get("context_pack_hash")
                                .and_then(|v| v.as_str())
                                .and_then(|s| hex::decode(s).ok());
                        }
                        break;
                    }
                }
            }
        }

        if context_pack_hash.is_some() {
            break;
        }

        cursor = events.last().map_or(cursor, |e| e.seq_id.unwrap_or(0) + 1);
        if cursor > MAX_SCAN_EVENTS {
            break;
        }
    }

    let Some(context_pack_hash) = context_pack_hash else {
        return output_error(
            json_output,
            "not_found",
            &format!(
                "No episode_spawned event found for episode {} with role {}",
                args.episode_id, args.role
            ),
            exit_codes::NOT_FOUND,
        );
    };

    // Load context pack from CAS
    let hex_hash = hex::encode(&context_pack_hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    let pack_path = cas_path.join("objects").join(prefix).join(suffix);

    let pack_content = match std::fs::read(&pack_path) {
        Ok(c) => c,
        Err(e) => {
            return output_error(
                json_output,
                "cas_error",
                &format!("Failed to read context pack from CAS: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Verify hash
    let computed_hash = blake3::hash(&pack_content);
    let deterministic = computed_hash.as_bytes() == context_pack_hash.as_slice();

    // Write context pack to output directory
    let pack_output_path = output_dir.join("context_pack.json");
    if let Err(e) = std::fs::write(&pack_output_path, &pack_content) {
        return output_error(
            json_output,
            "io_error",
            &format!("Failed to write context pack: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }
    artifacts_retrieved += 1;

    // Try to parse and extract referenced artifacts
    if let Ok(pack_json) = serde_json::from_slice::<serde_json::Value>(&pack_content) {
        // Extract artifact hashes and retrieve them
        if let Some(artifacts) = pack_json.get("artifacts").and_then(|v| v.as_array()) {
            for artifact in artifacts {
                if let Some(hash_str) = artifact.get("hash").and_then(|v| v.as_str()) {
                    if let Ok(artifact_hash) = hex::decode(hash_str) {
                        if retrieve_artifact_to_dir(cas_path, &artifact_hash, &output_dir).is_ok() {
                            artifacts_retrieved += 1;
                        }
                    }
                }
            }
        }
    }

    let response = ContextRebuildResponse {
        role: args.role.clone(),
        episode_id: args.episode_id.clone(),
        output_dir: output_dir.display().to_string(),
        context_pack_hash: hex_hash,
        artifacts_retrieved,
        deterministic,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Context Rebuild Results");
        println!("  Role:               {}", response.role);
        println!("  Episode ID:         {}", response.episode_id);
        println!("  Output Directory:   {}", response.output_dir);
        println!("  Context Pack Hash:  {}", response.context_pack_hash);
        println!("  Artifacts Retrieved: {}", response.artifacts_retrieved);
        println!(
            "  Deterministic:      {}",
            if response.deterministic { "yes" } else { "no" }
        );
    }

    exit_codes::SUCCESS
}

/// Retrieves an artifact from CAS to the output directory.
fn retrieve_artifact_to_dir(
    cas_path: &Path,
    hash: &[u8],
    output_dir: &Path,
) -> Result<(), std::io::Error> {
    let hex_hash = hex::encode(hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    let src_path = cas_path.join("objects").join(prefix).join(suffix);
    let dst_path = output_dir.join(&hex_hash);

    std::fs::copy(&src_path, &dst_path)?;
    Ok(())
}

// =============================================================================
// Resume Command
// =============================================================================

/// Execute the resume command.
fn run_resume(args: &ResumeArgs, ledger_path: &Path, json_output: bool) -> u8 {
    // Validate work ID
    if args.work_id.is_empty() {
        return output_error(
            json_output,
            "invalid_work_id",
            "Work ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Open ledger
    let ledger = match open_ledger(ledger_path) {
        Ok(l) => l,
        Err(e) => {
            return output_error(
                json_output,
                "ledger_error",
                &format!("Failed to open ledger: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Scan ledger to find last anchor and pending state
    let mut response = ResumeResponse {
        work_id: args.work_id.clone(),
        last_anchor_seq_id: 0,
        last_anchor_event_type: "none".to_string(),
        restart_action: "START_FRESH".to_string(),
        pending_operations: Vec::new(),
        last_episode_id: None,
    };

    let mut found_events = false;
    let mut last_committed_event: Option<(u64, String)> = None;
    let mut cursor = 1u64;
    let batch_size = 1000u64;

    loop {
        let events = match ledger.read_from(cursor, batch_size) {
            Ok(events) => events,
            Err(e) => {
                return output_error(
                    json_output,
                    "ledger_error",
                    &format!("Failed to read ledger: {e}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        };

        if events.is_empty() {
            break;
        }

        for event in &events {
            if let Some(work_info) = extract_work_info(event, &args.work_id) {
                found_events = true;
                let seq_id = event.seq_id.unwrap_or(0);

                // Track anchors (committed durable events)
                match event.event_type.as_str() {
                    "work_claimed" | "episode_spawned" | "session_terminated" | "gate_receipt"
                    | "review_receipt" | "merge_receipt" => {
                        last_committed_event = Some((seq_id, event.event_type.clone()));
                        if work_info.episode_id.is_some() {
                            response.last_episode_id = work_info.episode_id;
                        }
                    },
                    _ => {},
                }
            }
        }

        cursor = events.last().map_or(cursor, |e| e.seq_id.unwrap_or(0) + 1);
        if cursor > MAX_SCAN_EVENTS {
            break;
        }
    }

    if !found_events {
        return output_error(
            json_output,
            "not_found",
            &format!("No events found for work_id: {}", args.work_id),
            exit_codes::NOT_FOUND,
        );
    }

    // Determine restart action based on last anchor
    if let Some((seq_id, event_type)) = last_committed_event {
        response.last_anchor_seq_id = seq_id;
        response.last_anchor_event_type.clone_from(&event_type);

        response.restart_action = match event_type.as_str() {
            "work_claimed" => "SPAWN_EPISODE".to_string(),
            "episode_spawned" => "RESUME_EPISODE".to_string(),
            "session_terminated" => {
                response.pending_operations.push("RUN_GATES".to_string());
                "RUN_GATES".to_string()
            },
            "gate_receipt" => {
                response.pending_operations.push("AWAIT_REVIEW".to_string());
                "AWAIT_REVIEW".to_string()
            },
            "review_receipt" => {
                response.pending_operations.push("MERGE".to_string());
                "MERGE".to_string()
            },
            "merge_receipt" => "WORK_COMPLETE".to_string(),
            _ => "UNKNOWN".to_string(),
        };
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Resume Analysis");
        println!("  Work ID:            {}", response.work_id);
        println!("  Last Anchor Seq:    {}", response.last_anchor_seq_id);
        println!(
            "  Last Anchor Type:   {}",
            response.last_anchor_event_type
        );
        println!("  Restart Action:     {}", response.restart_action);
        if let Some(episode) = &response.last_episode_id {
            println!("  Last Episode ID:    {episode}");
        }
        if !response.pending_operations.is_empty() {
            println!(
                "  Pending Operations: {}",
                response.pending_operations.join(", ")
            );
        }
    }

    exit_codes::SUCCESS
}

// =============================================================================
// Helper Functions
// =============================================================================

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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_status_response_serialization() {
        let response = WorkStatusResponse {
            work_id: "work-123".to_string(),
            status: "CLAIMED".to_string(),
            actor_id: Some("actor-1".to_string()),
            role: Some("implementer".to_string()),
            latest_episode_id: None,
            latest_receipt_hash: None,
            event_count: 5,
            latest_seq_id: Some(42),
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: WorkStatusResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.work_id, "work-123");
        assert_eq!(restored.status, "CLAIMED");
    }

    #[test]
    fn test_episode_inspect_response_serialization() {
        let response = EpisodeInspectResponse {
            episode_id: "ep-001".to_string(),
            status: "RUNNING".to_string(),
            work_id: Some("work-123".to_string()),
            actor_id: None,
            role: Some("implementer".to_string()),
            tool_log_summary: Some(ToolLogSummary {
                total_executions: 10,
                successful_executions: 8,
                failed_executions: 2,
                total_tokens: 5000,
                total_bytes_io: 100_000,
                total_wall_ms: 30_000,
            }),
            tool_log_index: None,
            event_count: 15,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("ep-001"));
        assert!(json.contains("total_executions"));
    }

    #[test]
    fn test_receipt_show_response_serialization() {
        let response = ReceiptShowResponse {
            hash: "abc123".to_string(),
            receipt_type: "gate_receipt".to_string(),
            size_bytes: 1024,
            content: serde_json::json!({"verdict": "PASS"}),
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: ReceiptShowResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.receipt_type, "gate_receipt");
    }

    #[test]
    fn test_context_rebuild_response_serialization() {
        let response = ContextRebuildResponse {
            role: "implementer".to_string(),
            episode_id: "ep-001".to_string(),
            output_dir: "/tmp/rebuild".to_string(),
            context_pack_hash: "deadbeef".to_string(),
            artifacts_retrieved: 5,
            deterministic: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("deterministic"));
    }

    #[test]
    fn test_resume_response_serialization() {
        let response = ResumeResponse {
            work_id: "work-123".to_string(),
            last_anchor_seq_id: 100,
            last_anchor_event_type: "episode_spawned".to_string(),
            restart_action: "RESUME_EPISODE".to_string(),
            pending_operations: vec!["RUN_GATES".to_string()],
            last_episode_id: Some("ep-001".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: ResumeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.restart_action, "RESUME_EPISODE");
    }

    #[test]
    fn test_detect_receipt_type_gate() {
        let json = serde_json::json!({
            "schema": "apm2.gate_receipt.v1",
            "verdict": "PASS"
        });
        assert_eq!(detect_receipt_type(&json), "gate_receipt");
    }

    #[test]
    fn test_detect_receipt_type_review() {
        let json = serde_json::json!({
            "schema": "apm2.review_artifact.v1",
            "review_verdict": "APPROVED"
        });
        assert_eq!(detect_receipt_type(&json), "review_receipt");
    }

    #[test]
    fn test_detect_receipt_type_tool_log() {
        let json = serde_json::json!({
            "schema": "apm2.tool_log_index.v1",
            "episode_id": "ep-001"
        });
        assert_eq!(detect_receipt_type(&json), "tool_log_index");
    }

    #[test]
    fn test_detect_receipt_type_unknown() {
        let json = serde_json::json!({
            "some_field": "value"
        });
        assert_eq!(detect_receipt_type(&json), "unknown");
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_work_status_response_rejects_unknown_fields() {
        let json = r#"{
            "work_id": "work-1",
            "status": "CLAIMED",
            "event_count": 1,
            "malicious": "value"
        }"#;

        let result: Result<WorkStatusResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "WorkStatusResponse should reject unknown fields"
        );
    }

    #[test]
    fn test_resolve_ledger_path_explicit() {
        let explicit = PathBuf::from("/explicit/path/ledger.db");
        let resolved = resolve_ledger_path(Some(&explicit));
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn test_resolve_cas_path_explicit() {
        let explicit = PathBuf::from("/explicit/path/cas");
        let resolved = resolve_cas_path(Some(&explicit));
        assert_eq!(resolved, explicit);
    }
}
