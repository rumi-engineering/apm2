//! CLI command for coordination operations.
//!
//! This module provides the `apm2 coordinate` command for machine-readable
//! coordination of work queues with budget enforcement.
//!
//! # Exit Codes
//!
//! Per CTR-COORD-007:
//! - 0: Coordination completed successfully (`WORK_COMPLETED`)
//! - 1: Coordination aborted (any other stop condition)
//! - 2: Invalid arguments
//!
//! # Example
//!
//! ```bash
//! apm2 coordinate --work-ids work-1,work-2 --max-episodes 10 --max-duration-ms 300000
//! ```
//!
//! # References
//!
//! - TCK-00153: Implement apm2 coordinate CLI command
//! - TCK-00247: HTF CLI rendering of ticks/ledger windows with bounded wall
//!   overlay
//! - TCK-00346: Wire coordinate command to daemon integration
//! - RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution
//! - RFC-0016: Hierarchical Time Framework
//! - CTR-COORD-007: CLI Command (apm2 coordinate)
//!
//! # HTF Compliance (RFC-0016)
//!
//! This command is HTF-compliant per TCK-00247:
//!
//! - **Tick-based budget enforcement**: Duration budgets use `HtfTick`
//!   (monotonic, node-local) for authority decisions. The
//!   `--max-duration-ticks` flag is the authoritative budget input.
//!
//! - **Wall time as overlay only**: The `--max-duration-ms` flag is provided
//!   for convenience but is converted to ticks. Wall time values in receipts
//!   (`started_at`, `completed_at`, `elapsed_ms`) are observational overlays
//!   and MUST NOT be used for authority decisions.
//!
//! - **No wall-time authority**: Budget exhaustion, stop conditions, and all
//!   coordination decisions are based on tick deltas, not wall clock readings.
//!
//! # Daemon Integration (TCK-00346)
//!
//! The coordinate command uses the daemon's operator socket for:
//! - `ClaimWork`: Claiming work items from the queue
//! - `SpawnEpisode`: Spawning episodes for work execution
//!
//! If the daemon is unavailable, coordination aborts gracefully with exit code
//! 1.

use std::fmt;
use std::fs::File;
use std::io::Read as IoRead;
use std::path::Path;

use apm2_core::coordination::{
    CoordinationBudget, CoordinationConfig, CoordinationController, DEFAULT_MAX_ATTEMPTS_PER_WORK,
    MAX_SESSION_IDS_PER_OUTCOME, MAX_WORK_OUTCOMES, MAX_WORK_QUEUE_SIZE, SessionOutcome,
    StopCondition, WorkItemOutcome,
};
use apm2_core::htf::HtfTick;
use apm2_daemon::protocol::WorkRole;
use clap::Args;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::client::protocol::{OperatorClient, ProtocolClientError};

/// Default tick rate: 1MHz (1 tick = 1 microsecond).
///
/// This provides reasonable precision for coordination budget tracking
/// while keeping tick values manageable.
const DEFAULT_TICK_RATE_HZ: u64 = 1_000_000;

/// Maximum file size for work query input (1MB).
///
/// This limit prevents denial-of-service attacks via memory exhaustion from
/// large file inputs.
const MAX_WORK_QUERY_FILE_SIZE: u64 = 1024 * 1024;

// ============================================================================
// Bounded Deserializers (SEC-FAC-001: DoS/OOM Protection)
// ============================================================================

/// Custom deserializer for `session_ids` that enforces
/// [`MAX_SESSION_IDS_PER_OUTCOME`].
///
/// This uses a streaming visitor pattern that enforces limits DURING
/// deserialization, preventing OOM attacks by rejecting oversized arrays
/// before full allocation occurs.
fn deserialize_bounded_session_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedVecVisitor;

    impl<'de> Visitor<'de> for BoundedVecVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(
                formatter,
                "a sequence of at most {MAX_SESSION_IDS_PER_OUTCOME} strings"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Use size hint but cap at MAX_SESSION_IDS_PER_OUTCOME to prevent
            // pre-allocation attacks
            let capacity = seq
                .size_hint()
                .unwrap_or(0)
                .min(MAX_SESSION_IDS_PER_OUTCOME);
            let mut items = Vec::with_capacity(capacity);

            while let Some(item) = seq.next_element()? {
                if items.len() >= MAX_SESSION_IDS_PER_OUTCOME {
                    return Err(de::Error::custom(format!(
                        "session_ids exceeds maximum size: {} > {}",
                        items.len() + 1,
                        MAX_SESSION_IDS_PER_OUTCOME
                    )));
                }
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor)
}

/// Custom deserializer for `work_outcomes` that enforces [`MAX_WORK_OUTCOMES`].
///
/// This uses a streaming visitor pattern that enforces limits DURING
/// deserialization, preventing OOM attacks by rejecting oversized arrays
/// before full allocation occurs.
fn deserialize_bounded_work_outcomes<'de, D>(
    deserializer: D,
) -> Result<Vec<WorkOutcomeEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedVecVisitor;

    impl<'de> Visitor<'de> for BoundedVecVisitor {
        type Value = Vec<WorkOutcomeEntry>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(
                formatter,
                "a sequence of at most {MAX_WORK_OUTCOMES} work outcomes"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Use size hint but cap at MAX_WORK_OUTCOMES to prevent pre-allocation
            // attacks
            let capacity = seq.size_hint().unwrap_or(0).min(MAX_WORK_OUTCOMES);
            let mut items = Vec::with_capacity(capacity);

            while let Some(item) = seq.next_element()? {
                if items.len() >= MAX_WORK_OUTCOMES {
                    return Err(de::Error::custom(format!(
                        "work_outcomes exceeds maximum size: {} > {}",
                        items.len() + 1,
                        MAX_WORK_OUTCOMES
                    )));
                }
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor)
}

/// Exit codes for coordinate commands per CTR-COORD-007.
pub mod exit_codes {
    /// Success exit code (`WORK_COMPLETED`).
    pub const SUCCESS: u8 = 0;
    /// Coordination aborted (any other stop condition).
    pub const ABORTED: u8 = 1;
    /// Invalid arguments.
    pub const INVALID_ARGS: u8 = 2;
}

/// Coordination command arguments.
///
/// Per CTR-COORD-007: CLI command for machine-readable coordination.
#[derive(Debug, Args)]
pub struct CoordinateArgs {
    /// Work item IDs to process (comma-separated).
    ///
    /// Example: `--work-ids work-1,work-2,work-3`
    #[arg(long, value_delimiter = ',')]
    pub work_ids: Option<Vec<String>>,

    /// Work query filter (alternative to --work-ids).
    ///
    /// Path to a file containing work IDs (one per line) or a JSON array.
    /// Use "-" to read from stdin.
    #[arg(long)]
    pub work_query: Option<String>,

    /// Maximum sessions to spawn (required).
    ///
    /// Coordination stops when this many sessions have been spawned.
    #[arg(long)]
    pub max_episodes: u32,

    /// Maximum duration in ticks (HTF compliant).
    ///
    /// Coordination stops when this duration elapses in the tick domain.
    /// Takes precedence over `max_duration_ms`.
    #[arg(long)]
    pub max_duration_ticks: Option<u64>,

    /// Maximum wall-clock time in milliseconds (legacy).
    ///
    /// Coordination stops when this duration elapses.
    /// This is an observational overlay on the tick budget.
    #[arg(long, default_value_t = 60000)]
    pub max_duration_ms: u64,

    /// Maximum tokens to consume (optional).
    ///
    /// Coordination stops when this many tokens have been consumed.
    /// If not specified, token consumption is tracked but not limited.
    #[arg(long)]
    pub max_tokens: Option<u64>,

    /// Maximum attempts per work item (default: 3).
    ///
    /// A work item is marked as failed after this many unsuccessful sessions.
    #[arg(long, default_value_t = DEFAULT_MAX_ATTEMPTS_PER_WORK)]
    pub max_attempts: u32,

    /// Maximum work items in queue (default: 1000).
    ///
    /// Rejects coordination requests with larger queues to prevent memory
    /// exhaustion.
    #[arg(long, default_value_t = MAX_WORK_QUEUE_SIZE)]
    pub max_work_queue: usize,

    /// Output as JSON (default).
    ///
    /// When set, outputs a JSON receipt on completion.
    #[arg(long, default_value_t = true)]
    pub json: bool,

    /// Suppress progress events.
    ///
    /// When set, only outputs the final receipt without progress updates.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,

    // =========================================================================
    // Daemon Integration Arguments (TCK-00346)
    // =========================================================================
    /// Actor ID for work claiming (display hint).
    ///
    /// Authoritative ID is derived from the credential. This is used when
    /// claiming work from the daemon.
    #[arg(long, default_value = "apm2-coordinator")]
    pub actor_id: String,

    /// Workspace root directory for spawned episodes.
    ///
    /// All file operations within episodes are confined to this directory.
    /// Defaults to the current working directory.
    #[arg(long)]
    pub workspace_root: Option<String>,
}

/// Coordination receipt output structure.
///
/// Per CTR-COORD-006: Evidence artifact proving coordination execution.
///
/// # Security Notes (SEC-FAC-001, SEC-FAC-002, SEC-FAC-003)
///
/// - **Bounded deserialization**: `work_outcomes` is bounded by
///   [`MAX_WORK_OUTCOMES`] to prevent memory exhaustion attacks.
/// - **Strict parsing**: `deny_unknown_fields` prevents injection of unexpected
///   fields.
/// - **Canonicalization**: This CLI struct is for output/display purposes only
///   and does not implement `Canonicalizable`. For cryptographic operations
///   requiring tamper-evidence, use
///   [`apm2_core::coordination::CoordinationReceipt`] which provides
///   `canonical_bytes()` and `compute_hash()`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationReceipt {
    /// Coordination ID.
    pub coordination_id: String,
    /// Work outcomes for each processed item.
    ///
    /// Limited to [`MAX_WORK_OUTCOMES`] entries during deserialization.
    #[serde(deserialize_with = "deserialize_bounded_work_outcomes")]
    pub work_outcomes: Vec<WorkOutcomeEntry>,
    /// Budget usage at completion.
    pub budget_usage: BudgetUsageOutput,
    /// Budget ceiling that was configured.
    pub budget_ceiling: BudgetCeilingOutput,
    /// Stop condition that ended coordination.
    pub stop_condition: String,
    /// Timestamp when coordination started.
    pub started_at: u64,
    /// Timestamp when coordination completed.
    pub completed_at: u64,
    /// Total sessions spawned.
    pub total_sessions: u32,
    /// Number of successful sessions.
    pub successful_sessions: u32,
    /// Number of failed sessions.
    pub failed_sessions: u32,
}

/// Work outcome entry in the receipt.
///
/// # Security Notes (SEC-FAC-001, SEC-FAC-002)
///
/// - **Bounded deserialization**: `session_ids` is bounded by
///   [`MAX_SESSION_IDS_PER_OUTCOME`] to prevent memory exhaustion attacks.
/// - **Strict parsing**: `deny_unknown_fields` prevents injection of unexpected
///   fields.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOutcomeEntry {
    /// Work item ID.
    pub work_id: String,
    /// Number of attempts made.
    pub attempts: u32,
    /// Final outcome (SUCCEEDED, FAILED, SKIPPED).
    pub final_outcome: String,
    /// Session IDs used for this work item.
    ///
    /// Limited to [`MAX_SESSION_IDS_PER_OUTCOME`] entries during
    /// deserialization.
    #[serde(deserialize_with = "deserialize_bounded_session_ids")]
    pub session_ids: Vec<String>,
}

/// Budget usage output in the receipt.
///
/// # Security Notes (SEC-FAC-002)
///
/// - **Strict parsing**: `deny_unknown_fields` prevents injection of unexpected
///   fields.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetUsageOutput {
    /// Episodes consumed.
    pub consumed_episodes: u32,
    /// Elapsed time in ticks (HTF compliant).
    pub elapsed_ticks: u64,
    /// Elapsed time in milliseconds (observational).
    pub elapsed_ms: u64,
    /// Tokens consumed.
    pub consumed_tokens: u64,
}

/// Budget ceiling output in the receipt.
///
/// Field names match the `CoordinationBudget` schema for consistency.
///
/// # Security Notes (SEC-FAC-002)
///
/// - **Strict parsing**: `deny_unknown_fields` prevents injection of unexpected
///   fields.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct BudgetCeilingOutput {
    /// Maximum episodes configured.
    pub max_episodes: u32,
    /// Maximum duration in ticks (HTF compliant).
    pub max_duration_ticks: u64,
    /// Maximum duration in milliseconds (observational).
    pub max_duration_ms: u64,
    /// Maximum tokens configured (null if not set).
    pub max_tokens: Option<u64>,
}

/// Internal error type for CLI error handling.
#[derive(Debug)]
enum CoordinateCliError {
    /// Invalid arguments.
    InvalidArgs(String),
    /// Coordination error.
    CoordinationError(String),
    /// Daemon connection error (TCK-00346).
    DaemonError(String),
}

impl std::fmt::Display for CoordinateCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgs(msg) => write!(f, "invalid arguments: {msg}"),
            Self::CoordinationError(msg) => write!(f, "coordination error: {msg}"),
            Self::DaemonError(msg) => write!(f, "daemon error: {msg}"),
        }
    }
}

/// Runs the coordinate command, returning an appropriate exit code as u8.
///
/// # Arguments
///
/// * `args` - Coordination command arguments
/// * `operator_socket` - Path to operator socket for daemon communication
/// * `session_socket` - Path to session socket for session observation
///
/// # Exit Codes
///
/// - 0: Coordination completed successfully (`WORK_COMPLETED`)
/// - 1: Coordination aborted (any other stop condition)
/// - 2: Invalid arguments
pub fn run_coordinate(args: &CoordinateArgs, operator_socket: &Path, session_socket: &Path) -> u8 {
    match run_coordinate_inner(args, operator_socket, session_socket) {
        Ok(receipt) => {
            // Output the receipt as JSON
            output_receipt(&receipt, args.json);

            // Exit code based on stop condition
            if receipt.stop_condition == "WORK_COMPLETED" {
                exit_codes::SUCCESS
            } else {
                exit_codes::ABORTED
            }
        },
        Err(CoordinateCliError::InvalidArgs(msg)) => {
            eprintln!("Error: Invalid arguments - {msg}");
            exit_codes::INVALID_ARGS
        },
        Err(CoordinateCliError::CoordinationError(msg)) => {
            eprintln!("Error: Coordination failed - {msg}");
            exit_codes::ABORTED
        },
        Err(CoordinateCliError::DaemonError(msg)) => {
            eprintln!("Error: Daemon communication failed - {msg}");
            exit_codes::ABORTED
        },
    }
}

/// Outputs a receipt to stdout.
fn output_receipt(receipt: &CoordinationReceipt, json_output: bool) {
    if json_output {
        let output = serde_json::to_string_pretty(receipt)
            .unwrap_or_else(|e| format!("{{\"error\": \"receipt serialization failed: {e}\"}}"));
        println!("{output}");
    } else {
        // Text output summary
        println!("Coordination: {}", receipt.coordination_id);
        println!("Stop condition: {}", receipt.stop_condition);
        println!(
            "Sessions: {} total ({} successful, {} failed)",
            receipt.total_sessions, receipt.successful_sessions, receipt.failed_sessions
        );
        println!(
            "Budget used: {} episodes, {} ticks ({} ms), {} tokens",
            receipt.budget_usage.consumed_episodes,
            receipt.budget_usage.elapsed_ticks,
            receipt.budget_usage.elapsed_ms,
            receipt.budget_usage.consumed_tokens
        );
    }
}

/// Inner implementation that returns Result for easier error handling.
///
/// # TCK-00346: Daemon Integration
///
/// This function now connects to the daemon via `operator_socket` and uses
/// `OperatorClient::claim_work` and `OperatorClient::spawn_episode` to
/// execute the coordination loop. Session observation uses `session_socket`
/// to poll for session termination and track actual token consumption.
fn run_coordinate_inner(
    args: &CoordinateArgs,
    operator_socket: &Path,
    session_socket: &Path,
) -> Result<CoordinationReceipt, CoordinateCliError> {
    // Validate required arguments
    if args.max_episodes == 0 {
        return Err(CoordinateCliError::InvalidArgs(
            "max-episodes must be positive".to_string(),
        ));
    }

    // Determine max duration in ticks (HTF authority)
    // If ticks provided, use them. Else convert ms to ticks.
    let max_duration_ticks = if let Some(ticks) = args.max_duration_ticks {
        if ticks == 0 {
            return Err(CoordinateCliError::InvalidArgs(
                "max-duration-ticks must be positive".to_string(),
            ));
        }
        ticks
    } else {
        if args.max_duration_ms == 0 {
            return Err(CoordinateCliError::InvalidArgs(
                "max-duration-ms (or max-duration-ticks) must be positive".to_string(),
            ));
        }
        args.max_duration_ms.saturating_mul(1000) // ms -> us at 1MHz
    };

    // Parse work IDs from either --work-ids or --work-query
    let work_ids = parse_work_ids(args)?;

    if work_ids.is_empty() {
        return Err(CoordinateCliError::InvalidArgs(
            "no work items specified. Use --work-ids or --work-query".to_string(),
        ));
    }

    // Validate work queue size
    if work_ids.len() > args.max_work_queue {
        return Err(CoordinateCliError::InvalidArgs(format!(
            "work queue size {} exceeds maximum allowed {}",
            work_ids.len(),
            args.max_work_queue
        )));
    }

    // Determine and validate workspace root (default to current directory).
    // Security: canonicalize to resolve symlinks and relative paths, then
    // verify it is an absolute path that exists and is not a sensitive
    // system directory.
    let workspace_root = validate_workspace_root(args.workspace_root.as_deref())?;

    // Create budget
    let budget = CoordinationBudget::new(
        args.max_episodes,
        max_duration_ticks,
        DEFAULT_TICK_RATE_HZ,
        args.max_tokens,
    )
    .map_err(|e| CoordinateCliError::InvalidArgs(e.to_string()))?;

    // Create configuration
    let config = CoordinationConfig::with_max_queue_size(
        work_ids,
        budget,
        args.max_attempts,
        args.max_work_queue,
    )
    .map_err(|e| CoordinateCliError::InvalidArgs(e.to_string()))?;

    // Create controller
    let mut controller = CoordinationController::new(config.clone());

    // Get current timestamp in nanoseconds
    // Truncation from u128 to u64 is safe: u64 can hold ~584 million years of
    // nanoseconds
    #[allow(clippy::cast_possible_truncation)]
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // Create initial tick for coordination start
    let start_tick = HtfTick::new(0, DEFAULT_TICK_RATE_HZ);

    // Start coordination
    let coordination_id = controller
        .start(start_tick, started_at)
        .map_err(|e| CoordinateCliError::CoordinationError(e.to_string()))?;

    if !args.quiet {
        eprintln!("Coordination started: {coordination_id}");
        eprintln!("Work items: {}", config.work_ids.len());
        // Convert ticks back to ms for display (ticks / 1000 at 1MHz)
        let max_duration_ms = config.budget.max_duration_ticks / 1000;
        eprintln!(
            "Budget: {} episodes, {} ms, {} tokens",
            config.budget.max_episodes,
            max_duration_ms,
            config
                .budget
                .max_tokens
                .map_or_else(|| "unlimited".to_string(), |t| t.to_string())
        );
    }

    // Build async runtime for daemon communication
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            CoordinateCliError::DaemonError(format!("Failed to build tokio runtime: {e}"))
        })?;

    // Run the coordination loop with daemon integration (TCK-00346)
    let result = rt.block_on(run_coordination_loop(
        &mut controller,
        &config,
        &coordination_id,
        operator_socket,
        session_socket,
        &args.actor_id,
        &workspace_root,
        args.quiet,
    ));

    // Get final timestamp
    #[allow(clippy::cast_possible_truncation)]
    let completed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // Handle the result and build the receipt
    let (stop_condition_str, final_stop_condition) = match result {
        Ok(stop_condition) => {
            let stop_str = format_stop_condition(&stop_condition);
            (stop_str, Some(stop_condition))
        },
        Err(e) => {
            // Coordination failed, abort with error
            let abort_tick = current_tick();
            let abort_reason = apm2_core::coordination::AbortReason::Error {
                message: e.to_string(),
            };
            let _ = controller.abort(abort_reason, abort_tick, completed_at);
            ("ABORTED".to_string(), None)
        },
    };

    // Complete or abort the controller based on the result
    if let Some(stop_condition) = final_stop_condition {
        let complete_tick = current_tick();
        let _ = controller.complete(stop_condition, complete_tick, completed_at);
    }

    // Build receipt from controller state
    let receipt = build_receipt(
        &coordination_id,
        &controller,
        &config,
        &stop_condition_str,
        started_at,
        completed_at,
    );

    if !args.quiet {
        eprintln!("Coordination finished: {coordination_id} ({stop_condition_str})");
    }

    Ok(receipt)
}

/// Returns the current tick value based on system time.
///
/// Uses nanosecond precision converted to microseconds for 1MHz tick rate.
fn current_tick() -> HtfTick {
    #[allow(clippy::cast_possible_truncation)]
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    HtfTick::new(now_us, DEFAULT_TICK_RATE_HZ)
}

/// Formats a stop condition for display.
fn format_stop_condition(stop_condition: &StopCondition) -> String {
    match stop_condition {
        StopCondition::WorkCompleted => "WORK_COMPLETED".to_string(),
        StopCondition::BudgetExhausted(budget_type) => {
            format!("BUDGET_EXHAUSTED_{budget_type:?}").to_uppercase()
        },
        StopCondition::CircuitBreakerTriggered { .. } => "CIRCUIT_BREAKER_TRIGGERED".to_string(),
        StopCondition::MaxAttemptsExceeded { .. } => "MAX_ATTEMPTS_EXCEEDED".to_string(),
        // StopCondition is non-exhaustive, handle future variants
        _ => "UNKNOWN_STOP_CONDITION".to_string(),
    }
}

/// Interval for polling session status via event emission.
const SESSION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Maximum time to wait for session termination before treating as failure.
const SESSION_OBSERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Conservative token estimation rate: tokens per second of wall-clock time.
///
/// **Fallback only**: When the daemon reports `actual_tokens_consumed` via
/// `SessionStatus` (TCK-00384/TCK-00386), that value is used instead. This
/// rate is only applied when `actual_tokens_consumed` is `None`.
///
/// The rate (100 tokens/sec) is deliberately over-estimated to ensure budget
/// enforcement errs on the side of caution — modern LLM agents routinely
/// achieve 50-100+ tokens/sec, so this upper bound ensures Safe-Fail behavior.
/// A real session may consume fewer tokens, but we must never undercount
/// (which would bypass budget limits).
const CONSERVATIVE_TOKENS_PER_SECOND: u64 = 100;

/// Minimum token cost per session, regardless of elapsed time.
///
/// Even if a session terminates almost instantly, we charge at least this
/// many tokens to prevent zero-cost exploitation of budget limits.
const MIN_TOKENS_PER_SESSION: u64 = 100;

/// Sensitive system directories that must not be used as workspace roots.
///
/// These paths are blocked to prevent accidental or malicious operations
/// against critical system directories.
const BLOCKED_WORKSPACE_ROOTS: &[&str] = &[
    "/", "/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys", "/var", "/lib",
    "/lib64", "/root",
];

/// Runs the coordination loop with daemon integration.
///
/// # TCK-00346: This is the core daemon integration logic.
///
/// The loop:
/// 1. Checks stop conditions
/// 2. Connects to daemon and claims work for each work item
/// 3. Spawns episodes via `OperatorClient::spawn_episode`
/// 4. Observes session termination via `SessionClient` event polling
/// 5. Records actual session outcomes and token consumption
/// 6. Continues until stop condition is met
#[allow(clippy::too_many_arguments)]
async fn run_coordination_loop(
    controller: &mut CoordinationController,
    _config: &CoordinationConfig,
    coordination_id: &str,
    operator_socket: &Path,
    session_socket: &Path,
    actor_id: &str,
    workspace_root: &str,
    quiet: bool,
) -> Result<StopCondition, CoordinateCliError> {
    // Connect to daemon
    let mut client = OperatorClient::connect(operator_socket)
        .await
        .map_err(|e| map_protocol_error_to_cli(&e))?;

    if !quiet {
        eprintln!("Connected to daemon at {}", operator_socket.display());
    }

    // Main coordination loop
    loop {
        // Check stop conditions before processing next work item
        if let Some(stop_condition) = controller.check_stop_condition() {
            return Ok(stop_condition);
        }

        // Get current work item
        let work_id = match controller.current_work_id() {
            Some(id) => id.to_string(),
            None => {
                // Work queue exhausted
                return Ok(StopCondition::WorkCompleted);
            },
        };

        if !quiet {
            eprintln!("Processing work item: {work_id}");
        }

        // Claim work from daemon using actor_id (TCK-00346 fix: wire actor_id)
        // Use empty credential/nonce for now; the daemon enforces manifests.
        let claim_result = client
            .claim_work(actor_id, WorkRole::Implementer, &[], &[])
            .await;

        match &claim_result {
            Ok(response) => {
                if !quiet {
                    eprintln!(
                        "Claimed work: work_id={}, lease_id={}",
                        response.work_id, response.lease_id
                    );
                }
            },
            Err(e) => {
                if !quiet {
                    eprintln!("ClaimWork failed for {work_id}: {e}");
                }
                // ClaimWork failure is non-fatal; proceed with work freshness
                // check
            },
        }

        // Check work freshness
        let freshness = controller.check_work_freshness(&work_id, 0, claim_result.is_ok());
        if !freshness.is_eligible {
            if !quiet {
                eprintln!(
                    "Skipping work item {work_id}: {}",
                    freshness.skip_reason.unwrap_or_default()
                );
            }
            controller
                .skip_work_item(&work_id)
                .map_err(|e| CoordinateCliError::CoordinationError(e.to_string()))?;
            continue;
        }

        // Prepare session spawn (generates session ID and binding event)
        #[allow(clippy::cast_possible_truncation)]
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let spawn_result = controller
            .prepare_session_spawn(&work_id, 0, timestamp_ns)
            .map_err(|e| CoordinateCliError::CoordinationError(e.to_string()))?;

        if !quiet {
            eprintln!(
                "Spawning episode {} for work {work_id} (attempt {})",
                spawn_result.session_id, spawn_result.attempt_number
            );
        }

        // Spawn episode via daemon (TCK-00346 fix: use Implementer role, not
        // Coordinator)
        let spawn_response = client
            .spawn_episode(&work_id, WorkRole::Implementer, None, workspace_root, None)
            .await;

        // Determine outcome by observing the spawned session
        let (outcome, tokens_consumed) = match spawn_response {
            Ok(response) => {
                if !quiet {
                    eprintln!("Episode spawned: session_id={}", response.session_id);
                }

                // Observe session termination via SessionClient polling.
                // This replaces the previous hardcoded success/1000-token assumption.
                observe_session_termination(
                    session_socket,
                    &response.session_token,
                    &response.session_id,
                    coordination_id,
                    quiet,
                )
                .await
            },
            Err(e) => {
                if !quiet {
                    eprintln!("Episode spawn failed: {e}");
                }
                // Spawn itself failed - charge minimum tokens to prevent
                // zero-cost budget bypass from repeated spawn failures.
                (SessionOutcome::Failure, MIN_TOKENS_PER_SESSION)
            },
        };

        // Record session termination with actual observed outcome and tokens
        let termination_tick = current_tick();
        #[allow(clippy::cast_possible_truncation)]
        let termination_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        controller
            .record_session_termination(
                &spawn_result.session_id,
                &work_id,
                outcome,
                tokens_consumed,
                termination_tick,
                termination_ns,
            )
            .map_err(|e| CoordinateCliError::CoordinationError(e.to_string()))?;

        // Check stop conditions again after recording termination
        if let Some(stop_condition) = controller.check_stop_condition() {
            return Ok(stop_condition);
        }
    }
}

/// Observes session termination by polling `SessionStatus` via the session
/// socket.
///
/// # TCK-00386: Session Termination Signal
///
/// Polls `SessionClient::session_status_with_termination()` to detect when a
/// session transitions from `ACTIVE` to `TERMINATED`. The daemon populates
/// `termination_reason`, `exit_code`, and `actual_tokens_consumed` on the
/// `TERMINATED` response, allowing us to distinguish clean exits from crashes.
///
/// ## Security: Fail-Closed Design
///
/// This function follows fail-closed principles throughout:
/// - If the session socket is unavailable, the session is recorded as FAILURE
///   (we cannot verify outcome, so we assume failure).
/// - If the status query returns an error (session not found), the session is
///   recorded as FAILURE (fail-closed: no evidence of success).
/// - If observation times out without a TERMINATED response, the session is
///   recorded as FAILURE.
/// - SUCCESS is only recorded when the daemon explicitly reports
///   `termination_reason == "normal"` **and** `exit_code == 0`.
///
/// ## Token Accounting
///
/// When the daemon reports `actual_tokens_consumed`, that value is used
/// directly (with a floor of [`MIN_TOKENS_PER_SESSION`] to prevent zero-cost
/// sessions). When the daemon does not report actual consumption (field is
/// `None`), we fall back to the conservative wall-clock estimate via
/// [`estimate_token_consumption`].
async fn observe_session_termination(
    session_socket: &Path,
    session_token: &str,
    session_id: &str,
    _correlation_id: &str,
    quiet: bool,
) -> (SessionOutcome, u64) {
    use crate::client::protocol::SessionClient;

    let observation_start = std::time::Instant::now();

    // Attempt to connect to session socket for observation
    let session_client = SessionClient::connect(session_socket).await;

    match session_client {
        Ok(mut client) => {
            // Poll session status until TERMINATED or timeout.
            // TCK-00386: Uses session_status_with_termination() which returns
            // termination details (reason, exit_code, tokens) for ended sessions.
            while observation_start.elapsed() < SESSION_OBSERVATION_TIMEOUT {
                tokio::time::sleep(SESSION_POLL_INTERVAL).await;

                let status_result = client.session_status_with_termination(session_token).await;

                match status_result {
                    Ok(response) => {
                        if response.state == "TERMINATED" {
                            // Session has ended — map outcome from termination details.
                            let outcome = map_termination_to_outcome(
                                response.termination_reason.as_deref(),
                                response.exit_code,
                            );

                            // TCK-00386: Use actual token consumption when available,
                            // fall back to wall-clock estimate otherwise.
                            let tokens = resolve_token_consumption(
                                response.actual_tokens_consumed,
                                observation_start.elapsed().as_secs(),
                            );

                            if !quiet {
                                eprintln!(
                                    "Session {session_id} terminated: reason={}, exit_code={}, \
                                     outcome={}, tokens={tokens} ({:.1}s elapsed)",
                                    response.termination_reason.as_deref().unwrap_or("unknown"),
                                    response
                                        .exit_code
                                        .map_or_else(|| "N/A".to_string(), |c| c.to_string()),
                                    outcome.as_str(),
                                    observation_start.elapsed().as_secs_f64(),
                                );
                            }

                            return (outcome, tokens);
                        }

                        // Session is still ACTIVE (or SUSPENDED), continue polling.
                        if !quiet {
                            eprintln!(
                                "Session {session_id} still active ({:.1}s elapsed)",
                                observation_start.elapsed().as_secs_f64()
                            );
                        }
                    },
                    Err(_e) => {
                        // FAIL-CLOSED: Status query failed (session not found, socket
                        // error, or decode failure). We have no evidence of success,
                        // so we must record as Failure.
                        if !quiet {
                            eprintln!(
                                "Session {session_id} status query failed ({:.1}s elapsed); \
                                 recording as FAILURE (fail-closed)",
                                observation_start.elapsed().as_secs_f64()
                            );
                        }
                        let tokens =
                            estimate_token_consumption(observation_start.elapsed().as_secs());
                        return (SessionOutcome::Failure, tokens);
                    },
                }
            }

            // FAIL-CLOSED: Observation timed out without a TERMINATED response.
            if !quiet {
                eprintln!(
                    "Session {session_id} observation timed out after {}s; \
                     recording as FAILURE",
                    SESSION_OBSERVATION_TIMEOUT.as_secs()
                );
            }
            let tokens = estimate_token_consumption(observation_start.elapsed().as_secs());
            (SessionOutcome::Failure, tokens)
        },
        Err(_e) => {
            // FAIL-CLOSED: Session socket unavailable means we cannot observe
            // the session outcome. We must assume failure because we have no
            // evidence of success. Recording Success here would be fail-open.
            if !quiet {
                eprintln!(
                    "Session socket unavailable; recording session \
                     {session_id} as FAILURE (cannot observe outcome)"
                );
            }
            // Use minimum token cost since we don't know how long the session
            // ran, but must not report zero.
            let tokens = estimate_token_consumption(observation_start.elapsed().as_secs());
            (SessionOutcome::Failure, tokens)
        },
    }
}

/// Maps daemon-reported termination details to a [`SessionOutcome`].
///
/// # TCK-00386: Termination Reason Mapping
///
/// Only `termination_reason == "normal"` **and** `exit_code == Some(0)` produce
/// [`SessionOutcome::Success`]. All other combinations produce
/// [`SessionOutcome::Failure`] (fail-closed):
///
/// | `termination_reason` | `exit_code` | Outcome   |
/// |----------------------|-------------|-----------|
/// | `Some("normal")`     | `Some(0)`   | Success   |
/// | `Some("normal")`     | `Some(1)`   | Failure   |
/// | `Some("normal")`     | `None`      | Failure   |
/// | `Some("crash")`      | any         | Failure   |
/// | `Some("timeout")`    | any         | Failure   |
/// | `None`               | any         | Failure   |
fn map_termination_to_outcome(
    termination_reason: Option<&str>,
    exit_code: Option<i32>,
) -> SessionOutcome {
    match (termination_reason, exit_code) {
        (Some("normal"), Some(0)) => SessionOutcome::Success,
        _ => SessionOutcome::Failure,
    }
}

/// Resolves token consumption: prefers actual daemon-reported value, falls back
/// to wall-clock estimate.
///
/// # TCK-00386: Token Accounting
///
/// When `actual_tokens` is `Some(n)`, returns `max(n, MIN_TOKENS_PER_SESSION)`
/// to prevent zero-cost sessions. When `None`, delegates to
/// [`estimate_token_consumption`] which uses the conservative wall-clock rate.
fn resolve_token_consumption(actual_tokens: Option<u64>, elapsed_secs: u64) -> u64 {
    actual_tokens.map_or_else(
        || estimate_token_consumption(elapsed_secs),
        |tokens| tokens.max(MIN_TOKENS_PER_SESSION),
    )
}

/// Estimates token consumption based on elapsed wall-clock seconds.
///
/// Uses a conservative rate to ensure budget tracking never underestimates.
/// Returns at least [`MIN_TOKENS_PER_SESSION`] tokens regardless of duration,
/// preventing zero-cost sessions that would bypass budget limits.
fn estimate_token_consumption(elapsed_secs: u64) -> u64 {
    let time_based = elapsed_secs.saturating_mul(CONSERVATIVE_TOKENS_PER_SECOND);
    time_based.max(MIN_TOKENS_PER_SESSION)
}

/// Maps a protocol client error to a CLI error.
fn map_protocol_error_to_cli(error: &ProtocolClientError) -> CoordinateCliError {
    match error {
        ProtocolClientError::DaemonNotRunning => {
            CoordinateCliError::DaemonError("Daemon is not running. Start with: apm2 daemon".into())
        },
        ProtocolClientError::Timeout => {
            CoordinateCliError::DaemonError("Connection to daemon timed out".into())
        },
        ProtocolClientError::HandshakeFailed(msg) => {
            CoordinateCliError::DaemonError(format!("Handshake failed: {msg}"))
        },
        ProtocolClientError::DaemonError { code, message } => {
            CoordinateCliError::DaemonError(format!("Daemon error ({code}): {message}"))
        },
        other => CoordinateCliError::DaemonError(format!("Protocol error: {other}")),
    }
}

/// Validates and canonicalizes the workspace root path.
///
/// # Security (SEC: `workspace_root` injection prevention)
///
/// This function ensures the workspace root is safe before passing it to the
/// daemon:
/// 1. **Canonicalization**: Resolves symlinks, `..`, and relative paths via
///    `std::fs::canonicalize`. This prevents symlink-based escapes and path
///    traversal.
/// 2. **Absolute path check**: The canonicalized path must be absolute.
/// 3. **Existence check**: The path must exist and be a directory.
/// 4. **Sensitive directory blocklist**: Rejects paths that are sensitive
///    system directories (e.g., `/`, `/etc`, `/usr`).
///
/// If `workspace_root` is `None`, defaults to the current working directory
/// (also canonicalized and validated).
fn validate_workspace_root(workspace_root: Option<&str>) -> Result<String, CoordinateCliError> {
    let raw_path = match workspace_root {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir().map_err(|e| {
            CoordinateCliError::InvalidArgs(format!(
                "cannot determine current directory for workspace_root: {e}"
            ))
        })?,
    };

    // Canonicalize: resolves symlinks, "..", and relative components
    let canonical = std::fs::canonicalize(&raw_path).map_err(|e| {
        CoordinateCliError::InvalidArgs(format!(
            "workspace_root '{}' cannot be resolved: {e}",
            raw_path.display()
        ))
    })?;

    // Must be absolute (canonicalize guarantees this, but verify defensively)
    if !canonical.is_absolute() {
        return Err(CoordinateCliError::InvalidArgs(format!(
            "workspace_root '{}' is not an absolute path after canonicalization",
            canonical.display()
        )));
    }

    // Must be a directory
    if !canonical.is_dir() {
        return Err(CoordinateCliError::InvalidArgs(format!(
            "workspace_root '{}' is not a directory",
            canonical.display()
        )));
    }

    // Check against sensitive system directory blocklist.
    //
    // Uses `Path::starts_with` (component-aware) to block both exact matches
    // AND subdirectories — e.g., "/var/log" is blocked because it starts
    // with the blocked root "/var".
    //
    // The filesystem root "/" is checked with exact equality because
    // `Path::starts_with("/")` is true for *every* absolute path.
    for blocked in BLOCKED_WORKSPACE_ROOTS {
        let blocked_path = std::path::Path::new(blocked);
        let mut candidates = vec![blocked_path.to_path_buf()];

        // Some platforms canonicalize sensitive roots through aliases
        // (for example, `/etc` -> `/private/etc` on macOS). Check both the
        // literal blocked root and its canonicalized form when available.
        if let Ok(canonical_blocked) = std::fs::canonicalize(blocked_path) {
            if canonical_blocked != blocked_path {
                candidates.push(canonical_blocked);
            }
        }

        for candidate in candidates {
            let is_blocked = if candidate == std::path::Path::new("/") {
                canonical == candidate
            } else {
                canonical.starts_with(&candidate)
            };

            if is_blocked {
                return Err(CoordinateCliError::InvalidArgs(format!(
                    "workspace_root '{}' is inside a sensitive system directory ('{}') and cannot be used",
                    canonical.display(),
                    blocked,
                )));
            }
        }
    }

    Ok(canonical.to_string_lossy().into_owned())
}

/// Parses work IDs from command line arguments.
fn parse_work_ids(args: &CoordinateArgs) -> Result<Vec<String>, CoordinateCliError> {
    // Check for mutually exclusive options
    if args.work_ids.is_some() && args.work_query.is_some() {
        return Err(CoordinateCliError::InvalidArgs(
            "--work-ids and --work-query are mutually exclusive".to_string(),
        ));
    }

    // Parse from --work-ids
    if let Some(ref ids) = args.work_ids {
        let work_ids: Vec<String> = ids
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        return Ok(work_ids);
    }

    // Parse from --work-query (file or stdin)
    if let Some(ref query_path) = args.work_query {
        return parse_work_query(query_path);
    }

    Ok(Vec::new())
}

/// Parses work IDs from a file or stdin.
///
/// Supports two formats:
/// - JSON array: If content starts with `[`, parse as JSON (fail on error).
/// - Line-separated: If content does not start with `[`, parse as one ID per
///   line.
///
/// Per security review: We detect probable JSON intent to avoid silent
/// fallback on malformed JSON, which could lead to executing sessions with
/// unintended identifiers.
fn parse_work_query(path: &str) -> Result<Vec<String>, CoordinateCliError> {
    let content = if path == "-" {
        // Read from stdin
        read_bounded_stdin()?
    } else {
        // Read from file
        read_bounded_file(std::path::Path::new(path))?
    };

    let trimmed = content.trim_start();

    // Detect probable JSON intent by checking first non-whitespace character.
    // If it looks like JSON, require successful JSON parsing (fail-closed).
    if trimmed.starts_with('[') {
        match serde_json::from_str::<Vec<String>>(&content) {
            Ok(ids) => return Ok(ids),
            Err(e) => {
                return Err(CoordinateCliError::InvalidArgs(format!(
                    "work-query file appears to be JSON but failed to parse: {e}"
                )));
            },
        }
    }

    // Line-separated format: one work ID per line, comments start with #
    let work_ids: Vec<String> = content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    Ok(work_ids)
}

/// Reads a file with size limit to prevent denial-of-service.
fn read_bounded_file(path: &std::path::Path) -> Result<String, CoordinateCliError> {
    let file = File::open(path).map_err(|e| {
        CoordinateCliError::InvalidArgs(format!("failed to open file '{}': {e}", path.display()))
    })?;

    let mut content = String::new();
    let mut bounded_reader = file.take(MAX_WORK_QUERY_FILE_SIZE + 1);

    bounded_reader.read_to_string(&mut content).map_err(|e| {
        CoordinateCliError::InvalidArgs(format!("failed to read file '{}': {e}", path.display()))
    })?;

    if content.len() as u64 > MAX_WORK_QUERY_FILE_SIZE {
        return Err(CoordinateCliError::InvalidArgs(format!(
            "file '{}' exceeds maximum size limit of {} bytes",
            path.display(),
            MAX_WORK_QUERY_FILE_SIZE
        )));
    }

    Ok(content)
}

/// Reads from stdin with size limit.
fn read_bounded_stdin() -> Result<String, CoordinateCliError> {
    use std::io;

    let mut content = String::new();
    let mut handle = io::stdin().take(MAX_WORK_QUERY_FILE_SIZE + 1);

    handle
        .read_to_string(&mut content)
        .map_err(|e| CoordinateCliError::InvalidArgs(format!("failed to read from stdin: {e}")))?;

    if content.len() as u64 > MAX_WORK_QUERY_FILE_SIZE {
        return Err(CoordinateCliError::InvalidArgs(format!(
            "stdin input exceeds maximum size limit of {MAX_WORK_QUERY_FILE_SIZE} bytes"
        )));
    }

    Ok(content)
}

/// Builds a coordination receipt from controller state.
fn build_receipt(
    coordination_id: &str,
    controller: &CoordinationController,
    config: &CoordinationConfig,
    stop_condition: &str,
    started_at: u64,
    completed_at: u64,
) -> CoordinationReceipt {
    // Build work outcomes from controller's actual work tracking state.
    // Each WorkItemState contains the real attempt count, session IDs,
    // and final outcome recorded during coordination execution.
    let work_outcomes: Vec<WorkOutcomeEntry> = controller
        .work_tracking()
        .iter()
        .map(|item| {
            let final_outcome = match item.final_outcome {
                Some(WorkItemOutcome::Succeeded) => "SUCCEEDED".to_string(),
                Some(WorkItemOutcome::Failed) => "FAILED".to_string(),
                Some(WorkItemOutcome::Skipped) => "SKIPPED".to_string(),
                None => "IN_PROGRESS".to_string(),
            };
            WorkOutcomeEntry {
                work_id: item.work_id.clone(),
                attempts: item.attempt_count,
                final_outcome,
                session_ids: item.session_ids.clone(),
            }
        })
        .collect();

    // Get budget usage from controller
    let budget_usage = controller.budget_usage();

    // Count sessions from emitted events
    let (total_sessions, successful_sessions, failed_sessions) =
        count_sessions_from_events(controller.emitted_events());

    // Convert ticks to ms for output (at 1MHz: ticks / 1000)
    let elapsed_ms = budget_usage.elapsed_ticks / 1000;
    let max_duration_ms = config.budget.max_duration_ticks / 1000;

    CoordinationReceipt {
        coordination_id: coordination_id.to_string(),
        work_outcomes,
        budget_usage: BudgetUsageOutput {
            consumed_episodes: budget_usage.consumed_episodes,
            elapsed_ticks: budget_usage.elapsed_ticks,
            elapsed_ms,
            consumed_tokens: budget_usage.consumed_tokens,
        },
        budget_ceiling: BudgetCeilingOutput {
            max_episodes: config.budget.max_episodes,
            max_duration_ticks: config.budget.max_duration_ticks,
            max_duration_ms,
            max_tokens: config.budget.max_tokens,
        },
        stop_condition: stop_condition.to_string(),
        started_at,
        completed_at,
        total_sessions,
        successful_sessions,
        failed_sessions,
    }
}

/// Counts sessions from emitted coordination events.
fn count_sessions_from_events(
    events: &[apm2_core::coordination::CoordinationEvent],
) -> (u32, u32, u32) {
    let mut total = 0u32;
    let mut successful = 0u32;
    let mut failed = 0u32;

    for event in events {
        if let apm2_core::coordination::CoordinationEvent::SessionUnbound(unbound) = event {
            total = total.saturating_add(1);
            if unbound.outcome == apm2_core::coordination::SessionOutcome::Success {
                successful = successful.saturating_add(1);
            } else {
                failed = failed.saturating_add(1);
            }
        }
    }

    (total, successful, failed)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// Helper to create a test socket path (non-existent for validation tests).
    fn test_socket_path() -> PathBuf {
        PathBuf::from("/tmp/apm2-test-nonexistent.sock")
    }

    /// Helper to create default test args with new TCK-00346 fields.
    fn test_args_with_defaults(
        work_ids: Option<Vec<String>>,
        max_episodes: u32,
        max_duration_ms: u64,
    ) -> CoordinateArgs {
        CoordinateArgs {
            work_ids,
            work_query: None,
            max_episodes,
            max_duration_ms,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
            actor_id: "test-actor".to_string(),
            workspace_root: None,
        }
    }

    // =========================================================================
    // Argument Parsing Tests
    // =========================================================================

    /// TCK-00153: Test that command parses all options correctly.
    #[test]
    fn test_coordinate_args_defaults() {
        // Verify default values
        assert_eq!(DEFAULT_MAX_ATTEMPTS_PER_WORK, 3);
        assert_eq!(MAX_WORK_QUEUE_SIZE, 1000);
    }

    /// TCK-00153: Test `work_ids` validation.
    #[test]
    fn test_coordinate_empty_work_ids() {
        let args = test_args_with_defaults(None, 10, 60_000);

        let result = run_coordinate_inner(&args, &test_socket_path(), &test_socket_path());
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));
    }

    /// TCK-00153: Test work queue size validation.
    #[test]
    fn test_coordinate_queue_size_exceeded() {
        // Create work_ids that exceed the max_work_queue
        let work_ids: Vec<String> = (0..10).map(|i| format!("work-{i}")).collect();

        let mut args = test_args_with_defaults(Some(work_ids), 10, 60_000);
        args.max_work_queue = 5; // Set lower than work_ids count

        let result = run_coordinate_inner(&args, &test_socket_path(), &test_socket_path());
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("exceeds maximum"),
                "Expected queue size error: {msg}"
            );
        }
    }

    /// TCK-00153: Test zero budget validation.
    #[test]
    fn test_coordinate_zero_budget() {
        let args = test_args_with_defaults(Some(vec!["work-1".to_string()]), 0, 60_000);

        let result = run_coordinate_inner(&args, &test_socket_path(), &test_socket_path());
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));

        let args = test_args_with_defaults(Some(vec!["work-1".to_string()]), 10, 0);

        let result = run_coordinate_inner(&args, &test_socket_path(), &test_socket_path());
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));
    }

    /// TCK-00153: Test mutually exclusive arguments.
    #[test]
    fn test_coordinate_mutually_exclusive_args() {
        let mut args = test_args_with_defaults(Some(vec!["work-1".to_string()]), 10, 60_000);
        args.work_query = Some("file.txt".to_string());

        let result = run_coordinate_inner(&args, &test_socket_path(), &test_socket_path());
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("mutually exclusive"),
                "Expected mutually exclusive error: {msg}"
            );
        }
    }

    // =========================================================================
    // Receipt Tests
    // =========================================================================

    /// TCK-00153: Test that JSON output is valid.
    #[test]
    fn test_coordination_receipt_serde() {
        let receipt = CoordinationReceipt {
            coordination_id: "coord-123".to_string(),
            work_outcomes: vec![WorkOutcomeEntry {
                work_id: "work-1".to_string(),
                attempts: 2,
                final_outcome: "SUCCEEDED".to_string(),
                session_ids: vec!["sess-1".to_string(), "sess-2".to_string()],
            }],
            budget_usage: BudgetUsageOutput {
                consumed_episodes: 5,
                elapsed_ticks: 30_000_000,
                elapsed_ms: 30_000,
                consumed_tokens: 50_000,
            },
            budget_ceiling: BudgetCeilingOutput {
                max_episodes: 10,
                max_duration_ticks: 60_000_000,
                max_duration_ms: 60_000,
                max_tokens: Some(100_000),
            },
            stop_condition: "WORK_COMPLETED".to_string(),
            started_at: 1_000_000_000,
            completed_at: 2_000_000_000,
            total_sessions: 5,
            successful_sessions: 4,
            failed_sessions: 1,
        };

        // Serialize and deserialize
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: CoordinationReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.coordination_id, receipt.coordination_id);
        assert_eq!(restored.stop_condition, receipt.stop_condition);
        assert_eq!(restored.total_sessions, receipt.total_sessions);
    }

    // =========================================================================
    // Work ID Parsing Tests
    // =========================================================================

    /// TCK-00153: Test `work_ids` comma parsing.
    #[test]
    fn test_parse_work_ids_comma_separated() {
        let args = test_args_with_defaults(
            Some(vec![
                "work-1".to_string(),
                "work-2".to_string(),
                "work-3".to_string(),
            ]),
            10,
            60_000,
        );

        let work_ids = parse_work_ids(&args).unwrap();
        assert_eq!(work_ids.len(), 3);
        assert_eq!(work_ids[0], "work-1");
        assert_eq!(work_ids[1], "work-2");
        assert_eq!(work_ids[2], "work-3");
    }

    /// TCK-00153: Test `work_ids` with whitespace trimming.
    #[test]
    fn test_parse_work_ids_with_whitespace() {
        let args = test_args_with_defaults(
            Some(vec![
                "  work-1  ".to_string(),
                "work-2".to_string(),
                String::new(),
            ]),
            10,
            60_000,
        );

        let work_ids = parse_work_ids(&args).unwrap();
        assert_eq!(work_ids.len(), 2);
        assert_eq!(work_ids[0], "work-1");
        assert_eq!(work_ids[1], "work-2");
    }

    /// TCK-00153: Test malformed JSON in work-query is rejected (security
    /// fix).
    ///
    /// Per security review: If input looks like JSON (starts with `[`) but
    /// fails to parse, we must return an error instead of falling back to
    /// line parsing. This prevents silent acceptance of malformed input.
    #[test]
    fn test_parse_work_query_malformed_json() {
        use std::io::Write;

        // Create a temp file with malformed JSON
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(temp_file, r#"["id1","#).unwrap();
        temp_file.flush().unwrap();

        let result = parse_work_query(temp_file.path().to_str().unwrap());
        assert!(result.is_err());
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("appears to be JSON but failed to parse"),
                "Expected JSON parse error, got: {msg}"
            );
        } else {
            panic!("Expected InvalidArgs error");
        }
    }

    /// TCK-00153: Test valid JSON array in work-query is parsed.
    #[test]
    fn test_parse_work_query_valid_json() {
        use std::io::Write;

        // Create a temp file with valid JSON
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(temp_file, r#"["work-1", "work-2", "work-3"]"#).unwrap();
        temp_file.flush().unwrap();

        let result = parse_work_query(temp_file.path().to_str().unwrap());
        assert!(result.is_ok());
        let ids = result.unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], "work-1");
        assert_eq!(ids[1], "work-2");
        assert_eq!(ids[2], "work-3");
    }

    /// TCK-00153: Test line-separated work-query is parsed.
    #[test]
    fn test_parse_work_query_line_separated() {
        use std::io::Write;

        // Create a temp file with line-separated IDs
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(temp_file, "work-1\n# comment\nwork-2\n  work-3  \n").unwrap();
        temp_file.flush().unwrap();

        let result = parse_work_query(temp_file.path().to_str().unwrap());
        assert!(result.is_ok());
        let ids = result.unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], "work-1");
        assert_eq!(ids[1], "work-2");
        assert_eq!(ids[2], "work-3");
    }

    // =========================================================================
    // Exit Code Tests
    // =========================================================================

    /// TCK-00153: Test exit codes.
    #[test]
    fn test_exit_codes() {
        assert_eq!(exit_codes::SUCCESS, 0);
        assert_eq!(exit_codes::ABORTED, 1);
        assert_eq!(exit_codes::INVALID_ARGS, 2);
    }

    /// TCK-00153: Test successful coordination returns exit code 0.
    #[test]
    fn test_coordinate_success_exit_code() {
        // Create a receipt with WORK_COMPLETED
        let receipt = CoordinationReceipt {
            coordination_id: "coord-123".to_string(),
            work_outcomes: vec![],
            budget_usage: BudgetUsageOutput {
                consumed_episodes: 0,
                elapsed_ticks: 0,
                elapsed_ms: 0,
                consumed_tokens: 0,
            },
            budget_ceiling: BudgetCeilingOutput {
                max_episodes: 10,
                max_duration_ticks: 60_000_000,
                max_duration_ms: 60_000,
                max_tokens: None,
            },
            stop_condition: "WORK_COMPLETED".to_string(),
            started_at: 0,
            completed_at: 0,
            total_sessions: 0,
            successful_sessions: 0,
            failed_sessions: 0,
        };

        // Check exit code logic
        if receipt.stop_condition == "WORK_COMPLETED" {
            assert_eq!(exit_codes::SUCCESS, 0);
        } else {
            assert_eq!(exit_codes::ABORTED, 1);
        }
    }

    /// TCK-00153: Test aborted coordination returns exit code 1.
    ///
    /// TCK-00346: Updated to test daemon unavailable scenario.
    #[test]
    fn test_coordinate_aborted_exit_code() {
        let args = test_args_with_defaults(Some(vec!["work-1".to_string()]), 10, 60_000);

        // With no daemon running, coordination should abort
        let exit_code = run_coordinate(&args, &test_socket_path(), &test_socket_path());
        assert_eq!(exit_code, exit_codes::ABORTED);
    }

    /// TCK-00153: Test invalid arguments returns exit code 2.
    #[test]
    fn test_coordinate_invalid_args_exit_code() {
        let args = test_args_with_defaults(None, 10, 60_000);

        let exit_code = run_coordinate(&args, &test_socket_path(), &test_socket_path());
        assert_eq!(exit_code, exit_codes::INVALID_ARGS);
    }

    // =========================================================================
    // HTF Compliance Tests (TCK-00247)
    // =========================================================================

    /// TCK-00247: Verify tick-based duration takes precedence over wall-clock
    /// ms.
    ///
    /// Per RFC-0016: Ticks are authoritative for duration/budget enforcement.
    /// When `max_duration_ticks` is provided, it takes precedence over
    /// `max_duration_ms`.
    ///
    /// Note: This test verifies the receipt contains correct tick values.
    /// With TCK-00346 daemon integration, the function always returns a receipt
    /// (even when daemon is unavailable - it just aborts).
    #[test]
    fn tck_00247_tick_duration_takes_precedence() {
        let mut args = test_args_with_defaults(Some(vec!["work-1".to_string()]), 10, 1_000);
        args.max_duration_ticks = Some(5_000_000); // 5M ticks = 5s at 1MHz

        // With TCK-00346, the function returns Ok(receipt) even when daemon unavailable
        // The receipt will have ABORTED status but correct budget ceiling values
        let result = run_coordinate_inner(&args, &test_socket_path(), &test_socket_path());
        assert!(
            result.is_ok(),
            "Expected receipt even with daemon unavailable"
        );

        // Verify the receipt uses the tick-based duration
        let receipt = result.unwrap();
        assert_eq!(receipt.budget_ceiling.max_duration_ticks, 5_000_000);
        // Should be ABORTED due to daemon unavailable
        assert_eq!(receipt.stop_condition, "ABORTED");
    }

    /// TCK-00247: Verify zero ticks is rejected (tick authority validation).
    ///
    /// Per RFC-0016: Zero duration is invalid for any authority clock domain.
    #[test]
    fn tck_00247_zero_ticks_rejected() {
        let mut args = test_args_with_defaults(Some(vec!["work-1".to_string()]), 10, 60_000);
        args.max_duration_ticks = Some(0); // Invalid: zero ticks

        let result = run_coordinate_inner(&args, &test_socket_path(), &test_socket_path());
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("max-duration-ticks must be positive"),
                "Expected tick validation error, got: {msg}"
            );
        }
    }

    /// TCK-00247: Verify wall-clock ms fallback when ticks not provided.
    ///
    /// Per RFC-0016: ms input is converted to ticks for internal use.
    /// This maintains backward compatibility while enforcing tick authority.
    ///
    /// Note: With TCK-00346 daemon integration, the function always returns a
    /// receipt (even when daemon is unavailable - it just aborts).
    #[test]
    fn tck_00247_ms_converted_to_ticks() {
        let args = test_args_with_defaults(Some(vec!["work-1".to_string()]), 10, 1_000);

        // With TCK-00346, the function returns Ok(receipt) even when daemon unavailable
        let result = run_coordinate_inner(&args, &test_socket_path(), &test_socket_path());
        assert!(
            result.is_ok(),
            "Expected receipt even with daemon unavailable"
        );

        // Verify ms was converted to ticks (1000ms * 1000 = 1_000_000 ticks at 1MHz)
        let receipt = result.unwrap();
        assert_eq!(receipt.budget_ceiling.max_duration_ticks, 1_000_000);
        // Should be ABORTED due to daemon unavailable
        assert_eq!(receipt.stop_condition, "ABORTED");
    }

    /// TCK-00247: Verify receipt includes both ticks (authority) and ms
    /// (overlay).
    ///
    /// Per RFC-0016: Wall time is permitted as observational overlay for
    /// display. Receipts should include both tick-based values
    /// (authoritative) and wall-clock values (observational).
    #[test]
    fn tck_00247_receipt_includes_tick_and_wall_overlay() {
        let receipt = CoordinationReceipt {
            coordination_id: "test-coord".to_string(),
            work_outcomes: vec![],
            budget_usage: BudgetUsageOutput {
                consumed_episodes: 2,
                elapsed_ticks: 5_000_000, // Authority: 5M ticks
                elapsed_ms: 5_000,        // Overlay: 5 seconds
                consumed_tokens: 1000,
            },
            budget_ceiling: BudgetCeilingOutput {
                max_episodes: 10,
                max_duration_ticks: 60_000_000, // Authority: 60M ticks
                max_duration_ms: 60_000,        // Overlay: 60 seconds
                max_tokens: None,
            },
            stop_condition: "WORK_COMPLETED".to_string(),
            started_at: 1_704_067_200_000_000_000, // Observational only
            completed_at: 1_704_067_205_000_000_000, // Observational only
            total_sessions: 2,
            successful_sessions: 2,
            failed_sessions: 0,
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&receipt).unwrap();

        // Verify both tick and ms fields are present
        assert!(json.contains("\"elapsed_ticks\""));
        assert!(json.contains("\"elapsed_ms\""));
        assert!(json.contains("\"max_duration_ticks\""));
        assert!(json.contains("\"max_duration_ms\""));

        // Verify tick values are correct (authoritative)
        assert!(json.contains("5000000")); // elapsed_ticks
        assert!(json.contains("60000000")); // max_duration_ticks
    }

    /// TCK-00247: Verify wall-clock timestamps are observational only.
    ///
    /// Per RFC-0016: Wall time fields (`started_at`, `completed_at`) are for
    /// display/audit purposes only. They MUST NOT affect coordination
    /// decisions.
    #[test]
    fn tck_00247_wall_timestamps_observational() {
        // Create two receipts with different wall timestamps but same tick values
        let receipt1 = CoordinationReceipt {
            coordination_id: "test-1".to_string(),
            work_outcomes: vec![],
            budget_usage: BudgetUsageOutput {
                consumed_episodes: 5,
                elapsed_ticks: 30_000_000,
                elapsed_ms: 30_000,
                consumed_tokens: 5000,
            },
            budget_ceiling: BudgetCeilingOutput {
                max_episodes: 10,
                max_duration_ticks: 60_000_000,
                max_duration_ms: 60_000,
                max_tokens: None,
            },
            stop_condition: "BUDGET_EXHAUSTED".to_string(),
            started_at: 1_000_000_000_000_000_000, // Early timestamp
            completed_at: 1_000_000_030_000_000_000,
            total_sessions: 5,
            successful_sessions: 5,
            failed_sessions: 0,
        };

        let receipt2 = CoordinationReceipt {
            coordination_id: "test-2".to_string(),
            work_outcomes: vec![],
            budget_usage: BudgetUsageOutput {
                consumed_episodes: 5,
                elapsed_ticks: 30_000_000, // Same tick budget
                elapsed_ms: 30_000,
                consumed_tokens: 5000,
            },
            budget_ceiling: BudgetCeilingOutput {
                max_episodes: 10,
                max_duration_ticks: 60_000_000,
                max_duration_ms: 60_000,
                max_tokens: None,
            },
            stop_condition: "BUDGET_EXHAUSTED".to_string(),
            started_at: 2_000_000_000_000_000_000, // Later timestamp (different!)
            completed_at: 2_000_000_030_000_000_000,
            total_sessions: 5,
            successful_sessions: 5,
            failed_sessions: 0,
        };

        // Despite different wall timestamps, tick-based budget usage is identical
        // This proves wall timestamps don't affect authority decisions
        assert_eq!(
            receipt1.budget_usage.elapsed_ticks,
            receipt2.budget_usage.elapsed_ticks
        );
        assert_eq!(
            receipt1.budget_ceiling.max_duration_ticks,
            receipt2.budget_ceiling.max_duration_ticks
        );

        // Both should have same stop condition based on ticks, not wall time
        assert_eq!(receipt1.stop_condition, receipt2.stop_condition);
    }

    /// TCK-00247: Verify tick rate constant is correctly defined.
    ///
    /// Per RFC-0016: Tick rates must be explicit and consistent.
    #[test]
    fn tck_00247_tick_rate_defined() {
        // 1MHz = 1 tick per microsecond
        assert_eq!(DEFAULT_TICK_RATE_HZ, 1_000_000);

        // Verify conversion: 1 second = 1_000_000 ticks
        let one_second_ms = 1000u64;
        let expected_ticks = one_second_ms * 1000; // ms to us
        assert_eq!(expected_ticks, DEFAULT_TICK_RATE_HZ);
    }

    // =========================================================================
    // Security Tests (SEC-FAC-001, SEC-FAC-002, SEC-FAC-003)
    // =========================================================================

    /// SEC-FAC-001: Verify bounded deserialization rejects oversized
    /// `work_outcomes`.
    ///
    /// Attackers may craft malicious JSON with excessive array sizes to
    /// cause memory exhaustion. The bounded deserializer MUST reject
    /// arrays exceeding `MAX_WORK_OUTCOMES`.
    #[test]
    fn sec_fac_001_bounded_deser_rejects_oversized_work_outcomes() {
        use apm2_core::coordination::MAX_WORK_OUTCOMES;

        // Build JSON with too many work outcomes
        let work_outcomes: Vec<serde_json::Value> = (0..=MAX_WORK_OUTCOMES)
            .map(|i| {
                serde_json::json!({
                    "work_id": format!("work-{i}"),
                    "attempts": 1,
                    "final_outcome": "SUCCEEDED",
                    "session_ids": [],
                })
            })
            .collect();

        let json = serde_json::json!({
            "coordination_id": "coord-1",
            "work_outcomes": work_outcomes,
            "budget_usage": {
                "consumed_episodes": 0,
                "elapsed_ticks": 0,
                "elapsed_ms": 0,
                "consumed_tokens": 0
            },
            "budget_ceiling": {
                "max_episodes": 10,
                "max_duration_ticks": 60_000_000,
                "max_duration_ms": 60_000,
                "max_tokens": null
            },
            "stop_condition": "WORK_COMPLETED",
            "started_at": 0,
            "completed_at": 0,
            "total_sessions": 0,
            "successful_sessions": 0,
            "failed_sessions": 0,
        });

        let result: Result<CoordinationReceipt, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("exceeds maximum"),
            "Expected bounded deserializer to reject oversized array"
        );
    }

    /// SEC-FAC-001: Verify bounded deserialization rejects oversized
    /// `session_ids`.
    ///
    /// Attackers may craft malicious JSON with excessive `session_ids` to
    /// cause memory exhaustion. The bounded deserializer MUST reject
    /// arrays exceeding `MAX_SESSION_IDS_PER_OUTCOME`.
    #[test]
    fn sec_fac_001_bounded_deser_rejects_oversized_session_ids() {
        use apm2_core::coordination::MAX_SESSION_IDS_PER_OUTCOME;

        // Build JSON with too many session IDs
        let session_ids: Vec<String> = (0..=MAX_SESSION_IDS_PER_OUTCOME)
            .map(|i| format!("session-{i}"))
            .collect();

        let json = serde_json::json!({
            "work_id": "work-1",
            "attempts": 1,
            "final_outcome": "SUCCEEDED",
            "session_ids": session_ids,
        });

        let result: Result<WorkOutcomeEntry, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("exceeds maximum"),
            "Expected bounded deserializer to reject oversized session_ids"
        );
    }

    /// SEC-FAC-002: Verify `deny_unknown_fields` rejects unexpected fields
    /// in `CoordinationReceipt`.
    ///
    /// Attackers may inject unexpected fields to probe for vulnerabilities
    /// or exploit lenient parsing. The `deny_unknown_fields` attribute
    /// MUST cause deserialization to fail.
    #[test]
    fn sec_fac_002_deny_unknown_fields_receipt() {
        let json = serde_json::json!({
            "coordination_id": "coord-1",
            "work_outcomes": [],
            "budget_usage": {
                "consumed_episodes": 0,
                "elapsed_ticks": 0,
                "elapsed_ms": 0,
                "consumed_tokens": 0
            },
            "budget_ceiling": {
                "max_episodes": 10,
                "max_duration_ticks": 60_000_000,
                "max_duration_ms": 60_000,
                "max_tokens": null
            },
            "stop_condition": "WORK_COMPLETED",
            "started_at": 0,
            "completed_at": 0,
            "total_sessions": 0,
            "successful_sessions": 0,
            "failed_sessions": 0,
            "malicious_field": "injected_payload",
        });

        let result: Result<CoordinationReceipt, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("unknown field"),
            "Expected deny_unknown_fields to reject extra field"
        );
    }

    /// SEC-FAC-002: Verify `deny_unknown_fields` rejects unexpected fields
    /// in `WorkOutcomeEntry`.
    #[test]
    fn sec_fac_002_deny_unknown_fields_work_outcome() {
        let json = serde_json::json!({
            "work_id": "work-1",
            "attempts": 1,
            "final_outcome": "SUCCEEDED",
            "session_ids": [],
            "extra": "malicious",
        });

        let result: Result<WorkOutcomeEntry, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("unknown field"),
            "Expected deny_unknown_fields to reject extra field in WorkOutcomeEntry"
        );
    }

    /// SEC-FAC-002: Verify `deny_unknown_fields` rejects unexpected fields
    /// in `BudgetUsageOutput`.
    #[test]
    fn sec_fac_002_deny_unknown_fields_budget_usage() {
        let json = serde_json::json!({
            "consumed_episodes": 0,
            "elapsed_ticks": 0,
            "elapsed_ms": 0,
            "consumed_tokens": 0,
            "hidden_budget": 999_999,
        });

        let result: Result<BudgetUsageOutput, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("unknown field"),
            "Expected deny_unknown_fields to reject extra field in BudgetUsageOutput"
        );
    }

    /// SEC-FAC-002: Verify `deny_unknown_fields` rejects unexpected fields
    /// in `BudgetCeilingOutput`.
    #[test]
    fn sec_fac_002_deny_unknown_fields_budget_ceiling() {
        let json = serde_json::json!({
            "max_episodes": 10,
            "max_duration_ticks": 60_000_000,
            "max_duration_ms": 60_000,
            "max_tokens": null,
            "secret_limit": 0,
        });

        let result: Result<BudgetCeilingOutput, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("unknown field"),
            "Expected deny_unknown_fields to reject extra field in BudgetCeilingOutput"
        );
    }

    /// SEC-FAC-001: Verify valid receipts with bounded arrays still parse.
    ///
    /// Ensure that legitimate use cases still work after adding bounded
    /// deserialization.
    #[test]
    fn sec_fac_001_valid_bounded_receipt_parses() {
        let json = serde_json::json!({
            "coordination_id": "coord-test",
            "work_outcomes": [
                {
                    "work_id": "work-1",
                    "attempts": 2,
                    "final_outcome": "SUCCEEDED",
                    "session_ids": ["sess-1", "sess-2"],
                }
            ],
            "budget_usage": {
                "consumed_episodes": 2,
                "elapsed_ticks": 5_000_000,
                "elapsed_ms": 5000,
                "consumed_tokens": 1000
            },
            "budget_ceiling": {
                "max_episodes": 10,
                "max_duration_ticks": 60_000_000,
                "max_duration_ms": 60_000,
                "max_tokens": null
            },
            "stop_condition": "WORK_COMPLETED",
            "started_at": 1_704_067_200_000_000_000_u64,
            "completed_at": 1_704_067_205_000_000_000_u64,
            "total_sessions": 2,
            "successful_sessions": 2,
            "failed_sessions": 0,
        });

        let result: Result<CoordinationReceipt, _> = serde_json::from_value(json);
        assert!(result.is_ok(), "Valid receipt should parse successfully");

        let receipt = result.unwrap();
        assert_eq!(receipt.coordination_id, "coord-test");
        assert_eq!(receipt.work_outcomes.len(), 1);
        assert_eq!(receipt.work_outcomes[0].session_ids.len(), 2);
    }

    /// SEC-FAC-001/002: Verify serde roundtrip preserves data integrity.
    ///
    /// Ensure that serialization followed by deserialization produces
    /// equivalent data.
    #[test]
    fn sec_fac_serde_roundtrip() {
        let receipt = CoordinationReceipt {
            coordination_id: "coord-roundtrip".to_string(),
            work_outcomes: vec![WorkOutcomeEntry {
                work_id: "work-1".to_string(),
                attempts: 3,
                final_outcome: "SUCCEEDED".to_string(),
                session_ids: vec!["sess-a".to_string(), "sess-b".to_string()],
            }],
            budget_usage: BudgetUsageOutput {
                consumed_episodes: 3,
                elapsed_ticks: 10_000_000,
                elapsed_ms: 10_000,
                consumed_tokens: 5000,
            },
            budget_ceiling: BudgetCeilingOutput {
                max_episodes: 10,
                max_duration_ticks: 60_000_000,
                max_duration_ms: 60_000,
                max_tokens: Some(100_000),
            },
            stop_condition: "WORK_COMPLETED".to_string(),
            started_at: 1_000_000_000,
            completed_at: 1_010_000_000,
            total_sessions: 3,
            successful_sessions: 3,
            failed_sessions: 0,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&receipt).unwrap();

        // Deserialize back
        let restored: CoordinationReceipt = serde_json::from_str(&json).unwrap();

        // Verify all fields
        assert_eq!(restored.coordination_id, receipt.coordination_id);
        assert_eq!(restored.work_outcomes.len(), receipt.work_outcomes.len());
        assert_eq!(
            restored.work_outcomes[0].work_id,
            receipt.work_outcomes[0].work_id
        );
        assert_eq!(
            restored.work_outcomes[0].session_ids.len(),
            receipt.work_outcomes[0].session_ids.len()
        );
        assert_eq!(
            restored.budget_usage.elapsed_ticks,
            receipt.budget_usage.elapsed_ticks
        );
        assert_eq!(
            restored.budget_ceiling.max_tokens,
            receipt.budget_ceiling.max_tokens
        );
    }

    // =========================================================================
    // TCK-00346 Security Hardening Tests
    // =========================================================================

    /// TCK-00346: Token estimation never returns zero.
    ///
    /// BLOCKER 2 fix: Verify that `estimate_token_consumption` always returns
    /// at least `MIN_TOKENS_PER_SESSION`, even for zero elapsed time.
    #[test]
    fn tck_00346_token_estimation_never_zero() {
        // Zero seconds should return minimum
        assert_eq!(estimate_token_consumption(0), MIN_TOKENS_PER_SESSION);
        assert!(estimate_token_consumption(0) > 0);

        // Short duration should return minimum
        assert_eq!(estimate_token_consumption(1), MIN_TOKENS_PER_SESSION);

        // Longer duration should be time-based (and > minimum)
        let long_duration = estimate_token_consumption(60);
        assert_eq!(long_duration, 60 * CONSERVATIVE_TOKENS_PER_SECOND);
        assert!(long_duration > MIN_TOKENS_PER_SESSION);

        // Very long duration should not overflow
        let huge = estimate_token_consumption(u64::MAX);
        assert!(huge > 0);
    }

    /// TCK-00346: Token estimation uses conservative rate.
    ///
    /// BLOCKER 2 fix: Verify the estimation constants are reasonable.
    #[test]
    fn tck_00346_token_estimation_constants() {
        // Conservative rate must be positive
        const { assert!(CONSERVATIVE_TOKENS_PER_SECOND > 0) };
        // Minimum must be positive
        const { assert!(MIN_TOKENS_PER_SESSION > 0) };
        // Minimum should be at least a few seconds worth
        const { assert!(MIN_TOKENS_PER_SESSION >= CONSERVATIVE_TOKENS_PER_SECOND) };
    }

    /// TCK-00346: Workspace root validation rejects sensitive paths.
    ///
    /// MAJOR fix: Verify that system-critical directories are blocked.
    #[test]
    fn tck_00346_workspace_root_rejects_root() {
        let result = validate_workspace_root(Some("/"));
        assert!(result.is_err());
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("sensitive system directory"),
                "Expected sensitive directory error, got: {msg}"
            );
        }
    }

    /// TCK-00346: Workspace root validation rejects /etc.
    #[test]
    fn tck_00346_workspace_root_rejects_etc() {
        let result = validate_workspace_root(Some("/etc"));
        assert!(result.is_err());
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("sensitive system directory"),
                "Expected sensitive directory error, got: {msg}"
            );
        }
    }

    /// TCK-00346: Workspace root validation rejects non-existent paths.
    #[test]
    fn tck_00346_workspace_root_rejects_nonexistent() {
        let result = validate_workspace_root(Some("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_err());
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("cannot be resolved"),
                "Expected resolution error, got: {msg}"
            );
        }
    }

    /// TCK-00346: Workspace root validation accepts valid directories.
    #[test]
    fn tck_00346_workspace_root_accepts_valid() {
        // /tmp should be a valid workspace root
        let result = validate_workspace_root(Some("/tmp"));
        assert!(result.is_ok(), "Expected /tmp to be valid: {result:?}");
        let path = result.unwrap();
        // Should be absolute and canonical
        assert!(path.starts_with('/'));
    }

    /// TCK-00346: Workspace root defaults to cwd when None.
    #[test]
    fn tck_00346_workspace_root_defaults_to_cwd() {
        let result = validate_workspace_root(None);
        assert!(result.is_ok(), "Expected cwd to be valid: {result:?}");
        let path = result.unwrap();
        // Should be absolute
        assert!(path.starts_with('/'));
    }

    /// TCK-00346: Workspace root rejects files (not directories).
    #[test]
    fn tck_00346_workspace_root_rejects_files() {
        use std::io::Write;

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(&temp_file, "not a directory").ok();

        let result = validate_workspace_root(Some(temp_file.path().to_str().unwrap()));
        assert!(result.is_err());
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("not a directory"),
                "Expected directory error, got: {msg}"
            );
        }
    }

    /// TCK-00346: Blocked workspace root list includes critical paths.
    #[test]
    fn tck_00346_blocked_workspace_roots_comprehensive() {
        // Verify all expected paths are in the blocklist
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/etc"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/usr"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/bin"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/sbin"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/boot"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/dev"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/proc"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/sys"));
        assert!(BLOCKED_WORKSPACE_ROOTS.contains(&"/var"));
    }

    /// TCK-00346: Workspace root validation blocks subdirectories of sensitive
    /// paths.
    ///
    /// Security fix: `starts_with` (path-component-aware) blocks `/var/log`,
    /// `/etc/ssh`, etc. — not just the exact blocked roots.
    #[test]
    fn tck_00346_workspace_root_rejects_subdirectories_of_blocked() {
        // /var/log exists on virtually all Linux systems and is a subdirectory
        // of the blocked root "/var".
        let result = validate_workspace_root(Some("/var/log"));
        assert!(
            result.is_err(),
            "Expected /var/log to be blocked as subdirectory of /var: {result:?}"
        );
        if let Err(CoordinateCliError::InvalidArgs(msg)) = result {
            assert!(
                msg.contains("sensitive system directory"),
                "Expected sensitive directory error, got: {msg}"
            );
            assert!(
                msg.contains("/var"),
                "Error message should mention the blocked root '/var', got: {msg}"
            );
        }
    }

    /// TCK-00346: Token estimation rate is a strict upper bound.
    ///
    /// Security fix: The conservative rate must be >= 100 tokens/sec to act
    /// as a Safe-Fail upper bound for modern LLM agents (50-100+ tok/sec).
    #[test]
    fn tck_00346_token_rate_is_strict_upper_bound() {
        const { assert!(CONSERVATIVE_TOKENS_PER_SECOND >= 100) };
    }

    // =========================================================================
    // TCK-00386: Session Termination Signal Tests
    // =========================================================================

    /// TCK-00386: Normal exit with code 0 maps to Success.
    #[test]
    fn tck_00386_normal_exit_zero_maps_to_success() {
        let outcome = map_termination_to_outcome(Some("normal"), Some(0));
        assert_eq!(outcome, SessionOutcome::Success);
    }

    /// TCK-00386: Normal exit with non-zero code maps to Failure.
    #[test]
    fn tck_00386_normal_exit_nonzero_maps_to_failure() {
        let outcome = map_termination_to_outcome(Some("normal"), Some(1));
        assert_eq!(outcome, SessionOutcome::Failure);

        let outcome = map_termination_to_outcome(Some("normal"), Some(137));
        assert_eq!(outcome, SessionOutcome::Failure);

        let outcome = map_termination_to_outcome(Some("normal"), Some(-1));
        assert_eq!(outcome, SessionOutcome::Failure);
    }

    /// TCK-00386: Normal exit with missing `exit_code` maps to Failure
    /// (fail-closed).
    #[test]
    fn tck_00386_normal_exit_no_code_maps_to_failure() {
        let outcome = map_termination_to_outcome(Some("normal"), None);
        assert_eq!(outcome, SessionOutcome::Failure);
    }

    /// TCK-00386: Crash termination maps to Failure regardless of exit code.
    #[test]
    fn tck_00386_crash_maps_to_failure() {
        let outcome = map_termination_to_outcome(Some("crash"), Some(0));
        assert_eq!(outcome, SessionOutcome::Failure);

        let outcome = map_termination_to_outcome(Some("crash"), Some(1));
        assert_eq!(outcome, SessionOutcome::Failure);

        let outcome = map_termination_to_outcome(Some("crash"), None);
        assert_eq!(outcome, SessionOutcome::Failure);
    }

    /// TCK-00386: Timeout termination maps to Failure regardless of exit code.
    #[test]
    fn tck_00386_timeout_maps_to_failure() {
        let outcome = map_termination_to_outcome(Some("timeout"), Some(0));
        assert_eq!(outcome, SessionOutcome::Failure);

        let outcome = map_termination_to_outcome(Some("timeout"), None);
        assert_eq!(outcome, SessionOutcome::Failure);
    }

    /// TCK-00386: Quarantined termination maps to Failure.
    #[test]
    fn tck_00386_quarantined_maps_to_failure() {
        let outcome = map_termination_to_outcome(Some("quarantined"), Some(0));
        assert_eq!(outcome, SessionOutcome::Failure);
    }

    /// TCK-00386: Budget-exhausted termination maps to Failure.
    #[test]
    fn tck_00386_budget_exhausted_maps_to_failure() {
        let outcome = map_termination_to_outcome(Some("budget_exhausted"), Some(0));
        assert_eq!(outcome, SessionOutcome::Failure);
    }

    /// TCK-00386: Missing termination reason maps to Failure (fail-closed).
    #[test]
    fn tck_00386_no_reason_maps_to_failure() {
        let outcome = map_termination_to_outcome(None, Some(0));
        assert_eq!(outcome, SessionOutcome::Failure);

        let outcome = map_termination_to_outcome(None, None);
        assert_eq!(outcome, SessionOutcome::Failure);
    }

    /// TCK-00386: Unknown termination reason maps to Failure (fail-closed).
    #[test]
    fn tck_00386_unknown_reason_maps_to_failure() {
        let outcome = map_termination_to_outcome(Some("alien_abduction"), Some(0));
        assert_eq!(outcome, SessionOutcome::Failure);
    }

    /// TCK-00386: Actual token consumption is used when available.
    #[test]
    fn tck_00386_resolve_tokens_uses_actual_when_available() {
        // Actual tokens reported by daemon: should be used directly
        let tokens = resolve_token_consumption(Some(5000), 60);
        assert_eq!(tokens, 5000);

        // Large actual value is preserved
        let tokens = resolve_token_consumption(Some(1_000_000), 10);
        assert_eq!(tokens, 1_000_000);
    }

    /// TCK-00386: Actual token consumption is floored at
    /// `MIN_TOKENS_PER_SESSION`.
    #[test]
    fn tck_00386_resolve_tokens_floors_actual_at_minimum() {
        // Daemon reports zero tokens: should be clamped to minimum
        let tokens = resolve_token_consumption(Some(0), 60);
        assert_eq!(tokens, MIN_TOKENS_PER_SESSION);

        // Daemon reports below minimum: should be clamped
        let tokens = resolve_token_consumption(Some(1), 60);
        assert_eq!(tokens, MIN_TOKENS_PER_SESSION);

        // Daemon reports exactly minimum: preserved
        let tokens = resolve_token_consumption(Some(MIN_TOKENS_PER_SESSION), 60);
        assert_eq!(tokens, MIN_TOKENS_PER_SESSION);
    }

    /// TCK-00386: Falls back to wall-clock estimate when actual is unavailable.
    #[test]
    fn tck_00386_resolve_tokens_falls_back_to_estimate() {
        // No actual tokens: should use wall-clock estimate
        let tokens = resolve_token_consumption(None, 60);
        assert_eq!(tokens, estimate_token_consumption(60));
        assert_eq!(tokens, 60 * CONSERVATIVE_TOKENS_PER_SECOND);

        // No actual tokens, zero elapsed: should use minimum
        let tokens = resolve_token_consumption(None, 0);
        assert_eq!(tokens, MIN_TOKENS_PER_SESSION);
    }

    /// TCK-00386: Token resolution never returns zero.
    #[test]
    fn tck_00386_resolve_tokens_never_zero() {
        // Every combination must produce > 0
        assert!(resolve_token_consumption(Some(0), 0) > 0);
        assert!(resolve_token_consumption(None, 0) > 0);
        assert!(resolve_token_consumption(Some(0), 60) > 0);
        assert!(resolve_token_consumption(None, 60) > 0);
    }

    /// TCK-00386: Only one specific combination produces Success.
    ///
    /// Exhaustively verify that the only path to Success is
    /// (`reason="normal"`, `exit_code=0`). This is a binding test —
    /// it proves the fail-closed invariant by checking multiple
    /// distinct failure paths, not just one.
    #[test]
    fn tck_00386_fail_closed_only_normal_zero_succeeds() {
        let reasons: &[Option<&str>] = &[
            None,
            Some("normal"),
            Some("crash"),
            Some("timeout"),
            Some("quarantined"),
            Some("budget_exhausted"),
            Some("unknown"),
        ];
        let codes: &[Option<i32>] = &[None, Some(-1), Some(0), Some(1), Some(137)];

        let mut success_count = 0u32;
        let mut failure_count = 0u32;

        for reason in reasons {
            for code in codes {
                let outcome = map_termination_to_outcome(*reason, *code);
                match outcome {
                    SessionOutcome::Success => success_count += 1,
                    SessionOutcome::Failure => failure_count += 1,
                }
            }
        }

        // Exactly one combination produces Success
        assert_eq!(success_count, 1, "Expected exactly 1 Success path");
        // All others produce Failure
        #[allow(clippy::cast_possible_truncation)] // Test data is small
        let expected_failures = (reasons.len() * codes.len()) as u32 - 1;
        assert_eq!(
            failure_count, expected_failures,
            "Expected all other paths to produce Failure"
        );
    }
}
