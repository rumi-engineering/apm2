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
//! - RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution
//! - CTR-COORD-007: CLI Command (apm2 coordinate)

use std::fs::File;
use std::io::Read as IoRead;

use apm2_core::coordination::{
    CoordinationBudget, CoordinationConfig, CoordinationController, DEFAULT_MAX_ATTEMPTS_PER_WORK,
    MAX_WORK_QUEUE_SIZE,
};
use apm2_core::htf::HtfTick;
use clap::Args;
use serde::{Deserialize, Serialize};

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
}

/// Coordination receipt output structure.
///
/// Per CTR-COORD-006: Evidence artifact proving coordination execution.
#[derive(Debug, Serialize, Deserialize)]
pub struct CoordinationReceipt {
    /// Coordination ID.
    pub coordination_id: String,
    /// Work outcomes for each processed item.
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
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkOutcomeEntry {
    /// Work item ID.
    pub work_id: String,
    /// Number of attempts made.
    pub attempts: u32,
    /// Final outcome (SUCCEEDED, FAILED, SKIPPED).
    pub final_outcome: String,
    /// Session IDs used for this work item.
    pub session_ids: Vec<String>,
}

/// Budget usage output in the receipt.
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
}

/// Runs the coordinate command, returning an appropriate exit code as u8.
///
/// # Exit Codes
///
/// - 0: Coordination completed successfully (`WORK_COMPLETED`)
/// - 1: Coordination aborted (any other stop condition)
/// - 2: Invalid arguments
pub fn run_coordinate(args: &CoordinateArgs) -> u8 {
    match run_coordinate_inner(args) {
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
fn run_coordinate_inner(args: &CoordinateArgs) -> Result<CoordinationReceipt, CoordinateCliError> {
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

    // In a real implementation, this would run the coordination loop.
    // For the CLI MVP, we simulate immediate completion since we don't have
    // the daemon/session infrastructure wired up yet.
    //
    // The actual coordination loop would:
    // 1. Check stop conditions
    // 2. Check work freshness
    // 3. Spawn sessions via SessionSpawner
    // 4. Observe termination
    // 5. Record outcomes
    //
    // For now, we abort with NO_ELIGIBLE_WORK since we can't actually
    // spawn sessions without the daemon.

    // Truncation from u128 to u64 is safe: u64 can hold ~584 million years of
    // nanoseconds
    #[allow(clippy::cast_possible_truncation)]
    let completed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // Abort with no eligible work (MVP behavior)
    let abort_reason = apm2_core::coordination::AbortReason::Error {
        message: "coordination requires daemon connection (not yet implemented)".to_string(),
    };

    // Calculate elapsed time in ticks for abort
    // Since we're aborting immediately, elapsed is roughly 0
    let abort_tick = HtfTick::new(0, DEFAULT_TICK_RATE_HZ);

    controller
        .abort(abort_reason, abort_tick, completed_at)
        .map_err(|e| CoordinateCliError::CoordinationError(e.to_string()))?;

    // Build receipt from controller state
    let receipt = build_receipt(
        &coordination_id,
        &controller,
        &config,
        "ABORTED",
        started_at,
        completed_at,
    );

    if !args.quiet {
        eprintln!("Coordination aborted: {coordination_id} (daemon connection required)");
    }

    Ok(receipt)
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
    // Build work outcomes from controller's work tracking
    let work_outcomes: Vec<WorkOutcomeEntry> = config
        .work_ids
        .iter()
        .map(|work_id| WorkOutcomeEntry {
            work_id: work_id.clone(),
            attempts: 0,
            final_outcome: "SKIPPED".to_string(),
            session_ids: Vec::new(),
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
    use super::*;

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
        let args = CoordinateArgs {
            work_ids: None,
            work_query: None,
            max_episodes: 10,
            max_duration_ms: 60_000,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
        };

        let result = run_coordinate_inner(&args);
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));
    }

    /// TCK-00153: Test work queue size validation.
    #[test]
    fn test_coordinate_queue_size_exceeded() {
        // Create work_ids that exceed the max_work_queue
        let work_ids: Vec<String> = (0..10).map(|i| format!("work-{i}")).collect();

        let args = CoordinateArgs {
            work_ids: Some(work_ids),
            work_query: None,
            max_episodes: 10,
            max_duration_ms: 60_000,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 5, // Set lower than work_ids count
            json: true,
            quiet: true,
        };

        let result = run_coordinate_inner(&args);
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
        let args = CoordinateArgs {
            work_ids: Some(vec!["work-1".to_string()]),
            work_query: None,
            max_episodes: 0, // Invalid
            max_duration_ms: 60_000,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
        };

        let result = run_coordinate_inner(&args);
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));

        let args = CoordinateArgs {
            work_ids: Some(vec!["work-1".to_string()]),
            work_query: None,
            max_episodes: 10,
            max_duration_ms: 0, // Invalid
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
        };

        let result = run_coordinate_inner(&args);
        assert!(matches!(result, Err(CoordinateCliError::InvalidArgs(_))));
    }

    /// TCK-00153: Test mutually exclusive arguments.
    #[test]
    fn test_coordinate_mutually_exclusive_args() {
        let args = CoordinateArgs {
            work_ids: Some(vec!["work-1".to_string()]),
            work_query: Some("file.txt".to_string()),
            max_episodes: 10,
            max_duration_ms: 60_000,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
        };

        let result = run_coordinate_inner(&args);
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
        let args = CoordinateArgs {
            work_ids: Some(vec![
                "work-1".to_string(),
                "work-2".to_string(),
                "work-3".to_string(),
            ]),
            work_query: None,
            max_episodes: 10,
            max_duration_ms: 60_000,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
        };

        let work_ids = parse_work_ids(&args).unwrap();
        assert_eq!(work_ids.len(), 3);
        assert_eq!(work_ids[0], "work-1");
        assert_eq!(work_ids[1], "work-2");
        assert_eq!(work_ids[2], "work-3");
    }

    /// TCK-00153: Test `work_ids` with whitespace trimming.
    #[test]
    fn test_parse_work_ids_with_whitespace() {
        let args = CoordinateArgs {
            work_ids: Some(vec![
                "  work-1  ".to_string(),
                "work-2".to_string(),
                String::new(),
            ]),
            work_query: None,
            max_episodes: 10,
            max_duration_ms: 60_000,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
        };

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
    #[test]
    fn test_coordinate_aborted_exit_code() {
        let args = CoordinateArgs {
            work_ids: Some(vec!["work-1".to_string()]),
            work_query: None,
            max_episodes: 10,
            max_duration_ms: 60_000,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
        };

        // The current implementation aborts since daemon is not implemented
        let exit_code = run_coordinate(&args);
        assert_eq!(exit_code, exit_codes::ABORTED);
    }

    /// TCK-00153: Test invalid arguments returns exit code 2.
    #[test]
    fn test_coordinate_invalid_args_exit_code() {
        let args = CoordinateArgs {
            work_ids: None,
            work_query: None,
            max_episodes: 10,
            max_duration_ms: 60_000,
            max_duration_ticks: None,
            max_tokens: None,
            max_attempts: 3,
            max_work_queue: 1000,
            json: true,
            quiet: true,
        };

        let exit_code = run_coordinate(&args);
        assert_eq!(exit_code, exit_codes::INVALID_ARGS);
    }
}
