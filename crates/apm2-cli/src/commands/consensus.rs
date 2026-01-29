// AGENT-AUTHORED
//! Consensus cluster management CLI commands.
//!
//! This module implements the `apm2 consensus` subcommands for monitoring
//! and managing the distributed consensus layer per RFC-0014 and TCK-00193.
//!
//! # Commands
//!
//! - `apm2 consensus status` - Show cluster health and leader info
//! - `apm2 consensus byzantine-evidence list` - List detected Byzantine faults
//! - `apm2 consensus validators` - List validators and their status
//!
//! # JSON Output
//!
//! All commands support `--json` flag for machine-readable output.
//!
//! # Exit Codes
//!
//! - 0: Success
//! - 1: Error (daemon connection, etc.)
//! - 2: Cluster unhealthy (critical alerts)
//!
//! # Contract References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - `05_rollout_and_ops.yaml`: CLI commands specification

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

/// Exit codes for consensus commands.
pub mod exit_codes {
    /// Success exit code.
    pub const SUCCESS: u8 = 0;
    /// General error exit code (reserved for daemon connection errors).
    #[allow(dead_code)] // Reserved for future daemon integration
    pub const ERROR: u8 = 1;
    /// Cluster unhealthy exit code.
    pub const UNHEALTHY: u8 = 2;
}

/// Resource limits for consensus data.
pub mod limits {
    /// Maximum number of Byzantine evidence entries to return in a single
    /// query. Prevents unbounded memory usage from large evidence
    /// collections.
    pub const MAX_BYZANTINE_EVIDENCE_ENTRIES: usize = 1000;

    /// Maximum length of Byzantine evidence details string in bytes.
    /// Prevents unbounded memory usage from large evidence payloads.
    pub const MAX_BYZANTINE_EVIDENCE_DETAILS_LENGTH: usize = 4096;
}

/// Consensus command group.
#[derive(Debug, Args)]
pub struct ConsensusCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
    pub json: bool,

    #[command(subcommand)]
    pub subcommand: ConsensusSubcommand,
}

/// Consensus subcommands.
#[derive(Debug, Subcommand)]
pub enum ConsensusSubcommand {
    /// Show cluster health and leader info.
    ///
    /// Displays current epoch, round, leader, validator count, and health
    /// status.
    Status(StatusArgs),

    /// List validators in the consensus cluster.
    ///
    /// Shows validator IDs, public keys, and active status.
    Validators(ValidatorsArgs),

    /// Byzantine fault evidence commands.
    #[command(subcommand)]
    ByzantineEvidence(ByzantineEvidenceCommand),

    /// Show consensus metrics summary.
    ///
    /// Displays key metrics from the consensus layer for quick diagnostics.
    Metrics(MetricsArgs),
}

/// Arguments for `apm2 consensus status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Show detailed information including QC details.
    #[arg(long)]
    pub verbose: bool,
}

/// Arguments for `apm2 consensus validators`.
#[derive(Debug, Args)]
pub struct ValidatorsArgs {
    /// Show only active validators.
    #[arg(long)]
    pub active_only: bool,
}

/// Arguments for `apm2 consensus metrics`.
#[derive(Debug, Args)]
pub struct MetricsArgs {
    /// Time period for rate calculations (seconds).
    #[arg(long, default_value = "60")]
    pub period: u64,
}

/// Byzantine evidence subcommands.
#[derive(Debug, Subcommand)]
pub enum ByzantineEvidenceCommand {
    /// List detected Byzantine fault evidence.
    ///
    /// Shows equivocation, invalid signatures, and other detected faults.
    List(ByzantineListArgs),
}

/// Arguments for `apm2 consensus byzantine-evidence list`.
#[derive(Debug, Args)]
pub struct ByzantineListArgs {
    /// Filter by fault type: `equivocation`, `invalid_signature`,
    /// `quorum_forgery`, or `replay`.
    #[arg(long)]
    pub fault_type: Option<String>,

    /// Maximum number of entries to return (max 1000).
    #[arg(long, default_value = "100")]
    pub limit: u32,
}

impl ByzantineListArgs {
    /// Returns the effective limit, capped at the maximum allowed entries.
    #[must_use]
    pub fn effective_limit(&self) -> usize {
        (self.limit as usize).min(limits::MAX_BYZANTINE_EVIDENCE_ENTRIES)
    }
}

// ============================================================================
// Response Types for JSON output
// ============================================================================

/// Response for consensus status command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    /// Node ID reporting this status.
    pub node_id: String,
    /// Current consensus epoch.
    pub epoch: u64,
    /// Current consensus round.
    pub round: u64,
    /// Current leader validator ID (hex).
    pub leader_id: String,
    /// Whether this node is the current leader.
    pub is_leader: bool,
    /// Total validators in cluster.
    pub validator_count: usize,
    /// Active validators.
    pub active_validators: usize,
    /// Quorum threshold (2f+1).
    pub quorum_threshold: usize,
    /// Whether quorum is currently met.
    pub quorum_met: bool,
    /// Cluster health status.
    pub health: String,
    /// Highest QC round (if verbose).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_qc_round: Option<u64>,
    /// Locked QC round (if verbose).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_qc_round: Option<u64>,
    /// Committed blocks count (if verbose).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_blocks: Option<usize>,
    /// Last committed hash (if verbose).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_committed_hash: Option<String>,
}

/// Validator info for validators command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorInfo {
    /// Validator ID (hex).
    pub id: String,
    /// Validator index in the set.
    pub index: usize,
    /// Public key (hex).
    pub public_key: String,
    /// Whether validator is active (reachable).
    pub active: bool,
    /// Last seen timestamp (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

/// Response for validators command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorsResponse {
    /// List of validators.
    pub validators: Vec<ValidatorInfo>,
    /// Total count.
    pub total: usize,
    /// Active count.
    pub active: usize,
}

/// Byzantine evidence entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByzantineEvidence {
    /// Evidence ID.
    pub id: String,
    /// Fault type.
    pub fault_type: String,
    /// Validator ID that generated the fault.
    pub validator_id: String,
    /// Evidence details.
    pub details: String,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// Epoch when detected.
    pub epoch: u64,
    /// Round when detected.
    pub round: u64,
}

/// Response for byzantine-evidence list command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByzantineEvidenceResponse {
    /// List of evidence entries.
    pub evidence: Vec<ByzantineEvidence>,
    /// Total count.
    pub total: usize,
}

/// Metrics summary for quick diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsResponse {
    /// Node ID.
    pub node_id: String,
    /// Proposals committed (total).
    pub proposals_committed: u64,
    /// Proposals rejected (total).
    pub proposals_rejected: u64,
    /// Proposals timed out (total).
    pub proposals_timeout: u64,
    /// Leader elections (total).
    pub leader_elections: u64,
    /// Anti-entropy sync events (total).
    pub sync_events: u64,
    /// Anti-entropy conflicts (total).
    pub conflicts: u64,
    /// Byzantine evidence count (total).
    pub byzantine_evidence: u64,
    /// Finalization latency p50 (ms).
    pub latency_p50_ms: f64,
    /// Finalization latency p99 (ms).
    pub latency_p99_ms: f64,
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

/// Runs the consensus command, returning an appropriate exit code.
///
/// # Exit Codes
///
/// - 0: Success
/// - 1: General error
/// - 2: Cluster unhealthy
#[allow(clippy::too_many_lines)]
pub fn run_consensus(cmd: &ConsensusCommand, _socket_path: &std::path::Path) -> u8 {
    let json_output = cmd.json;

    match &cmd.subcommand {
        ConsensusSubcommand::Status(args) => run_status(args, json_output),
        ConsensusSubcommand::Validators(args) => run_validators(args, json_output),
        ConsensusSubcommand::ByzantineEvidence(subcmd) => match subcmd {
            ByzantineEvidenceCommand::List(args) => run_byzantine_list(args, json_output),
        },
        ConsensusSubcommand::Metrics(args) => run_metrics(args, json_output),
    }
}

/// Execute the status command.
///
/// Currently returns mock data since daemon integration is pending.
/// In production, this would query the daemon via UDS.
fn run_status(args: &StatusArgs, json_output: bool) -> u8 {
    // TODO: Query daemon for actual status via UDS
    // For now, return mock data to demonstrate the interface
    // NOTE: Using "unknown" health and quorum_met=false to indicate mock data

    let response = StatusResponse {
        node_id: "mock-node-001".to_string(),
        epoch: 0,
        round: 0,
        leader_id: "unknown".to_string(),
        is_leader: false,
        validator_count: 0,
        active_validators: 0,
        quorum_threshold: 0,
        quorum_met: false,
        health: "unknown".to_string(),
        high_qc_round: if args.verbose { Some(0) } else { None },
        locked_qc_round: None,
        committed_blocks: if args.verbose { Some(0) } else { None },
        last_committed_hash: None,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Consensus Cluster Status");
        println!("========================");
        println!();
        println!("WARNING: Daemon not connected. Displaying mock data.");
        println!();
        println!("Node ID:           {}", response.node_id);
        println!("Epoch:             {}", response.epoch);
        println!("Round:             {}", response.round);
        println!("Leader:            {}", response.leader_id);
        println!(
            "Is Leader:         {}",
            if response.is_leader { "yes" } else { "no" }
        );
        println!();
        println!("Validators:");
        println!("  Total:           {}", response.validator_count);
        println!("  Active:          {}", response.active_validators);
        println!(
            "  Quorum:          {}/{}",
            response.active_validators, response.quorum_threshold
        );
        println!(
            "  Quorum Met:      {}",
            if response.quorum_met { "yes" } else { "NO" }
        );
        println!();
        println!("Health:            {}", response.health.to_uppercase());

        if args.verbose {
            println!();
            println!("Details:");
            if let Some(hqr) = response.high_qc_round {
                println!("  High QC Round:   {hqr}");
            }
            if let Some(lqr) = response.locked_qc_round {
                println!("  Locked QC Round: {lqr}");
            }
            if let Some(cb) = response.committed_blocks {
                println!("  Committed Blocks: {cb}");
            }
            if let Some(ref lch) = response.last_committed_hash {
                println!("  Last Committed:  {lch}");
            }
        }
    }

    // Return unhealthy exit code since status is unknown (mock data)
    exit_codes::UNHEALTHY
}

/// Execute the validators command.
fn run_validators(args: &ValidatorsArgs, json_output: bool) -> u8 {
    // TODO: Query daemon for actual validator list
    // Return empty list to indicate no daemon connection (mock data)

    let all_validators: Vec<ValidatorInfo> = vec![];

    let validators: Vec<ValidatorInfo> = if args.active_only {
        all_validators.into_iter().filter(|v| v.active).collect()
    } else {
        all_validators
    };

    let active_count = validators.iter().filter(|v| v.active).count();
    let total = validators.len();

    let response = ValidatorsResponse {
        validators,
        total,
        active: active_count,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("WARNING: Daemon not connected. Displaying mock data.");
        println!();
        println!(
            "{:<6} {:<16} {:<8} {:<25}",
            "INDEX", "ID (TRUNCATED)", "ACTIVE", "LAST SEEN"
        );
        println!("{}", "-".repeat(60));
        for v in &response.validators {
            let truncated_id = if v.id.len() > 12 {
                format!("{}...", &v.id[..12])
            } else {
                v.id.clone()
            };
            println!(
                "{:<6} {:<16} {:<8} {:<25}",
                v.index,
                truncated_id,
                if v.active { "yes" } else { "no" },
                v.last_seen.as_deref().unwrap_or("-"),
            );
        }
        println!();
        println!(
            "Total: {} validators, {} active",
            response.total, response.active
        );
    }

    exit_codes::SUCCESS
}

/// Execute the byzantine-evidence list command.
fn run_byzantine_list(args: &ByzantineListArgs, json_output: bool) -> u8 {
    // TODO: Query daemon for actual evidence
    // Return empty list to indicate no daemon connection (mock data)

    let all_evidence: Vec<ByzantineEvidence> = vec![];

    // Use effective_limit to cap at MAX_BYZANTINE_EVIDENCE_ENTRIES
    let limit = args.effective_limit();

    // Filter by fault type if specified
    let evidence: Vec<ByzantineEvidence> = if let Some(ref ft) = args.fault_type {
        all_evidence
            .into_iter()
            .filter(|e| e.fault_type == *ft)
            .take(limit)
            .collect()
    } else {
        all_evidence.into_iter().take(limit).collect()
    };

    let total = evidence.len();

    let response = ByzantineEvidenceResponse { evidence, total };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else if response.evidence.is_empty() {
        println!("WARNING: Daemon not connected. Displaying mock data.");
        println!();
        println!("No Byzantine fault evidence detected.");
    } else {
        println!("WARNING: Daemon not connected. Displaying mock data.");
        println!();
        println!("Byzantine Fault Evidence");
        println!("========================");
        println!();
        for e in &response.evidence {
            println!("ID:         {}", e.id);
            println!("Type:       {}", e.fault_type);
            println!("Validator:  {}", e.validator_id);
            println!("Epoch/Round: {}/{}", e.epoch, e.round);
            println!("Timestamp:  {}", e.timestamp);
            println!("Details:    {}", e.details);
            println!();
        }
        println!("Total: {} evidence entries", response.total);
    }

    // Return unhealthy if any evidence exists (indicates active Byzantine behavior)
    if response.total > 0 {
        exit_codes::UNHEALTHY
    } else {
        exit_codes::SUCCESS
    }
}

/// Execute the metrics command.
fn run_metrics(_args: &MetricsArgs, json_output: bool) -> u8 {
    // TODO: Query daemon for actual metrics
    // Return zeroed metrics to indicate no daemon connection (mock data)

    let response = MetricsResponse {
        node_id: "mock-node-001".to_string(),
        proposals_committed: 0,
        proposals_rejected: 0,
        proposals_timeout: 0,
        leader_elections: 0,
        sync_events: 0,
        conflicts: 0,
        byzantine_evidence: 0,
        latency_p50_ms: 0.0,
        latency_p99_ms: 0.0,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Consensus Metrics Summary");
        println!("=========================");
        println!();
        println!("WARNING: Daemon not connected. Displaying mock data.");
        println!();
        println!("Node ID: {}", response.node_id);
        println!();
        println!("Proposals:");
        println!("  Committed:       {}", response.proposals_committed);
        println!("  Rejected:        {}", response.proposals_rejected);
        println!("  Timeout:         {}", response.proposals_timeout);
        println!();
        println!("Leader Elections:  {}", response.leader_elections);
        println!();
        println!("Anti-Entropy:");
        println!("  Sync Events:     {}", response.sync_events);
        println!("  Conflicts:       {}", response.conflicts);
        println!();
        println!("Byzantine Evidence: {}", response.byzantine_evidence);
        println!();
        println!("Latency:");
        println!("  p50:             {:.1}ms", response.latency_p50_ms);
        println!("  p99:             {:.1}ms", response.latency_p99_ms);
    }

    exit_codes::SUCCESS
}

// ============================================================================
// Helper functions
// ============================================================================

/// Output an error in the appropriate format.
#[allow(dead_code)]
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

/// Truncates Byzantine evidence details to the maximum allowed length.
///
/// This function should be used when receiving evidence from the daemon
/// to prevent unbounded memory usage from large payloads.
#[allow(dead_code)]
fn truncate_evidence_details(details: &str) -> String {
    if details.len() <= limits::MAX_BYZANTINE_EVIDENCE_DETAILS_LENGTH {
        details.to_string()
    } else {
        let mut truncated = details[..limits::MAX_BYZANTINE_EVIDENCE_DETAILS_LENGTH].to_string();
        truncated.push_str("... [TRUNCATED]");
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_response_serialization() {
        let response = StatusResponse {
            node_id: "test-node".to_string(),
            epoch: 1,
            round: 10,
            leader_id: "leader".to_string(),
            is_leader: false,
            validator_count: 4,
            active_validators: 4,
            quorum_threshold: 3,
            quorum_met: false,
            health: "unknown".to_string(),
            high_qc_round: None,
            locked_qc_round: None,
            committed_blocks: None,
            last_committed_hash: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: StatusResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.node_id, "test-node");
        assert_eq!(deserialized.epoch, 1);
        assert_eq!(deserialized.health, "unknown");
    }

    #[test]
    fn test_validator_info_serialization() {
        let info = ValidatorInfo {
            id: "abcd1234".to_string(),
            index: 0,
            public_key: "pubkey".to_string(),
            active: true,
            last_seen: Some("2026-01-29T12:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("abcd1234"));
    }

    #[test]
    fn test_byzantine_evidence_serialization() {
        let evidence = ByzantineEvidence {
            id: "evid-001".to_string(),
            fault_type: "equivocation".to_string(),
            validator_id: "val-001".to_string(),
            details: "test".to_string(),
            timestamp: "2026-01-29T12:00:00Z".to_string(),
            epoch: 1,
            round: 10,
        };

        let json = serde_json::to_string(&evidence).unwrap();
        assert!(json.contains("equivocation"));
    }

    #[test]
    fn test_metrics_response_serialization() {
        let response = MetricsResponse {
            node_id: "test-node".to_string(),
            proposals_committed: 100,
            proposals_rejected: 5,
            proposals_timeout: 1,
            leader_elections: 10,
            sync_events: 500,
            conflicts: 2,
            byzantine_evidence: 0,
            latency_p50_ms: 50.0,
            latency_p99_ms: 200.0,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: MetricsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.proposals_committed, 100);
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_status_response_rejects_unknown_fields() {
        let json = r#"{
            "node_id": "test",
            "epoch": 1,
            "round": 1,
            "leader_id": "leader",
            "is_leader": false,
            "validator_count": 4,
            "active_validators": 4,
            "quorum_threshold": 3,
            "quorum_met": true,
            "health": "healthy",
            "malicious": "value"
        }"#;

        let result: Result<StatusResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "StatusResponse should reject unknown fields"
        );
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ErrorResponse {
            code: "not_found".to_string(),
            message: "Resource not found".to_string(),
        };

        let json = serde_json::to_string_pretty(&error).unwrap();
        assert!(json.contains("not_found"));
    }

    // ========================================================================
    // Resource Limit Tests
    // ========================================================================

    #[test]
    fn test_byzantine_list_args_effective_limit() {
        let args = ByzantineListArgs {
            fault_type: None,
            limit: 100,
        };
        assert_eq!(args.effective_limit(), 100);
    }

    #[test]
    fn test_byzantine_list_args_effective_limit_capped() {
        let args = ByzantineListArgs {
            fault_type: None,
            limit: 5000, // Exceeds MAX_BYZANTINE_EVIDENCE_ENTRIES
        };
        assert_eq!(
            args.effective_limit(),
            limits::MAX_BYZANTINE_EVIDENCE_ENTRIES
        );
    }

    #[test]
    fn test_truncate_evidence_details_short() {
        let details = "Short details";
        let truncated = truncate_evidence_details(details);
        assert_eq!(truncated, details);
    }

    #[test]
    fn test_truncate_evidence_details_long() {
        let details = "a".repeat(limits::MAX_BYZANTINE_EVIDENCE_DETAILS_LENGTH + 100);
        let truncated = truncate_evidence_details(&details);
        assert!(truncated.len() < details.len());
        assert!(truncated.ends_with("... [TRUNCATED]"));
    }

    #[test]
    fn test_limits_constants() {
        // Verify the limits are reasonable values using const assertions
        const _: () = {
            assert!(limits::MAX_BYZANTINE_EVIDENCE_ENTRIES >= 100);
            assert!(limits::MAX_BYZANTINE_EVIDENCE_ENTRIES <= 10000);
            assert!(limits::MAX_BYZANTINE_EVIDENCE_DETAILS_LENGTH >= 1024);
            assert!(limits::MAX_BYZANTINE_EVIDENCE_DETAILS_LENGTH <= 1024 * 1024);
        };

        // Verify the values at runtime too
        assert_eq!(limits::MAX_BYZANTINE_EVIDENCE_ENTRIES, 1000);
        assert_eq!(limits::MAX_BYZANTINE_EVIDENCE_DETAILS_LENGTH, 4096);
    }
}
