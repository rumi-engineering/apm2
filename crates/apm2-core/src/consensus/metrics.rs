// AGENT-AUTHORED
//! Prometheus metrics for consensus health monitoring.
//!
//! This module provides metrics export for the APM2 distributed consensus
//! layer, enabling operational visibility into cluster health, BFT protocol
//! state, and anti-entropy synchronization.
//!
//! # Metrics Exported
//!
//! ## Consensus Metrics
//!
//! - `apm2_consensus_proposals_total` - Counter of consensus proposals by
//!   outcome
//! - `apm2_consensus_finalization_latency_seconds` - Histogram of finalization
//!   times
//! - `apm2_consensus_leader_elections_total` - Counter of leader election
//!   events
//! - `apm2_consensus_quorum_size` - Gauge showing required quorum threshold
//! - `apm2_consensus_validators_active` - Gauge of active validators
//! - `apm2_consensus_round_current` - Gauge of current consensus round
//! - `apm2_consensus_epoch_current` - Gauge of current consensus epoch
//!
//! ## Anti-Entropy Metrics
//!
//! - `apm2_antientropy_sync_events_total` - Counter of sync events by direction
//! - `apm2_antientropy_conflicts_total` - Counter of merge conflicts
//!
//! ## Schema Registry Metrics
//!
//! - `apm2_schema_registry_entries` - Gauge of registered schemas
//!
//! ## Byzantine Fault Metrics
//!
//! - `apm2_byzantine_evidence_total` - Counter of Byzantine fault evidence
//!
//! # Usage
//!
//! ```rust,ignore
//! use apm2_core::consensus::metrics::{ConsensusMetrics, ProposalOutcome};
//!
//! // Initialize metrics registry
//! let metrics = ConsensusMetrics::new("node-1");
//!
//! // Record proposal
//! metrics.record_proposal(ProposalOutcome::Committed);
//!
//! // Record finalization latency
//! metrics.record_finalization_latency(0.150); // 150ms
//!
//! // Update validator count
//! metrics.set_validators_active(4);
//!
//! // Export for Prometheus scraping
//! let output = metrics.render();
//! ```
//!
//! # Security Considerations
//!
//! - Metrics do not expose sensitive information (keys, signatures)
//! - Node IDs are included as labels for multi-node deployments
//! - Byzantine evidence counts are exposed to enable alerting
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00193: Operational Monitoring and Alerting
//! - `05_rollout_and_ops.yaml`: Observability section

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Resource Limits
// ============================================================================

/// Maximum length for node ID to prevent resource exhaustion.
pub const MAX_NODE_ID_LENGTH: usize = 128;

/// Maximum number of Byzantine evidence entries to store.
/// Prevents unbounded memory growth from malicious or buggy nodes.
pub const MAX_BYZANTINE_EVIDENCE: usize = 1000;

/// Maximum size of Prometheus render output buffer in bytes.
/// Prevents unbounded memory allocation during metrics export.
pub const MAX_RENDER_OUTPUT_SIZE: usize = 1024 * 1024; // 1MB

// ============================================================================
// Metrics Error
// ============================================================================

/// Error type for metrics operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsError {
    /// Node ID contains invalid characters (must be alphanumeric, hyphen, or
    /// underscore).
    InvalidNodeId(String),
    /// Node ID exceeds maximum length.
    NodeIdTooLong(usize),
}

impl std::fmt::Display for MetricsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNodeId(id) => {
                write!(
                    f,
                    "Invalid node_id: '{id}' (must contain only alphanumeric, hyphen, or underscore)",
                )
            },
            Self::NodeIdTooLong(len) => {
                write!(
                    f,
                    "Node ID too long: {len} bytes (max {MAX_NODE_ID_LENGTH})",
                )
            },
        }
    }
}

impl std::error::Error for MetricsError {}

/// Validates a node ID for use in Prometheus labels.
///
/// Node IDs must only contain alphanumeric characters, hyphens, or underscores
/// to prevent label injection attacks.
fn validate_node_id(node_id: &str) -> Result<(), MetricsError> {
    if node_id.len() > MAX_NODE_ID_LENGTH {
        return Err(MetricsError::NodeIdTooLong(node_id.len()));
    }
    if node_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        Ok(())
    } else {
        Err(MetricsError::InvalidNodeId(node_id.to_string()))
    }
}

// ============================================================================
// Label Types
// ============================================================================

/// Outcome of a consensus proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// Proposal was committed to the ledger.
    Committed,
    /// Proposal was rejected (invalid, stale, etc.).
    Rejected,
    /// Proposal timed out before quorum.
    Timeout,
}

impl ProposalOutcome {
    /// Returns the label value for this outcome.
    #[allow(dead_code)] // API for future use
    const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Rejected => "rejected",
            Self::Timeout => "timeout",
        }
    }
}

/// Reason for leader election.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderElectionReason {
    /// Scheduled rotation.
    Rotation,
    /// Leader timeout.
    Timeout,
    /// Leader crashed or unreachable.
    Crash,
    /// Initial bootstrap.
    Bootstrap,
}

impl LeaderElectionReason {
    /// Returns the label value for this reason.
    #[allow(dead_code)] // API for future use
    const fn as_str(self) -> &'static str {
        match self {
            Self::Rotation => "rotation",
            Self::Timeout => "timeout",
            Self::Crash => "crash",
            Self::Bootstrap => "bootstrap",
        }
    }
}

/// Direction of anti-entropy sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDirection {
    /// Events pulled from peer.
    Pull,
    /// Events pushed to peer.
    Push,
}

impl SyncDirection {
    /// Returns the label value for this direction.
    #[allow(dead_code)] // API for future use
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
        }
    }
}

/// Resolution of a merge conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Last-Writer-Wins resolved the conflict.
    Lww,
    /// Set union resolved the conflict.
    SetUnion,
    /// G-Counter merge resolved the conflict.
    GCounter,
    /// Manual adjudication required.
    Manual,
}

impl ConflictResolution {
    /// Returns the label value for this resolution.
    #[allow(dead_code)] // API for future use
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lww => "lww",
            Self::SetUnion => "set_union",
            Self::GCounter => "g_counter",
            Self::Manual => "manual",
        }
    }
}

/// Type of Byzantine fault detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByzantineFaultType {
    /// Validator signed conflicting messages (equivocation).
    Equivocation,
    /// Invalid signature detected.
    InvalidSignature,
    /// Quorum forgery attempt.
    QuorumForgery,
    /// Message replay detected.
    Replay,
}

impl ByzantineFaultType {
    /// Returns the label value for this fault type.
    #[allow(dead_code)] // API for future use
    const fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::InvalidSignature => "invalid_signature",
            Self::QuorumForgery => "quorum_forgery",
            Self::Replay => "replay",
        }
    }
}

// ============================================================================
// Histogram Buckets
// ============================================================================

/// Default latency buckets for finalization histogram (in seconds).
///
/// Covers range from 10ms to 10s with log-scale distribution.
/// Aligned with p99 < 500ms target from `05_rollout_and_ops.yaml`.
pub const DEFAULT_LATENCY_BUCKETS: &[f64] = &[
    0.010, // 10ms
    0.025, // 25ms
    0.050, // 50ms
    0.100, // 100ms
    0.250, // 250ms
    0.500, // 500ms (p99 target)
    1.000, // 1s
    2.500, // 2.5s
    5.000, // 5s
    10.00, // 10s
];

// ============================================================================
// Histogram
// ============================================================================

/// Simple histogram implementation for latency tracking.
///
/// Uses atomic counters for thread-safe operation without locks.
#[derive(Debug)]
pub struct Histogram {
    /// Bucket boundaries (upper bounds).
    buckets: &'static [f64],
    /// Count per bucket (cumulative).
    counts: Vec<AtomicU64>,
    /// Total sum of observed values.
    sum: AtomicU64,
    /// Total count of observations.
    count: AtomicU64,
}

impl Histogram {
    /// Creates a new histogram with the given buckets.
    #[must_use]
    pub fn new(buckets: &'static [f64]) -> Self {
        Self {
            buckets,
            counts: (0..=buckets.len()).map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Records an observation.
    pub fn observe(&self, value: f64) {
        // Find the bucket
        let bucket_idx = self
            .buckets
            .iter()
            .position(|&b| value <= b)
            .unwrap_or(self.buckets.len());

        // Increment bucket count
        self.counts[bucket_idx].fetch_add(1, Ordering::Relaxed);

        // Update sum atomically using CAS loop to avoid data race
        let mut current = self.sum.load(Ordering::Relaxed);
        loop {
            let current_f64 = f64::from_bits(current);
            let new_sum = (current_f64 + value).to_bits();
            match self.sum.compare_exchange_weak(
                current,
                new_sum,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current = x,
            }
        }

        // Increment total count
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the sum of all observations.
    #[must_use]
    pub fn sum(&self) -> f64 {
        f64::from_bits(self.sum.load(Ordering::Relaxed))
    }

    /// Returns the total count of observations.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Returns cumulative bucket counts.
    #[must_use]
    pub fn bucket_counts(&self) -> Vec<(f64, u64)> {
        let mut cumulative = 0u64;
        let mut result = Vec::with_capacity(self.buckets.len() + 1);

        for (i, &bound) in self.buckets.iter().enumerate() {
            cumulative += self.counts[i].load(Ordering::Relaxed);
            result.push((bound, cumulative));
        }

        // +Inf bucket
        cumulative += self.counts[self.buckets.len()].load(Ordering::Relaxed);
        result.push((f64::INFINITY, cumulative));

        result
    }
}

// ============================================================================
// ConsensusMetrics
// ============================================================================

/// Prometheus metrics collector for consensus health.
///
/// All metrics are prefixed with `apm2_` and include `node_id` as a label
/// for multi-node deployments.
///
/// # Thread Safety
///
/// All counters and gauges use atomic operations for lock-free updates.
#[derive(Debug)]
pub struct ConsensusMetrics {
    /// Node identifier for labels.
    node_id: String,

    // === Consensus Metrics ===
    /// Proposals by outcome (committed, rejected, timeout).
    proposals_committed: AtomicU64,
    proposals_rejected: AtomicU64,
    proposals_timeout: AtomicU64,

    /// Finalization latency histogram.
    finalization_latency: Histogram,

    /// Leader elections by reason.
    elections_rotation: AtomicU64,
    elections_timeout: AtomicU64,
    elections_crash: AtomicU64,
    elections_bootstrap: AtomicU64,

    /// Current quorum size requirement.
    quorum_size: AtomicU64,

    /// Number of active validators.
    validators_active: AtomicU64,

    /// Current consensus round.
    round_current: AtomicU64,

    /// Current consensus epoch.
    epoch_current: AtomicU64,

    // === Anti-Entropy Metrics ===
    /// Sync events by direction.
    sync_events_pull: AtomicU64,
    sync_events_push: AtomicU64,

    /// Conflicts by resolution type.
    conflicts_lww: AtomicU64,
    conflicts_set_union: AtomicU64,
    conflicts_g_counter: AtomicU64,
    conflicts_manual: AtomicU64,

    // === Schema Registry Metrics ===
    /// Number of registered schemas.
    schema_entries: AtomicU64,

    // === Byzantine Fault Metrics ===
    /// Byzantine evidence by fault type.
    byzantine_equivocation: AtomicU64,
    byzantine_invalid_signature: AtomicU64,
    byzantine_quorum_forgery: AtomicU64,
    byzantine_replay: AtomicU64,

    // === HEF Outbox Metrics (TCK-00304) ===
    /// Counter for HEF commit notifications dropped due to channel full.
    ///
    /// Per DOD: "Notification drops logged at WARN and increment
    /// `hef_notification_drops` metric."
    hef_notification_drops: AtomicU64,
}

impl ConsensusMetrics {
    /// Creates a new metrics collector for the given node.
    ///
    /// # Panics
    ///
    /// Panics if `node_id` contains invalid characters. Use [`try_new`] for
    /// fallible construction.
    ///
    /// [`try_new`]: Self::try_new
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self::try_new(node_id).expect("invalid node_id")
    }

    /// Creates a new metrics collector for the given node, returning an error
    /// if the `node_id` is invalid.
    ///
    /// Node IDs must only contain alphanumeric characters, hyphens, or
    /// underscores to prevent Prometheus label injection attacks.
    ///
    /// # Errors
    ///
    /// Returns `MetricsError::InvalidNodeId` if the `node_id` contains invalid
    /// characters. Returns `MetricsError::NodeIdTooLong` if the `node_id`
    /// exceeds the maximum length.
    pub fn try_new(node_id: impl Into<String>) -> Result<Self, MetricsError> {
        let node_id = node_id.into();
        validate_node_id(&node_id)?;
        Ok(Self {
            node_id,
            proposals_committed: AtomicU64::new(0),
            proposals_rejected: AtomicU64::new(0),
            proposals_timeout: AtomicU64::new(0),
            finalization_latency: Histogram::new(DEFAULT_LATENCY_BUCKETS),
            elections_rotation: AtomicU64::new(0),
            elections_timeout: AtomicU64::new(0),
            elections_crash: AtomicU64::new(0),
            elections_bootstrap: AtomicU64::new(0),
            quorum_size: AtomicU64::new(0),
            validators_active: AtomicU64::new(0),
            round_current: AtomicU64::new(0),
            epoch_current: AtomicU64::new(0),
            sync_events_pull: AtomicU64::new(0),
            sync_events_push: AtomicU64::new(0),
            conflicts_lww: AtomicU64::new(0),
            conflicts_set_union: AtomicU64::new(0),
            conflicts_g_counter: AtomicU64::new(0),
            conflicts_manual: AtomicU64::new(0),
            schema_entries: AtomicU64::new(0),
            byzantine_equivocation: AtomicU64::new(0),
            byzantine_invalid_signature: AtomicU64::new(0),
            byzantine_quorum_forgery: AtomicU64::new(0),
            byzantine_replay: AtomicU64::new(0),
            hef_notification_drops: AtomicU64::new(0),
        })
    }

    /// Returns the node ID.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    // ========================================================================
    // Consensus Metrics
    // ========================================================================

    /// Records a consensus proposal with the given outcome.
    pub fn record_proposal(&self, outcome: ProposalOutcome) {
        match outcome {
            ProposalOutcome::Committed => {
                self.proposals_committed.fetch_add(1, Ordering::Relaxed);
            },
            ProposalOutcome::Rejected => {
                self.proposals_rejected.fetch_add(1, Ordering::Relaxed);
            },
            ProposalOutcome::Timeout => {
                self.proposals_timeout.fetch_add(1, Ordering::Relaxed);
            },
        }
    }

    /// Records finalization latency in seconds.
    pub fn record_finalization_latency(&self, seconds: f64) {
        self.finalization_latency.observe(seconds);
    }

    /// Records a leader election event.
    pub fn record_leader_election(&self, reason: LeaderElectionReason) {
        match reason {
            LeaderElectionReason::Rotation => {
                self.elections_rotation.fetch_add(1, Ordering::Relaxed);
            },
            LeaderElectionReason::Timeout => {
                self.elections_timeout.fetch_add(1, Ordering::Relaxed);
            },
            LeaderElectionReason::Crash => {
                self.elections_crash.fetch_add(1, Ordering::Relaxed);
            },
            LeaderElectionReason::Bootstrap => {
                self.elections_bootstrap.fetch_add(1, Ordering::Relaxed);
            },
        }
    }

    /// Sets the current quorum size requirement.
    pub fn set_quorum_size(&self, size: u64) {
        self.quorum_size.store(size, Ordering::Relaxed);
    }

    /// Sets the number of active validators.
    pub fn set_validators_active(&self, count: u64) {
        self.validators_active.store(count, Ordering::Relaxed);
    }

    /// Sets the current consensus round.
    pub fn set_round_current(&self, round: u64) {
        self.round_current.store(round, Ordering::Relaxed);
    }

    /// Sets the current consensus epoch.
    pub fn set_epoch_current(&self, epoch: u64) {
        self.epoch_current.store(epoch, Ordering::Relaxed);
    }

    // ========================================================================
    // Anti-Entropy Metrics
    // ========================================================================

    /// Records an anti-entropy sync event.
    pub fn record_sync_event(&self, direction: SyncDirection) {
        match direction {
            SyncDirection::Pull => {
                self.sync_events_pull.fetch_add(1, Ordering::Relaxed);
            },
            SyncDirection::Push => {
                self.sync_events_push.fetch_add(1, Ordering::Relaxed);
            },
        }
    }

    /// Records a merge conflict and its resolution.
    pub fn record_conflict(&self, resolution: ConflictResolution) {
        match resolution {
            ConflictResolution::Lww => {
                self.conflicts_lww.fetch_add(1, Ordering::Relaxed);
            },
            ConflictResolution::SetUnion => {
                self.conflicts_set_union.fetch_add(1, Ordering::Relaxed);
            },
            ConflictResolution::GCounter => {
                self.conflicts_g_counter.fetch_add(1, Ordering::Relaxed);
            },
            ConflictResolution::Manual => {
                self.conflicts_manual.fetch_add(1, Ordering::Relaxed);
            },
        }
    }

    // ========================================================================
    // Schema Registry Metrics
    // ========================================================================

    /// Sets the number of registered schemas.
    pub fn set_schema_entries(&self, count: u64) {
        self.schema_entries.store(count, Ordering::Relaxed);
    }

    // ========================================================================
    // Byzantine Fault Metrics
    // ========================================================================

    /// Records Byzantine fault evidence.
    pub fn record_byzantine_evidence(&self, fault_type: ByzantineFaultType) {
        match fault_type {
            ByzantineFaultType::Equivocation => {
                self.byzantine_equivocation.fetch_add(1, Ordering::Relaxed);
            },
            ByzantineFaultType::InvalidSignature => {
                self.byzantine_invalid_signature
                    .fetch_add(1, Ordering::Relaxed);
            },
            ByzantineFaultType::QuorumForgery => {
                self.byzantine_quorum_forgery
                    .fetch_add(1, Ordering::Relaxed);
            },
            ByzantineFaultType::Replay => {
                self.byzantine_replay.fetch_add(1, Ordering::Relaxed);
            },
        }
    }

    // ========================================================================
    // HEF Outbox Metrics (TCK-00304)
    // ========================================================================

    /// Increments the HEF notification drops counter.
    ///
    /// Called when a commit notification cannot be sent because the channel
    /// is full. Per DOD: "Notification drops logged at WARN and increment
    /// `hef_notification_drops` metric."
    pub fn record_notification_drop(&self) {
        self.hef_notification_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the current count of HEF notification drops.
    #[must_use]
    pub fn notification_drops(&self) -> u64 {
        self.hef_notification_drops.load(Ordering::Relaxed)
    }

    // ========================================================================
    // Prometheus Export
    // ========================================================================

    /// Renders metrics in Prometheus text exposition format.
    #[must_use]
    #[allow(clippy::too_many_lines)] // Prometheus format requires many lines for completeness
    pub fn render(&self) -> String {
        let mut output = String::with_capacity(4096);

        // Helper to write gauge
        let write_gauge = |out: &mut String, name: &str, help: &str, labels: &str, value: u64| {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            let _ = writeln!(out, "{name}{{{labels}}} {value}");
        };

        let node_label = format!("node_id=\"{}\"", self.node_id);

        // === Consensus Proposals ===
        let _ = writeln!(
            output,
            "# HELP apm2_consensus_proposals_total Total consensus proposals made"
        );
        let _ = writeln!(output, "# TYPE apm2_consensus_proposals_total counter");
        let _ = writeln!(
            output,
            "apm2_consensus_proposals_total{{{node_label},outcome=\"committed\"}} {}",
            self.proposals_committed.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_consensus_proposals_total{{{node_label},outcome=\"rejected\"}} {}",
            self.proposals_rejected.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_consensus_proposals_total{{{node_label},outcome=\"timeout\"}} {}",
            self.proposals_timeout.load(Ordering::Relaxed)
        );

        // === Finalization Latency Histogram ===
        let _ = writeln!(
            output,
            "# HELP apm2_consensus_finalization_latency_seconds Time from proposal to finalization"
        );
        let _ = writeln!(
            output,
            "# TYPE apm2_consensus_finalization_latency_seconds histogram"
        );
        for (bound, count) in self.finalization_latency.bucket_counts() {
            if bound.is_infinite() {
                let _ = writeln!(
                    output,
                    "apm2_consensus_finalization_latency_seconds_bucket{{{node_label},le=\"+Inf\"}} {count}"
                );
            } else {
                let _ = writeln!(
                    output,
                    "apm2_consensus_finalization_latency_seconds_bucket{{{node_label},le=\"{bound}\"}} {count}"
                );
            }
        }
        let _ = writeln!(
            output,
            "apm2_consensus_finalization_latency_seconds_sum{{{node_label}}} {}",
            self.finalization_latency.sum()
        );
        let _ = writeln!(
            output,
            "apm2_consensus_finalization_latency_seconds_count{{{node_label}}} {}",
            self.finalization_latency.count()
        );

        // === Leader Elections ===
        let _ = writeln!(
            output,
            "# HELP apm2_consensus_leader_elections_total Leader election events"
        );
        let _ = writeln!(
            output,
            "# TYPE apm2_consensus_leader_elections_total counter"
        );
        let _ = writeln!(
            output,
            "apm2_consensus_leader_elections_total{{{node_label},reason=\"rotation\"}} {}",
            self.elections_rotation.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_consensus_leader_elections_total{{{node_label},reason=\"timeout\"}} {}",
            self.elections_timeout.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_consensus_leader_elections_total{{{node_label},reason=\"crash\"}} {}",
            self.elections_crash.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_consensus_leader_elections_total{{{node_label},reason=\"bootstrap\"}} {}",
            self.elections_bootstrap.load(Ordering::Relaxed)
        );

        // === Quorum Size ===
        write_gauge(
            &mut output,
            "apm2_consensus_quorum_size",
            "Current quorum requirement",
            &node_label,
            self.quorum_size.load(Ordering::Relaxed),
        );

        // === Validators Active ===
        write_gauge(
            &mut output,
            "apm2_consensus_validators_active",
            "Number of active validators",
            &node_label,
            self.validators_active.load(Ordering::Relaxed),
        );

        // === Current Round ===
        write_gauge(
            &mut output,
            "apm2_consensus_round_current",
            "Current consensus round",
            &node_label,
            self.round_current.load(Ordering::Relaxed),
        );

        // === Current Epoch ===
        write_gauge(
            &mut output,
            "apm2_consensus_epoch_current",
            "Current consensus epoch",
            &node_label,
            self.epoch_current.load(Ordering::Relaxed),
        );

        // === Anti-Entropy Sync Events ===
        let _ = writeln!(
            output,
            "# HELP apm2_antientropy_sync_events_total Events exchanged during anti-entropy sync"
        );
        let _ = writeln!(output, "# TYPE apm2_antientropy_sync_events_total counter");
        let _ = writeln!(
            output,
            "apm2_antientropy_sync_events_total{{{node_label},direction=\"pull\"}} {}",
            self.sync_events_pull.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_antientropy_sync_events_total{{{node_label},direction=\"push\"}} {}",
            self.sync_events_push.load(Ordering::Relaxed)
        );

        // === Anti-Entropy Conflicts ===
        let _ = writeln!(
            output,
            "# HELP apm2_antientropy_conflicts_total Merge conflicts detected"
        );
        let _ = writeln!(output, "# TYPE apm2_antientropy_conflicts_total counter");
        let _ = writeln!(
            output,
            "apm2_antientropy_conflicts_total{{{node_label},resolution=\"lww\"}} {}",
            self.conflicts_lww.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_antientropy_conflicts_total{{{node_label},resolution=\"set_union\"}} {}",
            self.conflicts_set_union.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_antientropy_conflicts_total{{{node_label},resolution=\"g_counter\"}} {}",
            self.conflicts_g_counter.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_antientropy_conflicts_total{{{node_label},resolution=\"manual\"}} {}",
            self.conflicts_manual.load(Ordering::Relaxed)
        );

        // === Schema Registry ===
        write_gauge(
            &mut output,
            "apm2_schema_registry_entries",
            "Number of registered schemas",
            &node_label,
            self.schema_entries.load(Ordering::Relaxed),
        );

        // === Byzantine Evidence ===
        let _ = writeln!(
            output,
            "# HELP apm2_byzantine_evidence_total Byzantine fault evidence generated"
        );
        let _ = writeln!(output, "# TYPE apm2_byzantine_evidence_total counter");
        let _ = writeln!(
            output,
            "apm2_byzantine_evidence_total{{{node_label},fault_type=\"equivocation\"}} {}",
            self.byzantine_equivocation.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_byzantine_evidence_total{{{node_label},fault_type=\"invalid_signature\"}} {}",
            self.byzantine_invalid_signature.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_byzantine_evidence_total{{{node_label},fault_type=\"quorum_forgery\"}} {}",
            self.byzantine_quorum_forgery.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "apm2_byzantine_evidence_total{{{node_label},fault_type=\"replay\"}} {}",
            self.byzantine_replay.load(Ordering::Relaxed)
        );

        // === HEF Outbox Metrics (TCK-00304) ===
        let _ = writeln!(
            output,
            "# HELP hef_notification_drops_total HEF commit notifications dropped due to channel full"
        );
        let _ = writeln!(output, "# TYPE hef_notification_drops_total counter");
        let _ = writeln!(
            output,
            "hef_notification_drops_total{{{node_label}}} {}",
            self.hef_notification_drops.load(Ordering::Relaxed)
        );

        // Truncate output if it exceeds the maximum size to prevent unbounded memory
        // usage
        if output.len() > MAX_RENDER_OUTPUT_SIZE {
            output.truncate(MAX_RENDER_OUTPUT_SIZE);
            // Ensure we end at a newline boundary for valid Prometheus format
            if let Some(last_newline) = output.rfind('\n') {
                output.truncate(last_newline + 1);
            }
            output.push_str("# TRUNCATED: Output exceeded maximum size\n");
        }

        output
    }
}

// ============================================================================
// Cluster Status
// ============================================================================

/// Consensus cluster status for CLI reporting.
#[derive(Debug, Clone)]
pub struct ClusterStatus {
    /// Node ID reporting this status.
    pub node_id: String,
    /// Current consensus epoch.
    pub epoch: u64,
    /// Current consensus round.
    pub round: u64,
    /// Current leader's validator ID (hex).
    pub leader_id: String,
    /// Whether this node is the current leader.
    pub is_leader: bool,
    /// Total number of validators in the cluster.
    pub validator_count: usize,
    /// Number of active (reachable) validators.
    pub active_validators: usize,
    /// Quorum threshold (2f+1).
    pub quorum_threshold: usize,
    /// Whether quorum is currently met.
    pub quorum_met: bool,
    /// Highest QC round.
    pub high_qc_round: u64,
    /// Locked QC round (if any).
    pub locked_qc_round: Option<u64>,
    /// Number of committed blocks.
    pub committed_blocks: usize,
    /// Last committed block hash (hex).
    pub last_committed_hash: Option<String>,
    /// Cluster health status.
    pub health: ClusterHealth,
}

/// Cluster health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterHealth {
    /// All validators active, quorum met.
    Healthy,
    /// Some validators unreachable but quorum met.
    Degraded,
    /// Quorum not met, consensus stalled.
    Critical,
    /// Unknown state (e.g., during bootstrap).
    Unknown,
}

impl ClusterHealth {
    /// Returns string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ClusterHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_metrics_creation() {
        let metrics = ConsensusMetrics::new("test-node");
        assert_eq!(metrics.node_id(), "test-node");
    }

    #[test]
    fn test_proposal_recording() {
        let metrics = ConsensusMetrics::new("test-node");

        metrics.record_proposal(ProposalOutcome::Committed);
        metrics.record_proposal(ProposalOutcome::Committed);
        metrics.record_proposal(ProposalOutcome::Rejected);

        let output = metrics.render();
        assert!(output.contains("outcome=\"committed\"} 2"));
        assert!(output.contains("outcome=\"rejected\"} 1"));
        assert!(output.contains("outcome=\"timeout\"} 0"));
    }

    #[test]
    fn test_finalization_latency_histogram() {
        let metrics = ConsensusMetrics::new("test-node");

        // Record some latencies
        metrics.record_finalization_latency(0.050); // 50ms
        metrics.record_finalization_latency(0.150); // 150ms
        metrics.record_finalization_latency(0.450); // 450ms

        let output = metrics.render();
        assert!(output.contains("apm2_consensus_finalization_latency_seconds_sum"));
        assert!(output.contains("apm2_consensus_finalization_latency_seconds_count"));
        assert!(output.contains("le=\"0.5\""));
    }

    #[test]
    fn test_leader_election_recording() {
        let metrics = ConsensusMetrics::new("test-node");

        metrics.record_leader_election(LeaderElectionReason::Bootstrap);
        metrics.record_leader_election(LeaderElectionReason::Timeout);
        metrics.record_leader_election(LeaderElectionReason::Timeout);

        let output = metrics.render();
        assert!(output.contains("reason=\"bootstrap\"} 1"));
        assert!(output.contains("reason=\"timeout\"} 2"));
    }

    #[test]
    fn test_gauge_metrics() {
        let metrics = ConsensusMetrics::new("test-node");

        metrics.set_quorum_size(3);
        metrics.set_validators_active(4);
        metrics.set_round_current(42);
        metrics.set_epoch_current(1);

        let output = metrics.render();
        assert!(output.contains("apm2_consensus_quorum_size"));
        assert!(output.contains("} 3"));
        assert!(output.contains("apm2_consensus_validators_active"));
        assert!(output.contains("} 4"));
        assert!(output.contains("apm2_consensus_round_current"));
        assert!(output.contains("} 42"));
    }

    #[test]
    fn test_sync_events() {
        let metrics = ConsensusMetrics::new("test-node");

        metrics.record_sync_event(SyncDirection::Pull);
        metrics.record_sync_event(SyncDirection::Pull);
        metrics.record_sync_event(SyncDirection::Push);

        let output = metrics.render();
        assert!(output.contains("direction=\"pull\"} 2"));
        assert!(output.contains("direction=\"push\"} 1"));
    }

    #[test]
    fn test_conflict_recording() {
        let metrics = ConsensusMetrics::new("test-node");

        metrics.record_conflict(ConflictResolution::Lww);
        metrics.record_conflict(ConflictResolution::SetUnion);

        let output = metrics.render();
        assert!(output.contains("resolution=\"lww\"} 1"));
        assert!(output.contains("resolution=\"set_union\"} 1"));
    }

    #[test]
    fn test_byzantine_evidence() {
        let metrics = ConsensusMetrics::new("test-node");

        metrics.record_byzantine_evidence(ByzantineFaultType::Equivocation);
        metrics.record_byzantine_evidence(ByzantineFaultType::InvalidSignature);

        let output = metrics.render();
        assert!(output.contains("fault_type=\"equivocation\"} 1"));
        assert!(output.contains("fault_type=\"invalid_signature\"} 1"));
    }

    #[test]
    fn test_schema_entries() {
        let metrics = ConsensusMetrics::new("test-node");

        metrics.set_schema_entries(42);

        let output = metrics.render();
        assert!(output.contains("apm2_schema_registry_entries"));
        assert!(output.contains("} 42"));
    }

    #[test]
    fn test_prometheus_format() {
        let metrics = ConsensusMetrics::new("test-node");

        let output = metrics.render();

        // Check Prometheus format requirements
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
        assert!(output.contains("counter"));
        assert!(output.contains("gauge"));
        assert!(output.contains("histogram"));
    }

    #[test]
    fn test_histogram_buckets() {
        let histogram = Histogram::new(DEFAULT_LATENCY_BUCKETS);

        histogram.observe(0.005); // Below first bucket
        histogram.observe(0.100); // In 0.1 bucket
        histogram.observe(0.600); // Above 0.5, below 1.0

        let buckets = histogram.bucket_counts();

        // Should have buckets.len() + 1 entries (including +Inf)
        assert_eq!(buckets.len(), DEFAULT_LATENCY_BUCKETS.len() + 1);

        // Total count should be 3
        assert_eq!(histogram.count(), 3);
    }

    #[test]
    fn test_cluster_health_display() {
        assert_eq!(ClusterHealth::Healthy.as_str(), "healthy");
        assert_eq!(ClusterHealth::Degraded.as_str(), "degraded");
        assert_eq!(ClusterHealth::Critical.as_str(), "critical");
        assert_eq!(ClusterHealth::Unknown.as_str(), "unknown");
    }

    /// TCK-00193: Verify all required metrics are exported.
    #[test]
    fn tck_00193_required_metrics_present() {
        let metrics = ConsensusMetrics::new("test-node");
        let output = metrics.render();

        // Required per 05_rollout_and_ops.yaml
        assert!(
            output.contains("apm2_consensus_proposals_total"),
            "Missing proposals counter"
        );
        assert!(
            output.contains("apm2_consensus_finalization_latency_seconds"),
            "Missing latency histogram"
        );
        assert!(
            output.contains("apm2_consensus_leader_elections_total"),
            "Missing elections counter"
        );
        assert!(
            output.contains("apm2_consensus_quorum_size"),
            "Missing quorum gauge"
        );
        assert!(
            output.contains("apm2_consensus_validators_active"),
            "Missing validators gauge"
        );
        assert!(
            output.contains("apm2_antientropy_sync_events_total"),
            "Missing sync counter"
        );
        assert!(
            output.contains("apm2_antientropy_conflicts_total"),
            "Missing conflicts counter"
        );
        assert!(
            output.contains("apm2_schema_registry_entries"),
            "Missing schema gauge"
        );
        assert!(
            output.contains("apm2_byzantine_evidence_total"),
            "Missing byzantine counter"
        );
    }

    /// TCK-00304: Verify HEF notification drops metric is exported.
    #[test]
    fn tck_00304_hef_notification_drops_metric() {
        let metrics = ConsensusMetrics::new("test-node");

        // Initially zero
        assert_eq!(metrics.notification_drops(), 0);

        // Increment the counter
        metrics.record_notification_drop();
        assert_eq!(metrics.notification_drops(), 1);

        metrics.record_notification_drop();
        metrics.record_notification_drop();
        assert_eq!(metrics.notification_drops(), 3);

        // Verify it appears in the rendered output
        let output = metrics.render();
        assert!(
            output.contains("hef_notification_drops_total"),
            "Missing hef_notification_drops counter"
        );
        assert!(
            output.contains("hef_notification_drops_total{node_id=\"test-node\"} 3"),
            "hef_notification_drops should be 3"
        );
    }

    // ========================================================================
    // Node ID Validation Tests (Security)
    // ========================================================================

    #[test]
    fn test_valid_node_id_alphanumeric() {
        assert!(ConsensusMetrics::try_new("node001").is_ok());
        assert!(ConsensusMetrics::try_new("Node001").is_ok());
        assert!(ConsensusMetrics::try_new("NODE001").is_ok());
    }

    #[test]
    fn test_valid_node_id_with_hyphen() {
        assert!(ConsensusMetrics::try_new("node-001").is_ok());
        assert!(ConsensusMetrics::try_new("my-node-001").is_ok());
    }

    #[test]
    fn test_valid_node_id_with_underscore() {
        assert!(ConsensusMetrics::try_new("node_001").is_ok());
        assert!(ConsensusMetrics::try_new("my_node_001").is_ok());
    }

    #[test]
    fn test_valid_node_id_mixed() {
        assert!(ConsensusMetrics::try_new("node-001_test").is_ok());
        assert!(ConsensusMetrics::try_new("My_Node-001").is_ok());
    }

    /// SECURITY TEST: Verify `node_id` with quotes is rejected (prevents label
    /// injection).
    #[test]
    fn test_invalid_node_id_with_quotes() {
        let result = ConsensusMetrics::try_new("node\"injection");
        assert!(result.is_err());
        assert!(matches!(result, Err(MetricsError::InvalidNodeId(_))));
    }

    /// SECURITY TEST: Verify `node_id` with newlines is rejected.
    #[test]
    fn test_invalid_node_id_with_newline() {
        let result = ConsensusMetrics::try_new("node\ninjection");
        assert!(result.is_err());
        assert!(matches!(result, Err(MetricsError::InvalidNodeId(_))));
    }

    /// SECURITY TEST: Verify `node_id` with backslash is rejected.
    #[test]
    fn test_invalid_node_id_with_backslash() {
        let result = ConsensusMetrics::try_new("node\\injection");
        assert!(result.is_err());
        assert!(matches!(result, Err(MetricsError::InvalidNodeId(_))));
    }

    /// SECURITY TEST: Verify `node_id` with spaces is rejected.
    #[test]
    fn test_invalid_node_id_with_space() {
        let result = ConsensusMetrics::try_new("node 001");
        assert!(result.is_err());
        assert!(matches!(result, Err(MetricsError::InvalidNodeId(_))));
    }

    /// SECURITY TEST: Verify `node_id` with special characters is rejected.
    #[test]
    fn test_invalid_node_id_with_special_chars() {
        assert!(ConsensusMetrics::try_new("node{001}").is_err());
        assert!(ConsensusMetrics::try_new("node=001").is_err());
        assert!(ConsensusMetrics::try_new("node,001").is_err());
        assert!(ConsensusMetrics::try_new("node;001").is_err());
    }

    /// SECURITY TEST: Verify `node_id` length limit is enforced.
    #[test]
    fn test_node_id_too_long() {
        let long_id = "a".repeat(MAX_NODE_ID_LENGTH + 1);
        let result = ConsensusMetrics::try_new(long_id);
        assert!(result.is_err());
        assert!(matches!(result, Err(MetricsError::NodeIdTooLong(_))));
    }

    /// Test that `node_id` at max length is accepted.
    #[test]
    fn test_node_id_at_max_length() {
        let max_id = "a".repeat(MAX_NODE_ID_LENGTH);
        assert!(ConsensusMetrics::try_new(max_id).is_ok());
    }

    #[test]
    fn test_metrics_error_display() {
        let err = MetricsError::InvalidNodeId("bad\"id".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Invalid node_id"));
        assert!(msg.contains("bad\"id"));

        let err = MetricsError::NodeIdTooLong(200);
        let msg = err.to_string();
        assert!(msg.contains("too long"));
        assert!(msg.contains("200"));
    }
}
