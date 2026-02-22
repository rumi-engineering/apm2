//! Shared types for orchestrator kernel runtimes.

/// Durable composite cursor `(timestamp_ns, event_id)`.
///
/// This cursor shape avoids skip-on-collision bugs when multiple events share
/// the same timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeCursor {
    /// Monotonic event timestamp in nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
    /// Deterministic event identifier tie-breaker.
    pub event_id: String,
}

/// Generic event envelope for kernel observation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope<Payload = Vec<u8>> {
    /// Stable event identifier.
    pub event_id: String,
    /// Event type discriminant.
    pub event_type: String,
    /// Work/session identifier.
    pub stream_id: String,
    /// Emitting actor.
    pub actor_id: String,
    /// Event timestamp in nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
    /// Opaque payload bytes.
    pub payload: Payload,
}

/// Domain execution outcome for a single intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome<Receipt> {
    /// Execution completed and produced durable receipt events.
    Completed {
        /// Receipts to persist in the Receipt phase.
        receipts: Vec<Receipt>,
    },
    /// Execution is fail-closed blocked and should not be retried
    /// automatically.
    Blocked {
        /// Human/actionable reason for blocked state.
        reason: String,
    },
    /// Execution hit a transient condition and can be retried later.
    ///
    /// Contracts:
    /// - The domain MUST return `Retry` only when no external side effect was
    ///   dispatched for this intent.
    Retry {
        /// Diagnostic reason for retry.
        reason: String,
    },
}

/// Per-tick bounded limits for observe/execute phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TickConfig {
    /// Maximum number of events observed in one tick.
    pub observe_limit: usize,
    /// Maximum number of intents executed in one tick.
    pub execute_limit: usize,
}

impl Default for TickConfig {
    fn default() -> Self {
        Self {
            observe_limit: 256,
            execute_limit: 64,
        }
    }
}

/// Deterministic kernel tick summary.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TickReport {
    /// Number of events observed from the ledger.
    pub observed_events: usize,
    /// Number of intents produced by the Plan phase.
    pub planned_intents: usize,
    /// Number of intents durably enqueued.
    pub enqueued_intents: usize,
    /// Number of intents dequeued for execution.
    pub dequeued_intents: usize,
    /// Number of intents that reached Execute.
    pub executed_intents: usize,
    /// Number of intents completed successfully.
    pub completed_intents: usize,
    /// Number of blocked intents.
    pub blocked_intents: usize,
    /// Number of retryable intents.
    pub retryable_intents: usize,
    /// Number of failed intents.
    pub failed_intents: usize,
    /// Number of completed intents skipped due to idempotent fence.
    pub skipped_completed_intents: usize,
    /// Number of receipts durably persisted.
    pub persisted_receipts: usize,
    /// Whether the durable cursor advanced this tick.
    pub cursor_advanced: bool,
}
