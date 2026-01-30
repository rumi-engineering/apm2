//! Coordination event types and payloads.
//!
//! This module defines the event types for the coordination layer:
//! - [`CoordinationEvent`]: Enum of all coordination event variants
//! - Event payload types for each variant
//!
//! Per AD-COORD-009: Events use JSON serialization via `serde_json`.
//! Events follow the existing pattern used by `SessionStarted`,
//! `WorkTransitioned`, and other event payloads.

use std::fmt;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, de};

use super::state::{
    AbortReason, BudgetUsage, CoordinationBudget, CoordinationError, MAX_WORK_QUEUE_SIZE,
    SessionOutcome, StopCondition,
};

/// Custom deserializer for `work_ids` that enforces [`MAX_WORK_QUEUE_SIZE`].
///
/// This uses a streaming visitor pattern that enforces limits DURING
/// deserialization, preventing OOM attacks by rejecting oversized arrays
/// before full allocation occurs.
fn deserialize_bounded_work_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedVecVisitor;

    impl<'de> Visitor<'de> for BoundedVecVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(
                formatter,
                "a sequence of at most {MAX_WORK_QUEUE_SIZE} strings"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Use size hint but cap at MAX_WORK_QUEUE_SIZE to prevent pre-allocation
            // attacks
            let capacity = seq.size_hint().unwrap_or(0).min(MAX_WORK_QUEUE_SIZE);
            let mut items = Vec::with_capacity(capacity);

            while let Some(item) = seq.next_element()? {
                if items.len() >= MAX_WORK_QUEUE_SIZE {
                    return Err(de::Error::custom(format!(
                        "work_ids exceeds maximum size: {} > {}",
                        items.len() + 1,
                        MAX_WORK_QUEUE_SIZE
                    )));
                }
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor)
}

/// Event type constant for coordination started.
pub const EVENT_TYPE_STARTED: &str = "coordination.started";

/// Event type constant for session bound.
pub const EVENT_TYPE_SESSION_BOUND: &str = "coordination.session_bound";

/// Event type constant for session unbound.
pub const EVENT_TYPE_SESSION_UNBOUND: &str = "coordination.session_unbound";

/// Event type constant for coordination completed.
pub const EVENT_TYPE_COMPLETED: &str = "coordination.completed";

/// Event type constant for coordination aborted.
pub const EVENT_TYPE_ABORTED: &str = "coordination.aborted";

/// Event type constant for context refinement request.
pub const EVENT_TYPE_CONTEXT_REFINEMENT: &str = "coordination.context_refinement_request";

/// Payload for `coordination.started` events.
///
/// Emitted when a coordination begins processing its work queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationStarted {
    /// Unique identifier for this coordination.
    pub coordination_id: String,

    /// Work item IDs in the queue.
    ///
    /// Limited to [`MAX_WORK_QUEUE_SIZE`] items. This limit is enforced both
    /// in [`CoordinationStarted::new`] and during deserialization.
    #[serde(deserialize_with = "deserialize_bounded_work_ids")]
    pub work_ids: Vec<String>,

    /// Budget constraints for this coordination.
    pub budget: CoordinationBudget,

    /// Maximum attempts per work item.
    pub max_attempts_per_work: u32,

    /// Timestamp when coordination started (nanoseconds since epoch).
    pub started_at: u64,
}

impl CoordinationStarted {
    /// Creates a new coordination started payload.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinationError::WorkQueueSizeExceeded`] if `work_ids`
    /// contains more than [`MAX_WORK_QUEUE_SIZE`] items.
    pub fn new(
        coordination_id: String,
        work_ids: Vec<String>,
        budget: CoordinationBudget,
        max_attempts_per_work: u32,
        started_at: u64,
    ) -> Result<Self, CoordinationError> {
        if work_ids.len() > MAX_WORK_QUEUE_SIZE {
            return Err(CoordinationError::WorkQueueSizeExceeded {
                actual: work_ids.len(),
                max: MAX_WORK_QUEUE_SIZE,
            });
        }
        Ok(Self {
            coordination_id,
            work_ids,
            budget,
            max_attempts_per_work,
            started_at,
        })
    }
}

/// Payload for `coordination.session_bound` events.
///
/// Per AD-COORD-003: This event MUST be emitted before `session.started`.
/// Per AD-COORD-006: The binding includes `expected_transition_count` for
/// optimistic concurrency control (CAS-at-commit).
/// Per AD-COORD-007: Session ID is generated before this event is emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationSessionBound {
    /// Coordination ID this session is bound to.
    pub coordination_id: String,

    /// Session ID that will process the work item.
    ///
    /// Per AD-COORD-007: Generated by controller before binding.
    pub session_id: String,

    /// Work item ID being processed.
    pub work_id: String,

    /// Attempt number for this work item (1-indexed).
    pub attempt_number: u32,

    /// Expected work item transition count for optimistic concurrency control.
    ///
    /// Per AD-COORD-006: This value is checked at ledger admission to ensure
    /// the work item's state hasn't changed since the binding was initiated.
    /// If `work.transition_count != expected_transition_count`, the binding
    /// is rejected (stale binding).
    pub expected_transition_count: u64,

    /// Ledger sequence ID at which work freshness was verified.
    ///
    /// Per AD-COORD-006: Work state was checked at this sequence.
    pub freshness_seq_id: u64,

    /// Timestamp when binding was created (nanoseconds since epoch).
    pub bound_at: u64,
}

impl CoordinationSessionBound {
    /// Creates a new session bound payload.
    ///
    /// This constructor uses a default `expected_transition_count` of 0.
    /// For explicit control over optimistic concurrency, use
    /// [`Self::with_transition_count`].
    #[must_use]
    pub const fn new(
        coordination_id: String,
        session_id: String,
        work_id: String,
        attempt_number: u32,
        freshness_seq_id: u64,
        bound_at: u64,
    ) -> Self {
        Self {
            coordination_id,
            session_id,
            work_id,
            attempt_number,
            expected_transition_count: 0,
            freshness_seq_id,
            bound_at,
        }
    }

    /// Creates a new session bound payload with explicit transition count.
    ///
    /// Per AD-COORD-006: The `expected_transition_count` is used for optimistic
    /// concurrency control (CAS-at-commit). If the work item's transition count
    /// has changed since binding was initiated, the binding is rejected.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn with_transition_count(
        coordination_id: String,
        session_id: String,
        work_id: String,
        attempt_number: u32,
        expected_transition_count: u64,
        freshness_seq_id: u64,
        bound_at: u64,
    ) -> Self {
        Self {
            coordination_id,
            session_id,
            work_id,
            attempt_number,
            expected_transition_count,
            freshness_seq_id,
            bound_at,
        }
    }
}

/// Payload for `coordination.session_unbound` events.
///
/// Per AD-COORD-003: This event MUST be emitted after `session.terminated`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationSessionUnbound {
    /// Coordination ID this session was bound to.
    pub coordination_id: String,

    /// Session ID that processed the work item.
    pub session_id: String,

    /// Work item ID that was processed.
    pub work_id: String,

    /// Outcome of the session.
    pub outcome: SessionOutcome,

    /// Tokens consumed by this session (from `final_entropy`).
    ///
    /// Per AD-COORD-011: Aggregated from `SessionTerminated` payload.
    pub tokens_consumed: u64,

    /// Timestamp when session was unbound (nanoseconds since epoch).
    pub unbound_at: u64,
}

impl CoordinationSessionUnbound {
    /// Creates a new session unbound payload.
    #[must_use]
    pub const fn new(
        coordination_id: String,
        session_id: String,
        work_id: String,
        outcome: SessionOutcome,
        tokens_consumed: u64,
        unbound_at: u64,
    ) -> Self {
        Self {
            coordination_id,
            session_id,
            work_id,
            outcome,
            tokens_consumed,
            unbound_at,
        }
    }
}

/// BLAKE3 hash size in bytes.
pub const BLAKE3_HASH_SIZE: usize = 32;

/// Payload for `coordination.completed` events.
///
/// Emitted when a coordination finishes processing (success or stop condition).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationCompleted {
    /// Coordination ID that completed.
    pub coordination_id: String,

    /// Stop condition that caused completion.
    pub stop_condition: StopCondition,

    /// Final budget usage.
    pub budget_usage: BudgetUsage,

    /// Total sessions spawned.
    pub total_sessions: u32,

    /// Number of successful sessions.
    pub successful_sessions: u32,

    /// Number of failed sessions.
    pub failed_sessions: u32,

    /// BLAKE3 hash of the coordination receipt (32 bytes).
    ///
    /// Per AD-COORD-012: Hash computed before event emission, stored in CAS.
    /// BLAKE3 produces a fixed 32-byte (256-bit) hash.
    #[serde(with = "serde_bytes_array")]
    pub receipt_hash: [u8; BLAKE3_HASH_SIZE],

    /// Timestamp when coordination completed (nanoseconds since epoch).
    pub completed_at: u64,
}

/// Serde helper for fixed-size byte arrays.
mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        vec.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected {} bytes, got {}", N, v.len()))
        })
    }
}

impl CoordinationCompleted {
    /// Creates a new coordination completed payload.
    ///
    /// The `receipt_hash` must be exactly 32 bytes (BLAKE3 hash size).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        coordination_id: String,
        stop_condition: StopCondition,
        budget_usage: BudgetUsage,
        total_sessions: u32,
        successful_sessions: u32,
        failed_sessions: u32,
        receipt_hash: [u8; BLAKE3_HASH_SIZE],
        completed_at: u64,
    ) -> Self {
        Self {
            coordination_id,
            stop_condition,
            budget_usage,
            total_sessions,
            successful_sessions,
            failed_sessions,
            receipt_hash,
            completed_at,
        }
    }
}

/// Payload for `coordination.aborted` events.
///
/// Emitted when a coordination is aborted before completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationAborted {
    /// Coordination ID that was aborted.
    pub coordination_id: String,

    /// Reason for abortion.
    pub reason: AbortReason,

    /// Budget usage at time of abort.
    pub budget_usage: BudgetUsage,

    /// Timestamp when coordination was aborted (nanoseconds since epoch).
    pub aborted_at: u64,
}

impl CoordinationAborted {
    /// Creates a new coordination aborted payload.
    #[must_use]
    pub const fn new(
        coordination_id: String,
        reason: AbortReason,
        budget_usage: BudgetUsage,
        aborted_at: u64,
    ) -> Self {
        Self {
            coordination_id,
            reason,
            budget_usage,
            aborted_at,
        }
    }
}

/// Payload for `coordination.context_refinement_request` events.
///
/// Emitted when a CONSUME mode session is terminated due to a `CONTEXT_MISS`.
/// This signals to the coordinator that the context pack needs to be refined
/// to include the missing file.
///
/// # RFC-0015: FAC Context Refinement Flow
///
/// When a CONSUME mode session attempts to read a file not in the manifest:
/// 1. Session is terminated with `CONTEXT_MISS` rationale
/// 2. Coordinator receives this `ContextRefinementRequest`
/// 3. Coordinator reissues the work with a refined context pack
///
/// The refinement loop continues until:
/// - The context pack includes all needed files, or
/// - A maximum refinement count is reached, or
/// - The coordinator determines the request is invalid
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRefinementRequest {
    /// Session ID that was terminated.
    pub session_id: String,

    /// Coordination ID (if bound to a coordination).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordination_id: Option<String>,

    /// Work item ID that was being processed.
    pub work_id: String,

    /// The manifest ID that was in use.
    pub manifest_id: String,

    /// The path that triggered the context miss.
    pub missed_path: String,

    /// The rationale code from the session termination.
    pub rationale_code: String,

    /// Number of refinement attempts so far for this work item.
    pub refinement_count: u32,

    /// Timestamp when the context miss occurred (nanoseconds since epoch).
    pub timestamp: u64,
}

impl ContextRefinementRequest {
    /// Creates a new context refinement request.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        session_id: String,
        coordination_id: Option<String>,
        work_id: String,
        manifest_id: String,
        missed_path: String,
        rationale_code: String,
        refinement_count: u32,
        timestamp: u64,
    ) -> Self {
        Self {
            session_id,
            coordination_id,
            work_id,
            manifest_id,
            missed_path,
            rationale_code,
            refinement_count,
            timestamp,
        }
    }

    /// Creates a context refinement request from a context miss result.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID that was terminated
    /// * `coordination_id` - The coordination ID (if applicable)
    /// * `work_id` - The work item ID
    /// * `manifest_id` - The manifest ID from the context miss
    /// * `missed_path` - The path that was not in the manifest
    /// * `refinement_count` - The number of refinement attempts so far
    /// * `timestamp` - The timestamp in nanoseconds since epoch
    #[must_use]
    pub fn from_context_miss(
        session_id: impl Into<String>,
        coordination_id: Option<String>,
        work_id: impl Into<String>,
        manifest_id: impl Into<String>,
        missed_path: impl Into<String>,
        refinement_count: u32,
        timestamp: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            coordination_id,
            work_id: work_id.into(),
            manifest_id: manifest_id.into(),
            missed_path: missed_path.into(),
            rationale_code: "CONTEXT_MISS".to_string(),
            refinement_count,
            timestamp,
        }
    }
}

/// Coordination event enum.
///
/// Contains all coordination event variants as a tagged union for
/// convenient pattern matching.
///
/// The `#[serde(rename = "...")]` attributes ensure that the JSON `type` tag
/// matches the `EVENT_TYPE_*` constants used by
/// [`CoordinationEvent::event_type`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[non_exhaustive]
pub enum CoordinationEvent {
    /// Coordination started processing work queue.
    #[serde(rename = "coordination.started")]
    Started(CoordinationStarted),

    /// Session bound to work item.
    #[serde(rename = "coordination.session_bound")]
    SessionBound(CoordinationSessionBound),

    /// Session unbound from work item.
    #[serde(rename = "coordination.session_unbound")]
    SessionUnbound(CoordinationSessionUnbound),

    /// Coordination completed.
    #[serde(rename = "coordination.completed")]
    Completed(CoordinationCompleted),

    /// Coordination aborted.
    #[serde(rename = "coordination.aborted")]
    Aborted(CoordinationAborted),

    /// Context refinement request (CONSUME mode context miss).
    #[serde(rename = "coordination.context_refinement_request")]
    ContextRefinementRequest(ContextRefinementRequest),
}

impl CoordinationEvent {
    /// Returns the event type string for this event.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::Started(_) => EVENT_TYPE_STARTED,
            Self::SessionBound(_) => EVENT_TYPE_SESSION_BOUND,
            Self::SessionUnbound(_) => EVENT_TYPE_SESSION_UNBOUND,
            Self::Completed(_) => EVENT_TYPE_COMPLETED,
            Self::Aborted(_) => EVENT_TYPE_ABORTED,
            Self::ContextRefinementRequest(_) => EVENT_TYPE_CONTEXT_REFINEMENT,
        }
    }

    /// Returns the coordination ID for this event.
    ///
    /// Note: For `ContextRefinementRequest`, returns an empty string if no
    /// coordination ID was set (the session may not be bound to a
    /// coordination).
    #[must_use]
    pub fn coordination_id(&self) -> &str {
        match self {
            Self::Started(e) => &e.coordination_id,
            Self::SessionBound(e) => &e.coordination_id,
            Self::SessionUnbound(e) => &e.coordination_id,
            Self::Completed(e) => &e.coordination_id,
            Self::Aborted(e) => &e.coordination_id,
            Self::ContextRefinementRequest(e) => e.coordination_id.as_deref().unwrap_or(""),
        }
    }

    /// Serializes the event payload to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes an event from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::state::BudgetType;

    // ========================================================================
    // CoordinationStarted Tests
    // ========================================================================

    #[test]
    fn test_coordination_started_new() {
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap();
        let event = CoordinationStarted::new(
            "coord-123".to_string(),
            vec!["work-1".to_string(), "work-2".to_string()],
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        assert_eq!(event.coordination_id, "coord-123");
        assert_eq!(event.work_ids.len(), 2);
        assert_eq!(event.max_attempts_per_work, 3);
        assert_eq!(event.started_at, 1_000_000_000);
    }

    #[test]
    fn test_coordination_started_serde_roundtrip() {
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap();
        let event = CoordinationStarted::new(
            "coord-123".to_string(),
            vec!["work-1".to_string()],
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        let json = serde_json::to_string(&event).unwrap();
        let restored: CoordinationStarted = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    // ========================================================================
    // CoordinationSessionBound Tests
    // ========================================================================

    #[test]
    fn test_coordination_session_bound_new() {
        let event = CoordinationSessionBound::new(
            "coord-123".to_string(),
            "session-456".to_string(),
            "work-789".to_string(),
            1,
            100,
            2_000_000_000,
        );

        assert_eq!(event.coordination_id, "coord-123");
        assert_eq!(event.session_id, "session-456");
        assert_eq!(event.work_id, "work-789");
        assert_eq!(event.attempt_number, 1);
        assert_eq!(event.expected_transition_count, 0); // default
        assert_eq!(event.freshness_seq_id, 100);
        assert_eq!(event.bound_at, 2_000_000_000);
    }

    #[test]
    fn test_coordination_session_bound_with_transition_count() {
        let event = CoordinationSessionBound::with_transition_count(
            "coord-123".to_string(),
            "session-456".to_string(),
            "work-789".to_string(),
            1,
            42, // expected_transition_count
            100,
            2_000_000_000,
        );

        assert_eq!(event.expected_transition_count, 42);
    }

    #[test]
    fn test_coordination_session_bound_serde_roundtrip() {
        let event = CoordinationSessionBound::new(
            "coord-123".to_string(),
            "session-456".to_string(),
            "work-789".to_string(),
            2,
            150,
            2_000_000_000,
        );

        let json = serde_json::to_string(&event).unwrap();
        let restored: CoordinationSessionBound = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    // ========================================================================
    // CoordinationSessionUnbound Tests
    // ========================================================================

    #[test]
    fn test_coordination_session_unbound_new() {
        let event = CoordinationSessionUnbound::new(
            "coord-123".to_string(),
            "session-456".to_string(),
            "work-789".to_string(),
            SessionOutcome::Success,
            5000,
            3_000_000_000,
        );

        assert_eq!(event.coordination_id, "coord-123");
        assert_eq!(event.session_id, "session-456");
        assert_eq!(event.work_id, "work-789");
        assert_eq!(event.outcome, SessionOutcome::Success);
        assert_eq!(event.tokens_consumed, 5000);
        assert_eq!(event.unbound_at, 3_000_000_000);
    }

    #[test]
    fn test_coordination_session_unbound_serde_roundtrip() {
        let event = CoordinationSessionUnbound::new(
            "coord-123".to_string(),
            "session-456".to_string(),
            "work-789".to_string(),
            SessionOutcome::Failure,
            1000,
            3_000_000_000,
        );

        let json = serde_json::to_string(&event).unwrap();
        let restored: CoordinationSessionUnbound = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    // ========================================================================
    // CoordinationCompleted Tests
    // ========================================================================

    /// Helper to create a test BLAKE3 hash (32 bytes).
    fn test_hash() -> [u8; BLAKE3_HASH_SIZE] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    #[test]
    fn test_coordination_completed_new() {
        let budget_usage = BudgetUsage {
            consumed_episodes: 5,
            elapsed_ms: 30_000,
            consumed_tokens: 50_000,
        };
        let receipt_hash = test_hash();
        let event = CoordinationCompleted::new(
            "coord-123".to_string(),
            StopCondition::WorkCompleted,
            budget_usage,
            5,
            4,
            1,
            receipt_hash,
            4_000_000_000,
        );

        assert_eq!(event.coordination_id, "coord-123");
        assert_eq!(event.stop_condition, StopCondition::WorkCompleted);
        assert_eq!(event.total_sessions, 5);
        assert_eq!(event.successful_sessions, 4);
        assert_eq!(event.failed_sessions, 1);
        assert_eq!(event.receipt_hash, receipt_hash);
        assert_eq!(event.completed_at, 4_000_000_000);
    }

    #[test]
    fn test_coordination_completed_serde_roundtrip() {
        let budget_usage = BudgetUsage {
            consumed_episodes: 5,
            elapsed_ms: 30_000,
            consumed_tokens: 50_000,
        };
        let event = CoordinationCompleted::new(
            "coord-123".to_string(),
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3,
            },
            budget_usage,
            3,
            0,
            3,
            test_hash(),
            4_000_000_000,
        );

        let json = serde_json::to_string(&event).unwrap();
        let restored: CoordinationCompleted = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    /// TCK-00148: Test that invalid hash length is rejected during
    /// deserialization.
    #[test]
    fn test_completed_event_invalid_hash() {
        // This test documents that the type system prevents invalid hash lengths
        // at compile time. The receipt_hash field is now [u8; 32], not Vec<u8>.
        //
        // Deserialization will fail if the JSON contains a different number of bytes.
        let json_with_short_hash = r#"{
            "coordination_id": "coord-123",
            "stop_condition": "WorkCompleted",
            "budget_usage": {"consumed_episodes": 0, "elapsed_ms": 0, "consumed_tokens": 0},
            "total_sessions": 1,
            "successful_sessions": 1,
            "failed_sessions": 0,
            "receipt_hash": [1, 2, 3, 4],
            "completed_at": 1000
        }"#;

        let result: Result<CoordinationCompleted, _> = serde_json::from_str(json_with_short_hash);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expected 32 bytes"),
            "Expected error about 32 bytes, got: {err}"
        );
    }

    // ========================================================================
    // CoordinationAborted Tests
    // ========================================================================

    #[test]
    fn test_coordination_aborted_new() {
        let budget_usage = BudgetUsage::new();
        let event = CoordinationAborted::new(
            "coord-123".to_string(),
            AbortReason::NoEligibleWork,
            budget_usage,
            1_000_000_000,
        );

        assert_eq!(event.coordination_id, "coord-123");
        assert_eq!(event.reason, AbortReason::NoEligibleWork);
        assert_eq!(event.aborted_at, 1_000_000_000);
    }

    #[test]
    fn test_coordination_aborted_serde_roundtrip() {
        let budget_usage = BudgetUsage {
            consumed_episodes: 2,
            elapsed_ms: 10_000,
            consumed_tokens: 5000,
        };
        let event = CoordinationAborted::new(
            "coord-123".to_string(),
            AbortReason::Cancelled {
                reason: "user requested".to_string(),
            },
            budget_usage,
            2_000_000_000,
        );

        let json = serde_json::to_string(&event).unwrap();
        let restored: CoordinationAborted = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    // ========================================================================
    // CoordinationEvent Tests
    // ========================================================================

    #[test]
    fn test_coordination_event_type() {
        let started = CoordinationEvent::Started(
            CoordinationStarted::new(
                "c".to_string(),
                vec![],
                CoordinationBudget::new(10, 60_000, None).unwrap(),
                3,
                1000,
            )
            .unwrap(),
        );
        assert_eq!(started.event_type(), EVENT_TYPE_STARTED);

        let bound = CoordinationEvent::SessionBound(CoordinationSessionBound::new(
            "c".to_string(),
            "s".to_string(),
            "w".to_string(),
            1,
            1,
            1000,
        ));
        assert_eq!(bound.event_type(), EVENT_TYPE_SESSION_BOUND);

        let unbound = CoordinationEvent::SessionUnbound(CoordinationSessionUnbound::new(
            "c".to_string(),
            "s".to_string(),
            "w".to_string(),
            SessionOutcome::Success,
            100,
            2000,
        ));
        assert_eq!(unbound.event_type(), EVENT_TYPE_SESSION_UNBOUND);

        let completed = CoordinationEvent::Completed(CoordinationCompleted::new(
            "c".to_string(),
            StopCondition::WorkCompleted,
            BudgetUsage::new(),
            1,
            1,
            0,
            [0u8; BLAKE3_HASH_SIZE],
            3000,
        ));
        assert_eq!(completed.event_type(), EVENT_TYPE_COMPLETED);

        let aborted = CoordinationEvent::Aborted(CoordinationAborted::new(
            "c".to_string(),
            AbortReason::NoEligibleWork,
            BudgetUsage::new(),
            4000,
        ));
        assert_eq!(aborted.event_type(), EVENT_TYPE_ABORTED);
    }

    #[test]
    fn test_coordination_event_coordination_id() {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
        let event = CoordinationEvent::Started(
            CoordinationStarted::new("coord-test".to_string(), vec![], budget, 3, 1000).unwrap(),
        );
        assert_eq!(event.coordination_id(), "coord-test");
    }

    #[test]
    fn test_coordination_event_json_roundtrip() {
        let events = vec![
            CoordinationEvent::Started(
                CoordinationStarted::new(
                    "c".to_string(),
                    vec!["w1".to_string(), "w2".to_string()],
                    CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap(),
                    3,
                    1000,
                )
                .unwrap(),
            ),
            CoordinationEvent::SessionBound(CoordinationSessionBound::new(
                "c".to_string(),
                "s".to_string(),
                "w1".to_string(),
                1,
                10,
                2000,
            )),
            CoordinationEvent::SessionUnbound(CoordinationSessionUnbound::new(
                "c".to_string(),
                "s".to_string(),
                "w1".to_string(),
                SessionOutcome::Success,
                500,
                3000,
            )),
            CoordinationEvent::Completed(CoordinationCompleted::new(
                "c".to_string(),
                StopCondition::WorkCompleted,
                BudgetUsage {
                    consumed_episodes: 2,
                    elapsed_ms: 5000,
                    consumed_tokens: 1000,
                },
                2,
                2,
                0,
                test_hash(),
                4000,
            )),
            CoordinationEvent::Aborted(CoordinationAborted::new(
                "c".to_string(),
                AbortReason::Error {
                    message: "test error".to_string(),
                },
                BudgetUsage::new(),
                5000,
            )),
        ];

        for event in events {
            let bytes = event.to_json_bytes().unwrap();
            let restored = CoordinationEvent::from_json_bytes(&bytes).unwrap();
            assert_eq!(event, restored);
        }
    }

    // ========================================================================
    // TCK-00148 Specific Tests (Serde Round-Trip)
    // ========================================================================

    /// TCK-00148: Verify all event types serialize and deserialize correctly.
    #[test]
    fn tck_00148_events_serde_roundtrip() {
        // CoordinationStarted
        let started = CoordinationStarted::new(
            "coord-1".to_string(),
            vec!["work-1".to_string()],
            CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap(),
            3,
            1000,
        )
        .unwrap();
        let json = serde_json::to_string(&started).unwrap();
        assert_eq!(started, serde_json::from_str(&json).unwrap());

        // CoordinationSessionBound (uses with_transition_count for explicit test)
        let bound = CoordinationSessionBound::with_transition_count(
            "coord-1".to_string(),
            "sess-1".to_string(),
            "work-1".to_string(),
            1,
            42, // expected_transition_count
            50,
            2000,
        );
        let json = serde_json::to_string(&bound).unwrap();
        assert_eq!(bound, serde_json::from_str(&json).unwrap());

        // CoordinationSessionUnbound (both outcomes)
        for outcome in [SessionOutcome::Success, SessionOutcome::Failure] {
            let unbound = CoordinationSessionUnbound::new(
                "coord-1".to_string(),
                "sess-1".to_string(),
                "work-1".to_string(),
                outcome,
                500,
                3000,
            );
            let json = serde_json::to_string(&unbound).unwrap();
            assert_eq!(unbound, serde_json::from_str(&json).unwrap());
        }

        // CoordinationCompleted (various stop conditions)
        for stop in [
            StopCondition::WorkCompleted,
            StopCondition::BudgetExhausted(BudgetType::Duration),
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3,
            },
        ] {
            let completed = CoordinationCompleted::new(
                "coord-1".to_string(),
                stop,
                BudgetUsage {
                    consumed_episodes: 5,
                    elapsed_ms: 30_000,
                    consumed_tokens: 50_000,
                },
                5,
                4,
                1,
                test_hash(),
                4000,
            );
            let json = serde_json::to_string(&completed).unwrap();
            assert_eq!(completed, serde_json::from_str(&json).unwrap());
        }

        // CoordinationAborted (various reasons)
        for reason in [
            AbortReason::NoEligibleWork,
            AbortReason::Cancelled {
                reason: "test".to_string(),
            },
            AbortReason::Error {
                message: "err".to_string(),
            },
        ] {
            let aborted =
                CoordinationAborted::new("coord-1".to_string(), reason, BudgetUsage::new(), 5000);
            let json = serde_json::to_string(&aborted).unwrap();
            assert_eq!(aborted, serde_json::from_str(&json).unwrap());
        }

        // CoordinationEvent (tagged union)
        let event = CoordinationEvent::Started(started);
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(event, serde_json::from_str(&json).unwrap());
    }

    // ========================================================================
    // Security Tests (TCK-00148)
    // ========================================================================

    /// TCK-00148: Test that `work_ids` queue size limit is enforced in
    /// `CoordinationStarted`.
    #[test]
    fn test_coordination_started_queue_limit() {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();

        // Create a work_ids list that exceeds the limit
        let oversized_work_ids: Vec<String> = (0..=MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(oversized_work_ids.len(), MAX_WORK_QUEUE_SIZE + 1);

        let result = CoordinationStarted::new(
            "coord-123".to_string(),
            oversized_work_ids,
            budget.clone(),
            3,
            1_000_000_000,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            CoordinationError::WorkQueueSizeExceeded {
                actual,
                max
            } if actual == MAX_WORK_QUEUE_SIZE + 1 && max == MAX_WORK_QUEUE_SIZE
        ));

        // Verify exact limit works
        let exact_work_ids: Vec<String> = (0..MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(exact_work_ids.len(), MAX_WORK_QUEUE_SIZE);

        let result = CoordinationStarted::new(
            "coord-124".to_string(),
            exact_work_ids,
            budget,
            3,
            1_000_000_000,
        );
        assert!(result.is_ok());
    }

    /// TCK-00148: Test that `work_ids` queue size limit is enforced during
    /// deserialization, preventing denial-of-service via oversized JSON
    /// payloads.
    #[test]
    fn test_coordination_started_queue_limit_serde() {
        // Build a JSON string with MAX_WORK_QUEUE_SIZE + 1 work_ids
        let oversized_work_ids: Vec<String> = (0..=MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(oversized_work_ids.len(), MAX_WORK_QUEUE_SIZE + 1);

        let json = serde_json::json!({
            "coordination_id": "coord-123",
            "work_ids": oversized_work_ids,
            "budget": {
                "max_episodes": 10,
                "max_duration_ms": 60000,
                "max_tokens": null
            },
            "max_attempts_per_work": 3,
            "started_at": 1_000_000_000_u64
        });

        let result: Result<CoordinationStarted, _> = serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work_ids exceeds maximum size"),
            "Expected error about work_ids size limit, got: {err}"
        );
    }

    /// TCK-00148: Test that the JSON `type` tag matches the `event_type()`
    /// return value for all coordination event variants.
    ///
    /// This ensures protocol consistency between the serialized wire format
    /// and the programmatic event type constants.
    #[test]
    fn test_event_type_matches_json_tag() {
        // Build all event variants
        let events = vec![
            CoordinationEvent::Started(
                CoordinationStarted::new(
                    "c".to_string(),
                    vec!["w1".to_string()],
                    CoordinationBudget::new(10, 60_000, None).unwrap(),
                    3,
                    1000,
                )
                .unwrap(),
            ),
            CoordinationEvent::SessionBound(CoordinationSessionBound::new(
                "c".to_string(),
                "s".to_string(),
                "w1".to_string(),
                1,
                10,
                2000,
            )),
            CoordinationEvent::SessionUnbound(CoordinationSessionUnbound::new(
                "c".to_string(),
                "s".to_string(),
                "w1".to_string(),
                SessionOutcome::Success,
                500,
                3000,
            )),
            CoordinationEvent::Completed(CoordinationCompleted::new(
                "c".to_string(),
                StopCondition::WorkCompleted,
                BudgetUsage::new(),
                1,
                1,
                0,
                [0u8; BLAKE3_HASH_SIZE],
                4000,
            )),
            CoordinationEvent::Aborted(CoordinationAborted::new(
                "c".to_string(),
                AbortReason::NoEligibleWork,
                BudgetUsage::new(),
                5000,
            )),
        ];

        for event in events {
            let json_bytes = event.to_json_bytes().unwrap();
            let json_value: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

            // Extract the "type" field from the serialized JSON
            let json_type = json_value
                .get("type")
                .expect("JSON should have a 'type' field")
                .as_str()
                .expect("'type' field should be a string");

            // Verify it matches the event_type() method
            assert_eq!(
                json_type,
                event.event_type(),
                "JSON type tag '{}' does not match event_type() '{}'",
                json_type,
                event.event_type()
            );
        }
    }
}
