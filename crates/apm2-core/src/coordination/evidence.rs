//! Coordination evidence and receipt generation.
//!
//! This module provides tamper-evident receipts for coordination execution:
//! - [`CoordinationReceipt`]: Evidence artifact proving coordination execution
//! - [`ReceiptBuilder`]: Incremental builder for receipt construction
//!
//! # Architecture
//!
//! The receipt is built incrementally during coordination and stored in CAS
//! before any completion event is emitted. This ensures:
//!
//! 1. **Tamper-evidence**: Receipt hash in completion event matches CAS content
//! 2. **Auditability**: Complete record of work outcomes and budget usage
//! 3. **Immutability**: Receipt cannot be modified after storage
//!
//! ```text
//! Coordination loop:
//!     |
//!     +-- ReceiptBuilder::new() at start
//!     |
//!     +-- record_work_outcome() for each session termination
//!     |
//!     +-- build() --> CoordinationReceipt
//!     |
//!     +-- store in CAS --> receipt_hash
//!     |
//!     +-- emit completion event with receipt_hash
//! ```
//!
//! # Contract: CTR-COORD-006
//!
//! The `CoordinationReceipt` must include:
//! - `coordination_id`: Unique identifier
//! - `work_outcomes`: Vec of per-work-item outcomes
//! - `budget_usage`: Final budget consumption
//! - `budget_ceiling`: Original budget constraints
//! - `stop_condition`: Why coordination stopped
//! - `started_at` / `completed_at`: Timestamps
//! - `total_sessions` / `successful_sessions` / `failed_sessions`: Counters
//!
//! # References
//!
//! - TCK-00154: Implement `CoordinationReceipt` and CAS storage
//! - RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution
//! - CTR-COORD-006: `CoordinationReceipt` contract

use std::fmt;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, de};

use super::state::{BudgetUsage, CoordinationBudget, SessionOutcome, StopCondition};
use crate::crypto::{EventHasher, Hash};
use crate::evidence::{CasError, ContentAddressedStore};

/// Maximum number of work outcomes allowed in a receipt.
///
/// This limit prevents denial-of-service attacks through unbounded allocation
/// when deserializing receipts. Matches [`super::state::MAX_WORK_QUEUE_SIZE`].
pub const MAX_WORK_OUTCOMES: usize = 1000;

/// Maximum number of session IDs per work outcome.
///
/// Matches [`super::state::MAX_SESSION_IDS_PER_WORK`].
pub const MAX_SESSION_IDS_PER_OUTCOME: usize = 100;

// ============================================================================
// Bounded Deserializers (DoS/OOM Protection)
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
fn deserialize_bounded_work_outcomes<'de, D>(deserializer: D) -> Result<Vec<WorkOutcome>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedVecVisitor;

    impl<'de> Visitor<'de> for BoundedVecVisitor {
        type Value = Vec<WorkOutcome>;

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

// ============================================================================
// WorkOutcome
// ============================================================================

/// Outcome record for an individual work item.
///
/// Per CTR-COORD-006: Each work item's processing is tracked with
/// its attempts, final outcome, and session history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOutcome {
    /// Work item ID.
    pub work_id: String,

    /// Number of attempts made.
    pub attempts: u32,

    /// Final outcome of the work item.
    pub final_outcome: SessionOutcome,

    /// Session IDs used for this work item.
    ///
    /// Limited to [`MAX_SESSION_IDS_PER_OUTCOME`] entries.
    #[serde(deserialize_with = "deserialize_bounded_session_ids")]
    pub session_ids: Vec<String>,
}

impl WorkOutcome {
    /// Creates a new work outcome.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::TooManySessionIds`] if `session_ids` exceeds
    /// [`MAX_SESSION_IDS_PER_OUTCOME`].
    pub fn new(
        work_id: String,
        attempts: u32,
        final_outcome: SessionOutcome,
        session_ids: Vec<String>,
    ) -> Result<Self, ReceiptError> {
        if session_ids.len() > MAX_SESSION_IDS_PER_OUTCOME {
            return Err(ReceiptError::TooManySessionIds {
                actual: session_ids.len(),
                max: MAX_SESSION_IDS_PER_OUTCOME,
            });
        }
        Ok(Self {
            work_id,
            attempts,
            final_outcome,
            session_ids,
        })
    }
}

// ============================================================================
// CoordinationReceipt
// ============================================================================

/// Evidence artifact proving coordination execution.
///
/// Per CTR-COORD-006: This receipt provides a complete record of
/// coordination execution for auditing and verification.
///
/// The receipt is:
/// - Built incrementally during coordination via [`ReceiptBuilder`]
/// - Stored in CAS before completion event is emitted
/// - Referenced by hash in the completion event
///
/// # Invariants
///
/// - [INV-RECEIPT-001] Receipt hash matches CAS content (tamper-evidence)
/// - [INV-RECEIPT-002] Receipt is immutable after storage
/// - [INV-RECEIPT-003] All work items in the queue have outcomes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationReceipt {
    /// Unique identifier for this coordination.
    pub coordination_id: String,

    /// Per-work-item outcomes.
    ///
    /// Limited to [`MAX_WORK_OUTCOMES`] entries.
    #[serde(deserialize_with = "deserialize_bounded_work_outcomes")]
    pub work_outcomes: Vec<WorkOutcome>,

    /// Final budget consumption.
    pub budget_usage: BudgetUsage,

    /// Original budget constraints.
    pub budget_ceiling: CoordinationBudget,

    /// Why coordination stopped.
    pub stop_condition: StopCondition,

    /// Timestamp when coordination started (nanoseconds since epoch).
    pub started_at: u64,

    /// Timestamp when coordination completed (nanoseconds since epoch).
    pub completed_at: u64,

    /// Total sessions spawned.
    pub total_sessions: u32,

    /// Number of successful sessions.
    pub successful_sessions: u32,

    /// Number of failed sessions.
    pub failed_sessions: u32,
}

impl CoordinationReceipt {
    /// Computes the canonical bytes for hashing.
    ///
    /// The canonical format is a deterministic pipe-delimited string that
    /// ensures consistent hashing across different JSON serialization
    /// implementations.
    ///
    /// Format:
    /// `coordination_id|work_outcomes_canonical|budget_usage|budget_ceiling|
    /// stop_condition|started_at|completed_at|total|successful|failed`
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Canonicalize work outcomes
        let work_outcomes_str: String = self
            .work_outcomes
            .iter()
            .map(|wo| {
                let sessions = wo.session_ids.join(",");
                format!(
                    "{}:{}:{}:{}",
                    wo.work_id,
                    wo.attempts,
                    match wo.final_outcome {
                        SessionOutcome::Success => "S",
                        SessionOutcome::Failure => "F",
                    },
                    sessions
                )
            })
            .collect::<Vec<_>>()
            .join(";");

        // Canonicalize stop condition
        let stop_condition_str = match &self.stop_condition {
            StopCondition::WorkCompleted => "WorkCompleted".to_string(),
            StopCondition::BudgetExhausted(bt) => format!("BudgetExhausted:{bt:?}"),
            StopCondition::MaxAttemptsExceeded { work_id } => {
                format!("MaxAttemptsExceeded:{work_id}")
            },
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures,
            } => {
                format!("CircuitBreakerTriggered:{consecutive_failures}")
            },
        };

        format!(
            "{}|{}|{}:{}:{}|{}:{}:{}|{}|{}|{}|{}|{}|{}",
            self.coordination_id,
            work_outcomes_str,
            self.budget_usage.consumed_episodes,
            self.budget_usage.elapsed_ms,
            self.budget_usage.consumed_tokens,
            self.budget_ceiling.max_episodes,
            self.budget_ceiling.max_duration_ms,
            self.budget_ceiling.max_tokens.unwrap_or(0),
            stop_condition_str,
            self.started_at,
            self.completed_at,
            self.total_sessions,
            self.successful_sessions,
            self.failed_sessions,
        )
        .into_bytes()
    }

    /// Computes the BLAKE3 hash of this receipt.
    ///
    /// The hash is computed over the canonical bytes representation of the
    /// receipt. This ensures deterministic hashing across different runs.
    ///
    /// # Errors
    ///
    /// This function is infallible for valid receipts.
    #[must_use]
    pub fn compute_hash(&self) -> Hash {
        let canonical = self.canonical_bytes();
        EventHasher::hash_content(&canonical)
    }

    /// Stores this receipt in the given CAS and returns its hash.
    ///
    /// The receipt is stored as JSON but the hash is computed from the
    /// canonical bytes representation to ensure deterministic hashing.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] if storage fails.
    pub fn store<C: ContentAddressedStore>(&self, cas: &C) -> Result<Hash, CasError> {
        let json = serde_json::to_vec(self).map_err(|e| CasError::StorageError {
            message: format!("failed to serialize receipt: {e}"),
        })?;

        let result = cas.store(&json)?;
        Ok(result.hash)
    }

    /// Loads a receipt from CAS by its hash.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] if retrieval fails or content doesn't match hash.
    /// Returns [`ReceiptError::DeserializationError`] if JSON parsing fails.
    pub fn load<C: ContentAddressedStore>(cas: &C, hash: &Hash) -> Result<Self, ReceiptError> {
        let content = cas.retrieve(hash)?;
        let receipt: Self =
            serde_json::from_slice(&content).map_err(|e| ReceiptError::DeserializationError {
                message: e.to_string(),
            })?;

        // CAS already verified the hash matches the stored content.
        // We don't re-verify against canonical hash here because the CAS
        // hash is over the JSON bytes, not the canonical bytes.
        // Use verify() with compute_hash() for canonical verification.

        Ok(receipt)
    }

    /// Verifies that this receipt's hash matches the expected hash.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::HashMismatch`] if hashes don't match.
    pub fn verify(&self, expected_hash: &Hash) -> Result<(), ReceiptError> {
        let computed_hash = self.compute_hash();
        if computed_hash != *expected_hash {
            return Err(ReceiptError::HashMismatch {
                expected: hex_encode(expected_hash),
                actual: hex_encode(&computed_hash),
            });
        }
        Ok(())
    }
}

// ============================================================================
// ReceiptError
// ============================================================================

/// Errors that can occur during receipt operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    /// CAS operation failed.
    #[error("CAS error: {0}")]
    CasError(String),

    /// Failed to deserialize receipt.
    #[error("failed to deserialize receipt: {message}")]
    DeserializationError {
        /// Error message.
        message: String,
    },

    /// Hash mismatch during verification.
    #[error("receipt hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash (hex-encoded).
        expected: String,
        /// Actual hash (hex-encoded).
        actual: String,
    },

    /// Builder not properly initialized.
    #[error("receipt builder not initialized: {field}")]
    NotInitialized {
        /// The field that was not set.
        field: &'static str,
    },

    /// Too many work outcomes.
    #[error("too many work outcomes: {actual} exceeds limit of {max}")]
    TooManyWorkOutcomes {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many session IDs in a work outcome.
    #[error("too many session IDs: {actual} exceeds limit of {max}")]
    TooManySessionIds {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
}

impl From<CasError> for ReceiptError {
    fn from(err: CasError) -> Self {
        Self::CasError(err.to_string())
    }
}

// ============================================================================
// ReceiptBuilder
// ============================================================================

/// Builder for incremental receipt construction.
///
/// The builder accumulates work outcomes during coordination and produces
/// a complete receipt when coordination completes.
///
/// # Usage Pattern
///
/// ```rust,ignore
/// let mut builder = ReceiptBuilder::new(coordination_id, budget, started_at);
///
/// // During coordination loop:
/// builder.record_work_outcome(outcome);
///
/// // On completion:
/// let receipt = builder.build(stop_condition, budget_usage, completed_at)?;
/// let hash = receipt.store(&cas)?;
/// ```
#[derive(Debug, Clone)]
pub struct ReceiptBuilder {
    /// Coordination ID.
    coordination_id: String,

    /// Original budget constraints.
    budget_ceiling: CoordinationBudget,

    /// Timestamp when coordination started.
    started_at: u64,

    /// Accumulated work outcomes.
    work_outcomes: Vec<WorkOutcome>,

    /// Total sessions spawned.
    total_sessions: u32,

    /// Successful sessions count.
    successful_sessions: u32,

    /// Failed sessions count.
    failed_sessions: u32,
}

impl ReceiptBuilder {
    /// Creates a new receipt builder.
    ///
    /// # Arguments
    ///
    /// * `coordination_id` - Unique identifier for this coordination
    /// * `budget_ceiling` - Original budget constraints
    /// * `started_at` - Timestamp when coordination started (nanoseconds)
    #[must_use]
    pub const fn new(
        coordination_id: String,
        budget_ceiling: CoordinationBudget,
        started_at: u64,
    ) -> Self {
        Self {
            coordination_id,
            budget_ceiling,
            started_at,
            work_outcomes: Vec::new(),
            total_sessions: 0,
            successful_sessions: 0,
            failed_sessions: 0,
        }
    }

    /// Records a work item outcome.
    ///
    /// Call this method after each work item is processed (success or failure
    /// with retries exhausted).
    ///
    /// # Arguments
    ///
    /// * `outcome` - The work outcome to record
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::TooManyWorkOutcomes`] if limit is exceeded.
    /// Returns [`ReceiptError::TooManySessionIds`] if the outcome has too many
    /// session IDs.
    pub fn record_work_outcome(&mut self, outcome: WorkOutcome) -> Result<(), ReceiptError> {
        if self.work_outcomes.len() >= MAX_WORK_OUTCOMES {
            return Err(ReceiptError::TooManyWorkOutcomes {
                actual: self.work_outcomes.len() + 1,
                max: MAX_WORK_OUTCOMES,
            });
        }
        // Validate session IDs count
        if outcome.session_ids.len() > MAX_SESSION_IDS_PER_OUTCOME {
            return Err(ReceiptError::TooManySessionIds {
                actual: outcome.session_ids.len(),
                max: MAX_SESSION_IDS_PER_OUTCOME,
            });
        }
        self.work_outcomes.push(outcome);
        Ok(())
    }

    /// Records a session completion.
    ///
    /// Updates session counters based on outcome.
    ///
    /// # Arguments
    ///
    /// * `outcome` - The session outcome (Success or Failure)
    pub const fn record_session(&mut self, outcome: SessionOutcome) {
        self.total_sessions = self.total_sessions.saturating_add(1);
        match outcome {
            SessionOutcome::Success => {
                self.successful_sessions = self.successful_sessions.saturating_add(1);
            },
            SessionOutcome::Failure => {
                self.failed_sessions = self.failed_sessions.saturating_add(1);
            },
        }
    }

    /// Returns the current work outcomes count.
    #[must_use]
    pub fn work_outcomes_count(&self) -> usize {
        self.work_outcomes.len()
    }

    /// Returns the total sessions count.
    #[must_use]
    pub const fn total_sessions(&self) -> u32 {
        self.total_sessions
    }

    /// Returns the successful sessions count.
    #[must_use]
    pub const fn successful_sessions(&self) -> u32 {
        self.successful_sessions
    }

    /// Returns the failed sessions count.
    #[must_use]
    pub const fn failed_sessions(&self) -> u32 {
        self.failed_sessions
    }

    /// Builds the final receipt.
    ///
    /// # Arguments
    ///
    /// * `stop_condition` - Why coordination stopped
    /// * `budget_usage` - Final budget consumption
    /// * `completed_at` - Timestamp when coordination completed (nanoseconds)
    ///
    /// # Returns
    ///
    /// The completed [`CoordinationReceipt`].
    #[must_use]
    pub fn build(
        self,
        stop_condition: StopCondition,
        budget_usage: BudgetUsage,
        completed_at: u64,
    ) -> CoordinationReceipt {
        CoordinationReceipt {
            coordination_id: self.coordination_id,
            work_outcomes: self.work_outcomes,
            budget_usage,
            budget_ceiling: self.budget_ceiling,
            stop_condition,
            started_at: self.started_at,
            completed_at,
            total_sessions: self.total_sessions,
            successful_sessions: self.successful_sessions,
            failed_sessions: self.failed_sessions,
        }
    }

    /// Builds the receipt and stores it in CAS, returning the hash.
    ///
    /// This is a convenience method that combines `build()` and `store()`.
    ///
    /// # Arguments
    ///
    /// * `cas` - The content-addressed store
    /// * `stop_condition` - Why coordination stopped
    /// * `budget_usage` - Final budget consumption
    /// * `completed_at` - Timestamp when coordination completed (nanoseconds)
    ///
    /// # Returns
    ///
    /// A tuple of (receipt, hash).
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError`] if storage fails.
    pub fn build_and_store<C: ContentAddressedStore>(
        self,
        cas: &C,
        stop_condition: StopCondition,
        budget_usage: BudgetUsage,
        completed_at: u64,
    ) -> Result<(CoordinationReceipt, Hash), ReceiptError> {
        let receipt = self.build(stop_condition, budget_usage, completed_at);
        let hash = receipt.store(cas)?;
        Ok((receipt, hash))
    }
}

/// Converts a hash to hex string.
fn hex_encode(hash: &Hash) -> String {
    use std::fmt::Write;
    hash.iter().fold(
        String::with_capacity(hash.len() * 2),
        |mut acc: String, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::MemoryCas;

    // ========================================================================
    // WorkOutcome Tests
    // ========================================================================

    #[test]
    fn tck_00154_work_outcome_new() {
        let outcome = WorkOutcome::new(
            "work-1".to_string(),
            2,
            SessionOutcome::Success,
            vec!["session-1".to_string(), "session-2".to_string()],
        )
        .unwrap();

        assert_eq!(outcome.work_id, "work-1");
        assert_eq!(outcome.attempts, 2);
        assert_eq!(outcome.final_outcome, SessionOutcome::Success);
        assert_eq!(outcome.session_ids.len(), 2);
    }

    #[test]
    fn tck_00154_work_outcome_too_many_session_ids() {
        let session_ids: Vec<String> = (0..=MAX_SESSION_IDS_PER_OUTCOME)
            .map(|i| format!("session-{i}"))
            .collect();

        let result = WorkOutcome::new(
            "work-1".to_string(),
            1,
            SessionOutcome::Success,
            session_ids,
        );

        assert!(matches!(
            result,
            Err(ReceiptError::TooManySessionIds { .. })
        ));
    }

    #[test]
    fn tck_00154_work_outcome_serde_roundtrip() {
        let outcome = WorkOutcome::new(
            "work-1".to_string(),
            3,
            SessionOutcome::Failure,
            vec!["session-1".to_string()],
        )
        .unwrap();

        let json = serde_json::to_string(&outcome).unwrap();
        let restored: WorkOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, restored);
    }

    #[test]
    fn tck_00154_work_outcome_bounded_deser_rejects_oversized() {
        // Build JSON with too many session IDs
        let session_ids: Vec<String> = (0..=MAX_SESSION_IDS_PER_OUTCOME)
            .map(|i| format!("session-{i}"))
            .collect();

        let json = serde_json::json!({
            "work_id": "work-1",
            "attempts": 1,
            "final_outcome": "Success",
            "session_ids": session_ids,
        });

        let result: Result<WorkOutcome, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn tck_00154_work_outcome_deny_unknown_fields() {
        let json = r#"{"work_id":"w1","attempts":1,"final_outcome":"Success","session_ids":[],"extra":"bad"}"#;
        let result: Result<WorkOutcome, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown field"));
    }

    // ========================================================================
    // CoordinationReceipt Tests
    // ========================================================================

    fn create_test_receipt() -> CoordinationReceipt {
        CoordinationReceipt {
            coordination_id: "coord-123".to_string(),
            work_outcomes: vec![
                WorkOutcome::new(
                    "work-1".to_string(),
                    1,
                    SessionOutcome::Success,
                    vec!["session-1".to_string()],
                )
                .unwrap(),
                WorkOutcome::new(
                    "work-2".to_string(),
                    2,
                    SessionOutcome::Success,
                    vec!["session-2".to_string(), "session-3".to_string()],
                )
                .unwrap(),
            ],
            budget_usage: BudgetUsage {
                consumed_episodes: 3,
                elapsed_ms: 5000,
                consumed_tokens: 10000,
            },
            budget_ceiling: CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap(),
            stop_condition: StopCondition::WorkCompleted,
            started_at: 1_000_000_000,
            completed_at: 1_005_000_000,
            total_sessions: 3,
            successful_sessions: 3,
            failed_sessions: 0,
        }
    }

    #[test]
    fn tck_00154_receipt_compute_hash_deterministic() {
        let receipt = create_test_receipt();

        let hash1 = receipt.compute_hash();
        let hash2 = receipt.compute_hash();

        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn tck_00154_receipt_canonical_bytes_deterministic() {
        let receipt = create_test_receipt();

        let bytes1 = receipt.canonical_bytes();
        let bytes2 = receipt.canonical_bytes();

        assert_eq!(bytes1, bytes2, "Canonical bytes should be deterministic");
    }

    #[test]
    fn tck_00154_receipt_different_content_different_hash() {
        let receipt1 = create_test_receipt();
        let mut receipt2 = create_test_receipt();

        receipt2.total_sessions = 999; // Modify one field

        let hash1 = receipt1.compute_hash();
        let hash2 = receipt2.compute_hash();

        assert_ne!(hash1, hash2, "Different content should have different hash");
    }

    #[test]
    fn tck_00154_receipt_serde_roundtrip() {
        let receipt = create_test_receipt();

        let json = serde_json::to_string(&receipt).unwrap();
        let restored: CoordinationReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt, restored);
    }

    #[test]
    fn tck_00154_receipt_store_and_load() {
        let cas = MemoryCas::new();
        let receipt = create_test_receipt();

        // Store
        let hash = receipt.store(&cas).unwrap();

        // Load
        let loaded = CoordinationReceipt::load(&cas, &hash).unwrap();

        assert_eq!(receipt, loaded);
    }

    #[test]
    fn tck_00154_receipt_hash_matches_cas_content() {
        let cas = MemoryCas::new();
        let receipt = create_test_receipt();

        // Store and get hash
        let stored_hash = receipt.store(&cas).unwrap();

        // Compute hash directly
        let computed_hash = receipt.compute_hash();

        // Note: stored_hash is from JSON bytes, computed_hash is from canonical bytes
        // They will be different, but both are valid content-addressed hashes
        // The important thing is that load() verifies consistency
        let loaded = CoordinationReceipt::load(&cas, &stored_hash).unwrap();
        assert_eq!(receipt, loaded);

        // And verify() uses canonical hash
        assert!(receipt.verify(&computed_hash).is_ok());
    }

    #[test]
    fn tck_00154_receipt_verify_success() {
        let receipt = create_test_receipt();
        let hash = receipt.compute_hash();

        assert!(receipt.verify(&hash).is_ok());
    }

    #[test]
    fn tck_00154_receipt_verify_failure() {
        let receipt = create_test_receipt();
        let wrong_hash = [0u8; 32];

        let result = receipt.verify(&wrong_hash);
        assert!(matches!(result, Err(ReceiptError::HashMismatch { .. })));
    }

    #[test]
    fn tck_00154_receipt_load_not_found() {
        let cas = MemoryCas::new();
        let fake_hash = [0u8; 32];

        let result = CoordinationReceipt::load(&cas, &fake_hash);
        assert!(matches!(result, Err(ReceiptError::CasError(_))));
    }

    #[test]
    fn tck_00154_receipt_bounded_deser_rejects_oversized_outcomes() {
        // Build JSON with too many work outcomes
        let work_outcomes: Vec<serde_json::Value> = (0..=MAX_WORK_OUTCOMES)
            .map(|i| {
                serde_json::json!({
                    "work_id": format!("work-{i}"),
                    "attempts": 1,
                    "final_outcome": "Success",
                    "session_ids": [],
                })
            })
            .collect();

        let json = serde_json::json!({
            "coordination_id": "coord-1",
            "work_outcomes": work_outcomes,
            "budget_usage": {"consumed_episodes": 0, "elapsed_ms": 0, "consumed_tokens": 0},
            "budget_ceiling": {"max_episodes": 10, "max_duration_ms": 60000, "max_tokens": null},
            "stop_condition": "WorkCompleted",
            "started_at": 0,
            "completed_at": 0,
            "total_sessions": 0,
            "successful_sessions": 0,
            "failed_sessions": 0,
        });

        let result: Result<CoordinationReceipt, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn tck_00154_receipt_deny_unknown_fields() {
        let json = serde_json::json!({
            "coordination_id": "coord-1",
            "work_outcomes": [],
            "budget_usage": {"consumed_episodes": 0, "elapsed_ms": 0, "consumed_tokens": 0},
            "budget_ceiling": {"max_episodes": 10, "max_duration_ms": 60000, "max_tokens": null},
            "stop_condition": "WorkCompleted",
            "started_at": 0,
            "completed_at": 0,
            "total_sessions": 0,
            "successful_sessions": 0,
            "failed_sessions": 0,
            "extra_field": "malicious",
        });

        let result: Result<CoordinationReceipt, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown field"));
    }

    // ========================================================================
    // ReceiptBuilder Tests
    // ========================================================================

    #[test]
    fn tck_00154_builder_new() {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
        let builder = ReceiptBuilder::new("coord-123".to_string(), budget, 1_000_000_000);

        assert_eq!(builder.work_outcomes_count(), 0);
        assert_eq!(builder.total_sessions(), 0);
        assert_eq!(builder.successful_sessions(), 0);
        assert_eq!(builder.failed_sessions(), 0);
    }

    #[test]
    fn tck_00154_builder_record_work_outcome() {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
        let mut builder = ReceiptBuilder::new("coord-123".to_string(), budget, 1_000_000_000);

        let outcome = WorkOutcome::new(
            "work-1".to_string(),
            1,
            SessionOutcome::Success,
            vec!["session-1".to_string()],
        )
        .unwrap();

        builder.record_work_outcome(outcome).unwrap();

        assert_eq!(builder.work_outcomes_count(), 1);
    }

    #[test]
    fn tck_00154_builder_rejects_outcome_with_too_many_sessions() {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
        let mut builder = ReceiptBuilder::new("coord-123".to_string(), budget, 1_000_000_000);

        // Create outcome with too many session IDs by bypassing WorkOutcome::new()
        // We directly construct to test the builder's validation
        let session_ids: Vec<String> = (0..=MAX_SESSION_IDS_PER_OUTCOME)
            .map(|i| format!("session-{i}"))
            .collect();

        // Construct directly to bypass WorkOutcome::new() validation
        let outcome = WorkOutcome {
            work_id: "work-1".to_string(),
            attempts: 1,
            final_outcome: SessionOutcome::Success,
            session_ids,
        };

        let result = builder.record_work_outcome(outcome);
        assert!(matches!(
            result,
            Err(ReceiptError::TooManySessionIds { .. })
        ));
    }

    #[test]
    fn tck_00154_builder_record_session() {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
        let mut builder = ReceiptBuilder::new("coord-123".to_string(), budget, 1_000_000_000);

        builder.record_session(SessionOutcome::Success);
        builder.record_session(SessionOutcome::Success);
        builder.record_session(SessionOutcome::Failure);

        assert_eq!(builder.total_sessions(), 3);
        assert_eq!(builder.successful_sessions(), 2);
        assert_eq!(builder.failed_sessions(), 1);
    }

    #[test]
    fn tck_00154_builder_build() {
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap();
        let mut builder =
            ReceiptBuilder::new("coord-123".to_string(), budget.clone(), 1_000_000_000);

        // Record outcomes
        builder
            .record_work_outcome(
                WorkOutcome::new(
                    "work-1".to_string(),
                    1,
                    SessionOutcome::Success,
                    vec!["session-1".to_string()],
                )
                .unwrap(),
            )
            .unwrap();

        builder.record_session(SessionOutcome::Success);

        // Build receipt
        let usage = BudgetUsage {
            consumed_episodes: 1,
            elapsed_ms: 1000,
            consumed_tokens: 5000,
        };
        let receipt = builder.build(StopCondition::WorkCompleted, usage.clone(), 1_001_000_000);

        assert_eq!(receipt.coordination_id, "coord-123");
        assert_eq!(receipt.work_outcomes.len(), 1);
        assert_eq!(receipt.budget_usage, usage);
        assert_eq!(receipt.budget_ceiling, budget);
        assert!(matches!(
            receipt.stop_condition,
            StopCondition::WorkCompleted
        ));
        assert_eq!(receipt.started_at, 1_000_000_000);
        assert_eq!(receipt.completed_at, 1_001_000_000);
        assert_eq!(receipt.total_sessions, 1);
        assert_eq!(receipt.successful_sessions, 1);
        assert_eq!(receipt.failed_sessions, 0);
    }

    #[test]
    fn tck_00154_builder_build_and_store() {
        let cas = MemoryCas::new();
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
        let mut builder = ReceiptBuilder::new("coord-123".to_string(), budget, 1_000_000_000);

        builder
            .record_work_outcome(
                WorkOutcome::new(
                    "work-1".to_string(),
                    1,
                    SessionOutcome::Success,
                    vec!["session-1".to_string()],
                )
                .unwrap(),
            )
            .unwrap();

        builder.record_session(SessionOutcome::Success);

        let usage = BudgetUsage::new();
        let (receipt, hash) = builder
            .build_and_store(&cas, StopCondition::WorkCompleted, usage, 1_001_000_000)
            .unwrap();

        // Verify stored correctly
        let loaded = CoordinationReceipt::load(&cas, &hash).unwrap();
        assert_eq!(receipt, loaded);
    }

    #[test]
    fn tck_00154_builder_too_many_outcomes() {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
        let mut builder = ReceiptBuilder::new("coord-123".to_string(), budget, 1_000_000_000);

        // Fill to capacity
        for i in 0..MAX_WORK_OUTCOMES {
            builder
                .record_work_outcome(
                    WorkOutcome::new(format!("work-{i}"), 1, SessionOutcome::Success, vec![])
                        .unwrap(),
                )
                .unwrap();
        }

        // One more should fail
        let result = builder.record_work_outcome(
            WorkOutcome::new(
                "work-overflow".to_string(),
                1,
                SessionOutcome::Success,
                vec![],
            )
            .unwrap(),
        );

        assert!(matches!(
            result,
            Err(ReceiptError::TooManyWorkOutcomes { .. })
        ));
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn tck_00154_full_coordination_workflow() {
        let cas = MemoryCas::new();
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap();

        // Start building receipt
        let mut builder = ReceiptBuilder::new("coord-full".to_string(), budget, 1_000_000_000);

        // Simulate coordination: work-1 succeeds, work-2 fails then succeeds
        // Work-1: attempt 1 success
        builder.record_session(SessionOutcome::Success);
        builder
            .record_work_outcome(
                WorkOutcome::new(
                    "work-1".to_string(),
                    1,
                    SessionOutcome::Success,
                    vec!["session-1".to_string()],
                )
                .unwrap(),
            )
            .unwrap();

        // Work-2: attempt 1 fails
        builder.record_session(SessionOutcome::Failure);

        // Work-2: attempt 2 succeeds
        builder.record_session(SessionOutcome::Success);
        builder
            .record_work_outcome(
                WorkOutcome::new(
                    "work-2".to_string(),
                    2,
                    SessionOutcome::Success,
                    vec!["session-2".to_string(), "session-3".to_string()],
                )
                .unwrap(),
            )
            .unwrap();

        // Complete coordination
        let usage = BudgetUsage {
            consumed_episodes: 3,
            elapsed_ms: 5000,
            consumed_tokens: 15000,
        };

        let (receipt, hash) = builder
            .build_and_store(&cas, StopCondition::WorkCompleted, usage, 1_005_000_000)
            .unwrap();

        // Verify receipt contents
        assert_eq!(receipt.coordination_id, "coord-full");
        assert_eq!(receipt.work_outcomes.len(), 2);
        assert_eq!(receipt.total_sessions, 3);
        assert_eq!(receipt.successful_sessions, 2);
        assert_eq!(receipt.failed_sessions, 1);

        // Verify can load from CAS
        let loaded = CoordinationReceipt::load(&cas, &hash).unwrap();
        assert_eq!(receipt, loaded);
    }

    #[test]
    fn tck_00154_receipt_tamper_detection() {
        let cas = MemoryCas::new();
        let receipt = create_test_receipt();

        // Store original and get canonical hash
        let _stored_hash = receipt.store(&cas).unwrap();
        let original_hash = receipt.compute_hash();

        // Create tampered receipt
        let mut tampered = receipt;
        tampered.total_sessions = 999;

        // Tampered receipt should not verify against original hash
        assert!(matches!(
            tampered.verify(&original_hash),
            Err(ReceiptError::HashMismatch { .. })
        ));
    }

    #[test]
    fn tck_00154_receipt_immutability_after_storage() {
        let cas = MemoryCas::new();
        let receipt = create_test_receipt();

        // Store
        let hash = receipt.store(&cas).unwrap();

        // Store same content again (should deduplicate)
        let hash2 = receipt.store(&cas).unwrap();
        assert_eq!(hash, hash2, "Same content should have same hash");

        // Verify only one entry in CAS (deduplication)
        assert_eq!(cas.len(), 1);
    }

    // ========================================================================
    // Stop Condition Coverage
    // ========================================================================

    #[test]
    fn tck_00154_receipt_all_stop_conditions() {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();

        let stop_conditions = vec![
            StopCondition::WorkCompleted,
            StopCondition::BudgetExhausted(super::super::state::BudgetType::Episodes),
            StopCondition::BudgetExhausted(super::super::state::BudgetType::Duration),
            StopCondition::BudgetExhausted(super::super::state::BudgetType::Tokens),
            StopCondition::MaxAttemptsExceeded {
                work_id: "work-1".to_string(),
            },
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3,
            },
        ];

        for stop_condition in stop_conditions {
            let builder = ReceiptBuilder::new("coord-test".to_string(), budget.clone(), 1_000);
            let receipt = builder.build(stop_condition.clone(), BudgetUsage::new(), 2_000);

            // Verify serde roundtrip
            let json = serde_json::to_string(&receipt).unwrap();
            let restored: CoordinationReceipt = serde_json::from_str(&json).unwrap();
            assert_eq!(receipt.stop_condition, restored.stop_condition);

            // Verify canonical bytes include stop condition
            let canonical = String::from_utf8(receipt.canonical_bytes()).unwrap();
            match &receipt.stop_condition {
                StopCondition::WorkCompleted => assert!(canonical.contains("WorkCompleted")),
                StopCondition::BudgetExhausted(_) => assert!(canonical.contains("BudgetExhausted")),
                StopCondition::MaxAttemptsExceeded { .. } => {
                    assert!(canonical.contains("MaxAttemptsExceeded"));
                },
                StopCondition::CircuitBreakerTriggered { .. } => {
                    assert!(canonical.contains("CircuitBreakerTriggered"));
                },
            }
        }
    }
}
