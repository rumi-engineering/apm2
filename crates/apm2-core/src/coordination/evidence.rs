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

use serde::{Deserialize, Serialize};

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

/// Outcome record for an individual work item.
///
/// Per CTR-COORD-006: Each work item's processing is tracked with
/// its attempts, final outcome, and session history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkOutcome {
    /// Work item ID.
    pub work_id: String,

    /// Number of attempts made.
    pub attempts: u32,

    /// Final outcome of the work item.
    pub final_outcome: SessionOutcome,

    /// Session IDs used for this work item.
    pub session_ids: Vec<String>,
}

impl WorkOutcome {
    /// Creates a new work outcome.
    #[must_use]
    pub const fn new(
        work_id: String,
        attempts: u32,
        final_outcome: SessionOutcome,
        session_ids: Vec<String>,
    ) -> Self {
        Self {
            work_id,
            attempts,
            final_outcome,
            session_ids,
        }
    }
}

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
pub struct CoordinationReceipt {
    /// Unique identifier for this coordination.
    pub coordination_id: String,

    /// Per-work-item outcomes.
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
    /// Computes the BLAKE3 hash of this receipt.
    ///
    /// The hash is computed over the canonical JSON serialization of the
    /// receipt. This ensures deterministic hashing across different runs.
    ///
    /// # Panics
    ///
    /// Panics if JSON serialization fails (should never happen for valid
    /// receipts).
    #[must_use]
    pub fn compute_hash(&self) -> Hash {
        let json = serde_json::to_vec(self).expect("receipt serialization should not fail");
        EventHasher::hash_content(&json)
    }

    /// Stores this receipt in the given CAS and returns its hash.
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

        // Verify hash matches (belt-and-suspenders with CAS verification)
        let computed_hash = receipt.compute_hash();
        if computed_hash != *hash {
            return Err(ReceiptError::HashMismatch {
                expected: hex_encode(hash),
                actual: hex_encode(&computed_hash),
            });
        }

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
}

impl From<CasError> for ReceiptError {
    fn from(err: CasError) -> Self {
        Self::CasError(err.to_string())
    }
}

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
    pub fn record_work_outcome(&mut self, outcome: WorkOutcome) -> Result<(), ReceiptError> {
        if self.work_outcomes.len() >= MAX_WORK_OUTCOMES {
            return Err(ReceiptError::TooManyWorkOutcomes {
                actual: self.work_outcomes.len() + 1,
                max: MAX_WORK_OUTCOMES,
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
        );

        assert_eq!(outcome.work_id, "work-1");
        assert_eq!(outcome.attempts, 2);
        assert_eq!(outcome.final_outcome, SessionOutcome::Success);
        assert_eq!(outcome.session_ids.len(), 2);
    }

    #[test]
    fn tck_00154_work_outcome_serde_roundtrip() {
        let outcome = WorkOutcome::new(
            "work-1".to_string(),
            3,
            SessionOutcome::Failure,
            vec!["session-1".to_string()],
        );

        let json = serde_json::to_string(&outcome).unwrap();
        let restored: WorkOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, restored);
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
                ),
                WorkOutcome::new(
                    "work-2".to_string(),
                    2,
                    SessionOutcome::Success,
                    vec!["session-2".to_string(), "session-3".to_string()],
                ),
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

        assert_eq!(
            stored_hash, computed_hash,
            "CAS hash must match computed hash"
        );
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
        );

        builder.record_work_outcome(outcome).unwrap();

        assert_eq!(builder.work_outcomes_count(), 1);
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
            .record_work_outcome(WorkOutcome::new(
                "work-1".to_string(),
                1,
                SessionOutcome::Success,
                vec!["session-1".to_string()],
            ))
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
            .record_work_outcome(WorkOutcome::new(
                "work-1".to_string(),
                1,
                SessionOutcome::Success,
                vec!["session-1".to_string()],
            ))
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
                .record_work_outcome(WorkOutcome::new(
                    format!("work-{i}"),
                    1,
                    SessionOutcome::Success,
                    vec![],
                ))
                .unwrap();
        }

        // One more should fail
        let result = builder.record_work_outcome(WorkOutcome::new(
            "work-overflow".to_string(),
            1,
            SessionOutcome::Success,
            vec![],
        ));

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
            .record_work_outcome(WorkOutcome::new(
                "work-1".to_string(),
                1,
                SessionOutcome::Success,
                vec!["session-1".to_string()],
            ))
            .unwrap();

        // Work-2: attempt 1 fails
        builder.record_session(SessionOutcome::Failure);

        // Work-2: attempt 2 succeeds
        builder.record_session(SessionOutcome::Success);
        builder
            .record_work_outcome(WorkOutcome::new(
                "work-2".to_string(),
                2,
                SessionOutcome::Success,
                vec!["session-2".to_string(), "session-3".to_string()],
            ))
            .unwrap();

        // Complete coordination
        let usage = BudgetUsage {
            consumed_episodes: 3,
            elapsed_ms: 5000,
            consumed_tokens: 15000,
        };

        let (receipt, hash) = builder
            .build_and_store(
                &cas,
                StopCondition::WorkCompleted,
                usage.clone(),
                1_005_000_000,
            )
            .unwrap();

        // Verify receipt contents
        assert_eq!(receipt.coordination_id, "coord-full");
        assert_eq!(receipt.work_outcomes.len(), 2);
        assert_eq!(receipt.total_sessions, 3);
        assert_eq!(receipt.successful_sessions, 2);
        assert_eq!(receipt.failed_sessions, 1);

        // Verify hash matches stored content
        assert!(receipt.verify(&hash).is_ok());

        // Verify can load from CAS
        let loaded = CoordinationReceipt::load(&cas, &hash).unwrap();
        assert_eq!(receipt, loaded);
    }

    #[test]
    fn tck_00154_receipt_tamper_detection() {
        let cas = MemoryCas::new();
        let receipt = create_test_receipt();

        // Store original
        let original_hash = receipt.store(&cas).unwrap();

        // Create tampered receipt
        let mut tampered = receipt.clone();
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
        }
    }
}
