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
//! # Hashing Strategy
//!
//! This module uses two distinct hashing approaches:
//!
//! 1. **Canonical Hash** ([`CoordinationReceipt::compute_hash`]): Used for
//!    tamper-evidence verification. Computed over length-prefixed binary
//!    encoding that is immune to delimiter injection attacks. This is the hash
//!    included in completion events and used for `verify()`.
//!
//! 2. **CAS Hash** ([`CoordinationReceipt::store`]): Used by
//!    [`ContentAddressedStore`] for content deduplication. Computed over JSON
//!    serialization. Different from canonical hash but provides
//!    content-addressable storage guarantees.
//!
//! Clients should use `compute_hash()` and `verify()` for tamper-evidence
//! checks, and CAS hash for storage/retrieval operations.
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

#[cfg(test)]
use super::state::BudgetType;
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
// Length-Prefixed Encoding Helpers
// ============================================================================

/// Writes a length-prefixed string to the buffer.
///
/// Format: 4-byte u32 LE length + UTF-8 bytes
///
/// This prevents delimiter injection attacks by unambiguously encoding
/// string boundaries.
fn write_length_prefixed_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    // Truncate to u32::MAX if needed (should never happen in practice)
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len().min(u32::MAX as usize) as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

/// Writes a u32 to the buffer in little-endian format.
fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Writes a u64 to the buffer in little-endian format.
fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

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

    /// Writes this work outcome to a buffer using length-prefixed encoding.
    fn write_canonical(&self, buf: &mut Vec<u8>) {
        write_length_prefixed_string(buf, &self.work_id);
        write_u32(buf, self.attempts);
        // Use stable string representation for outcome
        buf.push(match self.final_outcome {
            SessionOutcome::Success => b'S',
            SessionOutcome::Failure => b'F',
        });
        // Write session IDs count and each ID
        #[allow(clippy::cast_possible_truncation)]
        let session_count = self.session_ids.len().min(u32::MAX as usize) as u32;
        write_u32(buf, session_count);
        for session_id in &self.session_ids {
            write_length_prefixed_string(buf, session_id);
        }
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
    /// Uses length-prefixed binary encoding to prevent delimiter injection
    /// attacks. Each string is prefixed with its length as a 4-byte u32 LE,
    /// ensuring unambiguous parsing regardless of string content.
    ///
    /// This encoding is:
    /// - **Collision-resistant**: Different receipts always produce different
    ///   bytes
    /// - **Deterministic**: Same receipt always produces same bytes
    /// - **Stable**: Not dependent on Debug trait or compiler versions
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Pre-allocate reasonable buffer size
        let mut buf = Vec::with_capacity(1024);

        // Magic bytes for versioning (allows future format changes)
        // CRv2: TCK-00242 - replaced elapsed_ms/max_duration_ms with tick-based fields
        buf.extend_from_slice(b"CRv2");

        // Coordination ID
        write_length_prefixed_string(&mut buf, &self.coordination_id);

        // Work outcomes
        #[allow(clippy::cast_possible_truncation)]
        let work_count = self.work_outcomes.len().min(u32::MAX as usize) as u32;
        write_u32(&mut buf, work_count);
        for wo in &self.work_outcomes {
            wo.write_canonical(&mut buf);
        }

        // Budget usage (TCK-00242: tick-based elapsed time)
        write_u32(&mut buf, self.budget_usage.consumed_episodes);
        write_u64(&mut buf, self.budget_usage.elapsed_ticks);
        write_u64(&mut buf, self.budget_usage.tick_rate_hz);
        write_u64(&mut buf, self.budget_usage.consumed_tokens);

        // Budget ceiling (TCK-00242: tick-based duration)
        write_u32(&mut buf, self.budget_ceiling.max_episodes);
        write_u64(&mut buf, self.budget_ceiling.max_duration_ticks);
        write_u64(&mut buf, self.budget_ceiling.tick_rate_hz);
        // Optional max_tokens: write 0 for None, otherwise write the value
        write_u64(&mut buf, self.budget_ceiling.max_tokens.unwrap_or(0));
        // Discriminator for Option
        buf.push(u8::from(self.budget_ceiling.max_tokens.is_some()));

        // Stop condition - use stable string representation
        let stop_condition_tag = match &self.stop_condition {
            StopCondition::WorkCompleted => 0u8,
            StopCondition::BudgetExhausted(_) => 1u8,
            StopCondition::MaxAttemptsExceeded { .. } => 2u8,
            StopCondition::CircuitBreakerTriggered { .. } => 3u8,
        };
        buf.push(stop_condition_tag);

        // Stop condition payload
        match &self.stop_condition {
            StopCondition::WorkCompleted => {
                // No payload
            },
            StopCondition::BudgetExhausted(bt) => {
                // Use stable as_str() method instead of Debug
                write_length_prefixed_string(&mut buf, bt.as_str());
            },
            StopCondition::MaxAttemptsExceeded { work_id } => {
                write_length_prefixed_string(&mut buf, work_id);
            },
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures,
            } => {
                write_u32(&mut buf, *consecutive_failures);
            },
        }

        // Timestamps
        write_u64(&mut buf, self.started_at);
        write_u64(&mut buf, self.completed_at);

        // Session counts
        write_u32(&mut buf, self.total_sessions);
        write_u32(&mut buf, self.successful_sessions);
        write_u32(&mut buf, self.failed_sessions);

        buf
    }

    /// Computes the BLAKE3 hash of this receipt.
    ///
    /// The hash is computed over the canonical bytes representation of the
    /// receipt. This ensures deterministic hashing across different runs
    /// and is immune to delimiter injection attacks.
    ///
    /// This is the **tamper-evidence hash** that should be included in
    /// completion events and used for verification.
    #[must_use]
    pub fn compute_hash(&self) -> Hash {
        let canonical = self.canonical_bytes();
        EventHasher::hash_content(&canonical)
    }

    /// Stores this receipt in the given CAS and returns the CAS content hash.
    ///
    /// The receipt is stored as JSON. The returned hash is the CAS content
    /// hash (computed over JSON bytes), which differs from the canonical
    /// hash returned by [`Self::compute_hash`].
    ///
    /// Use `compute_hash()` for tamper-evidence verification.
    /// Use this method for CAS storage/retrieval operations.
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

    /// Loads a receipt from CAS by its CAS content hash.
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
        // The CAS hash is over JSON bytes, distinct from canonical hash.
        // Use verify() with compute_hash() for tamper-evidence verification.

        Ok(receipt)
    }

    /// Verifies that this receipt's canonical hash matches the expected hash.
    ///
    /// Use this method to verify tamper-evidence. The expected hash should
    /// come from a trusted source (e.g., completion event, signed manifest).
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

    /// Builds the receipt and stores it in CAS, returning both hashes.
    ///
    /// This is a convenience method that combines `build()`, `store()`, and
    /// `compute_hash()`.
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
    /// A tuple of (receipt, `canonical_hash`, `cas_hash`).
    /// - `canonical_hash`: Use for tamper-evidence (include in completion
    ///   events)
    /// - `cas_hash`: Use for CAS retrieval operations
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
    ) -> Result<(CoordinationReceipt, Hash, Hash), ReceiptError> {
        let receipt = self.build(stop_condition, budget_usage, completed_at);
        let canonical_hash = receipt.compute_hash();
        let cas_hash = receipt.store(cas)?;
        Ok((receipt, canonical_hash, cas_hash))
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

    /// Test tick rate: 1MHz (1 tick = 1 microsecond)
    const TEST_TICK_RATE_HZ: u64 = 1_000_000;

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
                elapsed_ticks: 5_000_000,
                tick_rate_hz: TEST_TICK_RATE_HZ,
                consumed_tokens: 10000,
            },
            budget_ceiling: CoordinationBudget::new(
                10,
                60_000_000,
                TEST_TICK_RATE_HZ,
                Some(100_000),
            )
            .unwrap(),
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
    fn tck_00154_receipt_delimiter_injection_produces_different_hash() {
        // CRITICAL TEST: Ensure delimiter injection doesn't cause hash collisions
        //
        // With naive delimiter-based encoding (e.g., "a|b" + "c" vs "a" + "b|c"),
        // different logical data could produce same bytes.
        //
        // Length-prefixed encoding prevents this.

        // Receipt 1: coordination_id = "a|b", work with id "c"
        let receipt1 = CoordinationReceipt {
            coordination_id: "a|b".to_string(),
            work_outcomes: vec![
                WorkOutcome::new("c".to_string(), 1, SessionOutcome::Success, vec![]).unwrap(),
            ],
            budget_usage: BudgetUsage::new(),
            budget_ceiling: CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None)
                .unwrap(),
            stop_condition: StopCondition::WorkCompleted,
            started_at: 0,
            completed_at: 0,
            total_sessions: 0,
            successful_sessions: 0,
            failed_sessions: 0,
        };

        // Receipt 2: coordination_id = "a", work with id "b|c"
        let receipt2 = CoordinationReceipt {
            coordination_id: "a".to_string(),
            work_outcomes: vec![
                WorkOutcome::new("b|c".to_string(), 1, SessionOutcome::Success, vec![]).unwrap(),
            ],
            budget_usage: BudgetUsage::new(),
            budget_ceiling: CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None)
                .unwrap(),
            stop_condition: StopCondition::WorkCompleted,
            started_at: 0,
            completed_at: 0,
            total_sessions: 0,
            successful_sessions: 0,
            failed_sessions: 0,
        };

        let hash1 = receipt1.compute_hash();
        let hash2 = receipt2.compute_hash();

        assert_ne!(
            hash1, hash2,
            "Delimiter injection must produce different hashes"
        );
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
        let cas_hash = receipt.store(&cas).unwrap();

        // Load
        let loaded = CoordinationReceipt::load(&cas, &cas_hash).unwrap();

        assert_eq!(receipt, loaded);
    }

    #[test]
    fn tck_00154_receipt_canonical_hash_differs_from_cas_hash() {
        let cas = MemoryCas::new();
        let receipt = create_test_receipt();

        // Get both hashes
        let canonical_hash = receipt.compute_hash();
        let cas_hash = receipt.store(&cas).unwrap();

        // They should be different (canonical is length-prefixed, CAS is JSON)
        assert_ne!(
            canonical_hash, cas_hash,
            "Canonical and CAS hashes should differ"
        );

        // But canonical hash should be stable
        let canonical_hash2 = receipt.compute_hash();
        assert_eq!(canonical_hash, canonical_hash2);

        // And both should work for their intended purposes
        assert!(receipt.verify(&canonical_hash).is_ok());
        let _loaded = CoordinationReceipt::load(&cas, &cas_hash).unwrap();
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
            "budget_usage": {"consumed_episodes": 0, "elapsed_ticks": 0, "tick_rate_hz": 1_000_000, "consumed_tokens": 0},
            "budget_ceiling": {"max_episodes": 10, "max_duration_ticks": 60_000_000, "tick_rate_hz": 1_000_000, "max_tokens": null},
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
            "budget_usage": {"consumed_episodes": 0, "elapsed_ticks": 0, "tick_rate_hz": 1_000_000, "consumed_tokens": 0},
            "budget_ceiling": {"max_episodes": 10, "max_duration_ticks": 60_000_000, "tick_rate_hz": 1_000_000, "max_tokens": null},
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
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let builder = ReceiptBuilder::new("coord-123".to_string(), budget, 1_000_000_000);

        assert_eq!(builder.work_outcomes_count(), 0);
        assert_eq!(builder.total_sessions(), 0);
        assert_eq!(builder.successful_sessions(), 0);
        assert_eq!(builder.failed_sessions(), 0);
    }

    #[test]
    fn tck_00154_builder_record_work_outcome() {
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
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
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let mut builder = ReceiptBuilder::new("coord-123".to_string(), budget, 1_000_000_000);

        // Create outcome with too many session IDs by direct construction
        let session_ids: Vec<String> = (0..=MAX_SESSION_IDS_PER_OUTCOME)
            .map(|i| format!("session-{i}"))
            .collect();

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
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
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
        let budget =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();
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
            elapsed_ticks: 1_000_000,
            tick_rate_hz: TEST_TICK_RATE_HZ,
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
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
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
        let (receipt, canonical_hash, cas_hash) = builder
            .build_and_store(&cas, StopCondition::WorkCompleted, usage, 1_001_000_000)
            .unwrap();

        // Verify stored correctly
        let loaded = CoordinationReceipt::load(&cas, &cas_hash).unwrap();
        assert_eq!(receipt, loaded);

        // Verify canonical hash works
        assert!(receipt.verify(&canonical_hash).is_ok());
    }

    #[test]
    fn tck_00154_builder_too_many_outcomes() {
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
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
        let budget =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();

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
            elapsed_ticks: 5_000_000,
            tick_rate_hz: TEST_TICK_RATE_HZ,
            consumed_tokens: 15000,
        };

        let (receipt, canonical_hash, cas_hash) = builder
            .build_and_store(&cas, StopCondition::WorkCompleted, usage, 1_005_000_000)
            .unwrap();

        // Verify receipt contents
        assert_eq!(receipt.coordination_id, "coord-full");
        assert_eq!(receipt.work_outcomes.len(), 2);
        assert_eq!(receipt.total_sessions, 3);
        assert_eq!(receipt.successful_sessions, 2);
        assert_eq!(receipt.failed_sessions, 1);

        // Verify can load from CAS
        let loaded = CoordinationReceipt::load(&cas, &cas_hash).unwrap();
        assert_eq!(receipt, loaded);

        // Verify tamper-evidence hash
        assert!(receipt.verify(&canonical_hash).is_ok());
    }

    #[test]
    fn tck_00154_receipt_tamper_detection() {
        let receipt = create_test_receipt();

        // Get canonical hash
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
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();

        let stop_conditions = vec![
            StopCondition::WorkCompleted,
            StopCondition::BudgetExhausted(BudgetType::Episodes),
            StopCondition::BudgetExhausted(BudgetType::Duration),
            StopCondition::BudgetExhausted(BudgetType::Tokens),
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

            // Verify hash is deterministic
            let hash1 = receipt.compute_hash();
            let hash2 = receipt.compute_hash();
            assert_eq!(hash1, hash2);

            // Verify serde roundtrip
            let json = serde_json::to_string(&receipt).unwrap();
            let restored: CoordinationReceipt = serde_json::from_str(&json).unwrap();
            assert_eq!(receipt.stop_condition, restored.stop_condition);
        }
    }

    #[test]
    fn tck_00154_stop_condition_uses_stable_encoding() {
        // Verify that BudgetType uses as_str() for stable encoding
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();

        let receipt_duration = {
            let builder = ReceiptBuilder::new("coord-1".to_string(), budget.clone(), 1_000);
            builder.build(
                StopCondition::BudgetExhausted(BudgetType::Duration),
                BudgetUsage::new(),
                2_000,
            )
        };

        let receipt_tokens = {
            let builder = ReceiptBuilder::new("coord-1".to_string(), budget.clone(), 1_000);
            builder.build(
                StopCondition::BudgetExhausted(BudgetType::Tokens),
                BudgetUsage::new(),
                2_000,
            )
        };

        // Different budget types should produce different hashes
        assert_ne!(
            receipt_duration.compute_hash(),
            receipt_tokens.compute_hash()
        );

        // Same budget type should produce same hash
        let receipt_duration2 = {
            let builder = ReceiptBuilder::new("coord-1".to_string(), budget, 1_000);
            builder.build(
                StopCondition::BudgetExhausted(BudgetType::Duration),
                BudgetUsage::new(),
                2_000,
            )
        };
        assert_eq!(
            receipt_duration.compute_hash(),
            receipt_duration2.compute_hash()
        );
    }
}
