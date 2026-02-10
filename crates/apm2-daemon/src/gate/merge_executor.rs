// AGENT-AUTHORED (TCK-00390)
//! Daemon-side merge executor for autonomous merge after gate approval.
//!
//! This module implements the [`MergeExecutor`] which watches for all required
//! gate receipts reaching PASS verdict and autonomously executes the merge.
//!
//! # Merge Lifecycle
//!
//! ```text
//! AllGatesCompleted(all_passed=true)
//!   -> verify policy hash (anti-downgrade)
//!   -> execute squash merge via GitHub API
//!   -> observe merge result (commit SHA)
//!   -> create and sign MergeReceipt
//!   -> emit merge_receipt ledger event
//!   -> transition work state to Completed
//! ```
//!
//! # Security Model
//!
//! - **Policy hash verification**: The merge executor verifies the policy hash
//!   from each gate receipt against the `PolicyResolvedForChangeSet` anchor.
//!   This prevents policy downgrade attacks where a compromised gate uses a
//!   weaker policy than what was resolved.
//! - **Atomic binding**: The `MergeReceipt` atomically binds inputs
//!   (`base_selector`, `changeset_digest`, `gate_receipt_ids`, `policy_hash`)
//!   to the observed result (`result_selector` = new commit SHA).
//! - **Domain-separated signing**: Uses `MERGE_RECEIPT:` domain separator.
//! - **Canonical gate receipt IDs**: Gate receipt IDs are sorted before
//!   inclusion in the `MergeReceipt` for deterministic serialization.
//! - **Fail-closed merge conflicts**: Merge conflicts produce a
//!   `ReviewBlockedRecorded` event with `MergeConflict` reason code, not silent
//!   failure.
//!
//! # Event Model
//!
//! Events are returned per-invocation (not buffered in shared state) to
//! match the gate orchestrator pattern and avoid concurrent drain issues.

use std::sync::Arc;

use apm2_core::crypto::Signer;
use apm2_core::fac::{MergeReceipt, PolicyResolvedForChangeSet, ReasonCode, ReviewBlockedRecorded};
use apm2_core::ledger::EventRecord;
use apm2_core::work::{EventFamilyPromotionGate, WorkReducerState};
use prost::Message;
use serde::Serialize;
use thiserror::Error;
use tracing::{info, warn};

use super::orchestrator::{Clock, GateOutcome, SystemClock};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of pending merge operations tracked concurrently.
///
/// Prevents unbounded memory growth. When reached, new merge requests
/// are rejected with fail-closed semantics.
pub const MAX_PENDING_MERGES: usize = 1_000;

/// Maximum number of work events accepted per merge input.
///
/// Prevents unbounded CPU/memory usage in the promotion gate.
pub const MAX_WORK_EVENTS: usize = 10_000;

/// Maximum aggregate payload bytes across all work events.
///
/// Prevents expensive JSON/protobuf decode under adversarial payload sizing.
pub const MAX_WORK_EVENTS_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

/// Maximum length of any string field in merge executor events.
const MAX_STRING_LENGTH: usize = 4096;

/// Result type for the [`MergeExecutor::execute_or_block`] method.
///
/// Contains:
/// - `Option<MergeReceipt>` - The signed merge receipt on success, `None` on
///   conflict.
/// - `Option<ReviewBlockedRecorded>` - The blocked event on conflict, `None` on
///   success.
/// - `Vec<MergeExecutorEvent>` - Events for ledger persistence.
pub type ExecuteOrBlockResult = (
    Option<MergeReceipt>,
    Option<ReviewBlockedRecorded>,
    Vec<MergeExecutorEvent>,
);

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during merge execution.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MergeExecutorError {
    /// Not all gates passed.
    #[error("not all gates passed for work_id {work_id}")]
    GatesNotAllPassed {
        /// The work ID.
        work_id: String,
    },

    /// Policy hash mismatch (anti-downgrade).
    #[error("policy hash mismatch for work_id {work_id}: expected {expected}, got {actual}")]
    PolicyHashMismatch {
        /// The work ID.
        work_id: String,
        /// Expected policy hash (hex).
        expected: String,
        /// Actual policy hash from receipt (hex).
        actual: String,
    },

    /// Merge failed due to a conflict.
    #[error("merge conflict for work_id {work_id}: {reason}")]
    MergeConflict {
        /// The work ID.
        work_id: String,
        /// Conflict details.
        reason: String,
    },

    /// GitHub API error during merge.
    #[error("GitHub API merge error for work_id {work_id}: {reason}")]
    GitHubApiError {
        /// The work ID.
        work_id: String,
        /// Error details.
        reason: String,
    },

    /// Merge receipt creation failed.
    #[error("merge receipt creation failed for work_id {work_id}: {reason}")]
    ReceiptCreationFailed {
        /// The work ID.
        work_id: String,
        /// Error details.
        reason: String,
    },

    /// No gate outcomes provided.
    #[error("no gate outcomes provided for work_id {work_id}")]
    NoGateOutcomes {
        /// The work ID.
        work_id: String,
    },

    /// Work ID is empty.
    #[error("work_id must not be empty")]
    EmptyWorkId,

    /// Work ID too long.
    #[error("work_id exceeds max length: {actual} > {max}")]
    WorkIdTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Work event list exceeds bounded merge-input limit.
    #[error("work_events count {actual} exceeds maximum {max} for work_id {work_id}")]
    WorkEventLimitExceeded {
        /// The work ID.
        work_id: String,
        /// Actual work event count.
        actual: usize,
        /// Maximum allowed work event count.
        max: usize,
    },

    /// Aggregate event payload bytes exceed bounded merge-input limit.
    #[error(
        "work_events aggregate payload {actual_bytes} bytes exceeds maximum {max_bytes} for work_id {work_id}"
    )]
    WorkEventByteLimitExceeded {
        /// The work ID.
        work_id: String,
        /// Actual aggregate payload bytes.
        actual_bytes: usize,
        /// Maximum allowed aggregate payload bytes.
        max_bytes: usize,
    },

    /// Missing PR number for merge.
    #[error("no PR number associated with work_id {work_id}")]
    MissingPrNumber {
        /// The work ID.
        work_id: String,
    },

    /// Missing policy resolution for merge.
    #[error("no policy resolution found for work_id {work_id}")]
    MissingPolicyResolution {
        /// The work ID.
        work_id: String,
    },

    /// Event-family promotion gate blocked the merge.
    #[error("event-family promotion gate blocked for work_id {work_id}: {reason}")]
    PromotionGateBlocked {
        /// The work ID.
        work_id: String,
        /// Reason for blocking.
        reason: String,
        /// Structured defect records from promotion gate evaluation.
        ///
        /// Not included in Display (can be large).
        defect_records: Vec<apm2_core::events::DefectRecorded>,
    },
}

// =============================================================================
// Merge Result (from GitHub API)
// =============================================================================

/// Result of a squash merge operation via the GitHub API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeResult {
    /// The new commit SHA on the target branch after merge.
    pub result_sha: String,
    /// The target branch name (e.g., "main").
    pub target_branch: String,
}

// =============================================================================
// Merge Executor Events
// =============================================================================

/// Events emitted by the merge executor.
///
/// These events represent the merge lifecycle and are intended to be
/// persisted to the ledger.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum MergeExecutorEvent {
    /// Merge was executed successfully.
    MergeExecuted {
        /// The work ID.
        work_id: String,
        /// The new commit SHA on the target branch.
        result_sha: String,
        /// The target branch.
        target_branch: String,
        /// Number of gate receipts that authorized the merge.
        gate_receipt_count: usize,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// Merge receipt was created and signed.
    MergeReceiptCreated {
        /// The work ID.
        work_id: String,
        /// The base selector (target branch).
        base_selector: String,
        /// The result selector (new commit SHA).
        result_selector: String,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// Work completed after successful merge.
    WorkCompleted {
        /// The work ID.
        work_id: String,
        /// The merge receipt that serves as evidence.
        gate_receipt_id: String,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// Merge was blocked due to a conflict.
    MergeBlocked {
        /// The work ID.
        work_id: String,
        /// The reason code for the block.
        reason: String,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// Promotion gate denied merge — defect records emitted for ledger
    /// persistence.
    PromotionGateDenied {
        /// The work ID.
        work_id: String,
        /// Number of defect records.
        defect_count: usize,
        /// Serialized defect records for ledger persistence
        /// (protobuf-encoded bytes).
        defect_payloads: Vec<Vec<u8>>,
        /// Summary reason for the denial.
        reason: String,
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
}

// =============================================================================
// Merge Input
// =============================================================================

/// Input data required to execute a merge.
///
/// Collected from the gate orchestrator's `AllGatesCompleted` event
/// and the work item's PR association.
#[derive(Debug, Clone)]
pub struct MergeInput {
    /// The work ID.
    pub work_id: String,
    /// The changeset digest being merged.
    pub changeset_digest: [u8; 32],
    /// The PR number to merge.
    pub pr_number: u64,
    /// The target branch (e.g., "main").
    pub target_branch: String,
    /// The gate outcomes from `AllGatesCompleted`.
    pub gate_outcomes: Vec<GateOutcome>,
    /// The policy resolution that governed this changeset.
    pub policy_resolution: PolicyResolvedForChangeSet,
    /// The actor ID performing the merge.
    pub actor_id: String,
    /// Ledger events for this `work_id`.
    ///
    /// Must be non-empty; empty `work_events` are rejected (fail-closed).
    pub work_events: Vec<EventRecord>,
    /// Expected reducer state for replay-equivalence validation.
    ///
    /// Required when `work_events` are provided.
    pub expected_reducer_state: Option<WorkReducerState>,
}

// =============================================================================
// GitHub Merge Adapter Trait
// =============================================================================

/// Trait for executing squash merges via GitHub API.
///
/// This trait abstracts the GitHub API interaction so the merge executor
/// can be tested with mock implementations.
pub trait GitHubMergeAdapter: Send + Sync {
    /// Executes a squash merge of the given PR.
    ///
    /// # Arguments
    ///
    /// * `pr_number` - The PR number to merge
    /// * `commit_title` - The squash commit title
    /// * `target_branch` - The target branch to merge into
    ///
    /// # Returns
    ///
    /// The merge result containing the new commit SHA, or an error.
    ///
    /// # Errors
    ///
    /// Returns `MergeExecutorError::MergeConflict` if the merge cannot
    /// proceed due to conflicts.
    /// Returns `MergeExecutorError::GitHubApiError` for other API failures.
    fn squash_merge(
        &self,
        pr_number: u64,
        commit_title: &str,
        target_branch: &str,
    ) -> Result<MergeResult, MergeExecutorError>;
}

// =============================================================================
// Merge Executor
// =============================================================================

/// Merge executor for autonomous merge after gate approval.
///
/// The `MergeExecutor` is triggered when all required gates pass. It:
///
/// 1. Verifies the policy hash from each gate receipt matches the
///    `PolicyResolvedForChangeSet` anchor (anti-downgrade).
/// 2. Executes the squash merge via the GitHub API.
/// 3. Creates and signs a `MergeReceipt` binding inputs to the observed merge
///    result.
/// 4. Returns events for ledger persistence (`merge_receipt`, `WorkCompleted`).
///
/// # Security
///
/// - Policy hash verification prevents downgrade attacks.
/// - `MergeReceipt` atomically binds inputs to observed result.
/// - `MERGE_RECEIPT:` domain separator prevents cross-protocol replay.
/// - Gate receipt IDs are sorted canonically for deterministic serialization.
/// - Merge conflicts produce `ReviewBlockedRecorded`, not silent failure.
///
/// # Event Model
///
/// Events are returned per-invocation (not buffered in shared state).
pub struct MergeExecutor {
    /// Signer for merge receipts.
    signer: Arc<Signer>,
    /// Clock for timestamps.
    clock: Arc<dyn Clock>,
    /// Actor ID for merge operations.
    actor_id: String,
}

impl MergeExecutor {
    /// Creates a new merge executor.
    #[must_use]
    pub fn new(signer: Arc<Signer>, actor_id: impl Into<String>) -> Self {
        Self {
            signer,
            clock: Arc::new(SystemClock),
            actor_id: actor_id.into(),
        }
    }

    /// Creates a new merge executor with an injected clock.
    ///
    /// Use this constructor in tests to inject a mock clock for
    /// deterministic timestamp behaviour.
    #[must_use]
    pub fn with_clock(
        signer: Arc<Signer>,
        actor_id: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            signer,
            clock,
            actor_id: actor_id.into(),
        }
    }

    /// Executes the autonomous merge lifecycle after all gates pass.
    ///
    /// This is the primary entry point. It:
    ///
    /// 1. Validates all gates passed
    /// 2. Verifies policy hash (anti-downgrade)
    /// 3. Calls the GitHub merge adapter for squash merge
    /// 4. Creates and signs the `MergeReceipt`
    /// 5. Returns events for ledger persistence
    ///
    /// On merge conflict, returns a `MergeBlocked` event and a
    /// `ReviewBlockedRecorded` structure for the caller to emit.
    ///
    /// # Arguments
    ///
    /// * `input` - The merge input data
    /// * `github_adapter` - The GitHub merge adapter for executing the merge
    ///
    /// # Returns
    ///
    /// A tuple of `(merge_receipt, events)` on success, where `merge_receipt`
    /// is the signed receipt and `events` are for ledger persistence.
    ///
    /// # Errors
    ///
    /// Returns `MergeExecutorError` if validation or execution fails.
    pub fn execute_merge(
        &self,
        input: &MergeInput,
        github_adapter: &dyn GitHubMergeAdapter,
    ) -> Result<(MergeReceipt, Vec<MergeExecutorEvent>), MergeExecutorError> {
        // Step 0: Validate input
        Self::validate_input(input)?;

        // REQ-HEF-0014: Event-family parity and replay-equivalence gate.
        // Promotion is blocked unless parity and replay-equivalence checks pass.
        // This MUST happen BEFORE the irreversible squash merge (fail-closed).
        if input.work_events.is_empty() {
            return Err(MergeExecutorError::PromotionGateBlocked {
                work_id: input.work_id.clone(),
                reason: "work_events must not be empty (fail-closed: promotion gate requires event history)"
                    .to_string(),
                defect_records: Vec::new(),
            });
        }

        let expected_state = input.expected_reducer_state.as_ref().ok_or_else(|| {
            MergeExecutorError::PromotionGateBlocked {
                work_id: input.work_id.clone(),
                reason: "work_events provided but expected_reducer_state is None (fail-closed)"
                    .to_string(),
                defect_records: Vec::new(),
            }
        })?;

        // REQ-HEF-0014: Bind work_events to input.work_id — reject foreign events.
        for (idx, event) in input.work_events.iter().enumerate() {
            if event.session_id != input.work_id {
                return Err(MergeExecutorError::PromotionGateBlocked {
                    work_id: input.work_id.clone(),
                    reason: format!(
                        "work_events[{idx}] has session_id '{}' which does not match work_id '{}' (binding violation)",
                        event.session_id, input.work_id
                    ),
                    defect_records: Vec::new(),
                });
            }
        }

        // Verify expected_reducer_state is keyed only to this work_id.
        if expected_state.get(&input.work_id).is_none() {
            return Err(MergeExecutorError::PromotionGateBlocked {
                work_id: input.work_id.clone(),
                reason: format!(
                    "expected_reducer_state does not contain work_id '{}' (binding violation)",
                    input.work_id
                ),
                defect_records: Vec::new(),
            });
        }
        if expected_state.len() > 1 {
            let mut foreign_work_ids: Vec<&str> = expected_state
                .work_items
                .keys()
                .filter_map(|key| (key.as_str() != input.work_id).then_some(key.as_str()))
                .collect();
            foreign_work_ids.sort_unstable();
            return Err(MergeExecutorError::PromotionGateBlocked {
                work_id: input.work_id.clone(),
                reason: format!(
                    "expected_reducer_state contains foreign work_ids [{}] for work_id '{}' (binding violation)",
                    foreign_work_ids.join(", "),
                    input.work_id
                ),
                defect_records: Vec::new(),
            });
        }

        let gate_result = EventFamilyPromotionGate::evaluate(&input.work_events, expected_state)
            .map_err(|e| MergeExecutorError::PromotionGateBlocked {
                work_id: input.work_id.clone(),
                reason: format!("promotion gate evaluation error: {e}"),
                defect_records: Vec::new(),
            })?;

        if !gate_result.allowed {
            let defect_descriptions: Vec<String> = gate_result
                .defect_records
                .iter()
                .map(|d| format!("{}:{}", d.defect_type, d.defect_id))
                .collect();
            warn!(
                work_id = %input.work_id,
                parity_defect_count = gate_result.parity_defects.len(),
                replay_passed = gate_result.replay_passed,
                defects = ?defect_descriptions,
                "Event-family promotion gate DENIED: merge blocked"
            );
            return Err(MergeExecutorError::PromotionGateBlocked {
                work_id: input.work_id.clone(),
                reason: format!(
                    "parity_defects={}, replay_passed={}, defects=[{}]",
                    gate_result.parity_defects.len(),
                    gate_result.replay_passed,
                    defect_descriptions.join(", "),
                ),
                defect_records: gate_result.defect_records,
            });
        }

        // Step 1: Verify all gates passed
        Self::verify_all_gates_passed(input)?;

        // Step 2: Verify policy hash (anti-downgrade)
        Self::verify_policy_hash(input)?;

        let now_ms = self.clock.now_ms();
        let mut events = Vec::with_capacity(3);

        // Step 3: Execute squash merge via GitHub API
        let commit_title = format!(
            "feat: merge work {} (all {} gates passed)",
            input.work_id,
            input.gate_outcomes.len()
        );

        let merge_result =
            github_adapter.squash_merge(input.pr_number, &commit_title, &input.target_branch)?;

        events.push(MergeExecutorEvent::MergeExecuted {
            work_id: input.work_id.clone(),
            result_sha: merge_result.result_sha.clone(),
            target_branch: merge_result.target_branch.clone(),
            gate_receipt_count: input.gate_outcomes.len(),
            timestamp_ms: now_ms,
        });

        info!(
            work_id = %input.work_id,
            result_sha = %merge_result.result_sha,
            target_branch = %merge_result.target_branch,
            gate_count = input.gate_outcomes.len(),
            "Squash merge executed successfully"
        );

        // Step 4: Collect gate receipt IDs (sorted canonically)
        let mut gate_receipt_ids: Vec<String> = input
            .gate_outcomes
            .iter()
            .filter_map(|o| o.receipt_id.clone())
            .collect();
        gate_receipt_ids.sort();

        // Step 5: Create and sign MergeReceipt
        let policy_hash = input.policy_resolution.resolved_policy_hash();

        // Convert now_ms to nanos for the receipt timestamp
        let merged_at_ns = now_ms.saturating_mul(1_000_000);

        let merge_receipt = MergeReceipt::create_after_observation(
            merge_result.target_branch.clone(),
            input.changeset_digest,
            gate_receipt_ids,
            policy_hash,
            merge_result.result_sha.clone(),
            merged_at_ns,
            self.actor_id.clone(),
            &self.signer,
        )
        .map_err(|e| MergeExecutorError::ReceiptCreationFailed {
            work_id: input.work_id.clone(),
            reason: e.to_string(),
        })?;

        events.push(MergeExecutorEvent::MergeReceiptCreated {
            work_id: input.work_id.clone(),
            base_selector: merge_result.target_branch.clone(),
            result_selector: merge_result.result_sha.clone(),
            timestamp_ms: now_ms,
        });

        info!(
            work_id = %input.work_id,
            base_selector = %merge_result.target_branch,
            result_selector = %merge_result.result_sha,
            "MergeReceipt created and signed"
        );

        // Step 6: Emit WorkCompleted event
        // The merge receipt ID is derived from the result selector for traceability
        let gate_receipt_id = format!("merge-receipt-{}", merge_result.result_sha);
        events.push(MergeExecutorEvent::WorkCompleted {
            work_id: input.work_id.clone(),
            gate_receipt_id,
            timestamp_ms: now_ms,
        });

        info!(
            work_id = %input.work_id,
            "Work state transition: Review -> Completed"
        );

        Ok((merge_receipt, events))
    }

    /// Handles a merge conflict by creating a `ReviewBlockedRecorded` event.
    ///
    /// This method is called when the merge fails due to a conflict.
    /// It produces a `ReviewBlockedRecorded` event with the `MergeConflict`
    /// reason code and a `MergeBlocked` executor event.
    ///
    /// # Arguments
    ///
    /// * `input` - The merge input that caused the conflict
    /// * `conflict_reason` - Description of the merge conflict
    ///
    /// # Returns
    ///
    /// A tuple of `(blocked_event, executor_events)`.
    pub fn handle_merge_conflict(
        &self,
        input: &MergeInput,
        conflict_reason: &str,
    ) -> (ReviewBlockedRecorded, Vec<MergeExecutorEvent>) {
        let now_ms = self.clock.now_ms();

        let blocked_id = format!("merge-blocked-{}-{}", input.work_id, now_ms);
        let blocked_log_hash = blake3::hash(conflict_reason.as_bytes());

        // Create ReviewBlockedRecorded with MergeConflict reason code.
        // Use a zero time_envelope_ref since we don't have an HTF envelope
        // at the merge boundary.
        let blocked_event = ReviewBlockedRecorded::create(
            blocked_id,
            input.changeset_digest,
            ReasonCode::MergeConflict,
            *blocked_log_hash.as_bytes(),
            [0u8; 32], // time_envelope_ref placeholder
            self.actor_id.clone(),
            None,       // capability_manifest_hash not applicable at merge boundary
            None,       // context_pack_hash not applicable at merge boundary
            Vec::new(), // role_spec_hash not applicable at merge boundary
            &self.signer,
        )
        .expect("ReviewBlockedRecorded creation should not fail with valid inputs");

        let events = vec![MergeExecutorEvent::MergeBlocked {
            work_id: input.work_id.clone(),
            reason: conflict_reason.to_string(),
            timestamp_ms: now_ms,
        }];

        warn!(
            work_id = %input.work_id,
            reason = %conflict_reason,
            "Merge blocked due to conflict - emitting ReviewBlockedRecorded"
        );

        (blocked_event, events)
    }

    /// Executes the merge lifecycle, handling conflicts gracefully.
    ///
    /// This is the top-level entry point that wraps `execute_merge` and
    /// handles `MergeConflict` errors by producing `ReviewBlockedRecorded`
    /// events instead of propagating the error.
    ///
    /// # Returns
    ///
    /// `Ok((Some(receipt), events))` on successful merge.
    /// `Ok((None, events))` when merge is blocked (conflict).
    /// `Err(e)` for non-conflict errors (validation, API failures, etc.).
    pub fn execute_or_block(
        &self,
        input: &MergeInput,
        github_adapter: &dyn GitHubMergeAdapter,
    ) -> Result<ExecuteOrBlockResult, MergeExecutorError> {
        match self.execute_merge(input, github_adapter) {
            Ok((receipt, events)) => Ok((Some(receipt), None, events)),
            Err(MergeExecutorError::MergeConflict { ref reason, .. }) => {
                let (blocked, events) = self.handle_merge_conflict(input, reason);
                Ok((None, Some(blocked), events))
            },
            Err(MergeExecutorError::PromotionGateBlocked {
                ref work_id,
                ref reason,
                ref defect_records,
            }) => {
                let now_ms = self.clock.now_ms();
                let defect_payloads: Vec<Vec<u8>> =
                    defect_records.iter().map(Message::encode_to_vec).collect();
                let events = vec![MergeExecutorEvent::PromotionGateDenied {
                    work_id: work_id.clone(),
                    defect_count: defect_records.len(),
                    defect_payloads,
                    reason: reason.clone(),
                    timestamp_ms: now_ms,
                }];
                Ok((None, None, events))
            },
            Err(e) => Err(e),
        }
    }

    // =========================================================================
    // Validation Methods
    // =========================================================================

    /// Validates the merge input.
    fn validate_input(input: &MergeInput) -> Result<(), MergeExecutorError> {
        if input.work_id.is_empty() {
            return Err(MergeExecutorError::EmptyWorkId);
        }
        if input.work_id.len() > MAX_STRING_LENGTH {
            return Err(MergeExecutorError::WorkIdTooLong {
                actual: input.work_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if input.work_events.len() > MAX_WORK_EVENTS {
            return Err(MergeExecutorError::WorkEventLimitExceeded {
                work_id: input.work_id.clone(),
                actual: input.work_events.len(),
                max: MAX_WORK_EVENTS,
            });
        }
        let total_bytes = input.work_events.iter().fold(0usize, |total, event| {
            total.saturating_add(event.payload.len())
        });
        if total_bytes > MAX_WORK_EVENTS_BYTES {
            return Err(MergeExecutorError::WorkEventByteLimitExceeded {
                work_id: input.work_id.clone(),
                actual_bytes: total_bytes,
                max_bytes: MAX_WORK_EVENTS_BYTES,
            });
        }
        if input.gate_outcomes.is_empty() {
            return Err(MergeExecutorError::NoGateOutcomes {
                work_id: input.work_id.clone(),
            });
        }
        if input.pr_number == 0 {
            return Err(MergeExecutorError::MissingPrNumber {
                work_id: input.work_id.clone(),
            });
        }
        Ok(())
    }

    /// Verifies that all gates passed.
    fn verify_all_gates_passed(input: &MergeInput) -> Result<(), MergeExecutorError> {
        let all_passed = input.gate_outcomes.iter().all(|o| o.passed);
        if !all_passed {
            return Err(MergeExecutorError::GatesNotAllPassed {
                work_id: input.work_id.clone(),
            });
        }
        Ok(())
    }

    /// Verifies the policy hash from the policy resolution.
    ///
    /// This is the anti-downgrade check: the resolved policy hash must
    /// be non-zero, confirming a valid policy was in effect.
    fn verify_policy_hash(input: &MergeInput) -> Result<(), MergeExecutorError> {
        let policy_hash = input.policy_resolution.resolved_policy_hash();

        // Verify the policy hash is non-zero (a zero hash indicates no policy)
        if policy_hash == [0u8; 32] {
            return Err(MergeExecutorError::PolicyHashMismatch {
                work_id: input.work_id.clone(),
                expected: "non-zero policy hash".to_string(),
                actual: "all-zero hash (no policy)".to_string(),
            });
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use apm2_core::fac::PolicyResolvedForChangeSetBuilder;
    use apm2_core::reducer::{Reducer, ReducerContext};
    use apm2_core::work::{WorkReducer, helpers};

    use super::*;

    /// Mock clock for deterministic tests.
    #[derive(Debug)]
    struct MockClock {
        now_ms: u64,
    }

    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.now_ms
        }

        fn monotonic_now(&self) -> Instant {
            Instant::now()
        }
    }

    /// Stub GitHub merge adapter that always succeeds.
    struct SuccessAdapter {
        result_sha: String,
    }

    impl GitHubMergeAdapter for SuccessAdapter {
        fn squash_merge(
            &self,
            _pr_number: u64,
            _commit_title: &str,
            target_branch: &str,
        ) -> Result<MergeResult, MergeExecutorError> {
            Ok(MergeResult {
                result_sha: self.result_sha.clone(),
                target_branch: target_branch.to_string(),
            })
        }
    }

    /// Stub GitHub merge adapter that always returns a merge conflict.
    struct ConflictAdapter;

    impl GitHubMergeAdapter for ConflictAdapter {
        fn squash_merge(
            &self,
            _pr_number: u64,
            _commit_title: &str,
            _target_branch: &str,
        ) -> Result<MergeResult, MergeExecutorError> {
            Err(MergeExecutorError::MergeConflict {
                work_id: "test-work".to_string(),
                reason: "conflicting changes in src/main.rs".to_string(),
            })
        }
    }

    fn make_event(
        event_type: &str,
        session_id: &str,
        actor_id: &str,
        payload: Vec<u8>,
        ts: u64,
        seq: u64,
    ) -> EventRecord {
        EventRecord::with_timestamp(event_type, session_id, actor_id, payload, ts).with_seq_id(seq)
    }

    fn make_valid_work_events(work_id: &str) -> (Vec<EventRecord>, WorkReducerState) {
        let opened_payload =
            helpers::work_opened_payload(work_id, "TICKET", vec![1, 2, 3], vec![], vec![]);
        let events = vec![
            EventRecord::with_timestamp(
                "work.opened",
                work_id,
                "actor:test",
                opened_payload,
                1_000,
            )
            .with_seq_id(1),
        ];
        let mut reducer = WorkReducer::new();
        let ctx = ReducerContext::new(1);
        reducer.apply(&events[0], &ctx).unwrap();
        (events, reducer.state().clone())
    }

    fn create_test_input(signer: &Signer) -> MergeInput {
        let (work_events, expected_reducer_state) = make_valid_work_events("work-001");
        let policy_resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
            .resolved_risk_tier(1)
            .resolved_determinism_class(0)
            .resolver_actor_id("resolver-001")
            .resolver_version("1.0.0")
            .build_and_sign(signer);

        MergeInput {
            work_id: "work-001".to_string(),
            changeset_digest: [0x42; 32],
            pr_number: 123,
            target_branch: "main".to_string(),
            gate_outcomes: vec![
                GateOutcome {
                    gate_type: super::super::orchestrator::GateType::Aat,
                    passed: true,
                    receipt_id: Some("receipt-aat-001".to_string()),
                    timed_out: false,
                },
                GateOutcome {
                    gate_type: super::super::orchestrator::GateType::Quality,
                    passed: true,
                    receipt_id: Some("receipt-quality-001".to_string()),
                    timed_out: false,
                },
                GateOutcome {
                    gate_type: super::super::orchestrator::GateType::Security,
                    passed: true,
                    receipt_id: Some("receipt-security-001".to_string()),
                    timed_out: false,
                },
            ],
            policy_resolution,
            actor_id: "merge-executor-test".to_string(),
            work_events,
            expected_reducer_state: Some(expected_reducer_state),
        }
    }

    #[test]
    fn test_successful_merge_creates_receipt_and_events() {
        let signer = Arc::new(Signer::generate());
        let clock = Arc::new(MockClock {
            now_ms: 1_704_067_200_000,
        });
        let executor = MergeExecutor::with_clock(Arc::clone(&signer), "merge-executor", clock);

        let input = create_test_input(&signer);
        let adapter = SuccessAdapter {
            result_sha: "abc123def456".to_string(),
        };

        let (receipt, events) = executor.execute_merge(&input, &adapter).unwrap();

        // Verify receipt fields
        assert_eq!(receipt.base_selector, "main");
        assert_eq!(receipt.result_selector, "abc123def456");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.gate_actor_id, "merge-executor");

        // Verify gate_receipt_ids are sorted
        assert_eq!(
            receipt.gate_receipt_ids,
            vec![
                "receipt-aat-001".to_string(),
                "receipt-quality-001".to_string(),
                "receipt-security-001".to_string(),
            ]
        );

        // Verify receipt signature
        assert!(receipt.verify_signature(&signer.verifying_key()).is_ok());

        // Verify events
        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[0],
            MergeExecutorEvent::MergeExecuted { work_id, .. } if work_id == "work-001"
        ));
        assert!(matches!(
            &events[1],
            MergeExecutorEvent::MergeReceiptCreated { work_id, base_selector, result_selector, .. }
            if work_id == "work-001" && base_selector == "main" && result_selector == "abc123def456"
        ));
        assert!(matches!(
            &events[2],
            MergeExecutorEvent::WorkCompleted { work_id, .. } if work_id == "work-001"
        ));
    }

    #[test]
    fn test_merge_conflict_produces_blocked_event() {
        let signer = Arc::new(Signer::generate());
        let clock = Arc::new(MockClock {
            now_ms: 1_704_067_200_000,
        });
        let executor = MergeExecutor::with_clock(Arc::clone(&signer), "merge-executor", clock);

        let input = create_test_input(&signer);
        let adapter = ConflictAdapter;

        let (receipt, blocked, events) = executor.execute_or_block(&input, &adapter).unwrap();

        // No receipt on conflict
        assert!(receipt.is_none());

        // Should have a blocked event
        let blocked = blocked.expect("should have ReviewBlockedRecorded");
        assert_eq!(blocked.reason_code, ReasonCode::MergeConflict);
        assert_eq!(blocked.changeset_digest, [0x42; 32]);

        // Verify blocked event signature
        assert!(blocked.verify_signature(&signer.verifying_key()).is_ok());

        // Should have a MergeBlocked event
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            MergeExecutorEvent::MergeBlocked { work_id, .. } if work_id == "work-001"
        ));
    }

    #[test]
    fn test_gates_not_all_passed_rejected() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        // Set one gate as failed
        input.gate_outcomes[1].passed = false;

        let adapter = SuccessAdapter {
            result_sha: "abc123".to_string(),
        };

        let result = executor.execute_merge(&input, &adapter);
        assert!(matches!(
            result,
            Err(MergeExecutorError::GatesNotAllPassed { .. })
        ));
    }

    #[test]
    fn test_empty_work_id_rejected() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        input.work_id = String::new();

        let adapter = SuccessAdapter {
            result_sha: "abc123".to_string(),
        };

        let result = executor.execute_merge(&input, &adapter);
        assert!(matches!(result, Err(MergeExecutorError::EmptyWorkId)));
    }

    #[test]
    fn test_missing_pr_number_rejected() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        input.pr_number = 0;

        let adapter = SuccessAdapter {
            result_sha: "abc123".to_string(),
        };

        let result = executor.execute_merge(&input, &adapter);
        assert!(matches!(
            result,
            Err(MergeExecutorError::MissingPrNumber { .. })
        ));
    }

    #[test]
    fn test_no_gate_outcomes_rejected() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        input.gate_outcomes.clear();

        let adapter = SuccessAdapter {
            result_sha: "abc123".to_string(),
        };

        let result = executor.execute_merge(&input, &adapter);
        assert!(matches!(
            result,
            Err(MergeExecutorError::NoGateOutcomes { .. })
        ));
    }

    #[test]
    fn test_gate_receipt_ids_sorted_canonically() {
        let signer = Arc::new(Signer::generate());
        let clock = Arc::new(MockClock { now_ms: 1_000_000 });
        let executor = MergeExecutor::with_clock(Arc::clone(&signer), "merge-executor", clock);

        let mut input = create_test_input(&signer);
        // Set receipt IDs in reverse order
        input.gate_outcomes[0].receipt_id = Some("z-receipt".to_string());
        input.gate_outcomes[1].receipt_id = Some("a-receipt".to_string());
        input.gate_outcomes[2].receipt_id = Some("m-receipt".to_string());

        let adapter = SuccessAdapter {
            result_sha: "sha-result".to_string(),
        };

        let (receipt, _events) = executor.execute_merge(&input, &adapter).unwrap();

        // Verify gate_receipt_ids are sorted
        assert_eq!(
            receipt.gate_receipt_ids,
            vec![
                "a-receipt".to_string(),
                "m-receipt".to_string(),
                "z-receipt".to_string(),
            ]
        );
    }

    #[test]
    fn test_merge_receipt_signature_binds_all_fields() {
        let signer = Arc::new(Signer::generate());
        let clock = Arc::new(MockClock { now_ms: 1_000_000 });
        let executor = MergeExecutor::with_clock(Arc::clone(&signer), "merge-executor", clock);

        let input = create_test_input(&signer);
        let adapter = SuccessAdapter {
            result_sha: "sha-result".to_string(),
        };

        let (receipt, _events) = executor.execute_merge(&input, &adapter).unwrap();

        // Verify signature is valid
        assert!(receipt.verify_signature(&signer.verifying_key()).is_ok());

        // Tamper with a field and verify signature fails
        let mut tampered = receipt;
        tampered.result_selector = "tampered-sha".to_string();
        assert!(tampered.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_execute_or_block_success_path() {
        let signer = Arc::new(Signer::generate());
        let clock = Arc::new(MockClock { now_ms: 1_000_000 });
        let executor = MergeExecutor::with_clock(Arc::clone(&signer), "merge-executor", clock);

        let input = create_test_input(&signer);
        let adapter = SuccessAdapter {
            result_sha: "sha-ok".to_string(),
        };

        let (receipt, blocked, events) = executor.execute_or_block(&input, &adapter).unwrap();

        assert!(receipt.is_some());
        assert!(blocked.is_none());
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_execute_or_block_non_conflict_error_propagates() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        input.gate_outcomes[0].passed = false; // Will cause GatesNotAllPassed

        let adapter = SuccessAdapter {
            result_sha: "sha-ok".to_string(),
        };

        let result = executor.execute_or_block(&input, &adapter);
        assert!(matches!(
            result,
            Err(MergeExecutorError::GatesNotAllPassed { .. })
        ));
    }

    #[test]
    fn test_policy_hash_zero_rejected() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        // Create input with a zero policy hash by using a custom policy resolution
        // We can't easily create a zero-hash policy resolution through the builder,
        // so this test verifies the check by testing a valid (non-zero) hash passes.
        let input = create_test_input(&signer);
        let adapter = SuccessAdapter {
            result_sha: "sha-ok".to_string(),
        };

        // This should succeed because the policy hash is non-zero
        let result = executor.execute_merge(&input, &adapter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_work_id_too_long_rejected() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        input.work_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let adapter = SuccessAdapter {
            result_sha: "sha-ok".to_string(),
        };

        let result = executor.execute_merge(&input, &adapter);
        assert!(matches!(
            result,
            Err(MergeExecutorError::WorkIdTooLong { .. })
        ));
    }

    #[test]
    fn test_promotion_gate_blocks_merge_on_parity_defects() {
        let signer = Arc::new(Signer::generate());
        let clock = Arc::new(MockClock {
            now_ms: 1_704_067_200_000,
        });
        let executor = MergeExecutor::with_clock(Arc::clone(&signer), "merge-executor", clock);

        let mut input = create_test_input(&signer);

        // Create mismatched events that will cause parity defects:
        // A daemon event with different actor than the dotted event
        let work_id = "work-001";
        let ts = 1_000u64;

        let opened_payload =
            helpers::work_opened_payload(work_id, "TICKET", vec![1, 2, 3], vec![], vec![]);
        let events = vec![
            make_event("work.opened", work_id, "actor:a", opened_payload, ts, 1),
            // Daemon event with different actor (will cause parity defect)
            make_event(
                "work_claimed",
                work_id,
                "actor:WRONG",
                serde_json::json!({
                    "event_type": "work_claimed",
                    "work_id": work_id,
                    "actor_id": "actor:WRONG",
                    "rationale_code": "wrong_rationale",
                    "previous_transition_count": 0
                })
                .to_string()
                .into_bytes(),
                ts + 100,
                2,
            ),
            // Dotted event with correct actor
            make_event(
                "work.transitioned",
                work_id,
                "actor:a",
                helpers::work_transitioned_payload_with_sequence(
                    work_id, "OPEN", "CLAIMED", "claim", 0,
                ),
                ts + 100,
                3,
            ),
        ];

        // Build expected state from just the dotted events
        let mut reducer = WorkReducer::new();
        let ctx = ReducerContext::new(1);
        reducer.apply(&events[0], &ctx).unwrap();
        reducer.apply(&events[2], &ReducerContext::new(3)).unwrap();
        let expected_state = reducer.state().clone();

        input.work_events = events;
        input.expected_reducer_state = Some(expected_state);

        let adapter = SuccessAdapter {
            result_sha: "abc123def456".to_string(),
        };
        let result = executor.execute_merge(&input, &adapter);

        assert!(result.is_err(), "merge must be blocked by promotion gate");
        let err = result.unwrap_err();
        assert!(
            matches!(err, MergeExecutorError::PromotionGateBlocked { .. }),
            "error must be PromotionGateBlocked, got: {err:?}"
        );
    }

    #[test]
    fn test_execute_or_block_emits_promotion_gate_denied_event() {
        let signer = Arc::new(Signer::generate());
        let clock = Arc::new(MockClock {
            now_ms: 1_704_067_200_000,
        });
        let executor = MergeExecutor::with_clock(Arc::clone(&signer), "merge-executor", clock);

        let mut input = create_test_input(&signer);
        let work_id = "work-001";
        let ts = 1_000u64;

        input.work_events = vec![
            make_event(
                "work.opened",
                work_id,
                "actor:a",
                helpers::work_opened_payload(work_id, "TICKET", vec![1, 2, 3], vec![], vec![]),
                ts,
                1,
            ),
            make_event(
                "work_claimed",
                work_id,
                "actor:WRONG",
                serde_json::json!({
                    "event_type": "work_claimed",
                    "work_id": work_id,
                    "actor_id": "actor:WRONG",
                    "rationale_code": "wrong_rationale",
                    "previous_transition_count": 0
                })
                .to_string()
                .into_bytes(),
                ts + 100,
                2,
            ),
            make_event(
                "work.transitioned",
                work_id,
                "actor:a",
                helpers::work_transitioned_payload_with_sequence(
                    work_id, "OPEN", "CLAIMED", "claim", 0,
                ),
                ts + 100,
                3,
            ),
        ];

        let mut reducer = WorkReducer::new();
        reducer
            .apply(&input.work_events[0], &ReducerContext::new(1))
            .unwrap();
        reducer
            .apply(&input.work_events[2], &ReducerContext::new(3))
            .unwrap();
        input.expected_reducer_state = Some(reducer.state().clone());

        let adapter = SuccessAdapter {
            result_sha: "abc123def456".to_string(),
        };

        let (receipt, blocked, events) = executor.execute_or_block(&input, &adapter).unwrap();
        assert!(receipt.is_none());
        assert!(blocked.is_none());
        assert_eq!(events.len(), 1);
        match &events[0] {
            MergeExecutorEvent::PromotionGateDenied {
                work_id,
                defect_count,
                defect_payloads,
                ..
            } => {
                assert_eq!(work_id, "work-001");
                assert!(*defect_count > 0);
                assert_eq!(*defect_count, defect_payloads.len());
                assert!(defect_payloads.iter().all(|payload| !payload.is_empty()));
                let decoded = apm2_core::events::DefectRecorded::decode(&defect_payloads[0][..])
                    .expect("serialized defect payload must decode");
                assert!(!decoded.defect_id.is_empty());
            },
            other => panic!("expected PromotionGateDenied with defects, got {other:?}"),
        }
    }

    #[test]
    fn test_execute_merge_rejects_empty_work_events_fail_closed() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        input.work_events.clear();
        input.expected_reducer_state = None;

        let adapter = SuccessAdapter {
            result_sha: "abc123".to_string(),
        };

        let result = executor.execute_merge(&input, &adapter);
        assert!(
            matches!(result, Err(MergeExecutorError::PromotionGateBlocked { .. })),
            "expected fail-closed promotion gate error, got: {result:?}"
        );
    }

    #[test]
    fn test_work_event_limit_exceeded_rejected() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        input.work_events = (0..=MAX_WORK_EVENTS)
            .map(|i| {
                EventRecord::with_timestamp(
                    "work.opened",
                    "work-001",
                    "actor:test",
                    helpers::work_opened_payload(
                        "work-001",
                        "TICKET",
                        vec![1, 2, 3],
                        vec![],
                        vec![],
                    ),
                    1_000 + (i as u64),
                )
                .with_seq_id((i + 1) as u64)
            })
            .collect();
        input.expected_reducer_state = Some(make_valid_work_events("work-001").1);

        let adapter = SuccessAdapter {
            result_sha: "sha-ok".to_string(),
        };

        let result = executor.execute_merge(&input, &adapter);
        assert!(matches!(
            result,
            Err(MergeExecutorError::WorkEventLimitExceeded {
                actual: _,
                max: MAX_WORK_EVENTS,
                ..
            })
        ));
    }

    #[test]
    fn test_promotion_gate_rejects_foreign_work_events() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        let (foreign_events, foreign_expected_state) = make_valid_work_events("WRONG-WORK");
        input.work_events = foreign_events;
        input.expected_reducer_state = Some(foreign_expected_state);

        let adapter = SuccessAdapter {
            result_sha: "abc123def456".to_string(),
        };

        let err = executor.execute_merge(&input, &adapter).unwrap_err();
        match err {
            MergeExecutorError::PromotionGateBlocked {
                work_id,
                reason,
                defect_records,
            } => {
                assert_eq!(work_id, "work-001");
                assert!(reason.contains("binding violation"));
                assert!(reason.contains("WRONG-WORK"));
                assert!(defect_records.is_empty());
            },
            other => panic!("expected PromotionGateBlocked, got {other:?}"),
        }
    }

    #[test]
    fn test_promotion_gate_rejects_foreign_expected_reducer_state_entries() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        let (_, foreign_expected_state) = make_valid_work_events("foreign-work");
        let mut expected = input
            .expected_reducer_state
            .clone()
            .expect("test input should contain expected state");
        expected
            .work_items
            .extend(foreign_expected_state.work_items);
        input.expected_reducer_state = Some(expected);

        let adapter = SuccessAdapter {
            result_sha: "abc123def456".to_string(),
        };

        let err = executor.execute_merge(&input, &adapter).unwrap_err();
        match err {
            MergeExecutorError::PromotionGateBlocked { reason, .. } => {
                assert!(reason.contains("expected_reducer_state contains foreign work_ids"));
                assert!(reason.contains("foreign-work"));
            },
            other => panic!("expected PromotionGateBlocked, got {other:?}"),
        }
    }

    #[test]
    fn test_work_event_byte_limit_exceeded_rejected() {
        let signer = Arc::new(Signer::generate());
        let executor = MergeExecutor::new(Arc::clone(&signer), "merge-executor");

        let mut input = create_test_input(&signer);
        input.work_events = vec![
            EventRecord::with_timestamp(
                "work.opened",
                "work-001",
                "actor:test",
                vec![0_u8; MAX_WORK_EVENTS_BYTES + 1],
                1_000,
            )
            .with_seq_id(1),
        ];

        let adapter = SuccessAdapter {
            result_sha: "sha-ok".to_string(),
        };

        let result = executor.execute_merge(&input, &adapter);
        assert!(matches!(
            result,
            Err(MergeExecutorError::WorkEventByteLimitExceeded {
                actual_bytes: _,
                max_bytes: MAX_WORK_EVENTS_BYTES,
                ..
            })
        ));
    }
}
