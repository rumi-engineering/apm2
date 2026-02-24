//! Work module error types.

use thiserror::Error;

use super::state::WorkState;

/// Errors that can occur during work lifecycle operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WorkError {
    /// Work item already exists.
    #[error("work already exists: {work_id}")]
    WorkAlreadyExists {
        /// The work ID that already exists.
        work_id: String,
    },

    /// Work item not found.
    #[error("work not found: {work_id}")]
    WorkNotFound {
        /// The work ID that was not found.
        work_id: String,
    },

    /// Invalid state transition attempted.
    #[error("invalid transition from {from_state} via {event_type}")]
    InvalidTransition {
        /// The current state.
        from_state: String,
        /// The event that triggered the invalid transition.
        event_type: String,
    },

    /// State transition not allowed by the state machine.
    #[error("transition from {from_state} to {to_state} is not allowed")]
    TransitionNotAllowed {
        /// The current state.
        from_state: WorkState,
        /// The attempted target state.
        to_state: WorkState,
    },

    /// Attempted to complete work without evidence.
    #[error("cannot complete work {work_id} without evidence")]
    CompletionWithoutEvidence {
        /// The work ID.
        work_id: String,
    },

    /// Merge receipt ID placed into `gate_receipt_id` field.
    ///
    /// The `gate_receipt_id` field is reserved for gate-level receipts.
    /// Merge receipts must be stored in the dedicated `merge_receipt_id`
    /// field to avoid semantic confusion.
    ///
    /// # Security (INV-0113)
    ///
    /// This is the fail-closed gate for domain separation: any value in
    /// `gate_receipt_id` that structurally matches a merge receipt prefix
    /// is rejected outright.
    #[error("gate_receipt_id contains a merge receipt identifier for work_id {work_id}: '{value}'")]
    MergeReceiptInGateReceiptField {
        /// The work ID.
        work_id: String,
        /// The invalid value that was placed in `gate_receipt_id`.
        value: String,
    },

    /// Invalid `merge_receipt_id` value — does not match the required
    /// `merge-receipt-` prefix.
    ///
    /// # Security (INV-0114)
    ///
    /// The `merge_receipt_id` field MUST start with `merge-receipt-` when
    /// non-empty.  This positive allowlist prevents gate receipt identifiers
    /// from being injected into the merge receipt field, enforcing
    /// bidirectional domain separation together with
    /// [`MergeReceiptInGateReceiptField`](Self::MergeReceiptInGateReceiptField).
    #[error(
        "merge_receipt_id for work_id {work_id} does not start with 'merge-receipt-': '{value}'"
    )]
    InvalidMergeReceiptId {
        /// The work ID.
        work_id: String,
        /// The invalid value that was placed in `merge_receipt_id`.
        value: String,
    },

    /// Invalid work state string.
    #[error("invalid work state: {value}")]
    InvalidWorkState {
        /// The invalid state string.
        value: String,
    },

    /// Invalid work type string.
    #[error("invalid work type: {value}")]
    InvalidWorkType {
        /// The invalid type string.
        value: String,
    },

    /// Sequence mismatch during transition (replay protection).
    #[error(
        "sequence mismatch for work {work_id}: expected transition_count {expected}, event implies {actual}"
    )]
    SequenceMismatch {
        /// The work ID.
        work_id: String,
        /// Expected transition count.
        expected: u32,
        /// Actual count implied by the event.
        actual: u32,
    },

    /// Protocol buffer decode error.
    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    /// PR association only allowed from `Claimed` or `InProgress` state.
    ///
    /// # Security
    ///
    /// Restricting PR association to pre-CI states (`Claimed`/`InProgress`)
    /// prevents an agent from bypassing CI gating by associating a work item
    /// with a PR that has already passed CI while the work is in
    /// `CiPending` or `Blocked` state.
    #[error(
        "PR association only allowed from Claimed/InProgress states, work {work_id} is in {current_state}"
    )]
    PrAssociationNotAllowed {
        /// The work ID.
        work_id: String,
        /// The current state of the work item.
        current_state: WorkState,
    },

    /// PR number already associated with another active work item.
    ///
    /// # Security
    ///
    /// Enforces uniqueness of PR numbers across active work items to prevent
    /// CI result confusion (contract CTR-CIQ002).
    #[error("PR number {pr_number} is already associated with active work item {existing_work_id}")]
    PrNumberAlreadyAssociated {
        /// The PR number that is already in use.
        pr_number: u64,
        /// The work ID that already has this PR number.
        existing_work_id: String,
    },

    /// CI-gated transition requires authorized rationale code.
    ///
    /// # Security
    ///
    /// Transitions from CI-gated states (`CiPending`) can only be performed
    /// by the CI event processor using specific rationale codes (`ci_passed`
    /// or `ci_failed`). This prevents agents from bypassing CI gating by
    /// directly emitting `WorkTransitioned` events.
    #[error(
        "CI-gated transition from {from_state} requires authorized rationale code, got '{rationale_code}'"
    )]
    CiGatedTransitionUnauthorized {
        /// The current (CI-gated) state.
        from_state: WorkState,
        /// The attempted target state.
        to_state: WorkState,
        /// The rationale code provided.
        rationale_code: String,
    },

    /// CI-gated transition requires authorized actor.
    ///
    /// # Security
    ///
    /// Transitions from CI-gated states (`CiPending`) can only be performed
    /// by the designated CI system actor. This prevents arbitrary agents from
    /// bypassing CI gating by emitting `WorkTransitioned` events with the
    /// correct rationale code but an unauthorized actor identity.
    #[error(
        "CI-gated transition from {from_state} requires authorized CI actor, got actor '{actor_id}'"
    )]
    CiGatedTransitionUnauthorizedActor {
        /// The current (CI-gated) state.
        from_state: WorkState,
        /// The actor ID that attempted the transition.
        actor_id: String,
    },
}
