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
}
