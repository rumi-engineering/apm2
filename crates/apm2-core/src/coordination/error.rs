//! Error types for coordination operations.
//!
//! This module defines error types specific to the coordination controller
//! and its operations. These errors are distinct from the state-level
//! [`CoordinationError`](super::state::CoordinationError) which handles
//! validation errors during state construction.
//!
//! # Error Categories
//!
//! - **Configuration errors**: Invalid controller setup
//! - **Work freshness errors**: Stale work detection
//! - **Session spawn errors**: Session creation failures
//! - **Observation errors**: Session termination monitoring failures
//!
//! # References
//!
//! - RFC-0032::REQ-0050: Implement `CoordinationController` serial execution loop
//! - AD-COORD-006: Work freshness validation before spawn

use std::fmt;

/// Error type for coordination controller operations.
///
/// These errors are returned by
/// [`CoordinationController`](super::controller::CoordinationController)
/// methods during coordination execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerError {
    /// Work queue is empty.
    ///
    /// Per AD-COORD-008: A coordination must have at least one work item.
    EmptyWorkQueue,

    /// Work queue size exceeds the maximum allowed limit.
    ///
    /// Per AD-COORD-008: Reject if `work_ids.len() > max_work_queue_size`.
    WorkQueueSizeExceeded {
        /// The actual size that was provided.
        actual: usize,
        /// The maximum allowed size.
        max: usize,
    },

    /// Budget parameters are invalid.
    ///
    /// Per TB-COORD-004: `max_episodes` and `max_duration_ms` must be positive.
    InvalidBudget {
        /// Description of which budget field is invalid.
        field: &'static str,
    },

    /// Work item not found in work state.
    ///
    /// The work ID specified in the queue does not exist in the work reducer.
    WorkNotFound {
        /// The missing work ID.
        work_id: String,
    },

    /// Work item is not claimable.
    ///
    /// The work is not in a state that allows claiming (e.g., already
    /// completed).
    WorkNotClaimable {
        /// The work ID that is not claimable.
        work_id: String,
        /// The current state of the work item.
        current_state: String,
    },

    /// Work state changed since freshness check.
    ///
    /// Per AD-COORD-006: Work freshness is checked at a known ledger sequence.
    /// If the work state changes between check and spawn, the spawn must be
    /// aborted.
    WorkFreshnessViolation {
        /// The work ID that became stale.
        work_id: String,
        /// The sequence ID at which freshness was verified.
        checked_seq_id: u64,
        /// The current sequence ID showing the change.
        current_seq_id: u64,
    },

    /// Session spawn failed.
    ///
    /// The session could not be created for the work item.
    SessionSpawnFailed {
        /// The work ID for which session spawn failed.
        work_id: String,
        /// Description of the failure.
        reason: String,
    },

    /// Session observation timed out.
    ///
    /// The session did not terminate within the expected time.
    SessionObservationTimeout {
        /// The session ID that timed out.
        session_id: String,
    },

    /// Coordination not found.
    ///
    /// The coordination ID does not exist in state.
    CoordinationNotFound {
        /// The missing coordination ID.
        coordination_id: String,
    },

    /// Coordination already exists.
    ///
    /// Attempting to start a coordination with an ID that already exists.
    CoordinationAlreadyExists {
        /// The duplicate coordination ID.
        coordination_id: String,
    },

    /// Coordination is in terminal state.
    ///
    /// Cannot continue operations on a completed or aborted coordination.
    CoordinationTerminal {
        /// The coordination ID in terminal state.
        coordination_id: String,
    },

    /// Session already bound.
    ///
    /// Attempting to bind a session that is already bound to a work item.
    SessionAlreadyBound {
        /// The session ID that is already bound.
        session_id: String,
    },

    /// Ledger append failed.
    ///
    /// Failed to append an event to the ledger.
    LedgerAppendFailed {
        /// Description of the failure.
        reason: String,
    },

    /// Internal error.
    ///
    /// An unexpected internal error occurred.
    Internal {
        /// Description of the error.
        message: String,
    },

    /// Tick rate mismatch.
    ///
    /// The provided `HtfTick` has a different tick rate than the configured
    /// budget. This would cause temporal confusion where duration calculations
    /// produce incorrect results.
    ///
    /// Per RFC-0016::REQ-0003: All tick values within a coordination must use the same
    /// tick rate as the budget for replay-stable duration tracking.
    InvalidTickRate {
        /// The expected tick rate from the budget configuration.
        expected_hz: u64,
        /// The actual tick rate from the provided `HtfTick`.
        actual_hz: u64,
    },

    /// Clock regression detected.
    ///
    /// The current tick value is less than the start tick, indicating a
    /// clock regression or discontinuity. Per fail-closed policy, this
    /// error must be handled rather than silently ignored.
    ///
    /// Per RFC-0016::REQ-0003: Clock regressions are detected and reported as errors
    /// to prevent coordination from continuing indefinitely.
    ClockRegression {
        /// The tick value when coordination started.
        start_tick: u64,
        /// The current tick value that is less than start.
        current_tick: u64,
    },
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWorkQueue => {
                write!(f, "work queue is empty")
            },
            Self::WorkQueueSizeExceeded { actual, max } => {
                write!(f, "work queue size {actual} exceeds maximum allowed {max}")
            },
            Self::InvalidBudget { field } => {
                write!(
                    f,
                    "budget field '{field}' must be a positive (non-zero) value"
                )
            },
            Self::WorkNotFound { work_id } => {
                write!(f, "work item not found: {work_id}")
            },
            Self::WorkNotClaimable {
                work_id,
                current_state,
            } => {
                write!(
                    f,
                    "work item '{work_id}' is not claimable (current state: {current_state})"
                )
            },
            Self::WorkFreshnessViolation {
                work_id,
                checked_seq_id,
                current_seq_id,
            } => {
                write!(
                    f,
                    "work item '{work_id}' state changed since freshness check \
                     (checked at seq {checked_seq_id}, now at seq {current_seq_id})"
                )
            },
            Self::SessionSpawnFailed { work_id, reason } => {
                write!(f, "failed to spawn session for work '{work_id}': {reason}")
            },
            Self::SessionObservationTimeout { session_id } => {
                write!(f, "session observation timed out: {session_id}")
            },
            Self::CoordinationNotFound { coordination_id } => {
                write!(f, "coordination not found: {coordination_id}")
            },
            Self::CoordinationAlreadyExists { coordination_id } => {
                write!(f, "coordination already exists: {coordination_id}")
            },
            Self::CoordinationTerminal { coordination_id } => {
                write!(f, "coordination is in terminal state: {coordination_id}")
            },
            Self::SessionAlreadyBound { session_id } => {
                write!(f, "session is already bound: {session_id}")
            },
            Self::LedgerAppendFailed { reason } => {
                write!(f, "failed to append to ledger: {reason}")
            },
            Self::Internal { message } => {
                write!(f, "internal error: {message}")
            },
            Self::InvalidTickRate {
                expected_hz,
                actual_hz,
            } => {
                write!(
                    f,
                    "tick rate mismatch: expected {expected_hz} Hz, got {actual_hz} Hz"
                )
            },
            Self::ClockRegression {
                start_tick,
                current_tick,
            } => {
                write!(
                    f,
                    "clock regression detected: current tick {current_tick} < start tick {start_tick}"
                )
            },
        }
    }
}

impl std::error::Error for ControllerError {}

/// Result type for controller operations.
pub type ControllerResult<T> = Result<T, ControllerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn tck_00150_error_display() {
        let errors = vec![
            (ControllerError::EmptyWorkQueue, "work queue is empty"),
            (
                ControllerError::WorkQueueSizeExceeded {
                    actual: 1001,
                    max: 1000,
                },
                "work queue size 1001 exceeds maximum allowed 1000",
            ),
            (
                ControllerError::InvalidBudget {
                    field: "max_episodes",
                },
                "budget field 'max_episodes' must be a positive (non-zero) value",
            ),
            (
                ControllerError::WorkNotFound {
                    work_id: "work-123".to_string(),
                },
                "work item not found: work-123",
            ),
            (
                ControllerError::WorkNotClaimable {
                    work_id: "work-123".to_string(),
                    current_state: "COMPLETED".to_string(),
                },
                "work item 'work-123' is not claimable (current state: COMPLETED)",
            ),
            (
                ControllerError::WorkFreshnessViolation {
                    work_id: "work-123".to_string(),
                    checked_seq_id: 100,
                    current_seq_id: 105,
                },
                "work item 'work-123' state changed since freshness check \
                 (checked at seq 100, now at seq 105)",
            ),
            (
                ControllerError::SessionSpawnFailed {
                    work_id: "work-123".to_string(),
                    reason: "adapter error".to_string(),
                },
                "failed to spawn session for work 'work-123': adapter error",
            ),
            (
                ControllerError::SessionObservationTimeout {
                    session_id: "session-456".to_string(),
                },
                "session observation timed out: session-456",
            ),
            (
                ControllerError::CoordinationNotFound {
                    coordination_id: "coord-789".to_string(),
                },
                "coordination not found: coord-789",
            ),
            (
                ControllerError::CoordinationAlreadyExists {
                    coordination_id: "coord-789".to_string(),
                },
                "coordination already exists: coord-789",
            ),
            (
                ControllerError::CoordinationTerminal {
                    coordination_id: "coord-789".to_string(),
                },
                "coordination is in terminal state: coord-789",
            ),
            (
                ControllerError::SessionAlreadyBound {
                    session_id: "session-456".to_string(),
                },
                "session is already bound: session-456",
            ),
            (
                ControllerError::LedgerAppendFailed {
                    reason: "disk full".to_string(),
                },
                "failed to append to ledger: disk full",
            ),
            (
                ControllerError::Internal {
                    message: "unexpected state".to_string(),
                },
                "internal error: unexpected state",
            ),
            (
                ControllerError::InvalidTickRate {
                    expected_hz: 1_000_000,
                    actual_hz: 1_000_000_000,
                },
                "tick rate mismatch: expected 1000000 Hz, got 1000000000 Hz",
            ),
            (
                ControllerError::ClockRegression {
                    start_tick: 1000,
                    current_tick: 500,
                },
                "clock regression detected: current tick 500 < start tick 1000",
            ),
        ];

        for (error, expected) in errors {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn tck_00150_error_debug() {
        let error = ControllerError::EmptyWorkQueue;
        let debug_str = format!("{error:?}");
        assert!(debug_str.contains("EmptyWorkQueue"));
    }

    #[test]
    fn tck_00150_error_clone() {
        let error = ControllerError::WorkNotFound {
            work_id: "work-123".to_string(),
        };
        let cloned = error.clone();
        assert_eq!(error, cloned);
    }

    #[test]
    fn tck_00150_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ControllerError>();
    }
}
