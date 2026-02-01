//! Session lifecycle error types.

use std::fmt;

use thiserror::Error;

/// Errors that can occur during session lifecycle operations.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Attempted an invalid state transition.
    #[error("invalid transition from {from_state} via {event_type}")]
    InvalidTransition {
        /// The current state name.
        from_state: String,
        /// The event type that triggered the transition.
        event_type: String,
    },

    /// Session not found for the given ID.
    #[error("session not found: {session_id}")]
    SessionNotFound {
        /// The session ID that was not found.
        session_id: String,
    },

    /// Session already exists with the given ID.
    #[error("session already exists: {session_id}")]
    SessionAlreadyExists {
        /// The session ID that already exists.
        session_id: String,
    },

    /// Restart attempt is not monotonically increasing.
    ///
    /// When restarting a session, the new `restart_attempt` must be strictly
    /// greater than the previous attempt to prevent replay attacks.
    #[error(
        "restart attempt not monotonic for {session_id}: previous={previous_attempt}, new={new_attempt}"
    )]
    RestartAttemptNotMonotonic {
        /// The session ID.
        session_id: String,
        /// The previous restart attempt number.
        previous_attempt: u32,
        /// The new restart attempt number (which is <= previous).
        new_attempt: u32,
    },

    /// Failed to decode protobuf message.
    #[error("decode error: {0}")]
    DecodeError(#[from] prost::DecodeError),

    /// Attempted to restart a session while still quarantined.
    ///
    /// When a session is quarantined, a restart is only allowed after the
    /// quarantine period has expired. This error is returned when a
    /// `SessionStarted` event is received for a quarantined session
    /// before the quarantine has expired.
    ///
    /// # SEC-HTF-003: Tick-Based Expiry (RFC-0016)
    ///
    /// When tick-based quarantine timing is available, expiry is checked
    /// using monotonic ticks which are immune to wall-clock manipulation.
    /// If a tick rate mismatch is detected, the quarantine is considered
    /// NOT expired (fail-closed behavior).
    #[error(
        "session {session_id} is still quarantined (remaining_ticks: {remaining_ticks:?}, expires_at: {expires_at_ns})"
    )]
    QuarantineNotExpired {
        /// The session ID.
        session_id: String,
        /// Wall-clock expiry timestamp (observational only).
        expires_at_ns: u64,
        /// Remaining ticks if tick-based timing is available, None for legacy.
        remaining_ticks: Option<u64>,
    },

    /// Attempted to restart a tick-based quarantined session without a valid
    /// time envelope reference.
    ///
    /// # SEC-HTF-003: Fail-Closed Behavior (RFC-0016)
    ///
    /// When a session has a tick-based quarantine, the restart event MUST
    /// include a `time_envelope_ref` to provide the authoritative current tick.
    /// Without this reference, we cannot securely verify quarantine expiry
    /// and must deny the restart (fail-closed behavior).
    ///
    /// This prevents attackers from bypassing quarantine by omitting time
    /// envelope data from restart events.
    #[error(
        "session {session_id} restart denied: tick-based quarantine requires time_envelope_ref (SEC-HTF-003)"
    )]
    MissingTimeEnvelopeRef {
        /// The session ID.
        session_id: String,
    },

    /// Clock regression detected during quarantine expiry check.
    ///
    /// # DD-HTF-0001: Defect Emission (RFC-0016)
    ///
    /// When tick rates mismatch during quarantine expiry checks, a clock
    /// regression defect is emitted. This indicates a potential security
    /// issue where ticks from different clock domains are being compared.
    ///
    /// The restart is denied with fail-closed behavior.
    #[error(
        "session {session_id} restart denied: clock regression detected (current_rate={current_tick_rate_hz}Hz, expected_rate={expected_tick_rate_hz}Hz)"
    )]
    ClockRegressionDetected {
        /// The session ID.
        session_id: String,
        /// Current tick rate in Hz.
        current_tick_rate_hz: u64,
        /// Expected tick rate in Hz.
        expected_tick_rate_hz: u64,
    },
}

/// Display implementation for state names used in error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateName {
    /// No session exists (initial state).
    None,
    /// Session is running.
    Running,
    /// Session has terminated.
    Terminated,
    /// Session is quarantined.
    Quarantined,
}

impl fmt::Display for StateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "(none)"),
            Self::Running => write!(f, "Running"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Quarantined => write!(f, "Quarantined"),
        }
    }
}

impl StateName {
    /// Returns the state name as a static string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "(none)",
            Self::Running => "Running",
            Self::Terminated => "Terminated",
            Self::Quarantined => "Quarantined",
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_state_name_display() {
        assert_eq!(StateName::None.to_string(), "(none)");
        assert_eq!(StateName::Running.to_string(), "Running");
        assert_eq!(StateName::Terminated.to_string(), "Terminated");
        assert_eq!(StateName::Quarantined.to_string(), "Quarantined");
    }

    #[test]
    fn test_invalid_transition_error() {
        let err = SessionError::InvalidTransition {
            from_state: "Running".to_string(),
            event_type: "session.started".to_string(),
        };
        assert!(err.to_string().contains("Running"));
        assert!(err.to_string().contains("session.started"));
    }

    #[test]
    fn test_session_not_found_error() {
        let err = SessionError::SessionNotFound {
            session_id: "session-123".to_string(),
        };
        assert!(err.to_string().contains("session-123"));
    }

    #[test]
    fn test_session_already_exists_error() {
        let err = SessionError::SessionAlreadyExists {
            session_id: "session-456".to_string(),
        };
        assert!(err.to_string().contains("session-456"));
    }
}
