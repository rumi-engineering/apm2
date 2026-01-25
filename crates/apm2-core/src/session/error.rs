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
