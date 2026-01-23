//! Session state types and transitions.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::error::StateName;

/// Classification of how a session exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitClassification {
    /// Session completed successfully.
    Success,
    /// Session failed due to an error.
    Failure,
    /// Session timed out.
    Timeout,
    /// Session exceeded its entropy budget.
    EntropyExceeded,
}

impl ExitClassification {
    /// Parses an exit classification from a string.
    ///
    /// Defaults to `Failure` for unknown values.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "SUCCESS" => Self::Success,
            "TIMEOUT" => Self::Timeout,
            "ENTROPY_EXCEEDED" => Self::EntropyExceeded,
            // FAILURE or any unknown value defaults to Failure
            _ => Self::Failure,
        }
    }

    /// Returns the classification as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
            Self::Timeout => "TIMEOUT",
            Self::EntropyExceeded => "ENTROPY_EXCEEDED",
        }
    }
}

impl FromStr for ExitClassification {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

/// The state of a session in the lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session is actively running.
    Running {
        /// Timestamp when the session started (nanoseconds since epoch).
        started_at: u64,
        /// ID of the actor running this session.
        actor_id: String,
        /// ID of the work item this session is processing.
        work_id: String,
        /// ID of the lease for this session.
        lease_id: String,
        /// Type of adapter (e.g., "claude-code", "gemini-cli").
        adapter_type: String,
        /// Total entropy budget for this session.
        entropy_budget: u64,
        /// Number of progress events received.
        progress_count: u64,
        /// Total entropy consumed so far.
        entropy_consumed: u64,
    },
    /// Session has terminated (final state).
    Terminated {
        /// Timestamp when the session started (nanoseconds since epoch).
        started_at: u64,
        /// Timestamp when the session terminated (nanoseconds since epoch).
        terminated_at: u64,
        /// How the session exited.
        exit_classification: ExitClassification,
        /// Code explaining the termination reason.
        rationale_code: String,
        /// Final entropy consumed when session ended.
        final_entropy: u64,
    },
    /// Session is quarantined (blocked from execution).
    Quarantined {
        /// Timestamp when the session started (nanoseconds since epoch).
        started_at: u64,
        /// Timestamp when the session was quarantined (nanoseconds since
        /// epoch).
        quarantined_at: u64,
        /// Reason for quarantine.
        reason: String,
        /// Timestamp until which the session is quarantined (nanoseconds since
        /// epoch).
        quarantine_until: u64,
    },
}

impl SessionState {
    /// Returns `true` if the session is in an active (running) state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Returns `true` if the session is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated { .. } | Self::Quarantined { .. })
    }

    /// Returns the state name for this state.
    #[must_use]
    pub const fn state_name(&self) -> StateName {
        match self {
            Self::Running { .. } => StateName::Running,
            Self::Terminated { .. } => StateName::Terminated,
            Self::Quarantined { .. } => StateName::Quarantined,
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_exit_classification_parse() {
        assert_eq!(
            ExitClassification::parse("SUCCESS"),
            ExitClassification::Success
        );
        assert_eq!(
            ExitClassification::parse("success"),
            ExitClassification::Success
        );
        assert_eq!(
            ExitClassification::parse("FAILURE"),
            ExitClassification::Failure
        );
        assert_eq!(
            ExitClassification::parse("TIMEOUT"),
            ExitClassification::Timeout
        );
        assert_eq!(
            ExitClassification::parse("ENTROPY_EXCEEDED"),
            ExitClassification::EntropyExceeded
        );
        assert_eq!(
            ExitClassification::parse("unknown"),
            ExitClassification::Failure
        );
    }

    #[test]
    fn test_exit_classification_as_str() {
        assert_eq!(ExitClassification::Success.as_str(), "SUCCESS");
        assert_eq!(ExitClassification::Failure.as_str(), "FAILURE");
        assert_eq!(ExitClassification::Timeout.as_str(), "TIMEOUT");
        assert_eq!(
            ExitClassification::EntropyExceeded.as_str(),
            "ENTROPY_EXCEEDED"
        );
    }

    #[test]
    fn test_session_state_is_active() {
        let running = SessionState::Running {
            started_at: 1000,
            actor_id: "actor-1".to_string(),
            work_id: "work-1".to_string(),
            lease_id: "lease-1".to_string(),
            adapter_type: "claude-code".to_string(),
            entropy_budget: 1000,
            progress_count: 0,
            entropy_consumed: 0,
        };
        assert!(running.is_active());

        let terminated = SessionState::Terminated {
            started_at: 1000,
            terminated_at: 2000,
            exit_classification: ExitClassification::Success,
            rationale_code: "completed".to_string(),
            final_entropy: 500,
        };
        assert!(!terminated.is_active());

        let quarantined = SessionState::Quarantined {
            started_at: 1000,
            quarantined_at: 2000,
            reason: "policy violation".to_string(),
            quarantine_until: 3000,
        };
        assert!(!quarantined.is_active());
    }

    #[test]
    fn test_session_state_is_terminal() {
        let running = SessionState::Running {
            started_at: 1000,
            actor_id: "actor-1".to_string(),
            work_id: "work-1".to_string(),
            lease_id: "lease-1".to_string(),
            adapter_type: "claude-code".to_string(),
            entropy_budget: 1000,
            progress_count: 0,
            entropy_consumed: 0,
        };
        assert!(!running.is_terminal());

        let terminated = SessionState::Terminated {
            started_at: 1000,
            terminated_at: 2000,
            exit_classification: ExitClassification::Success,
            rationale_code: "completed".to_string(),
            final_entropy: 500,
        };
        assert!(terminated.is_terminal());

        let quarantined = SessionState::Quarantined {
            started_at: 1000,
            quarantined_at: 2000,
            reason: "policy violation".to_string(),
            quarantine_until: 3000,
        };
        assert!(quarantined.is_terminal());
    }

    #[test]
    fn test_session_state_name() {
        let running = SessionState::Running {
            started_at: 1000,
            actor_id: "actor-1".to_string(),
            work_id: "work-1".to_string(),
            lease_id: "lease-1".to_string(),
            adapter_type: "claude-code".to_string(),
            entropy_budget: 1000,
            progress_count: 0,
            entropy_consumed: 0,
        };
        assert_eq!(running.state_name(), StateName::Running);

        let terminated = SessionState::Terminated {
            started_at: 1000,
            terminated_at: 2000,
            exit_classification: ExitClassification::Success,
            rationale_code: "completed".to_string(),
            final_entropy: 500,
        };
        assert_eq!(terminated.state_name(), StateName::Terminated);

        let quarantined = SessionState::Quarantined {
            started_at: 1000,
            quarantined_at: 2000,
            reason: "policy violation".to_string(),
            quarantine_until: 3000,
        };
        assert_eq!(quarantined.state_name(), StateName::Quarantined);
    }
}
