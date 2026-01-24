//! Session state types and transitions.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::entropy::EntropyTrackerSummary;
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
#[non_exhaustive]
pub enum SessionState {
    /// Session is actively running.
    #[non_exhaustive]
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
        /// Count of errors recorded against entropy budget.
        error_count: u64,
        /// Count of policy violations recorded against entropy budget.
        violation_count: u64,
        /// Count of stalls recorded against entropy budget.
        stall_count: u64,
        /// Count of timeouts recorded against entropy budget.
        timeout_count: u64,
    },
    /// Session has terminated (final state).
    #[non_exhaustive]
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
    #[non_exhaustive]
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

    /// Returns the entropy budget for a running session.
    #[must_use]
    pub const fn entropy_budget(&self) -> Option<u64> {
        match self {
            Self::Running { entropy_budget, .. } => Some(*entropy_budget),
            Self::Terminated { .. } | Self::Quarantined { .. } => None,
        }
    }

    /// Returns the entropy consumed for a running session.
    #[must_use]
    pub const fn entropy_consumed(&self) -> Option<u64> {
        match self {
            Self::Running {
                entropy_consumed, ..
            } => Some(*entropy_consumed),
            Self::Terminated { final_entropy, .. } => Some(*final_entropy),
            Self::Quarantined { .. } => None,
        }
    }

    /// Returns the remaining entropy budget for a running session.
    #[must_use]
    pub const fn entropy_remaining(&self) -> Option<u64> {
        match self {
            Self::Running {
                entropy_budget,
                entropy_consumed,
                ..
            } => Some(entropy_budget.saturating_sub(*entropy_consumed)),
            Self::Terminated { .. } | Self::Quarantined { .. } => None,
        }
    }

    /// Returns `true` if the entropy budget has been exceeded.
    #[must_use]
    pub const fn is_entropy_exceeded(&self) -> bool {
        match self {
            Self::Running {
                entropy_budget,
                entropy_consumed,
                ..
            } => *entropy_consumed >= *entropy_budget,
            Self::Terminated {
                exit_classification,
                ..
            } => matches!(exit_classification, ExitClassification::EntropyExceeded),
            Self::Quarantined { .. } => false,
        }
    }

    /// Returns a summary of the entropy tracking state for a running session.
    #[must_use]
    pub fn entropy_summary(&self, session_id: &str) -> Option<EntropyTrackerSummary> {
        match self {
            Self::Running {
                entropy_budget,
                entropy_consumed,
                error_count,
                violation_count,
                stall_count,
                timeout_count,
                ..
            } => Some(EntropyTrackerSummary {
                session_id: session_id.to_string(),
                budget: *entropy_budget,
                consumed: *entropy_consumed,
                remaining: entropy_budget.saturating_sub(*entropy_consumed),
                is_exceeded: *entropy_consumed >= *entropy_budget,
                error_count: *error_count,
                violation_count: *violation_count,
                stall_count: *stall_count,
                timeout_count: *timeout_count,
            }),
            Self::Terminated { .. } | Self::Quarantined { .. } => None,
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

    /// Helper to create a default running state for tests.
    fn running_state() -> SessionState {
        SessionState::Running {
            started_at: 1000,
            actor_id: "actor-1".to_string(),
            work_id: "work-1".to_string(),
            lease_id: "lease-1".to_string(),
            adapter_type: "claude-code".to_string(),
            entropy_budget: 1000,
            progress_count: 0,
            entropy_consumed: 0,
            error_count: 0,
            violation_count: 0,
            stall_count: 0,
            timeout_count: 0,
        }
    }

    #[test]
    fn test_session_state_is_active() {
        let running = running_state();
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
        let running = running_state();
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
        let running = running_state();
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

    #[test]
    fn test_entropy_budget_methods() {
        let running = running_state();
        assert_eq!(running.entropy_budget(), Some(1000));
        assert_eq!(running.entropy_consumed(), Some(0));
        assert_eq!(running.entropy_remaining(), Some(1000));
        assert!(!running.is_entropy_exceeded());
    }

    #[test]
    fn test_entropy_exceeded() {
        let running = SessionState::Running {
            started_at: 1000,
            actor_id: "actor-1".to_string(),
            work_id: "work-1".to_string(),
            lease_id: "lease-1".to_string(),
            adapter_type: "claude-code".to_string(),
            entropy_budget: 100,
            progress_count: 0,
            entropy_consumed: 100,
            error_count: 10,
            violation_count: 0,
            stall_count: 0,
            timeout_count: 0,
        };
        assert!(running.is_entropy_exceeded());
        assert_eq!(running.entropy_remaining(), Some(0));
    }

    #[test]
    fn test_entropy_summary() {
        let running = SessionState::Running {
            started_at: 1000,
            actor_id: "actor-1".to_string(),
            work_id: "work-1".to_string(),
            lease_id: "lease-1".to_string(),
            adapter_type: "claude-code".to_string(),
            entropy_budget: 1000,
            progress_count: 5,
            entropy_consumed: 150,
            error_count: 5,
            violation_count: 2,
            stall_count: 1,
            timeout_count: 3,
        };

        let summary = running.entropy_summary("session-1").unwrap();
        assert_eq!(summary.session_id, "session-1");
        assert_eq!(summary.budget, 1000);
        assert_eq!(summary.consumed, 150);
        assert_eq!(summary.remaining, 850);
        assert!(!summary.is_exceeded);
        assert_eq!(summary.error_count, 5);
        assert_eq!(summary.violation_count, 2);
        assert_eq!(summary.stall_count, 1);
        assert_eq!(summary.timeout_count, 3);
    }

    #[test]
    fn test_terminated_entropy_exceeded_classification() {
        let terminated = SessionState::Terminated {
            started_at: 1000,
            terminated_at: 2000,
            exit_classification: ExitClassification::EntropyExceeded,
            rationale_code: "entropy_budget_exhausted".to_string(),
            final_entropy: 1000,
        };
        assert!(terminated.is_entropy_exceeded());
        assert_eq!(terminated.entropy_consumed(), Some(1000));
    }

    #[test]
    fn test_terminated_not_entropy_exceeded() {
        let terminated = SessionState::Terminated {
            started_at: 1000,
            terminated_at: 2000,
            exit_classification: ExitClassification::Success,
            rationale_code: "completed".to_string(),
            final_entropy: 500,
        };
        assert!(!terminated.is_entropy_exceeded());
    }
}
