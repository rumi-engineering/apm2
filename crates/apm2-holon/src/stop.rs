//! Stop conditions for holon execution.
//!
//! Stop conditions determine when a holon should cease executing episodes.
//! They are evaluated after each episode to decide whether to continue
//! or terminate the execution loop.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Conditions under which a holon should stop executing episodes.
///
/// Stop conditions are evaluated by the holon's `should_stop` method
/// after each episode. The episode controller uses this to determine
/// whether to continue or terminate the execution loop.
///
/// # Example
///
/// ```rust
/// use apm2_holon::StopCondition;
///
/// let condition = StopCondition::GoalSatisfied;
/// assert!(condition.should_stop());
/// assert!(condition.is_successful());
///
/// let condition = StopCondition::Continue;
/// assert!(!condition.should_stop());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StopCondition {
    /// The holon should continue executing episodes.
    #[default]
    Continue,

    /// The goal has been satisfied; work is complete.
    GoalSatisfied,

    /// The token budget has been exhausted.
    BudgetExhausted {
        /// The resource that was exhausted.
        resource: String,
    },

    /// The maximum episode count has been reached.
    MaxEpisodesReached {
        /// The number of episodes executed.
        count: u64,
    },

    /// The time budget has been exhausted.
    TimeoutReached {
        /// Time limit in milliseconds.
        limit_ms: u64,
    },

    /// An external signal requested termination.
    ExternalSignal {
        /// The signal that was received.
        signal: String,
    },

    /// The holon cannot make further progress.
    Stalled {
        /// Reason for the stall.
        reason: String,
    },

    /// An unrecoverable error occurred.
    ErrorCondition {
        /// Description of the error.
        error: String,
    },

    /// The holon has escalated its work.
    Escalated {
        /// Reason for escalation.
        reason: String,
    },

    /// A policy violation occurred.
    PolicyViolation {
        /// The policy that was violated.
        policy: String,
    },
}

impl StopCondition {
    /// Creates a budget exhausted condition.
    #[must_use]
    pub fn budget_exhausted(resource: impl Into<String>) -> Self {
        Self::BudgetExhausted {
            resource: resource.into(),
        }
    }

    /// Creates a max episodes reached condition.
    #[must_use]
    pub const fn max_episodes_reached(count: u64) -> Self {
        Self::MaxEpisodesReached { count }
    }

    /// Creates a timeout reached condition.
    #[must_use]
    pub const fn timeout_reached(limit_ms: u64) -> Self {
        Self::TimeoutReached { limit_ms }
    }

    /// Creates an external signal condition.
    #[must_use]
    pub fn external_signal(signal: impl Into<String>) -> Self {
        Self::ExternalSignal {
            signal: signal.into(),
        }
    }

    /// Creates a stalled condition.
    #[must_use]
    pub fn stalled(reason: impl Into<String>) -> Self {
        Self::Stalled {
            reason: reason.into(),
        }
    }

    /// Creates an error condition.
    #[must_use]
    pub fn error(error: impl Into<String>) -> Self {
        Self::ErrorCondition {
            error: error.into(),
        }
    }

    /// Creates an escalated condition.
    #[must_use]
    pub fn escalated(reason: impl Into<String>) -> Self {
        Self::Escalated {
            reason: reason.into(),
        }
    }

    /// Creates a policy violation condition.
    #[must_use]
    pub fn policy_violation(policy: impl Into<String>) -> Self {
        Self::PolicyViolation {
            policy: policy.into(),
        }
    }

    /// Returns `true` if the holon should stop.
    #[must_use]
    pub const fn should_stop(&self) -> bool {
        !matches!(self, Self::Continue)
    }

    /// Returns `true` if this is a successful termination.
    ///
    /// A successful termination means the goal was achieved or
    /// the work was properly handed off (escalated).
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        matches!(self, Self::GoalSatisfied | Self::Escalated { .. })
    }

    /// Returns `true` if this is a resource-related termination.
    #[must_use]
    pub const fn is_resource_limit(&self) -> bool {
        matches!(
            self,
            Self::BudgetExhausted { .. }
                | Self::MaxEpisodesReached { .. }
                | Self::TimeoutReached { .. }
        )
    }

    /// Returns `true` if this is an error condition.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(
            self,
            Self::ErrorCondition { .. } | Self::PolicyViolation { .. }
        )
    }

    /// Returns `true` if this is a stall condition.
    #[must_use]
    pub const fn is_stalled(&self) -> bool {
        matches!(self, Self::Stalled { .. })
    }

    /// Returns the stop condition as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::GoalSatisfied => "goal_satisfied",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::MaxEpisodesReached { .. } => "max_episodes_reached",
            Self::TimeoutReached { .. } => "timeout_reached",
            Self::ExternalSignal { .. } => "external_signal",
            Self::Stalled { .. } => "stalled",
            Self::ErrorCondition { .. } => "error",
            Self::Escalated { .. } => "escalated",
            Self::PolicyViolation { .. } => "policy_violation",
        }
    }

    /// Converts the stop condition to an exit code.
    ///
    /// Exit codes follow Unix conventions:
    /// - 0: Success (goal satisfied)
    /// - 1: General error
    /// - 2: Resource limit exceeded
    /// - 3: External signal
    /// - 4: Policy violation
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            // Success: goal achieved or work handed off
            Self::Continue | Self::GoalSatisfied | Self::Escalated { .. } => 0,
            // General error
            Self::ErrorCondition { .. } | Self::Stalled { .. } => 1,
            // Resource limit exceeded
            Self::BudgetExhausted { .. }
            | Self::MaxEpisodesReached { .. }
            | Self::TimeoutReached { .. } => 2,
            // External signal
            Self::ExternalSignal { .. } => 3,
            // Policy violation
            Self::PolicyViolation { .. } => 4,
        }
    }
}

impl fmt::Display for StopCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "continue"),
            Self::GoalSatisfied => write!(f, "goal satisfied"),
            Self::BudgetExhausted { resource } => {
                write!(f, "budget exhausted: {resource}")
            },
            Self::MaxEpisodesReached { count } => {
                write!(f, "max episodes reached: {count}")
            },
            Self::TimeoutReached { limit_ms } => {
                write!(f, "timeout reached: {limit_ms}ms")
            },
            Self::ExternalSignal { signal } => {
                write!(f, "external signal: {signal}")
            },
            Self::Stalled { reason } => write!(f, "stalled: {reason}"),
            Self::ErrorCondition { error } => write!(f, "error: {error}"),
            Self::Escalated { reason } => write!(f, "escalated: {reason}"),
            Self::PolicyViolation { policy } => {
                write!(f, "policy violation: {policy}")
            },
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_continue() {
        let cond = StopCondition::Continue;
        assert!(!cond.should_stop());
        assert!(!cond.is_successful());
        assert!(!cond.is_resource_limit());
        assert_eq!(cond.as_str(), "continue");
    }

    #[test]
    fn test_goal_satisfied() {
        let cond = StopCondition::GoalSatisfied;
        assert!(cond.should_stop());
        assert!(cond.is_successful());
        assert_eq!(cond.exit_code(), 0);
        assert_eq!(cond.to_string(), "goal satisfied");
    }

    #[test]
    fn test_budget_exhausted() {
        let cond = StopCondition::budget_exhausted("tokens");
        assert!(cond.should_stop());
        assert!(!cond.is_successful());
        assert!(cond.is_resource_limit());
        assert_eq!(cond.exit_code(), 2);
        assert!(cond.to_string().contains("tokens"));
    }

    #[test]
    fn test_max_episodes_reached() {
        let cond = StopCondition::max_episodes_reached(10);
        assert!(cond.should_stop());
        assert!(cond.is_resource_limit());
        assert!(cond.to_string().contains("10"));
    }

    #[test]
    fn test_timeout_reached() {
        let cond = StopCondition::timeout_reached(5000);
        assert!(cond.should_stop());
        assert!(cond.is_resource_limit());
        assert!(cond.to_string().contains("5000"));
    }

    #[test]
    fn test_external_signal() {
        let cond = StopCondition::external_signal("SIGTERM");
        assert!(cond.should_stop());
        assert_eq!(cond.exit_code(), 3);
        assert!(cond.to_string().contains("SIGTERM"));
    }

    #[test]
    fn test_stalled() {
        let cond = StopCondition::stalled("no progress");
        assert!(cond.should_stop());
        assert!(cond.is_stalled());
        assert_eq!(cond.exit_code(), 1);
    }

    #[test]
    fn test_error_condition() {
        let cond = StopCondition::error("critical failure");
        assert!(cond.should_stop());
        assert!(cond.is_error());
        assert_eq!(cond.exit_code(), 1);
    }

    #[test]
    fn test_escalated() {
        let cond = StopCondition::escalated("beyond scope");
        assert!(cond.should_stop());
        assert!(cond.is_successful());
        assert_eq!(cond.exit_code(), 0);
    }

    #[test]
    fn test_policy_violation() {
        let cond = StopCondition::policy_violation("no_unsafe_code");
        assert!(cond.should_stop());
        assert!(cond.is_error());
        assert_eq!(cond.exit_code(), 4);
    }

    #[test]
    fn test_default() {
        let cond = StopCondition::default();
        assert_eq!(cond, StopCondition::Continue);
    }
}
