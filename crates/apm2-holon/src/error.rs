//! Error types for holon operations.
//!
//! This module defines the error types that can occur during holon lifecycle
//! operations. These errors are designed to be informative and actionable,
//! providing context for debugging and recovery.

use std::fmt;

use thiserror::Error;

/// Errors that can occur during holon operations.
///
/// These errors cover the full lifecycle of a holon, from intake through
/// episode execution to completion or escalation.
#[derive(Debug, Error)]
pub enum HolonError {
    /// The provided lease is invalid or expired.
    #[error("invalid lease {lease_id}: {reason}")]
    InvalidLease {
        /// The lease ID that failed validation.
        lease_id: String,
        /// Why the lease is invalid.
        reason: String,
    },

    /// The lease has expired.
    #[error("lease expired: {lease_id}")]
    LeaseExpired {
        /// The expired lease ID.
        lease_id: String,
    },

    /// The budget has been exhausted.
    #[error("budget exhausted: {resource} (used: {used}, limit: {limit})")]
    BudgetExhausted {
        /// The resource that was exhausted.
        resource: String,
        /// Amount used.
        used: u64,
        /// Budget limit.
        limit: u64,
    },

    /// The input failed validation.
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// Why the input is invalid.
        reason: String,
    },

    /// An episode execution error occurred.
    #[error("episode execution failed: {reason}")]
    EpisodeExecutionFailed {
        /// Why the episode failed.
        reason: String,
        /// Whether this error is recoverable.
        recoverable: bool,
    },

    /// Failed to emit an artifact to the ledger.
    #[error("artifact emission failed: {reason}")]
    ArtifactEmissionFailed {
        /// Why the artifact could not be emitted.
        reason: String,
    },

    /// Escalation to supervisor failed.
    #[error("escalation failed: {reason}")]
    EscalationFailed {
        /// Why escalation failed.
        reason: String,
    },

    /// The holon is in an invalid state for the requested operation.
    #[error("invalid state: expected {expected}, found {actual}")]
    InvalidState {
        /// The expected state.
        expected: String,
        /// The actual state.
        actual: String,
    },

    /// A required context field is missing.
    #[error("missing context: {field}")]
    MissingContext {
        /// The missing field name.
        field: String,
    },

    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

impl HolonError {
    /// Creates a new invalid lease error.
    #[must_use]
    pub fn invalid_lease(lease_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidLease {
            lease_id: lease_id.into(),
            reason: reason.into(),
        }
    }

    /// Creates a new lease expired error.
    #[must_use]
    pub fn lease_expired(lease_id: impl Into<String>) -> Self {
        Self::LeaseExpired {
            lease_id: lease_id.into(),
        }
    }

    /// Creates a new budget exhausted error.
    #[must_use]
    pub fn budget_exhausted(resource: impl Into<String>, used: u64, limit: u64) -> Self {
        Self::BudgetExhausted {
            resource: resource.into(),
            used,
            limit,
        }
    }

    /// Creates a new invalid input error.
    #[must_use]
    pub fn invalid_input(reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            reason: reason.into(),
        }
    }

    /// Creates a new episode execution failed error.
    #[must_use]
    pub fn episode_failed(reason: impl Into<String>, recoverable: bool) -> Self {
        Self::EpisodeExecutionFailed {
            reason: reason.into(),
            recoverable,
        }
    }

    /// Creates a new artifact emission failed error.
    #[must_use]
    pub fn artifact_failed(reason: impl Into<String>) -> Self {
        Self::ArtifactEmissionFailed {
            reason: reason.into(),
        }
    }

    /// Creates a new escalation failed error.
    #[must_use]
    pub fn escalation_failed(reason: impl Into<String>) -> Self {
        Self::EscalationFailed {
            reason: reason.into(),
        }
    }

    /// Creates a new invalid state error.
    #[must_use]
    pub fn invalid_state(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::InvalidState {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Creates a new missing context error.
    #[must_use]
    pub fn missing_context(field: impl Into<String>) -> Self {
        Self::MissingContext {
            field: field.into(),
        }
    }

    /// Creates a new internal error.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// Returns `true` if this error is recoverable.
    ///
    /// Recoverable errors may be retried or handled gracefully.
    /// Non-recoverable errors indicate fundamental issues that require
    /// escalation or termination.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        match self {
            Self::EpisodeExecutionFailed { recoverable, .. } => *recoverable,
            Self::ArtifactEmissionFailed { .. } => true,
            Self::InvalidLease { .. }
            | Self::LeaseExpired { .. }
            | Self::BudgetExhausted { .. }
            | Self::InvalidInput { .. }
            | Self::EscalationFailed { .. }
            | Self::InvalidState { .. }
            | Self::MissingContext { .. }
            | Self::Internal(_) => false,
        }
    }

    /// Returns `true` if this error should trigger escalation.
    ///
    /// Some errors can be handled locally, while others require
    /// forwarding to a supervisor for resolution.
    #[must_use]
    pub const fn should_escalate(&self) -> bool {
        match self {
            Self::EpisodeExecutionFailed { recoverable, .. } => !*recoverable,
            Self::InvalidInput { .. } | Self::ArtifactEmissionFailed { .. } => false,
            Self::InvalidLease { .. }
            | Self::LeaseExpired { .. }
            | Self::BudgetExhausted { .. }
            | Self::EscalationFailed { .. }
            | Self::InvalidState { .. }
            | Self::MissingContext { .. }
            | Self::Internal(_) => true,
        }
    }
}

/// Error classification for metrics and monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Lease-related errors.
    Lease,
    /// Budget-related errors.
    Budget,
    /// Input validation errors.
    Validation,
    /// Execution errors.
    Execution,
    /// Infrastructure/system errors.
    Infrastructure,
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lease => write!(f, "lease"),
            Self::Budget => write!(f, "budget"),
            Self::Validation => write!(f, "validation"),
            Self::Execution => write!(f, "execution"),
            Self::Infrastructure => write!(f, "infrastructure"),
        }
    }
}

impl HolonError {
    /// Returns the error classification for this error.
    #[must_use]
    pub const fn error_class(&self) -> ErrorClass {
        match self {
            Self::InvalidLease { .. } | Self::LeaseExpired { .. } => ErrorClass::Lease,
            Self::BudgetExhausted { .. } => ErrorClass::Budget,
            Self::InvalidInput { .. } | Self::MissingContext { .. } => ErrorClass::Validation,
            Self::EpisodeExecutionFailed { .. } => ErrorClass::Execution,
            Self::ArtifactEmissionFailed { .. }
            | Self::EscalationFailed { .. }
            | Self::InvalidState { .. }
            | Self::Internal(_) => ErrorClass::Infrastructure,
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_invalid_lease_error() {
        let err = HolonError::invalid_lease("lease-123", "not signed");
        assert!(err.to_string().contains("lease-123"));
        assert!(err.to_string().contains("not signed"));
        assert!(!err.is_recoverable());
        assert!(err.should_escalate());
        assert_eq!(err.error_class(), ErrorClass::Lease);
    }

    #[test]
    fn test_lease_expired_error() {
        let err = HolonError::lease_expired("lease-456");
        assert!(err.to_string().contains("lease-456"));
        assert!(!err.is_recoverable());
        assert!(err.should_escalate());
    }

    #[test]
    fn test_budget_exhausted_error() {
        let err = HolonError::budget_exhausted("tokens", 1000, 500);
        assert!(err.to_string().contains("tokens"));
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));
        assert!(!err.is_recoverable());
        assert_eq!(err.error_class(), ErrorClass::Budget);
    }

    #[test]
    fn test_invalid_input_error() {
        let err = HolonError::invalid_input("empty prompt");
        assert!(err.to_string().contains("empty prompt"));
        assert!(!err.is_recoverable());
        assert!(!err.should_escalate());
        assert_eq!(err.error_class(), ErrorClass::Validation);
    }

    #[test]
    fn test_episode_failed_recoverable() {
        let err = HolonError::episode_failed("timeout", true);
        assert!(err.is_recoverable());
        assert!(!err.should_escalate());
        assert_eq!(err.error_class(), ErrorClass::Execution);
    }

    #[test]
    fn test_episode_failed_not_recoverable() {
        let err = HolonError::episode_failed("critical failure", false);
        assert!(!err.is_recoverable());
        assert!(err.should_escalate());
    }

    #[test]
    fn test_artifact_failed_error() {
        let err = HolonError::artifact_failed("ledger unavailable");
        assert!(err.to_string().contains("ledger unavailable"));
        assert!(err.is_recoverable());
        assert!(!err.should_escalate());
    }

    #[test]
    fn test_escalation_failed_error() {
        let err = HolonError::escalation_failed("no supervisor");
        assert!(err.to_string().contains("no supervisor"));
        assert!(!err.is_recoverable());
        assert!(err.should_escalate());
    }

    #[test]
    fn test_invalid_state_error() {
        let err = HolonError::invalid_state("Ready", "Running");
        assert!(err.to_string().contains("Ready"));
        assert!(err.to_string().contains("Running"));
        assert!(!err.is_recoverable());
        assert!(err.should_escalate());
    }

    #[test]
    fn test_missing_context_error() {
        let err = HolonError::missing_context("work_id");
        assert!(err.to_string().contains("work_id"));
        assert!(!err.is_recoverable());
        assert!(err.should_escalate());
        assert_eq!(err.error_class(), ErrorClass::Validation);
    }

    #[test]
    fn test_internal_error() {
        let err = HolonError::internal("unexpected panic");
        assert!(err.to_string().contains("unexpected panic"));
        assert!(!err.is_recoverable());
        assert!(err.should_escalate());
        assert_eq!(err.error_class(), ErrorClass::Infrastructure);
    }

    #[test]
    fn test_error_class_display() {
        assert_eq!(ErrorClass::Lease.to_string(), "lease");
        assert_eq!(ErrorClass::Budget.to_string(), "budget");
        assert_eq!(ErrorClass::Validation.to_string(), "validation");
        assert_eq!(ErrorClass::Execution.to_string(), "execution");
        assert_eq!(ErrorClass::Infrastructure.to_string(), "infrastructure");
    }
}
