//! Error types for resource management operations.
//!
//! This module defines errors that can occur during lease and budget
//! operations.

use thiserror::Error;

/// Errors that can occur during resource management operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// The budget has been exhausted for a resource.
    #[error("budget exhausted for {resource}: requested {requested}, remaining {remaining}")]
    BudgetExhausted {
        /// The resource that was exhausted.
        resource: String,
        /// The amount requested.
        requested: u64,
        /// The amount remaining.
        remaining: u64,
    },

    /// The lease has expired.
    #[error("lease expired: {lease_id} at {expired_at_ns}")]
    LeaseExpired {
        /// The expired lease ID.
        lease_id: String,
        /// The time at which the lease expired (nanoseconds since epoch).
        expired_at_ns: u64,
    },

    /// The lease scope is invalid for the requested operation.
    #[error("lease scope violation: {reason}")]
    LeaseScopeViolation {
        /// The reason for the scope violation.
        reason: String,
    },

    /// The lease signature is invalid.
    #[error("invalid lease signature for {lease_id}")]
    InvalidSignature {
        /// The lease ID with the invalid signature.
        lease_id: String,
    },

    /// The lease derivation is invalid.
    #[error("invalid lease derivation: {reason}")]
    InvalidDerivation {
        /// The reason the derivation is invalid.
        reason: String,
    },

    /// A required field is missing.
    #[error("missing required field: {field}")]
    MissingField {
        /// The name of the missing field.
        field: String,
    },

    /// The lease ID is not valid.
    #[error("invalid lease ID format: {lease_id}")]
    InvalidLeaseId {
        /// The invalid lease ID.
        lease_id: String,
    },

    /// The operation is not permitted.
    #[error("operation not permitted: {reason}")]
    OperationNotPermitted {
        /// The reason the operation is not permitted.
        reason: String,
    },
}

impl ResourceError {
    /// Creates a new budget exhausted error.
    #[must_use]
    pub fn budget_exhausted(resource: impl Into<String>, requested: u64, remaining: u64) -> Self {
        Self::BudgetExhausted {
            resource: resource.into(),
            requested,
            remaining,
        }
    }

    /// Creates a new lease expired error.
    #[must_use]
    pub fn lease_expired(lease_id: impl Into<String>, expired_at_ns: u64) -> Self {
        Self::LeaseExpired {
            lease_id: lease_id.into(),
            expired_at_ns,
        }
    }

    /// Creates a new lease scope violation error.
    #[must_use]
    pub fn scope_violation(reason: impl Into<String>) -> Self {
        Self::LeaseScopeViolation {
            reason: reason.into(),
        }
    }

    /// Creates a new invalid signature error.
    #[must_use]
    pub fn invalid_signature(lease_id: impl Into<String>) -> Self {
        Self::InvalidSignature {
            lease_id: lease_id.into(),
        }
    }

    /// Creates a new invalid derivation error.
    #[must_use]
    pub fn invalid_derivation(reason: impl Into<String>) -> Self {
        Self::InvalidDerivation {
            reason: reason.into(),
        }
    }

    /// Creates a new missing field error.
    #[must_use]
    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingField {
            field: field.into(),
        }
    }

    /// Creates a new invalid lease ID error.
    #[must_use]
    pub fn invalid_lease_id(lease_id: impl Into<String>) -> Self {
        Self::InvalidLeaseId {
            lease_id: lease_id.into(),
        }
    }

    /// Creates a new operation not permitted error.
    #[must_use]
    pub fn operation_not_permitted(reason: impl Into<String>) -> Self {
        Self::OperationNotPermitted {
            reason: reason.into(),
        }
    }

    /// Returns `true` if this is a budget exhausted error.
    #[must_use]
    pub const fn is_budget_exhausted(&self) -> bool {
        matches!(self, Self::BudgetExhausted { .. })
    }

    /// Returns `true` if this is a lease expired error.
    #[must_use]
    pub const fn is_lease_expired(&self) -> bool {
        matches!(self, Self::LeaseExpired { .. })
    }

    /// Returns `true` if this error is recoverable.
    ///
    /// Currently, no resource errors are recoverable. Budget exhaustion and
    /// lease expiration are permanent conditions. Scope violations, invalid
    /// signatures, and other errors indicate fundamental issues that cannot
    /// be retried without external intervention.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        // All resource errors are currently non-recoverable
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_exhausted_error() {
        let err = ResourceError::budget_exhausted("tokens", 1000, 500);
        assert!(err.to_string().contains("tokens"));
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));
        assert!(err.is_budget_exhausted());
        assert!(!err.is_lease_expired());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_lease_expired_error() {
        let err = ResourceError::lease_expired("lease-123", 1_000_000_000);
        assert!(err.to_string().contains("lease-123"));
        assert!(err.to_string().contains("1000000000"));
        assert!(err.is_lease_expired());
        assert!(!err.is_budget_exhausted());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_scope_violation_error() {
        let err = ResourceError::scope_violation("cannot access tool X");
        assert!(err.to_string().contains("cannot access tool X"));
    }

    #[test]
    fn test_invalid_signature_error() {
        let err = ResourceError::invalid_signature("lease-456");
        assert!(err.to_string().contains("lease-456"));
    }

    #[test]
    fn test_invalid_derivation_error() {
        let err = ResourceError::invalid_derivation("scope exceeds parent");
        assert!(err.to_string().contains("scope exceeds parent"));
    }

    #[test]
    fn test_missing_field_error() {
        let err = ResourceError::missing_field("issuer_id");
        assert!(err.to_string().contains("issuer_id"));
    }

    #[test]
    fn test_invalid_lease_id_error() {
        let err = ResourceError::invalid_lease_id("bad-id");
        assert!(err.to_string().contains("bad-id"));
    }

    #[test]
    fn test_operation_not_permitted_error() {
        let err = ResourceError::operation_not_permitted("lease already expired");
        assert!(err.to_string().contains("lease already expired"));
    }

    #[test]
    fn test_error_equality() {
        let err1 = ResourceError::budget_exhausted("tokens", 100, 50);
        let err2 = ResourceError::budget_exhausted("tokens", 100, 50);
        let err3 = ResourceError::budget_exhausted("episodes", 100, 50);

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }
}
