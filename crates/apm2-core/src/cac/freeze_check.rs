//! Freeze check abstraction for admission control.
//!
//! This module defines the [`FreezeCheck`] trait which abstracts freeze status
//! checking for the admission pipeline. This enables the `AdmissionGate` to
//! enforce freeze policies without depending on the daemon's divergence
//! watchdog implementation.
//!
//! # Security Model
//!
//! The freeze check is a critical security control that prevents:
//! - Admitting artifacts to frozen repositories
//! - Circumventing divergence-triggered freezes
//! - Inconsistent ledger state after external modifications
//!
//! # Architectural Rationale
//!
//! The `FreezeCheck` trait is defined in `apm2-core` (rather than
//! `apm2-daemon`) to allow `AdmissionGate` to check freeze state without
//! creating a circular dependency. The daemon implements this trait via its
//! `FreezeRegistry`.
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::cac::freeze_check::{FreezeCheck, FreezeCheckError};
//!
//! struct NoOpFreezeCheck;
//!
//! impl FreezeCheck for NoOpFreezeCheck {
//!     fn check_admission(&self, _scope_value: &str) -> Result<(), FreezeCheckError> {
//!         Ok(()) // Always allow
//!     }
//!
//!     fn is_frozen(&self, _scope_value: &str) -> bool {
//!         false // Never frozen
//!     }
//! }
//! ```

use thiserror::Error;

/// Maximum length for freeze ID strings.
pub const MAX_FREEZE_ID_LENGTH: usize = 256;

/// Maximum length for reason strings.
pub const MAX_REASON_LENGTH: usize = 1024;

/// Errors that can occur during freeze checking.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FreezeCheckError {
    /// The repository/scope is frozen.
    #[error("repository frozen: freeze_id={freeze_id}, reason={reason}")]
    Frozen {
        /// The freeze ID that caused the rejection.
        freeze_id: String,
        /// The reason for the freeze.
        reason: String,
    },

    /// Internal error during freeze check.
    #[error("freeze check failed: {message}")]
    InternalError {
        /// Description of the internal error.
        message: String,
    },
}

impl FreezeCheckError {
    /// Creates a new `Frozen` error with the given freeze ID.
    ///
    /// The reason defaults to "divergence detected".
    #[must_use]
    pub fn frozen(freeze_id: impl Into<String>) -> Self {
        Self::Frozen {
            freeze_id: freeze_id.into(),
            reason: "divergence detected".to_string(),
        }
    }

    /// Creates a new `Frozen` error with the given freeze ID and reason.
    #[must_use]
    pub fn frozen_with_reason(freeze_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Frozen {
            freeze_id: freeze_id.into(),
            reason: reason.into(),
        }
    }

    /// Creates a new `InternalError`.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::InternalError {
            message: message.into(),
        }
    }
}

/// Trait for checking freeze status before admission.
///
/// This trait abstracts the freeze checking logic, allowing for dependency
/// injection and easier testing. It provides a standard interface for
/// components that need to verify whether a scope is frozen before
/// admitting new work.
///
/// # Security
///
/// Implementations must ensure that freeze checks are atomic and consistent.
/// A scope that is frozen must remain frozen until explicitly unfrozen.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to support concurrent admission
/// requests from multiple threads.
pub trait FreezeCheck: Send + Sync {
    /// Checks if admission is allowed for the given scope value.
    ///
    /// The scope value typically identifies a repository, work item, or
    /// namespace depending on the freeze scope.
    ///
    /// # Errors
    ///
    /// Returns [`FreezeCheckError::Frozen`] if the scope is frozen.
    /// Returns [`FreezeCheckError::InternalError`] if the check cannot be
    /// performed.
    fn check_admission(&self, scope_value: &str) -> Result<(), FreezeCheckError>;

    /// Returns whether the scope is currently frozen.
    ///
    /// This is a convenience method that returns `true` if `check_admission`
    /// would return a `Frozen` error.
    fn is_frozen(&self, scope_value: &str) -> bool;
}

/// A no-op freeze checker that always allows admission.
///
/// This implementation is useful for:
/// - Testing without freeze enforcement
/// - Environments where freeze checking is disabled
/// - Bootstrap scenarios before the freeze registry is initialized
///
/// # Security Warning
///
/// Using this implementation in production disables freeze enforcement,
/// which may allow artifacts to be admitted to repositories that should
/// be frozen due to divergence. Only use this implementation when freeze
/// checking is intentionally disabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpFreezeCheck;

impl FreezeCheck for NoOpFreezeCheck {
    fn check_admission(&self, _scope_value: &str) -> Result<(), FreezeCheckError> {
        Ok(())
    }

    fn is_frozen(&self, _scope_value: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freeze_check_error_frozen() {
        let err = FreezeCheckError::frozen("freeze-001");
        match err {
            FreezeCheckError::Frozen { freeze_id, reason } => {
                assert_eq!(freeze_id, "freeze-001");
                assert_eq!(reason, "divergence detected");
            },
            _ => panic!("expected Frozen error"),
        }
    }

    #[test]
    fn test_freeze_check_error_frozen_with_reason() {
        let err = FreezeCheckError::frozen_with_reason("freeze-002", "external modification");
        match err {
            FreezeCheckError::Frozen { freeze_id, reason } => {
                assert_eq!(freeze_id, "freeze-002");
                assert_eq!(reason, "external modification");
            },
            _ => panic!("expected Frozen error"),
        }
    }

    #[test]
    fn test_freeze_check_error_internal() {
        let err = FreezeCheckError::internal("lock poisoned");
        match err {
            FreezeCheckError::InternalError { message } => {
                assert_eq!(message, "lock poisoned");
            },
            _ => panic!("expected InternalError"),
        }
    }

    #[test]
    fn test_noop_freeze_check_allows_all() {
        let checker = NoOpFreezeCheck;
        assert!(checker.check_admission("any-repo").is_ok());
        assert!(!checker.is_frozen("any-repo"));
    }

    #[test]
    fn test_noop_freeze_check_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoOpFreezeCheck>();
    }
}
