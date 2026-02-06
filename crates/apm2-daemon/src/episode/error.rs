//! Episode error types.
//!
//! This module defines structured error types for episode lifecycle operations.
//! All errors are typed to enable callers to branch on error cause per
//! CTR-0703.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Unique identifier for an episode.
///
/// Format: `ep-{envelope_hash_prefix}-{timestamp_ns}-{seq}` where:
/// - `envelope_hash_prefix`: First 8 bytes of BLAKE3 hash (hex-encoded)
/// - `timestamp_ns`: Creation timestamp in nanoseconds since epoch
/// - `seq`: Monotonic sequence number for uniqueness under concurrent creation
///
/// Maximum length: 128 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EpisodeId(String);

/// Maximum length for episode identifiers.
pub const MAX_EPISODE_ID_LEN: usize = 128;

impl EpisodeId {
    /// Creates a new episode ID from a string.
    ///
    /// # Errors
    ///
    /// Returns `EpisodeError::InvalidId` if the ID is empty, too long,
    /// or contains forbidden characters (null bytes, `/`).
    pub fn new(id: impl Into<String>) -> Result<Self, EpisodeError> {
        let id = id.into();
        validate_episode_id(&id)?;
        Ok(Self(id))
    }

    /// Returns the inner string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EpisodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for EpisodeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Validates an episode ID string.
fn validate_episode_id(id: &str) -> Result<(), EpisodeError> {
    if id.is_empty() {
        return Err(EpisodeError::InvalidId {
            id: id.to_string(),
            reason: "episode ID cannot be empty".to_string(),
        });
    }
    if id.len() > MAX_EPISODE_ID_LEN {
        return Err(EpisodeError::InvalidId {
            id: id.chars().take(32).collect::<String>() + "...",
            reason: format!("episode ID exceeds maximum length of {MAX_EPISODE_ID_LEN} characters"),
        });
    }
    if id.contains('\0') {
        return Err(EpisodeError::InvalidId {
            id: id.replace('\0', "\\0"),
            reason: "episode ID cannot contain null bytes".to_string(),
        });
    }
    if id.contains('/') {
        return Err(EpisodeError::InvalidId {
            id: id.to_string(),
            reason: "episode ID cannot contain '/' character".to_string(),
        });
    }
    Ok(())
}

/// Episode lifecycle errors.
///
/// These errors are structured to enable programmatic handling per CTR-0703.
/// Each variant includes context sufficient for diagnosis and logging.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EpisodeError {
    /// Invalid episode ID format.
    #[error("invalid episode ID '{id}': {reason}")]
    InvalidId {
        /// The invalid ID (truncated if too long).
        id: String,
        /// Reason for rejection.
        reason: String,
    },

    /// Episode not found.
    #[error("episode not found: {id}")]
    NotFound {
        /// The episode ID that was not found.
        id: String,
    },

    /// Invalid state transition.
    #[error("invalid state transition for episode {id}: cannot transition from {from} to {to}")]
    InvalidTransition {
        /// Episode identifier.
        id: String,
        /// Current state name.
        from: &'static str,
        /// Attempted target state.
        to: &'static str,
    },

    /// Episode already exists.
    #[error("episode already exists: {id}")]
    AlreadyExists {
        /// The duplicate episode ID.
        id: String,
    },

    /// Maximum episodes limit reached.
    #[error("maximum episode limit reached: {limit}")]
    LimitReached {
        /// The configured limit.
        limit: usize,
    },

    /// Invalid lease for starting episode.
    #[error("invalid lease for episode {episode_id}: {reason}")]
    InvalidLease {
        /// Episode identifier.
        episode_id: String,
        /// Reason the lease is invalid.
        reason: String,
    },

    /// Envelope validation failed.
    #[error("envelope validation failed for episode {id}: {reason}")]
    EnvelopeValidation {
        /// Episode identifier.
        id: String,
        /// Validation failure reason.
        reason: String,
    },

    /// Internal error.
    #[error("internal episode error: {message}")]
    Internal {
        /// Error message.
        message: String,
    },

    /// Clock failure during time envelope stamping.
    ///
    /// Per SEC-CTRL-FAC-0015 (Fail-Closed), when a clock is configured but
    /// fails to stamp a time envelope, the operation MUST fail rather than
    /// silently continuing without a timestamp.
    #[error("clock failure during time stamping: {message}")]
    ClockFailure {
        /// Error message from the clock.
        message: String,
    },

    /// Custody domain violation (`SoD` enforcement).
    ///
    /// Per REQ-DCP-0006, spawn is rejected when executor custody domain
    /// overlaps with author custody domains for the changeset. This enforces
    /// Separation of Duties (`SoD`) to prevent self-review attacks.
    #[error(
        "custody domain violation: executor domain '{executor_domain}' overlaps with author domain '{author_domain}'"
    )]
    CustodyDomainViolation {
        /// The executor's custody domain that caused the violation.
        executor_domain: String,
        /// The author's custody domain that overlaps.
        author_domain: String,
    },

    /// Tool execution failed.
    #[error("tool execution failed for episode {id}: {message}")]
    ExecutionFailed {
        /// Episode identifier.
        id: String,
        /// Error message.
        message: String,
    },

    /// Ledger persistence failed.
    ///
    /// Per REQ-0005, episode events must be persisted to the ledger. Failure
    /// to persist is a critical error (Fail-Closed).
    #[error("ledger persistence failed for episode {id}: {message}")]
    LedgerFailure {
        /// Episode identifier (or "unknown").
        id: String,
        /// Error message.
        message: String,
    },

    /// Session termination persistence failed (TCK-00385 MAJOR 1).
    ///
    /// Per the fail-closed contract (session/mod.rs), persistence failures
    /// during `mark_terminated` are fatal for the session lifecycle. The
    /// episode stop/quarantine operation succeeded, but the session registry
    /// could not persist the termination state.
    #[error(
        "session termination persistence failed for episode {episode_id}, session {session_id}: {message}"
    )]
    SessionTerminationFailed {
        /// Episode identifier.
        episode_id: String,
        /// Session identifier.
        session_id: String,
        /// Error message from the registry.
        message: String,
    },
}

impl EpisodeError {
    /// Returns `true` if this is a retriable error.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        matches!(self, Self::LimitReached { .. })
    }

    /// Returns the error kind as a string identifier.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::InvalidId { .. } => "invalid_id",
            Self::NotFound { .. } => "not_found",
            Self::InvalidTransition { .. } => "invalid_transition",
            Self::AlreadyExists { .. } => "already_exists",
            Self::LimitReached { .. } => "limit_reached",
            Self::InvalidLease { .. } => "invalid_lease",
            Self::EnvelopeValidation { .. } => "envelope_validation",
            Self::Internal { .. } => "internal",
            Self::ClockFailure { .. } => "clock_failure",
            Self::CustodyDomainViolation { .. } => "custody_domain_violation",
            Self::ExecutionFailed { .. } => "execution_failed",
            Self::LedgerFailure { .. } => "ledger_failure",
            Self::SessionTerminationFailed { .. } => "session_termination_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_episode_id_valid() {
        let id = EpisodeId::new("ep-123").unwrap();
        assert_eq!(id.as_str(), "ep-123");
        assert_eq!(format!("{id}"), "ep-123");
    }

    #[test]
    fn test_episode_id_empty_rejected() {
        let result = EpisodeId::new("");
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidId { reason, .. }) if reason.contains("empty")
        ));
    }

    #[test]
    fn test_episode_id_too_long_rejected() {
        let long_id = "x".repeat(MAX_EPISODE_ID_LEN + 1);
        let result = EpisodeId::new(long_id);
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidId { reason, .. }) if reason.contains("maximum length")
        ));
    }

    #[test]
    fn test_episode_id_null_rejected() {
        let result = EpisodeId::new("ep\x00123");
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidId { reason, .. }) if reason.contains("null")
        ));
    }

    #[test]
    fn test_episode_id_slash_rejected() {
        let result = EpisodeId::new("ep/123");
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidId { reason, .. }) if reason.contains("'/'")
        ));
    }

    #[test]
    fn test_error_kind_strings() {
        let err = EpisodeError::NotFound {
            id: "x".to_string(),
        };
        assert_eq!(err.kind(), "not_found");

        let err = EpisodeError::InvalidTransition {
            id: "x".to_string(),
            from: "Running",
            to: "Created",
        };
        assert_eq!(err.kind(), "invalid_transition");

        let err = EpisodeError::LedgerFailure {
            id: "ep-123".to_string(),
            message: "disk full".to_string(),
        };
        assert_eq!(err.kind(), "ledger_failure");
    }

    #[test]
    fn test_error_retriable() {
        assert!(EpisodeError::LimitReached { limit: 100 }.is_retriable());
        assert!(
            !EpisodeError::NotFound {
                id: "x".to_string()
            }
            .is_retriable()
        );
    }
}
