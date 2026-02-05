//! View commitment types (TCK-00325).
//!
//! This module defines the `ViewCommitmentV1` structure used to bind the
//! materialized workspace state to the policy resolution.
//!
//! # Overview
//!
//! Per SEC-CTRL-FAC-0015, review outcomes MUST bind to a verifiable view
//! commitment. The `ViewCommitmentV1` captures:
//!
//! - **Work identifier**: Links to the specific work/episode
//! - **Result digest**: Cryptographic hash of the workspace state
//! - **Policy binding**: Reference to the resolved policy
//! - **Timestamp**: When the view was committed
//!
//! # Security Properties
//!
//! - **Fail Closed**: Missing view commitment causes `ReviewBlockedRecorded`
//! - **CAS Storage**: Commitment is stored in CAS and referenced by hash
//! - **Policy Binding**: Links workspace state to policy resolution
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::ViewCommitmentV1;
//!
//! let commitment = ViewCommitmentV1::new(
//!     "work-001",
//!     "abc123...def456", // BLAKE3 hash of workspace state
//!     "policy-ref-001",
//!     1_704_067_200_000_000_000, // nanoseconds since epoch
//! );
//!
//! assert!(commitment.validate().is_ok());
//! let cas_hash = commitment.compute_cas_hash();
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// View Commitment V1 schema identifier.
pub const VIEW_COMMITMENT_V1_SCHEMA: &str = "apm2.view_commitment.v1";

/// Maximum length for `work_id` field.
pub const MAX_WORK_ID_LENGTH: usize = 256;

/// Maximum length for `policy_resolved_ref` field.
pub const MAX_POLICY_REF_LENGTH: usize = 256;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during view commitment operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ViewCommitmentError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Invalid schema identifier.
    #[error("invalid schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema.
        expected: String,
        /// Actual schema.
        actual: String,
    },

    /// Invalid result digest format.
    #[error("invalid result_digest: {0}")]
    InvalidResultDigest(String),
}

/// View Commitment V1.
///
/// Represents the state of the workspace view after materialization and
/// execution. This commitment binds the policy resolution to the resulting
/// file state.
///
/// # Security Properties
///
/// - **Policy Binding**: Binds the view to a specific policy resolution
///   (`policy_resolved_ref`).
/// - **State Integrity**: Binds the view to a specific filesystem state
///   (`result_digest`).
/// - **Temporal Authority**: Binds the view to a specific time
///   (`committed_at_ns`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewCommitmentV1 {
    /// Schema identifier (always `apm2.view_commitment.v1`).
    pub schema: String,

    /// The unique work identifier for this commitment.
    pub work_id: String,

    /// The digest of the workspace state (e.g., git tree hash or file hash).
    /// Typically a BLAKE3 hash of the directory content or git tree.
    pub result_digest: String,

    /// Reference to the policy resolution used for this view.
    pub policy_resolved_ref: String,

    /// Timestamp when this view was committed (nanoseconds since epoch).
    pub committed_at_ns: u64,
}

impl ViewCommitmentV1 {
    /// Creates a new view commitment.
    #[must_use]
    pub fn new(
        work_id: impl Into<String>,
        result_digest: impl Into<String>,
        policy_resolved_ref: impl Into<String>,
        committed_at_ns: u64,
    ) -> Self {
        Self {
            schema: VIEW_COMMITMENT_V1_SCHEMA.to_string(),
            work_id: work_id.into(),
            result_digest: result_digest.into(),
            policy_resolved_ref: policy_resolved_ref.into(),
            committed_at_ns,
        }
    }

    /// Creates a new builder for `ViewCommitmentV1`.
    #[must_use]
    pub fn builder() -> ViewCommitmentV1Builder {
        ViewCommitmentV1Builder::default()
    }

    /// Validates the view commitment.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails:
    /// - Schema identifier is invalid
    /// - Required fields are empty
    /// - String fields exceed maximum length
    /// - Result digest is not valid hex
    pub fn validate(&self) -> Result<(), ViewCommitmentError> {
        // Validate schema
        if self.schema != VIEW_COMMITMENT_V1_SCHEMA {
            return Err(ViewCommitmentError::InvalidSchema {
                expected: VIEW_COMMITMENT_V1_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }

        // Validate work_id
        if self.work_id.is_empty() {
            return Err(ViewCommitmentError::MissingField("work_id"));
        }
        if self.work_id.len() > MAX_WORK_ID_LENGTH {
            return Err(ViewCommitmentError::StringTooLong {
                field: "work_id",
                len: self.work_id.len(),
                max: MAX_WORK_ID_LENGTH,
            });
        }

        // Validate result_digest (should be 64 hex chars for BLAKE3)
        if self.result_digest.is_empty() {
            return Err(ViewCommitmentError::MissingField("result_digest"));
        }
        if self.result_digest.len() != 64 {
            return Err(ViewCommitmentError::InvalidResultDigest(
                "result_digest must be 64 hex characters".to_string(),
            ));
        }
        if !self.result_digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ViewCommitmentError::InvalidResultDigest(
                "result_digest must be hex-encoded".to_string(),
            ));
        }

        // Validate policy_resolved_ref
        if self.policy_resolved_ref.is_empty() {
            return Err(ViewCommitmentError::MissingField("policy_resolved_ref"));
        }
        if self.policy_resolved_ref.len() > MAX_POLICY_REF_LENGTH {
            return Err(ViewCommitmentError::StringTooLong {
                field: "policy_resolved_ref",
                len: self.policy_resolved_ref.len(),
                max: MAX_POLICY_REF_LENGTH,
            });
        }

        Ok(())
    }

    /// Computes the CAS hash of this commitment.
    ///
    /// # Panics
    ///
    /// Panics if serialization fails (should never happen for valid struct).
    #[must_use]
    pub fn compute_cas_hash(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("ViewCommitmentV1 is always serializable");
        *blake3::hash(&json).as_bytes()
    }
}

// =============================================================================
// ViewCommitmentV1Builder
// =============================================================================

/// Builder for constructing a `ViewCommitmentV1`.
#[derive(Debug, Default)]
pub struct ViewCommitmentV1Builder {
    work_id: Option<String>,
    result_digest: Option<String>,
    policy_resolved_ref: Option<String>,
    committed_at_ns: Option<u64>,
}

#[allow(clippy::missing_const_for_fn)] // Builder methods take `mut self` and can't be const
impl ViewCommitmentV1Builder {
    /// Sets the work ID.
    #[must_use]
    pub fn work_id(mut self, id: impl Into<String>) -> Self {
        self.work_id = Some(id.into());
        self
    }

    /// Sets the result digest (hex-encoded BLAKE3 hash).
    #[must_use]
    pub fn result_digest(mut self, digest: impl Into<String>) -> Self {
        self.result_digest = Some(digest.into());
        self
    }

    /// Sets the result digest from raw bytes.
    #[must_use]
    pub fn result_digest_bytes(mut self, digest: [u8; 32]) -> Self {
        self.result_digest = Some(hex::encode(digest));
        self
    }

    /// Sets the policy resolved reference.
    #[must_use]
    pub fn policy_resolved_ref(mut self, reference: impl Into<String>) -> Self {
        self.policy_resolved_ref = Some(reference.into());
        self
    }

    /// Sets the committed timestamp in nanoseconds.
    #[must_use]
    pub fn committed_at_ns(mut self, ts: u64) -> Self {
        self.committed_at_ns = Some(ts);
        self
    }

    /// Builds the `ViewCommitmentV1`.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build(self) -> Result<ViewCommitmentV1, ViewCommitmentError> {
        let commitment = ViewCommitmentV1 {
            schema: VIEW_COMMITMENT_V1_SCHEMA.to_string(),
            work_id: self
                .work_id
                .ok_or(ViewCommitmentError::MissingField("work_id"))?,
            result_digest: self
                .result_digest
                .ok_or(ViewCommitmentError::MissingField("result_digest"))?,
            policy_resolved_ref: self
                .policy_resolved_ref
                .ok_or(ViewCommitmentError::MissingField("policy_resolved_ref"))?,
            committed_at_ns: self
                .committed_at_ns
                .ok_or(ViewCommitmentError::MissingField("committed_at_ns"))?,
        };

        commitment.validate()?;
        Ok(commitment)
    }
}

// Note: DomainSeparator is typically implemented for events that are SIGNED.
// ViewCommitment is currently just a data structure stored in CAS and
// referenced by signed events (like ReviewReceiptRecorded). It acts as the
// "Body" of the view.
//
// If we need to sign the ViewCommitment directly, we would implement
// DomainSeparator. For now, it is bound via the ReviewArtifactBundle ->
// ReviewReceiptRecorded chain.

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_commitment_new() {
        let commitment = ViewCommitmentV1::new(
            "work-001",
            "a".repeat(64),
            "policy-ref-001",
            1_704_067_200_000_000_000,
        );

        assert_eq!(commitment.schema, VIEW_COMMITMENT_V1_SCHEMA);
        assert_eq!(commitment.work_id, "work-001");
        assert!(commitment.validate().is_ok());
    }

    #[test]
    fn test_view_commitment_builder() {
        let commitment = ViewCommitmentV1::builder()
            .work_id("work-002")
            .result_digest("b".repeat(64))
            .policy_resolved_ref("policy-ref-002")
            .committed_at_ns(1_704_067_200_000_000_000)
            .build()
            .expect("valid commitment");

        assert_eq!(commitment.work_id, "work-002");
        assert!(commitment.validate().is_ok());
    }

    #[test]
    fn test_view_commitment_builder_with_bytes() {
        let digest = [0x42u8; 32];
        let commitment = ViewCommitmentV1::builder()
            .work_id("work-003")
            .result_digest_bytes(digest)
            .policy_resolved_ref("policy-ref-003")
            .committed_at_ns(1_704_067_200_000_000_000)
            .build()
            .expect("valid commitment");

        assert_eq!(commitment.result_digest, hex::encode(digest));
    }

    #[test]
    fn test_view_commitment_validation_missing_fields() {
        // Missing work_id
        let result = ViewCommitmentV1::builder()
            .result_digest("a".repeat(64))
            .policy_resolved_ref("policy-ref")
            .committed_at_ns(1000)
            .build();
        assert!(matches!(
            result,
            Err(ViewCommitmentError::MissingField("work_id"))
        ));

        // Missing result_digest
        let result = ViewCommitmentV1::builder()
            .work_id("work-001")
            .policy_resolved_ref("policy-ref")
            .committed_at_ns(1000)
            .build();
        assert!(matches!(
            result,
            Err(ViewCommitmentError::MissingField("result_digest"))
        ));

        // Missing policy_resolved_ref
        let result = ViewCommitmentV1::builder()
            .work_id("work-001")
            .result_digest("a".repeat(64))
            .committed_at_ns(1000)
            .build();
        assert!(matches!(
            result,
            Err(ViewCommitmentError::MissingField("policy_resolved_ref"))
        ));
    }

    #[test]
    fn test_view_commitment_validation_invalid_digest() {
        // Wrong length
        let mut commitment = ViewCommitmentV1::new(
            "work-001",
            "abc", // Too short
            "policy-ref",
            1000,
        );
        assert!(matches!(
            commitment.validate(),
            Err(ViewCommitmentError::InvalidResultDigest(_))
        ));

        // Non-hex characters
        commitment.result_digest = "g".repeat(64); // 'g' is not hex
        assert!(matches!(
            commitment.validate(),
            Err(ViewCommitmentError::InvalidResultDigest(_))
        ));
    }

    #[test]
    fn test_view_commitment_validation_string_too_long() {
        let long_work_id = "x".repeat(MAX_WORK_ID_LENGTH + 1);
        let commitment = ViewCommitmentV1::new(long_work_id, "a".repeat(64), "policy-ref", 1000);
        assert!(matches!(
            commitment.validate(),
            Err(ViewCommitmentError::StringTooLong {
                field: "work_id",
                ..
            })
        ));
    }

    #[test]
    fn test_view_commitment_cas_hash_deterministic() {
        let commitment1 = ViewCommitmentV1::new(
            "work-001",
            "a".repeat(64),
            "policy-ref",
            1_704_067_200_000_000_000,
        );
        let commitment2 = ViewCommitmentV1::new(
            "work-001",
            "a".repeat(64),
            "policy-ref",
            1_704_067_200_000_000_000,
        );

        assert_eq!(
            commitment1.compute_cas_hash(),
            commitment2.compute_cas_hash()
        );
    }

    #[test]
    fn test_view_commitment_cas_hash_differs_on_change() {
        let commitment1 = ViewCommitmentV1::new(
            "work-001",
            "a".repeat(64),
            "policy-ref",
            1_704_067_200_000_000_000,
        );
        let commitment2 = ViewCommitmentV1::new(
            "work-002", // Different work_id
            "a".repeat(64),
            "policy-ref",
            1_704_067_200_000_000_000,
        );

        assert_ne!(
            commitment1.compute_cas_hash(),
            commitment2.compute_cas_hash()
        );
    }
}
