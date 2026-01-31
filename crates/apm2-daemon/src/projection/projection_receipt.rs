// AGENT-AUTHORED (TCK-00212)
//! Projection receipt types for the FAC GitHub projection adapter.
//!
//! This module defines [`ProjectionReceipt`] which provides cryptographic proof
//! that a status was successfully projected to an external system (e.g.,
//! GitHub).
//!
//! # Security Model
//!
//! - Receipts are signed using the `PROJECTION_RECEIPT:` domain prefix
//! - All fields except the signature are included in canonical bytes
//! - Length-prefixed encoding prevents canonicalization collision attacks
//! - The receipt cryptographically binds:
//!   - The work item being projected
//!   - The changeset digest
//!   - The ledger head at time of projection
//!   - The projected status value
//!
//! # Idempotency
//!
//! Projections are idempotent with the key `(work_id, changeset_digest,
//! ledger_head)`. If a projection is retried with the same key, the same
//! receipt should be returned.
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::crypto::Signer;
//! use apm2_daemon::projection::{ProjectionReceipt, ProjectionReceiptBuilder, ProjectedStatus};
//!
//! let signer = Signer::generate();
//! let receipt = ProjectionReceiptBuilder::new("receipt-001", "work-001")
//!     .changeset_digest([0x42; 32])
//!     .ledger_head([0xAB; 32])
//!     .projected_status(ProjectedStatus::Success)
//!     .build_and_sign(&signer);
//!
//! // Verify signature
//! assert!(receipt.validate_signature(&signer.verifying_key()).is_ok());
//! ```

use apm2_core::crypto::{Signature, Signer, VerifyingKey};
use apm2_core::fac::{PROJECTION_RECEIPT_PREFIX, sign_with_domain, verify_with_domain};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum length for string fields to prevent denial-of-service attacks.
pub const MAX_STRING_LENGTH: usize = 1024;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during projection receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionReceiptError {
    /// The receipt signature is invalid.
    #[error("invalid receipt signature: {0}")]
    InvalidSignature(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid receipt data.
    #[error("invalid receipt data: {0}")]
    InvalidData(String),

    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual length of the string.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
}

// =============================================================================
// ProjectedStatus
// =============================================================================

/// The status that was projected to the external system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProjectedStatus {
    /// Gates are still running (pending).
    Pending,

    /// All gates passed successfully.
    Success,

    /// One or more gates failed.
    Failure,

    /// Gates were cancelled.
    Cancelled,

    /// An error occurred during gate execution.
    Error,
}

impl ProjectedStatus {
    /// Returns the canonical byte representation for signing.
    #[must_use]
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Pending => b"PENDING",
            Self::Success => b"SUCCESS",
            Self::Failure => b"FAILURE",
            Self::Cancelled => b"CANCELLED",
            Self::Error => b"ERROR",
        }
    }

    /// Returns the status as a string for display/API purposes.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Cancelled => "cancelled",
            Self::Error => "error",
        }
    }
}

impl std::fmt::Display for ProjectedStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// IdempotencyKey
// =============================================================================

/// The idempotency key for projection operations.
///
/// A projection is idempotent when the same `(work_id, changeset_digest,
/// ledger_head)` tuple is used. Retrying with the same key should return the
/// same receipt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey {
    /// The work item ID.
    pub work_id: String,
    /// The changeset digest (32 bytes).
    pub changeset_digest: [u8; 32],
    /// The ledger head hash at time of projection (32 bytes).
    pub ledger_head: [u8; 32],
}

impl IdempotencyKey {
    /// Creates a new idempotency key.
    #[must_use]
    pub fn new(
        work_id: impl Into<String>,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
    ) -> Self {
        Self {
            work_id: work_id.into(),
            changeset_digest,
            ledger_head,
        }
    }

    /// Returns the canonical bytes for this key.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 4 + self.work_id.len() + 32 + 32;
        let mut bytes = Vec::with_capacity(capacity);

        // work_id (length-prefixed)
        bytes.extend_from_slice(&(self.work_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.work_id.as_bytes());

        // changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // ledger_head
        bytes.extend_from_slice(&self.ledger_head);

        bytes
    }
}

// =============================================================================
// ProjectionReceipt
// =============================================================================

/// A cryptographically signed receipt proving a status was projected.
///
/// This receipt is generated after successfully projecting a status to an
/// external system (e.g., GitHub commit status). It provides cryptographic
/// proof of the projection.
///
/// # Fields (7 total)
///
/// - `receipt_id`: Unique identifier for this receipt
/// - `work_id`: Work item that was projected
/// - `changeset_digest`: Hash binding to specific changeset
/// - `ledger_head`: Ledger head hash at time of projection
/// - `projected_status`: The status that was projected
/// - `projected_at`: Unix timestamp (nanoseconds) when projection occurred
/// - `adapter_signature`: Ed25519 signature with domain separation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: String,

    /// Work item ID that was projected.
    pub work_id: String,

    /// Hash binding to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Ledger head hash at time of projection.
    #[serde(with = "serde_bytes")]
    pub ledger_head: [u8; 32],

    /// The status that was projected.
    pub projected_status: ProjectedStatus,

    /// Unix timestamp (nanoseconds) when projection occurred.
    pub projected_at: u64,

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub adapter_signature: [u8; 64],
}

impl ProjectionReceipt {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes all fields except the signature,
    /// encoded in a deterministic order.
    ///
    /// # Encoding
    ///
    /// Uses length-prefixed encoding (4-byte big-endian u32) for
    /// variable-length strings to prevent canonicalization collision
    /// attacks.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 4 + self.receipt_id.len()
            + 4 + self.work_id.len()
            + 32  // changeset_digest
            + 32  // ledger_head
            + 16  // projected_status (fixed max)
            + 8; // projected_at

        let mut bytes = Vec::with_capacity(capacity);

        // 1. receipt_id (length-prefixed)
        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        // 2. work_id (length-prefixed)
        bytes.extend_from_slice(&(self.work_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.work_id.as_bytes());

        // 3. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 4. ledger_head
        bytes.extend_from_slice(&self.ledger_head);

        // 5. projected_status (length-prefixed for consistency)
        let status_bytes = self.projected_status.as_bytes();
        bytes.extend_from_slice(&(status_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(status_bytes);

        // 6. projected_at (big-endian)
        bytes.extend_from_slice(&self.projected_at.to_be_bytes());

        bytes
    }

    /// Validates the receipt signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected adapter
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid,
    /// `Err(ProjectionReceiptError::InvalidSignature)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionReceiptError::InvalidSignature`] if signature
    /// verification fails.
    pub fn validate_signature(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), ProjectionReceiptError> {
        let signature = Signature::from_bytes(&self.adapter_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(
            verifying_key,
            PROJECTION_RECEIPT_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|e| ProjectionReceiptError::InvalidSignature(e.to_string()))
    }

    /// Returns the idempotency key for this receipt.
    #[must_use]
    pub fn idempotency_key(&self) -> IdempotencyKey {
        IdempotencyKey {
            work_id: self.work_id.clone(),
            changeset_digest: self.changeset_digest,
            ledger_head: self.ledger_head,
        }
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`ProjectionReceipt`] instances.
#[derive(Debug, Default)]
pub struct ProjectionReceiptBuilder {
    receipt_id: String,
    work_id: String,
    changeset_digest: Option<[u8; 32]>,
    ledger_head: Option<[u8; 32]>,
    projected_status: Option<ProjectedStatus>,
    projected_at: Option<u64>,
}

impl ProjectionReceiptBuilder {
    /// Creates a new builder with required IDs.
    #[must_use]
    pub fn new(receipt_id: impl Into<String>, work_id: impl Into<String>) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            work_id: work_id.into(),
            ..Default::default()
        }
    }

    /// Sets the changeset digest.
    #[must_use]
    pub const fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the ledger head.
    #[must_use]
    pub const fn ledger_head(mut self, head: [u8; 32]) -> Self {
        self.ledger_head = Some(head);
        self
    }

    /// Sets the projected status.
    #[must_use]
    pub const fn projected_status(mut self, status: ProjectedStatus) -> Self {
        self.projected_status = Some(status);
        self
    }

    /// Sets the projection timestamp.
    #[must_use]
    pub const fn projected_at(mut self, timestamp: u64) -> Self {
        self.projected_at = Some(timestamp);
        self
    }

    /// Builds the receipt and signs it with the provided signer.
    ///
    /// # `BOUNDARY_INTEGRITY` Compliance
    ///
    /// Per the `BOUNDARY_INTEGRITY` constraint, `projected_at` MUST be
    /// explicitly set by the adapter using its injected `TimeSource`.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing (including `projected_at`).
    #[must_use]
    pub fn build_and_sign(self, signer: &Signer) -> ProjectionReceipt {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the receipt.
    ///
    /// # `BOUNDARY_INTEGRITY` Compliance
    ///
    /// Per the `BOUNDARY_INTEGRITY` constraint, `projected_at` MUST be
    /// explicitly set by the adapter using its injected `TimeSource`. This
    /// prevents direct use of `SystemTime::now()` at the boundary layer.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionReceiptError::MissingField`] if any required field
    /// is not set (including `projected_at`).
    /// Returns [`ProjectionReceiptError::StringTooLong`] if any string field
    /// exceeds the maximum length.
    #[allow(clippy::cast_possible_truncation)]
    pub fn try_build_and_sign(
        self,
        signer: &Signer,
    ) -> Result<ProjectionReceipt, ProjectionReceiptError> {
        let changeset_digest = self
            .changeset_digest
            .ok_or(ProjectionReceiptError::MissingField("changeset_digest"))?;
        let ledger_head = self
            .ledger_head
            .ok_or(ProjectionReceiptError::MissingField("ledger_head"))?;
        let projected_status = self
            .projected_status
            .ok_or(ProjectionReceiptError::MissingField("projected_status"))?;

        // `BOUNDARY_INTEGRITY`: projected_at must be explicitly set by the adapter
        // using its injected TimeSource. No SystemTime::now() fallback allowed.
        let projected_at = self
            .projected_at
            .ok_or(ProjectionReceiptError::MissingField("projected_at"))?;

        // Validate string lengths
        if self.receipt_id.len() > MAX_STRING_LENGTH {
            return Err(ProjectionReceiptError::StringTooLong {
                field: "receipt_id",
                actual: self.receipt_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.work_id.len() > MAX_STRING_LENGTH {
            return Err(ProjectionReceiptError::StringTooLong {
                field: "work_id",
                actual: self.work_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Create receipt with placeholder signature
        let mut receipt = ProjectionReceipt {
            receipt_id: self.receipt_id,
            work_id: self.work_id,
            changeset_digest,
            ledger_head,
            projected_status,
            projected_at,
            adapter_signature: [0u8; 64],
        };

        // Sign the canonical bytes
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, PROJECTION_RECEIPT_PREFIX, &canonical);
        receipt.adapter_signature = signature.to_bytes();

        Ok(receipt)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_receipt(signer: &Signer) -> ProjectionReceipt {
        ProjectionReceiptBuilder::new("receipt-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000) // Fixed timestamp for deterministic tests
            .build_and_sign(signer)
    }

    // =========================================================================
    // ProjectedStatus Tests
    // =========================================================================

    #[test]
    fn test_projected_status_as_bytes() {
        assert_eq!(ProjectedStatus::Pending.as_bytes(), b"PENDING");
        assert_eq!(ProjectedStatus::Success.as_bytes(), b"SUCCESS");
        assert_eq!(ProjectedStatus::Failure.as_bytes(), b"FAILURE");
        assert_eq!(ProjectedStatus::Cancelled.as_bytes(), b"CANCELLED");
        assert_eq!(ProjectedStatus::Error.as_bytes(), b"ERROR");
    }

    #[test]
    fn test_projected_status_as_str() {
        assert_eq!(ProjectedStatus::Pending.as_str(), "pending");
        assert_eq!(ProjectedStatus::Success.as_str(), "success");
        assert_eq!(ProjectedStatus::Failure.as_str(), "failure");
        assert_eq!(ProjectedStatus::Cancelled.as_str(), "cancelled");
        assert_eq!(ProjectedStatus::Error.as_str(), "error");
    }

    #[test]
    fn test_projected_status_display() {
        assert_eq!(format!("{}", ProjectedStatus::Success), "success");
        assert_eq!(format!("{}", ProjectedStatus::Failure), "failure");
    }

    // =========================================================================
    // IdempotencyKey Tests
    // =========================================================================

    #[test]
    fn test_idempotency_key_equality() {
        let key1 = IdempotencyKey::new("work-001", [0x42; 32], [0xAB; 32]);
        let key2 = IdempotencyKey::new("work-001", [0x42; 32], [0xAB; 32]);
        let key3 = IdempotencyKey::new("work-002", [0x42; 32], [0xAB; 32]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_idempotency_key_hash() {
        use std::collections::HashSet;

        let key1 = IdempotencyKey::new("work-001", [0x42; 32], [0xAB; 32]);
        let key2 = IdempotencyKey::new("work-001", [0x42; 32], [0xAB; 32]);

        let mut set = HashSet::new();
        set.insert(key1);
        assert!(set.contains(&key2));
    }

    #[test]
    fn test_idempotency_key_canonical_bytes() {
        let key = IdempotencyKey::new("work-001", [0x42; 32], [0xAB; 32]);
        let bytes = key.canonical_bytes();

        // 4 bytes length + 8 bytes "work-001" + 32 bytes changeset + 32 bytes ledger
        assert_eq!(bytes.len(), 4 + 8 + 32 + 32);

        // Verify structure
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(len, 8); // "work-001".len()
        assert_eq!(&bytes[4..12], b"work-001");
        assert_eq!(&bytes[12..44], &[0x42; 32]);
        assert_eq!(&bytes[44..76], &[0xAB; 32]);
    }

    // =========================================================================
    // ProjectionReceipt Build Tests
    // =========================================================================

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        assert_eq!(receipt.receipt_id, "receipt-001");
        assert_eq!(receipt.work_id, "work-001");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.ledger_head, [0xAB; 32]);
        assert_eq!(receipt.projected_status, ProjectedStatus::Success);
        assert_eq!(receipt.projected_at, 1_704_067_200_000_000_000);
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        // Missing changeset_digest
        let result = ProjectionReceiptBuilder::new("receipt-001", "work-001")
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::MissingField("changeset_digest"))
        ));

        // Missing ledger_head
        let result = ProjectionReceiptBuilder::new("receipt-001", "work-001")
            .changeset_digest([0x42; 32])
            .projected_status(ProjectedStatus::Success)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::MissingField("ledger_head"))
        ));

        // Missing projected_status
        let result = ProjectionReceiptBuilder::new("receipt-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::MissingField("projected_status"))
        ));
    }

    #[test]
    fn test_string_too_long_error() {
        let signer = Signer::generate();
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = ProjectionReceiptBuilder::new(long_string, "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::StringTooLong {
                field: "receipt_id",
                ..
            })
        ));
    }

    #[test]
    fn test_missing_projected_at_error() {
        // `BOUNDARY_INTEGRITY`: projected_at must be explicitly provided
        let signer = Signer::generate();
        let result = ProjectionReceiptBuilder::new("receipt-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            // No projected_at - should fail
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::MissingField("projected_at"))
        ));
    }

    // =========================================================================
    // Signature Tests
    // =========================================================================

    #[test]
    fn test_signature_validation() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Valid signature
        assert!(receipt.validate_signature(&signer.verifying_key()).is_ok());

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            receipt
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);

        // Modify content after signing
        receipt.work_id = "work-other".to_string();

        // Signature should now be invalid
        assert!(receipt.validate_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_domain_separator_prevents_replay() {
        // Verify that receipt uses PROJECTION_RECEIPT: domain separator
        // by ensuring a signature created without the prefix fails
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Create a signature without domain prefix
        let canonical = receipt.canonical_bytes();
        let wrong_signature = signer.sign(&canonical); // No domain prefix!

        // Manually create a receipt with the wrong signature
        let mut bad_receipt = receipt;
        bad_receipt.adapter_signature = wrong_signature.to_bytes();

        // Verification should fail
        assert!(
            bad_receipt
                .validate_signature(&signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let receipt1 = create_test_receipt(&signer);
        let receipt2 = create_test_receipt(&signer);

        // Same content should produce same canonical bytes
        assert_eq!(receipt1.canonical_bytes(), receipt2.canonical_bytes());
    }

    #[test]
    fn test_deterministic_signatures() {
        let signer = Signer::generate();
        let receipt1 = create_test_receipt(&signer);
        let receipt2 = create_test_receipt(&signer);

        // Ed25519 is deterministic, so signatures should match
        assert_eq!(receipt1.adapter_signature, receipt2.adapter_signature);
    }

    #[test]
    fn test_length_prefixed_canonicalization_prevents_collision() {
        let signer = Signer::generate();

        // Create two receipts with different field values that could collide
        // with null-termination but not with length-prefixing
        let receipt1 = ProjectionReceiptBuilder::new("ab", "cd")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .build_and_sign(&signer);

        // "ab" + "cd" should NOT equal "a" + "bcd" with length-prefixing
        let receipt2 = ProjectionReceiptBuilder::new("a", "bcd")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .build_and_sign(&signer);

        // Canonical bytes should be different
        assert_ne!(receipt1.canonical_bytes(), receipt2.canonical_bytes());
    }

    // =========================================================================
    // Idempotency Key Extraction Tests
    // =========================================================================

    #[test]
    fn test_idempotency_key_extraction() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        let key = receipt.idempotency_key();
        assert_eq!(key.work_id, "work-001");
        assert_eq!(key.changeset_digest, [0x42; 32]);
        assert_eq!(key.ledger_head, [0xAB; 32]);
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_serde_roundtrip() {
        let signer = Signer::generate();
        let original = create_test_receipt(&signer);

        let json = serde_json::to_string(&original).unwrap();
        let recovered: ProjectionReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(original.receipt_id, recovered.receipt_id);
        assert_eq!(original.work_id, recovered.work_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(original.ledger_head, recovered.ledger_head);
        assert_eq!(original.projected_status, recovered.projected_status);
        assert_eq!(original.projected_at, recovered.projected_at);
        assert_eq!(original.adapter_signature, recovered.adapter_signature);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }
}
