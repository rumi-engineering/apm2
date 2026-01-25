//! Error types for evidence operations.

use thiserror::Error;

use super::cas::CasError;
use super::category::EvidenceCategory;
use super::classification::DataClassification;

/// Errors that can occur during evidence operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvidenceError {
    /// Content-addressed store operation failed.
    #[error("CAS operation failed: {0}")]
    CasError(#[from] CasError),

    /// The evidence ID is invalid.
    #[error("invalid evidence ID: {value}")]
    InvalidEvidenceId {
        /// The invalid value.
        value: String,
    },

    /// The work ID is invalid.
    #[error("invalid work ID: {value}")]
    InvalidWorkId {
        /// The invalid value.
        value: String,
    },

    /// The gate ID is invalid.
    #[error("invalid gate ID: {value}")]
    InvalidGateId {
        /// The invalid value or reason.
        value: String,
    },

    /// The receipt ID is invalid.
    #[error("invalid receipt ID: {value}")]
    InvalidReceiptId {
        /// The invalid value or reason.
        value: String,
    },

    /// Evidence with this ID already exists.
    #[error("evidence already exists: {evidence_id}")]
    DuplicateEvidence {
        /// The duplicate evidence ID.
        evidence_id: String,
    },

    /// Evidence not found.
    #[error("evidence not found: {evidence_id}")]
    EvidenceNotFound {
        /// The evidence ID that was not found.
        evidence_id: String,
    },

    /// Invalid evidence category string.
    #[error("invalid evidence category: {value}")]
    InvalidCategory {
        /// The invalid value.
        value: String,
    },

    /// Invalid data classification string.
    #[error("invalid data classification: {value}")]
    InvalidClassification {
        /// The invalid value.
        value: String,
    },

    /// Content hash mismatch during verification.
    #[error("content hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The expected hash (hex-encoded).
        expected: String,
        /// The actual hash (hex-encoded).
        actual: String,
    },

    /// Metadata entry is malformed (missing '=' separator).
    #[error("malformed metadata entry at index {index}: missing '=' separator")]
    MalformedMetadata {
        /// The index of the malformed entry.
        index: usize,
    },

    /// Classification policy violation.
    #[error("classification policy violation: {message}")]
    ClassificationViolation {
        /// The required classification.
        required: DataClassification,
        /// The actual classification.
        actual: DataClassification,
        /// Description of the violation.
        message: String,
    },

    /// Category mismatch.
    #[error("category mismatch: expected {expected:?}, got {actual:?}")]
    CategoryMismatch {
        /// The expected category.
        expected: EvidenceCategory,
        /// The actual category.
        actual: EvidenceCategory,
    },

    /// Content exceeds maximum allowed size.
    #[error("content too large: {size} bytes exceeds maximum of {max_size} bytes")]
    ContentTooLarge {
        /// The actual size.
        size: usize,
        /// The maximum allowed size.
        max_size: usize,
    },

    /// Empty content is not allowed.
    #[error("empty content is not allowed")]
    EmptyContent,

    /// Verification command is invalid.
    #[error("invalid verification command at index {index}: {reason}")]
    InvalidVerificationCommand {
        /// The index of the invalid command.
        index: usize,
        /// The reason it's invalid.
        reason: String,
    },
}
