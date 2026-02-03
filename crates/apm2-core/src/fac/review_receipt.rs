// AGENT-AUTHORED
//! Review receipt and artifact bundle types for FAC v0.
//!
//! This module implements the `ReviewReceiptRecorded` event and
//! `ReviewArtifactBundleV1` used to record successful review completion and
//! store review artifacts.
//!
//! # Design Overview
//!
//! - `ReviewArtifactBundleV1`: JSON bundle stored in CAS containing review text
//!   hash, tool logs, and metadata.
//! - `ReviewReceiptRecorded`: Ledger event binding the changeset to the
//!   artifact bundle.
//!
//! # Security Properties
//!
//! - **Domain Separation**: `REVIEW_RECEIPT_RECORDED:` prefix for signatures.
//! - **CAS Binding**: Artifacts are off-loaded to CAS; only hashes stored in
//!   ledger.
//! - **Resource Limits**: Strict bounds on metadata, log counts, and string
//!   lengths.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{
    REVIEW_RECEIPT_RECORDED_PREFIX, sign_with_domain, verify_with_domain,
};
use crate::crypto::{Signature, Signer, VerifyingKey};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for review ID.
pub const MAX_REVIEW_ID_LENGTH: usize = 128;

/// Maximum length for generic strings.
pub const MAX_STRING_LENGTH: usize = 256;

/// Maximum number of tool logs.
pub const MAX_TOOL_LOGS: usize = 1024;

/// Maximum number of metadata entries.
pub const MAX_METADATA_KEYS: usize = 32;

/// Maximum length for metadata keys.
pub const MAX_METADATA_KEY_LEN: usize = 64;

/// Maximum length for metadata values.
pub const MAX_METADATA_VALUE_LEN: usize = 1024;

/// Schema identifier for `ReviewArtifactBundleV1`.
pub const BUNDLE_SCHEMA: &str = "apm2.review_artifact_bundle.v1";

/// Current schema version.
pub const BUNDLE_VERSION: &str = "1.0.0";

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during review receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReviewReceiptError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// List field exceeds maximum items.
    #[error("list field '{field}' exceeds maximum items ({len} > {max})")]
    ListTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid data format.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

// =============================================================================
// ReviewArtifactBundleV1
// =============================================================================

/// CAS-hosted bundle containing review artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewArtifactBundleV1 {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Unique review ID.
    pub review_id: String,
    /// Changeset digest.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],
    /// Hash of review text in CAS.
    #[serde(with = "serde_bytes")]
    pub review_text_hash: [u8; 32],
    /// Hashes of tool logs in CAS.
    pub tool_log_hashes: Vec<String>, // Hex-encoded strings in JSON

    /// Metadata key-value pairs.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,

    /// HTF time envelope ref (hex encoded in JSON).
    pub time_envelope_ref: String,
}

impl ReviewArtifactBundleV1 {
    /// Validates resource limits.
    ///
    /// # Errors
    ///
    /// Returns error if limits are exceeded.
    pub fn validate(&self) -> Result<(), ReviewReceiptError> {
        if self.review_id.len() > MAX_REVIEW_ID_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "review_id",
                len: self.review_id.len(),
                max: MAX_REVIEW_ID_LENGTH,
            });
        }
        if self.tool_log_hashes.len() > MAX_TOOL_LOGS {
            return Err(ReviewReceiptError::ListTooLong {
                field: "tool_log_hashes",
                len: self.tool_log_hashes.len(),
                max: MAX_TOOL_LOGS,
            });
        }
        if self.metadata.len() > MAX_METADATA_KEYS {
            return Err(ReviewReceiptError::ListTooLong {
                field: "metadata",
                len: self.metadata.len(),
                max: MAX_METADATA_KEYS,
            });
        }
        for (k, v) in &self.metadata {
            if k.len() > MAX_METADATA_KEY_LEN {
                return Err(ReviewReceiptError::StringTooLong {
                    field: "metadata_key",
                    len: k.len(),
                    max: MAX_METADATA_KEY_LEN,
                });
            }
            if v.len() > MAX_METADATA_VALUE_LEN {
                return Err(ReviewReceiptError::StringTooLong {
                    field: "metadata_value",
                    len: v.len(),
                    max: MAX_METADATA_VALUE_LEN,
                });
            }
        }
        Ok(())
    }
}

// =============================================================================
// ReviewReceiptRecorded
// =============================================================================

/// Ledger event recording a successful review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewReceiptRecorded {
    /// Unique review ID.
    pub review_id: String,
    /// Changeset digest (32 bytes).
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],
    /// Artifact bundle hash (32 bytes).
    #[serde(with = "serde_bytes")]
    pub artifact_bundle_hash: [u8; 32],
    /// HTF time envelope reference (32 bytes).
    #[serde(with = "serde_bytes")]
    pub time_envelope_ref: [u8; 32],
    /// Reviewer actor ID.
    pub reviewer_actor_id: String,
    /// Signature (64 bytes).
    #[serde(with = "serde_bytes")]
    pub reviewer_signature: [u8; 64],
}

impl ReviewReceiptRecorded {
    /// Creates a new `ReviewReceiptRecorded` event.
    ///
    /// # Errors
    ///
    /// Returns error if string limits are exceeded.
    pub fn create(
        review_id: String,
        changeset_digest: [u8; 32],
        artifact_bundle_hash: [u8; 32],
        time_envelope_ref: [u8; 32],
        reviewer_actor_id: String,
        signer: &Signer,
    ) -> Result<Self, ReviewReceiptError> {
        if review_id.len() > MAX_REVIEW_ID_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "review_id",
                len: review_id.len(),
                max: MAX_REVIEW_ID_LENGTH,
            });
        }
        if reviewer_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "reviewer_actor_id",
                len: reviewer_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let mut event = Self {
            review_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            reviewer_actor_id,
            reviewer_signature: [0u8; 64],
        };

        let canonical = event.canonical_bytes();
        let signature = sign_with_domain(signer, REVIEW_RECEIPT_RECORDED_PREFIX, &canonical);
        event.reviewer_signature = signature.to_bytes();

        Ok(event)
    }

    /// Computes canonical bytes for signing.
    /// Encoding:
    /// - `review_id` (len + bytes)
    /// - `changeset_digest` (32 bytes)
    /// - `artifact_bundle_hash` (32 bytes)
    /// - `time_envelope_ref` (32 bytes)
    /// - `reviewer_actor_id` (len + bytes)
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(
            &u32::try_from(self.review_id.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(self.review_id.as_bytes());

        bytes.extend_from_slice(&self.changeset_digest);
        bytes.extend_from_slice(&self.artifact_bundle_hash);
        bytes.extend_from_slice(&self.time_envelope_ref);

        bytes.extend_from_slice(
            &u32::try_from(self.reviewer_actor_id.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(self.reviewer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the signature on the event.
    ///
    /// # Errors
    ///
    /// Returns error if verification fails.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), ReviewReceiptError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.reviewer_signature);

        verify_with_domain(key, REVIEW_RECEIPT_RECORDED_PREFIX, &canonical, &signature)
            .map_err(|e| ReviewReceiptError::SignatureVerificationFailed(e.to_string()))
    }
}

// =============================================================================
// Proto Conversions
// =============================================================================

pub use crate::events::ReviewReceiptRecorded as ReviewReceiptRecordedProto;

impl TryFrom<ReviewReceiptRecordedProto> for ReviewReceiptRecorded {
    type Error = ReviewReceiptError;

    fn try_from(proto: ReviewReceiptRecordedProto) -> Result<Self, Self::Error> {
        if proto.review_id.len() > MAX_REVIEW_ID_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "review_id",
                len: proto.review_id.len(),
                max: MAX_REVIEW_ID_LENGTH,
            });
        }
        if proto.reviewer_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "reviewer_actor_id",
                len: proto.reviewer_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let changeset_digest = proto.changeset_digest.try_into().map_err(|_| {
            ReviewReceiptError::InvalidData("changeset_digest must be 32 bytes".into())
        })?;

        let artifact_bundle_hash = proto.artifact_bundle_hash.try_into().map_err(|_| {
            ReviewReceiptError::InvalidData("artifact_bundle_hash must be 32 bytes".into())
        })?;

        let time_envelope_ref = proto
            .time_envelope_ref
            .as_ref()
            .map(|ter| {
                ter.hash.as_slice().try_into().map_err(|_| {
                    ReviewReceiptError::InvalidData("time_envelope_ref must be 32 bytes".into())
                })
            })
            .transpose()?
            .unwrap_or([0u8; 32]);

        let reviewer_signature = proto.reviewer_signature.try_into().map_err(|_| {
            ReviewReceiptError::InvalidData("reviewer_signature must be 64 bytes".into())
        })?;

        Ok(Self {
            review_id: proto.review_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            reviewer_actor_id: proto.reviewer_actor_id,
            reviewer_signature,
        })
    }
}

impl From<ReviewReceiptRecorded> for ReviewReceiptRecordedProto {
    fn from(event: ReviewReceiptRecorded) -> Self {
        use crate::events::TimeEnvelopeRef as TimeEnvelopeRefProto;

        Self {
            review_id: event.review_id,
            changeset_digest: event.changeset_digest.to_vec(),
            artifact_bundle_hash: event.artifact_bundle_hash.to_vec(),
            time_envelope_ref: Some(TimeEnvelopeRefProto {
                hash: event.time_envelope_ref.to_vec(),
            }),
            reviewer_actor_id: event.reviewer_actor_id,
            reviewer_signature: event.reviewer_signature.to_vec(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_review_receipt_create_and_verify() {
        let signer = Signer::generate();
        let event = ReviewReceiptRecorded::create(
            "rev-001".into(),
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            "actor-001".into(),
            &signer,
        )
        .unwrap();

        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_review_receipt_tamper() {
        let signer = Signer::generate();
        let mut event = ReviewReceiptRecorded::create(
            "rev-001".into(),
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            "actor-001".into(),
            &signer,
        )
        .unwrap();

        event.review_id = "rev-002".into();
        assert!(event.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_artifact_bundle_validation() {
        let mut bundle = ReviewArtifactBundleV1 {
            schema: BUNDLE_SCHEMA.into(),
            schema_version: BUNDLE_VERSION.into(),
            review_id: "rev-001".into(),
            changeset_digest: [0u8; 32],
            review_text_hash: [0u8; 32],
            tool_log_hashes: vec![],
            metadata: BTreeMap::new(),
            time_envelope_ref: "00".repeat(32),
        };

        assert!(bundle.validate().is_ok());

        // Test metadata limit
        for i in 0..=MAX_METADATA_KEYS {
            bundle.metadata.insert(format!("k{i}"), "v".into());
        }
        assert!(matches!(
            bundle.validate(),
            Err(ReviewReceiptError::ListTooLong {
                field: "metadata",
                ..
            })
        ));
    }
}
