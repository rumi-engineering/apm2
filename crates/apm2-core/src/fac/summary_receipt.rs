// AGENT-AUTHORED
//! Summary receipt types for lossy-but-verifiable review outcomes.
//!
//! This module implements [`SummaryReceipt`] per TCK-00327 and RFC-0019.
//! The summary receipt provides a "front page" for review outcomes with
//! loss profile and selectors enabling efficient queries without full
//! artifact retrieval.
//!
//! # Design Overview
//!
//! Per CTR-0006 in RFC-0019, `SummaryReceipt` is a lossy-but-verifiable
//! summary with:
//! - Loss profile describing what was omitted/summarized
//! - Selectors for efficient querying
//! - Reference to full artifact hashes for verification
//!
//! # Security Model
//!
//! - **Signed Binding**: Summary is signed to prevent tampering
//! - **Loss Profile**: Explicitly declares what information is omitted
//! - **Verifiable**: References to full artifacts enable verification
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{LossProfile, ReviewOutcome, SummaryReceiptBuilder};
//!
//! let signer = Signer::generate();
//! let summary = SummaryReceiptBuilder::new()
//!     .review_id("review-001")
//!     .changeset_digest([0x42; 32])
//!     .outcome(ReviewOutcome::Approved)
//!     .tool_log_index_hash([0x11; 32])
//!     .artifact_bundle_hash([0x22; 32])
//!     .loss_profile(LossProfile::default())
//!     .time_envelope_ref([0x44; 32])
//!     .build_and_sign(&signer)
//!     .expect("valid summary");
//!
//! assert!(summary.verify_signature(&signer.verifying_key()).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{sign_with_domain, verify_with_domain};
use crate::crypto::{Signature, Signer, VerifyingKey};

// =============================================================================
// Domain Separator
// =============================================================================

/// Domain prefix for `SummaryReceipt` signatures.
pub const SUMMARY_RECEIPT_PREFIX: &[u8] = b"SUMMARY_RECEIPT:";

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for review ID.
pub const MAX_REVIEW_ID_LENGTH: usize = 128;

/// Maximum length for summary text.
pub const MAX_SUMMARY_TEXT_LENGTH: usize = 4096;

/// Maximum number of selector tags.
pub const MAX_SELECTOR_TAGS: usize = 64;

/// Maximum length for a single selector tag.
pub const MAX_SELECTOR_TAG_LENGTH: usize = 128;

/// Schema identifier for `SummaryReceipt`.
pub const SUMMARY_RECEIPT_SCHEMA: &str = "apm2.summary_receipt.v1";

/// Current schema version.
pub const SUMMARY_RECEIPT_VERSION: &str = "1.0.0";

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during summary receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SummaryReceiptError {
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

    /// Collection size exceeds limit.
    #[error("collection size exceeds limit: {field} has {actual} items, max is {max}")]
    CollectionTooLarge {
        /// The field name.
        field: &'static str,
        /// Actual size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

// =============================================================================
// ReviewOutcome
// =============================================================================

/// Outcome of a review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewOutcome {
    /// Review approved the changeset.
    Approved,
    /// Review requested changes.
    RequestedChanges,
    /// Review left comments without verdict.
    Commented,
    /// Review was blocked due to failure.
    Blocked,
}

impl std::fmt::Display for ReviewOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approved => write!(f, "APPROVED"),
            Self::RequestedChanges => write!(f, "REQUESTED_CHANGES"),
            Self::Commented => write!(f, "COMMENTED"),
            Self::Blocked => write!(f, "BLOCKED"),
        }
    }
}

impl ReviewOutcome {
    /// Returns the numeric code for this outcome.
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::Approved => 1,
            Self::RequestedChanges => 2,
            Self::Commented => 3,
            Self::Blocked => 4,
        }
    }

    /// Creates an outcome from its numeric code.
    ///
    /// # Errors
    ///
    /// Returns error if the code is invalid.
    pub fn from_code(code: u8) -> Result<Self, SummaryReceiptError> {
        match code {
            1 => Ok(Self::Approved),
            2 => Ok(Self::RequestedChanges),
            3 => Ok(Self::Commented),
            4 => Ok(Self::Blocked),
            _ => Err(SummaryReceiptError::InvalidData(format!(
                "invalid outcome code: {code}"
            ))),
        }
    }
}

// =============================================================================
// LossProfile
// =============================================================================

/// Describes what information was omitted or summarized.
///
/// The loss profile enables consumers to understand the trade-offs between
/// summary compactness and information completeness.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossProfile {
    /// Whether the full review text was omitted.
    pub review_text_omitted: bool,
    /// Whether individual tool logs were omitted.
    pub tool_logs_omitted: bool,
    /// Whether line-level comments were aggregated.
    pub comments_aggregated: bool,
    /// Number of tool executions summarized (vs. individually listed).
    pub tool_count_summarized: u64,
    /// Number of files affected (summary statistic).
    pub files_affected: u64,
    /// Total lines changed (summary statistic).
    pub lines_changed: u64,
    /// Custom loss descriptors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_losses: Vec<String>,
}

impl LossProfile {
    /// Creates a new loss profile with no losses.
    #[must_use]
    pub const fn lossless() -> Self {
        Self {
            review_text_omitted: false,
            tool_logs_omitted: false,
            comments_aggregated: false,
            tool_count_summarized: 0,
            files_affected: 0,
            lines_changed: 0,
            custom_losses: Vec::new(),
        }
    }

    /// Sets the review text omitted flag.
    #[must_use]
    pub const fn with_review_text_omitted(mut self, omitted: bool) -> Self {
        self.review_text_omitted = omitted;
        self
    }

    /// Sets the tool logs omitted flag.
    #[must_use]
    pub const fn with_tool_logs_omitted(mut self, omitted: bool) -> Self {
        self.tool_logs_omitted = omitted;
        self
    }

    /// Sets the comments aggregated flag.
    #[must_use]
    pub const fn with_comments_aggregated(mut self, aggregated: bool) -> Self {
        self.comments_aggregated = aggregated;
        self
    }

    /// Sets the tool count summarized.
    #[must_use]
    pub const fn with_tool_count_summarized(mut self, count: u64) -> Self {
        self.tool_count_summarized = count;
        self
    }

    /// Sets the files affected count.
    #[must_use]
    pub const fn with_files_affected(mut self, count: u64) -> Self {
        self.files_affected = count;
        self
    }

    /// Sets the lines changed count.
    #[must_use]
    pub const fn with_lines_changed(mut self, count: u64) -> Self {
        self.lines_changed = count;
        self
    }

    /// Returns `true` if this profile indicates any loss.
    #[must_use]
    pub fn has_loss(&self) -> bool {
        self.review_text_omitted
            || self.tool_logs_omitted
            || self.comments_aggregated
            || self.tool_count_summarized > 0
            || !self.custom_losses.is_empty()
    }
}

// =============================================================================
// SummaryReceipt
// =============================================================================

/// A lossy-but-verifiable summary receipt for review outcomes.
///
/// This provides a compact "front page" for review outcomes that can be
/// efficiently queried without retrieving full artifacts.
///
/// # Fields
///
/// - `schema`: Schema identifier
/// - `schema_version`: Schema version
/// - `review_id`: Unique review identifier
/// - `changeset_digest`: BLAKE3 digest of the reviewed changeset
/// - `outcome`: Review outcome (`Approved`, `RequestedChanges`, etc.)
/// - `summary_text`: Optional human-readable summary
/// - `tool_log_index_hash`: Hash of the `ToolLogIndexV1` in CAS
/// - `artifact_bundle_hash`: Hash of the `ReviewArtifactBundleV1` in CAS
/// - `loss_profile`: Description of omitted/summarized information
/// - `selectors`: Tags for efficient querying
/// - `time_envelope_ref`: HTF time envelope reference
/// - `signer_identity`: Hex-encoded public key of signer
/// - `signature`: Ed25519 signature with domain separation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Unique review identifier.
    pub review_id: String,
    /// BLAKE3 digest of the reviewed changeset (32 bytes, hex-encoded).
    pub changeset_digest: String,
    /// Review outcome.
    pub outcome: ReviewOutcome,
    /// Optional human-readable summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_text: Option<String>,
    /// Hash of the `ToolLogIndexV1` in CAS (32 bytes, hex-encoded).
    pub tool_log_index_hash: String,
    /// Hash of the `ReviewArtifactBundleV1` in CAS (32 bytes, hex-encoded).
    pub artifact_bundle_hash: String,
    /// Description of omitted/summarized information.
    pub loss_profile: LossProfile,
    /// Tags for efficient querying.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    /// HTF time envelope reference hash (32 bytes, hex-encoded).
    pub time_envelope_ref: String,
    /// Hex-encoded public key of signer.
    pub signer_identity: String,
    /// Ed25519 signature over canonical bytes with domain separation
    /// (hex-encoded).
    pub signature: String,
}

impl SummaryReceipt {
    /// Computes the canonical bytes for signing/verification.
    ///
    /// Encoding order (length-prefixed for variable-length fields):
    /// 1. `schema` (len + bytes)
    /// 2. `schema_version` (len + bytes)
    /// 3. `review_id` (len + bytes)
    /// 4. `changeset_digest` (len + bytes, hex string)
    /// 5. `outcome` (1 byte code)
    /// 6. `summary_text` (1 byte present flag + optional len + bytes)
    /// 7. `tool_log_index_hash` (len + bytes, hex string)
    /// 8. `artifact_bundle_hash` (len + bytes, hex string)
    /// 9. `loss_profile` (serialized JSON)
    /// 10. `selectors` (count + each len + bytes)
    /// 11. `time_envelope_ref` (len + bytes, hex string)
    /// 12. `signer_identity` (len + bytes)
    ///
    /// # Panics
    ///
    /// Panics if `LossProfile` JSON serialization fails (should not happen).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // 1. schema
        bytes.extend_from_slice(&(self.schema.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema.as_bytes());

        // 2. schema_version
        bytes.extend_from_slice(&(self.schema_version.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema_version.as_bytes());

        // 3. review_id
        bytes.extend_from_slice(&(self.review_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.review_id.as_bytes());

        // 4. changeset_digest
        bytes.extend_from_slice(&(self.changeset_digest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.changeset_digest.as_bytes());

        // 5. outcome
        bytes.push(self.outcome.to_code());

        // 6. summary_text
        if let Some(ref text) = self.summary_text {
            bytes.push(1); // present
            bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
            bytes.extend_from_slice(text.as_bytes());
        } else {
            bytes.push(0); // absent
        }

        // 7. tool_log_index_hash
        bytes.extend_from_slice(&(self.tool_log_index_hash.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.tool_log_index_hash.as_bytes());

        // 8. artifact_bundle_hash
        bytes.extend_from_slice(&(self.artifact_bundle_hash.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.artifact_bundle_hash.as_bytes());

        // 9. loss_profile (as JSON for determinism)
        let loss_json =
            serde_json::to_string(&self.loss_profile).expect("LossProfile is serializable");
        bytes.extend_from_slice(&(loss_json.len() as u32).to_be_bytes());
        bytes.extend_from_slice(loss_json.as_bytes());

        // 10. selectors
        bytes.extend_from_slice(&(self.selectors.len() as u32).to_be_bytes());
        for selector in &self.selectors {
            bytes.extend_from_slice(&(selector.len() as u32).to_be_bytes());
            bytes.extend_from_slice(selector.as_bytes());
        }

        // 11. time_envelope_ref
        bytes.extend_from_slice(&(self.time_envelope_ref.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.time_envelope_ref.as_bytes());

        // 12. signer_identity
        bytes.extend_from_slice(&(self.signer_identity.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_identity.as_bytes());

        bytes
    }

    /// Verifies the receipt signature.
    ///
    /// # Errors
    ///
    /// Returns error if the signature doesn't match the canonical bytes.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), SummaryReceiptError> {
        let canonical = self.canonical_bytes();

        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|e| SummaryReceiptError::InvalidData(format!("invalid signature hex: {e}")))?
            .try_into()
            .map_err(|_| {
                SummaryReceiptError::InvalidData("signature must be 64 bytes".to_string())
            })?;

        let signature = Signature::from_bytes(&sig_bytes);

        verify_with_domain(key, SUMMARY_RECEIPT_PREFIX, &canonical, &signature)
            .map_err(|e| SummaryReceiptError::SignatureVerificationFailed(e.to_string()))
    }

    /// Computes the CAS hash of this receipt.
    ///
    /// # Panics
    ///
    /// Panics if JSON serialization fails, which should not happen for valid
    /// receipts.
    #[must_use]
    pub fn compute_cas_hash(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("SummaryReceipt is always serializable");
        *blake3::hash(&json).as_bytes()
    }

    /// Validates the receipt structure.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self) -> Result<(), SummaryReceiptError> {
        // Validate schema
        if self.schema != SUMMARY_RECEIPT_SCHEMA {
            return Err(SummaryReceiptError::InvalidData(format!(
                "invalid schema: expected {SUMMARY_RECEIPT_SCHEMA}, got {}",
                self.schema
            )));
        }

        // Validate review_id
        if self.review_id.is_empty() {
            return Err(SummaryReceiptError::MissingField("review_id"));
        }
        if self.review_id.len() > MAX_REVIEW_ID_LENGTH {
            return Err(SummaryReceiptError::StringTooLong {
                field: "review_id",
                len: self.review_id.len(),
                max: MAX_REVIEW_ID_LENGTH,
            });
        }

        // Validate changeset_digest format
        if self.changeset_digest.len() != 64 {
            return Err(SummaryReceiptError::InvalidData(
                "changeset_digest must be 64 hex characters".to_string(),
            ));
        }
        if !self.changeset_digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SummaryReceiptError::InvalidData(
                "changeset_digest must be hex-encoded".to_string(),
            ));
        }

        // Validate summary_text length
        if let Some(ref text) = self.summary_text {
            if text.len() > MAX_SUMMARY_TEXT_LENGTH {
                return Err(SummaryReceiptError::StringTooLong {
                    field: "summary_text",
                    len: text.len(),
                    max: MAX_SUMMARY_TEXT_LENGTH,
                });
            }
        }

        // Validate tool_log_index_hash format
        if self.tool_log_index_hash.len() != 64 {
            return Err(SummaryReceiptError::InvalidData(
                "tool_log_index_hash must be 64 hex characters".to_string(),
            ));
        }

        // Validate artifact_bundle_hash format
        if self.artifact_bundle_hash.len() != 64 {
            return Err(SummaryReceiptError::InvalidData(
                "artifact_bundle_hash must be 64 hex characters".to_string(),
            ));
        }

        // Validate selectors
        if self.selectors.len() > MAX_SELECTOR_TAGS {
            return Err(SummaryReceiptError::CollectionTooLarge {
                field: "selectors",
                actual: self.selectors.len(),
                max: MAX_SELECTOR_TAGS,
            });
        }
        for (i, selector) in self.selectors.iter().enumerate() {
            if selector.len() > MAX_SELECTOR_TAG_LENGTH {
                return Err(SummaryReceiptError::StringTooLong {
                    field: "selectors",
                    len: selector.len(),
                    max: MAX_SELECTOR_TAG_LENGTH,
                });
            }
            if selector.is_empty() {
                return Err(SummaryReceiptError::InvalidData(format!(
                    "selectors[{i}] cannot be empty"
                )));
            }
        }

        // Validate time_envelope_ref format
        if self.time_envelope_ref.len() != 64 {
            return Err(SummaryReceiptError::InvalidData(
                "time_envelope_ref must be 64 hex characters".to_string(),
            ));
        }

        Ok(())
    }

    /// Returns `true` if this summary has any information loss.
    #[must_use]
    pub fn has_loss(&self) -> bool {
        self.loss_profile.has_loss()
    }

    /// Returns `true` if this summary has the given selector tag.
    #[must_use]
    pub fn has_selector(&self, tag: &str) -> bool {
        self.selectors.iter().any(|s| s == tag)
    }
}

// =============================================================================
// SummaryReceiptBuilder
// =============================================================================

/// Builder for constructing a `SummaryReceipt`.
#[derive(Debug, Default)]
pub struct SummaryReceiptBuilder {
    review_id: Option<String>,
    changeset_digest: Option<[u8; 32]>,
    outcome: Option<ReviewOutcome>,
    summary_text: Option<String>,
    tool_log_index_hash: Option<[u8; 32]>,
    artifact_bundle_hash: Option<[u8; 32]>,
    loss_profile: LossProfile,
    selectors: Vec<String>,
    time_envelope_ref: Option<[u8; 32]>,
}

#[allow(clippy::missing_const_for_fn)]
impl SummaryReceiptBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the review ID.
    #[must_use]
    pub fn review_id(mut self, id: impl Into<String>) -> Self {
        self.review_id = Some(id.into());
        self
    }

    /// Sets the changeset digest.
    #[must_use]
    pub fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the review outcome.
    #[must_use]
    pub fn outcome(mut self, outcome: ReviewOutcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Sets the summary text.
    #[must_use]
    pub fn summary_text(mut self, text: impl Into<String>) -> Self {
        self.summary_text = Some(text.into());
        self
    }

    /// Sets the tool log index hash.
    #[must_use]
    pub fn tool_log_index_hash(mut self, hash: [u8; 32]) -> Self {
        self.tool_log_index_hash = Some(hash);
        self
    }

    /// Sets the artifact bundle hash.
    #[must_use]
    pub fn artifact_bundle_hash(mut self, hash: [u8; 32]) -> Self {
        self.artifact_bundle_hash = Some(hash);
        self
    }

    /// Sets the loss profile.
    #[must_use]
    pub fn loss_profile(mut self, profile: LossProfile) -> Self {
        self.loss_profile = profile;
        self
    }

    /// Adds a selector tag.
    #[must_use]
    pub fn add_selector(mut self, tag: impl Into<String>) -> Self {
        self.selectors.push(tag.into());
        self
    }

    /// Sets the selectors.
    #[must_use]
    pub fn selectors(mut self, tags: Vec<String>) -> Self {
        self.selectors = tags;
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, hash: [u8; 32]) -> Self {
        self.time_envelope_ref = Some(hash);
        self
    }

    /// Builds and signs the summary receipt.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build_and_sign(self, signer: &Signer) -> Result<SummaryReceipt, SummaryReceiptError> {
        let review_id = self
            .review_id
            .ok_or(SummaryReceiptError::MissingField("review_id"))?;
        let changeset_digest = self
            .changeset_digest
            .ok_or(SummaryReceiptError::MissingField("changeset_digest"))?;
        let outcome = self
            .outcome
            .ok_or(SummaryReceiptError::MissingField("outcome"))?;
        let tool_log_index_hash = self
            .tool_log_index_hash
            .ok_or(SummaryReceiptError::MissingField("tool_log_index_hash"))?;
        let artifact_bundle_hash = self
            .artifact_bundle_hash
            .ok_or(SummaryReceiptError::MissingField("artifact_bundle_hash"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(SummaryReceiptError::MissingField("time_envelope_ref"))?;

        // Validate lengths
        if review_id.len() > MAX_REVIEW_ID_LENGTH {
            return Err(SummaryReceiptError::StringTooLong {
                field: "review_id",
                len: review_id.len(),
                max: MAX_REVIEW_ID_LENGTH,
            });
        }
        if let Some(ref text) = self.summary_text {
            if text.len() > MAX_SUMMARY_TEXT_LENGTH {
                return Err(SummaryReceiptError::StringTooLong {
                    field: "summary_text",
                    len: text.len(),
                    max: MAX_SUMMARY_TEXT_LENGTH,
                });
            }
        }
        if self.selectors.len() > MAX_SELECTOR_TAGS {
            return Err(SummaryReceiptError::CollectionTooLarge {
                field: "selectors",
                actual: self.selectors.len(),
                max: MAX_SELECTOR_TAGS,
            });
        }

        // Get signer identity
        let signer_identity = hex::encode(signer.verifying_key().as_bytes());

        // Build receipt with placeholder signature
        let mut receipt = SummaryReceipt {
            schema: SUMMARY_RECEIPT_SCHEMA.to_string(),
            schema_version: SUMMARY_RECEIPT_VERSION.to_string(),
            review_id,
            changeset_digest: hex::encode(changeset_digest),
            outcome,
            summary_text: self.summary_text,
            tool_log_index_hash: hex::encode(tool_log_index_hash),
            artifact_bundle_hash: hex::encode(artifact_bundle_hash),
            loss_profile: self.loss_profile,
            selectors: self.selectors,
            time_envelope_ref: hex::encode(time_envelope_ref),
            signer_identity,
            signature: String::new(),
        };

        // Sign
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, SUMMARY_RECEIPT_PREFIX, &canonical);
        receipt.signature = hex::encode(signature.to_bytes());

        Ok(receipt)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_summary(signer: &Signer) -> SummaryReceipt {
        SummaryReceiptBuilder::new()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .outcome(ReviewOutcome::Approved)
            .summary_text("LGTM!")
            .tool_log_index_hash([0x11; 32])
            .artifact_bundle_hash([0x22; 32])
            .loss_profile(
                LossProfile::lossless()
                    .with_tool_count_summarized(5)
                    .with_files_affected(3),
            )
            .add_selector("quality:passed")
            .add_selector("tier:1")
            .time_envelope_ref([0x44; 32])
            .build_and_sign(signer)
            .expect("valid summary")
    }

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let summary = create_test_summary(&signer);

        assert_eq!(summary.schema, SUMMARY_RECEIPT_SCHEMA);
        assert_eq!(summary.review_id, "review-001");
        assert_eq!(summary.outcome, ReviewOutcome::Approved);
        assert_eq!(summary.summary_text, Some("LGTM!".to_string()));
        assert_eq!(summary.selectors.len(), 2);
    }

    #[test]
    fn test_signature_verification() {
        let signer = Signer::generate();
        let summary = create_test_summary(&signer);

        // Valid signature
        assert!(summary.verify_signature(&signer.verifying_key()).is_ok());

        // Wrong key should fail
        let other_signer = Signer::generate();
        assert!(
            summary
                .verify_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_signature_binds_to_content() {
        let signer = Signer::generate();
        let mut summary = create_test_summary(&signer);

        // Tamper with content
        summary.review_id = "tampered".to_string();

        // Signature should now be invalid
        assert!(summary.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let summary1 = create_test_summary(&signer);
        let summary2 = create_test_summary(&signer);

        assert_eq!(summary1.canonical_bytes(), summary2.canonical_bytes());
        assert_eq!(summary1.signature, summary2.signature);
    }

    #[test]
    fn test_cas_hash_deterministic() {
        let signer = Signer::generate();
        let summary1 = create_test_summary(&signer);
        let summary2 = create_test_summary(&signer);

        assert_eq!(summary1.compute_cas_hash(), summary2.compute_cas_hash());
    }

    #[test]
    fn test_validate() {
        let signer = Signer::generate();
        let summary = create_test_summary(&signer);

        assert!(summary.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_schema() {
        let signer = Signer::generate();
        let mut summary = create_test_summary(&signer);
        summary.schema = "invalid.schema".to_string();

        assert!(summary.validate().is_err());
    }

    #[test]
    fn test_missing_field() {
        let signer = Signer::generate();

        let result = SummaryReceiptBuilder::new()
            // Missing review_id
            .changeset_digest([0x42; 32])
            .outcome(ReviewOutcome::Approved)
            .tool_log_index_hash([0x11; 32])
            .artifact_bundle_hash([0x22; 32])
            .time_envelope_ref([0x44; 32])
            .build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(SummaryReceiptError::MissingField("review_id"))
        ));
    }

    #[test]
    fn test_review_outcome_codes() {
        assert_eq!(ReviewOutcome::Approved.to_code(), 1);
        assert_eq!(ReviewOutcome::RequestedChanges.to_code(), 2);
        assert_eq!(ReviewOutcome::Commented.to_code(), 3);
        assert_eq!(ReviewOutcome::Blocked.to_code(), 4);

        assert_eq!(
            ReviewOutcome::from_code(1).unwrap(),
            ReviewOutcome::Approved
        );
        assert!(ReviewOutcome::from_code(5).is_err());
    }

    #[test]
    fn test_loss_profile() {
        let lossless = LossProfile::lossless();
        assert!(!lossless.has_loss());

        let lossy = LossProfile::lossless()
            .with_review_text_omitted(true)
            .with_tool_count_summarized(10);
        assert!(lossy.has_loss());
    }

    #[test]
    fn test_has_selector() {
        let signer = Signer::generate();
        let summary = create_test_summary(&signer);

        assert!(summary.has_selector("quality:passed"));
        assert!(summary.has_selector("tier:1"));
        assert!(!summary.has_selector("unknown"));
    }

    #[test]
    fn test_domain_separator_prevents_replay() {
        let signer = Signer::generate();
        let summary = create_test_summary(&signer);

        // Sign without domain prefix
        let canonical = summary.canonical_bytes();
        let wrong_signature = signer.sign(&canonical);

        let mut bad_summary = summary;
        bad_summary.signature = hex::encode(wrong_signature.to_bytes());

        // Verification should fail
        assert!(
            bad_summary
                .verify_signature(&signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_selectors_too_many() {
        let signer = Signer::generate();
        let mut builder = SummaryReceiptBuilder::new()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .outcome(ReviewOutcome::Approved)
            .tool_log_index_hash([0x11; 32])
            .artifact_bundle_hash([0x22; 32])
            .time_envelope_ref([0x44; 32]);

        for i in 0..=MAX_SELECTOR_TAGS {
            builder = builder.add_selector(format!("tag-{i}"));
        }

        let result = builder.build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(SummaryReceiptError::CollectionTooLarge {
                field: "selectors",
                ..
            })
        ));
    }
}
