// AGENT-AUTHORED
//! Review receipt types for FAC v0 successful review completion.
//!
//! This module implements the `ReviewReceiptRecorded` event which is emitted
//! when a review completes successfully. The review artifacts are stored in CAS
//! and bound to the changeset via this ledger event.
//!
//! # Design Overview
//!
//! The [`ReviewReceiptRecorded`] event captures:
//! - The changeset digest being reviewed (from `ChangeSetPublished`)
//! - CAS reference to the `ReviewArtifactBundleV1` containing review outputs
//! - HTF time envelope for temporal authority
//! - Domain-separated signature for integrity
//!
//! The [`ReviewArtifactBundleV1`] structure contains:
//! - Review text CAS hash
//! - Tool log CAS hashes
//! - Review metadata (verdict, actor, timestamps)
//!
//! # Security Properties
//!
//! - **Domain Separation**: The signature uses the `REVIEW_RECEIPT_RECORDED:`
//!   domain prefix to prevent replay attacks.
//! - **CAS Binding**: Review artifacts are stored in CAS with hash reference
//!   for integrity verification.
//! - **HTF Time Binding**: Time envelope reference provides temporal authority
//!   for audit and ordering.
//! - **Changeset Binding**: The `changeset_digest` binds the review to a
//!   specific `ChangeSetPublished` event.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     ReviewArtifactBundleV1, ReviewReceiptRecorded, ReviewVerdict,
//! };
//!
//! let signer = Signer::generate();
//!
//! // Create the artifact bundle first
//! let bundle = ReviewArtifactBundleV1::builder()
//!     .review_id("review-001")
//!     .changeset_digest([0x42; 32])
//!     .review_text_hash([0x11; 32])
//!     .tool_log_hashes(vec![[0x22; 32], [0x33; 32]])
//!     .time_envelope_ref([0x44; 32])
//!     .build()
//!     .expect("valid bundle");
//!
//! // Compute CAS hash of the bundle
//! let bundle_hash = bundle.compute_cas_hash();
//!
//! // Create the receipt event
//! let event = ReviewReceiptRecorded::create(
//!     "RR-001".to_string(),
//!     [0x42; 32], // changeset_digest
//!     bundle_hash,
//!     [0x44; 32], // time_envelope_ref
//!     "reviewer-001".to_string(),
//!     Some([0x55; 32]), // capability_manifest_hash (TCK-00326, optional)
//!     Some([0x66; 32]), // context_pack_hash (TCK-00326, optional)
//!     &signer,
//! )
//! .expect("valid event");
//!
//! // Verify signature
//! assert!(event.verify_signature(&signer.verifying_key()).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{
    REVIEW_RECEIPT_RECORDED_PREFIX, sign_with_domain, verify_with_domain,
};
use crate::crypto::{Signature, Signer, VerifyingKey};
use crate::htf::TimeEnvelopeRef;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for string fields.
pub const MAX_STRING_LENGTH: usize = 256;

/// Maximum length for receipt ID.
pub const MAX_RECEIPT_ID_LENGTH: usize = 128;

/// Maximum length for review ID.
pub const MAX_REVIEW_ID_LENGTH: usize = 128;

/// Maximum number of tool log hashes.
pub const MAX_TOOL_LOG_HASHES: usize = 1024;

/// Schema identifier for `ReviewArtifactBundleV1`.
pub const SCHEMA_IDENTIFIER: &str = "apm2.review_artifact_bundle.v1";

/// Current schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

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

    /// Invalid verdict value.
    #[error("invalid verdict: {0}")]
    InvalidVerdict(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

// =============================================================================
// ReviewVerdict
// =============================================================================

/// Verdict outcome for a review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewVerdict {
    /// Review approved the changeset.
    Approve,
    /// Review requested changes to the changeset.
    RequestChanges,
    /// Review left comments without explicit approval/rejection.
    Comment,
}

impl std::fmt::Display for ReviewVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approve => write!(f, "APPROVE"),
            Self::RequestChanges => write!(f, "REQUEST_CHANGES"),
            Self::Comment => write!(f, "COMMENT"),
        }
    }
}

impl std::str::FromStr for ReviewVerdict {
    type Err = ReviewReceiptError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "APPROVE" => Ok(Self::Approve),
            "REQUEST_CHANGES" => Ok(Self::RequestChanges),
            "COMMENT" => Ok(Self::Comment),
            _ => Err(ReviewReceiptError::InvalidVerdict(s.to_string())),
        }
    }
}

impl ReviewVerdict {
    /// Returns the numeric code for this verdict.
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::Approve => 1,
            Self::RequestChanges => 2,
            Self::Comment => 3,
        }
    }

    /// Creates a verdict from its numeric code.
    ///
    /// # Errors
    ///
    /// Returns error if the code is invalid.
    pub fn from_code(code: u8) -> Result<Self, ReviewReceiptError> {
        match code {
            1 => Ok(Self::Approve),
            2 => Ok(Self::RequestChanges),
            3 => Ok(Self::Comment),
            _ => Err(ReviewReceiptError::InvalidVerdict(format!(
                "invalid code: {code}"
            ))),
        }
    }
}

// =============================================================================
// ReviewMetadata
// =============================================================================

/// Metadata for a review.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewMetadata {
    /// Actor ID of the reviewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_actor_id: Option<String>,
    /// Review verdict outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_verdict: Option<ReviewVerdict>,
    /// Unix nanoseconds when review started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_started_at: Option<u64>,
    /// Unix nanoseconds when review completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_completed_at: Option<u64>,
}

impl ReviewMetadata {
    /// Creates an empty metadata instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the reviewer actor ID.
    #[must_use]
    pub fn with_reviewer_actor_id(mut self, id: impl Into<String>) -> Self {
        self.reviewer_actor_id = Some(id.into());
        self
    }

    /// Sets the review verdict.
    #[must_use]
    pub const fn with_verdict(mut self, verdict: ReviewVerdict) -> Self {
        self.review_verdict = Some(verdict);
        self
    }

    /// Sets the review start timestamp.
    #[must_use]
    pub const fn with_started_at(mut self, ts: u64) -> Self {
        self.review_started_at = Some(ts);
        self
    }

    /// Sets the review completion timestamp.
    #[must_use]
    pub const fn with_completed_at(mut self, ts: u64) -> Self {
        self.review_completed_at = Some(ts);
        self
    }

    /// Validates the metadata.
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds maximum length.
    pub fn validate(&self) -> Result<(), ReviewReceiptError> {
        if let Some(ref id) = self.reviewer_actor_id {
            if id.len() > MAX_STRING_LENGTH {
                return Err(ReviewReceiptError::StringTooLong {
                    field: "reviewer_actor_id",
                    len: id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }
        Ok(())
    }
}

// =============================================================================
// ReviewArtifactBundleV1
// =============================================================================

/// A bundle of review artifacts stored in CAS.
///
/// This structure represents the canonical form of review outputs that are
/// stored in CAS and referenced by `ReviewReceiptRecorded` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewArtifactBundleV1 {
    /// Schema identifier (always `apm2.review_artifact_bundle.v1`).
    pub schema: String,
    /// Schema version (semver format).
    pub schema_version: String,
    /// Unique review identifier.
    pub review_id: String,
    /// BLAKE3 digest of the changeset being reviewed (32 bytes, hex-encoded).
    pub changeset_digest: String,
    /// BLAKE3 hash of the review text stored in CAS (32 bytes, hex-encoded).
    pub review_text_hash: String,
    /// BLAKE3 hashes of tool logs stored in CAS (each 32 bytes, hex-encoded).
    pub tool_log_hashes: Vec<String>,
    /// HTF time envelope reference hash (32 bytes, hex-encoded).
    pub time_envelope_ref: String,
    /// View commitment hash (from CAS).
    ///
    /// Represents the materialized workspace state at the time of review.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_commitment_hash: Option<String>,
    /// Policy resolved reference.
    ///
    /// The policy resolution binding used for the review session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_resolved_ref: Option<String>,
    /// Optional metadata for review context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ReviewMetadata>,
}

impl ReviewArtifactBundleV1 {
    /// Creates a builder for constructing a `ReviewArtifactBundleV1`.
    #[must_use]
    pub fn builder() -> ReviewArtifactBundleV1Builder {
        ReviewArtifactBundleV1Builder::default()
    }

    /// Computes the CAS hash of this bundle.
    ///
    /// The hash is computed over the canonical JSON representation.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal circumstances. The only panic
    /// path is if JSON serialization fails, which cannot happen for a valid
    /// `ReviewArtifactBundleV1` since all fields are serializable.
    #[must_use]
    pub fn compute_cas_hash(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("ReviewArtifactBundleV1 is always serializable");
        *blake3::hash(&json).as_bytes()
    }

    /// Validates the bundle.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self) -> Result<(), ReviewReceiptError> {
        // Validate schema
        if self.schema != SCHEMA_IDENTIFIER {
            return Err(ReviewReceiptError::InvalidData(format!(
                "invalid schema: expected {SCHEMA_IDENTIFIER}, got {}",
                self.schema
            )));
        }

        // Validate review_id
        if self.review_id.is_empty() {
            return Err(ReviewReceiptError::MissingField("review_id"));
        }
        if self.review_id.len() > MAX_REVIEW_ID_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "review_id",
                len: self.review_id.len(),
                max: MAX_REVIEW_ID_LENGTH,
            });
        }

        // Validate changeset_digest format (64 hex chars)
        if self.changeset_digest.len() != 64 {
            return Err(ReviewReceiptError::InvalidData(
                "changeset_digest must be 64 hex characters".into(),
            ));
        }
        if !self.changeset_digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ReviewReceiptError::InvalidData(
                "changeset_digest must be hex-encoded".into(),
            ));
        }

        // Validate review_text_hash format
        if self.review_text_hash.len() != 64 {
            return Err(ReviewReceiptError::InvalidData(
                "review_text_hash must be 64 hex characters".into(),
            ));
        }

        // Validate tool_log_hashes
        if self.tool_log_hashes.len() > MAX_TOOL_LOG_HASHES {
            return Err(ReviewReceiptError::CollectionTooLarge {
                field: "tool_log_hashes",
                actual: self.tool_log_hashes.len(),
                max: MAX_TOOL_LOG_HASHES,
            });
        }
        for hash in &self.tool_log_hashes {
            if hash.len() != 64 {
                return Err(ReviewReceiptError::InvalidData(
                    "tool_log_hash must be 64 hex characters".into(),
                ));
            }
        }

        // Validate time_envelope_ref format
        if self.time_envelope_ref.len() != 64 {
            return Err(ReviewReceiptError::InvalidData(
                "time_envelope_ref must be 64 hex characters".into(),
            ));
        }

        // Validate view_commitment_hash if present
        if let Some(ref hash) = self.view_commitment_hash {
            if hash.len() != 64 {
                return Err(ReviewReceiptError::InvalidData(
                    "view_commitment_hash must be 64 hex characters".into(),
                ));
            }
        }

        // Validate policy_resolved_ref if present
        if let Some(ref reference) = self.policy_resolved_ref {
            if reference.is_empty() {
                return Err(ReviewReceiptError::InvalidData(
                    "policy_resolved_ref must not be empty".into(),
                ));
            }
            if reference.len() > MAX_STRING_LENGTH {
                return Err(ReviewReceiptError::StringTooLong {
                    field: "policy_resolved_ref",
                    len: reference.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        // Validate metadata if present
        if let Some(ref metadata) = self.metadata {
            metadata.validate()?;
        }

        Ok(())
    }
}

// =============================================================================
// ReviewArtifactBundleV1Builder
// =============================================================================

/// Builder for constructing a `ReviewArtifactBundleV1`.
#[derive(Debug, Default)]
pub struct ReviewArtifactBundleV1Builder {
    review_id: Option<String>,
    changeset_digest: Option<[u8; 32]>,
    review_text_hash: Option<[u8; 32]>,
    tool_log_hashes: Vec<[u8; 32]>,
    time_envelope_ref: Option<[u8; 32]>,
    view_commitment_hash: Option<[u8; 32]>,
    policy_resolved_ref: Option<String>,
    metadata: Option<ReviewMetadata>,
}

#[allow(clippy::missing_const_for_fn)]
impl ReviewArtifactBundleV1Builder {
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

    /// Sets the review text hash.
    #[must_use]
    pub fn review_text_hash(mut self, hash: [u8; 32]) -> Self {
        self.review_text_hash = Some(hash);
        self
    }

    /// Sets the tool log hashes.
    #[must_use]
    pub fn tool_log_hashes(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.tool_log_hashes = hashes;
        self
    }

    /// Adds a tool log hash.
    #[must_use]
    pub fn add_tool_log_hash(mut self, hash: [u8; 32]) -> Self {
        self.tool_log_hashes.push(hash);
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, hash: [u8; 32]) -> Self {
        self.time_envelope_ref = Some(hash);
        self
    }

    /// Sets the view commitment hash.
    #[must_use]
    pub fn view_commitment_hash(mut self, hash: [u8; 32]) -> Self {
        self.view_commitment_hash = Some(hash);
        self
    }

    /// Sets the policy resolved reference.
    #[must_use]
    pub fn policy_resolved_ref(mut self, reference: impl Into<String>) -> Self {
        self.policy_resolved_ref = Some(reference.into());
        self
    }

    /// Sets the metadata.
    #[must_use]
    pub fn metadata(mut self, metadata: ReviewMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Builds the `ReviewArtifactBundleV1`.
    ///
    /// This method builds the bundle with optional `view_commitment_hash` and
    /// `policy_resolved_ref` fields. For fail-closed behavior that requires
    /// these fields, use [`Self::build_strict`] instead.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build(self) -> Result<ReviewArtifactBundleV1, ReviewReceiptError> {
        let review_id = self
            .review_id
            .ok_or(ReviewReceiptError::MissingField("review_id"))?;
        let changeset_digest = self
            .changeset_digest
            .ok_or(ReviewReceiptError::MissingField("changeset_digest"))?;
        let review_text_hash = self
            .review_text_hash
            .ok_or(ReviewReceiptError::MissingField("review_text_hash"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(ReviewReceiptError::MissingField("time_envelope_ref"))?;

        // Check tool_log_hashes size
        if self.tool_log_hashes.len() > MAX_TOOL_LOG_HASHES {
            return Err(ReviewReceiptError::CollectionTooLarge {
                field: "tool_log_hashes",
                actual: self.tool_log_hashes.len(),
                max: MAX_TOOL_LOG_HASHES,
            });
        }

        let bundle = ReviewArtifactBundleV1 {
            schema: SCHEMA_IDENTIFIER.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            review_id,
            changeset_digest: hex::encode(changeset_digest),
            review_text_hash: hex::encode(review_text_hash),
            tool_log_hashes: self.tool_log_hashes.iter().map(hex::encode).collect(),
            time_envelope_ref: hex::encode(time_envelope_ref),
            view_commitment_hash: self.view_commitment_hash.map(hex::encode),
            policy_resolved_ref: self.policy_resolved_ref,
            metadata: self.metadata,
        };

        bundle.validate()?;
        Ok(bundle)
    }

    /// Builds the `ReviewArtifactBundleV1` with strict holon-ready requirements
    /// (TCK-00325).
    ///
    /// This method enforces the fail-closed requirement from SEC-CTRL-FAC-0015:
    /// review outcomes MUST bind to a verifiable view commitment and policy
    /// resolution. Missing these bindings is a hard failure that should result
    /// in `ReviewBlockedRecorded` with `ReasonCode::MissingViewCommitment`.
    ///
    /// # Required Fields (in addition to base `build()` requirements)
    ///
    /// - `view_commitment_hash`: CAS hash of the `ViewCommitmentV1`
    /// - `policy_resolved_ref`: Reference to `PolicyResolvedForChangeSet`
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Any required field from `build()` is missing
    /// - `view_commitment_hash` is missing
    /// - `policy_resolved_ref` is missing
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::ReviewArtifactBundleV1;
    ///
    /// let bundle = ReviewArtifactBundleV1::builder()
    ///     .review_id("review-001")
    ///     .changeset_digest([0x42; 32])
    ///     .review_text_hash([0x11; 32])
    ///     .time_envelope_ref([0x44; 32])
    ///     .view_commitment_hash([0x55; 32])
    ///     .policy_resolved_ref("policy-ref-001")
    ///     .build_strict()
    ///     .expect("valid bundle with holon-ready bindings");
    ///
    /// assert!(bundle.view_commitment_hash.is_some());
    /// assert!(bundle.policy_resolved_ref.is_some());
    /// ```
    pub fn build_strict(self) -> Result<ReviewArtifactBundleV1, ReviewReceiptError> {
        // First validate that holon-ready fields are present
        if self.view_commitment_hash.is_none() {
            return Err(ReviewReceiptError::MissingField("view_commitment_hash"));
        }
        if self.policy_resolved_ref.is_none() {
            return Err(ReviewReceiptError::MissingField("policy_resolved_ref"));
        }

        // Delegate to normal build
        self.build()
    }

    /// Checks if the builder has holon-ready bindings set.
    ///
    /// Returns `true` if both `view_commitment_hash` and `policy_resolved_ref`
    /// are set. This can be used to decide whether to proceed with
    /// `build_strict()` or emit `ReviewBlockedRecorded`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::ReviewArtifactBundleV1;
    ///
    /// let builder = ReviewArtifactBundleV1::builder()
    ///     .review_id("review-001")
    ///     .changeset_digest([0x42; 32])
    ///     .review_text_hash([0x11; 32])
    ///     .time_envelope_ref([0x44; 32]);
    ///
    /// if builder.has_holon_ready_bindings() {
    ///     // Proceed with build_strict()
    /// } else {
    ///     // Emit ReviewBlockedRecorded with MissingViewCommitment
    /// }
    /// ```
    #[must_use]
    pub fn has_holon_ready_bindings(&self) -> bool {
        self.view_commitment_hash.is_some() && self.policy_resolved_ref.is_some()
    }
}

// =============================================================================
// ReviewReceiptRecorded
// =============================================================================

/// Event emitted when a review is successfully completed.
///
/// This event records the successful review outcome and stores it durably in
/// the ledger. It binds the review artifacts to the changeset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewReceiptRecorded {
    /// Unique identifier for this receipt.
    pub receipt_id: String,
    /// BLAKE3 digest of the changeset that was reviewed (32 bytes).
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],
    /// BLAKE3 hash of the `ReviewArtifactBundleV1` stored in CAS (32 bytes).
    #[serde(with = "serde_bytes")]
    pub artifact_bundle_hash: [u8; 32],
    /// HTF time envelope reference hash for temporal authority (32 bytes).
    #[serde(with = "serde_bytes")]
    pub time_envelope_ref: [u8; 32],
    /// Actor who recorded the receipt (the reviewer).
    pub reviewer_actor_id: String,
    /// Ed25519 signature over canonical bytes with `REVIEW_RECEIPT_RECORDED:`
    /// domain.
    #[serde(with = "serde_bytes")]
    pub reviewer_signature: [u8; 64],
    /// BLAKE3 hash of the `CapabilityManifest` in effect (32 bytes, TCK-00326).
    /// Binds the receipt to the authority under which the review was performed.
    ///
    /// This field is `Option` for backward compatibility with events created
    /// before TCK-00326. When `None`, it is not included in `canonical_bytes()`
    /// to preserve signature verification for historical events.
    #[serde(
        with = "crate::fac::serde_helpers::option_hash32",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_manifest_hash: Option<[u8; 32]>,
    /// BLAKE3 hash of the sealed `ContextPackManifest` in effect (32 bytes,
    /// TCK-00326). Binds the receipt to the context firewall configuration.
    ///
    /// This field is `Option` for backward compatibility with events created
    /// before TCK-00326. When `None`, it is not included in `canonical_bytes()`
    /// to preserve signature verification for historical events.
    #[serde(
        with = "crate::fac::serde_helpers::option_hash32",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub context_pack_hash: Option<[u8; 32]>,
}

impl ReviewReceiptRecorded {
    /// Creates a new `ReviewReceiptRecorded` event.
    ///
    /// # Arguments
    ///
    /// * `receipt_id` - Unique identifier for this receipt
    /// * `changeset_digest` - BLAKE3 digest of the changeset
    /// * `artifact_bundle_hash` - CAS hash of `ReviewArtifactBundleV1`
    /// * `time_envelope_ref` - HTF time envelope reference hash
    /// * `reviewer_actor_id` - ID of the reviewing actor
    /// * `capability_manifest_hash` - Hash of the `CapabilityManifest` in
    ///   effect (optional for backward compatibility)
    /// * `context_pack_hash` - Hash of the sealed `ContextPackManifest` in
    ///   effect (optional for backward compatibility)
    /// * `signer` - Signer to authorize the event
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds maximum length.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        receipt_id: String,
        changeset_digest: [u8; 32],
        artifact_bundle_hash: [u8; 32],
        time_envelope_ref: [u8; 32],
        reviewer_actor_id: String,
        capability_manifest_hash: Option<[u8; 32]>,
        context_pack_hash: Option<[u8; 32]>,
        signer: &Signer,
    ) -> Result<Self, ReviewReceiptError> {
        // Validate inputs
        if receipt_id.is_empty() {
            return Err(ReviewReceiptError::MissingField("receipt_id"));
        }
        if receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "receipt_id",
                len: receipt_id.len(),
                max: MAX_RECEIPT_ID_LENGTH,
            });
        }
        if reviewer_actor_id.is_empty() {
            return Err(ReviewReceiptError::MissingField("reviewer_actor_id"));
        }
        if reviewer_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "reviewer_actor_id",
                len: reviewer_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Construct event with placeholder signature
        let mut event = Self {
            receipt_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            reviewer_actor_id,
            reviewer_signature: [0u8; 64],
            capability_manifest_hash,
            context_pack_hash,
        };

        // Sign
        let canonical = event.canonical_bytes();
        let signature = sign_with_domain(signer, REVIEW_RECEIPT_RECORDED_PREFIX, &canonical);
        event.reviewer_signature = signature.to_bytes();

        Ok(event)
    }

    /// Creates a `ReviewReceiptRecorded` event with a `TimeEnvelopeRef`.
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds maximum length.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_envelope(
        receipt_id: String,
        changeset_digest: [u8; 32],
        artifact_bundle_hash: [u8; 32],
        envelope_ref: &TimeEnvelopeRef,
        reviewer_actor_id: String,
        capability_manifest_hash: Option<[u8; 32]>,
        context_pack_hash: Option<[u8; 32]>,
        signer: &Signer,
    ) -> Result<Self, ReviewReceiptError> {
        let time_envelope_ref: [u8; 32] = *envelope_ref.as_bytes();
        Self::create(
            receipt_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            reviewer_actor_id,
            capability_manifest_hash,
            context_pack_hash,
            signer,
        )
    }

    /// Computes the canonical bytes for signing/verification.
    ///
    /// Encoding:
    /// - `receipt_id` (len + bytes)
    /// - `changeset_digest` (32 bytes)
    /// - `artifact_bundle_hash` (32 bytes)
    /// - `time_envelope_ref` (32 bytes)
    /// - `reviewer_actor_id` (len + bytes)
    /// - `capability_manifest_hash` (32 bytes, TCK-00326, only if present)
    /// - `context_pack_hash` (32 bytes, TCK-00326, only if present)
    ///
    /// # Backward Compatibility
    ///
    /// The `capability_manifest_hash` and `context_pack_hash` fields are only
    /// included in the canonical encoding when they are `Some`. This preserves
    /// signature verification for historical events created before TCK-00326.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All strings are bounded
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // 1. receipt_id
        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        // 2. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 3. artifact_bundle_hash
        bytes.extend_from_slice(&self.artifact_bundle_hash);

        // 4. time_envelope_ref
        bytes.extend_from_slice(&self.time_envelope_ref);

        // 5. reviewer_actor_id
        bytes.extend_from_slice(&(self.reviewer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.reviewer_actor_id.as_bytes());

        // 6. capability_manifest_hash (TCK-00326, only if present for backward compat)
        if let Some(ref hash) = self.capability_manifest_hash {
            bytes.extend_from_slice(hash);
        }

        // 7. context_pack_hash (TCK-00326, only if present for backward compat)
        if let Some(ref hash) = self.context_pack_hash {
            bytes.extend_from_slice(hash);
        }

        bytes
    }

    /// Verifies the event signature.
    ///
    /// # Errors
    ///
    /// Returns error if the signature doesn't match the canonical bytes.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), ReviewReceiptError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.reviewer_signature);

        verify_with_domain(key, REVIEW_RECEIPT_RECORDED_PREFIX, &canonical, &signature)
            .map_err(|e| ReviewReceiptError::SignatureVerificationFailed(e.to_string()))
    }

    /// Returns the time envelope reference as a `TimeEnvelopeRef`.
    #[must_use]
    pub fn time_envelope(&self) -> Option<TimeEnvelopeRef> {
        TimeEnvelopeRef::from_slice(&self.time_envelope_ref)
    }
}

// =============================================================================
// ReviewReceiptRecordedBuilder
// =============================================================================

/// Builder for constructing a `ReviewReceiptRecorded` event.
#[derive(Debug, Default)]
pub struct ReviewReceiptRecordedBuilder {
    receipt_id: Option<String>,
    changeset_digest: Option<[u8; 32]>,
    artifact_bundle_hash: Option<[u8; 32]>,
    time_envelope_ref: Option<[u8; 32]>,
    reviewer_actor_id: Option<String>,
    capability_manifest_hash: Option<[u8; 32]>,
    context_pack_hash: Option<[u8; 32]>,
}

#[allow(clippy::missing_const_for_fn)]
impl ReviewReceiptRecordedBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the receipt ID.
    #[must_use]
    pub fn receipt_id(mut self, id: impl Into<String>) -> Self {
        self.receipt_id = Some(id.into());
        self
    }

    /// Sets the changeset digest.
    #[must_use]
    pub fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the artifact bundle hash.
    #[must_use]
    pub fn artifact_bundle_hash(mut self, hash: [u8; 32]) -> Self {
        self.artifact_bundle_hash = Some(hash);
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, hash: [u8; 32]) -> Self {
        self.time_envelope_ref = Some(hash);
        self
    }

    /// Sets the time envelope reference from a `TimeEnvelopeRef`.
    #[must_use]
    pub fn time_envelope(mut self, envelope_ref: &TimeEnvelopeRef) -> Self {
        self.time_envelope_ref = Some(*envelope_ref.as_bytes());
        self
    }

    /// Sets the reviewer actor ID.
    #[must_use]
    pub fn reviewer_actor_id(mut self, id: impl Into<String>) -> Self {
        self.reviewer_actor_id = Some(id.into());
        self
    }

    /// Sets the capability manifest hash (TCK-00326).
    #[must_use]
    pub fn capability_manifest_hash(mut self, hash: [u8; 32]) -> Self {
        self.capability_manifest_hash = Some(hash);
        self
    }

    /// Sets the context pack hash (TCK-00326).
    #[must_use]
    pub fn context_pack_hash(mut self, hash: [u8; 32]) -> Self {
        self.context_pack_hash = Some(hash);
        self
    }

    /// Builds the event and signs it.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    ///
    /// # Note
    ///
    /// The `capability_manifest_hash` and `context_pack_hash` fields are
    /// optional for backward compatibility with events created before
    /// TCK-00326.
    pub fn build_and_sign(
        self,
        signer: &Signer,
    ) -> Result<ReviewReceiptRecorded, ReviewReceiptError> {
        let receipt_id = self
            .receipt_id
            .ok_or(ReviewReceiptError::MissingField("receipt_id"))?;
        let changeset_digest = self
            .changeset_digest
            .ok_or(ReviewReceiptError::MissingField("changeset_digest"))?;
        let artifact_bundle_hash = self
            .artifact_bundle_hash
            .ok_or(ReviewReceiptError::MissingField("artifact_bundle_hash"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(ReviewReceiptError::MissingField("time_envelope_ref"))?;
        let reviewer_actor_id = self
            .reviewer_actor_id
            .ok_or(ReviewReceiptError::MissingField("reviewer_actor_id"))?;
        // These are optional for backward compatibility (TCK-00326)
        let capability_manifest_hash = self.capability_manifest_hash;
        let context_pack_hash = self.context_pack_hash;

        ReviewReceiptRecorded::create(
            receipt_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            reviewer_actor_id,
            capability_manifest_hash,
            context_pack_hash,
            signer,
        )
    }
}

// =============================================================================
// Proto Conversions
// =============================================================================

// Re-export proto type for wire format serialization
pub use crate::events::ReviewReceiptRecorded as ReviewReceiptRecordedProto;

impl TryFrom<ReviewReceiptRecordedProto> for ReviewReceiptRecorded {
    type Error = ReviewReceiptError;

    fn try_from(proto: ReviewReceiptRecordedProto) -> Result<Self, Self::Error> {
        // Validate resource limits
        if proto.receipt_id.is_empty() {
            return Err(ReviewReceiptError::MissingField("receipt_id"));
        }
        if proto.receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(ReviewReceiptError::StringTooLong {
                field: "receipt_id",
                len: proto.receipt_id.len(),
                max: MAX_RECEIPT_ID_LENGTH,
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

        // TCK-00326: Parse capability_manifest_hash and context_pack_hash
        // Map empty or all-zero fields to None for backward compatibility.
        // This ensures signature verification succeeds for historical events.
        let capability_manifest_hash: Option<[u8; 32]> = if proto
            .capability_manifest_hash
            .is_empty()
        {
            None
        } else {
            let hash: [u8; 32] = proto.capability_manifest_hash.try_into().map_err(|_| {
                ReviewReceiptError::InvalidData("capability_manifest_hash must be 32 bytes".into())
            })?;
            // Treat all-zeros as absent (backward compat)
            if hash == [0u8; 32] { None } else { Some(hash) }
        };

        let context_pack_hash: Option<[u8; 32]> = if proto.context_pack_hash.is_empty() {
            None
        } else {
            let hash: [u8; 32] = proto.context_pack_hash.try_into().map_err(|_| {
                ReviewReceiptError::InvalidData("context_pack_hash must be 32 bytes".into())
            })?;
            // Treat all-zeros as absent (backward compat)
            if hash == [0u8; 32] { None } else { Some(hash) }
        };

        Ok(Self {
            receipt_id: proto.receipt_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            reviewer_actor_id: proto.reviewer_actor_id,
            reviewer_signature,
            capability_manifest_hash,
            context_pack_hash,
        })
    }
}

impl From<ReviewReceiptRecorded> for ReviewReceiptRecordedProto {
    fn from(event: ReviewReceiptRecorded) -> Self {
        // Import the proto TimeEnvelopeRef type
        use crate::events::TimeEnvelopeRef as TimeEnvelopeRefProto;

        Self {
            receipt_id: event.receipt_id,
            changeset_digest: event.changeset_digest.to_vec(),
            artifact_bundle_hash: event.artifact_bundle_hash.to_vec(),
            time_envelope_ref: Some(TimeEnvelopeRefProto {
                hash: event.time_envelope_ref.to_vec(),
            }),
            reviewer_actor_id: event.reviewer_actor_id,
            reviewer_signature: event.reviewer_signature.to_vec(),
            // TCK-00326: Authority binding fields (empty Vec if None)
            capability_manifest_hash: event
                .capability_manifest_hash
                .map_or_else(Vec::new, |h| h.to_vec()),
            context_pack_hash: event
                .context_pack_hash
                .map_or_else(Vec::new, |h| h.to_vec()),
        }
    }
}

// =============================================================================
// Validation Functions
// =============================================================================

/// Validates that a `ReviewReceiptRecorded` event properly binds to a
/// changeset.
///
/// # Arguments
///
/// * `receipt` - The review receipt to validate
/// * `expected_changeset_digest` - The expected changeset digest from
///   `ChangeSetPublished`
///
/// # Errors
///
/// Returns error if the changeset digest doesn't match.
pub fn validate_changeset_binding(
    receipt: &ReviewReceiptRecorded,
    expected_changeset_digest: &[u8; 32],
) -> Result<(), ReviewReceiptError> {
    if receipt.changeset_digest != *expected_changeset_digest {
        return Err(ReviewReceiptError::InvalidData(format!(
            "changeset_digest mismatch: expected {}, got {}",
            hex::encode(expected_changeset_digest),
            hex::encode(receipt.changeset_digest)
        )));
    }
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_review_verdict_from_str() {
        assert_eq!(
            "APPROVE".parse::<ReviewVerdict>().unwrap(),
            ReviewVerdict::Approve
        );
        assert_eq!(
            "REQUEST_CHANGES".parse::<ReviewVerdict>().unwrap(),
            ReviewVerdict::RequestChanges
        );
        assert_eq!(
            "COMMENT".parse::<ReviewVerdict>().unwrap(),
            ReviewVerdict::Comment
        );
        assert!("UNKNOWN".parse::<ReviewVerdict>().is_err());
    }

    #[test]
    fn test_review_verdict_to_code_roundtrip() {
        for code in 1..=3u8 {
            let verdict = ReviewVerdict::from_code(code).unwrap();
            assert_eq!(verdict.to_code(), code);
        }
        assert!(ReviewVerdict::from_code(0).is_err());
        assert!(ReviewVerdict::from_code(4).is_err());
    }

    #[test]
    fn test_review_verdict_display() {
        assert_eq!(ReviewVerdict::Approve.to_string(), "APPROVE");
        assert_eq!(ReviewVerdict::RequestChanges.to_string(), "REQUEST_CHANGES");
        assert_eq!(ReviewVerdict::Comment.to_string(), "COMMENT");
    }

    #[test]
    fn test_artifact_bundle_build() {
        let bundle = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .tool_log_hashes(vec![[0x22; 32], [0x33; 32]])
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        assert_eq!(bundle.schema, SCHEMA_IDENTIFIER);
        assert_eq!(bundle.schema_version, SCHEMA_VERSION);
        assert_eq!(bundle.review_id, "review-001");
        assert_eq!(bundle.changeset_digest, hex::encode([0x42; 32]));
        assert_eq!(bundle.tool_log_hashes.len(), 2);
    }

    #[test]
    fn test_artifact_bundle_with_metadata() {
        let metadata = ReviewMetadata::new()
            .with_reviewer_actor_id("reviewer-001")
            .with_verdict(ReviewVerdict::Approve)
            .with_started_at(1000)
            .with_completed_at(2000);

        let bundle = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .metadata(metadata)
            .build()
            .expect("valid bundle");

        assert!(bundle.metadata.is_some());
        let meta = bundle.metadata.unwrap();
        assert_eq!(meta.reviewer_actor_id, Some("reviewer-001".to_string()));
        assert_eq!(meta.review_verdict, Some(ReviewVerdict::Approve));
    }

    #[test]
    fn test_artifact_bundle_cas_hash_deterministic() {
        let bundle1 = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        let bundle2 = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        // Same inputs produce same CAS hash
        assert_eq!(bundle1.compute_cas_hash(), bundle2.compute_cas_hash());
    }

    #[test]
    fn test_review_receipt_create_and_verify() {
        let signer = Signer::generate();
        let event = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0x55; 32]), // capability_manifest_hash (TCK-00326)
            Some([0x66; 32]), // context_pack_hash (TCK-00326)
            &signer,
        )
        .expect("valid event");

        // Verify signature
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_review_receipt_signature_fails_on_tamper() {
        let signer = Signer::generate();
        let mut event = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0x55; 32]), // capability_manifest_hash (TCK-00326)
            Some([0x66; 32]), // context_pack_hash (TCK-00326)
            &signer,
        )
        .expect("valid event");

        // Tamper with changeset_digest
        event.changeset_digest = [0xFF; 32];

        // Verification should fail
        assert!(event.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_review_receipt_builder() {
        let signer = Signer::generate();
        let event = ReviewReceiptRecordedBuilder::new()
            .receipt_id("RR-002")
            .changeset_digest([0x11; 32])
            .artifact_bundle_hash([0x22; 32])
            .time_envelope_ref([0x33; 32])
            .reviewer_actor_id("reviewer-002")
            .capability_manifest_hash([0x55; 32]) // TCK-00326
            .context_pack_hash([0x66; 32])        // TCK-00326
            .build_and_sign(&signer)
            .expect("valid event");

        assert_eq!(event.receipt_id, "RR-002");
        assert_eq!(event.capability_manifest_hash, Some([0x55; 32]));
        assert_eq!(event.context_pack_hash, Some([0x66; 32]));
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_review_receipt_builder_missing_fields() {
        let signer = Signer::generate();

        // Missing receipt_id
        let result = ReviewReceiptRecordedBuilder::new()
            .changeset_digest([0x11; 32])
            .artifact_bundle_hash([0x22; 32])
            .time_envelope_ref([0x33; 32])
            .reviewer_actor_id("reviewer-002")
            .capability_manifest_hash([0x55; 32])
            .context_pack_hash([0x66; 32])
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(ReviewReceiptError::MissingField("receipt_id"))
        ));

        // Missing artifact_bundle_hash
        let result = ReviewReceiptRecordedBuilder::new()
            .receipt_id("RR-002")
            .changeset_digest([0x11; 32])
            .time_envelope_ref([0x33; 32])
            .reviewer_actor_id("reviewer-002")
            .capability_manifest_hash([0x55; 32])
            .context_pack_hash([0x66; 32])
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(ReviewReceiptError::MissingField("artifact_bundle_hash"))
        ));

        // capability_manifest_hash and context_pack_hash are now optional for backward
        // compat so they should NOT cause MissingField errors
        let result = ReviewReceiptRecordedBuilder::new()
            .receipt_id("RR-002")
            .changeset_digest([0x11; 32])
            .artifact_bundle_hash([0x22; 32])
            .time_envelope_ref([0x33; 32])
            .reviewer_actor_id("reviewer-002")
            // No capability_manifest_hash or context_pack_hash
            .build_and_sign(&signer);
        assert!(result.is_ok());
        let event = result.unwrap();
        assert!(event.capability_manifest_hash.is_none());
        assert!(event.context_pack_hash.is_none());
    }

    #[test]
    fn test_review_receipt_string_too_long() {
        let signer = Signer::generate();
        let long_id = "x".repeat(MAX_RECEIPT_ID_LENGTH + 1);

        let result = ReviewReceiptRecorded::create(
            long_id,
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0x55; 32]), // capability_manifest_hash (TCK-00326)
            Some([0x66; 32]), // context_pack_hash (TCK-00326)
            &signer,
        );

        assert!(matches!(
            result,
            Err(ReviewReceiptError::StringTooLong {
                field: "receipt_id",
                ..
            })
        ));
    }

    #[test]
    fn test_review_receipt_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let event1 = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0x55; 32]), // capability_manifest_hash (TCK-00326)
            Some([0x66; 32]), // context_pack_hash (TCK-00326)
            &signer,
        )
        .expect("valid event");

        let event2 = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0x55; 32]), // capability_manifest_hash (TCK-00326)
            Some([0x66; 32]), // context_pack_hash (TCK-00326)
            &signer,
        )
        .expect("valid event");

        // Same inputs produce same canonical bytes
        assert_eq!(event1.canonical_bytes(), event2.canonical_bytes());
        // Ed25519 is deterministic, so signatures should match
        assert_eq!(event1.reviewer_signature, event2.reviewer_signature);
    }

    #[test]
    fn test_validate_changeset_binding() {
        let signer = Signer::generate();
        let expected_digest = [0x42; 32];

        let event = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            expected_digest,
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0x55; 32]), // capability_manifest_hash (TCK-00326)
            Some([0x66; 32]), // context_pack_hash (TCK-00326)
            &signer,
        )
        .expect("valid event");

        // Should pass with matching digest
        assert!(validate_changeset_binding(&event, &expected_digest).is_ok());

        // Should fail with mismatched digest
        let wrong_digest = [0xFF; 32];
        assert!(validate_changeset_binding(&event, &wrong_digest).is_err());
    }

    #[test]
    fn test_authority_binding_fields_in_receipt_signature() {
        // TCK-00326: Verify that capability_manifest_hash and context_pack_hash
        // are included in the signature
        let signer = Signer::generate();
        let event1 = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0x55; 32]), // capability_manifest_hash
            Some([0x66; 32]), // context_pack_hash
            &signer,
        )
        .expect("valid event");

        let event2 = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0xAA; 32]), // Different capability_manifest_hash
            Some([0x66; 32]), // Same context_pack_hash
            &signer,
        )
        .expect("valid event");

        // Different authority binding produces different canonical bytes and signature
        assert_ne!(event1.canonical_bytes(), event2.canonical_bytes());
        assert_ne!(event1.reviewer_signature, event2.reviewer_signature);
    }

    #[test]
    fn test_backward_compat_none_fields() {
        // TCK-00326: Events without capability_manifest_hash/context_pack_hash
        // should have shorter canonical bytes and verify correctly
        let signer = Signer::generate();
        let event_with = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            Some([0x55; 32]),
            Some([0x66; 32]),
            &signer,
        )
        .expect("valid event");

        let event_without = ReviewReceiptRecorded::create(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            None,
            None,
            &signer,
        )
        .expect("valid event");

        // Events without optional fields have shorter canonical bytes
        assert!(event_without.canonical_bytes().len() < event_with.canonical_bytes().len());
        // Both should verify correctly
        assert!(event_with.verify_signature(&signer.verifying_key()).is_ok());
        assert!(
            event_without
                .verify_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_artifact_bundle_validation_invalid_schema() {
        let mut bundle = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        bundle.schema = "invalid.schema".to_string();
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_artifact_bundle_validation_too_many_logs() {
        let result = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .tool_log_hashes(vec![[0x00; 32]; MAX_TOOL_LOG_HASHES + 1])
            .time_envelope_ref([0x44; 32])
            .build();

        assert!(matches!(
            result,
            Err(ReviewReceiptError::CollectionTooLarge {
                field: "tool_log_hashes",
                ..
            })
        ));
    }

    // ==========================================================================
    // TCK-00325: build_strict and holon-ready bindings tests
    // ==========================================================================

    #[test]
    fn test_artifact_bundle_build_strict_success() {
        let bundle = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .view_commitment_hash([0x55; 32])
            .policy_resolved_ref("policy-ref-001")
            .build_strict()
            .expect("valid bundle with holon-ready bindings");

        assert!(bundle.view_commitment_hash.is_some());
        assert!(bundle.policy_resolved_ref.is_some());
        assert_eq!(
            bundle.view_commitment_hash.unwrap(),
            hex::encode([0x55; 32])
        );
        assert_eq!(bundle.policy_resolved_ref.unwrap(), "policy-ref-001");
    }

    #[test]
    fn test_artifact_bundle_build_strict_missing_view_commitment() {
        // Missing view_commitment_hash should fail
        let result = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .policy_resolved_ref("policy-ref-001")
            // Note: view_commitment_hash NOT set
            .build_strict();

        assert!(matches!(
            result,
            Err(ReviewReceiptError::MissingField("view_commitment_hash"))
        ));
    }

    #[test]
    fn test_artifact_bundle_build_strict_missing_policy_ref() {
        // Missing policy_resolved_ref should fail
        let result = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .view_commitment_hash([0x55; 32])
            // Note: policy_resolved_ref NOT set
            .build_strict();

        assert!(matches!(
            result,
            Err(ReviewReceiptError::MissingField("policy_resolved_ref"))
        ));
    }

    #[test]
    fn test_artifact_bundle_has_holon_ready_bindings() {
        // Without bindings
        let builder = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32]);

        assert!(!builder.has_holon_ready_bindings());

        // With only view_commitment_hash
        let builder = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .view_commitment_hash([0x55; 32]);

        assert!(!builder.has_holon_ready_bindings());

        // With only policy_resolved_ref
        let builder = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .policy_resolved_ref("policy-ref");

        assert!(!builder.has_holon_ready_bindings());

        // With both bindings
        let builder = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .view_commitment_hash([0x55; 32])
            .policy_resolved_ref("policy-ref");

        assert!(builder.has_holon_ready_bindings());
    }

    #[test]
    fn test_artifact_bundle_build_vs_build_strict() {
        // Regular build() succeeds without holon-ready bindings
        let result = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .build();

        assert!(result.is_ok());
        let bundle = result.unwrap();
        assert!(bundle.view_commitment_hash.is_none());
        assert!(bundle.policy_resolved_ref.is_none());

        // build_strict() fails without holon-ready bindings
        let result = ReviewArtifactBundleV1::builder()
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .time_envelope_ref([0x44; 32])
            .build_strict();

        assert!(result.is_err());
    }
}
