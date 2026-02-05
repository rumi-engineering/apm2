// AGENT-AUTHORED (TCK-00323)
//! Projection receipt types for FAC v0 successful projection completion.
//!
//! This module implements the `ProjectionReceiptRecorded` event which is
//! emitted when a projection completes successfully. The projection artifacts
//! are stored in CAS and bound to the changeset via this ledger event.
//!
//! # Design Overview
//!
//! The [`ProjectionReceiptRecorded`] event captures:
//! - The changeset digest being projected (from `ChangeSetPublished`)
//! - CAS reference to the `ProjectionArtifactBundleV1` containing projection
//!   outputs
//! - HTF time envelope for temporal authority
//! - Domain-separated signature for integrity
//!
//! The [`ProjectionArtifactBundleV1`] structure contains:
//! - Projected status (success, failure, etc.)
//! - Ledger head hash at time of projection
//! - Work ID and changeset digest for binding
//! - Projection metadata (timestamps, actor info)
//!
//! # Security Properties
//!
//! - **Domain Separation**: The signature uses the
//!   `PROJECTION_RECEIPT_RECORDED:` domain prefix to prevent replay attacks.
//! - **CAS Binding**: Projection artifacts are stored in CAS with hash
//!   reference for integrity verification.
//! - **HTF Time Binding**: Time envelope reference provides temporal authority
//!   for audit and ordering.
//! - **Changeset Binding**: The `changeset_digest` binds the projection to a
//!   specific `ChangeSetPublished` event.
//! - **Idempotency**: Key `(work_id, changeset_digest, ledger_head)` prevents
//!   duplicate projections.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     ProjectedStatusCode, ProjectionArtifactBundleV1,
//!     ProjectionReceiptRecorded,
//! };
//!
//! let signer = Signer::generate();
//!
//! // Create the artifact bundle first
//! let bundle = ProjectionArtifactBundleV1::builder()
//!     .work_id("work-001")
//!     .changeset_digest([0x42; 32])
//!     .ledger_head([0xAB; 32])
//!     .projected_status(ProjectedStatusCode::Success)
//!     .time_envelope_ref([0x44; 32])
//!     .build()
//!     .expect("valid bundle");
//!
//! // Compute CAS hash of the bundle
//! let bundle_hash = bundle.compute_cas_hash();
//!
//! // Create the receipt event
//! let event = ProjectionReceiptRecorded::create(
//!     "PR-001".to_string(),
//!     [0x42; 32], // changeset_digest
//!     bundle_hash,
//!     [0x44; 32], // time_envelope_ref
//!     "projector-001".to_string(),
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
    PROJECTION_RECEIPT_RECORDED_PREFIX, sign_with_domain, verify_with_domain,
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

/// Maximum length for work ID.
pub const MAX_WORK_ID_LENGTH: usize = 128;

/// Schema identifier for `ProjectionArtifactBundleV1`.
pub const SCHEMA_IDENTIFIER: &str = "apm2.projection_artifact_bundle.v1";

/// Current schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during projection receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProjectionReceiptRecordedError {
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

    /// Invalid status code.
    #[error("invalid status code: {0}")]
    InvalidStatusCode(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

// =============================================================================
// ProjectedStatusCode
// =============================================================================

/// Status code outcome for a projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectedStatusCode {
    /// Gates are still running (pending).
    Pending,
    /// All gates passed successfully.
    Success,
    /// One or more gates failed.
    Failure,
    /// Gates were cancelled.
    Cancelled,
    /// An error occurred during projection.
    Error,
}

impl std::fmt::Display for ProjectedStatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "PENDING"),
            Self::Success => write!(f, "SUCCESS"),
            Self::Failure => write!(f, "FAILURE"),
            Self::Cancelled => write!(f, "CANCELLED"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

impl std::str::FromStr for ProjectedStatusCode {
    type Err = ProjectionReceiptRecordedError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PENDING" => Ok(Self::Pending),
            "SUCCESS" => Ok(Self::Success),
            "FAILURE" => Ok(Self::Failure),
            "CANCELLED" => Ok(Self::Cancelled),
            "ERROR" => Ok(Self::Error),
            _ => Err(ProjectionReceiptRecordedError::InvalidStatusCode(
                s.to_string(),
            )),
        }
    }
}

impl ProjectedStatusCode {
    /// Returns the numeric code for this status.
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Success => 1,
            Self::Failure => 2,
            Self::Cancelled => 3,
            Self::Error => 4,
        }
    }

    /// Creates a status from its numeric code.
    ///
    /// # Errors
    ///
    /// Returns error if the code is invalid.
    pub fn from_code(code: u8) -> Result<Self, ProjectionReceiptRecordedError> {
        match code {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Success),
            2 => Ok(Self::Failure),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::Error),
            _ => Err(ProjectionReceiptRecordedError::InvalidStatusCode(format!(
                "invalid code: {code}"
            ))),
        }
    }
}

// =============================================================================
// ProjectionMetadata
// =============================================================================

/// Metadata for a projection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionMetadata {
    /// Actor ID of the projector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projector_actor_id: Option<String>,
    /// Unix nanoseconds when projection started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection_started_at: Option<u64>,
    /// Unix nanoseconds when projection completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection_completed_at: Option<u64>,
    /// Target system for the projection (e.g., "github", "gitlab").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_system: Option<String>,
}

impl ProjectionMetadata {
    /// Creates an empty metadata instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the projector actor ID.
    #[must_use]
    pub fn with_projector_actor_id(mut self, id: impl Into<String>) -> Self {
        self.projector_actor_id = Some(id.into());
        self
    }

    /// Sets the projection start timestamp.
    #[must_use]
    pub const fn with_started_at(mut self, ts: u64) -> Self {
        self.projection_started_at = Some(ts);
        self
    }

    /// Sets the projection completion timestamp.
    #[must_use]
    pub const fn with_completed_at(mut self, ts: u64) -> Self {
        self.projection_completed_at = Some(ts);
        self
    }

    /// Sets the target system.
    #[must_use]
    pub fn with_target_system(mut self, system: impl Into<String>) -> Self {
        self.target_system = Some(system.into());
        self
    }

    /// Validates the metadata.
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds maximum length.
    pub fn validate(&self) -> Result<(), ProjectionReceiptRecordedError> {
        if let Some(ref id) = self.projector_actor_id {
            if id.len() > MAX_STRING_LENGTH {
                return Err(ProjectionReceiptRecordedError::StringTooLong {
                    field: "projector_actor_id",
                    len: id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }
        if let Some(ref system) = self.target_system {
            if system.len() > MAX_STRING_LENGTH {
                return Err(ProjectionReceiptRecordedError::StringTooLong {
                    field: "target_system",
                    len: system.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }
        Ok(())
    }
}

// =============================================================================
// ProjectionArtifactBundleV1
// =============================================================================

/// A bundle of projection artifacts stored in CAS.
///
/// This structure represents the canonical form of projection outputs that are
/// stored in CAS and referenced by `ProjectionReceiptRecorded` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionArtifactBundleV1 {
    /// Schema identifier (always `apm2.projection_artifact_bundle.v1`).
    pub schema: String,
    /// Schema version (semver format).
    pub schema_version: String,
    /// Work item ID that was projected.
    pub work_id: String,
    /// BLAKE3 digest of the changeset being projected (32 bytes, hex-encoded).
    pub changeset_digest: String,
    /// BLAKE3 hash of the ledger head at time of projection (32 bytes,
    /// hex-encoded).
    pub ledger_head: String,
    /// The status that was projected.
    pub projected_status: ProjectedStatusCode,
    /// HTF time envelope reference hash (32 bytes, hex-encoded).
    pub time_envelope_ref: String,
    /// Optional metadata for projection context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProjectionMetadata>,
}

impl ProjectionArtifactBundleV1 {
    /// Creates a builder for constructing a `ProjectionArtifactBundleV1`.
    #[must_use]
    pub fn builder() -> ProjectionArtifactBundleV1Builder {
        ProjectionArtifactBundleV1Builder::default()
    }

    /// Computes the CAS hash of this bundle.
    ///
    /// The hash is computed over the canonical JSON representation.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal circumstances. The only panic
    /// path is if JSON serialization fails, which cannot happen for a valid
    /// `ProjectionArtifactBundleV1` since all fields are serializable.
    #[must_use]
    pub fn compute_cas_hash(&self) -> [u8; 32] {
        let json =
            serde_json::to_vec(self).expect("ProjectionArtifactBundleV1 is always serializable");
        *blake3::hash(&json).as_bytes()
    }

    /// Returns the idempotency key for this bundle.
    ///
    /// The idempotency key is `(work_id, changeset_digest, ledger_head)`.
    /// This can be used to prevent duplicate projections.
    #[must_use]
    pub fn idempotency_key(&self) -> (String, String, String) {
        (
            self.work_id.clone(),
            self.changeset_digest.clone(),
            self.ledger_head.clone(),
        )
    }

    /// Validates the bundle.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self) -> Result<(), ProjectionReceiptRecordedError> {
        // Validate schema
        if self.schema != SCHEMA_IDENTIFIER {
            return Err(ProjectionReceiptRecordedError::InvalidData(format!(
                "invalid schema: expected {SCHEMA_IDENTIFIER}, got {}",
                self.schema
            )));
        }

        // Validate work_id
        if self.work_id.is_empty() {
            return Err(ProjectionReceiptRecordedError::MissingField("work_id"));
        }
        if self.work_id.len() > MAX_WORK_ID_LENGTH {
            return Err(ProjectionReceiptRecordedError::StringTooLong {
                field: "work_id",
                len: self.work_id.len(),
                max: MAX_WORK_ID_LENGTH,
            });
        }

        // Validate changeset_digest format (64 hex chars)
        if self.changeset_digest.len() != 64 {
            return Err(ProjectionReceiptRecordedError::InvalidData(
                "changeset_digest must be 64 hex characters".into(),
            ));
        }
        if !self.changeset_digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ProjectionReceiptRecordedError::InvalidData(
                "changeset_digest must be hex-encoded".into(),
            ));
        }

        // Validate ledger_head format (64 hex chars)
        if self.ledger_head.len() != 64 {
            return Err(ProjectionReceiptRecordedError::InvalidData(
                "ledger_head must be 64 hex characters".into(),
            ));
        }
        if !self.ledger_head.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ProjectionReceiptRecordedError::InvalidData(
                "ledger_head must be hex-encoded".into(),
            ));
        }

        // Validate time_envelope_ref format
        if self.time_envelope_ref.len() != 64 {
            return Err(ProjectionReceiptRecordedError::InvalidData(
                "time_envelope_ref must be 64 hex characters".into(),
            ));
        }

        // Validate metadata if present
        if let Some(ref metadata) = self.metadata {
            metadata.validate()?;
        }

        Ok(())
    }
}

// =============================================================================
// ProjectionArtifactBundleV1Builder
// =============================================================================

/// Builder for constructing a `ProjectionArtifactBundleV1`.
#[derive(Debug, Default)]
pub struct ProjectionArtifactBundleV1Builder {
    work_id: Option<String>,
    changeset_digest: Option<[u8; 32]>,
    ledger_head: Option<[u8; 32]>,
    projected_status: Option<ProjectedStatusCode>,
    time_envelope_ref: Option<[u8; 32]>,
    metadata: Option<ProjectionMetadata>,
}

#[allow(clippy::missing_const_for_fn)]
impl ProjectionArtifactBundleV1Builder {
    /// Sets the work ID.
    #[must_use]
    pub fn work_id(mut self, id: impl Into<String>) -> Self {
        self.work_id = Some(id.into());
        self
    }

    /// Sets the changeset digest.
    #[must_use]
    pub fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the ledger head.
    #[must_use]
    pub fn ledger_head(mut self, head: [u8; 32]) -> Self {
        self.ledger_head = Some(head);
        self
    }

    /// Sets the projected status.
    #[must_use]
    pub fn projected_status(mut self, status: ProjectedStatusCode) -> Self {
        self.projected_status = Some(status);
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, hash: [u8; 32]) -> Self {
        self.time_envelope_ref = Some(hash);
        self
    }

    /// Sets the metadata.
    #[must_use]
    pub fn metadata(mut self, metadata: ProjectionMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Builds the `ProjectionArtifactBundleV1`.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build(self) -> Result<ProjectionArtifactBundleV1, ProjectionReceiptRecordedError> {
        let work_id = self
            .work_id
            .ok_or(ProjectionReceiptRecordedError::MissingField("work_id"))?;
        let changeset_digest =
            self.changeset_digest
                .ok_or(ProjectionReceiptRecordedError::MissingField(
                    "changeset_digest",
                ))?;
        let ledger_head = self
            .ledger_head
            .ok_or(ProjectionReceiptRecordedError::MissingField("ledger_head"))?;
        let projected_status =
            self.projected_status
                .ok_or(ProjectionReceiptRecordedError::MissingField(
                    "projected_status",
                ))?;
        let time_envelope_ref =
            self.time_envelope_ref
                .ok_or(ProjectionReceiptRecordedError::MissingField(
                    "time_envelope_ref",
                ))?;

        let bundle = ProjectionArtifactBundleV1 {
            schema: SCHEMA_IDENTIFIER.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            work_id,
            changeset_digest: hex::encode(changeset_digest),
            ledger_head: hex::encode(ledger_head),
            projected_status,
            time_envelope_ref: hex::encode(time_envelope_ref),
            metadata: self.metadata,
        };

        bundle.validate()?;
        Ok(bundle)
    }
}

// =============================================================================
// ProjectionReceiptRecorded
// =============================================================================

/// Event emitted when a projection is successfully completed.
///
/// This event records the successful projection outcome and stores it durably
/// in the ledger. It binds the projection artifacts to the changeset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionReceiptRecorded {
    /// Unique identifier for this receipt.
    pub receipt_id: String,
    /// BLAKE3 digest of the changeset that was projected (32 bytes).
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],
    /// BLAKE3 hash of the `ProjectionArtifactBundleV1` stored in CAS (32
    /// bytes).
    #[serde(with = "serde_bytes")]
    pub artifact_bundle_hash: [u8; 32],
    /// HTF time envelope reference hash for temporal authority (32 bytes).
    #[serde(with = "serde_bytes")]
    pub time_envelope_ref: [u8; 32],
    /// Actor who recorded the receipt (the projector).
    pub projector_actor_id: String,
    /// Ed25519 signature over canonical bytes with
    /// `PROJECTION_RECEIPT_RECORDED:` domain.
    #[serde(with = "serde_bytes")]
    pub projector_signature: [u8; 64],
}

impl ProjectionReceiptRecorded {
    /// Creates a new `ProjectionReceiptRecorded` event.
    ///
    /// # Arguments
    ///
    /// * `receipt_id` - Unique identifier for this receipt
    /// * `changeset_digest` - BLAKE3 digest of the changeset
    /// * `artifact_bundle_hash` - CAS hash of `ProjectionArtifactBundleV1`
    /// * `time_envelope_ref` - HTF time envelope reference hash
    /// * `projector_actor_id` - ID of the projecting actor
    /// * `signer` - Signer to authorize the event
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds maximum length.
    pub fn create(
        receipt_id: String,
        changeset_digest: [u8; 32],
        artifact_bundle_hash: [u8; 32],
        time_envelope_ref: [u8; 32],
        projector_actor_id: String,
        signer: &Signer,
    ) -> Result<Self, ProjectionReceiptRecordedError> {
        // Validate inputs
        if receipt_id.is_empty() {
            return Err(ProjectionReceiptRecordedError::MissingField("receipt_id"));
        }
        if receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(ProjectionReceiptRecordedError::StringTooLong {
                field: "receipt_id",
                len: receipt_id.len(),
                max: MAX_RECEIPT_ID_LENGTH,
            });
        }
        if projector_actor_id.is_empty() {
            return Err(ProjectionReceiptRecordedError::MissingField(
                "projector_actor_id",
            ));
        }
        if projector_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ProjectionReceiptRecordedError::StringTooLong {
                field: "projector_actor_id",
                len: projector_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Construct event with placeholder signature
        let mut event = Self {
            receipt_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            projector_actor_id,
            projector_signature: [0u8; 64],
        };

        // Sign
        let canonical = event.canonical_bytes();
        let signature = sign_with_domain(signer, PROJECTION_RECEIPT_RECORDED_PREFIX, &canonical);
        event.projector_signature = signature.to_bytes();

        Ok(event)
    }

    /// Creates a `ProjectionReceiptRecorded` event with a `TimeEnvelopeRef`.
    ///
    /// # Errors
    ///
    /// Returns error if any string field exceeds maximum length.
    pub fn create_with_envelope(
        receipt_id: String,
        changeset_digest: [u8; 32],
        artifact_bundle_hash: [u8; 32],
        envelope_ref: &TimeEnvelopeRef,
        projector_actor_id: String,
        signer: &Signer,
    ) -> Result<Self, ProjectionReceiptRecordedError> {
        let time_envelope_ref: [u8; 32] = *envelope_ref.as_bytes();
        Self::create(
            receipt_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            projector_actor_id,
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
    /// - `projector_actor_id` (len + bytes)
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

        // 5. projector_actor_id
        bytes.extend_from_slice(&(self.projector_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.projector_actor_id.as_bytes());

        bytes
    }

    /// Verifies the event signature.
    ///
    /// # Errors
    ///
    /// Returns error if the signature doesn't match the canonical bytes.
    pub fn verify_signature(
        &self,
        key: &VerifyingKey,
    ) -> Result<(), ProjectionReceiptRecordedError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.projector_signature);

        verify_with_domain(
            key,
            PROJECTION_RECEIPT_RECORDED_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|e| ProjectionReceiptRecordedError::SignatureVerificationFailed(e.to_string()))
    }

    /// Returns the time envelope reference as a `TimeEnvelopeRef`.
    #[must_use]
    pub fn time_envelope(&self) -> Option<TimeEnvelopeRef> {
        TimeEnvelopeRef::from_slice(&self.time_envelope_ref)
    }
}

// =============================================================================
// ProjectionReceiptRecordedBuilder
// =============================================================================

/// Builder for constructing a `ProjectionReceiptRecorded` event.
#[derive(Debug, Default)]
pub struct ProjectionReceiptRecordedBuilder {
    receipt_id: Option<String>,
    changeset_digest: Option<[u8; 32]>,
    artifact_bundle_hash: Option<[u8; 32]>,
    time_envelope_ref: Option<[u8; 32]>,
    projector_actor_id: Option<String>,
}

#[allow(clippy::missing_const_for_fn)]
impl ProjectionReceiptRecordedBuilder {
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

    /// Sets the projector actor ID.
    #[must_use]
    pub fn projector_actor_id(mut self, id: impl Into<String>) -> Self {
        self.projector_actor_id = Some(id.into());
        self
    }

    /// Builds the event and signs it.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build_and_sign(
        self,
        signer: &Signer,
    ) -> Result<ProjectionReceiptRecorded, ProjectionReceiptRecordedError> {
        let receipt_id = self
            .receipt_id
            .ok_or(ProjectionReceiptRecordedError::MissingField("receipt_id"))?;
        let changeset_digest =
            self.changeset_digest
                .ok_or(ProjectionReceiptRecordedError::MissingField(
                    "changeset_digest",
                ))?;
        let artifact_bundle_hash =
            self.artifact_bundle_hash
                .ok_or(ProjectionReceiptRecordedError::MissingField(
                    "artifact_bundle_hash",
                ))?;
        let time_envelope_ref =
            self.time_envelope_ref
                .ok_or(ProjectionReceiptRecordedError::MissingField(
                    "time_envelope_ref",
                ))?;
        let projector_actor_id =
            self.projector_actor_id
                .ok_or(ProjectionReceiptRecordedError::MissingField(
                    "projector_actor_id",
                ))?;

        ProjectionReceiptRecorded::create(
            receipt_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            projector_actor_id,
            signer,
        )
    }
}

// =============================================================================
// Proto Conversions
// =============================================================================

// Re-export proto type for wire format serialization
pub use crate::events::ProjectionReceiptRecorded as ProjectionReceiptRecordedProto;

impl TryFrom<ProjectionReceiptRecordedProto> for ProjectionReceiptRecorded {
    type Error = ProjectionReceiptRecordedError;

    fn try_from(proto: ProjectionReceiptRecordedProto) -> Result<Self, Self::Error> {
        // Validate resource limits
        if proto.receipt_id.is_empty() {
            return Err(ProjectionReceiptRecordedError::MissingField("receipt_id"));
        }
        if proto.receipt_id.len() > MAX_RECEIPT_ID_LENGTH {
            return Err(ProjectionReceiptRecordedError::StringTooLong {
                field: "receipt_id",
                len: proto.receipt_id.len(),
                max: MAX_RECEIPT_ID_LENGTH,
            });
        }
        if proto.projector_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ProjectionReceiptRecordedError::StringTooLong {
                field: "projector_actor_id",
                len: proto.projector_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let changeset_digest = proto.changeset_digest.try_into().map_err(|_| {
            ProjectionReceiptRecordedError::InvalidData("changeset_digest must be 32 bytes".into())
        })?;

        let artifact_bundle_hash = proto.artifact_bundle_hash.try_into().map_err(|_| {
            ProjectionReceiptRecordedError::InvalidData(
                "artifact_bundle_hash must be 32 bytes".into(),
            )
        })?;

        let time_envelope_ref = proto
            .time_envelope_ref
            .as_ref()
            .map(|ter| {
                ter.hash.as_slice().try_into().map_err(|_| {
                    ProjectionReceiptRecordedError::InvalidData(
                        "time_envelope_ref must be 32 bytes".into(),
                    )
                })
            })
            .transpose()?
            .unwrap_or([0u8; 32]);

        let projector_signature = proto.projector_signature.try_into().map_err(|_| {
            ProjectionReceiptRecordedError::InvalidData(
                "projector_signature must be 64 bytes".into(),
            )
        })?;

        Ok(Self {
            receipt_id: proto.receipt_id,
            changeset_digest,
            artifact_bundle_hash,
            time_envelope_ref,
            projector_actor_id: proto.projector_actor_id,
            projector_signature,
        })
    }
}

impl From<ProjectionReceiptRecorded> for ProjectionReceiptRecordedProto {
    fn from(event: ProjectionReceiptRecorded) -> Self {
        // Import the proto TimeEnvelopeRef type
        use crate::events::TimeEnvelopeRef as TimeEnvelopeRefProto;

        Self {
            receipt_id: event.receipt_id,
            changeset_digest: event.changeset_digest.to_vec(),
            artifact_bundle_hash: event.artifact_bundle_hash.to_vec(),
            time_envelope_ref: Some(TimeEnvelopeRefProto {
                hash: event.time_envelope_ref.to_vec(),
            }),
            projector_actor_id: event.projector_actor_id,
            projector_signature: event.projector_signature.to_vec(),
        }
    }
}

// =============================================================================
// Validation Functions
// =============================================================================

/// Validates that a `ProjectionReceiptRecorded` event properly binds to a
/// changeset.
///
/// # Arguments
///
/// * `receipt` - The projection receipt to validate
/// * `expected_changeset_digest` - The expected changeset digest from
///   `ChangeSetPublished`
///
/// # Errors
///
/// Returns error if the changeset digest doesn't match.
pub fn validate_changeset_binding(
    receipt: &ProjectionReceiptRecorded,
    expected_changeset_digest: &[u8; 32],
) -> Result<(), ProjectionReceiptRecordedError> {
    if receipt.changeset_digest != *expected_changeset_digest {
        return Err(ProjectionReceiptRecordedError::InvalidData(format!(
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
    fn test_projected_status_code_from_str() {
        assert_eq!(
            "PENDING".parse::<ProjectedStatusCode>().unwrap(),
            ProjectedStatusCode::Pending
        );
        assert_eq!(
            "SUCCESS".parse::<ProjectedStatusCode>().unwrap(),
            ProjectedStatusCode::Success
        );
        assert_eq!(
            "FAILURE".parse::<ProjectedStatusCode>().unwrap(),
            ProjectedStatusCode::Failure
        );
        assert_eq!(
            "CANCELLED".parse::<ProjectedStatusCode>().unwrap(),
            ProjectedStatusCode::Cancelled
        );
        assert_eq!(
            "ERROR".parse::<ProjectedStatusCode>().unwrap(),
            ProjectedStatusCode::Error
        );
        assert!("UNKNOWN".parse::<ProjectedStatusCode>().is_err());
    }

    #[test]
    fn test_projected_status_code_to_code_roundtrip() {
        for code in 0..=4u8 {
            let status = ProjectedStatusCode::from_code(code).unwrap();
            assert_eq!(status.to_code(), code);
        }
        assert!(ProjectedStatusCode::from_code(5).is_err());
    }

    #[test]
    fn test_projected_status_code_display() {
        assert_eq!(ProjectedStatusCode::Pending.to_string(), "PENDING");
        assert_eq!(ProjectedStatusCode::Success.to_string(), "SUCCESS");
        assert_eq!(ProjectedStatusCode::Failure.to_string(), "FAILURE");
        assert_eq!(ProjectedStatusCode::Cancelled.to_string(), "CANCELLED");
        assert_eq!(ProjectedStatusCode::Error.to_string(), "ERROR");
    }

    #[test]
    fn test_artifact_bundle_build() {
        let bundle = ProjectionArtifactBundleV1::builder()
            .work_id("work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatusCode::Success)
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        assert_eq!(bundle.schema, SCHEMA_IDENTIFIER);
        assert_eq!(bundle.schema_version, SCHEMA_VERSION);
        assert_eq!(bundle.work_id, "work-001");
        assert_eq!(bundle.changeset_digest, hex::encode([0x42; 32]));
        assert_eq!(bundle.projected_status, ProjectedStatusCode::Success);
    }

    #[test]
    fn test_artifact_bundle_with_metadata() {
        let metadata = ProjectionMetadata::new()
            .with_projector_actor_id("projector-001")
            .with_started_at(1000)
            .with_completed_at(2000)
            .with_target_system("github");

        let bundle = ProjectionArtifactBundleV1::builder()
            .work_id("work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatusCode::Success)
            .time_envelope_ref([0x44; 32])
            .metadata(metadata)
            .build()
            .expect("valid bundle");

        assert!(bundle.metadata.is_some());
        let meta = bundle.metadata.unwrap();
        assert_eq!(meta.projector_actor_id, Some("projector-001".to_string()));
        assert_eq!(meta.target_system, Some("github".to_string()));
    }

    #[test]
    fn test_artifact_bundle_cas_hash_deterministic() {
        let bundle1 = ProjectionArtifactBundleV1::builder()
            .work_id("work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatusCode::Success)
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        let bundle2 = ProjectionArtifactBundleV1::builder()
            .work_id("work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatusCode::Success)
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        // Same inputs produce same CAS hash
        assert_eq!(bundle1.compute_cas_hash(), bundle2.compute_cas_hash());
    }

    #[test]
    fn test_artifact_bundle_idempotency_key() {
        let bundle = ProjectionArtifactBundleV1::builder()
            .work_id("work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatusCode::Success)
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        let key = bundle.idempotency_key();
        assert_eq!(key.0, "work-001");
        assert_eq!(key.1, hex::encode([0x42; 32]));
        assert_eq!(key.2, hex::encode([0xAB; 32]));
    }

    #[test]
    fn test_projection_receipt_create_and_verify() {
        let signer = Signer::generate();
        let event = ProjectionReceiptRecorded::create(
            "PR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "projector-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Verify signature
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_projection_receipt_signature_fails_on_tamper() {
        let signer = Signer::generate();
        let mut event = ProjectionReceiptRecorded::create(
            "PR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "projector-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Tamper with changeset_digest
        event.changeset_digest = [0xFF; 32];

        // Verification should fail
        assert!(event.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_projection_receipt_builder() {
        let signer = Signer::generate();
        let event = ProjectionReceiptRecordedBuilder::new()
            .receipt_id("PR-002")
            .changeset_digest([0x11; 32])
            .artifact_bundle_hash([0x22; 32])
            .time_envelope_ref([0x33; 32])
            .projector_actor_id("projector-002")
            .build_and_sign(&signer)
            .expect("valid event");

        assert_eq!(event.receipt_id, "PR-002");
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_projection_receipt_builder_missing_fields() {
        let signer = Signer::generate();

        // Missing receipt_id
        let result = ProjectionReceiptRecordedBuilder::new()
            .changeset_digest([0x11; 32])
            .artifact_bundle_hash([0x22; 32])
            .time_envelope_ref([0x33; 32])
            .projector_actor_id("projector-002")
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(ProjectionReceiptRecordedError::MissingField("receipt_id"))
        ));

        // Missing artifact_bundle_hash
        let result = ProjectionReceiptRecordedBuilder::new()
            .receipt_id("PR-002")
            .changeset_digest([0x11; 32])
            .time_envelope_ref([0x33; 32])
            .projector_actor_id("projector-002")
            .build_and_sign(&signer);
        assert!(matches!(
            result,
            Err(ProjectionReceiptRecordedError::MissingField(
                "artifact_bundle_hash"
            ))
        ));
    }

    #[test]
    fn test_projection_receipt_string_too_long() {
        let signer = Signer::generate();
        let long_id = "x".repeat(MAX_RECEIPT_ID_LENGTH + 1);

        let result = ProjectionReceiptRecorded::create(
            long_id,
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "projector-001".to_string(),
            &signer,
        );

        assert!(matches!(
            result,
            Err(ProjectionReceiptRecordedError::StringTooLong {
                field: "receipt_id",
                ..
            })
        ));
    }

    #[test]
    fn test_projection_receipt_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let event1 = ProjectionReceiptRecorded::create(
            "PR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "projector-001".to_string(),
            &signer,
        )
        .expect("valid event");

        let event2 = ProjectionReceiptRecorded::create(
            "PR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "projector-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Same inputs produce same canonical bytes
        assert_eq!(event1.canonical_bytes(), event2.canonical_bytes());
        // Ed25519 is deterministic, so signatures should match
        assert_eq!(event1.projector_signature, event2.projector_signature);
    }

    #[test]
    fn test_validate_changeset_binding() {
        let signer = Signer::generate();
        let expected_digest = [0x42; 32];

        let event = ProjectionReceiptRecorded::create(
            "PR-001".to_string(),
            expected_digest,
            [0x33; 32],
            [0x44; 32],
            "projector-001".to_string(),
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
    fn test_artifact_bundle_validation_invalid_schema() {
        let mut bundle = ProjectionArtifactBundleV1::builder()
            .work_id("work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatusCode::Success)
            .time_envelope_ref([0x44; 32])
            .build()
            .expect("valid bundle");

        bundle.schema = "invalid.schema".to_string();
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_proto_roundtrip() {
        let signer = Signer::generate();
        let event = ProjectionReceiptRecorded::create(
            "PR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "projector-001".to_string(),
            &signer,
        )
        .expect("valid event");

        // Convert to proto and back
        let proto: ProjectionReceiptRecordedProto = event.clone().into();
        let recovered: ProjectionReceiptRecorded = proto.try_into().expect("valid proto");

        assert_eq!(event.receipt_id, recovered.receipt_id);
        assert_eq!(event.changeset_digest, recovered.changeset_digest);
        assert_eq!(event.artifact_bundle_hash, recovered.artifact_bundle_hash);
        assert_eq!(event.time_envelope_ref, recovered.time_envelope_ref);
        assert_eq!(event.projector_actor_id, recovered.projector_actor_id);
        assert_eq!(event.projector_signature, recovered.projector_signature);

        // Signature should still verify
        assert!(recovered.verify_signature(&signer.verifying_key()).is_ok());
    }
}
