// AGENT-AUTHORED (TCK-00212, TCK-00506)
//! Projection receipt types for the FAC GitHub projection adapter.
//!
//! This module defines [`ProjectionReceipt`] which provides cryptographic proof
//! that a status was successfully projected to an external system (e.g.,
//! GitHub), and [`ProjectionAdmissionReceipt`] which extends that proof with
//! temporal binding fields required for economics gate compatibility.
//!
//! # Security Model
//!
//! - Legacy receipts are signed using the `PROJECTION_RECEIPT:` domain prefix
//! - Admission receipts use the `PROJECTION_ADMISSION_RECEIPT:` domain prefix
//! - Cross-domain signature confusion is prevented: a legacy-domain signature
//!   MUST NOT be accepted as proof of temporal binding
//! - All fields except the signature are included in canonical bytes
//! - Length-prefixed encoding prevents canonicalization collision attacks
//!
//! # Backwards Compatibility
//!
//! [`ProjectionReceipt`] accepts optional temporal fields for forwards
//! compatibility. Old serialized payloads without temporal fields deserialize
//! successfully. At validation time, fail-closed semantics apply: admission
//! paths that require temporal binding must use [`ProjectionAdmissionReceipt`]
//! which requires all temporal fields.
//!
//! # Idempotency
//!
//! Projections are idempotent with the key `(work_id, changeset_digest,
//! ledger_head)`. If a projection is retried with the same key, the same
//! receipt should be returned.

use apm2_core::crypto::{Hash, Signature, Signer, VerifyingKey};
use apm2_core::fac::{
    PROJECTION_ADMISSION_RECEIPT_PREFIX, PROJECTION_RECEIPT_PREFIX, sign_with_domain,
    verify_with_domain,
};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Maximum length for string fields to prevent denial-of-service attacks.
pub const MAX_STRING_LENGTH: usize = 1024;

/// Maximum length for `boundary_id` fields (matches economics module).
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

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

    /// A required temporal field is missing or zero.
    #[error("temporal field validation failed: {0}")]
    TemporalFieldInvalid(&'static str),
}

// =============================================================================
// Bounded Serde Deserialization
// =============================================================================

/// Deserializes a string with a bounded length, rejecting oversized values
/// before allocation to prevent denial-of-service.
fn deserialize_bounded_string<'de, D>(
    deserializer: D,
    max_len: usize,
    field_name: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStringVisitor {
        max_len: usize,
        field_name: &'static str,
    }

    impl Visitor<'_> for BoundedStringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a string of at most {} bytes for field '{}'",
                self.max_len, self.field_name
            )
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > self.max_len {
                Err(E::custom(format!(
                    "string field '{}' exceeds maximum length ({} > {})",
                    self.field_name,
                    value.len(),
                    self.max_len
                )))
            } else {
                Ok(value.to_owned())
            }
        }
    }

    deserializer.deserialize_str(BoundedStringVisitor {
        max_len,
        field_name,
    })
}

/// Bounded deserializer for `boundary_id` fields.
fn deser_boundary_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_BOUNDARY_ID_LENGTH, "boundary_id")
}

/// Bounded deserializer for `receipt_id` fields.
fn deser_receipt_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_STRING_LENGTH, "receipt_id")
}

/// Bounded deserializer for `work_id` fields.
fn deser_work_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_STRING_LENGTH, "work_id")
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
// ProjectionReceipt (Legacy, backwards-compatible)
// =============================================================================

/// A cryptographically signed receipt proving a status was projected.
///
/// This receipt is generated after successfully projecting a status to an
/// external system (e.g., GitHub commit status). It provides cryptographic
/// proof of the projection.
///
/// # Backwards Compatibility
///
/// Optional temporal fields (`boundary_id`, `time_authority_ref`, `window_ref`,
/// `eval_tick`) are not present in legacy payloads. Deserialization of old
/// receipts succeeds with `None` for these fields. The `deny_unknown_fields`
/// attribute is intentionally omitted to allow forwards compatibility with
/// payloads that include temporal fields.
///
/// # Fields
///
/// - `receipt_id`: Unique identifier for this receipt
/// - `work_id`: Work item that was projected
/// - `changeset_digest`: Hash binding to specific changeset
/// - `ledger_head`: Ledger head hash at time of projection
/// - `projected_status`: The status that was projected
/// - `projected_at`: Unix timestamp (nanoseconds) when projection occurred
/// - `adapter_signature`: Ed25519 signature with domain separation
/// - `boundary_id`: (Optional) Temporal boundary identifier
/// - `time_authority_ref`: (Optional) Time authority reference hash
/// - `window_ref`: (Optional) HTF evaluation window reference hash
/// - `eval_tick`: (Optional) Evaluation tick for temporal binding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Temporal boundary identifier (absent in legacy receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_id: Option<String>,

    /// Time authority reference hash (absent in legacy receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_authority_ref: Option<Hash>,

    /// HTF evaluation window reference hash (absent in legacy receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_ref: Option<Hash>,

    /// Evaluation tick for temporal binding (absent in legacy receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_tick: Option<u64>,
}

impl ProjectionReceipt {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// The canonical representation includes all fields except the signature
    /// and the optional temporal fields (which are NOT part of the legacy
    /// signing domain), encoded in a deterministic order.
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
    /// Uses the legacy `PROJECTION_RECEIPT:` domain. This MUST NOT be treated
    /// as proof of temporal binding -- for that, use
    /// [`ProjectionAdmissionReceipt::validate_signature`].
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

        // Create receipt with placeholder signature (no temporal fields for legacy)
        let mut receipt = ProjectionReceipt {
            receipt_id: self.receipt_id,
            work_id: self.work_id,
            changeset_digest,
            ledger_head,
            projected_status,
            projected_at,
            adapter_signature: [0u8; 64],
            boundary_id: None,
            time_authority_ref: None,
            window_ref: None,
            eval_tick: None,
        };

        // Sign the canonical bytes
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, PROJECTION_RECEIPT_PREFIX, &canonical);
        receipt.adapter_signature = signature.to_bytes();

        Ok(receipt)
    }
}

// =============================================================================
// ProjectionAdmissionReceipt (temporal-bound, economics-compatible)
// =============================================================================

/// Input assembly for constructing a [`DeferredReplayReceiptV1`] from a
/// [`ProjectionAdmissionReceipt`].
///
/// This type captures all fields needed to call
/// [`DeferredReplayReceiptV1::create_signed`] without loss. It acts as a
/// bridge between the daemon projection layer and the economics module.
///
/// [`DeferredReplayReceiptV1`]: apm2_core::economics::DeferredReplayReceiptV1
/// [`DeferredReplayReceiptV1::create_signed`]: apm2_core::economics::DeferredReplayReceiptV1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredReplayReceiptInput {
    /// Receipt identifier (maps to `DeferredReplayReceiptV1::receipt_id`).
    pub receipt_id: String,
    /// Boundary identifier (maps to `DeferredReplayReceiptV1::boundary_id`).
    pub boundary_id: String,
    /// Backlog digest: `changeset_digest` from the projection receipt serves as
    /// the content-addressed binding for backlog state.
    pub backlog_digest: Hash,
    /// Time authority reference hash.
    pub time_authority_ref: Hash,
    /// HTF evaluation window reference hash.
    pub window_ref: Hash,
    /// Evaluation tick (maps to `replay_horizon_tick`).
    pub eval_tick: u64,
}

/// A cryptographically signed projection receipt with required temporal
/// binding fields for economics gate compatibility.
///
/// Unlike [`ProjectionReceipt`], this type requires all temporal fields
/// (`boundary_id`, `time_authority_ref`, `window_ref`, `eval_tick`) and uses a
/// distinct signing domain (`PROJECTION_ADMISSION_RECEIPT:`) to prevent
/// cross-type signature confusion with legacy receipts.
///
/// # Security Model
///
/// - Uses `PROJECTION_ADMISSION_RECEIPT:` domain prefix (distinct from legacy)
/// - A legacy `PROJECTION_RECEIPT:` signature MUST NOT verify under this domain
/// - All fields including temporal references are signed
/// - Bounded deserialization rejects oversized `boundary_id` before allocation
///
/// # Economics Bridge
///
/// Use [`ProjectionAdmissionReceipt::to_deferred_replay_input`] to extract
/// the fields needed for [`DeferredReplayReceiptV1::create_signed`].
///
/// [`DeferredReplayReceiptV1::create_signed`]: apm2_core::economics::DeferredReplayReceiptV1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionAdmissionReceipt {
    /// Unique identifier for this receipt.
    #[serde(deserialize_with = "deser_receipt_id")]
    pub receipt_id: String,

    /// Work item ID that was projected.
    #[serde(deserialize_with = "deser_work_id")]
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

    /// Temporal boundary identifier (required for economics gate).
    #[serde(deserialize_with = "deser_boundary_id")]
    pub boundary_id: String,

    /// Time authority reference hash (required for HTF binding).
    #[serde(with = "serde_bytes")]
    pub time_authority_ref: [u8; 32],

    /// HTF evaluation window reference hash.
    #[serde(with = "serde_bytes")]
    pub window_ref: [u8; 32],

    /// Evaluation tick for temporal binding.
    pub eval_tick: u64,

    /// Ed25519 signature over canonical bytes with
    /// `PROJECTION_ADMISSION_RECEIPT:` domain separation.
    #[serde(with = "serde_bytes")]
    pub adapter_signature: [u8; 64],
}

impl ProjectionAdmissionReceipt {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// Includes ALL fields (base + temporal) except the signature.
    /// Uses length-prefixed encoding for variable-length strings.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 4 + self.receipt_id.len()
            + 4 + self.work_id.len()
            + 32  // changeset_digest
            + 32  // ledger_head
            + 4 + 16  // projected_status (length-prefixed, max 9 bytes)
            + 8   // projected_at
            + 4 + self.boundary_id.len() // boundary_id (length-prefixed)
            + 32  // time_authority_ref
            + 32  // window_ref
            + 8; // eval_tick

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

        // 7. boundary_id (length-prefixed)
        bytes.extend_from_slice(&(self.boundary_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.boundary_id.as_bytes());

        // 8. time_authority_ref
        bytes.extend_from_slice(&self.time_authority_ref);

        // 9. window_ref
        bytes.extend_from_slice(&self.window_ref);

        // 10. eval_tick (big-endian)
        bytes.extend_from_slice(&self.eval_tick.to_be_bytes());

        bytes
    }

    /// Validates the receipt signature using the
    /// `PROJECTION_ADMISSION_RECEIPT:` domain.
    ///
    /// This domain is distinct from the legacy `PROJECTION_RECEIPT:` domain.
    /// A legacy receipt signature will NOT verify under this domain, preventing
    /// cross-type signature confusion.
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
            PROJECTION_ADMISSION_RECEIPT_PREFIX,
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

    /// Extracts the fields needed for
    /// [`DeferredReplayReceiptV1::create_signed`]
    /// as a [`DeferredReplayReceiptInput`].
    ///
    /// This conversion is lossless for all required `DeferredReplayReceiptV1`
    /// fields:
    /// - `receipt_id` -> `receipt_id`
    /// - `boundary_id` -> `boundary_id`
    /// - `changeset_digest` -> `backlog_digest`
    /// - `time_authority_ref` -> `time_authority_ref`
    /// - `window_ref` -> `window_ref`
    /// - `eval_tick` -> `eval_tick` (maps to `replay_horizon_tick`)
    ///
    /// [`DeferredReplayReceiptV1::create_signed`]: apm2_core::economics::DeferredReplayReceiptV1
    #[must_use]
    pub fn to_deferred_replay_input(&self) -> DeferredReplayReceiptInput {
        DeferredReplayReceiptInput {
            receipt_id: self.receipt_id.clone(),
            boundary_id: self.boundary_id.clone(),
            backlog_digest: self.changeset_digest,
            time_authority_ref: self.time_authority_ref,
            window_ref: self.window_ref,
            eval_tick: self.eval_tick,
        }
    }
}

impl From<&ProjectionAdmissionReceipt> for DeferredReplayReceiptInput {
    fn from(receipt: &ProjectionAdmissionReceipt) -> Self {
        receipt.to_deferred_replay_input()
    }
}

// =============================================================================
// ProjectionAdmissionReceiptBuilder
// =============================================================================

/// Builder for constructing [`ProjectionAdmissionReceipt`] instances.
#[derive(Debug)]
pub struct ProjectionAdmissionReceiptBuilder {
    receipt_id: String,
    work_id: String,
    changeset_digest: Option<[u8; 32]>,
    ledger_head: Option<[u8; 32]>,
    projected_status: Option<ProjectedStatus>,
    projected_at: Option<u64>,
    boundary_id: Option<String>,
    time_authority_ref: Option<[u8; 32]>,
    window_ref: Option<[u8; 32]>,
    eval_tick: Option<u64>,
}

impl ProjectionAdmissionReceiptBuilder {
    /// Creates a new builder with required IDs.
    #[must_use]
    pub fn new(receipt_id: impl Into<String>, work_id: impl Into<String>) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            work_id: work_id.into(),
            changeset_digest: None,
            ledger_head: None,
            projected_status: None,
            projected_at: None,
            boundary_id: None,
            time_authority_ref: None,
            window_ref: None,
            eval_tick: None,
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

    /// Sets the temporal boundary identifier.
    #[must_use]
    pub fn boundary_id(mut self, id: impl Into<String>) -> Self {
        self.boundary_id = Some(id.into());
        self
    }

    /// Sets the time authority reference hash.
    #[must_use]
    pub const fn time_authority_ref(mut self, hash: [u8; 32]) -> Self {
        self.time_authority_ref = Some(hash);
        self
    }

    /// Sets the HTF evaluation window reference hash.
    #[must_use]
    pub const fn window_ref(mut self, hash: [u8; 32]) -> Self {
        self.window_ref = Some(hash);
        self
    }

    /// Sets the evaluation tick.
    #[must_use]
    pub const fn eval_tick(mut self, tick: u64) -> Self {
        self.eval_tick = Some(tick);
        self
    }

    /// Attempts to build and sign the admission receipt.
    ///
    /// All fields including temporal references are required. The receipt is
    /// signed with the `PROJECTION_ADMISSION_RECEIPT:` domain prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionReceiptError`] if any field is missing, exceeds
    /// bounds, or contains invalid data (e.g., zero hashes).
    #[allow(clippy::cast_possible_truncation)]
    pub fn try_build_and_sign(
        self,
        signer: &Signer,
    ) -> Result<ProjectionAdmissionReceipt, ProjectionReceiptError> {
        // Validate required base fields
        let changeset_digest = self
            .changeset_digest
            .ok_or(ProjectionReceiptError::MissingField("changeset_digest"))?;
        let ledger_head = self
            .ledger_head
            .ok_or(ProjectionReceiptError::MissingField("ledger_head"))?;
        let projected_status = self
            .projected_status
            .ok_or(ProjectionReceiptError::MissingField("projected_status"))?;
        let projected_at = self
            .projected_at
            .ok_or(ProjectionReceiptError::MissingField("projected_at"))?;

        // Validate required temporal fields
        let boundary_id = self
            .boundary_id
            .ok_or(ProjectionReceiptError::MissingField("boundary_id"))?;
        let time_authority_ref = self
            .time_authority_ref
            .ok_or(ProjectionReceiptError::MissingField("time_authority_ref"))?;
        let window_ref = self
            .window_ref
            .ok_or(ProjectionReceiptError::MissingField("window_ref"))?;
        let eval_tick = self
            .eval_tick
            .ok_or(ProjectionReceiptError::MissingField("eval_tick"))?;

        // Validate string lengths (bounded deserialization at construction)
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
        if boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
            return Err(ProjectionReceiptError::StringTooLong {
                field: "boundary_id",
                actual: boundary_id.len(),
                max: MAX_BOUNDARY_ID_LENGTH,
            });
        }

        // Fail-closed: reject empty boundary_id
        if boundary_id.is_empty() {
            return Err(ProjectionReceiptError::TemporalFieldInvalid(
                "boundary_id must not be empty",
            ));
        }

        // Fail-closed: reject zero hashes for temporal references
        if time_authority_ref == [0u8; 32] {
            return Err(ProjectionReceiptError::TemporalFieldInvalid(
                "time_authority_ref must not be zero",
            ));
        }
        if window_ref == [0u8; 32] {
            return Err(ProjectionReceiptError::TemporalFieldInvalid(
                "window_ref must not be zero",
            ));
        }

        // Create receipt with placeholder signature
        let mut receipt = ProjectionAdmissionReceipt {
            receipt_id: self.receipt_id,
            work_id: self.work_id,
            changeset_digest,
            ledger_head,
            projected_status,
            projected_at,
            boundary_id,
            time_authority_ref,
            window_ref,
            eval_tick,
            adapter_signature: [0u8; 64],
        };

        // Sign with PROJECTION_ADMISSION_RECEIPT: domain
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, PROJECTION_ADMISSION_RECEIPT_PREFIX, &canonical);
        receipt.adapter_signature = signature.to_bytes();

        Ok(receipt)
    }

    /// Builds the receipt and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing.
    #[must_use]
    pub fn build_and_sign(self, signer: &Signer) -> ProjectionAdmissionReceipt {
        self.try_build_and_sign(signer)
            .expect("missing required field for admission receipt")
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

    fn create_test_admission_receipt(signer: &Signer) -> ProjectionAdmissionReceipt {
        ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("boundary-alpha")
            .time_authority_ref([0xCC; 32])
            .window_ref([0xBB; 32])
            .eval_tick(42)
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
        // Legacy receipt has no temporal fields
        assert!(receipt.boundary_id.is_none());
        assert!(receipt.time_authority_ref.is_none());
        assert!(receipt.window_ref.is_none());
        assert!(receipt.eval_tick.is_none());
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
    // Legacy Signature Tests
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
    // Legacy Serialization / Backwards Compatibility Tests
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

    #[test]
    fn test_old_receipt_deserialization_backwards_compat() {
        // Simulate an old serialized payload that has NO temporal fields.
        // This must deserialize successfully with None for temporal fields.
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);
        let json = serde_json::to_string(&receipt).unwrap();

        // Verify no temporal fields are in the JSON (skip_serializing_if = None)
        assert!(!json.contains("boundary_id"));
        assert!(!json.contains("time_authority_ref"));
        assert!(!json.contains("window_ref"));
        assert!(!json.contains("eval_tick"));

        // Deserialize: should succeed
        let recovered: ProjectionReceipt = serde_json::from_str(&json).unwrap();
        assert!(recovered.boundary_id.is_none());
        assert!(recovered.time_authority_ref.is_none());
        assert!(recovered.window_ref.is_none());
        assert!(recovered.eval_tick.is_none());

        // Signature should still be valid via legacy domain
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_receipt_with_temporal_fields_roundtrip() {
        // A ProjectionReceipt that carries optional temporal fields should
        // round-trip through serde correctly.
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.boundary_id = Some("boundary-001".to_string());
        receipt.time_authority_ref = Some([0xCC; 32]);
        receipt.window_ref = Some([0xDD; 32]);
        receipt.eval_tick = Some(100);

        let json = serde_json::to_string(&receipt).unwrap();
        let recovered: ProjectionReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(recovered.boundary_id.as_deref(), Some("boundary-001"));
        assert_eq!(recovered.time_authority_ref, Some([0xCC; 32]));
        assert_eq!(recovered.window_ref, Some([0xDD; 32]));
        assert_eq!(recovered.eval_tick, Some(100));

        // Legacy signature is still valid (temporal fields not in legacy canonical
        // bytes)
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    // =========================================================================
    // ProjectionAdmissionReceipt Tests
    // =========================================================================

    #[test]
    fn test_admission_receipt_build_and_sign() {
        let signer = Signer::generate();
        let receipt = create_test_admission_receipt(&signer);

        assert_eq!(receipt.receipt_id, "admit-001");
        assert_eq!(receipt.work_id, "work-001");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.ledger_head, [0xAB; 32]);
        assert_eq!(receipt.projected_status, ProjectedStatus::Success);
        assert_eq!(receipt.projected_at, 1_704_067_200_000_000_000);
        assert_eq!(receipt.boundary_id, "boundary-alpha");
        assert_eq!(receipt.time_authority_ref, [0xCC; 32]);
        assert_eq!(receipt.window_ref, [0xBB; 32]);
        assert_eq!(receipt.eval_tick, 42);
        // Signature is non-zero (was signed)
        assert_ne!(receipt.adapter_signature, [0u8; 64]);
    }

    #[test]
    fn test_admission_receipt_signature_validation() {
        let signer = Signer::generate();
        let receipt = create_test_admission_receipt(&signer);

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
    fn test_admission_receipt_signature_binds_to_temporal_fields() {
        let signer = Signer::generate();
        let mut receipt = create_test_admission_receipt(&signer);

        // Tamper with boundary_id
        receipt.boundary_id = "tampered-boundary".to_string();
        assert!(receipt.validate_signature(&signer.verifying_key()).is_err());

        // Tamper with time_authority_ref
        let mut receipt = create_test_admission_receipt(&signer);
        receipt.time_authority_ref = [0xFF; 32];
        assert!(receipt.validate_signature(&signer.verifying_key()).is_err());

        // Tamper with window_ref
        let mut receipt = create_test_admission_receipt(&signer);
        receipt.window_ref = [0xFF; 32];
        assert!(receipt.validate_signature(&signer.verifying_key()).is_err());

        // Tamper with eval_tick
        let mut receipt = create_test_admission_receipt(&signer);
        receipt.eval_tick = 999;
        assert!(receipt.validate_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_cross_domain_signature_rejection() {
        // Sign with legacy domain, verify with admission domain => MUST fail.
        // This prevents accepting a legacy receipt as proof of temporal binding.
        let signer = Signer::generate();
        let legacy = create_test_receipt(&signer);

        // Construct an admission receipt with the same base fields but using
        // the legacy signature.
        let forged = ProjectionAdmissionReceipt {
            receipt_id: legacy.receipt_id.clone(),
            work_id: legacy.work_id.clone(),
            changeset_digest: legacy.changeset_digest,
            ledger_head: legacy.ledger_head,
            projected_status: legacy.projected_status,
            projected_at: legacy.projected_at,
            boundary_id: "forged-boundary".to_string(),
            time_authority_ref: [0xAA; 32],
            window_ref: [0xBB; 32],
            eval_tick: 1,
            adapter_signature: legacy.adapter_signature, // Legacy domain!
        };

        // Admission domain verification MUST fail
        assert!(forged.validate_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_admission_domain_does_not_verify_as_legacy() {
        // Sign with admission domain, verify with legacy domain => MUST fail.
        let signer = Signer::generate();
        let admission = create_test_admission_receipt(&signer);

        // Construct a legacy receipt with the admission signature
        let forged = ProjectionReceipt {
            receipt_id: admission.receipt_id.clone(),
            work_id: admission.work_id.clone(),
            changeset_digest: admission.changeset_digest,
            ledger_head: admission.ledger_head,
            projected_status: admission.projected_status,
            projected_at: admission.projected_at,
            adapter_signature: admission.adapter_signature, // Admission domain!
            boundary_id: None,
            time_authority_ref: None,
            window_ref: None,
            eval_tick: None,
        };

        // Legacy domain verification MUST fail
        assert!(forged.validate_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_admission_receipt_serde_roundtrip() {
        let signer = Signer::generate();
        let original = create_test_admission_receipt(&signer);

        let json = serde_json::to_string(&original).unwrap();
        let recovered: ProjectionAdmissionReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(original.receipt_id, recovered.receipt_id);
        assert_eq!(original.work_id, recovered.work_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(original.ledger_head, recovered.ledger_head);
        assert_eq!(original.projected_status, recovered.projected_status);
        assert_eq!(original.projected_at, recovered.projected_at);
        assert_eq!(original.boundary_id, recovered.boundary_id);
        assert_eq!(original.time_authority_ref, recovered.time_authority_ref);
        assert_eq!(original.window_ref, recovered.window_ref);
        assert_eq!(original.eval_tick, recovered.eval_tick);
        assert_eq!(original.adapter_signature, recovered.adapter_signature);

        // Signature should still be valid after round-trip
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_admission_receipt_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let r1 = create_test_admission_receipt(&signer);
        let r2 = create_test_admission_receipt(&signer);

        assert_eq!(r1.canonical_bytes(), r2.canonical_bytes());
        // Ed25519 is deterministic
        assert_eq!(r1.adapter_signature, r2.adapter_signature);
    }

    #[test]
    fn test_admission_receipt_canonical_bytes_includes_temporal() {
        let signer = Signer::generate();
        let receipt = create_test_admission_receipt(&signer);
        let bytes = receipt.canonical_bytes();

        // The canonical bytes should be longer than legacy due to temporal fields.
        // Legacy: receipt_id(4+9) + work_id(4+8) + changeset(32) + ledger(32)
        //       + status(4+7) + projected_at(8) = ~108
        // Admission adds: boundary_id(4+14) + time_auth_ref(32) + window_ref(32) +
        // eval_tick(8) = ~90
        assert!(
            bytes.len() > 100,
            "Canonical bytes should include temporal fields, got len={}",
            bytes.len()
        );

        // Verify boundary_id is embedded (search for its length prefix)
        let bid = "boundary-alpha";
        #[allow(clippy::cast_possible_truncation)]
        let bid_len = (bid.len() as u32).to_be_bytes();
        let found = bytes
            .windows(4 + bid.len())
            .any(|w| w[..4] == bid_len && &w[4..] == bid.as_bytes());
        assert!(found, "boundary_id must be present in canonical bytes");

        // Verify eval_tick is embedded (big-endian 42u64)
        let tick_bytes = 42u64.to_be_bytes();
        let found = bytes.windows(8).any(|w| w == tick_bytes);
        assert!(found, "eval_tick must be present in canonical bytes");
    }

    // =========================================================================
    // Admission Receipt Builder Validation Tests
    // =========================================================================

    #[test]
    fn test_admission_missing_boundary_id() {
        let signer = Signer::generate();
        let result = ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            // no boundary_id
            .time_authority_ref([0xAA; 32])
            .window_ref([0xBB; 32])
            .eval_tick(1)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::MissingField("boundary_id"))
        ));
    }

    #[test]
    fn test_admission_missing_time_authority_ref() {
        let signer = Signer::generate();
        let result = ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("b")
            // no time_authority_ref
            .window_ref([0xBB; 32])
            .eval_tick(1)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::MissingField("time_authority_ref"))
        ));
    }

    #[test]
    fn test_admission_missing_window_ref() {
        let signer = Signer::generate();
        let result = ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("b")
            .time_authority_ref([0xAA; 32])
            // no window_ref
            .eval_tick(1)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::MissingField("window_ref"))
        ));
    }

    #[test]
    fn test_admission_missing_eval_tick() {
        let signer = Signer::generate();
        let result = ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("b")
            .time_authority_ref([0xAA; 32])
            .window_ref([0xBB; 32])
            // no eval_tick
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::MissingField("eval_tick"))
        ));
    }

    #[test]
    fn test_admission_zero_time_authority_ref_rejected() {
        let signer = Signer::generate();
        let result = ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("b")
            .time_authority_ref([0u8; 32]) // zero!
            .window_ref([0xBB; 32])
            .eval_tick(1)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::TemporalFieldInvalid(_))
        ));
    }

    #[test]
    fn test_admission_zero_window_ref_rejected() {
        let signer = Signer::generate();
        let result = ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("b")
            .time_authority_ref([0xAA; 32])
            .window_ref([0u8; 32]) // zero!
            .eval_tick(1)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::TemporalFieldInvalid(_))
        ));
    }

    #[test]
    fn test_admission_empty_boundary_id_rejected() {
        let signer = Signer::generate();
        let result = ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("") // empty!
            .time_authority_ref([0xAA; 32])
            .window_ref([0xBB; 32])
            .eval_tick(1)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::TemporalFieldInvalid(
                "boundary_id must not be empty"
            ))
        ));
    }

    #[test]
    fn test_admission_oversized_boundary_id_rejected() {
        let signer = Signer::generate();
        let long_boundary = "x".repeat(MAX_BOUNDARY_ID_LENGTH + 1);

        let result = ProjectionAdmissionReceiptBuilder::new("admit-001", "work-001")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id(long_boundary)
            .time_authority_ref([0xAA; 32])
            .window_ref([0xBB; 32])
            .eval_tick(1)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ProjectionReceiptError::StringTooLong {
                field: "boundary_id",
                ..
            })
        ));
    }

    #[test]
    fn test_admission_bounded_deser_rejects_oversized_boundary_id() {
        // Craft JSON with oversized boundary_id -- bounded deserialization
        // must reject BEFORE allocation.
        let oversized_boundary = "x".repeat(MAX_BOUNDARY_ID_LENGTH + 1);
        let json = format!(
            r#"{{
                "receipt_id":"r1",
                "work_id":"w1",
                "changeset_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "ledger_head":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "projected_status":"Success",
                "projected_at":1,
                "boundary_id":"{oversized_boundary}",
                "time_authority_ref":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "window_ref":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "eval_tick":10,
                "adapter_signature":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            }}"#
        );

        let result: Result<ProjectionAdmissionReceipt, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "Oversized boundary_id must be rejected during deserialization"
        );
    }

    #[test]
    fn test_admission_bounded_deser_rejects_oversized_receipt_id() {
        let oversized = "x".repeat(MAX_STRING_LENGTH + 1);
        let json = format!(
            r#"{{
                "receipt_id":"{oversized}",
                "work_id":"w1",
                "changeset_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "ledger_head":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                "projected_status":"Success",
                "projected_at":1,
                "boundary_id":"b",
                "time_authority_ref":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "window_ref":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "eval_tick":10,
                "adapter_signature":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            }}"#
        );

        let result: Result<ProjectionAdmissionReceipt, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "Oversized receipt_id must be rejected during deserialization"
        );
    }

    // =========================================================================
    // DeferredReplayReceiptInput Conversion Tests
    // =========================================================================

    #[test]
    fn test_deferred_replay_input_conversion() {
        let signer = Signer::generate();
        let receipt = create_test_admission_receipt(&signer);
        let input = receipt.to_deferred_replay_input();

        assert_eq!(input.receipt_id, "admit-001");
        assert_eq!(input.boundary_id, "boundary-alpha");
        assert_eq!(input.backlog_digest, [0x42; 32]); // changeset_digest
        assert_eq!(input.time_authority_ref, [0xCC; 32]);
        assert_eq!(input.window_ref, [0xBB; 32]);
        assert_eq!(input.eval_tick, 42);
    }

    #[test]
    fn test_deferred_replay_input_from_ref() {
        let signer = Signer::generate();
        let receipt = create_test_admission_receipt(&signer);
        let input: DeferredReplayReceiptInput = (&receipt).into();

        assert_eq!(input.receipt_id, receipt.receipt_id);
        assert_eq!(input.boundary_id, receipt.boundary_id);
        assert_eq!(input.backlog_digest, receipt.changeset_digest);
        assert_eq!(input.time_authority_ref, receipt.time_authority_ref);
        assert_eq!(input.window_ref, receipt.window_ref);
        assert_eq!(input.eval_tick, receipt.eval_tick);
    }

    #[test]
    fn test_deferred_replay_input_conversion_is_lossless() {
        // Verify that all required DeferredReplayReceiptV1 fields are present
        // in the DeferredReplayReceiptInput.
        let signer = Signer::generate();
        let receipt = create_test_admission_receipt(&signer);
        let input = receipt.to_deferred_replay_input();

        // receipt_id is non-empty
        assert!(!input.receipt_id.is_empty(), "receipt_id must not be empty");
        // boundary_id is non-empty
        assert!(
            !input.boundary_id.is_empty(),
            "boundary_id must not be empty"
        );
        // backlog_digest is non-zero
        assert_ne!(
            input.backlog_digest, [0u8; 32],
            "backlog_digest must not be zero"
        );
        // time_authority_ref is non-zero
        assert_ne!(
            input.time_authority_ref, [0u8; 32],
            "time_authority_ref must not be zero"
        );
        // window_ref is non-zero
        assert_ne!(input.window_ref, [0u8; 32], "window_ref must not be zero");
        // eval_tick is present (u64, any value is valid)
        let _ = input.eval_tick;
    }

    // =========================================================================
    // Admission Receipt Idempotency Key Tests
    // =========================================================================

    #[test]
    fn test_admission_idempotency_key() {
        let signer = Signer::generate();
        let receipt = create_test_admission_receipt(&signer);
        let key = receipt.idempotency_key();

        assert_eq!(key.work_id, "work-001");
        assert_eq!(key.changeset_digest, [0x42; 32]);
        assert_eq!(key.ledger_head, [0xAB; 32]);
    }

    // =========================================================================
    // Admission receipt length-prefix collision prevention
    // =========================================================================

    #[test]
    fn test_admission_length_prefix_collision_prevention() {
        let signer = Signer::generate();

        let r1 = ProjectionAdmissionReceiptBuilder::new("ab", "cd")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("ef")
            .time_authority_ref([0xAA; 32])
            .window_ref([0xBB; 32])
            .eval_tick(1)
            .build_and_sign(&signer);

        let r2 = ProjectionAdmissionReceiptBuilder::new("a", "bcd")
            .changeset_digest([0x42; 32])
            .ledger_head([0xAB; 32])
            .projected_status(ProjectedStatus::Success)
            .projected_at(1_704_067_200_000_000_000)
            .boundary_id("ef")
            .time_authority_ref([0xAA; 32])
            .window_ref([0xBB; 32])
            .eval_tick(1)
            .build_and_sign(&signer);

        // Length-prefixed encoding prevents collision
        assert_ne!(r1.canonical_bytes(), r2.canonical_bytes());
    }
}
