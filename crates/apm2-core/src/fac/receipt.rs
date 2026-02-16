// AGENT-AUTHORED
//! Gate receipt types for the Forge Admission Cycle.
//!
//! This module defines [`GateReceipt`] which is a versioned envelope for gate
//! execution results. The receipt cryptographically binds a gate's output to a
//! specific lease and changeset.
//!
//! # Versioning Model
//!
//! `GateReceipt` implements a two-level versioning scheme:
//!
//! - **Envelope version** (`receipt_version`): Schema of the receipt envelope
//!   itself. Changes here affect all gate types.
//! - **Payload version** (`payload_schema_version`): Schema of the payload
//!   content. Each payload kind can evolve independently.
//!
//! # Supported Versions
//!
//! - Receipt versions: `[1]` (see [`SUPPORTED_RECEIPT_VERSIONS`])
//! - Payload kinds: `["aat", "quality", "security"]` (see
//!   [`SUPPORTED_PAYLOAD_KINDS`])
//! - Payload schema versions: `[1]` (see [`SUPPORTED_PAYLOAD_SCHEMA_VERSIONS`])
//!
//! # Validation Modes
//!
//! The [`GateReceipt::validate_version`] method supports two modes:
//!
//! - **Enforce mode** (`enforce: true`): Unknown versions are rejected with an
//!   error. Use this for processing receipts that must be fully validated.
//! - **Permissive mode** (`enforce: false`): Unknown versions return `Ok(())`
//!   silently. Use this for logging or archival.
//!
//! # Security Model
//!
//! - Signatures use the `GATE_RECEIPT:` domain prefix
//! - All fields except the signature are included in canonical bytes
//! - Length-prefixed encoding prevents canonicalization collision attacks
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{GateReceipt, GateReceiptBuilder};
//!
//! // Create a gate receipt
//! let signer = Signer::generate();
//! let receipt = GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
//!     .changeset_digest([0x42; 32])
//!     .executor_actor_id("executor-001")
//!     .receipt_version(1)
//!     .payload_kind("aat")
//!     .payload_schema_version(1)
//!     .payload_hash([0xAB; 32])
//!     .evidence_bundle_hash([0xCD; 32])
//!     .passed(true)
//!     .build_and_sign(&signer);
//!
//! // Validate version in enforce mode
//! assert!(receipt.validate_version(true).is_ok());
//!
//! // Verify signature
//! assert!(receipt.validate_signature(&signer.verifying_key()).is_ok());
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{GATE_RECEIPT_PREFIX, sign_with_domain, verify_with_domain};
use super::job_spec::parse_b3_256_digest;
use super::policy_resolution::MAX_STRING_LENGTH;
use crate::crypto::{Signature, VerifyingKey};
// Re-export the generated proto type for wire format serialization.
pub use crate::events::GateReceipt as GateReceiptProto;

/// Schema identifier for `FacJobReceiptV1`.
pub const FAC_JOB_RECEIPT_SCHEMA: &str = "apm2.fac.job_receipt.v1";

/// Maximum human-reason length for `FacJobReceiptV1`.
const MAX_FAC_JOB_REASON_LENGTH: usize = 512;

/// Maximum serialized size of a `FacJobReceiptV1` (bytes).
/// Protects against memory-exhaustion attacks during bounded deserialization.
pub const MAX_JOB_RECEIPT_SIZE: usize = 65_536;

/// Schema identifier for `LaneCleanupReceiptV1`.
pub const LANE_CLEANUP_RECEIPT_SCHEMA: &str = "apm2.fac.lane_cleanup_receipt.v1";

/// Maximum serialized size of a `LaneCleanupReceiptV1` (bytes).
/// Protects against memory-exhaustion attacks during bounded persistence.
pub const MAX_LANE_CLEANUP_RECEIPT_SIZE: usize = 65_536;

/// Schema identifier for `LaneCleanupReceiptV1`.
pub const FAC_LANE_CLEANUP_RECEIPT_SCHEMA: &str = LANE_CLEANUP_RECEIPT_SCHEMA;

/// Maximum cleanup reason length for `LaneCleanupReceiptV1`.
const MAX_CLEANUP_REASON_LENGTH: usize = MAX_STRING_LENGTH;

/// Maximum number of cleanup steps retained in a lane cleanup receipt.
const MAX_CLEANUP_STEPS: usize = 16;

/// Maximum RFC-0028 boundary defect classes included in a receipt trace.
const MAX_FAC_JOB_BOUNDARY_DEFECT_CLASSES: usize = 32;

// =============================================================================
// Version Constants
// =============================================================================

/// Supported receipt envelope versions.
///
/// Currently only version 1 is supported. New versions may be added as the
/// envelope schema evolves.
pub const SUPPORTED_RECEIPT_VERSIONS: &[u32] = &[1];

/// Supported payload kinds.
///
/// - `"aat"`: Agent Acceptance Testing payload
/// - `"quality"`: Quality gate payload (linting, tests, etc.)
/// - `"security"`: Security gate payload (vulnerability scans, etc.)
pub const SUPPORTED_PAYLOAD_KINDS: &[&str] = &["aat", "quality", "security"];

/// Supported payload schema versions.
///
/// Currently only version 1 is supported for all payload kinds. New versions
/// may be added as payload schemas evolve.
pub const SUPPORTED_PAYLOAD_SCHEMA_VERSIONS: &[u32] = &[1];

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during gate receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptError {
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

    /// Unsupported receipt version.
    #[error("unsupported receipt version: {version}, supported: {supported:?}")]
    UnsupportedVersion {
        /// The unsupported version.
        version: u32,
        /// List of supported versions.
        supported: Vec<u32>,
    },

    /// Unsupported payload kind.
    #[error("unsupported payload kind: {kind}, supported: {supported:?}")]
    UnsupportedPayloadKind {
        /// The unsupported payload kind.
        kind: String,
        /// List of supported payload kinds.
        supported: Vec<String>,
    },

    /// Unsupported payload schema version.
    #[error("unsupported payload schema version: {version}, supported: {supported:?}")]
    UnsupportedPayloadSchemaVersion {
        /// The unsupported payload schema version.
        version: u32,
        /// List of supported payload schema versions.
        supported: Vec<u32>,
    },
}

/// Errors that can occur during lane cleanup receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LaneCleanupReceiptError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Invalid cleanup receipt data.
    #[error("invalid receipt data: {0}")]
    InvalidData(String),

    /// Serialization error.
    #[error("serialization failed: {0}")]
    Serialization(String),

    /// I/O error during persistence.
    #[error("i/o error: {0}")]
    Io(String),
}

/// Canonical receipt for lane cleanup operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneCleanupReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Receipt identifier.
    pub receipt_id: String,
    /// Lane identifier.
    pub lane_id: String,
    /// Cleanup outcome.
    pub outcome: super::lane::LaneCleanupOutcome,
    /// Ordered cleanup steps completed before terminal status.
    #[serde(default)]
    pub steps_completed: Vec<String>,
    /// Human-readable failure reason if outcome is failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Unix epoch seconds for cleanup.
    pub timestamp_secs: u64,
    /// BLAKE3 digest of the canonicalized payload.
    pub content_hash: String,
}

impl LaneCleanupReceiptV1 {
    /// Returns canonical bytes for content hash computation.
    ///
    /// # Panics
    ///
    /// Panics if any canonical string component length exceeds `u32::MAX`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);

        bytes.extend_from_slice(
            &u32::try_from(self.schema.len())
                .expect("lane cleanup schema length fits into u32")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(self.schema.as_bytes());

        bytes.extend_from_slice(
            &u32::try_from(self.receipt_id.len())
                .expect("lane cleanup receipt_id length fits into u32")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(
            &u32::try_from(self.lane_id.len())
                .expect("lane cleanup lane_id length fits into u32")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(self.lane_id.as_bytes());

        let outcome_str = serde_json::to_string(&self.outcome)
            .expect("lane cleanup outcome serialization must not fail");
        bytes.extend_from_slice(
            &u32::try_from(outcome_str.len())
                .expect("lane cleanup outcome string length fits into u32")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(outcome_str.as_bytes());

        bytes.extend_from_slice(
            &u32::try_from(self.steps_completed.len())
                .expect("lane cleanup steps_completed length fits into u32")
                .to_be_bytes(),
        );
        for step in &self.steps_completed {
            bytes.extend_from_slice(
                &u32::try_from(step.len())
                    .expect("lane cleanup step string length fits into u32")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(step.as_bytes());
        }

        if let Some(reason) = &self.failure_reason {
            bytes.push(1u8);
            bytes.extend_from_slice(
                &u32::try_from(reason.len())
                    .expect("lane cleanup failure reason length fits into u32")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(reason.as_bytes());
        } else {
            bytes.push(0u8);
        }

        bytes.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.content_hash.len())
                .expect("lane cleanup content_hash length fits into u32")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(self.content_hash.as_bytes());

        bytes
    }

    /// Validate invariants and boundedness rules.
    ///
    /// # Errors
    ///
    /// Returns `LaneCleanupReceiptError` on missing fields, length violations,
    /// or malformed content.
    pub fn validate(&self) -> Result<(), LaneCleanupReceiptError> {
        if self.schema != LANE_CLEANUP_RECEIPT_SCHEMA {
            return Err(LaneCleanupReceiptError::InvalidData(format!(
                "schema mismatch: expected '{LANE_CLEANUP_RECEIPT_SCHEMA}', got '{}'",
                self.schema
            )));
        }
        if self.receipt_id.trim().is_empty() {
            return Err(LaneCleanupReceiptError::MissingField("receipt_id"));
        }
        if self.receipt_id.len() > MAX_STRING_LENGTH {
            return Err(LaneCleanupReceiptError::StringTooLong {
                field: "receipt_id",
                actual: self.receipt_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.lane_id.is_empty() {
            return Err(LaneCleanupReceiptError::MissingField("lane_id"));
        }
        if self.lane_id.len() > MAX_STRING_LENGTH {
            return Err(LaneCleanupReceiptError::StringTooLong {
                field: "lane_id",
                actual: self.lane_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if let Some(reason) = &self.failure_reason {
            if reason.len() > MAX_CLEANUP_REASON_LENGTH {
                return Err(LaneCleanupReceiptError::StringTooLong {
                    field: "failure_reason",
                    actual: reason.len(),
                    max: MAX_CLEANUP_REASON_LENGTH,
                });
            }
            if reason.is_empty() {
                return Err(LaneCleanupReceiptError::MissingField("failure_reason"));
            }
        } else if matches!(self.outcome, super::lane::LaneCleanupOutcome::Failed) {
            return Err(LaneCleanupReceiptError::MissingField("failure_reason"));
        }

        if self.steps_completed.len() > MAX_CLEANUP_STEPS {
            return Err(LaneCleanupReceiptError::StringTooLong {
                field: "steps_completed",
                actual: self.steps_completed.len(),
                max: MAX_CLEANUP_STEPS,
            });
        }

        for step in &self.steps_completed {
            if step.len() > MAX_STRING_LENGTH {
                return Err(LaneCleanupReceiptError::StringTooLong {
                    field: "steps_completed",
                    actual: step.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        if self.timestamp_secs == 0 {
            return Err(LaneCleanupReceiptError::InvalidData(
                "timestamp_secs must be non-zero".to_string(),
            ));
        }

        if !self.content_hash.is_empty() && !is_valid_b3_256_digest(&self.content_hash) {
            return Err(LaneCleanupReceiptError::InvalidData(
                "content_hash must be b3-256 format when set".to_string(),
            ));
        }

        Ok(())
    }

    fn compute_content_hash(&self) -> String {
        let mut clone = self.clone();
        clone.content_hash.clear();
        let canonical = clone.canonical_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.fac.lane_cleanup_receipt.v1\0");
        hasher.update(&canonical);
        format!("b3-256:{}", hasher.finalize().to_hex())
    }

    /// Persist a receipt into `receipts_dir`.
    ///
    /// Uses the atomic write protocol (CTR-2607): writes to a `NamedTempFile`
    /// with restrictive permissions (0o600 on Unix), calls `sync_all()` for
    /// durability, then atomically renames into `<content_hash>.json`.
    ///
    /// # Errors
    ///
    /// Returns `LaneCleanupReceiptError::Serialization`, `InvalidData`, or
    /// `Io` depending on failure mode.
    pub fn persist(
        &self,
        fac_receipts_dir: &Path,
        timestamp_secs: u64,
    ) -> Result<PathBuf, LaneCleanupReceiptError> {
        let mut copy = self.clone();
        copy.schema = LANE_CLEANUP_RECEIPT_SCHEMA.to_string();
        copy.timestamp_secs = timestamp_secs;
        copy.content_hash = copy.compute_content_hash();
        copy.validate()?;

        let bytes = serde_json::to_vec_pretty(&copy)
            .map_err(|e| LaneCleanupReceiptError::Serialization(e.to_string()))?;
        if bytes.len() > MAX_LANE_CLEANUP_RECEIPT_SIZE {
            return Err(LaneCleanupReceiptError::InvalidData(format!(
                "receipt too large: {} > {}",
                bytes.len(),
                MAX_LANE_CLEANUP_RECEIPT_SIZE
            )));
        }

        fs::create_dir_all(fac_receipts_dir)
            .map_err(|e| LaneCleanupReceiptError::Serialization(e.to_string()))?;

        let final_path = fac_receipts_dir.join(format!("{}.json", copy.content_hash));

        // Atomic write protocol: NamedTempFile + 0o600 + sync_all + rename
        // (matches LaneCorruptMarkerV1::persist via atomic_write in lane.rs)
        let temp = tempfile::NamedTempFile::new_in(fac_receipts_dir).map_err(|e| {
            LaneCleanupReceiptError::Io(format!(
                "creating temp file in {}: {e}",
                fac_receipts_dir.display()
            ))
        })?;

        // Set restrictive permissions before writing content (INV-LANE-CLEANUP-001).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(temp.path(), perms).map_err(|e| {
                LaneCleanupReceiptError::Io(format!(
                    "setting permissions on temp file {}: {e}",
                    temp.path().display()
                ))
            })?;
        }

        let mut file = temp.as_file();
        file.write_all(&bytes).map_err(|e| {
            LaneCleanupReceiptError::Io(format!(
                "writing temp file for {}: {e}",
                final_path.display()
            ))
        })?;
        file.sync_all().map_err(|e| {
            LaneCleanupReceiptError::Io(format!(
                "syncing temp file for {}: {e}",
                final_path.display()
            ))
        })?;

        temp.persist(&final_path).map_err(|e| {
            LaneCleanupReceiptError::Io(format!(
                "renaming temp file to {}: {}",
                final_path.display(),
                e.error
            ))
        })?;

        Ok(final_path)
    }
}

// =============================================================================
// FAC Job Receipt Types
// =============================================================================

/// Errors that can occur during `FacJobReceiptV1` operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FacJobReceiptError {
    /// Required field missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// The oversized field.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Invalid structured data.
    #[error("invalid receipt data: {0}")]
    InvalidData(String),

    /// Serialization/deserialization failure.
    #[error("receipt serialization failed: {0}")]
    Serialization(String),
}

/// Receipt outcome for a worker job.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FacJobOutcome {
    /// The job was completed successfully.
    #[default]
    Completed,
    /// The job was denied.
    Denied,
    /// The job was quarantined due to malformed input.
    Quarantined,
    /// The job was cancelled via `apm2 fac job cancel`.
    Cancelled,
    /// A cancellation has been requested (`stop_revoke` enqueued) but not yet
    /// confirmed by the worker.  This is a non-terminal status: the terminal
    /// `Cancelled` receipt is emitted only after the worker's
    /// `handle_stop_revoke` confirms the target was stopped.
    CancellationRequested,
}

/// Stable machine-readable denial reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DenialReasonCode {
    /// Malformed or oversized job spec.
    MalformedSpec,
    /// Job spec digest mismatch.
    DigestMismatch,
    /// Missing RFC-0028 channel context token.
    MissingChannelToken,
    /// RFC-0028 token decode failure.
    TokenDecodeFailed,
    /// RFC-0028 channel boundary violation.
    ChannelBoundaryViolation,
    /// Broker admission health gate not passed.
    AdmissionHealthGateFailed,
    /// RFC-0029 queue admission denied.
    QueueAdmissionDenied,
    /// RFC-0029 budget admission denied.
    BudgetAdmissionDenied,
    /// PCAC authority already consumed.
    AuthorityAlreadyConsumed,
    /// PCAC consume operation failed.
    PcacConsumeFailed,
    /// Lane acquisition failed.
    LaneAcquisitionFailed,
    /// General validation failure.
    ValidationFailed,
    /// Disk pressure preflight rejected job due to insufficient free space.
    InsufficientDiskSpace,
    /// Job was cancelled by an operator via `apm2 fac job cancel`.
    Cancelled,
    /// Job ID appeared in multiple queue directories (ambiguous state).
    AmbiguousJobState,
    /// The `stop_revoke` handler failed to stop and/or transition the target.
    StopRevokeFailed,
    /// Queue directory ownership or permissions are unsafe for control-lane
    /// authority.  The queue root or a subdirectory is not owned by the
    /// current uid or has group/world-accessible mode bits.
    UnsafeQueuePermissions,
    /// Canonicalizer tuple digest could not be parsed from b3-256 hex string.
    /// Fail-closed: unparseable digest cannot be used for token binding
    /// validation.
    InvalidCanonicalizerDigest,
    /// Control-plane rate limit or quota exceeded (TCK-00568).
    ControlPlaneBudgetDenied,
}

/// Trace of the RFC-0028 channel boundary check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelBoundaryTrace {
    /// Whether the boundary check passed.
    pub passed: bool,
    /// Number of defects found.
    pub defect_count: u32,
    /// Bound and stringified defect classes.
    pub defect_classes: Vec<String>,
    /// TCK-00565: Hex-encoded FAC policy hash from decoded token binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_fac_policy_hash: Option<String>,
    /// TCK-00565: Hex-encoded canonicalizer tuple digest from decoded token
    /// binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_canonicalizer_tuple_digest: Option<String>,
    /// TCK-00565: Boundary identifier from decoded token binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_boundary_id: Option<String>,
    /// TCK-00565: Issued-at tick from decoded token binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_issued_at_tick: Option<u64>,
    /// TCK-00565: Expiry tick from decoded token binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expiry_tick: Option<u64>,
}

/// Trace of the RFC-0029 queue admission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueAdmissionTrace {
    /// The admission verdict.
    pub verdict: String,
    /// The queue lane that was evaluated.
    pub queue_lane: String,
    /// Optional deny reason.
    pub defect_reason: Option<String>,
}

/// Placeholder trace for RFC-0029 budget admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetAdmissionTrace {
    /// Budget admission verdict.
    pub verdict: String,
    /// Optional reason for budget denial.
    pub reason: Option<String>,
}

/// Unified worker receipt for FAC job outcomes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacJobReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Unique receipt ID.
    pub receipt_id: String,
    /// Job ID from the spec.
    pub job_id: String,
    /// BLAKE3 digest of the job spec.
    pub job_spec_digest: String,
    /// Optional policy hash used for policy binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Optional patch digest for patch-injected jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_digest: Option<String>,
    /// Canonicalizer tuple digest for audit trail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonicalizer_tuple_digest: Option<String>,
    /// Outcome.
    pub outcome: FacJobOutcome,
    /// Stable denial reason for non-completed outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<DenialReasonCode>,
    /// If true, this receipt came from direct-mode execution without
    /// admission control.
    #[serde(default)]
    pub unsafe_direct: bool,
    /// Human-readable reason (bounded).
    pub reason: String,
    /// Optional canonical destination path after a move operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moved_job_path: Option<String>,
    /// RFC-0028 boundary trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rfc0028_channel_boundary: Option<ChannelBoundaryTrace>,
    /// RFC-0029 queue admission trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eio29_queue_admission: Option<QueueAdmissionTrace>,
    /// RFC-0029 budget admission trace.
    ///
    /// This field is a placeholder for future RFC-0029 budget economics.
    /// It is intentionally optional and currently not populated by the worker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eio29_budget_admission: Option<BudgetAdmissionTrace>,
    /// Containment verification trace (TCK-00548).
    ///
    /// Records whether child processes (rustc, nextest, etc.) were verified
    /// to share the same cgroup as the job unit, and whether sccache was
    /// auto-disabled due to containment failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containment: Option<super::containment::ContainmentTrace>,
    /// RFC-0029 observed runtime cost metrics (TCK-00532).
    ///
    /// Best-effort measurement of actual job resource consumption for
    /// post-run cost model calibration. Workers populate this from
    /// wall-clock timers and I/O accounting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_cost: Option<crate::economics::cost_model::ObservedJobCost>,
    /// Epoch timestamp.
    pub timestamp_secs: u64,
    /// BLAKE3 body hash for content-addressed storage.
    pub content_hash: String,
}

impl FacJobReceiptV1 {
    /// Returns canonical bytes for content hash computation.
    ///
    /// Encodes all fields except `content_hash` in deterministic order with
    /// length-prefixing to prevent canonicalization collisions.
    ///
    /// # Trailing Optional Field Policy
    ///
    /// ALL trailing optional fields (`moved_job_path`, `containment`,
    /// `observed_cost`) emit a presence marker (0u8 for None, 1u8 for Some)
    /// to prevent canonicalization collisions. Without markers, two receipts
    /// with different field occupancy patterns could produce identical
    /// canonical bytes if the encoded data happens to align.
    ///
    /// # Panics
    ///
    /// Panics only if serde serialization for internal enum variants fails.
    /// These variants are statically constrained to serializable values, so
    /// this path is not expected under normal operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);

        bytes.extend_from_slice(&(self.schema.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema.as_bytes());

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.job_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.job_id.as_bytes());

        bytes.extend_from_slice(&(self.job_spec_digest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.job_spec_digest.as_bytes());

        let outcome_str = serde_json::to_string(&self.outcome).expect("outcome serialization");
        bytes.extend_from_slice(&(outcome_str.len() as u32).to_be_bytes());
        bytes.extend_from_slice(outcome_str.as_bytes());

        if let Some(reason_code) = &self.denial_reason {
            bytes.push(1u8);
            let reason_str = serde_json::to_string(reason_code).expect("reason_code serialization");
            bytes.extend_from_slice(&(reason_str.len() as u32).to_be_bytes());
            bytes.extend_from_slice(reason_str.as_bytes());
        } else {
            bytes.push(0u8);
        }

        // NOTE: `unsafe_direct` is intentionally excluded from canonical bytes.
        // Including it would change the content hash for all existing receipts,
        // breaking content-addressed storage and ledger references. The field
        // is still present in the struct and in serde (de)serialization.

        bytes.extend_from_slice(&(self.reason.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.reason.as_bytes());

        if let Some(trace) = &self.rfc0028_channel_boundary {
            bytes.push(1u8);
            bytes.push(u8::from(trace.passed));
            bytes.extend_from_slice(&trace.defect_count.to_be_bytes());
            bytes.extend_from_slice(&(trace.defect_classes.len() as u32).to_be_bytes());
            for class in &trace.defect_classes {
                bytes.extend_from_slice(&(class.len() as u32).to_be_bytes());
                bytes.extend_from_slice(class.as_bytes());
            }
        } else {
            bytes.push(0u8);
        }

        if let Some(trace) = &self.eio29_queue_admission {
            bytes.push(1u8);
            bytes.extend_from_slice(&(trace.verdict.len() as u32).to_be_bytes());
            bytes.extend_from_slice(trace.verdict.as_bytes());
            bytes.extend_from_slice(&(trace.queue_lane.len() as u32).to_be_bytes());
            bytes.extend_from_slice(trace.queue_lane.as_bytes());
            if let Some(reason) = &trace.defect_reason {
                bytes.push(1u8);
                bytes.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                bytes.extend_from_slice(reason.as_bytes());
            } else {
                bytes.push(0u8);
            }
        } else {
            bytes.push(0u8);
        }

        if let Some(trace) = &self.eio29_budget_admission {
            bytes.push(1u8);
            bytes.extend_from_slice(&(trace.verdict.len() as u32).to_be_bytes());
            bytes.extend_from_slice(trace.verdict.as_bytes());
            if let Some(reason) = &trace.reason {
                bytes.push(1u8);
                bytes.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                bytes.extend_from_slice(reason.as_bytes());
            } else {
                bytes.push(0u8);
            }
        } else {
            bytes.push(0u8);
        }

        if let Some(digest) = &self.patch_digest {
            bytes.push(1u8);
            bytes.extend_from_slice(&(digest.len() as u32).to_be_bytes());
            bytes.extend_from_slice(digest.as_bytes());
        } else {
            bytes.push(0u8);
        }

        bytes.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        // Trailing optional fields: ALL emit presence markers (0u8 for None,
        // 1u8 for Some) to prevent canonicalization collisions. Without
        // markers, a receipt with `moved_job_path=Some(data)` and
        // `containment=None` could produce identical bytes to one with
        // `moved_job_path=None` and `containment=Some(colliding_data)`.
        //
        // Backward-compat note: adding `observed_cost` (TCK-00532) already
        // changes v1 canonical bytes (its 0u8 marker is new), so adding
        // absence markers for `moved_job_path` and `containment` is a
        // no-cost fix — all v1 hashes are recomputed anyway.
        if let Some(path) = &self.moved_job_path {
            bytes.push(1u8);
            bytes.extend_from_slice(&(path.len() as u32).to_be_bytes());
            bytes.extend_from_slice(path.as_bytes());
        } else {
            bytes.push(0u8);
        }

        // TCK-00548: Containment trace with presence marker.
        if let Some(trace) = &self.containment {
            bytes.push(1u8);
            bytes.push(u8::from(trace.verified));
            bytes.extend_from_slice(&(trace.cgroup_path.len() as u32).to_be_bytes());
            bytes.extend_from_slice(trace.cgroup_path.as_bytes());
            bytes.extend_from_slice(&trace.processes_checked.to_be_bytes());
            bytes.extend_from_slice(&trace.mismatch_count.to_be_bytes());
            bytes.push(u8::from(trace.sccache_auto_disabled));
        } else {
            bytes.push(0u8);
        }

        // TCK-00532: Observed job cost with presence marker.
        if let Some(cost) = &self.observed_cost {
            bytes.push(1u8);
            bytes.extend_from_slice(&cost.duration_ms.to_be_bytes());
            bytes.extend_from_slice(&cost.cpu_time_ms.to_be_bytes());
            bytes.extend_from_slice(&cost.bytes_written.to_be_bytes());
        } else {
            bytes.push(0u8);
        }

        bytes
    }

    /// Returns v2 canonical bytes that include `unsafe_direct` in the
    /// preimage.
    ///
    /// V2 hashing includes `unsafe_direct` as a boolean byte (0/1) after
    /// the `denial_reason` block and before the reason field.  This ensures
    /// that the direct-mode flag is integrity-bound in new receipts while
    /// keeping v1 `canonical_bytes()` unchanged for existing receipt
    /// verification.
    ///
    /// New receipts should use v2. Existing v1 receipts remain verifiable
    /// via `canonical_bytes()`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    pub fn canonical_bytes_v2(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);

        bytes.extend_from_slice(&(self.schema.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.schema.as_bytes());

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.job_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.job_id.as_bytes());

        bytes.extend_from_slice(&(self.job_spec_digest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.job_spec_digest.as_bytes());

        let outcome_str = serde_json::to_string(&self.outcome).unwrap_or_default();
        bytes.extend_from_slice(&(outcome_str.len() as u32).to_be_bytes());
        bytes.extend_from_slice(outcome_str.as_bytes());

        if let Some(reason_code) = &self.denial_reason {
            bytes.push(1u8);
            let reason_str = serde_json::to_string(reason_code).unwrap_or_default();
            bytes.extend_from_slice(&(reason_str.len() as u32).to_be_bytes());
            bytes.extend_from_slice(reason_str.as_bytes());
        } else {
            bytes.push(0u8);
        }

        // V2: Include `unsafe_direct` in canonical bytes for integrity
        // binding (MAJOR-3).
        bytes.push(u8::from(self.unsafe_direct));

        bytes.extend_from_slice(&(self.reason.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.reason.as_bytes());

        if let Some(trace) = &self.rfc0028_channel_boundary {
            bytes.push(1u8);
            bytes.push(u8::from(trace.passed));
            bytes.extend_from_slice(&trace.defect_count.to_be_bytes());
            bytes.extend_from_slice(&(trace.defect_classes.len() as u32).to_be_bytes());
            for class in &trace.defect_classes {
                bytes.extend_from_slice(&(class.len() as u32).to_be_bytes());
                bytes.extend_from_slice(class.as_bytes());
            }
        } else {
            bytes.push(0u8);
        }

        if let Some(trace) = &self.eio29_queue_admission {
            bytes.push(1u8);
            bytes.extend_from_slice(&(trace.verdict.len() as u32).to_be_bytes());
            bytes.extend_from_slice(trace.verdict.as_bytes());
            bytes.extend_from_slice(&(trace.queue_lane.len() as u32).to_be_bytes());
            bytes.extend_from_slice(trace.queue_lane.as_bytes());
            if let Some(reason) = &trace.defect_reason {
                bytes.push(1u8);
                bytes.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                bytes.extend_from_slice(reason.as_bytes());
            } else {
                bytes.push(0u8);
            }
        } else {
            bytes.push(0u8);
        }

        if let Some(trace) = &self.eio29_budget_admission {
            bytes.push(1u8);
            bytes.extend_from_slice(&(trace.verdict.len() as u32).to_be_bytes());
            bytes.extend_from_slice(trace.verdict.as_bytes());
            if let Some(reason) = &trace.reason {
                bytes.push(1u8);
                bytes.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                bytes.extend_from_slice(reason.as_bytes());
            } else {
                bytes.push(0u8);
            }
        } else {
            bytes.push(0u8);
        }

        if let Some(digest) = &self.patch_digest {
            bytes.push(1u8);
            bytes.extend_from_slice(&(digest.len() as u32).to_be_bytes());
            bytes.extend_from_slice(digest.as_bytes());
        } else {
            bytes.push(0u8);
        }

        // For backward compatibility with pre-tuple receipts, omit the `0u8`
        // presence marker when `canonicalizer_tuple_digest` is absent, because
        // older receipts encoded without this optional field at all.
        if let Some(digest) = &self.canonicalizer_tuple_digest {
            bytes.push(1u8);
            bytes.extend_from_slice(&(digest.len() as u32).to_be_bytes());
            bytes.extend_from_slice(digest.as_bytes());
        }

        bytes.extend_from_slice(&self.timestamp_secs.to_be_bytes());

        // V2 trailing optional fields: ALL emit presence markers (0u8/1u8)
        // to prevent canonicalization collisions. V2 is only used for new
        // receipts, so there is no backward-compatibility constraint.
        if let Some(path) = &self.moved_job_path {
            bytes.push(1u8);
            bytes.extend_from_slice(&(path.len() as u32).to_be_bytes());
            bytes.extend_from_slice(path.as_bytes());
        } else {
            bytes.push(0u8);
        }

        // TCK-00548: Containment trace with presence marker.
        if let Some(trace) = &self.containment {
            bytes.push(1u8);
            bytes.push(u8::from(trace.verified));
            bytes.extend_from_slice(&(trace.cgroup_path.len() as u32).to_be_bytes());
            bytes.extend_from_slice(trace.cgroup_path.as_bytes());
            bytes.extend_from_slice(&trace.processes_checked.to_be_bytes());
            bytes.extend_from_slice(&trace.mismatch_count.to_be_bytes());
            bytes.push(u8::from(trace.sccache_auto_disabled));
        } else {
            bytes.push(0u8);
        }

        // TCK-00532: Observed job cost with presence marker.
        if let Some(cost) = &self.observed_cost {
            bytes.push(1u8);
            bytes.extend_from_slice(&cost.duration_ms.to_be_bytes());
            bytes.extend_from_slice(&cost.cpu_time_ms.to_be_bytes());
            bytes.extend_from_slice(&cost.bytes_written.to_be_bytes());
        } else {
            bytes.push(0u8);
        }

        bytes
    }

    /// Validate all invariant and boundedness requirements for the receipt.
    ///
    /// # Errors
    ///
    /// Returns [`FacJobReceiptError`] if:
    ///
    /// - A string field exceeds maximum length bounds.
    /// - A digest field is not formatted as a valid `b3-256:<64 hex>`.
    /// - Outcome-specific invariants are violated.
    #[allow(clippy::too_many_lines)] // Validation flow for all fields and invariants is intentionally centralized.
    pub fn validate(&self) -> Result<(), FacJobReceiptError> {
        if self.schema.len() > MAX_STRING_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "schema",
                actual: self.schema.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.receipt_id.len() > MAX_STRING_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "receipt_id",
                actual: self.receipt_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.job_id.len() > MAX_STRING_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "job_id",
                actual: self.job_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.reason.chars().count() > MAX_FAC_JOB_REASON_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "reason",
                actual: self.reason.chars().count(),
                max: MAX_FAC_JOB_REASON_LENGTH,
            });
        }
        if self.job_spec_digest.len() > MAX_STRING_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "job_spec_digest",
                actual: self.job_spec_digest.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if let Some(path) = &self.moved_job_path {
            if path.len() > MAX_STRING_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "moved_job_path",
                    actual: path.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if path.chars().any(char::is_control) {
                return Err(FacJobReceiptError::InvalidData(
                    "moved_job_path contains control characters".to_string(),
                ));
            }
            if path.contains("..") {
                return Err(FacJobReceiptError::InvalidData(
                    "moved_job_path contains path traversal sequence".to_string(),
                ));
            }
            if std::path::Path::new(path).is_absolute() {
                return Err(FacJobReceiptError::InvalidData(
                    "moved_job_path must be a relative path".to_string(),
                ));
            }
        }
        if !is_valid_b3_256_digest(&self.job_spec_digest) {
            return Err(FacJobReceiptError::InvalidData(
                "job_spec_digest must be 'b3-256:<64 hex>'".to_string(),
            ));
        }
        if let Some(policy_hash) = &self.policy_hash {
            if !is_strict_b3_256_digest(policy_hash) {
                return Err(FacJobReceiptError::InvalidData(
                    "policy_hash must be exactly 71 chars in b3-256:<64hex> format".to_string(),
                ));
            }
        }
        if let Some(patch_digest) = &self.patch_digest {
            if !is_strict_b3_256_digest(patch_digest) {
                return Err(FacJobReceiptError::InvalidData(
                    "patch_digest must be exactly 71 chars in b3-256:<64hex> format".to_string(),
                ));
            }
        }
        if let Some(tuple_digest) = &self.canonicalizer_tuple_digest {
            if !is_strict_b3_256_digest(tuple_digest) {
                return Err(FacJobReceiptError::InvalidData(
                    "canonicalizer_tuple_digest must be exactly 71 chars in b3-256:<64hex> format"
                        .to_string(),
                ));
            }
        }
        if self.content_hash.len() > MAX_STRING_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "content_hash",
                actual: self.content_hash.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if !is_valid_b3_256_digest(&self.content_hash) {
            return Err(FacJobReceiptError::InvalidData(
                "content_hash must be 'b3-256:<64 hex>'".to_string(),
            ));
        }

        match self.outcome {
            FacJobOutcome::Completed => {
                if self.rfc0028_channel_boundary.is_none() {
                    return Err(FacJobReceiptError::MissingField("rfc0028_channel_boundary"));
                }
                if self.eio29_queue_admission.is_none() {
                    return Err(FacJobReceiptError::MissingField("eio29_queue_admission"));
                }
            },
            FacJobOutcome::Denied
            | FacJobOutcome::Quarantined
            | FacJobOutcome::Cancelled
            | FacJobOutcome::CancellationRequested => {
                if self.denial_reason.is_none() {
                    return Err(FacJobReceiptError::MissingField("denial_reason"));
                }
            },
        }

        if let Some(trace) = &self.rfc0028_channel_boundary {
            if trace.defect_classes.len() > MAX_FAC_JOB_BOUNDARY_DEFECT_CLASSES {
                return Err(FacJobReceiptError::InvalidData(
                    "channel boundary defect class count exceeds limit".to_string(),
                ));
            }
            for class in &trace.defect_classes {
                if class.len() > MAX_STRING_LENGTH {
                    return Err(FacJobReceiptError::StringTooLong {
                        field: "rfc0028_channel_boundary.defect_classes",
                        actual: class.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
            }
        }

        if let Some(trace) = &self.eio29_queue_admission {
            if trace.verdict.len() > MAX_STRING_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_queue_admission.verdict",
                    actual: trace.verdict.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if trace.queue_lane.len() > MAX_STRING_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_queue_admission.queue_lane",
                    actual: trace.queue_lane.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if let Some(defect_reason) = &trace.defect_reason
                && defect_reason.len() > MAX_STRING_LENGTH
            {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_queue_admission.defect_reason",
                    actual: defect_reason.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        if let Some(trace) = &self.eio29_budget_admission {
            if trace.verdict.len() > MAX_STRING_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_budget_admission.verdict",
                    actual: trace.verdict.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if let Some(reason) = &trace.reason
                && reason.len() > MAX_STRING_LENGTH
            {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_budget_admission.reason",
                    actual: reason.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        // TCK-00548: Validate containment trace bounds to prevent
        // memory exhaustion via oversized cgroup_path (MAJOR-1).
        if let Some(trace) = &self.containment {
            if trace.cgroup_path.len() > super::containment::MAX_CGROUP_PATH_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "containment.cgroup_path",
                    actual: trace.cgroup_path.len(),
                    max: super::containment::MAX_CGROUP_PATH_LENGTH,
                });
            }
        }

        Ok(())
    }
}

/// Builder for `FacJobReceiptV1`.
#[derive(Debug, Default)]
pub struct FacJobReceiptV1Builder {
    receipt_id: String,
    job_id: String,
    job_spec_digest: Option<String>,
    outcome: Option<FacJobOutcome>,
    denial_reason: Option<DenialReasonCode>,
    reason: Option<String>,
    unsafe_direct: bool,
    policy_hash: Option<String>,
    moved_job_path: Option<String>,
    patch_digest: Option<String>,
    canonicalizer_tuple_digest: Option<String>,
    rfc0028_channel_boundary: Option<ChannelBoundaryTrace>,
    eio29_queue_admission: Option<QueueAdmissionTrace>,
    eio29_budget_admission: Option<BudgetAdmissionTrace>,
    containment: Option<super::containment::ContainmentTrace>,
    observed_cost: Option<crate::economics::cost_model::ObservedJobCost>,
    timestamp_secs: Option<u64>,
}

impl FacJobReceiptV1Builder {
    /// Creates a new builder with required IDs and digest.
    #[must_use]
    pub fn new(
        receipt_id: impl Into<String>,
        job_id: impl Into<String>,
        job_spec_digest: impl Into<String>,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            job_id: job_id.into(),
            job_spec_digest: Some(job_spec_digest.into()),
            ..Self::default()
        }
    }

    /// Sets the outcome.
    #[must_use]
    pub const fn outcome(mut self, outcome: FacJobOutcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Sets the denial code.
    #[must_use]
    pub const fn denial_reason(mut self, reason: DenialReasonCode) -> Self {
        self.denial_reason = Some(reason);
        self
    }

    /// Sets the human reason.
    #[must_use]
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Marks whether this receipt was produced by unsafe direct mode.
    #[must_use]
    pub const fn unsafe_direct(mut self, unsafe_direct: bool) -> Self {
        self.unsafe_direct = unsafe_direct;
        self
    }

    /// Sets the policy hash.
    #[must_use]
    pub fn policy_hash(mut self, policy_hash: impl Into<String>) -> Self {
        self.policy_hash = Some(policy_hash.into());
        self
    }

    /// Sets the moved job path.
    #[must_use]
    pub fn moved_job_path(mut self, moved_job_path: impl Into<String>) -> Self {
        self.moved_job_path = Some(moved_job_path.into());
        self
    }

    /// Sets the patch digest.
    #[must_use]
    pub fn patch_digest(mut self, patch_digest: impl Into<String>) -> Self {
        self.patch_digest = Some(patch_digest.into());
        self
    }

    /// Sets the canonicalizer tuple digest.
    #[must_use]
    pub fn canonicalizer_tuple_digest(mut self, tuple_digest: impl Into<String>) -> Self {
        self.canonicalizer_tuple_digest = Some(tuple_digest.into());
        self
    }

    /// Sets the boundary trace.
    #[must_use]
    pub fn rfc0028_channel_boundary(mut self, trace: ChannelBoundaryTrace) -> Self {
        self.rfc0028_channel_boundary = Some(trace);
        self
    }

    /// Sets the queue admission trace.
    #[must_use]
    pub fn eio29_queue_admission(mut self, trace: QueueAdmissionTrace) -> Self {
        self.eio29_queue_admission = Some(trace);
        self
    }

    /// Sets the budget admission trace.
    #[must_use]
    pub fn eio29_budget_admission(mut self, trace: BudgetAdmissionTrace) -> Self {
        self.eio29_budget_admission = Some(trace);
        self
    }

    /// Sets the containment verification trace (TCK-00548).
    #[must_use]
    pub fn containment(mut self, trace: super::containment::ContainmentTrace) -> Self {
        self.containment = Some(trace);
        self
    }

    /// Sets the observed runtime cost metrics (TCK-00532).
    #[must_use]
    pub const fn observed_cost(
        mut self,
        cost: crate::economics::cost_model::ObservedJobCost,
    ) -> Self {
        self.observed_cost = Some(cost);
        self
    }

    /// Sets receipt timestamp.
    #[must_use]
    pub const fn timestamp_secs(mut self, timestamp_secs: u64) -> Self {
        self.timestamp_secs = Some(timestamp_secs);
        self
    }

    /// Builds a receipt and computes the content hash.
    ///
    /// # Errors
    ///
    /// Returns [`FacJobReceiptError`] if:
    /// - A required field is missing.
    /// - A string exceeds maximum allowed length.
    /// - The receipt is malformed (invalid digest, failed hashing, etc.).
    #[allow(clippy::too_many_lines)] // Validation logic for 12+ fields is sequential and correlated; splitting it obscures invariant dependencies.
    pub fn try_build(self) -> Result<FacJobReceiptV1, FacJobReceiptError> {
        let receipt_id = self.receipt_id;
        let job_id = self.job_id;
        let job_spec_digest = self
            .job_spec_digest
            .ok_or(FacJobReceiptError::MissingField("job_spec_digest"))?;
        let outcome = self.outcome.unwrap_or(FacJobOutcome::Denied);
        let reason = self.reason.unwrap_or_else(|| "unspecified".to_string());
        let timestamp_secs = self.timestamp_secs.unwrap_or(0);
        let patch_digest = self.patch_digest;
        let canonicalizer_tuple_digest = self.canonicalizer_tuple_digest;
        let moved_job_path = self.moved_job_path;

        if receipt_id.len() > MAX_STRING_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "receipt_id",
                actual: receipt_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if job_id.len() > MAX_STRING_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "job_id",
                actual: job_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        if !is_valid_b3_256_digest(&job_spec_digest) {
            return Err(FacJobReceiptError::InvalidData(
                "job_spec_digest must be 'b3-256:<64 hex>'".to_string(),
            ));
        }

        if let Some(policy_hash) = &self.policy_hash {
            if !is_strict_b3_256_digest(policy_hash) {
                return Err(FacJobReceiptError::InvalidData(
                    "policy_hash must be exactly 71 chars in b3-256:<64hex> format".to_string(),
                ));
            }
        }
        if let Some(canonicalizer_tuple_digest) = &canonicalizer_tuple_digest {
            if !is_strict_b3_256_digest(canonicalizer_tuple_digest) {
                return Err(FacJobReceiptError::InvalidData(
                    "canonicalizer_tuple_digest must be exactly 71 chars in b3-256:<64hex> format"
                        .to_string(),
                ));
            }
        }

        if job_spec_digest.len() > MAX_STRING_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "job_spec_digest",
                actual: job_spec_digest.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let reason_len = reason.chars().count();
        if reason_len > MAX_FAC_JOB_REASON_LENGTH {
            return Err(FacJobReceiptError::StringTooLong {
                field: "reason",
                actual: reason_len,
                max: MAX_FAC_JOB_REASON_LENGTH,
            });
        }
        if let Some(path) = &moved_job_path {
            if path.len() > MAX_STRING_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "moved_job_path",
                    actual: path.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if path.chars().any(char::is_control) {
                return Err(FacJobReceiptError::InvalidData(
                    "moved_job_path contains control characters".to_string(),
                ));
            }
            if path.contains("..") {
                return Err(FacJobReceiptError::InvalidData(
                    "moved_job_path contains path traversal sequence".to_string(),
                ));
            }
            if std::path::Path::new(path).is_absolute() {
                return Err(FacJobReceiptError::InvalidData(
                    "moved_job_path must be a relative path".to_string(),
                ));
            }
        }

        match outcome {
            FacJobOutcome::Completed => {
                if self.rfc0028_channel_boundary.is_none() {
                    return Err(FacJobReceiptError::MissingField("rfc0028_channel_boundary"));
                }
                if self.eio29_queue_admission.is_none() {
                    return Err(FacJobReceiptError::MissingField("eio29_queue_admission"));
                }
                // RFC-0029 budget admission is currently deferred and optional
                // for completed outcomes.
            },
            FacJobOutcome::Denied
            | FacJobOutcome::Quarantined
            | FacJobOutcome::Cancelled
            | FacJobOutcome::CancellationRequested => {
                if self.denial_reason.is_none() {
                    return Err(FacJobReceiptError::MissingField("denial_reason"));
                }
            },
        }

        if let Some(trace) = self.rfc0028_channel_boundary.as_ref() {
            if trace.defect_classes.len() > MAX_FAC_JOB_BOUNDARY_DEFECT_CLASSES {
                return Err(FacJobReceiptError::InvalidData(
                    "channel boundary defect class count exceeds limit".to_string(),
                ));
            }
            for class in &trace.defect_classes {
                if class.len() > MAX_STRING_LENGTH {
                    return Err(FacJobReceiptError::StringTooLong {
                        field: "rfc0028_channel_boundary.defect_classes",
                        actual: class.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
            }
        }

        if let Some(trace) = self.eio29_queue_admission.as_ref() {
            if trace.verdict.len() > MAX_STRING_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_queue_admission.verdict",
                    actual: trace.verdict.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if trace.queue_lane.len() > MAX_STRING_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_queue_admission.queue_lane",
                    actual: trace.queue_lane.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if let Some(defect_reason) = &trace.defect_reason
                && defect_reason.len() > MAX_STRING_LENGTH
            {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_queue_admission.defect_reason",
                    actual: defect_reason.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        if let Some(trace) = self.eio29_budget_admission.as_ref() {
            if trace.verdict.len() > MAX_STRING_LENGTH {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_budget_admission.verdict",
                    actual: trace.verdict.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if let Some(reason) = &trace.reason
                && reason.len() > MAX_STRING_LENGTH
            {
                return Err(FacJobReceiptError::StringTooLong {
                    field: "eio29_budget_admission.reason",
                    actual: reason.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        let candidate = FacJobReceiptV1 {
            schema: FAC_JOB_RECEIPT_SCHEMA.to_string(),
            receipt_id,
            job_id,
            job_spec_digest,
            policy_hash: self.policy_hash,
            patch_digest,
            canonicalizer_tuple_digest,
            outcome,
            denial_reason: self.denial_reason,
            unsafe_direct: self.unsafe_direct,
            reason,
            rfc0028_channel_boundary: self.rfc0028_channel_boundary,
            eio29_queue_admission: self.eio29_queue_admission,
            eio29_budget_admission: self.eio29_budget_admission,
            containment: self.containment,
            observed_cost: self.observed_cost,
            moved_job_path,
            timestamp_secs,
            content_hash: String::new(),
        };

        let mut receipt = candidate;
        receipt.content_hash = compute_job_receipt_content_hash(&receipt);
        Ok(receipt)
    }

    /// Builds a receipt and computes the **v2** content hash which
    /// includes `unsafe_direct` in the canonical preimage.
    ///
    /// Use this for new receipts created by the CLI (gates, direct mode)
    /// where `unsafe_direct` integrity binding is required.
    ///
    /// # Errors
    ///
    /// Returns [`FacJobReceiptError`] if required fields are missing or
    /// validation fails.
    #[allow(clippy::too_many_lines)]
    pub fn try_build_v2(self) -> Result<FacJobReceiptV1, FacJobReceiptError> {
        // Reuse all validation from try_build, then override the hash.
        let mut receipt = self.try_build()?;
        receipt.content_hash = compute_job_receipt_content_hash_v2(&receipt);
        Ok(receipt)
    }
}

/// Deserializes a bounded `FacJobReceiptV1` from JSON and validates content
/// constraints after parsing.
///
/// # Errors
///
/// Returns [`FacJobReceiptError`] if:
///
/// - Input exceeds `MAX_JOB_RECEIPT_SIZE`.
/// - JSON deserialization fails.
/// - Receipt validation fails.
pub fn deserialize_job_receipt(bytes: &[u8]) -> Result<FacJobReceiptV1, FacJobReceiptError> {
    if bytes.len() > MAX_JOB_RECEIPT_SIZE {
        return Err(FacJobReceiptError::InvalidData(format!(
            "receipt input size {} exceeds maximum {}",
            bytes.len(),
            MAX_JOB_RECEIPT_SIZE
        )));
    }

    let receipt: FacJobReceiptV1 = serde_json::from_slice(bytes)
        .map_err(|e| FacJobReceiptError::Serialization(e.to_string()))?;
    receipt.validate()?;
    Ok(receipt)
}

/// Compute the v1 content hash (does **not** include `unsafe_direct`).
///
/// Use [`compute_job_receipt_content_hash_v2`] for new receipts. This
/// function exists for backwards-compatible verification of receipts
/// produced by workers using `FacJobReceiptV1Builder::try_build`.
#[must_use]
pub fn compute_job_receipt_content_hash(receipt: &FacJobReceiptV1) -> String {
    let canonical = receipt.canonical_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.fac.job_receipt.content_hash.v1\0");
    hasher.update(&canonical);
    format!("b3-256:{}", hasher.finalize().to_hex())
}

/// Compute the v2 content hash that includes `unsafe_direct` in the
/// canonical preimage.
///
/// New receipts should use this function. Existing v1 receipts can still
/// be verified via `compute_job_receipt_content_hash` (v1, crate-internal).
#[must_use]
pub fn compute_job_receipt_content_hash_v2(receipt: &FacJobReceiptV1) -> String {
    let canonical = receipt.canonical_bytes_v2();
    let mut hasher = blake3::Hasher::new();
    // Distinct domain separator so v1 and v2 hashes never collide.
    hasher.update(b"apm2.fac.job_receipt.content_hash.v2\0");
    hasher.update(&canonical);
    format!("b3-256:{}", hasher.finalize().to_hex())
}

fn is_valid_b3_256_digest(value: &str) -> bool {
    parse_b3_256_digest(value).is_some()
}

fn is_strict_b3_256_digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("b3-256:") && is_valid_b3_256_digest(value)
}

/// Persist a content-addressed job receipt.
///
/// Writes the receipt to `<blake3_hex>.json` under `fac_receipts_dir` using
/// an atomic temp-file rename.
///
/// # Errors
///
/// Returns an error string if serialization, hashing, or persistence fails.
pub fn persist_content_addressed_receipt(
    fac_receipts_dir: &Path,
    receipt: &FacJobReceiptV1,
) -> Result<PathBuf, String> {
    let expected_hash = compute_job_receipt_content_hash(receipt);

    if !receipt.content_hash.is_empty() && receipt.content_hash != expected_hash {
        return Err("receipt content_hash does not match serialized body".to_string());
    }

    fs::create_dir_all(fac_receipts_dir)
        .map_err(|e| format!("cannot create receipt directory: {e}"))?;

    let canonical_receipt = FacJobReceiptV1 {
        content_hash: expected_hash.clone(),
        ..receipt.clone()
    };
    let body = serde_json::to_vec_pretty(&canonical_receipt)
        .map_err(|e| format!("cannot serialize receipt: {e}"))?;

    let final_path = fac_receipts_dir.join(format!("{expected_hash}.json"));
    let temp_path = fac_receipts_dir.join(format!("{expected_hash}.tmp"));
    fs::write(&temp_path, body).map_err(|e| format!("cannot write temp receipt file: {e}"))?;
    fs::rename(&temp_path, &final_path)
        .map_err(|e| format!("cannot move receipt to {}: {e}", final_path.display()))?;

    // Best-effort incremental index update (TCK-00560).
    // Index is non-authoritative cache; failure here does not affect
    // receipt persistence correctness. On failure, delete the stale index
    // to force a rebuild on next read, ensuring consistency.
    if let Err(e) = super::receipt_index::ReceiptIndexV1::incremental_update(
        fac_receipts_dir,
        &canonical_receipt,
    ) {
        eprintln!("WARN: failed to update receipt index: {e}");
        let index_path = super::receipt_index::ReceiptIndexV1::index_path(fac_receipts_dir);
        let _ = fs::remove_file(&index_path);
    }

    Ok(final_path)
}

/// Persist a content-addressed job receipt using v2 hashing
/// (includes `unsafe_direct` in canonical bytes).
///
/// New receipts should use this function for full integrity binding.
///
/// # Errors
///
/// Returns an error string if serialization, hashing, or persistence fails.
pub fn persist_content_addressed_receipt_v2(
    fac_receipts_dir: &Path,
    receipt: &FacJobReceiptV1,
) -> Result<PathBuf, String> {
    let expected_hash = compute_job_receipt_content_hash_v2(receipt);

    fs::create_dir_all(fac_receipts_dir)
        .map_err(|e| format!("cannot create receipt directory: {e}"))?;

    let canonical_receipt = FacJobReceiptV1 {
        content_hash: expected_hash.clone(),
        ..receipt.clone()
    };
    let body = serde_json::to_vec_pretty(&canonical_receipt)
        .map_err(|e| format!("cannot serialize receipt: {e}"))?;

    let final_path = fac_receipts_dir.join(format!("{expected_hash}.json"));
    let temp_path = fac_receipts_dir.join(format!("{expected_hash}.tmp"));
    fs::write(&temp_path, body).map_err(|e| format!("cannot write temp receipt file: {e}"))?;
    fs::rename(&temp_path, &final_path)
        .map_err(|e| format!("cannot move receipt to {}: {e}", final_path.display()))?;

    // Best-effort incremental index update (TCK-00560).
    // On failure, delete the stale index to force a rebuild on next read.
    if let Err(e) = super::receipt_index::ReceiptIndexV1::incremental_update(
        fac_receipts_dir,
        &canonical_receipt,
    ) {
        eprintln!("WARN: failed to update receipt index (v2): {e}");
        let index_path = super::receipt_index::ReceiptIndexV1::index_path(fac_receipts_dir);
        let _ = fs::remove_file(&index_path);
    }

    Ok(final_path)
}

// =============================================================================
// GateReceipt
// =============================================================================

/// A cryptographically signed gate receipt with versioning support.
///
/// The gate receipt is the canonical envelope for gate execution results. It
/// binds a gate's output to a specific lease and changeset, enabling audit
/// and verification of the gate execution.
///
/// # Fields (12 total)
///
/// - `receipt_id`: Unique identifier for this receipt
/// - `gate_id`: Gate that generated this receipt
/// - `lease_id`: Lease that authorized this gate execution
/// - `changeset_digest`: Hash binding to specific changeset
/// - `executor_actor_id`: Actor who executed the gate
/// - `receipt_version`: Envelope schema version (currently: 1)
/// - `payload_kind`: Type of payload ("aat", "quality", "security")
/// - `payload_schema_version`: Version of the payload schema
/// - `payload_hash`: Hash of the payload content
/// - `evidence_bundle_hash`: Hash of the evidence bundle
/// - `job_spec_digest`: Optional digest for the FAC job spec that triggered
///   this receipt.
/// - `passed`: Explicit pass/fail verdict declared by the executor
/// - `receipt_signature`: Ed25519 signature with domain separation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: String,

    /// Gate that generated this receipt.
    pub gate_id: String,

    /// Lease that authorized this gate execution.
    pub lease_id: String,

    /// Hash binding to specific changeset.
    #[serde(with = "serde_bytes")]
    pub changeset_digest: [u8; 32],

    /// Actor who executed the gate.
    pub executor_actor_id: String,

    /// Envelope schema version.
    ///
    /// Current supported versions: `[1]`
    pub receipt_version: u32,

    /// Type of payload.
    ///
    /// Supported kinds: `["aat", "quality", "security"]`
    pub payload_kind: String,

    /// Version of the payload schema.
    pub payload_schema_version: u32,

    /// Hash of the payload content.
    #[serde(with = "serde_bytes")]
    pub payload_hash: [u8; 32],

    /// Hash of the evidence bundle.
    #[serde(with = "serde_bytes")]
    pub evidence_bundle_hash: [u8; 32],

    /// BLAKE3 digest of the job spec that authorized this gate execution
    /// (TCK-00512). Present when the gate was triggered from a
    /// `FacJobSpecV1` queue item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_spec_digest: Option<String>,

    /// Explicit pass/fail verdict declared by the gate executor.
    ///
    /// This is the authoritative verdict field. The orchestrator uses this
    /// field directly rather than deriving the verdict from hash inspection.
    /// Receipts without an explicit verdict are rejected at the admission
    /// boundary (TCK-00388 Quality BLOCKER 2).
    pub passed: bool,

    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub receipt_signature: [u8; 64],
}

impl GateReceipt {
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
    #[allow(clippy::cast_possible_truncation)] // String lengths are validated elsewhere
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 4 + self.receipt_id.len()
            + 4 + self.gate_id.len()
            + 4 + self.lease_id.len()
            + 32  // changeset_digest
            + 4 + self.executor_actor_id.len()
            + 4   // receipt_version
            + 4 + self.payload_kind.len()
            + 4   // payload_schema_version
            + 32  // payload_hash
            + 32  // evidence_bundle_hash
            + 1   // job_spec_digest present marker when present
            + self
                .job_spec_digest
                .as_ref()
                .map_or(0, |digest| 1 + 4 + digest.len())
            + 1; // passed (bool)

        let mut bytes = Vec::with_capacity(capacity);

        // 1. receipt_id (length-prefixed)
        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        // 2. gate_id (length-prefixed)
        bytes.extend_from_slice(&(self.gate_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.gate_id.as_bytes());

        // 3. lease_id (length-prefixed)
        bytes.extend_from_slice(&(self.lease_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.lease_id.as_bytes());

        // 4. changeset_digest
        bytes.extend_from_slice(&self.changeset_digest);

        // 5. executor_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.executor_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.executor_actor_id.as_bytes());

        // 6. receipt_version (big-endian)
        bytes.extend_from_slice(&self.receipt_version.to_be_bytes());

        // 7. payload_kind (length-prefixed)
        bytes.extend_from_slice(&(self.payload_kind.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.payload_kind.as_bytes());

        // 8. payload_schema_version (big-endian)
        bytes.extend_from_slice(&self.payload_schema_version.to_be_bytes());

        // 9. payload_hash
        bytes.extend_from_slice(&self.payload_hash);

        // 10. evidence_bundle_hash
        bytes.extend_from_slice(&self.evidence_bundle_hash);

        // 11. job_spec_digest (optional)
        if let Some(digest) = self.job_spec_digest.as_ref() {
            bytes.push(1u8);
            bytes.extend_from_slice(&(digest.len() as u32).to_be_bytes());
            bytes.extend_from_slice(digest.as_bytes());
        }

        // 12. passed (1 byte: 0 = false, 1 = true)
        bytes.push(u8::from(self.passed));

        bytes
    }

    /// Validates the receipt signature using domain separation.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected executor
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid,
    /// `Err(ReceiptError::InvalidSignature)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::InvalidSignature`] if signature verification
    /// fails.
    pub fn validate_signature(&self, verifying_key: &VerifyingKey) -> Result<(), ReceiptError> {
        let signature = Signature::from_bytes(&self.receipt_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(verifying_key, GATE_RECEIPT_PREFIX, &canonical, &signature)
            .map_err(|e| ReceiptError::InvalidSignature(e.to_string()))
    }

    /// Validates the receipt version, payload kind, and payload schema version.
    ///
    /// # Arguments
    ///
    /// * `enforce` - If `true`, unknown versions/kinds return an error. If
    ///   `false`, unknown versions/kinds are silently accepted (permissive
    ///   mode).
    ///
    /// # Returns
    ///
    /// - `Ok(())` if validation passes (or permissive mode is enabled)
    /// - `Err(ReceiptError::UnsupportedVersion)` if `enforce` is `true` and
    ///   receipt version is unsupported
    /// - `Err(ReceiptError::UnsupportedPayloadKind)` if `enforce` is `true` and
    ///   payload kind is unsupported
    /// - `Err(ReceiptError::UnsupportedPayloadSchemaVersion)` if `enforce` is
    ///   `true` and payload schema version is unsupported
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::UnsupportedVersion`] if `enforce` is `true` and
    /// the receipt version is not in [`SUPPORTED_RECEIPT_VERSIONS`].
    ///
    /// Returns [`ReceiptError::UnsupportedPayloadKind`] if `enforce` is `true`
    /// and the payload kind is not in [`SUPPORTED_PAYLOAD_KINDS`].
    ///
    /// Returns [`ReceiptError::UnsupportedPayloadSchemaVersion`] if `enforce`
    /// is `true` and the payload schema version is not in
    /// [`SUPPORTED_PAYLOAD_SCHEMA_VERSIONS`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::crypto::Signer;
    /// use apm2_core::fac::GateReceiptBuilder;
    ///
    /// let signer = Signer::generate();
    /// let receipt = GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
    ///     .changeset_digest([0x42; 32])
    ///     .executor_actor_id("executor-001")
    ///     .receipt_version(1)
    ///     .payload_kind("aat")
    ///     .payload_schema_version(1)
    ///     .payload_hash([0xAB; 32])
    ///     .evidence_bundle_hash([0xCD; 32])
    ///     .passed(true)
    ///     .build_and_sign(&signer);
    ///
    /// // Enforce mode: errors on unknown versions
    /// assert!(receipt.validate_version(true).is_ok());
    ///
    /// // Permissive mode: silently accepts unknown versions
    /// assert!(receipt.validate_version(false).is_ok());
    /// ```
    pub fn validate_version(&self, enforce: bool) -> Result<(), ReceiptError> {
        // Check receipt version
        if !SUPPORTED_RECEIPT_VERSIONS.contains(&self.receipt_version) {
            if enforce {
                return Err(ReceiptError::UnsupportedVersion {
                    version: self.receipt_version,
                    supported: SUPPORTED_RECEIPT_VERSIONS.to_vec(),
                });
            }
            return Ok(());
        }

        // Check payload kind
        if !SUPPORTED_PAYLOAD_KINDS.contains(&self.payload_kind.as_str()) {
            if enforce {
                return Err(ReceiptError::UnsupportedPayloadKind {
                    kind: self.payload_kind.clone(),
                    supported: SUPPORTED_PAYLOAD_KINDS
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect(),
                });
            }
            return Ok(());
        }

        // Check payload schema version
        if !SUPPORTED_PAYLOAD_SCHEMA_VERSIONS.contains(&self.payload_schema_version) {
            if enforce {
                return Err(ReceiptError::UnsupportedPayloadSchemaVersion {
                    version: self.payload_schema_version,
                    supported: SUPPORTED_PAYLOAD_SCHEMA_VERSIONS.to_vec(),
                });
            }
            return Ok(());
        }

        Ok(())
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`GateReceipt`] instances.
#[derive(Debug, Default)]
pub struct GateReceiptBuilder {
    receipt_id: String,
    gate_id: String,
    lease_id: String,
    changeset_digest: Option<[u8; 32]>,
    executor_actor_id: Option<String>,
    receipt_version: Option<u32>,
    payload_kind: Option<String>,
    payload_schema_version: Option<u32>,
    payload_hash: Option<[u8; 32]>,
    evidence_bundle_hash: Option<[u8; 32]>,
    job_spec_digest: Option<String>,
    passed: Option<bool>,
}

impl GateReceiptBuilder {
    /// Creates a new builder with required IDs.
    #[must_use]
    pub fn new(
        receipt_id: impl Into<String>,
        gate_id: impl Into<String>,
        lease_id: impl Into<String>,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            gate_id: gate_id.into(),
            lease_id: lease_id.into(),
            ..Default::default()
        }
    }

    /// Sets the changeset digest.
    #[must_use]
    pub const fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the executor actor ID.
    #[must_use]
    pub fn executor_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.executor_actor_id = Some(actor_id.into());
        self
    }

    /// Sets the receipt envelope version.
    #[must_use]
    pub const fn receipt_version(mut self, version: u32) -> Self {
        self.receipt_version = Some(version);
        self
    }

    /// Sets the payload kind.
    #[must_use]
    pub fn payload_kind(mut self, kind: impl Into<String>) -> Self {
        self.payload_kind = Some(kind.into());
        self
    }

    /// Sets the payload schema version.
    #[must_use]
    pub const fn payload_schema_version(mut self, version: u32) -> Self {
        self.payload_schema_version = Some(version);
        self
    }

    /// Sets the payload hash.
    #[must_use]
    pub const fn payload_hash(mut self, hash: [u8; 32]) -> Self {
        self.payload_hash = Some(hash);
        self
    }

    /// Sets the evidence bundle hash.
    #[must_use]
    pub const fn evidence_bundle_hash(mut self, hash: [u8; 32]) -> Self {
        self.evidence_bundle_hash = Some(hash);
        self
    }

    /// Sets the optional job spec digest.
    #[must_use]
    pub fn job_spec_digest(mut self, digest: impl Into<String>) -> Self {
        self.job_spec_digest = Some(digest.into());
        self
    }

    /// Sets the explicit pass/fail verdict.
    ///
    /// This is the authoritative verdict field that the orchestrator reads
    /// directly. Receipts MUST declare their verdict explicitly rather than
    /// relying on hash-based inference (TCK-00388 Quality BLOCKER 2).
    #[must_use]
    pub const fn passed(mut self, passed: bool) -> Self {
        self.passed = Some(passed);
        self
    }

    /// Builds the receipt and signs it with the provided signer.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing.
    #[must_use]
    pub fn build_and_sign(self, signer: &crate::crypto::Signer) -> GateReceipt {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::MissingField`] if any required field is not set.
    /// Returns [`ReceiptError::StringTooLong`] if any string field exceeds the
    /// maximum length.
    #[allow(clippy::too_many_lines)]
    pub fn try_build_and_sign(
        self,
        signer: &crate::crypto::Signer,
    ) -> Result<GateReceipt, ReceiptError> {
        let changeset_digest = self
            .changeset_digest
            .ok_or(ReceiptError::MissingField("changeset_digest"))?;
        let executor_actor_id = self
            .executor_actor_id
            .ok_or(ReceiptError::MissingField("executor_actor_id"))?;
        let receipt_version = self
            .receipt_version
            .ok_or(ReceiptError::MissingField("receipt_version"))?;
        let payload_kind = self
            .payload_kind
            .ok_or(ReceiptError::MissingField("payload_kind"))?;
        let payload_schema_version = self
            .payload_schema_version
            .ok_or(ReceiptError::MissingField("payload_schema_version"))?;
        let payload_hash = self
            .payload_hash
            .ok_or(ReceiptError::MissingField("payload_hash"))?;
        let evidence_bundle_hash = self
            .evidence_bundle_hash
            .ok_or(ReceiptError::MissingField("evidence_bundle_hash"))?;
        let passed = self.passed.ok_or(ReceiptError::MissingField("passed"))?;
        let job_spec_digest = self.job_spec_digest;

        if let Some(ref digest) = job_spec_digest {
            if !digest.starts_with("b3-256:") || digest.len() != 71 {
                return Err(ReceiptError::InvalidData(format!(
                    "job_spec_digest must be 'b3-256:<64 hex chars>', got length {}",
                    digest.len()
                )));
            }
        }

        // Validate string lengths to prevent DoS
        if self.receipt_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "receipt_id",
                actual: self.receipt_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.gate_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "gate_id",
                actual: self.gate_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.lease_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "lease_id",
                actual: self.lease_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if executor_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "executor_actor_id",
                actual: executor_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if payload_kind.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "payload_kind",
                actual: payload_kind.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Create receipt with placeholder signature
        let mut receipt = GateReceipt {
            receipt_id: self.receipt_id,
            gate_id: self.gate_id,
            lease_id: self.lease_id,
            changeset_digest,
            executor_actor_id,
            receipt_version,
            payload_kind,
            payload_schema_version,
            payload_hash,
            evidence_bundle_hash,
            job_spec_digest,
            passed,
            receipt_signature: [0u8; 64],
        };

        // Sign the canonical bytes
        let canonical = receipt.canonical_bytes();
        let signature = sign_with_domain(signer, GATE_RECEIPT_PREFIX, &canonical);
        receipt.receipt_signature = signature.to_bytes();

        Ok(receipt)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

impl TryFrom<GateReceiptProto> for GateReceipt {
    type Error = ReceiptError;

    fn try_from(proto: GateReceiptProto) -> Result<Self, Self::Error> {
        // Validate string lengths to prevent DoS
        if proto.receipt_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "receipt_id",
                actual: proto.receipt_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.gate_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "gate_id",
                actual: proto.gate_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.lease_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "lease_id",
                actual: proto.lease_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.executor_actor_id.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "executor_actor_id",
                actual: proto.executor_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if proto.payload_kind.len() > MAX_STRING_LENGTH {
            return Err(ReceiptError::StringTooLong {
                field: "payload_kind",
                actual: proto.payload_kind.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let changeset_digest: [u8; 32] = proto.changeset_digest.try_into().map_err(|_| {
            ReceiptError::InvalidData("changeset_digest must be 32 bytes".to_string())
        })?;

        let payload_hash: [u8; 32] = proto
            .payload_hash
            .try_into()
            .map_err(|_| ReceiptError::InvalidData("payload_hash must be 32 bytes".to_string()))?;

        let evidence_bundle_hash: [u8; 32] =
            proto.evidence_bundle_hash.try_into().map_err(|_| {
                ReceiptError::InvalidData("evidence_bundle_hash must be 32 bytes".to_string())
            })?;
        let job_spec_digest = proto.job_spec_digest;

        let receipt_signature: [u8; 64] = proto.receipt_signature.try_into().map_err(|_| {
            ReceiptError::InvalidData("receipt_signature must be 64 bytes".to_string())
        })?;

        Ok(Self {
            receipt_id: proto.receipt_id,
            gate_id: proto.gate_id,
            lease_id: proto.lease_id,
            changeset_digest,
            executor_actor_id: proto.executor_actor_id,
            receipt_version: proto.receipt_version,
            payload_kind: proto.payload_kind,
            payload_schema_version: proto.payload_schema_version,
            payload_hash,
            evidence_bundle_hash,
            job_spec_digest,
            passed: proto.passed,
            receipt_signature,
        })
    }
}

impl From<GateReceipt> for GateReceiptProto {
    fn from(receipt: GateReceipt) -> Self {
        Self {
            receipt_id: receipt.receipt_id,
            gate_id: receipt.gate_id,
            lease_id: receipt.lease_id,
            changeset_digest: receipt.changeset_digest.to_vec(),
            executor_actor_id: receipt.executor_actor_id,
            receipt_version: receipt.receipt_version,
            payload_kind: receipt.payload_kind,
            payload_schema_version: receipt.payload_schema_version,
            payload_hash: receipt.payload_hash.to_vec(),
            evidence_bundle_hash: receipt.evidence_bundle_hash.to_vec(),
            job_spec_digest: receipt.job_spec_digest,
            receipt_signature: receipt.receipt_signature.to_vec(),
            // HTF time envelope reference (RFC-0016): not yet populated by this conversion.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
            passed: receipt.passed,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use prost::Message;

    use super::*;
    use crate::crypto::Signer;
    use crate::fac::LaneCleanupOutcome;

    fn sample_fac_receipt(
        outcome: FacJobOutcome,
        denial_reason: Option<DenialReasonCode>,
    ) -> Result<FacJobReceiptV1, FacJobReceiptError> {
        let mut builder = FacJobReceiptV1Builder::new(
            "receipt-job-001",
            "job-001",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .outcome(outcome)
        .reason("sample reason")
        .timestamp_secs(1_700_000_000)
        .rfc0028_channel_boundary(ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        });

        match outcome {
            FacJobOutcome::Completed => {
                builder = builder
                    .eio29_queue_admission(QueueAdmissionTrace {
                        verdict: "allow".to_string(),
                        queue_lane: "bulk".to_string(),
                        defect_reason: None,
                    })
                    .eio29_budget_admission(BudgetAdmissionTrace {
                        verdict: "allow".to_string(),
                        reason: None,
                    });
            },
            FacJobOutcome::Denied
            | FacJobOutcome::Quarantined
            | FacJobOutcome::Cancelled
            | FacJobOutcome::CancellationRequested => {
                if let Some(reason) = denial_reason {
                    builder = builder.denial_reason(reason);
                }
            },
        }

        builder.try_build()
    }

    fn make_valid_receipt() -> FacJobReceiptV1 {
        sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample fac receipt")
    }

    fn sample_cleanup_receipt(outcome: LaneCleanupOutcome) -> LaneCleanupReceiptV1 {
        LaneCleanupReceiptV1 {
            schema: LANE_CLEANUP_RECEIPT_SCHEMA.to_string(),
            receipt_id: "cleanup-001".to_string(),
            lane_id: "lane-00".to_string(),
            outcome,
            steps_completed: vec!["git_reset".to_string(), "git_clean".to_string()],
            failure_reason: if matches!(outcome, LaneCleanupOutcome::Failed) {
                Some("failed to clean".to_string())
            } else {
                None
            },
            timestamp_secs: 1_700_000_000,
            content_hash: String::new(),
        }
    }

    #[test]
    fn test_fac_job_receipt_canonical_bytes_deterministic() {
        let first =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        let second =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");

        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    }

    #[test]
    fn test_fac_job_receipt_canonical_bytes_collision_resistance() {
        let first =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        let mut second =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        second.receipt_id.push('x');

        assert_ne!(first.canonical_bytes(), second.canonical_bytes());
    }

    #[test]
    fn test_fac_job_receipt_deserialize_roundtrip() {
        let original =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");

        let bytes = serde_json::to_vec(&original).expect("serialize sample receipt");
        let restored = deserialize_job_receipt(&bytes).expect("deserialize receipt");

        assert_eq!(restored, original);
    }

    #[test]
    fn test_fac_job_receipt_unsafe_direct_roundtrip() {
        let mut original =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        original.unsafe_direct = true;

        let bytes = serde_json::to_vec(&original).expect("serialize unsafe_direct receipt");
        let restored = deserialize_job_receipt(&bytes).expect("deserialize unsafe_direct receipt");

        assert!(restored.unsafe_direct);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_fac_job_receipt_unsafe_direct_does_not_affect_canonical_bytes() {
        let base =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        let mut direct = base.clone();
        direct.unsafe_direct = true;

        // `unsafe_direct` is excluded from v1 canonical bytes so that
        // existing v1 content hashes remain stable.
        assert_eq!(
            base.canonical_bytes(),
            direct.canonical_bytes(),
            "v1 canonical_bytes must be identical regardless of unsafe_direct"
        );
    }

    #[test]
    fn test_fac_job_receipt_unsafe_direct_affects_v2_canonical_bytes() {
        let base =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        let mut direct = base.clone();
        direct.unsafe_direct = true;

        // V2 canonical bytes include `unsafe_direct` for integrity binding.
        assert_ne!(
            base.canonical_bytes_v2(),
            direct.canonical_bytes_v2(),
            "v2 canonical_bytes must differ when unsafe_direct differs"
        );
    }

    #[test]
    fn test_canonical_bytes_v2_includes_moved_job_path() {
        let mut r = make_valid_receipt();
        r.moved_job_path = None;
        let hash_none = r.canonical_bytes_v2();

        r.moved_job_path = Some("quarantine/job-001.json".to_string());
        let hash_some = r.canonical_bytes_v2();

        assert_ne!(
            hash_none, hash_some,
            "v2 hash must change when moved_job_path is set"
        );

        r.moved_job_path = Some("quarantine/job-002.json".to_string());
        let hash_different = r.canonical_bytes_v2();

        assert_ne!(
            hash_some, hash_different,
            "v2 hash must change when moved_job_path value changes"
        );
    }

    #[test]
    fn test_fac_job_receipt_v2_content_hash_differs_from_v1() {
        let receipt =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");

        let v1_hash = compute_job_receipt_content_hash(&receipt);
        let v2_hash = compute_job_receipt_content_hash_v2(&receipt);

        // Different domain separators → different hashes even for
        // identical `unsafe_direct=false` content.
        assert_ne!(
            v1_hash, v2_hash,
            "v1 and v2 hashes must differ due to domain separation"
        );
    }

    #[test]
    fn test_fac_job_receipt_v2_canonical_bytes_deterministic() {
        let first =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        let second =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");

        assert_eq!(first.canonical_bytes_v2(), second.canonical_bytes_v2());
    }

    #[test]
    fn test_cleanup_receipt_canonical_bytes_deterministic() {
        let first = sample_cleanup_receipt(LaneCleanupOutcome::Success);
        let second = sample_cleanup_receipt(LaneCleanupOutcome::Success);
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    }

    #[test]
    fn test_cleanup_receipt_validate_rejects_too_many_steps() {
        let mut receipt = sample_cleanup_receipt(LaneCleanupOutcome::Success);
        receipt.steps_completed = (0..=MAX_CLEANUP_STEPS)
            .map(|idx| format!("step-{idx}"))
            .collect();

        assert!(matches!(
            receipt.validate(),
            Err(LaneCleanupReceiptError::StringTooLong {
                field: "steps_completed",
                ..
            })
        ));
    }

    #[test]
    fn test_cleanup_receipt_persist_creates_file_with_content_hash() {
        let dir = tempfile::tempdir().expect("temp dir");
        let receipt = sample_cleanup_receipt(LaneCleanupOutcome::Success);
        let path = receipt.persist(dir.path(), 1_700_000_001).expect("persist");

        assert!(path.exists(), "receipt file must exist after persist");
        let content = std::fs::read_to_string(&path).expect("read receipt");
        let parsed: LaneCleanupReceiptV1 =
            serde_json::from_str(&content).expect("parse persisted receipt");
        assert!(!parsed.content_hash.is_empty());
        assert!(parsed.content_hash.starts_with("b3-256:"));
        assert_eq!(parsed.timestamp_secs, 1_700_000_001);
    }

    #[cfg(unix)]
    #[test]
    fn test_cleanup_receipt_persist_sets_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let receipt = sample_cleanup_receipt(LaneCleanupOutcome::Success);
        let path = receipt.persist(dir.path(), 1_700_000_002).expect("persist");

        let metadata = std::fs::metadata(&path).expect("metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "receipt file must have 0o600 permissions, got {mode:#o}"
        );
    }

    #[test]
    fn test_cleanup_receipt_persist_failed_outcome() {
        let dir = tempfile::tempdir().expect("temp dir");
        let receipt = sample_cleanup_receipt(LaneCleanupOutcome::Failed);
        let path = receipt.persist(dir.path(), 1_700_000_003).expect("persist");

        let content = std::fs::read_to_string(&path).expect("read receipt");
        let parsed: LaneCleanupReceiptV1 =
            serde_json::from_str(&content).expect("parse persisted receipt");
        assert_eq!(parsed.outcome, LaneCleanupOutcome::Failed);
        assert!(parsed.failure_reason.is_some());
    }

    #[test]
    fn test_fac_job_receipt_validate_rejects_oversized_strings() {
        let mut receipt =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        receipt.schema = "x".repeat(MAX_STRING_LENGTH + 1);

        assert!(matches!(
            receipt.validate(),
            Err(FacJobReceiptError::StringTooLong {
                field: "schema",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_rejects_oversized_moved_job_path() {
        let mut receipt = make_valid_receipt();
        receipt.moved_job_path = Some("x".repeat(MAX_STRING_LENGTH + 1));
        let bytes = receipt.canonical_bytes();
        receipt.content_hash = format!("b3-256:{}", blake3::hash(&bytes).to_hex());
        assert!(matches!(
            receipt.validate(),
            Err(FacJobReceiptError::StringTooLong {
                field: "moved_job_path",
                ..
            })
        ));
    }

    #[test]
    fn test_fac_job_receipt_validate_rejects_invalid_policy_hash() {
        let mut receipt =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        receipt.policy_hash = Some("not-a-digest".to_string());

        assert!(matches!(
            receipt.validate(),
            Err(FacJobReceiptError::InvalidData { .. })
        ));
    }

    #[test]
    fn test_fac_job_receipt_validate_rejects_missing_boundary_for_completed() {
        let mut receipt =
            sample_fac_receipt(FacJobOutcome::Completed, None).expect("sample completed receipt");
        receipt.rfc0028_channel_boundary = None;

        assert!(matches!(
            receipt.validate(),
            Err(FacJobReceiptError::MissingField("rfc0028_channel_boundary"))
        ));
    }

    #[test]
    fn test_fac_job_receipt_builder_requires_completion_boundary_trace() {
        let result = FacJobReceiptV1Builder::new(
            "receipt-job-002",
            "job-002",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .outcome(FacJobOutcome::Completed)
        .reason("ok")
        .timestamp_secs(1_700_000_001)
        .eio29_queue_admission(QueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: None,
        })
        .try_build();

        assert!(matches!(
            result,
            Err(FacJobReceiptError::MissingField("rfc0028_channel_boundary"))
        ));
    }

    #[test]
    fn test_fac_job_receipt_builder_requires_queue_admission_trace() {
        let result = FacJobReceiptV1Builder::new(
            "receipt-job-003",
            "job-003",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .outcome(FacJobOutcome::Completed)
        .reason("ok")
        .timestamp_secs(1_700_000_002)
        .rfc0028_channel_boundary(ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        })
        .try_build();

        assert!(matches!(
            result,
            Err(FacJobReceiptError::MissingField("eio29_queue_admission"))
        ));
    }

    #[test]
    fn test_fac_job_receipt_builder_allows_missing_budget_admission_trace_for_completed() {
        let result = FacJobReceiptV1Builder::new(
            "receipt-job-006",
            "job-006",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .outcome(FacJobOutcome::Completed)
        .reason("ok")
        .timestamp_secs(1_700_000_003)
        .rfc0028_channel_boundary(ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        })
        .eio29_queue_admission(QueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: None,
        })
        .try_build();

        assert!(
            result.is_ok(),
            "budget admission should be optional for completed outcomes"
        );
    }

    #[test]
    fn test_fac_job_receipt_builder_includes_moved_job_path() {
        let moved_job_path = "queue/quarantine/job-007.json";
        let receipt = FacJobReceiptV1Builder::new(
            "receipt-job-007",
            "job-007",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .outcome(FacJobOutcome::Denied)
        .denial_reason(DenialReasonCode::MalformedSpec)
        .reason("test moved")
        .moved_job_path(moved_job_path)
        .timestamp_secs(1_700_000_005)
        .rfc0028_channel_boundary(ChannelBoundaryTrace {
            passed: false,
            defect_count: 1,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        })
        .eio29_queue_admission(QueueAdmissionTrace {
            verdict: "deny".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: Some("quarantine required".to_string()),
        })
        .try_build()
        .expect("receipt with moved_job_path");

        assert_eq!(receipt.moved_job_path.as_deref(), Some(moved_job_path));
        let bytes = receipt.canonical_bytes();
        assert!(
            bytes
                .windows(moved_job_path.len())
                .any(|window| window == moved_job_path.as_bytes()),
            "moved path should be encoded in canonical bytes"
        );
    }

    #[test]
    fn test_fac_job_receipt_builder_requires_denial_reason() {
        let result = FacJobReceiptV1Builder::new(
            "receipt-job-004",
            "job-004",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .outcome(FacJobOutcome::Denied)
        .reason("not allowed")
        .rfc0028_channel_boundary(ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        })
        .eio29_queue_admission(QueueAdmissionTrace {
            verdict: "deny".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: Some("missing authority".to_string()),
        })
        .try_build();

        assert!(matches!(
            result,
            Err(FacJobReceiptError::MissingField("denial_reason"))
        ));
    }

    #[test]
    fn test_fac_job_receipt_builder_rejects_invalid_policy_hash() {
        let result = FacJobReceiptV1Builder::new(
            "receipt-job-007",
            "job-007",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .policy_hash("x")
        .outcome(FacJobOutcome::Completed)
        .reason("ok")
        .timestamp_secs(1_700_000_004)
        .rfc0028_channel_boundary(ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        })
        .eio29_queue_admission(QueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: None,
        })
        .try_build();

        assert!(matches!(
            result,
            Err(FacJobReceiptError::InvalidData { .. })
        ));
    }

    #[test]
    fn test_fac_job_outcome_serializes_snake_case() {
        let completed =
            serde_json::to_string(&FacJobOutcome::Completed).expect("serialize completed outcome");
        assert_eq!(completed, "\"completed\"");
        let denied =
            serde_json::to_string(&FacJobOutcome::Denied).expect("serialize denied outcome");
        assert_eq!(denied, "\"denied\"");
        let quarantined = serde_json::to_string(&FacJobOutcome::Quarantined)
            .expect("serialize quarantined outcome");
        assert_eq!(quarantined, "\"quarantined\"");
    }

    #[test]
    fn test_denial_reason_code_serializes_snake_case() {
        let map = [
            (DenialReasonCode::MalformedSpec, "\"malformed_spec\""),
            (DenialReasonCode::DigestMismatch, "\"digest_mismatch\""),
            (
                DenialReasonCode::MissingChannelToken,
                "\"missing_channel_token\"",
            ),
            (
                DenialReasonCode::TokenDecodeFailed,
                "\"token_decode_failed\"",
            ),
            (
                DenialReasonCode::ChannelBoundaryViolation,
                "\"channel_boundary_violation\"",
            ),
            (
                DenialReasonCode::AdmissionHealthGateFailed,
                "\"admission_health_gate_failed\"",
            ),
            (
                DenialReasonCode::QueueAdmissionDenied,
                "\"queue_admission_denied\"",
            ),
            (
                DenialReasonCode::BudgetAdmissionDenied,
                "\"budget_admission_denied\"",
            ),
            (
                DenialReasonCode::AuthorityAlreadyConsumed,
                "\"authority_already_consumed\"",
            ),
            (
                DenialReasonCode::PcacConsumeFailed,
                "\"pcac_consume_failed\"",
            ),
            (
                DenialReasonCode::LaneAcquisitionFailed,
                "\"lane_acquisition_failed\"",
            ),
            (DenialReasonCode::ValidationFailed, "\"validation_failed\""),
            (
                DenialReasonCode::InsufficientDiskSpace,
                "\"insufficient_disk_space\"",
            ),
            (
                DenialReasonCode::InvalidCanonicalizerDigest,
                "\"invalid_canonicalizer_digest\"",
            ),
        ];

        for (variant, expected) in map {
            assert_eq!(
                serde_json::to_string(&variant).expect("serialize reason"),
                expected
            );
        }
    }

    #[test]
    fn test_fac_job_receipt_builder_enforces_reason_bound() {
        let long_reason = "x".repeat(MAX_FAC_JOB_REASON_LENGTH + 1);
        let result = FacJobReceiptV1Builder::new(
            "receipt-job-005",
            "job-005",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .outcome(FacJobOutcome::Quarantined)
        .denial_reason(DenialReasonCode::MalformedSpec)
        .reason(long_reason)
        .rfc0028_channel_boundary(ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        })
        .eio29_queue_admission(QueueAdmissionTrace {
            verdict: "deny".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: Some("denied".to_string()),
        })
        .try_build();

        assert!(matches!(
            result,
            Err(FacJobReceiptError::StringTooLong {
                field: "reason",
                ..
            })
        ));
    }

    fn create_test_receipt(signer: &Signer) -> GateReceipt {
        GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .build_and_sign(signer)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn legacy_gate_receipt_bytes_without_job_spec(receipt: &GateReceipt) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(receipt.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(receipt.receipt_id.as_bytes());
        bytes.extend_from_slice(&(receipt.gate_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(receipt.gate_id.as_bytes());
        bytes.extend_from_slice(&(receipt.lease_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(receipt.lease_id.as_bytes());
        bytes.extend_from_slice(&receipt.changeset_digest);
        bytes.extend_from_slice(&(receipt.executor_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(receipt.executor_actor_id.as_bytes());
        bytes.extend_from_slice(&receipt.receipt_version.to_be_bytes());
        bytes.extend_from_slice(&(receipt.payload_kind.len() as u32).to_be_bytes());
        bytes.extend_from_slice(receipt.payload_kind.as_bytes());
        bytes.extend_from_slice(&receipt.payload_schema_version.to_be_bytes());
        bytes.extend_from_slice(&receipt.payload_hash);
        bytes.extend_from_slice(&receipt.evidence_bundle_hash);
        bytes.push(u8::from(receipt.passed));
        bytes
    }

    #[test]
    fn test_build_and_sign() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        assert_eq!(receipt.receipt_id, "receipt-001");
        assert_eq!(receipt.gate_id, "gate-aat");
        assert_eq!(receipt.lease_id, "lease-001");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.executor_actor_id, "executor-001");
        assert_eq!(receipt.receipt_version, 1);
        assert_eq!(receipt.payload_kind, "aat");
        assert_eq!(receipt.payload_schema_version, 1);
        assert_eq!(receipt.payload_hash, [0xAB; 32]);
        assert_eq!(receipt.evidence_bundle_hash, [0xCD; 32]);
    }

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
        receipt.gate_id = "gate-other".to_string();

        // Signature should now be invalid
        assert!(receipt.validate_signature(&signer.verifying_key()).is_err());
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
    fn test_canonical_bytes_without_job_spec_digest_matches_v1() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        assert_eq!(
            receipt.canonical_bytes(),
            legacy_gate_receipt_bytes_without_job_spec(&receipt)
        );
    }

    #[test]
    fn test_missing_field_error() {
        let signer = Signer::generate();

        // Missing changeset_digest
        let result = GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ReceiptError::MissingField("changeset_digest"))
        ));
    }

    #[test]
    fn test_builder_rejects_invalid_job_spec_digest() {
        let signer = Signer::generate();
        let bad_digest = "b3-256:not-a-valid-digest";

        let result = GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .job_spec_digest(bad_digest)
            .passed(true)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ReceiptError::InvalidData(message)) if message.contains("job_spec_digest")
        ));
    }

    #[test]
    fn test_domain_separator_prevents_replay() {
        // Verify that receipt uses GATE_RECEIPT: domain separator
        // by ensuring a signature created without the prefix fails
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Create a signature without domain prefix
        let canonical = receipt.canonical_bytes();
        let wrong_signature = signer.sign(&canonical); // No domain prefix!

        // Manually create a receipt with the wrong signature
        let mut bad_receipt = receipt;
        bad_receipt.receipt_signature = wrong_signature.to_bytes();

        // Verification should fail
        assert!(
            bad_receipt
                .validate_signature(&signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_length_prefixed_canonicalization_prevents_collision() {
        let signer = Signer::generate();

        // Create two receipts with different field values that could collide
        // with null-termination but not with length-prefixing
        let receipt1 = GateReceiptBuilder::new("ab", "cd", "ef")
            .changeset_digest([0x42; 32])
            .executor_actor_id("gh")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .build_and_sign(&signer);

        // "ab" + "cd" should NOT equal "a" + "bcd" with length-prefixing
        let receipt2 = GateReceiptBuilder::new("a", "bcd", "ef")
            .changeset_digest([0x42; 32])
            .executor_actor_id("gh")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .build_and_sign(&signer);

        // Canonical bytes should be different
        assert_ne!(receipt1.canonical_bytes(), receipt2.canonical_bytes());
    }

    // =========================================================================
    // Version Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_version_supported_version() {
        let signer = Signer::generate();
        let receipt = create_test_receipt(&signer);

        // Enforce mode - valid receipt should return Ok(())
        assert!(receipt.validate_version(true).is_ok());

        // Permissive mode - valid receipt should return Ok(())
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_validate_version_unsupported_version_enforce() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.receipt_version = 999; // Unsupported version

        let result = receipt.validate_version(true);
        assert!(matches!(
            result,
            Err(ReceiptError::UnsupportedVersion { version: 999, .. })
        ));
    }

    #[test]
    fn test_validate_version_unsupported_version_permissive() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.receipt_version = 999; // Unsupported version

        // Permissive mode: returns Ok(()) even for unsupported versions
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_validate_version_unsupported_payload_kind_enforce() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.payload_kind = "unknown".to_string(); // Unsupported kind

        let result = receipt.validate_version(true);
        assert!(matches!(
            result,
            Err(ReceiptError::UnsupportedPayloadKind { kind, .. }) if kind == "unknown"
        ));
    }

    #[test]
    fn test_validate_version_unsupported_payload_kind_permissive() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.payload_kind = "unknown".to_string(); // Unsupported kind

        // Permissive mode: returns Ok(()) even for unsupported payload kinds
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_validate_version_unsupported_payload_schema_version_enforce() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.payload_schema_version = 999; // Unsupported payload schema version

        let result = receipt.validate_version(true);
        assert!(matches!(
            result,
            Err(ReceiptError::UnsupportedPayloadSchemaVersion { version: 999, .. })
        ));
    }

    #[test]
    fn test_validate_version_unsupported_payload_schema_version_permissive() {
        let signer = Signer::generate();
        let mut receipt = create_test_receipt(&signer);
        receipt.payload_schema_version = 999; // Unsupported payload schema version

        // Permissive mode: returns Ok(()) even for unsupported payload schema versions
        assert!(receipt.validate_version(false).is_ok());
    }

    #[test]
    fn test_all_supported_payload_kinds() {
        let signer = Signer::generate();

        for kind in SUPPORTED_PAYLOAD_KINDS {
            let receipt = GateReceiptBuilder::new("receipt-001", "gate-test", "lease-001")
                .changeset_digest([0x42; 32])
                .executor_actor_id("executor-001")
                .receipt_version(1)
                .payload_kind(*kind)
                .payload_schema_version(1)
                .payload_hash([0xAB; 32])
                .evidence_bundle_hash([0xCD; 32])
                .passed(true)
                .build_and_sign(&signer);

            assert!(
                receipt.validate_version(true).is_ok(),
                "payload_kind '{kind}' should be supported"
            );
        }
    }

    #[test]
    fn test_supported_receipt_versions_constant() {
        // Verify version 1 is supported
        assert!(SUPPORTED_RECEIPT_VERSIONS.contains(&1));
    }

    #[test]
    fn test_supported_payload_kinds_constant() {
        // Verify expected payload kinds
        assert!(SUPPORTED_PAYLOAD_KINDS.contains(&"aat"));
        assert!(SUPPORTED_PAYLOAD_KINDS.contains(&"quality"));
        assert!(SUPPORTED_PAYLOAD_KINDS.contains(&"security"));
    }

    #[test]
    fn test_supported_payload_schema_versions_constant() {
        // Verify version 1 is supported
        assert!(SUPPORTED_PAYLOAD_SCHEMA_VERSIONS.contains(&1));
    }

    // =========================================================================
    // Proto Roundtrip Tests
    // =========================================================================

    #[test]
    fn test_proto_roundtrip() {
        let signer = Signer::generate();
        let original = create_test_receipt(&signer);

        // Convert to proto
        let proto: GateReceiptProto = original.clone().into();

        // Encode and decode
        let encoded = proto.encode_to_vec();
        let decoded_proto = GateReceiptProto::decode(encoded.as_slice()).unwrap();

        // Convert back to domain type
        let recovered = GateReceipt::try_from(decoded_proto).unwrap();

        // Fields should match
        assert_eq!(original.receipt_id, recovered.receipt_id);
        assert_eq!(original.gate_id, recovered.gate_id);
        assert_eq!(original.lease_id, recovered.lease_id);
        assert_eq!(original.changeset_digest, recovered.changeset_digest);
        assert_eq!(original.executor_actor_id, recovered.executor_actor_id);
        assert_eq!(original.receipt_version, recovered.receipt_version);
        assert_eq!(original.payload_kind, recovered.payload_kind);
        assert_eq!(
            original.payload_schema_version,
            recovered.payload_schema_version
        );
        assert_eq!(original.payload_hash, recovered.payload_hash);
        assert_eq!(
            original.evidence_bundle_hash,
            recovered.evidence_bundle_hash
        );
        assert_eq!(original.receipt_signature, recovered.receipt_signature);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_proto_roundtrip_with_job_spec_digest() {
        let signer = Signer::generate();
        let original = GateReceiptBuilder::new("receipt-001", "gate-aat", "lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .job_spec_digest(
                "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .passed(true)
            .build_and_sign(&signer);

        let proto: GateReceiptProto = original.clone().into();
        let encoded = proto.encode_to_vec();
        let decoded_proto = GateReceiptProto::decode(encoded.as_slice()).unwrap();
        let recovered = GateReceipt::try_from(decoded_proto).unwrap();

        assert_eq!(original.job_spec_digest, recovered.job_spec_digest);
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_invalid_proto_changeset_digest_length() {
        let proto = GateReceiptProto {
            receipt_id: "receipt-001".to_string(),
            gate_id: "gate-aat".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0x42; 16], // Wrong length - should be 32
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "aat".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0xAB; 32],
            evidence_bundle_hash: vec![0xCD; 32],
            job_spec_digest: None,
            receipt_signature: vec![0u8; 64],
            // HTF time envelope reference (RFC-0016): not yet populated.
            time_envelope_ref: None,
            passed: false,
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(result, Err(ReceiptError::InvalidData(_))));
    }

    #[test]
    fn test_invalid_proto_signature_length() {
        let proto = GateReceiptProto {
            receipt_id: "receipt-001".to_string(),
            gate_id: "gate-aat".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0x42; 32],
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "aat".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0xAB; 32],
            evidence_bundle_hash: vec![0xCD; 32],
            job_spec_digest: None,
            receipt_signature: vec![0u8; 32], // Wrong length - should be 64
            // HTF time envelope reference (RFC-0016): not yet populated.
            time_envelope_ref: None,
            passed: false,
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(result, Err(ReceiptError::InvalidData(_))));
    }

    #[test]
    fn test_string_too_long_rejected() {
        let signer = Signer::generate();
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = GateReceiptBuilder::new(long_string, "gate-aat", "lease-001")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .receipt_version(1)
            .payload_kind("aat")
            .payload_schema_version(1)
            .payload_hash([0xAB; 32])
            .evidence_bundle_hash([0xCD; 32])
            .passed(true)
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(ReceiptError::StringTooLong {
                field: "receipt_id",
                ..
            })
        ));
    }

    #[test]
    fn test_proto_string_too_long_rejected() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let proto = GateReceiptProto {
            receipt_id: long_string,
            gate_id: "gate-aat".to_string(),
            lease_id: "lease-001".to_string(),
            changeset_digest: vec![0x42; 32],
            executor_actor_id: "executor-001".to_string(),
            receipt_version: 1,
            payload_kind: "aat".to_string(),
            payload_schema_version: 1,
            payload_hash: vec![0xAB; 32],
            evidence_bundle_hash: vec![0xCD; 32],
            job_spec_digest: None,
            receipt_signature: vec![0u8; 64],
            // HTF time envelope reference (RFC-0016): not yet populated.
            time_envelope_ref: None,
            passed: false,
        };

        let result = GateReceipt::try_from(proto);
        assert!(matches!(
            result,
            Err(ReceiptError::StringTooLong {
                field: "receipt_id",
                ..
            })
        ));
    }

    // ========================================================================
    // Containment validation regression tests (MAJOR-1, MAJOR-2)
    // ========================================================================

    #[test]
    fn test_validate_rejects_oversized_containment_cgroup_path() {
        let mut receipt = make_valid_receipt();
        receipt.containment = Some(crate::fac::containment::ContainmentTrace {
            verified: true,
            cgroup_path: "x".repeat(crate::fac::containment::MAX_CGROUP_PATH_LENGTH + 1),
            processes_checked: 1,
            mismatch_count: 0,
            sccache_auto_disabled: false,
        });
        // Recompute content hash so other validations pass
        let bytes = receipt.canonical_bytes();
        receipt.content_hash = format!("b3-256:{}", blake3::hash(&bytes).to_hex());

        assert!(matches!(
            receipt.validate(),
            Err(FacJobReceiptError::StringTooLong {
                field: "containment.cgroup_path",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_accepts_valid_containment_trace() {
        let mut receipt = make_valid_receipt();
        receipt.containment = Some(crate::fac::containment::ContainmentTrace {
            verified: true,
            cgroup_path: "/system.slice/test.service".to_string(),
            processes_checked: 5,
            mismatch_count: 0,
            sccache_auto_disabled: false,
        });
        // Recompute content hash so hash validation passes
        let bytes = receipt.canonical_bytes();
        receipt.content_hash = format!("b3-256:{}", blake3::hash(&bytes).to_hex());

        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn test_canonical_bytes_v1_includes_containment_trace() {
        let mut r = make_valid_receipt();
        r.containment = None;
        let hash_none = r.canonical_bytes();

        r.containment = Some(crate::fac::containment::ContainmentTrace {
            verified: true,
            cgroup_path: "/system.slice/test.service".to_string(),
            processes_checked: 3,
            mismatch_count: 0,
            sccache_auto_disabled: false,
        });
        let hash_some = r.canonical_bytes();

        assert_ne!(
            hash_none, hash_some,
            "v1 canonical_bytes must change when containment trace is set"
        );
    }

    #[test]
    fn test_canonical_bytes_v1_containment_different_values_produce_different_hashes() {
        let mut r = make_valid_receipt();
        r.containment = Some(crate::fac::containment::ContainmentTrace {
            verified: true,
            cgroup_path: "/a".to_string(),
            processes_checked: 1,
            mismatch_count: 0,
            sccache_auto_disabled: false,
        });
        let hash_a = r.canonical_bytes();

        r.containment = Some(crate::fac::containment::ContainmentTrace {
            verified: false,
            cgroup_path: "/b".to_string(),
            processes_checked: 10,
            mismatch_count: 3,
            sccache_auto_disabled: true,
        });
        let hash_b = r.canonical_bytes();

        assert_ne!(
            hash_a, hash_b,
            "different containment values must produce different v1 hashes"
        );
    }

    #[test]
    fn test_canonical_bytes_v1_backward_compatible_without_containment() {
        // Verify that a receipt without containment produces the same
        // canonical bytes as before the TCK-00548 change.
        let r1 = make_valid_receipt();
        assert!(r1.containment.is_none());
        let bytes1 = r1.canonical_bytes();

        let r2 = make_valid_receipt();
        let bytes2 = r2.canonical_bytes();

        assert_eq!(
            bytes1, bytes2,
            "receipts without containment must produce identical v1 canonical bytes"
        );
    }

    #[test]
    fn test_canonical_bytes_v2_includes_containment_trace() {
        let mut r = make_valid_receipt();
        r.containment = None;
        let hash_none = r.canonical_bytes_v2();

        r.containment = Some(crate::fac::containment::ContainmentTrace {
            verified: true,
            cgroup_path: "/system.slice/test.service".to_string(),
            processes_checked: 3,
            mismatch_count: 0,
            sccache_auto_disabled: false,
        });
        let hash_some = r.canonical_bytes_v2();

        assert_ne!(
            hash_none, hash_some,
            "v2 canonical_bytes must change when containment trace is set"
        );
    }

    #[test]
    fn test_v1_canonical_bytes_no_collision_across_trailing_optional_fields() {
        // Regression test for BLOCKER f-705-security-1771265555805010-0:
        // Verify that different occupancy patterns for trailing optional fields
        // (moved_job_path, containment, observed_cost) always produce different
        // canonical bytes, preventing hash collisions in the integrity trail.
        let mut base = make_valid_receipt();
        base.moved_job_path = None;
        base.containment = None;
        base.observed_cost = None;
        let bytes_all_none = base.canonical_bytes();

        // moved_job_path set, containment None
        let mut r1 = base.clone();
        r1.moved_job_path = Some("quarantine/job.json".to_string());
        let bytes_moved_only = r1.canonical_bytes();

        // moved_job_path None, containment set
        let mut r2 = base.clone();
        r2.containment = Some(crate::fac::containment::ContainmentTrace {
            verified: true,
            cgroup_path: "quarantine/job.json".to_string(), // same string content
            processes_checked: 0,
            mismatch_count: 0,
            sccache_auto_disabled: false,
        });
        let bytes_containment_only = r2.canonical_bytes();

        // moved_job_path None, observed_cost set
        let mut r3 = base;
        r3.observed_cost = Some(crate::economics::cost_model::ObservedJobCost {
            duration_ms: 1000,
            cpu_time_ms: 500,
            bytes_written: 2000,
        });
        let bytes_cost_only = r3.canonical_bytes();

        // All four must be distinct (presence markers disambiguate).
        assert_ne!(
            bytes_all_none, bytes_moved_only,
            "all-None vs moved_job_path=Some must differ"
        );
        assert_ne!(
            bytes_all_none, bytes_containment_only,
            "all-None vs containment=Some must differ"
        );
        assert_ne!(
            bytes_all_none, bytes_cost_only,
            "all-None vs observed_cost=Some must differ"
        );
        assert_ne!(
            bytes_moved_only, bytes_containment_only,
            "moved_job_path=Some vs containment=Some must differ (collision prevented by presence markers)"
        );
        assert_ne!(
            bytes_moved_only, bytes_cost_only,
            "moved_job_path=Some vs observed_cost=Some must differ"
        );
        assert_ne!(
            bytes_containment_only, bytes_cost_only,
            "containment=Some vs observed_cost=Some must differ"
        );
    }

    #[test]
    fn test_v1_canonical_bytes_absence_marker_emitted_for_moved_job_path() {
        // Verify that moved_job_path=None emits a 0u8 presence marker.
        let mut r = make_valid_receipt();
        r.moved_job_path = None;
        r.containment = None;
        r.observed_cost = None;
        let bytes_none = r.canonical_bytes();

        r.moved_job_path = Some(String::new());
        let bytes_empty = r.canonical_bytes();

        // None (0u8) vs Some("") (1u8 + 0u32 length) must differ.
        assert_ne!(
            bytes_none, bytes_empty,
            "moved_job_path=None vs moved_job_path=Some('') must differ"
        );
    }

    #[test]
    fn test_v1_canonical_bytes_absence_marker_emitted_for_containment() {
        // Verify that containment=None emits a 0u8 presence marker.
        let mut r = make_valid_receipt();
        r.moved_job_path = None;
        r.containment = None;
        r.observed_cost = None;
        let bytes_none = r.canonical_bytes();

        r.containment = Some(crate::fac::containment::ContainmentTrace {
            verified: false,
            cgroup_path: String::new(),
            processes_checked: 0,
            mismatch_count: 0,
            sccache_auto_disabled: false,
        });
        let bytes_some = r.canonical_bytes();

        // None (0u8) vs Some(...) (1u8 + fields) must differ.
        assert_ne!(
            bytes_none, bytes_some,
            "containment=None vs containment=Some must differ"
        );
    }
}
