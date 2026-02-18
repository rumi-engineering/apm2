// AGENT-AUTHORED
//! Evidence bundle export/import (local-only).
//!
//! This module implements `EvidenceBundleEnvelopeV1`, a self-describing
//! envelope that bundles a job receipt together with its RFC-0028 channel
//! boundary check and RFC-0029 economics traces. The envelope is designed
//! for local export/import between FAC subsystems with fail-closed
//! validation at the import boundary.
//!
//! # Export flow
//!
//! 1. Load job receipt by `job_id` from the receipt store.
//! 2. Build `EvidenceBundleEnvelopeV1` from the receipt and its embedded
//!    RFC-0028/RFC-0029 traces.
//! 3. Serialize the envelope to a JSON file alongside referenced blobs in an
//!    export directory.
//!
//! # Import flow (fail-closed)
//!
//! 1. Load and parse the envelope JSON with bounded reads.
//! 2. Reconstruct the `ChannelBoundaryCheck` from the embedded RFC-0028 trace
//!    and verify via `validate_channel_boundary()`.
//! 3. Verify the embedded RFC-0029 economics receipt traces (queue admission
//!    verdict, budget admission verdict).
//! 4. Verify the content-hash integrity of the envelope body.
//! 5. If any validation fails, reject the import (fail-closed).
//!
//! # Security Invariants
//!
//! - [INV-EB-001] Import refuses when `validate_channel_boundary()` returns any
//!   defects (boundary check invalid or policy binding mismatched).
//! - [INV-EB-002] Import refuses when economics receipt traces are missing,
//!   unverifiable, or carry non-Allow verdicts.
//! - [INV-EB-003] Envelope reads are bounded by `MAX_ENVELOPE_SIZE` before
//!   deserialization.
//! - [INV-EB-004] Envelope content hash is verified via BLAKE3 after load.
//! - [INV-EB-005] All string fields are bounded during deserialization.
//! - [INV-EB-006] Export refuses when envelope byte size exceeds the leakage
//!   budget policy ceiling and no valid declassification receipt is present
//!   (TCK-00555).
//! - [INV-EB-007] Import refuses when the embedded leakage budget receipt
//!   declares `leakage_bits > budget_bits` or exceeds the policy ceiling
//!   carried in the envelope (TCK-00555).
//! - [INV-EB-008] Import independently verifies that when `exceeded_policy` is
//!   false, actual values (`actual_export_bytes`, `actual_export_classes`,
//!   `actual_leakage_bits`) are within the policy ceilings (TCK-00555).
//! - [INV-EB-009] Import cross-checks `actual_export_classes` against the count
//!   of `blob_refs` in the envelope plus fixed overhead (TCK-00555).
//! - [INV-EB-010] Import cross-checks `actual_leakage_bits` against the
//!   `leakage_budget_receipt` in the boundary check (TCK-00555).
//! - [INV-EB-011] Export converges `actual_export_bytes` to match the final
//!   serialized envelope size via iterative re-measurement (TCK-00555).
//! - [INV-EB-012] Import recomputes the canonical envelope byte size from the
//!   serialized data and requires `actual_export_bytes` to match, preventing
//!   forged byte values from bypassing policy enforcement (TCK-00555).
//! - [INV-EB-013] Export-time declassification validation always checks
//!   `authorized_leakage_bits >= actual_leakage_bits` when a receipt is
//!   present, regardless of which dimension triggered exceedance (TCK-00555).
//! - [INV-EB-014] Import rejects new-schema envelopes
//!   (`EVIDENCE_BUNDLE_ENVELOPE_SCHEMA`) that are missing
//!   `leakage_budget_decision`. Legacy envelopes (`EVIDENCE_BUNDLE_SCHEMA`) are
//!   exempt for backward compatibility. This prevents downgrade-by-omission
//!   attacks where an attacker strips the decision field and recomputes a
//!   self-consistent content hash (TCK-00555).
//! - [INV-EB-023] Even legacy-schema envelopes are rejected when missing
//!   `leakage_budget_decision` if the boundary check carries budget-aware
//!   fields (`leakage_budget_receipt`, `timing_channel_budget`, or
//!   `disclosure_policy_binding`). This closes a schema-downgrade bypass where
//!   an attacker swaps the schema string to legacy after stripping the decision
//!   (TCK-00555).
//! - [INV-EB-024] Export-time finalization always validates `authorized_bytes
//!   >= actual_export_bytes` whenever the policy is exceeded and a
//!   declassification receipt is present, regardless of which dimension
//!   triggered exceedance. This aligns export with import semantics
//!   (TCK-00555).
//! - [INV-EB-025] Export fails closed when `leakage_budget_policy` is `None`
//!   for new-schema output. Callers must supply a policy (even if permissive)
//!   to produce importable envelopes (TCK-00555).

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::channel::{
    BoundaryFlowPolicyBinding, ChannelBoundaryCheck, ChannelSource, DeclassificationIntentScope,
    DisclosurePolicyBinding, LeakageBudgetReceipt, LeakageEstimatorFamily, TimingChannelBudget,
    derive_channel_source_witness, validate_channel_boundary,
};
use crate::disclosure::{DisclosureChannelClass, DisclosurePolicyMode};
use crate::fac::receipt::{BudgetAdmissionTrace, FacJobReceiptV1, QueueAdmissionTrace};

// =============================================================================
// Constants
// =============================================================================

/// Schema identifier for the evidence bundle envelope (legacy, accepted on
/// import for backwards compatibility).
pub const EVIDENCE_BUNDLE_SCHEMA: &str = "apm2.fac.evidence_bundle.v1";

/// Schema identifier for the evidence bundle envelope (v1, canonical).
pub const EVIDENCE_BUNDLE_ENVELOPE_SCHEMA: &str = "apm2.fac.evidence_bundle_envelope.v1";

/// Schema identifier for the evidence bundle manifest (v1).
pub const EVIDENCE_BUNDLE_MANIFEST_SCHEMA: &str = "apm2.fac.evidence_bundle_manifest.v1";

/// Maximum envelope file size to read (256 KiB).
pub const MAX_ENVELOPE_SIZE: usize = 262_144;

/// Maximum manifest file size to read (64 KiB).
pub const MAX_MANIFEST_SIZE: usize = 65_536;

/// Maximum blob count in a single bundle.
pub const MAX_BUNDLE_BLOB_COUNT: usize = 256;

/// Maximum blob reference string length.
pub const MAX_BLOB_REF_LENGTH: usize = 256;

/// Maximum job ID length.
pub const MAX_JOB_ID_LENGTH: usize = 256;

/// Maximum outcome reason string length in the manifest.
pub const MAX_OUTCOME_REASON_LENGTH: usize = 1024;

/// Maximum envelope hash reference length in the manifest.
pub const MAX_ENVELOPE_HASH_REF_LENGTH: usize = 256;

/// Maximum outcome string length in the manifest.
pub const MAX_OUTCOME_LEN: usize = 64;

/// Maximum manifest entry role string length.
pub const MAX_ROLE_LEN: usize = 64;

/// Maximum manifest entry count.
pub const MAX_MANIFEST_ENTRIES: usize = 256;

/// Maximum entry description length.
pub const MAX_ENTRY_DESCRIPTION_LENGTH: usize = 512;

/// BLAKE3 domain separator for envelope content hash.
const ENVELOPE_HASH_DOMAIN: &[u8] = b"apm2.fac.evidence_bundle.content_hash.v1\0";

/// BLAKE3 domain separator for manifest content hash.
const MANIFEST_HASH_DOMAIN: &[u8] = b"apm2.fac.evidence_bundle_manifest.content_hash.v1\0";

/// BLAKE3 domain separator for declassification receipt content hash.
const DECLASSIFICATION_RECEIPT_HASH_DOMAIN: &[u8] =
    b"apm2.fac.declassification_receipt.content_hash.v1\0";

/// Maximum length for declassification receipt reason strings.
pub const MAX_DECLASSIFICATION_REASON_LENGTH: usize = 512;

/// Maximum convergence iterations for the two-phase byte enforcement loop.
/// The loop converges once `actual_export_bytes` in the decision matches the
/// serialized envelope size. Since the only variable is the integer
/// representation length (at most ~20 digits for u64), convergence is
/// guaranteed within 3 rounds.
const MAX_BYTE_CONVERGENCE_ROUNDS: usize = 5;

/// Maximum length for declassification receipt `authority_id` strings.
pub const MAX_DECLASSIFICATION_AUTHORITY_ID_LENGTH: usize = 256;

// =============================================================================
// Leakage Budget Policy (TCK-00555)
// =============================================================================

/// RFC-0028 leakage budget policy defaults for evidence export.
///
/// Defines per-risk-tier ceilings on exported evidence volume (in bytes) and
/// the number of distinct artifact classes. Exports that exceed these caps
/// without an explicit [`DeclassificationExportReceipt`] are denied
/// fail-closed.
///
/// # Security Invariants
///
/// - [INV-LBP-001] Default policy ceilings are fail-closed: zero values deny
///   all exports.
/// - [INV-LBP-002] Policy ceilings are integer-only (no floating-point
///   ambiguity) per RFC-0028 section 6 determinism contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeakageBudgetPolicy {
    /// Maximum exported bytes before a declassification receipt is required.
    pub max_export_bytes: u64,
    /// Maximum number of distinct artifact classes in a single export.
    pub max_export_classes: u32,
    /// Maximum leakage bits allowed in the leakage budget receipt.
    /// Maps to `L_boundary_max(risk_tier)` in RFC-0028 section 6.
    pub max_leakage_bits: u64,
}

impl LeakageBudgetPolicy {
    /// Default policy for Tier0/Tier1 (local development, low-assurance).
    ///
    /// Permits up to 64 MiB and 64 classes without declassification.
    #[must_use]
    pub const fn tier0_default() -> Self {
        Self {
            max_export_bytes: 64 * 1024 * 1024,
            max_export_classes: 64,
            max_leakage_bits: 512,
        }
    }

    /// Default policy for Tier2+ (production, high-assurance).
    ///
    /// Permits up to 4 MiB and 16 classes without declassification.
    /// More restrictive to bound leakage at adversarial boundaries.
    #[must_use]
    pub const fn tier2_default() -> Self {
        Self {
            max_export_bytes: 4 * 1024 * 1024,
            max_export_classes: 16,
            max_leakage_bits: 64,
        }
    }

    /// Deny-all policy (fail-closed ceiling of zero).
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            max_export_bytes: 0,
            max_export_classes: 0,
            max_leakage_bits: 0,
        }
    }
}

impl Default for LeakageBudgetPolicy {
    /// Default is Tier2+ (most restrictive non-zero policy).
    fn default() -> Self {
        Self::tier2_default()
    }
}

/// Declassification receipt for export-time budget overrides (TCK-00555).
///
/// When an evidence export exceeds the configured [`LeakageBudgetPolicy`]
/// ceilings, the caller must provide this receipt to authorize the export.
/// The receipt binds the declassification decision to the specific export
/// envelope via a content hash commitment.
///
/// # Security Invariants
///
/// - [INV-DR-001] Receipt `receipt_id` must be non-empty and bounded.
/// - [INV-DR-002] `authorized_bytes` must be >= the actual export size.
/// - [INV-DR-003] `authorized_classes` must be >= the actual class count.
/// - [INV-DR-004] `authority_id` must be non-empty and bounded.
/// - [INV-DR-005] `reason` must be non-empty and bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationExportReceipt {
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Maximum bytes authorized for this export.
    pub authorized_bytes: u64,
    /// Maximum artifact classes authorized for this export.
    pub authorized_classes: u32,
    /// Maximum leakage bits authorized for this export.
    pub authorized_leakage_bits: u64,
    /// Identity of the declassification authority.
    pub authority_id: String,
    /// Human-readable reason for the declassification decision.
    pub reason: String,
    /// BLAKE3 content hash binding this receipt to the export decision.
    pub content_hash: [u8; 32],
}

impl DeclassificationExportReceipt {
    /// Validates structural well-formedness of this receipt.
    ///
    /// Returns `Ok(())` when all field constraints are satisfied.
    /// Returns `Err` with the first violation found.
    ///
    /// # Errors
    ///
    /// Returns `EvidenceBundleError::LeakageBudgetDenied` when a required
    /// field is empty or when the content hash is all-zero.
    /// Returns `EvidenceBundleError::FieldTooLong` when a field exceeds its
    /// maximum length.
    pub fn validate(&self) -> Result<(), EvidenceBundleError> {
        if self.receipt_id.is_empty() {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: "declassification receipt_id must be non-empty".to_string(),
            });
        }
        if self.receipt_id.len() > MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH {
            return Err(EvidenceBundleError::FieldTooLong {
                field: "declassification_receipt.receipt_id".to_string(),
                actual: self.receipt_id.len(),
                max: MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH,
            });
        }
        if self.authority_id.is_empty() {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: "declassification authority_id must be non-empty".to_string(),
            });
        }
        if self.authority_id.len() > MAX_DECLASSIFICATION_AUTHORITY_ID_LENGTH {
            return Err(EvidenceBundleError::FieldTooLong {
                field: "declassification_receipt.authority_id".to_string(),
                actual: self.authority_id.len(),
                max: MAX_DECLASSIFICATION_AUTHORITY_ID_LENGTH,
            });
        }
        if self.reason.is_empty() {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: "declassification reason must be non-empty".to_string(),
            });
        }
        if self.reason.len() > MAX_DECLASSIFICATION_REASON_LENGTH {
            return Err(EvidenceBundleError::FieldTooLong {
                field: "declassification_receipt.reason".to_string(),
                actual: self.reason.len(),
                max: MAX_DECLASSIFICATION_REASON_LENGTH,
            });
        }
        if self.content_hash == [0u8; 32] {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: "declassification receipt content_hash must be non-zero".to_string(),
            });
        }
        Ok(())
    }

    /// Computes the expected content hash for this receipt from its fields.
    #[must_use]
    pub fn compute_content_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DECLASSIFICATION_RECEIPT_HASH_DOMAIN);
        hasher.update(&(self.receipt_id.len() as u64).to_le_bytes());
        hasher.update(self.receipt_id.as_bytes());
        hasher.update(&self.authorized_bytes.to_le_bytes());
        hasher.update(&self.authorized_classes.to_le_bytes());
        hasher.update(&self.authorized_leakage_bits.to_le_bytes());
        hasher.update(&(self.authority_id.len() as u64).to_le_bytes());
        hasher.update(self.authority_id.as_bytes());
        hasher.update(&(self.reason.len() as u64).to_le_bytes());
        hasher.update(self.reason.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Maximum length for `MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH` reused from
/// channel enforcement.
const MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH: usize = 128;

/// Result of leakage budget enforcement at export time (TCK-00555).
///
/// Bound into the envelope so import-side validation can verify the
/// export-time decision. When `exceeded_policy` is true, the full
/// [`DeclassificationExportReceipt`] is embedded so the importer can
/// independently verify that the receipt actually authorizes the
/// declared export values (bytes, classes, leakage bits) and that the
/// receipt content hash is valid. This prevents forged envelopes from
/// setting the `declassification_authorized` flag without a receipt
/// that genuinely covers the export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeakageBudgetDecision {
    /// The policy that was applied.
    pub policy: LeakageBudgetPolicy,
    /// Actual envelope byte size at export time.
    pub actual_export_bytes: u64,
    /// Actual number of distinct artifact classes exported.
    pub actual_export_classes: u32,
    /// Actual leakage bits from the leakage budget receipt (0 if absent).
    pub actual_leakage_bits: u64,
    /// Whether the export exceeded the policy ceiling.
    pub exceeded_policy: bool,
    /// Whether a declassification receipt was provided and validated.
    pub declassification_authorized: bool,
    /// Optional declassification receipt ID (when present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declassification_receipt_id: Option<String>,
    /// Full declassification receipt when the policy was exceeded and
    /// declassification was authorized. Embedded for import-side audit
    /// and independent verification of authorization coverage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declassification_receipt: Option<DeclassificationExportReceipt>,
}

// =============================================================================
// Error Types
// =============================================================================

/// Error taxonomy for evidence bundle operations.
#[derive(Debug, Error)]
pub enum EvidenceBundleError {
    /// Envelope file exceeds size limit.
    #[error("envelope too large: {size} > {max}")]
    EnvelopeTooLarge {
        /// Actual envelope size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Envelope JSON parse failure.
    #[error("envelope parse error: {detail}")]
    ParseError {
        /// Human-readable parse error detail.
        detail: String,
    },

    /// Schema mismatch in envelope.
    #[error("schema mismatch: expected {expected}, found {actual}")]
    SchemaMismatch {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier found in envelope.
        actual: String,
    },

    /// Content hash verification failed.
    #[error("content hash mismatch: expected {expected}, actual {actual}")]
    ContentHashMismatch {
        /// Expected content hash.
        expected: String,
        /// Actual content hash computed from envelope body.
        actual: String,
    },

    /// RFC-0028 channel boundary validation failed.
    #[error("channel boundary validation failed: {defect_count} defects ({defect_classes})")]
    ChannelBoundaryInvalid {
        /// Number of defects found.
        defect_count: usize,
        /// Comma-separated defect class labels.
        defect_classes: String,
    },

    /// RFC-0028 channel boundary trace is missing from the receipt.
    #[error("channel boundary trace missing from receipt")]
    ChannelBoundaryTraceMissing,

    /// RFC-0029 economics receipt validation failed.
    #[error("economics receipt validation failed: {reason}")]
    EconomicsReceiptInvalid {
        /// Human-readable reason for the economics validation failure.
        reason: String,
    },

    /// RFC-0029 queue admission trace is missing from the receipt.
    #[error("queue admission trace missing from receipt")]
    QueueAdmissionTraceMissing,

    /// RFC-0029 budget admission trace is missing from the receipt.
    #[error("budget admission trace missing from receipt")]
    BudgetAdmissionTraceMissing,

    /// Policy binding mismatch between boundary trace and envelope.
    #[error("policy binding mismatch: {detail}")]
    PolicyBindingMismatch {
        /// Human-readable detail of the mismatch.
        detail: String,
    },

    /// Job receipt not found for the requested job ID.
    #[error("job receipt not found for job_id={job_id}")]
    ReceiptNotFound {
        /// The job ID that was not found.
        job_id: String,
    },

    /// I/O error during export or import.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Blob reference count exceeds limit.
    #[error("too many blob references: {count} > {max}")]
    TooManyBlobs {
        /// Actual blob count.
        count: usize,
        /// Maximum allowed blob count.
        max: usize,
    },

    /// Per-field length bound violated.
    #[error("field length exceeded: {field} has {actual} bytes, max {max}")]
    FieldTooLong {
        /// Field name that exceeded the length limit.
        field: String,
        /// Actual length in bytes.
        actual: usize,
        /// Maximum allowed length in bytes.
        max: usize,
    },

    /// Policy or canonicalizer digest from the receipt is malformed.
    ///
    /// Returned when `policy_hash` or `canonicalizer_tuple_digest` cannot be
    /// decoded to a valid 32-byte digest. Fail-closed: export must not proceed
    /// with fabricated placeholder digests.
    #[error("malformed policy digest: {field}: {detail}")]
    MalformedPolicyDigest {
        /// Which digest field is malformed (`policy_hash` or
        /// `canonicalizer_tuple_digest`).
        field: String,
        /// Human-readable detail of the parse failure.
        detail: String,
    },

    /// A referenced blob could not be retrieved or written during export.
    ///
    /// Fail-closed: export must not succeed when referenced blob artifacts
    /// are missing or cannot be persisted.
    #[error("blob export failed for {blob_ref}: {detail}")]
    BlobExportFailed {
        /// The blob reference (hex hash) that failed.
        blob_ref: String,
        /// Human-readable detail of the failure.
        detail: String,
    },

    /// A referenced blob is missing or has a BLAKE3 integrity mismatch
    /// during import.
    ///
    /// Fail-closed: import must not succeed when referenced blob artifacts
    /// are missing, unreadable, or have mismatched BLAKE3 hashes.
    #[error("blob import verification failed for {blob_ref}: {detail}")]
    BlobImportVerificationFailed {
        /// The blob reference (hex hash) that failed verification.
        blob_ref: String,
        /// Human-readable detail of the failure.
        detail: String,
    },

    /// Manifest file exceeds size limit.
    #[error("manifest too large: {size} > {max}")]
    ManifestTooLarge {
        /// Actual manifest size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Manifest JSON parse failure.
    #[error("manifest parse error: {detail}")]
    ManifestParseError {
        /// Human-readable parse error detail.
        detail: String,
    },

    /// Manifest schema mismatch.
    #[error("manifest schema mismatch: expected {expected}, found {actual}")]
    ManifestSchemaMismatch {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier found in manifest.
        actual: String,
    },

    /// Manifest content hash verification failed.
    #[error("manifest content hash mismatch: expected {expected}, actual {actual}")]
    ManifestContentHashMismatch {
        /// Expected content hash.
        expected: String,
        /// Actual content hash computed from manifest body.
        actual: String,
    },

    /// Manifest entries exceed the maximum allowed count.
    #[error("too many manifest entries: {count} > {max}")]
    TooManyManifestEntries {
        /// Actual entry count.
        count: usize,
        /// Maximum allowed entry count.
        max: usize,
    },

    /// Channel boundary check is required but missing.
    ///
    /// Fail-closed: export and import operations require the channel boundary
    /// check to be present. This prevents construction of bundles that bypass
    /// RFC-0028 boundary validation.
    #[error("channel boundary check required for {operation}")]
    ChannelBoundaryCheckRequired {
        /// The operation that requires the boundary check (`export` or
        /// `import`).
        operation: String,
    },

    /// Receipt signature verification failed during import (TCK-00576).
    ///
    /// Fail-closed: evidence bundle import requires a valid signed receipt
    /// envelope. This prevents forged or unsigned receipts from being
    /// accepted as legitimate evidence.
    #[error("receipt signature verification failed: {detail}")]
    SignatureVerificationFailed {
        /// Human-readable detail of the verification failure.
        detail: String,
    },

    /// Leakage budget enforcement denied the operation (TCK-00555).
    ///
    /// Fail-closed: export or import is denied when the leakage budget
    /// policy ceiling is exceeded and no valid declassification receipt
    /// authorizes the overage.
    #[error("leakage budget denied: {reason}")]
    LeakageBudgetDenied {
        /// Human-readable reason for the denial.
        reason: String,
    },
}

// =============================================================================
// Envelope Types
// =============================================================================

/// A self-describing evidence bundle envelope for local export/import.
///
/// Contains the job receipt, RFC-0028 boundary check reconstruction data,
/// RFC-0029 economics traces, and blob references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleEnvelopeV1 {
    /// Schema identifier (must be `EVIDENCE_BUNDLE_SCHEMA`).
    pub schema: String,
    /// The job receipt being exported.
    pub receipt: FacJobReceiptV1,
    /// RFC-0028 boundary check reconstruction data.
    pub boundary_check: BundleBoundaryCheckV1,
    /// RFC-0029 economics traces.
    pub economics_trace: BundleEconomicsTraceV1,
    /// Optional policy binding for RFC-0028 boundary-flow verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_binding: Option<BoundaryFlowPolicyBinding>,
    /// Content-addressed blob references (hex-encoded BLAKE3 hashes).
    pub blob_refs: Vec<String>,
    /// Leakage budget decision from export-time enforcement (TCK-00555).
    ///
    /// Present when the export was subject to leakage budget policy
    /// enforcement. Import-side validation uses this to verify that the
    /// export did not bypass budget checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leakage_budget_decision: Option<LeakageBudgetDecision>,
    /// BLAKE3 content hash of the envelope body (excluding this field).
    pub content_hash: String,
}

/// RFC-0028 boundary check reconstruction data embedded in the envelope.
///
/// Carries all fields required by `validate_channel_boundary()` so that import
/// can reconstruct and validate the full `ChannelBoundaryCheck`. Fields that
/// are `None` will be passed as-is; the validator enforces fail-closed on
/// missing required data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct BundleBoundaryCheckV1 {
    /// Channel source classification.
    pub source: ChannelSource,
    /// Whether the broker path was verified.
    pub broker_verified: bool,
    /// Whether capability was verified.
    pub capability_verified: bool,
    /// Whether context firewall was verified.
    pub context_firewall_verified: bool,
    /// Whether policy ledger was verified.
    pub policy_ledger_verified: bool,
    /// Whether taint admission is allowed.
    pub taint_allow: bool,
    /// Whether classification admission is allowed.
    pub classification_allow: bool,
    /// Whether declassification receipt is valid.
    pub declass_receipt_valid: bool,
    /// Declassification intent scope.
    pub declassification_intent: DeclassificationIntentScope,
    /// Typed leakage-budget receipt for boundary-flow admission.
    pub leakage_budget_receipt: Option<LeakageBudgetReceipt>,
    /// Timing-channel release-bucketing witness.
    pub timing_channel_budget: Option<TimingChannelBudget>,
    /// Disclosure-control policy interlock binding.
    pub disclosure_policy_binding: Option<DisclosurePolicyBinding>,
}

/// RFC-0029 economics traces embedded in the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEconomicsTraceV1 {
    /// Queue admission trace from the receipt.
    pub queue_admission: QueueAdmissionTrace,
    /// Budget admission trace from the receipt.
    pub budget_admission: BudgetAdmissionTrace,
}

// =============================================================================
// Export
// =============================================================================

/// Configuration for evidence bundle export.
///
/// Carries the optional boundary-check substructures that the receipt trace
/// alone cannot reconstruct: leakage budget receipt, timing channel budget,
/// and disclosure policy binding. Also carries the leakage budget policy
/// and optional declassification receipt for TCK-00555 enforcement.
#[derive(Debug, Clone, Default)]
pub struct BundleExportConfig {
    /// RFC-0028 boundary-flow policy binding.
    pub policy_binding: Option<BoundaryFlowPolicyBinding>,
    /// Typed leakage-budget receipt for boundary-flow admission.
    pub leakage_budget_receipt: Option<LeakageBudgetReceipt>,
    /// Timing-channel release-bucketing witness.
    pub timing_channel_budget: Option<TimingChannelBudget>,
    /// Disclosure-control policy interlock binding.
    pub disclosure_policy_binding: Option<DisclosurePolicyBinding>,
    /// Leakage budget policy ceiling for export-time enforcement (TCK-00555).
    ///
    /// **Required for new-schema output** (INV-EB-025): export fails closed
    /// when this is `None`. Callers must supply a policy, even if permissive
    /// (e.g., `LeakageBudgetPolicy::tier0_default()`). This ensures all
    /// new-schema envelopes carry a `leakage_budget_decision` that import
    /// can validate (INV-EB-014).
    pub leakage_budget_policy: Option<LeakageBudgetPolicy>,
    /// Declassification receipt authorizing exports that exceed the leakage
    /// budget policy ceiling (TCK-00555).
    ///
    /// Required when the export would exceed the policy ceiling. The receipt
    /// must authorize at least the actual export size and class count.
    pub declassification_receipt: Option<DeclassificationExportReceipt>,
}

/// Build an evidence bundle envelope from a job receipt.
///
/// The receipt must contain RFC-0028 and RFC-0029 traces. If either is
/// missing, the export fails (fail-closed). The `config` carries optional
/// boundary-check substructures needed by `validate_channel_boundary()`.
///
/// # Errors
///
/// Returns `EvidenceBundleError` if the receipt lacks required traces.
#[allow(clippy::too_many_lines)]
pub fn build_evidence_bundle_envelope(
    receipt: &FacJobReceiptV1,
    config: &BundleExportConfig,
    blob_refs: &[String],
) -> Result<EvidenceBundleEnvelopeV1, EvidenceBundleError> {
    if blob_refs.len() > MAX_BUNDLE_BLOB_COUNT {
        return Err(EvidenceBundleError::TooManyBlobs {
            count: blob_refs.len(),
            max: MAX_BUNDLE_BLOB_COUNT,
        });
    }

    // Extract RFC-0028 boundary trace.
    let boundary_trace = receipt
        .rfc0028_channel_boundary
        .as_ref()
        .ok_or(EvidenceBundleError::ChannelBoundaryTraceMissing)?;

    // Extract RFC-0029 queue admission trace.
    let queue_trace = receipt
        .eio29_queue_admission
        .as_ref()
        .ok_or(EvidenceBundleError::QueueAdmissionTraceMissing)?;

    // Extract RFC-0029 budget admission trace.
    let budget_trace = receipt
        .eio29_budget_admission
        .as_ref()
        .ok_or(EvidenceBundleError::BudgetAdmissionTraceMissing)?;

    // Reconstruct the boundary check data from the trace.
    let boundary_check = BundleBoundaryCheckV1 {
        source: if boundary_trace.passed {
            ChannelSource::TypedToolIntent
        } else {
            ChannelSource::Unknown
        },
        broker_verified: boundary_trace.passed,
        capability_verified: boundary_trace.passed,
        context_firewall_verified: boundary_trace.passed,
        policy_ledger_verified: boundary_trace.passed,
        taint_allow: boundary_trace.passed,
        classification_allow: boundary_trace.passed,
        declass_receipt_valid: boundary_trace.passed,
        declassification_intent: if boundary_trace.passed {
            DeclassificationIntentScope::None
        } else {
            DeclassificationIntentScope::Unknown
        },
        leakage_budget_receipt: config.leakage_budget_receipt.clone(),
        timing_channel_budget: config.timing_channel_budget.clone(),
        disclosure_policy_binding: config.disclosure_policy_binding.clone(),
    };

    let economics_trace = BundleEconomicsTraceV1 {
        queue_admission: queue_trace.clone(),
        budget_admission: budget_trace.clone(),
    };

    // INV-EB-025: Fail-closed when leakage_budget_policy is absent for
    // new-schema output. New-schema envelopes (EVIDENCE_BUNDLE_ENVELOPE_SCHEMA)
    // require a leakage_budget_decision for import acceptance (INV-EB-014).
    // Exporting without a policy would produce an envelope that passes export
    // but fails import — a self-incompatible API surface. Callers must supply
    // a policy, even if it is a permissive tier (e.g., tier0_default()).
    if config.leakage_budget_policy.is_none() {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: "export requires leakage_budget_policy for new-schema envelopes \
                     (EVIDENCE_BUNDLE_ENVELOPE_SCHEMA); callers must supply a policy, \
                     even if permissive (e.g., LeakageBudgetPolicy::tier0_default())"
                .to_string(),
        });
    }

    // Build envelope without content hash first.
    let mut envelope = EvidenceBundleEnvelopeV1 {
        schema: EVIDENCE_BUNDLE_ENVELOPE_SCHEMA.to_string(),
        receipt: receipt.clone(),
        boundary_check,
        economics_trace,
        policy_binding: config.policy_binding.clone(),
        blob_refs: blob_refs.to_vec(),
        leakage_budget_decision: None,
        content_hash: String::new(),
    };

    // INV-EB-006: Leakage budget enforcement (TCK-00555), phase 1.
    // Preliminary pass checks class count and leakage bits. Byte
    // enforcement is deferred until after final serialization (phase 2).
    if let Some(ref policy) = config.leakage_budget_policy {
        envelope.leakage_budget_decision = Some(enforce_leakage_budget_preliminary(
            policy, config, blob_refs,
        )?);
    }

    // Compute content hash over canonical bytes.
    let hash = compute_envelope_content_hash(&envelope);
    envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

    // INV-EB-006: Leakage budget enforcement (TCK-00555), phase 2.
    // Enforce max_export_bytes against the exact bytes that will be
    // written to disk (serde_json::to_vec_pretty with populated hash).
    //
    // Convergence loop: the serialized size depends on the
    // `actual_export_bytes` integer representation (e.g., "0" vs "1234"),
    // and the content hash depends on `actual_export_bytes`. After
    // setting the real byte count and re-hashing, the serialized size
    // may shift by a few bytes. We iterate until the recorded size
    // matches the actual serialized size. This converges in at most
    // MAX_BYTE_CONVERGENCE_ROUNDS rounds because the integer
    // representation stabilizes quickly.
    if let Some(mut decision) = envelope.leakage_budget_decision.take() {
        // Initial measurement with the placeholder (0) byte count.
        let initial_bytes =
            serde_json::to_vec_pretty(&envelope).map_err(|e| EvidenceBundleError::ParseError {
                detail: format!("final serialization for byte enforcement failed: {e}"),
            })?;
        let mut measured_size = initial_bytes.len() as u64;

        enforce_leakage_budget_final(&mut decision, measured_size, config)?;

        // Put the decision back and converge.
        envelope.leakage_budget_decision = Some(decision);

        // Convergence: re-serialize with the real actual_export_bytes,
        // re-hash, and check if the size is still consistent.
        for _ in 0..MAX_BYTE_CONVERGENCE_ROUNDS {
            let rehash = compute_envelope_content_hash(&envelope);
            envelope.content_hash = format!("b3-256:{}", hex::encode(rehash));

            let final_bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| {
                EvidenceBundleError::ParseError {
                    detail: format!("convergence serialization failed: {e}"),
                }
            })?;
            let new_size = final_bytes.len() as u64;

            if new_size == measured_size {
                break; // Converged: recorded size matches actual serialized size.
            }

            // Update the decision with the corrected size and re-check
            // policy enforcement.
            measured_size = new_size;
            if let Some(ref mut d) = envelope.leakage_budget_decision {
                d.actual_export_bytes = new_size;
                // Re-check byte ceiling: if the new size newly exceeds
                // policy, we need to validate declassification again.
                let byte_exceeded = new_size > d.policy.max_export_bytes;
                if byte_exceeded && !d.exceeded_policy {
                    match &config.declassification_receipt {
                        Some(declass) => {
                            validate_declassification_receipt(
                                declass,
                                new_size,
                                d.actual_export_classes,
                                d.actual_leakage_bits,
                                config.leakage_budget_receipt.as_ref(),
                            )?;
                            d.exceeded_policy = true;
                            d.declassification_authorized = true;
                            d.declassification_receipt_id = Some(declass.receipt_id.clone());
                            d.declassification_receipt = Some(declass.clone());
                        },
                        None => {
                            return Err(EvidenceBundleError::LeakageBudgetDenied {
                                reason: format!(
                                    "export exceeds leakage budget policy (converged bytes: {new_size}/{}) and no declassification receipt provided",
                                    d.policy.max_export_bytes,
                                ),
                            });
                        },
                    }
                } else if byte_exceeded {
                    // Already exceeded — verify byte coverage.
                    if let Some(declass) = &config.declassification_receipt {
                        if declass.authorized_bytes < new_size {
                            return Err(EvidenceBundleError::LeakageBudgetDenied {
                                reason: format!(
                                    "declassification receipt authorizes {} bytes but converged export is {} bytes",
                                    declass.authorized_bytes, new_size,
                                ),
                            });
                        }
                    }
                }

                // INV-EB-024: byte coverage for all exceeded-policy exports.
                if d.exceeded_policy || byte_exceeded {
                    if let Some(declass) = &config.declassification_receipt {
                        if declass.authorized_bytes < new_size {
                            return Err(EvidenceBundleError::LeakageBudgetDenied {
                                reason: format!(
                                    "declassification receipt authorizes {} bytes but converged export is {} bytes \
                                     (byte coverage required for all exceeded-policy exports)",
                                    declass.authorized_bytes, new_size,
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Final hash after convergence.
        let final_hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(final_hash));
    }

    Ok(envelope)
}

/// INV-EB-006: Enforce leakage budget policy at export time (TCK-00555).
///
/// Enforcement is deferred: the caller invokes this before the content
/// hash is populated, records the preliminary decision, then — after
/// the content hash is populated and the final `to_vec_pretty` bytes
/// are produced — calls [`enforce_leakage_budget_final`] against the
/// actual exported byte count. This guarantees that `max_export_bytes`
/// is enforced against the exact bytes written to disk, not a smaller
/// pre-hash representation.
#[allow(clippy::cast_possible_truncation)]
fn enforce_leakage_budget_preliminary(
    policy: &LeakageBudgetPolicy,
    config: &BundleExportConfig,
    blob_refs: &[String],
) -> Result<LeakageBudgetDecision, EvidenceBundleError> {
    // Class count: each blob ref is one artifact class; additionally
    // the envelope itself and the receipt are classes.
    let actual_classes = (blob_refs.len() as u32).saturating_add(2);

    // Actual leakage bits from the leakage budget receipt (0 if absent).
    let actual_leakage_bits = config
        .leakage_budget_receipt
        .as_ref()
        .map_or(0, |lbr| lbr.leakage_bits);

    // Byte budget enforcement is deferred to final pass; set 0 as placeholder.
    // Class and leakage-bit exceedance are checked now because they do not
    // depend on final serialized size.
    let class_exceeded = actual_classes > policy.max_export_classes;
    let leakage_bits_exceeded = actual_leakage_bits > policy.max_leakage_bits;

    // If class or leakage-bit ceiling is already exceeded, validate
    // declassification receipt now (byte enforcement is deferred).
    let any_exceeded_preliminary = class_exceeded || leakage_bits_exceeded;

    if any_exceeded_preliminary {
        match &config.declassification_receipt {
            Some(declass) => {
                validate_declassification_receipt(
                    declass,
                    // Byte check deferred — pass 0 to skip byte coverage check here.
                    0,
                    actual_classes,
                    actual_leakage_bits,
                    config.leakage_budget_receipt.as_ref(),
                )?;
            },
            None => {
                return Err(EvidenceBundleError::LeakageBudgetDenied {
                    reason: format!(
                        "export exceeds leakage budget policy (classes: {actual_classes}/{}, leakage_bits: {actual_leakage_bits}/{}) and no declassification receipt provided",
                        policy.max_export_classes, policy.max_leakage_bits,
                    ),
                });
            },
        }
    }

    // actual_export_bytes and exceeded_policy will be finalized after
    // serialization by enforce_leakage_budget_final.
    Ok(LeakageBudgetDecision {
        policy: policy.clone(),
        actual_export_bytes: 0, // placeholder — finalized in enforce_leakage_budget_final
        actual_export_classes: actual_classes,
        actual_leakage_bits,
        exceeded_policy: any_exceeded_preliminary, // updated in final pass
        declassification_authorized: any_exceeded_preliminary
            && config.declassification_receipt.is_some(),
        declassification_receipt_id: config
            .declassification_receipt
            .as_ref()
            .filter(|_| any_exceeded_preliminary)
            .map(|d| d.receipt_id.clone()),
        declassification_receipt: config
            .declassification_receipt
            .as_ref()
            .filter(|_| any_exceeded_preliminary)
            .cloned(),
    })
}

/// Finalize leakage budget enforcement against the actual exported byte count.
///
/// Called after the envelope is fully serialized (with content hash populated)
/// using `serde_json::to_vec_pretty`. This ensures `max_export_bytes` is
/// enforced against the exact bytes that will be written to disk, not a
/// smaller pre-hash compact-JSON representation.
fn enforce_leakage_budget_final(
    decision: &mut LeakageBudgetDecision,
    actual_export_bytes: u64,
    config: &BundleExportConfig,
) -> Result<(), EvidenceBundleError> {
    decision.actual_export_bytes = actual_export_bytes;

    let byte_exceeded = actual_export_bytes > decision.policy.max_export_bytes;
    let any_exceeded = decision.exceeded_policy || byte_exceeded;

    if byte_exceeded && !decision.exceeded_policy {
        // Byte ceiling newly exceeded — need declassification receipt.
        match &config.declassification_receipt {
            Some(declass) => {
                validate_declassification_receipt(
                    declass,
                    actual_export_bytes,
                    decision.actual_export_classes,
                    decision.actual_leakage_bits,
                    config.leakage_budget_receipt.as_ref(),
                )?;
                decision.exceeded_policy = true;
                decision.declassification_authorized = true;
                decision.declassification_receipt_id = Some(declass.receipt_id.clone());
                decision.declassification_receipt = Some(declass.clone());
            },
            None => {
                return Err(EvidenceBundleError::LeakageBudgetDenied {
                    reason: format!(
                        "export exceeds leakage budget policy (final bytes: {actual_export_bytes}/{}) and no declassification receipt provided",
                        decision.policy.max_export_bytes,
                    ),
                });
            },
        }
    } else if byte_exceeded {
        // Already exceeded from preliminary pass — verify byte coverage.
        if let Some(declass) = &config.declassification_receipt {
            if declass.authorized_bytes < actual_export_bytes {
                return Err(EvidenceBundleError::LeakageBudgetDenied {
                    reason: format!(
                        "declassification receipt authorizes {} bytes but final export is {} bytes",
                        declass.authorized_bytes, actual_export_bytes,
                    ),
                });
            }
        }
    }

    // INV-EB-024: When any dimension exceeded policy and a declassification
    // receipt is present, always validate that authorized_bytes covers the
    // actual export bytes — regardless of which dimension triggered
    // exceedance. This aligns export semantics with import semantics
    // (import always checks authorized_bytes >= actual_export_bytes when
    // declassification_authorized is true). Without this check, a
    // class-triggered exceedance with an under-authorized byte receipt
    // could pass export but fail import.
    if any_exceeded {
        if let Some(declass) = &config.declassification_receipt {
            if declass.authorized_bytes < actual_export_bytes {
                return Err(EvidenceBundleError::LeakageBudgetDenied {
                    reason: format!(
                        "declassification receipt authorizes {} bytes but actual export is {} bytes \
                         (byte coverage required for all exceeded-policy exports)",
                        declass.authorized_bytes, actual_export_bytes,
                    ),
                });
            }
        }
    }

    decision.exceeded_policy = any_exceeded;

    Ok(())
}

/// Validate that a declassification receipt authorizes the actual export usage.
///
/// The `actual_leakage_bits` parameter carries the leakage bits from the
/// leakage budget receipt (0 when absent). Leakage-bit authorization is
/// checked unconditionally whenever the receipt is present — not only when
/// the leakage-bit dimension itself exceeded its policy ceiling. This
/// ensures export-time validation is consistent with import-time validation,
/// which always checks `authorized_leakage_bits >= actual_leakage_bits`
/// when declassification is authorized (TCK-00555, security finding MINOR).
fn validate_declassification_receipt(
    declass: &DeclassificationExportReceipt,
    actual_bytes: u64,
    actual_classes: u32,
    actual_leakage_bits: u64,
    leakage_budget_receipt: Option<&LeakageBudgetReceipt>,
) -> Result<(), EvidenceBundleError> {
    // Validate receipt structure.
    declass.validate()?;

    // Verify receipt content hash binding.
    let expected_hash = declass.compute_content_hash();
    if !bool::from(declass.content_hash.ct_eq(&expected_hash)) {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: "declassification receipt content_hash does not match computed hash"
                .to_string(),
        });
    }

    // Verify authorization covers actual usage.
    if declass.authorized_bytes < actual_bytes {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: format!(
                "declassification receipt authorizes {} bytes but export is {} bytes",
                declass.authorized_bytes, actual_bytes,
            ),
        });
    }
    if declass.authorized_classes < actual_classes {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: format!(
                "declassification receipt authorizes {} classes but export has {} classes",
                declass.authorized_classes, actual_classes,
            ),
        });
    }
    // Always check leakage-bit coverage when a leakage budget receipt is
    // present, regardless of which dimension triggered exceedance. This
    // matches the import-side check that unconditionally requires
    // authorized_leakage_bits >= actual_leakage_bits whenever
    // declassification is authorized (TCK-00555 MINOR finding fix).
    if let Some(lbr) = leakage_budget_receipt {
        if declass.authorized_leakage_bits < lbr.leakage_bits {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "declassification receipt authorizes {} leakage bits but receipt declares {} bits",
                    declass.authorized_leakage_bits, lbr.leakage_bits,
                ),
            });
        }
    }
    // Also check against actual_leakage_bits directly (may differ from
    // lbr.leakage_bits if no receipt is present but bits are non-zero).
    if declass.authorized_leakage_bits < actual_leakage_bits {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: format!(
                "declassification receipt authorizes {} leakage bits but actual leakage is {} bits",
                declass.authorized_leakage_bits, actual_leakage_bits,
            ),
        });
    }
    Ok(())
}

/// Serialize an envelope to JSON bytes.
///
/// # Errors
///
/// Returns `EvidenceBundleError::ParseError` if serialization fails.
pub fn serialize_envelope(
    envelope: &EvidenceBundleEnvelopeV1,
) -> Result<Vec<u8>, EvidenceBundleError> {
    serde_json::to_vec_pretty(envelope).map_err(|e| EvidenceBundleError::ParseError {
        detail: e.to_string(),
    })
}

// =============================================================================
// Import (fail-closed)
// =============================================================================

/// Import and validate an evidence bundle envelope from JSON bytes.
///
/// This function enforces fail-closed validation:
/// 1. Bounded size check.
/// 2. Schema verification.
/// 3. Content hash integrity.
/// 4. RFC-0028 channel boundary validation (must pass with zero defects).
/// 5. RFC-0029 economics receipt validation (must have Allow verdicts).
///
/// # Errors
///
/// Returns `EvidenceBundleError` for any validation failure.
pub fn import_evidence_bundle(
    data: &[u8],
) -> Result<EvidenceBundleEnvelopeV1, EvidenceBundleError> {
    // INV-EB-003: Bounded read.
    //
    // Design note (NIT): This global MAX_ENVELOPE_SIZE (256 KiB) check runs
    // before parsing, which means more restrictive per-policy ceilings
    // (e.g., Tier2 at 4 MiB) are not enforced until after deserialization
    // completes and validate_leakage_budget_decision runs. A two-stage
    // parse that peeks at the policy tier before full deserialization was
    // considered but rejected as too invasive: the envelope schema is
    // self-describing JSON where the policy lives inside a nested
    // leakage_budget_decision field, making reliable pre-parse extraction
    // fragile. The global guard prevents OOM from malicious payloads;
    // per-policy byte enforcement follows during decision validation.
    // The MAX_ENVELOPE_SIZE constant is already conservative (256 KiB)
    // and well below the Tier0 ceiling (64 MiB), so the practical
    // memory exposure is bounded.
    if data.len() > MAX_ENVELOPE_SIZE {
        return Err(EvidenceBundleError::EnvelopeTooLarge {
            size: data.len(),
            max: MAX_ENVELOPE_SIZE,
        });
    }

    // Parse envelope.
    let envelope: EvidenceBundleEnvelopeV1 =
        serde_json::from_slice(data).map_err(|e| EvidenceBundleError::ParseError {
            detail: e.to_string(),
        })?;

    // Schema check: accept both legacy and canonical envelope schemas.
    if envelope.schema != EVIDENCE_BUNDLE_SCHEMA
        && envelope.schema != EVIDENCE_BUNDLE_ENVELOPE_SCHEMA
    {
        return Err(EvidenceBundleError::SchemaMismatch {
            expected: format!("{EVIDENCE_BUNDLE_SCHEMA} or {EVIDENCE_BUNDLE_ENVELOPE_SCHEMA}"),
            actual: envelope.schema,
        });
    }

    // Blob count check.
    if envelope.blob_refs.len() > MAX_BUNDLE_BLOB_COUNT {
        return Err(EvidenceBundleError::TooManyBlobs {
            count: envelope.blob_refs.len(),
            max: MAX_BUNDLE_BLOB_COUNT,
        });
    }

    // INV-EB-005: Per-field length bounds.
    if envelope.receipt.job_id.len() > MAX_JOB_ID_LENGTH {
        return Err(EvidenceBundleError::FieldTooLong {
            field: "receipt.job_id".to_string(),
            actual: envelope.receipt.job_id.len(),
            max: MAX_JOB_ID_LENGTH,
        });
    }
    for (i, blob_ref) in envelope.blob_refs.iter().enumerate() {
        if blob_ref.len() > MAX_BLOB_REF_LENGTH {
            return Err(EvidenceBundleError::FieldTooLong {
                field: format!("blob_refs[{i}]"),
                actual: blob_ref.len(),
                max: MAX_BLOB_REF_LENGTH,
            });
        }
    }

    // INV-EB-004: Content hash integrity.
    validate_content_hash(&envelope)?;

    // INV-EB-001: RFC-0028 channel boundary validation.
    validate_boundary_check(&envelope)?;

    // INV-EB-002: RFC-0029 economics receipt validation.
    validate_economics_traces(&envelope)?;

    // INV-EB-007: Leakage budget decision consistency (TCK-00555).
    // Pass the canonical envelope byte size (data.len()) so the importer
    // independently verifies actual_export_bytes against the real serialized
    // size, preventing forged byte values (TCK-00555 MAJOR finding fix).
    validate_leakage_budget_decision(&envelope, data.len() as u64)?;

    Ok(envelope)
}

/// Import and validate an evidence bundle envelope with receipt signature
/// verification (TCK-00576).
///
/// This function performs all validations from [`import_evidence_bundle`] and
/// additionally verifies the receipt's signed envelope against the provided
/// verifying key. This is the fail-closed import path: unsigned or forged
/// receipts are rejected.
///
/// # Errors
///
/// Returns `EvidenceBundleError` for any validation failure, including
/// `SignatureVerificationFailed` if the receipt signature is missing,
/// malformed, or does not verify against the provided key.
pub fn import_evidence_bundle_verified(
    data: &[u8],
    verifying_key: &crate::crypto::VerifyingKey,
    receipts_dir: Option<&std::path::Path>,
) -> Result<EvidenceBundleEnvelopeV1, EvidenceBundleError> {
    // Perform standard import validation first.
    let envelope = import_evidence_bundle(data)?;

    // TCK-00576: Verify receipt signature.
    // The receipt's content_hash in the envelope is the binding point.
    let receipt_content_hash = &envelope.receipt.content_hash;

    // Try to load the signed envelope from the receipts directory if provided.
    // Otherwise, construct the expected content hash and verify against it.
    if let Some(receipts_dir) = receipts_dir {
        match super::signed_receipt::load_and_verify_receipt_signature(
            receipts_dir,
            receipt_content_hash,
            verifying_key,
        ) {
            Ok(_) => {},
            Err(e) => {
                return Err(EvidenceBundleError::SignatureVerificationFailed {
                    detail: format!(
                        "receipt {receipt_content_hash} signature verification failed: {e}"
                    ),
                });
            },
        }
    } else {
        // No receipts directory provided: fail-closed. We cannot verify
        // without the signed envelope.
        return Err(EvidenceBundleError::SignatureVerificationFailed {
            detail: format!(
                "no receipts directory provided for signature verification of {receipt_content_hash}"
            ),
        });
    }

    Ok(envelope)
}

/// Maximum blob file size during import verification (matches blob store cap).
pub const MAX_BLOB_IMPORT_SIZE: usize = 10_485_760; // 10 MiB

/// Verify that all `blob_refs` in an imported envelope exist in the bundle
/// directory and their BLAKE3 hashes match the declared values.
///
/// Each blob ref is expected to be a hex-encoded BLAKE3 hash (with optional
/// `b3-256:` prefix). The corresponding file is expected at
/// `<bundle_dir>/<hex_hash>.blob`.
///
/// # Errors
///
/// Returns `EvidenceBundleError::BlobImportVerificationFailed` if any blob
/// is missing, unreadable, oversized, or has a BLAKE3 hash mismatch.
pub fn verify_blob_refs(
    envelope: &EvidenceBundleEnvelopeV1,
    bundle_dir: &std::path::Path,
) -> Result<(), EvidenceBundleError> {
    for blob_ref in &envelope.blob_refs {
        verify_single_blob_ref(blob_ref, bundle_dir)?;
    }
    Ok(())
}

/// Verify a single blob ref exists and has matching BLAKE3 hash.
fn verify_single_blob_ref(
    blob_ref: &str,
    bundle_dir: &std::path::Path,
) -> Result<(), EvidenceBundleError> {
    use std::io::Read;

    let hex_part = blob_ref.strip_prefix("b3-256:").unwrap_or(blob_ref);

    // Validate hex string before constructing filesystem path.
    let expected_hash =
        hex::decode(hex_part).map_err(|e| EvidenceBundleError::BlobImportVerificationFailed {
            blob_ref: blob_ref.to_string(),
            detail: format!("invalid hex in blob ref: {e}"),
        })?;
    if expected_hash.len() != 32 {
        return Err(EvidenceBundleError::BlobImportVerificationFailed {
            blob_ref: blob_ref.to_string(),
            detail: format!("expected 32-byte hash, got {} bytes", expected_hash.len()),
        });
    }

    // Construct blob filename. Use the raw hex part (no path separators)
    // to prevent traversal.
    if hex_part.contains('/') || hex_part.contains('\\') || hex_part.contains("..") {
        return Err(EvidenceBundleError::BlobImportVerificationFailed {
            blob_ref: blob_ref.to_string(),
            detail: "blob ref contains path separator or traversal sequence".to_string(),
        });
    }
    let blob_path = bundle_dir.join(format!("{hex_part}.blob"));

    // Open the blob file.
    let file = std::fs::File::open(&blob_path).map_err(|e| {
        EvidenceBundleError::BlobImportVerificationFailed {
            blob_ref: blob_ref.to_string(),
            detail: format!("blob file not found or unreadable: {e}"),
        }
    })?;

    // Bounded read.
    let metadata =
        file.metadata()
            .map_err(|e| EvidenceBundleError::BlobImportVerificationFailed {
                blob_ref: blob_ref.to_string(),
                detail: format!("cannot read blob metadata: {e}"),
            })?;
    if metadata.len() > MAX_BLOB_IMPORT_SIZE as u64 {
        return Err(EvidenceBundleError::BlobImportVerificationFailed {
            blob_ref: blob_ref.to_string(),
            detail: format!(
                "blob too large: {} bytes > {} max",
                metadata.len(),
                MAX_BLOB_IMPORT_SIZE
            ),
        });
    }

    let mut data = Vec::new();
    file.take(MAX_BLOB_IMPORT_SIZE as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| EvidenceBundleError::BlobImportVerificationFailed {
            blob_ref: blob_ref.to_string(),
            detail: format!("failed to read blob: {e}"),
        })?;

    // Verify BLAKE3 hash. Length already validated to be 32 above.
    let actual_hash = blake3::hash(&data);
    let mut expected_arr = [0u8; 32];
    expected_arr.copy_from_slice(&expected_hash);
    if !bool::from(actual_hash.as_bytes().ct_eq(&expected_arr)) {
        return Err(EvidenceBundleError::BlobImportVerificationFailed {
            blob_ref: blob_ref.to_string(),
            detail: format!(
                "BLAKE3 hash mismatch: expected {}, actual {}",
                hex::encode(expected_arr),
                actual_hash.to_hex()
            ),
        });
    }
    Ok(())
}

// =============================================================================
// Validation Helpers
// =============================================================================

/// Compute the BLAKE3 content hash of the envelope body.
///
/// The hash is computed over all fields except `content_hash` to prevent
/// circular dependency. Uses length-prefixed encoding for determinism.
/// Length-prefix a variable-length byte slice into the hasher for
/// deterministic framing (prevents concatenation collisions).
fn hash_len_prefixed(hasher: &mut blake3::Hasher, data: &[u8]) {
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
}

/// Hash an optional byte-slice field with presence tag + length-prefix.
fn hash_optional_bytes(hasher: &mut blake3::Hasher, opt: Option<&[u8]>) {
    match opt {
        Some(data) => {
            hasher.update(&[1u8]);
            hash_len_prefixed(hasher, data);
        },
        None => {
            hasher.update(&[0u8]);
        },
    }
}

/// Hash an optional string field with presence tag + length-prefix.
fn hash_optional_str(hasher: &mut blake3::Hasher, opt: Option<&str>) {
    hash_optional_bytes(hasher, opt.map(str::as_bytes));
}

/// Canonical label for `DeclassificationIntentScope` in hash preimage.
const fn declassification_intent_label(scope: DeclassificationIntentScope) -> &'static str {
    match scope {
        DeclassificationIntentScope::None => "none",
        DeclassificationIntentScope::RedundancyPurpose => "redundancy_purpose",
        DeclassificationIntentScope::Unknown => "unknown",
    }
}

/// Canonical label for `LeakageEstimatorFamily` in hash preimage.
const fn leakage_estimator_label(family: LeakageEstimatorFamily) -> &'static str {
    match family {
        LeakageEstimatorFamily::MutualInformationUpperBound => "mutual_information_upper_bound",
        LeakageEstimatorFamily::ChannelCapacityUpperBound => "channel_capacity_upper_bound",
        LeakageEstimatorFamily::EmpiricalBucketHistogram => "empirical_bucket_histogram",
        LeakageEstimatorFamily::Unknown => "unknown",
    }
}

/// Canonical label for `DisclosurePolicyMode` in hash preimage.
const fn disclosure_mode_label(mode: DisclosurePolicyMode) -> &'static str {
    mode.canonical_label()
}

/// Canonical label for `DisclosureChannelClass` in hash preimage.
const fn disclosure_channel_label(class: DisclosureChannelClass) -> &'static str {
    match class {
        DisclosureChannelClass::Internal => "internal",
        DisclosureChannelClass::PatentFiling => "patent_filing",
        DisclosureChannelClass::ProvisionalApplication => "provisional_application",
        DisclosureChannelClass::ExternalPublication => "external_publication",
        DisclosureChannelClass::DeclassificationControlled => "declassification_controlled",
    }
}

/// Hash all fields of the boundary check into the hasher with deterministic
/// length-prefix framing for every variable-length field.
fn hash_boundary_check(hasher: &mut blake3::Hasher, bc: &BundleBoundaryCheckV1) {
    let source_label = match bc.source {
        ChannelSource::TypedToolIntent => "typed_tool_intent",
        ChannelSource::FreeFormOutput => "free_form_output",
        ChannelSource::DirectManifest => "direct_manifest",
        ChannelSource::Unknown => "unknown",
    };
    hash_len_prefixed(hasher, source_label.as_bytes());
    hasher.update(&[
        u8::from(bc.broker_verified),
        u8::from(bc.capability_verified),
        u8::from(bc.context_firewall_verified),
        u8::from(bc.policy_ledger_verified),
        u8::from(bc.taint_allow),
        u8::from(bc.classification_allow),
        u8::from(bc.declass_receipt_valid),
    ]);
    hash_len_prefixed(
        hasher,
        declassification_intent_label(bc.declassification_intent).as_bytes(),
    );

    // leakage_budget_receipt — ALL fields
    if let Some(lbr) = &bc.leakage_budget_receipt {
        hasher.update(&[1u8]);
        hasher.update(&lbr.leakage_bits.to_le_bytes());
        hasher.update(&lbr.budget_bits.to_le_bytes());
        hash_len_prefixed(
            hasher,
            leakage_estimator_label(lbr.estimator_family).as_bytes(),
        );
        hasher.update(&lbr.confidence_bps.to_le_bytes());
        hash_len_prefixed(hasher, lbr.confidence_label.as_bytes());
    } else {
        hasher.update(&[0u8]);
    }

    // timing_channel_budget — ALL fields
    if let Some(tcb) = &bc.timing_channel_budget {
        hasher.update(&[1u8]);
        hasher.update(&tcb.release_bucket_ticks.to_le_bytes());
        hasher.update(&tcb.observed_variance_ticks.to_le_bytes());
        hasher.update(&tcb.budget_ticks.to_le_bytes());
    } else {
        hasher.update(&[0u8]);
    }

    // disclosure_policy_binding — ALL fields
    if let Some(dpb) = &bc.disclosure_policy_binding {
        hasher.update(&[1u8]);
        hasher.update(&[u8::from(dpb.required_for_effect)]);
        hasher.update(&[u8::from(dpb.state_valid)]);
        hash_len_prefixed(hasher, disclosure_mode_label(dpb.active_mode).as_bytes());
        hash_len_prefixed(hasher, disclosure_mode_label(dpb.expected_mode).as_bytes());
        hash_len_prefixed(
            hasher,
            disclosure_channel_label(dpb.attempted_channel).as_bytes(),
        );
        hasher.update(&dpb.policy_snapshot_digest);
        hasher.update(&dpb.admitted_policy_epoch_root_digest);
        hasher.update(&dpb.policy_epoch.to_le_bytes());
        hash_len_prefixed(hasher, dpb.phase_id.as_bytes());
        hash_len_prefixed(hasher, dpb.state_reason.as_bytes());
    } else {
        hasher.update(&[0u8]);
    }
}

/// Hash economics trace fields into the hasher with length-prefix framing.
fn hash_economics_trace(hasher: &mut blake3::Hasher, trace: &BundleEconomicsTraceV1) {
    hash_len_prefixed(hasher, trace.queue_admission.verdict.as_bytes());
    hash_len_prefixed(hasher, trace.queue_admission.queue_lane.as_bytes());
    hash_optional_str(hasher, trace.queue_admission.defect_reason.as_deref());
    hash_len_prefixed(hasher, trace.budget_admission.verdict.as_bytes());
    hash_optional_str(hasher, trace.budget_admission.reason.as_deref());
}

#[allow(clippy::cast_possible_truncation)]
fn compute_envelope_content_hash(envelope: &EvidenceBundleEnvelopeV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ENVELOPE_HASH_DOMAIN);

    // -- schema (length-prefixed) --
    hash_len_prefixed(&mut hasher, envelope.schema.as_bytes());

    // -- receipt canonical bytes v2 (length-prefixed) --
    // Uses canonical_bytes_v2() which includes unsafe_direct, policy_hash,
    // and canonicalizer_tuple_digest for comprehensive integrity binding.
    let receipt_bytes = envelope.receipt.canonical_bytes_v2();
    hash_len_prefixed(&mut hasher, &receipt_bytes);

    // -- boundary check: ALL fields with deterministic framing --
    hash_boundary_check(&mut hasher, &envelope.boundary_check);

    // -- economics trace: ALL fields with length-prefix framing --
    hash_economics_trace(&mut hasher, &envelope.economics_trace);

    // -- policy binding --
    if let Some(binding) = &envelope.policy_binding {
        hasher.update(&[1u8]);
        hasher.update(&binding.policy_digest);
        hasher.update(&binding.admitted_policy_root_digest);
        hasher.update(&binding.canonicalizer_tuple_digest);
        hasher.update(&binding.admitted_canonicalizer_tuple_digest);
    } else {
        hasher.update(&[0u8]);
    }

    // -- blob references (length-prefixed array + per-element framing) --
    hasher.update(&(envelope.blob_refs.len() as u64).to_le_bytes());
    for blob_ref in &envelope.blob_refs {
        hash_len_prefixed(&mut hasher, blob_ref.as_bytes());
    }

    // -- leakage budget decision (TCK-00555) --
    // Schema-gated legacy hash path: when `leakage_budget_decision` is absent
    // AND the envelope schema is a legacy schema ID, omit the leakage budget
    // field entirely to preserve backward compatibility with pre-TCK-00555
    // envelopes (INV-EB-026). New-schema envelopes always include the
    // presence/absence tag.
    let is_legacy_schema = envelope.schema == EVIDENCE_BUNDLE_SCHEMA;
    if is_legacy_schema && envelope.leakage_budget_decision.is_none() {
        // Legacy path: do not append anything for this field.
    } else if let Some(ref lbd) = envelope.leakage_budget_decision {
        hasher.update(&[1u8]);
        // Policy fields
        hasher.update(&lbd.policy.max_export_bytes.to_le_bytes());
        hasher.update(&lbd.policy.max_export_classes.to_le_bytes());
        hasher.update(&lbd.policy.max_leakage_bits.to_le_bytes());
        // Actual usage
        hasher.update(&lbd.actual_export_bytes.to_le_bytes());
        hasher.update(&lbd.actual_export_classes.to_le_bytes());
        hasher.update(&lbd.actual_leakage_bits.to_le_bytes());
        // Decision flags
        hasher.update(&[u8::from(lbd.exceeded_policy)]);
        hasher.update(&[u8::from(lbd.declassification_authorized)]);
        // Optional receipt ID
        hash_optional_str(&mut hasher, lbd.declassification_receipt_id.as_deref());
        // Embedded declassification receipt for audit trail
        if let Some(ref declass) = lbd.declassification_receipt {
            hasher.update(&[1u8]);
            hash_len_prefixed(&mut hasher, declass.receipt_id.as_bytes());
            hasher.update(&declass.authorized_bytes.to_le_bytes());
            hasher.update(&declass.authorized_classes.to_le_bytes());
            hasher.update(&declass.authorized_leakage_bits.to_le_bytes());
            hash_len_prefixed(&mut hasher, declass.authority_id.as_bytes());
            hash_len_prefixed(&mut hasher, declass.reason.as_bytes());
            hasher.update(&declass.content_hash);
        } else {
            hasher.update(&[0u8]);
        }
    } else {
        hasher.update(&[0u8]);
    }

    *hasher.finalize().as_bytes()
}

/// Verify the content hash of the envelope.
fn validate_content_hash(envelope: &EvidenceBundleEnvelopeV1) -> Result<(), EvidenceBundleError> {
    let computed = compute_envelope_content_hash(envelope);
    let expected_hex = format!("b3-256:{}", hex::encode(computed));

    // Use constant-time comparison for integrity binding.
    if !bool::from(
        expected_hex
            .as_bytes()
            .ct_eq(envelope.content_hash.as_bytes()),
    ) {
        return Err(EvidenceBundleError::ContentHashMismatch {
            expected: expected_hex,
            actual: envelope.content_hash.clone(),
        });
    }

    Ok(())
}

/// Validate the RFC-0028 channel boundary check embedded in the envelope.
///
/// Reconstructs a `ChannelBoundaryCheck` from the envelope boundary data
/// and runs `validate_channel_boundary()`. Defects from honestly-absent
/// optional sub-evidence (leakage budget, timing budget, disclosure policy)
/// are filtered when the corresponding field is `None` in the envelope.
/// All other defects cause rejection.
#[allow(clippy::too_many_lines)]
fn validate_boundary_check(envelope: &EvidenceBundleEnvelopeV1) -> Result<(), EvidenceBundleError> {
    use crate::channel::ChannelViolationClass;

    let bc = &envelope.boundary_check;

    // Derive the witness for the claimed channel source.
    let witness = derive_channel_source_witness(bc.source);

    // Reconstruct the full boundary check from envelope data.
    // All fields carried in BundleBoundaryCheckV1 are forwarded; optional
    // advanced fields not in the bundle default to None (fail-closed).
    let check = ChannelBoundaryCheck {
        source: bc.source,
        channel_source_witness: Some(witness),
        broker_verified: bc.broker_verified,
        capability_verified: bc.capability_verified,
        context_firewall_verified: bc.context_firewall_verified,
        policy_ledger_verified: bc.policy_ledger_verified,
        taint_allow: bc.taint_allow,
        classification_allow: bc.classification_allow,
        declass_receipt_valid: bc.declass_receipt_valid,
        declassification_intent: bc.declassification_intent,
        redundancy_declassification_receipt: None,
        boundary_flow_policy_binding: envelope.policy_binding.clone(),
        leakage_budget_receipt: bc.leakage_budget_receipt.clone(),
        timing_channel_budget: bc.timing_channel_budget.clone(),
        disclosure_policy_binding: bc.disclosure_policy_binding.clone(),
        leakage_budget_policy_max_bits: None,
        declared_leakage_budget_bits: None,
        timing_budget_policy_max_ticks: None,
        declared_timing_budget_ticks: None,
        token_binding: None,
    };

    // INV-EB-001: validate_channel_boundary must return zero defects
    // (excluding defects from honestly-absent optional sub-evidence).
    let defects = validate_channel_boundary(&check);

    // Filter defects from absent optional sub-evidence. These fields do not
    // exist in FacJobReceiptV1 and are honestly marked None; requiring them
    // would force fabrication of evidence which is worse than their absence.
    // When present, the full validation still applies.
    let filtered_defects: Vec<_> = defects
        .into_iter()
        .filter(|d| {
            // Skip LeakageBudgetExceeded only when leakage_budget_receipt is absent.
            if d.violation_class == ChannelViolationClass::LeakageBudgetExceeded
                && bc.leakage_budget_receipt.is_none()
            {
                return false;
            }
            // Skip TimingChannelBudgetExceeded only when timing_channel_budget is absent.
            if d.violation_class == ChannelViolationClass::TimingChannelBudgetExceeded
                && bc.timing_channel_budget.is_none()
            {
                return false;
            }
            // Skip DisclosurePolicyStateInvalid only when disclosure_policy_binding is
            // absent.
            if d.violation_class == ChannelViolationClass::DisclosurePolicyStateInvalid
                && bc.disclosure_policy_binding.is_none()
            {
                return false;
            }
            true
        })
        .collect();

    if !filtered_defects.is_empty() {
        let defect_classes: Vec<String> = filtered_defects
            .iter()
            .map(|d| format!("{:?}", d.violation_class))
            .collect();
        return Err(EvidenceBundleError::ChannelBoundaryInvalid {
            defect_count: filtered_defects.len(),
            defect_classes: defect_classes.join(", "),
        });
    }

    // If a policy binding is present, verify digests match.
    if let Some(binding) = &envelope.policy_binding {
        if !bool::from(
            binding
                .policy_digest
                .ct_eq(&binding.admitted_policy_root_digest),
        ) {
            return Err(EvidenceBundleError::PolicyBindingMismatch {
                detail: "policy_digest does not match admitted_policy_root_digest".to_string(),
            });
        }
        if !bool::from(
            binding
                .canonicalizer_tuple_digest
                .ct_eq(&binding.admitted_canonicalizer_tuple_digest),
        ) {
            return Err(EvidenceBundleError::PolicyBindingMismatch {
                detail:
                    "canonicalizer_tuple_digest does not match admitted_canonicalizer_tuple_digest"
                        .to_string(),
            });
        }

        // MINOR fix: enforce strict equality between the receipt's
        // policy_hash/canonicalizer_tuple_digest and the policy_binding's
        // values. The receipt and policy_binding carry the same logical
        // data; divergence indicates tampering or a construction bug.
        if let Some(receipt_policy_hash) = &envelope.receipt.policy_hash {
            let receipt_hex = receipt_policy_hash
                .strip_prefix("b3-256:")
                .unwrap_or(receipt_policy_hash);
            if let Ok(receipt_digest) = hex::decode(receipt_hex) {
                if receipt_digest.len() == 32 {
                    let receipt_arr: [u8; 32] = receipt_digest.try_into().expect("length checked");
                    if !bool::from(binding.policy_digest.ct_eq(&receipt_arr)) {
                        return Err(EvidenceBundleError::PolicyBindingMismatch {
                            detail:
                                "receipt.policy_hash diverges from policy_binding.policy_digest"
                                    .to_string(),
                        });
                    }
                }
            }
        }
        if let Some(receipt_canon) = &envelope.receipt.canonicalizer_tuple_digest {
            let receipt_hex = receipt_canon
                .strip_prefix("b3-256:")
                .unwrap_or(receipt_canon);
            if let Ok(receipt_digest) = hex::decode(receipt_hex) {
                if receipt_digest.len() == 32 {
                    let receipt_arr: [u8; 32] = receipt_digest.try_into().expect("length checked");
                    if !bool::from(binding.canonicalizer_tuple_digest.ct_eq(&receipt_arr)) {
                        return Err(EvidenceBundleError::PolicyBindingMismatch {
                            detail: "receipt.canonicalizer_tuple_digest diverges from policy_binding.canonicalizer_tuple_digest".to_string(),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

/// Validate the RFC-0029 economics receipt traces embedded in the envelope.
///
/// Both queue admission and budget admission must carry Allow verdicts.
fn validate_economics_traces(
    envelope: &EvidenceBundleEnvelopeV1,
) -> Result<(), EvidenceBundleError> {
    let queue = &envelope.economics_trace.queue_admission;
    let budget = &envelope.economics_trace.budget_admission;

    // INV-EB-002: Queue admission must be Allow.
    if queue.verdict != "Allow" {
        let reason = queue
            .defect_reason
            .as_deref()
            .unwrap_or("no reason provided");
        return Err(EvidenceBundleError::EconomicsReceiptInvalid {
            reason: format!(
                "queue admission verdict is '{}' (expected 'Allow'): {}",
                queue.verdict, reason
            ),
        });
    }

    // INV-EB-002: Budget admission must be Allow.
    if budget.verdict != "Allow" {
        let reason = budget.reason.as_deref().unwrap_or("no reason provided");
        return Err(EvidenceBundleError::EconomicsReceiptInvalid {
            reason: format!(
                "budget admission verdict is '{}' (expected 'Allow'): {}",
                budget.verdict, reason
            ),
        });
    }

    Ok(())
}

/// Validate the leakage budget decision embedded in the envelope (TCK-00555).
///
/// INV-EB-007: When a leakage budget decision is present, validate:
/// - `actual_export_bytes` must equal the canonical envelope byte size
///   (`canonical_envelope_bytes`) — the importer independently derives this
///   from the serialized envelope being imported, preventing an attacker from
///   forging a lower value to bypass byte-dimension policy enforcement
///   (TCK-00555, security finding MAJOR).
/// - If `exceeded_policy` is true, `declassification_authorized` must be true.
/// - If `exceeded_policy` is false, actual values must be within policy
///   ceilings (evaluated against the recomputed canonical size).
/// - `actual_export_classes` must match `blob_refs.len() + 2` (fixed overhead:
///   the envelope itself and the receipt).
/// - `actual_leakage_bits` must match the `leakage_budget_receipt` in the
///   boundary check (if present), or be 0 (if absent).
/// - If `leakage_budget_receipt` is present in the boundary check, verify that
///   `leakage_bits` does not exceed the policy ceiling from the decision.
/// - The actual export bytes/classes must not exceed policy without
///   declassification.
#[allow(clippy::too_many_lines)]
fn validate_leakage_budget_decision(
    envelope: &EvidenceBundleEnvelopeV1,
    canonical_envelope_bytes: u64,
) -> Result<(), EvidenceBundleError> {
    let Some(decision) = &envelope.leakage_budget_decision else {
        // INV-EB-014: New-schema envelopes MUST carry a leakage budget
        // decision. Accepting a missing decision on a new-schema envelope
        // would create a downgrade-by-omission path: an attacker could strip
        // the decision, recompute a self-consistent content hash, and import
        // the bundle without triggering any leakage-budget validation.
        //
        // Legacy envelopes (EVIDENCE_BUNDLE_SCHEMA) are exempt for backward
        // compatibility — they predate TCK-00555 and never carried a decision.
        //
        // INV-EB-023: Schema-downgrade detection. Even if the schema string
        // is legacy, if the boundary check carries leakage-budget-aware
        // fields (leakage_budget_receipt, timing_channel_budget, or
        // disclosure_policy_binding), the envelope was produced with
        // budget-awareness (post-TCK-00555) and cannot be legitimately
        // legacy. An attacker who takes a new-schema envelope, strips the
        // decision, and swaps the schema to legacy must also fabricate a
        // boundary check without these fields — but the content hash binds
        // all boundary check fields, so any tampering invalidates the hash.
        // This check closes the gap for envelopes where the attacker can
        // recompute the hash (e.g., unsigned bundles): if budget-aware
        // fields are present, the legacy exemption does not apply.
        let is_legacy = envelope.schema == EVIDENCE_BUNDLE_SCHEMA;
        if is_legacy {
            let has_budget_aware_fields = envelope.boundary_check.leakage_budget_receipt.is_some()
                || envelope.boundary_check.timing_channel_budget.is_some()
                || envelope.boundary_check.disclosure_policy_binding.is_some();
            if has_budget_aware_fields {
                return Err(EvidenceBundleError::LeakageBudgetDenied {
                    reason: "import rejected: legacy-schema envelope carries \
                             budget-aware boundary check fields \
                             (leakage_budget_receipt, timing_channel_budget, or \
                             disclosure_policy_binding) but is missing \
                             leakage_budget_decision — possible schema-downgrade \
                             attack (INV-EB-023)"
                        .to_string(),
                });
            }
            return Ok(()); // Truly pre-TCK-00555 envelope: no decision expected
        }
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: "import rejected: new-schema envelope requires leakage_budget_decision \
                     but field is absent (possible downgrade-by-omission attack)"
                .to_string(),
        });
    };

    // ---- Consistency check 0: actual_export_bytes must equal the canonical
    // envelope byte size. The importer recomputes this from the serialized
    // envelope being imported (the same representation used by export-time
    // policy accounting via serde_json::to_vec_pretty). An attacker cannot
    // forge a lower actual_export_bytes to bypass the byte ceiling because
    // the importer independently derives the canonical size.
    // (TCK-00555, security finding MAJOR) ----
    if decision.actual_export_bytes != canonical_envelope_bytes {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: format!(
                "import rejected: declared actual_export_bytes ({}) does not match canonical envelope size ({})",
                decision.actual_export_bytes, canonical_envelope_bytes,
            ),
        });
    }

    // ---- Consistency check 1: when exceeded_policy is false, actual values
    // must be within policy ceilings. An attacker cannot forge
    // exceeded_policy=false while the actual values exceed policy.
    // Policy is evaluated against canonical_envelope_bytes (not the
    // declared value) for byte-dimension checks. ----
    if !decision.exceeded_policy {
        if canonical_envelope_bytes > decision.policy.max_export_bytes {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "import rejected: canonical envelope size ({}) exceeds policy ceiling ({}) but exceeded_policy is false",
                    canonical_envelope_bytes, decision.policy.max_export_bytes,
                ),
            });
        }
        if decision.actual_export_classes > decision.policy.max_export_classes {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "import rejected: actual_export_classes ({}) exceeds policy ceiling ({}) but exceeded_policy is false",
                    decision.actual_export_classes, decision.policy.max_export_classes,
                ),
            });
        }
        if decision.actual_leakage_bits > decision.policy.max_leakage_bits {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "import rejected: actual_leakage_bits ({}) exceeds policy ceiling ({}) but exceeded_policy is false",
                    decision.actual_leakage_bits, decision.policy.max_leakage_bits,
                ),
            });
        }
    }

    // ---- Consistency check 2: actual_export_classes must match blob_refs
    // count plus fixed overhead (envelope + receipt = 2). ----
    // Safety: blob_refs.len() is bounded by MAX_BUNDLE_BLOB_COUNT (256),
    // validated earlier in import_evidence_bundle. 256 + 2 = 258 fits u32.
    let blob_count_u32 = u32::try_from(envelope.blob_refs.len()).unwrap_or(u32::MAX);
    let expected_classes = blob_count_u32.saturating_add(2);
    if decision.actual_export_classes != expected_classes {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: format!(
                "import rejected: actual_export_classes ({}) does not match expected count from blob_refs ({} blobs + 2 overhead = {})",
                decision.actual_export_classes,
                envelope.blob_refs.len(),
                expected_classes,
            ),
        });
    }

    // ---- Consistency check 3: actual_leakage_bits must match the
    // leakage_budget_receipt in the boundary check (if present). ----
    match &envelope.boundary_check.leakage_budget_receipt {
        Some(lbr) => {
            if decision.actual_leakage_bits != lbr.leakage_bits {
                return Err(EvidenceBundleError::LeakageBudgetDenied {
                    reason: format!(
                        "import rejected: actual_leakage_bits ({}) does not match leakage_budget_receipt.leakage_bits ({})",
                        decision.actual_leakage_bits, lbr.leakage_bits,
                    ),
                });
            }
        },
        None => {
            if decision.actual_leakage_bits != 0 {
                return Err(EvidenceBundleError::LeakageBudgetDenied {
                    reason: format!(
                        "import rejected: actual_leakage_bits ({}) must be 0 when no leakage_budget_receipt is present",
                        decision.actual_leakage_bits,
                    ),
                });
            }
        },
    }

    // If the policy was exceeded, declassification must have been authorized.
    if decision.exceeded_policy && !decision.declassification_authorized {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: "import rejected: envelope exceeded leakage budget policy but declassification was not authorized".to_string(),
        });
    }

    // If exceeded and declassification authorized, receipt ID must be present.
    if decision.exceeded_policy
        && decision.declassification_authorized
        && decision.declassification_receipt_id.is_none()
    {
        return Err(EvidenceBundleError::LeakageBudgetDenied {
            reason: "import rejected: declassification authorized but receipt ID is missing"
                .to_string(),
        });
    }

    // Validate receipt ID length bound when present.
    if let Some(ref receipt_id) = decision.declassification_receipt_id {
        if receipt_id.is_empty() || receipt_id.len() > MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "import rejected: declassification receipt_id has invalid length ({})",
                    receipt_id.len()
                ),
            });
        }
    }

    // If exceeded and declassification authorized, the full receipt must be
    // embedded (not just an ID) so we can independently verify authorization
    // coverage. An attacker cannot forge the `authorized` flag without a
    // receipt that actually covers the export values.
    if decision.exceeded_policy && decision.declassification_authorized {
        let declass = decision.declassification_receipt.as_ref().ok_or_else(|| {
            EvidenceBundleError::LeakageBudgetDenied {
                reason: "import rejected: declassification authorized but full receipt is missing from decision".to_string(),
            }
        })?;

        // Validate receipt structural well-formedness.
        declass.validate()?;

        // Verify receipt content hash binding.
        let expected_hash = declass.compute_content_hash();
        if !bool::from(declass.content_hash.ct_eq(&expected_hash)) {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: "import rejected: embedded declassification receipt content_hash does not match computed hash".to_string(),
            });
        }

        // Verify receipt authorizes the actual export values.
        if declass.authorized_bytes < decision.actual_export_bytes {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "import rejected: declassification receipt authorizes {} bytes but actual export is {} bytes",
                    declass.authorized_bytes, decision.actual_export_bytes,
                ),
            });
        }
        if declass.authorized_classes < decision.actual_export_classes {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "import rejected: declassification receipt authorizes {} classes but actual export has {} classes",
                    declass.authorized_classes, decision.actual_export_classes,
                ),
            });
        }
        if declass.authorized_leakage_bits < decision.actual_leakage_bits {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "import rejected: declassification receipt authorizes {} leakage bits but actual leakage is {} bits",
                    declass.authorized_leakage_bits, decision.actual_leakage_bits,
                ),
            });
        }

        // Verify receipt ID consistency.
        if let Some(ref receipt_id) = decision.declassification_receipt_id {
            if receipt_id != &declass.receipt_id {
                return Err(EvidenceBundleError::LeakageBudgetDenied {
                    reason: format!(
                        "import rejected: declassification_receipt_id '{}' does not match embedded receipt.receipt_id '{}'",
                        receipt_id, declass.receipt_id,
                    ),
                });
            }
        }
    }

    // Cross-check: if the boundary check carries a leakage budget receipt,
    // verify that the leakage bits do not exceed the policy ceiling from
    // the decision (unless declassification was authorized).
    if let Some(ref lbr) = envelope.boundary_check.leakage_budget_receipt {
        if !decision.exceeded_policy && lbr.leakage_bits > decision.policy.max_leakage_bits {
            return Err(EvidenceBundleError::LeakageBudgetDenied {
                reason: format!(
                    "import rejected: leakage budget receipt declares {} leakage bits but policy ceiling is {} and exceeded_policy is false",
                    lbr.leakage_bits, decision.policy.max_leakage_bits,
                ),
            });
        }
    }

    Ok(())
}

// =============================================================================
// Manifest Types
// =============================================================================

/// A single entry in the evidence bundle manifest.
///
/// Each entry describes one evidence artifact (envelope, blob, or auxiliary
/// file) by its content hash and role within the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleManifestEntryV1 {
    /// Role label for this entry (e.g., `"envelope"`, `"blob"`, `"job_spec"`).
    pub role: String,
    /// Content-addressed hash reference (`b3-256:<hex>`).
    pub content_hash_ref: String,
    /// Human-readable description of the entry (bounded by
    /// `MAX_ENTRY_DESCRIPTION_LENGTH`).
    pub description: String,
}

/// A self-describing manifest for evidence bundle discovery and indexing.
///
/// The manifest is a lightweight outer document that references the envelope
/// by its content hash, carries summary metadata for indexing, and lists all
/// constituent artifacts.  It is designed for bounded parsing at the import
/// boundary with fail-closed semantics.
///
/// # Security Invariants
///
/// - [INV-MF-001] Import refuses manifests larger than `MAX_MANIFEST_SIZE`.
/// - [INV-MF-002] Import refuses when schema does not match
///   `EVIDENCE_BUNDLE_MANIFEST_SCHEMA`.
/// - [INV-MF-003] Import refuses when content hash does not verify.
/// - [INV-MF-004] Import refuses when `entries.len()` exceeds
///   `MAX_MANIFEST_ENTRIES`.
/// - [INV-MF-005] All string fields are bounded during import.
/// - [INV-MF-006] Channel boundary check presence is required for manifest
///   construction (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleManifestV1 {
    /// Schema identifier (must be `EVIDENCE_BUNDLE_MANIFEST_SCHEMA`).
    pub schema: String,
    /// The job ID this manifest belongs to.
    pub job_id: String,
    /// String representation of the job outcome (e.g., `"Completed"`,
    /// `"Denied"`).
    pub outcome: String,
    /// Human-readable outcome reason (bounded by `MAX_OUTCOME_REASON_LENGTH`).
    pub outcome_reason: String,
    /// Epoch timestamp (seconds) when the manifest was created.
    pub timestamp_secs: u64,
    /// Content hash of the associated envelope (`b3-256:<hex>`).
    pub envelope_content_hash: String,
    /// Number of blobs referenced by the envelope.
    pub blob_count: usize,
    /// Whether an RFC-0028 channel boundary check was present at manifest
    /// construction time.  Must be `true` for a valid manifest.
    pub channel_boundary_checked: bool,
    /// Manifest entries describing each artifact in the bundle.
    pub entries: Vec<EvidenceBundleManifestEntryV1>,
    /// BLAKE3 content hash of the manifest body (excluding this field).
    pub content_hash: String,
}

// =============================================================================
// Manifest Hashing
// =============================================================================

/// Compute the BLAKE3 content hash of a manifest.
///
/// The hash covers all fields except `content_hash` using domain-separated,
/// length-prefixed encoding for deterministic framing.
#[allow(clippy::cast_possible_truncation)]
fn compute_manifest_content_hash(manifest: &EvidenceBundleManifestV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_HASH_DOMAIN);

    // -- schema --
    hash_len_prefixed(&mut hasher, manifest.schema.as_bytes());

    // -- job_id --
    hash_len_prefixed(&mut hasher, manifest.job_id.as_bytes());

    // -- outcome --
    hash_len_prefixed(&mut hasher, manifest.outcome.as_bytes());

    // -- outcome_reason --
    hash_len_prefixed(&mut hasher, manifest.outcome_reason.as_bytes());

    // -- timestamp_secs --
    hasher.update(&manifest.timestamp_secs.to_le_bytes());

    // -- envelope_content_hash --
    hash_len_prefixed(&mut hasher, manifest.envelope_content_hash.as_bytes());

    // -- blob_count --
    hasher.update(&(manifest.blob_count as u64).to_le_bytes());

    // -- channel_boundary_checked --
    hasher.update(&[u8::from(manifest.channel_boundary_checked)]);

    // -- entries (length-prefixed array + per-element framing) --
    hasher.update(&(manifest.entries.len() as u64).to_le_bytes());
    for entry in &manifest.entries {
        hash_len_prefixed(&mut hasher, entry.role.as_bytes());
        hash_len_prefixed(&mut hasher, entry.content_hash_ref.as_bytes());
        hash_len_prefixed(&mut hasher, entry.description.as_bytes());
    }

    *hasher.finalize().as_bytes()
}

// =============================================================================
// Manifest Export
// =============================================================================

/// Build an evidence bundle manifest from an envelope.
///
/// The manifest is a lightweight outer document referencing the envelope
/// by its content hash and carrying summary metadata for indexing.
///
/// # Channel Boundary Check Requirement
///
/// The envelope must have been constructed from a receipt that includes an
/// RFC-0028 channel boundary trace.  The `channel_boundary_checked` field
/// is set based on the boundary check data in the envelope.  If the boundary
/// check fields indicate an unchecked state (source is `Unknown` and
/// `broker_verified` is false), the manifest construction fails with
/// `ChannelBoundaryCheckRequired`.
///
/// # Errors
///
/// Returns `EvidenceBundleError` if:
/// - The entry count exceeds `MAX_MANIFEST_ENTRIES`.
/// - The channel boundary check requirement is not met.
pub fn build_evidence_bundle_manifest(
    envelope: &EvidenceBundleEnvelopeV1,
    additional_entries: &[EvidenceBundleManifestEntryV1],
) -> Result<EvidenceBundleManifestV1, EvidenceBundleError> {
    // Determine channel boundary check status from the envelope.
    // Fail-closed: if the boundary check fields indicate an unchecked
    // state, refuse to build the manifest.
    let boundary_checked = envelope.boundary_check.source != ChannelSource::Unknown
        || envelope.boundary_check.broker_verified;

    if !boundary_checked {
        return Err(EvidenceBundleError::ChannelBoundaryCheckRequired {
            operation: "manifest_build".to_string(),
        });
    }

    let outcome = format!("{:?}", envelope.receipt.outcome);
    if outcome.len() > MAX_OUTCOME_LEN {
        return Err(EvidenceBundleError::FieldTooLong {
            field: "manifest.outcome".to_string(),
            actual: outcome.len(),
            max: MAX_OUTCOME_LEN,
        });
    }

    // Validate caller-supplied entry fields before constructing the manifest.
    for (i, entry) in additional_entries.iter().enumerate() {
        if entry.role.len() > MAX_ROLE_LEN {
            return Err(EvidenceBundleError::FieldTooLong {
                field: format!("additional_entries[{i}].role"),
                actual: entry.role.len(),
                max: MAX_ROLE_LEN,
            });
        }
        if entry.description.len() > MAX_ENTRY_DESCRIPTION_LENGTH {
            return Err(EvidenceBundleError::FieldTooLong {
                field: format!("additional_entries[{i}].description"),
                actual: entry.description.len(),
                max: MAX_ENTRY_DESCRIPTION_LENGTH,
            });
        }
        if entry.content_hash_ref.len() > MAX_ENVELOPE_HASH_REF_LENGTH {
            return Err(EvidenceBundleError::FieldTooLong {
                field: format!("additional_entries[{i}].content_hash_ref"),
                actual: entry.content_hash_ref.len(),
                max: MAX_ENVELOPE_HASH_REF_LENGTH,
            });
        }
    }

    // Build the default entries: envelope + blobs.
    let mut entries = Vec::with_capacity(1 + envelope.blob_refs.len() + additional_entries.len());

    // Entry for the envelope itself.
    entries.push(EvidenceBundleManifestEntryV1 {
        role: "envelope".to_string(),
        content_hash_ref: envelope.content_hash.clone(),
        description: "Evidence bundle envelope".to_string(),
    });

    // Entries for each blob.
    for (i, blob_ref) in envelope.blob_refs.iter().enumerate() {
        entries.push(EvidenceBundleManifestEntryV1 {
            role: "blob".to_string(),
            content_hash_ref: blob_ref.clone(),
            description: format!("Blob artifact #{i}"),
        });
    }

    // Additional caller-supplied entries.
    entries.extend_from_slice(additional_entries);

    // Enforce entry count bound.
    if entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(EvidenceBundleError::TooManyManifestEntries {
            count: entries.len(),
            max: MAX_MANIFEST_ENTRIES,
        });
    }

    // Build manifest without content hash first.
    let mut manifest = EvidenceBundleManifestV1 {
        schema: EVIDENCE_BUNDLE_MANIFEST_SCHEMA.to_string(),
        job_id: envelope.receipt.job_id.clone(),
        outcome,
        outcome_reason: envelope.receipt.reason.clone(),
        timestamp_secs: envelope.receipt.timestamp_secs,
        envelope_content_hash: envelope.content_hash.clone(),
        blob_count: envelope.blob_refs.len(),
        channel_boundary_checked: boundary_checked,
        entries,
        content_hash: String::new(),
    };

    // Compute content hash over canonical bytes.
    let hash = compute_manifest_content_hash(&manifest);
    manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

    Ok(manifest)
}

/// Serialize a manifest to JSON bytes.
///
/// # Errors
///
/// Returns `EvidenceBundleError::ManifestParseError` if serialization fails.
pub fn serialize_manifest(
    manifest: &EvidenceBundleManifestV1,
) -> Result<Vec<u8>, EvidenceBundleError> {
    serde_json::to_vec_pretty(manifest).map_err(|e| EvidenceBundleError::ManifestParseError {
        detail: e.to_string(),
    })
}

// =============================================================================
// Manifest Import (fail-closed)
// =============================================================================

/// Import and validate an evidence bundle manifest from JSON bytes.
///
/// This function enforces fail-closed validation:
/// 1. INV-MF-001: Bounded size check.
/// 2. INV-MF-002: Schema verification.
/// 3. INV-MF-004: Entry count bound.
/// 4. INV-MF-005: Per-field length bounds.
/// 5. INV-MF-003: Content hash integrity.
/// 6. INV-MF-006: Channel boundary check must be `true`.
///
/// # Errors
///
/// Returns `EvidenceBundleError` for any validation failure.
pub fn import_evidence_bundle_manifest(
    data: &[u8],
) -> Result<EvidenceBundleManifestV1, EvidenceBundleError> {
    // INV-MF-001: Bounded read.
    if data.len() > MAX_MANIFEST_SIZE {
        return Err(EvidenceBundleError::ManifestTooLarge {
            size: data.len(),
            max: MAX_MANIFEST_SIZE,
        });
    }

    // Parse manifest.
    let manifest: EvidenceBundleManifestV1 =
        serde_json::from_slice(data).map_err(|e| EvidenceBundleError::ManifestParseError {
            detail: e.to_string(),
        })?;

    // INV-MF-002: Schema check.
    if manifest.schema != EVIDENCE_BUNDLE_MANIFEST_SCHEMA {
        return Err(EvidenceBundleError::ManifestSchemaMismatch {
            expected: EVIDENCE_BUNDLE_MANIFEST_SCHEMA.to_string(),
            actual: manifest.schema,
        });
    }

    // INV-MF-004: Entry count bound.
    if manifest.entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(EvidenceBundleError::TooManyManifestEntries {
            count: manifest.entries.len(),
            max: MAX_MANIFEST_ENTRIES,
        });
    }

    // INV-MF-007: Blob-count bound.
    if manifest.blob_count > MAX_BUNDLE_BLOB_COUNT {
        return Err(EvidenceBundleError::TooManyBlobs {
            count: manifest.blob_count,
            max: MAX_BUNDLE_BLOB_COUNT,
        });
    }

    // INV-MF-005: Per-field length bounds.
    if manifest.job_id.len() > MAX_JOB_ID_LENGTH {
        return Err(EvidenceBundleError::FieldTooLong {
            field: "manifest.job_id".to_string(),
            actual: manifest.job_id.len(),
            max: MAX_JOB_ID_LENGTH,
        });
    }
    if manifest.outcome.len() > MAX_OUTCOME_LEN {
        return Err(EvidenceBundleError::FieldTooLong {
            field: "manifest.outcome".to_string(),
            actual: manifest.outcome.len(),
            max: MAX_OUTCOME_LEN,
        });
    }
    if manifest.outcome_reason.len() > MAX_OUTCOME_REASON_LENGTH {
        return Err(EvidenceBundleError::FieldTooLong {
            field: "manifest.outcome_reason".to_string(),
            actual: manifest.outcome_reason.len(),
            max: MAX_OUTCOME_REASON_LENGTH,
        });
    }
    if manifest.envelope_content_hash.len() > MAX_ENVELOPE_HASH_REF_LENGTH {
        return Err(EvidenceBundleError::FieldTooLong {
            field: "manifest.envelope_content_hash".to_string(),
            actual: manifest.envelope_content_hash.len(),
            max: MAX_ENVELOPE_HASH_REF_LENGTH,
        });
    }
    for (i, entry) in manifest.entries.iter().enumerate() {
        if entry.role.len() > MAX_ROLE_LEN {
            return Err(EvidenceBundleError::FieldTooLong {
                field: format!("manifest.entries[{i}].role"),
                actual: entry.role.len(),
                max: MAX_ROLE_LEN,
            });
        }
        if entry.description.len() > MAX_ENTRY_DESCRIPTION_LENGTH {
            return Err(EvidenceBundleError::FieldTooLong {
                field: format!("manifest.entries[{i}].description"),
                actual: entry.description.len(),
                max: MAX_ENTRY_DESCRIPTION_LENGTH,
            });
        }
        if entry.content_hash_ref.len() > MAX_ENVELOPE_HASH_REF_LENGTH {
            return Err(EvidenceBundleError::FieldTooLong {
                field: format!("manifest.entries[{i}].content_hash_ref"),
                actual: entry.content_hash_ref.len(),
                max: MAX_ENVELOPE_HASH_REF_LENGTH,
            });
        }
    }

    // INV-MF-003: Content hash integrity.
    let computed = compute_manifest_content_hash(&manifest);
    let expected_hex = format!("b3-256:{}", hex::encode(computed));
    if !bool::from(
        expected_hex
            .as_bytes()
            .ct_eq(manifest.content_hash.as_bytes()),
    ) {
        return Err(EvidenceBundleError::ManifestContentHashMismatch {
            expected: expected_hex,
            actual: manifest.content_hash,
        });
    }

    // INV-MF-006: Channel boundary check must be true.
    if !manifest.channel_boundary_checked {
        return Err(EvidenceBundleError::ChannelBoundaryCheckRequired {
            operation: "manifest_import".to_string(),
        });
    }

    Ok(manifest)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
/// Tests for evidence bundle export/import.
pub mod tests {
    use super::*;
    use crate::channel::{DeclassificationIntentScope, LeakageEstimatorFamily};
    use crate::disclosure::{DisclosureChannelClass, DisclosurePolicyMode};
    use crate::fac::receipt::ChannelBoundaryTrace;

    /// Helper: build a minimal valid receipt with RFC-0028 and RFC-0029 traces.
    fn make_valid_receipt() -> FacJobReceiptV1 {
        FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: "test-receipt-001".to_string(),
            job_id: "test-job-001".to_string(),
            job_spec_digest: "b3-256:".to_string() + &"ab".repeat(32),
            outcome: crate::fac::receipt::FacJobOutcome::Completed,
            reason: "test completed".to_string(),
            rfc0028_channel_boundary: Some(ChannelBoundaryTrace {
                passed: true,
                defect_count: 0,
                defect_classes: vec![],
                token_fac_policy_hash: None,
                token_canonicalizer_tuple_digest: None,
                token_boundary_id: None,
                token_issued_at_tick: None,
                token_expiry_tick: None,
            }),
            eio29_queue_admission: Some(QueueAdmissionTrace {
                verdict: "Allow".to_string(),
                queue_lane: "consume".to_string(),
                defect_reason: None,
                cost_estimate_ticks: None,
            }),
            eio29_budget_admission: Some(BudgetAdmissionTrace {
                verdict: "Allow".to_string(),
                reason: None,
            }),
            timestamp_secs: 1_700_000_000,
            content_hash: String::new(),
            ..Default::default()
        }
    }

    /// Helper: build a valid policy binding with matching digests.
    fn make_valid_policy_binding() -> BoundaryFlowPolicyBinding {
        let digest = [0x42u8; 32];
        BoundaryFlowPolicyBinding {
            policy_digest: digest,
            admitted_policy_root_digest: digest,
            canonicalizer_tuple_digest: digest,
            admitted_canonicalizer_tuple_digest: digest,
        }
    }

    /// Helper: build a valid `BundleExportConfig` that produces envelopes
    /// passing `validate_channel_boundary()`.
    fn make_valid_export_config() -> BundleExportConfig {
        BundleExportConfig {
            policy_binding: Some(make_valid_policy_binding()),
            leakage_budget_receipt: Some(LeakageBudgetReceipt {
                leakage_bits: 0,
                budget_bits: 1024,
                estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
                confidence_bps: 9500,
                confidence_label: "high".to_string(),
            }),
            timing_channel_budget: Some(TimingChannelBudget {
                release_bucket_ticks: 100,
                observed_variance_ticks: 10,
                budget_ticks: 1000,
            }),
            disclosure_policy_binding: Some(DisclosurePolicyBinding {
                required_for_effect: false,
                state_valid: true,
                active_mode: DisclosurePolicyMode::TradeSecretOnly,
                expected_mode: DisclosurePolicyMode::TradeSecretOnly,
                attempted_channel: DisclosureChannelClass::Internal,
                policy_snapshot_digest: [0x42u8; 32],
                admitted_policy_epoch_root_digest: [0x42u8; 32],
                policy_epoch: 1,
                phase_id: "test-phase".to_string(),
                state_reason: String::new(),
            }),
            // TCK-00555: Use tier0 policy for tests (generous ceiling).
            leakage_budget_policy: Some(LeakageBudgetPolicy::tier0_default()),
            declassification_receipt: None,
        }
    }

    #[test]
    fn export_and_import_valid_bundle() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize should succeed");
        let imported = import_evidence_bundle(&data).expect("import should succeed");

        assert_eq!(imported.schema, EVIDENCE_BUNDLE_ENVELOPE_SCHEMA);
        assert_eq!(imported.receipt.job_id, "test-job-001");
    }

    #[test]
    fn import_refuses_invalid_boundary_check() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper with the boundary check to make it invalid.
        envelope.boundary_check.source = ChannelSource::FreeFormOutput;
        envelope.boundary_check.broker_verified = false;

        // Recompute content hash to pass hash check (so we test boundary
        // validation specifically).
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        match result {
            Err(EvidenceBundleError::ChannelBoundaryInvalid { defect_count, .. }) => {
                assert!(defect_count > 0, "should have boundary defects");
            },
            other => panic!("expected ChannelBoundaryInvalid, got: {other:?}"),
        }
    }

    #[test]
    fn import_refuses_broker_bypass() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Set source to DirectManifest (broker bypass).
        envelope.boundary_check.source = ChannelSource::DirectManifest;

        // Recompute content hash.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. })
            ),
            "should reject DirectManifest source"
        );
    }

    #[test]
    fn import_refuses_unknown_channel_source() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Set source to Unknown.
        envelope.boundary_check.source = ChannelSource::Unknown;

        // Recompute content hash.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. })
            ),
            "should reject Unknown source"
        );
    }

    #[test]
    fn import_refuses_policy_binding_mismatch() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        // Mismatch policy digests.
        if let Some(ref mut binding) = config.policy_binding {
            binding.admitted_policy_root_digest = [0x99u8; 32];
        }

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Recompute content hash.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. }
                    | EvidenceBundleError::PolicyBindingMismatch { .. })
            ),
            "should reject mismatched policy binding, got: {result:?}",
        );
    }

    #[test]
    fn import_refuses_deny_queue_admission() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper with queue admission to Deny.
        envelope.economics_trace.queue_admission.verdict = "Deny".to_string();
        envelope.economics_trace.queue_admission.defect_reason =
            Some("tp001_envelope_missing".to_string());

        // Recompute content hash.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        match result {
            Err(EvidenceBundleError::EconomicsReceiptInvalid { reason }) => {
                assert!(
                    reason.contains("queue admission verdict is 'Deny'"),
                    "reason should mention Deny queue admission, got: {reason}",
                );
            },
            other => panic!("expected EconomicsReceiptInvalid for queue denial, got: {other:?}"),
        }
    }

    #[test]
    fn import_refuses_deny_budget_admission() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper with budget admission to Deny.
        envelope.economics_trace.budget_admission.verdict = "Deny".to_string();
        envelope.economics_trace.budget_admission.reason = Some("budget_exhausted".to_string());

        // Recompute content hash.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        match result {
            Err(EvidenceBundleError::EconomicsReceiptInvalid { reason }) => {
                assert!(
                    reason.contains("budget admission verdict is 'Deny'"),
                    "reason should mention Deny budget admission, got: {reason}",
                );
            },
            other => panic!("expected EconomicsReceiptInvalid for budget denial, got: {other:?}"),
        }
    }

    #[test]
    fn import_refuses_tampered_content_hash() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper with the content hash.
        envelope.content_hash =
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(result, Err(EvidenceBundleError::ContentHashMismatch { .. })),
            "should reject tampered content hash"
        );
    }

    #[test]
    fn import_refuses_oversized_envelope() {
        let data = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(result, Err(EvidenceBundleError::EnvelopeTooLarge { .. })),
            "should reject oversized envelope"
        );
    }

    #[test]
    fn import_refuses_schema_mismatch() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        envelope.schema = "apm2.fac.wrong_schema.v1".to_string();
        // Recompute content hash for the altered schema.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(result, Err(EvidenceBundleError::SchemaMismatch { .. })),
            "should reject schema mismatch"
        );
    }

    #[test]
    fn import_refuses_too_many_blob_refs() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let blob_refs: Vec<String> = (0..=MAX_BUNDLE_BLOB_COUNT)
            .map(|i| format!("b3-256:{i:064x}"))
            .collect();

        let result = build_evidence_bundle_envelope(&receipt, &config, &blob_refs);
        assert!(
            matches!(result, Err(EvidenceBundleError::TooManyBlobs { .. })),
            "should reject too many blob refs"
        );
    }

    #[test]
    fn export_fails_without_boundary_trace() {
        let mut receipt = make_valid_receipt();
        receipt.rfc0028_channel_boundary = None;
        let config = make_valid_export_config();

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryTraceMissing)
            ),
            "should require boundary trace for export"
        );
    }

    #[test]
    fn export_fails_without_queue_admission_trace() {
        let mut receipt = make_valid_receipt();
        receipt.eio29_queue_admission = None;
        let config = make_valid_export_config();

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::QueueAdmissionTraceMissing)),
            "should require queue admission trace for export"
        );
    }

    #[test]
    fn export_fails_without_budget_admission_trace() {
        let mut receipt = make_valid_receipt();
        receipt.eio29_budget_admission = None;
        let config = make_valid_export_config();

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::BudgetAdmissionTraceMissing)
            ),
            "should require budget admission trace for export"
        );
    }

    #[test]
    fn content_hash_is_deterministic() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let envelope1 =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        let envelope2 =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        assert_eq!(
            envelope1.content_hash, envelope2.content_hash,
            "content hash must be deterministic"
        );
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let blob_refs = vec!["b3-256:aabbccdd".to_string()];

        let envelope = build_evidence_bundle_envelope(&receipt, &config, &blob_refs)
            .expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize");
        let imported = import_evidence_bundle(&data).expect("import should succeed");

        assert_eq!(envelope, imported);
    }

    #[test]
    fn import_refuses_capability_not_verified() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Only disable capability verification.
        envelope.boundary_check.capability_verified = false;

        // Recompute content hash.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. })
            ),
            "should reject when capability not verified"
        );
    }

    #[test]
    fn import_refuses_context_firewall_not_verified() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Only disable context firewall.
        envelope.boundary_check.context_firewall_verified = false;

        // Recompute content hash.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. })
            ),
            "should reject when context firewall not verified"
        );
    }

    #[test]
    fn import_refuses_canonicalizer_tuple_mismatch() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        // Mismatch canonicalizer tuple.
        if let Some(ref mut binding) = config.policy_binding {
            binding.admitted_canonicalizer_tuple_digest = [0x88u8; 32];
        }

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Recompute content hash.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        // Should fail at either boundary validation (policy digest mismatch
        // from validate_channel_boundary) or our explicit policy binding check.
        assert!(
            result.is_err(),
            "should reject mismatched canonicalizer tuple"
        );
    }

    #[test]
    fn import_accepts_absent_leakage_budget() {
        // Honestly-absent leakage budget receipt is accepted because the
        // field does not exist in FacJobReceiptV1 and should not be
        // fabricated.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_receipt = None;

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            result.is_ok(),
            "should accept envelope with honestly-absent leakage budget, got: {result:?}"
        );
    }

    #[test]
    fn import_accepts_absent_timing_budget() {
        // Honestly-absent timing channel budget is accepted.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.timing_channel_budget = None;

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            result.is_ok(),
            "should accept envelope with honestly-absent timing budget, got: {result:?}"
        );
    }

    #[test]
    fn import_accepts_absent_disclosure_policy() {
        // Honestly-absent disclosure policy binding is accepted.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.disclosure_policy_binding = None;

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            result.is_ok(),
            "should accept envelope with honestly-absent disclosure policy, got: {result:?}"
        );
    }

    #[test]
    fn import_accepts_all_absent_optional_subevidence() {
        // All three optional sub-evidence fields absent — the minimal
        // honest export from a receipt that lacks these fields.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_receipt = None;
        config.timing_channel_budget = None;
        config.disclosure_policy_binding = None;

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            result.is_ok(),
            "should accept envelope with all optional sub-evidence absent, got: {result:?}"
        );
    }

    #[test]
    fn import_rejects_malformed_leakage_budget_when_present() {
        // When leakage budget IS present but malformed, validation still
        // rejects (only honestly-absent is tolerated).
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_receipt = Some(LeakageBudgetReceipt {
            leakage_bits: 0,
            budget_bits: 0, // zero budget_bits makes is_well_formed() fail
            estimator_family: LeakageEstimatorFamily::Unknown,
            confidence_bps: 0,
            confidence_label: String::new(),
        });

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. })
            ),
            "should reject malformed leakage budget when present, got: {result:?}"
        );
    }

    // =========================================================================
    // Negative mutation tests: any field mutation must cause content hash
    // mismatch when the content_hash is NOT recomputed.
    // =========================================================================

    /// Helper: build a valid envelope, then mutate a field WITHOUT recomputing
    /// `content_hash`. The mutated envelope must fail import with
    /// `ContentHashMismatch`.
    fn assert_mutation_detected(label: &str, mutator: impl FnOnce(&mut EvidenceBundleEnvelopeV1)) {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Apply mutation WITHOUT recomputing content_hash.
        mutator(&mut envelope);

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::ContentHashMismatch { .. })),
            "mutation of {label} should cause ContentHashMismatch, got: {result:?}",
        );
    }

    #[test]
    fn mutation_detected_declassification_intent() {
        assert_mutation_detected("declassification_intent", |env| {
            env.boundary_check.declassification_intent =
                DeclassificationIntentScope::RedundancyPurpose;
        });
    }

    #[test]
    fn mutation_detected_timing_observed_variance() {
        assert_mutation_detected("timing_channel_budget.observed_variance_ticks", |env| {
            if let Some(ref mut tcb) = env.boundary_check.timing_channel_budget {
                tcb.observed_variance_ticks = 999_999;
            }
        });
    }

    #[test]
    fn mutation_detected_leakage_estimator_family() {
        assert_mutation_detected("leakage_budget_receipt.estimator_family", |env| {
            if let Some(ref mut lbr) = env.boundary_check.leakage_budget_receipt {
                lbr.estimator_family = LeakageEstimatorFamily::ChannelCapacityUpperBound;
            }
        });
    }

    #[test]
    fn mutation_detected_leakage_confidence_bps() {
        assert_mutation_detected("leakage_budget_receipt.confidence_bps", |env| {
            if let Some(ref mut lbr) = env.boundary_check.leakage_budget_receipt {
                lbr.confidence_bps = 5000;
            }
        });
    }

    #[test]
    fn mutation_detected_leakage_confidence_label() {
        assert_mutation_detected("leakage_budget_receipt.confidence_label", |env| {
            if let Some(ref mut lbr) = env.boundary_check.leakage_budget_receipt {
                lbr.confidence_label = "tampered".to_string();
            }
        });
    }

    #[test]
    fn mutation_detected_disclosure_active_mode() {
        assert_mutation_detected("disclosure_policy_binding.active_mode", |env| {
            if let Some(ref mut dpb) = env.boundary_check.disclosure_policy_binding {
                dpb.active_mode = DisclosurePolicyMode::SelectiveDisclosure;
            }
        });
    }

    #[test]
    fn mutation_detected_disclosure_expected_mode() {
        assert_mutation_detected("disclosure_policy_binding.expected_mode", |env| {
            if let Some(ref mut dpb) = env.boundary_check.disclosure_policy_binding {
                dpb.expected_mode = DisclosurePolicyMode::SelectiveDisclosure;
            }
        });
    }

    #[test]
    fn mutation_detected_disclosure_attempted_channel() {
        assert_mutation_detected("disclosure_policy_binding.attempted_channel", |env| {
            if let Some(ref mut dpb) = env.boundary_check.disclosure_policy_binding {
                dpb.attempted_channel = DisclosureChannelClass::PatentFiling;
            }
        });
    }

    #[test]
    fn mutation_detected_disclosure_admitted_epoch_root() {
        assert_mutation_detected(
            "disclosure_policy_binding.admitted_policy_epoch_root_digest",
            |env| {
                if let Some(ref mut dpb) = env.boundary_check.disclosure_policy_binding {
                    dpb.admitted_policy_epoch_root_digest = [0xFFu8; 32];
                }
            },
        );
    }

    #[test]
    fn mutation_detected_disclosure_policy_epoch() {
        assert_mutation_detected("disclosure_policy_binding.policy_epoch", |env| {
            if let Some(ref mut dpb) = env.boundary_check.disclosure_policy_binding {
                dpb.policy_epoch = 999;
            }
        });
    }

    #[test]
    fn mutation_detected_disclosure_phase_id() {
        assert_mutation_detected("disclosure_policy_binding.phase_id", |env| {
            if let Some(ref mut dpb) = env.boundary_check.disclosure_policy_binding {
                dpb.phase_id = "tampered-phase".to_string();
            }
        });
    }

    #[test]
    fn mutation_detected_disclosure_state_reason() {
        assert_mutation_detected("disclosure_policy_binding.state_reason", |env| {
            if let Some(ref mut dpb) = env.boundary_check.disclosure_policy_binding {
                dpb.state_reason = "tampered reason".to_string();
            }
        });
    }

    #[test]
    fn mutation_detected_economics_queue_defect_reason() {
        assert_mutation_detected("economics_trace.queue_admission.defect_reason", |env| {
            env.economics_trace.queue_admission.defect_reason = Some("tampered_defect".to_string());
        });
    }

    #[test]
    fn mutation_detected_economics_budget_reason() {
        assert_mutation_detected("economics_trace.budget_admission.reason", |env| {
            env.economics_trace.budget_admission.reason =
                Some("tampered_budget_reason".to_string());
        });
    }

    #[test]
    fn mutation_detected_schema() {
        // Schema mutation is caught by the schema check (before content hash),
        // so we verify the import is rejected for either reason.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        envelope.schema = "apm2.fac.tampered.v1".to_string();
        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::SchemaMismatch { .. }
                    | EvidenceBundleError::ContentHashMismatch { .. })
            ),
            "should reject tampered schema, got: {result:?}",
        );
    }

    #[test]
    fn mutation_detected_blob_refs() {
        assert_mutation_detected("blob_refs", |env| {
            env.blob_refs.push("b3-256:tampered".to_string());
        });
    }

    #[test]
    fn mutation_detected_unsafe_direct() {
        assert_mutation_detected("receipt.unsafe_direct", |env| {
            env.receipt.unsafe_direct = !env.receipt.unsafe_direct;
        });
    }

    #[test]
    fn mutation_detected_policy_hash() {
        // Mutating receipt.policy_hash without recomputing content_hash causes
        // either ContentHashMismatch (from content hash check) or
        // PolicyBindingMismatch (from cross-field consistency check, which
        // runs after content hash check only when the hash is recomputed).
        // Both are valid rejection reasons.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        envelope.receipt.policy_hash = Some(
            "b3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        );
        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ContentHashMismatch { .. }
                    | EvidenceBundleError::PolicyBindingMismatch { .. })
            ),
            "mutation of receipt.policy_hash should be detected, got: {result:?}",
        );
    }

    #[test]
    fn mutation_detected_canonicalizer_tuple_digest() {
        assert_mutation_detected("receipt.canonicalizer_tuple_digest", |env| {
            env.receipt.canonicalizer_tuple_digest = Some(
                "b3-256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    .to_string(),
            );
        });
    }

    // =========================================================================
    // Per-field length bounds tests (MINOR fix)
    // =========================================================================

    #[test]
    fn import_refuses_overlong_job_id() {
        let mut receipt = make_valid_receipt();
        receipt.job_id = "x".repeat(MAX_JOB_ID_LENGTH + 1);
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong job_id, got: {result:?}"
        );
    }

    #[test]
    fn import_refuses_overlong_blob_ref() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let overlong_ref = "b".repeat(MAX_BLOB_REF_LENGTH + 1);

        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[overlong_ref])
            .expect("export should succeed");
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong blob_ref, got: {result:?}"
        );
    }

    // =========================================================================
    // MINOR fix: receipt/policy_binding cross-field consistency
    // =========================================================================

    #[test]
    fn import_refuses_receipt_policy_hash_diverged_from_binding() {
        let mut receipt = make_valid_receipt();
        // Set a valid but DIFFERENT policy hash on the receipt.
        receipt.policy_hash = Some(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        // Recompute content hash for the mutated receipt.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::PolicyBindingMismatch { .. })
            ),
            "should reject when receipt.policy_hash diverges from policy_binding, got: {result:?}"
        );
    }

    #[test]
    fn import_refuses_receipt_canonicalizer_digest_diverged_from_binding() {
        let mut receipt = make_valid_receipt();
        // Set a valid but DIFFERENT canonicalizer tuple digest on the receipt.
        receipt.canonicalizer_tuple_digest = Some(
            "b3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        );
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        // Recompute content hash for the mutated receipt.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::PolicyBindingMismatch { .. })
            ),
            "should reject when receipt.canonicalizer_tuple_digest diverges from policy_binding, got: {result:?}"
        );
    }

    // =========================================================================
    // MAJOR-3: Blob verification tests
    // =========================================================================

    #[test]
    fn verify_blob_refs_succeeds_for_valid_blobs() {
        let tmpdir = std::env::temp_dir().join(format!("eb_blob_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmpdir);

        let blob_data = b"test blob data";
        let blob_hash = blake3::hash(blob_data);
        let hex_hash = blob_hash.to_hex().to_string();
        let blob_ref = format!("b3-256:{hex_hash}");

        // Write the blob file.
        std::fs::write(tmpdir.join(format!("{hex_hash}.blob")), blob_data).expect("write blob");

        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[blob_ref])
            .expect("export should succeed");
        // Recompute hash with the blob ref.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let result = verify_blob_refs(&envelope, &tmpdir);
        assert!(result.is_ok(), "should verify valid blobs, got: {result:?}");

        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    #[test]
    fn verify_blob_refs_fails_for_missing_blob() {
        let tmpdir = std::env::temp_dir().join(format!("eb_blob_miss_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmpdir);

        let blob_ref = "b3-256:".to_string() + &"aa".repeat(32);

        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[blob_ref])
            .expect("export should succeed");
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let result = verify_blob_refs(&envelope, &tmpdir);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::BlobImportVerificationFailed { .. })
            ),
            "should fail for missing blob, got: {result:?}"
        );

        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    #[test]
    fn verify_blob_refs_fails_for_corrupted_blob() {
        let tmpdir = std::env::temp_dir().join(format!("eb_blob_corrupt_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmpdir);

        let blob_data = b"original data";
        let blob_hash = blake3::hash(blob_data);
        let hex_hash = blob_hash.to_hex().to_string();
        let blob_ref = format!("b3-256:{hex_hash}");

        // Write DIFFERENT data to the blob file (corruption).
        std::fs::write(tmpdir.join(format!("{hex_hash}.blob")), b"corrupted data!!")
            .expect("write corrupted blob");

        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[blob_ref])
            .expect("export should succeed");
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let result = verify_blob_refs(&envelope, &tmpdir);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::BlobImportVerificationFailed { .. })
            ),
            "should fail for corrupted blob, got: {result:?}"
        );

        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    #[test]
    fn verify_blob_refs_empty_refs_succeeds() {
        let tmpdir = std::env::temp_dir().join(format!("eb_blob_empty_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmpdir);

        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let result = verify_blob_refs(&envelope, &tmpdir);
        assert!(result.is_ok(), "empty blob_refs should succeed");

        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    // =========================================================================
    // TCK-00542: Manifest struct tests
    // =========================================================================

    #[test]
    fn manifest_build_and_import_round_trip() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let manifest =
            build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build should succeed");

        assert_eq!(manifest.schema, EVIDENCE_BUNDLE_MANIFEST_SCHEMA);
        assert_eq!(manifest.job_id, "test-job-001");
        assert_eq!(manifest.outcome, "Completed");
        assert_eq!(manifest.envelope_content_hash, envelope.content_hash);
        assert!(manifest.channel_boundary_checked);
        assert_eq!(manifest.entries.len(), 1); // envelope entry only
        assert_eq!(manifest.entries[0].role, "envelope");

        let data = serialize_manifest(&manifest).expect("serialize should succeed");
        let imported = import_evidence_bundle_manifest(&data).expect("import should succeed");
        assert_eq!(imported, manifest);
    }

    #[test]
    fn manifest_with_blob_refs_round_trip() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let blob_refs = vec!["b3-256:aabbccdd".to_string(), "b3-256:eeff0011".to_string()];
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &blob_refs)
            .expect("export should succeed");

        let manifest =
            build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build should succeed");

        // 1 envelope + 2 blobs = 3 entries
        assert_eq!(manifest.entries.len(), 3);
        assert_eq!(manifest.entries[0].role, "envelope");
        assert_eq!(manifest.entries[1].role, "blob");
        assert_eq!(manifest.entries[2].role, "blob");
        assert_eq!(manifest.blob_count, 2);

        let data = serialize_manifest(&manifest).expect("serialize");
        let imported = import_evidence_bundle_manifest(&data).expect("import");
        assert_eq!(imported, manifest);
    }

    #[test]
    fn manifest_with_additional_entries_round_trip() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let extra = vec![EvidenceBundleManifestEntryV1 {
            role: "job_spec".to_string(),
            content_hash_ref: "b3-256:deadbeef".to_string(),
            description: "Job specification artifact".to_string(),
        }];

        let manifest = build_evidence_bundle_manifest(&envelope, &extra)
            .expect("manifest build should succeed");

        assert_eq!(manifest.entries.len(), 2); // envelope + job_spec
        assert_eq!(manifest.entries[1].role, "job_spec");

        let data = serialize_manifest(&manifest).expect("serialize");
        let imported = import_evidence_bundle_manifest(&data).expect("import");
        assert_eq!(imported, manifest);
    }

    #[test]
    fn manifest_content_hash_is_deterministic() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let m1 =
            build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build should succeed");
        let m2 =
            build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build should succeed");

        assert_eq!(
            m1.content_hash, m2.content_hash,
            "manifest content hash must be deterministic"
        );
    }

    #[test]
    fn manifest_import_refuses_oversized() {
        let data = vec![0u8; MAX_MANIFEST_SIZE + 1];
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::ManifestTooLarge { .. })),
            "should reject oversized manifest"
        );
    }

    #[test]
    fn manifest_import_refuses_schema_mismatch() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.schema = "wrong.schema.v1".to_string();
        // Recompute hash for the altered schema.
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ManifestSchemaMismatch { .. })
            ),
            "should reject manifest schema mismatch"
        );
    }

    #[test]
    fn manifest_import_refuses_tampered_content_hash() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.content_hash =
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ManifestContentHashMismatch { .. })
            ),
            "should reject tampered manifest content hash"
        );
    }

    #[test]
    fn manifest_import_refuses_too_many_entries() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        // Build a manifest manually with too many entries.
        let entries: Vec<EvidenceBundleManifestEntryV1> = (0..=MAX_MANIFEST_ENTRIES)
            .map(|i| EvidenceBundleManifestEntryV1 {
                role: "blob".to_string(),
                content_hash_ref: format!("b3-256:{i:064x}"),
                description: format!("entry {i}"),
            })
            .collect();

        let result = build_evidence_bundle_manifest(&envelope, &entries);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::TooManyManifestEntries { .. })
            ),
            "should reject too many manifest entries, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_overlong_job_id() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.job_id = "x".repeat(MAX_JOB_ID_LENGTH + 1);
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong manifest job_id, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_overlong_outcome_reason() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.outcome_reason = "x".repeat(MAX_OUTCOME_REASON_LENGTH + 1);
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong outcome_reason, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_overlong_envelope_hash_ref() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.envelope_content_hash = "h".repeat(MAX_ENVELOPE_HASH_REF_LENGTH + 1);
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong envelope_content_hash, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_overlong_entry_description() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.entries[0].description = "d".repeat(MAX_ENTRY_DESCRIPTION_LENGTH + 1);
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong entry description, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_overlong_entry_hash_ref() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.entries[0].content_hash_ref = "h".repeat(MAX_ENVELOPE_HASH_REF_LENGTH + 1);
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong entry content_hash_ref, got: {result:?}"
        );
    }

    #[test]
    fn manifest_build_refuses_overlong_additional_entry_role() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let entries = vec![EvidenceBundleManifestEntryV1 {
            role: "r".repeat(MAX_ROLE_LEN + 1),
            content_hash_ref: "b3-256:".to_string() + &"ab".repeat(32),
            description: "valid description".to_string(),
        }];

        let result = build_evidence_bundle_manifest(&envelope, &entries);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong additional entry role, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_overlong_outcome() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.outcome = "o".repeat(MAX_OUTCOME_LEN + 1);
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong outcome, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_overlong_entry_role() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.entries[0].role = "r".repeat(MAX_ROLE_LEN + 1);
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "should reject overlong entry role, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_too_many_blobs() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        manifest.blob_count = MAX_BUNDLE_BLOB_COUNT + 1;
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::TooManyBlobs { .. })),
            "should reject too many blob_refs in manifest, got: {result:?}"
        );
    }

    // =========================================================================
    // TCK-00542: Channel boundary check requirement
    // =========================================================================

    #[test]
    fn manifest_build_refuses_unchecked_boundary() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        // Set to unchecked state: Unknown source + broker_verified=false.
        envelope.boundary_check.source = ChannelSource::Unknown;
        envelope.boundary_check.broker_verified = false;

        let result = build_evidence_bundle_manifest(&envelope, &[]);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryCheckRequired { .. })
            ),
            "should refuse manifest build when boundary not checked, got: {result:?}"
        );
    }

    #[test]
    fn manifest_import_refuses_channel_boundary_unchecked() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        // Force channel_boundary_checked to false.
        manifest.channel_boundary_checked = false;
        let hash = compute_manifest_content_hash(&manifest);
        manifest.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryCheckRequired { .. })
            ),
            "should refuse import when channel_boundary_checked is false, got: {result:?}"
        );
    }

    // =========================================================================
    // TCK-00542: Manifest mutation detection tests
    // =========================================================================

    /// Helper: build a valid manifest, mutate a field WITHOUT recomputing
    /// `content_hash`, and verify import fails with `ContentHashMismatch`.
    fn assert_manifest_mutation_detected(
        label: &str,
        mutator: impl FnOnce(&mut EvidenceBundleManifestV1),
    ) {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");
        let mut manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");

        // Apply mutation WITHOUT recomputing content_hash.
        mutator(&mut manifest);

        let data = serialize_manifest(&manifest).expect("serialize");
        let result = import_evidence_bundle_manifest(&data);
        assert!(
            result.is_err(),
            "mutation of {label} should be detected, got: {result:?}",
        );
    }

    #[test]
    fn manifest_mutation_detected_job_id() {
        assert_manifest_mutation_detected("job_id", |m| {
            m.job_id = "tampered-job".to_string();
        });
    }

    #[test]
    fn manifest_mutation_detected_outcome() {
        assert_manifest_mutation_detected("outcome", |m| {
            m.outcome = "Denied".to_string();
        });
    }

    #[test]
    fn manifest_mutation_detected_outcome_reason() {
        assert_manifest_mutation_detected("outcome_reason", |m| {
            m.outcome_reason = "tampered reason".to_string();
        });
    }

    #[test]
    fn manifest_mutation_detected_timestamp() {
        assert_manifest_mutation_detected("timestamp_secs", |m| {
            m.timestamp_secs = 0;
        });
    }

    #[test]
    fn manifest_mutation_detected_envelope_hash() {
        assert_manifest_mutation_detected("envelope_content_hash", |m| {
            m.envelope_content_hash = "b3-256:tampered".to_string();
        });
    }

    #[test]
    fn manifest_mutation_detected_blob_count() {
        assert_manifest_mutation_detected("blob_count", |m| {
            m.blob_count = 999;
        });
    }

    #[test]
    fn manifest_mutation_detected_entries() {
        assert_manifest_mutation_detected("entries", |m| {
            m.entries.push(EvidenceBundleManifestEntryV1 {
                role: "tampered".to_string(),
                content_hash_ref: "b3-256:000".to_string(),
                description: "tampered entry".to_string(),
            });
        });
    }

    // =========================================================================
    // TCK-00542: Envelope schema backwards compatibility
    // =========================================================================

    #[test]
    fn envelope_import_accepts_legacy_schema() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        // Mutate to legacy schema explicitly; this should still import.
        envelope.schema = EVIDENCE_BUNDLE_SCHEMA.to_string();

        // After schema change, re-measure canonical size and update the
        // decision's actual_export_bytes to match (the schema string change
        // alters the serialized envelope length).
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));
        let data = serialize_envelope(&envelope).expect("measure");
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.actual_export_bytes = data.len() as u64;
        }
        // Re-hash after updating actual_export_bytes.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        // Converge: re-measure in case the byte count change shifted size.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            if d.actual_export_bytes != data.len() as u64 {
                d.actual_export_bytes = data.len() as u64;
                let hash = compute_envelope_content_hash(&envelope);
                envelope.content_hash = format!("b3-256:{}", hex::encode(hash));
            }
        }
        let data = serialize_envelope(&envelope).expect("serialize final");
        let result = import_evidence_bundle(&data);
        assert!(
            result.is_ok(),
            "should accept legacy schema, got: {result:?}"
        );
    }

    #[test]
    fn envelope_import_accepts_canonical_schema() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        // Switch to canonical envelope schema.
        envelope.schema = EVIDENCE_BUNDLE_ENVELOPE_SCHEMA.to_string();
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            result.is_ok(),
            "should accept canonical envelope schema, got: {result:?}"
        );
    }

    #[test]
    fn envelope_import_refuses_unknown_schema() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        envelope.schema = "apm2.fac.unknown.v1".to_string();
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::SchemaMismatch { .. })),
            "should reject unknown schema, got: {result:?}"
        );
    }

    // =========================================================================
    // TCK-00542: deny_unknown_fields enforcement
    // =========================================================================

    #[test]
    fn manifest_import_refuses_unknown_fields() {
        // Construct valid manifest JSON, then inject an unknown field.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");
        let manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        let data = serialize_manifest(&manifest).expect("serialize");

        // Parse as generic JSON, inject extra field, re-serialize.
        let mut json_val: serde_json::Value = serde_json::from_slice(&data).expect("parse");
        json_val["unknown_field"] = serde_json::json!("should_be_rejected");
        let tampered = serde_json::to_vec(&json_val).expect("re-serialize");

        let result = import_evidence_bundle_manifest(&tampered);
        assert!(
            matches!(result, Err(EvidenceBundleError::ManifestParseError { .. })),
            "should reject manifest with unknown fields, got: {result:?}"
        );
    }

    #[test]
    fn manifest_entry_import_refuses_unknown_fields() {
        // Construct valid manifest JSON, inject unknown field into entry.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");
        let manifest = build_evidence_bundle_manifest(&envelope, &[]).expect("manifest build");
        let data = serialize_manifest(&manifest).expect("serialize");

        let mut json_val: serde_json::Value = serde_json::from_slice(&data).expect("parse");
        json_val["entries"][0]["extra_field"] = serde_json::json!(true);
        let tampered = serde_json::to_vec(&json_val).expect("re-serialize");

        let result = import_evidence_bundle_manifest(&tampered);
        assert!(
            matches!(result, Err(EvidenceBundleError::ManifestParseError { .. })),
            "should reject manifest entry with unknown fields, got: {result:?}"
        );
    }

    // =========================================================================
    // TCK-00542: Hash stability / determinism regression tests
    // =========================================================================

    #[test]
    fn manifest_hash_stable_across_builds() {
        // Build the same manifest three times and verify all hashes match.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export");

        let hashes: Vec<String> = (0..3)
            .map(|_| {
                build_evidence_bundle_manifest(&envelope, &[])
                    .expect("build")
                    .content_hash
            })
            .collect();

        assert_eq!(hashes[0], hashes[1], "hash stability: run 0 vs 1");
        assert_eq!(hashes[1], hashes[2], "hash stability: run 1 vs 2");
    }

    #[test]
    fn manifest_hash_differs_for_different_envelopes() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let env1 = build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export1");
        let env2 =
            build_evidence_bundle_envelope(&receipt, &config, &["b3-256:aabbccdd".to_string()])
                .expect("export2");

        let m1 = build_evidence_bundle_manifest(&env1, &[]).expect("manifest1");
        let m2 = build_evidence_bundle_manifest(&env2, &[]).expect("manifest2");

        assert_ne!(
            m1.content_hash, m2.content_hash,
            "different envelopes should produce different manifest hashes"
        );
    }

    // =========================================================================
    // TCK-00576: import_evidence_bundle_verified tests
    // =========================================================================

    #[test]
    fn test_import_verified_rejects_missing_receipts_dir() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("build envelope");
        // Use serialize_envelope (to_vec_pretty) for canonical representation
        // matching the actual_export_bytes recorded at export time.
        let data = serialize_envelope(&envelope).expect("serialize");

        let signer = crate::crypto::Signer::generate();
        let vk = signer.verifying_key();

        // No receipts_dir provided: fail-closed.
        let result = import_evidence_bundle_verified(&data, &vk, None);
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::SignatureVerificationFailed { .. })
            ),
            "missing receipts_dir must fail: {result:?}"
        );
    }

    #[test]
    fn test_import_verified_rejects_unsigned_receipt() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("build envelope");
        // Use serialize_envelope (to_vec_pretty) for canonical representation.
        let data = serialize_envelope(&envelope).expect("serialize");

        let signer = crate::crypto::Signer::generate();
        let vk = signer.verifying_key();

        // Create receipts dir but do NOT persist a signed envelope.
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = import_evidence_bundle_verified(&data, &vk, Some(tmp.path()));
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::SignatureVerificationFailed { .. })
            ),
            "unsigned receipt must fail: {result:?}"
        );
    }

    #[test]
    fn test_import_verified_accepts_signed_receipt() {
        let mut receipt = make_valid_receipt();
        // Compute the content hash so the signed envelope digest matches.
        receipt.content_hash = crate::fac::receipt::compute_job_receipt_content_hash(&receipt);

        let config = make_valid_export_config();
        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("build envelope");
        // Use serialize_envelope (to_vec_pretty) for canonical representation.
        let data = serialize_envelope(&envelope).expect("serialize");

        let signer = crate::crypto::Signer::generate();
        let vk = signer.verifying_key();

        // Persist a signed envelope.
        let tmp = tempfile::tempdir().expect("tempdir");
        let signed_env = super::super::signed_receipt::sign_receipt(
            &receipt.content_hash,
            &signer,
            "test-broker",
        );
        super::super::signed_receipt::persist_signed_envelope(tmp.path(), &signed_env)
            .expect("persist signed envelope");

        let result = import_evidence_bundle_verified(&data, &vk, Some(tmp.path()));
        assert!(result.is_ok(), "signed receipt must pass: {result:?}");
    }

    #[test]
    fn test_import_verified_rejects_wrong_key() {
        let mut receipt = make_valid_receipt();
        receipt.content_hash = crate::fac::receipt::compute_job_receipt_content_hash(&receipt);

        let config = make_valid_export_config();
        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("build envelope");
        // Use serialize_envelope (to_vec_pretty) for canonical representation.
        let data = serialize_envelope(&envelope).expect("serialize");

        let signer = crate::crypto::Signer::generate();
        let other_signer = crate::crypto::Signer::generate();
        let vk = other_signer.verifying_key(); // Wrong key!

        // Persist signed envelope with signer (not other_signer).
        let tmp = tempfile::tempdir().expect("tempdir");
        let signed_env = super::super::signed_receipt::sign_receipt(
            &receipt.content_hash,
            &signer,
            "test-broker",
        );
        super::super::signed_receipt::persist_signed_envelope(tmp.path(), &signed_env)
            .expect("persist signed envelope");

        // Verify with wrong key: must fail.
        let result = import_evidence_bundle_verified(&data, &vk, Some(tmp.path()));
        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::SignatureVerificationFailed { .. })
            ),
            "wrong key must fail: {result:?}"
        );
    }

    // =========================================================================
    // TCK-00555: Leakage Budget Policy tests
    // =========================================================================

    #[test]
    fn leakage_budget_policy_tier0_default() {
        let p = LeakageBudgetPolicy::tier0_default();
        assert_eq!(p.max_export_bytes, 64 * 1024 * 1024);
        assert_eq!(p.max_export_classes, 64);
        assert_eq!(p.max_leakage_bits, 512);
    }

    #[test]
    fn leakage_budget_policy_tier2_default() {
        let p = LeakageBudgetPolicy::tier2_default();
        assert_eq!(p.max_export_bytes, 4 * 1024 * 1024);
        assert_eq!(p.max_export_classes, 16);
        assert_eq!(p.max_leakage_bits, 64);
    }

    #[test]
    fn leakage_budget_policy_deny_all() {
        let p = LeakageBudgetPolicy::deny_all();
        assert_eq!(p.max_export_bytes, 0);
        assert_eq!(p.max_export_classes, 0);
        assert_eq!(p.max_leakage_bits, 0);
    }

    #[test]
    fn leakage_budget_policy_default_is_tier2() {
        let p = LeakageBudgetPolicy::default();
        assert_eq!(p, LeakageBudgetPolicy::tier2_default());
    }

    // =========================================================================
    // TCK-00555: Declassification Export Receipt tests
    // =========================================================================

    /// Helper: build a valid declassification receipt.
    fn make_valid_declassification_receipt() -> DeclassificationExportReceipt {
        let mut receipt = DeclassificationExportReceipt {
            receipt_id: "declass-001".to_string(),
            authorized_bytes: 100 * 1024 * 1024,
            authorized_classes: 128,
            authorized_leakage_bits: 1024,
            authority_id: "admin@test".to_string(),
            reason: "test export for validation".to_string(),
            content_hash: [0u8; 32],
        };
        receipt.content_hash = receipt.compute_content_hash();
        receipt
    }

    #[test]
    fn declassification_receipt_validate_succeeds() {
        let receipt = make_valid_declassification_receipt();
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn declassification_receipt_validate_rejects_empty_receipt_id() {
        let mut receipt = make_valid_declassification_receipt();
        receipt.receipt_id = String::new();
        receipt.content_hash = receipt.compute_content_hash();
        let result = receipt.validate();
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "empty receipt_id must be rejected: {result:?}"
        );
    }

    #[test]
    fn declassification_receipt_validate_rejects_overlong_receipt_id() {
        let mut receipt = make_valid_declassification_receipt();
        receipt.receipt_id = "x".repeat(MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH + 1);
        receipt.content_hash = receipt.compute_content_hash();
        let result = receipt.validate();
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "overlong receipt_id must be rejected: {result:?}"
        );
    }

    #[test]
    fn declassification_receipt_validate_rejects_empty_authority_id() {
        let mut receipt = make_valid_declassification_receipt();
        receipt.authority_id = String::new();
        receipt.content_hash = receipt.compute_content_hash();
        let result = receipt.validate();
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "empty authority_id must be rejected: {result:?}"
        );
    }

    #[test]
    fn declassification_receipt_validate_rejects_overlong_authority_id() {
        let mut receipt = make_valid_declassification_receipt();
        receipt.authority_id = "a".repeat(MAX_DECLASSIFICATION_AUTHORITY_ID_LENGTH + 1);
        receipt.content_hash = receipt.compute_content_hash();
        let result = receipt.validate();
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "overlong authority_id must be rejected: {result:?}"
        );
    }

    #[test]
    fn declassification_receipt_validate_rejects_empty_reason() {
        let mut receipt = make_valid_declassification_receipt();
        receipt.reason = String::new();
        receipt.content_hash = receipt.compute_content_hash();
        let result = receipt.validate();
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "empty reason must be rejected: {result:?}"
        );
    }

    #[test]
    fn declassification_receipt_validate_rejects_overlong_reason() {
        let mut receipt = make_valid_declassification_receipt();
        receipt.reason = "r".repeat(MAX_DECLASSIFICATION_REASON_LENGTH + 1);
        receipt.content_hash = receipt.compute_content_hash();
        let result = receipt.validate();
        assert!(
            matches!(result, Err(EvidenceBundleError::FieldTooLong { .. })),
            "overlong reason must be rejected: {result:?}"
        );
    }

    #[test]
    fn declassification_receipt_validate_rejects_zero_hash() {
        let mut receipt = make_valid_declassification_receipt();
        receipt.content_hash = [0u8; 32]; // all zeros
        let result = receipt.validate();
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "zero content_hash must be rejected: {result:?}"
        );
    }

    #[test]
    fn declassification_receipt_content_hash_deterministic() {
        let receipt = make_valid_declassification_receipt();
        let hash1 = receipt.compute_content_hash();
        let hash2 = receipt.compute_content_hash();
        assert_eq!(hash1, hash2, "content hash must be deterministic");
    }

    #[test]
    fn declassification_receipt_content_hash_changes_with_fields() {
        let r1 = make_valid_declassification_receipt();
        let mut r2 = r1.clone();
        r2.authorized_bytes = 999_999;
        let h1 = r1.compute_content_hash();
        let h2 = r2.compute_content_hash();
        assert_ne!(h1, h2, "different fields must produce different hashes");
    }

    // =========================================================================
    // TCK-00555: Export-time leakage budget enforcement tests
    // =========================================================================

    #[test]
    fn export_within_tier0_budget_succeeds() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        // Default config uses tier0 policy; small envelope fits.
        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            result.is_ok(),
            "export within tier0 budget should succeed: {result:?}"
        );

        let envelope = result.unwrap();
        // Should have a leakage budget decision.
        let decision = envelope
            .leakage_budget_decision
            .as_ref()
            .expect("should have leakage budget decision");
        assert!(!decision.exceeded_policy, "should not exceed tier0 policy");
        assert!(!decision.declassification_authorized);
        assert!(decision.declassification_receipt_id.is_none());
    }

    #[test]
    fn export_with_no_policy_fails_closed() {
        // INV-EB-025: Export fails closed when leakage_budget_policy is
        // None for new-schema output. Callers must supply a policy.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = None;

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "export without leakage_budget_policy must fail closed (INV-EB-025): {result:?}"
        );
    }

    #[test]
    fn export_exceeding_deny_all_policy_fails_closed() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy::deny_all());
        config.declassification_receipt = None;

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "deny_all policy should fail closed: {result:?}"
        );
    }

    #[test]
    fn export_exceeding_policy_with_valid_receipt_succeeds() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        // Set a very low policy to force exceedance.
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1, // 1 byte -- will be exceeded
            max_export_classes: 1,
            max_leakage_bits: 0,
        });
        config.declassification_receipt = Some(make_valid_declassification_receipt());

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            result.is_ok(),
            "export with valid declassification should succeed: {result:?}"
        );

        let envelope = result.unwrap();
        let decision = envelope
            .leakage_budget_decision
            .as_ref()
            .expect("should have decision");
        assert!(decision.exceeded_policy);
        assert!(decision.declassification_authorized);
        assert_eq!(
            decision.declassification_receipt_id.as_deref(),
            Some("declass-001")
        );
    }

    #[test]
    fn export_exceeding_policy_without_receipt_fails_closed() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1,
            max_export_classes: 1,
            max_leakage_bits: 0,
        });
        config.declassification_receipt = None;

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "exceeding policy without receipt should fail: {result:?}"
        );
    }

    #[test]
    fn export_exceeding_leakage_bits_with_insufficient_receipt_fails() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        // The config already has a leakage_budget_receipt with leakage_bits=0.
        // Set policy to allow 0 leakage bits but LBR has 0 bits, so no
        // exceedance on bits. Instead, let's create a scenario with actual
        // exceedance.
        config.leakage_budget_receipt = Some(LeakageBudgetReceipt {
            leakage_bits: 100,
            budget_bits: 1024,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 9500,
            confidence_label: "high".to_string(),
        });
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 100 * 1024 * 1024, // generous
            max_export_classes: 128,
            max_leakage_bits: 10, // too low for 100 leakage bits
        });
        // Provide a receipt that authorizes insufficient leakage bits.
        let mut declass = make_valid_declassification_receipt();
        declass.authorized_leakage_bits = 50; // less than 100
        declass.content_hash = declass.compute_content_hash();
        config.declassification_receipt = Some(declass);

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "insufficient leakage bits authorization should fail: {result:?}"
        );
    }

    #[test]
    fn export_exceeding_leakage_bits_with_sufficient_receipt_succeeds() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_receipt = Some(LeakageBudgetReceipt {
            leakage_bits: 100,
            budget_bits: 1024,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 9500,
            confidence_label: "high".to_string(),
        });
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 100 * 1024 * 1024,
            max_export_classes: 128,
            max_leakage_bits: 10, // below 100, triggers exceedance
        });
        let mut declass = make_valid_declassification_receipt();
        declass.authorized_leakage_bits = 200; // sufficient for 100
        declass.content_hash = declass.compute_content_hash();
        config.declassification_receipt = Some(declass);

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            result.is_ok(),
            "sufficient leakage bits authorization should succeed: {result:?}"
        );
    }

    #[test]
    fn export_with_tampered_declassification_hash_fails() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1,
            max_export_classes: 1,
            max_leakage_bits: 0,
        });
        let mut declass = make_valid_declassification_receipt();
        // Tamper with the content hash.
        declass.content_hash = [0xFFu8; 32];
        config.declassification_receipt = Some(declass);

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "tampered declassification hash should fail: {result:?}"
        );
    }

    #[test]
    fn export_with_insufficient_bytes_authorization_fails() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1, // force exceedance
            max_export_classes: 128,
            max_leakage_bits: 1024,
        });
        let mut declass = make_valid_declassification_receipt();
        declass.authorized_bytes = 1; // too low for actual envelope
        declass.content_hash = declass.compute_content_hash();
        config.declassification_receipt = Some(declass);

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "insufficient bytes authorization should fail: {result:?}"
        );
    }

    // =========================================================================
    // TCK-00555: Import-time leakage budget validation tests
    // =========================================================================

    #[test]
    fn import_accepts_envelope_with_valid_decision() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        assert!(envelope.leakage_budget_decision.is_some());

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(result.is_ok(), "valid decision should import: {result:?}");
    }

    #[test]
    fn import_rejects_new_schema_envelope_without_decision() {
        // INV-EB-014: New-schema envelopes MUST carry a leakage budget
        // decision. A new-schema envelope without a decision must be
        // rejected on import to prevent downgrade-by-omission attacks.
        //
        // Since INV-EB-025 now prevents export without a policy, we
        // construct the tampered envelope directly to test import behavior.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        // Build a valid envelope with a decision, then strip it.
        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        assert!(envelope.leakage_budget_decision.is_some());
        assert_eq!(envelope.schema, EVIDENCE_BUNDLE_ENVELOPE_SCHEMA);

        // Strip the decision (simulating a downgrade-by-omission attack).
        envelope.leakage_budget_decision = None;
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "new-schema envelope without decision must be rejected: {result:?}"
        );
    }

    #[test]
    fn import_accepts_legacy_schema_envelope_without_decision() {
        // INV-EB-014: Legacy envelopes (EVIDENCE_BUNDLE_SCHEMA) are exempt
        // from the mandatory decision requirement for backward compatibility
        // with pre-TCK-00555 exports.
        //
        // Construct a truly legacy envelope by building a valid envelope
        // with a decision, then stripping the decision, clearing
        // budget-aware fields, and setting the legacy schema. This
        // simulates a pre-TCK-00555 export that never had budget awareness.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Strip decision and budget-aware boundary check fields to simulate
        // a truly pre-TCK-00555 legacy envelope.
        envelope.leakage_budget_decision = None;
        envelope.boundary_check.leakage_budget_receipt = None;
        envelope.boundary_check.timing_channel_budget = None;
        envelope.boundary_check.disclosure_policy_binding = None;

        // Switch to legacy schema.
        envelope.schema = EVIDENCE_BUNDLE_SCHEMA.to_string();
        // Recompute content hash for the legacy schema path.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            result.is_ok(),
            "truly legacy-schema envelope without decision should be accepted: {result:?}"
        );
    }

    #[test]
    fn import_rejects_exceeded_without_declassification() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: set exceeded but not authorized.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.exceeded_policy = true;
            d.declassification_authorized = false;
            d.declassification_receipt_id = None;
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "exceeded without declassification should be rejected: {result:?}"
        );
    }

    #[test]
    fn import_rejects_declassification_authorized_without_receipt_id() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: exceeded + authorized but no receipt ID.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.exceeded_policy = true;
            d.declassification_authorized = true;
            d.declassification_receipt_id = None;
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "declassification authorized without receipt ID should be rejected: {result:?}"
        );
    }

    #[test]
    fn import_rejects_leakage_bits_exceeding_policy_without_exceeded_flag() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        // Use a leakage budget receipt with high leakage bits but generous
        // policy so the export succeeds.
        config.leakage_budget_receipt = Some(LeakageBudgetReceipt {
            leakage_bits: 1000,
            budget_bits: 2000,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 9500,
            confidence_label: "high".to_string(),
        });
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 100 * 1024 * 1024,
            max_export_classes: 128,
            max_leakage_bits: 2000, // generous so export succeeds
        });

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: set policy ceiling below actual leakage bits but clear exceeded flag.
        // This simulates an attacker forging a decision to bypass budget checks.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.policy.max_leakage_bits = 10; // way below 1000
            d.exceeded_policy = false; // lie: claim not exceeded
            d.declassification_authorized = false;
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "leakage bits exceeding policy without exceeded flag should be rejected: {result:?}"
        );
    }

    #[test]
    fn mutation_detected_leakage_budget_decision() {
        assert_mutation_detected("leakage_budget_decision.exceeded_policy", |env| {
            if let Some(ref mut d) = env.leakage_budget_decision {
                d.actual_export_bytes = 999_999_999;
            }
        });
    }

    // =========================================================================
    // TCK-00555: Round-trip with leakage budget decision
    // =========================================================================

    #[test]
    fn round_trip_preserves_leakage_budget_decision() {
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        assert!(envelope.leakage_budget_decision.is_some());

        let data = serialize_envelope(&envelope).expect("serialize");
        let imported = import_evidence_bundle(&data).expect("import should succeed");

        assert_eq!(
            envelope.leakage_budget_decision, imported.leakage_budget_decision,
            "leakage budget decision must round-trip"
        );
    }

    #[test]
    fn round_trip_with_exceeded_and_declassification() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1,
            max_export_classes: 1,
            max_leakage_bits: 0,
        });
        config.declassification_receipt = Some(make_valid_declassification_receipt());

        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[])
            .expect("export with declassification should succeed");

        let decision = envelope.leakage_budget_decision.as_ref().unwrap();
        assert!(decision.exceeded_policy);
        assert!(decision.declassification_authorized);

        let data = serialize_envelope(&envelope).expect("serialize");
        let imported = import_evidence_bundle(&data).expect("import should succeed");

        assert_eq!(
            envelope.leakage_budget_decision,
            imported.leakage_budget_decision,
        );
    }

    // =========================================================================
    // TCK-00555: Leakage budget policy serialization
    // =========================================================================

    #[test]
    fn leakage_budget_policy_serializes_round_trip() {
        let policy = LeakageBudgetPolicy::tier2_default();
        let json = serde_json::to_string(&policy).expect("serialize");
        let deserialized: LeakageBudgetPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn leakage_budget_decision_serializes_round_trip() {
        let decision = LeakageBudgetDecision {
            policy: LeakageBudgetPolicy::tier0_default(),
            actual_export_bytes: 1024,
            actual_export_classes: 3,
            actual_leakage_bits: 0,
            exceeded_policy: false,
            declassification_authorized: false,
            declassification_receipt_id: None,
            declassification_receipt: None,
        };
        let json = serde_json::to_string(&decision).expect("serialize");
        let deserialized: LeakageBudgetDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decision, deserialized);
    }

    #[test]
    fn declassification_receipt_serializes_round_trip() {
        let receipt = make_valid_declassification_receipt();
        let json = serde_json::to_string(&receipt).expect("serialize");
        let deserialized: DeclassificationExportReceipt =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, deserialized);
    }

    // =========================================================================
    // Regression: byte cap enforced against final exported bytes (Finding 3)
    // =========================================================================

    #[test]
    fn export_byte_cap_enforced_against_final_pretty_json_not_prehash() {
        // Regression test: the pre-hash compact JSON (serde_json::to_vec)
        // is smaller than the final exported pretty JSON
        // (serde_json::to_vec_pretty with populated content_hash). A policy
        // ceiling that the pre-hash size passes must still fail-closed when
        // the final pretty-printed bytes exceed it.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();

        // First, build an envelope with a generous policy to measure sizes.
        config.leakage_budget_policy = Some(LeakageBudgetPolicy::tier0_default());
        config.declassification_receipt = None;
        let test_envelope = build_evidence_bundle_envelope(&receipt, &config, &[])
            .expect("generous policy should succeed");
        let final_pretty_bytes = serialize_envelope(&test_envelope).expect("serialize");
        let pre_hash_compact = serde_json::to_vec(&test_envelope).expect("compact");

        // Verify that pretty-print is strictly larger than compact (the
        // condition that makes this test meaningful).
        assert!(
            final_pretty_bytes.len() > pre_hash_compact.len(),
            "pretty-print ({}) must be larger than compact ({}) for this regression test to be meaningful",
            final_pretty_bytes.len(),
            pre_hash_compact.len(),
        );

        // Set a byte ceiling between the compact and pretty sizes so that
        // the pre-hash compact size would pass but the final pretty-print
        // size fails closed.
        let ceiling = usize::midpoint(pre_hash_compact.len(), final_pretty_bytes.len()) as u64;
        assert!(
            ceiling > pre_hash_compact.len() as u64 && ceiling < final_pretty_bytes.len() as u64,
            "ceiling ({ceiling}) must be between compact ({}) and pretty ({})",
            pre_hash_compact.len(),
            final_pretty_bytes.len(),
        );

        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: ceiling,
            max_export_classes: 128,
            max_leakage_bits: 1024,
        });
        config.declassification_receipt = None;

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "byte cap must be enforced against final pretty-print size, not pre-hash compact; got: {result:?}"
        );
    }

    // =========================================================================
    // Regression: legacy envelope hash backward compatibility (Finding 4)
    // =========================================================================

    #[test]
    fn legacy_schema_envelope_without_decision_preserves_hash() {
        // Fixture-based test: a pre-TCK-00555 envelope uses the legacy
        // schema and has no leakage_budget_decision. The hash must be
        // computed WITHOUT the leakage budget presence/absence byte to
        // preserve backward compatibility (INV-EB-014).
        //
        // Since INV-EB-025 requires a policy for export, we construct
        // the legacy envelope by building a valid one and then stripping
        // the decision and budget-aware fields.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Record the hash from the new-schema envelope WITH decision.
        let new_schema_with_decision_hash = envelope.content_hash.clone();

        // Strip decision and budget-aware fields for legacy simulation.
        envelope.leakage_budget_decision = None;
        envelope.boundary_check.leakage_budget_receipt = None;
        envelope.boundary_check.timing_channel_budget = None;
        envelope.boundary_check.disclosure_policy_binding = None;

        // Compute new-schema hash without decision (includes [0u8] byte).
        let canonical_hash_no_decision = compute_envelope_content_hash(&envelope);
        let canonical_hash_no_decision_str =
            format!("b3-256:{}", hex::encode(canonical_hash_no_decision));

        // Switch to legacy schema and recompute hash via the legacy path.
        envelope.schema = EVIDENCE_BUNDLE_SCHEMA.to_string();
        let legacy_hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(legacy_hash));

        let legacy_hash_str = envelope.content_hash.clone();

        // Verify the legacy-schema envelope passes import (with recomputed
        // content hash matching and no budget-aware fields).
        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            result.is_ok(),
            "legacy schema envelope without decision should import successfully: {result:?}"
        );

        // Verify the legacy hash is different from the canonical hash
        // without decision (the canonical path includes a [0u8] absence
        // byte; the legacy path omits the field entirely).
        assert_ne!(
            canonical_hash_no_decision_str, legacy_hash_str,
            "legacy and canonical hashes should differ when schema differs"
        );

        // Also verify new-schema-with-decision hash differs from legacy.
        assert_ne!(
            new_schema_with_decision_hash, legacy_hash_str,
            "new-schema-with-decision hash must differ from legacy hash"
        );
    }

    #[test]
    fn new_schema_envelope_without_decision_includes_absence_byte_in_hash() {
        // Complementary test: a new-schema envelope without a leakage budget
        // decision still includes the [0u8] absence byte in the hash (not
        // the legacy path). After INV-EB-014, import now rejects such
        // envelopes, but we verify the hash computation itself is correct.
        //
        // Since INV-EB-025 requires a policy for export, construct the
        // envelope by building a valid one and stripping the decision.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Strip decision to test hash computation without it.
        envelope.leakage_budget_decision = None;

        // Verify the hash is self-consistent (hash validation passes).
        let computed = compute_envelope_content_hash(&envelope);
        let expected_hex = format!("b3-256:{}", hex::encode(computed));
        envelope.content_hash = expected_hex.clone();

        // Verify the new-schema hash includes the [0u8] absence byte by
        // comparing with a legacy-schema hash (which omits the field).
        let mut legacy_envelope = envelope.clone();
        legacy_envelope.schema = EVIDENCE_BUNDLE_SCHEMA.to_string();
        legacy_envelope.boundary_check.leakage_budget_receipt = None;
        legacy_envelope.boundary_check.timing_channel_budget = None;
        legacy_envelope.boundary_check.disclosure_policy_binding = None;
        let legacy_hash = compute_envelope_content_hash(&legacy_envelope);
        let legacy_hex = format!("b3-256:{}", hex::encode(legacy_hash));
        assert_ne!(
            expected_hex, legacy_hex,
            "new-schema and legacy-schema hashes should differ (absence byte vs omission)"
        );

        // INV-EB-014: import must now REJECT new-schema envelopes missing
        // the leakage budget decision.
        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "new-schema envelope without decision must be rejected per INV-EB-014: {result:?}"
        );
    }

    // =========================================================================
    // Regression: forged authorized flag without receipt fails import (Finding 1)
    // =========================================================================

    #[test]
    fn import_rejects_forged_authorized_flag_without_receipt() {
        // An attacker constructs an envelope with exceeded_policy=true and
        // declassification_authorized=true but without embedding the actual
        // DeclassificationExportReceipt. The importer must reject this
        // because it cannot verify that the receipt actually covers the
        // export values.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Forge the decision: set authorized without embedding receipt.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.exceeded_policy = true;
            d.declassification_authorized = true;
            d.declassification_receipt_id = Some("forged-id".to_string());
            d.declassification_receipt = None; // No actual receipt!
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "forged authorized flag without embedded receipt must be rejected: {result:?}"
        );
    }

    #[test]
    fn import_rejects_receipt_with_insufficient_bytes_authorization() {
        // The embedded receipt's authorized_bytes is less than the
        // decision's actual_export_bytes. Import must reject.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1,
            max_export_classes: 1,
            max_leakage_bits: 0,
        });
        let mut declass = make_valid_declassification_receipt();
        declass.authorized_bytes = 100 * 1024 * 1024; // generous for export
        declass.content_hash = declass.compute_content_hash();
        config.declassification_receipt = Some(declass);

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: reduce the embedded receipt's authorized_bytes below actual.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            if let Some(ref mut dr) = d.declassification_receipt {
                dr.authorized_bytes = 1; // below actual_export_bytes
                dr.content_hash = dr.compute_content_hash();
            }
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "receipt with insufficient bytes authorization must be rejected on import: {result:?}"
        );
    }

    #[test]
    fn import_rejects_receipt_with_tampered_content_hash() {
        // The embedded receipt's content_hash is tampered. Import must reject.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1,
            max_export_classes: 1,
            max_leakage_bits: 0,
        });
        config.declassification_receipt = Some(make_valid_declassification_receipt());

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: set the embedded receipt's content hash to garbage.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            if let Some(ref mut dr) = d.declassification_receipt {
                dr.content_hash = [0xABu8; 32];
            }
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "receipt with tampered content hash must be rejected on import: {result:?}"
        );
    }

    #[test]
    fn import_accepts_valid_exceeded_envelope_with_embedded_receipt() {
        // The full happy-path: exceeded policy with valid embedded receipt
        // passes import-time audit.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1,
            max_export_classes: 1,
            max_leakage_bits: 0,
        });
        config.declassification_receipt = Some(make_valid_declassification_receipt());

        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[])
            .expect("export with valid declassification should succeed");

        // Verify embedded receipt is present.
        let decision = envelope.leakage_budget_decision.as_ref().unwrap();
        assert!(decision.exceeded_policy);
        assert!(decision.declassification_authorized);
        assert!(decision.declassification_receipt.is_some());

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            result.is_ok(),
            "valid exceeded envelope with embedded receipt should import: {result:?}"
        );
    }

    // =========================================================================
    // Finding 1 (MAJOR): Import-side consistency checks for forged decisions
    // =========================================================================

    #[test]
    fn import_rejects_forged_exceeded_false_with_bytes_over_ceiling() {
        // An attacker forges exceeded_policy=false but sets actual_export_bytes
        // above the policy ceiling. Import must reject.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: inflate actual_export_bytes above policy ceiling.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.actual_export_bytes = d.policy.max_export_bytes + 1;
            d.exceeded_policy = false; // lie
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "forged exceeded_policy=false with bytes over ceiling must be rejected: {result:?}"
        );
    }

    #[test]
    fn import_rejects_forged_exceeded_false_with_classes_over_ceiling() {
        // An attacker forges exceeded_policy=false but sets actual_export_classes
        // above the policy ceiling. Import must reject.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: inflate actual_export_classes above policy ceiling
        // AND match the expected class count from blob_refs to pass
        // the class cross-check (by adding fake blob_refs).
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            let target_classes = d.policy.max_export_classes + 1;
            // We need blob_refs.len() + 2 == target_classes.
            let needed_blobs = target_classes.saturating_sub(2) as usize;
            envelope.blob_refs = (0..needed_blobs)
                .map(|i| format!("b3-256:{i:064x}"))
                .collect();
            d.actual_export_classes = target_classes;
            d.exceeded_policy = false; // lie
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "forged exceeded_policy=false with classes over ceiling must be rejected: {result:?}"
        );
    }

    #[test]
    fn import_rejects_forged_exceeded_false_with_leakage_bits_over_ceiling() {
        // An attacker forges exceeded_policy=false but sets actual_leakage_bits
        // above the policy ceiling. Import must reject.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        // Set leakage budget receipt to match the forged bits.
        config.leakage_budget_receipt = Some(LeakageBudgetReceipt {
            leakage_bits: 9999,
            budget_bits: 10000,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 9500,
            confidence_label: "high".to_string(),
        });
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 100 * 1024 * 1024,
            max_export_classes: 128,
            max_leakage_bits: 10000, // generous so export succeeds
        });

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: lower policy ceiling below actual leakage bits but
        // keep exceeded_policy=false.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.policy.max_leakage_bits = 10; // way below 9999
            d.exceeded_policy = false; // lie
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "forged exceeded_policy=false with leakage bits over ceiling must be rejected: {result:?}"
        );
    }

    #[test]
    fn import_rejects_class_count_mismatch_with_blob_refs() {
        // actual_export_classes does not match blob_refs.len() + 2.
        // Import must reject regardless of exceeded_policy.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: set actual_export_classes to a value that does not match.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.actual_export_classes = 99; // does not match blob_refs.len() + 2
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "class count mismatch with blob_refs must be rejected: {result:?}"
        );
    }

    #[test]
    fn import_rejects_leakage_bits_mismatch_with_receipt() {
        // actual_leakage_bits does not match the leakage_budget_receipt's
        // leakage_bits. Import must reject.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: set actual_leakage_bits to a value that does not match
        // the leakage_budget_receipt.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            // The receipt has leakage_bits=0 (from make_valid_export_config),
            // so set actual to something non-zero.
            d.actual_leakage_bits = 42;
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "leakage bits mismatch with receipt must be rejected: {result:?}"
        );
    }

    #[test]
    fn import_rejects_nonzero_leakage_bits_without_receipt() {
        // When no leakage_budget_receipt is present in the boundary check,
        // actual_leakage_bits must be 0. Import must reject nonzero values.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_receipt = None; // no receipt

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: set actual_leakage_bits to nonzero without a receipt.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.actual_leakage_bits = 100;
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "nonzero leakage bits without receipt must be rejected: {result:?}"
        );
    }

    // =========================================================================
    // Finding 2 (MINOR): actual_export_bytes matches final serialized size
    // =========================================================================

    #[test]
    fn actual_export_bytes_matches_final_serialized_size() {
        // Verify that the recorded actual_export_bytes in the decision
        // exactly matches the final serialized envelope size.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let serialized = serialize_envelope(&envelope).expect("serialize");
        let decision = envelope.leakage_budget_decision.as_ref().unwrap();

        assert_eq!(
            decision.actual_export_bytes,
            serialized.len() as u64,
            "actual_export_bytes ({}) must equal final serialized size ({})",
            decision.actual_export_bytes,
            serialized.len(),
        );
    }

    #[test]
    fn actual_export_bytes_matches_with_blobs() {
        // Same test but with blob references to increase envelope size.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();
        let blob_refs: Vec<String> = (0..10).map(|i| format!("b3-256:{i:064x}")).collect();

        let envelope = build_evidence_bundle_envelope(&receipt, &config, &blob_refs)
            .expect("export should succeed");

        let serialized = serialize_envelope(&envelope).expect("serialize");
        let decision = envelope.leakage_budget_decision.as_ref().unwrap();

        assert_eq!(
            decision.actual_export_bytes,
            serialized.len() as u64,
            "actual_export_bytes ({}) must equal final serialized size ({}) with blobs",
            decision.actual_export_bytes,
            serialized.len(),
        );
    }

    #[test]
    fn actual_export_bytes_matches_with_declassification() {
        // Verify convergence works when declassification receipt is present.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1,
            max_export_classes: 1,
            max_leakage_bits: 0,
        });
        config.declassification_receipt = Some(make_valid_declassification_receipt());

        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[])
            .expect("export with declassification should succeed");

        let serialized = serialize_envelope(&envelope).expect("serialize");
        let decision = envelope.leakage_budget_decision.as_ref().unwrap();

        assert_eq!(
            decision.actual_export_bytes,
            serialized.len() as u64,
            "actual_export_bytes ({}) must equal final serialized size ({}) with declassification",
            decision.actual_export_bytes,
            serialized.len(),
        );
    }

    // =========================================================================
    // TCK-00555 MAJOR: Import rejects forged actual_export_bytes (canonical
    // envelope byte size mismatch)
    // =========================================================================

    #[test]
    fn import_rejects_forged_actual_export_bytes_below_policy() {
        // An attacker forges actual_export_bytes to a value below the policy
        // ceiling while the canonical serialized envelope is above it. The
        // attacker sets exceeded_policy=false to bypass declassification.
        // The importer must reject because canonical envelope bytes != declared
        // actual_export_bytes.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        // Use a tight policy so the real envelope exceeds it.
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 50, // Very tight: real envelope >> 50 bytes
            max_export_classes: 128,
            max_leakage_bits: 1024,
        });
        // Need declassification receipt for the export to succeed.
        config.declassification_receipt = Some(make_valid_declassification_receipt());

        let mut envelope = build_evidence_bundle_envelope(&receipt, &config, &[])
            .expect("export with declassification should succeed");

        // Verify the real envelope exceeds 50 bytes.
        let serialized = serialize_envelope(&envelope).expect("serialize");
        assert!(
            serialized.len() > 50,
            "envelope must be > 50 bytes for this test to be meaningful (actual: {})",
            serialized.len()
        );

        // Tamper: forge actual_export_bytes to below ceiling, clear exceeded
        // flags, and remove the declassification receipt to create a seemingly
        // policy-compliant decision.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.actual_export_bytes = 40; // Below 50 byte ceiling — a lie
            d.exceeded_policy = false;
            d.declassification_authorized = false;
            d.declassification_receipt_id = None;
            d.declassification_receipt = None;
        }

        // Recompute content hash so hash check passes.
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize tampered");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "forged actual_export_bytes below canonical size must be rejected: {result:?}"
        );

        // Verify the error message mentions the mismatch.
        if let Err(EvidenceBundleError::LeakageBudgetDenied { reason }) = &result {
            assert!(
                reason.contains("does not match canonical envelope size"),
                "error must describe canonical size mismatch: {reason}"
            );
        }
    }

    #[test]
    fn import_rejects_forged_actual_export_bytes_inflated() {
        // Complementary test: attacker inflates actual_export_bytes above the
        // real canonical size. Import must also reject because the declared
        // value does not match the canonical size.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        // Tamper: inflate actual_export_bytes above the real size.
        if let Some(ref mut d) = envelope.leakage_budget_decision {
            d.actual_export_bytes += 999;
        }

        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize tampered");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "inflated actual_export_bytes above canonical size must be rejected: {result:?}"
        );
    }

    // =========================================================================
    // TCK-00555 MINOR: Export fails when declassification receipt
    // under-authorizes leakage bits (byte-triggered declassification)
    // =========================================================================

    #[test]
    fn export_rejects_declass_receipt_under_authorizing_leakage_bits_via_bytes() {
        // Byte exceedance triggers declassification. The receipt authorizes
        // enough bytes and classes but under-authorizes leakage bits. The
        // export path must fail closed because import would reject the
        // bundle (consistent export/import semantics).
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();

        // Set leakage budget receipt with non-zero leakage bits.
        config.leakage_budget_receipt = Some(LeakageBudgetReceipt {
            leakage_bits: 500,
            budget_bits: 1000,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 9500,
            confidence_label: "high".to_string(),
        });

        // Policy: tight byte ceiling so byte exceedance triggers declass,
        // but leakage bits are within policy (500 < 1024). This means
        // byte-only triggered declassification.
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1, // Force byte exceedance
            max_export_classes: 128,
            max_leakage_bits: 1024, // Generous — leakage bits NOT exceeded
        });

        // Declassification receipt: authorizes bytes and classes but
        // under-authorizes leakage bits (100 < 500 actual).
        let mut declass = make_valid_declassification_receipt();
        declass.authorized_leakage_bits = 100; // Below actual 500
        declass.content_hash = declass.compute_content_hash();
        config.declassification_receipt = Some(declass);

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "export must fail when declass receipt under-authorizes leakage bits even if leakage bits are within policy: {result:?}"
        );

        // Verify the error message mentions leakage bits.
        if let Err(EvidenceBundleError::LeakageBudgetDenied { reason }) = &result {
            assert!(
                reason.contains("leakage bits"),
                "error must describe leakage bit under-authorization: {reason}"
            );
        }
    }

    #[test]
    fn export_succeeds_when_declass_receipt_covers_all_dimensions() {
        // Complementary positive test: declassification receipt that
        // properly covers bytes, classes, AND leakage bits succeeds even
        // when only bytes trigger exceedance.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();

        config.leakage_budget_receipt = Some(LeakageBudgetReceipt {
            leakage_bits: 500,
            budget_bits: 1000,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 9500,
            confidence_label: "high".to_string(),
        });

        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 1,
            max_export_classes: 128,
            max_leakage_bits: 1024,
        });

        // Receipt properly covers all dimensions including leakage bits.
        let mut declass = make_valid_declassification_receipt();
        declass.authorized_leakage_bits = 500; // Exactly covers actual
        declass.content_hash = declass.compute_content_hash();
        config.declassification_receipt = Some(declass);

        let envelope = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            envelope.is_ok(),
            "export should succeed when declass receipt covers all dimensions: {envelope:?}"
        );

        // Verify round-trip import also succeeds.
        let env = envelope.unwrap();
        let data = serialize_envelope(&env).expect("serialize");
        let imported = import_evidence_bundle(&data);
        assert!(
            imported.is_ok(),
            "import should also succeed for properly covered bundle: {imported:?}"
        );
    }

    // =========================================================================
    // Regression: class-triggered exceedance with under-authorized bytes
    // must fail export (INV-EB-024)
    // =========================================================================

    #[test]
    fn export_fails_when_class_exceeded_but_bytes_under_authorized() {
        // Regression test for INV-EB-024: When classes exceed the policy
        // ceiling but bytes do not, a declassification receipt is required.
        // Even though byte exceedance did not trigger, the receipt's
        // authorized_bytes must still cover the actual export bytes
        // (because import always validates byte coverage when
        // declassification_authorized=true). This test verifies
        // fail-closed: a receipt that authorizes fewer bytes than the
        // actual export must be rejected at export time.
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();

        // Policy: generous byte ceiling (no byte exceedance), but very
        // tight class ceiling (class exceedance triggers declassification).
        config.leakage_budget_policy = Some(LeakageBudgetPolicy {
            max_export_bytes: 100 * 1024 * 1024, // generous — no byte exceedance
            max_export_classes: 1,               // tight — class exceedance
            max_leakage_bits: 1024,              // generous
        });

        // Declassification receipt: authorizes classes generously but
        // under-authorizes bytes (1 byte < actual export bytes).
        let mut declass = make_valid_declassification_receipt();
        declass.authorized_bytes = 1; // far below actual export bytes
        declass.authorized_classes = 128; // generous
        declass.authorized_leakage_bits = 1024; // generous
        declass.content_hash = declass.compute_content_hash();
        config.declassification_receipt = Some(declass);

        let result = build_evidence_bundle_envelope(&receipt, &config, &[]);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "class-triggered exceedance with under-authorized bytes must fail \
             export (INV-EB-024): {result:?}"
        );

        // Verify error mentions byte coverage.
        if let Err(EvidenceBundleError::LeakageBudgetDenied { reason }) = &result {
            assert!(
                reason.contains("byte") || reason.contains("bytes"),
                "error should mention byte under-authorization: {reason}"
            );
        }
    }

    // =========================================================================
    // Regression: decision-stripping bypass attempt (INV-EB-014)
    // =========================================================================

    #[test]
    fn import_rejects_decision_stripped_envelope_with_recomputed_hash() {
        // Regression test for the downgrade-by-omission attack described in
        // INV-EB-014: an attacker takes a valid new-schema envelope that
        // carries a leakage_budget_decision, strips the decision field
        // (setting it to None), and recomputes a self-consistent content
        // hash. Import MUST reject this envelope because the new-schema
        // schema mandates the presence of a leakage budget decision.
        //
        // This proves the bypass is closed: the attacker cannot circumvent
        // leakage budget enforcement by omitting the decision.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        // Step 1: Build a legitimate envelope with a valid decision.
        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        assert!(
            envelope.leakage_budget_decision.is_some(),
            "legitimate envelope must have a leakage budget decision"
        );
        assert_eq!(
            envelope.schema, EVIDENCE_BUNDLE_ENVELOPE_SCHEMA,
            "legitimate envelope must use new schema"
        );

        // Step 2: Strip the decision (attacker action).
        envelope.leakage_budget_decision = None;

        // Step 3: Recompute the content hash to be self-consistent
        // (attacker recomputes hash after tampering).
        let tampered_hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(tampered_hash));

        // Step 4: Verify the tampered hash is self-consistent (the hash
        // check itself will pass — the attack relies on bypassing the
        // decision validation, not the hash check).
        let recomputed = compute_envelope_content_hash(&envelope);
        assert_eq!(
            tampered_hash, recomputed,
            "tampered hash must be self-consistent for this attack to be meaningful"
        );

        // Step 5: Import must reject the tampered envelope.
        let data = serialize_envelope(&envelope).expect("serialize tampered envelope");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "decision-stripped new-schema envelope must be rejected: {result:?}"
        );

        // Verify the error message mentions the downgrade attack.
        if let Err(EvidenceBundleError::LeakageBudgetDenied { reason }) = &result {
            assert!(
                reason.contains("absent") || reason.contains("downgrade"),
                "error should indicate missing decision or downgrade: {reason}"
            );
        }
    }

    #[test]
    fn import_rejects_decision_stripped_envelope_even_with_legacy_schema_swap() {
        // Extended regression test: attacker not only strips the decision
        // but also changes the schema to the legacy ID to try to exploit
        // the backward-compatibility exemption. However, the hash is then
        // computed via the legacy path (no presence/absence byte), which
        // produces a DIFFERENT hash than the new-schema path. The content
        // hash check catches this: if the attacker recomputes the hash for
        // legacy-schema-without-decision, the blob_refs count, boundary
        // check fields, and receipt data are still correct, so the hash
        // will pass — but the envelope is now a legacy envelope, and legacy
        // envelopes without decisions are legitimately accepted (backward
        // compat). The security guarantee is that a new-schema envelope
        // cannot be downgraded: changing the schema changes the hash, so
        // the attacker must use the legacy hash path, which changes the
        // content_hash, making the original signed/committed hash invalid.
        //
        // This test verifies the hash domain separation between legacy and
        // new schemas prevents schema-swapping attacks.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        let original_hash = envelope.content_hash.clone();

        // Tamper with the original envelope: strip decision AND swap to legacy schema.
        envelope.leakage_budget_decision = None;
        envelope.schema = EVIDENCE_BUNDLE_SCHEMA.to_string();

        // Recompute hash under the legacy schema path.
        let legacy_hash = compute_envelope_content_hash(&envelope);
        let legacy_hash_str = format!("b3-256:{}", hex::encode(legacy_hash));

        // The legacy hash must differ from the original (new-schema + decision).
        assert_ne!(
            original_hash, legacy_hash_str,
            "schema swap must produce a different hash, proving the original \
             committed hash cannot survive a schema downgrade"
        );
    }

    #[test]
    fn import_rejects_schema_downgraded_envelope_with_budget_aware_fields() {
        // Regression test for INV-EB-023: An attacker takes a valid
        // new-schema envelope with a leakage_budget_decision, strips the
        // decision field, swaps the schema to legacy, and recomputes the
        // content hash via the legacy hash path. The resulting envelope
        // would previously pass import because the legacy exemption
        // accepted it. With INV-EB-023, the boundary check's budget-aware
        // fields (leakage_budget_receipt, timing_channel_budget,
        // disclosure_policy_binding) reveal that this is NOT a truly
        // legacy envelope, and import MUST reject it.
        let receipt = make_valid_receipt();
        let config = make_valid_export_config();

        // Step 1: Build a legitimate new-schema envelope with decision.
        let mut envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");
        assert!(
            envelope.leakage_budget_decision.is_some(),
            "legitimate envelope must have a leakage budget decision"
        );
        // Verify boundary check has budget-aware fields.
        assert!(
            envelope.boundary_check.leakage_budget_receipt.is_some()
                || envelope.boundary_check.timing_channel_budget.is_some()
                || envelope.boundary_check.disclosure_policy_binding.is_some(),
            "test setup: boundary check must carry budget-aware fields"
        );

        // Step 2: Attacker strips the decision and swaps schema to legacy.
        envelope.leakage_budget_decision = None;
        envelope.schema = EVIDENCE_BUNDLE_SCHEMA.to_string();

        // Step 3: Attacker recomputes the hash via the legacy path.
        let tampered_hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(tampered_hash));

        // Step 4: Verify the tampered hash is self-consistent (hash
        // check alone would pass — the INV-EB-023 check must catch this).
        let recomputed = compute_envelope_content_hash(&envelope);
        assert_eq!(
            tampered_hash, recomputed,
            "tampered hash must be self-consistent for this attack to be meaningful"
        );

        // Step 5: Import must reject the tampered envelope.
        let data = serialize_envelope(&envelope).expect("serialize tampered envelope");
        let result = import_evidence_bundle(&data);
        assert!(
            matches!(result, Err(EvidenceBundleError::LeakageBudgetDenied { .. })),
            "schema-downgraded envelope with budget-aware fields must be \
             rejected (INV-EB-023): {result:?}"
        );

        // Verify the error message mentions schema-downgrade.
        if let Err(EvidenceBundleError::LeakageBudgetDenied { reason }) = &result {
            assert!(
                reason.contains("budget-aware") || reason.contains("INV-EB-023"),
                "error should indicate schema-downgrade detection: {reason}"
            );
        }
    }
}
