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
/// and disclosure policy binding.
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

    // Build envelope without content hash first.
    let mut envelope = EvidenceBundleEnvelopeV1 {
        schema: EVIDENCE_BUNDLE_ENVELOPE_SCHEMA.to_string(),
        receipt: receipt.clone(),
        boundary_check,
        economics_trace,
        policy_binding: config.policy_binding.clone(),
        blob_refs: blob_refs.to_vec(),
        content_hash: String::new(),
    };

    // Compute content hash over canonical bytes.
    let hash = compute_envelope_content_hash(&envelope);
    envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

    Ok(envelope)
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
        let hash = compute_envelope_content_hash(&envelope);
        envelope.content_hash = format!("b3-256:{}", hex::encode(hash));

        let data = serialize_envelope(&envelope).expect("serialize");
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
}
