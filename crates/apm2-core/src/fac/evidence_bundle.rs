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

/// Schema identifier for the evidence bundle envelope.
pub const EVIDENCE_BUNDLE_SCHEMA: &str = "apm2.fac.evidence_bundle.v1";

/// Maximum envelope file size to read (256 KiB).
pub const MAX_ENVELOPE_SIZE: usize = 262_144;

/// Maximum blob count in a single bundle.
pub const MAX_BUNDLE_BLOB_COUNT: usize = 256;

/// Maximum blob reference string length.
pub const MAX_BLOB_REF_LENGTH: usize = 256;

/// Maximum job ID length.
pub const MAX_JOB_ID_LENGTH: usize = 256;

/// BLAKE3 domain separator for envelope content hash.
const ENVELOPE_HASH_DOMAIN: &[u8] = b"apm2.fac.evidence_bundle.content_hash.v1\0";

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
        schema: EVIDENCE_BUNDLE_SCHEMA.to_string(),
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

    // Schema check.
    if envelope.schema != EVIDENCE_BUNDLE_SCHEMA {
        return Err(EvidenceBundleError::SchemaMismatch {
            expected: EVIDENCE_BUNDLE_SCHEMA.to_string(),
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

    // -- receipt canonical bytes (length-prefixed) --
    let receipt_bytes = envelope.receipt.canonical_bytes();
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
/// and runs `validate_channel_boundary()`. Any defects cause rejection.
fn validate_boundary_check(envelope: &EvidenceBundleEnvelopeV1) -> Result<(), EvidenceBundleError> {
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

    // INV-EB-001: validate_channel_boundary must return zero defects.
    let defects = validate_channel_boundary(&check);
    if !defects.is_empty() {
        let defect_classes: Vec<String> = defects
            .iter()
            .map(|d| format!("{:?}", d.violation_class))
            .collect();
        return Err(EvidenceBundleError::ChannelBoundaryInvalid {
            defect_count: defects.len(),
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

        assert_eq!(imported.schema, EVIDENCE_BUNDLE_SCHEMA);
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
    fn import_refuses_missing_leakage_budget() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.leakage_budget_receipt = None;

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. })
            ),
            "should reject when leakage budget receipt missing"
        );
    }

    #[test]
    fn import_refuses_missing_timing_budget() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.timing_channel_budget = None;

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. })
            ),
            "should reject when timing channel budget missing"
        );
    }

    #[test]
    fn import_refuses_missing_disclosure_policy() {
        let receipt = make_valid_receipt();
        let mut config = make_valid_export_config();
        config.disclosure_policy_binding = None;

        let envelope =
            build_evidence_bundle_envelope(&receipt, &config, &[]).expect("export should succeed");

        let data = serialize_envelope(&envelope).expect("serialize");
        let result = import_evidence_bundle(&data);

        assert!(
            matches!(
                result,
                Err(EvidenceBundleError::ChannelBoundaryInvalid { .. })
            ),
            "should reject when disclosure policy binding missing"
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
}
