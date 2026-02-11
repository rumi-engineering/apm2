//! Markov-blanket channel enforcement for RFC-0020.
//!
//! Restricts authoritative actuation to typed tool-intent channel events
//! and emits structured defects for boundary violations.

use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::crypto::{Signature, Signer, VerifyingKey, parse_signature, verify_signature};
use crate::disclosure::{DisclosureChannelClass, DisclosurePolicyMode};

/// Maximum string length for channel enforcement detail fields.
pub const MAX_CHANNEL_DETAIL_LENGTH: usize = 512;
/// Maximum length for declassification receipt identifiers.
pub const MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH: usize = 128;
/// Maximum length for leakage estimator confidence labels.
pub const MAX_LEAKAGE_CONFIDENCE_LABEL_LENGTH: usize = 128;
/// Maximum length for disclosure phase identifiers in boundary bindings.
pub const MAX_DISCLOSURE_PHASE_ID_LENGTH: usize = 128;
/// Maximum length for disclosure state validation reasons.
pub const MAX_DISCLOSURE_STATE_REASON_LENGTH: usize = 256;
const CHANNEL_SOURCE_WITNESS_DOMAIN: &[u8] = b"apm2.channel_source_witness.v1";
const CHANNEL_CONTEXT_TOKEN_SCHEMA_ID: &str = "apm2.channel_context_token.v1";
const MAX_CHANNEL_CONTEXT_TOKEN_LEN: usize = 8192;
const CHANNEL_CONTEXT_TOKEN_DEFAULT_EXPIRES_AFTER_SECS: u64 = 300;

/// Channel source classification for actuation boundary enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelSource {
    /// Typed tool-intent channel event (structured, broker-mediated).
    TypedToolIntent,
    /// Free-form model output (unstructured text, non-authoritative).
    FreeFormOutput,
    /// Direct manifest invocation (bypass attempt).
    DirectManifest,
    /// Unknown/missing channel metadata.
    Unknown,
}

impl ChannelSource {
    const fn canonical_label(self) -> &'static str {
        match self {
            Self::TypedToolIntent => "typed_tool_intent",
            Self::FreeFormOutput => "free_form_output",
            Self::DirectManifest => "direct_manifest",
            Self::Unknown => "unknown",
        }
    }
}

/// Declassification intent scope for boundary-flow downgrade requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationIntentScope {
    /// No boundary downgrade is requested.
    None,
    /// Downgrade is requested for recoverability redundancy fragments only.
    RedundancyPurpose,
    /// Unknown/unscoped intent (explicit fail-closed deny).
    Unknown,
}

const fn default_unknown_declassification_intent_scope() -> DeclassificationIntentScope {
    DeclassificationIntentScope::Unknown
}

/// Estimator family for typed leakage-budget receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakageEstimatorFamily {
    /// Mutual-information upper-bound estimator family.
    MutualInformationUpperBound,
    /// Channel-capacity upper-bound estimator family.
    ChannelCapacityUpperBound,
    /// Deterministic histogram bucket estimator family.
    EmpiricalBucketHistogram,
    /// Unknown estimator family (fail-closed deny).
    Unknown,
}

/// Digest/coherence binding for RFC-0028 boundary-flow policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryFlowPolicyBinding {
    /// Flow policy digest presented at the boundary.
    pub policy_digest: [u8; 32],
    /// Admitted policy root digest from authoritative state.
    pub admitted_policy_root_digest: [u8; 32],
    /// Canonicalizer tuple digest presented at the boundary.
    pub canonicalizer_tuple_digest: [u8; 32],
    /// Admitted canonicalizer tuple digest from authoritative state.
    pub admitted_canonicalizer_tuple_digest: [u8; 32],
}

impl BoundaryFlowPolicyBinding {
    fn has_non_zero_digests(&self) -> bool {
        self.policy_digest != [0u8; 32]
            && self.admitted_policy_root_digest != [0u8; 32]
            && self.canonicalizer_tuple_digest != [0u8; 32]
            && self.admitted_canonicalizer_tuple_digest != [0u8; 32]
    }

    fn policy_digest_matches(&self) -> bool {
        bool::from(self.policy_digest.ct_eq(&self.admitted_policy_root_digest))
    }

    fn canonicalizer_tuple_matches(&self) -> bool {
        bool::from(
            self.canonicalizer_tuple_digest
                .ct_eq(&self.admitted_canonicalizer_tuple_digest),
        )
    }
}

/// Receipt metadata required for `redundancy_purpose` declassification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedundancyDeclassificationReceipt {
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// True when the release is scoped to fragment metadata only.
    pub scoped_fragment_only: bool,
    /// True when authority-bearing plaintext semantics are exposed.
    pub plaintext_semantics_exposed: bool,
}

impl RedundancyDeclassificationReceipt {
    fn is_well_formed(&self) -> bool {
        !self.receipt_id.is_empty()
            && self.receipt_id.len() <= MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH
            && self.scoped_fragment_only
            && !self.plaintext_semantics_exposed
    }
}

/// Typed leakage-budget receipt for boundary-flow admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeakageBudgetReceipt {
    /// Leakage estimate in `leakage_bits`.
    pub leakage_bits: u64,
    /// Budget ceiling in `leakage_bits`.
    pub budget_bits: u64,
    /// Estimator family declaration.
    pub estimator_family: LeakageEstimatorFamily,
    /// Confidence in basis points (`0..=10000`).
    pub confidence_bps: u16,
    /// Optional bounded confidence descriptor.
    pub confidence_label: String,
}

impl LeakageBudgetReceipt {
    fn is_well_formed(&self) -> bool {
        self.budget_bits > 0
            && self.confidence_bps <= 10_000
            && self.confidence_label.len() <= MAX_LEAKAGE_CONFIDENCE_LABEL_LENGTH
    }
}

/// Timing-channel budget witness for release bucketing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimingChannelBudget {
    /// Release bucket size in ticks.
    pub release_bucket_ticks: u64,
    /// Observed timing variance in ticks.
    pub observed_variance_ticks: u64,
    /// Maximum admissible timing variance in ticks.
    pub budget_ticks: u64,
}

impl TimingChannelBudget {
    const fn is_well_formed(&self) -> bool {
        self.release_bucket_ticks > 0 && self.budget_ticks > 0
    }
}

/// Disclosure-control policy binding for RFC-0028 REQ-0007 admission checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicyBinding {
    /// Whether this request must enforce disclosure interlock fail-closed.
    pub required_for_effect: bool,
    /// Whether snapshot signature/freshness/phase/mode validation passed.
    pub state_valid: bool,
    /// Active policy mode reported for this request.
    pub active_mode: DisclosurePolicyMode,
    /// Expected policy mode from `phase_disclosure_profile(phase_id)`.
    pub expected_mode: DisclosurePolicyMode,
    /// Channel class attempted by the request.
    pub attempted_channel: DisclosureChannelClass,
    /// Snapshot digest presented for this decision.
    pub policy_snapshot_digest: [u8; 32],
    /// Admitted policy epoch root digest from authoritative state.
    pub admitted_policy_epoch_root_digest: [u8; 32],
    /// Policy epoch associated with the snapshot.
    pub policy_epoch: u64,
    /// Phase identifier for evaluated window.
    pub phase_id: String,
    /// Bounded validation reason emitted on invalid state.
    pub state_reason: String,
}

impl DisclosurePolicyBinding {
    fn has_non_zero_snapshot_digest(&self) -> bool {
        self.policy_snapshot_digest != [0u8; 32]
            && self.admitted_policy_epoch_root_digest != [0u8; 32]
    }

    fn snapshot_digest_matches(&self) -> bool {
        bool::from(
            self.policy_snapshot_digest
                .ct_eq(&self.admitted_policy_epoch_root_digest),
        )
    }

    fn bounded_reason(&self) -> String {
        truncate_to_length(&self.state_reason, MAX_DISCLOSURE_STATE_REASON_LENGTH)
    }

    fn bounded_phase_id(&self) -> String {
        truncate_to_length(&self.phase_id, MAX_DISCLOSURE_PHASE_ID_LENGTH)
    }
}

/// Channel boundary enforcement result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct ChannelBoundaryCheck {
    /// The classified channel source.
    pub source: ChannelSource,
    /// Witness proving the channel source was attested by a trusted launcher.
    pub channel_source_witness: Option<[u8; 32]>,
    /// Whether the broker path was verified.
    pub broker_verified: bool,
    /// Whether capability enforcement was verified.
    pub capability_verified: bool,
    /// Whether context-firewall integrity was verified.
    pub context_firewall_verified: bool,
    /// Whether policy hash admission was verified against the ledger.
    pub policy_ledger_verified: bool,
    /// Whether taint lattice admission allows this flow.
    pub taint_allow: bool,
    /// Whether confidentiality/classification admission allows this flow.
    pub classification_allow: bool,
    /// Whether declassification receipt validation passed for this flow.
    pub declass_receipt_valid: bool,
    /// Declassification intent scope at this boundary.
    pub declassification_intent: DeclassificationIntentScope,
    /// Optional redundancy-purpose declassification receipt.
    pub redundancy_declassification_receipt: Option<RedundancyDeclassificationReceipt>,
    /// Policy digest/canonicalizer tuple binding witness.
    pub boundary_flow_policy_binding: Option<BoundaryFlowPolicyBinding>,
    /// Typed leakage-budget receipt.
    pub leakage_budget_receipt: Option<LeakageBudgetReceipt>,
    /// Timing-channel release-bucketing witness.
    pub timing_channel_budget: Option<TimingChannelBudget>,
    /// Disclosure-control policy interlock binding.
    #[serde(default)]
    pub disclosure_policy_binding: Option<DisclosurePolicyBinding>,
    /// Policy-derived maximum leakage budget in bits.
    #[serde(default)]
    pub leakage_budget_policy_max_bits: Option<u64>,
    /// Client-claimed leakage budget in bits before policy clamping.
    #[serde(default)]
    pub declared_leakage_budget_bits: Option<u64>,
    /// Policy-derived maximum timing budget in ticks.
    #[serde(default)]
    pub timing_budget_policy_max_ticks: Option<u64>,
    /// Client-claimed timing budget in ticks before policy clamping.
    #[serde(default)]
    pub declared_timing_budget_ticks: Option<u64>,
}

/// Serialized channel context payload signed by the daemon signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct ChannelContextTokenPayloadV1 {
    source: ChannelSource,
    pub lease_id: String,
    /// The specific request ID this token was issued for.
    pub request_id: String,
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at_secs: u64,
    /// Token validity window in seconds.
    pub expires_after_secs: u64,
    channel_source_witness: [u8; 32],
    broker_verified: bool,
    capability_verified: bool,
    context_firewall_verified: bool,
    policy_ledger_verified: bool,
    #[serde(default)]
    taint_allow: bool,
    #[serde(default)]
    classification_allow: bool,
    #[serde(default)]
    declass_receipt_valid: bool,
    #[serde(default = "default_unknown_declassification_intent_scope")]
    declassification_intent: DeclassificationIntentScope,
    #[serde(default)]
    redundancy_declassification_receipt: Option<RedundancyDeclassificationReceipt>,
    #[serde(default)]
    boundary_flow_policy_binding: Option<BoundaryFlowPolicyBinding>,
    #[serde(default)]
    leakage_budget_receipt: Option<LeakageBudgetReceipt>,
    #[serde(default)]
    timing_channel_budget: Option<TimingChannelBudget>,
    #[serde(default)]
    disclosure_policy_binding: Option<DisclosurePolicyBinding>,
    #[serde(default)]
    leakage_budget_policy_max_bits: Option<u64>,
    #[serde(default)]
    declared_leakage_budget_bits: Option<u64>,
    #[serde(default)]
    timing_budget_policy_max_ticks: Option<u64>,
    #[serde(default)]
    declared_timing_budget_ticks: Option<u64>,
}

/// Serialized signed channel context token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelContextTokenV1 {
    schema_id: String,
    payload: ChannelContextTokenPayloadV1,
    signature: String,
}

/// Channel context token decode/encode errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChannelContextTokenError {
    /// Token string exceeded the bounded maximum length.
    #[error("channel context token exceeds max length {max_len}")]
    TokenTooLong {
        /// Maximum accepted token length.
        max_len: usize,
    },
    /// Token was not valid base64.
    #[error("channel context token is not valid base64: {detail}")]
    InvalidBase64 {
        /// Decode failure detail.
        detail: String,
    },
    /// Token payload was not valid JSON.
    #[error("channel context token payload is not valid JSON: {detail}")]
    InvalidJson {
        /// Decode failure detail.
        detail: String,
    },
    /// Token payload carried an unsupported schema identifier.
    #[error("channel context token schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier.
        actual: String,
    },
    /// Token did not carry a witness even though one is required.
    #[error("channel context token missing channel source witness")]
    MissingWitness,
    /// Token witness did not validate against the claimed source.
    #[error("channel context token witness verification failed")]
    WitnessVerificationFailed,
    /// Token signature was malformed.
    #[error("channel context token signature is invalid: {detail}")]
    InvalidSignature {
        /// Signature decode/parse detail.
        detail: String,
    },
    /// Token signature did not verify against the daemon public key.
    #[error("channel context token signature verification failed")]
    SignatureVerificationFailed,
    /// Token lease binding did not match the expected lease ID.
    #[error("channel context token lease mismatch: expected {expected}, got {actual}")]
    LeaseMismatch {
        /// Lease identifier expected by the current operation.
        expected: String,
        /// Lease identifier carried in the token payload.
        actual: String,
    },
    /// Token request binding did not match the expected request ID.
    #[error("channel context token request mismatch: expected {expected}, got {actual}")]
    RequestIdMismatch {
        /// Request identifier expected by the current operation.
        expected: String,
        /// Request identifier carried in the token payload.
        actual: String,
    },
    /// Token expired before decode.
    #[error("channel context token expired")]
    ExpiredToken {
        /// Token issuance time in seconds since Unix epoch.
        issued_at_secs: u64,
        /// Token validity duration.
        expires_after_secs: u64,
        /// Decoder current time.
        current_time_secs: u64,
    },
}

/// Channel boundary violation defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelBoundaryDefect {
    /// The type of violation.
    pub violation_class: ChannelViolationClass,
    /// Human-readable detail (bounded to `MAX_CHANNEL_DETAIL_LENGTH`).
    pub detail: String,
}

impl ChannelBoundaryDefect {
    /// Construct a channel boundary defect with bounded detail length.
    #[must_use]
    pub fn new(violation_class: ChannelViolationClass, detail: impl Into<String>) -> Self {
        Self {
            violation_class,
            detail: truncate_channel_detail(detail.into()),
        }
    }
}

/// Classification of channel boundary violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelViolationClass {
    /// Free-form model output attempted to drive authoritative actuation.
    UntypedChannelSource,
    /// Direct manifest invocation bypassing broker.
    BrokerBypassDetected,
    /// Capability enforcement not verified before actuation.
    CapabilityNotVerified,
    /// Context-firewall integrity not verified before actuation.
    ContextFirewallNotVerified,
    /// Channel metadata missing or malformed.
    MissingChannelMetadata,
    /// Channel source unknown or unclassifiable.
    UnknownChannelSource,
    /// Policy hash was not verified against authoritative ledger admission.
    PolicyNotLedgerVerified,
    /// Taint lattice admission denied this boundary flow.
    TaintNotAdmitted,
    /// Confidentiality/classification admission denied this boundary flow.
    ClassificationNotAdmitted,
    /// Declassification receipt was required but missing/invalid.
    DeclassificationReceiptInvalid,
    /// Declassification intent was unknown or unscoped.
    UnknownOrUnscopedDeclassificationIntent,
    /// Policy digest binding mismatch or missing policy digest witness.
    PolicyDigestBindingMismatch,
    /// Canonicalizer tuple binding mismatch or missing witness.
    CanonicalizerTupleBindingMismatch,
    /// Leakage budget receipt missing, malformed, or over budget.
    LeakageBudgetExceeded,
    /// Timing-channel release bucketing/budget violated.
    TimingChannelBudgetExceeded,
    /// Disclosure-control state missing, stale, invalid, or ambiguous.
    DisclosurePolicyStateInvalid,
    /// Active disclosure mode mismatches the phase profile.
    DisclosurePolicyModeMismatch,
    /// Disclosure policy snapshot digest binding mismatch.
    DisclosurePolicyDigestBindingMismatch,
    /// Attempted disclosure channel is denied by active mode.
    DisclosureChannelNotAdmitted,
}

impl ChannelViolationClass {
    /// Returns `true` when this defect requires boundary-channel quarantine.
    #[must_use]
    pub const fn requires_quarantine(self) -> bool {
        matches!(
            self,
            Self::LeakageBudgetExceeded | Self::TimingChannelBudgetExceeded
        )
    }
}

/// Deterministically derives a witness token for the provided channel source.
///
/// The daemon uses this witness to bind channel-source classification into a
/// replay-stable token carried with boundary checks.
#[must_use]
pub fn derive_channel_source_witness(source: ChannelSource) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHANNEL_SOURCE_WITNESS_DOMAIN);
    hasher.update(source.canonical_label().as_bytes());
    *hasher.finalize().as_bytes()
}

fn matches_channel_source_witness(source: ChannelSource, witness: &[u8; 32]) -> bool {
    let expected = derive_channel_source_witness(source);
    bool::from(expected.ct_eq(witness))
}

fn canonical_payload(
    payload: &ChannelContextTokenPayloadV1,
) -> Result<Vec<u8>, ChannelContextTokenError> {
    let value =
        serde_json::to_value(payload).map_err(|error| ChannelContextTokenError::InvalidJson {
            detail: error.to_string(),
        })?;
    serde_json::to_vec(&value).map_err(|error| ChannelContextTokenError::InvalidJson {
        detail: error.to_string(),
    })
}

/// Validates a channel source witness token and daemon signature.
#[must_use]
pub fn verify_channel_source_witness(
    source: ChannelSource,
    witness: &[u8; 32],
    signed_payload: &[u8],
    signature: &Signature,
    daemon_verifying_key: &VerifyingKey,
) -> bool {
    if !matches_channel_source_witness(source, witness) {
        return false;
    }
    verify_signature(daemon_verifying_key, signed_payload, signature).is_ok()
}

/// Issues a base64-encoded channel context token from a boundary check.
///
/// The token includes the source witness and verification booleans so the CLI
/// can reconstruct a fail-closed `ChannelBoundaryCheck`.
///
/// # Errors
///
/// Returns an error if the boundary check has no channel source witness or if
/// serialization fails.
pub fn issue_channel_context_token(
    check: &ChannelBoundaryCheck,
    lease_id: &str,
    request_id: &str,
    issued_at_secs: u64,
    signer: &Signer,
) -> Result<String, ChannelContextTokenError> {
    issue_channel_context_token_with_freshness(
        check,
        lease_id,
        request_id,
        issued_at_secs,
        CHANNEL_CONTEXT_TOKEN_DEFAULT_EXPIRES_AFTER_SECS,
        signer,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_channel_context_token_with_freshness(
    check: &ChannelBoundaryCheck,
    lease_id: &str,
    request_id: &str,
    issued_at_secs: u64,
    expires_after_secs: u64,
    signer: &Signer,
) -> Result<String, ChannelContextTokenError> {
    let Some(channel_source_witness) = check.channel_source_witness else {
        return Err(ChannelContextTokenError::MissingWitness);
    };

    let payload = ChannelContextTokenPayloadV1 {
        source: check.source,
        lease_id: lease_id.to_string(),
        request_id: request_id.to_string(),
        issued_at_secs,
        expires_after_secs,
        channel_source_witness,
        broker_verified: check.broker_verified,
        capability_verified: check.capability_verified,
        context_firewall_verified: check.context_firewall_verified,
        policy_ledger_verified: check.policy_ledger_verified,
        taint_allow: check.taint_allow,
        classification_allow: check.classification_allow,
        declass_receipt_valid: check.declass_receipt_valid,
        declassification_intent: check.declassification_intent,
        redundancy_declassification_receipt: check.redundancy_declassification_receipt.clone(),
        boundary_flow_policy_binding: check.boundary_flow_policy_binding.clone(),
        leakage_budget_receipt: check.leakage_budget_receipt.clone(),
        timing_channel_budget: check.timing_channel_budget.clone(),
        disclosure_policy_binding: check.disclosure_policy_binding.clone(),
        leakage_budget_policy_max_bits: check.leakage_budget_policy_max_bits,
        declared_leakage_budget_bits: check.declared_leakage_budget_bits,
        timing_budget_policy_max_ticks: check.timing_budget_policy_max_ticks,
        declared_timing_budget_ticks: check.declared_timing_budget_ticks,
    };

    let payload_json = canonical_payload(&payload)?;
    let signature = signer.sign(&payload_json);
    let token = ChannelContextTokenV1 {
        schema_id: CHANNEL_CONTEXT_TOKEN_SCHEMA_ID.to_string(),
        payload,
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    };
    let token_json =
        serde_json::to_vec(&token).map_err(|error| ChannelContextTokenError::InvalidJson {
            detail: error.to_string(),
        })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(token_json))
}

/// Decodes and verifies a base64-encoded channel context token.
///
/// # Errors
///
/// Returns an error if the token cannot be decoded, fails schema checks, or
/// has an invalid source witness.
pub fn decode_channel_context_token(
    token: &str,
    daemon_verifying_key: &VerifyingKey,
    expected_lease_id: &str,
    current_time_secs: u64,
    expected_request_id: &str,
) -> Result<ChannelBoundaryCheck, ChannelContextTokenError> {
    if token.len() > MAX_CHANNEL_CONTEXT_TOKEN_LEN {
        return Err(ChannelContextTokenError::TokenTooLong {
            max_len: MAX_CHANNEL_CONTEXT_TOKEN_LEN,
        });
    }

    let payload_json = base64::engine::general_purpose::STANDARD
        .decode(token)
        .map_err(|error| ChannelContextTokenError::InvalidBase64 {
            detail: error.to_string(),
        })?;
    let payload: ChannelContextTokenV1 =
        serde_json::from_slice(&payload_json).map_err(|error| {
            ChannelContextTokenError::InvalidJson {
                detail: error.to_string(),
            }
        })?;

    if payload.schema_id != CHANNEL_CONTEXT_TOKEN_SCHEMA_ID {
        return Err(ChannelContextTokenError::SchemaMismatch {
            expected: CHANNEL_CONTEXT_TOKEN_SCHEMA_ID.to_string(),
            actual: payload.schema_id,
        });
    }

    let payload_json = canonical_payload(&payload.payload)?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.signature)
        .map_err(|error| ChannelContextTokenError::InvalidSignature {
            detail: error.to_string(),
        })?;
    let signature = parse_signature(&signature_bytes).map_err(|error| {
        ChannelContextTokenError::InvalidSignature {
            detail: error.to_string(),
        }
    })?;

    if !matches_channel_source_witness(
        payload.payload.source,
        &payload.payload.channel_source_witness,
    ) {
        return Err(ChannelContextTokenError::WitnessVerificationFailed);
    }
    if !verify_channel_source_witness(
        payload.payload.source,
        &payload.payload.channel_source_witness,
        &payload_json,
        &signature,
        daemon_verifying_key,
    ) {
        return Err(ChannelContextTokenError::SignatureVerificationFailed);
    }
    if payload.payload.lease_id != expected_lease_id {
        return Err(ChannelContextTokenError::LeaseMismatch {
            expected: expected_lease_id.to_string(),
            actual: payload.payload.lease_id,
        });
    }
    if payload.payload.request_id != expected_request_id {
        return Err(ChannelContextTokenError::RequestIdMismatch {
            expected: expected_request_id.to_string(),
            actual: payload.payload.request_id,
        });
    }

    let token_age_secs = current_time_secs.saturating_sub(payload.payload.issued_at_secs);
    if token_age_secs >= payload.payload.expires_after_secs {
        return Err(ChannelContextTokenError::ExpiredToken {
            issued_at_secs: payload.payload.issued_at_secs,
            expires_after_secs: payload.payload.expires_after_secs,
            current_time_secs,
        });
    }

    Ok(ChannelBoundaryCheck {
        source: payload.payload.source,
        channel_source_witness: Some(payload.payload.channel_source_witness),
        broker_verified: payload.payload.broker_verified,
        capability_verified: payload.payload.capability_verified,
        context_firewall_verified: payload.payload.context_firewall_verified,
        policy_ledger_verified: payload.payload.policy_ledger_verified,
        taint_allow: payload.payload.taint_allow,
        classification_allow: payload.payload.classification_allow,
        declass_receipt_valid: payload.payload.declass_receipt_valid,
        declassification_intent: payload.payload.declassification_intent,
        redundancy_declassification_receipt: payload.payload.redundancy_declassification_receipt,
        boundary_flow_policy_binding: payload.payload.boundary_flow_policy_binding,
        leakage_budget_receipt: payload.payload.leakage_budget_receipt,
        timing_channel_budget: payload.payload.timing_channel_budget,
        disclosure_policy_binding: payload.payload.disclosure_policy_binding,
        leakage_budget_policy_max_bits: payload.payload.leakage_budget_policy_max_bits,
        declared_leakage_budget_bits: payload.payload.declared_leakage_budget_bits,
        timing_budget_policy_max_ticks: payload.payload.timing_budget_policy_max_ticks,
        declared_timing_budget_ticks: payload.payload.declared_timing_budget_ticks,
    })
}

/// Validate that a channel boundary check satisfies actuation requirements.
///
/// Returns defects for any violations found. Empty vec = authorized.
/// Fail-closed: any missing/ambiguous check results in a defect.
#[must_use]
pub fn validate_channel_boundary(check: &ChannelBoundaryCheck) -> Vec<ChannelBoundaryDefect> {
    let mut defects = Vec::new();

    let source = resolve_effective_source(check, &mut defects);
    match source {
        ChannelSource::TypedToolIntent => {},
        ChannelSource::FreeFormOutput => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::UntypedChannelSource,
            "free-form model output cannot drive authoritative actuation",
        )),
        ChannelSource::DirectManifest => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::BrokerBypassDetected,
            "direct manifest invocation is a broker bypass",
        )),
        ChannelSource::Unknown => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::UnknownChannelSource,
            "channel source is unknown or unclassifiable",
        )),
    }

    if !check.broker_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::BrokerBypassDetected,
            "broker path was not verified",
        ));
    }

    if !check.capability_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::CapabilityNotVerified,
            "capability enforcement was not verified",
        ));
    }

    if !check.context_firewall_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::ContextFirewallNotVerified,
            "context-firewall integrity was not verified",
        ));
    }

    if !check.policy_ledger_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::PolicyNotLedgerVerified,
            "policy hash admission was not verified against ledger state",
        ));
    }

    validate_boundary_admit_predicate(check, &mut defects);
    validate_declassification_constraints(check, &mut defects);
    validate_boundary_flow_policy_binding(check, &mut defects);
    validate_leakage_budget(check, &mut defects);
    validate_timing_budget(check, &mut defects);
    validate_disclosure_policy_binding(check, &mut defects);

    defects
}

fn validate_boundary_flow_policy_binding(
    check: &ChannelBoundaryCheck,
    defects: &mut Vec<ChannelBoundaryDefect>,
) {
    let Some(binding) = &check.boundary_flow_policy_binding else {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::PolicyDigestBindingMismatch,
            "missing boundary-flow policy binding",
        ));
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::CanonicalizerTupleBindingMismatch,
            "missing canonicalizer tuple binding",
        ));
        return;
    };

    if !binding.has_non_zero_digests() || !binding.policy_digest_matches() {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::PolicyDigestBindingMismatch,
            "policy digest binding mismatch against admitted policy root",
        ));
    }

    if !binding.has_non_zero_digests() || !binding.canonicalizer_tuple_matches() {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::CanonicalizerTupleBindingMismatch,
            "canonicalizer tuple digest mismatch against admitted tuple",
        ));
    }
}

fn validate_boundary_admit_predicate(
    check: &ChannelBoundaryCheck,
    defects: &mut Vec<ChannelBoundaryDefect>,
) {
    if !check.capability_verified {
        // Existing CapabilityNotVerified defect is emitted above; keep this
        // helper focused on REQ-0004 deltas.
    }
    if !check.taint_allow {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::TaintNotAdmitted,
            "boundary_admit taint_allow predicate is false",
        ));
    }

    if !check.classification_allow {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::ClassificationNotAdmitted,
            "boundary_admit classification_allow predicate is false",
        ));
    }

    if !check.declass_receipt_valid {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::DeclassificationReceiptInvalid,
            "boundary_admit declass_receipt_valid predicate is false",
        ));
    }
}

fn validate_declassification_constraints(
    check: &ChannelBoundaryCheck,
    defects: &mut Vec<ChannelBoundaryDefect>,
) {
    match check.declassification_intent {
        DeclassificationIntentScope::Unknown => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::UnknownOrUnscopedDeclassificationIntent,
            "declassification intent is unknown or unscoped (fail-closed deny)",
        )),
        DeclassificationIntentScope::RedundancyPurpose => {
            let Some(receipt) = &check.redundancy_declassification_receipt else {
                defects.push(ChannelBoundaryDefect::new(
                    ChannelViolationClass::DeclassificationReceiptInvalid,
                    "redundancy-purpose declassification requires redundancy_declassification_receipt",
                ));
                return;
            };

            if !receipt.is_well_formed() {
                defects.push(ChannelBoundaryDefect::new(
                    ChannelViolationClass::DeclassificationReceiptInvalid,
                    "redundancy declassification receipt malformed or exposes plaintext semantics",
                ));
            }
        },
        DeclassificationIntentScope::None => {
            if check.redundancy_declassification_receipt.is_some() {
                defects.push(ChannelBoundaryDefect::new(
                    ChannelViolationClass::DeclassificationReceiptInvalid,
                    "redundancy declassification receipt supplied without scoped intent",
                ));
            }
        },
    }
}

fn validate_leakage_budget(check: &ChannelBoundaryCheck, defects: &mut Vec<ChannelBoundaryDefect>) {
    let Some(receipt) = &check.leakage_budget_receipt else {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::LeakageBudgetExceeded,
            "missing typed leakage-budget receipt",
        ));
        return;
    };

    if !receipt.is_well_formed() {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::LeakageBudgetExceeded,
            "leakage-budget receipt is malformed",
        ));
        return;
    }

    if receipt.estimator_family == LeakageEstimatorFamily::Unknown {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::LeakageBudgetExceeded,
            "unknown leakage estimator semantics",
        ));
    }

    if let Some(policy_max_bits) = check.leakage_budget_policy_max_bits {
        if policy_max_bits == 0 {
            defects.push(ChannelBoundaryDefect::new(
                ChannelViolationClass::LeakageBudgetExceeded,
                "policy leakage budget ceiling is zero (fail-closed)",
            ));
        } else {
            if receipt.budget_bits > policy_max_bits {
                defects.push(ChannelBoundaryDefect::new(
                    ChannelViolationClass::LeakageBudgetExceeded,
                    format!(
                        "leakage budget exceeds policy ceiling: budget_bits={} > policy_max_bits={policy_max_bits}",
                        receipt.budget_bits
                    ),
                ));
            }

            if let Some(claimed_budget_bits) = check.declared_leakage_budget_bits {
                if claimed_budget_bits > policy_max_bits {
                    defects.push(ChannelBoundaryDefect::new(
                        ChannelViolationClass::LeakageBudgetExceeded,
                        format!(
                            "declared leakage budget exceeds policy ceiling: declared_budget_bits={claimed_budget_bits} > policy_max_bits={policy_max_bits}",
                        ),
                    ));
                }
            }
        }
    }

    if receipt.leakage_bits > receipt.budget_bits {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::LeakageBudgetExceeded,
            format!(
                "leakage budget exceeded: leakage_bits={} > budget_bits={}",
                receipt.leakage_bits, receipt.budget_bits
            ),
        ));
    }
}

fn validate_timing_budget(check: &ChannelBoundaryCheck, defects: &mut Vec<ChannelBoundaryDefect>) {
    let Some(timing) = &check.timing_channel_budget else {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::TimingChannelBudgetExceeded,
            "missing timing-channel budget witness",
        ));
        return;
    };

    if !timing.is_well_formed() {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::TimingChannelBudgetExceeded,
            "timing-channel budget witness malformed",
        ));
        return;
    }

    if let Some(policy_max_ticks) = check.timing_budget_policy_max_ticks {
        if policy_max_ticks == 0 {
            defects.push(ChannelBoundaryDefect::new(
                ChannelViolationClass::TimingChannelBudgetExceeded,
                "policy timing budget ceiling is zero (fail-closed)",
            ));
        } else {
            if timing.budget_ticks > policy_max_ticks {
                defects.push(ChannelBoundaryDefect::new(
                    ChannelViolationClass::TimingChannelBudgetExceeded,
                    format!(
                        "timing budget exceeds policy ceiling: budget_ticks={} > policy_max_ticks={policy_max_ticks}",
                        timing.budget_ticks
                    ),
                ));
            }

            if let Some(claimed_budget_ticks) = check.declared_timing_budget_ticks {
                if claimed_budget_ticks > policy_max_ticks {
                    defects.push(ChannelBoundaryDefect::new(
                        ChannelViolationClass::TimingChannelBudgetExceeded,
                        format!(
                            "declared timing budget exceeds policy ceiling: declared_budget_ticks={claimed_budget_ticks} > policy_max_ticks={policy_max_ticks}",
                        ),
                    ));
                }
            }
        }
    }

    if timing.observed_variance_ticks > timing.budget_ticks {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::TimingChannelBudgetExceeded,
            format!(
                "timing variance exceeds budget: observed={} > budget={}",
                timing.observed_variance_ticks, timing.budget_ticks
            ),
        ));
    }
}

fn validate_disclosure_policy_binding(
    check: &ChannelBoundaryCheck,
    defects: &mut Vec<ChannelBoundaryDefect>,
) {
    let Some(binding) = &check.disclosure_policy_binding else {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::DisclosurePolicyStateInvalid,
            "missing disclosure policy binding",
        ));
        return;
    };

    if !binding.required_for_effect {
        return;
    }

    if !binding.state_valid {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::DisclosurePolicyStateInvalid,
            format!(
                "disclosure policy state invalid: phase_id={} policy_epoch={} reason={}",
                binding.bounded_phase_id(),
                binding.policy_epoch,
                binding.bounded_reason(),
            ),
        ));
    }

    if !binding.has_non_zero_snapshot_digest() || !binding.snapshot_digest_matches() {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::DisclosurePolicyDigestBindingMismatch,
            format!(
                "disclosure policy snapshot digest mismatch: policy_epoch={} phase_id={}",
                binding.policy_epoch,
                binding.bounded_phase_id(),
            ),
        ));
    }

    if binding.active_mode != binding.expected_mode {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::DisclosurePolicyModeMismatch,
            format!(
                "disclosure mode mismatch: active={:?} expected={:?} phase_id={}",
                binding.active_mode,
                binding.expected_mode,
                binding.bounded_phase_id(),
            ),
        ));
    }

    let channel_allowed = match binding.active_mode {
        DisclosurePolicyMode::TradeSecretOnly => {
            matches!(binding.attempted_channel, DisclosureChannelClass::Internal)
        },
        DisclosurePolicyMode::SelectiveDisclosure => matches!(
            binding.attempted_channel,
            DisclosureChannelClass::Internal | DisclosureChannelClass::DeclassificationControlled
        ),
    };

    if !channel_allowed {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::DisclosureChannelNotAdmitted,
            format!(
                "disclosure channel denied: active_mode={:?} attempted_channel={:?} policy_epoch={} phase_id={}",
                binding.active_mode,
                binding.attempted_channel,
                binding.policy_epoch,
                binding.bounded_phase_id(),
            ),
        ));
    }
}

fn resolve_effective_source(
    check: &ChannelBoundaryCheck,
    defects: &mut Vec<ChannelBoundaryDefect>,
) -> ChannelSource {
    if check.source != ChannelSource::TypedToolIntent {
        return check.source;
    }

    if let Some(witness) = check.channel_source_witness {
        if matches_channel_source_witness(ChannelSource::TypedToolIntent, &witness) {
            ChannelSource::TypedToolIntent
        } else {
            defects.push(ChannelBoundaryDefect::new(
                ChannelViolationClass::MissingChannelMetadata,
                "channel source witness verification failed",
            ));
            ChannelSource::Unknown
        }
    } else {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::MissingChannelMetadata,
            "channel source witness is required for typed tool-intent classification",
        ));
        ChannelSource::Unknown
    }
}

fn truncate_channel_detail(mut detail: String) -> String {
    if detail.len() <= MAX_CHANNEL_DETAIL_LENGTH {
        return detail;
    }

    let mut boundary = MAX_CHANNEL_DETAIL_LENGTH;
    while !detail.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    detail.truncate(boundary);
    detail
}

fn truncate_to_length(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    let mut boundary = max_len;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value[..boundary].to_string()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn valid_policy_binding() -> BoundaryFlowPolicyBinding {
        BoundaryFlowPolicyBinding {
            policy_digest: [0x11; 32],
            admitted_policy_root_digest: [0x11; 32],
            canonicalizer_tuple_digest: [0x22; 32],
            admitted_canonicalizer_tuple_digest: [0x22; 32],
        }
    }

    fn valid_leakage_receipt() -> LeakageBudgetReceipt {
        LeakageBudgetReceipt {
            leakage_bits: 0,
            budget_bits: 8,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 10_000,
            confidence_label: "deterministic".to_string(),
        }
    }

    fn valid_timing_budget() -> TimingChannelBudget {
        TimingChannelBudget {
            release_bucket_ticks: 10,
            observed_variance_ticks: 0,
            budget_ticks: 10,
        }
    }

    fn valid_disclosure_policy_binding() -> DisclosurePolicyBinding {
        DisclosurePolicyBinding {
            required_for_effect: true,
            state_valid: true,
            active_mode: DisclosurePolicyMode::TradeSecretOnly,
            expected_mode: DisclosurePolicyMode::TradeSecretOnly,
            attempted_channel: DisclosureChannelClass::Internal,
            policy_snapshot_digest: [0x44; 32],
            admitted_policy_epoch_root_digest: [0x44; 32],
            policy_epoch: 1,
            phase_id: "pre_federation".to_string(),
            state_reason: "valid".to_string(),
        }
    }

    fn baseline_check() -> ChannelBoundaryCheck {
        ChannelBoundaryCheck {
            source: ChannelSource::TypedToolIntent,
            channel_source_witness: Some(derive_channel_source_witness(
                ChannelSource::TypedToolIntent,
            )),
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified: true,
            taint_allow: true,
            classification_allow: true,
            declass_receipt_valid: true,
            declassification_intent: DeclassificationIntentScope::None,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: Some(valid_policy_binding()),
            leakage_budget_receipt: Some(valid_leakage_receipt()),
            timing_channel_budget: Some(valid_timing_budget()),
            disclosure_policy_binding: Some(valid_disclosure_policy_binding()),
            leakage_budget_policy_max_bits: Some(8),
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: Some(10),
            declared_timing_budget_ticks: None,
        }
    }

    fn now_secs() -> u64 {
        std::time::UNIX_EPOCH
            .elapsed()
            .expect("current time should be after unix epoch")
            .as_secs()
    }

    #[test]
    fn test_typed_tool_intent_all_verified_passes() {
        let check = baseline_check();
        let defects = validate_channel_boundary(&check);
        assert!(defects.is_empty());
    }

    #[test]
    fn test_freeform_output_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::FreeFormOutput;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::UntypedChannelSource
        );
    }

    #[test]
    fn test_direct_manifest_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::DirectManifest;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::BrokerBypassDetected
        );
    }

    #[test]
    fn test_unknown_source_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::Unknown;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::UnknownChannelSource
        );
    }

    #[test]
    fn test_broker_not_verified_denied() {
        let mut check = baseline_check();
        check.broker_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::BrokerBypassDetected
        );
    }

    #[test]
    fn test_capability_not_verified_denied() {
        let mut check = baseline_check();
        check.capability_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::CapabilityNotVerified
        );
    }

    #[test]
    fn test_context_firewall_not_verified_denied() {
        let mut check = baseline_check();
        check.context_firewall_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::ContextFirewallNotVerified
        );
    }

    #[test]
    fn test_policy_not_ledger_verified_denied() {
        let mut check = baseline_check();
        check.policy_ledger_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::PolicyNotLedgerVerified
        );
    }

    #[test]
    fn test_typed_tool_intent_without_witness_denied() {
        let mut check = baseline_check();
        check.channel_source_witness = None;
        let defects = validate_channel_boundary(&check);
        let classes: Vec<ChannelViolationClass> = defects
            .iter()
            .map(|defect| defect.violation_class)
            .collect();
        assert_eq!(
            classes,
            vec![
                ChannelViolationClass::MissingChannelMetadata,
                ChannelViolationClass::UnknownChannelSource,
            ]
        );
    }

    #[test]
    fn test_typed_tool_intent_with_invalid_witness_denied() {
        let mut check = baseline_check();
        check.channel_source_witness = Some([0xAA; 32]);
        let defects = validate_channel_boundary(&check);
        let classes: Vec<ChannelViolationClass> = defects
            .iter()
            .map(|defect| defect.violation_class)
            .collect();
        assert_eq!(
            classes,
            vec![
                ChannelViolationClass::MissingChannelMetadata,
                ChannelViolationClass::UnknownChannelSource,
            ]
        );
    }

    #[test]
    fn test_multiple_violations_emitted() {
        let mut check = baseline_check();
        check.source = ChannelSource::FreeFormOutput;
        check.channel_source_witness = None;
        check.broker_verified = false;
        check.capability_verified = false;
        check.context_firewall_verified = false;
        check.policy_ledger_verified = false;

        let defects = validate_channel_boundary(&check);
        let classes: Vec<ChannelViolationClass> = defects
            .iter()
            .map(|defect| defect.violation_class)
            .collect();
        assert_eq!(
            classes,
            vec![
                ChannelViolationClass::UntypedChannelSource,
                ChannelViolationClass::BrokerBypassDetected,
                ChannelViolationClass::CapabilityNotVerified,
                ChannelViolationClass::ContextFirewallNotVerified,
                ChannelViolationClass::PolicyNotLedgerVerified,
            ]
        );
    }

    #[test]
    fn test_channel_defect_serialization() {
        let detail = "a".repeat(MAX_CHANNEL_DETAIL_LENGTH + 32);
        let defect =
            ChannelBoundaryDefect::new(ChannelViolationClass::CapabilityNotVerified, detail);
        assert_eq!(defect.detail.len(), MAX_CHANNEL_DETAIL_LENGTH);

        let json = serde_json::to_string(&defect).expect("defect should serialize");
        let decoded: ChannelBoundaryDefect =
            serde_json::from_str(&json).expect("defect should deserialize");
        assert_eq!(decoded, defect);
    }

    #[test]
    fn test_boundary_downgrade_without_receipt_denied() {
        let mut check = baseline_check();
        check.classification_allow = false;
        check.declass_receipt_valid = false;

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(
            |defect| defect.violation_class == ChannelViolationClass::ClassificationNotAdmitted
        ));
        assert!(defects.iter().any(|defect| defect.violation_class
            == ChannelViolationClass::DeclassificationReceiptInvalid));
    }

    #[test]
    fn test_classification_defect_is_independent_of_declass_receipt_validity() {
        let mut check = baseline_check();
        check.classification_allow = false;
        check.declass_receipt_valid = true;
        check.declassification_intent = DeclassificationIntentScope::None;

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(
            |defect| defect.violation_class == ChannelViolationClass::ClassificationNotAdmitted
        ));
    }

    #[test]
    fn test_unknown_declassification_intent_denied() {
        let mut check = baseline_check();
        check.declassification_intent = DeclassificationIntentScope::Unknown;

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| defect.violation_class
            == ChannelViolationClass::UnknownOrUnscopedDeclassificationIntent));
    }

    #[test]
    fn test_redundancy_declassification_requires_receipt() {
        let mut check = baseline_check();
        check.declassification_intent = DeclassificationIntentScope::RedundancyPurpose;
        check.redundancy_declassification_receipt = None;
        check.declass_receipt_valid = false;

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| defect.violation_class
            == ChannelViolationClass::DeclassificationReceiptInvalid));
    }

    #[test]
    fn test_policy_digest_binding_mismatch_denied() {
        let mut check = baseline_check();
        check.boundary_flow_policy_binding = Some(BoundaryFlowPolicyBinding {
            policy_digest: [0xAA; 32],
            admitted_policy_root_digest: [0xBB; 32],
            canonicalizer_tuple_digest: [0x22; 32],
            admitted_canonicalizer_tuple_digest: [0x22; 32],
        });

        let defects = validate_channel_boundary(&check);
        assert!(
            defects.iter().any(|defect| defect.violation_class
                == ChannelViolationClass::PolicyDigestBindingMismatch)
        );
    }

    #[test]
    fn test_canonicalizer_tuple_binding_mismatch_denied() {
        let mut check = baseline_check();
        check.boundary_flow_policy_binding = Some(BoundaryFlowPolicyBinding {
            policy_digest: [0x11; 32],
            admitted_policy_root_digest: [0x11; 32],
            canonicalizer_tuple_digest: [0xAA; 32],
            admitted_canonicalizer_tuple_digest: [0xBB; 32],
        });

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| defect.violation_class
            == ChannelViolationClass::CanonicalizerTupleBindingMismatch));
    }

    #[test]
    fn test_leakage_budget_overrun_requires_quarantine() {
        let mut check = baseline_check();
        check.leakage_budget_receipt = Some(LeakageBudgetReceipt {
            leakage_bits: 21,
            budget_bits: 20,
            estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
            confidence_bps: 9_500,
            confidence_label: "adversarial-check".to_string(),
        });

        let defects = validate_channel_boundary(&check);
        assert!(
            defects.iter().any(
                |defect| defect.violation_class == ChannelViolationClass::LeakageBudgetExceeded
            )
        );
        assert!(ChannelViolationClass::LeakageBudgetExceeded.requires_quarantine());
    }

    #[test]
    fn test_timing_budget_overrun_requires_quarantine() {
        let mut check = baseline_check();
        check.timing_channel_budget = Some(TimingChannelBudget {
            release_bucket_ticks: 10,
            observed_variance_ticks: 22,
            budget_ticks: 20,
        });

        let defects = validate_channel_boundary(&check);
        assert!(
            defects.iter().any(|defect| defect.violation_class
                == ChannelViolationClass::TimingChannelBudgetExceeded)
        );
        assert!(ChannelViolationClass::TimingChannelBudgetExceeded.requires_quarantine());
    }

    #[test]
    fn test_declared_leakage_budget_above_policy_ceiling_denied() {
        let mut check = baseline_check();
        check.declared_leakage_budget_bits = Some(999_999);

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::LeakageBudgetExceeded
                && defect
                    .detail
                    .contains("declared leakage budget exceeds policy ceiling")
        }));
    }

    #[test]
    fn test_declared_timing_budget_above_policy_ceiling_denied() {
        let mut check = baseline_check();
        check.declared_timing_budget_ticks = Some(999_999);

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::TimingChannelBudgetExceeded
                && defect
                    .detail
                    .contains("declared timing budget exceeds policy ceiling")
        }));
    }

    #[test]
    fn test_missing_boundary_flow_fields_fail_closed() {
        let mut check = baseline_check();
        check.boundary_flow_policy_binding = None;
        check.leakage_budget_receipt = None;
        check.timing_channel_budget = None;
        check.disclosure_policy_binding = None;
        check.leakage_budget_policy_max_bits = None;
        check.declared_leakage_budget_bits = None;
        check.timing_budget_policy_max_ticks = None;
        check.declared_timing_budget_ticks = None;

        let defects = validate_channel_boundary(&check);
        assert!(
            defects.iter().any(|defect| defect.violation_class
                == ChannelViolationClass::PolicyDigestBindingMismatch)
        );
        assert!(defects.iter().any(|defect| defect.violation_class
            == ChannelViolationClass::CanonicalizerTupleBindingMismatch));
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::LeakageBudgetExceeded
                && defect
                    .detail
                    .contains("missing typed leakage-budget receipt")
        }));
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::TimingChannelBudgetExceeded
                && defect
                    .detail
                    .contains("missing timing-channel budget witness")
        }));
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::DisclosurePolicyStateInvalid
                && defect.detail.contains("missing disclosure policy binding")
        }));
    }

    #[test]
    fn test_trade_secret_mode_denies_patent_channel() {
        let mut check = baseline_check();
        let mut binding = valid_disclosure_policy_binding();
        binding.attempted_channel = DisclosureChannelClass::PatentFiling;
        check.disclosure_policy_binding = Some(binding);

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::DisclosureChannelNotAdmitted
                && defect.detail.contains("attempted_channel=PatentFiling")
        }));
    }

    #[test]
    fn test_trade_secret_mode_denies_provisional_channel() {
        let mut check = baseline_check();
        let mut binding = valid_disclosure_policy_binding();
        binding.attempted_channel = DisclosureChannelClass::ProvisionalApplication;
        check.disclosure_policy_binding = Some(binding);

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::DisclosureChannelNotAdmitted
                && defect
                    .detail
                    .contains("attempted_channel=ProvisionalApplication")
        }));
    }

    #[test]
    fn test_disclosure_policy_state_invalid_denied() {
        let mut check = baseline_check();
        let mut binding = valid_disclosure_policy_binding();
        binding.state_valid = false;
        binding.state_reason = "stale policy snapshot".to_string();
        check.disclosure_policy_binding = Some(binding);

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::DisclosurePolicyStateInvalid
                && defect.detail.contains("stale policy snapshot")
        }));
    }

    #[test]
    fn test_disclosure_policy_digest_mismatch_denied() {
        let mut check = baseline_check();
        let mut binding = valid_disclosure_policy_binding();
        binding.policy_snapshot_digest = [0x77; 32];
        binding.admitted_policy_epoch_root_digest = [0x88; 32];
        check.disclosure_policy_binding = Some(binding);

        let defects = validate_channel_boundary(&check);
        assert!(defects.iter().any(|defect| {
            defect.violation_class == ChannelViolationClass::DisclosurePolicyDigestBindingMismatch
        }));
    }

    #[test]
    fn test_channel_context_token_roundtrip() {
        let check = baseline_check();
        let signer = Signer::generate();
        let token = issue_channel_context_token(&check, "lease-1", "REQ-1", now_secs(), &signer)
            .expect("token should encode");
        let decoded = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            "REQ-1",
        )
        .expect("token should decode");
        assert_eq!(decoded, check);
    }

    #[test]
    fn test_channel_context_token_payload_v1_deserializes_legacy_payload() {
        let legacy_payload = serde_json::json!({
            "source": "typed_tool_intent",
            "lease_id": "lease-legacy-1",
            "request_id": "REQ-LEGACY-1",
            "issued_at_secs": 1_700_000_000_u64,
            "expires_after_secs": CHANNEL_CONTEXT_TOKEN_DEFAULT_EXPIRES_AFTER_SECS,
            "channel_source_witness": derive_channel_source_witness(ChannelSource::TypedToolIntent),
            "broker_verified": true,
            "capability_verified": true,
            "context_firewall_verified": true,
            "policy_ledger_verified": true
        });

        let payload: ChannelContextTokenPayloadV1 =
            serde_json::from_value(legacy_payload).expect("legacy v1 payload should deserialize");
        assert!(
            !payload.taint_allow && !payload.classification_allow && !payload.declass_receipt_valid,
            "missing legacy fields must default fail-closed to false"
        );
        assert_eq!(
            payload.declassification_intent,
            DeclassificationIntentScope::Unknown
        );
        assert!(
            payload.redundancy_declassification_receipt.is_none()
                && payload.boundary_flow_policy_binding.is_none()
                && payload.leakage_budget_receipt.is_none()
                && payload.timing_channel_budget.is_none()
                && payload.disclosure_policy_binding.is_none()
                && payload.leakage_budget_policy_max_bits.is_none()
                && payload.declared_leakage_budget_bits.is_none()
                && payload.timing_budget_policy_max_ticks.is_none()
                && payload.declared_timing_budget_ticks.is_none(),
            "missing legacy fields must default fail-closed to None"
        );
    }

    #[test]
    fn test_payload_serialization_is_deterministic() {
        let payload = ChannelContextTokenPayloadV1 {
            source: ChannelSource::TypedToolIntent,
            lease_id: "lease-1".to_string(),
            request_id: "REQ-1".to_string(),
            issued_at_secs: 1_700_000_000,
            expires_after_secs: CHANNEL_CONTEXT_TOKEN_DEFAULT_EXPIRES_AFTER_SECS,
            channel_source_witness: derive_channel_source_witness(ChannelSource::TypedToolIntent),
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified: true,
            taint_allow: true,
            classification_allow: true,
            declass_receipt_valid: true,
            declassification_intent: DeclassificationIntentScope::None,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: Some(valid_policy_binding()),
            leakage_budget_receipt: Some(valid_leakage_receipt()),
            timing_channel_budget: Some(valid_timing_budget()),
            disclosure_policy_binding: Some(valid_disclosure_policy_binding()),
            leakage_budget_policy_max_bits: Some(8),
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: Some(10),
            declared_timing_budget_ticks: None,
        };

        let bytes1 = canonical_payload(&payload).expect("payload should serialize");
        let bytes2 = canonical_payload(&payload).expect("payload should serialize");
        assert_eq!(
            bytes1, bytes2,
            "payload serialization must be deterministic"
        );
    }

    #[test]
    fn test_disclosure_policy_epoch_changes_payload_bytes() {
        let payload1 = ChannelContextTokenPayloadV1 {
            source: ChannelSource::TypedToolIntent,
            lease_id: "lease-epoch".to_string(),
            request_id: "REQ-EPOCH-1".to_string(),
            issued_at_secs: 1_700_000_000,
            expires_after_secs: CHANNEL_CONTEXT_TOKEN_DEFAULT_EXPIRES_AFTER_SECS,
            channel_source_witness: derive_channel_source_witness(ChannelSource::TypedToolIntent),
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified: true,
            taint_allow: true,
            classification_allow: true,
            declass_receipt_valid: true,
            declassification_intent: DeclassificationIntentScope::None,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: Some(valid_policy_binding()),
            leakage_budget_receipt: Some(valid_leakage_receipt()),
            timing_channel_budget: Some(valid_timing_budget()),
            disclosure_policy_binding: Some(valid_disclosure_policy_binding()),
            leakage_budget_policy_max_bits: Some(8),
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: Some(10),
            declared_timing_budget_ticks: None,
        };

        let mut payload2 = payload1.clone();
        if let Some(binding) = payload2.disclosure_policy_binding.as_mut() {
            binding.policy_epoch = 2;
            binding.policy_snapshot_digest = [0x45; 32];
            binding.admitted_policy_epoch_root_digest = [0x45; 32];
        }

        let bytes1 = canonical_payload(&payload1).expect("payload1 should serialize");
        let bytes2 = canonical_payload(&payload2).expect("payload2 should serialize");
        assert_ne!(
            bytes1, bytes2,
            "disclosure policy epoch/digest changes must alter decision evidence payload bytes",
        );
    }

    #[test]
    fn test_channel_context_token_rejects_invalid_witness() {
        let signer = Signer::generate();
        let payload = ChannelContextTokenPayloadV1 {
            source: ChannelSource::TypedToolIntent,
            lease_id: "lease-1".to_string(),
            request_id: "REQ-1".to_string(),
            issued_at_secs: now_secs(),
            expires_after_secs: CHANNEL_CONTEXT_TOKEN_DEFAULT_EXPIRES_AFTER_SECS,
            channel_source_witness: [0xCC; 32],
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified: true,
            taint_allow: true,
            classification_allow: true,
            declass_receipt_valid: true,
            declassification_intent: DeclassificationIntentScope::None,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: Some(valid_policy_binding()),
            leakage_budget_receipt: Some(valid_leakage_receipt()),
            timing_channel_budget: Some(valid_timing_budget()),
            disclosure_policy_binding: Some(valid_disclosure_policy_binding()),
            leakage_budget_policy_max_bits: Some(8),
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: Some(10),
            declared_timing_budget_ticks: None,
        };
        let payload_json = canonical_payload(&payload).expect("payload should serialize");
        let token_payload = ChannelContextTokenV1 {
            schema_id: CHANNEL_CONTEXT_TOKEN_SCHEMA_ID.to_string(),
            payload,
            signature: base64::engine::general_purpose::STANDARD
                .encode(signer.sign(&payload_json).to_bytes()),
        };
        let token = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&token_payload).expect("token payload should serialize"));

        let result = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            "REQ-1",
        );
        assert_eq!(
            result,
            Err(ChannelContextTokenError::WitnessVerificationFailed)
        );
    }

    #[test]
    fn test_forged_token_rejected() {
        let check = baseline_check();
        let daemon_signer = Signer::generate();
        let attacker_signer = Signer::generate();
        let forged_token =
            issue_channel_context_token(&check, "lease-1", "REQ-1", now_secs(), &attacker_signer)
                .expect("attacker token should encode");

        let result = decode_channel_context_token(
            &forged_token,
            &daemon_signer.verifying_key(),
            "lease-1",
            now_secs(),
            "REQ-1",
        );
        assert_eq!(
            result,
            Err(ChannelContextTokenError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn test_tampered_token_rejected() {
        let check = baseline_check();
        let signer = Signer::generate();
        let token = issue_channel_context_token(&check, "lease-1", "REQ-1", now_secs(), &signer)
            .expect("token should encode");

        let token_json = base64::engine::general_purpose::STANDARD
            .decode(token)
            .expect("token should be valid base64");
        let mut token_payload: ChannelContextTokenV1 =
            serde_json::from_slice(&token_json).expect("token payload should parse");
        token_payload.payload.policy_ledger_verified = false;

        let tampered_token = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&token_payload).expect("tampered token should serialize"));

        let result = decode_channel_context_token(
            &tampered_token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            "REQ-1",
        );
        assert_eq!(
            result,
            Err(ChannelContextTokenError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn test_token_with_wrong_lease_id_rejected() {
        let check = baseline_check();
        let signer = Signer::generate();
        let token = issue_channel_context_token(&check, "lease-a", "REQ-1", now_secs(), &signer)
            .expect("token should encode");

        let result = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-b",
            now_secs(),
            "REQ-1",
        );
        assert_eq!(
            result,
            Err(ChannelContextTokenError::LeaseMismatch {
                expected: "lease-b".to_string(),
                actual: "lease-a".to_string(),
            })
        );
    }

    #[test]
    fn test_token_with_matching_lease_id_accepted() {
        let check = baseline_check();
        let signer = Signer::generate();
        let token = issue_channel_context_token(&check, "lease-a", "REQ-1", now_secs(), &signer)
            .expect("token should encode");

        let decoded = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-a",
            now_secs(),
            "REQ-1",
        )
        .expect("matching lease must pass");
        assert_eq!(decoded, check);
    }

    #[test]
    fn test_expired_token_rejected() {
        let check = baseline_check();
        let signer = Signer::generate();
        let issued_at_secs = now_secs();
        let token = issue_channel_context_token_with_freshness(
            &check,
            "lease-1",
            "REQ-1",
            issued_at_secs,
            1,
            &signer,
        )
        .expect("token should encode");

        std::thread::sleep(Duration::from_secs(2));

        let result = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            "REQ-1",
        );
        assert!(
            matches!(result, Err(ChannelContextTokenError::ExpiredToken { .. })),
            "expired token must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_mismatched_request_id_rejected() {
        let check = baseline_check();
        let signer = Signer::generate();
        let token = issue_channel_context_token(&check, "lease-1", "REQ-A", now_secs(), &signer)
            .expect("token should encode");

        let result = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            "REQ-B",
        );
        assert_eq!(
            result,
            Err(ChannelContextTokenError::RequestIdMismatch {
                expected: "REQ-B".to_string(),
                actual: "REQ-A".to_string(),
            })
        );
    }

    #[test]
    fn test_replay_with_same_request_id_accepted() {
        let check = baseline_check();
        let signer = Signer::generate();
        let token =
            issue_channel_context_token(&check, "lease-1", "REQ-FRESH-1", now_secs(), &signer)
                .expect("token should encode");

        let first = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            "REQ-FRESH-1",
        )
        .expect("fresh token with matching request must decode");
        let second = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            "REQ-FRESH-1",
        )
        .expect("replayed token with same request must remain idempotent");
        assert_eq!(first, check);
        assert_eq!(second, check);
    }
}
