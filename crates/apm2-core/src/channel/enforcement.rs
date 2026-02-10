//! Markov-blanket channel enforcement for RFC-0020.
//!
//! Restricts authoritative actuation to typed tool-intent channel events
//! and emits structured defects for boundary violations.

use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::crypto::{Signature, Signer, VerifyingKey, parse_signature, verify_signature};

/// Maximum string length for channel enforcement detail fields.
pub const MAX_CHANNEL_DETAIL_LENGTH: usize = 512;
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
    expected_request_id: Option<&str>,
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
    if let Some(expected_request_id) = expected_request_id {
        if payload.payload.request_id != expected_request_id {
            return Err(ChannelContextTokenError::RequestIdMismatch {
                expected: expected_request_id.to_string(),
                actual: payload.payload.request_id,
            });
        }
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

    defects
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

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
        let check = ChannelBoundaryCheck {
            source: ChannelSource::FreeFormOutput,
            channel_source_witness: None,
            broker_verified: false,
            capability_verified: false,
            context_firewall_verified: false,
            policy_ledger_verified: false,
        };

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
            Some("REQ-1"),
        )
        .expect("token should decode");
        assert_eq!(decoded, check);
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
        };

        let bytes1 = canonical_payload(&payload).expect("payload should serialize");
        let bytes2 = canonical_payload(&payload).expect("payload should serialize");
        assert_eq!(
            bytes1, bytes2,
            "payload serialization must be deterministic"
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
            Some("REQ-1"),
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
            Some("REQ-1"),
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
            Some("REQ-1"),
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
            Some("REQ-1"),
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
            Some("REQ-1"),
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
            Some("REQ-1"),
        );
        assert!(
            matches!(result, Err(ChannelContextTokenError::ExpiredToken { .. })),
            "expired token must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_request_id_mismatch_rejected() {
        let check = baseline_check();
        let signer = Signer::generate();
        let token = issue_channel_context_token(&check, "lease-1", "REQ-A", now_secs(), &signer)
            .expect("token should encode");

        let result = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            Some("REQ-B"),
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
    fn test_valid_fresh_token_accepted() {
        let check = baseline_check();
        let signer = Signer::generate();
        let token =
            issue_channel_context_token(&check, "lease-1", "REQ-FRESH-1", now_secs(), &signer)
                .expect("token should encode");

        let decoded = decode_channel_context_token(
            &token,
            &signer.verifying_key(),
            "lease-1",
            now_secs(),
            Some("REQ-FRESH-1"),
        )
        .expect("fresh token with matching request must decode");
        assert_eq!(decoded, check);
    }
}
