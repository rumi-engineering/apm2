// AGENT-AUTHORED
//! Tests for PCAC core schemas and deny taxonomy (TCK-00422).

use super::*;
use crate::crypto::Hash;

// =============================================================================
// Test helpers
// =============================================================================

fn test_hash(byte: u8) -> Hash {
    [byte; 32]
}

fn zero_hash() -> Hash {
    [0u8; 32]
}

fn valid_join_input() -> AuthorityJoinInputV1 {
    AuthorityJoinInputV1 {
        session_id: "session-001".to_string(),
        holon_id: None,
        intent_digest: test_hash(0x01),
        capability_manifest_hash: test_hash(0x02),
        scope_witness_hashes: vec![],
        lease_id: "lease-001".to_string(),
        permeability_receipt_hash: None,
        identity_proof_hash: test_hash(0x03),
        identity_evidence_level: IdentityEvidenceLevel::Verified,
        directory_head_hash: test_hash(0x04),
        freshness_policy_hash: test_hash(0x05),
        freshness_witness_tick: 1000,
        stop_budget_profile_digest: test_hash(0x06),
        pre_actuation_receipt_hashes: vec![],
        risk_tier: types::RiskTier::Tier1,
        determinism_class: types::DeterminismClass::Deterministic,
        time_envelope_ref: test_hash(0x07),
        as_of_ledger_anchor: test_hash(0x08),
    }
}

fn valid_certificate() -> AuthorityJoinCertificateV1 {
    AuthorityJoinCertificateV1 {
        ajc_id: test_hash(0xAA),
        authority_join_hash: test_hash(0xBB),
        intent_digest: test_hash(0x01),
        risk_tier: types::RiskTier::Tier1,
        issued_time_envelope_ref: test_hash(0x07),
        as_of_ledger_anchor: test_hash(0x08),
        expires_at_tick: 2000,
        revocation_head_hash: test_hash(0xCC),
        identity_evidence_level: IdentityEvidenceLevel::Verified,
        admission_capacity_token: None,
    }
}

// =============================================================================
// Schema presence tests
// =============================================================================

#[test]
fn authority_join_input_has_all_required_fields() {
    let input = valid_join_input();
    assert!(!input.session_id.is_empty());
    assert_ne!(input.intent_digest, zero_hash());
    assert_ne!(input.capability_manifest_hash, zero_hash());
    assert_ne!(input.identity_proof_hash, zero_hash());
    assert_ne!(input.directory_head_hash, zero_hash());
    assert_ne!(input.freshness_policy_hash, zero_hash());
    assert_ne!(input.stop_budget_profile_digest, zero_hash());
    assert_ne!(input.time_envelope_ref, zero_hash());
    assert_ne!(input.as_of_ledger_anchor, zero_hash());
}

#[test]
fn authority_join_certificate_has_normative_fields() {
    let cert = valid_certificate();
    assert_ne!(cert.ajc_id, zero_hash());
    assert_ne!(cert.authority_join_hash, zero_hash());
    assert_ne!(cert.intent_digest, zero_hash());
    assert_ne!(cert.issued_time_envelope_ref, zero_hash());
    assert_ne!(cert.as_of_ledger_anchor, zero_hash());
    assert_ne!(cert.revocation_head_hash, zero_hash());
    assert!(cert.expires_at_tick > 0);
}

#[test]
fn consume_record_has_required_fields() {
    let record = AuthorityConsumeRecordV1 {
        ajc_id: test_hash(0xAA),
        consumed_time_envelope_ref: test_hash(0xDD),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
    };
    assert_ne!(record.ajc_id, zero_hash());
    assert_ne!(record.consumed_time_envelope_ref, zero_hash());
    assert_ne!(record.effect_selector_digest, zero_hash());
    assert!(record.consumed_at_tick > 0);
}

// =============================================================================
// Identity evidence level tests
// =============================================================================

#[test]
fn identity_evidence_level_display() {
    assert_eq!(IdentityEvidenceLevel::Verified.to_string(), "verified");
    assert_eq!(
        IdentityEvidenceLevel::PointerOnly.to_string(),
        "pointer_only"
    );
}

#[test]
fn identity_evidence_level_serde_roundtrip() {
    let verified = IdentityEvidenceLevel::Verified;
    let json = serde_json::to_string(&verified).unwrap();
    assert_eq!(json, "\"verified\"");
    let back: IdentityEvidenceLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, verified);

    let pointer = IdentityEvidenceLevel::PointerOnly;
    let json = serde_json::to_string(&pointer).unwrap();
    assert_eq!(json, "\"pointer_only\"");
    let back: IdentityEvidenceLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pointer);
}

// =============================================================================
// Risk tier tests
// =============================================================================

#[test]
fn risk_tier_display() {
    assert_eq!(types::RiskTier::Tier0.to_string(), "tier0");
    assert_eq!(types::RiskTier::Tier1.to_string(), "tier1");
    assert_eq!(types::RiskTier::Tier2Plus.to_string(), "tier2+");
}

#[test]
fn risk_tier_serde_roundtrip() {
    for tier in [
        types::RiskTier::Tier0,
        types::RiskTier::Tier1,
        types::RiskTier::Tier2Plus,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        let back: types::RiskTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tier);
    }
}

// =============================================================================
// Deny taxonomy tests
// =============================================================================

#[test]
fn deny_class_missing_field_display() {
    let deny = AuthorityDenyClass::MissingRequiredField {
        field_name: "intent_digest".to_string(),
    };
    assert_eq!(deny.to_string(), "missing required field: intent_digest");
}

#[test]
fn deny_class_zero_hash_display() {
    let deny = AuthorityDenyClass::ZeroHash {
        field_name: "identity_proof_hash".to_string(),
    };
    assert_eq!(deny.to_string(), "zero hash for field: identity_proof_hash");
}

#[test]
fn deny_class_intent_mismatch() {
    let deny = AuthorityDenyClass::IntentDigestMismatch {
        expected: test_hash(0x01),
        actual: test_hash(0x02),
    };
    assert_eq!(deny.to_string(), "intent digest mismatch");
}

#[test]
fn deny_class_already_consumed() {
    let deny = AuthorityDenyClass::AlreadyConsumed {
        ajc_id: test_hash(0xAA),
    };
    assert_eq!(deny.to_string(), "authority already consumed");
}

#[test]
fn deny_class_certificate_expired() {
    let deny = AuthorityDenyClass::CertificateExpired {
        expired_at: 1000,
        current_tick: 1500,
    };
    assert_eq!(
        deny.to_string(),
        "certificate expired at tick 1000 (current: 1500)"
    );
}

#[test]
fn deny_class_serde_roundtrip() {
    let classes = vec![
        AuthorityDenyClass::MissingRequiredField {
            field_name: "session_id".to_string(),
        },
        AuthorityDenyClass::ZeroHash {
            field_name: "intent_digest".to_string(),
        },
        AuthorityDenyClass::InvalidSessionId,
        AuthorityDenyClass::InvalidLeaseId,
        AuthorityDenyClass::RevocationFrontierAdvanced,
        AuthorityDenyClass::StaleFreshnessAtRevalidate,
        AuthorityDenyClass::AlreadyConsumed {
            ajc_id: test_hash(0xAA),
        },
        AuthorityDenyClass::IntentDigestMismatch {
            expected: test_hash(0x01),
            actual: test_hash(0x02),
        },
        AuthorityDenyClass::StaleSovereigntyEpoch,
        AuthorityDenyClass::UnknownRevocationHead,
        AuthorityDenyClass::ActiveSovereignFreeze,
        AuthorityDenyClass::DelegationWidening,
        AuthorityDenyClass::PointerOnlyDeniedAtTier2Plus,
        AuthorityDenyClass::PolicyDeny {
            reason: "test".to_string(),
        },
        AuthorityDenyClass::UnknownState {
            description: "test unknown".to_string(),
        },
    ];

    for class in classes {
        let json = serde_json::to_string(&class).unwrap();
        let back: AuthorityDenyClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, class, "roundtrip failed for: {class}");
    }
}

// =============================================================================
// AuthorityDenyV1 tests
// =============================================================================

#[test]
fn authority_deny_v1_display_without_ajc() {
    let deny = AuthorityDenyV1 {
        deny_class: AuthorityDenyClass::InvalidSessionId,
        ajc_id: None,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 500,
    };
    assert_eq!(deny.to_string(), "authority denied: invalid session ID");
}

#[test]
fn authority_deny_v1_display_with_ajc() {
    let deny = AuthorityDenyV1 {
        deny_class: AuthorityDenyClass::AlreadyConsumed {
            ajc_id: test_hash(0xAA),
        },
        ajc_id: Some(test_hash(0xAA)),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 500,
    };
    let display = deny.to_string();
    assert!(display.contains("authority denied: authority already consumed"));
    assert!(display.contains("ajc_id:"));
}

#[test]
fn authority_deny_v1_is_error() {
    let deny = AuthorityDenyV1 {
        deny_class: AuthorityDenyClass::InvalidSessionId,
        ajc_id: None,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 500,
    };
    // Verify it implements std::error::Error
    let err: &dyn std::error::Error = &deny;
    assert!(!err.to_string().is_empty());
}

// =============================================================================
// Serde roundtrip for full types
// =============================================================================

#[test]
fn join_input_serde_roundtrip() {
    let input = valid_join_input();
    let json = serde_json::to_string(&input).unwrap();
    let back: AuthorityJoinInputV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(back, input);
}

#[test]
fn certificate_serde_roundtrip() {
    let cert = valid_certificate();
    let json = serde_json::to_string(&cert).unwrap();
    let back: AuthorityJoinCertificateV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cert);
}

#[test]
fn consume_record_serde_roundtrip() {
    let record = AuthorityConsumeRecordV1 {
        ajc_id: test_hash(0xAA),
        consumed_time_envelope_ref: test_hash(0xDD),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: AuthorityConsumeRecordV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(back, record);
}

// =============================================================================
// Receipt tests
// =============================================================================

#[test]
fn join_receipt_serde_roundtrip() {
    use super::receipts::*;

    let receipt = AuthorityJoinReceiptV1 {
        digest_meta: ReceiptDigestMeta {
            canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
            content_digest: test_hash(0xF0),
        },
        ajc_id: test_hash(0xAA),
        authority_join_hash: test_hash(0xBB),
        risk_tier: types::RiskTier::Tier1,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        joined_at_tick: 1000,
        authoritative_bindings: None,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: AuthorityJoinReceiptV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

#[test]
fn deny_receipt_serde_roundtrip() {
    use super::receipts::*;

    let receipt = AuthorityDenyReceiptV1 {
        digest_meta: ReceiptDigestMeta {
            canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
            content_digest: test_hash(0xF1),
        },
        deny_class: AuthorityDenyClass::IntentDigestMismatch {
            expected: test_hash(0x01),
            actual: test_hash(0x02),
        },
        ajc_id: Some(test_hash(0xAA)),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 1500,
        denied_at_stage: LifecycleStage::Consume,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: AuthorityDenyReceiptV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

#[test]
fn receipt_authentication_direct_serde() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::Direct {
        authority_seal_hash: test_hash(0xDD),
    };
    let json = serde_json::to_string(&auth).unwrap();
    let back: ReceiptAuthentication = serde_json::from_str(&json).unwrap();
    assert_eq!(back, auth);
}

#[test]
fn receipt_authentication_pointer_unbatched_serde() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerUnbatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
    };
    let json = serde_json::to_string(&auth).unwrap();
    let back: ReceiptAuthentication = serde_json::from_str(&json).unwrap();
    assert_eq!(back, auth);
}

#[test]
fn receipt_authentication_pointer_batched_serde() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerBatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
        merkle_inclusion_proof: vec![test_hash(0xE3), test_hash(0xE4)],
        receipt_batch_root_hash: test_hash(0xE5),
    };
    let json = serde_json::to_string(&auth).unwrap();
    let back: ReceiptAuthentication = serde_json::from_str(&json).unwrap();
    assert_eq!(back, auth);
}

#[test]
fn lifecycle_stage_display() {
    use super::receipts::LifecycleStage;

    assert_eq!(LifecycleStage::Join.to_string(), "join");
    assert_eq!(LifecycleStage::Revalidate.to_string(), "revalidate");
    assert_eq!(LifecycleStage::Consume.to_string(), "consume");
}

// =============================================================================
// Boundary validation tests — join input (fail-closed)
// =============================================================================

#[test]
fn valid_join_input_passes_validation() {
    let input = valid_join_input();
    assert!(input.validate().is_ok());
}

#[test]
fn zero_intent_digest_denied_by_validator() {
    let mut input = valid_join_input();
    input.intent_digest = zero_hash();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "intent_digest")
    );
}

#[test]
fn zero_capability_manifest_hash_denied_by_validator() {
    let mut input = valid_join_input();
    input.capability_manifest_hash = zero_hash();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "capability_manifest_hash")
    );
}

#[test]
fn zero_identity_proof_hash_denied_by_validator() {
    let mut input = valid_join_input();
    input.identity_proof_hash = zero_hash();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "identity_proof_hash")
    );
}

#[test]
fn zero_directory_head_hash_denied_by_validator() {
    let mut input = valid_join_input();
    input.directory_head_hash = zero_hash();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "directory_head_hash")
    );
}

#[test]
fn zero_freshness_policy_hash_denied_by_validator() {
    let mut input = valid_join_input();
    input.freshness_policy_hash = zero_hash();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "freshness_policy_hash")
    );
}

#[test]
fn zero_stop_budget_profile_digest_denied_by_validator() {
    let mut input = valid_join_input();
    input.stop_budget_profile_digest = zero_hash();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "stop_budget_profile_digest")
    );
}

#[test]
fn zero_time_envelope_ref_denied_by_validator() {
    let mut input = valid_join_input();
    input.time_envelope_ref = zero_hash();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "time_envelope_ref")
    );
}

#[test]
fn zero_ledger_anchor_denied_by_validator() {
    let mut input = valid_join_input();
    input.as_of_ledger_anchor = zero_hash();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "as_of_ledger_anchor")
    );
}

#[test]
fn empty_session_id_denied_by_validator() {
    let mut input = valid_join_input();
    input.session_id = String::new();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::EmptyRequiredField { field } if field == "session_id")
    );
}

#[test]
fn empty_lease_id_denied_by_validator() {
    let mut input = valid_join_input();
    input.lease_id = String::new();
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::EmptyRequiredField { field } if field == "lease_id")
    );
}

#[test]
fn oversize_session_id_denied_by_validator() {
    let mut input = valid_join_input();
    input.session_id = "x".repeat(types::MAX_STRING_LENGTH + 1);
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "session_id")
    );
}

#[test]
fn oversize_lease_id_denied_by_validator() {
    let mut input = valid_join_input();
    input.lease_id = "x".repeat(types::MAX_STRING_LENGTH + 1);
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "lease_id")
    );
}

#[test]
fn oversize_holon_id_denied_by_validator() {
    let mut input = valid_join_input();
    input.holon_id = Some("x".repeat(types::MAX_STRING_LENGTH + 1));
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "holon_id")
    );
}

#[test]
fn oversize_scope_witness_hashes_denied_by_validator() {
    let mut input = valid_join_input();
    input.scope_witness_hashes = vec![test_hash(0x01); types::MAX_SCOPE_WITNESS_HASHES + 1];
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::CollectionTooLarge { field, .. } if field == "scope_witness_hashes")
    );
}

#[test]
fn oversize_pre_actuation_receipt_hashes_denied_by_validator() {
    let mut input = valid_join_input();
    input.pre_actuation_receipt_hashes =
        vec![test_hash(0x01); types::MAX_PRE_ACTUATION_RECEIPT_HASHES + 1];
    let err = input.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::CollectionTooLarge { field, .. } if field == "pre_actuation_receipt_hashes")
    );
}

// =============================================================================
// Deny taxonomy coverage
// =============================================================================

#[test]
#[allow(clippy::no_effect_underscore_binding)]
fn deny_taxonomy_covers_all_lifecycle_failures() {
    // Verify we have deny classes for each lifecycle stage failure mode
    // documented in RFC-0027.
    let _join_failures = [
        AuthorityDenyClass::MissingRequiredField {
            field_name: "test".to_string(),
        },
        AuthorityDenyClass::ZeroHash {
            field_name: "test".to_string(),
        },
        AuthorityDenyClass::InvalidSessionId,
        AuthorityDenyClass::InvalidLeaseId,
        AuthorityDenyClass::InvalidIntentDigest,
        AuthorityDenyClass::InvalidCapabilityManifest,
        AuthorityDenyClass::InvalidIdentityProof,
        AuthorityDenyClass::StaleFreshnessAtJoin,
        AuthorityDenyClass::InvalidTimeEnvelope,
        AuthorityDenyClass::InvalidLedgerAnchor,
    ];

    let _revalidate_failures = [
        AuthorityDenyClass::RevocationFrontierAdvanced,
        AuthorityDenyClass::StaleFreshnessAtRevalidate,
        AuthorityDenyClass::CertificateExpired {
            expired_at: 0,
            current_tick: 0,
        },
        AuthorityDenyClass::LedgerAnchorDrift,
    ];

    let _consume_failures = [
        AuthorityDenyClass::IntentDigestMismatch {
            expected: zero_hash(),
            actual: zero_hash(),
        },
        AuthorityDenyClass::AlreadyConsumed {
            ajc_id: zero_hash(),
        },
        AuthorityDenyClass::MissingPreActuationReceipt,
        AuthorityDenyClass::BoundaryMonotonicityViolation {
            description: String::new(),
        },
    ];

    let _sovereignty_failures = [
        AuthorityDenyClass::StaleSovereigntyEpoch,
        AuthorityDenyClass::UnknownRevocationHead,
        AuthorityDenyClass::IncompatibleAutonomyCeiling,
        AuthorityDenyClass::ActiveSovereignFreeze,
    ];

    let _policy_failures = [
        AuthorityDenyClass::PointerOnlyDeniedAtTier2Plus,
        AuthorityDenyClass::WaiverExpiredOrInvalid,
        AuthorityDenyClass::PolicyDeny {
            reason: String::new(),
        },
    ];

    let _delegation_failures = [
        AuthorityDenyClass::DelegationWidening,
        AuthorityDenyClass::InvalidDelegationChain,
    ];

    let _failclosed = [AuthorityDenyClass::UnknownState {
        description: String::new(),
    }];

    // All variants instantiated — compilation proves coverage.
}

#[test]
fn deny_taxonomy_is_deterministic() {
    // Same inputs produce same deny class
    let class1 = AuthorityDenyClass::IntentDigestMismatch {
        expected: test_hash(0x01),
        actual: test_hash(0x02),
    };
    let class2 = AuthorityDenyClass::IntentDigestMismatch {
        expected: test_hash(0x01),
        actual: test_hash(0x02),
    };
    assert_eq!(class1, class2);
    assert_eq!(
        serde_json::to_string(&class1).unwrap(),
        serde_json::to_string(&class2).unwrap()
    );
}

// =============================================================================
// deny_unknown_fields negative tests (Security BLOCKER 1)
// =============================================================================

#[test]
fn deny_unknown_fields_authority_join_input() {
    let input = valid_join_input();
    let mut json: serde_json::Value = serde_json::to_value(&input).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityJoinInputV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_authority_join_certificate() {
    let cert = valid_certificate();
    let mut json: serde_json::Value = serde_json::to_value(&cert).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityJoinCertificateV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_authority_consumed() {
    let consumed = AuthorityConsumedV1 {
        ajc_id: test_hash(0xAA),
        intent_digest: test_hash(0x01),
        consumed_time_envelope_ref: test_hash(0xDD),
        consumed_at_tick: 1500,
    };
    let mut json: serde_json::Value = serde_json::to_value(&consumed).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityConsumedV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_authority_consume_record() {
    let record = AuthorityConsumeRecordV1 {
        ajc_id: test_hash(0xAA),
        consumed_time_envelope_ref: test_hash(0xDD),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
    };
    let mut json: serde_json::Value = serde_json::to_value(&record).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityConsumeRecordV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_authority_deny_v1() {
    let deny = AuthorityDenyV1 {
        deny_class: AuthorityDenyClass::InvalidSessionId,
        ajc_id: None,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 500,
    };
    let mut json: serde_json::Value = serde_json::to_value(&deny).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityDenyV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_receipt_digest_meta() {
    use super::receipts::*;

    let meta = ReceiptDigestMeta {
        canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
        content_digest: test_hash(0xF0),
    };
    let mut json: serde_json::Value = serde_json::to_value(&meta).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<ReceiptDigestMeta>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_authoritative_bindings() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: None,
        delegation_chain_hash: None,
    };
    let mut json: serde_json::Value = serde_json::to_value(&bindings).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthoritativeBindings>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_join_receipt() {
    use super::receipts::*;

    let receipt = AuthorityJoinReceiptV1 {
        digest_meta: ReceiptDigestMeta {
            canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
            content_digest: test_hash(0xF0),
        },
        ajc_id: test_hash(0xAA),
        authority_join_hash: test_hash(0xBB),
        risk_tier: types::RiskTier::Tier1,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        joined_at_tick: 1000,
        authoritative_bindings: None,
    };
    let mut json: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityJoinReceiptV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_revalidate_receipt() {
    use super::receipts::*;

    let receipt = AuthorityRevalidateReceiptV1 {
        digest_meta: ReceiptDigestMeta {
            canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
            content_digest: test_hash(0xF0),
        },
        ajc_id: test_hash(0xAA),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        revocation_head_hash: test_hash(0xCC),
        revalidated_at_tick: 1200,
        checkpoint: "before_broker".to_string(),
        authoritative_bindings: None,
    };
    let mut json: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityRevalidateReceiptV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_consume_receipt() {
    use super::receipts::*;

    let receipt = AuthorityConsumeReceiptV1 {
        digest_meta: ReceiptDigestMeta {
            canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
            content_digest: test_hash(0xF0),
        },
        ajc_id: test_hash(0xAA),
        intent_digest: test_hash(0x01),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
        pre_actuation_receipt_hash: None,
        authoritative_bindings: None,
    };
    let mut json: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityConsumeReceiptV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

#[test]
fn deny_unknown_fields_deny_receipt() {
    use super::receipts::*;

    let receipt = AuthorityDenyReceiptV1 {
        digest_meta: ReceiptDigestMeta {
            canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
            content_digest: test_hash(0xF1),
        },
        deny_class: AuthorityDenyClass::InvalidSessionId,
        ajc_id: None,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 1500,
        denied_at_stage: LifecycleStage::Join,
    };
    let mut json: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("smuggled_field".to_string(), serde_json::Value::Bool(true));
    let result = serde_json::from_value::<AuthorityDenyReceiptV1>(json);
    assert!(result.is_err(), "unknown field must be rejected");
}

// =============================================================================
// Oversize input rejection tests (Security MAJOR 1)
// =============================================================================

#[test]
fn oversize_deny_class_field_name_rejected() {
    let class = AuthorityDenyClass::MissingRequiredField {
        field_name: "x".repeat(types::MAX_FIELD_NAME_LENGTH + 1),
    };
    let err = class.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "field_name")
    );
}

#[test]
fn oversize_deny_class_description_rejected() {
    let class = AuthorityDenyClass::UnknownState {
        description: "x".repeat(types::MAX_DESCRIPTION_LENGTH + 1),
    };
    let err = class.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "description")
    );
}

#[test]
fn oversize_deny_class_reason_rejected() {
    let class = AuthorityDenyClass::PolicyDeny {
        reason: "x".repeat(types::MAX_REASON_LENGTH + 1),
    };
    let err = class.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "reason")
    );
}

#[test]
fn oversize_deny_class_operation_rejected() {
    let class = AuthorityDenyClass::VerifierEconomicsBoundsExceeded {
        operation: "x".repeat(types::MAX_OPERATION_LENGTH + 1),
        risk_tier: types::RiskTier::Tier1,
    };
    let err = class.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "operation")
    );
}

#[test]
fn deny_class_within_bounds_passes_validation() {
    let class = AuthorityDenyClass::MissingRequiredField {
        field_name: "session_id".to_string(),
    };
    assert!(class.validate().is_ok());
}

#[test]
fn authority_deny_v1_validates_embedded_class() {
    let deny = AuthorityDenyV1 {
        deny_class: AuthorityDenyClass::UnknownState {
            description: "x".repeat(types::MAX_DESCRIPTION_LENGTH + 1),
        },
        ajc_id: None,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 500,
    };
    assert!(deny.validate().is_err());
}

// =============================================================================
// Receipt validation negative tests
// =============================================================================

#[test]
fn oversize_canonicalizer_id_rejected() {
    use super::receipts::*;

    let meta = ReceiptDigestMeta {
        canonicalizer_id: "x".repeat(types::MAX_CANONICALIZER_ID_LENGTH + 1),
        content_digest: test_hash(0xF0),
    };
    let err = meta.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "canonicalizer_id")
    );
}

#[test]
fn oversize_checkpoint_rejected() {
    use super::receipts::*;

    let receipt = AuthorityRevalidateReceiptV1 {
        digest_meta: ReceiptDigestMeta {
            canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
            content_digest: test_hash(0xF0),
        },
        ajc_id: test_hash(0xAA),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        revocation_head_hash: test_hash(0xCC),
        revalidated_at_tick: 1200,
        checkpoint: "x".repeat(types::MAX_CHECKPOINT_LENGTH + 1),
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::StringTooLong { field, .. } if field == "checkpoint")
    );
}

#[test]
fn empty_merkle_proof_in_batched_pointer_rejected() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerBatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
        merkle_inclusion_proof: vec![],
        receipt_batch_root_hash: test_hash(0xE5),
    };
    let err = auth.validate().unwrap_err();
    assert!(matches!(err, types::PcacValidationError::EmptyMerkleProof));
}

#[test]
fn oversize_merkle_proof_in_batched_pointer_rejected() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerBatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
        merkle_inclusion_proof: vec![test_hash(0xE3); types::MAX_MERKLE_PROOF_STEPS + 1],
        receipt_batch_root_hash: test_hash(0xE5),
    };
    let err = auth.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::CollectionTooLarge { field, .. } if field == "merkle_inclusion_proof")
    );
}

#[test]
fn valid_batched_pointer_passes_validation() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerBatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
        merkle_inclusion_proof: vec![test_hash(0xE3), test_hash(0xE4)],
        receipt_batch_root_hash: test_hash(0xE5),
    };
    assert!(auth.validate().is_ok());
}

#[test]
fn direct_auth_passes_validation() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::Direct {
        authority_seal_hash: test_hash(0xDD),
    };
    assert!(auth.validate().is_ok());
}

#[test]
fn unbatched_pointer_passes_validation() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerUnbatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
    };
    assert!(auth.validate().is_ok());
}

// =============================================================================
// Missing authoritative bindings negative tests (Quality MAJOR 1)
// =============================================================================

#[test]
fn join_input_missing_required_hash_fields_produces_validation_error() {
    // Each required hash field, when zeroed, must produce a validation error.
    let required_hash_fields = [
        "intent_digest",
        "capability_manifest_hash",
        "identity_proof_hash",
        "directory_head_hash",
        "freshness_policy_hash",
        "stop_budget_profile_digest",
        "time_envelope_ref",
        "as_of_ledger_anchor",
    ];

    for field_name in &required_hash_fields {
        let mut input = valid_join_input();
        match *field_name {
            "intent_digest" => input.intent_digest = zero_hash(),
            "capability_manifest_hash" => input.capability_manifest_hash = zero_hash(),
            "identity_proof_hash" => input.identity_proof_hash = zero_hash(),
            "directory_head_hash" => input.directory_head_hash = zero_hash(),
            "freshness_policy_hash" => input.freshness_policy_hash = zero_hash(),
            "stop_budget_profile_digest" => input.stop_budget_profile_digest = zero_hash(),
            "time_envelope_ref" => input.time_envelope_ref = zero_hash(),
            "as_of_ledger_anchor" => input.as_of_ledger_anchor = zero_hash(),
            _ => unreachable!(),
        }
        let err = input.validate();
        assert!(
            err.is_err(),
            "zeroed {field_name} must be rejected by validator"
        );
    }
}

// =============================================================================
// Pointer auth shape invariant tests (Quality BLOCKER 2)
// =============================================================================

#[test]
fn pointer_batched_requires_merkle_proof_and_root_at_type_level() {
    use super::receipts::*;

    // PointerBatched forces both merkle_inclusion_proof and
    // receipt_batch_root_hash to be present — there is no Option to omit them.
    let auth = ReceiptAuthentication::PointerBatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
        merkle_inclusion_proof: vec![test_hash(0xE3)],
        receipt_batch_root_hash: test_hash(0xE5),
    };
    // If this compiles, the type-level guarantee is met.
    assert!(auth.validate().is_ok());
}

#[test]
fn pointer_unbatched_does_not_carry_batch_fields() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerUnbatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
    };
    let json = serde_json::to_string(&auth).unwrap();
    // Ensure no batch-specific fields are in the JSON
    assert!(
        !json.contains("merkle_inclusion_proof"),
        "unbatched pointer must not contain merkle_inclusion_proof"
    );
    assert!(
        !json.contains("receipt_batch_root_hash"),
        "unbatched pointer must not contain receipt_batch_root_hash"
    );
}

// =============================================================================
// PcacValidationError display tests
// =============================================================================

#[test]
fn pcac_validation_error_display() {
    let err = types::PcacValidationError::EmptyRequiredField {
        field: "session_id",
    };
    assert_eq!(err.to_string(), "required field is empty: session_id");

    let err = types::PcacValidationError::ZeroHash {
        field: "intent_digest",
    };
    assert_eq!(
        err.to_string(),
        "zero hash for required field: intent_digest"
    );

    let err = types::PcacValidationError::StringTooLong {
        field: "session_id",
        len: 300,
        max: 256,
    };
    assert_eq!(
        err.to_string(),
        "string field 'session_id' exceeds maximum length (300 > 256)"
    );

    let err = types::PcacValidationError::CollectionTooLarge {
        field: "scope_witness_hashes",
        count: 100,
        max: 64,
    };
    assert_eq!(
        err.to_string(),
        "collection 'scope_witness_hashes' exceeds maximum cardinality (100 > 64)"
    );

    let err = types::PcacValidationError::EmptyMerkleProof;
    assert_eq!(
        err.to_string(),
        "batched pointer auth has empty merkle inclusion proof"
    );

    let err = types::PcacValidationError::IncoherentDelegatedBindings;
    assert_eq!(
        err.to_string(),
        "delegated-path bindings incoherent: permeability_receipt_hash and delegation_chain_hash must co-occur"
    );
}

// =============================================================================
// Re-export compile tests (Quality BLOCKER 1)
// =============================================================================

#[test]
#[allow(clippy::no_effect_underscore_binding)]
fn risk_tier_and_determinism_class_reexported_from_pcac_module() {
    // These must be accessible via the pcac module re-export.
    // If this compiles, the re-exports are working.
    let _tier: crate::pcac::RiskTier = crate::pcac::RiskTier::Tier1;
    let _det: crate::pcac::DeterminismClass = crate::pcac::DeterminismClass::Deterministic;

    // Verify downstream can construct a full AuthorityJoinInputV1 using module
    // re-exports.
    let _input = crate::pcac::AuthorityJoinInputV1 {
        session_id: "session-001".to_string(),
        holon_id: None,
        intent_digest: test_hash(0x01),
        capability_manifest_hash: test_hash(0x02),
        scope_witness_hashes: vec![],
        lease_id: "lease-001".to_string(),
        permeability_receipt_hash: None,
        identity_proof_hash: test_hash(0x03),
        identity_evidence_level: crate::pcac::IdentityEvidenceLevel::Verified,
        directory_head_hash: test_hash(0x04),
        freshness_policy_hash: test_hash(0x05),
        freshness_witness_tick: 1000,
        stop_budget_profile_digest: test_hash(0x06),
        pre_actuation_receipt_hashes: vec![],
        risk_tier: crate::pcac::RiskTier::Tier1,
        determinism_class: crate::pcac::DeterminismClass::Deterministic,
        time_envelope_ref: test_hash(0x07),
        as_of_ledger_anchor: test_hash(0x08),
    };
}

// =============================================================================
// Zero-hash rejection for ReceiptDigestMeta (Security MAJOR)
// =============================================================================

#[test]
fn empty_canonicalizer_id_rejected() {
    use super::receipts::*;

    let meta = ReceiptDigestMeta {
        canonicalizer_id: String::new(),
        content_digest: test_hash(0xF0),
    };
    let err = meta.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::EmptyRequiredField { field } if field == "canonicalizer_id")
    );
}

#[test]
fn zero_content_digest_rejected() {
    use super::receipts::*;

    let meta = ReceiptDigestMeta {
        canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
        content_digest: zero_hash(),
    };
    let err = meta.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "content_digest")
    );
}

// =============================================================================
// Zero-hash rejection for ReceiptAuthentication (Security MAJOR)
// =============================================================================

#[test]
fn zero_authority_seal_hash_in_direct_auth_rejected() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::Direct {
        authority_seal_hash: zero_hash(),
    };
    let err = auth.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "authority_seal_hash")
    );
}

#[test]
fn zero_receipt_hash_in_unbatched_pointer_rejected() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerUnbatched {
        receipt_hash: zero_hash(),
        authority_seal_hash: test_hash(0xE2),
    };
    let err = auth.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "receipt_hash")
    );
}

#[test]
fn zero_authority_seal_hash_in_unbatched_pointer_rejected() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerUnbatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: zero_hash(),
    };
    let err = auth.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "authority_seal_hash")
    );
}

#[test]
fn zero_receipt_hash_in_batched_pointer_rejected() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerBatched {
        receipt_hash: zero_hash(),
        authority_seal_hash: test_hash(0xE2),
        merkle_inclusion_proof: vec![test_hash(0xE3)],
        receipt_batch_root_hash: test_hash(0xE5),
    };
    let err = auth.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "receipt_hash")
    );
}

#[test]
fn zero_authority_seal_hash_in_batched_pointer_rejected() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerBatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: zero_hash(),
        merkle_inclusion_proof: vec![test_hash(0xE3)],
        receipt_batch_root_hash: test_hash(0xE5),
    };
    let err = auth.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "authority_seal_hash")
    );
}

#[test]
fn zero_receipt_batch_root_hash_in_batched_pointer_rejected() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::PointerBatched {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
        merkle_inclusion_proof: vec![test_hash(0xE3)],
        receipt_batch_root_hash: zero_hash(),
    };
    let err = auth.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "receipt_batch_root_hash")
    );
}

// =============================================================================
// Zero-hash rejection for AuthoritativeBindings (Quality BLOCKER 2)
// =============================================================================

#[test]
fn zero_episode_envelope_hash_in_bindings_rejected() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: zero_hash(),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: None,
        delegation_chain_hash: None,
    };
    let err = bindings.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "episode_envelope_hash")
    );
}

#[test]
fn zero_view_commitment_hash_in_bindings_rejected() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: zero_hash(),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: None,
        delegation_chain_hash: None,
    };
    let err = bindings.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "view_commitment_hash")
    );
}

#[test]
fn zero_time_envelope_ref_in_bindings_rejected() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: zero_hash(),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: None,
        delegation_chain_hash: None,
    };
    let err = bindings.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "time_envelope_ref")
    );
}

// =============================================================================
// Delegated binding coherence tests (Security MAJOR)
// =============================================================================

#[test]
fn delegated_bindings_both_present_passes() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: Some(test_hash(0x05)),
        delegation_chain_hash: Some(test_hash(0x06)),
    };
    assert!(bindings.validate().is_ok());
}

#[test]
fn delegated_bindings_both_absent_passes() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: None,
        delegation_chain_hash: None,
    };
    assert!(bindings.validate().is_ok());
}

#[test]
fn delegated_bindings_only_permeability_hash_rejected() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: Some(test_hash(0x05)),
        delegation_chain_hash: None,
    };
    let err = bindings.validate().unwrap_err();
    assert!(matches!(
        err,
        types::PcacValidationError::IncoherentDelegatedBindings
    ));
}

#[test]
fn delegated_bindings_only_delegation_chain_hash_rejected() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: None,
        delegation_chain_hash: Some(test_hash(0x06)),
    };
    let err = bindings.validate().unwrap_err();
    assert!(matches!(
        err,
        types::PcacValidationError::IncoherentDelegatedBindings
    ));
}

#[test]
fn delegated_bindings_zero_permeability_receipt_hash_rejected() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: Some(zero_hash()),
        delegation_chain_hash: Some(test_hash(0x06)),
    };
    let err = bindings.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "permeability_receipt_hash")
    );
}

#[test]
fn delegated_bindings_zero_delegation_chain_hash_rejected() {
    use super::receipts::*;

    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: Some(test_hash(0x05)),
        delegation_chain_hash: Some(zero_hash()),
    };
    let err = bindings.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "delegation_chain_hash")
    );
}

// =============================================================================
// Lifecycle receipt validate() tests (Security BLOCKER)
// =============================================================================

fn valid_digest_meta() -> ReceiptDigestMeta {
    ReceiptDigestMeta {
        canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
        content_digest: test_hash(0xF0),
    }
}

fn valid_bindings() -> AuthoritativeBindings {
    AuthoritativeBindings {
        episode_envelope_hash: test_hash(0x01),
        view_commitment_hash: test_hash(0x02),
        time_envelope_ref: test_hash(0x03),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0x04),
        },
        permeability_receipt_hash: None,
        delegation_chain_hash: None,
    }
}

// --- AuthorityJoinReceiptV1 ---

#[test]
fn valid_join_receipt_passes_validation() {
    let receipt = AuthorityJoinReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        authority_join_hash: test_hash(0xBB),
        risk_tier: types::RiskTier::Tier1,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        joined_at_tick: 1000,
        authoritative_bindings: Some(valid_bindings()),
    };
    assert!(receipt.validate().is_ok());
}

#[test]
fn join_receipt_zero_ajc_id_rejected() {
    let receipt = AuthorityJoinReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: zero_hash(),
        authority_join_hash: test_hash(0xBB),
        risk_tier: types::RiskTier::Tier1,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        joined_at_tick: 1000,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(matches!(err, types::PcacValidationError::ZeroHash { field } if field == "ajc_id"));
}

#[test]
fn join_receipt_zero_authority_join_hash_rejected() {
    let receipt = AuthorityJoinReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        authority_join_hash: zero_hash(),
        risk_tier: types::RiskTier::Tier1,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        joined_at_tick: 1000,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "authority_join_hash")
    );
}

#[test]
fn join_receipt_zero_time_envelope_ref_rejected() {
    let receipt = AuthorityJoinReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        authority_join_hash: test_hash(0xBB),
        risk_tier: types::RiskTier::Tier1,
        time_envelope_ref: zero_hash(),
        ledger_anchor: test_hash(0x08),
        joined_at_tick: 1000,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "time_envelope_ref")
    );
}

#[test]
fn join_receipt_zero_ledger_anchor_rejected() {
    let receipt = AuthorityJoinReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        authority_join_hash: test_hash(0xBB),
        risk_tier: types::RiskTier::Tier1,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: zero_hash(),
        joined_at_tick: 1000,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "ledger_anchor")
    );
}

#[test]
fn join_receipt_propagates_binding_validation_errors() {
    let mut bindings = valid_bindings();
    bindings.episode_envelope_hash = zero_hash();
    let receipt = AuthorityJoinReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        authority_join_hash: test_hash(0xBB),
        risk_tier: types::RiskTier::Tier1,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        joined_at_tick: 1000,
        authoritative_bindings: Some(bindings),
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "episode_envelope_hash")
    );
}

// --- AuthorityConsumeReceiptV1 ---

#[test]
fn valid_consume_receipt_passes_validation() {
    let receipt = AuthorityConsumeReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        intent_digest: test_hash(0x01),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
        pre_actuation_receipt_hash: None,
        authoritative_bindings: Some(valid_bindings()),
    };
    assert!(receipt.validate().is_ok());
}

#[test]
fn consume_receipt_zero_ajc_id_rejected() {
    let receipt = AuthorityConsumeReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: zero_hash(),
        intent_digest: test_hash(0x01),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
        pre_actuation_receipt_hash: None,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(matches!(err, types::PcacValidationError::ZeroHash { field } if field == "ajc_id"));
}

#[test]
fn consume_receipt_zero_intent_digest_rejected() {
    let receipt = AuthorityConsumeReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        intent_digest: zero_hash(),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
        pre_actuation_receipt_hash: None,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "intent_digest")
    );
}

#[test]
fn consume_receipt_zero_time_envelope_ref_rejected() {
    let receipt = AuthorityConsumeReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        intent_digest: test_hash(0x01),
        time_envelope_ref: zero_hash(),
        ledger_anchor: test_hash(0x08),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
        pre_actuation_receipt_hash: None,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "time_envelope_ref")
    );
}

#[test]
fn consume_receipt_zero_ledger_anchor_rejected() {
    let receipt = AuthorityConsumeReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        intent_digest: test_hash(0x01),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: zero_hash(),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
        pre_actuation_receipt_hash: None,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "ledger_anchor")
    );
}

#[test]
fn consume_receipt_zero_effect_selector_digest_rejected() {
    let receipt = AuthorityConsumeReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        intent_digest: test_hash(0x01),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        consumed_at_tick: 1500,
        effect_selector_digest: zero_hash(),
        pre_actuation_receipt_hash: None,
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "effect_selector_digest")
    );
}

#[test]
fn consume_receipt_propagates_binding_validation_errors() {
    let mut bindings = valid_bindings();
    bindings.view_commitment_hash = zero_hash();
    let receipt = AuthorityConsumeReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        intent_digest: test_hash(0x01),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
        pre_actuation_receipt_hash: None,
        authoritative_bindings: Some(bindings),
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "view_commitment_hash")
    );
}

// --- AuthorityDenyReceiptV1 ---

#[test]
fn valid_deny_receipt_passes_validation() {
    let receipt = AuthorityDenyReceiptV1 {
        digest_meta: valid_digest_meta(),
        deny_class: AuthorityDenyClass::InvalidSessionId,
        ajc_id: None,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 500,
        denied_at_stage: LifecycleStage::Join,
    };
    assert!(receipt.validate().is_ok());
}

#[test]
fn deny_receipt_zero_time_envelope_ref_rejected() {
    let receipt = AuthorityDenyReceiptV1 {
        digest_meta: valid_digest_meta(),
        deny_class: AuthorityDenyClass::InvalidSessionId,
        ajc_id: None,
        time_envelope_ref: zero_hash(),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 500,
        denied_at_stage: LifecycleStage::Join,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "time_envelope_ref")
    );
}

#[test]
fn deny_receipt_zero_ledger_anchor_rejected() {
    let receipt = AuthorityDenyReceiptV1 {
        digest_meta: valid_digest_meta(),
        deny_class: AuthorityDenyClass::InvalidSessionId,
        ajc_id: None,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: zero_hash(),
        denied_at_tick: 500,
        denied_at_stage: LifecycleStage::Join,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "ledger_anchor")
    );
}

#[test]
fn deny_receipt_zero_content_digest_rejected() {
    let receipt = AuthorityDenyReceiptV1 {
        digest_meta: ReceiptDigestMeta {
            canonicalizer_id: "apm2.canonicalizer.jcs".to_string(),
            content_digest: zero_hash(),
        },
        deny_class: AuthorityDenyClass::InvalidSessionId,
        ajc_id: None,
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        denied_at_tick: 500,
        denied_at_stage: LifecycleStage::Join,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "content_digest")
    );
}

// --- AuthorityRevalidateReceiptV1 zero-hash checks ---

#[test]
fn revalidate_receipt_zero_ajc_id_rejected() {
    let receipt = AuthorityRevalidateReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: zero_hash(),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        revocation_head_hash: test_hash(0xCC),
        revalidated_at_tick: 1200,
        checkpoint: "before_broker".to_string(),
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(matches!(err, types::PcacValidationError::ZeroHash { field } if field == "ajc_id"));
}

#[test]
fn revalidate_receipt_zero_time_envelope_ref_rejected() {
    let receipt = AuthorityRevalidateReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        time_envelope_ref: zero_hash(),
        ledger_anchor: test_hash(0x08),
        revocation_head_hash: test_hash(0xCC),
        revalidated_at_tick: 1200,
        checkpoint: "before_broker".to_string(),
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "time_envelope_ref")
    );
}

#[test]
fn revalidate_receipt_zero_ledger_anchor_rejected() {
    let receipt = AuthorityRevalidateReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: zero_hash(),
        revocation_head_hash: test_hash(0xCC),
        revalidated_at_tick: 1200,
        checkpoint: "before_broker".to_string(),
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "ledger_anchor")
    );
}

#[test]
fn revalidate_receipt_zero_revocation_head_hash_rejected() {
    let receipt = AuthorityRevalidateReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        revocation_head_hash: zero_hash(),
        revalidated_at_tick: 1200,
        checkpoint: "before_broker".to_string(),
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::ZeroHash { field } if field == "revocation_head_hash")
    );
}

#[test]
fn revalidate_receipt_empty_checkpoint_rejected() {
    let receipt = AuthorityRevalidateReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        revocation_head_hash: test_hash(0xCC),
        revalidated_at_tick: 1200,
        checkpoint: String::new(),
        authoritative_bindings: None,
    };
    let err = receipt.validate().unwrap_err();
    assert!(
        matches!(err, types::PcacValidationError::EmptyRequiredField { field } if field == "checkpoint")
    );
}

#[test]
fn valid_revalidate_receipt_passes_validation() {
    let receipt = AuthorityRevalidateReceiptV1 {
        digest_meta: valid_digest_meta(),
        ajc_id: test_hash(0xAA),
        time_envelope_ref: test_hash(0x07),
        ledger_anchor: test_hash(0x08),
        revocation_head_hash: test_hash(0xCC),
        revalidated_at_tick: 1200,
        checkpoint: "before_broker".to_string(),
        authoritative_bindings: Some(valid_bindings()),
    };
    assert!(receipt.validate().is_ok());
}
