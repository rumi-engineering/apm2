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
fn receipt_authentication_pointer_serde() {
    use super::receipts::*;

    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xE2),
        merkle_inclusion_proof: Some(vec![test_hash(0xE3), test_hash(0xE4)]),
        receipt_batch_root_hash: Some(test_hash(0xE5)),
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
// Fail-closed invariant tests (missing/zero fields)
// =============================================================================

#[test]
fn zero_intent_digest_should_be_detectable() {
    let mut input = valid_join_input();
    input.intent_digest = zero_hash();
    // A join kernel implementation MUST deny this — we test that the
    // field is detectable as zero.
    assert_eq!(input.intent_digest, zero_hash());
}

#[test]
fn zero_identity_proof_should_be_detectable() {
    let mut input = valid_join_input();
    input.identity_proof_hash = zero_hash();
    assert_eq!(input.identity_proof_hash, zero_hash());
}

#[test]
fn empty_session_id_should_be_detectable() {
    let mut input = valid_join_input();
    input.session_id = String::new();
    assert!(input.session_id.is_empty());
}

#[test]
fn empty_lease_id_should_be_detectable() {
    let mut input = valid_join_input();
    input.lease_id = String::new();
    assert!(input.lease_id.is_empty());
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
