// AGENT-AUTHORED
//! Tests for PCAC core schemas, deny taxonomy (TCK-00422), and
//! receipt authentication verification (TCK-00425).

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
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: test_hash(0xE3),
                sibling_is_left: false,
            },
            MerkleProofEntry {
                sibling_hash: test_hash(0xE4),
                sibling_is_left: false,
            },
        ]),
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

// =============================================================================
// Auth verifier helpers (TCK-00425)
// =============================================================================

fn valid_direct_auth(seal: Hash) -> ReceiptAuthentication {
    ReceiptAuthentication::Direct {
        authority_seal_hash: seal,
    }
}

/// Build a valid pointer authentication with a direction-aware merkle proof
/// that actually verifies. We compute the batch root deterministically from
/// `receipt_hash` and proof siblings using the same `hash_leaf` /
/// `hash_internal` logic that the verifier uses.
///
/// This proof simulates a left-branch leaf (sibling is on the right at each
/// level, so `sibling_is_left = false`).
fn valid_pointer_auth(seal: Hash) -> ReceiptAuthentication {
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let receipt_hash = test_hash(0xE1);
    let sibling0 = test_hash(0xE3);
    let sibling1 = test_hash(0xE4);

    // Recompute the expected root: hash_leaf(receipt_hash), then fold.
    // sibling_is_left=false means current is on the left, sibling on right.
    let leaf = hash_leaf(&receipt_hash);
    let level1 = hash_internal(&leaf, &sibling0);
    let root = hash_internal(&level1, &sibling1);

    ReceiptAuthentication::Pointer {
        receipt_hash,
        authority_seal_hash: seal,
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: sibling0,
                sibling_is_left: false,
            },
            MerkleProofEntry {
                sibling_hash: sibling1,
                sibling_is_left: false,
            },
        ]),
        receipt_batch_root_hash: Some(root),
    }
}

/// Build a valid pointer authentication with a right-branch merkle proof.
///
/// This proof simulates a right-branch leaf (sibling is on the left at each
/// level, so `sibling_is_left = true`).
fn valid_pointer_auth_right_branch(seal: Hash) -> ReceiptAuthentication {
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let receipt_hash = test_hash(0xE1);
    let sibling0 = test_hash(0xE3);
    let sibling1 = test_hash(0xE4);

    // Recompute the expected root: hash_leaf(receipt_hash), then fold.
    // sibling_is_left=true means sibling is on the left, current on right.
    let leaf = hash_leaf(&receipt_hash);
    let level1 = hash_internal(&sibling0, &leaf);
    let root = hash_internal(&sibling1, &level1);

    ReceiptAuthentication::Pointer {
        receipt_hash,
        authority_seal_hash: seal,
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: sibling0,
                sibling_is_left: true,
            },
            MerkleProofEntry {
                sibling_hash: sibling1,
                sibling_is_left: true,
            },
        ]),
        receipt_batch_root_hash: Some(root),
    }
}

fn valid_bindings(seal: Hash) -> AuthoritativeBindings {
    AuthoritativeBindings {
        episode_envelope_hash: test_hash(0xA1),
        view_commitment_hash: test_hash(0xA2),
        // Must match the contextual TIME_REF for MAJOR 1 contextual binding
        time_envelope_ref: TIME_REF,
        authentication: valid_direct_auth(seal),
        permeability_receipt_hash: None,
        delegation_chain_hash: None,
    }
}

const SEAL: Hash = [0xDD; 32];
const TIME_REF: Hash = [0x07; 32];
const LEDGER: Hash = [0x08; 32];
const TICK: u64 = 1000;

// =============================================================================
// Direct authentication tests (TCK-00425)
// =============================================================================

#[test]
fn direct_auth_happy_path() {
    let auth = valid_direct_auth(SEAL);
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn direct_auth_zero_seal_hash_denied() {
    let auth = ReceiptAuthentication::Direct {
        authority_seal_hash: zero_hash(),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "authority_seal_hash")
    );
}

#[test]
fn direct_auth_seal_mismatch_denied() {
    let wrong_seal = test_hash(0xFF);
    let auth = valid_direct_auth(wrong_seal);
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { .. }
    ));
}

// =============================================================================
// Pointer authentication tests (TCK-00425)
// =============================================================================

#[test]
fn pointer_auth_happy_path_with_merkle_proof() {
    let auth = valid_pointer_auth(SEAL);
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn pointer_auth_happy_path_without_batching() {
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: None,
        receipt_batch_root_hash: None,
    };
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn pointer_auth_zero_receipt_hash_denied() {
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: zero_hash(),
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: None,
        receipt_batch_root_hash: None,
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "receipt_hash")
    );
}

#[test]
fn pointer_auth_zero_seal_hash_denied() {
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: zero_hash(),
        merkle_inclusion_proof: None,
        receipt_batch_root_hash: None,
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "authority_seal_hash")
    );
}

#[test]
fn pointer_auth_seal_mismatch_denied() {
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: test_hash(0xFF),
        merkle_inclusion_proof: None,
        receipt_batch_root_hash: None,
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { .. }
    ));
}

#[test]
fn pointer_auth_empty_merkle_proof_denied() {
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![]),
        receipt_batch_root_hash: Some(test_hash(0xE5)),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { .. }
    ));
}

#[test]
fn pointer_auth_zero_hash_sibling_allowed_as_canonical_padding() {
    // Zero-hash siblings are the canonical EMPTY_HASH padding used by
    // consensus::merkle for odd-sized trees. The verifier must allow them
    // and rely on root recomputation for integrity. This proof will fail
    // because the batch root doesn't match the recomputed root (not because
    // of the zero sibling itself).
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let receipt_hash = test_hash(0xE1);
    let sibling0 = test_hash(0xE3);
    let zero_sibling = zero_hash(); // canonical EMPTY_HASH padding

    // Compute the correct root with the zero sibling
    let leaf = hash_leaf(&receipt_hash);
    let level1 = hash_internal(&leaf, &sibling0);
    let root = hash_internal(&level1, &zero_sibling);

    let auth = ReceiptAuthentication::Pointer {
        receipt_hash,
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: sibling0,
                sibling_is_left: false,
            },
            MerkleProofEntry {
                sibling_hash: zero_sibling,
                sibling_is_left: false,
            },
        ]),
        receipt_batch_root_hash: Some(root),
    };
    // Must pass: the zero sibling is canonical padding and the proof
    // recomputation matches the batch root.
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(
        result.is_ok(),
        "zero-hash sibling (canonical padding) with matching root must be accepted"
    );
}

#[test]
fn pointer_auth_zero_batch_root_denied() {
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![MerkleProofEntry {
            sibling_hash: test_hash(0xE3),
            sibling_is_left: false,
        }]),
        receipt_batch_root_hash: Some(zero_hash()),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "receipt_batch_root_hash")
    );
}

#[test]
fn pointer_auth_proof_without_batch_root_denied() {
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![MerkleProofEntry {
            sibling_hash: test_hash(0xE3),
            sibling_is_left: false,
        }]),
        receipt_batch_root_hash: None,
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { .. }
    ));
}

#[test]
fn pointer_auth_batch_root_without_proof_denied() {
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: None,
        receipt_batch_root_hash: Some(test_hash(0xE5)),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { .. }
    ));
}

// =============================================================================
// Authoritative bindings validation tests (TCK-00425)
// =============================================================================

#[test]
fn valid_bindings_pass() {
    let bindings = valid_bindings(SEAL);
    let result = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, None);
    assert!(result.is_ok());
}

#[test]
fn zero_episode_envelope_hash_denied() {
    let mut bindings = valid_bindings(SEAL);
    bindings.episode_envelope_hash = zero_hash();
    let err = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, None).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "episode_envelope_hash")
    );
}

#[test]
fn zero_view_commitment_hash_denied() {
    let mut bindings = valid_bindings(SEAL);
    bindings.view_commitment_hash = zero_hash();
    let err = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, None).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "view_commitment_hash")
    );
}

#[test]
fn zero_time_envelope_ref_denied() {
    let mut bindings = valid_bindings(SEAL);
    bindings.time_envelope_ref = zero_hash();
    let err = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, None).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "time_envelope_ref")
    );
}

#[test]
fn zero_permeability_receipt_hash_denied() {
    let mut bindings = valid_bindings(SEAL);
    bindings.permeability_receipt_hash = Some(zero_hash());
    let err = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, None).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "permeability_receipt_hash")
    );
}

#[test]
fn zero_delegation_chain_hash_denied() {
    let mut bindings = valid_bindings(SEAL);
    bindings.delegation_chain_hash = Some(zero_hash());
    let err = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, None).unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "delegation_chain_hash")
    );
}

#[test]
fn valid_delegation_bindings_pass() {
    let mut bindings = valid_bindings(SEAL);
    bindings.permeability_receipt_hash = Some(test_hash(0xB1));
    bindings.delegation_chain_hash = Some(test_hash(0xB2));
    let result = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, None);
    assert!(result.is_ok());
}

// =============================================================================
// Fact classification tests (TCK-00425)
// =============================================================================

#[test]
fn classify_acceptance_fact_with_direct_auth() {
    let bindings = valid_bindings(SEAL);
    let class = classify_fact(Some(&bindings), &SEAL, None, TIME_REF, LEDGER, TICK, None);
    assert_eq!(class, FactClass::AcceptanceFact);
}

#[test]
fn classify_acceptance_fact_with_pointer_auth() {
    let mut bindings = valid_bindings(SEAL);
    bindings.authentication = valid_pointer_auth(SEAL);
    let class = classify_fact(Some(&bindings), &SEAL, None, TIME_REF, LEDGER, TICK, None);
    assert_eq!(class, FactClass::AcceptanceFact);
}

#[test]
fn classify_routing_fact_no_bindings() {
    let class = classify_fact(None, &SEAL, None, TIME_REF, LEDGER, TICK, None);
    assert_eq!(class, FactClass::RoutingFact);
}

#[test]
fn classify_routing_fact_zero_envelope() {
    let mut bindings = valid_bindings(SEAL);
    bindings.episode_envelope_hash = zero_hash();
    let class = classify_fact(Some(&bindings), &SEAL, None, TIME_REF, LEDGER, TICK, None);
    assert_eq!(class, FactClass::RoutingFact);
}

#[test]
fn classify_routing_fact_bad_auth() {
    let mut bindings = valid_bindings(SEAL);
    bindings.authentication = ReceiptAuthentication::Direct {
        authority_seal_hash: zero_hash(),
    };
    let class = classify_fact(Some(&bindings), &SEAL, None, TIME_REF, LEDGER, TICK, None);
    assert_eq!(class, FactClass::RoutingFact);
}

#[test]
fn classify_routing_fact_seal_mismatch() {
    let bindings = valid_bindings(test_hash(0xFF));
    let class = classify_fact(Some(&bindings), &SEAL, None, TIME_REF, LEDGER, TICK, None);
    assert_eq!(class, FactClass::RoutingFact);
}

// =============================================================================
// FactClass serde and display tests (TCK-00425)
// =============================================================================

#[test]
fn fact_class_display() {
    assert_eq!(FactClass::AcceptanceFact.to_string(), "acceptance_fact");
    assert_eq!(FactClass::RoutingFact.to_string(), "routing_fact");
}

#[test]
fn fact_class_serde_roundtrip() {
    for class in [FactClass::AcceptanceFact, FactClass::RoutingFact] {
        let json = serde_json::to_string(&class).unwrap();
        let back: FactClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, class);
    }
}

// =============================================================================
// Fail-closed on unknown state (TCK-00425)
// =============================================================================

#[test]
fn deny_carries_correct_context() {
    let auth = ReceiptAuthentication::Direct {
        authority_seal_hash: zero_hash(),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert_eq!(err.time_envelope_ref, TIME_REF);
    assert_eq!(err.ledger_anchor, LEDGER);
    assert_eq!(err.denied_at_tick, TICK);
    assert!(err.ajc_id.is_none());
}

// =============================================================================
// Merkle inclusion verification negative tests (TCK-00425, BLOCKER fix)
// =============================================================================

#[test]
fn pointer_auth_wrong_batch_root_denied() {
    // Proof siblings are valid non-zero hashes, but batch_root is an
    // arbitrary hash that does not match the recomputed root.
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: test_hash(0xE3),
                sibling_is_left: false,
            },
            MerkleProofEntry {
                sibling_hash: test_hash(0xE4),
                sibling_is_left: false,
            },
        ]),
        receipt_batch_root_hash: Some(test_hash(0xFF)), // wrong root
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("recomputed root does not match")
    ));
}

#[test]
fn pointer_auth_wrong_sibling_branch_denied() {
    // Build a valid proof for receipt_hash 0xE1 then swap one sibling.
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let receipt_hash = test_hash(0xE1);
    let correct_sibling0 = test_hash(0xE3);
    let sibling1 = test_hash(0xE4);

    // Compute the correct root.
    let leaf = hash_leaf(&receipt_hash);
    let level1 = hash_internal(&leaf, &correct_sibling0);
    let correct_root = hash_internal(&level1, &sibling1);

    // Now use a WRONG sibling at position 0.
    let wrong_sibling0 = test_hash(0xAA);
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash,
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: wrong_sibling0,
                sibling_is_left: false,
            },
            MerkleProofEntry {
                sibling_hash: sibling1,
                sibling_is_left: false,
            },
        ]),
        receipt_batch_root_hash: Some(correct_root),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("recomputed root does not match")
    ));
}

#[test]
fn pointer_auth_wrong_receipt_hash_denied() {
    // Build a valid proof for receipt_hash 0xE1, then submit it with a
    // different receipt_hash (0xE2). The recomputed root won't match.
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let original_receipt = test_hash(0xE1);
    let sibling0 = test_hash(0xE3);
    let sibling1 = test_hash(0xE4);

    let leaf = hash_leaf(&original_receipt);
    let level1 = hash_internal(&leaf, &sibling0);
    let root = hash_internal(&level1, &sibling1);

    // Use a different receipt_hash.
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE2), // different receipt
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: sibling0,
                sibling_is_left: false,
            },
            MerkleProofEntry {
                sibling_hash: sibling1,
                sibling_is_left: false,
            },
        ]),
        receipt_batch_root_hash: Some(root),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("recomputed root does not match")
    ));
}

#[test]
fn pointer_auth_proof_exceeds_max_depth_denied() {
    // Build a proof that exceeds MAX_MERKLE_INCLUSION_PROOF_DEPTH.
    #[allow(clippy::cast_possible_truncation)]
    let too_many: Vec<MerkleProofEntry> = (0
        ..=super::auth_verifier::MAX_MERKLE_INCLUSION_PROOF_DEPTH)
        .map(|i| MerkleProofEntry {
            sibling_hash: test_hash((i as u8).wrapping_add(1)),
            sibling_is_left: false,
        })
        .collect();
    // Also need a matching root -- but we expect denial before verification.
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: test_hash(0xE1),
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(too_many),
        receipt_batch_root_hash: Some(test_hash(0xFF)),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("exceeds maximum")
    ));
}

#[test]
fn pointer_auth_single_sibling_proof_valid() {
    // Minimal valid proof: one sibling (left-branch leaf).
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let receipt_hash = test_hash(0xE1);
    let sibling = test_hash(0xE3);
    let leaf = hash_leaf(&receipt_hash);
    let root = hash_internal(&leaf, &sibling);

    let auth = ReceiptAuthentication::Pointer {
        receipt_hash,
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![MerkleProofEntry {
            sibling_hash: sibling,
            sibling_is_left: false,
        }]),
        receipt_batch_root_hash: Some(root),
    };
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

// =============================================================================
// Right-branch direction-aware proof tests (TCK-00425, MAJOR 2 fix)
// =============================================================================

#[test]
fn pointer_auth_right_branch_proof_valid() {
    // Right-branch leaf: sibling is on the left at each level.
    let auth = valid_pointer_auth_right_branch(SEAL);
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn pointer_auth_right_branch_single_sibling_valid() {
    // Minimal valid proof: one sibling, right-branch leaf.
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let receipt_hash = test_hash(0xE1);
    let sibling = test_hash(0xE3);
    let leaf = hash_leaf(&receipt_hash);
    // sibling is on the left, current on the right
    let root = hash_internal(&sibling, &leaf);

    let auth = ReceiptAuthentication::Pointer {
        receipt_hash,
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![MerkleProofEntry {
            sibling_hash: sibling,
            sibling_is_left: true,
        }]),
        receipt_batch_root_hash: Some(root),
    };
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn pointer_auth_mixed_direction_proof_valid() {
    // Mixed directions: first level is right-branch, second is left-branch.
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let receipt_hash = test_hash(0xE1);
    let sibling0 = test_hash(0xE3);
    let sibling1 = test_hash(0xE4);

    let leaf = hash_leaf(&receipt_hash);
    // Level 0: sibling is on the left (current on right)
    let level1 = hash_internal(&sibling0, &leaf);
    // Level 1: sibling is on the right (current on left)
    let root = hash_internal(&level1, &sibling1);

    let auth = ReceiptAuthentication::Pointer {
        receipt_hash,
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: sibling0,
                sibling_is_left: true,
            },
            MerkleProofEntry {
                sibling_hash: sibling1,
                sibling_is_left: false,
            },
        ]),
        receipt_batch_root_hash: Some(root),
    };
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn pointer_auth_wrong_direction_bit_denied() {
    // Build a valid left-branch proof, then flip a direction bit.
    // The recomputed root should not match.
    use crate::consensus::merkle::{hash_internal, hash_leaf};

    let receipt_hash = test_hash(0xE1);
    let sibling0 = test_hash(0xE3);
    let sibling1 = test_hash(0xE4);

    // Left-branch root computation
    let leaf = hash_leaf(&receipt_hash);
    let level1 = hash_internal(&leaf, &sibling0);
    let root = hash_internal(&level1, &sibling1);

    // Now flip first direction bit to right-branch
    let auth = ReceiptAuthentication::Pointer {
        receipt_hash,
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(vec![
            MerkleProofEntry {
                sibling_hash: sibling0,
                sibling_is_left: true, // wrong: was false in original proof
            },
            MerkleProofEntry {
                sibling_hash: sibling1,
                sibling_is_left: false,
            },
        ]),
        receipt_batch_root_hash: Some(root),
    };
    let err =
        verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("recomputed root does not match")
    ));
}

#[test]
fn pointer_auth_from_canonical_merkle_tree_left_leaf() {
    // MAJOR 2 fix: derive proof from consensus::merkle::MerkleTree::proof_for
    // for a left leaf (even index).
    use crate::consensus::merkle::MerkleTree;
    use crate::crypto::EventHasher;

    let leaves: Vec<_> = (0..8u64)
        .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
        .collect();
    let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
    let root = tree.root();

    // Index 0 is a left leaf
    let proof = tree.proof_for(0).unwrap();
    assert!(proof.verify(&root).is_ok());

    // Convert canonical MerkleProof to ReceiptAuthentication proof entries.
    let proof_entries: Vec<MerkleProofEntry> = proof
        .path
        .iter()
        .map(|(sibling_hash, is_right)| MerkleProofEntry {
            sibling_hash: *sibling_hash,
            // In MerkleProof, is_right means the CURRENT node is on the right,
            // so the sibling is on the left.
            sibling_is_left: *is_right,
        })
        .collect();

    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: leaves[0],
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(proof_entries),
        receipt_batch_root_hash: Some(root),
    };
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(
        result.is_ok(),
        "left leaf proof from canonical tree must verify"
    );
}

#[test]
fn pointer_auth_from_canonical_merkle_tree_right_leaf() {
    // MAJOR 2 fix: derive proof from consensus::merkle::MerkleTree::proof_for
    // for a right leaf (odd index).
    use crate::consensus::merkle::MerkleTree;
    use crate::crypto::EventHasher;

    let leaves: Vec<_> = (0..8u64)
        .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
        .collect();
    let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
    let root = tree.root();

    // Index 3 is a right leaf (odd index)
    let proof = tree.proof_for(3).unwrap();
    assert!(proof.verify(&root).is_ok());

    // Convert canonical MerkleProof to ReceiptAuthentication proof entries.
    let proof_entries: Vec<MerkleProofEntry> = proof
        .path
        .iter()
        .map(|(sibling_hash, is_right)| MerkleProofEntry {
            sibling_hash: *sibling_hash,
            sibling_is_left: *is_right,
        })
        .collect();

    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: leaves[3],
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(proof_entries),
        receipt_batch_root_hash: Some(root),
    };
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(
        result.is_ok(),
        "right leaf proof from canonical tree must verify"
    );
}

#[test]
fn pointer_auth_from_canonical_merkle_tree_all_leaves() {
    // Verify all leaves in a canonical tree can be proven through
    // ReceiptAuthentication.
    use crate::consensus::merkle::MerkleTree;
    use crate::crypto::EventHasher;

    let leaves: Vec<_> = (0..16u64)
        .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
        .collect();
    let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
    let root = tree.root();

    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof_for(idx).unwrap();
        assert!(proof.verify(&root).is_ok());

        let proof_entries: Vec<MerkleProofEntry> = proof
            .path
            .iter()
            .map(|(sibling_hash, is_right)| MerkleProofEntry {
                sibling_hash: *sibling_hash,
                sibling_is_left: *is_right,
            })
            .collect();

        let auth = ReceiptAuthentication::Pointer {
            receipt_hash: *leaf,
            authority_seal_hash: SEAL,
            merkle_inclusion_proof: Some(proof_entries),
            receipt_batch_root_hash: Some(root),
        };
        let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
        assert!(
            result.is_ok(),
            "leaf {idx} proof from canonical tree must verify"
        );
    }
}

// =============================================================================
// Seal-anchored batch root tests (TCK-00425, BLOCKER 2 fix)
// =============================================================================

#[test]
fn pointer_auth_seal_subject_hash_matches_batch_root() {
    // When seal_subject_hash is provided and matches batch_root, verification
    // should succeed.
    let auth = valid_pointer_auth(SEAL);
    // Extract the batch root from the valid pointer auth.
    let batch_root = match &auth {
        ReceiptAuthentication::Pointer {
            receipt_batch_root_hash: Some(root),
            ..
        } => *root,
        _ => panic!("expected pointer auth with batch root"),
    };
    let result =
        verify_receipt_authentication(&auth, &SEAL, Some(&batch_root), TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn pointer_auth_seal_subject_hash_mismatch_denied() {
    // When seal_subject_hash is provided but does NOT match batch_root,
    // verification must fail — the batch root is not anchored to the seal.
    let auth = valid_pointer_auth(SEAL);
    let wrong_subject = test_hash(0xBB);
    let err =
        verify_receipt_authentication(&auth, &SEAL, Some(&wrong_subject), TIME_REF, LEDGER, TICK)
            .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("batch root not anchored to authority seal")
    ));
}

#[test]
fn pointer_auth_no_seal_subject_hash_skips_anchor_check() {
    // When seal_subject_hash is None, the anchor check is skipped.
    // This is the existing behavior for backward compatibility.
    let auth = valid_pointer_auth(SEAL);
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

// =============================================================================
// Contextual binding tests (TCK-00425, MAJOR 1 fix)
// =============================================================================

#[test]
fn bindings_time_envelope_ref_mismatch_denied() {
    // Bindings time_envelope_ref does not match the contextual argument.
    let mut bindings = valid_bindings(SEAL);
    bindings.time_envelope_ref = test_hash(0xFF); // different from TIME_REF
    let err = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, None).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("time_envelope_ref")
    ));
}

#[test]
fn bindings_view_commitment_mismatch_denied() {
    // Bindings view_commitment_hash does not match the expected value.
    let bindings = valid_bindings(SEAL);
    let wrong_vc = test_hash(0xFF);
    let err = validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, Some(&wrong_vc))
        .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("view_commitment_hash")
    ));
}

#[test]
fn bindings_view_commitment_match_ok() {
    // Bindings view_commitment_hash matches the expected value.
    let bindings = valid_bindings(SEAL);
    let expected_vc = test_hash(0xA2); // same as in valid_bindings
    let result =
        validate_authoritative_bindings(&bindings, TIME_REF, LEDGER, TICK, Some(&expected_vc));
    assert!(result.is_ok());
}

#[test]
fn classify_fact_with_contextual_binding_mismatch_is_routing() {
    // If bindings.time_envelope_ref doesn't match contextual, classify as
    // routing fact (fail-closed).
    let mut bindings = valid_bindings(SEAL);
    bindings.time_envelope_ref = test_hash(0xFF);
    let class = classify_fact(Some(&bindings), &SEAL, None, TIME_REF, LEDGER, TICK, None);
    assert_eq!(class, FactClass::RoutingFact);
}

#[test]
fn classify_acceptance_fact_with_right_branch_pointer_auth() {
    // Classification should work with right-branch pointer auth too.
    let mut bindings = valid_bindings(SEAL);
    bindings.authentication = valid_pointer_auth_right_branch(SEAL);
    let class = classify_fact(Some(&bindings), &SEAL, None, TIME_REF, LEDGER, TICK, None);
    assert_eq!(class, FactClass::AcceptanceFact);
}

// =============================================================================
// Replay lifecycle ordering tests (TCK-00425, REQ-0006)
// =============================================================================

#[test]
fn replay_lifecycle_valid_ordering() {
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let result = validate_replay_lifecycle_order(&entries, Some(300), &[], TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn replay_lifecycle_valid_with_effect_after_consume() {
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 10,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 20,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 30,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let result = validate_replay_lifecycle_order(&entries, Some(50), &[], TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn replay_lifecycle_missing_join_denied() {
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::BoundaryMonotonicityViolation { ref description }
        if description.contains("missing AuthorityJoin")
    ));
}

#[test]
fn replay_lifecycle_missing_revalidate_denied() {
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::BoundaryMonotonicityViolation { ref description }
        if description.contains("missing AuthorityRevalidate")
    ));
}

#[test]
fn replay_lifecycle_missing_consume_denied() {
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::BoundaryMonotonicityViolation { ref description }
        if description.contains("missing AuthorityConsume")
    ));
}

#[test]
fn replay_lifecycle_join_not_before_revalidate_denied() {
    // Join tick == Revalidate tick (must be strict <)
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::BoundaryMonotonicityViolation { ref description }
        if description.contains("AuthorityJoin tick")
    ));
}

#[test]
fn replay_lifecycle_revalidate_not_before_consume_denied() {
    // Revalidate tick >= Consume tick
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 300,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::BoundaryMonotonicityViolation { ref description }
        if description.contains("AuthorityRevalidate tick")
    ));
}

#[test]
fn replay_lifecycle_consume_after_effect_receipt_denied() {
    // Consume tick > effect receipt tick
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 400,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let err = validate_replay_lifecycle_order(&entries, Some(300), &[], TIME_REF, LEDGER, TICK)
        .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::BoundaryMonotonicityViolation { ref description }
        if description.contains("EffectReceipt tick")
    ));
}

#[test]
fn replay_lifecycle_consume_equal_to_effect_receipt_ok() {
    // Consume tick == effect receipt tick (allowed: <=)
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let result = validate_replay_lifecycle_order(&entries, Some(300), &[], TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn replay_lifecycle_missing_pre_actuation_selector_denied() {
    // Consume requires pre-actuation but selector is None
    let known_hashes = [test_hash(0xAB)];
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: true,
            pre_actuation_selector_hash: None,
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &known_hashes, TIME_REF, LEDGER, TICK)
            .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::MissingPreActuationReceipt
    ));
}

#[test]
fn replay_lifecycle_zero_pre_actuation_selector_denied() {
    // Consume requires pre-actuation but selector hash is zero
    let known_hashes = [test_hash(0xAB)];
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: true,
            pre_actuation_selector_hash: Some(zero_hash()),
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &known_hashes, TIME_REF, LEDGER, TICK)
            .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::MissingPreActuationReceipt
    ));
}

#[test]
fn replay_lifecycle_valid_pre_actuation_selector_ok() {
    // Consume requires pre-actuation and selector is present, non-zero,
    // and present in the known pre-actuation hash set.
    let known_hashes = [test_hash(0xAB)];
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: true,
            pre_actuation_selector_hash: Some(test_hash(0xAB)),
        },
    ];
    let result =
        validate_replay_lifecycle_order(&entries, None, &known_hashes, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

#[test]
fn replay_lifecycle_exceeds_max_entries_denied() {
    // Build a sequence exceeding MAX_REPLAY_LIFECYCLE_ENTRIES
    let mut entries = Vec::new();
    entries.push(ReplayLifecycleEntry {
        stage: LifecycleStage::Join,
        tick: 1,
        requires_pre_actuation: false,
        pre_actuation_selector_hash: None,
    });
    for i in 2..=super::auth_verifier::MAX_REPLAY_LIFECYCLE_ENTRIES {
        entries.push(ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: i as u64,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        });
    }
    // One more to exceed
    entries.push(ReplayLifecycleEntry {
        stage: LifecycleStage::Consume,
        tick: 999,
        requires_pre_actuation: false,
        pre_actuation_selector_hash: None,
    });
    let err =
        validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::UnknownState { ref description }
        if description.contains("exceeds maximum")
    ));
}

#[test]
fn replay_lifecycle_join_after_revalidate_denied() {
    // Join tick > Revalidate tick (strict order violation)
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 500,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 600,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::BoundaryMonotonicityViolation { .. }
    ));
}

#[test]
fn replay_lifecycle_no_effect_receipt_ok() {
    // No effect receipt tick provided -- only entry ordering is checked
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 10,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 20,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 30,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
    ];
    let result = validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK);
    assert!(result.is_ok());
}

// =============================================================================
// REQ-0006 referential selector invariant tests (Security BLOCKER fix)
// =============================================================================

#[test]
fn replay_lifecycle_arbitrary_nonzero_selector_not_in_known_set_denied() {
    // REQ-0006: A consume entry with a non-zero pre_actuation_selector_hash
    // that does NOT appear in the known pre-actuation set must be denied.
    // This closes the vulnerability where an arbitrary hash could bypass the
    // selector-reference invariant.
    let known_hashes = [test_hash(0xAB)];
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: true,
            // Non-zero but NOT in known_hashes
            pre_actuation_selector_hash: Some(test_hash(0xCD)),
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &known_hashes, TIME_REF, LEDGER, TICK)
            .unwrap_err();
    assert!(
        matches!(
            err.deny_class,
            AuthorityDenyClass::MissingPreActuationReceipt
        ),
        "arbitrary non-zero selector not in known set must be denied"
    );
}

#[test]
fn replay_lifecycle_selector_in_known_set_passes() {
    // REQ-0006: When the selector IS in the known set, validation passes.
    let known_hashes = [test_hash(0xAB), test_hash(0xCD)];
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: true,
            pre_actuation_selector_hash: Some(test_hash(0xCD)),
        },
    ];
    let result =
        validate_replay_lifecycle_order(&entries, None, &known_hashes, TIME_REF, LEDGER, TICK);
    assert!(result.is_ok(), "selector present in known set must pass");
}

#[test]
fn replay_lifecycle_empty_known_set_with_pre_actuation_denied() {
    // REQ-0006: If the known set is empty but pre-actuation is required,
    // any non-zero selector must be denied (fail-closed: no known hashes
    // means no valid reference).
    let entries = vec![
        ReplayLifecycleEntry {
            stage: LifecycleStage::Join,
            tick: 100,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Revalidate,
            tick: 200,
            requires_pre_actuation: false,
            pre_actuation_selector_hash: None,
        },
        ReplayLifecycleEntry {
            stage: LifecycleStage::Consume,
            tick: 300,
            requires_pre_actuation: true,
            pre_actuation_selector_hash: Some(test_hash(0xAB)),
        },
    ];
    let err =
        validate_replay_lifecycle_order(&entries, None, &[], TIME_REF, LEDGER, TICK).unwrap_err();
    assert!(
        matches!(
            err.deny_class,
            AuthorityDenyClass::MissingPreActuationReceipt
        ),
        "empty known set must deny any pre-actuation selector"
    );
}

// =============================================================================
// deny_unknown_fields negative serde tests (Security MAJOR fix)
// =============================================================================

#[test]
fn receipt_digest_meta_rejects_unknown_fields() {
    use super::receipts::ReceiptDigestMeta;
    let json = r#"{"canonicalizer_id":"jcs","content_digest":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"extra_field":"unexpected"}"#;
    let result = serde_json::from_str::<ReceiptDigestMeta>(json);
    assert!(
        result.is_err(),
        "unknown field must be rejected by ReceiptDigestMeta"
    );
}

#[test]
fn merkle_proof_entry_rejects_unknown_fields() {
    let json = r#"{"sibling_hash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sibling_is_left":false,"injected":true}"#;
    let result = serde_json::from_str::<MerkleProofEntry>(json);
    assert!(
        result.is_err(),
        "unknown field must be rejected by MerkleProofEntry"
    );
}

#[test]
fn authoritative_bindings_rejects_unknown_fields() {
    use super::receipts::*;
    let bindings = AuthoritativeBindings {
        episode_envelope_hash: test_hash(0xA1),
        view_commitment_hash: test_hash(0xA2),
        time_envelope_ref: test_hash(0x07),
        authentication: ReceiptAuthentication::Direct {
            authority_seal_hash: test_hash(0xDD),
        },
        permeability_receipt_hash: None,
        delegation_chain_hash: None,
    };
    let mut json: serde_json::Value = serde_json::to_value(&bindings).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("rogue_field".to_string(), serde_json::json!("injected"));
    let result = serde_json::from_value::<AuthoritativeBindings>(json);
    assert!(
        result.is_err(),
        "unknown field must be rejected by AuthoritativeBindings"
    );
}

#[test]
fn authority_join_receipt_rejects_unknown_fields() {
    use super::receipts::ReceiptDigestMeta;
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
        .insert("extra".to_string(), serde_json::json!(42));
    let result = serde_json::from_value::<AuthorityJoinReceiptV1>(json);
    assert!(
        result.is_err(),
        "unknown field must be rejected by AuthorityJoinReceiptV1"
    );
}

#[test]
fn authority_consume_receipt_rejects_unknown_fields() {
    use super::receipts::ReceiptDigestMeta;
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
        .insert("rogue".to_string(), serde_json::json!("bad"));
    let result = serde_json::from_value::<AuthorityConsumeReceiptV1>(json);
    assert!(
        result.is_err(),
        "unknown field must be rejected by AuthorityConsumeReceiptV1"
    );
}

#[test]
fn authority_join_input_rejects_unknown_fields() {
    let input = valid_join_input();
    let mut json: serde_json::Value = serde_json::to_value(&input).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("injected_field".to_string(), serde_json::json!("attacker"));
    let result = serde_json::from_value::<AuthorityJoinInputV1>(json);
    assert!(
        result.is_err(),
        "unknown field must be rejected by AuthorityJoinInputV1"
    );
}

#[test]
fn authority_join_certificate_rejects_unknown_fields() {
    let cert = valid_certificate();
    let mut json: serde_json::Value = serde_json::to_value(&cert).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("extra".to_string(), serde_json::json!(true));
    let result = serde_json::from_value::<AuthorityJoinCertificateV1>(json);
    assert!(
        result.is_err(),
        "unknown field must be rejected by AuthorityJoinCertificateV1"
    );
}

#[test]
fn authority_consume_record_rejects_unknown_fields() {
    let record = AuthorityConsumeRecordV1 {
        ajc_id: test_hash(0xAA),
        consumed_time_envelope_ref: test_hash(0xDD),
        consumed_at_tick: 1500,
        effect_selector_digest: test_hash(0xEE),
    };
    let mut json: serde_json::Value = serde_json::to_value(&record).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("rogue".to_string(), serde_json::json!(99));
    let result = serde_json::from_value::<AuthorityConsumeRecordV1>(json);
    assert!(
        result.is_err(),
        "unknown field must be rejected by AuthorityConsumeRecordV1"
    );
}

// =============================================================================
// Odd-sized canonical Merkle tree proof tests (Quality BLOCKER + MAJOR fix)
// =============================================================================

#[test]
fn pointer_auth_from_canonical_merkle_tree_3_leaves() {
    // Odd-size tree: 3 leaves means the rightmost leaf gets EMPTY_HASH
    // padding as its sibling.
    use crate::consensus::merkle::MerkleTree;
    use crate::crypto::EventHasher;

    let leaves: Vec<_> = (0..3u64)
        .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
        .collect();
    let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
    let root = tree.root();

    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof_for(idx).unwrap();
        assert!(
            proof.verify(&root).is_ok(),
            "canonical proof {idx} must self-verify"
        );

        let proof_entries: Vec<MerkleProofEntry> = proof
            .path
            .iter()
            .map(|(sibling_hash, is_right)| MerkleProofEntry {
                sibling_hash: *sibling_hash,
                sibling_is_left: *is_right,
            })
            .collect();

        let auth = ReceiptAuthentication::Pointer {
            receipt_hash: *leaf,
            authority_seal_hash: SEAL,
            merkle_inclusion_proof: Some(proof_entries),
            receipt_batch_root_hash: Some(root),
        };
        let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
        assert!(
            result.is_ok(),
            "leaf {idx} proof from 3-leaf canonical tree must verify through auth verifier"
        );
    }
}

#[test]
fn pointer_auth_from_canonical_merkle_tree_5_leaves() {
    // Odd-size tree: 5 leaves
    use crate::consensus::merkle::MerkleTree;
    use crate::crypto::EventHasher;

    let leaves: Vec<_> = (0..5u64)
        .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
        .collect();
    let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
    let root = tree.root();

    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof_for(idx).unwrap();
        assert!(
            proof.verify(&root).is_ok(),
            "canonical proof {idx} must self-verify"
        );

        let proof_entries: Vec<MerkleProofEntry> = proof
            .path
            .iter()
            .map(|(sibling_hash, is_right)| MerkleProofEntry {
                sibling_hash: *sibling_hash,
                sibling_is_left: *is_right,
            })
            .collect();

        let auth = ReceiptAuthentication::Pointer {
            receipt_hash: *leaf,
            authority_seal_hash: SEAL,
            merkle_inclusion_proof: Some(proof_entries),
            receipt_batch_root_hash: Some(root),
        };
        let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
        assert!(
            result.is_ok(),
            "leaf {idx} proof from 5-leaf canonical tree must verify through auth verifier"
        );
    }
}

#[test]
fn pointer_auth_from_canonical_merkle_tree_1000_leaves() {
    // Large odd-size tree: 1000 leaves. Rightmost leaves will have
    // EMPTY_HASH padding siblings.
    use crate::consensus::merkle::MerkleTree;
    use crate::crypto::EventHasher;

    let leaves: Vec<_> = (0..1000u64)
        .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
        .collect();
    let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
    let root = tree.root();

    // Verify a representative set including the rightmost leaf where
    // EMPTY_HASH padding occurs.
    let test_indices = [0, 1, 2, 498, 499, 500, 997, 998, 999];
    for &idx in &test_indices {
        let proof = tree.proof_for(idx).unwrap();
        assert!(
            proof.verify(&root).is_ok(),
            "canonical proof {idx} must self-verify"
        );

        let proof_entries: Vec<MerkleProofEntry> = proof
            .path
            .iter()
            .map(|(sibling_hash, is_right)| MerkleProofEntry {
                sibling_hash: *sibling_hash,
                sibling_is_left: *is_right,
            })
            .collect();

        let auth = ReceiptAuthentication::Pointer {
            receipt_hash: leaves[idx],
            authority_seal_hash: SEAL,
            merkle_inclusion_proof: Some(proof_entries),
            receipt_batch_root_hash: Some(root),
        };
        let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
        assert!(
            result.is_ok(),
            "leaf {idx} proof from 1000-leaf canonical tree must verify through auth verifier"
        );
    }
}

#[test]
fn pointer_auth_odd_tree_rightmost_leaf_has_empty_hash_sibling() {
    // Verify that the rightmost leaf in a 3-leaf tree actually produces an
    // EMPTY_HASH sibling and still verifies. This is the specific regression
    // scenario from the Quality BLOCKER.
    use crate::consensus::merkle::{EMPTY_HASH, MerkleTree};
    use crate::crypto::EventHasher;

    let leaves: Vec<_> = (0..3u64)
        .map(|i| EventHasher::hash_content(&i.to_le_bytes()))
        .collect();
    let tree = MerkleTree::new(leaves.iter().copied()).unwrap();
    let root = tree.root();

    // Leaf index 2 is the rightmost in a 3-leaf tree. Its sibling at
    // level 0 should be EMPTY_HASH (the padding value).
    let proof = tree.proof_for(2).unwrap();
    assert!(
        proof.path.iter().any(|(h, _)| *h == EMPTY_HASH),
        "rightmost leaf in odd tree must have EMPTY_HASH sibling as padding"
    );
    assert!(proof.verify(&root).is_ok());

    let proof_entries: Vec<MerkleProofEntry> = proof
        .path
        .iter()
        .map(|(sibling_hash, is_right)| MerkleProofEntry {
            sibling_hash: *sibling_hash,
            sibling_is_left: *is_right,
        })
        .collect();

    let auth = ReceiptAuthentication::Pointer {
        receipt_hash: leaves[2],
        authority_seal_hash: SEAL,
        merkle_inclusion_proof: Some(proof_entries),
        receipt_batch_root_hash: Some(root),
    };
    let result = verify_receipt_authentication(&auth, &SEAL, None, TIME_REF, LEDGER, TICK);
    assert!(
        result.is_ok(),
        "rightmost leaf with EMPTY_HASH padding sibling must verify through auth verifier"
    );
}
