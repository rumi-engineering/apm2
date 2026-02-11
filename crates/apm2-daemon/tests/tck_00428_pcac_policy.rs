//! TCK-00428: PCAC policy surface implementation and fail-closed defaults.
//!
//! Verifies:
//! - `PcacPolicyKnobs` struct has all required fields (lifecycle, evidence
//!   level, freshness, sovereignty).
//! - Default implementation provides fail-closed/strict settings.
//! - Unknown policy states result in denial (simulated via invalid inputs).
//! - Waiver validation enforces expiry and scope binding.

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    IdentityEvidenceLevel, PcacPolicyKnobs, PointerOnlyWaiver, SovereigntyEnforcementMode,
};

const fn test_hash(byte: u8) -> Hash {
    [byte; 32]
}

#[test]
fn tck_00428_policy_knobs_structure_and_defaults() {
    let policy = PcacPolicyKnobs::default();

    // Check default values enforce strict security posture
    assert!(
        policy.lifecycle_enforcement,
        "lifecycle_enforcement must default to true (enabled)"
    );
    assert_eq!(
        policy.min_tier2_identity_evidence,
        IdentityEvidenceLevel::Verified,
        "min_tier2_identity_evidence must default to Verified"
    );
    assert!(
        policy.freshness_max_age_ticks > 0,
        "freshness_max_age_ticks must be positive"
    );
    // TCK-00427 established strict mode as default for sovereignty
    assert_eq!(
        policy.tier2_sovereignty_mode,
        SovereigntyEnforcementMode::Strict,
        "tier2_sovereignty_mode must default to Strict"
    );
    assert!(
        policy.pointer_only_waiver.is_none(),
        "pointer_only_waiver must default to None"
    );
}

#[test]
fn tck_00428_policy_deserialization_rejects_unknown_fields() {
    // Ensure serde(deny_unknown_fields) is active
    let json = r#"{
        "lifecycle_enforcement": true,
        "min_tier2_identity_evidence": "verified",
        "freshness_max_age_ticks": 100,
        "tier2_sovereignty_mode": "strict",
        "unknown_field": "fail_closed"
    }"#;

    let result: Result<PcacPolicyKnobs, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "policy deserialization must reject unknown fields (fail-closed)"
    );
}

#[test]
fn tck_00428_waiver_validation_logic() {
    // Waiver valid logic is implemented in PointerOnlyWaiver::validate()
    let valid_waiver = PointerOnlyWaiver {
        waiver_id: "WVR-TEST-001".to_string(),
        expires_at_tick: 1000,
        scope_binding_hash: test_hash(0xAA),
    };
    assert!(valid_waiver.validate().is_ok());

    let invalid_id_waiver = PointerOnlyWaiver {
        waiver_id: String::new(),
        ..valid_waiver
    };
    assert!(
        invalid_id_waiver.validate().is_err(),
        "empty waiver_id must fail validation"
    );

    let expired_waiver = PointerOnlyWaiver {
        expires_at_tick: 0,
        ..valid_waiver.clone()
    };
    assert!(
        expired_waiver.validate().is_err(),
        "zero expiry tick must fail validation"
    );

    let zero_scope_waiver = PointerOnlyWaiver {
        scope_binding_hash: [0u8; 32],
        ..valid_waiver
    };
    assert!(
        zero_scope_waiver.validate().is_err(),
        "zero scope hash must fail validation"
    );
}
