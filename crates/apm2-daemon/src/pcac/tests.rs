// AGENT-AUTHORED
//! Tests for PCAC lifecycle gate (TCK-00423).

use std::sync::Arc;

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityDenyClass, AuthorityJoinInputV1, AuthorityJoinKernel, DeterminismClass,
    IdentityEvidenceLevel, RiskTier,
};

use super::lifecycle_gate::{InProcessKernel, LifecycleGate};

fn test_hash(byte: u8) -> Hash {
    [byte; 32]
}

fn zero_hash() -> Hash {
    [0u8; 32]
}

fn valid_input() -> AuthorityJoinInputV1 {
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
        risk_tier: RiskTier::Tier1,
        determinism_class: DeterminismClass::Deterministic,
        time_envelope_ref: test_hash(0x07),
        as_of_ledger_anchor: test_hash(0x08),
    }
}

// =============================================================================
// InProcessKernel join tests
// =============================================================================

#[test]
fn join_succeeds_with_valid_input() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).expect("join should succeed");

    assert_ne!(cert.ajc_id, zero_hash());
    assert_ne!(cert.authority_join_hash, zero_hash());
    assert_eq!(cert.intent_digest, input.intent_digest);
    assert_eq!(cert.risk_tier, RiskTier::Tier1);
    assert_eq!(cert.issued_time_envelope_ref, input.time_envelope_ref);
    assert_eq!(cert.as_of_ledger_anchor, input.as_of_ledger_anchor);
    assert!(cert.expires_at_tick > 100);
}

#[test]
fn join_denies_empty_session_id() {
    let kernel = InProcessKernel::new(100);
    let mut input = valid_input();
    input.session_id = String::new();

    let err = kernel.join(&input).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::InvalidSessionId
    ));
}

#[test]
fn join_denies_empty_lease_id() {
    let kernel = InProcessKernel::new(100);
    let mut input = valid_input();
    input.lease_id = String::new();

    let err = kernel.join(&input).unwrap_err();
    assert!(matches!(err.deny_class, AuthorityDenyClass::InvalidLeaseId));
}

#[test]
fn join_denies_zero_intent_digest() {
    let kernel = InProcessKernel::new(100);
    let mut input = valid_input();
    input.intent_digest = zero_hash();

    let err = kernel.join(&input).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "intent_digest"
    ));
}

#[test]
fn join_denies_zero_identity_proof() {
    let kernel = InProcessKernel::new(100);
    let mut input = valid_input();
    input.identity_proof_hash = zero_hash();

    let err = kernel.join(&input).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::ZeroHash { ref field_name } if field_name == "identity_proof_hash"
    ));
}

#[test]
fn join_denies_stale_freshness() {
    let kernel = InProcessKernel::new(100);
    let mut input = valid_input();
    input.freshness_witness_tick = 0;

    let err = kernel.join(&input).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::StaleFreshnessAtJoin
    ));
}

#[test]
fn join_denies_pointer_only_at_tier2plus() {
    let kernel = InProcessKernel::new(100);
    let mut input = valid_input();
    input.risk_tier = RiskTier::Tier2Plus;
    input.identity_evidence_level = IdentityEvidenceLevel::PointerOnly;

    let err = kernel.join(&input).unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::PointerOnlyDeniedAtTier2Plus
    ));
}

// =============================================================================
// InProcessKernel revalidate tests
// =============================================================================

#[test]
fn revalidate_succeeds_with_valid_state() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();

    let result = kernel.revalidate(
        &cert,
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        cert.revocation_head_hash,
    );
    assert!(result.is_ok());
}

#[test]
fn revalidate_denies_expired_certificate() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();

    // Advance tick past expiry
    kernel.advance_tick(cert.expires_at_tick + 1);

    let err = kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::CertificateExpired { .. }
    ));
}

#[test]
fn revalidate_denies_revocation_frontier_advanced() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();

    let err = kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            test_hash(0xFF), // Different revocation head
        )
        .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::RevocationFrontierAdvanced
    ));
}

// =============================================================================
// InProcessKernel consume tests
// =============================================================================

#[test]
fn consume_succeeds_with_matching_intent() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();

    let (witness, record) = kernel
        .consume(&cert, input.intent_digest, input.time_envelope_ref)
        .unwrap();
    assert_eq!(witness.ajc_id, cert.ajc_id);
    assert_eq!(record.ajc_id, cert.ajc_id);
    assert_ne!(record.effect_selector_digest, zero_hash());
}

#[test]
fn consume_denies_intent_mismatch() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();

    let err = kernel
        .consume(&cert, test_hash(0xFF), input.time_envelope_ref)
        .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::IntentDigestMismatch { .. }
    ));
}

#[test]
fn consume_denies_double_consume() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();

    // First consume succeeds
    kernel
        .consume(&cert, input.intent_digest, input.time_envelope_ref)
        .unwrap();

    // Second consume is denied (Law 1: Linear Consumption)
    let err = kernel
        .consume(&cert, input.intent_digest, input.time_envelope_ref)
        .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::AlreadyConsumed { .. }
    ));
}

// =============================================================================
// LifecycleGate tests
// =============================================================================

#[test]
fn lifecycle_gate_succeeds_full_sequence() {
    let kernel = Arc::new(InProcessKernel::new(100));
    let gate = LifecycleGate::new(kernel);
    let input = valid_input();

    let receipts = gate
        .execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash, // Revocation head matches
        )
        .expect("full lifecycle should succeed");

    assert_ne!(receipts.certificate.ajc_id, zero_hash());
    assert_eq!(receipts.certificate.intent_digest, input.intent_digest);
    assert_eq!(receipts.consume_record.ajc_id, receipts.certificate.ajc_id);
    assert_eq!(
        receipts.consumed_witness.ajc_id,
        receipts.certificate.ajc_id
    );
}

#[test]
fn lifecycle_gate_denies_at_join_stage() {
    let kernel = Arc::new(InProcessKernel::new(100));
    let gate = LifecycleGate::new(kernel);
    let mut input = valid_input();
    input.session_id = String::new();

    let err = gate
        .execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
        )
        .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::InvalidSessionId
    ));
}

#[test]
fn lifecycle_gate_denies_at_revalidate_stage() {
    let kernel = Arc::new(InProcessKernel::new(100));
    let gate = LifecycleGate::new(kernel);
    let input = valid_input();

    // Use a different revocation head to trigger revalidation failure.
    let err = gate
        .execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            test_hash(0xFF), // Changed revocation head
        )
        .unwrap_err();
    assert!(matches!(
        err.deny_class,
        AuthorityDenyClass::RevocationFrontierAdvanced
    ));
}

#[test]
fn lifecycle_gate_prevents_effect_without_consume() {
    // Verify that same-tick replay of the same input is denied (Law 1).
    let kernel = Arc::new(InProcessKernel::new(100));
    let kernel_trait: Arc<dyn AuthorityJoinKernel> = Arc::clone(&kernel) as _;
    let gate = LifecycleGate::new(kernel_trait);
    let input = valid_input();

    // First execution succeeds.
    gate.execute(
        &input,
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        input.directory_head_hash,
    )
    .unwrap();

    // Same input at same tick produces same AJC ID -> AlreadyConsumed.
    let err = gate
        .execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
        )
        .unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::AlreadyConsumed { .. }),
        "same-tick replay must be denied"
    );

    // Advancing the tick produces a distinct AJC ID, so a new lifecycle
    // execution succeeds independently.
    kernel.advance_tick(101);
    let result = gate.execute(
        &input,
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        input.directory_head_hash,
    );
    assert!(
        result.is_ok(),
        "distinct-tick lifecycle should produce new AJC"
    );
}

#[test]
fn no_side_effect_without_successful_consume() {
    // Integration test: Verify that the gate returns an error if any stage
    // fails, meaning no lifecycle receipts are available and therefore no
    // side effect should execute.
    let kernel = Arc::new(InProcessKernel::new(100));
    let gate = LifecycleGate::new(kernel);

    // Zero intent digest -> join denial
    let mut input = valid_input();
    input.intent_digest = zero_hash();
    assert!(
        gate.execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
        )
        .is_err()
    );

    // Zero time envelope ref -> join denial
    let mut input = valid_input();
    input.time_envelope_ref = zero_hash();
    assert!(
        gate.execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
        )
        .is_err()
    );

    // Zero ledger anchor -> join denial
    let mut input = valid_input();
    input.as_of_ledger_anchor = zero_hash();
    assert!(
        gate.execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
        )
        .is_err()
    );
}

// =============================================================================
// Replay ordering tests (Law 6: Boundary Monotonicity)
// =============================================================================

#[test]
fn lifecycle_receipts_have_monotonic_ticks() {
    let kernel = Arc::new(InProcessKernel::new(100));
    let gate = LifecycleGate::new(kernel);
    let input = valid_input();

    let receipts = gate
        .execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
        )
        .unwrap();

    // consume_at_tick >= current kernel tick (boundary monotonicity)
    assert!(receipts.consume_record.consumed_at_tick >= 100);
}

// =============================================================================
// Pre-actuation receipt prerequisite tests
// =============================================================================

#[test]
fn pre_actuation_receipt_binding() {
    // When pre_actuation_receipt_hashes are present in the input,
    // the kernel still succeeds (Phase 1 does not enforce mandatory
    // pre-actuation — that's TCK-00424). This test verifies the
    // field is accepted without error.
    let kernel = Arc::new(InProcessKernel::new(100));
    let gate = LifecycleGate::new(kernel);
    let mut input = valid_input();
    input.pre_actuation_receipt_hashes = vec![test_hash(0xA0), test_hash(0xA1)];

    let result = gate.execute(
        &input,
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        input.directory_head_hash,
    );
    assert!(result.is_ok());
}

// =============================================================================
// TCK-00427: Sovereignty integration in LifecycleGate
// =============================================================================

#[test]
fn lifecycle_gate_with_sovereignty_passes_tier2_valid_state() {
    use apm2_core::pcac::{AutonomyCeiling, FreezeAction, SovereigntyEpoch};

    use super::sovereignty::{SovereigntyChecker, SovereigntyState};

    let kernel = Arc::new(InProcessKernel::new(100));
    let checker = SovereigntyChecker::new();
    let gate = LifecycleGate::with_sovereignty_checker(kernel, checker);

    let mut input = valid_input();
    input.risk_tier = RiskTier::Tier2Plus;

    let sov_state = SovereigntyState {
        epoch: Some(SovereigntyEpoch {
            epoch_id: "epoch-001".to_string(),
            freshness_tick: 100,
            signature: test_hash(0xCC),
        }),
        principal_id: "principal-001".to_string(),
        revocation_head_known: true,
        autonomy_ceiling: Some(AutonomyCeiling {
            max_risk_tier: RiskTier::Tier2Plus,
            policy_binding_hash: test_hash(0xDD),
        }),
        active_freeze: FreezeAction::NoAction,
    };

    let result = gate.execute_with_sovereignty(
        &input,
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        input.directory_head_hash,
        Some(&sov_state),
        100,
    );
    assert!(
        result.is_ok(),
        "Tier2+ with valid sovereignty state should pass"
    );
}

#[test]
fn lifecycle_gate_with_sovereignty_denies_tier2_stale_epoch() {
    use apm2_core::pcac::{AutonomyCeiling, FreezeAction, SovereigntyEpoch};

    use super::sovereignty::{SovereigntyChecker, SovereigntyState};

    let kernel = Arc::new(InProcessKernel::new(100));
    let checker = SovereigntyChecker::with_staleness_threshold(50);
    let gate = LifecycleGate::with_sovereignty_checker(kernel, checker);

    let mut input = valid_input();
    input.risk_tier = RiskTier::Tier2Plus;

    let sov_state = SovereigntyState {
        epoch: Some(SovereigntyEpoch {
            epoch_id: "epoch-001".to_string(),
            freshness_tick: 10, // Very stale
            signature: test_hash(0xCC),
        }),
        principal_id: "principal-001".to_string(),
        revocation_head_known: true,
        autonomy_ceiling: Some(AutonomyCeiling {
            max_risk_tier: RiskTier::Tier2Plus,
            policy_binding_hash: test_hash(0xDD),
        }),
        active_freeze: FreezeAction::NoAction,
    };

    let err = gate
        .execute_with_sovereignty(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
            Some(&sov_state),
            200, // tick 200, epoch at 10 -> drift 190 > threshold 50
        )
        .unwrap_err();
    assert!(
        matches!(
            err.deny_class,
            AuthorityDenyClass::StaleSovereigntyEpoch { .. }
        ),
        "Tier2+ with stale epoch should be denied"
    );
}

#[test]
fn lifecycle_gate_with_sovereignty_denies_tier2_frozen() {
    use apm2_core::pcac::{AutonomyCeiling, FreezeAction, SovereigntyEpoch};

    use super::sovereignty::{SovereigntyChecker, SovereigntyState};

    let kernel = Arc::new(InProcessKernel::new(100));
    let checker = SovereigntyChecker::new();
    let gate = LifecycleGate::with_sovereignty_checker(kernel, checker);

    let mut input = valid_input();
    input.risk_tier = RiskTier::Tier2Plus;

    let sov_state = SovereigntyState {
        epoch: Some(SovereigntyEpoch {
            epoch_id: "epoch-001".to_string(),
            freshness_tick: 100,
            signature: test_hash(0xCC),
        }),
        principal_id: "principal-001".to_string(),
        revocation_head_known: true,
        autonomy_ceiling: Some(AutonomyCeiling {
            max_risk_tier: RiskTier::Tier2Plus,
            policy_binding_hash: test_hash(0xDD),
        }),
        active_freeze: FreezeAction::HardFreeze,
    };

    let err = gate
        .execute_with_sovereignty(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
            Some(&sov_state),
            100,
        )
        .unwrap_err();
    assert!(
        matches!(
            err.deny_class,
            AuthorityDenyClass::ActiveSovereignFreeze { .. }
        ),
        "Tier2+ with active freeze should be denied"
    );
}

#[test]
fn lifecycle_gate_with_sovereignty_tier1_bypasses_bad_state() {
    use apm2_core::pcac::FreezeAction;

    use super::sovereignty::{SovereigntyChecker, SovereigntyState};

    let kernel = Arc::new(InProcessKernel::new(100));
    let checker = SovereigntyChecker::new();
    let gate = LifecycleGate::with_sovereignty_checker(kernel, checker);

    let input = valid_input(); // risk_tier is Tier1

    // Completely invalid sovereignty state.
    let sov_state = SovereigntyState {
        epoch: None,
        principal_id: String::new(),
        revocation_head_known: false,
        autonomy_ceiling: None,
        active_freeze: FreezeAction::HardFreeze,
    };

    let result = gate.execute_with_sovereignty(
        &input,
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        input.directory_head_hash,
        Some(&sov_state),
        200,
    );
    assert!(
        result.is_ok(),
        "Tier1 should bypass all sovereignty checks even with bad state"
    );
}

#[test]
fn lifecycle_gate_without_sovereignty_state_passes_tier2() {
    use super::sovereignty::SovereigntyChecker;

    let kernel = Arc::new(InProcessKernel::new(100));
    let checker = SovereigntyChecker::new();
    let gate = LifecycleGate::with_sovereignty_checker(kernel, checker);

    let mut input = valid_input();
    input.risk_tier = RiskTier::Tier2Plus;

    // No sovereignty state provided -- checker is configured but state
    // is None, so sovereignty checks are skipped.
    let result = gate.execute_with_sovereignty(
        &input,
        input.time_envelope_ref,
        input.as_of_ledger_anchor,
        input.directory_head_hash,
        None,
        100,
    );
    assert!(
        result.is_ok(),
        "Tier2+ without sovereignty state should pass (sovereignty not yet populated)"
    );
}

#[test]
fn lifecycle_gate_with_sovereignty_denies_incompatible_ceiling() {
    use apm2_core::pcac::{AutonomyCeiling, FreezeAction, SovereigntyEpoch};

    use super::sovereignty::{SovereigntyChecker, SovereigntyState};

    let kernel = Arc::new(InProcessKernel::new(100));
    let checker = SovereigntyChecker::new();
    let gate = LifecycleGate::with_sovereignty_checker(kernel, checker);

    let mut input = valid_input();
    input.risk_tier = RiskTier::Tier2Plus;

    // Ceiling allows only Tier1, but request is Tier2Plus.
    let sov_state = SovereigntyState {
        epoch: Some(SovereigntyEpoch {
            epoch_id: "epoch-001".to_string(),
            freshness_tick: 100,
            signature: test_hash(0xCC),
        }),
        principal_id: "principal-001".to_string(),
        revocation_head_known: true,
        autonomy_ceiling: Some(AutonomyCeiling {
            max_risk_tier: RiskTier::Tier1, // Too low for Tier2Plus
            policy_binding_hash: test_hash(0xDD),
        }),
        active_freeze: FreezeAction::NoAction,
    };

    let err = gate
        .execute_with_sovereignty(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
            Some(&sov_state),
            100,
        )
        .unwrap_err();
    assert!(
        matches!(
            err.deny_class,
            AuthorityDenyClass::IncompatibleAutonomyCeiling { .. }
        ),
        "Tier2+ with ceiling at Tier1 should be denied"
    );
}

// =============================================================================
// TCK-00427 MAJOR 2: compute_join_hash covers all normative fields
// =============================================================================

#[test]
fn compute_join_hash_changes_on_scope_witness() {
    let kernel = Arc::new(InProcessKernel::new(100));

    let input_a = valid_input();
    let mut input_b = valid_input();
    input_b.scope_witness_hashes = vec![test_hash(0xF0)];

    let cert_a = kernel.join(&input_a).unwrap();
    let cert_b = kernel.join(&input_b).unwrap();

    assert_ne!(
        cert_a.authority_join_hash, cert_b.authority_join_hash,
        "Adding scope witness hash must change the join hash"
    );
}

#[test]
fn compute_join_hash_changes_on_freshness_policy() {
    let kernel = Arc::new(InProcessKernel::new(100));

    let input_a = valid_input();
    let mut input_b = valid_input();
    input_b.freshness_policy_hash = test_hash(0xF1);

    let cert_a = kernel.join(&input_a).unwrap();
    let cert_b = kernel.join(&input_b).unwrap();

    assert_ne!(
        cert_a.authority_join_hash, cert_b.authority_join_hash,
        "Changing freshness_policy_hash must change the join hash"
    );
}

#[test]
fn compute_join_hash_changes_on_risk_tier() {
    let kernel = Arc::new(InProcessKernel::new(100));

    let mut input_a = valid_input();
    input_a.risk_tier = RiskTier::Tier0;
    let mut input_b = valid_input();
    input_b.risk_tier = RiskTier::Tier1;

    let cert_a = kernel.join(&input_a).unwrap();
    let cert_b = kernel.join(&input_b).unwrap();

    assert_ne!(
        cert_a.authority_join_hash, cert_b.authority_join_hash,
        "Changing risk_tier must change the join hash"
    );
}

#[test]
fn compute_join_hash_changes_on_stop_budget_digest() {
    let kernel = Arc::new(InProcessKernel::new(100));

    let input_a = valid_input();
    let mut input_b = valid_input();
    input_b.stop_budget_profile_digest = test_hash(0xF2);

    let cert_a = kernel.join(&input_a).unwrap();
    let cert_b = kernel.join(&input_b).unwrap();

    assert_ne!(
        cert_a.authority_join_hash, cert_b.authority_join_hash,
        "Changing stop_budget_profile_digest must change the join hash"
    );
}

#[test]
fn compute_join_hash_changes_on_freshness_tick() {
    let kernel = Arc::new(InProcessKernel::new(100));

    let input_a = valid_input();
    let mut input_b = valid_input();
    input_b.freshness_witness_tick = 9999;

    let cert_a = kernel.join(&input_a).unwrap();
    let cert_b = kernel.join(&input_b).unwrap();

    assert_ne!(
        cert_a.authority_join_hash, cert_b.authority_join_hash,
        "Changing freshness_witness_tick must change the join hash"
    );
}
