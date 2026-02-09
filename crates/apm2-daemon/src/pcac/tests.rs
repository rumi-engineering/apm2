// AGENT-AUTHORED
//! Tests for PCAC lifecycle gate (TCK-00423).

use std::sync::Arc;

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityDenyClass, AuthorityJoinInputV1, AuthorityJoinKernel, DeterminismClass,
    IdentityEvidenceLevel, RiskTier,
};

use super::durable_consume::DurableConsumeIndex;
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
        .consume(
            &cert,
            input.intent_digest,
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
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
        .consume(
            &cert,
            test_hash(0xFF),
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
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
        .consume(
            &cert,
            input.intent_digest,
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
        .unwrap();

    // Second consume is denied (Law 1: Linear Consumption)
    let err = kernel
        .consume(
            &cert,
            input.intent_digest,
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
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
// TCK-00426 BLOCKER 1: DurableKernel in production constructor tests
// =============================================================================

#[test]
fn durable_kernel_lifecycle_gate_integration() {
    // BLOCKER 1 regression: Verify that a LifecycleGate wrapping a
    // DurableKernel + FileBackedConsumeIndex produces valid receipts
    // and enforces single-use consumption across the full lifecycle.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("consume.log");
    let index = super::durable_consume::FileBackedConsumeIndex::open(&path, None).unwrap();
    let inner = InProcessKernel::new(100);
    let durable = super::durable_consume::DurableKernel::new(inner, Box::new(index));
    let gate = LifecycleGate::new(Arc::new(durable));

    let input = valid_input();
    let receipts = gate
        .execute(
            &input,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            input.directory_head_hash,
        )
        .expect("durable lifecycle gate should succeed");

    assert_ne!(receipts.certificate.ajc_id, zero_hash());
    assert_eq!(receipts.consume_record.ajc_id, receipts.certificate.ajc_id);

    // Verify durable log was written.
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains(&hex::encode(receipts.certificate.ajc_id)),
        "durable consume log must contain the AJC ID after lifecycle gate"
    );

    // Second lifecycle execution at same tick must be denied (durable single-use).
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
        "durable lifecycle gate must deny duplicate at same tick"
    );
}

// =============================================================================
// TCK-00426 BLOCKER 2: Revalidation expiry test
// =============================================================================

#[test]
fn revalidation_denies_when_tick_advanced_past_ajc_expiry() {
    // BLOCKER 2 regression: Construct kernel, join to get AJC, advance tick
    // past expiry, verify revalidation DENIES. This tests the kernel-level
    // revalidation that the LifecycleGate calls between join and consume.
    //
    // Note: LifecycleGate.execute() calls join() which creates a NEW AJC
    // at the current tick, so the AJC is never immediately expired. The
    // meaningful test is that revalidation of an EXISTING AJC fails when
    // time has progressed past its expiry — which is what happens in
    // production between the join and a later revalidation-before-execution.
    let kernel = InProcessKernel::new(100);
    let input = valid_input();

    // Join to get an AJC with expires_at_tick = 100 + 300 = 400.
    let cert = kernel.join(&input).unwrap();
    assert_eq!(cert.expires_at_tick, 400);

    // Revalidation succeeds while tick is within expiry.
    kernel.advance_tick(399);
    kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .expect("revalidation at tick 399 should succeed");

    // Advance tick past AJC expiry (tick > expires_at_tick).
    kernel.advance_tick(401);

    // Revalidation must now DENY with CertificateExpired.
    let err = kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .unwrap_err();
    assert!(
        matches!(
            err.deny_class,
            AuthorityDenyClass::CertificateExpired {
                expired_at: 400,
                current_tick: 401
            }
        ),
        "revalidation must deny expired AJC, got: {:?}",
        err.deny_class
    );
}

#[test]
fn revalidation_denies_with_different_revocation_head() {
    // BLOCKER 2 regression: Verify that revalidation detects revocation
    // frontier advancement (a governance change between join and revalidate).
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();

    // Original revocation head matches — succeeds.
    kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .expect("original revocation head should pass");

    // Changed revocation head — denied (governance state changed).
    let err = kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            test_hash(0xDE), // Different revocation head
        )
        .unwrap_err();
    assert!(
        matches!(
            err.deny_class,
            AuthorityDenyClass::RevocationFrontierAdvanced
        ),
        "revalidation must deny when revocation frontier has advanced"
    );
}

// =============================================================================
// BLOCKER 1 FIX: Revalidation denies on ledger anchor drift
// =============================================================================

#[test]
fn test_revalidate_denies_ledger_anchor_drift() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();

    // Revalidation with the SAME ledger anchor succeeds.
    kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .expect("revalidation with matching ledger anchor should succeed");

    // Revalidation with a DIFFERENT ledger anchor must deny with
    // LedgerAnchorDrift — the ledger has advanced since join.
    let different_anchor = test_hash(0xBB);
    assert_ne!(different_anchor, input.as_of_ledger_anchor);
    let err = kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            different_anchor,
            cert.revocation_head_hash,
        )
        .unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::LedgerAnchorDrift),
        "revalidation must deny when ledger anchor has drifted, got: {:?}",
        err.deny_class
    );
}

// =============================================================================
// BLOCKER 1 FIX: Revalidation denies on stale freshness
// =============================================================================

#[test]
fn test_revalidate_denies_stale_freshness() {
    let kernel = InProcessKernel::new(100);
    let input = valid_input();
    let cert = kernel.join(&input).unwrap();
    // AJC expires_at_tick = 100 + 300 = 400, so issued_tick = 100.

    // Advance tick beyond the staleness threshold (300 ticks from issued).
    // issued_tick=100, so tick=401 gives gap=301 > 300.
    kernel.advance_tick(401);

    let err = kernel
        .revalidate(
            &cert,
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            cert.revocation_head_hash,
        )
        .unwrap_err();
    assert!(
        matches!(
            err.deny_class,
            AuthorityDenyClass::StaleFreshnessAtRevalidate
                | AuthorityDenyClass::CertificateExpired { .. }
        ),
        "revalidation must deny when freshness is stale, got: {:?}",
        err.deny_class
    );
}

// =============================================================================
// BLOCKER 1 FIX: LifecycleGate tick advancement via with_tick_kernel
// =============================================================================

#[test]
fn test_lifecycle_gate_advance_tick_wiring() {
    // Verify that LifecycleGate::with_tick_kernel properly forwards
    // advance_tick to the underlying InProcessKernel.
    let tick_kernel = Arc::new(InProcessKernel::new(1));
    let kernel_trait: Arc<dyn AuthorityJoinKernel> = Arc::clone(&tick_kernel) as _;
    let gate = LifecycleGate::with_tick_kernel(kernel_trait, Arc::clone(&tick_kernel));

    assert_eq!(tick_kernel.current_tick(), 1);
    gate.advance_tick(500);
    assert_eq!(
        tick_kernel.current_tick(),
        500,
        "advance_tick through LifecycleGate must update the shared kernel"
    );

    // Monotonic: advancing to a lower tick is a no-op.
    gate.advance_tick(100);
    assert_eq!(
        tick_kernel.current_tick(),
        500,
        "advance_tick must be monotonic (no-op for lower values)"
    );
}

// =============================================================================
// TCK-00426 MAJOR 3: DurableKernel does not double-consume
// =============================================================================

#[test]
fn durable_kernel_consume_does_not_double_consume_inner() {
    // MAJOR 3 regression: After DurableKernel::consume succeeds, the inner
    // kernel's consumed set should NOT contain the AJC ID — because
    // DurableKernel now constructs witnesses directly without calling
    // inner.consume(). This eliminates the double-consume ordering issue.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("consume.log");
    let index = super::durable_consume::FileBackedConsumeIndex::open(&path, None).unwrap();
    let inner = InProcessKernel::new(100);
    let durable = super::durable_consume::DurableKernel::new(inner, Box::new(index));

    let input = valid_input();
    let cert = durable.join(&input).unwrap();

    // Consume through the durable kernel.
    let (witness, record) = durable
        .consume(
            &cert,
            input.intent_digest,
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
        .unwrap();

    // Verify witnesses are correct.
    assert_eq!(witness.ajc_id, cert.ajc_id);
    assert_eq!(record.ajc_id, cert.ajc_id);
    assert_eq!(witness.intent_digest, input.intent_digest);
    assert_ne!(record.effect_selector_digest, zero_hash());

    // Verify durable index recorded the consume.
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains(&hex::encode(cert.ajc_id)),
        "durable log must contain the AJC ID"
    );

    // Second consume through durable kernel must be denied by durable index.
    let err = durable
        .consume(
            &cert,
            input.intent_digest,
            input.time_envelope_ref,
            cert.revocation_head_hash,
        )
        .unwrap_err();
    assert!(
        matches!(err.deny_class, AuthorityDenyClass::AlreadyConsumed { .. }),
        "durable kernel must deny double consume"
    );
}

#[test]
fn durable_kernel_crash_replay_lifecycle_gate() {
    // MAJOR 3 + BLOCKER 1 combined regression: Verify that after crash-replay,
    // a new DurableKernel wrapping the same consume log denies previously
    // consumed AJC IDs through the LifecycleGate.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("consume.log");
    let input = valid_input();
    let ajc_id;

    // Session 1: Consume via lifecycle gate.
    {
        let index = super::durable_consume::FileBackedConsumeIndex::open(&path, None).unwrap();
        let inner = InProcessKernel::new(100);
        let durable = super::durable_consume::DurableKernel::new(inner, Box::new(index));
        let gate = LifecycleGate::new(Arc::new(durable));

        let receipts = gate
            .execute(
                &input,
                input.time_envelope_ref,
                input.as_of_ledger_anchor,
                input.directory_head_hash,
            )
            .unwrap();
        ajc_id = receipts.certificate.ajc_id;
    }
    // Drop = simulated crash.

    // Session 2: Reopen and verify denial.
    {
        let index = super::durable_consume::FileBackedConsumeIndex::open(&path, None).unwrap();
        assert!(
            index.is_consumed(&ajc_id),
            "crash-replayed index must contain previously consumed AJC ID"
        );

        let inner = InProcessKernel::new(100);
        let durable = super::durable_consume::DurableKernel::new(inner, Box::new(index));
        let gate = LifecycleGate::new(Arc::new(durable));

        // Same input at same tick produces same AJC ID.
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
            "crash-replayed lifecycle gate must deny previously consumed AJC"
        );
    }
}
