// AGENT-AUTHORED (TCK-00388)
//! TCK-00388: Gate execution orchestrator integration tests.
//!
//! This test module verifies the gate orchestrator's runtime wiring by
//! exercising the real `GateOrchestrator` entrypoints, including:
//!
//! - Full lifecycle: changeset publication -> policy resolution -> lease
//!   issuance -> receipt collection -> all-gates-completed
//! - Per-invocation event return (no global buffer)
//! - Event ordering invariant (`PolicyResolved` before `GateLeaseIssued`)
//! - Receipt signature verification (BLOCKER 4)
//! - Admission check before events (BLOCKER 2)
//! - Lifecycle-only timeout progression via `poll_session_lifecycle`
//! - Fail-closed timeout semantics
//!
//! # Verification Commands
//!
//! - IT-00388-01: `cargo test -p apm2-daemon
//!   tck_00388_full_lifecycle_through_daemon_entry_point`
//! - IT-00388-02: `cargo test -p apm2-daemon
//!   tck_00388_event_ordering_invariant`
//! - IT-00388-03: `cargo test -p apm2-daemon
//!   tck_00388_receipt_signature_verified`
//! - IT-00388-04: `cargo test -p apm2-daemon
//!   tck_00388_admission_check_before_events`
//! - IT-00388-05: `cargo test -p apm2-daemon
//!   tck_00388_fail_closed_timeout_semantics`
//!
//! # Security Properties
//!
//! Per RFC-0018 and the ticket notes:
//! - Events only emitted after successful admission (no orphaned events)
//! - Receipt signatures verified against executor verifying key
//! - Fail-closed: timeouts produce FAIL verdicts, never silent expiry
//! - Policy resolution always precedes lease issuance
//! - Session termination does not bootstrap gate start

use std::sync::Arc;

use apm2_core::crypto::Signer;
use apm2_core::fac::{ChangesetPublication, GateReceiptBuilder};
use apm2_daemon::gate::{
    GateOrchestrator, GateOrchestratorConfig, GateOrchestratorError, GateOrchestratorEvent,
    GateType,
};
use apm2_daemon::state::DispatcherState;

/// Helper: creates a test `ChangesetPublication`.
fn test_publication(work_id: &str, digest: [u8; 32]) -> ChangesetPublication {
    ChangesetPublication {
        work_id: work_id.to_string(),
        changeset_digest: digest,
        bundle_cas_hash: [0xA5; 32],
        published_at_ms: 1_706_000_000,
        publisher_actor_id: "actor:publisher".to_string(),
        changeset_published_event_id: format!("evt-{work_id}"),
    }
}

// =========================================================================
// IT-00388-01: Full lifecycle through daemon entry point
// =========================================================================

#[tokio::test]
async fn tck_00388_full_lifecycle_through_daemon_entry_point() {
    let signer = Arc::new(Signer::generate());
    let config = GateOrchestratorConfig::default();
    let orch = GateOrchestrator::new(config, Arc::clone(&signer));

    // Step 1: Authoritative changeset publication starts orchestration.
    let (gate_types, executor_signers, setup_events) = orch
        .start_for_changeset(test_publication("work-integ-01", [0x42; 32]))
        .await
        .unwrap();

    assert_eq!(gate_types.len(), 3, "should issue 3 gate types");
    assert_eq!(
        setup_events.len(),
        4,
        "1 PolicyResolved + 3 GateLeaseIssued"
    );

    // Step 2: Record executor spawned for each gate
    for &gt in &gate_types {
        let spawn_events = orch
            .record_executor_spawned("work-integ-01", gt, &format!("ep-{gt}"))
            .await
            .unwrap();
        assert_eq!(spawn_events.len(), 1);
        assert!(matches!(
            spawn_events[0],
            GateOrchestratorEvent::GateExecutorSpawned { .. }
        ));
    }

    // Step 3: Record receipts for each gate (signed with executor signers)
    let mut all_events = Vec::new();
    for gt in GateType::all() {
        let lease = orch.gate_lease("work-integ-01", gt).await.unwrap();
        let exec_signer = &executor_signers[&gt];
        let receipt = GateReceiptBuilder::new(
            format!("receipt-{}", gt.as_gate_id()),
            gt.as_gate_id(),
            &lease.lease_id,
        )
        .changeset_digest([0x42; 32])
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind(gt.payload_kind())
        .payload_schema_version(1)
        .payload_hash([0xBB; 32])
        .evidence_bundle_hash([0xCC; 32])
        .passed(true)
        .build_and_sign(exec_signer);

        let (outcomes, events) = orch
            .record_gate_receipt("work-integ-01", gt, receipt)
            .await
            .unwrap();
        all_events.extend(events);

        if gt == *GateType::all().last().unwrap() {
            // Last gate should trigger AllGatesCompleted
            let outcomes = outcomes.expect("last gate should produce outcomes");
            assert_eq!(outcomes.len(), 3);
            assert!(outcomes.iter().all(|o| o.passed));
        }
    }

    // Verify we got receipt events and AllGatesCompleted
    let receipt_count = all_events
        .iter()
        .filter(|e| matches!(e, GateOrchestratorEvent::GateReceiptCollected { .. }))
        .count();
    assert_eq!(receipt_count, 3);

    let completed_count = all_events
        .iter()
        .filter(|e| matches!(e, GateOrchestratorEvent::AllGatesCompleted { .. }))
        .count();
    assert_eq!(completed_count, 1);
}

// =========================================================================
// IT-00388-02: Event ordering invariant
// =========================================================================

#[tokio::test]
async fn tck_00388_event_ordering_invariant() {
    let signer = Arc::new(Signer::generate());
    let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));

    let (_gate_types, _signers, events) = orch
        .start_for_changeset(test_publication("work-integ-02", [0x42; 32]))
        .await
        .unwrap();

    // ORDERING INVARIANT: PolicyResolved MUST be first
    assert!(
        matches!(events[0], GateOrchestratorEvent::PolicyResolved { .. }),
        "First event must be PolicyResolved, got {:?}",
        events[0]
    );

    // All subsequent events must be GateLeaseIssued
    for (i, event) in events.iter().enumerate().skip(1) {
        assert!(
            matches!(event, GateOrchestratorEvent::GateLeaseIssued { .. }),
            "Event at index {i} should be GateLeaseIssued, got {event:?}"
        );
    }
}

// =========================================================================
// IT-00388-03: Receipt signature verification
// =========================================================================

#[tokio::test]
async fn tck_00388_receipt_signature_verified() {
    let signer = Arc::new(Signer::generate());
    let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));

    let (_gate_types, executor_signers, _events) = orch
        .start_for_changeset(test_publication("work-integ-03", [0x42; 32]))
        .await
        .unwrap();

    let lease = orch
        .gate_lease("work-integ-03", GateType::Quality)
        .await
        .unwrap();

    // Sign with wrong key -> should be rejected
    let wrong_signer = Signer::generate();
    let bad_receipt = GateReceiptBuilder::new("receipt-bad", "gate-quality", &lease.lease_id)
        .changeset_digest([0x42; 32])
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind("quality")
        .payload_schema_version(1)
        .payload_hash([0xBB; 32])
        .evidence_bundle_hash([0xCC; 32])
        .passed(true)
        .build_and_sign(&wrong_signer);

    let err = orch
        .record_gate_receipt("work-integ-03", GateType::Quality, bad_receipt)
        .await
        .unwrap_err();

    assert!(
        matches!(&err, GateOrchestratorError::ReceiptBindingMismatch { reason, .. } if reason.contains("signature")),
        "Expected signature verification failure, got: {err:?}"
    );

    // Sign with correct executor-bound key -> should succeed
    let exec_signer = &executor_signers[&GateType::Quality];
    let good_receipt = GateReceiptBuilder::new("receipt-good", "gate-quality", &lease.lease_id)
        .changeset_digest([0x42; 32])
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind("quality")
        .payload_schema_version(1)
        .payload_hash([0xBB; 32])
        .evidence_bundle_hash([0xCC; 32])
        .passed(true)
        .build_and_sign(exec_signer);

    let result = orch
        .record_gate_receipt("work-integ-03", GateType::Quality, good_receipt)
        .await;
    assert!(result.is_ok(), "Correctly signed receipt should succeed");
}

// =========================================================================
// IT-00388-04: Admission check before events (BLOCKER 2)
// =========================================================================

#[tokio::test]
async fn tck_00388_admission_check_before_events() {
    let signer = Arc::new(Signer::generate());
    let config = GateOrchestratorConfig {
        max_concurrent_orchestrations: 1,
        ..Default::default()
    };
    let orch = GateOrchestrator::new(config, Arc::clone(&signer));

    // First orchestration succeeds
    let (_gate_types, _signers, events) = orch
        .start_for_changeset(test_publication("work-integ-04a", [0x44; 32]))
        .await
        .unwrap();
    assert!(!events.is_empty(), "First orchestration should emit events");

    // Second orchestration fails due to capacity - no events should leak
    let result = orch
        .start_for_changeset(test_publication("work-integ-04b", [0x45; 32]))
        .await;
    assert!(result.is_err(), "Expected capacity error");
    let err = result.err().unwrap();
    assert!(
        matches!(err, GateOrchestratorError::MaxOrchestrationsExceeded { .. }),
        "Expected capacity error"
    );

    // Duplicate orchestration fails too (separate test with higher capacity
    // so the duplicate check is exercised rather than capacity check).
    let config2 = GateOrchestratorConfig {
        max_concurrent_orchestrations: 10,
        ..Default::default()
    };
    let orch2 = GateOrchestrator::new(config2, Arc::clone(&signer));

    orch2
        .start_for_changeset(test_publication("work-integ-04c", [0x46; 32]))
        .await
        .unwrap();

    // Same (work_id, digest) is idempotent no-op.
    let no_op_result = orch2
        .start_for_changeset(test_publication("work-integ-04c", [0x46; 32]))
        .await;
    assert!(
        no_op_result.is_ok(),
        "duplicate publication should be idempotent no-op"
    );
    let (gate_types, signers, events) = no_op_result.expect("duplicate should be no-op");
    assert!(gate_types.is_empty(), "no-op should not issue gates");
    assert!(
        signers.is_empty(),
        "no-op should not return executor signers"
    );
    assert!(events.is_empty(), "no-op should not emit events");

    // CSID-003: Same work_id with a different digest while active is ALLOWED
    // (different changeset orchestrations can run concurrently for the same work).
    let different_digest_result = orch2
        .start_for_changeset(test_publication("work-integ-04c", [0x47; 32]))
        .await;
    assert!(
        different_digest_result.is_ok(),
        "same work_id with different digest should be allowed (CSID-003)"
    );
}

// =========================================================================
// IT-00388-05: Fail-closed timeout semantics
// =========================================================================

#[tokio::test]
async fn tck_00388_fail_closed_timeout_semantics() {
    let signer = Arc::new(Signer::generate());
    let config = GateOrchestratorConfig {
        gate_timeout_ms: 0, // Instant timeout
        ..Default::default()
    };
    let orch = GateOrchestrator::new(config, Arc::clone(&signer));

    let (gate_types, _signers, _events) = orch
        .start_for_changeset(test_publication("work-integ-05", [0x42; 32]))
        .await
        .unwrap();

    assert_eq!(gate_types.len(), 3);

    // Lifecycle polling advances timeout progression but never bootstraps gates.
    let events = orch.poll_session_lifecycle().await;

    // All 3 gates should have timed out (instant timeout)
    let timeout_count = events
        .iter()
        .filter(|e| matches!(e, GateOrchestratorEvent::GateTimedOut { .. }))
        .count();
    assert_eq!(timeout_count, 3, "All 3 gates should have timed out");

    // Should also have AllGatesCompleted with all_passed=false
    let completed_count = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                GateOrchestratorEvent::AllGatesCompleted {
                    all_passed: false,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        completed_count, 1,
        "Should have AllGatesCompleted with all_passed=false"
    );
}

// =========================================================================
// IT-00388-06: DispatcherState wiring (Quality BLOCKER 4 fix)
// =========================================================================

#[tokio::test]
async fn tck_00388_dispatcher_state_wiring() {
    let signer = Arc::new(Signer::generate());
    let config = GateOrchestratorConfig::default();
    let orch = Arc::new(GateOrchestrator::new(config, signer));

    // Wire the orchestrator into DispatcherState
    let dispatcher = DispatcherState::new(None).with_gate_orchestrator(Arc::clone(&orch));

    // Verify the orchestrator is accessible
    assert!(
        dispatcher.gate_orchestrator().is_some(),
        "gate_orchestrator should be present after with_gate_orchestrator"
    );

    // Poll lifecycle through the dispatcher.
    let events = dispatcher
        .poll_gate_lifecycle()
        .await
        .expect("should return Some when orchestrator is wired");

    // Session termination is lifecycle-only and MUST NOT start gates.
    assert!(
        events.is_empty(),
        "no gate bootstrap from session termination"
    );
    assert_eq!(
        orch.active_count().await,
        0,
        "session lifecycle hook must not create orchestration"
    );
}

#[tokio::test]
async fn tck_00388_dispatcher_state_without_orchestrator() {
    // Without gate orchestrator, lifecycle polling returns None.
    let dispatcher = DispatcherState::new(None);

    assert!(
        dispatcher.gate_orchestrator().is_none(),
        "gate_orchestrator should be None by default"
    );

    let result = dispatcher.poll_gate_lifecycle().await;
    assert!(
        result.is_none(),
        "should return None when no orchestrator is wired"
    );
}
