// AGENT-AUTHORED (TCK-00388)
//! TCK-00388: Gate execution orchestrator integration tests.
//!
//! This test module verifies the gate orchestrator's runtime wiring by
//! exercising the real `GateOrchestrator` through its daemon entry point
//! (`handle_session_terminated`), including:
//!
//! - Full lifecycle: session termination -> policy resolution -> lease issuance
//!   -> receipt collection -> all-gates-completed
//! - Per-invocation event return (no global buffer)
//! - Event ordering invariant (`PolicyResolved` before `GateLeaseIssued`)
//! - Receipt signature verification (BLOCKER 4)
//! - Admission check before events (BLOCKER 2)
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

use std::sync::Arc;

use apm2_core::crypto::Signer;
use apm2_core::fac::GateReceiptBuilder;
use apm2_daemon::gate::{
    GateOrchestrator, GateOrchestratorConfig, GateOrchestratorError, GateOrchestratorEvent,
    GateType, SessionTerminatedInfo,
};
use apm2_daemon::state::DispatcherState;

/// Helper: creates a test `SessionTerminatedInfo`.
///
/// Uses `terminated_at_ms: 0` to bypass freshness checks in tests.
fn test_session_info(work_id: &str) -> SessionTerminatedInfo {
    SessionTerminatedInfo {
        session_id: format!("session-{work_id}"),
        work_id: work_id.to_string(),
        changeset_digest: [0x42; 32],
        terminated_at_ms: 0,
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

    // Step 1: Session terminates via daemon entry point
    let (gate_types, executor_signers, setup_events) = orch
        .handle_session_terminated(test_session_info("work-integ-01"))
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
        .handle_session_terminated(test_session_info("work-integ-02"))
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
        .handle_session_terminated(test_session_info("work-integ-03"))
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
        .handle_session_terminated(test_session_info("work-integ-04a"))
        .await
        .unwrap();
    assert!(!events.is_empty(), "First orchestration should emit events");

    // Second orchestration fails due to capacity - no events should leak
    let result = orch
        .handle_session_terminated(test_session_info("work-integ-04b"))
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
        .handle_session_terminated(test_session_info("work-integ-04c"))
        .await
        .unwrap();

    let result = orch2
        .handle_session_terminated(test_session_info("work-integ-04c"))
        .await;
    assert!(result.is_err(), "Expected replay/duplicate error");
    let err = result.err().unwrap();
    assert!(
        matches!(err, GateOrchestratorError::ReplayDetected { .. }),
        "Expected ReplayDetected error, got: {err:?}"
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

    let (gate_types, _signers, mut events) = orch
        .handle_session_terminated(test_session_info("work-integ-05"))
        .await
        .unwrap();

    assert_eq!(gate_types.len(), 3);

    // Run timeout sweep explicitly via the canonical lifecycle APIs.
    for (work_id, gate_type) in orch.check_timeouts().await {
        if work_id == "work-integ-05" {
            let (_outcomes, timeout_events) =
                orch.handle_gate_timeout(&work_id, gate_type).await.unwrap();
            events.extend(timeout_events);
        }
    }

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

    // Call the wired orchestrator through the dispatcher access point.
    let info = test_session_info("work-wiring");
    let events = dispatcher
        .gate_orchestrator()
        .expect("should return Some when orchestrator is wired")
        .handle_session_terminated(info)
        .await
        .expect("should succeed for valid session info")
        .2;

    // Should have PolicyResolved + 3 GateLeaseIssued = 4 events
    assert_eq!(events.len(), 4, "1 PolicyResolved + 3 GateLeaseIssued");
    assert!(matches!(
        events[0],
        GateOrchestratorEvent::PolicyResolved { .. }
    ));
}

#[tokio::test]
async fn tck_00388_dispatcher_state_without_orchestrator() {
    // Without gate orchestrator, no runtime gate lifecycle wiring exists.
    let dispatcher = DispatcherState::new(None);

    assert!(
        dispatcher.gate_orchestrator().is_none(),
        "gate_orchestrator should be None by default"
    );

    assert!(dispatcher.gate_orchestrator().is_none());
}
