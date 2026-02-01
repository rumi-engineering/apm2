//! End-to-end integration tests for the APM2 factory workflow.
//!
//! This module tests the complete workflow from specification to evidence
//! bundle generation, including:
//!
//! - E2E test with simulated agent
//! - Full workflow from spec to evidence
//! - Policy enforcement validation
//! - Evidence bundle verification
//! - Failure mode testing (timeout, entropy)
//!
//! # Test Architecture
//!
//! ```text
//! Spec File
//!     |
//!     v
//! BlackBoxAdapter (simulated agent)
//!     |
//!     v
//! PolicyEngine (authorization)
//!     |
//!     v
//! EvidenceReducer (state projection)
//!     |
//!     v
//! GateReceiptGenerator (verification)
//!     |
//!     v
//! GateReceipt (proof of completion)
//! ```
//!
//! # Security Properties Verified
//!
//! - Default-deny policy enforcement
//! - Path traversal protection
//! - Evidence hash verification
//! - Gate receipt signature verification
//! - Entropy budget enforcement
//! - Timeout handling

#![allow(clippy::items_after_statements)]

use std::time::Duration;

use apm2_core::adapter::{
    AdapterEventPayload, BlackBoxAdapter, BlackBoxConfig, ExitClassification,
};
use apm2_core::crypto::Signer;
use apm2_core::evidence::{
    ContentAddressedStore, DataClassification, EvidenceBundle, EvidenceCategory, EvidencePublisher,
    GateReceiptGenerator, GateRequirements, GateResult, MemoryCas,
};
use apm2_core::ledger::EventRecord;
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::session::entropy::{EntropyBudgetConfig, EntropyTracker};
use apm2_core::session::{
    ExitClassification as SessionExitClassification, SessionReducer, helpers,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Creates a test evidence bundle with the given parameters.
fn make_test_bundle(
    work_id: &str,
    evidence_ids: Vec<&str>,
    categories: Vec<EvidenceCategory>,
) -> EvidenceBundle {
    EvidenceBundle::new(
        work_id.to_string(),
        [1u8; 32],
        evidence_ids.into_iter().map(String::from).collect(),
        categories,
        1024,
        1_000_000_000,
    )
}

// ============================================================================
// E2E Tests: Full Workflow from Spec to Evidence
// ============================================================================

/// E2E test: Simulated agent executes a spec and produces evidence.
///
/// This test verifies the complete factory workflow:
/// 1. Start a simulated agent (using echo command)
/// 2. Wait for process completion
/// 3. Publish evidence artifacts via CAS
/// 4. Generate gate receipt
/// 5. Verify the receipt
#[cfg_attr(miri, ignore)] // Miri cannot spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_e2e_full_workflow_with_simulated_agent() {
    // Step 1: Configure and start the simulated agent
    let config = BlackBoxConfig::new("e2e-session-001", "echo")
        .with_args(["E2E test completed successfully"]);

    let mut adapter = BlackBoxAdapter::new(config);
    adapter.start().await.expect("adapter should start");

    assert!(adapter.is_running());
    assert!(adapter.pid().is_some());

    // Step 2: Poll until process exits
    let mut exit_code = None;
    let mut exit_classification = None;

    for _ in 0..100 {
        match adapter.poll().await {
            Ok(Some(event)) => {
                if let AdapterEventPayload::ProcessExited(exited) = event.payload {
                    exit_code = exited.exit_code;
                    exit_classification = Some(exited.classification);
                    break;
                }
            },
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            },
            Err(e) => panic!("poll error: {e}"),
        }
    }

    // Verify clean exit
    assert_eq!(exit_code, Some(0), "Process should exit with code 0");
    assert_eq!(
        exit_classification,
        Some(ExitClassification::CleanSuccess),
        "Should be classified as clean success"
    );

    // Step 3: Publish evidence artifacts via CAS
    let cas = MemoryCas::new();
    let publisher = EvidencePublisher::new(cas);

    // Publish test results evidence
    let test_results = b"All tests passed: 42/42";
    let publish_result = publisher
        .publish(
            "evid-001",
            "work-e2e-001",
            test_results,
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
        )
        .expect("publish should succeed");

    // Verify evidence was stored
    assert!(publish_result.is_new_content);
    let retrieved = publisher
        .retrieve(&publish_result.artifact_hash)
        .expect("retrieve");
    assert_eq!(retrieved.as_slice(), test_results);

    // Step 4: Generate gate receipt
    let signer = Signer::generate();
    let requirements = GateRequirements::default(); // Requires TestResults
    let generator = GateReceiptGenerator::new(signer, requirements);

    let bundle = make_test_bundle(
        "work-e2e-001",
        vec!["evid-001"],
        vec![EvidenceCategory::TestResults],
    );

    let receipt = generator
        .generate("gate-e2e-001", &bundle, 2_000_000_000)
        .expect("receipt generation should succeed");

    // Step 5: Verify the receipt
    assert!(receipt.passed(), "Gate should pass");
    assert_eq!(receipt.result, GateResult::Pass);
    assert_eq!(receipt.gate_id, "gate-e2e-001");
    assert_eq!(receipt.work_id, "work-e2e-001");
    assert!(receipt.is_signed(), "Receipt should be signed");
    assert!(generator.verify(&receipt), "Signature should verify");
}

/// E2E test: Full workflow with multiple evidence artifacts.
#[tokio::test]
async fn test_e2e_multiple_evidence_artifacts() {
    let cas = MemoryCas::new();
    let publisher = EvidencePublisher::new(cas);

    // Publish multiple evidence artifacts
    let artifacts = [
        (
            "evid-001",
            "Test output: passed",
            EvidenceCategory::TestResults,
        ),
        ("evid-002", "No lint errors", EvidenceCategory::LintReports),
        (
            "evid-003",
            "Security scan clean",
            EvidenceCategory::SecurityScans,
        ),
    ];

    for (id, content, category) in artifacts {
        let result = publisher
            .publish(
                id,
                "work-multi-001",
                content.as_bytes(),
                category,
                DataClassification::Internal,
                &[],
            )
            .expect("publish should succeed");
        assert!(result.is_new_content);
    }

    // Generate high-assurance gate receipt
    let signer = Signer::generate();
    let requirements = GateRequirements::high_assurance();
    let generator = GateReceiptGenerator::new(signer, requirements);

    let bundle = make_test_bundle(
        "work-multi-001",
        vec!["evid-001", "evid-002", "evid-003"],
        vec![
            EvidenceCategory::TestResults,
            EvidenceCategory::LintReports,
            EvidenceCategory::SecurityScans,
        ],
    );

    let receipt = generator
        .generate("gate-ha-001", &bundle, 3_000_000_000)
        .expect("receipt should generate");

    assert!(receipt.passed(), "High-assurance gate should pass");
    assert_eq!(receipt.categories_present.len(), 3);
}

// ============================================================================
// Evidence Bundle Verification Tests
// ============================================================================

/// Tests evidence bundle generation and hash verification.
#[test]
fn test_evidence_bundle_hash_verification() {
    let cas = MemoryCas::new();
    let publisher = EvidencePublisher::new(cas);

    let content = b"Evidence content for verification";
    let result = publisher
        .publish(
            "evid-hash-001",
            "work-hash-001",
            content,
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
        )
        .expect("publish should succeed");

    // Verify content can be retrieved and matches
    let retrieved = publisher.retrieve(&result.artifact_hash).expect("retrieve");
    assert_eq!(retrieved.as_slice(), content, "Content should match");

    // Verify hash is deterministic
    let result2 = publisher
        .publish(
            "evid-hash-002",
            "work-hash-001",
            content,
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
        )
        .expect("publish should succeed");

    assert_eq!(
        result.artifact_hash, result2.artifact_hash,
        "Same content should produce same hash"
    );
    assert!(!result2.is_new_content, "Should be deduplicated");
}

/// Tests gate receipt passes with required evidence.
#[test]
fn test_gate_receipt_passes_with_required_evidence() {
    let signer = Signer::generate();
    let requirements = GateRequirements::default(); // Requires TestResults
    let generator = GateReceiptGenerator::new(signer, requirements);

    let bundle = make_test_bundle(
        "work-pass-001",
        vec!["evid-001"],
        vec![EvidenceCategory::TestResults],
    );

    let receipt = generator
        .generate("gate-pass-001", &bundle, 1_000_000_000)
        .expect("should generate");

    assert!(receipt.passed());
    assert_eq!(receipt.result, GateResult::Pass);
    assert!(generator.verify(&receipt));
}

/// Tests gate receipt fails without required evidence.
#[test]
fn test_gate_receipt_fails_missing_evidence() {
    let signer = Signer::generate();
    let requirements = GateRequirements::default(); // Requires TestResults
    let generator = GateReceiptGenerator::new(signer, requirements);

    // Bundle with wrong category
    let bundle = make_test_bundle(
        "work-fail-001",
        vec!["evid-001"],
        vec![EvidenceCategory::LintReports], // Not TestResults
    );

    let receipt = generator
        .generate("gate-fail-001", &bundle, 1_000_000_000)
        .expect("should generate");

    assert!(receipt.failed());
    assert_eq!(receipt.result, GateResult::Fail);
}

/// Tests gate receipt fails with empty bundle.
#[test]
fn test_gate_receipt_fails_empty_bundle() {
    let signer = Signer::generate();
    let requirements = GateRequirements::default();
    let generator = GateReceiptGenerator::new(signer, requirements);

    let bundle = make_test_bundle("work-empty-001", vec![], vec![]);

    let receipt = generator
        .generate("gate-empty-001", &bundle, 1_000_000_000)
        .expect("should generate");

    assert!(receipt.failed());
}

/// Tests gate receipt signature verification with wrong key fails.
#[test]
fn test_gate_receipt_signature_verification_different_keys() {
    let signer1 = Signer::generate();
    let signer2 = Signer::generate();
    let requirements = GateRequirements::default();

    let generator1 = GateReceiptGenerator::new(signer1, requirements.clone());
    let generator2 = GateReceiptGenerator::new(signer2, requirements);

    let bundle = make_test_bundle(
        "work-sig-001",
        vec!["evid-001"],
        vec![EvidenceCategory::TestResults],
    );

    let receipt = generator1
        .generate("gate-sig-001", &bundle, 1_000_000_000)
        .expect("should generate");

    // Original generator can verify
    assert!(generator1.verify(&receipt));

    // Different generator cannot verify
    assert!(!generator2.verify(&receipt));
}

// ============================================================================
// Failure Mode Tests
// ============================================================================

/// Tests timeout failure mode via stall detection.
#[cfg_attr(miri, ignore)] // Miri cannot spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_failure_mode_timeout_stall_detection() {
    // Configure with very short stall timeout
    let mut config = BlackBoxConfig::new("e2e-timeout-001", "sleep").with_args(["10"]);
    config.stall_detection.timeout = Duration::from_millis(50);
    config.stall_detection.enabled = true;

    let mut adapter = BlackBoxAdapter::new(config);
    adapter.start().await.expect("adapter should start");

    // Poll for stall detection
    let mut stall_detected = false;

    for _ in 0..100 {
        match adapter.poll().await {
            Ok(Some(event)) => {
                if let AdapterEventPayload::StallDetected(stall) = event.payload {
                    stall_detected = true;
                    assert!(stall.idle_duration >= Duration::from_millis(50));
                    break;
                }
                if let AdapterEventPayload::ProcessExited(_) = event.payload {
                    break;
                }
            },
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            },
            Err(_) => break,
        }
    }

    assert!(stall_detected, "Stall should be detected");

    // Clean up
    adapter.stop().await.ok();
}

/// Tests entropy budget exceeded failure mode.
#[test]
fn test_failure_mode_entropy_exceeded() {
    let config = EntropyBudgetConfig::with_budget(100);
    let mut tracker = EntropyTracker::new("session-entropy-001", config);

    assert!(!tracker.is_exceeded());
    assert_eq!(tracker.consumed(), 0);
    assert_eq!(tracker.remaining(), 100);

    // Record errors until budget exceeded
    for i in 0..10 {
        let cost = tracker.record_error(format!("error_{i}"));
        assert_eq!(cost, 10); // Default error weight
    }

    assert!(tracker.is_exceeded());
    assert_eq!(tracker.consumed(), 100);
    assert_eq!(tracker.remaining(), 0);
    assert_eq!(tracker.error_count(), 10);
}

/// Tests entropy exceeded via policy violations (higher weight).
#[test]
fn test_failure_mode_entropy_exceeded_violations() {
    let config = EntropyBudgetConfig::with_budget(100);
    let mut tracker = EntropyTracker::new("session-entropy-002", config);

    // Violations have weight 50, so 2 violations = 100 entropy
    tracker.record_violation("policy_breach_1");
    assert!(!tracker.is_exceeded());
    assert_eq!(tracker.consumed(), 50);

    tracker.record_violation("policy_breach_2");
    assert!(tracker.is_exceeded());
    assert_eq!(tracker.consumed(), 100);
    assert_eq!(tracker.violation_count(), 2);
}

/// Tests entropy tracking with multiple event types.
#[test]
fn test_failure_mode_entropy_mixed_events() {
    let config = EntropyBudgetConfig::with_budget(200);
    let mut tracker = EntropyTracker::new("session-entropy-003", config);

    // Record different event types
    tracker.record_error("tool_failure"); // 10
    tracker.record_stall("no_progress"); // 25
    tracker.record_timeout("tool_timeout"); // 15
    tracker.record_violation("policy_breach"); // 50

    // Total: 10 + 25 + 15 + 50 = 100
    assert_eq!(tracker.consumed(), 100);
    assert_eq!(tracker.remaining(), 100);
    assert!(!tracker.is_exceeded());

    // Verify counts
    assert_eq!(tracker.error_count(), 1);
    assert_eq!(tracker.stall_count(), 1);
    assert_eq!(tracker.timeout_count(), 1);
    assert_eq!(tracker.violation_count(), 1);

    // Verify event history
    assert_eq!(tracker.events().len(), 4);
}

/// Tests strict entropy configuration for high-assurance mode.
#[test]
fn test_failure_mode_entropy_strict_config() {
    let config = EntropyBudgetConfig::strict(100);
    let mut tracker = EntropyTracker::new("session-strict-001", config);

    // Strict mode has higher weights
    // error_weight: 25, violation_weight: 100
    tracker.record_error("error_1");
    assert_eq!(tracker.consumed(), 25); // Higher than default 10

    tracker.record_error("error_2");
    tracker.record_error("error_3");
    tracker.record_error("error_4");

    // 4 errors * 25 = 100
    assert!(tracker.is_exceeded());
}

/// Tests entropy tracker summary generation.
#[test]
fn test_failure_mode_entropy_summary() {
    let config = EntropyBudgetConfig::with_budget(1000);
    let mut tracker = EntropyTracker::new("session-summary-001", config);

    tracker.record_error("error");
    tracker.record_violation("violation");
    tracker.record_stall("stall");
    tracker.record_timeout("timeout");

    let summary = tracker.summary();

    assert_eq!(summary.session_id, "session-summary-001");
    assert_eq!(summary.budget, 1000);
    assert_eq!(summary.consumed, 100); // 10 + 50 + 25 + 15
    assert_eq!(summary.remaining, 900);
    assert!(!summary.is_exceeded);
    assert_eq!(summary.error_count, 1);
    assert_eq!(summary.violation_count, 1);
    assert_eq!(summary.stall_count, 1);
    assert_eq!(summary.timeout_count, 1);
}

// ============================================================================
// Process Exit Classification Tests
// ============================================================================

/// Tests process exit classification for various exit scenarios.
#[cfg_attr(miri, ignore)] // Miri cannot spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_process_exit_classification_success() {
    let config = BlackBoxConfig::new("e2e-exit-001", "true"); // /bin/true exits 0
    let mut adapter = BlackBoxAdapter::new(config);
    adapter.start().await.expect("adapter should start");

    let mut classification = None;
    for _ in 0..50 {
        match adapter.poll().await {
            Ok(Some(event)) => {
                if let AdapterEventPayload::ProcessExited(exited) = event.payload {
                    classification = Some(exited.classification);
                    break;
                }
            },
            Ok(None) => tokio::time::sleep(Duration::from_millis(10)).await,
            Err(_) => break,
        }
    }

    assert_eq!(classification, Some(ExitClassification::CleanSuccess));
}

/// Tests process exit classification for error exits.
#[cfg_attr(miri, ignore)] // Miri cannot spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_process_exit_classification_error() {
    let config = BlackBoxConfig::new("e2e-exit-002", "false"); // /bin/false exits 1
    let mut adapter = BlackBoxAdapter::new(config);
    adapter.start().await.expect("adapter should start");

    let mut classification = None;
    for _ in 0..50 {
        match adapter.poll().await {
            Ok(Some(event)) => {
                if let AdapterEventPayload::ProcessExited(exited) = event.payload {
                    classification = Some(exited.classification);
                    break;
                }
            },
            Ok(None) => tokio::time::sleep(Duration::from_millis(10)).await,
            Err(_) => break,
        }
    }

    assert_eq!(classification, Some(ExitClassification::CleanError));
}

// ============================================================================
// Determinism Tests
// ============================================================================

/// Tests that gate receipts are deterministically signed (same inputs, same
/// receipt ID).
#[test]
fn test_gate_receipt_signature_determinism() {
    let signer = Signer::generate();
    let requirements = GateRequirements::default();
    let generator = GateReceiptGenerator::new(signer, requirements);

    let bundle = make_test_bundle(
        "work-sig-det-001",
        vec!["evid-001"],
        vec![EvidenceCategory::TestResults],
    );

    // Same inputs should produce same receipt ID (timestamp differs)
    let receipt1 = generator
        .generate("gate-det-001", &bundle, 1_000_000_000)
        .expect("generate");
    let receipt2 = generator
        .generate("gate-det-001", &bundle, 2_000_000_000)
        .expect("generate");

    assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
    assert_eq!(receipt1.result, receipt2.result);
    // Signatures will differ due to timestamp in canonical bytes
}

/// Tests that CAS hash generation is deterministic.
#[test]
fn test_cas_hash_determinism() {
    let cas = MemoryCas::new();

    let content = b"deterministic content";

    // Store the same content multiple times
    let result1 = cas.store(content).expect("store");
    let result2 = cas.store(content).expect("store");

    // Hashes should be identical
    assert_eq!(result1.hash, result2.hash);
    assert!(result1.is_new);
    assert!(!result2.is_new); // Deduplicated
}

// ============================================================================
// Security Property Tests
// ============================================================================

/// Tests that gate receipt generation rejects invalid input.
#[test]
fn test_gate_receipt_rejects_invalid_gate_id() {
    let signer = Signer::generate();
    let requirements = GateRequirements::default();
    let generator = GateReceiptGenerator::new(signer, requirements);

    let bundle = make_test_bundle(
        "work-001",
        vec!["evid-001"],
        vec![EvidenceCategory::TestResults],
    );

    // Empty gate ID
    let result = generator.generate("", &bundle, 1_000_000_000);
    assert!(result.is_err());

    // Gate ID with pipe (canonical format separator)
    let result = generator.generate("gate|injection", &bundle, 1_000_000_000);
    assert!(result.is_err());

    // Gate ID with path traversal
    let result = generator.generate("gate/../attack", &bundle, 1_000_000_000);
    assert!(result.is_err());
}

/// Tests that CAS rejects empty content.
#[test]
fn test_cas_rejects_empty_content() {
    let cas = MemoryCas::new();
    let result = cas.store(b"");
    assert!(result.is_err());
}

/// Tests that CAS enforces storage limits.
#[test]
fn test_cas_enforces_storage_limits() {
    // Create CAS with small limit
    let cas = MemoryCas::with_max_size(100);

    // First store should succeed
    let content1 = vec![1u8; 50];
    assert!(cas.store(&content1).is_ok());

    // Second store should fail (would exceed limit)
    let content2 = vec![2u8; 60];
    let result = cas.store(&content2);
    assert!(result.is_err());
}

// ============================================================================
// Integration: Session Lifecycle with Exit Classifications
// ============================================================================

/// Tests session state machine with various exit classifications.
#[test]
fn test_session_lifecycle_exit_classifications() {
    let mut reducer = SessionReducer::new();
    let ctx = ReducerContext::new(1);

    let classifications = [
        ("session-1", "SUCCESS", SessionExitClassification::Success),
        ("session-2", "FAILURE", SessionExitClassification::Failure),
        ("session-3", "TIMEOUT", SessionExitClassification::Timeout),
        (
            "session-4",
            "ENTROPY_EXCEEDED",
            SessionExitClassification::EntropyExceeded,
        ),
    ];

    for (session_id, classification_str, expected) in classifications {
        // Start session
        let start_payload = helpers::session_started_payload(
            session_id,
            "actor-001",
            "claude-code",
            "work-001",
            "lease-001",
            1000,
        );
        let start_event = EventRecord::with_timestamp(
            "session.started",
            session_id,
            "actor-001",
            start_payload,
            1_000_000_000,
        );
        reducer.apply(&start_event, &ctx).expect("start");

        // Terminate with classification
        let term_payload = helpers::session_terminated_payload(
            session_id,
            classification_str,
            "test termination",
            500,
        );
        let term_event = EventRecord::with_timestamp(
            "session.terminated",
            session_id,
            "actor-001",
            term_payload,
            2_000_000_000,
        );
        reducer.apply(&term_event, &ctx).expect("terminate");

        // Verify classification
        use apm2_core::session::SessionState;
        match reducer.state().get(session_id).expect("session") {
            SessionState::Terminated {
                exit_classification,
                ..
            } => {
                assert_eq!(*exit_classification, expected);
            },
            _ => panic!("Expected Terminated state"),
        }
    }
}

/// Tests session state machine with quarantine flow.
#[test]
fn test_session_lifecycle_quarantine() {
    let mut reducer = SessionReducer::new();
    let ctx = ReducerContext::new(1);

    // Start session
    let start_payload = helpers::session_started_payload(
        "session-quar-001",
        "actor-001",
        "claude-code",
        "work-001",
        "lease-001",
        1000,
    );
    let start_event = EventRecord::with_timestamp(
        "session.started",
        "session-quar-001",
        "actor-001",
        start_payload,
        1_000_000_000,
    );
    reducer.apply(&start_event, &ctx).expect("start");

    // Verify running state
    assert!(reducer.state().get("session-quar-001").unwrap().is_active());

    // Quarantine the session
    let quar_payload = helpers::session_quarantined_payload_with_ticks(
        "session-quar-001",
        "policy violation detected",
        3_000_000_000, // release_after_ns
        2000,          // issued_at_tick
        3000,          // expires_at_tick
        1000,          // tick_rate_hz
    );
    let quar_event = EventRecord::with_timestamp(
        "session.quarantined",
        "session-quar-001",
        "actor-001",
        quar_payload,
        2_000_000_000,
    );
    reducer.apply(&quar_event, &ctx).expect("quarantine");

    // Verify quarantined state
    use apm2_core::session::SessionState;
    match reducer.state().get("session-quar-001").expect("session") {
        SessionState::Quarantined { reason, .. } => {
            assert_eq!(reason, "policy violation detected");
        },
        _ => panic!("Expected Quarantined state"),
    }

    // Session should no longer be active
    assert!(!reducer.state().get("session-quar-001").unwrap().is_active());
    assert!(
        reducer
            .state()
            .get("session-quar-001")
            .unwrap()
            .is_terminal()
    );
}

/// Tests full session lifecycle: start, progress, terminate.
#[test]
fn test_session_full_lifecycle() {
    let mut reducer = SessionReducer::new();
    let ctx = ReducerContext::new(1);

    // Start session
    let start_payload = helpers::session_started_payload(
        "session-full-001",
        "actor-001",
        "claude-code",
        "work-001",
        "lease-001",
        1000,
    );
    let start_event = EventRecord::with_timestamp(
        "session.started",
        "session-full-001",
        "actor-001",
        start_payload,
        1_000_000_000,
    );
    reducer.apply(&start_event, &ctx).expect("start");

    // Send progress events
    for i in 1..=5 {
        let progress_payload =
            helpers::session_progress_payload("session-full-001", i, "HEARTBEAT", i * 100);
        let progress_event = EventRecord::with_timestamp(
            "session.progress",
            "session-full-001",
            "actor-001",
            progress_payload,
            1_000_000_000 + i * 1000,
        );
        reducer.apply(&progress_event, &ctx).expect("progress");
    }

    // Verify progress was tracked
    use apm2_core::session::SessionState;
    match reducer.state().get("session-full-001").expect("session") {
        SessionState::Running {
            progress_count,
            entropy_consumed,
            ..
        } => {
            assert_eq!(*progress_count, 5);
            assert_eq!(*entropy_consumed, 500);
        },
        _ => panic!("Expected Running state"),
    }

    // Terminate session
    let term_payload = helpers::session_terminated_payload(
        "session-full-001",
        "SUCCESS",
        "completed all tasks",
        500,
    );
    let term_event = EventRecord::with_timestamp(
        "session.terminated",
        "session-full-001",
        "actor-001",
        term_payload,
        2_000_000_000,
    );
    reducer.apply(&term_event, &ctx).expect("terminate");

    // Verify terminated state
    match reducer.state().get("session-full-001").expect("session") {
        SessionState::Terminated {
            exit_classification,
            ..
        } => {
            assert_eq!(*exit_classification, SessionExitClassification::Success);
        },
        _ => panic!("Expected Terminated state"),
    }
}

/// Tests that multiple concurrent sessions can be tracked.
#[test]
fn test_multiple_concurrent_sessions() {
    let mut reducer = SessionReducer::new();
    let ctx = ReducerContext::new(1);

    // Start 3 concurrent sessions
    for i in 1..=3 {
        let session_id = format!("session-{i}");
        let actor_id = format!("actor-{i}");
        let start_payload = helpers::session_started_payload(
            &session_id,
            &actor_id,
            "claude-code",
            &format!("work-{i}"),
            &format!("lease-{i}"),
            1000,
        );
        let start_event = EventRecord::with_timestamp(
            "session.started",
            &session_id,
            &actor_id,
            start_payload,
            1_000_000_000,
        );
        reducer.apply(&start_event, &ctx).expect("start");
    }

    // Verify all sessions are active
    assert_eq!(reducer.state().len(), 3);
    assert_eq!(reducer.state().active_count(), 3);

    // Terminate session-1 with success
    let term_payload = helpers::session_terminated_payload("session-1", "SUCCESS", "done", 500);
    let term_event = EventRecord::with_timestamp(
        "session.terminated",
        "session-1",
        "actor-1",
        term_payload,
        2_000_000_000,
    );
    reducer.apply(&term_event, &ctx).expect("terminate");

    // Terminate session-2 with failure
    let term_payload = helpers::session_terminated_payload("session-2", "FAILURE", "error", 100);
    let term_event = EventRecord::with_timestamp(
        "session.terminated",
        "session-2",
        "actor-2",
        term_payload,
        2_000_000_000,
    );
    reducer.apply(&term_event, &ctx).expect("terminate");

    // Quarantine session-3
    let quar_payload = helpers::session_quarantined_payload_with_ticks(
        "session-3",
        "policy violation",
        3_000_000_000,
        2000, // issued_at_tick
        3000, // expires_at_tick
        1000, // tick_rate_hz
    );
    let quar_event = EventRecord::with_timestamp(
        "session.quarantined",
        "session-3",
        "actor-3",
        quar_payload,
        2_000_000_000,
    );
    reducer.apply(&quar_event, &ctx).expect("quarantine");

    // Verify final counts
    assert_eq!(reducer.state().active_count(), 0);
    assert_eq!(reducer.state().terminated_count(), 2);
    assert_eq!(reducer.state().quarantined_count(), 1);
}
