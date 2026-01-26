//! Integration tests for the agent handoff flow (TCK-00089).
//!
//! This module verifies the complete handoff flow from webhook reception to
//! agent claiming, implementing requirements from RFC-0008.
//!
//! # Test Categories
//!
//! 1. **E2E Flow**: Full webhook -> event -> transition -> claim flow
//! 2. **Signature Validation**: Valid and invalid HMAC-SHA256 signatures
//! 3. **Idempotency**: Duplicate delivery ID handling
//! 4. **Anti-Gaming**: Agents cannot directly set CI status
//! 5. **Error Cases**: Malformed payloads, missing headers
//! 6. **Feature Flags**: Each phase can be disabled
//! 7. **Edge Cases**: Reruns, cancellations, state machine transitions
//!
//! # Evidence
//!
//! - EVID-8005: Anti-gaming controls verified

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use apm2_core::agent::exit::{ExitReason, WorkPhase as ExitWorkPhase};
use apm2_core::events::ci::{
    CIConclusion, CIEventsConfig, CIGatedQueueConfig, CIWorkflowCompleted, CIWorkflowPayload,
    InMemoryDeliveryIdStore, InMemoryEventStore,
};
use apm2_core::session::exit_handler::{ExitHandlerContext, ExitHandlerError, handle_exit_signal};
use apm2_core::webhook::{
    CIEventEmitter, EmitResult, RateLimitConfig, RateLimiter, SignatureValidator, WebhookError,
    WorkflowConclusion, WorkflowRunCompleted, WorkflowRunPayload,
};
use apm2_core::work::ci_queue::WorkLookupResult;
use apm2_core::work::{
    CiQueueProcessResult, Work, WorkState, WorkType, process_ci_event, target_phase_for_conclusion,
};
use secrecy::SecretString;

// ============================================================================
// Test Fixtures
// ============================================================================

/// Test webhook secret (minimum 32 bytes as required by `WebhookConfig`).
const TEST_SECRET: &str = "test-secret-key-32-bytes-minimum";

/// Computes the HMAC-SHA256 signature for a webhook payload.
fn compute_signature(payload: &[u8], secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload);
    let result = mac.finalize();
    let bytes = result.into_bytes();

    format!(
        "sha256={}",
        bytes.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    )
}

/// Creates a workflow run completed payload.
fn make_payload(action: &str, conclusion: &str, pr_number: u64) -> Vec<u8> {
    format!(
        r#"{{
            "action": "{action}",
            "workflow_run": {{
                "id": 12345,
                "name": "CI",
                "head_sha": "abc123def456",
                "head_branch": "feature/test",
                "conclusion": "{conclusion}",
                "pull_requests": [{{"number": {pr_number}}}]
            }}
        }}"#
    )
    .into_bytes()
}

/// Creates an enabled event emitter for testing.
fn enabled_emitter() -> CIEventEmitter {
    CIEventEmitter::with_config(
        CIEventsConfig::enabled(),
        Arc::new(InMemoryDeliveryIdStore::new()),
        Arc::new(InMemoryEventStore::new()),
    )
}

/// Creates a test work item in `CiPending` state.
fn make_ci_pending_work(work_id: &str, pr_number: u64, commit_sha: &str) -> Work {
    let mut work = Work::new(
        work_id.to_string(),
        WorkType::Ticket,
        vec![1, 2, 3],
        vec!["REQ-001".to_string()],
        vec![],
        1_000_000_000,
    );
    work.state = WorkState::CiPending;
    work.pr_number = Some(pr_number);
    work.commit_sha = Some(commit_sha.to_string());
    work
}

// ============================================================================
// E2E Flow Tests
// ============================================================================

/// E2E test: Full handoff flow from webhook to agent claiming.
///
/// This test verifies:
/// 1. Webhook is received with valid signature
/// 2. CI event is emitted to ledger
/// 3. Work item transitions from `CiPending` to `ReadyForReview`
/// 4. Work item becomes claimable
#[tokio::test]
async fn test_e2e_handoff_flow() {
    // Setup: Create work item in CiPending state
    let pr_number = 42_u64;
    let commit_sha = "abc123def456";
    let work = make_ci_pending_work("work-e2e-001", pr_number, commit_sha);

    assert_eq!(work.state, WorkState::CiPending);
    assert!(!work.state.is_claimable());

    // Step 1: Simulate webhook payload
    let payload = make_payload("completed", "success", pr_number);
    let signature = compute_signature(&payload, TEST_SECRET);

    // Step 2: Validate signature
    let validator = SignatureValidator::new(SecretString::from(TEST_SECRET));
    let sig_result = validator.verify(&payload, &signature);
    assert!(sig_result.is_ok(), "Signature should be valid");

    // Step 3: Parse payload
    let parsed = WorkflowRunPayload::parse(&payload).unwrap();
    let completed = parsed.into_completed().unwrap();

    assert_eq!(completed.conclusion, WorkflowConclusion::Success);
    assert_eq!(completed.pull_request_numbers, vec![pr_number]);

    // Step 4: Emit CI event
    let emitter = enabled_emitter();
    let emit_result = emitter.emit(&completed, true, "delivery-e2e-001").unwrap();

    match emit_result {
        EmitResult::Emitted { event_id } => {
            // Verify event was persisted
            let stored = emitter.event_store().get(event_id);
            assert!(stored.is_some(), "Event should be stored");

            let event = stored.unwrap();
            assert_eq!(event.payload.pr_numbers, vec![pr_number]);
            assert_eq!(event.payload.conclusion, CIConclusion::Success);
            assert!(event.signature_verified);
        },
        other => panic!("Expected Emitted, got {other:?}"),
    }

    // Step 5: Process CI event through queue
    let ci_event = CIWorkflowCompleted::new(
        CIWorkflowPayload {
            pr_numbers: vec![pr_number],
            commit_sha: commit_sha.to_string(),
            conclusion: CIConclusion::Success,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![],
        },
        true,
        "delivery-e2e-001".to_string(),
    );

    let config = CIGatedQueueConfig::enabled();
    let result = process_ci_event(&ci_event, &config, |pr| {
        if pr == pr_number {
            Some(WorkLookupResult {
                work_id: work.work_id.clone(),
                state: work.state,
                commit_sha: work.commit_sha.clone(),
            })
        } else {
            None
        }
    });

    // Step 6: Verify transition
    match result {
        CiQueueProcessResult::Transitioned {
            work_id,
            previous_phase,
            next_phase,
            event: transition_event,
        } => {
            assert_eq!(work_id, "work-e2e-001");
            assert_eq!(previous_phase, WorkState::CiPending);
            assert_eq!(next_phase, WorkState::ReadyForReview);
            assert_eq!(transition_event.previous_phase, "CI_PENDING");
            assert_eq!(transition_event.next_phase, "READY_FOR_REVIEW");
        },
        other => panic!("Expected Transitioned, got {other:?}"),
    }

    // Step 7: Verify work is now claimable
    assert!(WorkState::ReadyForReview.is_claimable());
}

/// E2E test: Handoff flow with CI failure transitions to Blocked state.
#[tokio::test]
async fn test_e2e_handoff_ci_failure() {
    let pr_number = 43_u64;
    let commit_sha = "def456abc789";
    let work = make_ci_pending_work("work-e2e-002", pr_number, commit_sha);

    // Simulate CI failure
    let payload = make_payload("completed", "failure", pr_number);
    let signature = compute_signature(&payload, TEST_SECRET);

    let validator = SignatureValidator::new(SecretString::from(TEST_SECRET));
    assert!(validator.verify(&payload, &signature).is_ok());

    let parsed = WorkflowRunPayload::parse(&payload).unwrap();
    let completed = parsed.into_completed().unwrap();

    assert_eq!(completed.conclusion, WorkflowConclusion::Failure);

    // Process CI event
    let ci_event = CIWorkflowCompleted::new(
        CIWorkflowPayload {
            pr_numbers: vec![pr_number],
            commit_sha: commit_sha.to_string(),
            conclusion: CIConclusion::Failure,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![],
        },
        true,
        "delivery-e2e-002".to_string(),
    );

    let config = CIGatedQueueConfig::enabled();
    let result = process_ci_event(&ci_event, &config, |pr| {
        if pr == pr_number {
            Some(WorkLookupResult {
                work_id: work.work_id.clone(),
                state: work.state,
                commit_sha: work.commit_sha.clone(),
            })
        } else {
            None
        }
    });

    match result {
        CiQueueProcessResult::Transitioned { next_phase, .. } => {
            assert_eq!(next_phase, WorkState::Blocked);
            assert!(!next_phase.is_claimable());
        },
        other => panic!("Expected Transitioned, got {other:?}"),
    }
}

// ============================================================================
// Signature Validation Tests
// ============================================================================

/// Test: Valid signature is accepted.
#[test]
fn test_valid_signature_accepted() {
    let validator = SignatureValidator::new(SecretString::from(TEST_SECRET));
    let payload = make_payload("completed", "success", 42);
    let signature = compute_signature(&payload, TEST_SECRET);

    let result = validator.verify(&payload, &signature);
    assert!(result.is_ok());
}

/// Test: Invalid signature is rejected with UNAUTHORIZED.
#[test]
fn test_invalid_signature_rejected() {
    let validator = SignatureValidator::new(SecretString::from(TEST_SECRET));
    let payload = make_payload("completed", "success", 42);
    // Use wrong secret
    let signature = compute_signature(&payload, "wrong-secret");

    let result = validator.verify(&payload, &signature);
    assert!(matches!(result, Err(WebhookError::InvalidSignature)));
}

/// Test: Missing sha256= prefix is rejected.
#[test]
fn test_missing_signature_prefix_rejected() {
    let validator = SignatureValidator::new(SecretString::from(TEST_SECRET));
    let payload = make_payload("completed", "success", 42);

    let result = validator.verify(&payload, "abcdef1234567890");
    assert!(matches!(
        result,
        Err(WebhookError::InvalidSignatureFormat(_))
    ));
}

/// Test: Invalid hex in signature is rejected.
#[test]
fn test_invalid_hex_signature_rejected() {
    let validator = SignatureValidator::new(SecretString::from(TEST_SECRET));
    let payload = make_payload("completed", "success", 42);

    let result = validator.verify(&payload, "sha256=notvalidhex!!!");
    assert!(matches!(
        result,
        Err(WebhookError::InvalidSignatureFormat(_))
    ));
}

/// Test: Tampered payload is rejected.
#[test]
fn test_tampered_payload_rejected() {
    let validator = SignatureValidator::new(SecretString::from(TEST_SECRET));
    let original_payload = make_payload("completed", "success", 42);
    let signature = compute_signature(&original_payload, TEST_SECRET);

    // Tamper with payload
    let tampered_payload = make_payload("completed", "failure", 42);

    let result = validator.verify(&tampered_payload, &signature);
    assert!(matches!(result, Err(WebhookError::InvalidSignature)));
}

// ============================================================================
// Idempotency Tests
// ============================================================================

/// Test: Duplicate delivery ID returns OK (not ACCEPTED).
#[test]
fn test_duplicate_delivery_id_idempotent() {
    let emitter = enabled_emitter();
    let completed = WorkflowRunCompleted {
        workflow_run_id: 12345,
        workflow_name: "CI".to_string(),
        commit_sha: "abc123".to_string(),
        branch: "feature/test".to_string(),
        conclusion: WorkflowConclusion::Success,
        pull_request_numbers: vec![42],
    };

    // First delivery
    let result1 = emitter.emit(&completed, true, "dup-delivery-001").unwrap();
    assert!(matches!(result1, EmitResult::Emitted { .. }));

    // Duplicate delivery
    let result2 = emitter.emit(&completed, true, "dup-delivery-001").unwrap();
    assert_eq!(result2, EmitResult::Duplicate);

    // Only one event in store
    assert_eq!(emitter.event_store().count(), 1);
}

/// Test: Different delivery IDs create separate events.
#[test]
fn test_different_delivery_ids_create_events() {
    let emitter = enabled_emitter();
    let completed = WorkflowRunCompleted {
        workflow_run_id: 12345,
        workflow_name: "CI".to_string(),
        commit_sha: "abc123".to_string(),
        branch: "feature/test".to_string(),
        conclusion: WorkflowConclusion::Success,
        pull_request_numbers: vec![42],
    };

    let result1 = emitter.emit(&completed, true, "unique-1").unwrap();
    let result2 = emitter.emit(&completed, true, "unique-2").unwrap();
    let result3 = emitter.emit(&completed, true, "unique-3").unwrap();

    assert!(matches!(result1, EmitResult::Emitted { .. }));
    assert!(matches!(result2, EmitResult::Emitted { .. }));
    assert!(matches!(result3, EmitResult::Emitted { .. }));

    // Three events in store
    assert_eq!(emitter.event_store().count(), 3);
}

// ============================================================================
// Anti-Gaming Tests
// ============================================================================

/// Test: Agent cannot set CI status directly (only `CIWorkflowCompleted` events
/// can transition `CiPending` work items).
///
/// This verifies EVID-8005: Anti-gaming controls.
#[test]
fn test_anti_gaming_agent_cannot_set_ci() {
    // Create work item in CiPending state
    let work = make_ci_pending_work("work-anti-gaming-001", 42, "abc123");

    // Work item is in CiPending state, not claimable
    assert_eq!(work.state, WorkState::CiPending);
    assert!(!work.state.is_claimable());

    // Verify: Only CiPending can transition to ReadyForReview
    assert!(WorkState::CiPending.can_transition_to(&WorkState::ReadyForReview));

    // Verify: InProgress cannot directly transition to ReadyForReview
    // (would skip CI gate)
    assert!(!WorkState::InProgress.can_transition_to(&WorkState::ReadyForReview));

    // Verify: Only valid transition paths exist
    // CiPending -> ReadyForReview (CI success)
    // CiPending -> Blocked (CI failure)
    // CiPending -> Aborted
    assert!(WorkState::CiPending.can_transition_to(&WorkState::ReadyForReview));
    assert!(WorkState::CiPending.can_transition_to(&WorkState::Blocked));
    assert!(WorkState::CiPending.can_transition_to(&WorkState::Aborted));

    // Cannot skip to Completed or Review
    assert!(!WorkState::CiPending.can_transition_to(&WorkState::Completed));
    assert!(!WorkState::CiPending.can_transition_to(&WorkState::Review));
}

/// Test: Work items not in `CiPending` are rejected by CI queue processor.
#[test]
fn test_anti_gaming_wrong_state_rejected() {
    let config = CIGatedQueueConfig::enabled();

    // Create a CI event
    let ci_event = CIWorkflowCompleted::new(
        CIWorkflowPayload {
            pr_numbers: vec![42],
            commit_sha: "abc123".to_string(),
            conclusion: CIConclusion::Success,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![],
        },
        true,
        "delivery-anti-gaming-001".to_string(),
    );

    // Test with work in InProgress state (should be rejected)
    let result = process_ci_event(&ci_event, &config, |_| {
        Some(WorkLookupResult {
            work_id: "work-001".to_string(),
            state: WorkState::InProgress, // Wrong state!
            commit_sha: Some("abc123".to_string()),
        })
    });

    assert!(matches!(
        result,
        CiQueueProcessResult::NotInCiPending {
            current_state: WorkState::InProgress,
            ..
        }
    ));
}

/// Test: Commit SHA mismatch prevents stale CI results from gaming.
#[test]
fn test_anti_gaming_commit_sha_mismatch() {
    let config = CIGatedQueueConfig::enabled();

    // CI event has SHA "new-sha"
    let ci_event = CIWorkflowCompleted::new(
        CIWorkflowPayload {
            pr_numbers: vec![42],
            commit_sha: "new-sha".to_string(),
            conclusion: CIConclusion::Success,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![],
        },
        true,
        "delivery-sha-mismatch-001".to_string(),
    );

    // Work item has different SHA "old-sha"
    let result = process_ci_event(&ci_event, &config, |_| {
        Some(WorkLookupResult {
            work_id: "work-001".to_string(),
            state: WorkState::CiPending,
            commit_sha: Some("old-sha".to_string()), // Different SHA!
        })
    });

    assert!(matches!(
        result,
        CiQueueProcessResult::CommitShaMismatch {
            expected_sha,
            actual_sha,
            ..
        } if expected_sha == "old-sha" && actual_sha == "new-sha"
    ));
}

// ============================================================================
// Error Cases Tests
// ============================================================================

/// Test: Malformed JSON payload is rejected.
#[test]
fn test_malformed_json_rejected() {
    let payload = b"not valid json";
    let result = WorkflowRunPayload::parse(payload);

    assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
}

/// Test: Missing required fields in payload is rejected.
#[test]
fn test_missing_fields_rejected() {
    let payload = br#"{"action": "completed"}"#;
    let result = WorkflowRunPayload::parse(payload);

    assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
}

/// Test: Non-completed action is rejected.
#[test]
fn test_non_completed_action_rejected() {
    let payload = make_payload("requested", "success", 42);
    let parsed = WorkflowRunPayload::parse(&payload).unwrap();
    let result = parsed.into_completed();

    assert!(matches!(result, Err(WebhookError::UnsupportedEventType(_))));
}

/// Test: Unknown conclusion is rejected.
#[test]
fn test_unknown_conclusion_rejected() {
    let payload = make_payload("completed", "unknown_status", 42);
    let parsed = WorkflowRunPayload::parse(&payload).unwrap();
    let result = parsed.into_completed();

    assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
}

/// Test: Missing conclusion in completed action is rejected.
#[test]
fn test_missing_conclusion_rejected() {
    let payload = r#"{
        "action": "completed",
        "workflow_run": {
            "id": 12345,
            "name": "CI",
            "head_sha": "abc123",
            "head_branch": "main",
            "pull_requests": []
        }
    }"#
    .as_bytes();

    let parsed = WorkflowRunPayload::parse(payload).unwrap();
    let result = parsed.into_completed();

    assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
}

// ============================================================================
// Feature Flag Tests
// ============================================================================

/// Test: Disabled CI events returns Disabled result.
#[test]
fn test_feature_flag_ci_events_disabled() {
    let emitter = CIEventEmitter::with_config(
        CIEventsConfig::disabled(),
        Arc::new(InMemoryDeliveryIdStore::new()),
        Arc::new(InMemoryEventStore::new()),
    );

    let completed = WorkflowRunCompleted {
        workflow_run_id: 12345,
        workflow_name: "CI".to_string(),
        commit_sha: "abc123".to_string(),
        branch: "feature/test".to_string(),
        conclusion: WorkflowConclusion::Success,
        pull_request_numbers: vec![42],
    };

    let result = emitter
        .emit(&completed, true, "delivery-disabled-001")
        .unwrap();
    assert_eq!(result, EmitResult::Disabled);

    // No events stored
    assert_eq!(emitter.event_store().count(), 0);
}

/// Test: Disabled CI queue returns Disabled result.
#[test]
fn test_feature_flag_ci_queue_disabled() {
    let config = CIGatedQueueConfig::disabled();

    let ci_event = CIWorkflowCompleted::new(
        CIWorkflowPayload {
            pr_numbers: vec![42],
            commit_sha: "abc123".to_string(),
            conclusion: CIConclusion::Success,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![],
        },
        true,
        "delivery-001".to_string(),
    );

    let result = process_ci_event(&ci_event, &config, |_| {
        Some(WorkLookupResult {
            work_id: "work-001".to_string(),
            state: WorkState::CiPending,
            commit_sha: Some("abc123".to_string()),
        })
    });

    assert_eq!(result, CiQueueProcessResult::Disabled);
}

// ============================================================================
// Phase Transition Edge Cases
// ============================================================================

/// Test: CI cancelled transitions to Blocked.
#[test]
fn test_ci_cancelled_transitions_to_blocked() {
    let config = CIGatedQueueConfig::enabled();

    let ci_event = CIWorkflowCompleted::new(
        CIWorkflowPayload {
            pr_numbers: vec![42],
            commit_sha: "abc123".to_string(),
            conclusion: CIConclusion::Cancelled,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![],
        },
        true,
        "delivery-cancelled-001".to_string(),
    );

    let result = process_ci_event(&ci_event, &config, |_| {
        Some(WorkLookupResult {
            work_id: "work-001".to_string(),
            state: WorkState::CiPending,
            commit_sha: Some("abc123".to_string()),
        })
    });

    match result {
        CiQueueProcessResult::Transitioned { next_phase, .. } => {
            assert_eq!(next_phase, WorkState::Blocked);
        },
        other => panic!("Expected Transitioned, got {other:?}"),
    }
}

/// Test: CI event with no PR numbers is handled gracefully.
#[test]
fn test_ci_event_no_pr_numbers() {
    let config = CIGatedQueueConfig::enabled();

    let ci_event = CIWorkflowCompleted::new(
        CIWorkflowPayload {
            pr_numbers: vec![], // No PRs!
            commit_sha: "abc123".to_string(),
            conclusion: CIConclusion::Success,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![],
        },
        true,
        "delivery-no-pr-001".to_string(),
    );

    let result = process_ci_event(&ci_event, &config, |_| {
        Some(WorkLookupResult {
            work_id: "work-001".to_string(),
            state: WorkState::CiPending,
            commit_sha: Some("abc123".to_string()),
        })
    });

    assert_eq!(result, CiQueueProcessResult::NoPrNumbers);
}

/// Test: CI event for unknown PR returns `NoWorkItem`.
#[test]
fn test_ci_event_unknown_pr() {
    let config = CIGatedQueueConfig::enabled();

    let ci_event = CIWorkflowCompleted::new(
        CIWorkflowPayload {
            pr_numbers: vec![999], // Unknown PR
            commit_sha: "abc123".to_string(),
            conclusion: CIConclusion::Success,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![],
        },
        true,
        "delivery-unknown-pr-001".to_string(),
    );

    let result = process_ci_event(&ci_event, &config, |_| None); // No work found

    assert_eq!(result, CiQueueProcessResult::NoWorkItem { pr_number: 999 });
}

/// Test: Blocked work can transition back to `CiPending` (retry).
#[test]
fn test_blocked_to_ci_pending_retry() {
    // Verify transition is allowed
    assert!(WorkState::Blocked.can_transition_to(&WorkState::CiPending));
    assert!(WorkState::Blocked.can_transition_to(&WorkState::InProgress));
}

/// Test: `ReadyForReview` transitions to Review when claimed.
#[test]
fn test_ready_for_review_to_review() {
    assert!(WorkState::ReadyForReview.can_transition_to(&WorkState::Review));
    assert!(WorkState::ReadyForReview.is_claimable());
}

/// Test: `target_phase_for_conclusion` returns correct phases.
#[test]
fn test_target_phase_for_conclusion() {
    assert_eq!(
        target_phase_for_conclusion(CIConclusion::Success),
        WorkState::ReadyForReview
    );
    assert_eq!(
        target_phase_for_conclusion(CIConclusion::Failure),
        WorkState::Blocked
    );
    assert_eq!(
        target_phase_for_conclusion(CIConclusion::Cancelled),
        WorkState::Blocked
    );
}

// ============================================================================
// Exit Signal Integration Tests
// ============================================================================

/// Test: Valid exit signal is processed correctly.
#[test]
fn test_exit_signal_valid() {
    let json = r#"{
        "protocol": "apm2_agent_exit",
        "version": "1.0.0",
        "phase_completed": "IMPLEMENTATION",
        "exit_reason": "completed",
        "pr_url": "https://github.com/org/repo/pull/123"
    }"#;

    let ctx = ExitHandlerContext {
        session_id: "session-001".to_string(),
        actor_id: "actor-001".to_string(),
        active_work_phase: Some(ExitWorkPhase::Implementation),
    };

    let result = handle_exit_signal(json, &ctx).unwrap();

    assert_eq!(
        result.exit_signal.phase_completed,
        ExitWorkPhase::Implementation
    );
    assert_eq!(result.exit_signal.exit_reason, ExitReason::Completed);
    assert_eq!(result.next_phase, ExitWorkPhase::CiPending);
    assert_eq!(result.event.session_id, "session-001");
}

/// Test: Exit signal with phase mismatch is rejected.
#[test]
fn test_exit_signal_phase_mismatch() {
    let json = r#"{
        "protocol": "apm2_agent_exit",
        "version": "1.0.0",
        "phase_completed": "REVIEW",
        "exit_reason": "completed"
    }"#;

    let ctx = ExitHandlerContext {
        session_id: "session-001".to_string(),
        actor_id: "actor-001".to_string(),
        active_work_phase: Some(ExitWorkPhase::Implementation), // Mismatch!
    };

    let result = handle_exit_signal(json, &ctx);

    assert!(matches!(
        result,
        Err(ExitHandlerError::PhaseMismatch { .. })
    ));
}

/// Test: Exit signal with no active phase is rejected.
#[test]
fn test_exit_signal_no_active_phase() {
    let json = r#"{
        "protocol": "apm2_agent_exit",
        "version": "1.0.0",
        "phase_completed": "IMPLEMENTATION",
        "exit_reason": "completed"
    }"#;

    let ctx = ExitHandlerContext {
        session_id: "session-001".to_string(),
        actor_id: "actor-001".to_string(),
        active_work_phase: None, // No active phase!
    };

    let result = handle_exit_signal(json, &ctx);

    assert!(matches!(result, Err(ExitHandlerError::NoActivePhase)));
}

/// Test: Exit signal with wrong protocol is rejected.
#[test]
fn test_exit_signal_wrong_protocol() {
    let json = r#"{
        "protocol": "wrong_protocol",
        "version": "1.0.0",
        "phase_completed": "IMPLEMENTATION",
        "exit_reason": "completed"
    }"#;

    let ctx = ExitHandlerContext {
        session_id: "session-001".to_string(),
        actor_id: "actor-001".to_string(),
        active_work_phase: Some(ExitWorkPhase::Implementation),
    };

    let result = handle_exit_signal(json, &ctx);

    assert!(matches!(result, Err(ExitHandlerError::ValidationFailed(_))));
}

/// Test: Blocked exit reason transitions to Blocked phase.
#[test]
fn test_exit_signal_blocked_reason() {
    let json = r#"{
        "protocol": "apm2_agent_exit",
        "version": "1.0.0",
        "phase_completed": "IMPLEMENTATION",
        "exit_reason": "blocked",
        "notes": "Waiting for API credentials"
    }"#;

    let ctx = ExitHandlerContext {
        session_id: "session-001".to_string(),
        actor_id: "actor-001".to_string(),
        active_work_phase: Some(ExitWorkPhase::Implementation),
    };

    let result = handle_exit_signal(json, &ctx).unwrap();

    assert_eq!(result.exit_signal.exit_reason, ExitReason::Blocked);
    assert_eq!(result.next_phase, ExitWorkPhase::Blocked);
}

// ============================================================================
// Rate Limiting Integration Tests
// ============================================================================

/// Test: Rate limiter enforces request limits.
#[test]
fn test_rate_limiter_enforces_limits() {
    let config = RateLimitConfig {
        max_requests: 2,
        window_secs: 60,
        cleanup_interval: 100,
        max_tracked_ips: 1000,
    };
    let limiter = RateLimiter::new(config);

    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    // First two requests succeed (within limit)
    assert!(limiter.check(ip).is_ok());
    assert!(limiter.check(ip).is_ok());

    // Third request should be rate limited
    let result = limiter.check(ip);
    assert!(matches!(result, Err(WebhookError::RateLimitExceeded)));
}

/// Test: Different IPs have separate rate limits.
#[test]
fn test_rate_limiter_per_ip() {
    let config = RateLimitConfig {
        max_requests: 1,
        window_secs: 60,
        cleanup_interval: 100,
        max_tracked_ips: 1000,
    };
    let limiter = RateLimiter::new(config);

    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    // Both IPs can make one request
    assert!(limiter.check(ip1).is_ok());
    assert!(limiter.check(ip2).is_ok());

    // Second request from each IP is rate limited
    assert!(matches!(
        limiter.check(ip1),
        Err(WebhookError::RateLimitExceeded)
    ));
    assert!(matches!(
        limiter.check(ip2),
        Err(WebhookError::RateLimitExceeded)
    ));
}

// ============================================================================
// All Conclusion Types Tests
// ============================================================================

/// Test: All workflow conclusion types are handled correctly.
#[test]
fn test_all_conclusion_types() {
    let conclusions = [
        ("success", WorkflowConclusion::Success),
        ("failure", WorkflowConclusion::Failure),
        ("cancelled", WorkflowConclusion::Cancelled),
        ("skipped", WorkflowConclusion::Skipped),
        ("timed_out", WorkflowConclusion::TimedOut),
        ("action_required", WorkflowConclusion::ActionRequired),
        ("stale", WorkflowConclusion::Stale),
        ("neutral", WorkflowConclusion::Neutral),
    ];

    for (str_val, expected) in conclusions {
        let payload = make_payload("completed", str_val, 42);
        let parsed = WorkflowRunPayload::parse(&payload).unwrap();
        let completed = parsed.into_completed().unwrap();
        assert_eq!(completed.conclusion, expected, "Failed for {str_val}");
    }
}

/// Test: `CIConclusion` conversion from `WorkflowConclusion`.
#[test]
fn test_ci_conclusion_conversion() {
    assert_eq!(
        CIConclusion::from(WorkflowConclusion::Success),
        CIConclusion::Success
    );
    assert_eq!(
        CIConclusion::from(WorkflowConclusion::Failure),
        CIConclusion::Failure
    );
    assert_eq!(
        CIConclusion::from(WorkflowConclusion::Cancelled),
        CIConclusion::Cancelled
    );
    // Non-standard conclusions map to Cancelled
    assert_eq!(
        CIConclusion::from(WorkflowConclusion::Skipped),
        CIConclusion::Cancelled
    );
    assert_eq!(
        CIConclusion::from(WorkflowConclusion::TimedOut),
        CIConclusion::Cancelled
    );
}
