//! Tests for the work module.

use super::error::WorkError;
use super::reducer::{WorkReducer, helpers};
use super::state::WorkState;
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

fn create_event(event_type: &str, session_id: &str, payload: Vec<u8>) -> EventRecord {
    EventRecord::with_timestamp(event_type, session_id, "test-actor", payload, 1_000_000_000)
}

// =============================================================================
// WorkOpened Tests
// =============================================================================

#[test]
fn test_work_reducer_new() {
    let reducer = WorkReducer::new();
    assert!(reducer.state().is_empty());
    assert_eq!(reducer.name(), "work-lifecycle");
}

#[test]
fn test_work_opened_creates_work() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::work_opened_payload(
        "work-1",
        "TICKET",
        vec![1, 2, 3, 4],
        vec!["REQ-001".to_string()],
        vec![],
    );
    let event = create_event("work.opened", "session-1", payload);

    reducer.apply(&event, &ctx).unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.work_id, "work-1");
    assert_eq!(work.state, WorkState::Open);
    assert_eq!(work.spec_snapshot_hash, vec![1, 2, 3, 4]);
    assert_eq!(work.requirement_ids, vec!["REQ-001"]);
    assert!(work.parent_work_ids.is_empty());
    assert!(work.is_active());
}

#[test]
fn test_work_opened_with_parents() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::work_opened_payload(
        "work-2",
        "RFC_REFINEMENT",
        vec![5, 6, 7],
        vec!["REQ-001".to_string(), "REQ-002".to_string()],
        vec!["work-1".to_string()],
    );
    let event = create_event("work.opened", "session-1", payload);

    reducer.apply(&event, &ctx).unwrap();

    let work = reducer.state().get("work-2").unwrap();
    assert_eq!(work.parent_work_ids, vec!["work-1"]);
    assert_eq!(work.requirement_ids.len(), 2);
}

#[test]
fn test_duplicate_work_opened_errors() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::work_opened_payload("work-1", "TICKET", vec![1, 2, 3], vec![], vec![]);
    let event = create_event("work.opened", "session-1", payload.clone());
    reducer.apply(&event, &ctx).unwrap();

    let event2 = create_event("work.opened", "session-1", payload);
    let result = reducer.apply(&event2, &ctx);
    assert!(matches!(result, Err(WorkError::WorkAlreadyExists { .. })));
}

// =============================================================================
// WorkTransitioned Tests
// =============================================================================

#[test]
fn test_work_transition_open_to_claimed() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open work
    let open_payload =
        helpers::work_opened_payload("work-1", "TICKET", vec![1, 2, 3], vec![], vec![]);
    let open_event = create_event("work.opened", "session-1", open_payload);
    reducer.apply(&open_event, &ctx).unwrap();

    // Transition to claimed
    let trans_payload =
        helpers::work_transitioned_payload("work-1", "OPEN", "CLAIMED", "agent_claimed");
    let mut trans_event = create_event("work.transitioned", "session-1", trans_payload);
    trans_event.timestamp_ns = 2_000_000_000;
    reducer.apply(&trans_event, &ctx).unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Claimed);
    assert_eq!(work.transition_count, 1);
    assert_eq!(work.last_transition_at, 2_000_000_000);
    assert_eq!(work.last_rationale_code, "agent_claimed");
}

#[test]
fn test_work_transition_claimed_to_in_progress() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open work
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    let open_event = create_event("work.opened", "session-1", open_payload);
    reducer.apply(&open_event, &ctx).unwrap();

    // Claim
    let claim_payload = helpers::work_transitioned_payload("work-1", "OPEN", "CLAIMED", "claimed");
    let claim_event = create_event("work.transitioned", "session-1", claim_payload);
    reducer.apply(&claim_event, &ctx).unwrap();

    // Start work
    let start_payload =
        helpers::work_transitioned_payload("work-1", "CLAIMED", "IN_PROGRESS", "started");
    let start_event = create_event("work.transitioned", "session-1", start_payload);
    reducer.apply(&start_event, &ctx).unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::InProgress);
    assert_eq!(work.transition_count, 2);
}

#[test]
fn test_work_transition_in_progress_to_review() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open -> Claimed -> InProgress
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    let claim_payload = helpers::work_transitioned_payload("work-1", "OPEN", "CLAIMED", "claimed");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", claim_payload),
            &ctx,
        )
        .unwrap();

    let start_payload =
        helpers::work_transitioned_payload("work-1", "CLAIMED", "IN_PROGRESS", "started");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", start_payload),
            &ctx,
        )
        .unwrap();

    // Submit for review
    let review_payload =
        helpers::work_transitioned_payload("work-1", "IN_PROGRESS", "REVIEW", "ready_for_review");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Review);
    assert_eq!(work.transition_count, 3);
}

#[test]
fn test_work_transition_in_progress_to_needs_input() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open -> Claimed -> InProgress
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Block on input
    let block_payload = helpers::work_transitioned_payload(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_INPUT",
        "waiting_for_requirements",
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", block_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::NeedsInput);
}

#[test]
fn test_work_transition_needs_input_to_in_progress() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open -> Claimed -> InProgress -> NeedsInput
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let block_payload =
        helpers::work_transitioned_payload("work-1", "IN_PROGRESS", "NEEDS_INPUT", "blocked");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", block_payload),
            &ctx,
        )
        .unwrap();

    // Resume
    let resume_payload = helpers::work_transitioned_payload(
        "work-1",
        "NEEDS_INPUT",
        "IN_PROGRESS",
        "input_received",
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", resume_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::InProgress);
}

#[test]
fn test_work_transition_review_to_in_progress_revision() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open -> Claimed -> InProgress -> Review
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let review_payload =
        helpers::work_transitioned_payload("work-1", "IN_PROGRESS", "REVIEW", "submitted");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    // Review requests changes
    let revision_payload =
        helpers::work_transitioned_payload("work-1", "REVIEW", "IN_PROGRESS", "changes_requested");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", revision_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::InProgress);
}

#[test]
fn test_work_transition_claimed_release_to_open() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open -> Claimed
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    let claim_payload = helpers::work_transitioned_payload("work-1", "OPEN", "CLAIMED", "claimed");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", claim_payload),
            &ctx,
        )
        .unwrap();

    // Release claim
    let release_payload =
        helpers::work_transitioned_payload("work-1", "CLAIMED", "OPEN", "claim_released");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", release_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Open);
}

#[test]
fn test_invalid_transition_errors() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open work
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    // Try to go directly from Open to InProgress (should fail)
    let bad_trans = helpers::work_transitioned_payload("work-1", "OPEN", "IN_PROGRESS", "bad");
    let result = reducer.apply(
        &create_event("work.transitioned", "session-1", bad_trans),
        &ctx,
    );
    assert!(matches!(
        result,
        Err(WorkError::TransitionNotAllowed { .. })
    ));
}

#[test]
fn test_transition_wrong_from_state_errors() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open work
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    // Try transition with wrong from_state (says CLAIMED but work is OPEN)
    let bad_trans = helpers::work_transitioned_payload("work-1", "CLAIMED", "IN_PROGRESS", "bad");
    let result = reducer.apply(
        &create_event("work.transitioned", "session-1", bad_trans),
        &ctx,
    );
    assert!(matches!(result, Err(WorkError::InvalidTransition { .. })));
}

#[test]
fn test_transition_unknown_work_errors() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let trans = helpers::work_transitioned_payload("unknown-work", "OPEN", "CLAIMED", "claim");
    let result = reducer.apply(&create_event("work.transitioned", "session-1", trans), &ctx);
    assert!(matches!(result, Err(WorkError::WorkNotFound { .. })));
}

// =============================================================================
// WorkCompleted Tests
// =============================================================================

#[test]
fn test_work_completed_from_review() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> Review
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let review_payload =
        helpers::work_transitioned_payload("work-1", "IN_PROGRESS", "REVIEW", "submitted");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    // Complete with evidence
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string(), "EVID-002".to_string()],
        "GATE-001",
    );
    let mut complete_event = create_event("work.completed", "session-1", complete_payload);
    complete_event.timestamp_ns = 5_000_000_000;
    reducer.apply(&complete_event, &ctx).unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Completed);
    assert!(work.is_terminal());
    assert_eq!(work.evidence_bundle_hash, Some(vec![10, 20, 30]));
    assert_eq!(work.evidence_ids, vec!["EVID-001", "EVID-002"]);
    assert_eq!(work.gate_receipt_id, Some("GATE-001".to_string()));
    assert_eq!(work.last_transition_at, 5_000_000_000);
}

#[test]
fn test_work_completed_not_from_review_errors() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress (not Review)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Try to complete from InProgress (should fail)
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string()],
        "GATE-001",
    );
    let result = reducer.apply(
        &create_event("work.completed", "session-1", complete_payload),
        &ctx,
    );
    assert!(matches!(result, Err(WorkError::InvalidTransition { .. })));
}

#[test]
fn test_work_completed_without_evidence_errors() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> Review
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let review_payload =
        helpers::work_transitioned_payload("work-1", "IN_PROGRESS", "REVIEW", "submitted");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    // Try to complete without evidence
    let complete_payload = helpers::work_completed_payload("work-1", vec![], vec![], "");
    let result = reducer.apply(
        &create_event("work.completed", "session-1", complete_payload),
        &ctx,
    );
    assert!(matches!(
        result,
        Err(WorkError::CompletionWithoutEvidence { .. })
    ));
}

// =============================================================================
// WorkAborted Tests
// =============================================================================

#[test]
fn test_work_aborted_from_open() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    let abort_payload = helpers::work_aborted_payload("work-1", "MANUAL", "user_cancelled");
    reducer
        .apply(
            &create_event("work.aborted", "session-1", abort_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Aborted);
    assert!(work.is_terminal());
    assert_eq!(work.abort_reason, Some("MANUAL".to_string()));
}

#[test]
fn test_work_aborted_from_in_progress() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let abort_payload = helpers::work_aborted_payload("work-1", "TIMEOUT", "deadline_exceeded");
    reducer
        .apply(
            &create_event("work.aborted", "session-1", abort_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Aborted);
    assert_eq!(work.abort_reason, Some("TIMEOUT".to_string()));
    assert_eq!(work.last_rationale_code, "deadline_exceeded");
}

#[test]
fn test_work_aborted_from_review() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let review_payload =
        helpers::work_transitioned_payload("work-1", "IN_PROGRESS", "REVIEW", "submitted");
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    let abort_payload = helpers::work_aborted_payload("work-1", "POLICY_DENY", "policy_violation");
    reducer
        .apply(
            &create_event("work.aborted", "session-1", abort_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Aborted);
}

#[test]
fn test_work_aborted_already_terminal_errors() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Complete work first
    setup_completed_work(&mut reducer, &ctx, "work-1");

    // Try to abort completed work
    let abort_payload = helpers::work_aborted_payload("work-1", "MANUAL", "late_cancel");
    let result = reducer.apply(
        &create_event("work.aborted", "session-1", abort_payload),
        &ctx,
    );
    assert!(matches!(result, Err(WorkError::InvalidTransition { .. })));
}

#[test]
fn test_work_transition_after_completed_errors() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_completed_work(&mut reducer, &ctx, "work-1");

    // Try to transition completed work
    let trans = helpers::work_transitioned_payload("work-1", "COMPLETED", "IN_PROGRESS", "reopen");
    let result = reducer.apply(&create_event("work.transitioned", "session-1", trans), &ctx);
    assert!(matches!(result, Err(WorkError::InvalidTransition { .. })));
}

// =============================================================================
// State Query Tests
// =============================================================================

#[test]
fn test_state_counts() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Create 5 work items in different states
    for i in 1..=5 {
        let payload =
            helpers::work_opened_payload(&format!("work-{i}"), "TICKET", vec![], vec![], vec![]);
        reducer
            .apply(&create_event("work.opened", "session-1", payload), &ctx)
            .unwrap();
    }

    assert_eq!(reducer.state().len(), 5);
    assert_eq!(reducer.state().active_count(), 5);
    assert_eq!(reducer.state().completed_count(), 0);
    assert_eq!(reducer.state().aborted_count(), 0);

    // Complete work-1 (need to go through full lifecycle)
    let claim1 = helpers::work_transitioned_payload("work-1", "OPEN", "CLAIMED", "claim");
    reducer
        .apply(&create_event("work.transitioned", "s", claim1), &ctx)
        .unwrap();
    let start1 = helpers::work_transitioned_payload("work-1", "CLAIMED", "IN_PROGRESS", "start");
    reducer
        .apply(&create_event("work.transitioned", "s", start1), &ctx)
        .unwrap();
    let review1 = helpers::work_transitioned_payload("work-1", "IN_PROGRESS", "REVIEW", "review");
    reducer
        .apply(&create_event("work.transitioned", "s", review1), &ctx)
        .unwrap();
    let complete1 =
        helpers::work_completed_payload("work-1", vec![1], vec!["E1".to_string()], "G1");
    reducer
        .apply(&create_event("work.completed", "s", complete1), &ctx)
        .unwrap();

    // Abort work-2
    let abort2 = helpers::work_aborted_payload("work-2", "MANUAL", "cancelled");
    reducer
        .apply(&create_event("work.aborted", "s", abort2), &ctx)
        .unwrap();

    assert_eq!(reducer.state().len(), 5);
    assert_eq!(reducer.state().active_count(), 3);
    assert_eq!(reducer.state().completed_count(), 1);
    assert_eq!(reducer.state().aborted_count(), 1);
}

#[test]
fn test_in_state_query() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Create work items
    for i in 1..=3 {
        let payload =
            helpers::work_opened_payload(&format!("work-{i}"), "TICKET", vec![], vec![], vec![]);
        reducer
            .apply(&create_event("work.opened", "session-1", payload), &ctx)
            .unwrap();
    }

    // Claim work-1
    let claim1 = helpers::work_transitioned_payload("work-1", "OPEN", "CLAIMED", "claim");
    reducer
        .apply(&create_event("work.transitioned", "s", claim1), &ctx)
        .unwrap();

    let open_work = reducer.state().in_state(WorkState::Open);
    assert_eq!(open_work.len(), 2);

    let claimed_work = reducer.state().in_state(WorkState::Claimed);
    assert_eq!(claimed_work.len(), 1);
    assert_eq!(claimed_work[0].work_id, "work-1");
}

#[test]
fn test_by_requirement_query() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Work items with different requirements
    let payload1 = helpers::work_opened_payload(
        "work-1",
        "TICKET",
        vec![],
        vec!["REQ-001".to_string(), "REQ-002".to_string()],
        vec![],
    );
    reducer
        .apply(&create_event("work.opened", "s", payload1), &ctx)
        .unwrap();

    let payload2 = helpers::work_opened_payload(
        "work-2",
        "TICKET",
        vec![],
        vec!["REQ-001".to_string()],
        vec![],
    );
    reducer
        .apply(&create_event("work.opened", "s", payload2), &ctx)
        .unwrap();

    let payload3 = helpers::work_opened_payload(
        "work-3",
        "TICKET",
        vec![],
        vec!["REQ-003".to_string()],
        vec![],
    );
    reducer
        .apply(&create_event("work.opened", "s", payload3), &ctx)
        .unwrap();

    let req001_work = reducer.state().by_requirement("REQ-001");
    assert_eq!(req001_work.len(), 2);

    let req002_work = reducer.state().by_requirement("REQ-002");
    assert_eq!(req002_work.len(), 1);
    assert_eq!(req002_work[0].work_id, "work-1");

    let req003_work = reducer.state().by_requirement("REQ-003");
    assert_eq!(req003_work.len(), 1);

    let unknown_req = reducer.state().by_requirement("REQ-999");
    assert!(unknown_req.is_empty());
}

#[test]
fn test_reset() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", payload), &ctx)
        .unwrap();
    assert!(!reducer.state().is_empty());

    reducer.reset();
    assert!(reducer.state().is_empty());
}

#[test]
fn test_ignores_non_work_events() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let event = create_event("session.started", "session-1", vec![1, 2, 3]);
    let result = reducer.apply(&event, &ctx);
    assert!(result.is_ok());
    assert!(reducer.state().is_empty());
}

// =============================================================================
// Spec Snapshot Tests
// =============================================================================

#[test]
fn test_spec_snapshot_hash_preserved() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let snapshot_hash = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
    let payload = helpers::work_opened_payload(
        "work-1",
        "TICKET",
        snapshot_hash.clone(),
        vec!["REQ-001".to_string()],
        vec![],
    );
    reducer
        .apply(&create_event("work.opened", "s", payload), &ctx)
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.spec_snapshot_hash, snapshot_hash);

    // Verify it persists through transitions
    let claim = helpers::work_transitioned_payload("work-1", "OPEN", "CLAIMED", "claim");
    reducer
        .apply(&create_event("work.transitioned", "s", claim), &ctx)
        .unwrap();

    let work_after = reducer.state().get("work-1").unwrap();
    assert_eq!(work_after.spec_snapshot_hash, snapshot_hash);
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Sets up a work item in the `InProgress` state.
fn setup_in_progress_work(reducer: &mut WorkReducer, ctx: &ReducerContext, work_id: &str) {
    let open_payload = helpers::work_opened_payload(work_id, "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), ctx)
        .unwrap();

    let claim_payload = helpers::work_transitioned_payload(work_id, "OPEN", "CLAIMED", "claim");
    reducer
        .apply(&create_event("work.transitioned", "s", claim_payload), ctx)
        .unwrap();

    let start_payload =
        helpers::work_transitioned_payload(work_id, "CLAIMED", "IN_PROGRESS", "start");
    reducer
        .apply(&create_event("work.transitioned", "s", start_payload), ctx)
        .unwrap();
}

/// Sets up a work item in the Completed state.
fn setup_completed_work(reducer: &mut WorkReducer, ctx: &ReducerContext, work_id: &str) {
    setup_in_progress_work(reducer, ctx, work_id);

    let review_payload =
        helpers::work_transitioned_payload(work_id, "IN_PROGRESS", "REVIEW", "review");
    reducer
        .apply(&create_event("work.transitioned", "s", review_payload), ctx)
        .unwrap();

    let complete_payload =
        helpers::work_completed_payload(work_id, vec![1], vec!["E1".to_string()], "G1");
    reducer
        .apply(&create_event("work.completed", "s", complete_payload), ctx)
        .unwrap();
}

// =============================================================================
// NeedsAdjudication Tests
// =============================================================================

#[test]
fn test_work_transition_in_progress_to_needs_adjudication() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let adj_payload = helpers::work_transitioned_payload(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_ADJUDICATION",
        "requires_human_decision",
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", adj_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::NeedsAdjudication);
}

#[test]
fn test_work_transition_needs_adjudication_to_in_progress() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> NeedsAdjudication
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let adj_payload = helpers::work_transitioned_payload(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_ADJUDICATION",
        "awaiting_decision",
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", adj_payload),
            &ctx,
        )
        .unwrap();

    // Resume after adjudication
    let resume_payload = helpers::work_transitioned_payload(
        "work-1",
        "NEEDS_ADJUDICATION",
        "IN_PROGRESS",
        "decision_received",
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", resume_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::InProgress);
}

#[test]
fn test_work_aborted_from_needs_adjudication() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    let adj_payload = helpers::work_transitioned_payload(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_ADJUDICATION",
        "awaiting",
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", adj_payload),
            &ctx,
        )
        .unwrap();

    let abort_payload = helpers::work_aborted_payload("work-1", "TIMEOUT", "adjudication_timeout");
    reducer
        .apply(
            &create_event("work.aborted", "session-1", abort_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Aborted);
}

// =============================================================================
// Security Tests - Strict Parsing & Replay Protection
// =============================================================================

#[test]
fn test_invalid_work_type_rejected() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Try to open work with invalid type
    let payload = helpers::work_opened_payload(
        "work-1",
        "INVALID_TYPE", // Not a valid work type
        vec![1, 2, 3],
        vec![],
        vec![],
    );
    let event = create_event("work.opened", "session-1", payload);

    let result = reducer.apply(&event, &ctx);
    assert!(matches!(result, Err(WorkError::InvalidWorkType { .. })));
}

#[test]
fn test_invalid_work_state_rejected() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open valid work first
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), &ctx)
        .unwrap();

    // Try transition with invalid from_state
    let trans_payload = helpers::work_transitioned_payload(
        "work-1",
        "INVALID_STATE", // Not a valid state
        "CLAIMED",
        "test",
    );
    let result = reducer.apply(&create_event("work.transitioned", "s", trans_payload), &ctx);
    assert!(matches!(result, Err(WorkError::InvalidWorkState { .. })));
}

#[test]
fn test_invalid_to_state_rejected() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open valid work first
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), &ctx)
        .unwrap();

    // Try transition with invalid to_state
    let trans_payload = helpers::work_transitioned_payload(
        "work-1",
        "OPEN",
        "BOGUS_STATE", // Not a valid state
        "test",
    );
    let result = reducer.apply(&create_event("work.transitioned", "s", trans_payload), &ctx);
    assert!(matches!(result, Err(WorkError::InvalidWorkState { .. })));
}

#[test]
fn test_sequence_mismatch_rejected() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open work (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), &ctx)
        .unwrap();

    // Transition with correct sequence (previous_transition_count = 0)
    let trans_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1", "OPEN", "CLAIMED", "claim", 0, // Correct: work.transition_count is 0
    );
    reducer
        .apply(&create_event("work.transitioned", "s", trans_payload), &ctx)
        .unwrap();

    // Work now has transition_count = 1
    // Try to transition with wrong sequence (should fail)
    let bad_seq_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        5, // Wrong: work.transition_count is 1, not 5
    );
    let result = reducer.apply(
        &create_event("work.transitioned", "s", bad_seq_payload),
        &ctx,
    );
    assert!(matches!(result, Err(WorkError::SequenceMismatch { .. })));

    // Verify work state unchanged (transition was rejected)
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Claimed);
    assert_eq!(work.transition_count, 1);
}

#[test]
fn test_sequence_validation_with_correct_count() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open work
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), &ctx)
        .unwrap();

    // First transition with sequence validation
    let trans1 = helpers::work_transitioned_payload_with_sequence(
        "work-1", "OPEN", "CLAIMED", "claim", 0, // Correct
    );
    reducer
        .apply(&create_event("work.transitioned", "s", trans1), &ctx)
        .unwrap();

    // Second transition with sequence validation
    let trans2 = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        1, // Correct
    );
    reducer
        .apply(&create_event("work.transitioned", "s", trans2), &ctx)
        .unwrap();

    // Verify all transitions succeeded
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::InProgress);
    assert_eq!(work.transition_count, 2);
}

#[test]
fn test_sequence_zero_skips_validation() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open work
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), &ctx)
        .unwrap();

    // Transition with sequence = 0 (backward compatibility - skips validation)
    let trans1 = helpers::work_transitioned_payload_with_sequence(
        "work-1", "OPEN", "CLAIMED", "claim", 0, // Zero means no validation
    );
    reducer
        .apply(&create_event("work.transitioned", "s", trans1), &ctx)
        .unwrap();

    // Another transition with sequence = 0
    let trans2 = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        0, // Zero means no validation
    );
    reducer
        .apply(&create_event("work.transitioned", "s", trans2), &ctx)
        .unwrap();

    // Transitions work without explicit sequence
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::InProgress);
    assert_eq!(work.transition_count, 2);
}
