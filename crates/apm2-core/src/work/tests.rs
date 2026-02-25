//! Tests for the work module.

use serde_json::json;

use super::error::WorkError;
use super::reducer::{CI_SYSTEM_ACTOR_ID, WorkReducer, helpers};
use super::state::WorkState;
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

fn create_event(event_type: &str, session_id: &str, payload: Vec<u8>) -> EventRecord {
    EventRecord::with_timestamp(event_type, session_id, "test-actor", payload, 1_000_000_000)
}

fn create_event_with_actor(
    event_type: &str,
    session_id: &str,
    actor_id: &str,
    payload: Vec<u8>,
) -> EventRecord {
    EventRecord::with_timestamp(event_type, session_id, actor_id, payload, 1_000_000_000)
}

fn default_changeset_digest() -> [u8; 32] {
    [0x42; 32]
}

fn apply_changeset_published(
    reducer: &mut WorkReducer,
    ctx: &ReducerContext,
    work_id: &str,
    digest: [u8; 32],
) {
    let payload = serde_json::to_vec(&json!({
        "event_type": "changeset_published",
        "work_id": work_id,
        "changeset_digest": hex::encode(digest),
    }))
    .expect("serialize changeset_published payload");
    // session_id must match payload work_id (envelope binding — CSID-004)
    reducer
        .apply(&create_event("changeset_published", work_id, payload), ctx)
        .expect("apply changeset_published");
}

fn apply_gate_receipt_collected(
    reducer: &mut WorkReducer,
    ctx: &ReducerContext,
    work_id: &str,
    digest: [u8; 32],
) {
    let payload = serde_json::to_vec(&json!({
        "work_id": work_id,
        "changeset_digest": hex::encode(digest),
    }))
    .expect("serialize gate receipt payload");
    // session_id must match payload work_id (envelope binding — CSID-004)
    reducer
        .apply(
            &create_event("gate.receipt_collected", work_id, payload),
            ctx,
        )
        .expect("apply gate.receipt_collected");
}

fn apply_review_receipt_recorded(
    reducer: &mut WorkReducer,
    ctx: &ReducerContext,
    work_id: &str,
    digest: [u8; 32],
) {
    let payload = serde_json::to_vec(&json!({
        "event_type": "review_receipt_recorded",
        "work_id": work_id,
        "changeset_digest": hex::encode(digest),
    }))
    .expect("serialize review receipt payload");
    // session_id must match payload work_id (envelope binding — CSID-004)
    reducer
        .apply(
            &create_event("review_receipt_recorded", work_id, payload),
            ctx,
        )
        .expect("apply review_receipt_recorded");
}

fn apply_merge_receipt_recorded(
    reducer: &mut WorkReducer,
    ctx: &ReducerContext,
    work_id: &str,
    digest: [u8; 32],
) {
    let payload = serde_json::to_vec(&json!({
        "event_type": "merge_receipt_recorded",
        "work_id": work_id,
        "changeset_digest": hex::encode(digest),
    }))
    .expect("serialize merge receipt payload");
    // session_id must match payload work_id (envelope binding — CSID-004)
    reducer
        .apply(
            &create_event("merge_receipt_recorded", work_id, payload),
            ctx,
        )
        .expect("apply merge_receipt_recorded");
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

    // Open work (transition_count = 0)
    let open_payload =
        helpers::work_opened_payload("work-1", "TICKET", vec![1, 2, 3], vec![], vec![]);
    let open_event = create_event("work.opened", "session-1", open_payload);
    reducer.apply(&open_event, &ctx).unwrap();

    // Transition to claimed (previous_transition_count = 0)
    let trans_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "OPEN",
        "CLAIMED",
        "agent_claimed",
        0,
    );
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

    // Open work (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    let open_event = create_event("work.opened", "session-1", open_payload);
    reducer.apply(&open_event, &ctx).unwrap();

    // Claim (previous_transition_count = 0)
    let claim_payload =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claimed", 0);
    let claim_event = create_event("work.transitioned", "session-1", claim_payload);
    reducer.apply(&claim_event, &ctx).unwrap();

    // Start work (previous_transition_count = 1)
    let start_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "started",
        1,
    );
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

    // Open -> Claimed -> InProgress (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    let claim_payload =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claimed", 0);
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", claim_payload),
            &ctx,
        )
        .unwrap();

    let start_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "started",
        1,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", start_payload),
            &ctx,
        )
        .unwrap();

    // Publish a changeset — required by the review-start boundary guard
    // (CSID-004) which now covers ALL transitions to Review (not just
    // ReadyForReview -> Review).
    apply_changeset_published(&mut reducer, &ctx, "work-1", default_changeset_digest());

    // Submit for review (previous_transition_count = 2)
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "REVIEW",
        "ready_for_review",
        2,
    );
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

    // Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Block on input (previous_transition_count = 2)
    let block_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_INPUT",
        "waiting_for_requirements",
        2,
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

    // Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Block on input (previous_transition_count = 2)
    let block_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_INPUT",
        "blocked",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", block_payload),
            &ctx,
        )
        .unwrap();

    // Resume (previous_transition_count = 3)
    let resume_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "NEEDS_INPUT",
        "IN_PROGRESS",
        "input_received",
        3,
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

    // Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Submit for review (previous_transition_count = 2)
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "REVIEW",
        "submitted",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    // Review requests changes (previous_transition_count = 3)
    let revision_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "REVIEW",
        "IN_PROGRESS",
        "changes_requested",
        3,
    );
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

    // Open -> Claimed (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    let claim_payload =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claimed", 0);
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", claim_payload),
            &ctx,
        )
        .unwrap();

    // Release claim (previous_transition_count = 1)
    let release_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "OPEN",
        "claim_released",
        1,
    );
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

    // Open work (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    // Try to go directly from Open to InProgress (should fail - transition not
    // allowed)
    let bad_trans = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "OPEN",
        "IN_PROGRESS",
        "bad",
        0, // Correct sequence, but invalid transition
    );
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

    // Open work (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    // Try transition with wrong from_state (says CLAIMED but work is OPEN)
    let bad_trans = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "bad",
        0,
    );
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

    let trans = helpers::work_transitioned_payload_with_sequence(
        "unknown-work",
        "OPEN",
        "CLAIMED",
        "claim",
        0,
    );
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

    // Setup: Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Submit for review (previous_transition_count = 2)
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "REVIEW",
        "submitted",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();
    apply_merge_receipt_recorded(&mut reducer, &ctx, "work-1", default_changeset_digest());

    // Complete with evidence
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string(), "EVID-002".to_string()],
        "GATE-001",
        "merge-receipt-sha123",
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
    assert_eq!(
        work.merge_receipt_id,
        Some("merge-receipt-sha123".to_string())
    );
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
        "",
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

    // Setup: Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Submit for review (previous_transition_count = 2)
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "REVIEW",
        "submitted",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    // Try to complete without evidence
    let complete_payload = helpers::work_completed_payload("work-1", vec![], vec![], "", "");
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
// RFC-0032::REQ-0271: merge_receipt_id / gate_receipt_id field semantics
// =============================================================================

#[test]
fn test_work_completed_rejects_merge_receipt_in_gate_receipt_id() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> Review
    setup_review_work(&mut reducer, &ctx, "work-1");
    apply_merge_receipt_recorded(&mut reducer, &ctx, "work-1", default_changeset_digest());

    // Attempt to complete with a merge-receipt-* string in gate_receipt_id
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string()],
        "merge-receipt-abc123",
        "",
    );
    let result = reducer.apply(
        &create_event("work.completed", "session-1", complete_payload),
        &ctx,
    );
    assert!(
        matches!(
            result,
            Err(WorkError::MergeReceiptInGateReceiptField { .. })
        ),
        "expected MergeReceiptInGateReceiptField error, got: {result:?}"
    );
}

#[test]
fn test_work_completed_accepts_merge_receipt_in_dedicated_field() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> Review
    setup_review_work(&mut reducer, &ctx, "work-1");
    apply_merge_receipt_recorded(&mut reducer, &ctx, "work-1", default_changeset_digest());

    // Complete with merge_receipt_id in the dedicated field (gate_receipt_id left
    // empty)
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string()],
        "",
        "merge-receipt-abc123",
    );
    let mut complete_event = create_event("work.completed", "session-1", complete_payload);
    complete_event.timestamp_ns = 5_000_000_000;
    reducer.apply(&complete_event, &ctx).unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Completed);
    assert_eq!(work.gate_receipt_id, None);
    assert_eq!(
        work.merge_receipt_id,
        Some("merge-receipt-abc123".to_string())
    );
}

#[test]
fn test_work_completed_stores_both_gate_and_merge_receipt_ids() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> Review
    setup_review_work(&mut reducer, &ctx, "work-1");
    apply_merge_receipt_recorded(&mut reducer, &ctx, "work-1", default_changeset_digest());

    // Complete with both gate_receipt_id (a real gate receipt) and merge_receipt_id
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string()],
        "gate-receipt-quality-001",
        "merge-receipt-sha456",
    );
    let mut complete_event = create_event("work.completed", "session-1", complete_payload);
    complete_event.timestamp_ns = 5_000_000_000;
    reducer.apply(&complete_event, &ctx).unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Completed);
    assert_eq!(
        work.gate_receipt_id,
        Some("gate-receipt-quality-001".to_string())
    );
    assert_eq!(
        work.merge_receipt_id,
        Some("merge-receipt-sha456".to_string())
    );
}

// RFC-0032::REQ-0271 Round 2: Bidirectional domain separation (INV-0113 +
// INV-0114)

#[test]
fn test_work_completed_rejects_invalid_merge_receipt_id_prefix() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_review_work(&mut reducer, &ctx, "work-1");

    // Attempt to complete with a merge_receipt_id that does NOT start with
    // "merge-receipt-".  This should fail per INV-0114.
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string()],
        "",
        "gate-receipt-injected-into-merge-field",
    );
    let result = reducer.apply(
        &create_event("work.completed", "session-1", complete_payload),
        &ctx,
    );
    assert!(
        matches!(result, Err(WorkError::InvalidMergeReceiptId { .. })),
        "expected InvalidMergeReceiptId error, got: {result:?}"
    );

    // Verify work is still in Review state (mutation not applied)
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Review);
}

#[test]
fn test_work_completed_rejects_bare_string_in_merge_receipt_id() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_review_work(&mut reducer, &ctx, "work-1");

    // A bare string with no recognized prefix in merge_receipt_id
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string()],
        "",
        "some-random-value",
    );
    let result = reducer.apply(
        &create_event("work.completed", "session-1", complete_payload),
        &ctx,
    );
    assert!(
        matches!(result, Err(WorkError::InvalidMergeReceiptId { .. })),
        "expected InvalidMergeReceiptId error for bare string, got: {result:?}"
    );
}

#[test]
fn test_work_completed_accepts_case_variant_merge_receipt_prefix() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_review_work(&mut reducer, &ctx, "work-1");
    // Seed merge-stage digest (required for non-empty merge_receipt_id).
    apply_merge_receipt_recorded(&mut reducer, &ctx, "work-1", default_changeset_digest());

    // Case-variant prefix (MERGE-RECEIPT-) is accepted — the domain
    // separation check normalizes to ASCII lowercase before the
    // starts_with comparison, so all case variants of "merge-receipt-"
    // are valid merge receipt identifiers.
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string()],
        "gate-receipt-quality-001",
        "MERGE-RECEIPT-abc123",
    );
    let result = reducer.apply(
        &create_event("work.completed", "session-1", complete_payload),
        &ctx,
    );
    assert!(
        result.is_ok(),
        "expected case-variant MERGE-RECEIPT- prefix to be accepted, got: {result:?}"
    );
}

#[test]
fn test_work_completed_rejects_case_variant_gate_receipt_cross_injection() {
    let ctx = ReducerContext::new(1);

    // Part A: Case-variant merge receipt prefix in gate_receipt_id field
    // must be rejected — the domain separation check normalizes to ASCII
    // lowercase so "MERGE-RECEIPT-", "Merge-Receipt-", etc. are all caught.
    let case_variants_gate = [
        "MERGE-RECEIPT-abc123",
        "Merge-Receipt-abc123",
        "MERGE-receipt-abc123",
        "Merge-RECEIPT-abc123",
    ];
    for variant in &case_variants_gate {
        let mut reducer = WorkReducer::new();
        setup_review_work(&mut reducer, &ctx, "work-1");
        let payload = helpers::work_completed_payload(
            "work-1",
            vec![10, 20, 30],
            vec!["EVID-001".to_string()],
            variant, // case-variant in gate_receipt_id
            "",
        );
        let result = reducer.apply(&create_event("work.completed", "session-1", payload), &ctx);
        assert!(
            matches!(
                result,
                Err(WorkError::MergeReceiptInGateReceiptField { .. })
            ),
            "expected MergeReceiptInGateReceiptField for gate_receipt_id \
             case-variant '{variant}', got: {result:?}"
        );
    }

    // Part B: Case-variant merge receipt prefix in merge_receipt_id field
    // is now accepted because the check normalizes to lowercase — all
    // case variants of "merge-receipt-" are valid merge receipt prefixes.
    let case_variants_merge = [
        "MERGE-RECEIPT-abc123",
        "Merge-Receipt-abc123",
        "Merge-RECEIPT-abc123",
    ];
    for variant in &case_variants_merge {
        let mut reducer = WorkReducer::new();
        setup_review_work(&mut reducer, &ctx, "work-1");
        // Seed merge-stage digest (required for non-empty merge_receipt_id).
        apply_merge_receipt_recorded(&mut reducer, &ctx, "work-1", default_changeset_digest());
        let payload = helpers::work_completed_payload(
            "work-1",
            vec![10, 20, 30],
            vec!["EVID-001".to_string()],
            "gate-receipt-quality-001",
            variant, // case-variant in merge_receipt_id — should pass now
        );
        let result = reducer.apply(&create_event("work.completed", "session-1", payload), &ctx);
        assert!(
            result.is_ok(),
            "expected case-insensitive merge_receipt_id '{variant}' to be \
             accepted, got: {result:?}"
        );
    }
}

#[test]
fn test_work_completed_accepts_empty_merge_receipt_id() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_review_work(&mut reducer, &ctx, "work-1");

    // Empty merge_receipt_id is valid (not all completions involve merges)
    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![10, 20, 30],
        vec!["EVID-001".to_string()],
        "gate-receipt-quality-001",
        "",
    );
    let mut complete_event = create_event("work.completed", "session-1", complete_payload);
    complete_event.timestamp_ns = 5_000_000_000;
    reducer.apply(&complete_event, &ctx).unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Completed);
    assert_eq!(work.merge_receipt_id, None);
    assert_eq!(
        work.gate_receipt_id,
        Some("gate-receipt-quality-001".to_string())
    );
}

#[test]
fn test_work_completed_bidirectional_domain_separation() {
    // Verify that BOTH directions of cross-injection are blocked:
    // 1. merge receipt ID in gate_receipt_id field → MergeReceiptInGateReceiptField
    // 2. gate receipt ID in merge_receipt_id field → InvalidMergeReceiptId
    let ctx = ReducerContext::new(1);

    // Direction 1: merge receipt in gate field
    {
        let mut reducer = WorkReducer::new();
        setup_review_work(&mut reducer, &ctx, "work-1");
        let payload = helpers::work_completed_payload(
            "work-1",
            vec![1],
            vec!["E".to_string()],
            "merge-receipt-in-wrong-field",
            "",
        );
        let result = reducer.apply(&create_event("work.completed", "session-1", payload), &ctx);
        assert!(
            matches!(
                result,
                Err(WorkError::MergeReceiptInGateReceiptField { .. })
            ),
            "direction 1 failed: {result:?}"
        );
    }

    // Direction 2: gate receipt in merge field
    {
        let mut reducer = WorkReducer::new();
        setup_review_work(&mut reducer, &ctx, "work-2");
        let payload = helpers::work_completed_payload(
            "work-2",
            vec![1],
            vec!["E".to_string()],
            "",
            "gate-receipt-quality-in-wrong-field",
        );
        let result = reducer.apply(&create_event("work.completed", "session-1", payload), &ctx);
        assert!(
            matches!(result, Err(WorkError::InvalidMergeReceiptId { .. })),
            "direction 2 failed: {result:?}"
        );
    }
}

#[test]
fn test_work_completed_no_state_mutation_on_validation_failure() {
    // Verify that when domain-separation validation rejects a completion,
    // the work item's state is NOT mutated (fail-closed: admission before
    // mutation).
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_review_work(&mut reducer, &ctx, "work-1");

    // Capture pre-validation state
    let pre_transition_count = reducer.state().get("work-1").unwrap().transition_count;

    // Attempt invalid completion (gate receipt in merge field)
    let payload = helpers::work_completed_payload(
        "work-1",
        vec![1],
        vec!["E".to_string()],
        "",
        "not-a-valid-merge-receipt",
    );
    let result = reducer.apply(&create_event("work.completed", "session-1", payload), &ctx);
    assert!(result.is_err());

    // Verify state is completely unchanged
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(
        work.state,
        WorkState::Review,
        "state must not change on validation failure"
    );
    assert_eq!(
        work.transition_count, pre_transition_count,
        "transition_count must not change on validation failure"
    );
    assert_eq!(
        work.evidence_bundle_hash, None,
        "evidence must not be set on validation failure"
    );
    assert!(
        work.evidence_ids.is_empty(),
        "evidence_ids must stay empty on validation failure"
    );
    assert_eq!(
        work.gate_receipt_id, None,
        "gate_receipt_id must stay None on validation failure"
    );
    assert_eq!(
        work.merge_receipt_id, None,
        "merge_receipt_id must stay None on validation failure"
    );
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

    // Setup: Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Submit for review (previous_transition_count = 2)
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "REVIEW",
        "submitted",
        2,
    );
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

    // Create 5 work items in different states (each starts with transition_count =
    // 0)
    for i in 1..=5 {
        let payload =
            helpers::work_opened_payload(&format!("work-{i}"), "TICKET", vec![], vec![], vec![]);
        reducer
            .apply(&create_event("work.opened", "session-1", payload), &ctx)
            .unwrap();
    }
    apply_changeset_published(&mut reducer, &ctx, "work-1", default_changeset_digest());

    assert_eq!(reducer.state().len(), 5);
    assert_eq!(reducer.state().active_count(), 5);
    assert_eq!(reducer.state().completed_count(), 0);
    assert_eq!(reducer.state().aborted_count(), 0);

    // Complete work-1 (need to go through full lifecycle)
    let claim1 =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim", 0);
    reducer
        .apply(&create_event("work.transitioned", "s", claim1), &ctx)
        .unwrap();
    let start1 = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        1,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", start1), &ctx)
        .unwrap();
    let review1 = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "REVIEW",
        "review",
        2,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", review1), &ctx)
        .unwrap();
    apply_review_receipt_recorded(&mut reducer, &ctx, "work-1", default_changeset_digest());
    let complete1 =
        helpers::work_completed_payload("work-1", vec![1], vec!["E1".to_string()], "G1", "");
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

    // Create work items (each starts with transition_count = 0)
    for i in 1..=3 {
        let payload =
            helpers::work_opened_payload(&format!("work-{i}"), "TICKET", vec![], vec![], vec![]);
        reducer
            .apply(&create_event("work.opened", "session-1", payload), &ctx)
            .unwrap();
    }

    // Claim work-1 (previous_transition_count = 0)
    let claim1 =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim", 0);
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

    // Verify it persists through transitions (previous_transition_count = 0)
    let claim =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim", 0);
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
/// After this function: `transition_count` = 2
fn setup_in_progress_work(reducer: &mut WorkReducer, ctx: &ReducerContext, work_id: &str) {
    let open_payload = helpers::work_opened_payload(work_id, "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), ctx)
        .unwrap();

    // Seed authoritative latest-changeset projection for fail-closed stage
    // admission checks.
    apply_changeset_published(reducer, ctx, work_id, default_changeset_digest());

    // transition_count = 0, so use previous_transition_count = 0
    let claim_payload =
        helpers::work_transitioned_payload_with_sequence(work_id, "OPEN", "CLAIMED", "claim", 0);
    reducer
        .apply(&create_event("work.transitioned", "s", claim_payload), ctx)
        .unwrap();

    // transition_count = 1, so use previous_transition_count = 1
    let start_payload = helpers::work_transitioned_payload_with_sequence(
        work_id,
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        1,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", start_payload), ctx)
        .unwrap();
}

/// Sets up a work item in the `Review` state.
/// After this function: `transition_count` = 3
fn setup_review_work(reducer: &mut WorkReducer, ctx: &ReducerContext, work_id: &str) {
    setup_in_progress_work(reducer, ctx, work_id);

    // transition_count = 2 after setup_in_progress_work
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        work_id,
        "IN_PROGRESS",
        "REVIEW",
        "submitted",
        2,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", review_payload), ctx)
        .unwrap();

    // Seed review-stage digest binding.
    apply_review_receipt_recorded(reducer, ctx, work_id, default_changeset_digest());
}

/// Sets up a work item in the Completed state.
/// After this function: `transition_count` = 4
fn setup_completed_work(reducer: &mut WorkReducer, ctx: &ReducerContext, work_id: &str) {
    setup_in_progress_work(reducer, ctx, work_id);

    // transition_count = 2 after setup_in_progress_work
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        work_id,
        "IN_PROGRESS",
        "REVIEW",
        "review",
        2,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", review_payload), ctx)
        .unwrap();

    // Seed review-stage digest binding required by fail-closed completion.
    apply_review_receipt_recorded(reducer, ctx, work_id, default_changeset_digest());

    let complete_payload =
        helpers::work_completed_payload(work_id, vec![1], vec!["E1".to_string()], "G1", "");
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

    // Setup: Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Transition to NeedsAdjudication (previous_transition_count = 2)
    let adj_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_ADJUDICATION",
        "requires_human_decision",
        2,
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

    // Setup: Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Transition to NeedsAdjudication (previous_transition_count = 2)
    let adj_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_ADJUDICATION",
        "awaiting_decision",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", adj_payload),
            &ctx,
        )
        .unwrap();

    // Resume after adjudication (previous_transition_count = 3)
    let resume_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "NEEDS_ADJUDICATION",
        "IN_PROGRESS",
        "decision_received",
        3,
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

    // Setup: Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Transition to NeedsAdjudication (previous_transition_count = 2)
    let adj_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "NEEDS_ADJUDICATION",
        "awaiting",
        2,
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

    // Open valid work first (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), &ctx)
        .unwrap();

    // Try transition with invalid from_state (sequence is correct but state is
    // invalid)
    let trans_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "INVALID_STATE", // Not a valid state
        "CLAIMED",
        "test",
        0,
    );
    let result = reducer.apply(&create_event("work.transitioned", "s", trans_payload), &ctx);
    assert!(matches!(result, Err(WorkError::InvalidWorkState { .. })));
}

#[test]
fn test_invalid_to_state_rejected() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open valid work first (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), &ctx)
        .unwrap();

    // Try transition with invalid to_state (sequence is correct but state is
    // invalid)
    let trans_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "OPEN",
        "BOGUS_STATE", // Not a valid state
        "test",
        0,
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
fn test_cyclic_replay_attack_prevented() {
    // Test that replay protection prevents cyclic attacks:
    // Open -> Claimed -> Open (release) -> attempt to replay first claim event
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Open work (transition_count = 0)
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(&create_event("work.opened", "s", open_payload), &ctx)
        .unwrap();

    // First claim (previous_transition_count = 0)
    let claim1 =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim1", 0);
    reducer
        .apply(&create_event("work.transitioned", "s", claim1), &ctx)
        .unwrap();

    // Release back to Open (previous_transition_count = 1)
    let release =
        helpers::work_transitioned_payload_with_sequence("work-1", "CLAIMED", "OPEN", "release", 1);
    reducer
        .apply(&create_event("work.transitioned", "s", release), &ctx)
        .unwrap();

    // Work is back in Open state, but transition_count is now 2
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Open);
    assert_eq!(work.transition_count, 2);

    // Try to replay the first claim event with previous_transition_count = 0
    // This should fail because work.transition_count is now 2
    let replay_claim =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim1", 0);
    let result = reducer.apply(&create_event("work.transitioned", "s", replay_claim), &ctx);
    assert!(matches!(result, Err(WorkError::SequenceMismatch { .. })));

    // Verify state unchanged
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Open);
    assert_eq!(work.transition_count, 2);

    // Correct claim with proper sequence should succeed
    let correct_claim = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "OPEN",
        "CLAIMED",
        "claim_correct",
        2,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", correct_claim), &ctx)
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Claimed);
    assert_eq!(work.transition_count, 3);
}

// =============================================================================
// CI-Gated Phase Transition Tests
// =============================================================================

#[test]
fn test_work_transition_in_progress_to_ci_pending() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress (transition_count = 2)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Transition to CiPending (PR created, waiting for CI)
    let ci_pending_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "CI_PENDING",
        "pr_created",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", ci_pending_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::CiPending);
    assert_eq!(work.transition_count, 3);
    assert_eq!(work.last_rationale_code, "pr_created");
}

#[test]
fn test_work_transition_ci_pending_to_ready_for_review() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // CI passed, transition to ReadyForReview (must use CI system actor)
    let ready_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                ready_payload,
            ),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::ReadyForReview);
    assert_eq!(work.transition_count, 4);
    assert_eq!(work.last_rationale_code, "ci_passed");
}

#[test]
fn test_work_transition_ci_pending_to_blocked() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // CI failed, transition to Blocked (must use CI system actor)
    let blocked_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "BLOCKED",
        "ci_failed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                blocked_payload,
            ),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Blocked);
    assert_eq!(work.transition_count, 4);
    assert_eq!(work.last_rationale_code, "ci_failed");
}

#[test]
fn test_work_transition_blocked_to_ci_pending_retry() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending -> Blocked
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // CI failed, transition to Blocked (must use CI system actor)
    let blocked_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "BLOCKED",
        "ci_failed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                blocked_payload,
            ),
            &ctx,
        )
        .unwrap();

    // Fix pushed, retry CI (transition back to CiPending)
    // Note: Blocked -> CiPending is NOT a CI-gated transition, any actor can retry
    let retry_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "BLOCKED",
        "CI_PENDING",
        "ci_retry",
        4,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", retry_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::CiPending);
    assert_eq!(work.transition_count, 5);
    assert_eq!(work.last_rationale_code, "ci_retry");
}

#[test]
fn test_work_transition_ready_for_review_to_review() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending -> ReadyForReview
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // CI passed, transition to ReadyForReview (must use CI system actor)
    let ready_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                ready_payload,
            ),
            &ctx,
        )
        .unwrap();

    // Review agent claims work (not a CI-gated transition, any actor can claim)
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "READY_FOR_REVIEW",
        "REVIEW",
        "review_claimed",
        4,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Review);
    assert_eq!(work.transition_count, 5);
}

#[test]
fn test_ci_pending_not_claimable() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    let work = reducer.state().get("work-1").unwrap();
    assert!(!work.state.is_claimable());
}

#[test]
fn test_blocked_not_claimable() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending -> Blocked
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    let blocked_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "BLOCKED",
        "ci_failed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                blocked_payload,
            ),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert!(!work.state.is_claimable());
}

#[test]
fn test_ready_for_review_is_claimable() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending -> ReadyForReview
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    let ready_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                ready_payload,
            ),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert!(work.state.is_claimable());
}

#[test]
fn test_claimable_work_query() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Create work items in different states
    for i in 1..=5 {
        let payload =
            helpers::work_opened_payload(&format!("work-{i}"), "TICKET", vec![], vec![], vec![]);
        reducer
            .apply(&create_event("work.opened", "session-1", payload), &ctx)
            .unwrap();
    }

    // Claim work-1 (no longer claimable)
    let claim1 =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim", 0);
    reducer
        .apply(&create_event("work.transitioned", "s", claim1), &ctx)
        .unwrap();

    // Get all claimable work
    let claimable = reducer.state().claimable_work();
    assert_eq!(claimable.len(), 4); // work-2 through work-5

    // All should be in Open state
    for work in claimable {
        assert_eq!(work.state, WorkState::Open);
    }
}

#[test]
fn test_work_pr_associated() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Verify no PR number or commit_sha initially
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.pr_number, None);
    assert_eq!(work.commit_sha, None);

    // Associate PR number
    let pr_payload = helpers::work_pr_associated_payload("work-1", 42, "abc123def456");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", pr_payload),
            &ctx,
        )
        .unwrap();

    // Verify PR number and commit_sha are set
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.pr_number, Some(42));
    assert_eq!(work.commit_sha, Some("abc123def456".to_string()));
}

#[test]
fn test_work_lookup_by_pr_number() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup multiple work items in InProgress state (required for PR association)
    setup_in_progress_work(&mut reducer, &ctx, "work-1");
    setup_in_progress_work(&mut reducer, &ctx, "work-2");
    setup_in_progress_work(&mut reducer, &ctx, "work-3");

    // Associate PR numbers with work-1 and work-2
    let pr_payload1 = helpers::work_pr_associated_payload("work-1", 100, "sha1");
    let pr_payload2 = helpers::work_pr_associated_payload("work-2", 200, "sha2");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", pr_payload1),
            &ctx,
        )
        .unwrap();
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", pr_payload2),
            &ctx,
        )
        .unwrap();

    // Lookup by PR number
    let work100 = reducer.state().by_pr_number(100);
    assert!(work100.is_some());
    assert_eq!(work100.unwrap().work_id, "work-1");

    let work200 = reducer.state().by_pr_number(200);
    assert!(work200.is_some());
    assert_eq!(work200.unwrap().work_id, "work-2");

    // No PR for work-3
    let work300 = reducer.state().by_pr_number(300);
    assert!(work300.is_none());
}

#[test]
fn test_ci_gated_work_query() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Create and transition work items to different CI states
    for i in 1..=3 {
        let payload =
            helpers::work_opened_payload(&format!("work-{i}"), "TICKET", vec![], vec![], vec![]);
        reducer
            .apply(&create_event("work.opened", "session-1", payload), &ctx)
            .unwrap();
    }

    // work-1: Open -> Claimed -> InProgress -> CiPending
    let claim1 =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim", 0);
    reducer
        .apply(&create_event("work.transitioned", "s", claim1), &ctx)
        .unwrap();
    let start1 = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        1,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", start1), &ctx)
        .unwrap();
    let ci1 = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "CI_PENDING",
        "pr_created",
        2,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", ci1), &ctx)
        .unwrap();

    // work-2: Open -> Claimed -> InProgress -> CiPending -> Blocked
    let claim2 =
        helpers::work_transitioned_payload_with_sequence("work-2", "OPEN", "CLAIMED", "claim", 0);
    reducer
        .apply(&create_event("work.transitioned", "s", claim2), &ctx)
        .unwrap();
    let start2 = helpers::work_transitioned_payload_with_sequence(
        "work-2",
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        1,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", start2), &ctx)
        .unwrap();
    let ci2 = helpers::work_transitioned_payload_with_sequence(
        "work-2",
        "IN_PROGRESS",
        "CI_PENDING",
        "pr_created",
        2,
    );
    reducer
        .apply(&create_event("work.transitioned", "s", ci2), &ctx)
        .unwrap();
    let blocked2 = helpers::work_transitioned_payload_with_sequence(
        "work-2",
        "CI_PENDING",
        "BLOCKED",
        "ci_failed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor("work.transitioned", "s", CI_SYSTEM_ACTOR_ID, blocked2),
            &ctx,
        )
        .unwrap();

    // work-3 stays in Open state

    // Query CI-gated work
    let ci_gated = reducer.state().ci_gated_work();
    assert_eq!(ci_gated.len(), 2); // work-1 (CiPending) and work-2 (Blocked)
}

#[test]
fn test_work_aborted_from_ci_pending() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // Abort from CiPending
    let abort_payload = helpers::work_aborted_payload("work-1", "MANUAL", "cancelled_by_user");
    reducer
        .apply(
            &create_event("work.aborted", "session-1", abort_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Aborted);
    assert!(work.is_terminal());
}

#[test]
fn test_work_aborted_from_blocked() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending -> Blocked
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    let blocked_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "BLOCKED",
        "ci_failed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                blocked_payload,
            ),
            &ctx,
        )
        .unwrap();

    // Abort from Blocked
    let abort_payload = helpers::work_aborted_payload("work-1", "TIMEOUT", "abandoned");
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
fn test_work_aborted_from_ready_for_review() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending -> ReadyForReview
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    let ready_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                ready_payload,
            ),
            &ctx,
        )
        .unwrap();

    // Abort from ReadyForReview
    let abort_payload = helpers::work_aborted_payload("work-1", "MANUAL", "cancelled");
    reducer
        .apply(
            &create_event("work.aborted", "session-1", abort_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Aborted);
}

/// Sets up a work item in the `CiPending` state.
/// After this function: `transition_count` = 3
fn setup_ci_pending_work(reducer: &mut WorkReducer, ctx: &ReducerContext, work_id: &str) {
    setup_in_progress_work(reducer, ctx, work_id);

    // transition_count = 2 after setup_in_progress_work
    let ci_pending_payload = helpers::work_transitioned_payload_with_sequence(
        work_id,
        "IN_PROGRESS",
        "CI_PENDING",
        "pr_created",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "s", ci_pending_payload),
            ctx,
        )
        .unwrap();

    // Seed CI-stage digest binding from gate flow.
    apply_gate_receipt_collected(reducer, ctx, work_id, default_changeset_digest());
}

// =============================================================================
// WorkPrAssociated Security Tests
// =============================================================================

#[test]
fn test_pr_association_allowed_from_claimed_or_in_progress() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Create work in Open state
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();

    // Try to associate PR from Open state (should fail)
    let pr_payload = helpers::work_pr_associated_payload("work-1", 42, "sha123");
    let result = reducer.apply(
        &create_event("work.pr_associated", "session-1", pr_payload),
        &ctx,
    );
    assert!(matches!(
        result,
        Err(WorkError::PrAssociationNotAllowed { .. })
    ));

    // Transition to Claimed and verify PR association succeeds pre-CI.
    let claimed_payload =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim", 0);
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", claimed_payload),
            &ctx,
        )
        .unwrap();

    let claimed_pr_payload = helpers::work_pr_associated_payload("work-1", 42, "sha123");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", claimed_pr_payload),
            &ctx,
        )
        .unwrap();

    // Verify work is in Claimed with PR metadata bound.
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Claimed);
    assert_eq!(work.pr_number, Some(42));
    assert_eq!(work.commit_sha, Some("sha123".to_string()));
}

#[test]
fn test_pr_association_fails_from_ci_pending() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // Verify work is in CiPending state
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::CiPending);

    // Try to associate PR from CiPending state (should fail)
    // This prevents bypassing CI gating by associating with a PR that already
    // passed
    let pr_payload = helpers::work_pr_associated_payload("work-1", 99, "sha_bypass_attempt");
    let result = reducer.apply(
        &create_event("work.pr_associated", "session-1", pr_payload),
        &ctx,
    );
    assert!(matches!(
        result,
        Err(WorkError::PrAssociationNotAllowed { .. })
    ));
}

#[test]
fn test_pr_association_fails_from_blocked() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending -> Blocked
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");
    let blocked_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "BLOCKED",
        "ci_failed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                blocked_payload,
            ),
            &ctx,
        )
        .unwrap();

    // Verify work is in Blocked state
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Blocked);

    // Try to associate PR from Blocked state (should fail)
    // This prevents bypassing CI gating by associating with a different PR
    let pr_payload = helpers::work_pr_associated_payload("work-1", 99, "sha_bypass_attempt");
    let result = reducer.apply(
        &create_event("work.pr_associated", "session-1", pr_payload),
        &ctx,
    );
    assert!(matches!(
        result,
        Err(WorkError::PrAssociationNotAllowed { .. })
    ));
}

#[test]
fn test_pr_number_uniqueness_enforced() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup two work items in InProgress state
    setup_in_progress_work(&mut reducer, &ctx, "work-1");
    setup_in_progress_work(&mut reducer, &ctx, "work-2");

    // Associate PR 100 with work-1
    let pr_payload1 = helpers::work_pr_associated_payload("work-1", 100, "sha1");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", pr_payload1),
            &ctx,
        )
        .unwrap();

    // Try to associate the same PR 100 with work-2 (should fail - CTR-CIQ002)
    let pr_payload2 = helpers::work_pr_associated_payload("work-2", 100, "sha2");
    let result = reducer.apply(
        &create_event("work.pr_associated", "session-1", pr_payload2),
        &ctx,
    );
    assert!(matches!(
        result,
        Err(WorkError::PrNumberAlreadyAssociated { .. })
    ));

    // Verify work-2 still has no PR
    let work2 = reducer.state().get("work-2").unwrap();
    assert_eq!(work2.pr_number, None);
}

#[test]
fn test_pr_number_rebinds_from_legacy_to_canonical_ticket_work() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let legacy_work_id = "W-439f2df5-4650-4632-9889-a39af6dae839";
    let canonical_work_id = "W-TCK-02680";

    setup_in_progress_work(&mut reducer, &ctx, legacy_work_id);
    setup_in_progress_work(&mut reducer, &ctx, canonical_work_id);

    let legacy_payload = helpers::work_pr_associated_payload(legacy_work_id, 803, "legacy_sha");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", legacy_payload),
            &ctx,
        )
        .unwrap();

    let canonical_payload =
        helpers::work_pr_associated_payload(canonical_work_id, 803, "canonical_sha");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", canonical_payload),
            &ctx,
        )
        .unwrap();

    let legacy = reducer.state().get(legacy_work_id).unwrap();
    assert_eq!(legacy.state, WorkState::Aborted);
    assert_eq!(legacy.last_rationale_code, "pr_rebound_ticket_work_id");
    assert!(
        legacy
            .abort_reason
            .as_deref()
            .is_some_and(|reason| reason.contains(canonical_work_id))
    );

    let canonical = reducer.state().get(canonical_work_id).unwrap();
    assert_eq!(canonical.pr_number, Some(803));
    assert_eq!(canonical.commit_sha.as_deref(), Some("canonical_sha"));
}

#[test]
fn test_pr_number_can_be_reused_after_terminal_state() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup work-1 in InProgress state
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Associate PR 100 with work-1
    let pr_payload1 = helpers::work_pr_associated_payload("work-1", 100, "sha1");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", pr_payload1),
            &ctx,
        )
        .unwrap();

    // Abort work-1 (terminal state)
    let abort_payload = helpers::work_aborted_payload("work-1", "MANUAL", "cancelled");
    reducer
        .apply(
            &create_event("work.aborted", "session-1", abort_payload),
            &ctx,
        )
        .unwrap();

    // Now work-1 is in terminal state, PR 100 should be available

    // Setup work-2 in InProgress state
    setup_in_progress_work(&mut reducer, &ctx, "work-2");

    // Associate PR 100 with work-2 (should succeed - work-1 is terminal)
    let pr_payload2 = helpers::work_pr_associated_payload("work-2", 100, "sha2");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", pr_payload2),
            &ctx,
        )
        .unwrap();

    let work2 = reducer.state().get("work-2").unwrap();
    assert_eq!(work2.pr_number, Some(100));
}

#[test]
fn test_commit_sha_stored_on_pr_association() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Associate PR with specific commit SHA
    let commit_sha = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";
    let pr_payload = helpers::work_pr_associated_payload("work-1", 42, commit_sha);
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", pr_payload),
            &ctx,
        )
        .unwrap();

    // Verify commit_sha is stored
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.pr_number, Some(42));
    assert_eq!(work.commit_sha, Some(commit_sha.to_string()));
}

#[test]
fn test_pr_association_fails_for_unknown_work() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Try to associate PR with non-existent work
    let pr_payload = helpers::work_pr_associated_payload("unknown-work", 42, "sha123");
    let result = reducer.apply(
        &create_event("work.pr_associated", "session-1", pr_payload),
        &ctx,
    );
    assert!(matches!(result, Err(WorkError::WorkNotFound { .. })));
}

#[test]
fn test_pr_association_idempotent_same_pr() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Associate PR 42 with work-1
    let pr_payload = helpers::work_pr_associated_payload("work-1", 42, "sha1");
    reducer
        .apply(
            &create_event("work.pr_associated", "session-1", pr_payload.clone()),
            &ctx,
        )
        .unwrap();

    // Associate the same PR again (should succeed - idempotent)
    let result = reducer.apply(
        &create_event("work.pr_associated", "session-1", pr_payload),
        &ctx,
    );
    assert!(result.is_ok());

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.pr_number, Some(42));
}

// =============================================================================
// CI-Gated Transition Authorization Tests
// =============================================================================

#[test]
fn test_ci_gated_transition_requires_authorized_rationale_ci_passed() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // Verify work is in CiPending state
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::CiPending);

    // CI-gated transition with authorized rationale and actor (should succeed)
    let payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        3, // transition_count after CiPending
    );
    let result = reducer.apply(
        &create_event_with_actor(
            "work.transitioned",
            "session-1",
            CI_SYSTEM_ACTOR_ID,
            payload,
        ),
        &ctx,
    );
    assert!(result.is_ok());

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::ReadyForReview);
}

#[test]
fn test_ci_gated_transition_requires_authorized_rationale_ci_failed() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // CI-gated transition with authorized rationale and actor (should succeed)
    let payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "BLOCKED",
        "ci_failed",
        3,
    );
    let result = reducer.apply(
        &create_event_with_actor(
            "work.transitioned",
            "session-1",
            CI_SYSTEM_ACTOR_ID,
            payload,
        ),
        &ctx,
    );
    assert!(result.is_ok());

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Blocked);
}

#[test]
fn test_ci_gated_transition_rejects_unauthorized_rationale() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // Try to transition with unauthorized rationale (should fail)
    // This prevents agents from bypassing CI gating by directly emitting
    // transitions
    let payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "manual_bypass_attempt", // Unauthorized rationale!
        3,
    );
    let result = reducer.apply(
        &create_event("work.transitioned", "session-1", payload),
        &ctx,
    );

    // Should fail with CiGatedTransitionUnauthorized
    assert!(matches!(
        result,
        Err(WorkError::CiGatedTransitionUnauthorized { .. })
    ));

    // Work should still be in CiPending state
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::CiPending);
}

#[test]
fn test_ci_gated_transition_rejects_empty_rationale() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // Try to transition with empty rationale (should fail)
    let payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "", // Empty rationale!
        3,
    );
    let result = reducer.apply(
        &create_event("work.transitioned", "session-1", payload),
        &ctx,
    );

    // Should fail with CiGatedTransitionUnauthorized
    assert!(matches!(
        result,
        Err(WorkError::CiGatedTransitionUnauthorized { .. })
    ));
}

#[test]
fn test_ci_gated_transition_rejects_unauthorized_actor() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress -> CiPending
    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // Try to transition with correct rationale but WRONG actor (should fail)
    // This prevents agents from bypassing CI gating even with correct rationale
    let payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed", // Correct rationale
        3,
    );
    let result = reducer.apply(
        // Use "malicious-agent" instead of CI_SYSTEM_ACTOR_ID
        &create_event_with_actor("work.transitioned", "session-1", "malicious-agent", payload),
        &ctx,
    );

    // Should fail with CiGatedTransitionUnauthorizedActor
    assert!(matches!(
        result,
        Err(WorkError::CiGatedTransitionUnauthorizedActor { .. })
    ));

    // Work should still be in CiPending state
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::CiPending);
}

#[test]
fn test_non_ci_gated_transition_allows_any_rationale() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Setup: Open -> Claimed -> InProgress
    setup_in_progress_work(&mut reducer, &ctx, "work-1");

    // Non-CI-gated transition (InProgress -> Review) with arbitrary rationale
    // (should succeed)
    let payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "REVIEW",
        "any_rationale_is_fine",
        2,
    );
    let result = reducer.apply(
        &create_event("work.transitioned", "session-1", payload),
        &ctx,
    );
    assert!(result.is_ok());

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Review);
}

#[test]
fn test_ci_transition_denied_when_no_changeset_published() {
    // When no changeset has been published for a work item (no entry in
    // latest_changeset_by_work), the CI transition guard must DENY the
    // transition (fail-closed CSID-004). Work stays at CiPending.
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    // Manual setup without changeset publication projection.
    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();
    let claim_payload =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim", 0);
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", claim_payload),
            &ctx,
        )
        .unwrap();
    let start_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        1,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", start_payload),
            &ctx,
        )
        .unwrap();
    let ci_pending_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "CI_PENDING",
        "pr_created",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", ci_pending_payload),
            &ctx,
        )
        .unwrap();

    let ready_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        3,
    );
    // The transition should succeed at the reducer level (no error), but the
    // work should remain at CiPending because the guard denies the transition
    // (returns Ok(false) — silently ignores the transition).
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                ready_payload,
            ),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(
        work.state,
        WorkState::CiPending,
        "transition must be DENIED when no changeset has been published (fail-closed CSID-004)"
    );
}

#[test]
fn test_ci_transition_ignores_stale_receipt_digest() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_ci_pending_work(&mut reducer, &ctx, "work-1");

    // Publish a newer changeset after CI receipt context was established.
    let latest_digest = [0x99; 32];
    apply_changeset_published(&mut reducer, &ctx, "work-1", latest_digest);

    // Transition based on stale digest context must be ignored.
    let ready_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CI_PENDING",
        "READY_FOR_REVIEW",
        "ci_passed",
        3,
    );
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                ready_payload.clone(),
            ),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(
        work.state,
        WorkState::CiPending,
        "stale receipt digest must not advance CI transition"
    );

    // Once gate flow for latest digest is observed, transition may proceed.
    apply_gate_receipt_collected(&mut reducer, &ctx, "work-1", latest_digest);
    reducer
        .apply(
            &create_event_with_actor(
                "work.transitioned",
                "session-1",
                CI_SYSTEM_ACTOR_ID,
                ready_payload,
            ),
            &ctx,
        )
        .unwrap();
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::ReadyForReview);
}

#[test]
fn test_review_receipt_stale_digest_is_ignored() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_in_progress_work(&mut reducer, &ctx, "work-1");
    apply_review_receipt_recorded(&mut reducer, &ctx, "work-1", [0xAB; 32]);

    assert!(
        !reducer
            .state()
            .review_receipt_digest_by_work
            .contains_key("work-1"),
        "stale review receipt digest must not be admitted"
    );
}

#[test]
fn test_work_completion_denied_for_stale_digest_context() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_review_work(&mut reducer, &ctx, "work-1");

    // Move latest digest forward; existing review receipt digest is now stale.
    let new_digest = [0xEE; 32];
    apply_changeset_published(&mut reducer, &ctx, "work-1", new_digest);

    let complete_payload =
        helpers::work_completed_payload("work-1", vec![1], vec!["E1".to_string()], "G1", "");
    reducer
        .apply(
            &create_event("work.completed", "session-1", complete_payload.clone()),
            &ctx,
        )
        .unwrap();
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(
        work.state,
        WorkState::Review,
        "stale digest context must deny completion"
    );

    // Admit matching review digest, then completion succeeds.
    apply_review_receipt_recorded(&mut reducer, &ctx, "work-1", new_digest);
    reducer
        .apply(
            &create_event("work.completed", "session-1", complete_payload),
            &ctx,
        )
        .unwrap();
    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(work.state, WorkState::Completed);
}

#[test]
fn test_work_completion_merge_receipt_uses_latest_digest_binding() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    setup_review_work(&mut reducer, &ctx, "work-1");

    let complete_payload = helpers::work_completed_payload(
        "work-1",
        vec![1],
        vec!["E1".to_string()],
        "gate-receipt-quality-1",
        "merge-receipt-sha123",
    );

    // Without merge digest context, completion is denied.
    reducer
        .apply(
            &create_event("work.completed", "session-1", complete_payload.clone()),
            &ctx,
        )
        .unwrap();
    assert_eq!(
        reducer.state().get("work-1").unwrap().state,
        WorkState::Review
    );

    // Once merge digest matches latest, completion is admitted.
    apply_merge_receipt_recorded(&mut reducer, &ctx, "work-1", default_changeset_digest());
    reducer
        .apply(
            &create_event("work.completed", "session-1", complete_payload),
            &ctx,
        )
        .unwrap();
    assert_eq!(
        reducer.state().get("work-1").unwrap().state,
        WorkState::Completed
    );
}

/// Regression: `InProgress -> Review` must also be guarded by the
/// latest-changeset check (CSID-004). Without a `changeset_published`
/// event, the transition is silently denied (fail-closed).
#[test]
fn test_in_progress_to_review_denied_without_changeset_published() {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);

    let open_payload = helpers::work_opened_payload("work-1", "TICKET", vec![], vec![], vec![]);
    reducer
        .apply(
            &create_event("work.opened", "session-1", open_payload),
            &ctx,
        )
        .unwrap();
    let claim_payload =
        helpers::work_transitioned_payload_with_sequence("work-1", "OPEN", "CLAIMED", "claim", 0);
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", claim_payload),
            &ctx,
        )
        .unwrap();
    let start_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "CLAIMED",
        "IN_PROGRESS",
        "start",
        1,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", start_payload),
            &ctx,
        )
        .unwrap();

    // Attempt InProgress -> Review WITHOUT changeset published.
    // Should be silently denied (work stays at InProgress).
    let review_payload = helpers::work_transitioned_payload_with_sequence(
        "work-1",
        "IN_PROGRESS",
        "REVIEW",
        "ready_for_review",
        2,
    );
    reducer
        .apply(
            &create_event("work.transitioned", "session-1", review_payload),
            &ctx,
        )
        .unwrap();

    let work = reducer.state().get("work-1").unwrap();
    assert_eq!(
        work.state,
        WorkState::InProgress,
        "InProgress -> Review must be denied without a changeset published"
    );
    // transition_count remains 2 (Open->Claimed, Claimed->InProgress)
    assert_eq!(work.transition_count, 2);
}
