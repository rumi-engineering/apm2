//! TCK-00417 integration tests:
//! event-family parity convergence and replay-equivalence gates.

use std::collections::{BTreeSet, HashSet};

use apm2_core::ledger::EventRecord;
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::work::{
    EventFamilyPromotionGate, MAPPING_MATRIX, ParityField, ParityValidator,
    ReplayEquivalenceChecker, TransitionClass, WorkError, WorkReducer, WorkReducerState, WorkState,
    helpers,
};
use apm2_daemon::protocol::{LedgerEventEmitter, StubLedgerEventEmitter};

fn event_record(
    event_type: &str,
    session_id: &str,
    actor_id: &str,
    payload: Vec<u8>,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    EventRecord::with_timestamp(event_type, session_id, actor_id, payload, timestamp_ns)
        .with_seq_id(seq_id)
}

fn daemon_work_claimed_event(
    work_id: &str,
    actor_id: &str,
    rationale_code: &str,
    previous_transition_count: u32,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = serde_json::json!({
        "event_type": "work_claimed",
        "work_id": work_id,
        "actor_id": actor_id,
        "rationale_code": rationale_code,
        "previous_transition_count": previous_transition_count,
    })
    .to_string()
    .into_bytes();

    event_record(
        "work_claimed",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn daemon_work_transitioned_event(
    work_id: &str,
    actor_id: &str,
    from_state: &str,
    to_state: &str,
    rationale_code: &str,
    previous_transition_count: u32,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = serde_json::json!({
        "event_type": "work_transitioned",
        "work_id": work_id,
        "from_state": from_state,
        "to_state": to_state,
        "rationale_code": rationale_code,
        "previous_transition_count": previous_transition_count,
        "actor_id": actor_id,
        "timestamp_ns": timestamp_ns,
    })
    .to_string()
    .into_bytes();

    event_record(
        "work_transitioned",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

fn dotted_opened_event(
    work_id: &str,
    actor_id: &str,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = helpers::work_opened_payload(work_id, "TICKET", vec![1, 2, 3], vec![], vec![]);
    event_record(
        "work.opened",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn dotted_transition_event(
    work_id: &str,
    actor_id: &str,
    from_state: &str,
    to_state: &str,
    rationale_code: &str,
    previous_transition_count: u32,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = helpers::work_transitioned_payload_with_sequence(
        work_id,
        from_state,
        to_state,
        rationale_code,
        previous_transition_count,
    );
    event_record(
        "work.transitioned",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

fn dotted_pr_associated_event(
    work_id: &str,
    actor_id: &str,
    pr_number: u64,
    commit_sha: &str,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = helpers::work_pr_associated_payload(work_id, pr_number, commit_sha);
    event_record(
        "work.pr_associated",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

fn dotted_completed_event(
    work_id: &str,
    actor_id: &str,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = helpers::work_completed_payload(
        work_id,
        vec![9, 9, 9, 9],
        vec!["EVID-1".to_string()],
        "GR-1",
    );
    event_record(
        "work.completed",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

fn reduce_expected_state(events: &[EventRecord]) -> WorkReducerState {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);
    for event in events {
        reducer
            .apply(event, &ctx)
            .expect("expected-state replay must succeed");
    }
    reducer.state().clone()
}

#[test]
fn parity_mapping_completeness_covers_protobuf_variants() {
    assert_eq!(MAPPING_MATRIX.len(), 8);

    let mapped_variants: BTreeSet<&str> = MAPPING_MATRIX
        .iter()
        .map(|mapping| mapping.protobuf_variant)
        .collect();
    assert_eq!(mapped_variants.len(), 5);

    let expected_variants: BTreeSet<&str> = [
        "WorkOpened",
        "WorkTransitioned",
        "WorkCompleted",
        "WorkAborted",
        "WorkPrAssociated",
    ]
    .into_iter()
    .collect();

    assert_eq!(mapped_variants, expected_variants);
}

#[test]
fn parity_field_equivalence_across_daemon_dotted_and_protobuf() {
    let work_id = "W-PARITY-001";
    let actor_id = "actor:parity";
    let events = vec![
        dotted_opened_event(work_id, actor_id, 1_000, 1),
        daemon_work_claimed_event(work_id, actor_id, "work_claimed_via_ipc", 0, 1_100, 2),
        daemon_work_transitioned_event(
            work_id,
            actor_id,
            "OPEN",
            "CLAIMED",
            "work_claimed_via_ipc",
            0,
            1_100,
            3,
        ),
        dotted_transition_event(
            work_id,
            actor_id,
            "OPEN",
            "CLAIMED",
            "work_claimed_via_ipc",
            0,
            1_100,
            4,
        ),
        daemon_work_transitioned_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "episode_spawned_via_ipc",
            1,
            1_200,
            5,
        ),
        dotted_transition_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "episode_spawned_via_ipc",
            1,
            1_200,
            6,
        ),
    ];

    let results = ParityValidator::validate_all(&events);
    assert_eq!(results.len(), 8);

    let passed_count = results.iter().filter(|result| result.passed).count();
    assert_eq!(passed_count, 8);

    let claimed = results
        .iter()
        .find(|result| result.transition_class == TransitionClass::WorkClaimed)
        .expect("WorkClaimed mapping result must exist");
    assert!(
        claimed.passed,
        "WorkClaimed parity must pass: {:?}",
        claimed.defects
    );

    let started = results
        .iter()
        .find(|result| result.transition_class == TransitionClass::WorkStarted)
        .expect("WorkStarted mapping result must exist");
    assert!(
        started.passed,
        "WorkStarted parity must pass: {:?}",
        started.defects
    );
}

#[test]
fn replay_from_checkpoint_converges_to_identical_projection() {
    let work_id = "W-REPLAY-001";
    let actor_id = "actor:replay";
    let events = vec![
        dotted_opened_event(work_id, actor_id, 2_000, 1),
        dotted_transition_event(work_id, actor_id, "OPEN", "CLAIMED", "claim", 0, 2_100, 2),
        dotted_transition_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "start",
            1,
            2_200,
            3,
        ),
        dotted_transition_event(
            work_id,
            actor_id,
            "IN_PROGRESS",
            "REVIEW",
            "ready_for_review",
            2,
            2_300,
            4,
        ),
        dotted_completed_event(work_id, actor_id, 2_400, 5),
    ];

    let expected_state = reduce_expected_state(&events);
    let mut checker = ReplayEquivalenceChecker::new();
    let replay = checker
        .verify_replay_equivalence(&events, &expected_state)
        .expect("replay-equivalence should succeed");

    assert!(
        replay.matches,
        "replay projection must match expected state"
    );
    assert_eq!(replay.applied_event_count, 5);
    assert_eq!(replay.actual_state.completed_count(), 1);
}

#[test]
fn duplicate_delivery_is_deduplicated_without_duplicate_side_effects() {
    let work_id = "W-DUP-001";
    let actor_id = "actor:dedupe";
    let base_events = vec![
        dotted_opened_event(work_id, actor_id, 3_000, 1),
        dotted_transition_event(work_id, actor_id, "OPEN", "CLAIMED", "claim", 0, 3_100, 2),
        dotted_transition_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "start",
            1,
            3_200,
            3,
        ),
    ];

    let mut duplicate_events = base_events.clone();
    duplicate_events.extend(base_events.iter().cloned());

    let expected_state = reduce_expected_state(&base_events);
    let mut checker = ReplayEquivalenceChecker::new();
    let replay = checker
        .verify_replay_equivalence(&duplicate_events, &expected_state)
        .expect("deduplicated replay should succeed");

    assert!(replay.matches, "deduplicated replay must converge");
    assert_eq!(replay.deduplicated_event_count, 3);
    assert_eq!(replay.applied_event_count, 3);

    let work = replay
        .actual_state
        .get(work_id)
        .expect("replayed work must exist");
    assert_eq!(work.transition_count, 2);
}

#[test]
fn restart_recovery_replay_converges() {
    let work_id = "W-RESTART-001";
    let actor_id = "actor:restart";
    let events = vec![
        dotted_opened_event(work_id, actor_id, 4_000, 1),
        dotted_transition_event(work_id, actor_id, "OPEN", "CLAIMED", "claim", 0, 4_100, 2),
        dotted_transition_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "start",
            1,
            4_200,
            3,
        ),
        dotted_transition_event(
            work_id,
            actor_id,
            "IN_PROGRESS",
            "REVIEW",
            "ready_for_review",
            2,
            4_300,
            4,
        ),
    ];

    let expected_state = reduce_expected_state(&events);

    let mut first_checker = ReplayEquivalenceChecker::new();
    let first_replay = first_checker
        .verify_replay_equivalence(&events, &expected_state)
        .expect("first replay should succeed");

    let mut second_checker = ReplayEquivalenceChecker::new();
    let second_replay = second_checker
        .verify_replay_equivalence(&events, &expected_state)
        .expect("second replay should succeed");

    assert!(first_replay.matches, "first replay must converge");
    assert!(second_replay.matches, "second replay must converge");
    assert_eq!(
        first_replay.actual_state.in_state(WorkState::Review).len(),
        1
    );
    assert_eq!(
        second_replay.actual_state.in_state(WorkState::Review).len(),
        1
    );
}

#[test]
fn fault_injection_out_of_order_transition_is_rejected() {
    let work_id = "W-ORDER-001";
    let actor_id = "actor:order";
    let ordered_events = vec![
        dotted_opened_event(work_id, actor_id, 5_000, 1),
        dotted_transition_event(work_id, actor_id, "OPEN", "CLAIMED", "claim", 0, 5_100, 2),
        dotted_transition_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "start",
            1,
            5_200,
            3,
        ),
    ];

    let out_of_order_events = vec![
        dotted_opened_event(work_id, actor_id, 5_000, 1),
        dotted_transition_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "start",
            1,
            5_200,
            3,
        ),
        dotted_transition_event(work_id, actor_id, "OPEN", "CLAIMED", "claim", 0, 5_100, 2),
    ];

    let expected_state = reduce_expected_state(&ordered_events);
    let mut checker = ReplayEquivalenceChecker::new();
    let result = checker.verify_replay_equivalence(&out_of_order_events, &expected_state);

    let err = result.expect_err("out-of-order replay must fail");
    assert!(
        matches!(
            err,
            WorkError::InvalidTransition { .. } | WorkError::SequenceMismatch { .. }
        ),
        "expected transition/sequence rejection, got {err:?}"
    );
}

#[test]
fn parity_failure_detection_reports_structured_defects() {
    let work_id = "W-PARITY-FAIL-001";
    let events = vec![
        dotted_opened_event(work_id, "actor:a", 6_000, 1),
        daemon_work_claimed_event(work_id, "actor:a", "daemon_claimed", 0, 6_100, 2),
        dotted_transition_event(
            work_id,
            "actor:b",
            "OPEN",
            "CLAIMED",
            "reducer_claimed",
            0,
            6_100,
            3,
        ),
    ];

    let results = ParityValidator::validate_all(&events);
    let defects: Vec<_> = results
        .iter()
        .flat_map(|result| result.defects.iter())
        .collect();
    assert_eq!(defects.len(), 2);

    let fields: HashSet<ParityField> = defects.iter().map(|defect| defect.field).collect();
    assert!(fields.contains(&ParityField::Rationale));
    assert!(fields.contains(&ParityField::Actor));
}

#[test]
fn promotion_gate_blocks_on_parity_failures_and_emits_defect_records() {
    let work_id = "W-GATE-BLOCK-001";
    // The dotted events match expected state (replay passes), but the daemon
    // event has a different actor and rationale (parity fails).
    let parity_failure_events = vec![
        dotted_opened_event(work_id, "actor:gate-a", 7_000, 1),
        daemon_work_claimed_event(work_id, "actor:gate-b", "wrong_rationale", 0, 7_100, 2),
        dotted_transition_event(
            work_id,
            "actor:gate-a",
            "OPEN",
            "CLAIMED",
            "daemon_claimed",
            0,
            7_100,
            3,
        ),
    ];

    let expected_state = reduce_expected_state(&[
        dotted_opened_event(work_id, "actor:gate-a", 7_000, 1),
        dotted_transition_event(
            work_id,
            "actor:gate-a",
            "OPEN",
            "CLAIMED",
            "daemon_claimed",
            0,
            7_100,
            2,
        ),
    ]);

    let result = EventFamilyPromotionGate::evaluate(&parity_failure_events, &expected_state)
        .expect("promotion gate evaluation should execute");

    assert!(
        !result.allowed,
        "promotion must be blocked on parity defects"
    );
    assert!(
        result.replay_passed,
        "replay must still pass in this failure mode"
    );
    assert_eq!(result.parity_defects.len(), 2);
    assert_eq!(result.defect_records.len(), 2);

    let emitter = StubLedgerEventEmitter::new();
    for defect in &result.defect_records {
        emitter
            .emit_defect_recorded(defect, defect.detected_at)
            .expect("defect emission should succeed");
    }

    let emitted_events = emitter.get_all_events();
    assert_eq!(emitted_events.len(), 2);
}

#[test]
fn duplicate_side_effects_block_promotion_gate() {
    let work_id = "W-DUPE-SE-001";
    let actor_id = "actor:dupe-se";
    let pr_number = 501u64;
    let commit_sha = "cafebabe123";

    // Build a normal sequence to InProgress with PR association.
    let base_events = vec![
        dotted_opened_event(work_id, actor_id, 8_000, 1),
        dotted_transition_event(work_id, actor_id, "OPEN", "CLAIMED", "claim", 0, 8_100, 2),
        dotted_transition_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "start",
            1,
            8_200,
            3,
        ),
        dotted_pr_associated_event(work_id, actor_id, pr_number, commit_sha, 8_300, 4),
    ];

    let expected_state = reduce_expected_state(&base_events);

    // Same logical PR association with a unique fingerprint (different
    // timestamp/seq). Reducer accepts it but state should remain unchanged.
    let mut events_with_dupe_se = base_events;
    events_with_dupe_se.push(dotted_pr_associated_event(
        work_id, actor_id, pr_number, commit_sha, 8_400, 5,
    ));

    let result = EventFamilyPromotionGate::evaluate(&events_with_dupe_se, &expected_state)
        .expect("promotion gate evaluation should execute");

    let replay = result
        .replay_result
        .as_ref()
        .expect("replay result must be present");
    assert!(
        replay.duplicate_side_effects > 0,
        "duplicate side effects must be detected and non-zero"
    );
    assert!(
        !result.replay_passed,
        "replay must fail when duplicate side effects exist"
    );
    assert!(
        !result.allowed,
        "promotion must be blocked when duplicate side effects exist"
    );
}
