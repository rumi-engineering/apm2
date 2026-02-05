//! Integration tests for the orchestration module (TCK-00332).
//!
//! These tests verify:
//! - A `work_id` can run >= 20 revision iterations without human interaction
//! - Restart resumes orchestration deterministically from ledger state
//! - Termination reasons are recorded as authoritative facts

#![allow(clippy::cast_possible_truncation)]

use apm2_holon::orchestration::{
    IterationCompleted, IterationOutcome, OrchestrationConfig, OrchestrationDriver,
    OrchestrationEvent, OrchestrationStarted, OrchestrationStateV1, OrchestrationTerminated,
    TerminationReason,
};

/// Test that orchestration can run >= 20 iterations without human interaction.
///
/// This test creates an orchestration state and runs 25 simulated iterations,
/// verifying that each iteration completes successfully and the state is
/// properly tracked.
#[test]
fn test_twenty_plus_iterations_without_human_interaction() {
    let driver = OrchestrationDriver::new(
        OrchestrationConfig::default()
            .with_max_iterations(100)
            .with_token_budget(100_000_000)
            .with_time_budget_ms(10_000_000),
    );

    let mut state = driver
        .create_state("work-integration-test", "orch-001")
        .unwrap();
    state.set_started_at_ns(1_000_000_000);

    let mut events: Vec<OrchestrationEvent> = vec![];

    // Emit start event
    let start_event = OrchestrationStarted::new(
        state.orchestration_id(),
        state.work_id(),
        state.max_iterations(),
        state.initial_token_budget(),
        state.initial_time_budget_ms(),
        state.started_at_ns(),
    );
    events.push(start_event.into());

    // Run 25 iterations (exceeds 20 requirement)
    for i in 1..=25 {
        let tokens_used = 1000;
        let time_used_ms = 500;
        let timestamp_ns = (i + 1) * 1_000_000_000;
        let changeset_hash = [i as u8; 32];
        let receipt_hash = [(i + 100) as u8; 32];

        // Record iteration in state
        let termination = state.record_iteration(
            tokens_used,
            time_used_ms,
            timestamp_ns,
            Some(changeset_hash),
            Some(receipt_hash),
        );

        // Emit iteration event
        let outcome = if i == 25 {
            IterationOutcome::AllReviewsPassed
        } else {
            IterationOutcome::ChangeSetProduced
        };

        let iter_event = IterationCompleted::new(
            state.orchestration_id(),
            state.work_id(),
            i,
            outcome,
            tokens_used,
            time_used_ms,
            timestamp_ns,
        )
        .with_changeset_hash(changeset_hash)
        .with_receipt_hash(receipt_hash);
        events.push(iter_event.into());

        // Should not terminate before iteration 25
        if i < 25 {
            assert!(
                termination.is_none(),
                "Should not terminate at iteration {i}"
            );
        }
    }

    // Verify 25 iterations completed
    assert_eq!(state.iteration_count(), 25);
    assert!(!state.is_terminated());

    // Mark as completed
    state.terminate(TerminationReason::pass());

    let term_event = OrchestrationTerminated::new(
        state.orchestration_id(),
        state.work_id(),
        TerminationReason::pass(),
        state.iteration_count(),
        state.tokens_consumed(),
        state.time_consumed_ms(),
        26_000_000_000,
    );
    events.push(term_event.into());

    assert!(state.is_terminated());
    assert!(state.is_success());

    // Verify all events were recorded
    assert_eq!(events.len(), 27); // 1 start + 25 iterations + 1 termination
}

/// Test crash-only resumability: restart from ledger head without duplicating
/// projections.
///
/// This test simulates a crash by:
/// 1. Starting orchestration and running 10 iterations
/// 2. Collecting all ledger events
/// 3. Reconstructing state from events (simulating daemon restart)
/// 4. Continuing execution from the reconstructed state
/// 5. Verifying state is identical and no work is duplicated
#[test]
fn test_crash_only_resumability() {
    let driver = OrchestrationDriver::new(
        OrchestrationConfig::default()
            .with_max_iterations(50)
            .with_token_budget(50_000_000)
            .with_time_budget_ms(5_000_000),
    );

    // Phase 1: Initial execution (10 iterations)
    let mut events: Vec<OrchestrationEvent> = vec![];

    let start_event = OrchestrationStarted::new(
        "orch-resume-test",
        "work-resume-test",
        50,
        50_000_000,
        5_000_000,
        1_000_000_000,
    );
    events.push(start_event.into());

    // Record 10 iterations
    for i in 1..=10 {
        let iter_event = IterationCompleted::new(
            "orch-resume-test",
            "work-resume-test",
            i,
            IterationOutcome::ChangeSetProduced,
            1000,
            100,
            (i + 1) * 1_000_000_000,
        )
        .with_changeset_hash([i as u8; 32]);
        events.push(iter_event.into());
    }

    // Phase 2: Simulate crash and recovery by reconstructing from events
    let resumed_state = driver
        .resume_from_events(&events)
        .expect("Should resume successfully")
        .expect("Should have state");

    // Verify resumed state matches expected values
    assert_eq!(resumed_state.work_id(), "work-resume-test");
    assert_eq!(resumed_state.orchestration_id(), "orch-resume-test");
    assert_eq!(resumed_state.iteration_count(), 10);
    assert_eq!(resumed_state.tokens_consumed(), 10_000);
    assert_eq!(resumed_state.time_consumed_ms(), 1000);
    assert_eq!(resumed_state.max_iterations(), 50);
    assert_eq!(resumed_state.remaining_iterations(), 40);
    assert!(!resumed_state.is_terminated());

    // Phase 3: Continue execution from resumed state
    let mut continued_state = resumed_state;

    for i in 11..=20 {
        let termination = continued_state.record_iteration(
            1000,
            100,
            (i + 1) * 1_000_000_000,
            Some([i as u8; 32]),
            None,
        );

        let iter_event = IterationCompleted::new(
            "orch-resume-test",
            "work-resume-test",
            i,
            IterationOutcome::ChangeSetProduced,
            1000,
            100,
            (i + 1) * 1_000_000_000,
        );
        events.push(iter_event.into());

        assert!(
            termination.is_none(),
            "Should not terminate at iteration {i}"
        );
    }

    // Verify total 20 iterations completed
    assert_eq!(continued_state.iteration_count(), 20);
    assert_eq!(continued_state.tokens_consumed(), 20_000);

    // Verify determinism: resume again and check identical state
    let re_resumed = driver
        .resume_from_events(&events)
        .expect("Should resume successfully")
        .expect("Should have state");

    assert_eq!(re_resumed.iteration_count(), 20);
    assert_eq!(re_resumed.tokens_consumed(), 20_000);
    assert_eq!(re_resumed.time_consumed_ms(), 2000);
}

/// Test that termination reasons are recorded as authoritative facts.
///
/// This test verifies that each termination reason type is properly
/// recorded in the terminated event and can be retrieved from the state.
#[test]
fn test_termination_reasons_as_authoritative_facts() {
    let test_cases = vec![
        (TerminationReason::pass(), "pass"),
        (
            TerminationReason::blocked(apm2_holon::BlockedReasonCode::ReviewerBlocked {
                reviewer_role: "security".to_string(),
                finding_summary: Some("critical vulnerability".to_string()),
            }),
            "blocked",
        ),
        (
            TerminationReason::budget_exhausted("tokens", 1000, 1000),
            "budget_exhausted",
        ),
        (
            TerminationReason::operator_stop("manual intervention"),
            "operator_stop",
        ),
        (
            TerminationReason::max_iterations_reached(100),
            "max_iterations_reached",
        ),
        (TerminationReason::error("fatal error"), "error"),
    ];

    for (reason, expected_str) in test_cases {
        let mut state = OrchestrationStateV1::new(
            format!("work-{expected_str}"),
            format!("orch-{expected_str}"),
            100,
            1_000_000,
            3_600_000,
        );

        // Terminate with the reason
        assert!(state.terminate(reason.clone()));
        assert!(state.is_terminated());

        // Verify the reason is recorded correctly
        let recorded_reason = state.termination_reason().unwrap();
        assert_eq!(recorded_reason.as_str(), expected_str);
        assert_eq!(*recorded_reason, reason);

        // Create terminated event
        let term_event = OrchestrationTerminated::new(
            state.orchestration_id(),
            state.work_id(),
            reason.clone(),
            0,
            0,
            0,
            1_000_000_000,
        );

        // Verify event records the reason
        assert_eq!(term_event.reason(), &reason);
        assert_eq!(term_event.reason().as_str(), expected_str);
    }
}

/// Test deterministic resume from ledger with all event types.
///
/// This test creates a complete orchestration lifecycle and verifies
/// that the final state can be reconstructed deterministically.
#[test]
fn test_deterministic_resume_complete_lifecycle() {
    let driver = OrchestrationDriver::with_defaults();

    // Create events for a complete lifecycle
    let mut events: Vec<OrchestrationEvent> = vec![];

    // Start event
    events.push(
        OrchestrationStarted::new(
            "orch-lifecycle",
            "work-lifecycle",
            100,
            10_000_000,
            1_000_000,
            1_000_000_000,
        )
        .with_initial_changeset_hash([0u8; 32])
        .into(),
    );

    // 5 iterations
    for i in 1..=5 {
        let outcome = if i == 5 {
            IterationOutcome::AllReviewsPassed
        } else {
            IterationOutcome::ChangeSetProduced
        };

        events.push(
            IterationCompleted::new(
                "orch-lifecycle",
                "work-lifecycle",
                i,
                outcome,
                10_000,
                1000,
                (i + 1) * 1_000_000_000,
            )
            .with_changeset_hash([i as u8; 32])
            .with_receipt_hash([(i + 100) as u8; 32])
            .into(),
        );
    }

    // Termination event
    events.push(
        OrchestrationTerminated::new(
            "orch-lifecycle",
            "work-lifecycle",
            TerminationReason::pass(),
            5,
            50_000,
            5000,
            7_000_000_000,
        )
        .with_final_changeset_hash([5u8; 32])
        .with_final_receipt_hash([105u8; 32])
        .into(),
    );

    // Resume and verify
    let state = driver
        .resume_from_events(&events)
        .expect("Should resume successfully")
        .expect("Should have state");

    assert_eq!(state.iteration_count(), 5);
    assert_eq!(state.tokens_consumed(), 50_000);
    assert_eq!(state.time_consumed_ms(), 5000);
    assert!(state.is_terminated());
    assert!(state.is_success());
    assert_eq!(state.last_changeset_hash(), Some(&[5u8; 32]));
    assert_eq!(state.last_receipt_hash(), Some(&[105u8; 32]));

    // Verify driver detects already-terminated state
    let termination_check = driver.check_termination(&state);
    assert!(termination_check.is_some());
    assert!(matches!(termination_check, Some(TerminationReason::Pass)));
}

/// Test error handling during resume with invalid event sequences.
#[test]
fn test_resume_error_handling() {
    let driver = OrchestrationDriver::with_defaults();

    // Test 1: IterationCompleted without OrchestrationStarted
    let events: Vec<OrchestrationEvent> = vec![
        IterationCompleted::new(
            "orch-orphan",
            "work-orphan",
            1,
            IterationOutcome::ChangeSetProduced,
            1000,
            100,
            2_000_000_000,
        )
        .into(),
    ];

    let result = driver.resume_from_events(&events);
    assert!(result.is_err());

    // Test 2: OrchestrationTerminated without OrchestrationStarted
    let events: Vec<OrchestrationEvent> = vec![
        OrchestrationTerminated::new(
            "orch-orphan",
            "work-orphan",
            TerminationReason::pass(),
            0,
            0,
            0,
            2_000_000_000,
        )
        .into(),
    ];

    let result = driver.resume_from_events(&events);
    assert!(result.is_err());

    // Test 3: Out-of-order iteration numbers
    let events: Vec<OrchestrationEvent> = vec![
        OrchestrationStarted::new(
            "orch-order",
            "work-order",
            100,
            1_000_000,
            1_000_000,
            1_000_000_000,
        )
        .into(),
        IterationCompleted::new(
            "orch-order",
            "work-order",
            5, // Wrong: should be 1
            IterationOutcome::ChangeSetProduced,
            1000,
            100,
            2_000_000_000,
        )
        .into(),
    ];

    let result = driver.resume_from_events(&events);
    assert!(result.is_err());
}

/// Test that budget exhaustion is properly detected and recorded.
#[test]
fn test_budget_exhaustion_detection() {
    // Token budget exhaustion
    let mut state = OrchestrationStateV1::new(
        "work-budget-test",
        "orch-budget-test",
        100,
        5000, // Very small token budget
        1_000_000,
    );

    let termination = state.record_iteration(
        5000, // Consume all tokens
        100,
        2_000_000_000,
        None,
        None,
    );

    assert!(termination.is_some());
    match termination.unwrap() {
        TerminationReason::BudgetExhausted {
            resource,
            consumed,
            limit,
        } => {
            assert_eq!(resource, "tokens");
            assert_eq!(consumed, 5000);
            assert_eq!(limit, 5000);
        },
        _ => panic!("Expected BudgetExhausted"),
    }

    // Time budget exhaustion
    let mut state = OrchestrationStateV1::new(
        "work-time-test",
        "orch-time-test",
        100,
        1_000_000,
        1000, // Very small time budget
    );

    let termination = state.record_iteration(
        100,
        1000, // Consume all time
        2_000_000_000,
        None,
        None,
    );

    assert!(termination.is_some());
    match termination.unwrap() {
        TerminationReason::BudgetExhausted { resource, .. } => {
            assert_eq!(resource, "time");
        },
        _ => panic!("Expected BudgetExhausted for time"),
    }
}

/// Test iteration binding to `ChangeSetBundleV1` and reviewer receipts.
#[test]
fn test_iteration_binding_to_artifacts() {
    let mut state = OrchestrationStateV1::new(
        "work-artifacts",
        "orch-artifacts",
        100,
        1_000_000,
        1_000_000,
    );

    let changeset_hash = [42u8; 32];
    let receipt_hash = [84u8; 32];

    state.record_iteration(
        1000,
        100,
        2_000_000_000,
        Some(changeset_hash),
        Some(receipt_hash),
    );

    // Verify hashes are bound to state
    assert_eq!(state.last_changeset_hash(), Some(&changeset_hash));
    assert_eq!(state.last_receipt_hash(), Some(&receipt_hash));

    // Create iteration event with bindings
    let event = IterationCompleted::new(
        "orch-artifacts",
        "work-artifacts",
        1,
        IterationOutcome::ChangeSetProduced,
        1000,
        100,
        2_000_000_000,
    )
    .with_changeset_hash(changeset_hash)
    .with_receipt_hash(receipt_hash)
    .with_implementer_episode_id("impl-ep-001")
    .with_reviewer_episode_id("sec-rev-ep-001")
    .with_reviewer_episode_id("qual-rev-ep-001");

    // Verify all bindings are present
    assert_eq!(event.changeset_hash(), Some(&changeset_hash));
    assert_eq!(event.receipt_hash(), Some(&receipt_hash));
    assert_eq!(event.implementer_episode_id(), Some("impl-ep-001"));
    assert_eq!(event.reviewer_episode_ids().len(), 2);
    assert!(
        event
            .reviewer_episode_ids()
            .contains(&"sec-rev-ep-001".to_string())
    );
    assert!(
        event
            .reviewer_episode_ids()
            .contains(&"qual-rev-ep-001".to_string())
    );
}
