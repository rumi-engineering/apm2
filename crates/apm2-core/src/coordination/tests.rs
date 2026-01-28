//! Property tests for the coordination reducer.
//!
//! This module contains property-based tests that verify the critical
//! invariants of the coordination reducer:
//!
//! - **Determinism**: Same event sequence produces same state
//! - **Idempotency**: Applying the same event twice is a no-op
//! - **Budget monotonicity**: Budget usage never decreases
//!
//! # Test Requirements
//!
//! - PT-COORD-REDUCE-001: Reducer determinism property test (1000 iterations)
//! - PT-COORD-REDUCE-002: Reducer idempotency property test (1000 iterations)
//! - PT-COORD-REDUCE-003: Budget monotonicity property test (1000 iterations)
//!
//! # References
//!
//! - TCK-00149: Implement `CoordinationReducer` with determinism property tests
//! - RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution

// Test code uses proptest which generates patterns that trigger these lints.
// Cast truncation is intentional in tests where we only need small byte values.
// Redundant clone warnings are false positives within proptest macros.
#![allow(
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::redundant_clone
)]

use proptest::prelude::*;

use crate::coordination::events::{
    BLAKE3_HASH_SIZE, CoordinationAborted, CoordinationCompleted, CoordinationSessionBound,
    CoordinationSessionUnbound, CoordinationStarted, EVENT_TYPE_ABORTED, EVENT_TYPE_COMPLETED,
    EVENT_TYPE_SESSION_BOUND, EVENT_TYPE_SESSION_UNBOUND, EVENT_TYPE_STARTED,
};
use crate::coordination::reducer::CoordinationReducer;
use crate::coordination::state::{
    AbortReason, BudgetUsage, CoordinationBudget, SessionOutcome, StopCondition,
};
use crate::ledger::EventRecord;
use crate::reducer::{CheckpointableReducer, Reducer, ReducerContext};

// ============================================================================
// Arbitrary Event Generators
// ============================================================================

/// Generates a random coordination ID.
fn arb_coordination_id() -> impl Strategy<Value = String> {
    "coord-[a-z]{3}[0-9]{2}".prop_map(|s| s)
}

/// Generates a random session ID.
fn arb_session_id() -> impl Strategy<Value = String> {
    "sess-[a-z]{3}[0-9]{2}".prop_map(|s| s)
}

/// Generates a random work ID.
fn arb_work_id() -> impl Strategy<Value = String> {
    "work-[a-z]{2}[0-9]{2}".prop_map(|s| s)
}

/// Generates a list of work IDs (1-5 items for manageable test size).
fn arb_work_ids() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(arb_work_id(), 1..=5)
}

/// Generates a valid coordination budget.
fn arb_budget() -> impl Strategy<Value = CoordinationBudget> {
    (
        1u32..100,
        1000u64..100_000,
        prop::option::of(1000u64..100_000),
    )
        .prop_map(|(episodes, duration, tokens)| {
            CoordinationBudget::new(episodes, duration, tokens).unwrap()
        })
}

/// Generates a valid `CoordinationStarted` event.
fn arb_started_event() -> impl Strategy<Value = CoordinationStarted> {
    (arb_coordination_id(), arb_work_ids(), arb_budget(), 1u32..5).prop_map(
        |(coord_id, work_ids, budget, max_attempts)| {
            CoordinationStarted::new(coord_id, work_ids, budget, max_attempts, 1_000_000_000)
                .unwrap()
        },
    )
}

/// Generates a `CoordinationSessionBound` event for a given coordination and
/// work.
#[allow(dead_code)]
fn arb_bound_event(
    coord_id: String,
    work_id: String,
    attempt: u32,
) -> impl Strategy<Value = CoordinationSessionBound> {
    arb_session_id().prop_map(move |session_id| {
        CoordinationSessionBound::new(
            coord_id.clone(),
            session_id,
            work_id.clone(),
            attempt,
            0, // expected_transition_count
            100,
            2_000_000_000,
        )
    })
}

/// Generates a session outcome.
fn arb_outcome() -> impl Strategy<Value = SessionOutcome> {
    prop_oneof![Just(SessionOutcome::Success), Just(SessionOutcome::Failure)]
}

/// Generates a `CoordinationSessionUnbound` event.
#[allow(dead_code)]
fn arb_unbound_event(
    coord_id: String,
    session_id: String,
    work_id: String,
) -> impl Strategy<Value = CoordinationSessionUnbound> {
    (arb_outcome(), 0u64..10000).prop_map(move |(outcome, tokens)| {
        CoordinationSessionUnbound::new(
            coord_id.clone(),
            session_id.clone(),
            work_id.clone(),
            outcome,
            tokens,
            3_000_000_000,
        )
    })
}

/// Generates a stop condition.
fn arb_stop_condition() -> impl Strategy<Value = StopCondition> {
    prop_oneof![
        Just(StopCondition::WorkCompleted),
        arb_work_id().prop_map(|work_id| StopCondition::MaxAttemptsExceeded { work_id }),
        Just(StopCondition::BudgetExhausted(
            crate::coordination::state::BudgetType::Episodes
        )),
        Just(StopCondition::BudgetExhausted(
            crate::coordination::state::BudgetType::Duration
        )),
        Just(StopCondition::BudgetExhausted(
            crate::coordination::state::BudgetType::Tokens
        )),
        (1u32..5).prop_map(|failures| StopCondition::CircuitBreakerTriggered {
            consecutive_failures: failures
        }),
    ]
}

/// Generates a `CoordinationCompleted` event.
#[allow(dead_code)]
fn arb_completed_event(coord_id: String) -> impl Strategy<Value = CoordinationCompleted> {
    (arb_stop_condition(), 0u32..10, 0u64..60_000, 0u64..100_000).prop_map(
        move |(stop, episodes, elapsed, tokens)| {
            CoordinationCompleted::new(
                coord_id.clone(),
                stop,
                BudgetUsage {
                    consumed_episodes: episodes,
                    elapsed_ms: elapsed,
                    consumed_tokens: tokens,
                },
                episodes,
                episodes.saturating_sub(1),
                1,
                [0u8; BLAKE3_HASH_SIZE],
                4_000_000_000,
            )
        },
    )
}

/// Generates an abort reason.
fn arb_abort_reason() -> impl Strategy<Value = AbortReason> {
    prop_oneof![
        Just(AbortReason::NoEligibleWork),
        "[a-z]{5,10}".prop_map(|reason| AbortReason::Cancelled { reason }),
        "[a-z]{5,15}".prop_map(|message| AbortReason::Error { message }),
    ]
}

/// Generates a `CoordinationAborted` event.
#[allow(dead_code)]
fn arb_aborted_event(coord_id: String) -> impl Strategy<Value = CoordinationAborted> {
    arb_abort_reason().prop_map(move |reason| {
        CoordinationAborted::new(coord_id.clone(), reason, BudgetUsage::new(), 4_000_000_000)
    })
}

// ============================================================================
// Event Record Helpers
// ============================================================================

/// Creates an `EventRecord` from a `CoordinationStarted` event.
fn started_to_record(event: &CoordinationStarted) -> EventRecord {
    EventRecord::with_timestamp(
        EVENT_TYPE_STARTED,
        &event.coordination_id,
        "test-actor",
        serde_json::to_vec(event).unwrap(),
        event.started_at,
    )
}

/// Creates an `EventRecord` from a `CoordinationSessionBound` event.
fn bound_to_record(event: &CoordinationSessionBound) -> EventRecord {
    EventRecord::with_timestamp(
        EVENT_TYPE_SESSION_BOUND,
        &event.coordination_id,
        "test-actor",
        serde_json::to_vec(event).unwrap(),
        event.bound_at,
    )
}

/// Creates an `EventRecord` from a `CoordinationSessionUnbound` event.
fn unbound_to_record(event: &CoordinationSessionUnbound) -> EventRecord {
    EventRecord::with_timestamp(
        EVENT_TYPE_SESSION_UNBOUND,
        &event.coordination_id,
        "test-actor",
        serde_json::to_vec(event).unwrap(),
        event.unbound_at,
    )
}

/// Creates an `EventRecord` from a `CoordinationCompleted` event.
fn completed_to_record(event: &CoordinationCompleted) -> EventRecord {
    EventRecord::with_timestamp(
        EVENT_TYPE_COMPLETED,
        &event.coordination_id,
        "test-actor",
        serde_json::to_vec(event).unwrap(),
        event.completed_at,
    )
}

/// Creates an `EventRecord` from a `CoordinationAborted` event.
fn aborted_to_record(event: &CoordinationAborted) -> EventRecord {
    EventRecord::with_timestamp(
        EVENT_TYPE_ABORTED,
        &event.coordination_id,
        "test-actor",
        serde_json::to_vec(event).unwrap(),
        event.aborted_at,
    )
}

// ============================================================================
// Property Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// PT-COORD-REDUCE-001: Reducer determinism property test.
    ///
    /// Running a reducer twice over the same events must produce identical state.
    /// This is the critical property enabling checkpoint correctness.
    #[test]
    fn tck_00149_prop_reducer_determinism(started in arb_started_event()) {
        let mut reducer1 = CoordinationReducer::new();
        let mut reducer2 = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Create event record
        let event = started_to_record(&started);

        // Apply to both reducers
        reducer1.apply(&event, &ctx).unwrap();
        reducer2.apply(&event, &ctx).unwrap();

        // States must be identical
        prop_assert_eq!(reducer1.state(), reducer2.state());
    }

    /// PT-COORD-REDUCE-002: Reducer idempotency property test.
    ///
    /// Applying the same event twice must produce the same state as applying once.
    #[test]
    fn tck_00149_prop_reducer_idempotency(started in arb_started_event()) {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Create event record
        let event = started_to_record(&started);

        // Apply once
        reducer.apply(&event, &ctx).unwrap();
        let state_after_one = reducer.state().clone();

        // Apply again
        reducer.apply(&event, &ctx).unwrap();
        let state_after_two = reducer.state().clone();

        // States must be identical (idempotent)
        prop_assert_eq!(state_after_one, state_after_two);
    }

    /// PT-COORD-REDUCE-003: Budget monotonicity property test.
    ///
    /// Budget usage (consumed_episodes, consumed_tokens) never decreases during
    /// event processing.
    #[test]
    fn tck_00149_prop_budget_monotonicity(
        started in arb_started_event(),
        num_sessions in 1usize..5
    ) {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_event = started_to_record(&started);
        reducer.apply(&start_event, &ctx).unwrap();

        let mut prev_episodes = 0u32;
        let mut prev_tokens = 0u64;

        // Process multiple sessions
        for i in 0..num_sessions {
            // Skip if no work items
            let work_id = match started.work_ids.get(i % started.work_ids.len()) {
                Some(w) => w.clone(),
                None => continue,
            };

            let session_id = format!("session-{i}");
            let attempt = (i as u32) + 1;

            // Bind
            let bound = CoordinationSessionBound::new(
                started.coordination_id.clone(),
                session_id.clone(),
                work_id.clone(),
                attempt,
                0, // expected_transition_count
                100,
                2_000_000_000,
            );
            reducer.apply(&bound_to_record(&bound), &ctx).unwrap();

            // Unbind with some token consumption
            let tokens = (i as u64 + 1) * 100;
            let outcome = if i % 2 == 0 {
                SessionOutcome::Success
            } else {
                SessionOutcome::Failure
            };
            let unbound = CoordinationSessionUnbound::new(
                started.coordination_id.clone(),
                session_id,
                work_id,
                outcome,
                tokens,
                3_000_000_000,
            );
            reducer.apply(&unbound_to_record(&unbound), &ctx).unwrap();

            // Verify monotonicity
            if let Some(coord) = reducer.state().get(&started.coordination_id) {
                prop_assert!(
                    coord.budget_usage.consumed_episodes >= prev_episodes,
                    "consumed_episodes decreased: {} -> {}",
                    prev_episodes,
                    coord.budget_usage.consumed_episodes
                );
                prop_assert!(
                    coord.budget_usage.consumed_tokens >= prev_tokens,
                    "consumed_tokens decreased: {} -> {}",
                    prev_tokens,
                    coord.budget_usage.consumed_tokens
                );

                prev_episodes = coord.budget_usage.consumed_episodes;
                prev_tokens = coord.budget_usage.consumed_tokens;
            }
        }
    }

    /// Property: Checkpoint serialization is lossless.
    ///
    /// Serializing and deserializing state must produce identical state.
    #[test]
    fn tck_00149_prop_checkpoint_serialization_lossless(started in arb_started_event()) {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Process event
        let event = started_to_record(&started);
        reducer.apply(&event, &ctx).unwrap();

        // Get state before serialization
        let state_before = reducer.state().clone();

        // Serialize and deserialize using CheckpointableReducer trait
        let serialized = CheckpointableReducer::serialize_state(&reducer).unwrap();
        reducer.reset();
        CheckpointableReducer::deserialize_state(&mut reducer, &serialized).unwrap();

        // State must be identical
        prop_assert_eq!(&state_before, reducer.state());
    }

    /// Property: Completed events are idempotent.
    #[test]
    fn tck_00149_prop_completed_idempotent(
        started in arb_started_event(),
        completed in arb_stop_condition()
    ) {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_event = started_to_record(&started);
        reducer.apply(&start_event, &ctx).unwrap();

        // Complete coordination
        let completed_event = CoordinationCompleted::new(
            started.coordination_id.clone(),
            completed,
            BudgetUsage::new(),
            1, 1, 0,
            [0u8; BLAKE3_HASH_SIZE],
            4_000_000_000,
        );
        let record = completed_to_record(&completed_event);

        // Apply once
        reducer.apply(&record, &ctx).unwrap();
        let state1 = reducer.state().clone();

        // Apply again
        reducer.apply(&record, &ctx).unwrap();
        let state2 = reducer.state().clone();

        prop_assert_eq!(state1, state2);
    }

    /// Property: Aborted events are idempotent.
    #[test]
    fn tck_00149_prop_aborted_idempotent(
        started in arb_started_event(),
        reason in arb_abort_reason()
    ) {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_event = started_to_record(&started);
        reducer.apply(&start_event, &ctx).unwrap();

        // Abort coordination
        let aborted_event = CoordinationAborted::new(
            started.coordination_id.clone(),
            reason,
            BudgetUsage::new(),
            4_000_000_000,
        );
        let record = aborted_to_record(&aborted_event);

        // Apply once
        reducer.apply(&record, &ctx).unwrap();
        let state1 = reducer.state().clone();

        // Apply again
        reducer.apply(&record, &ctx).unwrap();
        let state2 = reducer.state().clone();

        prop_assert_eq!(state1, state2);
    }

    /// Property: Reset always produces empty state.
    #[test]
    fn tck_00149_prop_reset_produces_empty_state(started in arb_started_event()) {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Add some state
        let event = started_to_record(&started);
        reducer.apply(&event, &ctx).unwrap();

        // Reset
        reducer.reset();

        // Must be empty
        prop_assert!(reducer.state().is_empty());
        prop_assert_eq!(reducer.state().binding_count(), 0);
    }
}

// ============================================================================
// Determinism Integration Tests
// ============================================================================

/// TCK-00149: Test determinism across a complex event sequence.
///
/// This test verifies that replaying events from genesis produces
/// deterministic state, matching the pattern from the reducer framework tests.
#[test]
fn tck_00149_determinism_complex_sequence() {
    let mut reducer1 = CoordinationReducer::new();
    let mut reducer2 = CoordinationReducer::new();
    let ctx = ReducerContext::new(1);

    let budget = CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap();

    // Build event sequence
    let events: Vec<EventRecord> = vec![
        // Start coordination
        started_to_record(
            &CoordinationStarted::new(
                "coord-1".to_string(),
                vec!["work-1".to_string(), "work-2".to_string()],
                budget.clone(),
                3,
                1_000_000_000,
            )
            .unwrap(),
        ),
        // Bind session to work-1
        bound_to_record(&CoordinationSessionBound::new(
            "coord-1".to_string(),
            "session-1".to_string(),
            "work-1".to_string(),
            1,
            0, // expected_transition_count
            100,
            2_000_000_000,
        )),
        // Unbind with failure
        unbound_to_record(&CoordinationSessionUnbound::new(
            "coord-1".to_string(),
            "session-1".to_string(),
            "work-1".to_string(),
            SessionOutcome::Failure,
            1000,
            3_000_000_000,
        )),
        // Retry work-1
        bound_to_record(&CoordinationSessionBound::new(
            "coord-1".to_string(),
            "session-2".to_string(),
            "work-1".to_string(),
            2,
            0, // expected_transition_count
            200,
            4_000_000_000,
        )),
        // Unbind with success
        unbound_to_record(&CoordinationSessionUnbound::new(
            "coord-1".to_string(),
            "session-2".to_string(),
            "work-1".to_string(),
            SessionOutcome::Success,
            2000,
            5_000_000_000,
        )),
        // Bind session to work-2
        bound_to_record(&CoordinationSessionBound::new(
            "coord-1".to_string(),
            "session-3".to_string(),
            "work-2".to_string(),
            1,
            0, // expected_transition_count
            300,
            6_000_000_000,
        )),
        // Unbind with success
        unbound_to_record(&CoordinationSessionUnbound::new(
            "coord-1".to_string(),
            "session-3".to_string(),
            "work-2".to_string(),
            SessionOutcome::Success,
            1500,
            7_000_000_000,
        )),
        // Complete coordination
        completed_to_record(&CoordinationCompleted::new(
            "coord-1".to_string(),
            StopCondition::WorkCompleted,
            BudgetUsage {
                consumed_episodes: 3,
                elapsed_ms: 6000,
                consumed_tokens: 4500,
            },
            3,
            2,
            1,
            [0u8; BLAKE3_HASH_SIZE],
            8_000_000_000,
        )),
    ];

    // Apply to both reducers
    for event in &events {
        reducer1.apply(event, &ctx).unwrap();
        reducer2.apply(event, &ctx).unwrap();
    }

    // States must be identical
    assert_eq!(reducer1.state(), reducer2.state());

    // Verify expected state
    let coord = reducer1.state().get("coord-1").unwrap();
    assert!(coord.is_terminal());
    assert!(matches!(
        coord.status,
        crate::coordination::state::CoordinationStatus::Completed(StopCondition::WorkCompleted)
    ));
}

/// TCK-00149: Test that checkpoint + remaining events = full replay.
///
/// This is the critical determinism property for crash recovery.
#[test]
fn tck_00149_checkpoint_replay_equals_genesis_replay() {
    let ctx = ReducerContext::new(1);
    let budget = CoordinationBudget::new(10, 60_000, None).unwrap();

    // Build event sequence (split into two parts)
    let events_part1: Vec<EventRecord> = vec![
        started_to_record(
            &CoordinationStarted::new(
                "coord-1".to_string(),
                vec!["work-1".to_string(), "work-2".to_string()],
                budget.clone(),
                3,
                1_000_000_000,
            )
            .unwrap(),
        ),
        bound_to_record(&CoordinationSessionBound::new(
            "coord-1".to_string(),
            "session-1".to_string(),
            "work-1".to_string(),
            1,
            0, // expected_transition_count
            100,
            2_000_000_000,
        )),
    ];

    let events_part2: Vec<EventRecord> = vec![
        unbound_to_record(&CoordinationSessionUnbound::new(
            "coord-1".to_string(),
            "session-1".to_string(),
            "work-1".to_string(),
            SessionOutcome::Success,
            1000,
            3_000_000_000,
        )),
        completed_to_record(&CoordinationCompleted::new(
            "coord-1".to_string(),
            StopCondition::WorkCompleted,
            BudgetUsage {
                consumed_episodes: 1,
                elapsed_ms: 2000,
                consumed_tokens: 1000,
            },
            1,
            1,
            0,
            [0u8; BLAKE3_HASH_SIZE],
            4_000_000_000,
        )),
    ];

    // Reducer with checkpoint simulation
    let mut reducer_checkpoint = CoordinationReducer::new();
    for event in &events_part1 {
        reducer_checkpoint.apply(event, &ctx).unwrap();
    }

    // Checkpoint state
    let checkpoint_data = CheckpointableReducer::serialize_state(&reducer_checkpoint).unwrap();

    // Continue from checkpoint
    for event in &events_part2 {
        reducer_checkpoint.apply(event, &ctx).unwrap();
    }

    // Full replay from genesis
    let mut reducer_genesis = CoordinationReducer::new();
    for event in events_part1.iter().chain(events_part2.iter()) {
        reducer_genesis.apply(event, &ctx).unwrap();
    }

    // States must be identical
    assert_eq!(reducer_checkpoint.state(), reducer_genesis.state());

    // Also test restoring from checkpoint and continuing
    let mut reducer_restored = CoordinationReducer::new();
    CheckpointableReducer::deserialize_state(&mut reducer_restored, &checkpoint_data).unwrap();
    for event in &events_part2 {
        reducer_restored.apply(event, &ctx).unwrap();
    }

    assert_eq!(reducer_restored.state(), reducer_genesis.state());
}

// ============================================================================
// TCK-00148 Tests (from previous ticket, required for completeness)
// ============================================================================

use crate::coordination::{
    BindingInfo, BudgetType, CoordinationEvent, CoordinationSession, CoordinationState,
    CoordinationStatus, WorkItemOutcome, WorkItemTracking,
};

/// TCK-00148: Verify all types are Send + Sync for async runtime.
#[test]
fn tck_00148_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    // State types
    assert_send_sync::<CoordinationBudget>();
    assert_send_sync::<BudgetUsage>();
    assert_send_sync::<BudgetType>();
    assert_send_sync::<StopCondition>();
    assert_send_sync::<AbortReason>();
    assert_send_sync::<CoordinationStatus>();
    assert_send_sync::<SessionOutcome>();
    assert_send_sync::<BindingInfo>();
    assert_send_sync::<WorkItemTracking>();
    assert_send_sync::<WorkItemOutcome>();
    assert_send_sync::<CoordinationSession>();
    assert_send_sync::<CoordinationState>();

    // Reducer types
    assert_send_sync::<CoordinationReducer>();

    // Event types
    assert_send_sync::<CoordinationStarted>();
    assert_send_sync::<CoordinationSessionBound>();
    assert_send_sync::<CoordinationSessionUnbound>();
    assert_send_sync::<CoordinationCompleted>();
    assert_send_sync::<CoordinationAborted>();
    assert_send_sync::<CoordinationEvent>();
}

/// TCK-00148: Verify all types derive required traits.
#[test]
fn tck_00148_types_derive_required_traits() {
    // Test Debug (via format!)
    let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
    let _ = format!("{budget:?}");

    let usage = BudgetUsage::new();
    let _ = format!("{usage:?}");

    let stop = StopCondition::WorkCompleted;
    let _ = format!("{stop:?}");

    let status = CoordinationStatus::Running;
    let _ = format!("{status:?}");

    let binding = BindingInfo::new("s".to_string(), "w".to_string(), 1, 1000);
    let _ = format!("{binding:?}");

    let session =
        CoordinationSession::new("c".to_string(), vec!["w".to_string()], budget, 3, 1000).unwrap();
    let _ = format!("{session:?}");

    let state = CoordinationState::new();
    let _ = format!("{state:?}");

    // Test Clone (via clone() and then use it)
    let budget2 = CoordinationBudget::new(10, 60_000, None).unwrap();
    let budget_clone = budget2.clone();
    assert_eq!(budget2, budget_clone);

    let usage2 = BudgetUsage::new();
    let usage_clone = usage2.clone();
    assert_eq!(usage2, usage_clone);

    let stop2 = StopCondition::WorkCompleted;
    let stop_clone = stop2.clone();
    assert_eq!(stop2, stop_clone);

    let status2 = CoordinationStatus::Running;
    let status_clone = status2.clone();
    assert_eq!(status2, status_clone);

    let binding2 = BindingInfo::new("s".to_string(), "w".to_string(), 1, 1000);
    let binding_clone = binding2.clone();
    assert_eq!(binding2, binding_clone);

    let session2 = CoordinationSession::new(
        "c".to_string(),
        vec!["w".to_string()],
        CoordinationBudget::new(10, 60_000, None).unwrap(),
        3,
        1000,
    )
    .unwrap();
    let session_clone = session2.clone();
    assert_eq!(session2, session_clone);

    let state2 = CoordinationState::new();
    let state_clone = state2.clone();
    assert_eq!(state2, state_clone);

    // Test Serialize/Deserialize (via serde_json)
    let json = serde_json::to_string(&budget_clone).unwrap();
    let _: CoordinationBudget = serde_json::from_str(&json).unwrap();

    let json = serde_json::to_string(&usage_clone).unwrap();
    let _: BudgetUsage = serde_json::from_str(&json).unwrap();

    let json = serde_json::to_string(&stop_clone).unwrap();
    let _: StopCondition = serde_json::from_str(&json).unwrap();

    let json = serde_json::to_string(&status_clone).unwrap();
    let _: CoordinationStatus = serde_json::from_str(&json).unwrap();

    let json = serde_json::to_string(&binding_clone).unwrap();
    let _: BindingInfo = serde_json::from_str(&json).unwrap();

    let json = serde_json::to_string(&session_clone).unwrap();
    let _: CoordinationSession = serde_json::from_str(&json).unwrap();

    let json = serde_json::to_string(&state_clone).unwrap();
    let _: CoordinationState = serde_json::from_str(&json).unwrap();
}

/// TCK-00148: Comprehensive JSON round-trip test for all types.
#[test]
fn tck_00148_json_roundtrip_comprehensive() {
    // Build a complete CoordinationState with all nested types
    let budget = CoordinationBudget::new(10, 60_000, Some(100_000)).unwrap();
    let mut session = CoordinationSession::new(
        "coord-123".to_string(),
        vec!["work-1".to_string(), "work-2".to_string()],
        budget,
        3,
        1_000_000_000,
    )
    .unwrap();
    session.status = CoordinationStatus::Running;
    session.budget_usage = BudgetUsage {
        consumed_episodes: 2,
        elapsed_ms: 15_000,
        consumed_tokens: 25_000,
    };
    session.consecutive_failures = 1;

    let mut state = CoordinationState::new();
    state.coordinations.insert("coord-123".to_string(), session);

    let binding = BindingInfo::new(
        "session-456".to_string(),
        "work-1".to_string(),
        1,
        2_000_000_000,
    );
    state.bindings.insert("session-456".to_string(), binding);

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&state).unwrap();

    // Deserialize back
    let restored: CoordinationState = serde_json::from_str(&json).unwrap();

    // Verify equality
    assert_eq!(state, restored);

    // Verify nested values
    let coord = restored.get("coord-123").unwrap();
    assert_eq!(coord.work_queue.len(), 2);
    assert_eq!(coord.budget_usage.consumed_episodes, 2);
    assert!(matches!(coord.status, CoordinationStatus::Running));

    let binding = restored.get_binding("session-456").unwrap();
    assert_eq!(binding.work_id, "work-1");
    assert_eq!(binding.attempt_number, 1);
}
