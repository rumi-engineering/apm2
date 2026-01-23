//! Integration and property tests for the session lifecycle reducer.
//!
//! These tests verify:
//! - Replay determinism: same events produce identical state
//! - Checkpoint correctness: checkpoint + tail equals full replay
//! - State machine invariants: valid transitions only

// Test code uses proptest which generates patterns that trigger these lints.
#![allow(
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use proptest::prelude::*;

use super::reducer::helpers;
use super::{ExitClassification, SessionReducer, SessionState};
use crate::ledger::{EventRecord, Ledger};
use crate::reducer::{
    CheckpointStore, CheckpointableReducer, Reducer, ReducerContext, ReducerRunner,
    ReducerRunnerConfig,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Generates a random session ID.
fn arb_session_id() -> impl Strategy<Value = String> {
    "[a-z]{3}-[0-9]{4}".prop_map(|s| s)
}

/// Generates a random actor ID.
fn arb_actor_id() -> impl Strategy<Value = String> {
    "actor-[a-z]{3}".prop_map(|s| s)
}

/// Generates a random adapter type.
fn arb_adapter_type() -> impl Strategy<Value = &'static str> {
    prop::sample::select(&["claude-code", "gemini-cli", "codex-cli"][..])
}

/// Generates a random entropy budget.
fn arb_entropy_budget() -> impl Strategy<Value = u64> {
    100u64..10000
}

/// Session event type for property testing.
#[derive(Debug, Clone)]
enum SessionEventType {
    Started {
        session_id: String,
        actor_id: String,
        adapter_type: String,
        entropy_budget: u64,
    },
    Progress {
        session_id: String,
        actor_id: String,
        entropy_consumed: u64,
    },
    Terminated {
        session_id: String,
        actor_id: String,
        classification: String,
    },
    Quarantined {
        session_id: String,
        actor_id: String,
    },
}

impl SessionEventType {
    fn to_event_record(&self, seq: u64) -> EventRecord {
        let timestamp = 1_000_000_000 + seq * 1_000_000;
        match self {
            Self::Started {
                session_id,
                actor_id,
                adapter_type,
                entropy_budget,
            } => {
                let payload = helpers::session_started_payload(
                    session_id,
                    actor_id,
                    adapter_type,
                    &format!("work-{seq}"),
                    &format!("lease-{seq}"),
                    *entropy_budget,
                );
                EventRecord::with_timestamp(
                    "session.started",
                    session_id,
                    actor_id,
                    payload,
                    timestamp,
                )
            },
            Self::Progress {
                session_id,
                actor_id,
                entropy_consumed,
            } => {
                let payload = helpers::session_progress_payload(
                    session_id,
                    seq,
                    "HEARTBEAT",
                    *entropy_consumed,
                );
                EventRecord::with_timestamp(
                    "session.progress",
                    session_id,
                    actor_id,
                    payload,
                    timestamp,
                )
            },
            Self::Terminated {
                session_id,
                actor_id,
                classification,
            } => {
                let payload =
                    helpers::session_terminated_payload(session_id, classification, "done", seq);
                EventRecord::with_timestamp(
                    "session.terminated",
                    session_id,
                    actor_id,
                    payload,
                    timestamp,
                )
            },
            Self::Quarantined {
                session_id,
                actor_id,
            } => {
                let payload = helpers::session_quarantined_payload(
                    session_id,
                    "violation",
                    timestamp + 1_000_000_000,
                );
                EventRecord::with_timestamp(
                    "session.quarantined",
                    session_id,
                    actor_id,
                    payload,
                    timestamp,
                )
            },
        }
    }
}

/// Generates a valid sequence of session events.
///
/// Each session follows valid state transitions:
/// - Started -> (Progress)* -> (Terminated | Quarantined)?
fn arb_valid_session_events(
    max_sessions: usize,
    max_progress: usize,
) -> impl Strategy<Value = Vec<SessionEventType>> {
    (1..=max_sessions, 0..=max_progress)
        .prop_flat_map(|(num_sessions, progress_per_session)| {
            let sessions: Vec<_> = (0..num_sessions)
                .map(|i| {
                    (
                        arb_session_id(),
                        arb_actor_id(),
                        arb_adapter_type(),
                        arb_entropy_budget(),
                        prop::bool::ANY, // whether to terminate
                        prop::bool::ANY, // terminate vs quarantine
                    )
                        .prop_map(
                            move |(
                                session_id,
                                actor_id,
                                adapter_type,
                                entropy_budget,
                                do_end,
                                is_terminate,
                            )| {
                                let session_id = format!("{session_id}-{i}");
                                let mut events = vec![SessionEventType::Started {
                                    session_id: session_id.clone(),
                                    actor_id: actor_id.clone(),
                                    adapter_type: adapter_type.to_string(),
                                    entropy_budget,
                                }];

                                // Add progress events
                                for p in 0..progress_per_session {
                                    events.push(SessionEventType::Progress {
                                        session_id: session_id.clone(),
                                        actor_id: actor_id.clone(),
                                        entropy_consumed: (p as u64 + 1) * 100,
                                    });
                                }

                                // Optionally terminate or quarantine
                                if do_end {
                                    if is_terminate {
                                        events.push(SessionEventType::Terminated {
                                            session_id,
                                            actor_id,
                                            classification: "SUCCESS".to_string(),
                                        });
                                    } else {
                                        events.push(SessionEventType::Quarantined {
                                            session_id,
                                            actor_id,
                                        });
                                    }
                                }

                                events
                            },
                        )
                })
                .collect();

            sessions
        })
        .prop_map(|session_groups: Vec<Vec<SessionEventType>>| {
            // Keep original order for determinism (sessions in sequence)
            session_groups.into_iter().flatten().collect()
        })
}

// ============================================================================
// Property Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property: Replay from genesis produces deterministic state.
    ///
    /// Running a reducer twice over the same events must produce identical state.
    #[test]
    fn prop_replay_deterministic(events in arb_valid_session_events(5, 3)) {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Convert to EventRecords and add to ledger
        let records: Vec<EventRecord> = events
            .iter()
            .enumerate()
            .map(|(i, e)| e.to_event_record(i as u64))
            .collect();
        ledger.append_batch(&records).unwrap();

        let runner = ReducerRunner::new(&ledger, &checkpoint_store);

        // First run
        let mut reducer1 = SessionReducer::new();
        runner.run_from_genesis(&mut reducer1).unwrap();

        // Second run
        let mut reducer2 = SessionReducer::new();
        runner.run_from_genesis(&mut reducer2).unwrap();

        // States must be identical
        prop_assert_eq!(reducer1.state(), reducer2.state());
    }

    /// Property: Checkpoint replay equals genesis replay.
    ///
    /// This is the critical determinism property: checkpointed state + remaining events
    /// must equal full replay state.
    #[test]
    fn prop_checkpoint_matches_genesis(events in arb_valid_session_events(5, 3)) {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Convert to EventRecords and add to ledger
        let records: Vec<EventRecord> = events
            .iter()
            .enumerate()
            .map(|(i, e)| e.to_event_record(i as u64))
            .collect();
        ledger.append_batch(&records).unwrap();

        // Run with checkpointing
        let config = ReducerRunnerConfig {
            checkpoint_interval: 3, // Frequent checkpoints for testing
            batch_size: 2,
        };
        let runner = ReducerRunner::with_config(&ledger, &checkpoint_store, config);

        let mut reducer_checkpoint = SessionReducer::new();
        runner.run(&mut reducer_checkpoint).unwrap();

        // Run from genesis (no checkpoints used)
        let mut reducer_genesis = SessionReducer::new();
        runner.run_from_genesis(&mut reducer_genesis).unwrap();

        // States must be identical
        prop_assert_eq!(reducer_checkpoint.state(), reducer_genesis.state());
    }

    /// Property: State counts are consistent.
    ///
    /// active + terminated + quarantined = total sessions
    #[test]
    fn prop_state_counts_consistent(events in arb_valid_session_events(10, 2)) {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        for (i, event) in events.iter().enumerate() {
            let record = event.to_event_record(i as u64);
            // Ignore errors (some events may be invalid due to random generation)
            let _ = reducer.apply(&record, &ctx);
        }

        let state = reducer.state();
        let total = state.len();
        let active = state.active_count();
        let terminated = state.terminated_count();
        let quarantined = state.quarantined_count();

        prop_assert_eq!(
            total,
            active + terminated + quarantined,
            "State counts should sum to total: {} != {} + {} + {}",
            total,
            active,
            terminated,
            quarantined
        );
    }

    /// Property: Checkpoint serialization is lossless.
    ///
    /// Serializing and deserializing state must produce identical state.
    #[test]
    fn prop_checkpoint_serialization_lossless(events in arb_valid_session_events(5, 2)) {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Convert to EventRecords and add to ledger
        let records: Vec<EventRecord> = events
            .iter()
            .enumerate()
            .map(|(i, e)| e.to_event_record(i as u64))
            .collect();
        ledger.append_batch(&records).unwrap();

        let runner = ReducerRunner::new(&ledger, &checkpoint_store);
        let mut reducer = SessionReducer::new();
        runner.run(&mut reducer).unwrap();

        // Get state before serialization
        let state_before = reducer.state().clone();

        // Serialize and deserialize
        let serialized = CheckpointableReducer::serialize_state(&reducer).unwrap();
        reducer.reset();
        CheckpointableReducer::deserialize_state(&mut reducer, &serialized).unwrap();

        // State must be identical
        prop_assert_eq!(&state_before, reducer.state());
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_session_lifecycle() {
    let mut reducer = SessionReducer::new();
    let ctx = ReducerContext::new(1);

    // Start session
    let start_payload = helpers::session_started_payload(
        "session-1",
        "actor-1",
        "claude-code",
        "work-1",
        "lease-1",
        1000,
    );
    let start_event = EventRecord::with_timestamp(
        "session.started",
        "session-1",
        "actor-1",
        start_payload,
        1_000_000_000,
    );
    reducer.apply(&start_event, &ctx).unwrap();

    // Verify running state
    let state = reducer.state().get("session-1").unwrap();
    assert!(state.is_active());
    assert!(!state.is_terminal());

    // Send progress events
    for i in 1..=5 {
        let progress_payload =
            helpers::session_progress_payload("session-1", i, "HEARTBEAT", i * 100);
        let progress_event = EventRecord::with_timestamp(
            "session.progress",
            "session-1",
            "actor-1",
            progress_payload,
            1_000_000_000 + i * 1000,
        );
        reducer.apply(&progress_event, &ctx).unwrap();
    }

    // Verify progress was tracked
    match reducer.state().get("session-1").unwrap() {
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
    let term_payload =
        helpers::session_terminated_payload("session-1", "SUCCESS", "completed", 500);
    let term_event = EventRecord::with_timestamp(
        "session.terminated",
        "session-1",
        "actor-1",
        term_payload,
        2_000_000_000,
    );
    reducer.apply(&term_event, &ctx).unwrap();

    // Verify terminated state
    let final_state = reducer.state().get("session-1").unwrap();
    assert!(!final_state.is_active());
    assert!(final_state.is_terminal());
    match final_state {
        SessionState::Terminated {
            exit_classification,
            ..
        } => {
            assert_eq!(*exit_classification, ExitClassification::Success);
        },
        _ => panic!("Expected Terminated state"),
    }
}

#[test]
fn test_multiple_concurrent_sessions() {
    let mut reducer = SessionReducer::new();
    let ctx = ReducerContext::new(1);

    // Start 3 sessions
    for i in 1..=3 {
        let start_payload = helpers::session_started_payload(
            &format!("session-{i}"),
            &format!("actor-{i}"),
            "claude-code",
            &format!("work-{i}"),
            &format!("lease-{i}"),
            1000,
        );
        let start_event = EventRecord::with_timestamp(
            "session.started",
            format!("session-{i}"),
            format!("actor-{i}"),
            start_payload,
            1_000_000_000,
        );
        reducer.apply(&start_event, &ctx).unwrap();
    }

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
    reducer.apply(&term_event, &ctx).unwrap();

    // Terminate session-2 with failure
    let term_payload2 = helpers::session_terminated_payload("session-2", "FAILURE", "error", 100);
    let term_event2 = EventRecord::with_timestamp(
        "session.terminated",
        "session-2",
        "actor-2",
        term_payload2,
        2_000_000_000,
    );
    reducer.apply(&term_event2, &ctx).unwrap();

    // Quarantine session-3
    let quar_payload =
        helpers::session_quarantined_payload("session-3", "policy violation", 3_000_000_000);
    let quar_event = EventRecord::with_timestamp(
        "session.quarantined",
        "session-3",
        "actor-3",
        quar_payload,
        2_000_000_000,
    );
    reducer.apply(&quar_event, &ctx).unwrap();

    // Verify final states
    assert_eq!(reducer.state().active_count(), 0);
    assert_eq!(reducer.state().terminated_count(), 2);
    assert_eq!(reducer.state().quarantined_count(), 1);

    match reducer.state().get("session-1").unwrap() {
        SessionState::Terminated {
            exit_classification,
            ..
        } => assert_eq!(*exit_classification, ExitClassification::Success),
        _ => panic!("Expected Terminated state"),
    }

    match reducer.state().get("session-2").unwrap() {
        SessionState::Terminated {
            exit_classification,
            ..
        } => assert_eq!(*exit_classification, ExitClassification::Failure),
        _ => panic!("Expected Terminated state"),
    }

    match reducer.state().get("session-3").unwrap() {
        SessionState::Quarantined { reason, .. } => assert_eq!(reason, "policy violation"),
        _ => panic!("Expected Quarantined state"),
    }
}

#[test]
fn test_crash_recovery_simulation() {
    let ledger = Ledger::in_memory().unwrap();
    let checkpoint_store = CheckpointStore::in_memory().unwrap();

    // Add initial events
    let events1: Vec<EventRecord> = (0..10)
        .map(|i| {
            let session_id = format!("session-{}", i % 3);
            let actor_id = format!("actor-{}", i % 3);
            if i < 3 {
                // Start events for sessions 0, 1, 2
                let payload = helpers::session_started_payload(
                    &session_id,
                    &actor_id,
                    "claude-code",
                    &format!("work-{i}"),
                    &format!("lease-{i}"),
                    1000,
                );
                EventRecord::with_timestamp(
                    "session.started",
                    &session_id,
                    &actor_id,
                    payload,
                    1_000_000_000 + i * 1000,
                )
            } else {
                // Progress events
                let payload =
                    helpers::session_progress_payload(&session_id, i, "HEARTBEAT", i * 50);
                EventRecord::with_timestamp(
                    "session.progress",
                    &session_id,
                    &actor_id,
                    payload,
                    1_000_000_000 + i * 1000,
                )
            }
        })
        .collect();
    ledger.append_batch(&events1).unwrap();

    // First run with checkpointing
    let config = ReducerRunnerConfig {
        checkpoint_interval: 5,
        batch_size: 3,
    };
    let runner = ReducerRunner::with_config(&ledger, &checkpoint_store, config);

    let mut reducer1 = SessionReducer::new();
    let result1 = runner.run(&mut reducer1).unwrap();

    assert_eq!(result1.events_processed, 10);

    // Simulate crash by creating new reducer instance
    // Add more events (terminations)
    let events2: Vec<EventRecord> = (0..3)
        .map(|i| {
            let session_id = format!("session-{i}");
            let actor_id = format!("actor-{i}");
            let payload = helpers::session_terminated_payload(&session_id, "SUCCESS", "done", 500);
            EventRecord::with_timestamp(
                "session.terminated",
                &session_id,
                &actor_id,
                payload,
                2_000_000_000 + i * 1000,
            )
        })
        .collect();
    ledger.append_batch(&events2).unwrap();

    // Recovery: new reducer instance should resume from checkpoint
    let mut reducer2 = SessionReducer::new();
    let result2 = runner.run(&mut reducer2).unwrap();

    // Should have resumed from checkpoint
    assert!(result2.resumed_from_checkpoint);
    assert!(result2.events_processed < 13); // Less than all events

    // Verify final state matches full replay
    let mut reducer_verify = SessionReducer::new();
    runner.run_from_genesis(&mut reducer_verify).unwrap();

    assert_eq!(reducer2.state(), reducer_verify.state());

    // All sessions should now be terminated
    assert_eq!(reducer2.state().active_count(), 0);
    assert_eq!(reducer2.state().terminated_count(), 3);
}

#[test]
fn test_exit_classifications() {
    let mut reducer = SessionReducer::new();
    let ctx = ReducerContext::new(1);

    let classifications = ["SUCCESS", "FAILURE", "TIMEOUT", "ENTROPY_EXCEEDED"];

    for (i, classification) in classifications.iter().enumerate() {
        let session_id = format!("session-{i}");

        // Start
        let start_payload = helpers::session_started_payload(
            &session_id,
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = EventRecord::with_timestamp(
            "session.started",
            &session_id,
            "actor-1",
            start_payload,
            1_000_000_000,
        );
        reducer.apply(&start_event, &ctx).unwrap();

        // Terminate
        let term_payload =
            helpers::session_terminated_payload(&session_id, classification, "test", 500);
        let term_event = EventRecord::with_timestamp(
            "session.terminated",
            &session_id,
            "actor-1",
            term_payload,
            2_000_000_000,
        );
        reducer.apply(&term_event, &ctx).unwrap();
    }

    // Verify each classification was correctly parsed
    match reducer.state().get("session-0").unwrap() {
        SessionState::Terminated {
            exit_classification,
            ..
        } => {
            assert_eq!(*exit_classification, ExitClassification::Success);
        },
        _ => panic!("Expected Terminated"),
    }

    match reducer.state().get("session-1").unwrap() {
        SessionState::Terminated {
            exit_classification,
            ..
        } => {
            assert_eq!(*exit_classification, ExitClassification::Failure);
        },
        _ => panic!("Expected Terminated"),
    }

    match reducer.state().get("session-2").unwrap() {
        SessionState::Terminated {
            exit_classification,
            ..
        } => {
            assert_eq!(*exit_classification, ExitClassification::Timeout);
        },
        _ => panic!("Expected Terminated"),
    }

    match reducer.state().get("session-3").unwrap() {
        SessionState::Terminated {
            exit_classification,
            ..
        } => {
            assert_eq!(*exit_classification, ExitClassification::EntropyExceeded);
        },
        _ => panic!("Expected Terminated"),
    }
}
