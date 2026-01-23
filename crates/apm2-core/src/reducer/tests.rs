//! Tests for the reducer framework.
//!
//! This module contains integration tests and property tests that verify
//! reducer determinism - a critical requirement for the APM2 kernel.

// Test code uses proptest which generates patterns that trigger these lints.
// Cast truncation is intentional in tests where we only need small byte values.
#![allow(
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use proptest::prelude::*;
use serde::{Deserialize, Serialize};

use crate::ledger::{EventRecord, Ledger};
use crate::reducer::traits::CheckpointableReducer;
use crate::reducer::{
    Checkpoint, CheckpointStore, Reducer, ReducerContext, ReducerRunner, ReducerRunnerConfig,
};

// ============================================================================
// Test Reducers
// ============================================================================

/// A reducer that tracks session counts.
#[derive(Debug, Default)]
struct SessionCountReducer {
    state: SessionCountState,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SessionCountState {
    active_sessions: u64,
    total_started: u64,
    total_ended: u64,
}

impl Reducer for SessionCountReducer {
    type State = SessionCountState;
    type Error = std::convert::Infallible;

    fn name(&self) -> &'static str {
        "session-count"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        match event.event_type.as_str() {
            "session.start" => {
                self.state.active_sessions += 1;
                self.state.total_started += 1;
            },
            "session.end" => {
                self.state.active_sessions = self.state.active_sessions.saturating_sub(1);
                self.state.total_ended += 1;
            },
            _ => {},
        }
        Ok(())
    }

    fn state(&self) -> &Self::State {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::State {
        &mut self.state
    }

    fn reset(&mut self) {
        self.state = SessionCountState::default();
    }
}

/// A reducer that computes aggregate metrics.
#[derive(Debug, Default)]
struct MetricsReducer {
    state: MetricsState,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MetricsState {
    event_count: u64,
    payload_bytes_total: u64,
    events_by_type: Vec<(String, u64)>,
}

impl MetricsState {
    fn increment_type(&mut self, event_type: &str) {
        for (t, count) in &mut self.events_by_type {
            if t == event_type {
                *count += 1;
                return;
            }
        }
        // Not found, add new entry
        self.events_by_type.push((event_type.to_string(), 1));
        // Keep sorted for deterministic comparison
        self.events_by_type.sort_by(|a, b| a.0.cmp(&b.0));
    }
}

impl Reducer for MetricsReducer {
    type State = MetricsState;
    type Error = std::convert::Infallible;

    fn name(&self) -> &'static str {
        "metrics"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        self.state.event_count += 1;
        self.state.payload_bytes_total += event.payload.len() as u64;
        self.state.increment_type(&event.event_type);
        Ok(())
    }

    fn state(&self) -> &Self::State {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::State {
        &mut self.state
    }

    fn reset(&mut self) {
        self.state = MetricsState::default();
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Event types for property testing.
const EVENT_TYPES: &[&str] = &[
    "session.start",
    "session.end",
    "session.update",
    "tool.request",
    "tool.response",
    "policy.check",
    "health.check",
];

/// Generates a random event type.
fn arb_event_type() -> impl Strategy<Value = &'static str> {
    prop::sample::select(EVENT_TYPES)
}

/// Generates a random session ID.
fn arb_session_id() -> impl Strategy<Value = String> {
    "[a-z]{3}-[0-9]{4}".prop_map(|s| s)
}

/// Generates a random payload.
fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..100)
}

/// Generates a single random event.
fn arb_event() -> impl Strategy<Value = EventRecord> {
    (arb_event_type(), arb_session_id(), arb_payload()).prop_map(
        |(event_type, session_id, payload)| EventRecord::new(event_type, session_id, payload),
    )
}

/// Generates a sequence of random events.
fn arb_events(max_count: usize) -> impl Strategy<Value = Vec<EventRecord>> {
    prop::collection::vec(arb_event(), 1..=max_count)
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
    fn prop_replay_from_genesis_is_deterministic(events in arb_events(100)) {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Add events
        ledger.append_batch(&events).unwrap();

        let runner = ReducerRunner::new(&ledger, &checkpoint_store);

        // First run
        let mut reducer1 = SessionCountReducer::default();
        runner.run_from_genesis(&mut reducer1).unwrap();

        // Second run
        let mut reducer2 = SessionCountReducer::default();
        runner.run_from_genesis(&mut reducer2).unwrap();

        // States must be identical
        prop_assert_eq!(reducer1.state(), reducer2.state());
    }

    /// Property: Replay from checkpoint produces same state as from genesis.
    ///
    /// This is the critical determinism property: checkpointed state + remaining events
    /// must equal full replay state.
    #[test]
    fn prop_checkpoint_replay_equals_genesis_replay(events in arb_events(50)) {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Add events
        ledger.append_batch(&events).unwrap();

        // Run to create checkpoint
        let config = ReducerRunnerConfig {
            checkpoint_interval: 10, // Frequent checkpoints
            batch_size: 5,
        };
        let runner = ReducerRunner::with_config(&ledger, &checkpoint_store, config);

        let mut reducer_checkpoint = SessionCountReducer::default();
        runner.run(&mut reducer_checkpoint).unwrap();

        // Run from genesis (no checkpoint)
        let mut reducer_genesis = SessionCountReducer::default();
        runner.run_from_genesis(&mut reducer_genesis).unwrap();

        // States must be identical
        prop_assert_eq!(reducer_checkpoint.state(), reducer_genesis.state());
    }

    /// Property: Incremental updates produce same state as full replay.
    ///
    /// Adding events and running incrementally must equal running from genesis.
    #[test]
    fn prop_incremental_equals_full_replay(
        initial_events in arb_events(30),
        additional_events in arb_events(20)
    ) {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store1 = CheckpointStore::in_memory().unwrap();
        let checkpoint_store2 = CheckpointStore::in_memory().unwrap();

        // Add initial events
        ledger.append_batch(&initial_events).unwrap();

        // Run incrementally with checkpoints
        let runner1 = ReducerRunner::new(&ledger, &checkpoint_store1);
        let mut reducer_incremental = MetricsReducer::default();
        runner1.run(&mut reducer_incremental).unwrap();

        // Add more events
        ledger.append_batch(&additional_events).unwrap();

        // Continue incrementally
        runner1.run(&mut reducer_incremental).unwrap();

        // Run from genesis over all events
        let runner2 = ReducerRunner::new(&ledger, &checkpoint_store2);
        let mut reducer_genesis = MetricsReducer::default();
        runner2.run_from_genesis(&mut reducer_genesis).unwrap();

        // States must be identical
        prop_assert_eq!(reducer_incremental.state(), reducer_genesis.state());
    }

    /// Property: Metrics reducer is deterministic.
    #[test]
    fn prop_metrics_reducer_deterministic(events in arb_events(75)) {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        ledger.append_batch(&events).unwrap();

        let runner = ReducerRunner::new(&ledger, &checkpoint_store);

        // Multiple runs
        let mut reducer1 = MetricsReducer::default();
        let mut reducer2 = MetricsReducer::default();

        runner.run_from_genesis(&mut reducer1).unwrap();
        runner.run_from_genesis(&mut reducer2).unwrap();

        prop_assert_eq!(reducer1.state(), reducer2.state());
    }

    /// Property: Checkpoint serialization is lossless.
    ///
    /// Serializing and deserializing state must produce identical state.
    #[test]
    fn prop_checkpoint_serialization_lossless(events in arb_events(50)) {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        ledger.append_batch(&events).unwrap();

        let runner = ReducerRunner::new(&ledger, &checkpoint_store);
        let mut reducer = SessionCountReducer::default();
        runner.run(&mut reducer).unwrap();

        // Get state before serialization
        let state_before = reducer.state().clone();

        // Serialize and deserialize using fully-qualified syntax
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
fn test_checkpoint_store_persistence_simulation() {
    let checkpoint_store = CheckpointStore::in_memory().unwrap();

    // Save checkpoints
    checkpoint_store
        .save(&Checkpoint::new("reducer-a", 100, vec![1, 2, 3]))
        .unwrap();
    checkpoint_store
        .save(&Checkpoint::new("reducer-a", 200, vec![4, 5, 6]))
        .unwrap();

    // Verify latest
    let latest = checkpoint_store.load_latest("reducer-a").unwrap();
    assert_eq!(latest.seq_id, 200);

    // Verify at specific seq
    let at_100 = checkpoint_store.load_at("reducer-a", 100).unwrap();
    assert_eq!(at_100.state_data, vec![1, 2, 3]);
}

#[test]
fn test_multiple_reducers_independent() {
    let ledger = Ledger::in_memory().unwrap();
    let checkpoint_store = CheckpointStore::in_memory().unwrap();

    // Add events
    let events = (0..20)
        .map(|i| {
            let event_type = if i % 2 == 0 {
                "session.start"
            } else {
                "session.end"
            };
            EventRecord::new(event_type, format!("session-{}", i / 2), vec![])
        })
        .collect::<Vec<_>>();
    ledger.append_batch(&events).unwrap();

    let runner = ReducerRunner::new(&ledger, &checkpoint_store);

    // Run session counter
    let mut session_counter = SessionCountReducer::default();
    runner.run(&mut session_counter).unwrap();

    // Run metrics
    let mut metrics = MetricsReducer::default();
    runner.run(&mut metrics).unwrap();

    // Verify independent state
    assert_eq!(session_counter.state().total_started, 10);
    assert_eq!(session_counter.state().total_ended, 10);
    assert_eq!(metrics.state().event_count, 20);

    // Each reducer should have its own checkpoint
    assert!(checkpoint_store.exists("session-count").unwrap());
    assert!(checkpoint_store.exists("metrics").unwrap());
}

#[test]
fn test_determinism_after_crash_recovery_simulation() {
    let ledger = Ledger::in_memory().unwrap();
    let checkpoint_store = CheckpointStore::in_memory().unwrap();

    // Add initial events
    let events1: Vec<EventRecord> = (0u8..50)
        .map(|i| EventRecord::new(format!("event.{}", i % 5), "session-1", vec![i]))
        .collect();
    ledger.append_batch(&events1).unwrap();

    // First "run" - process and checkpoint
    let config = ReducerRunnerConfig {
        checkpoint_interval: 10,
        batch_size: 5,
    };
    let runner = ReducerRunner::with_config(&ledger, &checkpoint_store, config);

    let mut reducer1 = MetricsReducer::default();
    let result1 = runner.run(&mut reducer1).unwrap();
    let state_after_first_run = reducer1.state().clone();

    assert!(result1.events_processed == 50);

    // Simulate crash by creating a new reducer instance
    // Add more events
    let events2: Vec<EventRecord> = (50u8..75)
        .map(|i| EventRecord::new(format!("event.{}", i % 5), "session-1", vec![i]))
        .collect();
    ledger.append_batch(&events2).unwrap();

    // "Recovery" - new reducer instance, should resume from checkpoint
    let mut reducer2 = MetricsReducer::default();
    let result2 = runner.run(&mut reducer2).unwrap();

    // Should only have processed the new events
    assert!(result2.resumed_from_checkpoint);
    assert_eq!(result2.events_processed, 25);

    // Verify final state by running from genesis
    let mut reducer_verify = MetricsReducer::default();
    runner.run_from_genesis(&mut reducer_verify).unwrap();

    assert_eq!(reducer2.state(), reducer_verify.state());

    // Also verify intermediate state was preserved correctly
    // by checking the state matches incremental progression
    assert_eq!(reducer2.state().event_count, 75);
    assert!(reducer2.state().event_count > state_after_first_run.event_count);
}

#[test]
fn test_checkpoint_pruning() {
    let checkpoint_store = CheckpointStore::in_memory().unwrap();

    // Create many checkpoints
    for i in 1u8..=10 {
        checkpoint_store
            .save(&Checkpoint::new("prune-test", u64::from(i) * 10, vec![i]))
            .unwrap();
    }

    // Verify all exist
    let all = checkpoint_store.list("prune-test").unwrap();
    assert_eq!(all.len(), 10);

    // Prune old ones (keep seq_id >= 50)
    let deleted = checkpoint_store.prune("prune-test", 50).unwrap();
    assert_eq!(deleted, 4); // 10, 20, 30, 40 deleted

    // Verify remaining
    let remaining = checkpoint_store.list("prune-test").unwrap();
    assert_eq!(remaining.len(), 6);
    assert!(remaining.iter().all(|c| c.seq_id >= 50));
}

#[test]
fn test_session_count_invariants() {
    let ledger = Ledger::in_memory().unwrap();
    let checkpoint_store = CheckpointStore::in_memory().unwrap();

    // Create a specific sequence: 5 starts, 3 ends
    let events = vec![
        EventRecord::new("session.start", "s1", vec![]),
        EventRecord::new("session.start", "s2", vec![]),
        EventRecord::new("session.end", "s1", vec![]),
        EventRecord::new("session.start", "s3", vec![]),
        EventRecord::new("session.end", "s2", vec![]),
        EventRecord::new("session.start", "s4", vec![]),
        EventRecord::new("session.start", "s5", vec![]),
        EventRecord::new("session.end", "s3", vec![]),
    ];
    ledger.append_batch(&events).unwrap();

    let runner = ReducerRunner::new(&ledger, &checkpoint_store);
    let mut reducer = SessionCountReducer::default();
    runner.run(&mut reducer).unwrap();

    // Verify invariants
    assert_eq!(reducer.state().total_started, 5);
    assert_eq!(reducer.state().total_ended, 3);
    assert_eq!(reducer.state().active_sessions, 2); // 5 - 3
}

#[test]
fn test_empty_ledger_handling() {
    let ledger = Ledger::in_memory().unwrap();
    let checkpoint_store = CheckpointStore::in_memory().unwrap();

    let runner = ReducerRunner::new(&ledger, &checkpoint_store);
    let mut reducer = SessionCountReducer::default();

    let result = runner.run(&mut reducer).unwrap();

    assert_eq!(result.events_processed, 0);
    assert!(!result.checkpoint_created);
    assert!(!result.resumed_from_checkpoint);
    assert_eq!(reducer.state().active_sessions, 0);
}

#[test]
fn test_large_batch_processing() {
    let ledger = Ledger::in_memory().unwrap();
    let checkpoint_store = CheckpointStore::in_memory().unwrap();

    // Create 1000 events using u16 range to avoid overflow
    let events: Vec<EventRecord> = (0u16..1000)
        .map(|i| {
            let event_type = match i % 4 {
                0 => "session.start",
                1 => "session.update",
                2 => "tool.request",
                _ => "session.end",
            };
            EventRecord::new(
                event_type,
                format!("session-{}", i % 10),
                vec![(i % 256) as u8],
            )
        })
        .collect();
    ledger.append_batch(&events).unwrap();

    let config = ReducerRunnerConfig {
        checkpoint_interval: 100,
        batch_size: 50,
    };
    let runner = ReducerRunner::with_config(&ledger, &checkpoint_store, config);

    let mut reducer = MetricsReducer::default();
    let result = runner.run(&mut reducer).unwrap();

    assert_eq!(result.events_processed, 1000);
    assert!(result.checkpoint_created);
    assert_eq!(reducer.state().event_count, 1000);

    // Multiple checkpoints should exist
    let checkpoints = checkpoint_store.list("metrics").unwrap();
    assert!(!checkpoints.is_empty());
}
