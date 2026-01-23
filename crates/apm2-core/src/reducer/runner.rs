//! Reducer runner for processing events from the ledger.
//!
//! The runner handles loading checkpoints, replaying events, and saving new
//! checkpoints at configurable intervals.

use thiserror::Error;

use super::checkpoint::{Checkpoint, CheckpointStore, CheckpointStoreError};
use super::traits::{CheckpointableReducer, ReducerContext};
use crate::ledger::{EventRecord, Ledger, LedgerError};

/// Errors that can occur during reducer processing.
#[derive(Debug, Error)]
pub enum ReducerRunnerError {
    /// Error from the ledger.
    #[error("ledger error: {0}")]
    Ledger(#[from] LedgerError),

    /// Error from checkpoint storage.
    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointStoreError),

    /// Error during state serialization.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Error during event processing.
    #[error("reducer error: {0}")]
    Reducer(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Configuration for the reducer runner.
#[derive(Debug, Clone)]
pub struct ReducerRunnerConfig {
    /// Number of events to process before saving a checkpoint.
    /// Set to 0 to disable automatic checkpointing.
    pub checkpoint_interval: u64,

    /// Batch size for reading events from the ledger.
    pub batch_size: u64,
}

impl Default for ReducerRunnerConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: 1000,
            batch_size: 100,
        }
    }
}

/// Result of running a reducer to completion.
#[derive(Debug, Clone)]
pub struct ReducerRunResult {
    /// The sequence ID of the last processed event.
    pub last_seq_id: u64,

    /// Total number of events processed in this run.
    pub events_processed: u64,

    /// Whether a checkpoint was created.
    pub checkpoint_created: bool,

    /// Whether processing started from a checkpoint (vs genesis).
    pub resumed_from_checkpoint: bool,
}

/// Runs reducers over events from a ledger with checkpoint support.
pub struct ReducerRunner<'a> {
    ledger: &'a Ledger,
    checkpoint_store: &'a CheckpointStore,
    config: ReducerRunnerConfig,
}

impl<'a> ReducerRunner<'a> {
    /// Creates a new reducer runner.
    #[must_use]
    pub fn new(ledger: &'a Ledger, checkpoint_store: &'a CheckpointStore) -> Self {
        Self {
            ledger,
            checkpoint_store,
            config: ReducerRunnerConfig::default(),
        }
    }

    /// Creates a new reducer runner with custom configuration.
    #[must_use]
    pub const fn with_config(
        ledger: &'a Ledger,
        checkpoint_store: &'a CheckpointStore,
        config: ReducerRunnerConfig,
    ) -> Self {
        Self {
            ledger,
            checkpoint_store,
            config,
        }
    }

    /// Runs a reducer from the latest checkpoint (or genesis) to the current
    /// ledger head.
    ///
    /// This method:
    /// 1. Attempts to load the latest checkpoint for the reducer
    /// 2. If found, restores state and replays from checkpoint `seq_id` + 1
    /// 3. If not found, replays from genesis (`seq_id` = 1)
    /// 4. Saves checkpoints at configured intervals
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the ledger fails, checkpoint operations
    /// fail, or the reducer returns an error during event processing.
    pub fn run<R>(&self, reducer: &mut R) -> Result<ReducerRunResult, ReducerRunnerError>
    where
        R: CheckpointableReducer,
        R::State: serde::Serialize + serde::de::DeserializeOwned,
    {
        let (start_seq_id, resumed) = self.restore_from_checkpoint(reducer)?;
        self.process_from(reducer, start_seq_id, resumed)
    }

    /// Runs a reducer from genesis, ignoring any existing checkpoints.
    ///
    /// This is useful for verifying determinism or rebuilding projections.
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn run_from_genesis<R>(
        &self,
        reducer: &mut R,
    ) -> Result<ReducerRunResult, ReducerRunnerError>
    where
        R: CheckpointableReducer,
        R::State: serde::Serialize + serde::de::DeserializeOwned,
    {
        reducer.reset();
        self.process_from(reducer, 1, false)
    }

    /// Runs a reducer from a specific checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint is not found or processing fails.
    pub fn run_from_checkpoint<R>(
        &self,
        reducer: &mut R,
        checkpoint_seq_id: u64,
    ) -> Result<ReducerRunResult, ReducerRunnerError>
    where
        R: CheckpointableReducer,
        R::State: serde::Serialize + serde::de::DeserializeOwned,
    {
        let checkpoint = self
            .checkpoint_store
            .load_at(reducer.name(), checkpoint_seq_id)?;
        reducer.deserialize_state(&checkpoint.state_data)?;
        self.process_from(reducer, checkpoint_seq_id + 1, true)
    }

    /// Attempts to restore reducer state from the latest checkpoint.
    ///
    /// Returns the sequence ID to start processing from and whether a
    /// checkpoint was found.
    fn restore_from_checkpoint<R>(&self, reducer: &mut R) -> Result<(u64, bool), ReducerRunnerError>
    where
        R: CheckpointableReducer,
        R::State: serde::Serialize + serde::de::DeserializeOwned,
    {
        match self.checkpoint_store.load_latest(reducer.name()) {
            Ok(checkpoint) => {
                reducer.deserialize_state(&checkpoint.state_data)?;
                // Start from the event after the checkpoint
                Ok((checkpoint.seq_id + 1, true))
            },
            Err(CheckpointStoreError::NotFound { .. }) => {
                // No checkpoint, start from genesis
                reducer.reset();
                Ok((1, false))
            },
            Err(e) => Err(e.into()),
        }
    }

    /// Processes events from a starting sequence ID.
    fn process_from<R>(
        &self,
        reducer: &mut R,
        start_seq_id: u64,
        resumed_from_checkpoint: bool,
    ) -> Result<ReducerRunResult, ReducerRunnerError>
    where
        R: CheckpointableReducer,
        R::State: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut current_seq_id = start_seq_id;
        let mut events_processed: u64 = 0;
        let mut events_since_checkpoint: u64 = 0;
        let mut checkpoint_created = false;
        let checkpoint_seq_id = if resumed_from_checkpoint {
            Some(start_seq_id.saturating_sub(1))
        } else {
            None
        };

        loop {
            let events = self
                .ledger
                .read_from(current_seq_id, self.config.batch_size)?;

            if events.is_empty() {
                break;
            }

            for event in &events {
                let seq_id = event.seq_id.unwrap_or(current_seq_id);
                let ctx = if resumed_from_checkpoint {
                    ReducerContext::replay(seq_id, checkpoint_seq_id.unwrap_or(0))
                } else {
                    ReducerContext::new(seq_id)
                };

                reducer
                    .apply(event, &ctx)
                    .map_err(|e| ReducerRunnerError::Reducer(Box::new(e)))?;

                current_seq_id = seq_id + 1;
                events_processed += 1;
                events_since_checkpoint += 1;

                // Save checkpoint at intervals
                if self.config.checkpoint_interval > 0
                    && events_since_checkpoint >= self.config.checkpoint_interval
                {
                    self.save_checkpoint(reducer, seq_id)?;
                    events_since_checkpoint = 0;
                    checkpoint_created = true;
                }
            }
        }

        // Save final checkpoint if we processed any events
        if events_processed > 0 && events_since_checkpoint > 0 {
            let last_seq_id = current_seq_id.saturating_sub(1);
            self.save_checkpoint(reducer, last_seq_id)?;
            checkpoint_created = true;
        }

        Ok(ReducerRunResult {
            last_seq_id: current_seq_id.saturating_sub(1),
            events_processed,
            checkpoint_created,
            resumed_from_checkpoint,
        })
    }

    /// Saves a checkpoint for the reducer at the given sequence ID.
    fn save_checkpoint<R>(&self, reducer: &R, seq_id: u64) -> Result<(), ReducerRunnerError>
    where
        R: CheckpointableReducer,
        R::State: serde::Serialize + serde::de::DeserializeOwned,
    {
        let state_data = reducer.serialize_state()?;
        let checkpoint = Checkpoint::new(reducer.name(), seq_id, state_data);
        self.checkpoint_store.save(&checkpoint)?;
        Ok(())
    }
}

/// Processes a single event for a reducer without checkpointing.
///
/// This is useful for real-time event processing where checkpointing
/// is handled separately.
///
/// # Errors
///
/// Returns an error if the reducer fails to process the event.
pub fn apply_event<R>(
    reducer: &mut R,
    event: &EventRecord,
    seq_id: u64,
) -> Result<(), ReducerRunnerError>
where
    R: super::traits::Reducer,
{
    let ctx = ReducerContext::new(seq_id);
    reducer
        .apply(event, &ctx)
        .map_err(|e| ReducerRunnerError::Reducer(Box::new(e)))
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::ledger::EventRecord;
    use crate::reducer::traits::Reducer;

    /// A simple test reducer that counts events by type.
    #[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
    struct TestState {
        total: u64,
        start: u64,
        end: u64,
    }

    #[derive(Debug, Default)]
    struct TestReducer {
        state: TestState,
    }

    impl Reducer for TestReducer {
        type State = TestState;
        type Error = std::convert::Infallible;

        fn name(&self) -> &'static str {
            "test-reducer"
        }

        fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
            self.state.total += 1;
            match event.event_type.as_str() {
                "session.start" => self.state.start += 1,
                "session.end" => self.state.end += 1,
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
            self.state = TestState::default();
        }
    }

    fn create_test_events(count: usize) -> Vec<EventRecord> {
        (0..count)
            .map(|i| {
                let event_type = if i % 3 == 0 {
                    "session.start"
                } else if i % 3 == 1 {
                    "session.update"
                } else {
                    "session.end"
                };
                EventRecord::new(event_type, "session-1", vec![])
            })
            .collect()
    }

    #[test]
    fn test_runner_from_genesis() {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Add some events
        let events = create_test_events(10);
        ledger.append_batch(&events).unwrap();

        let mut reducer = TestReducer::default();
        let runner = ReducerRunner::new(&ledger, &checkpoint_store);

        let result = runner.run(&mut reducer).unwrap();

        assert_eq!(result.events_processed, 10);
        assert!(!result.resumed_from_checkpoint);
        assert_eq!(reducer.state().total, 10);
        assert_eq!(reducer.state().start, 4); // 0, 3, 6, 9
        assert_eq!(reducer.state().end, 3); // 2, 5, 8
    }

    #[test]
    fn test_runner_incremental_from_checkpoint() {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Add initial events
        let events = create_test_events(10);
        ledger.append_batch(&events).unwrap();

        let mut reducer = TestReducer::default();
        let runner = ReducerRunner::new(&ledger, &checkpoint_store);

        // First run
        let result1 = runner.run(&mut reducer).unwrap();
        assert_eq!(result1.events_processed, 10);
        assert!(!result1.resumed_from_checkpoint);

        // Add more events
        let more_events = create_test_events(5);
        ledger.append_batch(&more_events).unwrap();

        // Second run should resume from checkpoint
        let mut reducer2 = TestReducer::default();
        let result2 = runner.run(&mut reducer2).unwrap();

        assert_eq!(result2.events_processed, 5);
        assert!(result2.resumed_from_checkpoint);
        assert_eq!(reducer2.state().total, 15);
    }

    #[test]
    fn test_runner_explicit_from_genesis() {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Add events and run once to create checkpoint
        let events = create_test_events(10);
        ledger.append_batch(&events).unwrap();

        let mut reducer = TestReducer::default();
        let runner = ReducerRunner::new(&ledger, &checkpoint_store);
        runner.run(&mut reducer).unwrap();

        // Now run from genesis explicitly
        let mut reducer2 = TestReducer::default();
        let result = runner.run_from_genesis(&mut reducer2).unwrap();

        assert_eq!(result.events_processed, 10);
        assert!(!result.resumed_from_checkpoint);
        assert_eq!(reducer2.state().total, 10);
    }

    #[test]
    fn test_runner_checkpoint_interval() {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        // Add many events
        let events = create_test_events(25);
        ledger.append_batch(&events).unwrap();

        let config = ReducerRunnerConfig {
            checkpoint_interval: 10,
            batch_size: 5,
        };

        let mut reducer = TestReducer::default();
        let runner = ReducerRunner::with_config(&ledger, &checkpoint_store, config);

        let result = runner.run(&mut reducer).unwrap();

        assert_eq!(result.events_processed, 25);
        assert!(result.checkpoint_created);

        // Verify multiple checkpoints were created
        let checkpoints = checkpoint_store.list("test-reducer").unwrap();
        assert!(!checkpoints.is_empty());
    }

    #[test]
    fn test_runner_empty_ledger() {
        let ledger = Ledger::in_memory().unwrap();
        let checkpoint_store = CheckpointStore::in_memory().unwrap();

        let mut reducer = TestReducer::default();
        let runner = ReducerRunner::new(&ledger, &checkpoint_store);

        let result = runner.run(&mut reducer).unwrap();

        assert_eq!(result.events_processed, 0);
        assert!(!result.checkpoint_created);
        assert_eq!(reducer.state().total, 0);
    }

    #[test]
    fn test_apply_event_standalone() {
        let event = EventRecord::new("session.start", "session-1", vec![]);
        let mut reducer = TestReducer::default();

        apply_event(&mut reducer, &event, 1).unwrap();

        assert_eq!(reducer.state().total, 1);
        assert_eq!(reducer.state().start, 1);
    }
}
