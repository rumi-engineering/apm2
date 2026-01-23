//! Reducer trait definitions.

use std::fmt::Debug;

use crate::ledger::EventRecord;

/// Context provided to reducers during event processing.
#[derive(Debug, Clone)]
pub struct ReducerContext {
    /// Current sequence position in the ledger.
    pub seq_id: u64,

    /// Whether this is a replay from checkpoint (vs genesis).
    pub is_replay: bool,

    /// The checkpoint sequence ID we're replaying from (if any).
    pub checkpoint_seq_id: Option<u64>,
}

impl ReducerContext {
    /// Creates a new context for normal (non-replay) processing.
    #[must_use]
    pub const fn new(seq_id: u64) -> Self {
        Self {
            seq_id,
            is_replay: false,
            checkpoint_seq_id: None,
        }
    }

    /// Creates a new context for replay from checkpoint.
    #[must_use]
    pub const fn replay(seq_id: u64, checkpoint_seq_id: u64) -> Self {
        Self {
            seq_id,
            is_replay: true,
            checkpoint_seq_id: Some(checkpoint_seq_id),
        }
    }
}

/// A reducer that processes events and maintains derived state.
///
/// Reducers must be deterministic: applying the same sequence of events
/// must always produce the same state. This property is critical for
/// checkpoint correctness.
///
/// # Type Parameters
///
/// - `State`: The projection state type. Must be serializable for
///   checkpointing.
/// - `Error`: The error type for apply operations.
pub trait Reducer: Send + Sync {
    /// The projection state type.
    type State: Debug + Clone + Send + Sync;

    /// Error type for apply operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns the unique name of this reducer.
    ///
    /// This name is used as the key for checkpoint storage.
    fn name(&self) -> &'static str;

    /// Applies an event to update the projection state.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to process
    /// * `ctx` - Context about the current processing position
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be processed.
    fn apply(&mut self, event: &EventRecord, ctx: &ReducerContext) -> Result<(), Self::Error>;

    /// Returns a reference to the current projection state.
    fn state(&self) -> &Self::State;

    /// Returns a mutable reference to the current projection state.
    ///
    /// Used for checkpoint restoration.
    fn state_mut(&mut self) -> &mut Self::State;

    /// Resets the reducer to its initial state.
    ///
    /// Called when replaying from genesis.
    fn reset(&mut self);
}

/// Extension trait for reducers with serializable state.
///
/// Reducers implementing this trait can be checkpointed.
pub trait CheckpointableReducer: Reducer
where
    Self::State: serde::Serialize + serde::de::DeserializeOwned,
{
    /// Serializes the current state for checkpointing.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn serialize_state(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self.state())
    }

    /// Deserializes state from a checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    fn deserialize_state(&mut self, data: &[u8]) -> Result<(), serde_json::Error> {
        let state: Self::State = serde_json::from_slice(data)?;
        *self.state_mut() = state;
        Ok(())
    }
}

// Blanket implementation for all reducers with serializable state
impl<R> CheckpointableReducer for R
where
    R: Reducer,
    R::State: serde::Serialize + serde::de::DeserializeOwned,
{
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    /// A simple test reducer that counts events.
    #[derive(Debug, Default)]
    struct CountingReducer {
        count: u64,
    }

    impl Reducer for CountingReducer {
        type State = u64;
        type Error = std::convert::Infallible;

        fn name(&self) -> &'static str {
            "counting"
        }

        fn apply(
            &mut self,
            _event: &EventRecord,
            _ctx: &ReducerContext,
        ) -> Result<(), Self::Error> {
            self.count += 1;
            Ok(())
        }

        fn state(&self) -> &Self::State {
            &self.count
        }

        fn state_mut(&mut self) -> &mut Self::State {
            &mut self.count
        }

        fn reset(&mut self) {
            self.count = 0;
        }
    }

    #[test]
    fn test_reducer_context_new() {
        let ctx = ReducerContext::new(42);
        assert_eq!(ctx.seq_id, 42);
        assert!(!ctx.is_replay);
        assert!(ctx.checkpoint_seq_id.is_none());
    }

    #[test]
    fn test_reducer_context_replay() {
        let ctx = ReducerContext::replay(100, 50);
        assert_eq!(ctx.seq_id, 100);
        assert!(ctx.is_replay);
        assert_eq!(ctx.checkpoint_seq_id, Some(50));
    }

    #[test]
    fn test_counting_reducer() {
        let mut reducer = CountingReducer::default();
        let event = EventRecord::new("test", "session-1", vec![]);
        let ctx = ReducerContext::new(1);

        assert_eq!(*reducer.state(), 0);

        reducer.apply(&event, &ctx).unwrap();
        assert_eq!(*reducer.state(), 1);

        reducer.apply(&event, &ctx).unwrap();
        assert_eq!(*reducer.state(), 2);

        reducer.reset();
        assert_eq!(*reducer.state(), 0);
    }
}
