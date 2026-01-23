//! Reducer framework for event processing and state projection.
//!
//! This module provides a framework for building reducers that process events
//! from the ledger and maintain derived state (projections). Reducers support
//! checkpointing for efficient incremental processing.
//!
//! # Architecture
//!
//! ```text
//! Events (Ledger) --> Reducer --> Projection State
//!                        |
//!                   Checkpoint
//! ```
//!
//! # Key Concepts
//!
//! - **Reducer**: A trait that transforms events into state changes
//! - **Projection**: The derived state maintained by a reducer
//! - **Checkpoint**: A saved point in time allowing incremental replay
//!
//! # Determinism
//!
//! Reducers must be deterministic: given the same sequence of events,
//! they must produce the same projection state. This is verified by
//! property tests that compare replay-from-genesis with replay-from-checkpoint.
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::reducer::{Reducer, ReducerContext};
//! use apm2_core::ledger::EventRecord;
//!
//! struct SessionCountReducer {
//!     active_sessions: u64,
//! }
//!
//! impl Reducer for SessionCountReducer {
//!     type State = u64;
//!     type Error = std::convert::Infallible;
//!
//!     fn apply(&mut self, event: &EventRecord, ctx: &ReducerContext) -> Result<(), Self::Error> {
//!         match event.event_type.as_str() {
//!             "session.start" => self.active_sessions += 1,
//!             "session.end" => self.active_sessions = self.active_sessions.saturating_sub(1),
//!             _ => {}
//!         }
//!         Ok(())
//!     }
//!
//!     fn state(&self) -> &Self::State {
//!         &self.active_sessions
//!     }
//! }
//! ```

mod checkpoint;
mod runner;
mod traits;

#[cfg(test)]
mod tests;

pub use checkpoint::{Checkpoint, CheckpointStore, CheckpointStoreError};
pub use runner::{
    ReducerRunResult, ReducerRunner, ReducerRunnerConfig, ReducerRunnerError, apply_event,
};
pub use traits::{Reducer, ReducerContext};
