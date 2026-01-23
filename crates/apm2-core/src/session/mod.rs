//! Session lifecycle state machine.
//!
//! This module implements the session lifecycle state machine for the APM2
//! kernel. Sessions progress through states based on events, enabling
//! deterministic session management with state transitions, event emission, and
//! checkpoint support.
//!
//! # State Machine
//!
//! ```text
//!                     SessionStarted
//!         ┌───────────────────────────────────────┐
//!         │                                       ▼
//!     ┌───────┐                              ┌─────────┐
//!     │(none) │                              │ Running │◄──────────┐
//!     └───────┘                              └────┬────┘           │
//!                                                 │           SessionProgress
//!                 ┌───────────────────────────────┼───────────────────────────┐
//!                 │                               │                           │
//!     SessionTerminated                  SessionQuarantined          (loop back)
//!                 │                               │
//!                 ▼                               ▼
//!         ┌────────────┐                 ┌─────────────┐
//!         │ Terminated │                 │ Quarantined │
//!         └────────────┘                 └─────────────┘
//! ```
//!
//! # Valid Transitions
//!
//! | From | Event | To |
//! |------|-------|----|
//! | (none) | `SessionStarted` | Running |
//! | Running | `SessionProgress` | Running (counters updated) |
//! | Running | `SessionTerminated` | Terminated |
//! | Running | `SessionQuarantined` | Quarantined |
//!
//! Invalid transitions return `SessionError::InvalidTransition`.
//!
//! # Entropy Budget
//!
//! Sessions operate under an entropy budget that tracks accumulated "chaos"
//! (errors, stalls, violations). When the budget is exceeded, the session
//! must be terminated with exit classification `EntropyExceeded`.
//!
//! See the [`entropy`] module for the `EntropyTracker` and configuration.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::ledger::EventRecord;
//! use apm2_core::reducer::{Reducer, ReducerContext};
//! use apm2_core::session::{
//!     ExitClassification, SessionReducer, SessionState, helpers,
//! };
//!
//! // Create a reducer
//! let mut reducer = SessionReducer::new();
//! let ctx = ReducerContext::new(1);
//!
//! // Start a session
//! let payload = helpers::session_started_payload(
//!     "session-123",
//!     "actor-456",
//!     "claude-code",
//!     "work-789",
//!     "lease-012",
//!     1000,
//! );
//! let event = EventRecord::with_timestamp(
//!     "session.started",
//!     "session-123",
//!     "actor-456",
//!     payload,
//!     1_000_000_000,
//! );
//! reducer.apply(&event, &ctx).unwrap();
//!
//! // Check state
//! assert!(reducer.state().get("session-123").unwrap().is_active());
//! ```

pub mod entropy;
pub mod error;
pub mod reducer;
pub mod state;

#[cfg(test)]
mod tests;

// Re-export main types
pub use entropy::{
    EntropyBudgetConfig, EntropyEvent, EntropySource, EntropyTracker, EntropyTrackerSummary,
};
pub use error::{SessionError, StateName};
pub use reducer::{SessionReducer, SessionReducerState, helpers};
pub use state::{ExitClassification, SessionState};
