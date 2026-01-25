//! Ledger event types for episode lifecycle tracking.
//!
//! This module provides event types that are emitted during episode execution
//! and can be recorded to a ledger for auditing, replay, and debugging.
//!
//! # Overview
//!
//! The ledger captures the complete history of episode execution through
//! events:
//! - [`EpisodeStarted`]: Captures the initial context when an episode begins
//! - [`EpisodeCompleted`]: Captures the outcome and resource consumption
//!
//! These events enable:
//! - **Auditing**: Track all execution for compliance and debugging
//! - **Replay**: Reconstruct execution history from events
//! - **Metrics**: Calculate resource consumption and success rates
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::ledger::{
//!     EpisodeCompleted, EpisodeCompletionReason, EpisodeEvent, EpisodeStarted,
//! };
//!
//! // Record episode start - use try_new for validated construction
//! let started = EpisodeStarted::try_new(
//!     "ep-001",
//!     "work-123",
//!     "lease-456",
//!     1,
//!     1_000_000_000,
//! )
//! .expect("valid IDs");
//!
//! // Simulate execution...
//!
//! // Record episode completion
//! let completed = EpisodeCompleted::new(
//!     "ep-001",
//!     EpisodeCompletionReason::GoalSatisfied,
//!     1_500_000_000,
//! );
//!
//! // Wrap events for storage
//! let events: Vec<EpisodeEvent> = vec![started.into(), completed.into()];
//! assert_eq!(events.len(), 2);
//! ```

mod chain;
mod events;

pub use chain::{
    ChainError, EpisodeOutcome, EventHash, EventHashError, EventType, LedgerEvent,
    LedgerEventBuilder, LedgerValidationError, current_timestamp_ns, verify_chain,
};
pub use events::{
    EpisodeCompleted, EpisodeCompletionReason, EpisodeEvent, EpisodeStarted, MAX_GOAL_SPEC_LENGTH,
    MAX_ID_LENGTH, validate_goal_spec, validate_id,
};
