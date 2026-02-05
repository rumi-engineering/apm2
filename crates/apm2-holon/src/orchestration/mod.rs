//! Orchestration state machine for FAC revision loops.
//!
//! This module implements the orchestration layer for Forge Admission Cycle
//! (FAC) revision loops as specified in RFC-0019 and TCK-00332. The
//! orchestrator drives implementer + reviewer episodes iteratively until a
//! terminal condition is reached.
//!
//! # Design
//!
//! The orchestration follows a crash-only recovery model: all state is derived
//! from ledger events, enabling deterministic restart from any checkpoint
//! without duplicating projections.
//!
//! ## Terminal Conditions
//!
//! The orchestrator terminates under these conditions:
//! - **Pass**: All reviews pass without blocking findings
//! - **Blocked**: A reviewer signals the work cannot proceed
//! - **BudgetExhausted**: Resource limits exceeded (iterations, tokens, time)
//! - **OperatorStop**: External signal requests termination
//!
//! ## Ledger Events
//!
//! The orchestrator emits three event types:
//! - [`OrchestrationStarted`]: Emitted when orchestration begins for a work_id
//! - [`IterationCompleted`]: Emitted after each revision cycle completes
//! - [`OrchestrationTerminated`]: Emitted when orchestration terminates
//!
//! ## Crash Recovery
//!
//! On restart, the orchestrator:
//! 1. Scans ledger for the most recent `OrchestrationStarted` for the work_id
//! 2. Counts `IterationCompleted` events to determine current iteration
//! 3. Checks for `OrchestrationTerminated` to detect already-completed work
//! 4. Resumes from the reconstructed state
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::orchestration::{
//!     OrchestrationConfig, OrchestrationDriver, OrchestrationStateV1,
//!     TerminationReason,
//! };
//!
//! // Create orchestration state
//! let state = OrchestrationStateV1::new(
//!     "work-123", "orch-001", 100,       // max_iterations
//!     1_000_000, // token_budget
//!     3_600_000, // time_budget_ms (1 hour)
//! );
//!
//! assert_eq!(state.iteration_count(), 0);
//! assert!(!state.is_terminated());
//! ```

mod events;
mod state;

pub use events::{
    IterationCompleted, IterationOutcome, OrchestrationEvent, OrchestrationStarted,
    OrchestrationTerminated,
};
pub use state::{
    BlockedReasonCode, OrchestrationConfig, OrchestrationDriver, OrchestrationStateV1,
    TerminationReason,
};
