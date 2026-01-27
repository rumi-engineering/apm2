//! Agent Coordination Layer for Autonomous Work Loop Execution.
//!
//! This module implements the coordination layer for the APM2 kernel,
//! enabling autonomous processing of work queues with budget enforcement
//! and circuit breaker protection.
//!
//! # Architecture
//!
//! The coordination layer is a peer reducer to the session and work modules.
//! Per AD-COORD-002: Coordination observes events from Work/Session/Lease
//! reducers but does NOT directly modify their state.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Coordination Layer                       │
//! │                                                             │
//! │  CoordinationController                                     │
//! │    │                                                        │
//! │    ├── Emits: coordination.started                          │
//! │    ├── Emits: coordination.session_bound                    │
//! │    ├── Orchestrates: session spawn                          │
//! │    ├── Observes: session.terminated                         │
//! │    ├── Emits: coordination.session_unbound                  │
//! │    └── Emits: coordination.completed / aborted              │
//! │                                                             │
//! │  CoordinationReducer                                        │
//! │    └── Projects: CoordinationState                          │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//!           │                   │
//!           │ observes          │ emits
//!           ▼                   ▼
//!     ┌───────────┐      ┌───────────┐
//!     │  Session  │      │  Ledger   │
//!     │  Reducer  │      │           │
//!     └───────────┘      └───────────┘
//! ```
//!
//! # Key Concepts
//!
//! - **Coordination**: A work queue processing session with budget constraints
//! - **Binding**: Association between a session and a work item
//! - **Budget**: Episode, duration, and token limits
//! - **Circuit Breaker**: Aborts on 3 consecutive failures (AD-COORD-005)
//! - **Stop Condition**: Why a coordination stopped (priority ordered per
//!   AD-COORD-013)
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::coordination::{
//!     CoordinationBudget, CoordinationSession, CoordinationState,
//! };
//!
//! // Create a budget with limits
//! let budget = CoordinationBudget::new(
//!     10,         // max 10 episodes
//!     300_000,    // max 5 minutes
//!     Some(100_000), // max 100k tokens
//! );
//!
//! // Create a coordination session
//! let session = CoordinationSession::new(
//!     "coord-123".to_string(),
//!     vec!["work-1".to_string(), "work-2".to_string()],
//!     budget,
//!     3, // max attempts per work
//!     1_000_000_000, // started_at
//! );
//! ```
//!
//! # References
//!
//! - RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution
//! - AD-COORD-001: New coordination module in apm2-core
//! - AD-COORD-002: Coordination does NOT modify other reducer states
//! - AD-COORD-003: Binding events bracket session lifecycle
//! - AD-COORD-004: Mandatory budget parameters
//! - AD-COORD-005: Circuit breaker threshold of 3 consecutive failures
//! - AD-COORD-009: Coordination event serialization via JSON

pub mod controller;
pub mod error;
pub mod events;
pub mod evidence;
pub mod reducer;
pub mod state;

#[cfg(test)]
mod tests;

// Re-export controller types
pub use controller::{
    CIRCUIT_BREAKER_THRESHOLD, CoordinationConfig, CoordinationController,
    DEFAULT_MAX_ATTEMPTS_PER_WORK, FreshnessCheck, SpawnResult, TerminationResult, WorkItemState,
};
// Re-export error types
pub use error::{ControllerError, ControllerResult};
// Re-export event types
pub use events::{
    BLAKE3_HASH_SIZE, CoordinationAborted, CoordinationCompleted, CoordinationEvent,
    CoordinationSessionBound, CoordinationSessionUnbound, CoordinationStarted, EVENT_TYPE_ABORTED,
    EVENT_TYPE_COMPLETED, EVENT_TYPE_SESSION_BOUND, EVENT_TYPE_SESSION_UNBOUND, EVENT_TYPE_STARTED,
};
// Re-export evidence types (TCK-00154)
pub use evidence::{
    CoordinationReceipt, MAX_SESSION_IDS_PER_OUTCOME, MAX_WORK_OUTCOMES, ReceiptBuilder,
    ReceiptError, WorkOutcome,
};
// Re-export reducer types
pub use reducer::{CoordinationReducer, CoordinationReducerError};
// Re-export state types
pub use state::{
    AbortReason, BindingInfo, BudgetType, BudgetUsage, CoordinationBudget, CoordinationError,
    CoordinationSession, CoordinationState, CoordinationStatus, MAX_HASHMAP_SIZE,
    MAX_WORK_QUEUE_SIZE, SessionOutcome, StopCondition, WorkItemOutcome, WorkItemTracking,
};
