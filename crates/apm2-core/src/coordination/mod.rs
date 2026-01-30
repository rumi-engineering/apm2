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
//! │    ├── Orchestrates: session spawn via SessionSpawner       │
//! │    ├── Observes: session.terminated                         │
//! │    ├── Emits: coordination.session_unbound                  │
//! │    └── Emits: coordination.completed / aborted              │
//! │                                                             │
//! │  CoordinationReducer                                        │
//! │    └── Projects: CoordinationState                          │
//! │                                                             │
//! │  SessionSpawner (trait)                                     │
//! │    └── Decouples session execution from coordination logic  │
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
//! - **`SessionSpawner`**: Trait for decoupled session execution (AD-COORD-014)
//!
//! # `SessionSpawner` Trait
//!
//! The [`SessionSpawner`] trait decouples the coordination controller from
//! specific session spawning implementations (local thread, daemon IPC, etc.).
//!
//! Per AD-COORD-014: This prevents coordination logic from depending on brittle
//! CLI/Daemon infrastructure, enables local testing, and supports future
//! multi-provider configurations.
//!
//! ```rust,ignore
//! use apm2_core::coordination::{SessionSpawner, SpawnError};
//!
//! struct MySpawner;
//!
//! impl SessionSpawner for MySpawner {
//!     fn spawn(
//!         &self,
//!         session_id: &str,
//!         work_id: &str,
//!     ) -> Result<(), SpawnError> {
//!         // Implementation-specific session spawning
//!         Ok(())
//!     }
//!
//!     fn observe_termination(
//!         &self,
//!         session_id: &str,
//!     ) -> Result<SessionTerminationInfo, SpawnError> {
//!         // Wait for and return session termination info
//!         todo!()
//!     }
//! }
//! ```
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
//! - AD-COORD-014: `SessionSpawner` trait for execution decoupling

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
    BLAKE3_HASH_SIZE, ContextRefinementRequest, CoordinationAborted, CoordinationCompleted,
    CoordinationEvent, CoordinationSessionBound, CoordinationSessionUnbound, CoordinationStarted,
    EVENT_TYPE_ABORTED, EVENT_TYPE_COMPLETED, EVENT_TYPE_CONTEXT_REFINEMENT,
    EVENT_TYPE_SESSION_BOUND, EVENT_TYPE_SESSION_UNBOUND, EVENT_TYPE_STARTED,
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

// ============================================================================
// SessionSpawner Trait (AD-COORD-014, CTR-COORD-005)
// ============================================================================

/// Information about a terminated session.
///
/// Returned by [`SessionSpawner::observe_termination`] to provide the
/// coordination controller with session outcome details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTerminationInfo {
    /// The session ID that terminated.
    pub session_id: String,

    /// The outcome of the session execution.
    pub outcome: SessionOutcome,

    /// Tokens consumed during the session (for budget tracking).
    pub tokens_consumed: u64,
}

impl SessionTerminationInfo {
    /// Creates a new termination info with the given parameters.
    #[must_use]
    pub const fn new(session_id: String, outcome: SessionOutcome, tokens_consumed: u64) -> Self {
        Self {
            session_id,
            outcome,
            tokens_consumed,
        }
    }

    /// Creates a successful termination info.
    #[must_use]
    pub fn success(session_id: impl Into<String>, tokens_consumed: u64) -> Self {
        Self::new(session_id.into(), SessionOutcome::Success, tokens_consumed)
    }

    /// Creates a failed termination info.
    #[must_use]
    pub fn failure(session_id: impl Into<String>, tokens_consumed: u64) -> Self {
        Self::new(session_id.into(), SessionOutcome::Failure, tokens_consumed)
    }
}

/// Error returned by [`SessionSpawner`] operations.
///
/// Per AD-COORD-006: If `SessionSpawner::spawn` returns an error, the
/// controller MUST immediately emit
/// `coordination.session_unbound(reason=SPAWN_FAILED)` and mark the work
/// outcome as failed/skipped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpawnError {
    /// Session spawn failed.
    #[error("session spawn failed: {reason}")]
    SpawnFailed {
        /// Description of the failure.
        reason: String,
    },

    /// Session observation timed out.
    #[error("session observation timed out for session {session_id}")]
    ObservationTimeout {
        /// The session ID that timed out.
        session_id: String,
    },

    /// Session not found (for observation).
    #[error("session not found: {session_id}")]
    SessionNotFound {
        /// The missing session ID.
        session_id: String,
    },

    /// Internal error.
    #[error("internal error: {message}")]
    Internal {
        /// Error description.
        message: String,
    },
}

/// Trait for decoupled session execution (AD-COORD-014, CTR-COORD-005).
///
/// This trait decouples the [`CoordinationController`] from specific session
/// spawning implementations (local thread, daemon IPC, etc.).
///
/// # Contract
///
/// Per CTR-COORD-005:
/// - `spawn` starts a new session with the given ID for the specified work item
/// - `observe_termination` blocks until the session terminates
///
/// # CAS-at-Commit Ordering (AD-COORD-006)
///
/// The coordination controller MUST commit the `session_bound` event to the
/// ledger BEFORE calling `spawn`. This ensures:
///
/// 1. The binding is authoritatively recorded before any side effects
/// 2. TOCTOU races are prevented via `expected_transition_count` validation
/// 3. Failed spawns can be properly tracked with `session_unbound` events
///
/// # Example
///
/// ```rust,ignore
/// use apm2_core::coordination::{SessionSpawner, SessionTerminationInfo, SpawnError};
///
/// struct LocalSpawner;
///
/// impl SessionSpawner for LocalSpawner {
///     fn spawn(&self, session_id: &str, work_id: &str) -> Result<(), SpawnError> {
///         // Start the session (implementation-specific)
///         Ok(())
///     }
///
///     fn observe_termination(
///         &self,
///         session_id: &str,
///     ) -> Result<SessionTerminationInfo, SpawnError> {
///         // Wait for session to complete and return outcome
///         Ok(SessionTerminationInfo::success(session_id.to_string(), 1000))
///     }
/// }
/// ```
pub trait SessionSpawner: Send + Sync {
    /// Spawns a new session with the given ID for the specified work item.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The pre-generated session ID (per AD-COORD-007)
    /// * `work_id` - The work item ID being processed
    ///
    /// # Returns
    ///
    /// `Ok(())` if the session was successfully started, or an error if spawn
    /// failed.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::SpawnFailed`] if the session could not be started.
    fn spawn(&self, session_id: &str, work_id: &str) -> Result<(), SpawnError>;

    /// Observes session termination and returns the outcome.
    ///
    /// This method blocks until the session terminates (success, failure, or
    /// timeout).
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to observe
    ///
    /// # Returns
    ///
    /// Information about the terminated session, including outcome and token
    /// consumption.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::ObservationTimeout`] if the session does not
    /// terminate within the expected time.
    /// Returns [`SpawnError::SessionNotFound`] if the session was not found.
    fn observe_termination(&self, session_id: &str) -> Result<SessionTerminationInfo, SpawnError>;
}
