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

pub mod events;
pub mod state;

// Re-export main types from state module
// Re-export event types
pub use events::{
    CoordinationAborted, CoordinationCompleted, CoordinationEvent, CoordinationSessionBound,
    CoordinationSessionUnbound, CoordinationStarted, EVENT_TYPE_ABORTED, EVENT_TYPE_COMPLETED,
    EVENT_TYPE_SESSION_BOUND, EVENT_TYPE_SESSION_UNBOUND, EVENT_TYPE_STARTED,
};
pub use state::{
    AbortReason, BindingInfo, BudgetType, BudgetUsage, CoordinationBudget, CoordinationSession,
    CoordinationState, CoordinationStatus, SessionOutcome, StopCondition, WorkItemOutcome,
    WorkItemTracking,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// TCK-00148: Verify all types are Send + Sync for async runtime.
    #[test]
    fn tck_00148_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        // State types
        assert_send_sync::<CoordinationBudget>();
        assert_send_sync::<BudgetUsage>();
        assert_send_sync::<BudgetType>();
        assert_send_sync::<StopCondition>();
        assert_send_sync::<AbortReason>();
        assert_send_sync::<CoordinationStatus>();
        assert_send_sync::<SessionOutcome>();
        assert_send_sync::<BindingInfo>();
        assert_send_sync::<WorkItemTracking>();
        assert_send_sync::<WorkItemOutcome>();
        assert_send_sync::<CoordinationSession>();
        assert_send_sync::<CoordinationState>();

        // Event types
        assert_send_sync::<CoordinationStarted>();
        assert_send_sync::<CoordinationSessionBound>();
        assert_send_sync::<CoordinationSessionUnbound>();
        assert_send_sync::<CoordinationCompleted>();
        assert_send_sync::<CoordinationAborted>();
        assert_send_sync::<CoordinationEvent>();
    }

    /// TCK-00148: Verify all types derive required traits.
    #[test]
    fn tck_00148_types_derive_required_traits() {
        // Test Debug (via format!)
        let budget = CoordinationBudget::new(10, 60_000, None);
        let _ = format!("{budget:?}");

        let usage = BudgetUsage::new();
        let _ = format!("{usage:?}");

        let stop = StopCondition::WorkCompleted;
        let _ = format!("{stop:?}");

        let status = CoordinationStatus::Running;
        let _ = format!("{status:?}");

        let binding = BindingInfo::new("s".to_string(), "w".to_string(), 1, 1000);
        let _ = format!("{binding:?}");

        let session =
            CoordinationSession::new("c".to_string(), vec!["w".to_string()], budget, 3, 1000);
        let _ = format!("{session:?}");

        let state = CoordinationState::new();
        let _ = format!("{state:?}");

        // Test Clone (via clone() and then use it)
        let budget2 = CoordinationBudget::new(10, 60_000, None);
        let budget_clone = budget2.clone();
        assert_eq!(budget2, budget_clone);

        let usage2 = BudgetUsage::new();
        let usage_clone = usage2.clone();
        assert_eq!(usage2, usage_clone);

        let stop2 = StopCondition::WorkCompleted;
        let stop_clone = stop2.clone();
        assert_eq!(stop2, stop_clone);

        let status2 = CoordinationStatus::Running;
        let status_clone = status2.clone();
        assert_eq!(status2, status_clone);

        let binding2 = BindingInfo::new("s".to_string(), "w".to_string(), 1, 1000);
        let binding_clone = binding2.clone();
        assert_eq!(binding2, binding_clone);

        let session2 = CoordinationSession::new(
            "c".to_string(),
            vec!["w".to_string()],
            CoordinationBudget::new(10, 60_000, None),
            3,
            1000,
        );
        let session_clone = session2.clone();
        assert_eq!(session2, session_clone);

        let state2 = CoordinationState::new();
        let state_clone = state2.clone();
        assert_eq!(state2, state_clone);

        // Test Serialize/Deserialize (via serde_json)
        let json = serde_json::to_string(&budget_clone).unwrap();
        let _: CoordinationBudget = serde_json::from_str(&json).unwrap();

        let json = serde_json::to_string(&usage_clone).unwrap();
        let _: BudgetUsage = serde_json::from_str(&json).unwrap();

        let json = serde_json::to_string(&stop_clone).unwrap();
        let _: StopCondition = serde_json::from_str(&json).unwrap();

        let json = serde_json::to_string(&status_clone).unwrap();
        let _: CoordinationStatus = serde_json::from_str(&json).unwrap();

        let json = serde_json::to_string(&binding_clone).unwrap();
        let _: BindingInfo = serde_json::from_str(&json).unwrap();

        let json = serde_json::to_string(&session_clone).unwrap();
        let _: CoordinationSession = serde_json::from_str(&json).unwrap();

        let json = serde_json::to_string(&state_clone).unwrap();
        let _: CoordinationState = serde_json::from_str(&json).unwrap();
    }

    /// TCK-00148: Comprehensive JSON round-trip test for all types.
    #[test]
    fn tck_00148_json_roundtrip_comprehensive() {
        // Build a complete CoordinationState with all nested types
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000));
        let mut session = CoordinationSession::new(
            "coord-123".to_string(),
            vec!["work-1".to_string(), "work-2".to_string()],
            budget,
            3,
            1_000_000_000,
        );
        session.status = CoordinationStatus::Running;
        session.budget_usage = BudgetUsage {
            consumed_episodes: 2,
            elapsed_ms: 15_000,
            consumed_tokens: 25_000,
        };
        session.consecutive_failures = 1;

        let mut state = CoordinationState::new();
        state.coordinations.insert("coord-123".to_string(), session);

        let binding = BindingInfo::new(
            "session-456".to_string(),
            "work-1".to_string(),
            1,
            2_000_000_000,
        );
        state.bindings.insert("session-456".to_string(), binding);

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&state).unwrap();

        // Deserialize back
        let restored: CoordinationState = serde_json::from_str(&json).unwrap();

        // Verify equality
        assert_eq!(state, restored);

        // Verify nested values
        let coord = restored.get("coord-123").unwrap();
        assert_eq!(coord.work_queue.len(), 2);
        assert_eq!(coord.budget_usage.consumed_episodes, 2);
        assert!(matches!(coord.status, CoordinationStatus::Running));

        let binding = restored.get_binding("session-456").unwrap();
        assert_eq!(binding.work_id, "work-1");
        assert_eq!(binding.attempt_number, 1);
    }
}
