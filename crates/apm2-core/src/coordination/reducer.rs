//! Coordination event reducer implementation.
//!
//! This module implements [`CoordinationReducer`] which processes coordination
//! events and maintains [`CoordinationState`]. The reducer follows the same
//! patterns established in [`crate::session::reducer`].
//!
//! # Determinism Requirements
//!
//! Per INV-0101: Given the same event sequence and initial state, `apply` MUST
//! produce identical final states. This is verified by property tests comparing
//! replay-from-genesis with replay-from-checkpoint.
//!
//! # Event Processing
//!
//! The reducer handles all coordination event types:
//! - `coordination.started` - Initialize a new coordination session
//! - `coordination.session_bound` - Record session-to-work binding
//! - `coordination.session_unbound` - Process session completion, update
//!   tracking
//! - `coordination.completed` - Mark coordination as completed
//! - `coordination.aborted` - Mark coordination as aborted
//!
//! # References
//!
//! - RFC-0012: Agent Coordination Layer for Autonomous Work Loop Execution
//! - AD-COORD-002: Coordination does NOT modify other reducer states
//! - AD-COORD-009: Coordination event serialization via JSON

use std::convert::Infallible;

use super::events::{
    CoordinationAborted, CoordinationCompleted, CoordinationSessionBound,
    CoordinationSessionUnbound, CoordinationStarted, EVENT_TYPE_ABORTED, EVENT_TYPE_COMPLETED,
    EVENT_TYPE_SESSION_BOUND, EVENT_TYPE_SESSION_UNBOUND, EVENT_TYPE_STARTED,
};
use super::state::{
    BindingInfo, CoordinationSession, CoordinationState, CoordinationStatus, SessionOutcome,
    WorkItemOutcome,
};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

/// Error type for coordination reducer operations.
///
/// The coordination reducer is designed to be infallible for well-formed
/// events. Malformed events are logged and skipped rather than causing errors,
/// following the principle that the ledger is the source of truth and reducers
/// should be resilient to corrupted or unexpected data.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CoordinationReducerError {
    /// Failed to deserialize event payload.
    #[error("failed to deserialize coordination event: {0}")]
    DeserializationError(String),

    /// Event references unknown coordination.
    #[error("coordination not found: {0}")]
    CoordinationNotFound(String),

    /// Event references unknown binding.
    #[error("binding not found for session: {0}")]
    BindingNotFound(String),
}

/// Reducer for coordination lifecycle events.
///
/// Processes coordination events and maintains the state of all coordinations.
/// Implements the state machine:
///
/// ```text
/// (none) --Started--> Initializing --> Running
/// Running --SessionBound--> Running (binding added)
/// Running --SessionUnbound--> Running (binding removed, tracking updated)
/// Running --Completed--> Completed(StopCondition)
/// Running --Aborted--> Aborted(AbortReason)
/// ```
///
/// # Determinism
///
/// This reducer is deterministic: applying the same sequence of events always
/// produces the same state. This property is verified by property tests.
#[derive(Debug, Default)]
pub struct CoordinationReducer {
    state: CoordinationState,
}

impl CoordinationReducer {
    /// Creates a new coordination reducer with empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles a `coordination.started` event.
    ///
    /// Creates a new coordination session in the `Initializing` state.
    /// This is idempotent - if a coordination with this ID already exists,
    /// the event is ignored to prevent resetting budget usage or work progress.
    fn handle_started(&mut self, event: CoordinationStarted) {
        // Idempotency: Skip if coordination already exists
        // This prevents a replayed Started event from resetting accumulated state
        if self
            .state
            .coordinations
            .contains_key(&event.coordination_id)
        {
            return;
        }

        // Enforce MAX_HASHMAP_SIZE limit to match deserialization bounds (CTR-1303)
        // This prevents unbounded growth that would cause checkpoint deserialization
        // failure
        if self.state.coordinations.len() >= super::state::MAX_HASHMAP_SIZE {
            // State at capacity - skip this event
            // In production, this would be logged as a warning
            return;
        }

        // Create the coordination session
        let Ok(session) = CoordinationSession::new(
            event.coordination_id.clone(),
            event.work_ids.clone(),
            event.budget.clone(),
            event.max_attempts_per_work,
            event.started_at,
        ) else {
            // Work queue size exceeded - skip this event
            // In production, this would be logged as a warning
            return;
        };

        // Insert into state
        self.state
            .coordinations
            .insert(event.coordination_id, session);
    }

    /// Handles a `coordination.session_bound` event.
    ///
    /// Records the binding between a session and a work item.
    fn handle_session_bound(&mut self, event: CoordinationSessionBound) {
        // Get the coordination session
        let Some(coordination) = self.state.coordinations.get_mut(&event.coordination_id) else {
            // Unknown coordination - skip
            return;
        };

        // Update status to Running if still Initializing
        if matches!(coordination.status, CoordinationStatus::Initializing) {
            coordination.status = CoordinationStatus::Running;
        }

        // Update work tracking
        if let Some(tracking) = coordination.work_tracking.get_mut(&event.work_id) {
            tracking.attempt_count = event.attempt_number;
            // Only add session_id if:
            // 1. Not already present (idempotency - prevents duplicates on replay)
            // 2. Within bounds (MAX_SESSION_IDS_PER_WORK)
            if !tracking.session_ids.contains(&event.session_id)
                && tracking.session_ids.len() < super::state::MAX_SESSION_IDS_PER_WORK
            {
                tracking.session_ids.push(event.session_id.clone());
            }
        }

        // Enforce MAX_HASHMAP_SIZE limit for bindings to match deserialization bounds
        // (CTR-1303) Skip if at capacity, but allow update of existing binding
        if self.state.bindings.len() >= super::state::MAX_HASHMAP_SIZE
            && !self.state.bindings.contains_key(&event.session_id)
        {
            // Bindings at capacity - skip this event
            return;
        }

        // Create binding info
        let binding = BindingInfo::new(
            event.session_id.clone(),
            event.work_id,
            event.attempt_number,
            event.bound_at,
        );

        // Insert binding (idempotent)
        self.state.bindings.insert(event.session_id, binding);
    }

    /// Handles a `coordination.session_unbound` event.
    ///
    /// Processes the session outcome and updates tracking state.
    fn handle_session_unbound(&mut self, event: &CoordinationSessionUnbound) {
        // Remove the binding
        let Some(binding) = self.state.bindings.remove(&event.session_id) else {
            // Unknown binding - skip
            return;
        };

        // Get the coordination session
        let Some(coordination) = self.state.coordinations.get_mut(&event.coordination_id) else {
            // Unknown coordination - skip
            return;
        };

        // Update budget usage
        coordination.budget_usage.consumed_episodes = coordination
            .budget_usage
            .consumed_episodes
            .saturating_add(1);
        coordination.budget_usage.consumed_tokens = coordination
            .budget_usage
            .consumed_tokens
            .saturating_add(event.tokens_consumed);

        // Update consecutive failures tracking
        match event.outcome {
            SessionOutcome::Success => {
                // Reset consecutive failures on success (circuit breaker reset)
                coordination.consecutive_failures = 0;

                // Mark work item as succeeded
                if let Some(tracking) = coordination.work_tracking.get_mut(&binding.work_id) {
                    tracking.final_outcome = Some(WorkItemOutcome::Succeeded);
                }

                // Advance to next work item
                coordination.work_index = coordination.work_index.saturating_add(1);
            },
            SessionOutcome::Failure => {
                // Increment consecutive failures
                coordination.consecutive_failures =
                    coordination.consecutive_failures.saturating_add(1);

                // Check if we should advance (retry exhausted) or retry
                if let Some(tracking) = coordination.work_tracking.get_mut(&binding.work_id) {
                    if tracking.attempt_count >= coordination.max_attempts_per_work {
                        // Mark as failed and advance
                        tracking.final_outcome = Some(WorkItemOutcome::Failed);
                        coordination.work_index = coordination.work_index.saturating_add(1);
                    }
                    // Otherwise, retry same work item (work_index unchanged)
                }
            },
        }
    }

    /// Handles a `coordination.completed` event.
    ///
    /// Marks the coordination as completed with the given stop condition.
    fn handle_completed(&mut self, event: CoordinationCompleted) {
        let Some(coordination) = self.state.coordinations.get_mut(&event.coordination_id) else {
            // Unknown coordination - skip
            return;
        };

        // Update status
        coordination.status = CoordinationStatus::Completed(event.stop_condition);
        coordination.completed_at = Some(event.completed_at);

        // Update final budget usage
        coordination.budget_usage = event.budget_usage;
    }

    /// Handles a `coordination.aborted` event.
    ///
    /// Marks the coordination as aborted with the given reason.
    fn handle_aborted(&mut self, event: CoordinationAborted) {
        let Some(coordination) = self.state.coordinations.get_mut(&event.coordination_id) else {
            // Unknown coordination - skip
            return;
        };

        // Update status
        coordination.status = CoordinationStatus::Aborted(event.reason);
        coordination.completed_at = Some(event.aborted_at);

        // Update final budget usage
        coordination.budget_usage = event.budget_usage;
    }
}

impl Reducer for CoordinationReducer {
    type State = CoordinationState;
    type Error = Infallible;

    fn name(&self) -> &'static str {
        "coordination-lifecycle"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        // Only process coordination events
        if !event.event_type.starts_with("coordination.") {
            return Ok(());
        }

        // Parse event based on type
        match event.event_type.as_str() {
            EVENT_TYPE_STARTED => {
                if let Ok(started) = serde_json::from_slice::<CoordinationStarted>(&event.payload) {
                    self.handle_started(started);
                }
            },
            EVENT_TYPE_SESSION_BOUND => {
                if let Ok(bound) =
                    serde_json::from_slice::<CoordinationSessionBound>(&event.payload)
                {
                    self.handle_session_bound(bound);
                }
            },
            EVENT_TYPE_SESSION_UNBOUND => {
                if let Ok(unbound) =
                    serde_json::from_slice::<CoordinationSessionUnbound>(&event.payload)
                {
                    self.handle_session_unbound(&unbound);
                }
            },
            EVENT_TYPE_COMPLETED => {
                if let Ok(completed) =
                    serde_json::from_slice::<CoordinationCompleted>(&event.payload)
                {
                    self.handle_completed(completed);
                }
            },
            EVENT_TYPE_ABORTED => {
                if let Ok(aborted) = serde_json::from_slice::<CoordinationAborted>(&event.payload) {
                    self.handle_aborted(aborted);
                }
            },
            _ => {
                // Unknown coordination event type - skip
            },
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
        self.state = CoordinationState::default();
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::coordination::events::BLAKE3_HASH_SIZE;
    use crate::coordination::state::{AbortReason, BudgetUsage, CoordinationBudget, StopCondition};

    /// Helper to create an event record with a JSON payload.
    fn create_event(event_type: &str, payload: &[u8]) -> EventRecord {
        EventRecord::with_timestamp(
            event_type,
            "coord-test",
            "test-actor",
            payload.to_vec(),
            1000,
        )
    }

    /// Helper to create a started event payload.
    fn started_payload(coordination_id: &str, work_ids: Vec<String>) -> Vec<u8> {
        let budget = CoordinationBudget::new(10, 60_000, None).unwrap();
        let event = CoordinationStarted::new(
            coordination_id.to_string(),
            work_ids,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();
        serde_json::to_vec(&event).unwrap()
    }

    /// Helper to create a session bound event payload.
    fn bound_payload(
        coordination_id: &str,
        session_id: &str,
        work_id: &str,
        attempt: u32,
    ) -> Vec<u8> {
        let event = CoordinationSessionBound::new(
            coordination_id.to_string(),
            session_id.to_string(),
            work_id.to_string(),
            attempt,
            100,
            2_000_000_000,
        );
        serde_json::to_vec(&event).unwrap()
    }

    /// Helper to create a session unbound event payload.
    fn unbound_payload(
        coordination_id: &str,
        session_id: &str,
        work_id: &str,
        outcome: SessionOutcome,
        tokens: u64,
    ) -> Vec<u8> {
        let event = CoordinationSessionUnbound::new(
            coordination_id.to_string(),
            session_id.to_string(),
            work_id.to_string(),
            outcome,
            tokens,
            3_000_000_000,
        );
        serde_json::to_vec(&event).unwrap()
    }

    /// Helper to create a completed event payload.
    fn completed_payload(coordination_id: &str, stop_condition: StopCondition) -> Vec<u8> {
        let event = CoordinationCompleted::new(
            coordination_id.to_string(),
            stop_condition,
            BudgetUsage {
                consumed_episodes: 2,
                elapsed_ms: 5000,
                consumed_tokens: 10000,
            },
            2,
            2,
            0,
            [0u8; BLAKE3_HASH_SIZE],
            4_000_000_000,
        );
        serde_json::to_vec(&event).unwrap()
    }

    /// Helper to create an aborted event payload.
    fn aborted_payload(coordination_id: &str, reason: AbortReason) -> Vec<u8> {
        let event = CoordinationAborted::new(
            coordination_id.to_string(),
            reason,
            BudgetUsage::new(),
            4_000_000_000,
        );
        serde_json::to_vec(&event).unwrap()
    }

    // ========================================================================
    // Basic Reducer Tests
    // ========================================================================

    #[test]
    fn tck_00149_reducer_new() {
        let reducer = CoordinationReducer::new();
        assert!(reducer.state().is_empty());
        assert_eq!(reducer.name(), "coordination-lifecycle");
    }

    #[test]
    fn tck_00149_handle_started_creates_coordination() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        let payload = started_payload("coord-1", vec!["work-1".to_string(), "work-2".to_string()]);
        let event = create_event(EVENT_TYPE_STARTED, &payload);

        reducer.apply(&event, &ctx).unwrap();

        assert_eq!(reducer.state().len(), 1);
        let coord = reducer.state().get("coord-1").unwrap();
        assert_eq!(coord.coordination_id, "coord-1");
        assert_eq!(coord.work_queue.len(), 2);
        assert!(matches!(coord.status, CoordinationStatus::Initializing));
    }

    #[test]
    fn tck_00149_handle_session_bound_creates_binding() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload =
            started_payload("coord-1", vec!["work-1".to_string(), "work-2".to_string()]);
        let start_event = create_event(EVENT_TYPE_STARTED, &start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Bind session
        let bound_payload = bound_payload("coord-1", "session-1", "work-1", 1);
        let bound_event = create_event(EVENT_TYPE_SESSION_BOUND, &bound_payload);
        reducer.apply(&bound_event, &ctx).unwrap();

        // Verify binding
        assert_eq!(reducer.state().binding_count(), 1);
        let binding = reducer.state().get_binding("session-1").unwrap();
        assert_eq!(binding.work_id, "work-1");
        assert_eq!(binding.attempt_number, 1);

        // Verify status transitioned to Running
        let coord = reducer.state().get("coord-1").unwrap();
        assert!(matches!(coord.status, CoordinationStatus::Running));
    }

    #[test]
    fn tck_00149_handle_session_bound_idempotent_session_ids() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Bind session for the first time
        let bound_data = bound_payload("coord-1", "session-1", "work-1", 1);
        let bound_event = create_event(EVENT_TYPE_SESSION_BOUND, &bound_data);
        reducer.apply(&bound_event, &ctx).unwrap();

        // Count session_ids after first bind
        let coord = reducer.state().get("coord-1").unwrap();
        let tracking = coord.work_tracking.get("work-1").unwrap();
        assert_eq!(
            tracking.session_ids.len(),
            1,
            "Should have exactly 1 session_id"
        );
        assert_eq!(tracking.session_ids[0], "session-1");

        // Replay the same bound event (simulating duplicate/replay)
        reducer.apply(&bound_event, &ctx).unwrap();
        reducer.apply(&bound_event, &ctx).unwrap();
        reducer.apply(&bound_event, &ctx).unwrap();

        // Verify session_ids did not grow (idempotency)
        let coord = reducer.state().get("coord-1").unwrap();
        let tracking = coord.work_tracking.get("work-1").unwrap();
        assert_eq!(
            tracking.session_ids.len(),
            1,
            "Replayed bound events should not duplicate session_ids"
        );

        // Bind a new session - should be recorded
        let bound_data_2 = bound_payload("coord-1", "session-2", "work-1", 2);
        reducer
            .apply(&create_event(EVENT_TYPE_SESSION_BOUND, &bound_data_2), &ctx)
            .unwrap();

        let coord = reducer.state().get("coord-1").unwrap();
        let tracking = coord.work_tracking.get("work-1").unwrap();
        assert_eq!(
            tracking.session_ids.len(),
            2,
            "New session should be recorded after replays"
        );
        assert!(tracking.session_ids.contains(&"session-1".to_string()));
        assert!(tracking.session_ids.contains(&"session-2".to_string()));
    }

    #[test]
    fn tck_00149_handle_session_unbound_success_advances() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload =
            started_payload("coord-1", vec!["work-1".to_string(), "work-2".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Bind and unbind with success
        let bound_payload = bound_payload("coord-1", "session-1", "work-1", 1);
        reducer
            .apply(
                &create_event(EVENT_TYPE_SESSION_BOUND, &bound_payload),
                &ctx,
            )
            .unwrap();

        let unbound_payload = unbound_payload(
            "coord-1",
            "session-1",
            "work-1",
            SessionOutcome::Success,
            5000,
        );
        reducer
            .apply(
                &create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound_payload),
                &ctx,
            )
            .unwrap();

        // Verify binding removed
        assert_eq!(reducer.state().binding_count(), 0);

        // Verify work index advanced
        let coord = reducer.state().get("coord-1").unwrap();
        assert_eq!(coord.work_index, 1);

        // Verify work tracking updated
        let tracking = coord.work_tracking.get("work-1").unwrap();
        assert_eq!(tracking.final_outcome, Some(WorkItemOutcome::Succeeded));

        // Verify budget usage updated
        assert_eq!(coord.budget_usage.consumed_episodes, 1);
        assert_eq!(coord.budget_usage.consumed_tokens, 5000);

        // Verify consecutive failures reset
        assert_eq!(coord.consecutive_failures, 0);
    }

    #[test]
    fn tck_00149_handle_session_unbound_failure_increments_failures() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Bind and unbind with failure (first attempt)
        let bound_payload = bound_payload("coord-1", "session-1", "work-1", 1);
        reducer
            .apply(
                &create_event(EVENT_TYPE_SESSION_BOUND, &bound_payload),
                &ctx,
            )
            .unwrap();

        let unbound_payload = unbound_payload(
            "coord-1",
            "session-1",
            "work-1",
            SessionOutcome::Failure,
            1000,
        );
        reducer
            .apply(
                &create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound_payload),
                &ctx,
            )
            .unwrap();

        // Verify consecutive failures incremented
        let coord = reducer.state().get("coord-1").unwrap();
        assert_eq!(coord.consecutive_failures, 1);

        // Verify work index NOT advanced (retry available)
        assert_eq!(coord.work_index, 0);
    }

    #[test]
    fn tck_00149_handle_session_unbound_failure_exhausts_retries() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination with max_attempts = 3
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Simulate 3 failed attempts
        for i in 1..=3u32 {
            let bound = bound_payload("coord-1", &format!("session-{i}"), "work-1", i);
            reducer
                .apply(&create_event(EVENT_TYPE_SESSION_BOUND, &bound), &ctx)
                .unwrap();

            let unbound = unbound_payload(
                "coord-1",
                &format!("session-{i}"),
                "work-1",
                SessionOutcome::Failure,
                1000,
            );
            reducer
                .apply(&create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound), &ctx)
                .unwrap();
        }

        // Verify work marked as failed and index advanced
        let coord = reducer.state().get("coord-1").unwrap();
        let tracking = coord.work_tracking.get("work-1").unwrap();
        assert_eq!(tracking.final_outcome, Some(WorkItemOutcome::Failed));
        assert_eq!(coord.work_index, 1); // Moved past work-1
    }

    #[test]
    fn tck_00149_handle_completed() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Complete coordination
        let completed = completed_payload("coord-1", StopCondition::WorkCompleted);
        reducer
            .apply(&create_event(EVENT_TYPE_COMPLETED, &completed), &ctx)
            .unwrap();

        let coord = reducer.state().get("coord-1").unwrap();
        assert!(matches!(
            coord.status,
            CoordinationStatus::Completed(StopCondition::WorkCompleted)
        ));
        assert!(coord.completed_at.is_some());
    }

    #[test]
    fn tck_00149_handle_aborted() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Abort coordination
        let aborted = aborted_payload("coord-1", AbortReason::NoEligibleWork);
        reducer
            .apply(&create_event(EVENT_TYPE_ABORTED, &aborted), &ctx)
            .unwrap();

        let coord = reducer.state().get("coord-1").unwrap();
        assert!(matches!(
            coord.status,
            CoordinationStatus::Aborted(AbortReason::NoEligibleWork)
        ));
        assert!(coord.completed_at.is_some());
    }

    // ========================================================================
    // Idempotency Tests
    // ========================================================================

    #[test]
    fn tck_00149_started_is_idempotent() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        let payload = started_payload("coord-1", vec!["work-1".to_string()]);
        let event = create_event(EVENT_TYPE_STARTED, &payload);

        // Apply twice
        reducer.apply(&event, &ctx).unwrap();
        let state1 = reducer.state().clone();

        reducer.apply(&event, &ctx).unwrap();
        let state2 = reducer.state().clone();

        // States should be equal (idempotent)
        assert_eq!(state1, state2);
    }

    #[test]
    fn tck_00149_started_does_not_reset_accumulated_state() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Process a session to accumulate some state
        let bound_payload = bound_payload("coord-1", "session-1", "work-1", 1);
        reducer
            .apply(
                &create_event(EVENT_TYPE_SESSION_BOUND, &bound_payload),
                &ctx,
            )
            .unwrap();

        let unbound_payload = unbound_payload(
            "coord-1",
            "session-1",
            "work-1",
            SessionOutcome::Success,
            5000,
        );
        reducer
            .apply(
                &create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound_payload),
                &ctx,
            )
            .unwrap();

        // Record accumulated state
        let coord_before = reducer.state().get("coord-1").unwrap();
        let budget_before = coord_before.budget_usage.consumed_episodes;
        let work_index_before = coord_before.work_index;
        assert_eq!(budget_before, 1, "Should have consumed 1 episode");
        assert_eq!(work_index_before, 1, "Should have advanced work_index");

        // Try to replay the Started event
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Verify state was NOT reset
        let coord_after = reducer.state().get("coord-1").unwrap();
        assert_eq!(
            coord_after.budget_usage.consumed_episodes, budget_before,
            "Duplicate Started should not reset budget_usage"
        );
        assert_eq!(
            coord_after.work_index, work_index_before,
            "Duplicate Started should not reset work_index"
        );
    }

    #[test]
    fn tck_00149_completed_is_idempotent() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Complete twice
        let completed = completed_payload("coord-1", StopCondition::WorkCompleted);
        let event = create_event(EVENT_TYPE_COMPLETED, &completed);

        reducer.apply(&event, &ctx).unwrap();
        let state1 = reducer.state().clone();

        reducer.apply(&event, &ctx).unwrap();
        let state2 = reducer.state().clone();

        assert_eq!(state1, state2);
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn tck_00149_ignores_non_coordination_events() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        let event = EventRecord::new("session.started", "session-1", "actor-1", vec![1, 2, 3]);
        reducer.apply(&event, &ctx).unwrap();

        assert!(reducer.state().is_empty());
    }

    #[test]
    fn tck_00149_ignores_unknown_coordination() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Bind to unknown coordination
        let bound = bound_payload("unknown", "session-1", "work-1", 1);
        reducer
            .apply(&create_event(EVENT_TYPE_SESSION_BOUND, &bound), &ctx)
            .unwrap();

        // Should not create binding
        assert_eq!(reducer.state().binding_count(), 0);
    }

    #[test]
    fn tck_00149_ignores_malformed_payload() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        let event = create_event(EVENT_TYPE_STARTED, b"not valid json");
        reducer.apply(&event, &ctx).unwrap();

        assert!(reducer.state().is_empty());
    }

    #[test]
    fn tck_00149_reset_clears_state() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Add some state
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();
        assert!(!reducer.state().is_empty());

        // Reset
        reducer.reset();
        assert!(reducer.state().is_empty());
    }

    // ========================================================================
    // Circuit Breaker Tests
    // ========================================================================

    #[test]
    fn tck_00149_circuit_breaker_consecutive_failures() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination with 2 work items, max_attempts = 3
        let start_payload =
            started_payload("coord-1", vec!["work-1".to_string(), "work-2".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Fail work-1 exhaustively (3 times)
        for i in 1..=3u32 {
            let bound = bound_payload("coord-1", &format!("session-{i}"), "work-1", i);
            reducer
                .apply(&create_event(EVENT_TYPE_SESSION_BOUND, &bound), &ctx)
                .unwrap();

            let unbound = unbound_payload(
                "coord-1",
                &format!("session-{i}"),
                "work-1",
                SessionOutcome::Failure,
                1000,
            );
            reducer
                .apply(&create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound), &ctx)
                .unwrap();
        }

        // Consecutive failures should be 3 (circuit breaker threshold)
        let coord = reducer.state().get("coord-1").unwrap();
        assert_eq!(coord.consecutive_failures, 3);
    }

    #[test]
    fn tck_00149_circuit_breaker_resets_on_success() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload =
            started_payload("coord-1", vec!["work-1".to_string(), "work-2".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Fail twice
        for i in 1..=2u32 {
            let bound = bound_payload("coord-1", &format!("session-fail-{i}"), "work-1", i);
            reducer
                .apply(&create_event(EVENT_TYPE_SESSION_BOUND, &bound), &ctx)
                .unwrap();

            let unbound = unbound_payload(
                "coord-1",
                &format!("session-fail-{i}"),
                "work-1",
                SessionOutcome::Failure,
                1000,
            );
            reducer
                .apply(&create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound), &ctx)
                .unwrap();
        }

        // Verify 2 consecutive failures
        assert_eq!(
            reducer.state().get("coord-1").unwrap().consecutive_failures,
            2
        );

        // Succeed on third attempt
        let bound = bound_payload("coord-1", "session-success", "work-1", 3);
        reducer
            .apply(&create_event(EVENT_TYPE_SESSION_BOUND, &bound), &ctx)
            .unwrap();

        let unbound = unbound_payload(
            "coord-1",
            "session-success",
            "work-1",
            SessionOutcome::Success,
            5000,
        );
        reducer
            .apply(&create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound), &ctx)
            .unwrap();

        // Consecutive failures should reset to 0
        let coord = reducer.state().get("coord-1").unwrap();
        assert_eq!(coord.consecutive_failures, 0);
    }

    // ========================================================================
    // Budget Tracking Tests
    // ========================================================================

    #[test]
    fn tck_00149_budget_usage_accumulates() {
        let mut reducer = CoordinationReducer::new();
        let ctx = ReducerContext::new(1);

        // Start coordination
        let start_payload = started_payload("coord-1", vec!["work-1".to_string()]);
        reducer
            .apply(&create_event(EVENT_TYPE_STARTED, &start_payload), &ctx)
            .unwrap();

        // Session 1: 1000 tokens
        let bound1 = bound_payload("coord-1", "session-1", "work-1", 1);
        reducer
            .apply(&create_event(EVENT_TYPE_SESSION_BOUND, &bound1), &ctx)
            .unwrap();
        let unbound1 = unbound_payload(
            "coord-1",
            "session-1",
            "work-1",
            SessionOutcome::Failure,
            1000,
        );
        reducer
            .apply(&create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound1), &ctx)
            .unwrap();

        // Session 2: 2000 tokens
        let bound2 = bound_payload("coord-1", "session-2", "work-1", 2);
        reducer
            .apply(&create_event(EVENT_TYPE_SESSION_BOUND, &bound2), &ctx)
            .unwrap();
        let unbound2 = unbound_payload(
            "coord-1",
            "session-2",
            "work-1",
            SessionOutcome::Success,
            2000,
        );
        reducer
            .apply(&create_event(EVENT_TYPE_SESSION_UNBOUND, &unbound2), &ctx)
            .unwrap();

        // Verify accumulated budget usage
        let coord = reducer.state().get("coord-1").unwrap();
        assert_eq!(coord.budget_usage.consumed_episodes, 2);
        assert_eq!(coord.budget_usage.consumed_tokens, 3000); // 1000 + 2000
    }
}
