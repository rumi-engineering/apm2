//! Session lifecycle reducer implementation.

use std::collections::HashMap;

use prost::Message;
use serde::{Deserialize, Serialize};

use super::error::SessionError;
use super::state::{ExitClassification, SessionState};
use crate::events::{PolicyEvent, SessionEvent, policy_event, session_event};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

/// State maintained by the session reducer.
///
/// Maps session IDs to their current state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionReducerState {
    /// Map of session ID to session state.
    pub sessions: HashMap<String, SessionState>,
}

impl SessionReducerState {
    /// Creates a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns `true` if there are no sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Returns the state for a session, if it exists.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<&SessionState> {
        self.sessions.get(session_id)
    }

    /// Returns the number of active (running) sessions.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_active()).count()
    }

    /// Returns the number of terminated sessions.
    #[must_use]
    pub fn terminated_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| matches!(s, SessionState::Terminated { .. }))
            .count()
    }

    /// Returns the number of quarantined sessions.
    #[must_use]
    pub fn quarantined_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| matches!(s, SessionState::Quarantined { .. }))
            .count()
    }
}

/// Reducer for session lifecycle events.
///
/// Processes session events and maintains the state of all sessions.
/// Implements the state machine:
///
/// ```text
/// (none) --SessionStarted--> Running
/// Running --SessionProgress--> Running (counters updated)
/// Running --SessionTerminated--> Terminated
/// Running --SessionQuarantined--> Quarantined
/// ```
#[derive(Debug, Default)]
pub struct SessionReducer {
    state: SessionReducerState,
}

impl SessionReducer {
    /// Creates a new session reducer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles a session started event.
    fn handle_started(
        &mut self,
        event: crate::events::SessionStarted,
        timestamp: u64,
    ) -> Result<(), SessionError> {
        let session_id = event.session_id.clone();

        // Check if session already exists
        if self.state.sessions.contains_key(&session_id) {
            return Err(SessionError::SessionAlreadyExists { session_id });
        }

        // Create new running state
        let state = SessionState::Running {
            started_at: timestamp,
            actor_id: event.actor_id,
            work_id: event.work_id,
            lease_id: event.lease_id,
            adapter_type: event.adapter_type,
            entropy_budget: event.entropy_budget,
            progress_count: 0,
            entropy_consumed: 0,
            error_count: 0,
            violation_count: 0,
            stall_count: 0,
            timeout_count: 0,
        };

        self.state.sessions.insert(session_id, state);
        Ok(())
    }

    /// Handles a session progress event.
    fn handle_progress(
        &mut self,
        event: &crate::events::SessionProgress,
        _timestamp: u64,
    ) -> Result<(), SessionError> {
        let session_id = &event.session_id;

        let state = self.state.sessions.get_mut(session_id).ok_or_else(|| {
            SessionError::SessionNotFound {
                session_id: session_id.clone(),
            }
        })?;

        // Can only progress from Running state
        match state {
            SessionState::Running {
                progress_count,
                entropy_consumed,
                ..
            } => {
                *progress_count += 1;
                *entropy_consumed = event.entropy_consumed;
                Ok(())
            },
            other => Err(SessionError::InvalidTransition {
                from_state: other.state_name().to_string(),
                event_type: "session.progress".to_string(),
            }),
        }
    }

    /// Handles a session terminated event.
    fn handle_terminated(
        &mut self,
        event: crate::events::SessionTerminated,
        timestamp: u64,
    ) -> Result<(), SessionError> {
        let session_id = &event.session_id;

        let current_state =
            self.state
                .sessions
                .get(session_id)
                .ok_or_else(|| SessionError::SessionNotFound {
                    session_id: session_id.clone(),
                })?;

        // Can only terminate from Running state
        let started_at = match current_state {
            SessionState::Running { started_at, .. } => *started_at,
            other => {
                return Err(SessionError::InvalidTransition {
                    from_state: other.state_name().to_string(),
                    event_type: "session.terminated".to_string(),
                });
            },
        };

        // Transition to Terminated state
        let new_state = SessionState::Terminated {
            started_at,
            terminated_at: timestamp,
            exit_classification: ExitClassification::parse(&event.exit_classification),
            rationale_code: event.rationale_code,
            final_entropy: event.final_entropy,
        };

        self.state.sessions.insert(session_id.clone(), new_state);
        Ok(())
    }

    /// Handles a session quarantined event.
    fn handle_quarantined(
        &mut self,
        event: crate::events::SessionQuarantined,
        timestamp: u64,
    ) -> Result<(), SessionError> {
        let session_id = &event.session_id;

        let current_state =
            self.state
                .sessions
                .get(session_id)
                .ok_or_else(|| SessionError::SessionNotFound {
                    session_id: session_id.clone(),
                })?;

        // Can only quarantine from Running state
        let started_at = match current_state {
            SessionState::Running { started_at, .. } => *started_at,
            other => {
                return Err(SessionError::InvalidTransition {
                    from_state: other.state_name().to_string(),
                    event_type: "session.quarantined".to_string(),
                });
            },
        };

        // Transition to Quarantined state
        let new_state = SessionState::Quarantined {
            started_at,
            quarantined_at: timestamp,
            reason: event.reason,
            quarantine_until: event.quarantine_until,
        };

        self.state.sessions.insert(session_id.clone(), new_state);
        Ok(())
    }

    /// Handles a policy violation event by incrementing the violation counter.
    ///
    /// Note: This only increments the count. Entropy consumption is tracked
    /// via `SessionProgress` events which contain the canonical
    /// `entropy_consumed` value from the actual tracker (which uses the
    /// session's configured weights).
    fn handle_policy_violation(
        &mut self,
        event: &crate::events::PolicyViolation,
    ) -> Result<(), SessionError> {
        let session_id = &event.session_id;

        let state = self.state.sessions.get_mut(session_id).ok_or_else(|| {
            SessionError::SessionNotFound {
                session_id: session_id.clone(),
            }
        })?;

        // Can only record violations for Running sessions
        match state {
            SessionState::Running {
                violation_count, ..
            } => {
                *violation_count += 1;
                // Note: entropy_consumed is NOT updated here - that's tracked via
                // SessionProgress events which contain the authoritative value
                // from the EntropyTracker with the session's configured weights.
                Ok(())
            },
            other => Err(SessionError::InvalidTransition {
                from_state: other.state_name().to_string(),
                event_type: "policy.violation".to_string(),
            }),
        }
    }

    /// Handles a budget exceeded event by updating entropy consumption.
    fn handle_budget_exceeded(
        &mut self,
        event: &crate::events::BudgetExceeded,
    ) -> Result<(), SessionError> {
        let session_id = &event.session_id;

        let state = self.state.sessions.get_mut(session_id).ok_or_else(|| {
            SessionError::SessionNotFound {
                session_id: session_id.clone(),
            }
        })?;

        // Update entropy consumed based on budget type
        match state {
            SessionState::Running {
                entropy_consumed,
                error_count,
                timeout_count,
                ..
            } => {
                // Record the budget exceeded event based on type
                match event.budget_type.as_str() {
                    "TIME" | "TIMEOUT" => *timeout_count += 1,
                    _ => *error_count += 1,
                }
                // Set consumed to the reported value
                *entropy_consumed = event.consumed;
                Ok(())
            },
            other => Err(SessionError::InvalidTransition {
                from_state: other.state_name().to_string(),
                event_type: "policy.budget_exceeded".to_string(),
            }),
        }
    }
}

impl Reducer for SessionReducer {
    type State = SessionReducerState;
    type Error = SessionError;

    fn name(&self) -> &'static str {
        "session-lifecycle"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        // Handle session events
        if event.event_type.starts_with("session.") {
            let session_event = SessionEvent::decode(&event.payload[..])?;
            let timestamp = event.timestamp_ns;

            return match session_event.event {
                Some(session_event::Event::Started(e)) => self.handle_started(e, timestamp),
                Some(session_event::Event::Progress(ref e)) => self.handle_progress(e, timestamp),
                Some(session_event::Event::Terminated(e)) => self.handle_terminated(e, timestamp),
                Some(session_event::Event::Quarantined(e)) => self.handle_quarantined(e, timestamp),
                None => Ok(()),
            };
        }

        // Handle policy events (for entropy tracking)
        if event.event_type.starts_with("policy.") {
            let policy_event = PolicyEvent::decode(&event.payload[..])?;

            return match policy_event.event {
                Some(policy_event::Event::Violation(ref e)) => self.handle_policy_violation(e),
                Some(policy_event::Event::BudgetExceeded(ref e)) => self.handle_budget_exceeded(e),
                Some(policy_event::Event::Loaded(_)) | None => Ok(()),
            };
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
        self.state = SessionReducerState::default();
    }
}

/// Helper to create a session event payload for testing and event creation.
pub mod helpers {
    use prost::Message;

    use crate::events::{
        BudgetExceeded, PolicyEvent, PolicyViolation, SessionEvent, SessionProgress,
        SessionQuarantined, SessionStarted, SessionTerminated, policy_event, session_event,
    };

    /// Creates a `SessionStarted` event payload.
    #[must_use]
    pub fn session_started_payload(
        session_id: &str,
        actor_id: &str,
        adapter_type: &str,
        work_id: &str,
        lease_id: &str,
        entropy_budget: u64,
    ) -> Vec<u8> {
        let started = SessionStarted {
            session_id: session_id.to_string(),
            actor_id: actor_id.to_string(),
            adapter_type: adapter_type.to_string(),
            work_id: work_id.to_string(),
            lease_id: lease_id.to_string(),
            entropy_budget,
        };
        let event = SessionEvent {
            event: Some(session_event::Event::Started(started)),
        };
        event.encode_to_vec()
    }

    /// Creates a `SessionProgress` event payload.
    #[must_use]
    pub fn session_progress_payload(
        session_id: &str,
        progress_sequence: u64,
        progress_type: &str,
        entropy_consumed: u64,
    ) -> Vec<u8> {
        let progress = SessionProgress {
            session_id: session_id.to_string(),
            progress_sequence,
            progress_type: progress_type.to_string(),
            entropy_consumed,
        };
        let event = SessionEvent {
            event: Some(session_event::Event::Progress(progress)),
        };
        event.encode_to_vec()
    }

    /// Creates a `SessionTerminated` event payload.
    #[must_use]
    pub fn session_terminated_payload(
        session_id: &str,
        exit_classification: &str,
        rationale_code: &str,
        final_entropy: u64,
    ) -> Vec<u8> {
        let terminated = SessionTerminated {
            session_id: session_id.to_string(),
            exit_classification: exit_classification.to_string(),
            rationale_code: rationale_code.to_string(),
            final_entropy,
        };
        let event = SessionEvent {
            event: Some(session_event::Event::Terminated(terminated)),
        };
        event.encode_to_vec()
    }

    /// Creates a `SessionQuarantined` event payload.
    #[must_use]
    pub fn session_quarantined_payload(
        session_id: &str,
        reason: &str,
        quarantine_until: u64,
    ) -> Vec<u8> {
        let quarantined = SessionQuarantined {
            session_id: session_id.to_string(),
            reason: reason.to_string(),
            quarantine_until,
        };
        let event = SessionEvent {
            event: Some(session_event::Event::Quarantined(quarantined)),
        };
        event.encode_to_vec()
    }

    /// Creates a `PolicyViolation` event payload.
    #[must_use]
    pub fn policy_violation_payload(
        session_id: &str,
        violation_type: &str,
        rule_id: &str,
        details: &str,
    ) -> Vec<u8> {
        let violation = PolicyViolation {
            session_id: session_id.to_string(),
            violation_type: violation_type.to_string(),
            rule_id: rule_id.to_string(),
            details: details.to_string(),
        };
        let event = PolicyEvent {
            event: Some(policy_event::Event::Violation(violation)),
        };
        event.encode_to_vec()
    }

    /// Creates a `BudgetExceeded` event payload.
    #[must_use]
    pub fn budget_exceeded_payload(
        session_id: &str,
        budget_type: &str,
        limit: u64,
        consumed: u64,
    ) -> Vec<u8> {
        let exceeded = BudgetExceeded {
            session_id: session_id.to_string(),
            budget_type: budget_type.to_string(),
            limit,
            consumed,
        };
        let event = PolicyEvent {
            event: Some(policy_event::Event::BudgetExceeded(exceeded)),
        };
        event.encode_to_vec()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn create_event(event_type: &str, session_id: &str, payload: Vec<u8>) -> EventRecord {
        EventRecord::with_timestamp(event_type, session_id, "test-actor", payload, 1_000_000_000)
    }

    #[test]
    fn test_session_reducer_new() {
        let reducer = SessionReducer::new();
        assert!(reducer.state().is_empty());
        assert_eq!(reducer.name(), "session-lifecycle");
    }

    #[test]
    fn test_session_started_creates_running() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        let payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let event = create_event("session.started", "session-1", payload);

        reducer.apply(&event, &ctx).unwrap();

        let state = reducer.state().get("session-1").unwrap();
        assert!(state.is_active());
        match state {
            SessionState::Running {
                actor_id,
                work_id,
                lease_id,
                adapter_type,
                entropy_budget,
                progress_count,
                entropy_consumed,
                ..
            } => {
                assert_eq!(actor_id, "actor-1");
                assert_eq!(work_id, "work-1");
                assert_eq!(lease_id, "lease-1");
                assert_eq!(adapter_type, "claude-code");
                assert_eq!(*entropy_budget, 1000);
                assert_eq!(*progress_count, 0);
                assert_eq!(*entropy_consumed, 0);
            },
            _ => panic!("Expected Running state"),
        }
    }

    #[test]
    fn test_session_progress_updates_counters() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Progress event
        let progress_payload = helpers::session_progress_payload("session-1", 1, "HEARTBEAT", 100);
        let progress_event = create_event("session.progress", "session-1", progress_payload);
        reducer.apply(&progress_event, &ctx).unwrap();

        let state = reducer.state().get("session-1").unwrap();
        match state {
            SessionState::Running {
                progress_count,
                entropy_consumed,
                ..
            } => {
                assert_eq!(*progress_count, 1);
                assert_eq!(*entropy_consumed, 100);
            },
            _ => panic!("Expected Running state"),
        }

        // Another progress event
        let progress_payload2 =
            helpers::session_progress_payload("session-1", 2, "TOOL_COMPLETE", 250);
        let progress_event2 = create_event("session.progress", "session-1", progress_payload2);
        reducer.apply(&progress_event2, &ctx).unwrap();

        let state2 = reducer.state().get("session-1").unwrap();
        match state2 {
            SessionState::Running {
                progress_count,
                entropy_consumed,
                ..
            } => {
                assert_eq!(*progress_count, 2);
                assert_eq!(*entropy_consumed, 250);
            },
            _ => panic!("Expected Running state"),
        }
    }

    #[test]
    fn test_session_terminated_from_running() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Terminate session
        let term_payload =
            helpers::session_terminated_payload("session-1", "SUCCESS", "completed", 500);
        let mut term_event = create_event("session.terminated", "session-1", term_payload);
        term_event.timestamp_ns = 2_000_000_000;
        reducer.apply(&term_event, &ctx).unwrap();

        let state = reducer.state().get("session-1").unwrap();
        assert!(state.is_terminal());
        match state {
            SessionState::Terminated {
                started_at,
                terminated_at,
                exit_classification,
                rationale_code,
                final_entropy,
            } => {
                assert_eq!(*started_at, 1_000_000_000);
                assert_eq!(*terminated_at, 2_000_000_000);
                assert_eq!(*exit_classification, ExitClassification::Success);
                assert_eq!(rationale_code, "completed");
                assert_eq!(*final_entropy, 500);
            },
            _ => panic!("Expected Terminated state"),
        }
    }

    #[test]
    fn test_session_quarantined_from_running() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Quarantine session
        let quar_payload =
            helpers::session_quarantined_payload("session-1", "policy violation", 3_000_000_000);
        let mut quar_event = create_event("session.quarantined", "session-1", quar_payload);
        quar_event.timestamp_ns = 2_000_000_000;
        reducer.apply(&quar_event, &ctx).unwrap();

        let state = reducer.state().get("session-1").unwrap();
        assert!(state.is_terminal());
        match state {
            SessionState::Quarantined {
                started_at,
                quarantined_at,
                reason,
                quarantine_until,
            } => {
                assert_eq!(*started_at, 1_000_000_000);
                assert_eq!(*quarantined_at, 2_000_000_000);
                assert_eq!(reason, "policy violation");
                assert_eq!(*quarantine_until, 3_000_000_000);
            },
            _ => panic!("Expected Quarantined state"),
        }
    }

    #[test]
    fn test_duplicate_session_start_errors() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload.clone());
        reducer.apply(&start_event, &ctx).unwrap();

        // Try to start again
        let start_event2 = create_event("session.started", "session-1", start_payload);
        let result = reducer.apply(&start_event2, &ctx);
        assert!(matches!(
            result,
            Err(SessionError::SessionAlreadyExists { .. })
        ));
    }

    #[test]
    fn test_progress_on_unknown_session_errors() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        let progress_payload =
            helpers::session_progress_payload("unknown-session", 1, "HEARTBEAT", 100);
        let progress_event = create_event("session.progress", "unknown-session", progress_payload);
        let result = reducer.apply(&progress_event, &ctx);
        assert!(matches!(result, Err(SessionError::SessionNotFound { .. })));
    }

    #[test]
    fn test_terminate_unknown_session_errors() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        let term_payload =
            helpers::session_terminated_payload("unknown-session", "FAILURE", "error", 0);
        let term_event = create_event("session.terminated", "unknown-session", term_payload);
        let result = reducer.apply(&term_event, &ctx);
        assert!(matches!(result, Err(SessionError::SessionNotFound { .. })));
    }

    #[test]
    fn test_terminate_already_terminated_errors() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Terminate session
        let term_payload =
            helpers::session_terminated_payload("session-1", "SUCCESS", "completed", 500);
        let term_event = create_event("session.terminated", "session-1", term_payload.clone());
        reducer.apply(&term_event, &ctx).unwrap();

        // Try to terminate again
        let term_event2 = create_event("session.terminated", "session-1", term_payload);
        let result = reducer.apply(&term_event2, &ctx);
        assert!(matches!(
            result,
            Err(SessionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_progress_on_terminated_session_errors() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start and terminate session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        let term_payload =
            helpers::session_terminated_payload("session-1", "SUCCESS", "completed", 500);
        let term_event = create_event("session.terminated", "session-1", term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        // Try to progress
        let progress_payload = helpers::session_progress_payload("session-1", 1, "HEARTBEAT", 100);
        let progress_event = create_event("session.progress", "session-1", progress_payload);
        let result = reducer.apply(&progress_event, &ctx);
        assert!(matches!(
            result,
            Err(SessionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_ignores_non_session_events() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        let event = create_event("tool.request", "session-1", vec![1, 2, 3]);
        let result = reducer.apply(&event, &ctx);
        assert!(result.is_ok());
        assert!(reducer.state().is_empty());
    }

    #[test]
    fn test_reset() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Add a session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();
        assert!(!reducer.state().is_empty());

        // Reset
        reducer.reset();
        assert!(reducer.state().is_empty());
    }

    #[test]
    fn test_state_counts() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start 3 sessions
        for i in 1..=3 {
            let start_payload = helpers::session_started_payload(
                &format!("session-{i}"),
                &format!("actor-{i}"),
                "claude-code",
                &format!("work-{i}"),
                &format!("lease-{i}"),
                1000,
            );
            let start_event =
                create_event("session.started", &format!("session-{i}"), start_payload);
            reducer.apply(&start_event, &ctx).unwrap();
        }

        assert_eq!(reducer.state().len(), 3);
        assert_eq!(reducer.state().active_count(), 3);
        assert_eq!(reducer.state().terminated_count(), 0);
        assert_eq!(reducer.state().quarantined_count(), 0);

        // Terminate session-1
        let term_payload = helpers::session_terminated_payload("session-1", "SUCCESS", "done", 500);
        let term_event = create_event("session.terminated", "session-1", term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        // Quarantine session-2
        let quar_payload =
            helpers::session_quarantined_payload("session-2", "violation", 9_000_000_000);
        let quar_event = create_event("session.quarantined", "session-2", quar_payload);
        reducer.apply(&quar_event, &ctx).unwrap();

        assert_eq!(reducer.state().len(), 3);
        assert_eq!(reducer.state().active_count(), 1);
        assert_eq!(reducer.state().terminated_count(), 1);
        assert_eq!(reducer.state().quarantined_count(), 1);
    }

    // ========================================================================
    // Entropy Budget Tracking Tests
    // ========================================================================

    #[test]
    fn test_policy_violation_increments_counter() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Record policy violation
        let violation_payload =
            helpers::policy_violation_payload("session-1", "UNAUTHORIZED_ACCESS", "rule-1", "test");
        let violation_event = create_event("policy.violation", "session-1", violation_payload);
        reducer.apply(&violation_event, &ctx).unwrap();

        let state = reducer.state().get("session-1").unwrap();
        match state {
            SessionState::Running {
                violation_count,
                entropy_consumed,
                ..
            } => {
                assert_eq!(*violation_count, 1);
                // entropy_consumed is NOT updated by policy violations directly;
                // it's updated via SessionProgress events from the tracker
                assert_eq!(*entropy_consumed, 0);
            },
            _ => panic!("Expected Running state"),
        }
    }

    #[test]
    fn test_multiple_violations_accumulate() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Record multiple violations
        for i in 1..=3 {
            let violation_payload = helpers::policy_violation_payload(
                "session-1",
                "UNAUTHORIZED_ACCESS",
                &format!("rule-{i}"),
                &format!("violation {i}"),
            );
            let violation_event = create_event("policy.violation", "session-1", violation_payload);
            reducer.apply(&violation_event, &ctx).unwrap();
        }

        let state = reducer.state().get("session-1").unwrap();
        match state {
            SessionState::Running {
                violation_count,
                entropy_consumed,
                ..
            } => {
                assert_eq!(*violation_count, 3);
                // Violations only increment count; entropy is tracked via SessionProgress
                assert_eq!(*entropy_consumed, 0);
            },
            _ => panic!("Expected Running state"),
        }
    }

    #[test]
    fn test_budget_exceeded_updates_consumed() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Record budget exceeded
        let exceeded_payload = helpers::budget_exceeded_payload("session-1", "TOKEN", 1000, 1500);
        let exceeded_event = create_event("policy.budget_exceeded", "session-1", exceeded_payload);
        reducer.apply(&exceeded_event, &ctx).unwrap();

        let state = reducer.state().get("session-1").unwrap();
        match state {
            SessionState::Running {
                error_count,
                entropy_consumed,
                ..
            } => {
                assert_eq!(*error_count, 1);
                assert_eq!(*entropy_consumed, 1500);
            },
            _ => panic!("Expected Running state"),
        }
    }

    #[test]
    fn test_budget_exceeded_timeout_type() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Record timeout budget exceeded
        let exceeded_payload =
            helpers::budget_exceeded_payload("session-1", "TIMEOUT", 60000, 75000);
        let exceeded_event = create_event("policy.budget_exceeded", "session-1", exceeded_payload);
        reducer.apply(&exceeded_event, &ctx).unwrap();

        let state = reducer.state().get("session-1").unwrap();
        match state {
            SessionState::Running {
                timeout_count,
                error_count,
                entropy_consumed,
                ..
            } => {
                assert_eq!(*timeout_count, 1);
                assert_eq!(*error_count, 0); // Timeout doesn't increment error count
                assert_eq!(*entropy_consumed, 75000);
            },
            _ => panic!("Expected Running state"),
        }
    }

    #[test]
    fn test_policy_violation_on_unknown_session_errors() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        let violation_payload = helpers::policy_violation_payload(
            "unknown-session",
            "UNAUTHORIZED_ACCESS",
            "rule-1",
            "test",
        );
        let violation_event =
            create_event("policy.violation", "unknown-session", violation_payload);
        let result = reducer.apply(&violation_event, &ctx);
        assert!(matches!(result, Err(SessionError::SessionNotFound { .. })));
    }

    #[test]
    fn test_policy_violation_on_terminated_session_errors() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start and terminate session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        let term_payload =
            helpers::session_terminated_payload("session-1", "SUCCESS", "completed", 500);
        let term_event = create_event("session.terminated", "session-1", term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        // Try to record violation on terminated session
        let violation_payload =
            helpers::policy_violation_payload("session-1", "UNAUTHORIZED_ACCESS", "rule-1", "test");
        let violation_event = create_event("policy.violation", "session-1", violation_payload);
        let result = reducer.apply(&violation_event, &ctx);
        assert!(matches!(
            result,
            Err(SessionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_entropy_exceeded_leads_to_termination() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session with small budget
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            100,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Simulate entropy consumption via SessionProgress events
        // (in real usage, the EntropyTracker emits progress events with updated
        // entropy)
        let progress_payload = helpers::session_progress_payload("session-1", 1, "VIOLATION", 150);
        let progress_event = create_event("session.progress", "session-1", progress_payload);
        reducer.apply(&progress_event, &ctx).unwrap();

        // Check entropy exceeded
        let state = reducer.state().get("session-1").unwrap();
        assert!(state.is_entropy_exceeded());

        // Terminate with ENTROPY_EXCEEDED classification
        let term_payload = helpers::session_terminated_payload(
            "session-1",
            "ENTROPY_EXCEEDED",
            "entropy_budget_exhausted",
            150,
        );
        let term_event = create_event("session.terminated", "session-1", term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        let final_state = reducer.state().get("session-1").unwrap();
        assert!(final_state.is_terminal());
        match final_state {
            SessionState::Terminated {
                exit_classification,
                ..
            } => {
                assert_eq!(*exit_classification, ExitClassification::EntropyExceeded);
            },
            _ => panic!("Expected Terminated state"),
        }
    }

    #[test]
    fn test_session_entropy_summary() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session
        let start_payload = helpers::session_started_payload(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Record violation (only increments count)
        let violation_payload =
            helpers::policy_violation_payload("session-1", "UNAUTHORIZED_ACCESS", "rule-1", "test");
        let violation_event = create_event("policy.violation", "session-1", violation_payload);
        reducer.apply(&violation_event, &ctx).unwrap();

        // Record entropy via SessionProgress
        let progress_payload = helpers::session_progress_payload("session-1", 1, "HEARTBEAT", 50);
        let progress_event = create_event("session.progress", "session-1", progress_payload);
        reducer.apply(&progress_event, &ctx).unwrap();

        let state = reducer.state().get("session-1").unwrap();
        let summary = state.entropy_summary("session-1").unwrap();

        assert_eq!(summary.session_id, "session-1");
        assert_eq!(summary.budget, 1000);
        assert_eq!(summary.consumed, 50);
        assert_eq!(summary.remaining, 950);
        assert!(!summary.is_exceeded);
        assert_eq!(summary.violation_count, 1);
    }
}
