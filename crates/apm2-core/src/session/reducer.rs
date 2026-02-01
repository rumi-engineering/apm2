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
    ///
    /// Allows session restart: if a session exists but is in a terminal state
    /// (Terminated or Quarantined), a new `SessionStarted` event can
    /// reinitialize it. This supports crash recovery scenarios where the
    /// same session ID is reused.
    ///
    /// **Monotonicity Enforcement**: When restarting a session, the new
    /// `restart_attempt` must be strictly greater than the previous attempt.
    /// This prevents replay attacks that could reset a session to a fresh
    /// state.
    fn handle_started(
        &mut self,
        event: crate::events::SessionStarted,
        timestamp: u64,
    ) -> Result<(), SessionError> {
        let session_id = event.session_id.clone();

        // Check if session already exists
        if let Some(existing) = self.state.sessions.get(&session_id) {
            // Allow restart only if session is in a terminal state
            if existing.is_active() {
                return Err(SessionError::SessionAlreadyExists { session_id });
            }

            // Enforce monotonicity: new restart_attempt must be > previous
            let last_attempt = existing.last_restart_attempt();
            if event.restart_attempt <= last_attempt {
                return Err(SessionError::RestartAttemptNotMonotonic {
                    session_id,
                    previous_attempt: last_attempt,
                    new_attempt: event.restart_attempt,
                });
            }
        }

        // Create new running state with restart tracking
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
            resume_cursor: event.resume_cursor,
            restart_attempt: event.restart_attempt,
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
        let (started_at, restart_attempt) = match current_state {
            SessionState::Running {
                started_at,
                restart_attempt,
                ..
            } => (*started_at, *restart_attempt),
            other => {
                return Err(SessionError::InvalidTransition {
                    from_state: other.state_name().to_string(),
                    event_type: "session.terminated".to_string(),
                });
            },
        };

        // Transition to Terminated state (preserving restart_attempt for monotonicity)
        let new_state = SessionState::Terminated {
            started_at,
            terminated_at: timestamp,
            exit_classification: ExitClassification::parse(&event.exit_classification),
            rationale_code: event.rationale_code,
            final_entropy: event.final_entropy,
            last_restart_attempt: restart_attempt,
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
        let (started_at, restart_attempt) = match current_state {
            SessionState::Running {
                started_at,
                restart_attempt,
                ..
            } => (*started_at, *restart_attempt),
            other => {
                return Err(SessionError::InvalidTransition {
                    from_state: other.state_name().to_string(),
                    event_type: "session.quarantined".to_string(),
                });
            },
        };

        // Transition to Quarantined state (preserving restart_attempt for monotonicity)
        // HTF tick fields (RFC-0016): authoritative for expiry when present
        let (issued_at_tick, expires_at_tick, tick_rate_hz) = if event.tick_rate_hz > 0 {
            (
                Some(event.issued_at_tick),
                Some(event.expires_at_tick),
                Some(event.tick_rate_hz),
            )
        } else {
            (None, None, None)
        };

        let new_state = SessionState::Quarantined {
            started_at,
            quarantined_at: timestamp,
            reason: event.reason,
            quarantine_until: event.quarantine_until,
            issued_at_tick,
            expires_at_tick,
            tick_rate_hz,
            last_restart_attempt: restart_attempt,
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

    /// Handles a session crash detected event.
    ///
    /// This event is informational - it records that a crash was detected
    /// but doesn't change session state (that's done by `restart_scheduled`
    /// or terminated events).
    fn handle_crash_detected(
        &self,
        event: &crate::events::SessionCrashDetected,
        _timestamp: u64,
    ) -> Result<(), SessionError> {
        let session_id = &event.session_id;

        // Verify session exists
        if !self.state.sessions.contains_key(session_id) {
            return Err(SessionError::SessionNotFound {
                session_id: session_id.clone(),
            });
        }

        // Crash detection is informational - state transitions happen via
        // SessionTerminated or SessionRestartScheduled events
        Ok(())
    }

    /// Handles a session restart scheduled event.
    ///
    /// This event is informational - it records that a restart has been
    /// scheduled but the actual restart happens via a new `SessionStarted`
    /// event.
    fn handle_restart_scheduled(
        &self,
        event: &crate::events::SessionRestartScheduled,
        _timestamp: u64,
    ) -> Result<(), SessionError> {
        let session_id = &event.session_id;

        // Verify session exists
        if !self.state.sessions.contains_key(session_id) {
            return Err(SessionError::SessionNotFound {
                session_id: session_id.clone(),
            });
        }

        // Restart scheduling is informational - the actual restart happens
        // via a new SessionStarted event with resume_cursor set
        Ok(())
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
                Some(session_event::Event::CrashDetected(ref e)) => {
                    self.handle_crash_detected(e, timestamp)
                },
                Some(session_event::Event::RestartScheduled(ref e)) => {
                    self.handle_restart_scheduled(e, timestamp)
                },
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
        BudgetExceeded, PolicyEvent, PolicyViolation, SessionCrashDetected, SessionEvent,
        SessionProgress, SessionQuarantined, SessionRestartScheduled, SessionStarted,
        SessionTerminated, policy_event, session_event,
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
        session_started_payload_with_restart(
            session_id,
            actor_id,
            adapter_type,
            work_id,
            lease_id,
            entropy_budget,
            0, // resume_cursor
            0, // restart_attempt
        )
    }

    /// Creates a `SessionStarted` event payload for a restarted session.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn session_started_payload_with_restart(
        session_id: &str,
        actor_id: &str,
        adapter_type: &str,
        work_id: &str,
        lease_id: &str,
        entropy_budget: u64,
        resume_cursor: u64,
        restart_attempt: u32,
    ) -> Vec<u8> {
        let started = SessionStarted {
            session_id: session_id.to_string(),
            actor_id: actor_id.to_string(),
            adapter_type: adapter_type.to_string(),
            work_id: work_id.to_string(),
            lease_id: lease_id.to_string(),
            entropy_budget,
            resume_cursor,
            restart_attempt,
            // HTF time envelope reference (RFC-0016): not yet populated by this helper.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
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
            // HTF time envelope reference (RFC-0016): not yet populated by this helper.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
        };
        let event = SessionEvent {
            event: Some(session_event::Event::Terminated(terminated)),
        };
        event.encode_to_vec()
    }

    /// Creates a `SessionQuarantined` event payload (legacy, wall-clock only).
    ///
    /// **DEPRECATED**: Use [`session_quarantined_payload_with_ticks`] for RFC-0016 HTF
    /// compliant quarantine events with tick-based timing.
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use session_quarantined_payload_with_ticks for tick-based timing (RFC-0016 HTF)"
    )]
    pub fn session_quarantined_payload(
        session_id: &str,
        reason: &str,
        quarantine_until: u64,
    ) -> Vec<u8> {
        let quarantined = SessionQuarantined {
            session_id: session_id.to_string(),
            reason: reason.to_string(),
            quarantine_until,
            // HTF fields (RFC-0016): not populated in legacy helper
            time_envelope_ref: None,
            issued_at_tick: 0,
            expires_at_tick: 0,
            tick_rate_hz: 0,
        };
        let event = SessionEvent {
            event: Some(session_event::Event::Quarantined(quarantined)),
        };
        event.encode_to_vec()
    }

    /// Creates a `SessionQuarantined` event payload with tick-based timing (RFC-0016 HTF).
    ///
    /// This is the preferred method for creating quarantine events as it uses
    /// monotonic ticks that are immune to wall-clock manipulation.
    #[must_use]
    pub fn session_quarantined_payload_with_ticks(
        session_id: &str,
        reason: &str,
        quarantine_until: u64,
        issued_at_tick: u64,
        expires_at_tick: u64,
        tick_rate_hz: u64,
    ) -> Vec<u8> {
        let quarantined = SessionQuarantined {
            session_id: session_id.to_string(),
            reason: reason.to_string(),
            quarantine_until,
            // HTF time envelope reference (RFC-0016): not yet populated by this helper.
            // The daemon clock service (TCK-00240) will stamp envelopes at runtime boundaries.
            time_envelope_ref: None,
            issued_at_tick,
            expires_at_tick,
            tick_rate_hz,
        };
        let event = SessionEvent {
            event: Some(session_event::Event::Quarantined(quarantined)),
        };
        event.encode_to_vec()
    }

    /// Creates a `SessionCrashDetected` event payload.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn session_crash_detected_payload(
        session_id: &str,
        crash_type: &str,
        exit_code: i32,
        signal: i32,
        uptime_ms: u64,
        last_cursor: u64,
        restart_count: u32,
    ) -> Vec<u8> {
        let crash = SessionCrashDetected {
            session_id: session_id.to_string(),
            crash_type: crash_type.to_string(),
            exit_code,
            signal,
            uptime_ms,
            last_cursor,
            restart_count,
        };
        let event = SessionEvent {
            event: Some(session_event::Event::CrashDetected(crash)),
        };
        event.encode_to_vec()
    }

    /// Creates a `SessionRestartScheduled` event payload.
    #[must_use]
    pub fn session_restart_scheduled_payload(
        session_id: &str,
        scheduled_at: u64,
        restart_at: u64,
        resume_cursor: u64,
        attempt_number: u32,
        backoff_type: &str,
    ) -> Vec<u8> {
        let restart = SessionRestartScheduled {
            session_id: session_id.to_string(),
            scheduled_at,
            restart_at,
            resume_cursor,
            attempt_number,
            backoff_type: backoff_type.to_string(),
        };
        let event = SessionEvent {
            event: Some(session_event::Event::RestartScheduled(restart)),
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
                ..
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
                ..
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

        // Try to start again while still running - should error
        let start_event2 = create_event("session.started", "session-1", start_payload);
        let result = reducer.apply(&start_event2, &ctx);
        assert!(matches!(
            result,
            Err(SessionError::SessionAlreadyExists { .. })
        ));
    }

    #[test]
    fn test_session_restart_after_termination() {
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
            helpers::session_terminated_payload("session-1", "FAILURE", "crashed", 500);
        let term_event = create_event("session.terminated", "session-1", term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        // Verify session is terminated
        assert!(reducer.state().get("session-1").unwrap().is_terminal());

        // Restart with same session ID - should succeed since it's terminal
        let restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500, // resume_cursor
            1,   // restart_attempt
        );
        let mut restart_event = create_event("session.started", "session-1", restart_payload);
        restart_event.timestamp_ns = 3_000_000_000;
        reducer.apply(&restart_event, &ctx).unwrap();

        // Verify session is running again with restart tracking
        let state = reducer.state().get("session-1").unwrap();
        assert!(state.is_active());
        match state {
            SessionState::Running {
                started_at,
                resume_cursor,
                restart_attempt,
                ..
            } => {
                assert_eq!(*started_at, 3_000_000_000);
                assert_eq!(*resume_cursor, 500);
                assert_eq!(*restart_attempt, 1);
            },
            _ => panic!("Expected Running state"),
        }
    }

    /// Tests that `restart_attempt` must be strictly monotonically increasing.
    /// Gemini security review requirement: `Start(0) -> Terminate -> Start(0)`
    /// should fail.
    #[test]
    fn test_restart_monotonicity() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start session with attempt=0
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
            helpers::session_terminated_payload("session-1", "FAILURE", "crashed", 500);
        let term_event = create_event("session.terminated", "session-1", term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        // Verify last_restart_attempt is preserved in Terminated state
        let state = reducer.state().get("session-1").unwrap();
        assert_eq!(state.last_restart_attempt(), 0);

        // Try to restart with same attempt (0) - should FAIL
        let bad_restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500, // resume_cursor
            0,   // restart_attempt (NOT greater than previous)
        );
        let bad_restart_event = create_event("session.started", "session-1", bad_restart_payload);
        let result = reducer.apply(&bad_restart_event, &ctx);
        assert!(matches!(
            result,
            Err(SessionError::RestartAttemptNotMonotonic { .. })
        ));

        // Restart with attempt=1 - should succeed
        let good_restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500, // resume_cursor
            1,   // restart_attempt (greater than previous 0)
        );
        let good_restart_event = create_event("session.started", "session-1", good_restart_payload);
        reducer.apply(&good_restart_event, &ctx).unwrap();

        // Session should be running now
        assert!(reducer.state().get("session-1").unwrap().is_active());
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

    // ========================================================================
    // Restart Monotonicity Boundary Tests (MAINT-009)
    // ========================================================================

    /// Helper to set up a session, terminate it, and return the reducer.
    fn setup_terminated_session(
        session_id: &str,
        initial_restart_attempt: u32,
    ) -> (SessionReducer, ReducerContext) {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        let start_payload = helpers::session_started_payload_with_restart(
            session_id,
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            0,
            initial_restart_attempt,
        );
        let start_event = create_event("session.started", session_id, start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        let term_payload =
            helpers::session_terminated_payload(session_id, "FAILURE", "crashed", 500);
        let term_event = create_event("session.terminated", session_id, term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        (reducer, ctx)
    }

    /// Tests `restart_attempt` 0 -> 0 transition MUST FAIL.
    #[test]
    fn test_restart_monotonicity_0_to_0_fails() {
        let (mut reducer, ctx) = setup_terminated_session("session-1", 0);

        let restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500,
            0, // same as previous
        );
        let restart_event = create_event("session.started", "session-1", restart_payload);
        let result = reducer.apply(&restart_event, &ctx);

        assert!(
            matches!(
                result,
                Err(SessionError::RestartAttemptNotMonotonic {
                    previous_attempt: 0,
                    new_attempt: 0,
                    ..
                })
            ),
            "restart_attempt 0 -> 0 should fail"
        );
    }

    /// Tests `restart_attempt` 0 -> 1 transition MUST succeed.
    #[test]
    fn test_restart_monotonicity_0_to_1_succeeds() {
        let (mut reducer, ctx) = setup_terminated_session("session-1", 0);

        let restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500,
            1, // greater than previous
        );
        let restart_event = create_event("session.started", "session-1", restart_payload);
        let result = reducer.apply(&restart_event, &ctx);

        assert!(result.is_ok(), "restart_attempt 0 -> 1 should succeed");
        let state = reducer.state().get("session-1").unwrap();
        assert!(state.is_active());
        assert_eq!(state.last_restart_attempt(), 1);
    }

    /// Tests `restart_attempt` 5 -> 5 transition MUST FAIL.
    #[test]
    fn test_restart_monotonicity_5_to_5_fails() {
        let (mut reducer, ctx) = setup_terminated_session("session-1", 5);

        let restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500,
            5, // same as previous
        );
        let restart_event = create_event("session.started", "session-1", restart_payload);
        let result = reducer.apply(&restart_event, &ctx);

        assert!(
            matches!(
                result,
                Err(SessionError::RestartAttemptNotMonotonic {
                    previous_attempt: 5,
                    new_attempt: 5,
                    ..
                })
            ),
            "restart_attempt 5 -> 5 should fail"
        );
    }

    /// Tests `restart_attempt` 5 -> 6 transition MUST succeed.
    #[test]
    fn test_restart_monotonicity_5_to_6_succeeds() {
        let (mut reducer, ctx) = setup_terminated_session("session-1", 5);

        let restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500,
            6, // greater than previous
        );
        let restart_event = create_event("session.started", "session-1", restart_payload);
        let result = reducer.apply(&restart_event, &ctx);

        assert!(result.is_ok(), "restart_attempt 5 -> 6 should succeed");
        let state = reducer.state().get("session-1").unwrap();
        assert!(state.is_active());
        assert_eq!(state.last_restart_attempt(), 6);
    }

    /// Tests `restart_attempt` `u32::MAX` -> any transition MUST FAIL (overflow
    /// protection).
    #[test]
    fn test_restart_monotonicity_max_overflow_protection() {
        let (mut reducer, ctx) = setup_terminated_session("session-1", u32::MAX);

        // Verify last_restart_attempt is u32::MAX in terminated state
        let state = reducer.state().get("session-1").unwrap();
        assert_eq!(state.last_restart_attempt(), u32::MAX);

        // Try to restart with u32::MAX again - MUST FAIL
        let restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500,
            u32::MAX,
        );
        let restart_event = create_event("session.started", "session-1", restart_payload);
        let result = reducer.apply(&restart_event, &ctx);

        assert!(
            matches!(
                result,
                Err(SessionError::RestartAttemptNotMonotonic {
                    previous_attempt,
                    new_attempt,
                    ..
                }) if previous_attempt == u32::MAX && new_attempt == u32::MAX
            ),
            "restart_attempt u32::MAX -> u32::MAX should fail"
        );

        // Also test with 0 - should still fail (0 is not > u32::MAX)
        let restart_zero = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            500,
            0,
        );
        let restart_event_zero = create_event("session.started", "session-1", restart_zero);
        let result_zero = reducer.apply(&restart_event_zero, &ctx);

        assert!(
            matches!(
                result_zero,
                Err(SessionError::RestartAttemptNotMonotonic { .. })
            ),
            "restart_attempt u32::MAX -> 0 should fail"
        );
    }

    /// Tests that Terminated state preserves `last_restart_attempt` and error
    /// context.
    #[test]
    fn test_restart_preserves_terminated_state_data() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start with restart_attempt=3 and resume_cursor=1000
        let start_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            1000, // resume_cursor
            3,    // restart_attempt
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Verify Running state has correct resume_cursor and restart_attempt
        let running_state = reducer.state().get("session-1").unwrap();
        match running_state {
            SessionState::Running {
                resume_cursor,
                restart_attempt,
                ..
            } => {
                assert_eq!(*resume_cursor, 1000);
                assert_eq!(*restart_attempt, 3);
            },
            _ => panic!("Expected Running state"),
        }

        // Terminate with specific error context
        let term_payload =
            helpers::session_terminated_payload("session-1", "FAILURE", "crash_loop_detected", 750);
        let term_event = create_event("session.terminated", "session-1", term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        // Verify Terminated state preserves all data
        let term_state = reducer.state().get("session-1").unwrap();
        match term_state {
            SessionState::Terminated {
                last_restart_attempt,
                rationale_code,
                final_entropy,
                exit_classification,
                ..
            } => {
                assert_eq!(*last_restart_attempt, 3);
                assert_eq!(rationale_code, "crash_loop_detected");
                assert_eq!(*final_entropy, 750);
                assert_eq!(*exit_classification, ExitClassification::Failure);
            },
            _ => panic!("Expected Terminated state"),
        }
    }

    /// Tests that Quarantined state preserves `last_restart_attempt` and
    /// reason.
    #[test]
    fn test_restart_preserves_quarantined_state_data() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start with restart_attempt=7
        let start_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            2000, // resume_cursor
            7,    // restart_attempt
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Quarantine the session
        let quar_payload = helpers::session_quarantined_payload(
            "session-1",
            "excessive_policy_violations",
            5_000_000_000,
        );
        let quar_event = create_event("session.quarantined", "session-1", quar_payload);
        reducer.apply(&quar_event, &ctx).unwrap();

        // Verify Quarantined state preserves all data
        let quar_state = reducer.state().get("session-1").unwrap();
        match quar_state {
            SessionState::Quarantined {
                last_restart_attempt,
                reason,
                quarantine_until,
                ..
            } => {
                assert_eq!(*last_restart_attempt, 7);
                assert_eq!(reason, "excessive_policy_violations");
                assert_eq!(*quarantine_until, 5_000_000_000);
            },
            _ => panic!("Expected Quarantined state"),
        }
    }

    /// Tests that restart correctly uses preserved `last_restart_attempt` for
    /// validation.
    #[test]
    fn test_restart_uses_preserved_last_restart_attempt() {
        let mut reducer = SessionReducer::new();
        let ctx = ReducerContext::new(1);

        // Start with restart_attempt=10
        let start_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            3000, // resume_cursor
            10,   // restart_attempt
        );
        let start_event = create_event("session.started", "session-1", start_payload);
        reducer.apply(&start_event, &ctx).unwrap();

        // Terminate
        let term_payload =
            helpers::session_terminated_payload("session-1", "FAILURE", "process_killed", 500);
        let term_event = create_event("session.terminated", "session-1", term_payload);
        reducer.apply(&term_event, &ctx).unwrap();

        // Verify we can read last_restart_attempt from terminated state
        let term_state = reducer.state().get("session-1").unwrap();
        let last_attempt = term_state.last_restart_attempt();
        assert_eq!(last_attempt, 10);

        // Restart with next attempt - should succeed
        let restart_payload = helpers::session_started_payload_with_restart(
            "session-1",
            "actor-1",
            "claude-code",
            "work-1",
            "lease-1",
            1000,
            3500,             // new resume_cursor
            last_attempt + 1, // restart_attempt = 11
        );
        let restart_event = create_event("session.started", "session-1", restart_payload);
        reducer.apply(&restart_event, &ctx).unwrap();

        // Verify new Running state has updated values
        let new_state = reducer.state().get("session-1").unwrap();
        match new_state {
            SessionState::Running {
                resume_cursor,
                restart_attempt,
                ..
            } => {
                assert_eq!(*resume_cursor, 3500);
                assert_eq!(*restart_attempt, 11);
            },
            _ => panic!("Expected Running state after restart"),
        }
    }
}
