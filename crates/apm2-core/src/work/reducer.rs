//! Work lifecycle reducer implementation.

use std::collections::HashMap;

use prost::Message;
use serde::{Deserialize, Serialize};

use super::error::WorkError;
use super::state::{Work, WorkState, WorkType};
use crate::events::{WorkEvent, work_event};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

/// State maintained by the work reducer.
///
/// Maps work IDs to their current state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkReducerState {
    /// Map of work ID to work item.
    pub work_items: HashMap<String, Work>,
}

impl WorkReducerState {
    /// Creates a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of work items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.work_items.len()
    }

    /// Returns `true` if there are no work items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.work_items.is_empty()
    }

    /// Returns the work item for a given ID, if it exists.
    #[must_use]
    pub fn get(&self, work_id: &str) -> Option<&Work> {
        self.work_items.get(work_id)
    }

    /// Returns the number of active (non-terminal) work items.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.work_items.values().filter(|w| w.is_active()).count()
    }

    /// Returns the number of completed work items.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.work_items
            .values()
            .filter(|w| w.state == WorkState::Completed)
            .count()
    }

    /// Returns the number of aborted work items.
    #[must_use]
    pub fn aborted_count(&self) -> usize {
        self.work_items
            .values()
            .filter(|w| w.state == WorkState::Aborted)
            .count()
    }

    /// Returns all work items in a specific state.
    #[must_use]
    pub fn in_state(&self, state: WorkState) -> Vec<&Work> {
        self.work_items
            .values()
            .filter(|w| w.state == state)
            .collect()
    }

    /// Returns all active work items (non-terminal states).
    #[must_use]
    pub fn active_work(&self) -> Vec<&Work> {
        self.work_items.values().filter(|w| w.is_active()).collect()
    }

    /// Returns work items by requirement ID.
    #[must_use]
    pub fn by_requirement(&self, requirement_id: &str) -> Vec<&Work> {
        self.work_items
            .values()
            .filter(|w| w.requirement_ids.contains(&requirement_id.to_string()))
            .collect()
    }
}

/// Reducer for work lifecycle events.
///
/// Processes work events and maintains the state of all work items.
/// Implements the state machine:
///
/// ```text
/// (none) --WorkOpened--> Open
/// Open --WorkTransitioned--> Claimed
/// Claimed --WorkTransitioned--> InProgress | Open
/// InProgress --WorkTransitioned--> Review | NeedsInput | NeedsAdjudication
/// Review --WorkTransitioned--> InProgress
/// Review --WorkCompleted--> Completed
/// Any active --WorkAborted--> Aborted
/// ```
#[derive(Debug, Default)]
pub struct WorkReducer {
    state: WorkReducerState,
}

impl WorkReducer {
    /// Creates a new work reducer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles a work opened event.
    fn handle_opened(
        &mut self,
        event: crate::events::WorkOpened,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let work_id = event.work_id.clone();

        // Check if work already exists
        if self.state.work_items.contains_key(&work_id) {
            return Err(WorkError::WorkAlreadyExists { work_id });
        }

        // Strict parsing: reject unknown work types
        let work_type = WorkType::parse(&event.work_type)?;

        // Create new work item
        let work = Work::new(
            work_id.clone(),
            work_type,
            event.spec_snapshot_hash,
            event.requirement_ids,
            event.parent_work_ids,
            timestamp,
        );

        self.state.work_items.insert(work_id, work);
        Ok(())
    }

    /// Handles a work transitioned event.
    fn handle_transitioned(
        &mut self,
        event: crate::events::WorkTransitioned,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let work_id = &event.work_id;

        let work =
            self.state
                .work_items
                .get_mut(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Verify work is not in a terminal state
        if work.is_terminal() {
            return Err(WorkError::InvalidTransition {
                from_state: work.state.as_str().to_string(),
                event_type: "work.transitioned".to_string(),
            });
        }

        // Strict parsing: reject unknown states
        let from_state = WorkState::parse(&event.from_state)?;
        let to_state = WorkState::parse(&event.to_state)?;

        // Verify the from_state matches current state
        if work.state != from_state {
            return Err(WorkError::InvalidTransition {
                from_state: work.state.as_str().to_string(),
                event_type: format!(
                    "work.transitioned (expected from_state={}, got={})",
                    work.state.as_str(),
                    event.from_state
                ),
            });
        }

        // Replay protection: validate sequence via previous_transition_count
        // All transitions MUST provide the correct sequence to prevent replay attacks
        let expected_count = work.transition_count;
        if event.previous_transition_count != expected_count {
            return Err(WorkError::SequenceMismatch {
                work_id: work_id.clone(),
                expected: expected_count,
                actual: event.previous_transition_count,
            });
        }

        // Verify the transition is allowed
        if !from_state.can_transition_to(&to_state) {
            return Err(WorkError::TransitionNotAllowed {
                from_state,
                to_state,
            });
        }

        // Apply the transition
        work.state = to_state;
        work.last_transition_at = timestamp;
        work.transition_count += 1;
        work.last_rationale_code = event.rationale_code;

        Ok(())
    }

    /// Handles a work completed event.
    fn handle_completed(
        &mut self,
        event: crate::events::WorkCompleted,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let work_id = &event.work_id;

        let work =
            self.state
                .work_items
                .get_mut(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Can only complete from Review state
        if work.state != WorkState::Review {
            return Err(WorkError::InvalidTransition {
                from_state: work.state.as_str().to_string(),
                event_type: "work.completed".to_string(),
            });
        }

        // Must have evidence
        if event.evidence_ids.is_empty() && event.evidence_bundle_hash.is_empty() {
            return Err(WorkError::CompletionWithoutEvidence {
                work_id: work_id.clone(),
            });
        }

        // Apply completion
        work.state = WorkState::Completed;
        work.last_transition_at = timestamp;
        work.transition_count += 1;
        work.evidence_bundle_hash = Some(event.evidence_bundle_hash);
        work.evidence_ids = event.evidence_ids;
        work.gate_receipt_id = if event.gate_receipt_id.is_empty() {
            None
        } else {
            Some(event.gate_receipt_id)
        };

        Ok(())
    }

    /// Handles a work aborted event.
    fn handle_aborted(
        &mut self,
        event: crate::events::WorkAborted,
        timestamp: u64,
    ) -> Result<(), WorkError> {
        let work_id = &event.work_id;

        let work =
            self.state
                .work_items
                .get_mut(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Cannot abort already terminal work
        if work.is_terminal() {
            return Err(WorkError::InvalidTransition {
                from_state: work.state.as_str().to_string(),
                event_type: "work.aborted".to_string(),
            });
        }

        // Apply abort
        work.state = WorkState::Aborted;
        work.last_transition_at = timestamp;
        work.transition_count += 1;
        work.abort_reason = Some(event.abort_reason);
        work.last_rationale_code = event.rationale_code;

        Ok(())
    }
}

impl Reducer for WorkReducer {
    type State = WorkReducerState;
    type Error = WorkError;

    fn name(&self) -> &'static str {
        "work-lifecycle"
    }

    fn apply(&mut self, event: &EventRecord, _ctx: &ReducerContext) -> Result<(), Self::Error> {
        // Only handle work events
        if !event.event_type.starts_with("work.") {
            return Ok(());
        }

        let work_event = WorkEvent::decode(&event.payload[..])?;
        let timestamp = event.timestamp_ns;

        match work_event.event {
            Some(work_event::Event::Opened(e)) => self.handle_opened(e, timestamp),
            Some(work_event::Event::Transitioned(e)) => self.handle_transitioned(e, timestamp),
            Some(work_event::Event::Completed(e)) => self.handle_completed(e, timestamp),
            Some(work_event::Event::Aborted(e)) => self.handle_aborted(e, timestamp),
            None => Ok(()),
        }
    }

    fn state(&self) -> &Self::State {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::State {
        &mut self.state
    }

    fn reset(&mut self) {
        self.state = WorkReducerState::default();
    }
}

/// Helper functions for creating work event payloads.
pub mod helpers {
    use prost::Message;

    use crate::events::{
        WorkAborted, WorkCompleted, WorkEvent, WorkOpened, WorkTransitioned, work_event,
    };

    /// Creates a `WorkOpened` event payload.
    #[must_use]
    pub fn work_opened_payload(
        work_id: &str,
        work_type: &str,
        spec_snapshot_hash: Vec<u8>,
        requirement_ids: Vec<String>,
        parent_work_ids: Vec<String>,
    ) -> Vec<u8> {
        let opened = WorkOpened {
            work_id: work_id.to_string(),
            work_type: work_type.to_string(),
            spec_snapshot_hash,
            requirement_ids,
            parent_work_ids,
        };
        let event = WorkEvent {
            event: Some(work_event::Event::Opened(opened)),
        };
        event.encode_to_vec()
    }

    /// Creates a `WorkTransitioned` event payload.
    ///
    /// Set `previous_transition_count` to the work item's current
    /// `transition_count` for replay protection, or 0 to skip validation
    /// (backward compatibility).
    #[must_use]
    pub fn work_transitioned_payload(
        work_id: &str,
        from_state: &str,
        to_state: &str,
        rationale_code: &str,
    ) -> Vec<u8> {
        work_transitioned_payload_with_sequence(work_id, from_state, to_state, rationale_code, 0)
    }

    /// Creates a `WorkTransitioned` event payload with explicit sequence
    /// validation.
    ///
    /// # Arguments
    ///
    /// * `previous_transition_count` - The expected `transition_count` of the
    ///   work item before this transition. Used for replay protection.
    #[must_use]
    pub fn work_transitioned_payload_with_sequence(
        work_id: &str,
        from_state: &str,
        to_state: &str,
        rationale_code: &str,
        previous_transition_count: u32,
    ) -> Vec<u8> {
        let transitioned = WorkTransitioned {
            work_id: work_id.to_string(),
            from_state: from_state.to_string(),
            to_state: to_state.to_string(),
            rationale_code: rationale_code.to_string(),
            previous_transition_count,
        };
        let event = WorkEvent {
            event: Some(work_event::Event::Transitioned(transitioned)),
        };
        event.encode_to_vec()
    }

    /// Creates a `WorkCompleted` event payload.
    #[must_use]
    pub fn work_completed_payload(
        work_id: &str,
        evidence_bundle_hash: Vec<u8>,
        evidence_ids: Vec<String>,
        gate_receipt_id: &str,
    ) -> Vec<u8> {
        let completed = WorkCompleted {
            work_id: work_id.to_string(),
            evidence_bundle_hash,
            evidence_ids,
            gate_receipt_id: gate_receipt_id.to_string(),
        };
        let event = WorkEvent {
            event: Some(work_event::Event::Completed(completed)),
        };
        event.encode_to_vec()
    }

    /// Creates a `WorkAborted` event payload.
    #[must_use]
    pub fn work_aborted_payload(
        work_id: &str,
        abort_reason: &str,
        rationale_code: &str,
    ) -> Vec<u8> {
        let aborted = WorkAborted {
            work_id: work_id.to_string(),
            abort_reason: abort_reason.to_string(),
            rationale_code: rationale_code.to_string(),
        };
        let event = WorkEvent {
            event: Some(work_event::Event::Aborted(aborted)),
        };
        event.encode_to_vec()
    }
}
