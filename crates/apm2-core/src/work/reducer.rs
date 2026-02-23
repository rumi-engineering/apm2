//! Work lifecycle reducer implementation.

use std::collections::HashMap;

use prost::Message;
use serde::{Deserialize, Serialize};

use super::error::WorkError;
use super::state::{Work, WorkState, WorkType};
use crate::events::{WorkEvent, work_event};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

/// The designated actor ID for the CI system processor.
///
/// Only events signed by this actor can transition work items from CI-gated
/// states (`CiPending`). This prevents arbitrary agents from bypassing CI
/// gating by emitting `WorkTransitioned` events.
///
/// # Security
///
/// This constant defines the system-level identity that the CI event processor
/// must use when signing transition events. The value uses a `system:` prefix
/// to distinguish it from regular agent identities.
pub const CI_SYSTEM_ACTOR_ID: &str = "system:ci-processor";

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

    /// Returns the work item associated with a PR number, if any.
    ///
    /// # CI Gating
    ///
    /// This method is used to match `CIWorkflowCompleted` events to work items
    /// for phase transitions.
    #[must_use]
    pub fn by_pr_number(&self, pr_number: u64) -> Option<&Work> {
        self.work_items
            .values()
            .find(|w| w.pr_number == Some(pr_number))
    }

    /// Returns all work items in CI-gated states (`CiPending` or `Blocked`).
    ///
    /// # CI Gating
    ///
    /// These work items are waiting for CI events to trigger phase transitions.
    #[must_use]
    pub fn ci_gated_work(&self) -> Vec<&Work> {
        self.work_items
            .values()
            .filter(|w| {
                matches!(
                    w.state,
                    crate::work::WorkState::CiPending | crate::work::WorkState::Blocked
                )
            })
            .collect()
    }

    /// Returns all work items that are claimable (`Open` or `ReadyForReview`).
    ///
    /// # CI Gating
    ///
    /// Only these work items can be claimed by agents. Work items in
    /// `CiPending` or `Blocked` states cannot be claimed.
    #[must_use]
    pub fn claimable_work(&self) -> Vec<&Work> {
        self.work_items
            .values()
            .filter(|w| w.state.is_claimable())
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
    ///
    /// # Arguments
    ///
    /// * `event` - The transition event payload
    /// * `timestamp` - Event timestamp
    /// * `actor_id` - The actor ID from the event record (signer identity)
    fn handle_transitioned(
        &mut self,
        event: crate::events::WorkTransitioned,
        timestamp: u64,
        actor_id: &str,
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

        // Security check: CI-gated transitions require both:
        // 1. Authorized rationale codes (ci_passed/ci_failed)
        // 2. Authorized actor ID (system:ci-processor)
        // This prevents agents from bypassing CI gating by directly emitting
        // WorkTransitioned events.
        if from_state == WorkState::CiPending {
            // Check rationale code
            let rationale = &event.rationale_code;
            if rationale != "ci_passed" && rationale != "ci_failed" {
                return Err(WorkError::CiGatedTransitionUnauthorized {
                    from_state,
                    to_state,
                    rationale_code: rationale.clone(),
                });
            }

            // Check actor ID - only the CI system processor can sign these events
            if actor_id != CI_SYSTEM_ACTOR_ID {
                return Err(WorkError::CiGatedTransitionUnauthorizedActor {
                    from_state,
                    actor_id: actor_id.to_string(),
                });
            }
        }

        // Apply the transition
        work.state = to_state;
        work.last_transition_at = timestamp;
        work.transition_count += 1;
        work.last_rationale_code = event.rationale_code;

        // Record first claim timestamp (immutable once set).
        if to_state == WorkState::Claimed && work.claimed_at.is_none() {
            work.claimed_at = Some(timestamp);
        }

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

        // --- Domain separation: gate_receipt_id vs merge_receipt_id ---
        //
        // INV-0113 (fail-closed): gate_receipt_id MUST NOT contain a merge
        // receipt identifier.  Any value whose ASCII-lowercase form starts
        // with "merge-receipt-" is rejected.  Case-insensitive comparison
        // prevents bypass via case-variant prefixes (e.g. "MERGE-RECEIPT-",
        // "Merge-Receipt-").
        //
        // INV-0114 (positive allowlist): merge_receipt_id, when non-empty,
        // MUST start with "merge-receipt-" (case-insensitive).  This
        // prevents gate receipt identifiers from being injected into the
        // merge field.
        //
        // Together these two checks enforce bidirectional domain separation
        // at the reducer boundary.

        if event
            .gate_receipt_id
            .to_ascii_lowercase()
            .starts_with("merge-receipt-")
        {
            return Err(WorkError::MergeReceiptInGateReceiptField {
                work_id: work_id.clone(),
                value: event.gate_receipt_id,
            });
        }

        if !event.merge_receipt_id.is_empty()
            && !event
                .merge_receipt_id
                .to_ascii_lowercase()
                .starts_with("merge-receipt-")
        {
            return Err(WorkError::InvalidMergeReceiptId {
                work_id: work_id.clone(),
                value: event.merge_receipt_id,
            });
        }

        // Apply completion (all deny gates passed — safe to mutate)
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
        work.merge_receipt_id = if event.merge_receipt_id.is_empty() {
            None
        } else {
            Some(event.merge_receipt_id)
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

    /// Handles a work PR associated event.
    ///
    /// # CI Gating
    ///
    /// Associates a PR number with a work item, enabling CI event matching
    /// for phase transitions.
    ///
    /// # Security Constraints
    ///
    /// - **State Restriction**: PR association is only allowed when the work
    ///   item is in `Claimed` or `InProgress` state. This permits manual
    ///   operator-supervised push flows before explicit `InProgress`
    ///   transition, while still preventing CI-gating bypass from
    ///   `CiPending`/`Blocked` and terminal states.
    ///
    /// - **Uniqueness Constraint (CTR-CIQ002)**: A PR number cannot be
    ///   associated with a work item if it is already associated with another
    ///   active (non-terminal) work item. This prevents CI result confusion.
    fn handle_pr_associated(
        &mut self,
        event: &crate::events::WorkPrAssociated,
    ) -> Result<(), WorkError> {
        let work_id = &event.work_id;
        let pr_number = event.pr_number;
        let commit_sha = &event.commit_sha;

        // Security check: Verify PR number is not already associated with another
        // active work item (CTR-CIQ002 uniqueness constraint)
        if let Some(existing_work) = self
            .state
            .work_items
            .values()
            .find(|w| w.pr_number == Some(pr_number) && w.is_active() && w.work_id != *work_id)
        {
            return Err(WorkError::PrNumberAlreadyAssociated {
                pr_number,
                existing_work_id: existing_work.work_id.clone(),
            });
        }

        let work =
            self.state
                .work_items
                .get_mut(work_id)
                .ok_or_else(|| WorkError::WorkNotFound {
                    work_id: work_id.clone(),
                })?;

        // Security check: PR association only allowed from Claimed or
        // InProgress state.
        if !matches!(work.state, WorkState::Claimed | WorkState::InProgress) {
            return Err(WorkError::PrAssociationNotAllowed {
                work_id: work_id.clone(),
                current_state: work.state,
            });
        }

        // Set the PR number and commit SHA for CI event matching
        work.pr_number = Some(pr_number);
        work.commit_sha = Some(commit_sha.clone());

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
        let actor_id = &event.actor_id;

        match work_event.event {
            Some(work_event::Event::Opened(e)) => self.handle_opened(e, timestamp),
            Some(work_event::Event::Transitioned(e)) => {
                self.handle_transitioned(e, timestamp, actor_id)
            },
            Some(work_event::Event::Completed(e)) => self.handle_completed(e, timestamp),
            Some(work_event::Event::Aborted(e)) => self.handle_aborted(e, timestamp),
            Some(work_event::Event::PrAssociated(ref e)) => self.handle_pr_associated(e),
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
        WorkAborted, WorkCompleted, WorkEvent, WorkOpened, WorkPrAssociated, WorkTransitioned,
        work_event,
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

    /// Creates a `WorkTransitioned` event payload for the **first transition
    /// only**.
    ///
    /// This helper sets `previous_transition_count` to 0, which is only valid
    /// for the first transition from the Open state (where `transition_count`
    /// is 0).
    ///
    /// For subsequent transitions, use
    /// [`work_transitioned_payload_with_sequence`] with the work item's
    /// current `transition_count`.
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
    ///
    /// # Parameters
    ///
    /// * `gate_receipt_id` - ID of the gate receipt that authorized this
    ///   completion.  Must NOT contain a merge receipt identifier (values
    ///   starting with `merge-receipt-` are rejected at the reducer level per
    ///   INV-0113).
    /// * `merge_receipt_id` - Dedicated merge receipt identifier populated when
    ///   work completes via the merge executor.  When non-empty, MUST start
    ///   with `merge-receipt-` (positive allowlist per INV-0114).  Pass `""`
    ///   when no merge receipt is involved.
    #[must_use]
    pub fn work_completed_payload(
        work_id: &str,
        evidence_bundle_hash: Vec<u8>,
        evidence_ids: Vec<String>,
        gate_receipt_id: &str,
        merge_receipt_id: &str,
    ) -> Vec<u8> {
        let completed = WorkCompleted {
            work_id: work_id.to_string(),
            evidence_bundle_hash,
            evidence_ids,
            gate_receipt_id: gate_receipt_id.to_string(),
            merge_receipt_id: merge_receipt_id.to_string(),
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

    /// Creates a `WorkPrAssociated` event payload.
    ///
    /// # CI Gating
    ///
    /// This event associates a PR number with a work item, enabling CI event
    /// matching for phase transitions. Should be emitted when an agent creates
    /// a PR for a work item.
    #[must_use]
    pub fn work_pr_associated_payload(work_id: &str, pr_number: u64, commit_sha: &str) -> Vec<u8> {
        let pr_associated = WorkPrAssociated {
            work_id: work_id.to_string(),
            pr_number,
            commit_sha: commit_sha.to_string(),
        };
        let event = WorkEvent {
            event: Some(work_event::Event::PrAssociated(pr_associated)),
        };
        event.encode_to_vec()
    }
}
