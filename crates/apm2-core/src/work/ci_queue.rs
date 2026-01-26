//! CI-gated queue processor for work item phase transitions.
//!
//! This module processes `CIWorkflowCompleted` events and triggers phase
//! transitions for work items waiting on CI completion.
//!
//! # CI Gating
//!
//! When CI events are enabled and matched to work items by PR number, this
//! processor:
//!
//! 1. Looks up the work item associated with the PR number
//! 2. Verifies the work item is in `CiPending` state
//! 3. Transitions the work item based on CI conclusion:
//!    - `Success` → `ReadyForReview`
//!    - `Failure` → `Blocked`
//! 4. Emits a `WorkReadyForNextPhase` event to record the transition
//!
//! # Feature Flag
//!
//! Processing is gated behind the `CI_GATED_QUEUE_ENABLED` environment variable
//! (fail-closed by default).
//!
//! # Contracts
//!
//! - [CTR-CIQ001] Work items must be in `CiPending` state to be transitioned.
//! - [CTR-CIQ002] Only one work item per PR number at a time.
//! - [CTR-CIQ003] Transitions are idempotent (duplicate events are skipped).
//! - [CTR-CIQ004] `WorkReadyForNextPhase` events are emitted for all transitions.

use uuid::Uuid;

use super::state::WorkState;
use crate::events::ci::{
    CIConclusion, CIGatedQueueConfig, CIWorkflowCompleted, WorkReadyForNextPhase,
};

/// Result of processing a CI workflow completion event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiQueueProcessResult {
    /// The work item was successfully transitioned.
    Transitioned {
        /// The work item ID that was transitioned.
        work_id: String,
        /// The previous phase.
        previous_phase: WorkState,
        /// The new phase.
        next_phase: WorkState,
        /// The emitted `WorkReadyForNextPhase` event.
        event: WorkReadyForNextPhase,
    },

    /// No work item was found for the PR number.
    NoWorkItem {
        /// The PR number from the CI event.
        pr_number: u64,
    },

    /// The work item was not in `CiPending` state.
    NotInCiPending {
        /// The work item ID.
        work_id: String,
        /// The current state of the work item.
        current_state: WorkState,
    },

    /// CI-gated queue processing is disabled.
    Disabled,

    /// The CI event had no PR numbers.
    NoPrNumbers,
}

/// Determines the target phase for a work item based on CI conclusion.
///
/// # CI Gating
///
/// - `Success` → `ReadyForReview`: CI passed, work is ready for review.
/// - `Failure` → `Blocked`: CI failed, work needs attention.
/// - `Cancelled` → `Blocked`: CI was cancelled, treat as failure.
#[must_use]
pub const fn target_phase_for_conclusion(conclusion: CIConclusion) -> WorkState {
    match conclusion {
        CIConclusion::Success => WorkState::ReadyForReview,
        CIConclusion::Failure | CIConclusion::Cancelled => WorkState::Blocked,
    }
}

/// Processes a CI workflow completion event for a single work item.
///
/// This is the core logic for the CI-gated queue processor. It:
///
/// 1. Checks if the feature flag is enabled
/// 2. Verifies the event has PR numbers
/// 3. Looks up the work item by PR number
/// 4. Validates the work item is in `CiPending` state
/// 5. Creates the transition event
///
/// # Arguments
///
/// * `event` - The `CIWorkflowCompleted` event to process.
/// * `config` - Feature flag configuration.
/// * `lookup_work_by_pr` - Function to look up work item by PR number.
///
/// # Returns
///
/// A `CiQueueProcessResult` indicating the outcome.
pub fn process_ci_event<F>(
    event: &CIWorkflowCompleted,
    config: &CIGatedQueueConfig,
    lookup_work_by_pr: F,
) -> CiQueueProcessResult
where
    F: FnOnce(u64) -> Option<(String, WorkState)>,
{
    // Check feature flag
    if !config.enabled {
        return CiQueueProcessResult::Disabled;
    }

    // Get the first PR number (we only support one work item per PR)
    let Some(&pr_number) = event.payload.pr_numbers.first() else {
        return CiQueueProcessResult::NoPrNumbers;
    };

    // Look up work item by PR number
    let Some((work_id, current_state)) = lookup_work_by_pr(pr_number) else {
        return CiQueueProcessResult::NoWorkItem { pr_number };
    };

    // Verify work item is in CiPending state [CTR-CIQ001]
    if current_state != WorkState::CiPending {
        return CiQueueProcessResult::NotInCiPending {
            work_id,
            current_state,
        };
    }

    // Determine target phase based on CI conclusion
    let next_phase = target_phase_for_conclusion(event.payload.conclusion);

    // Create the transition event [CTR-CIQ004]
    let transition_event = WorkReadyForNextPhase::new(
        work_id.clone(),
        current_state.as_str().to_string(),
        next_phase.as_str().to_string(),
        event.event_id,
    );

    CiQueueProcessResult::Transitioned {
        work_id,
        previous_phase: current_state,
        next_phase,
        event: transition_event,
    }
}

/// Validates that a work item can be transitioned from CI completion.
///
/// # Arguments
///
/// * `current_state` - The current state of the work item.
///
/// # Returns
///
/// `true` if the work item can be transitioned by CI completion.
#[must_use]
pub const fn can_transition_from_ci(current_state: WorkState) -> bool {
    matches!(current_state, WorkState::CiPending)
}

/// Builder for constructing work transition events from the reducer.
///
/// This builder creates protobuf-compatible transition payloads that can be
/// applied to the work reducer.
pub struct CiTransitionBuilder {
    work_id: String,
    from_state: WorkState,
    to_state: WorkState,
    triggered_by: Uuid,
}

impl CiTransitionBuilder {
    /// Creates a new transition builder.
    #[must_use]
    pub const fn new(work_id: String, from_state: WorkState, to_state: WorkState, triggered_by: Uuid) -> Self {
        Self {
            work_id,
            from_state,
            to_state,
            triggered_by,
        }
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the from state.
    #[must_use]
    pub const fn from_state(&self) -> WorkState {
        self.from_state
    }

    /// Returns the to state.
    #[must_use]
    pub const fn to_state(&self) -> WorkState {
        self.to_state
    }

    /// Returns the ID of the CI event that triggered this transition.
    #[must_use]
    pub const fn triggered_by(&self) -> Uuid {
        self.triggered_by
    }

    /// Builds a rationale code for the transition.
    #[must_use]
    pub fn rationale_code(&self) -> String {
        match self.to_state {
            WorkState::ReadyForReview => "ci_passed".to_string(),
            WorkState::Blocked => "ci_failed".to_string(),
            _ => "ci_transition".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::events::ci::CIWorkflowPayload;

    fn sample_ci_event(conclusion: CIConclusion, pr_numbers: Vec<u64>) -> CIWorkflowCompleted {
        CIWorkflowCompleted::with_timestamp(
            CIWorkflowPayload {
                pr_numbers,
                commit_sha: "abc123".to_string(),
                conclusion,
                workflow_name: "CI".to_string(),
                workflow_run_id: 12345,
                checks: vec![],
            },
            true,
            "delivery-123".to_string(),
            Utc::now(),
        )
    }

    #[test]
    fn test_target_phase_for_success() {
        assert_eq!(
            target_phase_for_conclusion(CIConclusion::Success),
            WorkState::ReadyForReview
        );
    }

    #[test]
    fn test_target_phase_for_failure() {
        assert_eq!(
            target_phase_for_conclusion(CIConclusion::Failure),
            WorkState::Blocked
        );
    }

    #[test]
    fn test_target_phase_for_cancelled() {
        assert_eq!(
            target_phase_for_conclusion(CIConclusion::Cancelled),
            WorkState::Blocked
        );
    }

    #[test]
    fn test_process_ci_event_disabled() {
        let event = sample_ci_event(CIConclusion::Success, vec![42]);
        let config = CIGatedQueueConfig::disabled();

        let result = process_ci_event(&event, &config, |_| None);

        assert_eq!(result, CiQueueProcessResult::Disabled);
    }

    #[test]
    fn test_process_ci_event_no_pr_numbers() {
        let event = sample_ci_event(CIConclusion::Success, vec![]);
        let config = CIGatedQueueConfig::enabled();

        let result = process_ci_event(&event, &config, |_| None);

        assert_eq!(result, CiQueueProcessResult::NoPrNumbers);
    }

    #[test]
    fn test_process_ci_event_no_work_item() {
        let event = sample_ci_event(CIConclusion::Success, vec![42]);
        let config = CIGatedQueueConfig::enabled();

        let result = process_ci_event(&event, &config, |_| None);

        assert_eq!(result, CiQueueProcessResult::NoWorkItem { pr_number: 42 });
    }

    #[test]
    fn test_process_ci_event_not_in_ci_pending() {
        let event = sample_ci_event(CIConclusion::Success, vec![42]);
        let config = CIGatedQueueConfig::enabled();

        let result = process_ci_event(&event, &config, |_| {
            Some(("work-123".to_string(), WorkState::InProgress))
        });

        assert_eq!(
            result,
            CiQueueProcessResult::NotInCiPending {
                work_id: "work-123".to_string(),
                current_state: WorkState::InProgress,
            }
        );
    }

    #[test]
    fn test_process_ci_event_success_transition() {
        let event = sample_ci_event(CIConclusion::Success, vec![42]);
        let config = CIGatedQueueConfig::enabled();

        let result = process_ci_event(&event, &config, |pr| {
            if pr == 42 {
                Some(("work-123".to_string(), WorkState::CiPending))
            } else {
                None
            }
        });

        match result {
            CiQueueProcessResult::Transitioned {
                work_id,
                previous_phase,
                next_phase,
                event: transition_event,
            } => {
                assert_eq!(work_id, "work-123");
                assert_eq!(previous_phase, WorkState::CiPending);
                assert_eq!(next_phase, WorkState::ReadyForReview);
                assert_eq!(transition_event.work_id, "work-123");
                assert_eq!(transition_event.previous_phase, "CI_PENDING");
                assert_eq!(transition_event.next_phase, "READY_FOR_REVIEW");
            },
            other => panic!("Expected Transitioned, got {other:?}"),
        }
    }

    #[test]
    fn test_process_ci_event_failure_transition() {
        let event = sample_ci_event(CIConclusion::Failure, vec![42]);
        let config = CIGatedQueueConfig::enabled();

        let result = process_ci_event(&event, &config, |_| {
            Some(("work-123".to_string(), WorkState::CiPending))
        });

        match result {
            CiQueueProcessResult::Transitioned {
                next_phase, ..
            } => {
                assert_eq!(next_phase, WorkState::Blocked);
            },
            other => panic!("Expected Transitioned, got {other:?}"),
        }
    }

    #[test]
    fn test_can_transition_from_ci() {
        assert!(can_transition_from_ci(WorkState::CiPending));
        assert!(!can_transition_from_ci(WorkState::Open));
        assert!(!can_transition_from_ci(WorkState::Claimed));
        assert!(!can_transition_from_ci(WorkState::InProgress));
        assert!(!can_transition_from_ci(WorkState::ReadyForReview));
        assert!(!can_transition_from_ci(WorkState::Blocked));
        assert!(!can_transition_from_ci(WorkState::Review));
        assert!(!can_transition_from_ci(WorkState::Completed));
        assert!(!can_transition_from_ci(WorkState::Aborted));
    }

    #[test]
    fn test_ci_transition_builder() {
        let triggered_by = Uuid::new_v4();
        let builder = CiTransitionBuilder::new(
            "work-123".to_string(),
            WorkState::CiPending,
            WorkState::ReadyForReview,
            triggered_by,
        );

        assert_eq!(builder.work_id(), "work-123");
        assert_eq!(builder.from_state(), WorkState::CiPending);
        assert_eq!(builder.to_state(), WorkState::ReadyForReview);
        assert_eq!(builder.triggered_by(), triggered_by);
        assert_eq!(builder.rationale_code(), "ci_passed");
    }

    #[test]
    fn test_ci_transition_builder_blocked() {
        let triggered_by = Uuid::new_v4();
        let builder = CiTransitionBuilder::new(
            "work-456".to_string(),
            WorkState::CiPending,
            WorkState::Blocked,
            triggered_by,
        );

        assert_eq!(builder.rationale_code(), "ci_failed");
    }
}
