//! Work state types and transitions.

use serde::{Deserialize, Serialize};

use super::error::WorkError;

/// The type of work being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkType {
    /// Implementation of a specific ticket.
    Ticket,
    /// PRD refinement task.
    PrdRefinement,
    /// RFC refinement task.
    RfcRefinement,
    /// Code or artifact review.
    Review,
}

impl WorkType {
    /// Parses a work type from a string.
    ///
    /// # Errors
    ///
    /// Returns `WorkError::InvalidWorkType` if the string is not a recognized
    /// work type.
    pub fn parse(s: &str) -> Result<Self, WorkError> {
        match s.to_uppercase().as_str() {
            "TICKET" => Ok(Self::Ticket),
            "PRD_REFINEMENT" => Ok(Self::PrdRefinement),
            "RFC_REFINEMENT" => Ok(Self::RfcRefinement),
            "REVIEW" => Ok(Self::Review),
            _ => Err(WorkError::InvalidWorkType {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the string representation of this work type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ticket => "TICKET",
            Self::PrdRefinement => "PRD_REFINEMENT",
            Self::RfcRefinement => "RFC_REFINEMENT",
            Self::Review => "REVIEW",
        }
    }
}

/// The lifecycle state of a work item.
///
/// # Discriminant Stability
///
/// Explicit discriminant values are used to maintain semver compatibility.
/// New variants MUST be assigned new discriminant values; existing variants
/// MUST NOT have their discriminants changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[repr(u8)]
pub enum WorkState {
    /// Work is open and available for claiming.
    Open              = 0,
    /// Work has been claimed by an agent.
    Claimed           = 1,
    /// Work is actively being processed.
    InProgress        = 2,
    /// Work is under review.
    Review            = 3,
    /// Work is blocked waiting for input.
    NeedsInput        = 4,
    /// Work requires adjudication (human decision).
    NeedsAdjudication = 5,
    /// Work has been successfully completed.
    Completed         = 6,
    /// Work has been aborted.
    Aborted           = 7,
    /// Work is waiting for CI completion (not claimable).
    ///
    /// # CI Gating
    ///
    /// Work enters this state when a PR has been created and CI is running.
    /// Agents cannot claim work in this state. The work will transition to
    /// `ReadyForReview` (CI success) or `Blocked` (CI failure) based on
    /// `CIWorkflowCompleted` events.
    CiPending         = 8,
    /// Work is ready for review after CI passed (claimable).
    ///
    /// # CI Gating
    ///
    /// Work enters this state after `CIWorkflowCompleted` with `Success`
    /// conclusion. Review agents can claim work in this state.
    ReadyForReview    = 9,
    /// Work is blocked due to CI failure or other issues (not claimable).
    ///
    /// # CI Gating
    ///
    /// Work enters this state after `CIWorkflowCompleted` with `Failure`
    /// conclusion. The work can transition back to `CiPending` when CI is
    /// retried (e.g., after a fix is pushed).
    Blocked           = 10,
}

impl std::fmt::Display for WorkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl WorkState {
    /// Parses a work state from a string.
    ///
    /// # Errors
    ///
    /// Returns `WorkError::InvalidWorkState` if the string is not a recognized
    /// state.
    pub fn parse(s: &str) -> Result<Self, WorkError> {
        match s.to_uppercase().as_str() {
            "OPEN" => Ok(Self::Open),
            "CLAIMED" => Ok(Self::Claimed),
            "IN_PROGRESS" => Ok(Self::InProgress),
            "CI_PENDING" => Ok(Self::CiPending),
            "READY_FOR_REVIEW" => Ok(Self::ReadyForReview),
            "BLOCKED" => Ok(Self::Blocked),
            "REVIEW" => Ok(Self::Review),
            "NEEDS_INPUT" => Ok(Self::NeedsInput),
            "NEEDS_ADJUDICATION" => Ok(Self::NeedsAdjudication),
            "COMPLETED" => Ok(Self::Completed),
            "ABORTED" => Ok(Self::Aborted),
            _ => Err(WorkError::InvalidWorkState {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the string representation of this state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Claimed => "CLAIMED",
            Self::InProgress => "IN_PROGRESS",
            Self::CiPending => "CI_PENDING",
            Self::ReadyForReview => "READY_FOR_REVIEW",
            Self::Blocked => "BLOCKED",
            Self::Review => "REVIEW",
            Self::NeedsInput => "NEEDS_INPUT",
            Self::NeedsAdjudication => "NEEDS_ADJUDICATION",
            Self::Completed => "COMPLETED",
            Self::Aborted => "ABORTED",
        }
    }

    /// Returns true if this is a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }

    /// Returns true if this is an active (non-terminal) state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.is_terminal()
    }

    /// Checks if a transition from this state to the target state is valid.
    ///
    /// # CI-Gated Transitions
    ///
    /// The CI-gated workflow adds these transitions:
    /// - `InProgress` -> `CiPending`: PR created, waiting for CI
    /// - `CiPending` -> `ReadyForReview`: CI passed
    /// - `CiPending` -> `Blocked`: CI failed
    /// - `Blocked` -> `CiPending`: CI retried (after fix pushed)
    /// - `ReadyForReview` -> `Review`: Review agent claimed work
    #[must_use]
    pub const fn can_transition_to(&self, target: &Self) -> bool {
        match (self, target) {
            // Valid transitions from non-terminal states
            (Self::Open, Self::Claimed | Self::Aborted)
            | (Self::Claimed, Self::InProgress | Self::Open | Self::Aborted)
            | (
                Self::InProgress,
                Self::Review
                    | Self::CiPending
                    | Self::NeedsInput
                    | Self::NeedsAdjudication
                    | Self::Aborted,
            )
            // CI-gated transitions (from CiPending)
            | (Self::CiPending, Self::ReadyForReview | Self::Blocked | Self::Aborted)
            // CI passed, ready for review agent to claim
            | (Self::ReadyForReview, Self::Review | Self::Aborted)
            // CI failed, can retry (back to CiPending) or abort
            | (Self::Blocked, Self::CiPending | Self::InProgress | Self::Aborted)
            // Review transitions
            | (Self::Review, Self::Completed | Self::InProgress | Self::Aborted)
            | (Self::NeedsInput | Self::NeedsAdjudication, Self::InProgress | Self::Aborted) => {
                true
            },

            // All other transitions are invalid (including from terminal states)
            _ => false,
        }
    }

    /// Returns true if work in this state can be claimed by an agent.
    ///
    /// # Claimable States
    ///
    /// - `Open`: Work is newly created and can be claimed for implementation.
    /// - `ReadyForReview`: CI passed and work is ready for review agent.
    ///
    /// # Non-Claimable States
    ///
    /// - `Claimed`: Already claimed by another agent.
    /// - `InProgress`: Work is being actively processed.
    /// - `CiPending`: Waiting for CI completion - cannot be claimed.
    /// - `Blocked`: CI failed - cannot be claimed until fixed.
    /// - `Review`: Under review by an agent.
    /// - `NeedsInput`/`NeedsAdjudication`: Blocked on external input.
    /// - `Completed`/`Aborted`: Terminal states.
    #[must_use]
    pub const fn is_claimable(&self) -> bool {
        matches!(self, Self::Open | Self::ReadyForReview)
    }
}

/// A work item tracked by the kernel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Work {
    /// Unique identifier for this work item.
    pub work_id: String,

    /// Type of work.
    pub work_type: WorkType,

    /// Current lifecycle state.
    pub state: WorkState,

    /// Hash of the specification snapshot at creation time.
    pub spec_snapshot_hash: Vec<u8>,

    /// Requirement IDs linked to this work.
    pub requirement_ids: Vec<String>,

    /// Parent work IDs (for hierarchical work).
    pub parent_work_ids: Vec<String>,

    /// Timestamp when work was opened (Unix nanos).
    pub opened_at: u64,

    /// Timestamp of last state transition (Unix nanos).
    pub last_transition_at: u64,

    /// Number of state transitions that have occurred.
    pub transition_count: u32,

    /// Rationale code from the last transition.
    pub last_rationale_code: String,

    /// Evidence bundle hash (populated on completion).
    pub evidence_bundle_hash: Option<Vec<u8>>,

    /// Evidence IDs (populated on completion).
    pub evidence_ids: Vec<String>,

    /// Gate receipt ID (populated on completion).
    ///
    /// Must NOT contain merge receipt identifiers (values matching
    /// `merge-receipt-*`).  Use `merge_receipt_id` for merge receipts.
    pub gate_receipt_id: Option<String>,

    /// Merge receipt ID (populated on completion via merge executor).
    ///
    /// When present, MUST start with `merge-receipt-` (positive allowlist
    /// per INV-0114).  Distinct from `gate_receipt_id`: a merge receipt
    /// atomically binds gate outcomes to the observed merge result, while
    /// a gate receipt attests a single gate evaluation.
    pub merge_receipt_id: Option<String>,

    /// Abort reason (populated on abort).
    pub abort_reason: Option<String>,

    /// PR number associated with this work (for CI event matching).
    ///
    /// # CI Gating
    ///
    /// When an agent creates a PR for this work, the PR number is recorded
    /// here. This enables matching `CIWorkflowCompleted` events to work
    /// items so that CI completion can trigger phase transitions (e.g.,
    /// `CiPending` -> `ReadyForReview`).
    ///
    /// A value of `None` indicates no PR has been created yet.
    pub pr_number: Option<u64>,

    /// Commit SHA associated with the PR (for CI event verification).
    ///
    /// # CI Gating
    ///
    /// When an agent associates a PR with this work, the commit SHA is recorded
    /// here. This enables `process_ci_event` to verify that CI results match
    /// the specific commit pushed by the agent, preventing stale CI results
    /// from incorrectly transitioning work items.
    ///
    /// A value of `None` indicates no PR has been associated yet.
    pub commit_sha: Option<String>,

    /// Timestamp of the first claim transition (Unix nanos).
    ///
    /// Recorded when the work item first transitions from `Open` to `Claimed`.
    /// Unlike `last_transition_at`, this field is immutable after being set
    /// and accurately represents the moment of initial claim regardless of
    /// subsequent state changes.
    pub claimed_at: Option<u64>,
}

impl Work {
    /// Creates a new work item in the Open state.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: String/Vec aren't const-constructible
    pub fn new(
        work_id: String,
        work_type: WorkType,
        spec_snapshot_hash: Vec<u8>,
        requirement_ids: Vec<String>,
        parent_work_ids: Vec<String>,
        opened_at: u64,
    ) -> Self {
        Self {
            work_id,
            work_type,
            state: WorkState::Open,
            spec_snapshot_hash,
            requirement_ids,
            parent_work_ids,
            opened_at,
            last_transition_at: opened_at,
            transition_count: 0,
            last_rationale_code: String::new(),
            evidence_bundle_hash: None,
            evidence_ids: Vec::new(),
            gate_receipt_id: None,
            merge_receipt_id: None,
            abort_reason: None,
            pr_number: None,
            commit_sha: None,
            claimed_at: None,
        }
    }

    /// Sets the PR number for this work item.
    ///
    /// # CI Gating
    ///
    /// This method should be called when a PR is created for this work item.
    /// The PR number is used to match `CIWorkflowCompleted` events to work
    /// items for phase transitions.
    pub const fn set_pr_number(&mut self, pr_number: u64) {
        self.pr_number = Some(pr_number);
    }

    /// Returns true if this work is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Returns true if this work is active (non-terminal).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Returns a summary of this work item.
    #[must_use]
    pub fn summary(&self) -> WorkSummary {
        WorkSummary {
            work_id: self.work_id.clone(),
            work_type: self.work_type,
            state: self.state,
            requirement_count: self.requirement_ids.len(),
            transition_count: self.transition_count,
            opened_at: self.opened_at,
            last_transition_at: self.last_transition_at,
        }
    }
}

/// A summary view of a work item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkSummary {
    /// Work ID.
    pub work_id: String,

    /// Type of work.
    pub work_type: WorkType,

    /// Current state.
    pub state: WorkState,

    /// Number of linked requirements.
    pub requirement_count: usize,

    /// Number of state transitions.
    pub transition_count: u32,

    /// When the work was opened.
    pub opened_at: u64,

    /// When the last transition occurred.
    pub last_transition_at: u64,
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_work_type_parse() {
        assert_eq!(WorkType::parse("TICKET").unwrap(), WorkType::Ticket);
        assert_eq!(WorkType::parse("ticket").unwrap(), WorkType::Ticket);
        assert_eq!(
            WorkType::parse("PRD_REFINEMENT").unwrap(),
            WorkType::PrdRefinement
        );
        assert_eq!(
            WorkType::parse("RFC_REFINEMENT").unwrap(),
            WorkType::RfcRefinement
        );
        assert_eq!(WorkType::parse("REVIEW").unwrap(), WorkType::Review);
    }

    #[test]
    fn test_work_type_parse_unknown_fails() {
        let result = WorkType::parse("UNKNOWN");
        assert!(matches!(result, Err(WorkError::InvalidWorkType { .. })));

        let result = WorkType::parse("garbage");
        assert!(matches!(result, Err(WorkError::InvalidWorkType { .. })));

        let result = WorkType::parse("");
        assert!(matches!(result, Err(WorkError::InvalidWorkType { .. })));
    }

    #[test]
    fn test_work_type_as_str() {
        assert_eq!(WorkType::Ticket.as_str(), "TICKET");
        assert_eq!(WorkType::PrdRefinement.as_str(), "PRD_REFINEMENT");
        assert_eq!(WorkType::RfcRefinement.as_str(), "RFC_REFINEMENT");
        assert_eq!(WorkType::Review.as_str(), "REVIEW");
    }

    #[test]
    fn test_work_state_parse() {
        assert_eq!(WorkState::parse("OPEN").unwrap(), WorkState::Open);
        assert_eq!(WorkState::parse("open").unwrap(), WorkState::Open);
        assert_eq!(WorkState::parse("CLAIMED").unwrap(), WorkState::Claimed);
        assert_eq!(
            WorkState::parse("IN_PROGRESS").unwrap(),
            WorkState::InProgress
        );
        assert_eq!(
            WorkState::parse("CI_PENDING").unwrap(),
            WorkState::CiPending
        );
        assert_eq!(
            WorkState::parse("ci_pending").unwrap(),
            WorkState::CiPending
        );
        assert_eq!(
            WorkState::parse("READY_FOR_REVIEW").unwrap(),
            WorkState::ReadyForReview
        );
        assert_eq!(WorkState::parse("BLOCKED").unwrap(), WorkState::Blocked);
        assert_eq!(WorkState::parse("REVIEW").unwrap(), WorkState::Review);
        assert_eq!(
            WorkState::parse("NEEDS_INPUT").unwrap(),
            WorkState::NeedsInput
        );
        assert_eq!(
            WorkState::parse("NEEDS_ADJUDICATION").unwrap(),
            WorkState::NeedsAdjudication
        );
        assert_eq!(WorkState::parse("COMPLETED").unwrap(), WorkState::Completed);
        assert_eq!(WorkState::parse("ABORTED").unwrap(), WorkState::Aborted);
    }

    #[test]
    fn test_work_state_parse_unknown_fails() {
        let result = WorkState::parse("UNKNOWN");
        assert!(matches!(result, Err(WorkError::InvalidWorkState { .. })));

        let result = WorkState::parse("garbage");
        assert!(matches!(result, Err(WorkError::InvalidWorkState { .. })));

        let result = WorkState::parse("");
        assert!(matches!(result, Err(WorkError::InvalidWorkState { .. })));
    }

    #[test]
    fn test_work_state_as_str() {
        assert_eq!(WorkState::Open.as_str(), "OPEN");
        assert_eq!(WorkState::Claimed.as_str(), "CLAIMED");
        assert_eq!(WorkState::InProgress.as_str(), "IN_PROGRESS");
        assert_eq!(WorkState::CiPending.as_str(), "CI_PENDING");
        assert_eq!(WorkState::ReadyForReview.as_str(), "READY_FOR_REVIEW");
        assert_eq!(WorkState::Blocked.as_str(), "BLOCKED");
        assert_eq!(WorkState::Review.as_str(), "REVIEW");
        assert_eq!(WorkState::NeedsInput.as_str(), "NEEDS_INPUT");
        assert_eq!(WorkState::NeedsAdjudication.as_str(), "NEEDS_ADJUDICATION");
        assert_eq!(WorkState::Completed.as_str(), "COMPLETED");
        assert_eq!(WorkState::Aborted.as_str(), "ABORTED");
    }

    #[test]
    fn test_work_state_terminal() {
        assert!(!WorkState::Open.is_terminal());
        assert!(!WorkState::Claimed.is_terminal());
        assert!(!WorkState::InProgress.is_terminal());
        assert!(!WorkState::CiPending.is_terminal());
        assert!(!WorkState::ReadyForReview.is_terminal());
        assert!(!WorkState::Blocked.is_terminal());
        assert!(!WorkState::Review.is_terminal());
        assert!(!WorkState::NeedsInput.is_terminal());
        assert!(!WorkState::NeedsAdjudication.is_terminal());
        assert!(WorkState::Completed.is_terminal());
        assert!(WorkState::Aborted.is_terminal());
    }

    #[test]
    fn test_work_state_active() {
        assert!(WorkState::Open.is_active());
        assert!(WorkState::Claimed.is_active());
        assert!(WorkState::InProgress.is_active());
        assert!(WorkState::CiPending.is_active());
        assert!(WorkState::ReadyForReview.is_active());
        assert!(WorkState::Blocked.is_active());
        assert!(WorkState::Review.is_active());
        assert!(WorkState::NeedsInput.is_active());
        assert!(WorkState::NeedsAdjudication.is_active());
        assert!(!WorkState::Completed.is_active());
        assert!(!WorkState::Aborted.is_active());
    }

    #[test]
    fn test_work_state_claimable() {
        // Claimable states
        assert!(WorkState::Open.is_claimable());
        assert!(WorkState::ReadyForReview.is_claimable());

        // Non-claimable states
        assert!(!WorkState::Claimed.is_claimable());
        assert!(!WorkState::InProgress.is_claimable());
        assert!(!WorkState::CiPending.is_claimable());
        assert!(!WorkState::Blocked.is_claimable());
        assert!(!WorkState::Review.is_claimable());
        assert!(!WorkState::NeedsInput.is_claimable());
        assert!(!WorkState::NeedsAdjudication.is_claimable());
        assert!(!WorkState::Completed.is_claimable());
        assert!(!WorkState::Aborted.is_claimable());
    }

    #[test]
    fn test_work_state_transitions_from_open() {
        assert!(WorkState::Open.can_transition_to(&WorkState::Claimed));
        assert!(WorkState::Open.can_transition_to(&WorkState::Aborted));
        assert!(!WorkState::Open.can_transition_to(&WorkState::InProgress));
        assert!(!WorkState::Open.can_transition_to(&WorkState::Completed));
    }

    #[test]
    fn test_work_state_transitions_from_claimed() {
        assert!(WorkState::Claimed.can_transition_to(&WorkState::InProgress));
        assert!(WorkState::Claimed.can_transition_to(&WorkState::Open));
        assert!(WorkState::Claimed.can_transition_to(&WorkState::Aborted));
        assert!(!WorkState::Claimed.can_transition_to(&WorkState::Completed));
    }

    #[test]
    fn test_work_state_transitions_from_in_progress() {
        assert!(WorkState::InProgress.can_transition_to(&WorkState::Review));
        assert!(WorkState::InProgress.can_transition_to(&WorkState::CiPending));
        assert!(WorkState::InProgress.can_transition_to(&WorkState::NeedsInput));
        assert!(WorkState::InProgress.can_transition_to(&WorkState::NeedsAdjudication));
        assert!(WorkState::InProgress.can_transition_to(&WorkState::Aborted));
        assert!(!WorkState::InProgress.can_transition_to(&WorkState::Completed));
        assert!(!WorkState::InProgress.can_transition_to(&WorkState::Open));
    }

    #[test]
    fn test_work_state_transitions_from_ci_pending() {
        // CI success -> ReadyForReview
        assert!(WorkState::CiPending.can_transition_to(&WorkState::ReadyForReview));
        // CI failure -> Blocked
        assert!(WorkState::CiPending.can_transition_to(&WorkState::Blocked));
        // Can abort from CI pending
        assert!(WorkState::CiPending.can_transition_to(&WorkState::Aborted));
        // Cannot skip to completion
        assert!(!WorkState::CiPending.can_transition_to(&WorkState::Completed));
        // Cannot go back to InProgress directly
        assert!(!WorkState::CiPending.can_transition_to(&WorkState::InProgress));
    }

    #[test]
    fn test_work_state_transitions_from_ready_for_review() {
        // Review agent claims work
        assert!(WorkState::ReadyForReview.can_transition_to(&WorkState::Review));
        // Can abort
        assert!(WorkState::ReadyForReview.can_transition_to(&WorkState::Aborted));
        // Cannot skip to completion
        assert!(!WorkState::ReadyForReview.can_transition_to(&WorkState::Completed));
        // Cannot go back to CiPending
        assert!(!WorkState::ReadyForReview.can_transition_to(&WorkState::CiPending));
    }

    #[test]
    fn test_work_state_transitions_from_blocked() {
        // Retry CI after fix
        assert!(WorkState::Blocked.can_transition_to(&WorkState::CiPending));
        // Can go back to InProgress for more work
        assert!(WorkState::Blocked.can_transition_to(&WorkState::InProgress));
        // Can abort
        assert!(WorkState::Blocked.can_transition_to(&WorkState::Aborted));
        // Cannot skip to completion
        assert!(!WorkState::Blocked.can_transition_to(&WorkState::Completed));
        // Cannot skip to ReadyForReview
        assert!(!WorkState::Blocked.can_transition_to(&WorkState::ReadyForReview));
    }

    #[test]
    fn test_work_state_transitions_from_review() {
        assert!(WorkState::Review.can_transition_to(&WorkState::Completed));
        assert!(WorkState::Review.can_transition_to(&WorkState::InProgress));
        assert!(WorkState::Review.can_transition_to(&WorkState::Aborted));
        assert!(!WorkState::Review.can_transition_to(&WorkState::Open));
    }

    #[test]
    fn test_work_state_transitions_from_needs_input() {
        assert!(WorkState::NeedsInput.can_transition_to(&WorkState::InProgress));
        assert!(WorkState::NeedsInput.can_transition_to(&WorkState::Aborted));
        assert!(!WorkState::NeedsInput.can_transition_to(&WorkState::Completed));
    }

    #[test]
    fn test_work_state_transitions_from_needs_adjudication() {
        assert!(WorkState::NeedsAdjudication.can_transition_to(&WorkState::InProgress));
        assert!(WorkState::NeedsAdjudication.can_transition_to(&WorkState::Aborted));
        assert!(!WorkState::NeedsAdjudication.can_transition_to(&WorkState::Completed));
    }

    #[test]
    fn test_work_state_transitions_from_terminal() {
        assert!(!WorkState::Completed.can_transition_to(&WorkState::Open));
        assert!(!WorkState::Completed.can_transition_to(&WorkState::InProgress));
        assert!(!WorkState::Aborted.can_transition_to(&WorkState::Open));
        assert!(!WorkState::Aborted.can_transition_to(&WorkState::InProgress));
    }

    #[test]
    fn test_work_new() {
        let work = Work::new(
            "work-1".to_string(),
            WorkType::Ticket,
            vec![1, 2, 3],
            vec!["REQ-001".to_string()],
            vec![],
            1_000_000_000,
        );

        assert_eq!(work.work_id, "work-1");
        assert_eq!(work.work_type, WorkType::Ticket);
        assert_eq!(work.state, WorkState::Open);
        assert_eq!(work.spec_snapshot_hash, vec![1, 2, 3]);
        assert_eq!(work.requirement_ids, vec!["REQ-001"]);
        assert!(work.parent_work_ids.is_empty());
        assert_eq!(work.opened_at, 1_000_000_000);
        assert_eq!(work.last_transition_at, 1_000_000_000);
        assert_eq!(work.transition_count, 0);
        assert!(work.is_active());
        assert!(!work.is_terminal());
    }

    #[test]
    fn test_work_summary() {
        let work = Work::new(
            "work-1".to_string(),
            WorkType::Ticket,
            vec![1, 2, 3],
            vec!["REQ-001".to_string(), "REQ-002".to_string()],
            vec![],
            1_000_000_000,
        );

        let summary = work.summary();
        assert_eq!(summary.work_id, "work-1");
        assert_eq!(summary.work_type, WorkType::Ticket);
        assert_eq!(summary.state, WorkState::Open);
        assert_eq!(summary.requirement_count, 2);
        assert_eq!(summary.transition_count, 0);
    }
}
