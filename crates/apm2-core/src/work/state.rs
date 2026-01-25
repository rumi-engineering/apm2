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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkState {
    /// Work is open and available for claiming.
    Open,
    /// Work has been claimed by an agent.
    Claimed,
    /// Work is actively being processed.
    InProgress,
    /// Work is under review.
    Review,
    /// Work is blocked waiting for input.
    NeedsInput,
    /// Work requires adjudication (human decision).
    NeedsAdjudication,
    /// Work has been successfully completed.
    Completed,
    /// Work has been aborted.
    Aborted,
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
    #[must_use]
    pub const fn can_transition_to(&self, target: &Self) -> bool {
        match (self, target) {
            // Valid transitions from non-terminal states
            (Self::Open, Self::Claimed | Self::Aborted)
            | (Self::Claimed, Self::InProgress | Self::Open | Self::Aborted)
            | (
                Self::InProgress,
                Self::Review | Self::NeedsInput | Self::NeedsAdjudication | Self::Aborted,
            )
            | (Self::Review, Self::Completed | Self::InProgress | Self::Aborted)
            | (Self::NeedsInput | Self::NeedsAdjudication, Self::InProgress | Self::Aborted) => {
                true
            },

            // All other transitions are invalid (including from terminal states)
            _ => false,
        }
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
    pub gate_receipt_id: Option<String>,

    /// Abort reason (populated on abort).
    pub abort_reason: Option<String>,
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
            abort_reason: None,
        }
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
        assert!(WorkState::Review.is_active());
        assert!(WorkState::NeedsInput.is_active());
        assert!(WorkState::NeedsAdjudication.is_active());
        assert!(!WorkState::Completed.is_active());
        assert!(!WorkState::Aborted.is_active());
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
        assert!(WorkState::InProgress.can_transition_to(&WorkState::NeedsInput));
        assert!(WorkState::InProgress.can_transition_to(&WorkState::NeedsAdjudication));
        assert!(WorkState::InProgress.can_transition_to(&WorkState::Aborted));
        assert!(!WorkState::InProgress.can_transition_to(&WorkState::Completed));
        assert!(!WorkState::InProgress.can_transition_to(&WorkState::Open));
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
