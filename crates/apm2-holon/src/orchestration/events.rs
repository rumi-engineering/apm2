//! Ledger events for orchestration lifecycle.
//!
//! This module defines the event types emitted during orchestration execution
//! and recorded to the ledger for auditing and replay.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::state::TerminationReason;
use crate::error::HolonError;
use crate::ledger::validate_id;

/// Maximum length for role strings.
pub const MAX_ROLE_LENGTH: usize = 256;

/// Maximum length for reason/error/description strings.
pub const MAX_REASON_LENGTH: usize = 1024;

/// Maximum number of entries in vector fields (e.g., `blocked_by`,
/// `reviewer_episode_ids`).
pub const MAX_VECTOR_ENTRIES: usize = 100;

/// Outcome of a single iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum IterationOutcome {
    /// The iteration produced a new changeset that needs review.
    ChangeSetProduced,

    /// All reviews passed; work is complete.
    AllReviewsPassed,

    /// One or more reviews blocked; revision needed.
    ReviewsBlocked {
        /// Roles that blocked.
        blocked_by: Vec<String>,
    },

    /// The implementer could not make progress.
    ImplementerStalled {
        /// Reason for the stall.
        reason: String,
    },

    /// An error occurred during the iteration.
    Error {
        /// Error description.
        error: String,
    },
}

impl IterationOutcome {
    /// Returns `true` if this outcome indicates success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::AllReviewsPassed)
    }

    /// Returns `true` if this outcome indicates a blocking condition.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(
            self,
            Self::ReviewsBlocked { .. } | Self::ImplementerStalled { .. }
        )
    }

    /// Returns `true` if this outcome indicates an error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Returns the outcome as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ChangeSetProduced => "changeset_produced",
            Self::AllReviewsPassed => "all_reviews_passed",
            Self::ReviewsBlocked { .. } => "reviews_blocked",
            Self::ImplementerStalled { .. } => "implementer_stalled",
            Self::Error { .. } => "error",
        }
    }

    /// Validates bounds on all string and vector fields.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if any field exceeds limits.
    pub fn validate(&self) -> Result<(), HolonError> {
        match self {
            Self::ReviewsBlocked { blocked_by } => {
                if blocked_by.len() > MAX_VECTOR_ENTRIES {
                    return Err(HolonError::invalid_input(format!(
                        "blocked_by exceeds max entries: {} > {MAX_VECTOR_ENTRIES}",
                        blocked_by.len()
                    )));
                }
                for role in blocked_by {
                    if role.len() > MAX_ROLE_LENGTH {
                        return Err(HolonError::invalid_input(format!(
                            "blocked_by role exceeds max length: {} > {MAX_ROLE_LENGTH}",
                            role.len()
                        )));
                    }
                }
            },
            Self::ImplementerStalled { reason } => {
                if reason.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "stall reason exceeds max length: {} > {MAX_REASON_LENGTH}",
                        reason.len()
                    )));
                }
            },
            Self::Error { error } => {
                if error.len() > MAX_REASON_LENGTH {
                    return Err(HolonError::invalid_input(format!(
                        "error exceeds max length: {} > {MAX_REASON_LENGTH}",
                        error.len()
                    )));
                }
            },
            Self::ChangeSetProduced | Self::AllReviewsPassed => {},
        }
        Ok(())
    }
}

impl fmt::Display for IterationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChangeSetProduced => write!(f, "changeset produced"),
            Self::AllReviewsPassed => write!(f, "all reviews passed"),
            Self::ReviewsBlocked { blocked_by } => {
                write!(f, "reviews blocked by: {}", blocked_by.join(", "))
            },
            Self::ImplementerStalled { reason } => {
                write!(f, "implementer stalled: {reason}")
            },
            Self::Error { error } => write!(f, "error: {error}"),
        }
    }
}

/// Event emitted when orchestration starts.
///
/// This event captures the initial configuration and context at the
/// beginning of an orchestration session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationStarted {
    /// Unique orchestration session ID.
    orchestration_id: String,

    /// Work ID being orchestrated.
    work_id: String,

    /// Maximum iterations allowed.
    max_iterations: u64,

    /// Initial token budget.
    token_budget: u64,

    /// Initial time budget in milliseconds.
    time_budget_ms: u64,

    /// Timestamp when orchestration started (nanoseconds since epoch).
    started_at_ns: u64,

    /// BLAKE3 hash of the initial changeset bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_changeset_hash: Option<[u8; 32]>,

    /// BLAKE3 hash of the capability manifest governing the orchestration.
    #[serde(skip_serializing_if = "Option::is_none")]
    capability_manifest_hash: Option<[u8; 32]>,
}

impl OrchestrationStarted {
    /// Creates a new orchestration started event with validation.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if ID validation fails.
    pub fn try_new(
        orchestration_id: impl Into<String>,
        work_id: impl Into<String>,
        max_iterations: u64,
        token_budget: u64,
        time_budget_ms: u64,
        started_at_ns: u64,
    ) -> Result<Self, HolonError> {
        let orchestration_id = orchestration_id.into();
        let work_id = work_id.into();

        validate_id(&orchestration_id, "orchestration_id")?;
        validate_id(&work_id, "work_id")?;

        Ok(Self {
            orchestration_id,
            work_id,
            max_iterations,
            token_budget,
            time_budget_ms,
            started_at_ns,
            initial_changeset_hash: None,
            capability_manifest_hash: None,
        })
    }

    /// Creates a new orchestration started event without validation.
    #[must_use]
    pub fn new(
        orchestration_id: impl Into<String>,
        work_id: impl Into<String>,
        max_iterations: u64,
        token_budget: u64,
        time_budget_ms: u64,
        started_at_ns: u64,
    ) -> Self {
        Self {
            orchestration_id: orchestration_id.into(),
            work_id: work_id.into(),
            max_iterations,
            token_budget,
            time_budget_ms,
            started_at_ns,
            initial_changeset_hash: None,
            capability_manifest_hash: None,
        }
    }

    /// Returns the orchestration ID.
    #[must_use]
    pub fn orchestration_id(&self) -> &str {
        &self.orchestration_id
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the maximum iterations.
    #[must_use]
    pub const fn max_iterations(&self) -> u64 {
        self.max_iterations
    }

    /// Returns the token budget.
    #[must_use]
    pub const fn token_budget(&self) -> u64 {
        self.token_budget
    }

    /// Returns the time budget in milliseconds.
    #[must_use]
    pub const fn time_budget_ms(&self) -> u64 {
        self.time_budget_ms
    }

    /// Returns the start timestamp.
    #[must_use]
    pub const fn started_at_ns(&self) -> u64 {
        self.started_at_ns
    }

    /// Returns the initial changeset hash.
    #[must_use]
    pub const fn initial_changeset_hash(&self) -> Option<&[u8; 32]> {
        self.initial_changeset_hash.as_ref()
    }

    /// Returns the capability manifest hash.
    #[must_use]
    pub const fn capability_manifest_hash(&self) -> Option<&[u8; 32]> {
        self.capability_manifest_hash.as_ref()
    }

    /// Sets the initial changeset hash.
    #[must_use]
    pub const fn with_initial_changeset_hash(mut self, hash: [u8; 32]) -> Self {
        self.initial_changeset_hash = Some(hash);
        self
    }

    /// Sets the capability manifest hash.
    #[must_use]
    pub const fn with_capability_manifest_hash(mut self, hash: [u8; 32]) -> Self {
        self.capability_manifest_hash = Some(hash);
        self
    }
}

/// Event emitted when an iteration completes.
///
/// This event captures the outcome and resource consumption of a single
/// revision cycle (implementer + reviewer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IterationCompleted {
    /// Orchestration session ID.
    orchestration_id: String,

    /// Work ID being orchestrated.
    work_id: String,

    /// Iteration number (1-indexed).
    iteration_number: u64,

    /// Outcome of the iteration.
    outcome: IterationOutcome,

    /// Tokens consumed in this iteration.
    tokens_consumed: u64,

    /// Time consumed in this iteration (milliseconds).
    time_consumed_ms: u64,

    /// Timestamp when iteration completed (nanoseconds since epoch).
    completed_at_ns: u64,

    /// BLAKE3 hash of the changeset bundle processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    changeset_hash: Option<[u8; 32]>,

    /// BLAKE3 hash of the reviewer receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_hash: Option<[u8; 32]>,

    /// Implementer episode ID (if an implementer ran).
    #[serde(skip_serializing_if = "Option::is_none")]
    implementer_episode_id: Option<String>,

    /// Reviewer episode IDs (multiple reviewers may run).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    reviewer_episode_ids: Vec<String>,
}

impl IterationCompleted {
    /// Creates a new iteration completed event with validation.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if ID validation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        orchestration_id: impl Into<String>,
        work_id: impl Into<String>,
        iteration_number: u64,
        outcome: IterationOutcome,
        tokens_consumed: u64,
        time_consumed_ms: u64,
        completed_at_ns: u64,
    ) -> Result<Self, HolonError> {
        let orchestration_id = orchestration_id.into();
        let work_id = work_id.into();

        validate_id(&orchestration_id, "orchestration_id")?;
        validate_id(&work_id, "work_id")?;

        Ok(Self {
            orchestration_id,
            work_id,
            iteration_number,
            outcome,
            tokens_consumed,
            time_consumed_ms,
            completed_at_ns,
            changeset_hash: None,
            receipt_hash: None,
            implementer_episode_id: None,
            reviewer_episode_ids: Vec::new(),
        })
    }

    /// Creates a new iteration completed event without validation.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        orchestration_id: impl Into<String>,
        work_id: impl Into<String>,
        iteration_number: u64,
        outcome: IterationOutcome,
        tokens_consumed: u64,
        time_consumed_ms: u64,
        completed_at_ns: u64,
    ) -> Self {
        Self {
            orchestration_id: orchestration_id.into(),
            work_id: work_id.into(),
            iteration_number,
            outcome,
            tokens_consumed,
            time_consumed_ms,
            completed_at_ns,
            changeset_hash: None,
            receipt_hash: None,
            implementer_episode_id: None,
            reviewer_episode_ids: Vec::new(),
        }
    }

    /// Returns the orchestration ID.
    #[must_use]
    pub fn orchestration_id(&self) -> &str {
        &self.orchestration_id
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the iteration number.
    #[must_use]
    pub const fn iteration_number(&self) -> u64 {
        self.iteration_number
    }

    /// Returns the outcome.
    #[must_use]
    pub const fn outcome(&self) -> &IterationOutcome {
        &self.outcome
    }

    /// Returns tokens consumed.
    #[must_use]
    pub const fn tokens_consumed(&self) -> u64 {
        self.tokens_consumed
    }

    /// Returns time consumed in milliseconds.
    #[must_use]
    pub const fn time_consumed_ms(&self) -> u64 {
        self.time_consumed_ms
    }

    /// Returns the completion timestamp.
    #[must_use]
    pub const fn completed_at_ns(&self) -> u64 {
        self.completed_at_ns
    }

    /// Returns the changeset hash.
    #[must_use]
    pub const fn changeset_hash(&self) -> Option<&[u8; 32]> {
        self.changeset_hash.as_ref()
    }

    /// Returns the receipt hash.
    #[must_use]
    pub const fn receipt_hash(&self) -> Option<&[u8; 32]> {
        self.receipt_hash.as_ref()
    }

    /// Returns the implementer episode ID.
    #[must_use]
    pub fn implementer_episode_id(&self) -> Option<&str> {
        self.implementer_episode_id.as_deref()
    }

    /// Returns the reviewer episode IDs.
    #[must_use]
    pub fn reviewer_episode_ids(&self) -> &[String] {
        &self.reviewer_episode_ids
    }

    /// Sets the changeset hash.
    #[must_use]
    pub const fn with_changeset_hash(mut self, hash: [u8; 32]) -> Self {
        self.changeset_hash = Some(hash);
        self
    }

    /// Sets the receipt hash.
    #[must_use]
    pub const fn with_receipt_hash(mut self, hash: [u8; 32]) -> Self {
        self.receipt_hash = Some(hash);
        self
    }

    /// Sets the implementer episode ID.
    #[must_use]
    pub fn with_implementer_episode_id(mut self, id: impl Into<String>) -> Self {
        self.implementer_episode_id = Some(id.into());
        self
    }

    /// Adds a reviewer episode ID.
    #[must_use]
    pub fn with_reviewer_episode_id(mut self, id: impl Into<String>) -> Self {
        self.reviewer_episode_ids.push(id.into());
        self
    }

    /// Validates all fields in the event.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if any field exceeds limits.
    pub fn validate(&self) -> Result<(), HolonError> {
        // Validate outcome
        self.outcome.validate()?;

        // Validate reviewer_episode_ids count
        if self.reviewer_episode_ids.len() > MAX_VECTOR_ENTRIES {
            return Err(HolonError::invalid_input(format!(
                "reviewer_episode_ids exceeds max entries: {} > {MAX_VECTOR_ENTRIES}",
                self.reviewer_episode_ids.len()
            )));
        }

        // Validate episode ID lengths
        if let Some(ref id) = self.implementer_episode_id {
            if id.len() > MAX_ROLE_LENGTH {
                return Err(HolonError::invalid_input(format!(
                    "implementer_episode_id exceeds max length: {} > {MAX_ROLE_LENGTH}",
                    id.len()
                )));
            }
        }

        for id in &self.reviewer_episode_ids {
            if id.len() > MAX_ROLE_LENGTH {
                return Err(HolonError::invalid_input(format!(
                    "reviewer_episode_id exceeds max length: {} > {MAX_ROLE_LENGTH}",
                    id.len()
                )));
            }
        }

        Ok(())
    }
}

/// Event emitted when orchestration terminates.
///
/// This event captures the final state and reason for termination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationTerminated {
    /// Orchestration session ID.
    orchestration_id: String,

    /// Work ID that was orchestrated.
    work_id: String,

    /// Reason for termination.
    reason: TerminationReason,

    /// Total iterations executed.
    total_iterations: u64,

    /// Total tokens consumed.
    total_tokens_consumed: u64,

    /// Total time consumed in milliseconds.
    total_time_consumed_ms: u64,

    /// Timestamp when orchestration terminated (nanoseconds since epoch).
    terminated_at_ns: u64,

    /// BLAKE3 hash of the final changeset bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    final_changeset_hash: Option<[u8; 32]>,

    /// BLAKE3 hash of the final receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    final_receipt_hash: Option<[u8; 32]>,
}

impl OrchestrationTerminated {
    /// Creates a new orchestration terminated event with validation.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if ID validation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        orchestration_id: impl Into<String>,
        work_id: impl Into<String>,
        reason: TerminationReason,
        total_iterations: u64,
        total_tokens_consumed: u64,
        total_time_consumed_ms: u64,
        terminated_at_ns: u64,
    ) -> Result<Self, HolonError> {
        let orchestration_id = orchestration_id.into();
        let work_id = work_id.into();

        validate_id(&orchestration_id, "orchestration_id")?;
        validate_id(&work_id, "work_id")?;

        Ok(Self {
            orchestration_id,
            work_id,
            reason,
            total_iterations,
            total_tokens_consumed,
            total_time_consumed_ms,
            terminated_at_ns,
            final_changeset_hash: None,
            final_receipt_hash: None,
        })
    }

    /// Creates a new orchestration terminated event without validation.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        orchestration_id: impl Into<String>,
        work_id: impl Into<String>,
        reason: TerminationReason,
        total_iterations: u64,
        total_tokens_consumed: u64,
        total_time_consumed_ms: u64,
        terminated_at_ns: u64,
    ) -> Self {
        Self {
            orchestration_id: orchestration_id.into(),
            work_id: work_id.into(),
            reason,
            total_iterations,
            total_tokens_consumed,
            total_time_consumed_ms,
            terminated_at_ns,
            final_changeset_hash: None,
            final_receipt_hash: None,
        }
    }

    /// Returns the orchestration ID.
    #[must_use]
    pub fn orchestration_id(&self) -> &str {
        &self.orchestration_id
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the termination reason.
    #[must_use]
    pub const fn reason(&self) -> &TerminationReason {
        &self.reason
    }

    /// Returns total iterations executed.
    #[must_use]
    pub const fn total_iterations(&self) -> u64 {
        self.total_iterations
    }

    /// Returns total tokens consumed.
    #[must_use]
    pub const fn total_tokens_consumed(&self) -> u64 {
        self.total_tokens_consumed
    }

    /// Returns total time consumed in milliseconds.
    #[must_use]
    pub const fn total_time_consumed_ms(&self) -> u64 {
        self.total_time_consumed_ms
    }

    /// Returns the termination timestamp.
    #[must_use]
    pub const fn terminated_at_ns(&self) -> u64 {
        self.terminated_at_ns
    }

    /// Returns the final changeset hash.
    #[must_use]
    pub const fn final_changeset_hash(&self) -> Option<&[u8; 32]> {
        self.final_changeset_hash.as_ref()
    }

    /// Returns the final receipt hash.
    #[must_use]
    pub const fn final_receipt_hash(&self) -> Option<&[u8; 32]> {
        self.final_receipt_hash.as_ref()
    }

    /// Returns `true` if termination was successful (Pass).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.reason.is_success()
    }

    /// Sets the final changeset hash.
    #[must_use]
    pub const fn with_final_changeset_hash(mut self, hash: [u8; 32]) -> Self {
        self.final_changeset_hash = Some(hash);
        self
    }

    /// Sets the final receipt hash.
    #[must_use]
    pub const fn with_final_receipt_hash(mut self, hash: [u8; 32]) -> Self {
        self.final_receipt_hash = Some(hash);
        self
    }
}

/// Wrapper enum for all orchestration-related ledger events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum OrchestrationEvent {
    /// Orchestration started.
    Started(OrchestrationStarted),

    /// An iteration completed.
    IterationCompleted(IterationCompleted),

    /// Orchestration terminated.
    Terminated(OrchestrationTerminated),
}

impl OrchestrationEvent {
    /// Returns the orchestration ID for this event.
    #[must_use]
    pub fn orchestration_id(&self) -> &str {
        match self {
            Self::Started(e) => e.orchestration_id(),
            Self::IterationCompleted(e) => e.orchestration_id(),
            Self::Terminated(e) => e.orchestration_id(),
        }
    }

    /// Returns the work ID for this event.
    #[must_use]
    pub fn work_id(&self) -> &str {
        match self {
            Self::Started(e) => e.work_id(),
            Self::IterationCompleted(e) => e.work_id(),
            Self::Terminated(e) => e.work_id(),
        }
    }

    /// Returns the timestamp for this event.
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        match self {
            Self::Started(e) => e.started_at_ns(),
            Self::IterationCompleted(e) => e.completed_at_ns(),
            Self::Terminated(e) => e.terminated_at_ns(),
        }
    }

    /// Returns `true` if this is a started event.
    #[must_use]
    pub const fn is_started(&self) -> bool {
        matches!(self, Self::Started(_))
    }

    /// Returns `true` if this is an iteration completed event.
    #[must_use]
    pub const fn is_iteration_completed(&self) -> bool {
        matches!(self, Self::IterationCompleted(_))
    }

    /// Returns `true` if this is a terminated event.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        matches!(self, Self::Terminated(_))
    }

    /// Returns the event type as a string.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::Started(_) => "orchestration_started",
            Self::IterationCompleted(_) => "iteration_completed",
            Self::Terminated(_) => "orchestration_terminated",
        }
    }
}

impl From<OrchestrationStarted> for OrchestrationEvent {
    fn from(event: OrchestrationStarted) -> Self {
        Self::Started(event)
    }
}

impl From<IterationCompleted> for OrchestrationEvent {
    fn from(event: IterationCompleted) -> Self {
        Self::IterationCompleted(event)
    }
}

impl From<OrchestrationTerminated> for OrchestrationEvent {
    fn from(event: OrchestrationTerminated) -> Self {
        Self::Terminated(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iteration_outcome_properties() {
        assert!(IterationOutcome::AllReviewsPassed.is_success());
        assert!(!IterationOutcome::ChangeSetProduced.is_success());

        assert!(
            IterationOutcome::ReviewsBlocked {
                blocked_by: vec!["security".to_string()]
            }
            .is_blocked()
        );
        assert!(
            IterationOutcome::ImplementerStalled {
                reason: "stuck".to_string()
            }
            .is_blocked()
        );

        assert!(
            IterationOutcome::Error {
                error: "crash".to_string()
            }
            .is_error()
        );
    }

    #[test]
    fn test_iteration_outcome_display() {
        let outcome = IterationOutcome::ReviewsBlocked {
            blocked_by: vec!["security".to_string(), "quality".to_string()],
        };
        let display = outcome.to_string();
        assert!(display.contains("security"));
        assert!(display.contains("quality"));
    }

    #[test]
    fn test_orchestration_started_creation() {
        let event = OrchestrationStarted::try_new(
            "orch-001",
            "work-123",
            100,
            1_000_000,
            3_600_000,
            1_000_000_000,
        )
        .unwrap();

        assert_eq!(event.orchestration_id(), "orch-001");
        assert_eq!(event.work_id(), "work-123");
        assert_eq!(event.max_iterations(), 100);
        assert_eq!(event.token_budget(), 1_000_000);
        assert_eq!(event.time_budget_ms(), 3_600_000);
        assert!(event.initial_changeset_hash().is_none());
    }

    #[test]
    fn test_orchestration_started_with_hashes() {
        let event = OrchestrationStarted::new(
            "orch-001",
            "work-123",
            100,
            1_000_000,
            3_600_000,
            1_000_000_000,
        )
        .with_initial_changeset_hash([1u8; 32])
        .with_capability_manifest_hash([2u8; 32]);

        assert_eq!(event.initial_changeset_hash(), Some(&[1u8; 32]));
        assert_eq!(event.capability_manifest_hash(), Some(&[2u8; 32]));
    }

    #[test]
    fn test_orchestration_started_validation() {
        // Invalid orchestration_id
        let result =
            OrchestrationStarted::try_new("", "work-123", 100, 1_000_000, 3_600_000, 1_000_000_000);
        assert!(result.is_err());

        // Invalid work_id
        let result =
            OrchestrationStarted::try_new("orch-001", "", 100, 1_000_000, 3_600_000, 1_000_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_iteration_completed_creation() {
        let event = IterationCompleted::try_new(
            "orch-001",
            "work-123",
            1,
            IterationOutcome::ChangeSetProduced,
            5000,
            10_000,
            2_000_000_000,
        )
        .unwrap();

        assert_eq!(event.orchestration_id(), "orch-001");
        assert_eq!(event.work_id(), "work-123");
        assert_eq!(event.iteration_number(), 1);
        assert!(matches!(
            event.outcome(),
            IterationOutcome::ChangeSetProduced
        ));
        assert_eq!(event.tokens_consumed(), 5000);
        assert_eq!(event.time_consumed_ms(), 10_000);
    }

    #[test]
    fn test_iteration_completed_with_details() {
        let event = IterationCompleted::new(
            "orch-001",
            "work-123",
            5,
            IterationOutcome::AllReviewsPassed,
            1000,
            500,
            3_000_000_000,
        )
        .with_changeset_hash([1u8; 32])
        .with_receipt_hash([2u8; 32])
        .with_implementer_episode_id("impl-ep-001")
        .with_reviewer_episode_id("rev-ep-001")
        .with_reviewer_episode_id("rev-ep-002");

        assert_eq!(event.changeset_hash(), Some(&[1u8; 32]));
        assert_eq!(event.receipt_hash(), Some(&[2u8; 32]));
        assert_eq!(event.implementer_episode_id(), Some("impl-ep-001"));
        assert_eq!(event.reviewer_episode_ids().len(), 2);
    }

    #[test]
    fn test_orchestration_terminated_creation() {
        let event = OrchestrationTerminated::try_new(
            "orch-001",
            "work-123",
            TerminationReason::pass(),
            10,
            50_000,
            100_000,
            10_000_000_000,
        )
        .unwrap();

        assert_eq!(event.orchestration_id(), "orch-001");
        assert_eq!(event.work_id(), "work-123");
        assert!(event.is_success());
        assert_eq!(event.total_iterations(), 10);
        assert_eq!(event.total_tokens_consumed(), 50_000);
    }

    #[test]
    fn test_orchestration_terminated_with_hashes() {
        let event = OrchestrationTerminated::new(
            "orch-001",
            "work-123",
            TerminationReason::max_iterations_reached(100),
            100,
            1_000_000,
            3_600_000,
            10_000_000_000,
        )
        .with_final_changeset_hash([1u8; 32])
        .with_final_receipt_hash([2u8; 32]);

        assert!(!event.is_success());
        assert_eq!(event.final_changeset_hash(), Some(&[1u8; 32]));
        assert_eq!(event.final_receipt_hash(), Some(&[2u8; 32]));
    }

    #[test]
    fn test_orchestration_event_wrapper() {
        let started = OrchestrationStarted::new(
            "orch-001",
            "work-123",
            100,
            1_000_000,
            3_600_000,
            1_000_000_000,
        );
        let event: OrchestrationEvent = started.into();

        assert!(event.is_started());
        assert!(!event.is_iteration_completed());
        assert!(!event.is_terminated());
        assert_eq!(event.orchestration_id(), "orch-001");
        assert_eq!(event.work_id(), "work-123");
        assert_eq!(event.event_type(), "orchestration_started");

        let completed = IterationCompleted::new(
            "orch-001",
            "work-123",
            1,
            IterationOutcome::ChangeSetProduced,
            1000,
            500,
            2_000_000_000,
        );
        let event: OrchestrationEvent = completed.into();
        assert!(event.is_iteration_completed());
        assert_eq!(event.event_type(), "iteration_completed");

        let terminated = OrchestrationTerminated::new(
            "orch-001",
            "work-123",
            TerminationReason::pass(),
            5,
            25_000,
            50_000,
            5_000_000_000,
        );
        let event: OrchestrationEvent = terminated.into();
        assert!(event.is_terminated());
        assert_eq!(event.event_type(), "orchestration_terminated");
    }

    #[test]
    fn test_event_serialization_roundtrip() {
        let started = OrchestrationStarted::new(
            "orch-001",
            "work-123",
            100,
            1_000_000,
            3_600_000,
            1_000_000_000,
        )
        .with_initial_changeset_hash([1u8; 32]);

        let json = serde_json::to_string(&started).unwrap();
        let deserialized: OrchestrationStarted = serde_json::from_str(&json).unwrap();
        assert_eq!(started, deserialized);

        let completed = IterationCompleted::new(
            "orch-001",
            "work-123",
            1,
            IterationOutcome::ReviewsBlocked {
                blocked_by: vec!["security".to_string()],
            },
            1000,
            500,
            2_000_000_000,
        );

        let json = serde_json::to_string(&completed).unwrap();
        let deserialized: IterationCompleted = serde_json::from_str(&json).unwrap();
        assert_eq!(completed, deserialized);

        let terminated = OrchestrationTerminated::new(
            "orch-001",
            "work-123",
            TerminationReason::budget_exhausted("tokens", 1000, 1000),
            5,
            1000,
            5000,
            5_000_000_000,
        );

        let json = serde_json::to_string(&terminated).unwrap();
        let deserialized: OrchestrationTerminated = serde_json::from_str(&json).unwrap();
        assert_eq!(terminated, deserialized);
    }

    /// SECURITY TEST: Verify events reject unknown fields.
    #[test]
    fn test_orchestration_started_rejects_unknown_fields() {
        let json = r#"{
            "orchestration_id": "orch-001",
            "work_id": "work-123",
            "max_iterations": 100,
            "token_budget": 1000000,
            "time_budget_ms": 3600000,
            "started_at_ns": 1000000000,
            "malicious_field": "should_be_rejected"
        }"#;

        let result: Result<OrchestrationStarted, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_iteration_completed_rejects_unknown_fields() {
        let json = r#"{
            "orchestration_id": "orch-001",
            "work_id": "work-123",
            "iteration_number": 1,
            "outcome": "ChangeSetProduced",
            "tokens_consumed": 1000,
            "time_consumed_ms": 500,
            "completed_at_ns": 2000000000,
            "malicious_field": "should_be_rejected"
        }"#;

        let result: Result<IterationCompleted, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_orchestration_terminated_rejects_unknown_fields() {
        let json = r#"{
            "orchestration_id": "orch-001",
            "work_id": "work-123",
            "reason": "Pass",
            "total_iterations": 5,
            "total_tokens_consumed": 25000,
            "total_time_consumed_ms": 50000,
            "terminated_at_ns": 5000000000,
            "malicious_field": "should_be_rejected"
        }"#;

        let result: Result<OrchestrationTerminated, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_orchestration_event_rejects_unknown_fields() {
        let json = r#"{
            "Started": {
                "orchestration_id": "orch-001",
                "work_id": "work-123",
                "max_iterations": 100,
                "token_budget": 1000000,
                "time_budget_ms": 3600000,
                "started_at_ns": 1000000000,
                "malicious_field": "should_be_rejected"
            }
        }"#;

        let result: Result<OrchestrationEvent, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
