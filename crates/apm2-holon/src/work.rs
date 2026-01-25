//! Work object and lifecycle state machine.
//!
//! This module defines the [`WorkObject`] struct and [`WorkLifecycle`] state
//! machine for tracking work items through their lifecycle in the holonic
//! coordination framework.
//!
//! # Design
//!
//! The work lifecycle follows a state machine pattern with explicit
//! transitions. Invalid transitions are rejected with an error, ensuring
//! correctness.
//!
//! # States
//!
//! - `Created`: Work has been created but not yet assigned
//! - `Leased`: Work has been assigned to a holon via a lease
//! - `InProgress`: Work is actively being executed
//! - `Blocked`: Work is waiting for external dependencies
//! - `Completed`: Work has finished successfully (terminal)
//! - `Failed`: Work has failed and cannot be retried (terminal)
//! - `Escalated`: Work has been escalated to a supervisor
//! - `Cancelled`: Work has been cancelled (terminal)
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::work::{WorkLifecycle, WorkObject};
//!
//! let mut work = WorkObject::new("work-123", "Implement feature X");
//! assert_eq!(work.lifecycle(), WorkLifecycle::Created);
//!
//! // Assign the work via a lease
//! work.transition_to_leased("lease-456").unwrap();
//! assert_eq!(work.lifecycle(), WorkLifecycle::Leased);
//!
//! // Start working
//! work.transition_to_in_progress().unwrap();
//! assert_eq!(work.lifecycle(), WorkLifecycle::InProgress);
//!
//! // Complete the work
//! work.transition_to_completed().unwrap();
//! assert_eq!(work.lifecycle(), WorkLifecycle::Completed);
//! assert!(work.is_terminal());
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::HolonError;

/// Unique identifier for a work item.
pub type WorkId = String;

/// Unique identifier for a requirement binding.
pub type RequirementId = String;

/// Unique identifier for an artifact.
pub type ArtifactId = String;

/// Unique identifier for an episode.
pub type EpisodeId = String;

/// Maximum number of attempts allowed per work object.
///
/// This limit prevents unbounded growth of the attempts vector, which
/// could lead to denial-of-service during serialization or storage.
pub const MAX_ATTEMPTS: usize = 100;

/// Maximum number of metadata entries allowed per work object.
///
/// This limit prevents unbounded growth of metadata, which could lead
/// to denial-of-service during serialization or storage.
pub const MAX_METADATA_ENTRIES: usize = 50;

/// The lifecycle states of a work object.
///
/// This enum represents all possible states in the work lifecycle.
/// Transitions between states are validated to ensure correctness.
///
/// # Terminal States
///
/// `Completed`, `Failed`, and `Cancelled` are terminal states.
/// No further transitions are allowed from these states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum WorkLifecycle {
    /// Work has been created but not yet assigned.
    #[default]
    Created,

    /// Work has been assigned to a holon via a lease.
    Leased,

    /// Work is actively being executed.
    InProgress,

    /// Work is waiting for external dependencies.
    Blocked,

    /// Work has finished successfully (terminal).
    Completed,

    /// Work has failed and cannot be retried (terminal).
    Failed,

    /// Work has been escalated to a supervisor.
    Escalated,

    /// Work has been cancelled (terminal).
    Cancelled,
}

impl WorkLifecycle {
    /// Returns `true` if this is a terminal state.
    ///
    /// Terminal states (`Completed`, `Failed`, `Cancelled`) do not allow
    /// any further transitions.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Returns `true` if this state represents success.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Returns `true` if work can be actively executed in this state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::InProgress)
    }

    /// Returns `true` if work is waiting in this state.
    #[must_use]
    pub const fn is_waiting(&self) -> bool {
        matches!(
            self,
            Self::Created | Self::Leased | Self::Blocked | Self::Escalated
        )
    }

    /// Returns the state as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Leased => "leased",
            Self::InProgress => "in_progress",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Escalated => "escalated",
            Self::Cancelled => "cancelled",
        }
    }

    /// Returns the valid transitions from this state.
    #[must_use]
    pub const fn valid_transitions(&self) -> &'static [Self] {
        match self {
            Self::Created => &[Self::Leased, Self::Cancelled],
            Self::Leased | Self::Escalated => &[Self::InProgress, Self::Cancelled],
            Self::InProgress => &[
                Self::Blocked,
                Self::Completed,
                Self::Failed,
                Self::Escalated,
            ],
            Self::Blocked => &[Self::InProgress, Self::Escalated, Self::Cancelled],
            // Terminal states have no valid transitions
            Self::Completed | Self::Failed | Self::Cancelled => &[],
        }
    }

    /// Returns `true` if transitioning to `target` is valid from this state.
    #[must_use]
    pub fn can_transition_to(&self, target: Self) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl fmt::Display for WorkLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A record of a single execution attempt on a work object.
///
/// Each time a holon attempts to execute work, an attempt record is created
/// to track the episode, outcome, and any artifacts produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    /// Unique identifier for this attempt.
    attempt_id: String,

    /// The episode ID associated with this attempt.
    episode_id: EpisodeId,

    /// The lease ID that authorized this attempt.
    lease_id: String,

    /// When the attempt started (nanoseconds since epoch).
    started_at_ns: u64,

    /// When the attempt ended (nanoseconds since epoch).
    ended_at_ns: Option<u64>,

    /// The outcome of the attempt.
    outcome: AttemptOutcome,

    /// Tokens consumed during this attempt.
    tokens_consumed: u64,

    /// Artifact IDs produced during this attempt.
    artifact_ids: Vec<ArtifactId>,

    /// Error message if the attempt failed.
    error_message: Option<String>,
}

/// The outcome of an execution attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AttemptOutcome {
    /// The attempt is still in progress.
    #[default]
    InProgress,

    /// The attempt completed successfully.
    Completed,

    /// The attempt failed with a recoverable error.
    Failed,

    /// The attempt was interrupted (e.g., budget exhausted).
    Interrupted,

    /// The attempt resulted in escalation.
    Escalated,
}

impl AttemptRecord {
    /// Creates a new attempt record.
    #[must_use]
    pub fn new(
        attempt_id: impl Into<String>,
        episode_id: impl Into<String>,
        lease_id: impl Into<String>,
        started_at_ns: u64,
    ) -> Self {
        Self {
            attempt_id: attempt_id.into(),
            episode_id: episode_id.into(),
            lease_id: lease_id.into(),
            started_at_ns,
            ended_at_ns: None,
            outcome: AttemptOutcome::InProgress,
            tokens_consumed: 0,
            artifact_ids: Vec::new(),
            error_message: None,
        }
    }

    /// Returns the attempt ID.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Returns the episode ID.
    #[must_use]
    pub fn episode_id(&self) -> &str {
        &self.episode_id
    }

    /// Returns the lease ID.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// Returns when the attempt started.
    #[must_use]
    pub const fn started_at_ns(&self) -> u64 {
        self.started_at_ns
    }

    /// Returns when the attempt ended, if it has ended.
    #[must_use]
    pub const fn ended_at_ns(&self) -> Option<u64> {
        self.ended_at_ns
    }

    /// Returns the outcome of the attempt.
    #[must_use]
    pub const fn outcome(&self) -> AttemptOutcome {
        self.outcome
    }

    /// Returns the tokens consumed during this attempt.
    #[must_use]
    pub const fn tokens_consumed(&self) -> u64 {
        self.tokens_consumed
    }

    /// Returns the artifact IDs produced during this attempt.
    #[must_use]
    pub fn artifact_ids(&self) -> &[ArtifactId] {
        &self.artifact_ids
    }

    /// Returns the error message, if any.
    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Returns `true` if this attempt is still in progress.
    #[must_use]
    pub const fn is_in_progress(&self) -> bool {
        matches!(self.outcome, AttemptOutcome::InProgress)
    }

    /// Returns `true` if this attempt completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self.outcome, AttemptOutcome::Completed)
    }

    /// Marks the attempt as completed.
    pub const fn complete(&mut self, ended_at_ns: u64, tokens_consumed: u64) {
        self.ended_at_ns = Some(ended_at_ns);
        self.outcome = AttemptOutcome::Completed;
        self.tokens_consumed = tokens_consumed;
    }

    /// Marks the attempt as failed.
    pub fn fail(&mut self, ended_at_ns: u64, error_message: impl Into<String>) {
        self.ended_at_ns = Some(ended_at_ns);
        self.outcome = AttemptOutcome::Failed;
        self.error_message = Some(error_message.into());
    }

    /// Marks the attempt as interrupted.
    pub const fn interrupt(&mut self, ended_at_ns: u64, tokens_consumed: u64) {
        self.ended_at_ns = Some(ended_at_ns);
        self.outcome = AttemptOutcome::Interrupted;
        self.tokens_consumed = tokens_consumed;
    }

    /// Marks the attempt as escalated.
    pub const fn escalate(&mut self, ended_at_ns: u64) {
        self.ended_at_ns = Some(ended_at_ns);
        self.outcome = AttemptOutcome::Escalated;
    }

    /// Adds an artifact ID to this attempt.
    pub fn add_artifact(&mut self, artifact_id: impl Into<ArtifactId>) {
        self.artifact_ids.push(artifact_id.into());
    }

    /// Adds tokens consumed to this attempt.
    pub const fn add_tokens(&mut self, tokens: u64) {
        self.tokens_consumed = self.tokens_consumed.saturating_add(tokens);
    }
}

impl AttemptOutcome {
    /// Returns the outcome as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Escalated => "escalated",
        }
    }
}

impl fmt::Display for AttemptOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A work object representing a unit of work in the holonic coordination
/// framework.
///
/// Work objects track the full lifecycle of a work item, including:
/// - Stable identifier (`WorkId`) that persists across restarts
/// - Lifecycle state tracking with validated transitions
/// - Requirement bindings for traceability
/// - Produced artifact references for evidence
/// - Execution attempt history with episode provenance
/// - Version for optimistic concurrency control
///
/// # Limits
///
/// To prevent unbounded state growth:
/// - Maximum [`MAX_ATTEMPTS`] attempts are stored (oldest pruned when exceeded)
/// - Maximum [`MAX_METADATA_ENTRIES`] metadata entries allowed
///
/// # Timestamp Precision
///
/// Timestamps are stored as nanoseconds since Unix epoch in a `u64`. This will
/// overflow around year 2554, which is acceptable for the foreseeable future.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkObject {
    /// Unique identifier for this work item.
    id: WorkId,

    /// Human-readable title or description of the work.
    title: String,

    /// Current lifecycle state.
    lifecycle: WorkLifecycle,

    /// Monotonically increasing version for optimistic concurrency control.
    ///
    /// This version increments on every state transition or mutation,
    /// providing a reliable way to detect concurrent modifications in
    /// distributed systems (independent of wall-clock time).
    version: u64,

    /// The lease ID currently assigned to this work.
    lease_id: Option<String>,

    /// Requirement IDs this work is bound to.
    requirement_ids: Vec<RequirementId>,

    /// Artifact IDs produced by this work.
    artifact_ids: Vec<ArtifactId>,

    /// History of execution attempts (limited to [`MAX_ATTEMPTS`]).
    attempts: Vec<AttemptRecord>,

    /// When the work was created (nanoseconds since epoch).
    created_at_ns: u64,

    /// When the work was last updated (nanoseconds since epoch).
    updated_at_ns: u64,

    /// Parent work ID (if this is a sub-work item).
    parent_work_id: Option<WorkId>,

    /// Reason for the current state (e.g., block reason, failure reason).
    state_reason: Option<String>,

    /// Additional metadata as key-value pairs (limited to
    /// [`MAX_METADATA_ENTRIES`]).
    metadata: Vec<(String, String)>,
}

impl WorkObject {
    /// Creates a new work object with the given ID and title.
    #[must_use]
    pub fn new(id: impl Into<WorkId>, title: impl Into<String>) -> Self {
        let now = current_timestamp_ns();
        Self {
            id: id.into(),
            title: title.into(),
            lifecycle: WorkLifecycle::Created,
            version: 1,
            lease_id: None,
            requirement_ids: Vec::new(),
            artifact_ids: Vec::new(),
            attempts: Vec::new(),
            created_at_ns: now,
            updated_at_ns: now,
            parent_work_id: None,
            state_reason: None,
            metadata: Vec::new(),
        }
    }

    /// Creates a new work object with a specific creation timestamp.
    ///
    /// This is useful for testing and deterministic replay.
    #[must_use]
    pub fn new_with_timestamp(
        id: impl Into<WorkId>,
        title: impl Into<String>,
        created_at_ns: u64,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            lifecycle: WorkLifecycle::Created,
            version: 1,
            lease_id: None,
            requirement_ids: Vec::new(),
            artifact_ids: Vec::new(),
            attempts: Vec::new(),
            created_at_ns,
            updated_at_ns: created_at_ns,
            parent_work_id: None,
            state_reason: None,
            metadata: Vec::new(),
        }
    }

    /// Returns the work ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the work title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> WorkLifecycle {
        self.lifecycle
    }

    /// Returns the version number for optimistic concurrency control.
    ///
    /// This version monotonically increments on every mutation, providing
    /// a reliable way to detect concurrent modifications.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the lease ID, if assigned.
    #[must_use]
    pub fn lease_id(&self) -> Option<&str> {
        self.lease_id.as_deref()
    }

    /// Returns the requirement IDs this work is bound to.
    #[must_use]
    pub fn requirement_ids(&self) -> &[RequirementId] {
        &self.requirement_ids
    }

    /// Returns the artifact IDs produced by this work.
    #[must_use]
    pub fn artifact_ids(&self) -> &[ArtifactId] {
        &self.artifact_ids
    }

    /// Returns the execution attempt history.
    #[must_use]
    pub fn attempts(&self) -> &[AttemptRecord] {
        &self.attempts
    }

    /// Returns when the work was created.
    #[must_use]
    pub const fn created_at_ns(&self) -> u64 {
        self.created_at_ns
    }

    /// Returns when the work was last updated.
    #[must_use]
    pub const fn updated_at_ns(&self) -> u64 {
        self.updated_at_ns
    }

    /// Returns the parent work ID, if any.
    #[must_use]
    pub fn parent_work_id(&self) -> Option<&str> {
        self.parent_work_id.as_deref()
    }

    /// Returns the reason for the current state.
    #[must_use]
    pub fn state_reason(&self) -> Option<&str> {
        self.state_reason.as_deref()
    }

    /// Returns the metadata as key-value pairs.
    #[must_use]
    pub fn metadata(&self) -> &[(String, String)] {
        &self.metadata
    }

    /// Returns `true` if the work is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.lifecycle.is_terminal()
    }

    /// Returns `true` if the work completed successfully.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        self.lifecycle.is_successful()
    }

    /// Returns the number of attempts made.
    #[must_use]
    pub fn attempt_count(&self) -> usize {
        self.attempts.len()
    }

    /// Returns the current (most recent) attempt, if any.
    #[must_use]
    pub fn current_attempt(&self) -> Option<&AttemptRecord> {
        self.attempts.last()
    }

    /// Returns a mutable reference to the current attempt, if any.
    pub fn current_attempt_mut(&mut self) -> Option<&mut AttemptRecord> {
        self.attempts.last_mut()
    }

    /// Sets the parent work ID.
    pub fn set_parent_work_id(&mut self, parent_id: impl Into<WorkId>) {
        self.parent_work_id = Some(parent_id.into());
    }

    /// Adds a requirement binding.
    pub fn bind_requirement(&mut self, requirement_id: impl Into<RequirementId>) {
        let req_id = requirement_id.into();
        if !self.requirement_ids.contains(&req_id) {
            self.requirement_ids.push(req_id);
        }
    }

    /// Adds an artifact reference.
    pub fn add_artifact(&mut self, artifact_id: impl Into<ArtifactId>) {
        self.artifact_ids.push(artifact_id.into());
    }

    /// Adds or updates a metadata key-value pair.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::ResourceExhausted` if adding a new key would
    /// exceed [`MAX_METADATA_ENTRIES`].
    pub fn set_metadata(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HolonError> {
        let key = key.into();

        // Check if key already exists (update case - no limit check needed)
        if let Some(entry) = self.metadata.iter_mut().find(|(k, _)| k == &key) {
            entry.1 = value.into();
            self.version = self.version.saturating_add(1);
            return Ok(());
        }

        // New key - check limit
        if self.metadata.len() >= MAX_METADATA_ENTRIES {
            return Err(HolonError::resource_exhausted(format!(
                "metadata limit exceeded: maximum {MAX_METADATA_ENTRIES} entries allowed"
            )));
        }

        self.metadata.push((key, value.into()));
        self.version = self.version.saturating_add(1);
        Ok(())
    }

    /// Gets a metadata value by key.
    #[must_use]
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    // =========================================================================
    // State Transitions
    // =========================================================================

    /// Validates and performs a state transition.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if the transition is not valid.
    fn transition_to(&mut self, target: WorkLifecycle) -> Result<WorkLifecycle, HolonError> {
        let current = self.lifecycle;
        if !current.can_transition_to(target) {
            return Err(HolonError::invalid_state(
                format!("valid from {current}: {:?}", current.valid_transitions()),
                target.to_string(),
            ));
        }
        let previous = self.lifecycle;
        self.lifecycle = target;
        self.version = self.version.saturating_add(1);
        self.updated_at_ns = current_timestamp_ns();
        Ok(previous)
    }

    /// Validates and performs a state transition with a specific timestamp.
    ///
    /// This is useful for testing and deterministic replay.
    fn transition_to_at(
        &mut self,
        target: WorkLifecycle,
        timestamp_ns: u64,
    ) -> Result<WorkLifecycle, HolonError> {
        let current = self.lifecycle;
        if !current.can_transition_to(target) {
            return Err(HolonError::invalid_state(
                format!("valid from {current}: {:?}", current.valid_transitions()),
                target.to_string(),
            ));
        }
        let previous = self.lifecycle;
        self.lifecycle = target;
        self.version = self.version.saturating_add(1);
        self.updated_at_ns = timestamp_ns;
        Ok(previous)
    }

    /// Transitions to the `Leased` state.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `Created` state.
    pub fn transition_to_leased(&mut self, lease_id: impl Into<String>) -> Result<(), HolonError> {
        self.transition_to(WorkLifecycle::Leased)?;
        self.lease_id = Some(lease_id.into());
        Ok(())
    }

    /// Transitions to the `Leased` state with a specific timestamp.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `Created` state.
    pub fn transition_to_leased_at(
        &mut self,
        lease_id: impl Into<String>,
        timestamp_ns: u64,
    ) -> Result<(), HolonError> {
        self.transition_to_at(WorkLifecycle::Leased, timestamp_ns)?;
        self.lease_id = Some(lease_id.into());
        Ok(())
    }

    /// Transitions to the `InProgress` state.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `Leased`, `Blocked`, or
    /// `Escalated` state.
    pub fn transition_to_in_progress(&mut self) -> Result<(), HolonError> {
        self.transition_to(WorkLifecycle::InProgress)?;
        self.state_reason = None;
        Ok(())
    }

    /// Transitions to the `InProgress` state with a specific timestamp.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `Leased`, `Blocked`, or
    /// `Escalated` state.
    pub fn transition_to_in_progress_at(&mut self, timestamp_ns: u64) -> Result<(), HolonError> {
        self.transition_to_at(WorkLifecycle::InProgress, timestamp_ns)?;
        self.state_reason = None;
        Ok(())
    }

    /// Transitions to the `Blocked` state with a reason.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` state.
    pub fn transition_to_blocked(&mut self, reason: impl Into<String>) -> Result<(), HolonError> {
        self.transition_to(WorkLifecycle::Blocked)?;
        self.state_reason = Some(reason.into());
        Ok(())
    }

    /// Transitions to the `Blocked` state with a specific timestamp.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` state.
    pub fn transition_to_blocked_at(
        &mut self,
        reason: impl Into<String>,
        timestamp_ns: u64,
    ) -> Result<(), HolonError> {
        self.transition_to_at(WorkLifecycle::Blocked, timestamp_ns)?;
        self.state_reason = Some(reason.into());
        Ok(())
    }

    /// Transitions to the `Completed` state.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` state.
    pub fn transition_to_completed(&mut self) -> Result<(), HolonError> {
        self.transition_to(WorkLifecycle::Completed)?;
        Ok(())
    }

    /// Transitions to the `Completed` state with a specific timestamp.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` state.
    pub fn transition_to_completed_at(&mut self, timestamp_ns: u64) -> Result<(), HolonError> {
        self.transition_to_at(WorkLifecycle::Completed, timestamp_ns)?;
        Ok(())
    }

    /// Transitions to the `Failed` state with a reason.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` state.
    pub fn transition_to_failed(&mut self, reason: impl Into<String>) -> Result<(), HolonError> {
        self.transition_to(WorkLifecycle::Failed)?;
        self.state_reason = Some(reason.into());
        Ok(())
    }

    /// Transitions to the `Failed` state with a specific timestamp.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` state.
    pub fn transition_to_failed_at(
        &mut self,
        reason: impl Into<String>,
        timestamp_ns: u64,
    ) -> Result<(), HolonError> {
        self.transition_to_at(WorkLifecycle::Failed, timestamp_ns)?;
        self.state_reason = Some(reason.into());
        Ok(())
    }

    /// Transitions to the `Escalated` state with a reason.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` or `Blocked`
    /// state.
    pub fn transition_to_escalated(&mut self, reason: impl Into<String>) -> Result<(), HolonError> {
        self.transition_to(WorkLifecycle::Escalated)?;
        self.state_reason = Some(reason.into());
        Ok(())
    }

    /// Transitions to the `Escalated` state with a specific timestamp.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` or `Blocked`
    /// state.
    pub fn transition_to_escalated_at(
        &mut self,
        reason: impl Into<String>,
        timestamp_ns: u64,
    ) -> Result<(), HolonError> {
        self.transition_to_at(WorkLifecycle::Escalated, timestamp_ns)?;
        self.state_reason = Some(reason.into());
        Ok(())
    }

    /// Transitions to the `Cancelled` state with a reason.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if in a terminal state other than
    /// `Cancelled`.
    pub fn transition_to_cancelled(&mut self, reason: impl Into<String>) -> Result<(), HolonError> {
        self.transition_to(WorkLifecycle::Cancelled)?;
        self.state_reason = Some(reason.into());
        self.lease_id = None;
        Ok(())
    }

    /// Transitions to the `Cancelled` state with a specific timestamp.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if in a terminal state other than
    /// `Cancelled`.
    pub fn transition_to_cancelled_at(
        &mut self,
        reason: impl Into<String>,
        timestamp_ns: u64,
    ) -> Result<(), HolonError> {
        self.transition_to_at(WorkLifecycle::Cancelled, timestamp_ns)?;
        self.state_reason = Some(reason.into());
        self.lease_id = None;
        Ok(())
    }

    // =========================================================================
    // Attempt Management
    // =========================================================================

    /// Starts a new execution attempt.
    ///
    /// The work must be in `InProgress` state to start an attempt. If the
    /// number of attempts exceeds [`MAX_ATTEMPTS`], the oldest attempt is
    /// pruned to make room for the new one.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` state.
    /// Returns `HolonError::MissingContext` if no lease ID is set.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal operation. The internal
    /// `expect` call is guarded by an invariant that is always satisfied.
    pub fn start_attempt(
        &mut self,
        attempt_id: impl Into<String>,
        episode_id: impl Into<String>,
    ) -> Result<&mut AttemptRecord, HolonError> {
        if self.lifecycle != WorkLifecycle::InProgress {
            return Err(HolonError::invalid_state(
                "InProgress",
                self.lifecycle.to_string(),
            ));
        }

        let lease_id = self
            .lease_id
            .clone()
            .ok_or_else(|| HolonError::missing_context("lease_id"))?;

        // Prune oldest attempts if at limit
        while self.attempts.len() >= MAX_ATTEMPTS {
            self.attempts.remove(0);
        }

        let attempt = AttemptRecord::new(attempt_id, episode_id, lease_id, current_timestamp_ns());
        self.attempts.push(attempt);
        self.version = self.version.saturating_add(1);

        // SAFETY: We just pushed an element, so last_mut will always succeed.
        // Using unwrap_unchecked would require unsafe, so we use expect with a
        // clear message instead.
        Ok(self
            .attempts
            .last_mut()
            .expect("internal invariant: just pushed an attempt"))
    }

    /// Starts a new execution attempt with a specific timestamp.
    ///
    /// If the number of attempts exceeds [`MAX_ATTEMPTS`], the oldest attempt
    /// is pruned to make room for the new one.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidState` if not in `InProgress` state.
    /// Returns `HolonError::MissingContext` if no lease ID is set.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal operation. The internal
    /// `expect` call is guarded by an invariant that is always satisfied.
    pub fn start_attempt_at(
        &mut self,
        attempt_id: impl Into<String>,
        episode_id: impl Into<String>,
        timestamp_ns: u64,
    ) -> Result<&mut AttemptRecord, HolonError> {
        if self.lifecycle != WorkLifecycle::InProgress {
            return Err(HolonError::invalid_state(
                "InProgress",
                self.lifecycle.to_string(),
            ));
        }

        let lease_id = self
            .lease_id
            .clone()
            .ok_or_else(|| HolonError::missing_context("lease_id"))?;

        // Prune oldest attempts if at limit
        while self.attempts.len() >= MAX_ATTEMPTS {
            self.attempts.remove(0);
        }

        let attempt = AttemptRecord::new(attempt_id, episode_id, lease_id, timestamp_ns);
        self.attempts.push(attempt);
        self.version = self.version.saturating_add(1);

        // SAFETY: We just pushed an element, so last_mut will always succeed.
        Ok(self
            .attempts
            .last_mut()
            .expect("internal invariant: just pushed an attempt"))
    }
}

/// Returns the current timestamp in nanoseconds since epoch.
fn current_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::cast_possible_truncation)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// A lifecycle event emitted when a work object transitions state.
///
/// These events can be recorded to a ledger for auditing and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkLifecycleEvent {
    /// The work ID this event belongs to.
    pub work_id: WorkId,

    /// The previous lifecycle state.
    pub from_state: WorkLifecycle,

    /// The new lifecycle state.
    pub to_state: WorkLifecycle,

    /// When the transition occurred (nanoseconds since epoch).
    pub timestamp_ns: u64,

    /// The lease ID at the time of transition.
    pub lease_id: Option<String>,

    /// Reason for the transition (if applicable).
    pub reason: Option<String>,

    /// The attempt ID associated with this transition (if applicable).
    pub attempt_id: Option<String>,
}

impl WorkLifecycleEvent {
    /// Creates a new lifecycle event.
    #[must_use]
    pub fn new(
        work_id: impl Into<WorkId>,
        from_state: WorkLifecycle,
        to_state: WorkLifecycle,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            work_id: work_id.into(),
            from_state,
            to_state,
            timestamp_ns,
            lease_id: None,
            reason: None,
            attempt_id: None,
        }
    }

    /// Sets the lease ID.
    #[must_use]
    pub fn with_lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = Some(lease_id.into());
        self
    }

    /// Sets the reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Sets the attempt ID.
    #[must_use]
    pub fn with_attempt_id(mut self, attempt_id: impl Into<String>) -> Self {
        self.attempt_id = Some(attempt_id.into());
        self
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    // =========================================================================
    // WorkLifecycle Tests
    // =========================================================================

    #[test]
    fn test_lifecycle_default_is_created() {
        assert_eq!(WorkLifecycle::default(), WorkLifecycle::Created);
    }

    #[test]
    fn test_lifecycle_terminal_states() {
        assert!(!WorkLifecycle::Created.is_terminal());
        assert!(!WorkLifecycle::Leased.is_terminal());
        assert!(!WorkLifecycle::InProgress.is_terminal());
        assert!(!WorkLifecycle::Blocked.is_terminal());
        assert!(WorkLifecycle::Completed.is_terminal());
        assert!(WorkLifecycle::Failed.is_terminal());
        assert!(!WorkLifecycle::Escalated.is_terminal());
        assert!(WorkLifecycle::Cancelled.is_terminal());
    }

    #[test]
    fn test_lifecycle_successful_states() {
        assert!(!WorkLifecycle::Created.is_successful());
        assert!(!WorkLifecycle::InProgress.is_successful());
        assert!(WorkLifecycle::Completed.is_successful());
        assert!(!WorkLifecycle::Failed.is_successful());
    }

    #[test]
    fn test_lifecycle_active_states() {
        assert!(!WorkLifecycle::Created.is_active());
        assert!(!WorkLifecycle::Leased.is_active());
        assert!(WorkLifecycle::InProgress.is_active());
        assert!(!WorkLifecycle::Blocked.is_active());
        assert!(!WorkLifecycle::Completed.is_active());
    }

    #[test]
    fn test_lifecycle_waiting_states() {
        assert!(WorkLifecycle::Created.is_waiting());
        assert!(WorkLifecycle::Leased.is_waiting());
        assert!(!WorkLifecycle::InProgress.is_waiting());
        assert!(WorkLifecycle::Blocked.is_waiting());
        assert!(WorkLifecycle::Escalated.is_waiting());
        assert!(!WorkLifecycle::Completed.is_waiting());
    }

    #[test]
    fn test_lifecycle_as_str() {
        assert_eq!(WorkLifecycle::Created.as_str(), "created");
        assert_eq!(WorkLifecycle::Leased.as_str(), "leased");
        assert_eq!(WorkLifecycle::InProgress.as_str(), "in_progress");
        assert_eq!(WorkLifecycle::Blocked.as_str(), "blocked");
        assert_eq!(WorkLifecycle::Completed.as_str(), "completed");
        assert_eq!(WorkLifecycle::Failed.as_str(), "failed");
        assert_eq!(WorkLifecycle::Escalated.as_str(), "escalated");
        assert_eq!(WorkLifecycle::Cancelled.as_str(), "cancelled");
    }

    #[test]
    fn test_lifecycle_display() {
        assert_eq!(WorkLifecycle::InProgress.to_string(), "in_progress");
    }

    #[test]
    fn test_lifecycle_valid_transitions_from_created() {
        let valid = WorkLifecycle::Created.valid_transitions();
        assert!(valid.contains(&WorkLifecycle::Leased));
        assert!(valid.contains(&WorkLifecycle::Cancelled));
        assert!(!valid.contains(&WorkLifecycle::InProgress));
        assert!(!valid.contains(&WorkLifecycle::Completed));
    }

    #[test]
    fn test_lifecycle_valid_transitions_from_leased() {
        let valid = WorkLifecycle::Leased.valid_transitions();
        assert!(valid.contains(&WorkLifecycle::InProgress));
        assert!(valid.contains(&WorkLifecycle::Cancelled));
        assert!(!valid.contains(&WorkLifecycle::Completed));
    }

    #[test]
    fn test_lifecycle_valid_transitions_from_in_progress() {
        let valid = WorkLifecycle::InProgress.valid_transitions();
        assert!(valid.contains(&WorkLifecycle::Blocked));
        assert!(valid.contains(&WorkLifecycle::Completed));
        assert!(valid.contains(&WorkLifecycle::Failed));
        assert!(valid.contains(&WorkLifecycle::Escalated));
        assert!(!valid.contains(&WorkLifecycle::Created));
        assert!(!valid.contains(&WorkLifecycle::Cancelled));
    }

    #[test]
    fn test_lifecycle_valid_transitions_from_blocked() {
        let valid = WorkLifecycle::Blocked.valid_transitions();
        assert!(valid.contains(&WorkLifecycle::InProgress));
        assert!(valid.contains(&WorkLifecycle::Escalated));
        assert!(valid.contains(&WorkLifecycle::Cancelled));
    }

    #[test]
    fn test_lifecycle_valid_transitions_from_escalated() {
        let valid = WorkLifecycle::Escalated.valid_transitions();
        assert!(valid.contains(&WorkLifecycle::InProgress));
        assert!(valid.contains(&WorkLifecycle::Cancelled));
    }

    #[test]
    fn test_lifecycle_terminal_states_have_no_transitions() {
        assert!(WorkLifecycle::Completed.valid_transitions().is_empty());
        assert!(WorkLifecycle::Failed.valid_transitions().is_empty());
        assert!(WorkLifecycle::Cancelled.valid_transitions().is_empty());
    }

    #[test]
    fn test_can_transition_to() {
        assert!(WorkLifecycle::Created.can_transition_to(WorkLifecycle::Leased));
        assert!(!WorkLifecycle::Created.can_transition_to(WorkLifecycle::Completed));
        assert!(WorkLifecycle::InProgress.can_transition_to(WorkLifecycle::Completed));
        assert!(!WorkLifecycle::Completed.can_transition_to(WorkLifecycle::Created));
    }

    // =========================================================================
    // AttemptRecord Tests
    // =========================================================================

    #[test]
    fn test_attempt_record_new() {
        let attempt = AttemptRecord::new("att-1", "ep-1", "lease-1", 1000);
        assert_eq!(attempt.attempt_id(), "att-1");
        assert_eq!(attempt.episode_id(), "ep-1");
        assert_eq!(attempt.lease_id(), "lease-1");
        assert_eq!(attempt.started_at_ns(), 1000);
        assert!(attempt.ended_at_ns().is_none());
        assert_eq!(attempt.outcome(), AttemptOutcome::InProgress);
        assert!(attempt.is_in_progress());
    }

    #[test]
    fn test_attempt_record_complete() {
        let mut attempt = AttemptRecord::new("att-1", "ep-1", "lease-1", 1000);
        attempt.complete(2000, 500);

        assert_eq!(attempt.ended_at_ns(), Some(2000));
        assert_eq!(attempt.outcome(), AttemptOutcome::Completed);
        assert_eq!(attempt.tokens_consumed(), 500);
        assert!(attempt.is_completed());
        assert!(!attempt.is_in_progress());
    }

    #[test]
    fn test_attempt_record_fail() {
        let mut attempt = AttemptRecord::new("att-1", "ep-1", "lease-1", 1000);
        attempt.fail(2000, "timeout");

        assert_eq!(attempt.ended_at_ns(), Some(2000));
        assert_eq!(attempt.outcome(), AttemptOutcome::Failed);
        assert_eq!(attempt.error_message(), Some("timeout"));
    }

    #[test]
    fn test_attempt_record_interrupt() {
        let mut attempt = AttemptRecord::new("att-1", "ep-1", "lease-1", 1000);
        attempt.interrupt(2000, 300);

        assert_eq!(attempt.outcome(), AttemptOutcome::Interrupted);
        assert_eq!(attempt.tokens_consumed(), 300);
    }

    #[test]
    fn test_attempt_record_escalate() {
        let mut attempt = AttemptRecord::new("att-1", "ep-1", "lease-1", 1000);
        attempt.escalate(2000);

        assert_eq!(attempt.outcome(), AttemptOutcome::Escalated);
    }

    #[test]
    fn test_attempt_record_add_artifact() {
        let mut attempt = AttemptRecord::new("att-1", "ep-1", "lease-1", 1000);
        assert!(attempt.artifact_ids().is_empty());

        attempt.add_artifact("art-1");
        attempt.add_artifact("art-2");

        assert_eq!(attempt.artifact_ids(), &["art-1", "art-2"]);
    }

    #[test]
    fn test_attempt_record_add_tokens() {
        let mut attempt = AttemptRecord::new("att-1", "ep-1", "lease-1", 1000);
        assert_eq!(attempt.tokens_consumed(), 0);

        attempt.add_tokens(100);
        assert_eq!(attempt.tokens_consumed(), 100);

        attempt.add_tokens(50);
        assert_eq!(attempt.tokens_consumed(), 150);
    }

    #[test]
    fn test_attempt_outcome_as_str() {
        assert_eq!(AttemptOutcome::InProgress.as_str(), "in_progress");
        assert_eq!(AttemptOutcome::Completed.as_str(), "completed");
        assert_eq!(AttemptOutcome::Failed.as_str(), "failed");
        assert_eq!(AttemptOutcome::Interrupted.as_str(), "interrupted");
        assert_eq!(AttemptOutcome::Escalated.as_str(), "escalated");
    }

    // =========================================================================
    // WorkObject Tests
    // =========================================================================

    #[test]
    fn test_work_object_new() {
        let work = WorkObject::new("work-1", "Test work");
        assert_eq!(work.id(), "work-1");
        assert_eq!(work.title(), "Test work");
        assert_eq!(work.lifecycle(), WorkLifecycle::Created);
        assert!(work.lease_id().is_none());
        assert!(work.requirement_ids().is_empty());
        assert!(work.artifact_ids().is_empty());
        assert!(work.attempts().is_empty());
        assert!(!work.is_terminal());
    }

    #[test]
    fn test_work_object_new_with_timestamp() {
        let work = WorkObject::new_with_timestamp("work-1", "Test", 1000);
        assert_eq!(work.created_at_ns(), 1000);
        assert_eq!(work.updated_at_ns(), 1000);
    }

    #[test]
    fn test_work_object_bind_requirement() {
        let mut work = WorkObject::new("work-1", "Test");
        work.bind_requirement("REQ-001");
        work.bind_requirement("REQ-002");
        work.bind_requirement("REQ-001"); // Duplicate should be ignored

        assert_eq!(work.requirement_ids(), &["REQ-001", "REQ-002"]);
    }

    #[test]
    fn test_work_object_add_artifact() {
        let mut work = WorkObject::new("work-1", "Test");
        work.add_artifact("art-1");
        work.add_artifact("art-2");

        assert_eq!(work.artifact_ids(), &["art-1", "art-2"]);
    }

    #[test]
    fn test_work_object_metadata() {
        let mut work = WorkObject::new("work-1", "Test");
        work.set_metadata("key1", "value1").unwrap();
        work.set_metadata("key2", "value2").unwrap();
        work.set_metadata("key1", "updated").unwrap(); // Update existing

        assert_eq!(work.get_metadata("key1"), Some("updated"));
        assert_eq!(work.get_metadata("key2"), Some("value2"));
        assert_eq!(work.get_metadata("key3"), None);
    }

    #[test]
    fn test_work_object_set_parent() {
        let mut work = WorkObject::new("work-1", "Test");
        assert!(work.parent_work_id().is_none());

        work.set_parent_work_id("parent-1");
        assert_eq!(work.parent_work_id(), Some("parent-1"));
    }

    #[test]
    fn test_version_increments_on_transition() {
        let mut work = WorkObject::new_with_timestamp("work-1", "Test", 1000);
        assert_eq!(work.version(), 1);

        work.transition_to_leased_at("lease-1", 2000).unwrap();
        assert_eq!(work.version(), 2);

        work.transition_to_in_progress_at(3000).unwrap();
        assert_eq!(work.version(), 3);

        work.transition_to_completed_at(4000).unwrap();
        assert_eq!(work.version(), 4);
    }

    #[test]
    fn test_version_increments_on_metadata_change() {
        let mut work = WorkObject::new_with_timestamp("work-1", "Test", 1000);
        assert_eq!(work.version(), 1);

        work.set_metadata("key1", "value1").unwrap();
        assert_eq!(work.version(), 2);

        // Update existing key also increments version
        work.set_metadata("key1", "updated").unwrap();
        assert_eq!(work.version(), 3);
    }

    #[test]
    fn test_metadata_limit_enforced() {
        let mut work = WorkObject::new("work-1", "Test");

        // Fill to the limit
        for i in 0..MAX_METADATA_ENTRIES {
            work.set_metadata(format!("key{i}"), "value").unwrap();
        }

        // Next new key should fail
        let result = work.set_metadata("one_more_key", "value");
        assert!(result.is_err());

        // Updating existing key should still work
        let result = work.set_metadata("key0", "updated");
        assert!(result.is_ok());
    }

    #[test]
    fn test_attempts_pruned_at_limit() {
        let mut work = WorkObject::new_with_timestamp("work-1", "Test", 1000);
        work.transition_to_leased_at("lease-1", 2000).unwrap();
        work.transition_to_in_progress_at(3000).unwrap();

        // Create MAX_ATTEMPTS + 5 attempts
        for i in 0..(MAX_ATTEMPTS + 5) {
            work.start_attempt_at(format!("att-{i}"), format!("ep-{i}"), 4000 + i as u64)
                .unwrap();
        }

        // Should have exactly MAX_ATTEMPTS
        assert_eq!(work.attempt_count(), MAX_ATTEMPTS);

        // Oldest attempts should have been pruned - first attempt should be att-5
        assert_eq!(work.attempts()[0].attempt_id(), "att-5");

        // Most recent should be the last one added
        assert_eq!(
            work.current_attempt().unwrap().attempt_id(),
            format!("att-{}", MAX_ATTEMPTS + 4)
        );
    }

    // =========================================================================
    // WorkObject State Transition Tests
    // =========================================================================

    #[test]
    fn test_transition_created_to_leased() {
        let mut work = WorkObject::new("work-1", "Test");
        assert!(work.transition_to_leased("lease-1").is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::Leased);
        assert_eq!(work.lease_id(), Some("lease-1"));
    }

    #[test]
    fn test_transition_leased_to_in_progress() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        assert!(work.transition_to_in_progress().is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::InProgress);
    }

    #[test]
    fn test_transition_in_progress_to_completed() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        assert!(work.transition_to_completed().is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::Completed);
        assert!(work.is_terminal());
        assert!(work.is_successful());
    }

    #[test]
    fn test_transition_in_progress_to_failed() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        assert!(work.transition_to_failed("timeout").is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::Failed);
        assert_eq!(work.state_reason(), Some("timeout"));
        assert!(work.is_terminal());
        assert!(!work.is_successful());
    }

    #[test]
    fn test_transition_in_progress_to_blocked() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        assert!(work.transition_to_blocked("waiting for dependency").is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::Blocked);
        assert_eq!(work.state_reason(), Some("waiting for dependency"));
    }

    #[test]
    fn test_transition_blocked_to_in_progress() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        work.transition_to_blocked("waiting").unwrap();
        assert!(work.transition_to_in_progress().is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::InProgress);
        assert!(work.state_reason().is_none()); // Reason should be cleared
    }

    #[test]
    fn test_transition_in_progress_to_escalated() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        assert!(work.transition_to_escalated("beyond scope").is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::Escalated);
        assert_eq!(work.state_reason(), Some("beyond scope"));
    }

    #[test]
    fn test_transition_escalated_to_in_progress() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        work.transition_to_escalated("needs help").unwrap();
        assert!(work.transition_to_in_progress().is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::InProgress);
    }

    #[test]
    fn test_transition_to_cancelled_from_various_states() {
        // From Created
        let mut work = WorkObject::new("work-1", "Test");
        assert!(work.transition_to_cancelled("abandoned").is_ok());
        assert_eq!(work.lifecycle(), WorkLifecycle::Cancelled);

        // From Leased
        let mut work = WorkObject::new("work-2", "Test");
        work.transition_to_leased("lease-1").unwrap();
        assert!(work.transition_to_cancelled("abandoned").is_ok());
        assert!(work.lease_id().is_none()); // Lease should be cleared

        // From Blocked
        let mut work = WorkObject::new("work-3", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        work.transition_to_blocked("waiting").unwrap();
        assert!(work.transition_to_cancelled("abandoned").is_ok());

        // From Escalated
        let mut work = WorkObject::new("work-4", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        work.transition_to_escalated("help").unwrap();
        assert!(work.transition_to_cancelled("abandoned").is_ok());
    }

    // =========================================================================
    // Invalid Transition Tests
    // =========================================================================

    #[test]
    fn test_invalid_transition_created_to_completed() {
        let mut work = WorkObject::new("work-1", "Test");
        let result = work.transition_to_completed();
        assert!(result.is_err());
        assert_eq!(work.lifecycle(), WorkLifecycle::Created);
    }

    #[test]
    fn test_invalid_transition_created_to_in_progress() {
        let mut work = WorkObject::new("work-1", "Test");
        let result = work.transition_to_in_progress();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_leased_to_completed() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        let result = work.transition_to_completed();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_from_terminal_state() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        work.transition_to_completed().unwrap();

        // Cannot transition from Completed
        assert!(work.transition_to_in_progress().is_err());
        assert!(work.transition_to_failed("reason").is_err());
        assert!(work.transition_to_cancelled("reason").is_err());
    }

    #[test]
    fn test_invalid_transition_in_progress_to_leased() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        let result = work.transition_to_leased("lease-2");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_in_progress_to_cancelled() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();
        // InProgress cannot directly transition to Cancelled
        let result = work.transition_to_cancelled("reason");
        assert!(result.is_err());
    }

    // =========================================================================
    // Attempt Management Tests
    // =========================================================================

    #[test]
    fn test_start_attempt_in_progress() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();

        let attempt = work.start_attempt_at("att-1", "ep-1", 1000).unwrap();
        assert_eq!(attempt.attempt_id(), "att-1");
        assert_eq!(attempt.episode_id(), "ep-1");
        assert_eq!(attempt.lease_id(), "lease-1");

        assert_eq!(work.attempt_count(), 1);
        assert_eq!(work.current_attempt().unwrap().attempt_id(), "att-1");
    }

    #[test]
    fn test_start_attempt_not_in_progress() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();

        let result = work.start_attempt("att-1", "ep-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_attempts() {
        let mut work = WorkObject::new("work-1", "Test");
        work.transition_to_leased("lease-1").unwrap();
        work.transition_to_in_progress().unwrap();

        work.start_attempt_at("att-1", "ep-1", 1000).unwrap();
        work.current_attempt_mut()
            .unwrap()
            .fail(2000, "first failure");

        work.start_attempt_at("att-2", "ep-2", 3000).unwrap();
        work.current_attempt_mut().unwrap().complete(4000, 500);

        assert_eq!(work.attempt_count(), 2);
        assert!(work.attempts()[0].outcome() == AttemptOutcome::Failed);
        assert!(work.attempts()[1].outcome() == AttemptOutcome::Completed);
    }

    // =========================================================================
    // WorkLifecycleEvent Tests
    // =========================================================================

    #[test]
    fn test_lifecycle_event_new() {
        let event = WorkLifecycleEvent::new(
            "work-1",
            WorkLifecycle::Created,
            WorkLifecycle::Leased,
            1000,
        );
        assert_eq!(event.work_id, "work-1");
        assert_eq!(event.from_state, WorkLifecycle::Created);
        assert_eq!(event.to_state, WorkLifecycle::Leased);
        assert_eq!(event.timestamp_ns, 1000);
        assert!(event.lease_id.is_none());
        assert!(event.reason.is_none());
    }

    #[test]
    fn test_lifecycle_event_with_details() {
        let event = WorkLifecycleEvent::new(
            "work-1",
            WorkLifecycle::InProgress,
            WorkLifecycle::Failed,
            1000,
        )
        .with_lease_id("lease-1")
        .with_reason("timeout")
        .with_attempt_id("att-1");

        assert_eq!(event.lease_id, Some("lease-1".to_string()));
        assert_eq!(event.reason, Some("timeout".to_string()));
        assert_eq!(event.attempt_id, Some("att-1".to_string()));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;

    /// A minimal state machine reference model for property testing.
    ///
    /// This model captures only the valid transitions and can be used
    /// to verify the actual implementation matches the specification.
    struct StateMachineModel {
        state: WorkLifecycle,
    }

    impl StateMachineModel {
        fn new() -> Self {
            Self {
                state: WorkLifecycle::Created,
            }
        }

        fn transition(&mut self, target: WorkLifecycle) -> bool {
            if self.state.can_transition_to(target) {
                self.state = target;
                true
            } else {
                false
            }
        }
    }

    /// Test that valid transitions succeed in both model and implementation.
    #[test]
    fn test_valid_transitions_match_model() {
        let transitions = [
            (WorkLifecycle::Created, WorkLifecycle::Leased),
            (WorkLifecycle::Created, WorkLifecycle::Cancelled),
            (WorkLifecycle::Leased, WorkLifecycle::InProgress),
            (WorkLifecycle::Leased, WorkLifecycle::Cancelled),
            (WorkLifecycle::InProgress, WorkLifecycle::Blocked),
            (WorkLifecycle::InProgress, WorkLifecycle::Completed),
            (WorkLifecycle::InProgress, WorkLifecycle::Failed),
            (WorkLifecycle::InProgress, WorkLifecycle::Escalated),
            (WorkLifecycle::Blocked, WorkLifecycle::InProgress),
            (WorkLifecycle::Blocked, WorkLifecycle::Escalated),
            (WorkLifecycle::Blocked, WorkLifecycle::Cancelled),
            (WorkLifecycle::Escalated, WorkLifecycle::InProgress),
            (WorkLifecycle::Escalated, WorkLifecycle::Cancelled),
        ];

        for (from, to) in transitions {
            let model_result = from.can_transition_to(to);
            assert!(model_result, "Model should allow {from:?} -> {to:?}");
        }
    }

    /// Test that terminal states have no outgoing transitions.
    #[test]
    fn test_terminal_states_have_no_transitions() {
        let terminal_states = [
            WorkLifecycle::Completed,
            WorkLifecycle::Failed,
            WorkLifecycle::Cancelled,
        ];

        let all_states = [
            WorkLifecycle::Created,
            WorkLifecycle::Leased,
            WorkLifecycle::InProgress,
            WorkLifecycle::Blocked,
            WorkLifecycle::Completed,
            WorkLifecycle::Failed,
            WorkLifecycle::Escalated,
            WorkLifecycle::Cancelled,
        ];

        for terminal in terminal_states {
            for target in all_states {
                assert!(
                    !terminal.can_transition_to(target),
                    "Terminal state {terminal:?} should not transition to {target:?}",
                );
            }
        }
    }

    /// Test the happy path: `Created` -> `Leased` -> `InProgress` ->
    /// `Completed`.
    #[test]
    fn test_happy_path_state_machine() {
        let mut model = StateMachineModel::new();
        let mut work = WorkObject::new_with_timestamp("work-1", "Test", 1000);

        // Created -> Leased
        assert!(model.transition(WorkLifecycle::Leased));
        assert!(work.transition_to_leased_at("lease-1", 2000).is_ok());
        assert_eq!(model.state, work.lifecycle());

        // Leased -> InProgress
        assert!(model.transition(WorkLifecycle::InProgress));
        assert!(work.transition_to_in_progress_at(3000).is_ok());
        assert_eq!(model.state, work.lifecycle());

        // InProgress -> Completed
        assert!(model.transition(WorkLifecycle::Completed));
        assert!(work.transition_to_completed_at(4000).is_ok());
        assert_eq!(model.state, work.lifecycle());

        assert!(model.state.is_terminal());
        assert!(work.is_terminal());
    }

    /// Test the failure path: `Created` -> `Leased` -> `InProgress` ->
    /// `Failed`.
    #[test]
    fn test_failure_path_state_machine() {
        let mut model = StateMachineModel::new();
        let mut work = WorkObject::new_with_timestamp("work-1", "Test", 1000);

        model.transition(WorkLifecycle::Leased);
        work.transition_to_leased_at("lease-1", 2000).unwrap();

        model.transition(WorkLifecycle::InProgress);
        work.transition_to_in_progress_at(3000).unwrap();

        model.transition(WorkLifecycle::Failed);
        work.transition_to_failed_at("error", 4000).unwrap();

        assert_eq!(model.state, work.lifecycle());
        assert!(work.is_terminal());
        assert!(!work.is_successful());
    }

    /// Test the blocked recovery path.
    #[test]
    fn test_blocked_recovery_path() {
        let mut model = StateMachineModel::new();
        let mut work = WorkObject::new_with_timestamp("work-1", "Test", 1000);

        model.transition(WorkLifecycle::Leased);
        work.transition_to_leased_at("lease-1", 2000).unwrap();

        model.transition(WorkLifecycle::InProgress);
        work.transition_to_in_progress_at(3000).unwrap();

        model.transition(WorkLifecycle::Blocked);
        work.transition_to_blocked_at("waiting", 4000).unwrap();
        assert_eq!(model.state, work.lifecycle());

        // Recover from blocked
        model.transition(WorkLifecycle::InProgress);
        work.transition_to_in_progress_at(5000).unwrap();
        assert_eq!(model.state, work.lifecycle());

        model.transition(WorkLifecycle::Completed);
        work.transition_to_completed_at(6000).unwrap();
        assert!(work.is_terminal());
    }

    /// Test the escalation path.
    #[test]
    fn test_escalation_path() {
        let mut model = StateMachineModel::new();
        let mut work = WorkObject::new_with_timestamp("work-1", "Test", 1000);

        model.transition(WorkLifecycle::Leased);
        work.transition_to_leased_at("lease-1", 2000).unwrap();

        model.transition(WorkLifecycle::InProgress);
        work.transition_to_in_progress_at(3000).unwrap();

        model.transition(WorkLifecycle::Escalated);
        work.transition_to_escalated_at("needs help", 4000).unwrap();
        assert_eq!(model.state, work.lifecycle());

        // Continue after escalation
        model.transition(WorkLifecycle::InProgress);
        work.transition_to_in_progress_at(5000).unwrap();
        assert_eq!(model.state, work.lifecycle());
    }

    /// Test that all invalid transitions are properly rejected.
    #[test]
    fn test_invalid_transitions_rejected() {
        // These are all transitions that should fail
        let invalid_transitions = [
            // From Created - only Leased and Cancelled are valid
            (WorkLifecycle::Created, WorkLifecycle::InProgress),
            (WorkLifecycle::Created, WorkLifecycle::Blocked),
            (WorkLifecycle::Created, WorkLifecycle::Completed),
            (WorkLifecycle::Created, WorkLifecycle::Failed),
            (WorkLifecycle::Created, WorkLifecycle::Escalated),
            // From Leased - only InProgress and Cancelled are valid
            (WorkLifecycle::Leased, WorkLifecycle::Created),
            (WorkLifecycle::Leased, WorkLifecycle::Blocked),
            (WorkLifecycle::Leased, WorkLifecycle::Completed),
            (WorkLifecycle::Leased, WorkLifecycle::Failed),
            (WorkLifecycle::Leased, WorkLifecycle::Escalated),
            // From InProgress - cannot go back or cancel directly
            (WorkLifecycle::InProgress, WorkLifecycle::Created),
            (WorkLifecycle::InProgress, WorkLifecycle::Leased),
            (WorkLifecycle::InProgress, WorkLifecycle::Cancelled),
            // From Blocked - cannot complete or fail directly
            (WorkLifecycle::Blocked, WorkLifecycle::Created),
            (WorkLifecycle::Blocked, WorkLifecycle::Leased),
            (WorkLifecycle::Blocked, WorkLifecycle::Completed),
            (WorkLifecycle::Blocked, WorkLifecycle::Failed),
            // From Escalated - limited transitions
            (WorkLifecycle::Escalated, WorkLifecycle::Created),
            (WorkLifecycle::Escalated, WorkLifecycle::Leased),
            (WorkLifecycle::Escalated, WorkLifecycle::Blocked),
            (WorkLifecycle::Escalated, WorkLifecycle::Completed),
            (WorkLifecycle::Escalated, WorkLifecycle::Failed),
        ];

        for (from, to) in invalid_transitions {
            assert!(
                !from.can_transition_to(to),
                "Transition {from:?} -> {to:?} should be invalid",
            );
        }
    }

    /// Test state machine determinism: same sequence always produces same
    /// result.
    #[test]
    fn test_determinism() {
        let run_sequence = || {
            let mut work = WorkObject::new_with_timestamp("work-1", "Test", 1000);
            work.transition_to_leased_at("lease-1", 2000).unwrap();
            work.transition_to_in_progress_at(3000).unwrap();
            work.transition_to_blocked_at("waiting", 4000).unwrap();
            work.transition_to_in_progress_at(5000).unwrap();
            work.transition_to_completed_at(6000).unwrap();
            work
        };

        let work1 = run_sequence();
        let work2 = run_sequence();

        assert_eq!(work1.lifecycle(), work2.lifecycle());
        assert_eq!(work1.updated_at_ns(), work2.updated_at_ns());
    }
}
