//! Ledger events for episode lifecycle tracking.
//!
//! This module defines the event types that are emitted during episode
//! execution and recorded to the ledger for auditing and replay. Events follow
//! an append-only model and are immutable once created.
//!
//! # Event Types
//!
//! - [`EpisodeStarted`]: Emitted when an episode begins execution
//! - [`EpisodeCompleted`]: Emitted when an episode finishes (success or
//!   failure)
//! - [`EpisodeEvent`]: Enum wrapper for all episode-related events
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::ledger::{
//!     EpisodeCompleted, EpisodeCompletionReason, EpisodeStarted,
//! };
//!
//! // Create an episode started event
//! let started = EpisodeStarted::try_new(
//!     "ep-001",
//!     "work-123",
//!     "lease-456",
//!     1,
//!     1_000_000_000,
//! )
//! .expect("valid IDs");
//!
//! // Create a completion event
//! let completed = EpisodeCompleted::new(
//!     "ep-001",
//!     EpisodeCompletionReason::GoalSatisfied,
//!     1_500_000_000,
//! )
//! .with_tokens_consumed(500)
//! .with_artifact_count(2);
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::HolonError;
use crate::stop::StopCondition;

/// Maximum length for IDs (`episode_id`, `work_id`, `lease_id`).
///
/// This limit prevents resource exhaustion attacks through excessively long
/// IDs.
pub const MAX_ID_LENGTH: usize = 256;

/// Maximum length for goal specification strings.
///
/// This limit prevents resource exhaustion attacks through excessively large
/// goal specifications. 4KB is sufficient for detailed task descriptions
/// while preventing memory abuse.
pub const MAX_GOAL_SPEC_LENGTH: usize = 4096;

/// Validates a goal specification string.
///
/// # Rules
///
/// - Can be empty (optional field)
/// - Must not exceed `MAX_GOAL_SPEC_LENGTH` bytes
/// - Must not contain null bytes
///
/// # Errors
///
/// Returns `HolonError::InvalidInput` if validation fails.
pub fn validate_goal_spec(goal_spec: &str) -> Result<(), HolonError> {
    if goal_spec.len() > MAX_GOAL_SPEC_LENGTH {
        return Err(HolonError::invalid_input(format!(
            "goal_spec exceeds maximum length of {MAX_GOAL_SPEC_LENGTH} bytes"
        )));
    }
    if goal_spec.contains('\0') {
        return Err(HolonError::invalid_input(
            "goal_spec contains null byte".to_string(),
        ));
    }
    Ok(())
}

/// Validates an ID string.
///
/// # Rules
///
/// - Must not be empty
/// - Must not exceed `MAX_ID_LENGTH` bytes
/// - Must not contain `/` (prevents path traversal in storage)
/// - Must not contain null bytes
///
/// # Errors
///
/// Returns `HolonError::InvalidInput` if validation fails.
pub fn validate_id(id: &str, field_name: &str) -> Result<(), HolonError> {
    if id.is_empty() {
        return Err(HolonError::invalid_input(format!(
            "{field_name} cannot be empty"
        )));
    }
    if id.len() > MAX_ID_LENGTH {
        return Err(HolonError::invalid_input(format!(
            "{field_name} exceeds maximum length of {MAX_ID_LENGTH} bytes"
        )));
    }
    if id.contains('/') {
        return Err(HolonError::invalid_input(format!(
            "{field_name} contains invalid character '/'"
        )));
    }
    if id.contains('\0') {
        return Err(HolonError::invalid_input(format!(
            "{field_name} contains null byte"
        )));
    }
    Ok(())
}

/// Event emitted when an episode starts execution.
///
/// This event captures the initial state and context at the beginning of
/// an episode, enabling replay and audit of the execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeStarted {
    /// Unique identifier for this episode.
    episode_id: String,

    /// The work ID being processed.
    work_id: String,

    /// The lease ID authorizing this execution.
    lease_id: String,

    /// The episode number (1-indexed).
    episode_number: u64,

    /// Timestamp when the episode started (nanoseconds since epoch).
    started_at_ns: u64,

    /// Parent episode ID (if this is a sub-episode).
    parent_episode_id: Option<String>,

    /// Remaining token budget at start.
    remaining_tokens: Option<u64>,

    /// Remaining time budget in milliseconds at start.
    remaining_time_ms: Option<u64>,

    /// Goal specification for this episode.
    goal_spec: Option<String>,
}

impl EpisodeStarted {
    /// Creates a new episode started event with ID validation.
    ///
    /// This is the recommended constructor for external callers. It validates
    /// all ID fields according to [`validate_id`] rules.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if any ID fails validation:
    /// - Empty IDs
    /// - IDs exceeding 256 bytes
    /// - IDs containing `/` or null bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_holon::ledger::EpisodeStarted;
    ///
    /// let event = EpisodeStarted::try_new(
    ///     "ep-001",
    ///     "work-123",
    ///     "lease-456",
    ///     1,
    ///     1_000_000_000,
    /// )
    /// .expect("valid IDs");
    /// ```
    pub fn try_new(
        episode_id: impl Into<String>,
        work_id: impl Into<String>,
        lease_id: impl Into<String>,
        episode_number: u64,
        started_at_ns: u64,
    ) -> Result<Self, HolonError> {
        let episode_id = episode_id.into();
        let work_id = work_id.into();
        let lease_id = lease_id.into();

        validate_id(&episode_id, "episode_id")?;
        validate_id(&work_id, "work_id")?;
        validate_id(&lease_id, "lease_id")?;

        Ok(Self {
            episode_id,
            work_id,
            lease_id,
            episode_number,
            started_at_ns,
            parent_episode_id: None,
            remaining_tokens: None,
            remaining_time_ms: None,
            goal_spec: None,
        })
    }

    /// Creates a new episode started event without validation.
    ///
    /// # Warning
    ///
    /// **This constructor skips ID validation.** It should only be used when
    /// IDs are guaranteed to be valid (e.g., internal logic or after prior
    /// validation). For external input, always use [`try_new`](Self::try_new).
    ///
    /// # Safety Note (Logic)
    ///
    /// This constructor skips ID validation for performance in internal code
    /// paths where IDs are already validated. External callers should prefer
    /// [`try_new`](Self::try_new) which validates all ID fields.
    ///
    /// # Preconditions
    ///
    /// All ID arguments must satisfy [`validate_id`] rules:
    /// - Not empty
    /// - At most 256 bytes
    /// - No `/` or null bytes
    #[must_use]
    pub fn new(
        episode_id: impl Into<String>,
        work_id: impl Into<String>,
        lease_id: impl Into<String>,
        episode_number: u64,
        started_at_ns: u64,
    ) -> Self {
        Self {
            episode_id: episode_id.into(),
            work_id: work_id.into(),
            lease_id: lease_id.into(),
            episode_number,
            started_at_ns,
            parent_episode_id: None,
            remaining_tokens: None,
            remaining_time_ms: None,
            goal_spec: None,
        }
    }

    /// Returns the episode ID.
    #[must_use]
    pub fn episode_id(&self) -> &str {
        &self.episode_id
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the lease ID.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// Returns the episode number.
    #[must_use]
    pub const fn episode_number(&self) -> u64 {
        self.episode_number
    }

    /// Returns the start timestamp.
    #[must_use]
    pub const fn started_at_ns(&self) -> u64 {
        self.started_at_ns
    }

    /// Returns the parent episode ID.
    #[must_use]
    pub fn parent_episode_id(&self) -> Option<&str> {
        self.parent_episode_id.as_deref()
    }

    /// Returns the remaining token budget at start.
    #[must_use]
    pub const fn remaining_tokens(&self) -> Option<u64> {
        self.remaining_tokens
    }

    /// Returns the remaining time budget at start.
    #[must_use]
    pub const fn remaining_time_ms(&self) -> Option<u64> {
        self.remaining_time_ms
    }

    /// Returns the goal specification.
    #[must_use]
    pub fn goal_spec(&self) -> Option<&str> {
        self.goal_spec.as_deref()
    }

    /// Sets the parent episode ID.
    #[must_use]
    pub fn with_parent_episode_id(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_episode_id = Some(parent_id.into());
        self
    }

    /// Sets the remaining token budget.
    #[must_use]
    pub const fn with_remaining_tokens(mut self, tokens: u64) -> Self {
        self.remaining_tokens = Some(tokens);
        self
    }

    /// Sets the remaining time budget.
    #[must_use]
    pub const fn with_remaining_time_ms(mut self, time_ms: u64) -> Self {
        self.remaining_time_ms = Some(time_ms);
        self
    }

    /// Sets the goal specification.
    #[must_use]
    pub fn with_goal_spec(mut self, goal: impl Into<String>) -> Self {
        self.goal_spec = Some(goal.into());
        self
    }
}

/// The reason an episode completed.
///
/// This enum captures why an episode ended, which is used for metrics,
/// debugging, and determining the next action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum EpisodeCompletionReason {
    /// The goal was satisfied.
    GoalSatisfied,

    /// The episode needs to continue (not terminal).
    NeedsContinuation,

    /// The budget was exhausted.
    BudgetExhausted {
        /// The resource that was exhausted.
        resource: String,
    },

    /// The maximum episode count was reached.
    MaxEpisodesReached {
        /// The number of episodes executed.
        count: u64,
    },

    /// The time limit was reached.
    TimeoutReached {
        /// Time limit in milliseconds.
        limit_ms: u64,
    },

    /// The episode was blocked.
    Blocked {
        /// Reason for the block.
        reason: String,
    },

    /// The episode was escalated.
    Escalated {
        /// Reason for escalation.
        reason: String,
    },

    /// An error occurred.
    Error {
        /// Error description.
        error: String,
    },

    /// An external signal was received.
    ExternalSignal {
        /// The signal that was received.
        signal: String,
    },

    /// The episode stalled.
    Stalled {
        /// Reason for the stall.
        reason: String,
    },

    /// A policy was violated.
    PolicyViolation {
        /// The policy that was violated.
        policy: String,
    },
}

impl EpisodeCompletionReason {
    /// Returns `true` if this is a successful completion.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        matches!(self, Self::GoalSatisfied)
    }

    /// Returns `true` if execution should continue.
    #[must_use]
    pub const fn should_continue(&self) -> bool {
        matches!(self, Self::NeedsContinuation)
    }

    /// Returns `true` if this is a resource-related termination.
    #[must_use]
    pub const fn is_resource_limit(&self) -> bool {
        matches!(
            self,
            Self::BudgetExhausted { .. }
                | Self::MaxEpisodesReached { .. }
                | Self::TimeoutReached { .. }
        )
    }

    /// Returns `true` if this is an error condition.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. } | Self::PolicyViolation { .. })
    }

    /// Returns the reason as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GoalSatisfied => "goal_satisfied",
            Self::NeedsContinuation => "needs_continuation",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::MaxEpisodesReached { .. } => "max_episodes_reached",
            Self::TimeoutReached { .. } => "timeout_reached",
            Self::Blocked { .. } => "blocked",
            Self::Escalated { .. } => "escalated",
            Self::Error { .. } => "error",
            Self::ExternalSignal { .. } => "external_signal",
            Self::Stalled { .. } => "stalled",
            Self::PolicyViolation { .. } => "policy_violation",
        }
    }
}

impl fmt::Display for EpisodeCompletionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GoalSatisfied => write!(f, "goal satisfied"),
            Self::NeedsContinuation => write!(f, "needs continuation"),
            Self::BudgetExhausted { resource } => write!(f, "budget exhausted: {resource}"),
            Self::MaxEpisodesReached { count } => write!(f, "max episodes reached: {count}"),
            Self::TimeoutReached { limit_ms } => write!(f, "timeout reached: {limit_ms}ms"),
            Self::Blocked { reason } => write!(f, "blocked: {reason}"),
            Self::Escalated { reason } => write!(f, "escalated: {reason}"),
            Self::Error { error } => write!(f, "error: {error}"),
            Self::ExternalSignal { signal } => write!(f, "external signal: {signal}"),
            Self::Stalled { reason } => write!(f, "stalled: {reason}"),
            Self::PolicyViolation { policy } => write!(f, "policy violation: {policy}"),
        }
    }
}

impl From<&StopCondition> for EpisodeCompletionReason {
    fn from(condition: &StopCondition) -> Self {
        match condition {
            StopCondition::Continue => Self::NeedsContinuation,
            StopCondition::GoalSatisfied => Self::GoalSatisfied,
            StopCondition::BudgetExhausted { resource } => Self::BudgetExhausted {
                resource: resource.clone(),
            },
            StopCondition::MaxEpisodesReached { count } => {
                Self::MaxEpisodesReached { count: *count }
            },
            StopCondition::TimeoutReached { limit_ms } => Self::TimeoutReached {
                limit_ms: *limit_ms,
            },
            StopCondition::ExternalSignal { signal } => Self::ExternalSignal {
                signal: signal.clone(),
            },
            StopCondition::Stalled { reason } => Self::Stalled {
                reason: reason.clone(),
            },
            StopCondition::ErrorCondition { error } => Self::Error {
                error: error.clone(),
            },
            StopCondition::Escalated { reason } => Self::Escalated {
                reason: reason.clone(),
            },
            StopCondition::PolicyViolation { policy } => Self::PolicyViolation {
                policy: policy.clone(),
            },
        }
    }
}

impl From<StopCondition> for EpisodeCompletionReason {
    fn from(condition: StopCondition) -> Self {
        Self::from(&condition)
    }
}

/// Event emitted when an episode completes.
///
/// This event captures the outcome and resource consumption of an episode,
/// enabling audit, metrics, and debugging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeCompleted {
    /// The episode ID that completed.
    episode_id: String,

    /// Why the episode completed.
    reason: EpisodeCompletionReason,

    /// Timestamp when the episode completed (nanoseconds since epoch).
    completed_at_ns: u64,

    /// Tokens consumed during this episode.
    tokens_consumed: u64,

    /// Time consumed during this episode (milliseconds).
    time_consumed_ms: u64,

    /// Number of artifacts produced.
    artifact_count: u64,

    /// Updated progress state after this episode.
    progress_update: Option<String>,

    /// Error message if the episode failed.
    error_message: Option<String>,
}

impl EpisodeCompleted {
    /// Creates a new episode completed event.
    #[must_use]
    pub fn new(
        episode_id: impl Into<String>,
        reason: EpisodeCompletionReason,
        completed_at_ns: u64,
    ) -> Self {
        Self {
            episode_id: episode_id.into(),
            reason,
            completed_at_ns,
            tokens_consumed: 0,
            time_consumed_ms: 0,
            artifact_count: 0,
            progress_update: None,
            error_message: None,
        }
    }

    /// Returns the episode ID.
    #[must_use]
    pub fn episode_id(&self) -> &str {
        &self.episode_id
    }

    /// Returns the completion reason.
    #[must_use]
    pub const fn reason(&self) -> &EpisodeCompletionReason {
        &self.reason
    }

    /// Returns the completion timestamp.
    #[must_use]
    pub const fn completed_at_ns(&self) -> u64 {
        self.completed_at_ns
    }

    /// Returns the tokens consumed.
    #[must_use]
    pub const fn tokens_consumed(&self) -> u64 {
        self.tokens_consumed
    }

    /// Returns the time consumed in milliseconds.
    #[must_use]
    pub const fn time_consumed_ms(&self) -> u64 {
        self.time_consumed_ms
    }

    /// Returns the artifact count.
    #[must_use]
    pub const fn artifact_count(&self) -> u64 {
        self.artifact_count
    }

    /// Returns the progress update.
    #[must_use]
    pub fn progress_update(&self) -> Option<&str> {
        self.progress_update.as_deref()
    }

    /// Returns the error message.
    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Returns `true` if this was a successful completion.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        self.reason.is_successful()
    }

    /// Sets the tokens consumed.
    #[must_use]
    pub const fn with_tokens_consumed(mut self, tokens: u64) -> Self {
        self.tokens_consumed = tokens;
        self
    }

    /// Sets the time consumed.
    #[must_use]
    pub const fn with_time_consumed_ms(mut self, time_ms: u64) -> Self {
        self.time_consumed_ms = time_ms;
        self
    }

    /// Sets the artifact count.
    #[must_use]
    pub const fn with_artifact_count(mut self, count: u64) -> Self {
        self.artifact_count = count;
        self
    }

    /// Sets the progress update.
    #[must_use]
    pub fn with_progress_update(mut self, progress: impl Into<String>) -> Self {
        self.progress_update = Some(progress.into());
        self
    }

    /// Sets the error message.
    #[must_use]
    pub fn with_error_message(mut self, error: impl Into<String>) -> Self {
        self.error_message = Some(error.into());
        self
    }
}

/// Wrapper enum for all episode-related ledger events.
///
/// This allows storing heterogeneous episode events in a single collection
/// while preserving type information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum EpisodeEvent {
    /// An episode started.
    Started(EpisodeStarted),

    /// An episode completed.
    Completed(EpisodeCompleted),
}

impl EpisodeEvent {
    /// Returns the episode ID for this event.
    #[must_use]
    pub fn episode_id(&self) -> &str {
        match self {
            Self::Started(e) => e.episode_id(),
            Self::Completed(e) => e.episode_id(),
        }
    }

    /// Returns the timestamp for this event.
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        match self {
            Self::Started(e) => e.started_at_ns(),
            Self::Completed(e) => e.completed_at_ns(),
        }
    }

    /// Returns `true` if this is a started event.
    #[must_use]
    pub const fn is_started(&self) -> bool {
        matches!(self, Self::Started(_))
    }

    /// Returns `true` if this is a completed event.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// Returns the event type as a string.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::Started(_) => "episode_started",
            Self::Completed(_) => "episode_completed",
        }
    }
}

impl From<EpisodeStarted> for EpisodeEvent {
    fn from(event: EpisodeStarted) -> Self {
        Self::Started(event)
    }
}

impl From<EpisodeCompleted> for EpisodeEvent {
    fn from(event: EpisodeCompleted) -> Self {
        Self::Completed(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_episode_started_creation() {
        let started = EpisodeStarted::new("ep-001", "work-123", "lease-456", 1, 1_000_000_000);

        assert_eq!(started.episode_id(), "ep-001");
        assert_eq!(started.work_id(), "work-123");
        assert_eq!(started.lease_id(), "lease-456");
        assert_eq!(started.episode_number(), 1);
        assert_eq!(started.started_at_ns(), 1_000_000_000);
        assert!(started.parent_episode_id().is_none());
    }

    #[test]
    fn test_episode_started_with_optional_fields() {
        let started = EpisodeStarted::new("ep-001", "work-123", "lease-456", 1, 1_000_000_000)
            .with_parent_episode_id("ep-000")
            .with_remaining_tokens(1000)
            .with_remaining_time_ms(60_000)
            .with_goal_spec("Complete the task");

        assert_eq!(started.parent_episode_id(), Some("ep-000"));
        assert_eq!(started.remaining_tokens(), Some(1000));
        assert_eq!(started.remaining_time_ms(), Some(60_000));
        assert_eq!(started.goal_spec(), Some("Complete the task"));
    }

    #[test]
    fn test_episode_completed_creation() {
        let completed = EpisodeCompleted::new(
            "ep-001",
            EpisodeCompletionReason::GoalSatisfied,
            1_500_000_000,
        );

        assert_eq!(completed.episode_id(), "ep-001");
        assert!(completed.is_successful());
        assert_eq!(completed.completed_at_ns(), 1_500_000_000);
        assert_eq!(completed.tokens_consumed(), 0);
    }

    #[test]
    fn test_episode_completed_with_consumption() {
        let completed = EpisodeCompleted::new(
            "ep-001",
            EpisodeCompletionReason::GoalSatisfied,
            1_500_000_000,
        )
        .with_tokens_consumed(500)
        .with_time_consumed_ms(5000)
        .with_artifact_count(2)
        .with_progress_update("Task complete");

        assert_eq!(completed.tokens_consumed(), 500);
        assert_eq!(completed.time_consumed_ms(), 5000);
        assert_eq!(completed.artifact_count(), 2);
        assert_eq!(completed.progress_update(), Some("Task complete"));
    }

    #[test]
    fn test_episode_completed_with_error() {
        let completed = EpisodeCompleted::new(
            "ep-001",
            EpisodeCompletionReason::Error {
                error: "timeout".to_string(),
            },
            1_500_000_000,
        )
        .with_error_message("Connection timed out after 30s");

        assert!(!completed.is_successful());
        assert_eq!(
            completed.error_message(),
            Some("Connection timed out after 30s")
        );
    }

    #[test]
    fn test_completion_reason_properties() {
        assert!(EpisodeCompletionReason::GoalSatisfied.is_successful());
        assert!(!EpisodeCompletionReason::NeedsContinuation.is_successful());
        assert!(EpisodeCompletionReason::NeedsContinuation.should_continue());

        assert!(
            EpisodeCompletionReason::BudgetExhausted {
                resource: "tokens".to_string()
            }
            .is_resource_limit()
        );

        assert!(
            EpisodeCompletionReason::Error {
                error: "test".to_string()
            }
            .is_error()
        );
    }

    #[test]
    fn test_completion_reason_as_str() {
        assert_eq!(
            EpisodeCompletionReason::GoalSatisfied.as_str(),
            "goal_satisfied"
        );
        assert_eq!(
            EpisodeCompletionReason::NeedsContinuation.as_str(),
            "needs_continuation"
        );
        assert_eq!(
            EpisodeCompletionReason::BudgetExhausted {
                resource: "tokens".to_string()
            }
            .as_str(),
            "budget_exhausted"
        );
    }

    #[test]
    fn test_completion_reason_display() {
        assert_eq!(
            EpisodeCompletionReason::GoalSatisfied.to_string(),
            "goal satisfied"
        );
        assert_eq!(
            EpisodeCompletionReason::BudgetExhausted {
                resource: "tokens".to_string()
            }
            .to_string(),
            "budget exhausted: tokens"
        );
    }

    #[test]
    fn test_stop_condition_to_completion_reason() {
        let reason: EpisodeCompletionReason = StopCondition::GoalSatisfied.into();
        assert_eq!(reason, EpisodeCompletionReason::GoalSatisfied);

        let reason: EpisodeCompletionReason = StopCondition::budget_exhausted("tokens").into();
        assert!(matches!(
            reason,
            EpisodeCompletionReason::BudgetExhausted { resource } if resource == "tokens"
        ));

        let reason: EpisodeCompletionReason = StopCondition::Continue.into();
        assert_eq!(reason, EpisodeCompletionReason::NeedsContinuation);
    }

    #[test]
    fn test_episode_event_wrapper() {
        let started = EpisodeStarted::new("ep-001", "work-123", "lease-456", 1, 1_000_000_000);
        let event: EpisodeEvent = started.into();

        assert!(event.is_started());
        assert!(!event.is_completed());
        assert_eq!(event.episode_id(), "ep-001");
        assert_eq!(event.timestamp_ns(), 1_000_000_000);
        assert_eq!(event.event_type(), "episode_started");

        let completed = EpisodeCompleted::new(
            "ep-001",
            EpisodeCompletionReason::GoalSatisfied,
            1_500_000_000,
        );
        let event: EpisodeEvent = completed.into();

        assert!(!event.is_started());
        assert!(event.is_completed());
        assert_eq!(event.event_type(), "episode_completed");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let started = EpisodeStarted::new("ep-001", "work-123", "lease-456", 1, 1_000_000_000)
            .with_remaining_tokens(1000);

        let json = serde_json::to_string(&started).unwrap();
        let deserialized: EpisodeStarted = serde_json::from_str(&json).unwrap();
        assert_eq!(started, deserialized);

        let completed = EpisodeCompleted::new(
            "ep-001",
            EpisodeCompletionReason::GoalSatisfied,
            1_500_000_000,
        )
        .with_tokens_consumed(500);

        let json = serde_json::to_string(&completed).unwrap();
        let deserialized: EpisodeCompleted = serde_json::from_str(&json).unwrap();
        assert_eq!(completed, deserialized);
    }

    /// SECURITY TEST: Verify `EpisodeStarted` rejects unknown fields.
    ///
    /// Finding: MEDIUM - Permissive Parsing
    /// Fix: Added `#[serde(deny_unknown_fields)]` to prevent
    /// malicious/corrupted data from being silently accepted.
    #[test]
    fn test_episode_started_rejects_unknown_fields() {
        let json_with_unknown_field = r#"{
            "episode_id": "ep-001",
            "work_id": "work-123",
            "lease_id": "lease-456",
            "episode_number": 1,
            "started_at_ns": 1000000000,
            "parent_episode_id": null,
            "remaining_tokens": null,
            "remaining_time_ms": null,
            "goal_spec": null,
            "malicious_field": "should_be_rejected"
        }"#;

        let result: Result<EpisodeStarted, _> = serde_json::from_str(json_with_unknown_field);
        assert!(
            result.is_err(),
            "EpisodeStarted should reject JSON with unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "Error should mention 'unknown field': {err}"
        );
    }

    /// SECURITY TEST: Verify `EpisodeCompleted` rejects unknown fields.
    #[test]
    fn test_episode_completed_rejects_unknown_fields() {
        let json_with_unknown_field = r#"{
            "episode_id": "ep-001",
            "reason": "GoalSatisfied",
            "completed_at_ns": 1500000000,
            "tokens_consumed": 100,
            "time_consumed_ms": 500,
            "artifact_count": 1,
            "progress_update": null,
            "error_message": null,
            "extra_field": "should_be_rejected"
        }"#;

        let result: Result<EpisodeCompleted, _> = serde_json::from_str(json_with_unknown_field);
        assert!(
            result.is_err(),
            "EpisodeCompleted should reject JSON with unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "Error should mention 'unknown field': {err}"
        );
    }

    /// SECURITY TEST: Verify `EpisodeCompletionReason` rejects unknown fields.
    #[test]
    fn test_episode_completion_reason_rejects_unknown_fields() {
        // Test a variant with fields
        let json_with_unknown_field = r#"{
            "BudgetExhausted": {
                "resource": "tokens",
                "extra_field": "should_be_rejected"
            }
        }"#;

        let result: Result<EpisodeCompletionReason, _> =
            serde_json::from_str(json_with_unknown_field);
        assert!(
            result.is_err(),
            "EpisodeCompletionReason should reject JSON with unknown fields"
        );
    }

    /// SECURITY TEST: Verify `EpisodeEvent` rejects unknown fields.
    #[test]
    fn test_episode_event_rejects_unknown_fields() {
        let json_with_unknown_field = r#"{
            "Started": {
                "episode_id": "ep-001",
                "work_id": "work-123",
                "lease_id": "lease-456",
                "episode_number": 1,
                "started_at_ns": 1000000000,
                "parent_episode_id": null,
                "remaining_tokens": null,
                "remaining_time_ms": null,
                "goal_spec": null,
                "malicious_field": "should_be_rejected"
            }
        }"#;

        let result: Result<EpisodeEvent, _> = serde_json::from_str(json_with_unknown_field);
        assert!(
            result.is_err(),
            "EpisodeEvent should reject JSON with unknown fields in inner struct"
        );
    }

    // ========================================================================
    // SECURITY TESTS: ID Validation (Finding 3 - Unvalidated Input)
    // ========================================================================

    /// SECURITY TEST: Verify `try_new` accepts valid IDs.
    #[test]
    fn test_try_new_accepts_valid_ids() {
        let result = EpisodeStarted::try_new("ep-001", "work-123", "lease-456", 1, 1_000_000_000);
        assert!(result.is_ok(), "try_new should accept valid IDs");
    }

    /// SECURITY TEST: Verify `try_new` rejects empty `episode_id`.
    ///
    /// Finding: MEDIUM - Unvalidated Input
    /// Fix: Added `try_new()` with ID validation.
    #[test]
    fn test_try_new_rejects_empty_episode_id() {
        let result = EpisodeStarted::try_new(
            "", // Empty episode_id
            "work-123",
            "lease-456",
            1,
            1_000_000_000,
        );
        assert!(result.is_err(), "try_new should reject empty episode_id");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("episode_id") && err.contains("empty"),
            "Error should mention 'episode_id' and 'empty': {err}"
        );
    }

    /// SECURITY TEST: Verify `try_new` rejects empty `work_id`.
    #[test]
    fn test_try_new_rejects_empty_work_id() {
        let result = EpisodeStarted::try_new(
            "ep-001",
            "", // Empty work_id
            "lease-456",
            1,
            1_000_000_000,
        );
        assert!(result.is_err(), "try_new should reject empty work_id");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work_id") && err.contains("empty"),
            "Error should mention 'work_id' and 'empty': {err}"
        );
    }

    /// SECURITY TEST: Verify `try_new` rejects empty `lease_id`.
    #[test]
    fn test_try_new_rejects_empty_lease_id() {
        let result = EpisodeStarted::try_new(
            "ep-001",
            "work-123",
            "", // Empty lease_id
            1,
            1_000_000_000,
        );
        assert!(result.is_err(), "try_new should reject empty lease_id");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("lease_id") && err.contains("empty"),
            "Error should mention 'lease_id' and 'empty': {err}"
        );
    }

    /// SECURITY TEST: Verify `try_new` rejects IDs containing slash.
    ///
    /// Slashes in IDs could enable path traversal attacks if IDs are used
    /// as part of file paths or storage keys.
    #[test]
    fn test_try_new_rejects_id_with_slash() {
        let result = EpisodeStarted::try_new(
            "ep-001",
            "work/../../etc/passwd", // Path traversal attempt
            "lease-456",
            1,
            1_000_000_000,
        );
        assert!(result.is_err(), "try_new should reject IDs with '/'");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work_id") && err.contains('/'),
            "Error should mention 'work_id' and '/': {err}"
        );
    }

    /// SECURITY TEST: Verify `try_new` rejects IDs exceeding max length.
    #[test]
    fn test_try_new_rejects_overly_long_id() {
        let long_id = "x".repeat(MAX_ID_LENGTH + 1);
        let result = EpisodeStarted::try_new(
            "ep-001",
            &long_id, // Too long
            "lease-456",
            1,
            1_000_000_000,
        );
        assert!(
            result.is_err(),
            "try_new should reject IDs exceeding max length"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work_id") && err.contains("maximum length"),
            "Error should mention 'work_id' and 'maximum length': {err}"
        );
    }

    /// SECURITY TEST: Verify `try_new` rejects IDs containing null bytes.
    #[test]
    fn test_try_new_rejects_id_with_null_byte() {
        let result = EpisodeStarted::try_new(
            "ep-001",
            "work-\0-123", // Null byte in ID
            "lease-456",
            1,
            1_000_000_000,
        );
        assert!(result.is_err(), "try_new should reject IDs with null bytes");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work_id") && err.contains("null"),
            "Error should mention 'work_id' and 'null': {err}"
        );
    }

    /// SECURITY TEST: Verify `validate_id` function directly.
    #[test]
    fn test_validate_id_accepts_valid_ids() {
        assert!(validate_id("simple-id", "test").is_ok());
        assert!(validate_id("id_with_underscores", "test").is_ok());
        assert!(validate_id("id-with-hyphens", "test").is_ok());
        assert!(validate_id("id.with.dots", "test").is_ok());
        assert!(validate_id("123", "test").is_ok());
        assert!(validate_id("a", "test").is_ok()); // Single char
        assert!(validate_id(&"x".repeat(MAX_ID_LENGTH), "test").is_ok()); // Max length
    }

    /// SECURITY TEST: Verify `validate_id` rejects invalid IDs.
    #[test]
    fn test_validate_id_rejects_invalid_ids() {
        // Empty
        assert!(validate_id("", "test").is_err());

        // Too long
        assert!(validate_id(&"x".repeat(MAX_ID_LENGTH + 1), "test").is_err());

        // Contains slash
        assert!(validate_id("path/to/id", "test").is_err());

        // Contains null
        assert!(validate_id("id\0with\0nulls", "test").is_err());
    }

    // ========================================================================
    // SECURITY TESTS: Goal Spec Validation (Finding - Unbounded String)
    // ========================================================================

    /// SECURITY TEST: Verify `validate_goal_spec` accepts valid goal specs.
    #[test]
    fn test_validate_goal_spec_accepts_valid() {
        assert!(validate_goal_spec("").is_ok()); // Empty is allowed
        assert!(validate_goal_spec("Simple goal").is_ok());
        assert!(validate_goal_spec(&"x".repeat(MAX_GOAL_SPEC_LENGTH)).is_ok()); // Max length
    }

    /// SECURITY TEST: Verify `validate_goal_spec` rejects overly long specs.
    ///
    /// Finding: MEDIUM - Unbounded `goal_spec` string could cause OOM/ledger
    /// bloat. Fix: Added `MAX_GOAL_SPEC_LENGTH` validation.
    #[test]
    fn test_validate_goal_spec_rejects_too_long() {
        let long_spec = "x".repeat(MAX_GOAL_SPEC_LENGTH + 1);
        let result = validate_goal_spec(&long_spec);
        assert!(
            result.is_err(),
            "validate_goal_spec should reject specs exceeding max length"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("goal_spec") && err.contains("maximum length"),
            "Error should mention 'goal_spec' and 'maximum length': {err}"
        );
    }

    /// SECURITY TEST: Verify `validate_goal_spec` rejects specs with null
    /// bytes.
    #[test]
    fn test_validate_goal_spec_rejects_null_bytes() {
        let result = validate_goal_spec("goal\0spec");
        assert!(
            result.is_err(),
            "validate_goal_spec should reject specs with null bytes"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("goal_spec") && err.contains("null"),
            "Error should mention 'goal_spec' and 'null': {err}"
        );
    }
}
