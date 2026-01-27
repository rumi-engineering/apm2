//! Coordination state types and structures.
//!
//! This module defines the core state types for the coordination layer:
//! - [`CoordinationState`]: The reducer projection containing all coordinations
//! - [`CoordinationSession`]: Individual coordination tracking state
//! - [`BindingInfo`]: Session-to-work binding information
//! - [`CoordinationBudget`]: Budget constraints for a coordination
//! - [`BudgetUsage`]: Current budget consumption tracking
//! - [`CoordinationStatus`]: Lifecycle status of a coordination
//! - [`StopCondition`]: Why a coordination stopped
//!
//! Types follow patterns established in [`crate::session::state`].

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};

/// Maximum number of work items allowed in a coordination queue.
///
/// This limit prevents denial-of-service attacks through unbounded allocation
/// when deserializing coordination events from JSON. The limit is enforced both
/// in constructors and during deserialization.
pub const MAX_WORK_QUEUE_SIZE: usize = 1000;

/// Custom deserializer for `work_queue` that enforces [`MAX_WORK_QUEUE_SIZE`].
///
/// This prevents denial-of-service attacks through unbounded allocation
/// when deserializing coordination state from untrusted JSON.
fn deserialize_bounded_work_queue<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<String> = Vec::deserialize(deserializer)?;
    if v.len() > MAX_WORK_QUEUE_SIZE {
        return Err(de::Error::custom(format!(
            "work_queue exceeds maximum size: {} > {}",
            v.len(),
            MAX_WORK_QUEUE_SIZE
        )));
    }
    Ok(v)
}

/// Errors that can occur during coordination operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinationError {
    /// Work queue size exceeds the maximum allowed limit.
    WorkQueueSizeExceeded {
        /// The actual size that was provided.
        actual: usize,
        /// The maximum allowed size.
        max: usize,
    },
}

impl fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkQueueSizeExceeded { actual, max } => {
                write!(f, "work queue size {actual} exceeds maximum allowed {max}")
            },
        }
    }
}

impl std::error::Error for CoordinationError {}

/// Budget constraints for a coordination.
///
/// Per AD-COORD-004: `max_episodes` and `max_duration_ms` are required.
/// `max_tokens` is optional but recommended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationBudget {
    /// Maximum number of session episodes (required).
    pub max_episodes: u32,

    /// Maximum duration in milliseconds (required).
    pub max_duration_ms: u64,

    /// Maximum token consumption (optional).
    ///
    /// When `None`, token consumption is tracked but not enforced.
    pub max_tokens: Option<u64>,
}

impl CoordinationBudget {
    /// Creates a new coordination budget.
    #[must_use]
    pub const fn new(max_episodes: u32, max_duration_ms: u64, max_tokens: Option<u64>) -> Self {
        Self {
            max_episodes,
            max_duration_ms,
            max_tokens,
        }
    }
}

/// Current budget consumption tracking.
///
/// All counters are monotonically non-decreasing within a coordination.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetUsage {
    /// Number of episodes (sessions) consumed.
    pub consumed_episodes: u32,

    /// Elapsed time in milliseconds since coordination started.
    pub elapsed_ms: u64,

    /// Total tokens consumed across all sessions.
    ///
    /// Aggregated from session `final_entropy` per AD-COORD-011.
    pub consumed_tokens: u64,
}

impl BudgetUsage {
    /// Creates a new empty budget usage tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            consumed_episodes: 0,
            elapsed_ms: 0,
            consumed_tokens: 0,
        }
    }
}

/// The type of budget that was exhausted.
///
/// Used in [`StopCondition::BudgetExhausted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BudgetType {
    /// Duration budget exhausted.
    Duration,
    /// Token budget exhausted.
    Tokens,
    /// Episode budget exhausted.
    Episodes,
}

impl BudgetType {
    /// Returns the string representation of this budget type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Duration => "DURATION",
            Self::Tokens => "TOKENS",
            Self::Episodes => "EPISODES",
        }
    }
}

/// Why a coordination stopped.
///
/// Stop conditions have a priority ordering per AD-COORD-013:
/// 1. `CircuitBreakerTriggered` (highest - safety critical)
/// 2. `BudgetExhausted(Duration)` (runtime limit)
/// 3. `BudgetExhausted(Tokens)` (resource limit)
/// 4. `BudgetExhausted(Episodes)` (session count limit)
/// 5. `MaxAttemptsExceeded` (work-level failure)
/// 6. `WorkCompleted` (lowest - success)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StopCondition {
    /// All work items completed successfully.
    WorkCompleted,

    /// A work item exhausted its retry attempts.
    MaxAttemptsExceeded {
        /// The work item that exhausted retries.
        work_id: String,
    },

    /// A budget ceiling was reached.
    BudgetExhausted(BudgetType),

    /// Circuit breaker triggered due to consecutive failures.
    ///
    /// Per AD-COORD-005: Triggered after 3 consecutive session failures
    /// across different work items.
    CircuitBreakerTriggered {
        /// Number of consecutive failures when triggered.
        consecutive_failures: u32,
    },
}

impl StopCondition {
    /// Returns the priority of this stop condition (lower = higher priority).
    ///
    /// Per AD-COORD-013 priority ordering.
    #[must_use]
    pub const fn priority(&self) -> u8 {
        match self {
            Self::CircuitBreakerTriggered { .. } => 0,
            Self::BudgetExhausted(BudgetType::Duration) => 1,
            Self::BudgetExhausted(BudgetType::Tokens) => 2,
            Self::BudgetExhausted(BudgetType::Episodes) => 3,
            Self::MaxAttemptsExceeded { .. } => 4,
            Self::WorkCompleted => 5,
        }
    }

    /// Returns `true` if this is a success condition.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::WorkCompleted)
    }

    /// Returns the string representation of this stop condition.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WorkCompleted => "WORK_COMPLETED",
            Self::MaxAttemptsExceeded { .. } => "MAX_ATTEMPTS_EXCEEDED",
            Self::BudgetExhausted(BudgetType::Duration) => "BUDGET_EXHAUSTED_DURATION",
            Self::BudgetExhausted(BudgetType::Tokens) => "BUDGET_EXHAUSTED_TOKENS",
            Self::BudgetExhausted(BudgetType::Episodes) => "BUDGET_EXHAUSTED_EPISODES",
            Self::CircuitBreakerTriggered { .. } => "CIRCUIT_BREAKER_TRIGGERED",
        }
    }
}

/// Why a coordination was aborted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AbortReason {
    /// Coordination was manually cancelled.
    Cancelled {
        /// Reason for cancellation.
        reason: String,
    },

    /// Coordination encountered an unrecoverable error.
    Error {
        /// Error message.
        message: String,
    },

    /// No eligible work items in the queue.
    NoEligibleWork,
}

impl AbortReason {
    /// Returns the string representation of this abort reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Cancelled { .. } => "CANCELLED",
            Self::Error { .. } => "ERROR",
            Self::NoEligibleWork => "NO_ELIGIBLE_WORK",
        }
    }
}

/// Lifecycle status of a coordination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CoordinationStatus {
    /// Coordination is initializing.
    Initializing,

    /// Coordination is actively running.
    Running,

    /// Coordination completed (may be success or failure).
    Completed(StopCondition),

    /// Coordination was aborted.
    Aborted(AbortReason),
}

impl CoordinationStatus {
    /// Returns `true` if the coordination is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed(_) | Self::Aborted(_))
    }

    /// Returns `true` if the coordination is actively running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns the string representation of this status.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Initializing => "INITIALIZING",
            Self::Running => "RUNNING",
            Self::Completed(_) => "COMPLETED",
            Self::Aborted(_) => "ABORTED",
        }
    }
}

/// Outcome of a session for a work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionOutcome {
    /// Session completed successfully.
    Success,
    /// Session failed.
    Failure,
}

impl SessionOutcome {
    /// Returns the string representation of this outcome.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
        }
    }

    /// Returns `true` if this is a success outcome.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Information about a session-to-work binding.
///
/// Per AD-COORD-003: Binding events bracket session lifecycle.
/// `coordination.session_bound` MUST be emitted before `session.started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingInfo {
    /// Session ID bound to the work item.
    pub session_id: String,

    /// Work item ID being processed.
    pub work_id: String,

    /// Attempt number for this work item (1-indexed).
    pub attempt_number: u32,

    /// Timestamp when binding was created (nanoseconds since epoch).
    pub bound_at: u64,
}

impl BindingInfo {
    /// Creates a new binding info.
    #[must_use]
    pub const fn new(
        session_id: String,
        work_id: String,
        attempt_number: u32,
        bound_at: u64,
    ) -> Self {
        Self {
            session_id,
            work_id,
            attempt_number,
            bound_at,
        }
    }
}

/// Tracking state for an individual work item within a coordination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkItemTracking {
    /// Work item ID.
    pub work_id: String,

    /// Number of attempts made for this work item.
    pub attempt_count: u32,

    /// Session IDs used for this work item.
    pub session_ids: Vec<String>,

    /// Final outcome (set when work item processing is complete).
    pub final_outcome: Option<WorkItemOutcome>,
}

/// Final outcome for a work item in a coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkItemOutcome {
    /// Work item completed successfully.
    Succeeded,
    /// Work item failed (retries exhausted).
    Failed,
    /// Work item was skipped (e.g., stale state).
    Skipped,
}

impl WorkItemOutcome {
    /// Returns the string representation of this outcome.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Skipped => "SKIPPED",
        }
    }
}

impl WorkItemTracking {
    /// Creates a new work item tracking entry.
    #[must_use]
    pub const fn new(work_id: String) -> Self {
        Self {
            work_id,
            attempt_count: 0,
            session_ids: Vec::new(),
            final_outcome: None,
        }
    }
}

/// Individual coordination tracking state.
///
/// Represents a single coordination (work queue processing session).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationSession {
    /// Unique identifier for this coordination.
    pub coordination_id: String,

    /// Work queue (list of work item IDs to process).
    ///
    /// Limited to [`MAX_WORK_QUEUE_SIZE`] items. This limit is enforced both
    /// in [`CoordinationSession::new`] and during deserialization.
    #[serde(deserialize_with = "deserialize_bounded_work_queue")]
    pub work_queue: Vec<String>,

    /// Current index in work queue (0-indexed).
    pub work_index: usize,

    /// Per-work tracking information.
    pub work_tracking: HashMap<String, WorkItemTracking>,

    /// Budget constraints.
    pub budget: CoordinationBudget,

    /// Current budget usage.
    pub budget_usage: BudgetUsage,

    /// Consecutive session failures (for circuit breaker).
    ///
    /// Per AD-COORD-005: Reset to 0 on any success.
    pub consecutive_failures: u32,

    /// Current status.
    pub status: CoordinationStatus,

    /// Timestamp when coordination started (nanoseconds since epoch).
    pub started_at: u64,

    /// Timestamp when coordination completed (nanoseconds since epoch).
    ///
    /// `None` until coordination reaches terminal state.
    pub completed_at: Option<u64>,

    /// Maximum attempts per work item.
    pub max_attempts_per_work: u32,
}

impl CoordinationSession {
    /// Creates a new coordination session.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinationError::WorkQueueSizeExceeded`] if the work queue
    /// contains more than [`MAX_WORK_QUEUE_SIZE`] items.
    pub fn new(
        coordination_id: String,
        work_queue: Vec<String>,
        budget: CoordinationBudget,
        max_attempts_per_work: u32,
        started_at: u64,
    ) -> Result<Self, CoordinationError> {
        if work_queue.len() > MAX_WORK_QUEUE_SIZE {
            return Err(CoordinationError::WorkQueueSizeExceeded {
                actual: work_queue.len(),
                max: MAX_WORK_QUEUE_SIZE,
            });
        }

        let work_tracking = work_queue
            .iter()
            .map(|id| (id.clone(), WorkItemTracking::new(id.clone())))
            .collect();

        Ok(Self {
            coordination_id,
            work_queue,
            work_index: 0,
            work_tracking,
            budget,
            budget_usage: BudgetUsage::new(),
            consecutive_failures: 0,
            status: CoordinationStatus::Initializing,
            started_at,
            completed_at: None,
            max_attempts_per_work,
        })
    }

    /// Returns `true` if the coordination is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// Returns `true` if the coordination is actively running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.status.is_running()
    }

    /// Returns the current work ID being processed, if any.
    #[must_use]
    pub fn current_work_id(&self) -> Option<&str> {
        self.work_queue.get(self.work_index).map(String::as_str)
    }

    /// Returns `true` if all work items have been processed.
    #[must_use]
    pub fn is_work_queue_exhausted(&self) -> bool {
        self.work_index >= self.work_queue.len()
    }
}

/// The coordination reducer state projection.
///
/// Contains all active and completed coordinations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationState {
    /// Map of coordination ID to coordination session state.
    pub coordinations: HashMap<String, CoordinationSession>,

    /// Map of session ID to binding info for active bindings.
    ///
    /// Per AD-COORD-003: Bindings are created on `session_bound` and
    /// removed on `session_unbound`.
    pub bindings: HashMap<String, BindingInfo>,
}

impl CoordinationState {
    /// Creates a new empty coordination state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            coordinations: HashMap::new(),
            bindings: HashMap::new(),
        }
    }

    /// Gets a coordination session by ID.
    #[must_use]
    pub fn get(&self, coordination_id: &str) -> Option<&CoordinationSession> {
        self.coordinations.get(coordination_id)
    }

    /// Gets a mutable reference to a coordination session by ID.
    #[must_use]
    pub fn get_mut(&mut self, coordination_id: &str) -> Option<&mut CoordinationSession> {
        self.coordinations.get_mut(coordination_id)
    }

    /// Gets a binding by session ID.
    #[must_use]
    pub fn get_binding(&self, session_id: &str) -> Option<&BindingInfo> {
        self.bindings.get(session_id)
    }

    /// Returns the number of coordinations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.coordinations.len()
    }

    /// Returns `true` if there are no coordinations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.coordinations.is_empty()
    }

    /// Returns the number of active bindings.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// Returns the number of active (non-terminal) coordinations.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.coordinations
            .values()
            .filter(|c| !c.is_terminal())
            .count()
    }

    /// Returns the number of completed coordinations.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.coordinations
            .values()
            .filter(|c| matches!(c.status, CoordinationStatus::Completed(_)))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // CoordinationBudget Tests
    // ========================================================================

    #[test]
    fn test_coordination_budget_new() {
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000));
        assert_eq!(budget.max_episodes, 10);
        assert_eq!(budget.max_duration_ms, 60_000);
        assert_eq!(budget.max_tokens, Some(100_000));
    }

    #[test]
    fn test_coordination_budget_no_tokens() {
        let budget = CoordinationBudget::new(5, 30_000, None);
        assert_eq!(budget.max_episodes, 5);
        assert_eq!(budget.max_duration_ms, 30_000);
        assert_eq!(budget.max_tokens, None);
    }

    #[test]
    fn test_coordination_budget_serde_roundtrip() {
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000));
        let json = serde_json::to_string(&budget).unwrap();
        let restored: CoordinationBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, restored);
    }

    // ========================================================================
    // BudgetUsage Tests
    // ========================================================================

    #[test]
    fn test_budget_usage_new() {
        let usage = BudgetUsage::new();
        assert_eq!(usage.consumed_episodes, 0);
        assert_eq!(usage.elapsed_ms, 0);
        assert_eq!(usage.consumed_tokens, 0);
    }

    #[test]
    fn test_budget_usage_default() {
        let usage = BudgetUsage::default();
        assert_eq!(usage, BudgetUsage::new());
    }

    #[test]
    fn test_budget_usage_serde_roundtrip() {
        let usage = BudgetUsage {
            consumed_episodes: 5,
            elapsed_ms: 30_000,
            consumed_tokens: 50_000,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let restored: BudgetUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(usage, restored);
    }

    // ========================================================================
    // StopCondition Tests
    // ========================================================================

    #[test]
    fn test_stop_condition_priority_ordering() {
        // Per AD-COORD-013: CircuitBreaker > Duration > Tokens > Episodes > MaxAttempts
        // > WorkCompleted
        let circuit_breaker = StopCondition::CircuitBreakerTriggered {
            consecutive_failures: 3,
        };
        let budget_duration = StopCondition::BudgetExhausted(BudgetType::Duration);
        let budget_tokens = StopCondition::BudgetExhausted(BudgetType::Tokens);
        let budget_episodes = StopCondition::BudgetExhausted(BudgetType::Episodes);
        let max_attempts = StopCondition::MaxAttemptsExceeded {
            work_id: "work-1".to_string(),
        };
        let work_completed = StopCondition::WorkCompleted;

        assert!(circuit_breaker.priority() < budget_duration.priority());
        assert!(budget_duration.priority() < budget_tokens.priority());
        assert!(budget_tokens.priority() < budget_episodes.priority());
        assert!(budget_episodes.priority() < max_attempts.priority());
        assert!(max_attempts.priority() < work_completed.priority());
    }

    #[test]
    fn test_stop_condition_is_success() {
        assert!(StopCondition::WorkCompleted.is_success());
        assert!(
            !StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3
            }
            .is_success()
        );
        assert!(!StopCondition::BudgetExhausted(BudgetType::Duration).is_success());
    }

    #[test]
    fn test_stop_condition_serde_roundtrip() {
        let conditions = vec![
            StopCondition::WorkCompleted,
            StopCondition::MaxAttemptsExceeded {
                work_id: "work-123".to_string(),
            },
            StopCondition::BudgetExhausted(BudgetType::Duration),
            StopCondition::BudgetExhausted(BudgetType::Tokens),
            StopCondition::BudgetExhausted(BudgetType::Episodes),
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3,
            },
        ];

        for condition in conditions {
            let json = serde_json::to_string(&condition).unwrap();
            let restored: StopCondition = serde_json::from_str(&json).unwrap();
            assert_eq!(condition, restored);
        }
    }

    // ========================================================================
    // CoordinationStatus Tests
    // ========================================================================

    #[test]
    fn test_coordination_status_is_terminal() {
        assert!(!CoordinationStatus::Initializing.is_terminal());
        assert!(!CoordinationStatus::Running.is_terminal());
        assert!(CoordinationStatus::Completed(StopCondition::WorkCompleted).is_terminal());
        assert!(CoordinationStatus::Aborted(AbortReason::NoEligibleWork).is_terminal());
    }

    #[test]
    fn test_coordination_status_is_running() {
        assert!(!CoordinationStatus::Initializing.is_running());
        assert!(CoordinationStatus::Running.is_running());
        assert!(!CoordinationStatus::Completed(StopCondition::WorkCompleted).is_running());
        assert!(!CoordinationStatus::Aborted(AbortReason::NoEligibleWork).is_running());
    }

    #[test]
    fn test_coordination_status_serde_roundtrip() {
        let statuses = vec![
            CoordinationStatus::Initializing,
            CoordinationStatus::Running,
            CoordinationStatus::Completed(StopCondition::WorkCompleted),
            CoordinationStatus::Aborted(AbortReason::Cancelled {
                reason: "test".to_string(),
            }),
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let restored: CoordinationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }

    // ========================================================================
    // BindingInfo Tests
    // ========================================================================

    #[test]
    fn test_binding_info_new() {
        let binding = BindingInfo::new(
            "session-123".to_string(),
            "work-456".to_string(),
            1,
            1_000_000_000,
        );
        assert_eq!(binding.session_id, "session-123");
        assert_eq!(binding.work_id, "work-456");
        assert_eq!(binding.attempt_number, 1);
        assert_eq!(binding.bound_at, 1_000_000_000);
    }

    #[test]
    fn test_binding_info_serde_roundtrip() {
        let binding = BindingInfo::new(
            "session-123".to_string(),
            "work-456".to_string(),
            2,
            2_000_000_000,
        );
        let json = serde_json::to_string(&binding).unwrap();
        let restored: BindingInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, restored);
    }

    // ========================================================================
    // CoordinationSession Tests
    // ========================================================================

    #[test]
    fn test_coordination_session_new() {
        let budget = CoordinationBudget::new(10, 60_000, None);
        let work_queue = vec!["work-1".to_string(), "work-2".to_string()];
        let session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        assert_eq!(session.coordination_id, "coord-123");
        assert_eq!(session.work_queue.len(), 2);
        assert_eq!(session.work_index, 0);
        assert_eq!(session.consecutive_failures, 0);
        assert_eq!(session.max_attempts_per_work, 3);
        assert!(matches!(session.status, CoordinationStatus::Initializing));
        assert!(!session.is_terminal());
        assert!(!session.is_running());
    }

    #[test]
    fn test_coordination_session_current_work_id() {
        let budget = CoordinationBudget::new(10, 60_000, None);
        let work_queue = vec!["work-1".to_string(), "work-2".to_string()];
        let mut session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        assert_eq!(session.current_work_id(), Some("work-1"));
        session.work_index = 1;
        assert_eq!(session.current_work_id(), Some("work-2"));
        session.work_index = 2;
        assert_eq!(session.current_work_id(), None);
    }

    #[test]
    fn test_coordination_session_work_queue_exhausted() {
        let budget = CoordinationBudget::new(10, 60_000, None);
        let work_queue = vec!["work-1".to_string()];
        let mut session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        assert!(!session.is_work_queue_exhausted());
        session.work_index = 1;
        assert!(session.is_work_queue_exhausted());
    }

    #[test]
    fn test_coordination_session_serde_roundtrip() {
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000));
        let work_queue = vec!["work-1".to_string(), "work-2".to_string()];
        let session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        let json = serde_json::to_string(&session).unwrap();
        let restored: CoordinationSession = serde_json::from_str(&json).unwrap();
        assert_eq!(session, restored);
    }

    // ========================================================================
    // CoordinationState Tests
    // ========================================================================

    #[test]
    fn test_coordination_state_new() {
        let state = CoordinationState::new();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert_eq!(state.binding_count(), 0);
    }

    #[test]
    fn test_coordination_state_get() {
        let mut state = CoordinationState::new();
        let budget = CoordinationBudget::new(10, 60_000, None);
        let work_queue = vec!["work-1".to_string()];
        let session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        state.coordinations.insert("coord-123".to_string(), session);

        assert!(state.get("coord-123").is_some());
        assert!(state.get("nonexistent").is_none());
    }

    #[test]
    fn test_coordination_state_counts() {
        let mut state = CoordinationState::new();
        let budget = CoordinationBudget::new(10, 60_000, None);

        // Add an active coordination
        let mut active =
            CoordinationSession::new("coord-1".to_string(), vec![], budget.clone(), 3, 1_000)
                .unwrap();
        active.status = CoordinationStatus::Running;
        state.coordinations.insert("coord-1".to_string(), active);

        // Add a completed coordination
        let mut completed =
            CoordinationSession::new("coord-2".to_string(), vec![], budget, 3, 1_000).unwrap();
        completed.status = CoordinationStatus::Completed(StopCondition::WorkCompleted);
        state.coordinations.insert("coord-2".to_string(), completed);

        assert_eq!(state.len(), 2);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.completed_count(), 1);
    }

    #[test]
    fn test_coordination_state_serde_roundtrip() {
        let mut state = CoordinationState::new();
        let budget = CoordinationBudget::new(10, 60_000, None);
        let work_queue = vec!["work-1".to_string()];
        let session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();
        state.coordinations.insert("coord-123".to_string(), session);

        let binding = BindingInfo::new(
            "session-456".to_string(),
            "work-1".to_string(),
            1,
            2_000_000_000,
        );
        state.bindings.insert("session-456".to_string(), binding);

        let json = serde_json::to_string(&state).unwrap();
        let restored: CoordinationState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }

    // ========================================================================
    // TCK-00148 Specific Tests (Serde Round-Trip)
    // ========================================================================

    /// TCK-00148: Verify all types serialize and deserialize correctly.
    #[test]
    fn tck_00148_serde_roundtrip_all_types() {
        // CoordinationBudget
        let budget = CoordinationBudget::new(10, 60_000, Some(100_000));
        let json = serde_json::to_string(&budget).unwrap();
        assert_eq!(budget, serde_json::from_str(&json).unwrap());

        // BudgetUsage
        let usage = BudgetUsage {
            consumed_episodes: 5,
            elapsed_ms: 30_000,
            consumed_tokens: 50_000,
        };
        let json = serde_json::to_string(&usage).unwrap();
        assert_eq!(usage, serde_json::from_str(&json).unwrap());

        // StopCondition (all variants)
        for condition in [
            StopCondition::WorkCompleted,
            StopCondition::MaxAttemptsExceeded {
                work_id: "w".to_string(),
            },
            StopCondition::BudgetExhausted(BudgetType::Duration),
            StopCondition::BudgetExhausted(BudgetType::Tokens),
            StopCondition::BudgetExhausted(BudgetType::Episodes),
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3,
            },
        ] {
            let json = serde_json::to_string(&condition).unwrap();
            assert_eq!(condition, serde_json::from_str(&json).unwrap());
        }

        // CoordinationStatus (all variants)
        for status in [
            CoordinationStatus::Initializing,
            CoordinationStatus::Running,
            CoordinationStatus::Completed(StopCondition::WorkCompleted),
            CoordinationStatus::Aborted(AbortReason::NoEligibleWork),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(status, serde_json::from_str(&json).unwrap());
        }

        // BindingInfo
        let binding = BindingInfo::new("s".to_string(), "w".to_string(), 1, 1000);
        let json = serde_json::to_string(&binding).unwrap();
        assert_eq!(binding, serde_json::from_str(&json).unwrap());

        // CoordinationSession
        let session =
            CoordinationSession::new("c".to_string(), vec!["w".to_string()], budget, 3, 1000)
                .unwrap();
        let json = serde_json::to_string(&session).unwrap();
        assert_eq!(session, serde_json::from_str(&json).unwrap());

        // CoordinationState
        let mut state = CoordinationState::new();
        state.coordinations.insert("c".to_string(), session);
        state.bindings.insert("s".to_string(), binding);
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(state, serde_json::from_str(&json).unwrap());
    }

    // ========================================================================
    // Security Tests (TCK-00148)
    // ========================================================================

    /// TCK-00148: Test that work queue size limit is enforced.
    #[test]
    fn test_coordination_session_queue_limit() {
        let budget = CoordinationBudget::new(10, 60_000, None);

        // Create a work queue that exceeds the limit
        let oversized_queue: Vec<String> = (0..=MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(oversized_queue.len(), MAX_WORK_QUEUE_SIZE + 1);

        let result = CoordinationSession::new(
            "coord-123".to_string(),
            oversized_queue,
            budget.clone(),
            3,
            1_000_000_000,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            CoordinationError::WorkQueueSizeExceeded {
                actual,
                max
            } if actual == MAX_WORK_QUEUE_SIZE + 1 && max == MAX_WORK_QUEUE_SIZE
        ));

        // Verify exact limit works
        let exact_queue: Vec<String> = (0..MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(exact_queue.len(), MAX_WORK_QUEUE_SIZE);

        let result = CoordinationSession::new(
            "coord-124".to_string(),
            exact_queue,
            budget,
            3,
            1_000_000_000,
        );
        assert!(result.is_ok());
    }

    /// TCK-00148: Test that `work_queue` size limit is enforced during
    /// deserialization, preventing denial-of-service via oversized JSON
    /// payloads.
    #[test]
    fn test_coordination_session_queue_limit_serde() {
        // Build a JSON string with MAX_WORK_QUEUE_SIZE + 1 work items
        let oversized_queue: Vec<String> = (0..=MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(oversized_queue.len(), MAX_WORK_QUEUE_SIZE + 1);

        // Build work_tracking HashMap for the oversized queue
        let work_tracking: std::collections::HashMap<String, serde_json::Value> = oversized_queue
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    serde_json::json!({
                        "work_id": id,
                        "attempt_count": 0,
                        "session_ids": [],
                        "final_outcome": null
                    }),
                )
            })
            .collect();

        let json = serde_json::json!({
            "coordination_id": "coord-123",
            "work_queue": oversized_queue,
            "work_index": 0,
            "work_tracking": work_tracking,
            "budget": {
                "max_episodes": 10,
                "max_duration_ms": 60000,
                "max_tokens": null
            },
            "budget_usage": {
                "consumed_episodes": 0,
                "elapsed_ms": 0,
                "consumed_tokens": 0
            },
            "consecutive_failures": 0,
            "status": "Initializing",
            "started_at": 1_000_000_000_u64,
            "completed_at": null,
            "max_attempts_per_work": 3
        });

        let result: Result<CoordinationSession, _> = serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work_queue exceeds maximum size"),
            "Expected error about work_queue size limit, got: {err}"
        );
    }
}
