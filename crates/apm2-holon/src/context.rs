//! Episode context for bounded holon execution.
//!
//! The [`EpisodeContext`] provides all the information a holon needs to execute
//! a single bounded episode of work. It includes the work ID, lease ID, budget
//! constraints, and progress tracking.

use serde::{Deserialize, Serialize};

/// Context for a single episode of holon execution.
///
/// An episode is a bounded unit of execution. The context provides:
/// - Identification (work ID, lease ID, episode number)
/// - Budget constraints (remaining tokens, time, etc.)
/// - Progress state (goal, current progress)
/// - Capability negotiation (available capabilities for planning)
///
/// The holon uses this context to make decisions about what to do
/// in this episode and whether to continue or stop.
///
/// # Example
///
/// ```rust
/// use apm2_holon::EpisodeContext;
///
/// let ctx = EpisodeContext::builder()
///     .work_id("work-123")
///     .lease_id("lease-456")
///     .episode_number(1)
///     .build();
///
/// assert_eq!(ctx.work_id(), "work-123");
/// assert_eq!(ctx.episode_number(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpisodeContext {
    /// Unique identifier for the work item being processed.
    work_id: String,

    /// Lease ID that authorizes this execution.
    lease_id: String,

    /// The current episode number (1-indexed).
    episode_number: u64,

    /// Maximum episodes allowed for this work.
    max_episodes: Option<u64>,

    /// Remaining token budget.
    remaining_tokens: Option<u64>,

    /// Remaining time budget in milliseconds.
    remaining_time_ms: Option<u64>,

    /// Goal specification (what we're trying to achieve).
    goal_spec: Option<String>,

    /// Current progress state (what we've achieved so far).
    progress_state: Option<String>,

    /// Parent holon ID (if this is a sub-holon).
    parent_holon_id: Option<String>,

    /// Timestamp when this episode started (nanoseconds since epoch).
    started_at_ns: u64,

    /// Available capability IDs for planning phase negotiation.
    ///
    /// This field contains the capability IDs that are available for this
    /// episode, as verified by an AAT receipt. Planning steps that require
    /// capabilities not in this list should be filtered out or degraded.
    ///
    /// Empty vector means no capability filtering (all capabilities allowed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    capability_ids: Vec<String>,
}

impl EpisodeContext {
    /// Creates a new builder for constructing an `EpisodeContext`.
    #[must_use]
    pub fn builder() -> EpisodeContextBuilder {
        EpisodeContextBuilder::default()
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

    /// Returns the current episode number (1-indexed).
    #[must_use]
    pub const fn episode_number(&self) -> u64 {
        self.episode_number
    }

    /// Returns the maximum number of episodes allowed.
    #[must_use]
    pub const fn max_episodes(&self) -> Option<u64> {
        self.max_episodes
    }

    /// Returns the remaining token budget.
    #[must_use]
    pub const fn remaining_tokens(&self) -> Option<u64> {
        self.remaining_tokens
    }

    /// Returns the remaining time budget in milliseconds.
    #[must_use]
    pub const fn remaining_time_ms(&self) -> Option<u64> {
        self.remaining_time_ms
    }

    /// Returns the goal specification.
    #[must_use]
    pub fn goal_spec(&self) -> Option<&str> {
        self.goal_spec.as_deref()
    }

    /// Returns the current progress state.
    #[must_use]
    pub fn progress_state(&self) -> Option<&str> {
        self.progress_state.as_deref()
    }

    /// Returns the parent holon ID.
    #[must_use]
    pub fn parent_holon_id(&self) -> Option<&str> {
        self.parent_holon_id.as_deref()
    }

    /// Returns the timestamp when this episode started.
    #[must_use]
    pub const fn started_at_ns(&self) -> u64 {
        self.started_at_ns
    }

    /// Returns the available capability IDs for planning phase negotiation.
    ///
    /// This returns the capability IDs that are available for this episode,
    /// as verified by an AAT receipt. Planning steps that require capabilities
    /// not in this list should be filtered out or degraded.
    ///
    /// Returns an empty slice if no capability filtering is configured.
    #[must_use]
    pub fn capability_ids(&self) -> &[String] {
        &self.capability_ids
    }

    /// Returns `true` if the given capability is available.
    ///
    /// If no capabilities are configured (empty list), all capabilities
    /// are considered available (no filtering).
    #[must_use]
    pub fn has_capability(&self, capability_id: &str) -> bool {
        self.capability_ids.is_empty() || self.capability_ids.iter().any(|c| c == capability_id)
    }

    /// Filters a list of capability IDs to only those available in this
    /// context.
    ///
    /// This is useful for planning phase integration where available
    /// capabilities determine which plan steps can execute.
    ///
    /// If no capabilities are configured (empty list), returns all input
    /// capabilities (no filtering).
    #[must_use]
    pub fn filter_capabilities(&self, capability_ids: &[String]) -> Vec<String> {
        if self.capability_ids.is_empty() {
            return capability_ids.to_vec();
        }
        capability_ids
            .iter()
            .filter(|id| self.capability_ids.contains(id))
            .cloned()
            .collect()
    }

    /// Returns `true` if this is the first episode.
    #[must_use]
    pub const fn is_first_episode(&self) -> bool {
        self.episode_number == 1
    }

    /// Returns `true` if the episode limit has been reached.
    #[must_use]
    pub const fn episode_limit_reached(&self) -> bool {
        match self.max_episodes {
            Some(max) => self.episode_number >= max,
            None => false,
        }
    }

    /// Returns `true` if the token budget is exhausted.
    #[must_use]
    pub const fn tokens_exhausted(&self) -> bool {
        matches!(self.remaining_tokens, Some(0))
    }

    /// Returns `true` if the time budget is exhausted.
    #[must_use]
    pub const fn time_exhausted(&self) -> bool {
        matches!(self.remaining_time_ms, Some(0))
    }

    /// Returns `true` if any budget is exhausted.
    #[must_use]
    pub const fn any_budget_exhausted(&self) -> bool {
        self.tokens_exhausted() || self.time_exhausted() || self.episode_limit_reached()
    }

    /// Creates a context for the next episode, decrementing budgets.
    #[must_use]
    pub fn next_episode(&self, tokens_used: u64, time_used_ms: u64) -> Self {
        Self {
            work_id: self.work_id.clone(),
            lease_id: self.lease_id.clone(),
            episode_number: self.episode_number + 1,
            max_episodes: self.max_episodes,
            remaining_tokens: self.remaining_tokens.map(|t| t.saturating_sub(tokens_used)),
            remaining_time_ms: self
                .remaining_time_ms
                .map(|t| t.saturating_sub(time_used_ms)),
            goal_spec: self.goal_spec.clone(),
            progress_state: self.progress_state.clone(),
            parent_holon_id: self.parent_holon_id.clone(),
            started_at_ns: current_timestamp_ns(),
            capability_ids: self.capability_ids.clone(),
        }
    }

    /// Returns a new context with updated progress state.
    #[must_use]
    pub fn with_progress(&self, progress: impl Into<String>) -> Self {
        Self {
            progress_state: Some(progress.into()),
            ..self.clone()
        }
    }
}

/// Builder for constructing [`EpisodeContext`] instances.
#[derive(Debug, Default)]
pub struct EpisodeContextBuilder {
    work_id: Option<String>,
    lease_id: Option<String>,
    episode_number: Option<u64>,
    max_episodes: Option<u64>,
    remaining_tokens: Option<u64>,
    remaining_time_ms: Option<u64>,
    goal_spec: Option<String>,
    progress_state: Option<String>,
    parent_holon_id: Option<String>,
    started_at_ns: Option<u64>,
    capability_ids: Vec<String>,
}

impl EpisodeContextBuilder {
    /// Sets the work ID.
    #[must_use]
    pub fn work_id(mut self, work_id: impl Into<String>) -> Self {
        self.work_id = Some(work_id.into());
        self
    }

    /// Sets the lease ID.
    #[must_use]
    pub fn lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = Some(lease_id.into());
        self
    }

    /// Sets the episode number.
    #[must_use]
    pub const fn episode_number(mut self, n: u64) -> Self {
        self.episode_number = Some(n);
        self
    }

    /// Sets the maximum episodes.
    #[must_use]
    pub const fn max_episodes(mut self, max: u64) -> Self {
        self.max_episodes = Some(max);
        self
    }

    /// Sets the remaining token budget.
    #[must_use]
    pub const fn remaining_tokens(mut self, tokens: u64) -> Self {
        self.remaining_tokens = Some(tokens);
        self
    }

    /// Sets the remaining time budget in milliseconds.
    #[must_use]
    pub const fn remaining_time_ms(mut self, ms: u64) -> Self {
        self.remaining_time_ms = Some(ms);
        self
    }

    /// Sets the goal specification.
    #[must_use]
    pub fn goal_spec(mut self, goal: impl Into<String>) -> Self {
        self.goal_spec = Some(goal.into());
        self
    }

    /// Sets the progress state.
    #[must_use]
    pub fn progress_state(mut self, progress: impl Into<String>) -> Self {
        self.progress_state = Some(progress.into());
        self
    }

    /// Sets the parent holon ID.
    #[must_use]
    pub fn parent_holon_id(mut self, parent: impl Into<String>) -> Self {
        self.parent_holon_id = Some(parent.into());
        self
    }

    /// Sets the start timestamp.
    #[must_use]
    pub const fn started_at_ns(mut self, ts: u64) -> Self {
        self.started_at_ns = Some(ts);
        self
    }

    /// Sets the available capability IDs for planning phase negotiation.
    ///
    /// These capability IDs determine which plan steps can execute. Steps
    /// requiring capabilities not in this list should be filtered out.
    #[must_use]
    pub fn capability_ids(mut self, capability_ids: Vec<String>) -> Self {
        self.capability_ids = capability_ids;
        self
    }

    /// Adds a single capability ID to the available capabilities.
    #[must_use]
    pub fn add_capability_id(mut self, capability_id: impl Into<String>) -> Self {
        self.capability_ids.push(capability_id.into());
        self
    }

    /// Builds the `EpisodeContext`.
    ///
    /// # Panics
    ///
    /// Panics if `work_id` or `lease_id` is not set.
    #[must_use]
    pub fn build(self) -> EpisodeContext {
        EpisodeContext {
            work_id: self.work_id.expect("work_id is required"),
            lease_id: self.lease_id.expect("lease_id is required"),
            episode_number: self.episode_number.unwrap_or(1),
            max_episodes: self.max_episodes,
            remaining_tokens: self.remaining_tokens,
            remaining_time_ms: self.remaining_time_ms,
            goal_spec: self.goal_spec,
            progress_state: self.progress_state,
            parent_holon_id: self.parent_holon_id,
            started_at_ns: self.started_at_ns.unwrap_or_else(current_timestamp_ns),
            capability_ids: self.capability_ids,
        }
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

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .build();

        assert_eq!(ctx.work_id(), "work-123");
        assert_eq!(ctx.lease_id(), "lease-456");
        assert_eq!(ctx.episode_number(), 1);
        assert!(ctx.is_first_episode());
    }

    #[test]
    fn test_builder_full() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .episode_number(5)
            .max_episodes(10)
            .remaining_tokens(1000)
            .remaining_time_ms(60_000)
            .goal_spec("Complete the task")
            .progress_state("50% done")
            .parent_holon_id("parent-789")
            .started_at_ns(1_000_000_000)
            .build();

        assert_eq!(ctx.episode_number(), 5);
        assert_eq!(ctx.max_episodes(), Some(10));
        assert_eq!(ctx.remaining_tokens(), Some(1000));
        assert_eq!(ctx.remaining_time_ms(), Some(60_000));
        assert_eq!(ctx.goal_spec(), Some("Complete the task"));
        assert_eq!(ctx.progress_state(), Some("50% done"));
        assert_eq!(ctx.parent_holon_id(), Some("parent-789"));
        assert_eq!(ctx.started_at_ns(), 1_000_000_000);
        assert!(!ctx.is_first_episode());
    }

    #[test]
    fn test_episode_limit_reached() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .episode_number(10)
            .max_episodes(10)
            .build();

        assert!(ctx.episode_limit_reached());
    }

    #[test]
    fn test_tokens_exhausted() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .remaining_tokens(0)
            .build();

        assert!(ctx.tokens_exhausted());
        assert!(ctx.any_budget_exhausted());
    }

    #[test]
    fn test_time_exhausted() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .remaining_time_ms(0)
            .build();

        assert!(ctx.time_exhausted());
        assert!(ctx.any_budget_exhausted());
    }

    #[test]
    fn test_next_episode() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .episode_number(1)
            .remaining_tokens(1000)
            .remaining_time_ms(60_000)
            .build();

        let next = ctx.next_episode(100, 5_000);

        assert_eq!(next.episode_number(), 2);
        assert_eq!(next.remaining_tokens(), Some(900));
        assert_eq!(next.remaining_time_ms(), Some(55_000));
    }

    #[test]
    fn test_with_progress() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .build();

        let updated = ctx.with_progress("Step 1 complete");

        assert_eq!(updated.progress_state(), Some("Step 1 complete"));
        assert_eq!(updated.work_id(), ctx.work_id());
    }

    #[test]
    #[should_panic(expected = "work_id is required")]
    fn test_builder_missing_work_id() {
        let _ = EpisodeContext::builder().lease_id("lease-456").build();
    }

    #[test]
    #[should_panic(expected = "lease_id is required")]
    fn test_builder_missing_lease_id() {
        let _ = EpisodeContext::builder().work_id("work-123").build();
    }

    #[test]
    fn test_no_budget_limits() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .build();

        assert!(!ctx.episode_limit_reached());
        assert!(!ctx.tokens_exhausted());
        assert!(!ctx.time_exhausted());
        assert!(!ctx.any_budget_exhausted());
    }

    // =========================================================================
    // Capability ID Tests (TCK-00146)
    // =========================================================================

    #[test]
    fn test_capability_ids_empty_by_default() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .build();

        assert!(ctx.capability_ids().is_empty());
    }

    #[test]
    fn test_capability_ids_builder() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .capability_ids(vec![
                "cac:patch:apply".to_string(),
                "cac:admission:validate".to_string(),
            ])
            .build();

        assert_eq!(ctx.capability_ids().len(), 2);
        assert!(
            ctx.capability_ids()
                .contains(&"cac:patch:apply".to_string())
        );
        assert!(
            ctx.capability_ids()
                .contains(&"cac:admission:validate".to_string())
        );
    }

    #[test]
    fn test_add_capability_id() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .add_capability_id("cac:patch:apply")
            .add_capability_id("cac:admission:validate")
            .build();

        assert_eq!(ctx.capability_ids().len(), 2);
    }

    #[test]
    fn test_has_capability_with_capabilities_set() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .capability_ids(vec![
                "cac:patch:apply".to_string(),
                "cac:admission:validate".to_string(),
            ])
            .build();

        assert!(ctx.has_capability("cac:patch:apply"));
        assert!(ctx.has_capability("cac:admission:validate"));
        assert!(!ctx.has_capability("cac:export:render"));
    }

    #[test]
    fn test_has_capability_with_empty_list_allows_all() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .build();

        // Empty capability list means no filtering - all capabilities allowed
        assert!(ctx.has_capability("cac:patch:apply"));
        assert!(ctx.has_capability("cac:any:capability"));
    }

    #[test]
    fn test_filter_capabilities() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .capability_ids(vec![
                "cac:patch:apply".to_string(),
                "cac:admission:validate".to_string(),
            ])
            .build();

        let requested = vec![
            "cac:patch:apply".to_string(),
            "cac:export:render".to_string(), // Not available
            "cac:admission:validate".to_string(),
        ];

        let filtered = ctx.filter_capabilities(&requested);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"cac:patch:apply".to_string()));
        assert!(filtered.contains(&"cac:admission:validate".to_string()));
        assert!(!filtered.contains(&"cac:export:render".to_string()));
    }

    #[test]
    fn test_filter_capabilities_empty_list_returns_all() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .build();

        let requested = vec![
            "cac:patch:apply".to_string(),
            "cac:export:render".to_string(),
        ];

        let filtered = ctx.filter_capabilities(&requested);

        // Empty capability list means no filtering
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered, requested);
    }

    #[test]
    fn test_next_episode_preserves_capability_ids() {
        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .remaining_tokens(1000)
            .remaining_time_ms(60_000)
            .capability_ids(vec![
                "cac:patch:apply".to_string(),
                "cac:admission:validate".to_string(),
            ])
            .build();

        let next = ctx.next_episode(100, 5_000);

        // Capability IDs should be preserved across episodes
        assert_eq!(next.capability_ids().len(), 2);
        assert!(next.has_capability("cac:patch:apply"));
        assert!(next.has_capability("cac:admission:validate"));
    }
}
