//! Episode controller implementation.
//!
//! This module contains the core episode controller logic for executing
//! bounded episode loops with stop condition evaluation.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{DEFAULT_EPISODE_TIMEOUT_MS, DEFAULT_MAX_EPISODES};
use crate::context::EpisodeContext;
use crate::error::HolonError;
use crate::ledger::{EpisodeCompleted, EpisodeCompletionReason, EpisodeEvent, EpisodeStarted};
use crate::resource::Lease;
use crate::stop::StopCondition;
use crate::traits::Holon;

/// Configuration for the episode controller.
///
/// This struct controls the behavior of the episode execution loop,
/// including limits, timeouts, and event emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeControllerConfig {
    /// Maximum number of episodes to execute in a single loop.
    /// This acts as a safety limit even if the holon doesn't signal completion.
    pub max_episodes: u64,

    /// Default timeout per episode in milliseconds.
    /// Individual episodes may have tighter limits from their context.
    pub episode_timeout_ms: u64,

    /// Whether to emit ledger events for episode lifecycle.
    pub emit_events: bool,

    /// Whether to strictly enforce budget limits (fail fast vs. best effort).
    pub strict_budget_enforcement: bool,
}

impl Default for EpisodeControllerConfig {
    fn default() -> Self {
        Self {
            max_episodes: DEFAULT_MAX_EPISODES,
            episode_timeout_ms: DEFAULT_EPISODE_TIMEOUT_MS,
            emit_events: true,
            strict_budget_enforcement: true,
        }
    }
}

impl EpisodeControllerConfig {
    /// Creates a new configuration with the specified max episodes.
    #[must_use]
    pub const fn with_max_episodes(mut self, max: u64) -> Self {
        self.max_episodes = max;
        self
    }

    /// Creates a new configuration with the specified timeout.
    #[must_use]
    pub const fn with_episode_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.episode_timeout_ms = timeout_ms;
        self
    }

    /// Creates a new configuration with event emission enabled/disabled.
    #[must_use]
    pub const fn with_emit_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Creates a new configuration with strict budget enforcement.
    #[must_use]
    pub const fn with_strict_budget_enforcement(mut self, strict: bool) -> Self {
        self.strict_budget_enforcement = strict;
        self
    }
}

/// The outcome of an episode loop execution.
///
/// This enum captures why the episode loop terminated, providing context
/// for the caller to decide what to do next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum EpisodeLoopOutcome {
    /// The goal was satisfied; work is complete.
    Completed {
        /// Number of episodes executed.
        episodes_executed: u64,
        /// Total tokens consumed.
        tokens_consumed: u64,
    },

    /// The budget was exhausted before completion.
    BudgetExhausted {
        /// The resource that was exhausted.
        resource: String,
        /// Number of episodes executed.
        episodes_executed: u64,
        /// Total tokens consumed.
        tokens_consumed: u64,
    },

    /// The maximum episode limit was reached.
    MaxEpisodesReached {
        /// Number of episodes executed.
        episodes_executed: u64,
        /// Total tokens consumed.
        tokens_consumed: u64,
    },

    /// The holon signaled it is blocked.
    Blocked {
        /// Reason for the block.
        reason: String,
        /// Number of episodes executed.
        episodes_executed: u64,
    },

    /// The holon escalated the work.
    Escalated {
        /// Reason for escalation.
        reason: String,
        /// Number of episodes executed.
        episodes_executed: u64,
    },

    /// An error occurred during execution.
    Error {
        /// Error description.
        error: String,
        /// Number of episodes executed before error.
        episodes_executed: u64,
        /// Whether this error is recoverable.
        recoverable: bool,
    },
}

impl EpisodeLoopOutcome {
    /// Returns `true` if this is a successful completion.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Returns `true` if the work can potentially continue.
    #[must_use]
    pub const fn can_continue(&self) -> bool {
        matches!(
            self,
            Self::BudgetExhausted { .. } | Self::MaxEpisodesReached { .. } | Self::Blocked { .. }
        )
    }

    /// Returns `true` if this is an error outcome.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Returns the number of episodes executed.
    #[must_use]
    pub const fn episodes_executed(&self) -> u64 {
        match self {
            Self::Completed {
                episodes_executed, ..
            }
            | Self::BudgetExhausted {
                episodes_executed, ..
            }
            | Self::MaxEpisodesReached {
                episodes_executed, ..
            }
            | Self::Blocked {
                episodes_executed, ..
            }
            | Self::Escalated {
                episodes_executed, ..
            }
            | Self::Error {
                episodes_executed, ..
            } => *episodes_executed,
        }
    }

    /// Returns the outcome as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed { .. } => "completed",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::MaxEpisodesReached { .. } => "max_episodes_reached",
            Self::Blocked { .. } => "blocked",
            Self::Escalated { .. } => "escalated",
            Self::Error { .. } => "error",
        }
    }
}

impl fmt::Display for EpisodeLoopOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed {
                episodes_executed,
                tokens_consumed,
            } => {
                write!(
                    f,
                    "completed after {episodes_executed} episodes ({tokens_consumed} tokens)"
                )
            },
            Self::BudgetExhausted {
                resource,
                episodes_executed,
                ..
            } => {
                write!(
                    f,
                    "budget exhausted ({resource}) after {episodes_executed} episodes"
                )
            },
            Self::MaxEpisodesReached {
                episodes_executed, ..
            } => {
                write!(f, "max episodes ({episodes_executed}) reached")
            },
            Self::Blocked {
                reason,
                episodes_executed,
            } => {
                write!(f, "blocked after {episodes_executed} episodes: {reason}")
            },
            Self::Escalated {
                reason,
                episodes_executed,
            } => {
                write!(f, "escalated after {episodes_executed} episodes: {reason}")
            },
            Self::Error {
                error,
                episodes_executed,
                ..
            } => {
                write!(f, "error after {episodes_executed} episodes: {error}")
            },
        }
    }
}

/// The result of an episode loop execution.
///
/// This struct contains the outcome along with collected events and
/// any output produced.
#[derive(Debug, Clone)]
pub struct EpisodeLoopResult<T> {
    /// The outcome of the loop.
    pub outcome: EpisodeLoopOutcome,

    /// Events emitted during execution (if event emission is enabled).
    pub events: Vec<EpisodeEvent>,

    /// The final output, if the goal was satisfied.
    pub output: Option<T>,

    /// The final stop condition that terminated the loop.
    pub final_stop_condition: StopCondition,
}

impl<T> EpisodeLoopResult<T> {
    /// Creates a new result with the given outcome.
    #[must_use]
    const fn new(outcome: EpisodeLoopOutcome, final_stop_condition: StopCondition) -> Self {
        Self {
            outcome,
            events: Vec::new(),
            output: None,
            final_stop_condition,
        }
    }

    /// Returns `true` if this is a successful completion.
    #[must_use]
    pub const fn is_successful(&self) -> bool {
        self.outcome.is_successful()
    }

    /// Returns the number of episodes executed.
    #[must_use]
    pub const fn episodes_executed(&self) -> u64 {
        self.outcome.episodes_executed()
    }
}

/// Episode controller for managing bounded holon execution.
///
/// The controller implements the episode loop pattern:
///
/// 1. Construct `EpisodeContext` from work state and budget
/// 2. Execute episode via `Holon::execute_episode`
/// 3. Evaluate stop condition via `Holon::should_stop`
/// 4. Emit ledger events
/// 5. Repeat until stop condition is met
///
/// # Type Parameters
///
/// The controller is generic over the output type `T` which must match
/// the holon's output type.
#[derive(Debug, Clone)]
pub struct EpisodeController {
    /// Configuration for the controller.
    config: EpisodeControllerConfig,
}

impl EpisodeController {
    /// Creates a new episode controller with the given configuration.
    #[must_use]
    pub const fn new(config: EpisodeControllerConfig) -> Self {
        Self { config }
    }

    /// Creates a new episode controller with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(EpisodeControllerConfig::default())
    }

    /// Returns the controller configuration.
    #[must_use]
    pub const fn config(&self) -> &EpisodeControllerConfig {
        &self.config
    }

    /// Constructs an `EpisodeContext` from work state and lease.
    ///
    /// This method creates the context that will be passed to the holon
    /// for episode execution.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work ID being processed
    /// * `lease` - The lease authorizing execution
    /// * `episode_number` - Current episode number (1-indexed)
    /// * `goal_spec` - Optional goal specification
    /// * `progress_state` - Optional current progress
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    #[must_use]
    pub fn build_context(
        &self,
        work_id: &str,
        lease: &Lease,
        episode_number: u64,
        goal_spec: Option<&str>,
        progress_state: Option<&str>,
        timestamp_ns: u64,
    ) -> EpisodeContext {
        let budget = lease.budget();
        let max_episodes = self.config.max_episodes.min(budget.remaining_episodes());

        let mut builder = EpisodeContext::builder()
            .work_id(work_id)
            .lease_id(lease.lease_id())
            .episode_number(episode_number)
            .max_episodes(max_episodes)
            .remaining_tokens(budget.remaining_tokens())
            .remaining_time_ms(budget.remaining_duration_ms())
            .started_at_ns(timestamp_ns);

        if let Some(goal) = goal_spec {
            builder = builder.goal_spec(goal);
        }

        if let Some(progress) = progress_state {
            builder = builder.progress_state(progress);
        }

        builder.build()
    }

    /// Evaluates the stop condition based on context and holon state.
    ///
    /// This method checks stop conditions in priority order:
    /// 1. Context budget exhaustion
    /// 2. Holon's own stop condition
    /// 3. Max episodes reached
    ///
    /// # Arguments
    ///
    /// * `ctx` - The current episode context
    /// * `holon_stop` - The stop condition from the holon
    #[must_use]
    pub fn evaluate_stop_condition(
        &self,
        ctx: &EpisodeContext,
        holon_stop: &StopCondition,
    ) -> StopCondition {
        // Priority 1: Check context-level budget exhaustion
        if ctx.tokens_exhausted() {
            return StopCondition::budget_exhausted("tokens");
        }
        if ctx.time_exhausted() {
            return StopCondition::budget_exhausted("time");
        }

        // Priority 2: Check holon's own stop condition
        if holon_stop.should_stop() {
            return holon_stop.clone();
        }

        // Priority 3: Check max episodes
        if ctx.episode_limit_reached() {
            return StopCondition::max_episodes_reached(ctx.episode_number());
        }

        // No stop condition - continue
        StopCondition::Continue
    }

    /// Runs the episode loop for a holon.
    ///
    /// This is the main entry point for executing episodes. It handles:
    /// - Context construction
    /// - Episode execution
    /// - Stop condition evaluation
    /// - Event emission
    /// - Budget tracking
    ///
    /// # Arguments
    ///
    /// * `holon` - The holon to execute
    /// * `work_id` - The work ID being processed
    /// * `lease` - The lease authorizing execution (mutable for budget
    ///   deduction)
    /// * `goal_spec` - Optional goal specification
    /// * `initial_episode_number` - Starting episode number (1-indexed). Use a
    ///   value > 1 when resuming from a previous execution to ensure
    ///   monotonically increasing episode numbers across restarts.
    /// * `clock` - Function to get current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// Returns an `EpisodeLoopResult` containing the outcome, events, and
    /// output.
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidInput` if:
    /// - `work_id` fails ID validation (empty, too long, contains `/` or null)
    /// - `lease_id` fails ID validation
    /// - `goal_spec` exceeds maximum length or contains null bytes
    ///
    /// Returns `HolonError` if a fatal error occurs during execution.
    // Note: This function manages the episode loop state machine. Further
    // decomposition would hurt readability by spreading the control flow.
    #[allow(clippy::too_many_lines)]
    pub fn run_episode_loop<H, F>(
        &self,
        holon: &mut H,
        work_id: &str,
        lease: &mut Lease,
        goal_spec: Option<&str>,
        initial_episode_number: u64,
        mut clock: F,
    ) -> Result<EpisodeLoopResult<H::Output>, HolonError>
    where
        H: Holon,
        F: FnMut() -> u64,
    {
        // Validate inputs before processing
        crate::ledger::validate_id(work_id, "work_id")?;
        crate::ledger::validate_id(lease.lease_id(), "lease_id")?;
        if let Some(spec) = goal_spec {
            crate::ledger::validate_goal_spec(spec)?;
        }

        let mut events = Vec::new();
        let mut episode_number: u64 = initial_episode_number.max(1);
        let mut total_tokens_consumed: u64 = 0;
        let mut progress_state: Option<String> = None;
        let mut final_output: Option<H::Output> = None;
        // Note: This initial value is always overwritten in the loop, but we need
        // to initialize it because it's used after the loop exits.
        #[allow(unused_assignments)]
        let mut final_stop_condition = StopCondition::Continue;

        loop {
            let start_ns = clock();

            // Build context for this episode
            let ctx = self.build_context(
                work_id,
                lease,
                episode_number,
                goal_spec,
                progress_state.as_deref(),
                start_ns,
            );

            // Check if we should stop before executing (e.g., budget already exhausted)
            let pre_check = self.evaluate_stop_condition(&ctx, &StopCondition::Continue);
            if pre_check.should_stop() {
                final_stop_condition = pre_check;
                break;
            }

            // Generate episode ID
            let episode_id = format!("{work_id}-ep-{episode_number}");

            // Emit episode started event
            if self.config.emit_events {
                events.push(Self::make_started_event(
                    &episode_id,
                    work_id,
                    lease.lease_id(),
                    episode_number,
                    start_ns,
                    &ctx,
                    goal_spec,
                ));
            }

            // Execute the episode
            let result = holon.execute_episode(&ctx);
            let end_ns = clock();

            match result {
                Ok(episode_result) => {
                    // Track resource consumption - capture before potential move
                    let tokens_used = episode_result.tokens_consumed();
                    let time_used_ms = episode_result.time_consumed_ms();
                    let artifact_count = episode_result.artifact_count();
                    let is_completed = episode_result.is_completed();
                    let is_escalated = episode_result.is_escalated();
                    total_tokens_consumed = total_tokens_consumed.saturating_add(tokens_used);

                    // Deduct from lease budget - check if deduction succeeds
                    // If deduction fails, we've exceeded budget and should stop
                    let exceeded_resource = Self::deduct_budget(lease, tokens_used, time_used_ms);

                    // If budget was exceeded, stop the loop
                    if let Some(resource) = exceeded_resource {
                        final_stop_condition = StopCondition::budget_exhausted(resource.clone());
                        Self::emit_completed_if(
                            self.config.emit_events,
                            &mut events,
                            &episode_id,
                            EpisodeCompletionReason::BudgetExhausted { resource },
                            end_ns,
                            tokens_used,
                            time_used_ms,
                            0,
                            None,
                        );
                        break;
                    }

                    // Update progress state
                    if let Some(progress) = episode_result.progress_update() {
                        progress_state = Some(progress.to_string());
                    }

                    // Check for completion
                    if is_completed {
                        final_output = episode_result.into_output();
                        final_stop_condition = StopCondition::GoalSatisfied;
                        Self::emit_completed_if(
                            self.config.emit_events,
                            &mut events,
                            &episode_id,
                            EpisodeCompletionReason::GoalSatisfied,
                            end_ns,
                            tokens_used,
                            time_used_ms,
                            artifact_count,
                            None,
                        );
                        break;
                    }

                    // Check for escalation
                    if is_escalated {
                        final_stop_condition =
                            StopCondition::escalated("holon requested escalation");
                        Self::emit_completed_if(
                            self.config.emit_events,
                            &mut events,
                            &episode_id,
                            EpisodeCompletionReason::Escalated {
                                reason: "holon requested escalation".to_string(),
                            },
                            end_ns,
                            tokens_used,
                            0,
                            0,
                            None,
                        );
                        break;
                    }

                    // Evaluate stop condition
                    let holon_stop = holon.should_stop(&ctx);
                    let effective_stop = self.evaluate_stop_condition(&ctx, &holon_stop);
                    let reason = EpisodeCompletionReason::from(&effective_stop);
                    Self::emit_completed_if(
                        self.config.emit_events,
                        &mut events,
                        &episode_id,
                        reason,
                        end_ns,
                        tokens_used,
                        time_used_ms,
                        0,
                        progress_state.as_deref(),
                    );

                    if effective_stop.should_stop() {
                        final_stop_condition = effective_stop;
                        break;
                    }

                    // Continue to next episode
                    episode_number = episode_number.saturating_add(1);
                    if episode_number > self.config.max_episodes {
                        final_stop_condition =
                            StopCondition::max_episodes_reached(self.config.max_episodes);
                        break;
                    }
                },
                Err(error) => {
                    Self::emit_error_event_if(
                        self.config.emit_events,
                        &mut events,
                        &episode_id,
                        &error,
                        end_ns,
                    );
                    final_stop_condition = StopCondition::error(error.to_string());
                    if self.config.strict_budget_enforcement && !error.is_recoverable() {
                        return Err(error);
                    }
                    break;
                },
            }
        }

        // Build the outcome from the final stop condition
        let outcome =
            Self::build_outcome(&final_stop_condition, episode_number, total_tokens_consumed);

        let mut result = EpisodeLoopResult::new(outcome, final_stop_condition);
        result.events = events;
        result.output = final_output;

        Ok(result)
    }

    /// Creates an episode started event.
    #[allow(clippy::too_many_arguments)]
    fn make_started_event(
        episode_id: &str,
        work_id: &str,
        lease_id: &str,
        episode_number: u64,
        start_ns: u64,
        ctx: &EpisodeContext,
        goal_spec: Option<&str>,
    ) -> EpisodeEvent {
        let mut event =
            EpisodeStarted::new(episode_id, work_id, lease_id, episode_number, start_ns)
                .with_remaining_tokens(ctx.remaining_tokens().unwrap_or(u64::MAX))
                .with_remaining_time_ms(ctx.remaining_time_ms().unwrap_or(u64::MAX));
        if let Some(goal) = goal_spec {
            event = event.with_goal_spec(goal);
        }
        EpisodeEvent::Started(event)
    }

    /// Emits a completed event if event emission is enabled.
    #[allow(clippy::too_many_arguments)]
    fn emit_completed_if(
        emit: bool,
        events: &mut Vec<EpisodeEvent>,
        episode_id: &str,
        reason: EpisodeCompletionReason,
        end_ns: u64,
        tokens_used: u64,
        time_used_ms: u64,
        artifact_count: u64,
        progress: Option<&str>,
    ) {
        if !emit {
            return;
        }
        let mut event = EpisodeCompleted::new(episode_id, reason, end_ns)
            .with_tokens_consumed(tokens_used)
            .with_time_consumed_ms(time_used_ms);
        if artifact_count > 0 {
            event = event.with_artifact_count(artifact_count);
        }
        if let Some(p) = progress {
            event = event.with_progress_update(p);
        }
        events.push(EpisodeEvent::Completed(event));
    }

    /// Emits an error event if event emission is enabled.
    fn emit_error_event_if(
        emit: bool,
        events: &mut Vec<EpisodeEvent>,
        episode_id: &str,
        error: &HolonError,
        end_ns: u64,
    ) {
        if !emit {
            return;
        }
        let event = EpisodeCompleted::new(
            episode_id,
            EpisodeCompletionReason::Error {
                error: error.to_string(),
            },
            end_ns,
        )
        .with_error_message(error.to_string());
        events.push(EpisodeEvent::Completed(event));
    }

    /// Deducts resource consumption from the lease budget.
    ///
    /// Returns `Some(resource_name)` if a budget was exceeded, `None`
    /// otherwise.
    fn deduct_budget(lease: &mut Lease, tokens_used: u64, time_used_ms: u64) -> Option<String> {
        if tokens_used > 0 && lease.budget_mut().deduct_tokens(tokens_used).is_err() {
            return Some("tokens".to_string());
        }
        if time_used_ms > 0 && lease.budget_mut().deduct_duration_ms(time_used_ms).is_err() {
            return Some("time".to_string());
        }
        if lease.budget_mut().deduct_episodes(1).is_err() {
            return Some("episodes".to_string());
        }
        None
    }

    /// Builds the outcome from a stop condition.
    fn build_outcome(
        stop: &StopCondition,
        episodes_executed: u64,
        tokens_consumed: u64,
    ) -> EpisodeLoopOutcome {
        match stop {
            StopCondition::Continue => {
                // This shouldn't happen in normal operation
                EpisodeLoopOutcome::Completed {
                    episodes_executed,
                    tokens_consumed,
                }
            },
            StopCondition::GoalSatisfied => EpisodeLoopOutcome::Completed {
                episodes_executed,
                tokens_consumed,
            },
            StopCondition::BudgetExhausted { resource } => EpisodeLoopOutcome::BudgetExhausted {
                resource: resource.clone(),
                episodes_executed,
                tokens_consumed,
            },
            StopCondition::MaxEpisodesReached { .. } => EpisodeLoopOutcome::MaxEpisodesReached {
                episodes_executed,
                tokens_consumed,
            },
            StopCondition::TimeoutReached { .. } => EpisodeLoopOutcome::BudgetExhausted {
                resource: "time".to_string(),
                episodes_executed,
                tokens_consumed,
            },
            StopCondition::Stalled { reason }
            | StopCondition::ExternalSignal { signal: reason } => EpisodeLoopOutcome::Blocked {
                reason: reason.clone(),
                episodes_executed,
            },
            StopCondition::Escalated { reason } => EpisodeLoopOutcome::Escalated {
                reason: reason.clone(),
                episodes_executed,
            },
            StopCondition::ErrorCondition { error } => EpisodeLoopOutcome::Error {
                error: error.clone(),
                episodes_executed,
                recoverable: false,
            },
            StopCondition::PolicyViolation { policy } => EpisodeLoopOutcome::Error {
                error: format!("policy violation: {policy}"),
                episodes_executed,
                recoverable: false,
            },
        }
    }
}

impl Default for EpisodeController {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{Budget, LeaseScope};
    use crate::traits::MockHolon;

    fn test_lease() -> Lease {
        Lease::builder()
            .lease_id("test-lease")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(u64::MAX)
            .build()
            .unwrap()
    }

    fn mock_clock() -> impl FnMut() -> u64 {
        let mut time = 1_000_000_000u64;
        move || {
            let current = time;
            time += 1_000_000; // Advance 1ms each call
            current
        }
    }

    #[test]
    fn test_config_default() {
        let config = EpisodeControllerConfig::default();
        assert_eq!(config.max_episodes, DEFAULT_MAX_EPISODES);
        assert_eq!(config.episode_timeout_ms, DEFAULT_EPISODE_TIMEOUT_MS);
        assert!(config.emit_events);
        assert!(config.strict_budget_enforcement);
    }

    #[test]
    fn test_config_builder() {
        let config = EpisodeControllerConfig::default()
            .with_max_episodes(50)
            .with_episode_timeout_ms(30_000)
            .with_emit_events(false)
            .with_strict_budget_enforcement(false);

        assert_eq!(config.max_episodes, 50);
        assert_eq!(config.episode_timeout_ms, 30_000);
        assert!(!config.emit_events);
        assert!(!config.strict_budget_enforcement);
    }

    /// SECURITY TEST: Verify `EpisodeControllerConfig` rejects unknown fields.
    ///
    /// Finding: MEDIUM - Permissive Parsing
    /// Fix: Added `#[serde(deny_unknown_fields)]` to prevent
    /// malicious/corrupted data from being silently accepted.
    #[test]
    fn test_config_rejects_unknown_fields() {
        let json_with_unknown_field = r#"{
            "max_episodes": 100,
            "episode_timeout_ms": 60000,
            "emit_events": true,
            "strict_budget_enforcement": true,
            "malicious_config": "should_be_rejected"
        }"#;

        let result: Result<EpisodeControllerConfig, _> =
            serde_json::from_str(json_with_unknown_field);
        assert!(
            result.is_err(),
            "EpisodeControllerConfig should reject JSON with unknown fields"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field"),
            "Error should mention 'unknown field': {err}"
        );
    }

    /// SECURITY TEST: Verify `EpisodeLoopOutcome` rejects unknown fields.
    #[test]
    fn test_outcome_rejects_unknown_fields() {
        let json_with_unknown_field = r#"{
            "Completed": {
                "episodes_executed": 5,
                "tokens_consumed": 1000,
                "extra_field": "should_be_rejected"
            }
        }"#;

        let result: Result<EpisodeLoopOutcome, _> = serde_json::from_str(json_with_unknown_field);
        assert!(
            result.is_err(),
            "EpisodeLoopOutcome should reject JSON with unknown fields"
        );
    }

    #[test]
    fn test_build_context() {
        let controller = EpisodeController::with_defaults();
        let lease = test_lease();

        let ctx = controller.build_context(
            "work-123",
            &lease,
            1,
            Some("Complete the task"),
            None,
            1_000_000_000,
        );

        assert_eq!(ctx.work_id(), "work-123");
        assert_eq!(ctx.lease_id(), "test-lease");
        assert_eq!(ctx.episode_number(), 1);
        assert_eq!(ctx.goal_spec(), Some("Complete the task"));
        assert_eq!(ctx.remaining_tokens(), Some(10_000));
    }

    #[test]
    fn test_evaluate_stop_condition_tokens_exhausted() {
        let controller = EpisodeController::with_defaults();

        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .remaining_tokens(0) // Exhausted
            .build();

        let result = controller.evaluate_stop_condition(&ctx, &StopCondition::Continue);
        assert!(matches!(
            result,
            StopCondition::BudgetExhausted { resource } if resource == "tokens"
        ));
    }

    #[test]
    fn test_evaluate_stop_condition_holon_stop() {
        let controller = EpisodeController::with_defaults();

        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .remaining_tokens(1000)
            .build();

        let holon_stop = StopCondition::GoalSatisfied;
        let result = controller.evaluate_stop_condition(&ctx, &holon_stop);
        assert_eq!(result, StopCondition::GoalSatisfied);
    }

    #[test]
    fn test_evaluate_stop_condition_max_episodes() {
        let controller = EpisodeController::with_defaults();

        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .episode_number(10)
            .max_episodes(10) // At limit
            .remaining_tokens(1000)
            .build();

        let result = controller.evaluate_stop_condition(&ctx, &StopCondition::Continue);
        assert!(matches!(result, StopCondition::MaxEpisodesReached { .. }));
    }

    #[test]
    fn test_evaluate_stop_condition_continue() {
        let controller = EpisodeController::with_defaults();

        let ctx = EpisodeContext::builder()
            .work_id("work-123")
            .lease_id("lease-456")
            .episode_number(5)
            .max_episodes(10)
            .remaining_tokens(1000)
            .build();

        let result = controller.evaluate_stop_condition(&ctx, &StopCondition::Continue);
        assert_eq!(result, StopCondition::Continue);
    }

    #[test]
    fn test_run_episode_loop_success() {
        let controller = EpisodeController::new(
            EpisodeControllerConfig::default()
                .with_max_episodes(10)
                .with_emit_events(true),
        );

        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(3);
        let mut lease = test_lease();

        let clock = mock_clock();
        let result = controller
            .run_episode_loop(
                &mut holon,
                "work-123",
                &mut lease,
                Some("Complete task"),
                1, // initial_episode_number
                clock,
            )
            .unwrap();

        assert!(result.is_successful());
        assert_eq!(result.episodes_executed(), 3);
        assert!(result.output.is_some());

        // Should have events (started + completed for each episode)
        assert_eq!(result.events.len(), 6); // 3 started + 3 completed
    }

    #[test]
    fn test_run_episode_loop_max_episodes() {
        let controller = EpisodeController::new(
            EpisodeControllerConfig::default()
                .with_max_episodes(5)
                .with_emit_events(false),
        );

        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(100); // Never completes
        let mut lease = test_lease();

        let clock = mock_clock();
        let result = controller
            .run_episode_loop(&mut holon, "work-123", &mut lease, None, 1, clock)
            .unwrap();

        assert!(!result.is_successful());
        assert!(matches!(
            result.outcome,
            EpisodeLoopOutcome::MaxEpisodesReached { .. }
        ));
        assert_eq!(result.episodes_executed(), 5);
    }

    #[test]
    fn test_run_episode_loop_budget_exhausted() {
        let controller = EpisodeController::new(
            EpisodeControllerConfig::default()
                .with_max_episodes(100)
                .with_emit_events(false),
        );

        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(100);

        // Create a lease with very limited episodes
        let mut lease = Lease::builder()
            .lease_id("limited-lease")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(3, 100, 10_000, 60_000)) // Only 3 episodes
            .expires_at_ns(u64::MAX)
            .build()
            .unwrap();

        let clock = mock_clock();
        let result = controller
            .run_episode_loop(&mut holon, "work-123", &mut lease, None, 1, clock)
            .unwrap();

        assert!(!result.is_successful());
        // Should stop due to budget
        assert!(matches!(
            result.outcome,
            EpisodeLoopOutcome::BudgetExhausted { .. }
                | EpisodeLoopOutcome::MaxEpisodesReached { .. }
        ));
    }

    #[test]
    fn test_run_episode_loop_escalation() {
        let controller =
            EpisodeController::new(EpisodeControllerConfig::default().with_emit_events(true));

        let mut holon = MockHolon::new("test-holon");
        holon.escalate_next_episode = true;

        let mut lease = test_lease();

        let clock = mock_clock();
        let result = controller
            .run_episode_loop(&mut holon, "work-123", &mut lease, None, 1, clock)
            .unwrap();

        assert!(!result.is_successful());
        assert!(matches!(
            result.outcome,
            EpisodeLoopOutcome::Escalated { .. }
        ));
    }

    #[test]
    fn test_run_episode_loop_error_recoverable() {
        let controller = EpisodeController::new(
            EpisodeControllerConfig::default()
                .with_strict_budget_enforcement(false) // Don't fail fast
                .with_emit_events(true),
        );

        let mut holon = MockHolon::new("test-holon");
        holon.fail_next_episode = true;

        let mut lease = test_lease();

        let clock = mock_clock();
        let result =
            controller.run_episode_loop(&mut holon, "work-123", &mut lease, None, 1, clock);

        // Should succeed (return result) even with error because
        // strict_budget_enforcement=false
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(matches!(result.outcome, EpisodeLoopOutcome::Error { .. }));
    }

    #[test]
    fn test_episode_loop_outcome_properties() {
        let completed = EpisodeLoopOutcome::Completed {
            episodes_executed: 5,
            tokens_consumed: 1000,
        };
        assert!(completed.is_successful());
        assert!(!completed.can_continue());
        assert_eq!(completed.episodes_executed(), 5);
        assert_eq!(completed.as_str(), "completed");

        let budget_exhausted = EpisodeLoopOutcome::BudgetExhausted {
            resource: "tokens".to_string(),
            episodes_executed: 3,
            tokens_consumed: 500,
        };
        assert!(!budget_exhausted.is_successful());
        assert!(budget_exhausted.can_continue());

        let error = EpisodeLoopOutcome::Error {
            error: "test".to_string(),
            episodes_executed: 1,
            recoverable: false,
        };
        assert!(error.is_error());
        assert!(!error.can_continue());
    }

    #[test]
    fn test_episode_loop_outcome_display() {
        let completed = EpisodeLoopOutcome::Completed {
            episodes_executed: 5,
            tokens_consumed: 1000,
        };
        assert!(completed.to_string().contains("5 episodes"));
        assert!(completed.to_string().contains("1000 tokens"));

        let budget = EpisodeLoopOutcome::BudgetExhausted {
            resource: "tokens".to_string(),
            episodes_executed: 3,
            tokens_consumed: 500,
        };
        assert!(budget.to_string().contains("tokens"));
    }

    /// SECURITY TEST: Verify episode numbers increase monotonically across
    /// restarts.
    ///
    /// This test proves that when `run_episode_loop` is called twice for the
    /// same work ID with an appropriate `initial_episode_number`, episode
    /// numbers continue from where they left off (e.g., 1..3 then 4..6).
    ///
    /// Finding: HIGH - Restart/Resume Vulnerability
    /// Fix: Accept `initial_episode_number` parameter to enable monotonic
    /// numbering.
    #[test]
    fn test_episode_numbers_increase_monotonically_across_restarts() {
        let controller = EpisodeController::new(
            EpisodeControllerConfig::default()
                .with_max_episodes(100) // High limit so we don't hit it
                .with_emit_events(true),
        );

        // First run: episodes 1-3
        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(3);
        let mut lease = Lease::builder()
            .lease_id("test-lease")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(20, 200, 20_000, 120_000))
            .expires_at_ns(u64::MAX)
            .build()
            .unwrap();

        let clock = mock_clock();
        let result1 = controller
            .run_episode_loop(
                &mut holon, "work-123", &mut lease, None, 1, // Start from episode 1
                clock,
            )
            .unwrap();

        // Collect episode numbers from first run
        let first_run_episodes: Vec<u64> = result1
            .events
            .iter()
            .filter_map(|e| {
                if let crate::ledger::EpisodeEvent::Started(started) = e {
                    Some(started.episode_number())
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(first_run_episodes, vec![1, 2, 3]);
        let last_episode_first_run = *first_run_episodes.last().unwrap();

        // Second run: episodes 4-6 (simulating restart/resume)
        let mut holon2 = MockHolon::new("test-holon").with_episodes_until_complete(3);
        let clock2 = mock_clock();
        let result2 = controller
            .run_episode_loop(
                &mut holon2,
                "work-123",
                &mut lease,
                None,
                last_episode_first_run + 1, // Continue from episode 4
                clock2,
            )
            .unwrap();

        // Collect episode numbers from second run
        let second_run_episodes: Vec<u64> = result2
            .events
            .iter()
            .filter_map(|e| {
                if let crate::ledger::EpisodeEvent::Started(started) = e {
                    Some(started.episode_number())
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(second_run_episodes, vec![4, 5, 6]);

        // Verify all episode numbers across both runs are unique and monotonic
        let all_episodes: Vec<u64> = first_run_episodes
            .into_iter()
            .chain(second_run_episodes)
            .collect();
        let mut sorted_episodes = all_episodes.clone();
        sorted_episodes.sort_unstable();
        sorted_episodes.dedup();

        assert_eq!(
            all_episodes, sorted_episodes,
            "Episode numbers must be unique and monotonically increasing across restarts"
        );
        assert_eq!(all_episodes, vec![1, 2, 3, 4, 5, 6]);
    }

    /// SECURITY TEST: Verify `initial_episode_number` of 0 is clamped to 1.
    #[test]
    fn test_initial_episode_number_clamped_to_one() {
        let controller = EpisodeController::new(
            EpisodeControllerConfig::default()
                .with_max_episodes(5)
                .with_emit_events(true),
        );

        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(1);
        let mut lease = test_lease();

        let clock = mock_clock();
        let result = controller
            .run_episode_loop(
                &mut holon, "work-123", &mut lease, None,
                0, // Invalid: should be clamped to 1
                clock,
            )
            .unwrap();

        // First episode should be numbered 1, not 0
        let first_episode_number = result
            .events
            .iter()
            .find_map(|e| {
                if let crate::ledger::EpisodeEvent::Started(started) = e {
                    Some(started.episode_number())
                } else {
                    None
                }
            })
            .unwrap();

        assert_eq!(
            first_episode_number, 1,
            "Episode number 0 should be clamped to 1"
        );
    }
}
