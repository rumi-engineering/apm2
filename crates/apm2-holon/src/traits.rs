//! The Holon trait definition.
//!
//! This module defines the core [`Holon`] trait that specifies the contract
//! surface for any agent participating in holonic coordination.
//!
//! # Design Philosophy
//!
//! The Holon trait embodies Axiom I (Markov Blanket) from the Principia
//! Holonica: each holon defines a clear boundary through its trait contract,
//! with well-defined interfaces for communication across that boundary.
//!
//! Key design decisions:
//! - **Associated types** allow implementers to define their own
//!   Input/Output/State types
//! - **Send + Sync bounds** ensure holons can be used in concurrent contexts
//! - **Separation of intake/execute** allows for lease validation before
//!   execution
//! - **Explicit escalation** ensures holons can properly hand off work

use crate::artifact::Artifact;
use crate::context::EpisodeContext;
use crate::error::HolonError;
use crate::result::EpisodeResult;
use crate::stop::StopCondition;

/// The core trait defining the contract surface for holonic agents.
///
/// A holon is an autonomous agent unit that participates in holonic
/// coordination. It can accept work, execute bounded episodes, produce
/// evidence, and escalate to supervisors when needed.
///
/// # Associated Types
///
/// - `Input`: The type of input this holon accepts
/// - `Output`: The type of output this holon produces
/// - `State`: The internal state type (may be `()` for stateless holons)
///
/// All associated types must implement `Send + Sync` to ensure the holon
/// can be used safely in concurrent contexts.
///
/// # Lifecycle
///
/// 1. **Intake**: The holon receives work via `intake()`, validating the lease
/// 2. **Execute**: Episodes are executed via `execute_episode()` until a stop
///    condition
/// 3. **Emit**: Artifacts are produced via `emit_artifact()` during execution
/// 4. **Complete/Escalate**: Work either completes or is escalated via
///    `escalate()`
///
/// # Example
///
/// ```rust
/// use apm2_holon::{
///     Artifact, EpisodeContext, EpisodeResult, Holon, HolonError,
///     StopCondition,
/// };
///
/// /// A simple counter holon that increments until reaching a target.
/// struct CounterHolon {
///     current: u64,
///     target: u64,
/// }
///
/// impl Holon for CounterHolon {
///     type Input = u64; // Target count
///     type Output = u64; // Final count
///     type State = u64; // Current count
///
///     fn intake(
///         &mut self,
///         input: Self::Input,
///         _lease_id: &str,
///     ) -> Result<(), HolonError> {
///         self.target = input;
///         self.current = 0;
///         Ok(())
///     }
///
///     fn execute_episode(
///         &mut self,
///         _ctx: &EpisodeContext,
///     ) -> Result<EpisodeResult<Self::Output>, HolonError> {
///         self.current += 1;
///         if self.current >= self.target {
///             Ok(EpisodeResult::completed(self.current))
///         } else {
///             Ok(EpisodeResult::continuation())
///         }
///     }
///
///     fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
///         Ok(())
///     }
///
///     fn escalate(&mut self, _reason: &str) -> Result<(), HolonError> {
///         Ok(())
///     }
///
///     fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition {
///         if self.current >= self.target {
///             StopCondition::GoalSatisfied
///         } else if ctx.episode_limit_reached() {
///             StopCondition::max_episodes_reached(ctx.episode_number())
///         } else {
///             StopCondition::Continue
///         }
///     }
///
///     fn state(&self) -> &Self::State {
///         &self.current
///     }
/// }
/// ```
pub trait Holon: Send + Sync {
    /// The type of input this holon accepts.
    type Input: Send + Sync;

    /// The type of output this holon produces.
    type Output: Send + Sync;

    /// The internal state type of this holon.
    type State: Send + Sync;

    /// Accepts a work request and validates the lease.
    ///
    /// This method is called when work is assigned to the holon. It should:
    /// - Validate that the lease is valid for this work
    /// - Prepare the holon's internal state for execution
    /// - Return an error if the work cannot be accepted
    ///
    /// # Arguments
    ///
    /// * `input` - The work input to process
    /// * `lease_id` - The lease ID authorizing this work
    ///
    /// # Errors
    ///
    /// Returns `HolonError::InvalidLease` if the lease is invalid.
    /// Returns `HolonError::InvalidInput` if the input is malformed.
    fn intake(&mut self, input: Self::Input, lease_id: &str) -> Result<(), HolonError>;

    /// Executes a single episode of work within the given context.
    ///
    /// An episode is a bounded unit of execution. The holon should:
    /// - Perform work towards the goal
    /// - Respect budget constraints in the context
    /// - Return a result indicating completion, continuation, or failure
    ///
    /// # Arguments
    ///
    /// * `ctx` - The episode context with budget and progress information
    ///
    /// # Errors
    ///
    /// Returns `HolonError::EpisodeExecutionFailed` if the episode fails.
    /// Returns `HolonError::BudgetExhausted` if the budget is exceeded.
    fn execute_episode(
        &mut self,
        ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError>;

    /// Emits an artifact to the ledger.
    ///
    /// Artifacts are evidence produced during execution. They are logged
    /// to the ledger for auditing and verification.
    ///
    /// # Arguments
    ///
    /// * `artifact` - The artifact to emit
    ///
    /// # Errors
    ///
    /// Returns `HolonError::ArtifactEmissionFailed` if the artifact cannot be
    /// logged.
    fn emit_artifact(&self, artifact: Artifact) -> Result<(), HolonError>;

    /// Escalates work to a supervisor.
    ///
    /// Called when the holon cannot complete the work and needs to hand it off
    /// to a higher-level coordinator. The supervisor will receive the current
    /// state and can delegate to a different holon.
    ///
    /// # Arguments
    ///
    /// * `reason` - Why the work is being escalated
    ///
    /// # Errors
    ///
    /// Returns `HolonError::EscalationFailed` if escalation cannot be
    /// performed.
    fn escalate(&mut self, reason: &str) -> Result<(), HolonError>;

    /// Evaluates whether the holon should stop executing.
    ///
    /// Called after each episode to determine if execution should continue.
    /// The holon should check:
    /// - Has the goal been satisfied?
    /// - Have budget limits been reached?
    /// - Is the holon stuck or making no progress?
    ///
    /// # Arguments
    ///
    /// * `ctx` - The episode context with budget information
    ///
    /// # Returns
    ///
    /// A `StopCondition` indicating whether to continue or stop, and why.
    fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition;

    /// Returns a reference to the holon's internal state.
    ///
    /// This allows inspection of the holon's current state without
    /// modifying it. Useful for monitoring and debugging.
    fn state(&self) -> &Self::State;

    /// Returns the holon's identifier.
    ///
    /// The default implementation returns `None`. Implementers can
    /// override to provide a meaningful identifier.
    fn holon_id(&self) -> Option<&str> {
        None
    }

    /// Returns the holon's type name.
    ///
    /// The default implementation uses the Rust type name.
    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

/// A mock holon for testing.
///
/// This implementation demonstrates correct trait usage and can be used
/// in tests to verify holon-related code.
#[cfg(any(test, feature = "test-utils"))]
pub struct MockHolon {
    /// The holon's identifier.
    pub id: String,
    /// Current state value.
    pub state: u64,
    /// Whether intake has been called.
    pub intake_called: bool,
    /// Number of episodes executed.
    pub episodes_executed: u64,
    /// Episodes until completion.
    pub episodes_until_complete: u64,
    /// Whether to fail on next episode.
    pub fail_next_episode: bool,
    /// Whether to escalate on next episode.
    pub escalate_next_episode: bool,
    /// Emitted artifacts.
    pub emitted_artifacts: Vec<Artifact>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockHolon {
    /// Creates a new mock holon.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            state: 0,
            intake_called: false,
            episodes_executed: 0,
            episodes_until_complete: 1,
            fail_next_episode: false,
            escalate_next_episode: false,
            emitted_artifacts: Vec::new(),
        }
    }

    /// Sets the number of episodes until completion.
    #[must_use]
    pub const fn with_episodes_until_complete(mut self, n: u64) -> Self {
        self.episodes_until_complete = n;
        self
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Holon for MockHolon {
    type Input = String;
    type Output = String;
    type State = u64;

    fn intake(&mut self, _input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        self.intake_called = true;
        Ok(())
    }

    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        if self.fail_next_episode {
            self.fail_next_episode = false;
            return Err(HolonError::episode_failed("mock failure", true));
        }

        if self.escalate_next_episode {
            self.escalate_next_episode = false;
            return Ok(EpisodeResult::escalated());
        }

        self.episodes_executed += 1;
        self.state += 1;

        if self.episodes_executed >= self.episodes_until_complete {
            Ok(EpisodeResult::completed(format!(
                "completed after {} episodes",
                self.episodes_executed
            )))
        } else {
            Ok(EpisodeResult::continue_with_progress(format!(
                "episode {} done",
                self.episodes_executed
            )))
        }
    }

    fn emit_artifact(&self, artifact: Artifact) -> Result<(), HolonError> {
        // Note: We can't mutate self here, but in tests we can check
        // the artifact was valid. In a real implementation, this would
        // write to a ledger.
        let _ = artifact;
        Ok(())
    }

    fn escalate(&mut self, _reason: &str) -> Result<(), HolonError> {
        Ok(())
    }

    fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition {
        if self.episodes_executed >= self.episodes_until_complete {
            StopCondition::GoalSatisfied
        } else if ctx.episode_limit_reached() {
            StopCondition::max_episodes_reached(ctx.episode_number())
        } else if ctx.tokens_exhausted() {
            StopCondition::budget_exhausted("tokens")
        } else {
            StopCondition::Continue
        }
    }

    fn state(&self) -> &Self::State {
        &self.state
    }

    fn holon_id(&self) -> Option<&str> {
        Some(&self.id)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_mock_holon_creation() {
        let holon = MockHolon::new("test-holon");
        assert_eq!(holon.id, "test-holon");
        assert_eq!(holon.state, 0);
        assert!(!holon.intake_called);
        assert_eq!(holon.episodes_executed, 0);
    }

    #[test]
    fn test_mock_holon_intake() {
        let mut holon = MockHolon::new("test-holon");
        let result = holon.intake("input".to_string(), "lease-123");
        assert!(result.is_ok());
        assert!(holon.intake_called);
    }

    #[test]
    fn test_mock_holon_execute_episode() {
        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(3);
        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // First episode
        let result = holon.execute_episode(&ctx).unwrap();
        assert!(result.needs_continuation());
        assert_eq!(holon.episodes_executed, 1);

        // Second episode
        let result = holon.execute_episode(&ctx).unwrap();
        assert!(result.needs_continuation());
        assert_eq!(holon.episodes_executed, 2);

        // Third episode (completes)
        let result = holon.execute_episode(&ctx).unwrap();
        assert!(result.is_completed());
        assert_eq!(holon.episodes_executed, 3);
    }

    #[test]
    fn test_mock_holon_should_stop() {
        let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(2);
        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // Before any episodes
        let condition = holon.should_stop(&ctx);
        assert_eq!(condition, StopCondition::Continue);

        // After first episode
        let _ = holon.execute_episode(&ctx).unwrap();
        let condition = holon.should_stop(&ctx);
        assert_eq!(condition, StopCondition::Continue);

        // After second episode (completes)
        let _ = holon.execute_episode(&ctx).unwrap();
        let condition = holon.should_stop(&ctx);
        assert_eq!(condition, StopCondition::GoalSatisfied);
    }

    #[test]
    fn test_mock_holon_fail_episode() {
        let mut holon = MockHolon::new("test-holon");
        holon.fail_next_episode = true;

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        let result = holon.execute_episode(&ctx);
        assert!(result.is_err());

        // Next episode should succeed
        let result = holon.execute_episode(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_holon_escalate_episode() {
        let mut holon = MockHolon::new("test-holon");
        holon.escalate_next_episode = true;

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        let result = holon.execute_episode(&ctx).unwrap();
        assert!(result.is_escalated());
    }

    #[test]
    fn test_mock_holon_state() {
        let mut holon = MockHolon::new("test-holon");
        assert_eq!(*holon.state(), 0);

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        let _ = holon.execute_episode(&ctx).unwrap();
        assert_eq!(*holon.state(), 1);

        let _ = holon.execute_episode(&ctx).unwrap();
        assert_eq!(*holon.state(), 2);
    }

    #[test]
    fn test_mock_holon_id() {
        let holon = MockHolon::new("my-holon-id");
        assert_eq!(holon.holon_id(), Some("my-holon-id"));
    }

    #[test]
    fn test_mock_holon_type_name() {
        let holon = MockHolon::new("test");
        let type_name = holon.type_name();
        assert!(type_name.contains("MockHolon"));
    }

    #[test]
    fn test_holon_budget_exhaustion_stop() {
        let holon = MockHolon::new("test-holon").with_episodes_until_complete(100);

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .remaining_tokens(0)
            .build();

        let condition = holon.should_stop(&ctx);
        assert_eq!(condition, StopCondition::budget_exhausted("tokens"));
    }

    #[test]
    fn test_holon_max_episodes_stop() {
        let holon = MockHolon::new("test-holon").with_episodes_until_complete(100);

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .episode_number(10)
            .max_episodes(10)
            .build();

        let condition = holon.should_stop(&ctx);
        assert!(matches!(
            condition,
            StopCondition::MaxEpisodesReached { .. }
        ));
    }
}
