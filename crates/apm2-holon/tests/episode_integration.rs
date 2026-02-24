//! Integration tests for episode controller and ledger events.
//!
//! These tests verify the complete episode execution flow including:
//! - Episode context construction
//! - Stop condition evaluation
//! - Ledger event emission
//! - Budget enforcement
//!
//! # Test Coverage
//!
//! - Happy path: Episodes execute until goal is satisfied
//! - Budget exhaustion: Stops when any resource is depleted
//! - Max episodes: Stops when episode limit is reached
//! - Escalation: Handles holon escalation requests
//! - Error handling: Handles episode execution errors
//! - Event chain: Verifies event sequence integrity

use apm2_holon::episode::{EpisodeController, EpisodeControllerConfig, EpisodeLoopOutcome};
use apm2_holon::resource::{Budget, Lease, LeaseScope};
use apm2_holon::{
    Artifact, EpisodeCompletionReason, EpisodeContext, EpisodeEvent, EpisodeResult, Holon,
    HolonError, StopCondition,
};

// ============================================================================
// Test Holons
// ============================================================================

/// A simple holon that counts episodes until reaching a target.
struct CountingHolon {
    target: u64,
    current: u64,
    tokens_per_episode: u64,
}

impl CountingHolon {
    const fn new(target: u64) -> Self {
        Self {
            target,
            current: 0,
            tokens_per_episode: 100,
        }
    }

    const fn with_tokens_per_episode(mut self, tokens: u64) -> Self {
        self.tokens_per_episode = tokens;
        self
    }
}

impl Holon for CountingHolon {
    type Input = ();
    type Output = u64;
    type State = u64;

    fn intake(&mut self, _input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        self.current = 0;
        Ok(())
    }

    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        self.current += 1;

        if self.current >= self.target {
            Ok(EpisodeResult::completed(self.current)
                .with_tokens_consumed(self.tokens_per_episode)
                .with_artifact_count(1))
        } else {
            Ok(EpisodeResult::continue_with_progress(format!(
                "Episode {} of {}",
                self.current, self.target
            ))
            .with_tokens_consumed(self.tokens_per_episode))
        }
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        Ok(())
    }

    fn escalate(&mut self, _reason: &str) -> Result<(), HolonError> {
        Ok(())
    }

    fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition {
        if self.current >= self.target {
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
        &self.current
    }
}

/// A holon that always escalates on the first episode.
struct EscalatingHolon;

impl Holon for EscalatingHolon {
    type Input = ();
    type Output = ();
    type State = ();

    fn intake(&mut self, _input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        Ok(())
    }

    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        Ok(EpisodeResult::escalated())
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        Ok(())
    }

    fn escalate(&mut self, _reason: &str) -> Result<(), HolonError> {
        Ok(())
    }

    fn should_stop(&self, _ctx: &EpisodeContext) -> StopCondition {
        StopCondition::escalated("need supervisor help")
    }

    fn state(&self) -> &Self::State {
        &()
    }
}

/// A holon that fails on the nth episode.
struct FailingHolon {
    fail_on_episode: u64,
    current: u64,
}

impl FailingHolon {
    const fn new(fail_on_episode: u64) -> Self {
        Self {
            fail_on_episode,
            current: 0,
        }
    }
}

impl Holon for FailingHolon {
    type Input = ();
    type Output = ();
    type State = u64;

    fn intake(&mut self, _input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        self.current = 0;
        Ok(())
    }

    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        self.current += 1;

        if self.current == self.fail_on_episode {
            Err(HolonError::episode_failed("intentional failure", false))
        } else {
            Ok(EpisodeResult::continuation())
        }
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        Ok(())
    }

    fn escalate(&mut self, _reason: &str) -> Result<(), HolonError> {
        Ok(())
    }

    fn should_stop(&self, _ctx: &EpisodeContext) -> StopCondition {
        StopCondition::Continue
    }

    fn state(&self) -> &Self::State {
        &self.current
    }
}

/// A holon that reports itself as blocked.
struct BlockingHolon {
    block_on_episode: u64,
    current: u64,
}

impl BlockingHolon {
    const fn new(block_on_episode: u64) -> Self {
        Self {
            block_on_episode,
            current: 0,
        }
    }
}

impl Holon for BlockingHolon {
    type Input = ();
    type Output = ();
    type State = u64;

    fn intake(&mut self, _input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        self.current = 0;
        Ok(())
    }

    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        self.current += 1;
        Ok(EpisodeResult::continuation())
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        Ok(())
    }

    fn escalate(&mut self, _reason: &str) -> Result<(), HolonError> {
        Ok(())
    }

    fn should_stop(&self, _ctx: &EpisodeContext) -> StopCondition {
        if self.current >= self.block_on_episode {
            StopCondition::stalled("waiting for external resource")
        } else {
            StopCondition::Continue
        }
    }

    fn state(&self) -> &Self::State {
        &self.current
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn test_lease(episodes: u64, tokens: u64) -> Lease {
    Lease::builder()
        .lease_id("test-lease")
        .issuer_id("registrar")
        .holder_id("agent")
        .scope(LeaseScope::unlimited())
        .budget(Budget::new(episodes, 100, tokens, 600_000))
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

// ============================================================================
// Integration Tests
// ============================================================================

/// Test the happy path: holon executes episodes until goal is satisfied.
#[test]
fn test_happy_path_goal_satisfied() {
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(100)
            .with_emit_events(true),
    );

    let mut holon = CountingHolon::new(5);
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(
            &mut holon,
            "work-001",
            &mut lease,
            Some("Count to 5"),
            1, // initial_episode_number
            clock,
        )
        .expect("should not fail");

    // Verify outcome
    assert!(result.is_successful());
    assert_eq!(result.episodes_executed(), 5);
    assert!(matches!(
        result.outcome,
        EpisodeLoopOutcome::Completed { .. }
    ));
    assert!(result.output.is_some());
    assert_eq!(result.output.unwrap(), 5);

    // Verify stop condition
    assert_eq!(result.final_stop_condition, StopCondition::GoalSatisfied);

    // Verify events: should have started + completed for each episode
    assert_eq!(result.events.len(), 10); // 5 started + 5 completed

    // Verify event ordering
    for (i, event) in result.events.iter().enumerate() {
        if i % 2 == 0 {
            assert!(event.is_started(), "Even indices should be started events");
        } else {
            assert!(
                event.is_completed(),
                "Odd indices should be completed events"
            );
        }
    }

    // Verify budget was deducted
    assert_eq!(lease.budget().remaining_episodes(), 95); // 100 - 5
    assert_eq!(lease.budget().remaining_tokens(), 9500); // 10000 - 5*100
}

/// Test budget exhaustion: stops when tokens are depleted.
#[test]
fn test_budget_exhaustion_tokens() {
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(100)
            .with_emit_events(true),
    );

    // Holon uses 100 tokens per episode, budget has 350 tokens
    // Should complete 3 episodes, then stop on 4th due to token exhaustion
    let mut holon = CountingHolon::new(10).with_tokens_per_episode(100);
    let mut lease = test_lease(100, 350);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    // Verify outcome - should stop due to budget
    assert!(!result.is_successful());
    assert!(matches!(
        result.outcome,
        EpisodeLoopOutcome::BudgetExhausted { .. } | EpisodeLoopOutcome::MaxEpisodesReached { .. }
    ));

    // Should have executed at most 4 episodes (budget allows 3 full + partial 4th)
    assert!(result.episodes_executed() <= 4);

    // Budget should be depleted
    assert!(lease.budget().remaining_tokens() < 100);
}

/// Test max episodes limit: stops when episode limit is reached.
#[test]
fn test_max_episodes_reached() {
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(3) // Low limit
            .with_emit_events(true),
    );

    let mut holon = CountingHolon::new(100); // Would need 100 episodes
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    // Verify outcome
    assert!(!result.is_successful());
    assert!(matches!(
        result.outcome,
        EpisodeLoopOutcome::MaxEpisodesReached { .. }
    ));
    assert_eq!(result.episodes_executed(), 3);
}

/// Test escalation: holon requests escalation.
#[test]
fn test_escalation() {
    let controller =
        EpisodeController::new(EpisodeControllerConfig::default().with_emit_events(true));

    let mut holon = EscalatingHolon;
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    // Verify outcome
    assert!(!result.is_successful());
    assert!(matches!(
        result.outcome,
        EpisodeLoopOutcome::Escalated { .. }
    ));
    assert_eq!(result.episodes_executed(), 1);

    // Verify final stop condition
    assert!(matches!(
        result.final_stop_condition,
        StopCondition::Escalated { .. }
    ));
}

/// Test error handling: holon fails during execution.
#[test]
fn test_error_handling() {
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_strict_budget_enforcement(false) // Don't propagate error
            .with_emit_events(true),
    );

    let mut holon = FailingHolon::new(3); // Fails on 3rd episode
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should return result even on error");

    // Verify outcome
    assert!(!result.is_successful());
    assert!(matches!(result.outcome, EpisodeLoopOutcome::Error { .. }));
    assert_eq!(result.episodes_executed(), 3);

    // Should have error event
    let completed_events: Vec<_> = result.events.iter().filter(|e| e.is_completed()).collect();

    // Last completed event should be error
    let last_completed = completed_events.last().unwrap();
    if let EpisodeEvent::Completed(c) = last_completed {
        assert!(matches!(c.reason(), EpisodeCompletionReason::Error { .. }));
    }
}

/// Test blocking: holon reports itself as blocked.
#[test]
fn test_blocking() {
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(10)
            .with_emit_events(true),
    );

    let mut holon = BlockingHolon::new(3); // Blocks after 3rd episode
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    // Verify outcome
    assert!(!result.is_successful());
    assert!(matches!(result.outcome, EpisodeLoopOutcome::Blocked { .. }));
    assert_eq!(result.episodes_executed(), 3);

    // Verify final stop condition
    assert!(matches!(
        result.final_stop_condition,
        StopCondition::Stalled { .. }
    ));
}

/// Test event chain integrity.
#[test]
fn test_event_chain_integrity() {
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(5)
            .with_emit_events(true),
    );

    let mut holon = CountingHolon::new(3);
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    // Verify event chain
    let mut episode_ids_started = Vec::new();
    let mut episode_ids_completed = Vec::new();

    for event in &result.events {
        match event {
            EpisodeEvent::Started(e) => {
                episode_ids_started.push(e.episode_id().to_string());
            },
            EpisodeEvent::Completed(e) => {
                episode_ids_completed.push(e.episode_id().to_string());
            },
            _ => {
                // Handle future variants - non-exhaustive enum
            },
        }
    }

    // Every started episode should have a corresponding completed event
    assert_eq!(episode_ids_started.len(), episode_ids_completed.len());

    // Episode IDs should match
    for (started, completed) in episode_ids_started.iter().zip(episode_ids_completed.iter()) {
        assert_eq!(started, completed, "Episode IDs should match");
    }

    // Events should be in chronological order
    let mut last_timestamp = 0;
    for event in &result.events {
        let ts = event.timestamp_ns();
        assert!(
            ts >= last_timestamp,
            "Events should be in chronological order"
        );
        last_timestamp = ts;
    }
}

/// Test that events are not emitted when disabled.
#[test]
fn test_events_disabled() {
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(10)
            .with_emit_events(false), // Disable events
    );

    let mut holon = CountingHolon::new(3);
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    // Should complete successfully
    assert!(result.is_successful());
    assert_eq!(result.episodes_executed(), 3);

    // No events should be emitted
    assert!(result.events.is_empty());
}

/// Test lease budget integration with episode controller.
#[test]
fn test_lease_budget_integration() {
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(100)
            .with_emit_events(false),
    );

    let mut holon = CountingHolon::new(5).with_tokens_per_episode(200);
    let mut lease = test_lease(10, 2000);

    let initial_episodes = lease.budget().remaining_episodes();
    let initial_tokens = lease.budget().remaining_tokens();

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    assert!(result.is_successful());
    assert_eq!(result.episodes_executed(), 5);

    // Verify budget deductions
    let consumed_episodes = initial_episodes - lease.budget().remaining_episodes();
    let consumed_tokens = initial_tokens - lease.budget().remaining_tokens();

    assert_eq!(consumed_episodes, 5);
    assert_eq!(consumed_tokens, 1000); // 5 * 200
}

/// Test context construction with goal specification.
#[test]
fn test_context_with_goal_spec() {
    // We'll verify context construction indirectly by checking the events
    let controller =
        EpisodeController::new(EpisodeControllerConfig::default().with_emit_events(true));

    let mut holon = CountingHolon::new(1);
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(
            &mut holon,
            "work-001",
            &mut lease,
            Some("Test goal specification"),
            1, // initial_episode_number
            clock,
        )
        .expect("should not fail");

    // Find the started event and check goal spec
    let started = result
        .events
        .iter()
        .find(|e| e.is_started())
        .expect("should have started event");

    if let EpisodeEvent::Started(e) = started {
        assert_eq!(e.goal_spec(), Some("Test goal specification"));
    }
}

/// Test multiple stop condition priorities.
#[test]
fn test_stop_condition_priorities() {
    // Create a controller with very low limits to test priorities
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(5)
            .with_emit_events(false),
    );

    // Create a holon that never completes
    let mut holon = CountingHolon::new(1000);

    // Lease with very limited tokens - should exhaust before max episodes
    let mut lease = test_lease(10, 250); // 250 tokens, 100 per episode = 2.5 episodes

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    // Should stop due to token budget, not max episodes
    assert!(!result.is_successful());
    assert!(
        result.episodes_executed() < 5,
        "Should stop before max episodes due to budget"
    );
}

/// Test serialization of episode events.
#[test]
fn test_event_serialization() {
    let controller =
        EpisodeController::new(EpisodeControllerConfig::default().with_emit_events(true));

    let mut holon = CountingHolon::new(2);
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let result = controller
        .run_episode_loop(&mut holon, "work-001", &mut lease, None, 1, clock)
        .expect("should not fail");

    // All events should be serializable
    for event in &result.events {
        let json = serde_json::to_string(event).expect("should serialize");
        let _: EpisodeEvent = serde_json::from_str(&json).expect("should deserialize");
    }
}

// ============================================================================
// Security Tests: Input Validation at Entry Point
// ============================================================================

/// SECURITY TEST: Verify `run_episode_loop` rejects invalid `work_id`.
///
/// Finding: HIGH - Input validation bypass
/// Fix: Added `validate_id` check in `run_episode_loop` before processing.
#[test]
fn test_run_episode_loop_rejects_invalid_work_id() {
    let controller =
        EpisodeController::new(EpisodeControllerConfig::default().with_emit_events(true));

    let mut holon = CountingHolon::new(1);
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();

    // Test with work_id containing '/' (path traversal)
    let result = controller.run_episode_loop(
        &mut holon,
        "work/../../etc/passwd",
        &mut lease,
        None,
        1,
        clock,
    );

    assert!(result.is_err(), "Should reject work_id containing '/'");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("work_id"),
        "Error should mention 'work_id': {err}"
    );
}

/// SECURITY TEST: Verify `run_episode_loop` rejects empty `work_id`.
#[test]
fn test_run_episode_loop_rejects_empty_work_id() {
    let controller =
        EpisodeController::new(EpisodeControllerConfig::default().with_emit_events(true));

    let mut holon = CountingHolon::new(1);
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();

    let result = controller.run_episode_loop(&mut holon, "", &mut lease, None, 1, clock);

    assert!(result.is_err(), "Should reject empty work_id");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("work_id") && err.contains("empty"),
        "Error should mention 'work_id' and 'empty': {err}"
    );
}

/// SECURITY TEST: Verify `run_episode_loop` rejects overly long `goal_spec`.
#[test]
fn test_run_episode_loop_rejects_long_goal_spec() {
    use apm2_holon::MAX_GOAL_SPEC_LENGTH;

    let controller =
        EpisodeController::new(EpisodeControllerConfig::default().with_emit_events(true));

    let mut holon = CountingHolon::new(1);
    let mut lease = test_lease(100, 10_000);

    let clock = mock_clock();
    let long_goal = "x".repeat(MAX_GOAL_SPEC_LENGTH + 1);

    let result = controller.run_episode_loop(
        &mut holon,
        "work-001",
        &mut lease,
        Some(&long_goal),
        1,
        clock,
    );

    assert!(result.is_err(), "Should reject overly long goal_spec");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("goal_spec") && err.contains("maximum length"),
        "Error should mention 'goal_spec' and 'maximum length': {err}"
    );
}
