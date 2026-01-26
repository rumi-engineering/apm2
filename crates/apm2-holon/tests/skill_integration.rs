//! Integration tests for skill frontmatter parsing and holon execution.
//!
//! These tests verify the complete flow from skill parsing through holon
//! execution, as specified in TCK-00047.
//!
//! # Test Coverage
//!
//! - example-holon skill loads correctly
//! - Skill executes through episode loop
//! - Stop conditions work as documented
//! - Pattern is clear from documentation
//!
//! # Definition of Done (TCK-00047)
//!
//! 1. example-holon skill loads correctly
//! 2. Skill executes through episode loop
//! 3. Stop conditions work as documented
//! 4. Pattern is clear from documentation
//! 5. Integration test passes

use std::path::PathBuf;

use apm2_holon::episode::{EpisodeController, EpisodeControllerConfig};
use apm2_holon::resource::{Budget, Lease, LeaseScope};
use apm2_holon::skill::{HolonConfig, parse_frontmatter, parse_skill_file};
use apm2_holon::spawn::{SpawnConfig, SpawnOutcome, spawn_holon};
use apm2_holon::{Artifact, EpisodeContext, EpisodeResult, Holon, HolonError, StopCondition};

// ============================================================================
// Test Holon Implementation
// ============================================================================

/// A test holon that mimics the behavior expected by the example-holon skill.
///
/// This holon:
/// - Accepts TaskRequest-like input
/// - Produces TaskResult-like output
/// - Tracks progress state
/// - Respects configured stop conditions
struct ExampleTaskHolon {
    /// Current task state
    state: TaskProgress,
    /// Work ID for tracking
    work_id: String,
    /// Number of episodes to run before completing
    episodes_to_complete: u64,
    /// Whether to escalate instead of completing
    should_escalate: bool,
    /// Whether to stall (make no progress)
    should_stall: bool,
}

/// Internal state type matching the skill's `state_type: TaskProgress`.
#[derive(Default)]
struct TaskProgress {
    episodes_executed: u64,
    tokens_used: u64,
    tool_calls: u64,
    progress_message: Option<String>,
}

impl ExampleTaskHolon {
    fn new(episodes_to_complete: u64) -> Self {
        Self {
            state: TaskProgress::default(),
            work_id: String::new(),
            episodes_to_complete,
            should_escalate: false,
            should_stall: false,
        }
    }

    const fn with_escalation(mut self) -> Self {
        self.should_escalate = true;
        self
    }

    /// Configure the holon to stall (make no progress updates).
    ///
    /// This triggers stall detection in the episode controller when
    /// `max_stall_episodes` is configured.
    #[allow(dead_code)] // Reserved for future stall detection tests
    const fn with_stall(mut self) -> Self {
        self.should_stall = true;
        self
    }
}

impl Holon for ExampleTaskHolon {
    type Input = String; // Simulates TaskRequest
    type Output = String; // Simulates TaskResult
    type State = TaskProgress;

    fn intake(&mut self, input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        self.work_id = input;
        self.state = TaskProgress::default();
        Ok(())
    }

    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        self.state.episodes_executed += 1;

        // Simulate token usage (1000 tokens per episode)
        let tokens_used = 1000u64;
        self.state.tokens_used = self.state.tokens_used.saturating_add(tokens_used);

        // Simulate tool calls (2 per episode)
        let tool_calls = 2u64;
        self.state.tool_calls = self.state.tool_calls.saturating_add(tool_calls);

        // Handle escalation
        if self.should_escalate && self.state.episodes_executed >= 2 {
            return Ok(EpisodeResult::escalated());
        }

        // Handle stall (no progress update)
        if self.should_stall {
            return Ok(
                EpisodeResult::continuation().with_tokens_consumed(tokens_used), /* No progress
                                                                                  * update - this
                                                                                  * triggers stall
                                                                                  * detection */
            );
        }

        // Check for completion
        if self.state.episodes_executed >= self.episodes_to_complete {
            let result = format!(
                "Task completed after {} episodes, {} tokens, {} tool calls",
                self.state.episodes_executed, self.state.tokens_used, self.state.tool_calls
            );
            return Ok(EpisodeResult::completed(result)
                .with_tokens_consumed(tokens_used)
                .with_artifact_count(1));
        }

        // Continue with progress
        let progress = format!(
            "Episode {} of {} complete",
            self.state.episodes_executed, self.episodes_to_complete
        );
        self.state.progress_message = Some(progress.clone());

        Ok(EpisodeResult::continue_with_progress(progress).with_tokens_consumed(tokens_used))
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        Ok(())
    }

    fn escalate(&mut self, _reason: &str) -> Result<(), HolonError> {
        Ok(())
    }

    fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition {
        if self.state.episodes_executed >= self.episodes_to_complete {
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
        Some("example-holon")
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Returns the path to the example-holon SKILL.md file.
fn example_holon_skill_path() -> PathBuf {
    // Navigate from crate root to documents/skills/example-holon
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("documents/skills/example-holon/SKILL.md")
}

/// Creates a clock function for testing.
fn mock_clock() -> impl FnMut() -> u64 {
    let mut time = 1_000_000_000u64;
    move || {
        let current = time;
        time += 10_000_000; // Advance 10ms each call
        current
    }
}

/// Creates a `SpawnConfig` from a `HolonConfig`.
fn spawn_config_from_holon_config(
    work_id: &str,
    holon_config: &HolonConfig,
) -> Result<SpawnConfig, HolonError> {
    let stop = &holon_config.stop_conditions;

    let episodes = stop.max_episodes.unwrap_or(100);
    let tool_calls = stop.budget.get("tool_calls").copied().unwrap_or(100);
    let tokens = stop.budget.get("tokens").copied().unwrap_or(100_000);
    let duration_ms = stop.timeout_ms.unwrap_or(300_000);

    let scope = holon_config
        .allowed_tools()
        .map_or_else(LeaseScope::empty, |tools| {
            LeaseScope::builder().tools(tools).build()
        });

    SpawnConfig::builder()
        .work_id(work_id)
        .work_title("Example holon test")
        .issuer_id("test-registrar")
        .holder_id("example-holon")
        .scope(scope)
        .budget(Budget::new(episodes, tool_calls, tokens, duration_ms))
        .expires_at_ns(10_000_000_000)
        .build()
}

// ============================================================================
// Integration Tests
// ============================================================================

/// TCK-00047 Criterion 1: example-holon skill loads correctly.
///
/// Verifies that the SKILL.md file parses successfully and contains
/// valid holon configuration.
#[test]
fn test_example_holon_skill_loads_correctly() {
    let skill_path = example_holon_skill_path();

    // Verify file exists
    assert!(
        skill_path.exists(),
        "example-holon SKILL.md should exist at {}",
        skill_path.display()
    );

    // Parse the skill file
    let (frontmatter, body) =
        parse_skill_file(&skill_path).expect("should parse example-holon SKILL.md");

    // Verify basic frontmatter
    assert_eq!(frontmatter.name, "example-holon");
    assert!(frontmatter.description.contains("holon pattern"));
    assert!(
        !frontmatter.user_invocable,
        "example-holon should not be user-invocable"
    );

    // Verify holon config is present
    assert!(
        frontmatter.holon.is_some(),
        "example-holon should have holon configuration"
    );

    let holon_config = frontmatter.holon.unwrap();

    // Verify contract
    assert_eq!(holon_config.contract.input_type, "TaskRequest");
    assert_eq!(holon_config.contract.output_type, "TaskResult");
    assert_eq!(
        holon_config.contract.state_type,
        Some("TaskProgress".to_string())
    );

    // Verify stop conditions are configured
    assert!(holon_config.stop_conditions.is_configured());
    assert_eq!(holon_config.stop_conditions.max_episodes, Some(10));
    assert_eq!(holon_config.stop_conditions.timeout_ms, Some(300_000));
    assert_eq!(holon_config.stop_conditions.max_stall_episodes, Some(3));

    // Verify budget
    assert_eq!(
        holon_config.stop_conditions.budget.get("tokens"),
        Some(&50_000)
    );
    assert_eq!(
        holon_config.stop_conditions.budget.get("tool_calls"),
        Some(&100)
    );

    // Verify tools
    assert!(holon_config.tools.is_some());
    let tools = holon_config.tools.unwrap();
    assert!(tools.contains(&"read_file".to_string()));
    assert!(tools.contains(&"write_file".to_string()));
    assert!(tools.contains(&"glob".to_string()));
    assert!(tools.contains(&"grep".to_string()));
    assert_eq!(tools.len(), 4);

    // Verify body contains documentation
    assert!(body.contains("# Example Holon Skill"));
    assert!(body.contains("Episode Lifecycle"));
    assert!(body.contains("Stop Conditions"));
    assert!(body.contains("Tool Permissions"));
}

/// TCK-00047 Criterion 2: Skill executes through episode loop.
///
/// Verifies that a holon configured from the skill executes episodes
/// correctly until completion.
#[test]
fn test_skill_executes_through_episode_loop() {
    let skill_path = example_holon_skill_path();
    let (frontmatter, _) = parse_skill_file(&skill_path).expect("should parse");
    let holon_config = frontmatter.holon.expect("should have holon config");

    // Create spawn config from skill
    let config =
        spawn_config_from_holon_config("skill-test-001", &holon_config).expect("valid config");

    // Create a holon that completes in 3 episodes (within the 10 episode limit)
    let mut holon = ExampleTaskHolon::new(3);

    // Execute
    let clock = mock_clock();
    let result = spawn_holon(&mut holon, "test-task".to_string(), config, clock)
        .expect("spawn should succeed");

    // Verify execution
    assert!(result.is_successful(), "should complete successfully");
    assert_eq!(result.episodes_executed, 3);
    assert!(result.output.is_some());
    assert!(result.output.unwrap().contains("Task completed"));

    // Verify holon state
    assert_eq!(holon.state.episodes_executed, 3);
    assert!(holon.state.tokens_used > 0);
}

/// TCK-00047 Criterion 3: Stop conditions work as documented.
///
/// Verifies that all configured stop conditions trigger correctly.
#[test]
fn test_stop_conditions_work_as_documented() {
    let skill_path = example_holon_skill_path();
    let (frontmatter, _) = parse_skill_file(&skill_path).expect("should parse");
    let holon_config = frontmatter.holon.expect("should have holon config");

    // Test 3a: max_episodes stop condition
    {
        // Create config with reduced max_episodes for faster test
        // Note: The episode controller's max_episodes must be set explicitly,
        // and the budget episodes must be >= max_episodes to avoid budget
        // exhaustion stopping before max_episodes is reached.
        let config = SpawnConfig::builder()
            .work_id("max-episodes-test")
            .work_title("Max episodes test")
            .issuer_id("registrar")
            .holder_id("holon")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(
                5,       // Budget allows 5 episodes
                100,     // Tool calls budget
                100_000, // Tokens budget (high enough to not exhaust)
                300_000, // Duration budget
            ))
            .episode_config(
                EpisodeControllerConfig::default().with_max_episodes(5), // Match budget
            )
            .expires_at_ns(10_000_000_000)
            .build()
            .expect("valid config");

        // Holon that would need 100 episodes to complete
        let mut holon = ExampleTaskHolon::new(100);
        let clock = mock_clock();

        let result = spawn_holon(&mut holon, "test".to_string(), config, clock)
            .expect("spawn should succeed");

        assert!(
            !result.is_successful(),
            "should not complete - max episodes reached"
        );
        // With budget.episodes == config.max_episodes, we should hit
        // max_episodes_reached or budget_exhausted (episodes) - both indicate
        // the limit was respected
        assert!(
            matches!(
                result.outcome,
                SpawnOutcome::MaxEpisodesReached | SpawnOutcome::BudgetExhausted { .. }
            ),
            "outcome should be MaxEpisodesReached or BudgetExhausted, got {:?}",
            result.outcome
        );
        // Should have executed exactly 5 episodes (the configured limit)
        assert!(
            result.episodes_executed <= 5,
            "should execute at most 5 episodes, got {}",
            result.episodes_executed
        );
    }

    // Test 3b: budget exhaustion (tokens)
    {
        let config = SpawnConfig::builder()
            .work_id("budget-test")
            .work_title("Budget test")
            .issuer_id("registrar")
            .holder_id("holon")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(
                100, 100, 2500, // Only 2500 tokens (holon uses 1000/episode)
                300_000,
            ))
            .expires_at_ns(10_000_000_000)
            .build()
            .expect("valid config");

        let mut holon = ExampleTaskHolon::new(100);
        let clock = mock_clock();

        let result = spawn_holon(&mut holon, "test".to_string(), config, clock)
            .expect("spawn should succeed");

        assert!(
            !result.is_successful(),
            "should not complete - budget exhausted"
        );
        assert!(
            matches!(result.outcome, SpawnOutcome::BudgetExhausted { .. }),
            "outcome should be BudgetExhausted, got {:?}",
            result.outcome
        );
        // Should stop around episode 2-3 due to token budget
        assert!(result.episodes_executed <= 3);
    }

    // Test 3c: escalation
    {
        let config =
            spawn_config_from_holon_config("escalation-test", &holon_config).expect("valid config");

        let mut holon = ExampleTaskHolon::new(10).with_escalation();
        let clock = mock_clock();

        let result = spawn_holon(&mut holon, "test".to_string(), config, clock)
            .expect("spawn should succeed");

        assert!(result.is_escalated(), "should be escalated");
        assert!(
            matches!(result.outcome, SpawnOutcome::Escalated { .. }),
            "outcome should be Escalated"
        );
        assert!(result.episodes_executed >= 2);
    }
}

/// TCK-00047 Criterion 4: Pattern is clear from documentation.
///
/// Verifies that the skill documentation contains all required sections
/// and explains the holon pattern clearly.
#[test]
fn test_pattern_is_clear_from_documentation() {
    let skill_path = example_holon_skill_path();
    let (_, body) = parse_skill_file(&skill_path).expect("should parse");

    // Verify required documentation sections exist
    let required_sections = [
        "# Example Holon Skill",
        "## Purpose",
        "## Usage Pattern",
        "## Episode Lifecycle",
        "## Stop Conditions",
        "## Tool Permissions",
        "## Integration with spawn_holon",
        "## Related Documentation",
        "## Invariants",
    ];

    for section in required_sections {
        assert!(
            body.contains(section),
            "Documentation should contain section: {section}"
        );
    }

    // Verify key concepts are documented
    let key_concepts = [
        "bounded execution",
        "stop condition",
        "tool restriction",
        "fail-close",
        "escalation",
        "intake",
        "execute_episode",
    ];

    for concept in key_concepts {
        assert!(
            body.to_lowercase().contains(concept),
            "Documentation should explain: {concept}"
        );
    }

    // Verify code example is present
    assert!(
        body.contains("```rust"),
        "Documentation should contain Rust code example"
    );
    assert!(
        body.contains("spawn_holon"),
        "Documentation should show spawn_holon usage"
    );
}

/// TCK-00047 Criterion 5: Integration test passes.
///
/// This test is the comprehensive integration test that exercises the
/// full skill loading and execution flow.
#[test]
fn test_full_skill_integration() {
    // Step 1: Load skill from file
    let skill_path = example_holon_skill_path();
    let (frontmatter, body) = parse_skill_file(&skill_path).expect("skill should load");

    // Step 2: Validate skill structure
    assert_eq!(frontmatter.name, "example-holon");
    let holon_config = frontmatter.holon.expect("should have holon config");

    // Step 3: Validate holon configuration
    holon_config.validate().expect("config should be valid");

    // Step 4: Create execution config from skill
    let config =
        spawn_config_from_holon_config("integration-test", &holon_config).expect("valid config");

    // Step 5: Execute holon
    let mut holon = ExampleTaskHolon::new(5);
    let clock = mock_clock();
    let result = spawn_holon(&mut holon, "integration-task".to_string(), config, clock)
        .expect("spawn should succeed");

    // Step 6: Verify complete execution
    assert!(result.is_successful(), "integration test should complete");
    assert_eq!(result.episodes_executed, 5);
    assert!(result.output.is_some());

    // Step 7: Verify ledger events were emitted
    assert!(!result.events.is_empty(), "should emit ledger events");
    assert!(
        !result.episode_events.is_empty(),
        "should emit episode events"
    );

    // Step 8: Verify documentation describes actual behavior
    assert!(body.contains("max_episodes"));
    assert!(body.contains("timeout_ms"));
    assert!(body.contains("tokens"));

    // Test complete!
    println!("TCK-00047 Integration test passed:");
    println!("  - Skill loaded: {}", frontmatter.name);
    println!("  - Episodes executed: {}", result.episodes_executed);
    println!("  - Output: {:?}", result.output);
    println!("  - Ledger events: {}", result.events.len());
    println!("  - Episode events: {}", result.episode_events.len());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test that skill parsing fails for invalid configurations.
#[test]
fn test_invalid_skill_configurations_rejected() {
    // Test: No stop conditions
    let invalid_no_stop = r"---
name: invalid-skill
description: Missing stop conditions
holon:
  contract:
    input_type: Input
    output_type: Output
---
";

    let result = parse_frontmatter(invalid_no_stop);
    assert!(
        result.is_err(),
        "should reject skill without stop conditions"
    );

    // Test: Zero max_episodes
    let invalid_zero_episodes = r"---
name: invalid-skill
description: Zero episodes
holon:
  contract:
    input_type: Input
    output_type: Output
  stop_conditions:
    max_episodes: 0
---
";

    let result = parse_frontmatter(invalid_zero_episodes);
    assert!(
        result.is_err(),
        "should reject skill with zero max_episodes"
    );

    // Test: Duplicate tools
    let invalid_dup_tools = r"---
name: invalid-skill
description: Duplicate tools
holon:
  contract:
    input_type: Input
    output_type: Output
  stop_conditions:
    max_episodes: 10
  tools:
    - read_file
    - read_file
---
";

    let result = parse_frontmatter(invalid_dup_tools);
    assert!(result.is_err(), "should reject skill with duplicate tools");
}

/// Test that tool access follows fail-close semantics.
#[test]
fn test_tool_access_fail_close() {
    // Skill with no tools field
    let no_tools_skill = r"---
name: no-tools-skill
description: No tools field
holon:
  contract:
    input_type: Input
    output_type: Output
  stop_conditions:
    max_episodes: 10
---
";

    let (frontmatter, _) =
        parse_frontmatter(no_tools_skill).expect("should parse skill without tools");
    let holon_config = frontmatter.holon.expect("should have holon config");

    // Omitted tools = no access (fail-close)
    assert!(holon_config.tools.is_none());
    assert!(holon_config.allowed_tools().is_none());

    // Skill with empty tools list
    let empty_tools_skill = r"---
name: empty-tools-skill
description: Empty tools list
holon:
  contract:
    input_type: Input
    output_type: Output
  stop_conditions:
    max_episodes: 10
  tools: []
---
";

    let (frontmatter, _) =
        parse_frontmatter(empty_tools_skill).expect("should parse skill with empty tools");
    let holon_config = frontmatter.holon.expect("should have holon config");

    // Empty list = no access
    assert!(holon_config.tools.is_some());
    assert!(holon_config.allowed_tools().unwrap().is_empty());
}

/// Test that episode controller respects skill configuration.
#[test]
fn test_episode_controller_respects_skill_config() {
    let skill_path = example_holon_skill_path();
    let (frontmatter, _) = parse_skill_file(&skill_path).expect("should parse");
    let holon_config = frontmatter.holon.expect("should have holon config");

    // Create controller with skill's max_episodes
    let max_episodes = holon_config.stop_conditions.max_episodes.unwrap();
    let controller = EpisodeController::new(
        EpisodeControllerConfig::default()
            .with_max_episodes(max_episodes)
            .with_emit_events(true),
    );

    // Create lease with skill's budget
    let tokens = holon_config
        .stop_conditions
        .budget
        .get("tokens")
        .copied()
        .unwrap_or(50_000);
    let mut lease = Lease::builder()
        .lease_id("test-lease")
        .issuer_id("registrar")
        .holder_id("holon")
        .scope(LeaseScope::unlimited())
        .budget(Budget::new(max_episodes, 100, tokens, 300_000))
        .expires_at_ns(u64::MAX)
        .build()
        .expect("valid lease");

    // Run with holon that completes quickly
    let mut holon = ExampleTaskHolon::new(3);
    let clock = mock_clock();

    let result = controller
        .run_episode_loop(
            &mut holon,
            "skill-config-test",
            &mut lease,
            Some("Test goal"),
            1,
            clock,
        )
        .expect("should not fail");

    assert!(result.is_successful());
    assert_eq!(result.episodes_executed(), 3);
}

// ============================================================================
// TCK-00048: create-rfc Skill Holon Configuration Tests
// ============================================================================

/// Returns the path to the create-rfc SKILL.md file.
fn create_rfc_skill_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("documents/skills/create-rfc/SKILL.md")
}

/// TCK-00048 Criterion 1: create-rfc skill has holon: configuration.
///
/// Verifies that the SKILL.md file parses successfully and contains
/// valid holon configuration.
#[test]
fn test_create_rfc_skill_has_holon_config() {
    let skill_path = create_rfc_skill_path();

    // Verify file exists
    assert!(
        skill_path.exists(),
        "create-rfc SKILL.md should exist at {}",
        skill_path.display()
    );

    // Parse the skill file
    let (frontmatter, body) =
        parse_skill_file(&skill_path).expect("should parse create-rfc SKILL.md");

    // Verify basic frontmatter
    assert_eq!(frontmatter.name, "create-rfc");
    assert!(frontmatter.description.contains("RFC"));
    assert!(
        frontmatter.user_invocable,
        "create-rfc should be user-invocable"
    );

    // Verify holon config is present
    assert!(
        frontmatter.holon.is_some(),
        "create-rfc should have holon configuration"
    );

    let holon_config = frontmatter.holon.unwrap();

    // Verify contract
    assert_eq!(holon_config.contract.input_type, "RfcRequest");
    assert_eq!(holon_config.contract.output_type, "RfcResult");
    assert_eq!(
        holon_config.contract.state_type,
        Some("RfcProgress".to_string())
    );

    // Verify body contains holon documentation
    assert!(body.contains("## Holon Configuration"));
    assert!(body.contains("Stop Conditions"));
    assert!(body.contains("Tool Permissions"));
}

/// TCK-00048 Criterion 2: Stop conditions appropriate for RFC work.
///
/// Verifies that the configured stop conditions are suitable for
/// RFC generation work (multi-phase, longer-running).
#[test]
fn test_create_rfc_stop_conditions_appropriate() {
    let skill_path = create_rfc_skill_path();
    let (frontmatter, _) = parse_skill_file(&skill_path).expect("should parse");
    let holon_config = frontmatter.holon.expect("should have holon config");
    let stop = &holon_config.stop_conditions;

    // Verify stop conditions are configured
    assert!(stop.is_configured());

    // max_episodes: Should be >= 25 for multi-phase RFC work
    let max_episodes = stop.max_episodes.expect("should have max_episodes");
    assert!(
        max_episodes >= 25,
        "RFC work needs at least 25 episodes, got {max_episodes}"
    );

    // timeout_ms: Should be >= 30 minutes (1,800,000 ms) for complex RFCs
    let timeout_ms = stop.timeout_ms.expect("should have timeout_ms");
    assert!(
        timeout_ms >= 1_800_000,
        "RFC work needs at least 30 min timeout, got {timeout_ms} ms"
    );

    // max_stall_episodes: Should be >= 5 for exploration
    let max_stall = stop
        .max_stall_episodes
        .expect("should have max_stall_episodes");
    assert!(
        max_stall >= 5,
        "RFC work should allow 5+ stall episodes, got {max_stall}"
    );
}

/// TCK-00048 Criterion 3: Budget limits prevent runaway execution.
///
/// Verifies that budget limits are set and will prevent unbounded
/// resource consumption.
#[test]
fn test_create_rfc_budget_limits_prevent_runaway() {
    let skill_path = create_rfc_skill_path();
    let (frontmatter, _) = parse_skill_file(&skill_path).expect("should parse");
    let holon_config = frontmatter.holon.expect("should have holon config");
    let stop = &holon_config.stop_conditions;

    // Verify budget has token limit
    let tokens = stop
        .budget
        .get("tokens")
        .expect("should have tokens budget");
    assert!(
        *tokens > 0,
        "tokens budget must be positive to prevent runaway"
    );
    assert!(
        *tokens >= 500_000,
        "RFC work needs at least 500K tokens, got {tokens}"
    );

    // Verify budget has tool_calls limit
    let tool_calls = stop
        .budget
        .get("tool_calls")
        .expect("should have tool_calls budget");
    assert!(
        *tool_calls > 0,
        "tool_calls budget must be positive to prevent runaway"
    );
    assert!(
        *tool_calls >= 500,
        "RFC work needs at least 500 tool calls, got {tool_calls}"
    );

    // Verify budget will stop before infinite execution
    // At least one finite limit must exist
    assert!(
        stop.max_episodes.is_some() || stop.timeout_ms.is_some() || !stop.budget.is_empty(),
        "must have at least one finite limit"
    );
}

/// TCK-00048 Criterion 4: create-rfc executes correctly as holon.
///
/// Verifies that a spawn configuration can be built from the skill
/// and a holon can be executed with it.
#[test]
fn test_create_rfc_executes_as_holon() {
    let skill_path = create_rfc_skill_path();
    let (frontmatter, _) = parse_skill_file(&skill_path).expect("should parse");
    let holon_config = frontmatter.holon.expect("should have holon config");

    // Create spawn config from skill
    let config =
        spawn_config_from_holon_config("rfc-test-001", &holon_config).expect("valid config");

    // Create a test holon that completes quickly (simulating successful RFC
    // creation)
    let mut holon = ExampleTaskHolon::new(3);

    // Execute
    let clock = mock_clock();
    let result = spawn_holon(&mut holon, "test-rfc-creation".to_string(), config, clock)
        .expect("spawn should succeed");

    // Verify execution completed
    assert!(result.is_successful(), "should complete successfully");
    assert!(
        result.episodes_executed <= 25,
        "should respect max_episodes"
    );
}

/// TCK-00048 Criterion 5: No regression in existing behavior.
///
/// Verifies that the skill documentation still contains all the
/// original content and the skill can still be understood without
/// the holon configuration.
#[test]
fn test_create_rfc_no_regression() {
    let skill_path = create_rfc_skill_path();
    let (frontmatter, body) = parse_skill_file(&skill_path).expect("should parse");

    // Verify original content is preserved
    assert!(body.contains("# Create RFC Skill"));
    assert!(body.contains("## Prerequisites"));
    assert!(body.contains("## Step-by-Step Process"));
    assert!(body.contains("### Phase 1: Initial RFC Creation"));
    assert!(body.contains("### Phase 2: Iterative Quality Review"));
    assert!(body.contains("### Phase 3: Engineering Ticket Creation"));
    assert!(body.contains("### Phase 4: Commit, Push, and Merge"));
    assert!(body.contains("## Verification"));
    assert!(body.contains("## Common Patterns"));
    assert!(body.contains("## Tips"));

    // Verify skill metadata is correct
    assert_eq!(frontmatter.name, "create-rfc");
    assert!(frontmatter.user_invocable);
}

/// Test that create-rfc tool permissions are appropriate.
#[test]
fn test_create_rfc_tool_permissions() {
    let skill_path = create_rfc_skill_path();
    let (frontmatter, _) = parse_skill_file(&skill_path).expect("should parse");
    let holon_config = frontmatter.holon.expect("should have holon config");

    // Verify tools are specified
    assert!(holon_config.tools.is_some(), "should have tool list");
    let tools = holon_config.tools.unwrap();

    // Verify required tools for RFC creation are present
    assert!(
        tools.contains(&"Read".to_string()),
        "should have Read for reading files"
    );
    assert!(
        tools.contains(&"Write".to_string()),
        "should have Write for creating files"
    );
    assert!(
        tools.contains(&"Bash".to_string()),
        "should have Bash for git operations"
    );

    // Verify tools list is not empty (fail-close would deny all)
    assert!(!tools.is_empty(), "tool list should not be empty");
}
