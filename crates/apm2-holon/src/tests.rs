//! Integration tests for the apm2-holon crate.

use crate::prelude::*;
use crate::traits::MockHolon;

/// Test that all public types can be imported from the prelude.
#[test]
fn test_prelude_imports() {
    // These should all compile if the prelude is correct
    let _: fn() -> EpisodeContext = || {
        EpisodeContext::builder()
            .work_id("test")
            .lease_id("test")
            .build()
    };

    let _: EpisodeResult<()> = EpisodeResult::completed(());
    let _: StopCondition = StopCondition::Continue;
    let _: HolonError = HolonError::internal("test");
    let _: Artifact = Artifact::builder().kind("test").work_id("test").build();
}

/// Test a complete holon execution cycle.
#[test]
fn test_complete_execution_cycle() {
    let mut holon = MockHolon::new("test-holon").with_episodes_until_complete(3);

    // 1. Intake
    let result = holon.intake("work request".to_string(), "lease-123");
    assert!(result.is_ok());
    assert!(holon.intake_called);

    // 2. Create initial context
    let mut ctx = EpisodeContext::builder()
        .work_id("work-123")
        .lease_id("lease-123")
        .max_episodes(10)
        .remaining_tokens(1000)
        .goal_spec("Complete the task")
        .build();

    // 3. Execute episodes until done
    let mut episode_count = 0;
    loop {
        // Check stop condition
        let stop = holon.should_stop(&ctx);
        if stop.should_stop() {
            assert!(stop.is_successful());
            break;
        }

        // Execute episode
        let result = holon.execute_episode(&ctx).unwrap();
        episode_count += 1;

        if result.is_completed() {
            break;
        }

        // Update context for next episode
        ctx = ctx.next_episode(100, 1000);
    }

    assert_eq!(episode_count, 3);
    assert_eq!(*holon.state(), 3);
}

/// Test that budget exhaustion stops execution.
#[test]
fn test_budget_exhaustion_stops_execution() {
    let holon = MockHolon::new("test-holon").with_episodes_until_complete(100);

    let ctx = EpisodeContext::builder()
        .work_id("work-123")
        .lease_id("lease-123")
        .remaining_tokens(0)
        .build();

    let stop = holon.should_stop(&ctx);
    assert!(stop.should_stop());
    assert!(stop.is_resource_limit());
}

/// Test episode context progression.
#[test]
fn test_episode_context_progression() {
    let ctx = EpisodeContext::builder()
        .work_id("work-123")
        .lease_id("lease-123")
        .episode_number(1)
        .remaining_tokens(1000)
        .remaining_time_ms(60_000)
        .build();

    assert!(ctx.is_first_episode());
    assert_eq!(ctx.remaining_tokens(), Some(1000));

    let ctx2 = ctx.next_episode(100, 5_000);
    assert!(!ctx2.is_first_episode());
    assert_eq!(ctx2.episode_number(), 2);
    assert_eq!(ctx2.remaining_tokens(), Some(900));
    assert_eq!(ctx2.remaining_time_ms(), Some(55_000));

    let ctx3 = ctx2.next_episode(900, 55_000);
    assert_eq!(ctx3.remaining_tokens(), Some(0));
    assert_eq!(ctx3.remaining_time_ms(), Some(0));
    assert!(ctx3.tokens_exhausted());
    assert!(ctx3.time_exhausted());
}

/// Test episode result construction and inspection.
#[test]
fn test_episode_result_variants() {
    // Completed
    let result: EpisodeResult<i32> = EpisodeResult::completed(42);
    assert!(result.is_completed());
    assert!(result.is_terminal());
    assert_eq!(result.output(), Some(&42));

    // Needs continuation with progress
    let result: EpisodeResult<i32> = EpisodeResult::continue_with_progress("50% done");
    assert!(result.needs_continuation());
    assert!(!result.is_terminal());
    assert_eq!(result.progress_update(), Some("50% done"));

    // Failed
    let result: EpisodeResult<i32> = EpisodeResult::failed();
    assert!(result.is_failed());
    assert!(result.is_terminal());

    // Escalated
    let result: EpisodeResult<i32> = EpisodeResult::escalated();
    assert!(result.is_escalated());
    assert!(result.is_terminal());

    // Interrupted
    let result: EpisodeResult<i32> = EpisodeResult::interrupted();
    assert!(result.is_interrupted());
    assert!(!result.is_terminal());
}

/// Test stop condition classification.
#[test]
fn test_stop_condition_classification() {
    // Successful outcomes
    assert!(StopCondition::GoalSatisfied.is_successful());
    assert!(StopCondition::escalated("reason").is_successful());

    // Resource limits
    assert!(StopCondition::budget_exhausted("tokens").is_resource_limit());
    assert!(StopCondition::max_episodes_reached(10).is_resource_limit());
    assert!(StopCondition::timeout_reached(5000).is_resource_limit());

    // Errors
    assert!(StopCondition::error("failure").is_error());
    assert!(StopCondition::policy_violation("no_unsafe").is_error());

    // Stalls
    assert!(StopCondition::stalled("no progress").is_stalled());

    // Continue doesn't stop
    assert!(!StopCondition::Continue.should_stop());
}

/// Test artifact construction.
#[test]
fn test_artifact_construction() {
    let artifact = Artifact::builder()
        .kind(crate::artifact::kinds::CODE_CHANGE)
        .work_id("work-123")
        .episode_id("ep-456")
        .content("Changed function signature")
        .content_hash("blake3:abc123def456")
        .mime_type("text/x-rust")
        .size_bytes(1024)
        .path("src/lib.rs")
        .metadata("line_start", "10")
        .metadata("line_end", "25")
        .build();

    assert_eq!(artifact.kind(), "code_change");
    assert_eq!(artifact.work_id(), "work-123");
    assert_eq!(artifact.episode_id(), Some("ep-456"));
    assert_eq!(artifact.content(), Some("Changed function signature"));
    assert_eq!(artifact.content_hash(), Some("blake3:abc123def456"));
    assert_eq!(artifact.mime_type(), Some("text/x-rust"));
    assert_eq!(artifact.size_bytes(), Some(1024));
    assert_eq!(artifact.path(), Some("src/lib.rs"));
    assert_eq!(artifact.get_metadata("line_start"), Some("10"));
    assert_eq!(artifact.get_metadata("line_end"), Some("25"));
}

/// Test error construction and classification.
#[test]
fn test_error_classification() {
    // Lease errors
    let err = HolonError::invalid_lease("lease-123", "expired");
    assert!(!err.is_recoverable());
    assert!(err.should_escalate());
    assert_eq!(err.error_class(), crate::error::ErrorClass::Lease);

    // Budget errors
    let err = HolonError::budget_exhausted("tokens", 1000, 500);
    assert!(!err.is_recoverable());
    assert_eq!(err.error_class(), crate::error::ErrorClass::Budget);

    // Validation errors
    let err = HolonError::invalid_input("empty prompt");
    assert!(!err.is_recoverable());
    assert!(!err.should_escalate());
    assert_eq!(err.error_class(), crate::error::ErrorClass::Validation);

    // Execution errors (recoverable)
    let err = HolonError::episode_failed("timeout", true);
    assert!(err.is_recoverable());
    assert!(!err.should_escalate());

    // Execution errors (not recoverable)
    let err = HolonError::episode_failed("critical", false);
    assert!(!err.is_recoverable());
    assert!(err.should_escalate());
}

/// Test that a holon can be used with different input/output types.
#[test]
fn test_holon_generic_types() {
    // The MockHolon uses String for Input/Output and u64 for State
    let mut holon = MockHolon::new("generic-test");

    holon.intake("test input".to_string(), "lease-1").unwrap();

    let ctx = EpisodeContext::builder()
        .work_id("work-1")
        .lease_id("lease-1")
        .build();

    let result = holon.execute_episode(&ctx).unwrap();
    assert!(result.is_completed());

    // Output is String
    let output = result.into_output().unwrap();
    assert!(output.contains("completed"));

    // State is u64
    assert_eq!(*holon.state(), 1);
}
