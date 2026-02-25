//! End-to-end budget exhaustion tests.
//!
//! This module tests budget enforcement and exhaustion scenarios:
//! - Token budget exhaustion
//! - Tool calls budget exhaustion
//! - Wall time exhaustion
//! - CPU time exhaustion
//! - I/O bytes exhaustion
//! - Evidence bytes exhaustion
//! - Budget exhausted termination class
//! - Stop signal propagation
//!
//! # Contract References
//!
//! - RFC-0033::REQ-0041: E2E lifecycle and budget tests
//! - RFC-0033::REQ-0032: Tool execution and budget charging
//! - CTR-2504: Defensive time handling
//!
//! # Test Coverage
//!
//! | Test ID        | Description                          |
//! |----------------|--------------------------------------|
//! | E2E-00175-02   | Budget exhaustion E2E                |
//! | UT-BG-001      | Token exhaustion                     |
//! | UT-BG-002      | Tool calls exhaustion                |
//! | UT-BG-003      | Wall time exhaustion                 |
//! | UT-BG-004      | CPU time exhaustion                  |
//! | UT-BG-005      | I/O bytes exhaustion                 |
//! | UT-BG-006      | Evidence bytes exhaustion            |
//! | UT-BG-007      | Budget exhausted termination         |
//! | UT-BG-008      | Concurrent budget charging           |

mod common;

use apm2_daemon::episode::{
    BudgetDelta, BudgetExhaustedError, BudgetTracker, EpisodeBudget, StopSignal, TerminationClass,
};
use common::TestDaemon;

// =============================================================================
// UT-BG-001: Token Budget Exhaustion
// =============================================================================

/// Test token budget exhaustion.
#[tokio::test]
async fn test_token_budget_exhaustion() {
    let budget = EpisodeBudget::builder()
        .tokens(1000)
        .tool_calls(100)
        .build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Charge 800 tokens - should succeed
    let delta = BudgetDelta::single_call().with_tokens(800);
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    // Verify remaining
    let remaining = TestDaemon::remaining_budget(&tracker);
    assert_eq!(remaining.tokens(), 200);

    // Charge 300 more tokens - should fail (exceeds remaining)
    let delta = BudgetDelta::single_call().with_tokens(300);
    let result = TestDaemon::charge_budget(&tracker, &delta);

    assert!(matches!(
        result,
        Err(BudgetExhaustedError::Tokens {
            requested: 300,
            remaining: 200
        })
    ));
}

/// Test token budget exactly exhausted.
#[tokio::test]
async fn test_token_budget_exact_exhaustion() {
    let budget = EpisodeBudget::builder().tokens(500).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Charge exactly the limit
    let delta = BudgetDelta::single_call().with_tokens(500);
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    assert!(tracker.is_tokens_exhausted());
    assert!(tracker.is_exhausted());

    // Any further charge should fail
    let delta = BudgetDelta::single_call().with_tokens(1);
    let result = TestDaemon::charge_budget(&tracker, &delta);
    assert!(matches!(result, Err(BudgetExhaustedError::Tokens { .. })));
}

/// Test token budget with multiple small charges.
#[tokio::test]
async fn test_token_budget_incremental_exhaustion() {
    let budget = EpisodeBudget::builder().tokens(100).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Charge 10 tokens 10 times
    for _ in 0..10 {
        let delta = BudgetDelta::single_call().with_tokens(10);
        TestDaemon::charge_budget(&tracker, &delta).unwrap();
    }

    assert!(tracker.is_tokens_exhausted());

    // 11th charge should fail
    let delta = BudgetDelta::single_call().with_tokens(10);
    let result = TestDaemon::charge_budget(&tracker, &delta);
    assert!(matches!(result, Err(BudgetExhaustedError::Tokens { .. })));
}

// =============================================================================
// UT-BG-002: Tool Calls Budget Exhaustion
// =============================================================================

/// Test tool calls budget exhaustion.
#[tokio::test]
async fn test_tool_calls_budget_exhaustion() {
    let budget = EpisodeBudget::builder().tool_calls(5).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Make 5 tool calls
    for _ in 0..5 {
        let delta = BudgetDelta::single_call();
        TestDaemon::charge_budget(&tracker, &delta).unwrap();
    }

    assert!(tracker.is_tool_calls_exhausted());
    assert!(tracker.is_exhausted());

    // 6th call should fail
    let delta = BudgetDelta::single_call();
    let result = TestDaemon::charge_budget(&tracker, &delta);
    assert!(matches!(
        result,
        Err(BudgetExhaustedError::ToolCalls {
            requested: 1,
            remaining: 0
        })
    ));
}

/// Test tool calls budget with batch calls.
#[tokio::test]
async fn test_tool_calls_batch_exhaustion() {
    let budget = EpisodeBudget::builder().tool_calls(10).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Batch of 3 calls
    let delta = BudgetDelta {
        tool_calls: 3,
        ..Default::default()
    };
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    // Batch of 5 calls
    let delta = BudgetDelta {
        tool_calls: 5,
        ..Default::default()
    };
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    // Batch of 3 should fail (only 2 remaining)
    let delta = BudgetDelta {
        tool_calls: 3,
        ..Default::default()
    };
    let result = TestDaemon::charge_budget(&tracker, &delta);
    assert!(matches!(
        result,
        Err(BudgetExhaustedError::ToolCalls {
            requested: 3,
            remaining: 2
        })
    ));
}

// =============================================================================
// UT-BG-003: Wall Time Exhaustion
// =============================================================================

/// Test wall time budget exhaustion.
#[tokio::test]
async fn test_wall_time_budget_exhaustion() {
    let budget = EpisodeBudget::builder().wall_ms(60_000).build(); // 1 minute
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Charge 50 seconds
    let delta = BudgetDelta::single_call().with_wall_ms(50_000);
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    // Charge 15 more seconds - should fail
    let delta = BudgetDelta::single_call().with_wall_ms(15_000);
    let result = TestDaemon::charge_budget(&tracker, &delta);

    assert!(matches!(
        result,
        Err(BudgetExhaustedError::WallTime {
            requested: 15_000,
            remaining: 10_000
        })
    ));
}

/// Test wall time exact exhaustion.
#[tokio::test]
async fn test_wall_time_exact_exhaustion() {
    let budget = EpisodeBudget::builder().wall_ms(1000).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Charge exactly 1000ms
    let delta = BudgetDelta::single_call().with_wall_ms(1000);
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    assert!(tracker.is_wall_time_exhausted());
    assert!(tracker.is_exhausted());
}

// =============================================================================
// UT-BG-004: CPU Time Exhaustion
// =============================================================================

/// Test CPU time budget exhaustion.
#[tokio::test]
async fn test_cpu_time_budget_exhaustion() {
    let budget = EpisodeBudget::builder().cpu_ms(30_000).build(); // 30 seconds
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Charge 25 seconds
    let delta = BudgetDelta {
        cpu_ms: 25_000,
        tool_calls: 1,
        ..Default::default()
    };
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    // Charge 10 more seconds - should fail
    let delta = BudgetDelta {
        cpu_ms: 10_000,
        tool_calls: 1,
        ..Default::default()
    };
    let result = TestDaemon::charge_budget(&tracker, &delta);

    assert!(matches!(
        result,
        Err(BudgetExhaustedError::CpuTime {
            requested: 10_000,
            remaining: 5_000
        })
    ));
}

/// Test CPU time is tracked separately from wall time.
#[tokio::test]
async fn test_cpu_time_separate_from_wall_time() {
    let budget = EpisodeBudget::builder()
        .wall_ms(100_000)
        .cpu_ms(10_000)
        .build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // CPU-intensive operation: 9s CPU in 20s wall time
    let delta = BudgetDelta {
        wall_ms: 20_000,
        cpu_ms: 9_000,
        tool_calls: 1,
        ..Default::default()
    };
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    // Wall time not exhausted, but CPU time nearly is
    assert!(!tracker.is_wall_time_exhausted());
    assert!(!tracker.is_cpu_time_exhausted());

    // Another CPU-heavy operation
    let delta = BudgetDelta {
        wall_ms: 5_000,
        cpu_ms: 2_000, // Exceeds CPU limit
        tool_calls: 1,
        ..Default::default()
    };
    let result = TestDaemon::charge_budget(&tracker, &delta);
    assert!(matches!(result, Err(BudgetExhaustedError::CpuTime { .. })));
}

// =============================================================================
// UT-BG-005: I/O Bytes Exhaustion
// =============================================================================

/// Test I/O bytes budget exhaustion.
#[tokio::test]
async fn test_io_bytes_budget_exhaustion() {
    let budget = EpisodeBudget::builder().bytes_io(1_000_000).build(); // 1 MB
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Read/write 800 KB
    let delta = BudgetDelta::single_call().with_bytes_io(800_000);
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    // Try to read/write 300 KB more - should fail
    let delta = BudgetDelta::single_call().with_bytes_io(300_000);
    let result = TestDaemon::charge_budget(&tracker, &delta);

    assert!(matches!(
        result,
        Err(BudgetExhaustedError::BytesIo {
            requested: 300_000,
            remaining: 200_000
        })
    ));
}

/// Test I/O bytes with combined read/write operations.
#[tokio::test]
async fn test_io_bytes_combined_operations() {
    let budget = EpisodeBudget::builder().bytes_io(100_000).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Multiple I/O operations
    for _ in 0..9 {
        let delta = BudgetDelta::single_call().with_bytes_io(10_000);
        TestDaemon::charge_budget(&tracker, &delta).unwrap();
    }

    // 10th operation with 15KB should fail
    let delta = BudgetDelta::single_call().with_bytes_io(15_000);
    let result = TestDaemon::charge_budget(&tracker, &delta);
    assert!(matches!(result, Err(BudgetExhaustedError::BytesIo { .. })));
}

// =============================================================================
// UT-BG-006: Evidence Bytes Exhaustion
// =============================================================================

/// Test evidence bytes budget exhaustion.
#[tokio::test]
async fn test_evidence_bytes_budget_exhaustion() {
    let budget = EpisodeBudget::builder().evidence_bytes(100_000).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Store 50 KB of evidence
    tracker.charge_evidence(50_000).unwrap();

    // Store 60 KB more - should fail
    let result = tracker.charge_evidence(60_000);

    assert!(matches!(
        result,
        Err(BudgetExhaustedError::EvidenceBytes {
            requested: 60_000,
            remaining: 50_000
        })
    ));
}

/// Test evidence bytes exact exhaustion.
#[tokio::test]
async fn test_evidence_bytes_exact_exhaustion() {
    let budget = EpisodeBudget::builder().evidence_bytes(10_000).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Exactly exhaust
    tracker.charge_evidence(10_000).unwrap();

    assert!(tracker.is_evidence_bytes_exhausted());

    // Any more should fail
    let result = tracker.charge_evidence(1);
    assert!(matches!(
        result,
        Err(BudgetExhaustedError::EvidenceBytes { .. })
    ));
}

// =============================================================================
// UT-BG-007: Budget Exhausted Termination
// =============================================================================

/// Test budget exhausted stop signal.
#[tokio::test]
async fn test_budget_exhausted_stop_signal() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let handle = daemon.start_episode(&episode_id).await.unwrap();

    // Signal budget exhausted
    daemon
        .signal_episode(
            &episode_id,
            StopSignal::BudgetExhausted {
                resource: "tokens".to_string(),
            },
        )
        .await
        .unwrap();

    assert!(handle.should_stop());
    let signal = handle.current_stop_signal();
    assert!(matches!(
        signal,
        StopSignal::BudgetExhausted { ref resource } if resource == "tokens"
    ));

    // Verify termination class mapping
    assert_eq!(
        signal.termination_class(),
        Some(TerminationClass::BudgetExhausted)
    );
}

/// Test budget exhausted termination class.
#[tokio::test]
async fn test_budget_exhausted_termination_class() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    daemon
        .stop_episode(&episode_id, TerminationClass::BudgetExhausted)
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(
        state,
        apm2_daemon::episode::EpisodeState::Terminated {
            termination_class: TerminationClass::BudgetExhausted,
            ..
        }
    ));
}

/// Test budget exhausted event in lifecycle.
#[tokio::test]
async fn test_budget_exhausted_lifecycle() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();
    daemon.drain_events().await; // Clear previous events

    daemon
        .stop_episode(&episode_id, TerminationClass::BudgetExhausted)
        .await
        .unwrap();

    let events = daemon.drain_events().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type(), "episode.stopped");

    // Verify the stopped event has BudgetExhausted
    if let apm2_daemon::episode::EpisodeEvent::Stopped {
        termination_class, ..
    } = &events[0]
    {
        assert_eq!(*termination_class, TerminationClass::BudgetExhausted);
    } else {
        panic!("Expected Stopped event");
    }
}

// =============================================================================
// UT-BG-008: Concurrent Budget Charging
// =============================================================================

/// Test concurrent budget charging respects limits.
#[tokio::test]
async fn test_concurrent_budget_charging_respects_limits() {
    use std::sync::Arc;

    let budget = EpisodeBudget::builder().tool_calls(100).build();
    let tracker = Arc::new(BudgetTracker::from_envelope(budget));

    // Spawn 20 threads each trying to charge 10 tool calls
    let mut handles = Vec::new();
    for _ in 0..20 {
        let tracker_clone = Arc::clone(&tracker);
        let handle = tokio::spawn(async move {
            let mut successes = 0;
            for _ in 0..10 {
                if tracker_clone.charge(&BudgetDelta::single_call()).is_ok() {
                    successes += 1;
                }
            }
            successes
        });
        handles.push(handle);
    }

    // Collect results
    let total_successes: u32 = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .sum();

    // Total successes should be exactly 100 (the limit)
    assert_eq!(
        total_successes, 100,
        "Expected exactly 100 successful charges, got {total_successes}"
    );

    // Verify consumed equals limit
    let consumed = tracker.consumed();
    assert_eq!(consumed.tool_calls, 100);
}

/// Test concurrent token charging.
#[tokio::test]
async fn test_concurrent_token_charging() {
    use std::sync::Arc;

    let budget = EpisodeBudget::builder().tokens(10_000).build();
    let tracker = Arc::new(BudgetTracker::from_envelope(budget));

    // Spawn 10 threads each charging 100 tokens 10 times
    let mut handles = Vec::new();
    for _ in 0..10 {
        let tracker_clone = Arc::clone(&tracker);
        let handle = tokio::spawn(async move {
            for _ in 0..10 {
                let _ = tracker_clone.charge(&BudgetDelta::single_call().with_tokens(100));
            }
        });
        handles.push(handle);
    }

    // Wait for all
    futures::future::join_all(handles).await;

    // Consumed should not exceed limit
    let consumed = tracker.consumed();
    assert!(
        consumed.tokens <= 10_000,
        "Consumed {} tokens but limit is 10_000",
        consumed.tokens
    );
}

// =============================================================================
// Unlimited Budget Tests
// =============================================================================

/// Test unlimited budget allows large charges.
#[tokio::test]
async fn test_unlimited_budget() {
    let tracker = BudgetTracker::unlimited();

    // Very large charges should succeed
    let delta = BudgetDelta::single_call()
        .with_tokens(1_000_000_000)
        .with_bytes_io(1_000_000_000);
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    assert!(!TestDaemon::is_budget_exhausted(&tracker));
}

/// Test unlimited budget remaining returns zero (not MAX).
#[tokio::test]
async fn test_unlimited_budget_remaining_is_zero() {
    let tracker = BudgetTracker::unlimited();

    let remaining = tracker.remaining();

    // For unlimited, remaining is 0 (not u64::MAX)
    assert_eq!(remaining.tokens(), 0);
    assert_eq!(remaining.tool_calls(), 0);
    assert_eq!(remaining.wall_ms(), 0);
    assert!(remaining.is_unlimited());
}

// =============================================================================
// Budget Reconciliation Tests
// =============================================================================

/// Test budget reconciliation refunds excess pre-charge.
#[tokio::test]
async fn test_budget_reconciliation_refund() {
    let tracker = TestDaemon::create_test_budget_tracker();

    // Pre-charge an estimate
    let estimate = BudgetDelta::single_call()
        .with_tokens(1000)
        .with_bytes_io(5000);
    TestDaemon::charge_budget(&tracker, &estimate).unwrap();

    // Actual usage was less
    let actual = BudgetDelta::single_call()
        .with_tokens(600)
        .with_bytes_io(3000);

    // Reconcile should succeed
    tracker.reconcile(&estimate, &actual).unwrap();

    // Verify refund was applied
    let consumed = TestDaemon::consumed_budget(&tracker);
    assert_eq!(consumed.tokens, 600);
    assert_eq!(consumed.bytes_io, 3000);
}

/// Test budget reconciliation fails when actual exceeds estimate.
#[tokio::test]
async fn test_budget_reconciliation_actual_exceeds_estimate() {
    let tracker = TestDaemon::create_test_budget_tracker();

    // Pre-charge an estimate
    let estimate = BudgetDelta::single_call().with_tokens(500);
    TestDaemon::charge_budget(&tracker, &estimate).unwrap();

    // Actual usage exceeded estimate
    let actual = BudgetDelta::single_call().with_tokens(700);

    // Reconcile should fail
    let result = tracker.reconcile(&estimate, &actual);
    assert!(matches!(
        result,
        Err(BudgetExhaustedError::ActualExceededEstimate {
            resource: "tokens",
            ..
        })
    ));

    // Budget should remain at the charged amount
    let consumed = TestDaemon::consumed_budget(&tracker);
    assert_eq!(consumed.tokens, 500);
}

// =============================================================================
// Edge Cases
// =============================================================================

/// Test zero charge is allowed.
#[tokio::test]
async fn test_zero_charge_allowed() {
    let tracker = TestDaemon::create_test_budget_tracker();

    let delta = BudgetDelta::default();
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    let consumed = TestDaemon::consumed_budget(&tracker);
    assert!(consumed.tokens == 0);
    assert!(consumed.tool_calls == 0);
}

/// Test checking exhaustion status of individual resources.
#[tokio::test]
async fn test_individual_resource_exhaustion_status() {
    let budget = EpisodeBudget::builder()
        .tokens(100)
        .tool_calls(5)
        .wall_ms(1000)
        .cpu_ms(500)
        .bytes_io(10_000)
        .evidence_bytes(5000)
        .build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Exhaust tokens only
    tracker
        .charge(&BudgetDelta::default().with_tokens(100))
        .unwrap();

    assert!(tracker.is_tokens_exhausted());
    assert!(!tracker.is_tool_calls_exhausted());
    assert!(!tracker.is_wall_time_exhausted());
    assert!(!tracker.is_cpu_time_exhausted());
    assert!(!tracker.is_bytes_io_exhausted());
    assert!(!tracker.is_evidence_bytes_exhausted());

    // Overall is exhausted because tokens are
    assert!(tracker.is_exhausted());
}

/// Test budget limits are immutable.
#[tokio::test]
async fn test_budget_limits_immutable() {
    let budget = EpisodeBudget::builder().tokens(1000).tool_calls(50).build();
    let tracker = TestDaemon::create_budget_tracker(budget);

    // Charge some resources
    let delta = BudgetDelta::single_call().with_tokens(500);
    TestDaemon::charge_budget(&tracker, &delta).unwrap();

    // Limits should remain unchanged
    let limits = tracker.limits();
    assert_eq!(limits.tokens(), 1000);
    assert_eq!(limits.tool_calls(), 50);
}

/// Test `would_exceed` predicate on `BudgetDelta`.
#[tokio::test]
async fn test_budget_delta_would_exceed() {
    let remaining = EpisodeBudget::builder().tokens(100).tool_calls(5).build();

    let delta1 = BudgetDelta::single_call().with_tokens(50);
    assert!(!delta1.would_exceed(&remaining));

    let delta2 = BudgetDelta::single_call().with_tokens(150);
    assert!(delta2.would_exceed(&remaining));

    let delta3 = BudgetDelta {
        tool_calls: 6,
        ..Default::default()
    };
    assert!(delta3.would_exceed(&remaining));

    // Unlimited budget
    let unlimited = EpisodeBudget::unlimited();
    let large_delta = BudgetDelta::single_call().with_tokens(1_000_000);
    assert!(!large_delta.would_exceed(&unlimited));
}
