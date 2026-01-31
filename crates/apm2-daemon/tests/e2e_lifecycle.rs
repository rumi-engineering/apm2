//! End-to-end episode lifecycle tests.
//!
//! This module tests the complete episode lifecycle including:
//! - Create -> Start -> Stop cycle
//! - Concurrent episode management
//! - Episode status queries
//! - Invalid transition rejection
//! - Termination enforcement
//! - Quarantine on failure
//! - Event emission verification
//!
//! # Contract References
//!
//! - TCK-00175: E2E lifecycle and budget tests
//! - REQ-EPISODE-001: Episode envelope requirements
//! - REQ-DAEMON-001: Daemon requirements
//! - AD-EPISODE-002: Episode state machine
//!
//! # Test Coverage
//!
//! | Test ID        | Description                          |
//! |----------------|--------------------------------------|
//! | E2E-00175-01   | Lifecycle E2E                        |
//! | UT-LF-001      | Happy path lifecycle                 |
//! | UT-LF-002      | Concurrent episodes                  |
//! | UT-LF-003      | Status queries                       |
//! | UT-LF-004      | Invalid transitions                  |
//! | UT-LF-005      | Termination enforcement              |
//! | UT-LF-006      | Quarantine on crash                  |
//! | UT-LF-007      | Event emission                       |

mod common;

use apm2_daemon::episode::{
    EpisodeError, EpisodeEvent, EpisodeRuntimeConfig, EpisodeState, QuarantineReason, StopSignal,
    TerminationClass,
};
use common::TestDaemon;

// =============================================================================
// UT-LF-001: Happy Path Lifecycle Tests
// =============================================================================

/// Test the basic create -> start -> stop lifecycle.
#[tokio::test]
async fn test_episode_lifecycle_happy_path() {
    let daemon = TestDaemon::start();

    // Create episode
    let episode_id = daemon.create_episode().await.unwrap();

    // Verify created state
    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(state, EpisodeState::Created { .. }));
    assert!(!state.is_terminal());
    assert!(state.is_active());

    // Start episode
    let handle = daemon.start_episode(&episode_id).await.unwrap();
    assert!(!handle.should_stop());
    assert_eq!(handle.episode_id().as_str(), episode_id.as_str());

    // Verify running state
    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(state, EpisodeState::Running { .. }));
    assert!(state.is_running());

    // Stop episode
    daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await
        .unwrap();

    // Verify terminated state
    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(
        state,
        EpisodeState::Terminated {
            termination_class: TerminationClass::Success,
            ..
        }
    ));
    assert!(state.is_terminal());
}

/// Test lifecycle with failure termination.
#[tokio::test]
async fn test_episode_lifecycle_failure() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    daemon
        .stop_episode(&episode_id, TerminationClass::Failure)
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(
        state,
        EpisodeState::Terminated {
            termination_class: TerminationClass::Failure,
            ..
        }
    ));
}

/// Test lifecycle with cancellation.
#[tokio::test]
async fn test_episode_lifecycle_cancelled() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    daemon
        .stop_episode(&episode_id, TerminationClass::Cancelled)
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(
        state,
        EpisodeState::Terminated {
            termination_class: TerminationClass::Cancelled,
            ..
        }
    ));
}

/// Test lifecycle with timeout.
#[tokio::test]
async fn test_episode_lifecycle_timeout() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    daemon
        .stop_episode(&episode_id, TerminationClass::Timeout)
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(
        state,
        EpisodeState::Terminated {
            termination_class: TerminationClass::Timeout,
            ..
        }
    ));
}

// =============================================================================
// UT-LF-002: Concurrent Episode Tests
// =============================================================================

/// Test concurrent episode creation.
#[tokio::test]
async fn test_concurrent_episode_creation() {
    let daemon = TestDaemon::start();

    // Create multiple episodes
    let ep1 = daemon.create_episode().await.unwrap();
    let ep2 = daemon.create_episode().await.unwrap();
    let ep3 = daemon.create_episode().await.unwrap();

    // All should be created
    assert_eq!(daemon.active_count().await, 3);

    // Verify each is in Created state
    for ep_id in [&ep1, &ep2, &ep3] {
        let state = daemon.observe_episode(ep_id).await.unwrap();
        assert!(matches!(state, EpisodeState::Created { .. }));
    }

    // Start all episodes
    daemon.start_episode(&ep1).await.unwrap();
    daemon.start_episode(&ep2).await.unwrap();
    daemon.start_episode(&ep3).await.unwrap();

    // All should be running
    for ep_id in [&ep1, &ep2, &ep3] {
        let state = daemon.observe_episode(ep_id).await.unwrap();
        assert!(matches!(state, EpisodeState::Running { .. }));
    }

    // Stop all episodes
    daemon
        .stop_episode(&ep1, TerminationClass::Success)
        .await
        .unwrap();
    daemon
        .stop_episode(&ep2, TerminationClass::Failure)
        .await
        .unwrap();
    daemon
        .stop_episode(&ep3, TerminationClass::Cancelled)
        .await
        .unwrap();

    // All should be terminal
    assert_eq!(daemon.active_count().await, 0);
    assert_eq!(daemon.total_count().await, 3);
}

/// Test episode limit enforcement.
#[tokio::test]
async fn test_episode_limit_enforcement() {
    let daemon = TestDaemon::with_max_episodes(3);

    // Create up to limit
    let ep1 = daemon.create_episode().await.unwrap();
    let ep2 = daemon.create_episode().await.unwrap();
    let ep3 = daemon.create_episode().await.unwrap();

    assert_eq!(daemon.total_count().await, 3);

    // Fourth creation should fail
    let result = daemon.create_episode().await;
    assert!(matches!(
        result,
        Err(EpisodeError::LimitReached { limit: 3 })
    ));

    // Stop one episode
    daemon.start_episode(&ep1).await.unwrap();
    daemon
        .stop_episode(&ep1, TerminationClass::Success)
        .await
        .unwrap();

    // Still at limit (terminated episode still tracked)
    let result = daemon.create_episode().await;
    assert!(matches!(result, Err(EpisodeError::LimitReached { .. })));

    // Cleanup terminal episodes
    let cleaned = daemon.cleanup_terminal().await;
    assert_eq!(cleaned, 1);

    // Now we can create again
    let _ep4 = daemon.create_episode().await.unwrap();
    assert_eq!(daemon.total_count().await, 3);

    // Cleanup
    drop(ep2);
    drop(ep3);
}

/// Test concurrent lifecycle operations with async spawn.
#[tokio::test]
async fn test_concurrent_lifecycle_operations() {
    use std::sync::Arc;

    let daemon = Arc::new(TestDaemon::start());

    // Create multiple episodes concurrently
    let mut handles = Vec::new();
    for _ in 0..10 {
        let d = Arc::clone(&daemon);
        handles.push(tokio::spawn(async move {
            let ep_id = d.create_episode().await.unwrap();
            let _handle = d.start_episode(&ep_id).await.unwrap();
            d.stop_episode(&ep_id, TerminationClass::Success)
                .await
                .unwrap();
            ep_id
        }));
    }

    // Wait for all to complete
    let mut episode_ids = std::collections::HashSet::new();
    for handle in handles {
        let ep_id = handle.await.unwrap();
        episode_ids.insert(ep_id.as_str().to_string());
    }

    // All 10 should have unique IDs
    assert_eq!(episode_ids.len(), 10);

    // All should be terminal
    assert_eq!(daemon.active_count().await, 0);
    assert_eq!(daemon.total_count().await, 10);
}

// =============================================================================
// UT-LF-003: Status Query Tests
// =============================================================================

/// Test episode status transitions.
#[tokio::test]
async fn test_episode_status_transitions() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();

    // Created
    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert_eq!(state.state_name(), "Created");
    assert!(!state.is_running());
    assert!(!state.is_terminal());
    assert!(state.is_active());

    // Running
    daemon.start_episode(&episode_id).await.unwrap();
    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert_eq!(state.state_name(), "Running");
    assert!(state.is_running());
    assert!(!state.is_terminal());
    assert!(state.is_active());

    // Terminated
    daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await
        .unwrap();
    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert_eq!(state.state_name(), "Terminated");
    assert!(!state.is_running());
    assert!(state.is_terminal());
    assert!(!state.is_active());
}

/// Test session handle properties.
#[tokio::test]
async fn test_session_handle_properties() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let handle = daemon
        .start_episode_with_lease(&episode_id, "test-lease-123")
        .await
        .unwrap();

    // Verify handle properties
    assert_eq!(handle.episode_id().as_str(), episode_id.as_str());
    assert_eq!(handle.lease_id(), "test-lease-123");
    assert!(!handle.session_id().is_empty());
    assert!(!handle.should_stop());
}

/// Test querying non-existent episode.
#[tokio::test]
async fn test_query_nonexistent_episode() {
    let daemon = TestDaemon::start();

    let fake_id = apm2_daemon::episode::EpisodeId::new("ep-nonexistent").unwrap();
    let result = daemon.observe_episode(&fake_id).await;

    assert!(matches!(result, Err(EpisodeError::NotFound { .. })));
}

// =============================================================================
// UT-LF-004: Invalid Transition Tests
// =============================================================================

/// Test starting an already running episode.
#[tokio::test]
async fn test_invalid_start_already_running() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    // Try to start again
    let result = daemon.start_episode(&episode_id).await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));
}

/// Test starting a terminated episode.
#[tokio::test]
async fn test_invalid_start_terminated() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();
    daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await
        .unwrap();

    // Try to start terminated episode
    let result = daemon.start_episode(&episode_id).await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));
}

/// Test stopping a non-running episode.
#[tokio::test]
async fn test_invalid_stop_not_running() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();

    // Try to stop without starting
    let result = daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));
}

/// Test double stop.
#[tokio::test]
async fn test_invalid_double_stop() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();
    daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await
        .unwrap();

    // Try to stop again
    let result = daemon
        .stop_episode(&episode_id, TerminationClass::Cancelled)
        .await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));
}

/// Test quarantining a created (not running) episode.
#[tokio::test]
async fn test_invalid_quarantine_not_running() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();

    // Try to quarantine without starting
    let result = daemon
        .quarantine_episode(&episode_id, QuarantineReason::crash("test"))
        .await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));
}

/// Test invalid lease ID (empty).
#[tokio::test]
async fn test_invalid_empty_lease_id() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();

    // Try to start with empty lease
    let result = daemon.start_episode_with_lease(&episode_id, "").await;
    assert!(matches!(result, Err(EpisodeError::InvalidLease { .. })));
}

// =============================================================================
// UT-LF-005: Termination Enforcement Tests
// =============================================================================

/// Test graceful stop signal.
#[tokio::test]
async fn test_graceful_stop_signal() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let handle = daemon.start_episode(&episode_id).await.unwrap();

    // Signal graceful stop
    daemon
        .signal_episode(
            &episode_id,
            StopSignal::Graceful {
                reason: "test graceful stop".to_string(),
            },
        )
        .await
        .unwrap();

    // Handle should indicate stop
    assert!(handle.should_stop());
    assert!(matches!(
        handle.current_stop_signal(),
        StopSignal::Graceful { reason } if reason == "test graceful stop"
    ));
}

/// Test immediate stop signal.
#[tokio::test]
async fn test_immediate_stop_signal() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let handle = daemon.start_episode(&episode_id).await.unwrap();

    // Signal immediate stop
    daemon
        .signal_episode(
            &episode_id,
            StopSignal::Immediate {
                reason: "test immediate stop".to_string(),
            },
        )
        .await
        .unwrap();

    assert!(handle.should_stop());
    assert!(matches!(
        handle.current_stop_signal(),
        StopSignal::Immediate { reason } if reason == "test immediate stop"
    ));
}

/// Test external signal (SIGTERM simulation).
#[tokio::test]
async fn test_external_sigterm_signal() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let handle = daemon.start_episode(&episode_id).await.unwrap();

    // Signal SIGTERM
    daemon
        .signal_episode(
            &episode_id,
            StopSignal::External {
                signal: "SIGTERM".to_string(),
            },
        )
        .await
        .unwrap();

    assert!(handle.should_stop());
    let signal = handle.current_stop_signal();
    assert!(matches!(
        signal,
        StopSignal::External { ref signal } if signal == "SIGTERM"
    ));

    // Verify termination class mapping
    assert_eq!(
        signal.termination_class(),
        Some(TerminationClass::Cancelled)
    );
}

/// Test external signal (SIGKILL simulation).
#[tokio::test]
async fn test_external_sigkill_signal() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let handle = daemon.start_episode(&episode_id).await.unwrap();

    // Signal SIGKILL
    daemon
        .signal_episode(
            &episode_id,
            StopSignal::External {
                signal: "SIGKILL".to_string(),
            },
        )
        .await
        .unwrap();

    assert!(handle.should_stop());
    let signal = handle.current_stop_signal();

    // Verify SIGKILL maps to Killed termination
    assert_eq!(signal.termination_class(), Some(TerminationClass::Killed));
}

/// Test signaling a non-running episode fails.
#[tokio::test]
async fn test_signal_nonrunning_episode_fails() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();

    // Try to signal before starting
    let result = daemon
        .signal_episode(
            &episode_id,
            StopSignal::Graceful {
                reason: "test".to_string(),
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));
}

/// Test killed termination class.
#[tokio::test]
async fn test_killed_termination() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    daemon
        .stop_episode(&episode_id, TerminationClass::Killed)
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(
        state,
        EpisodeState::Terminated {
            termination_class: TerminationClass::Killed,
            ..
        }
    ));
}

// =============================================================================
// UT-LF-006: Quarantine Tests
// =============================================================================

/// Test quarantine on crash.
#[tokio::test]
async fn test_quarantine_on_crash() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    let reason = QuarantineReason::crash("simulated crash");
    daemon
        .quarantine_episode(&episode_id, reason.clone())
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(state, EpisodeState::Quarantined { .. }));
    assert!(state.is_terminal());

    if let EpisodeState::Quarantined { reason: r, .. } = state {
        assert_eq!(r.code, "CRASH");
        assert!(r.description.contains("simulated crash"));
    }
}

/// Test quarantine on policy violation.
#[tokio::test]
async fn test_quarantine_on_policy_violation() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    let reason = QuarantineReason::policy_violation("DENY_EXECUTE");
    daemon
        .quarantine_episode(&episode_id, reason)
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(state, EpisodeState::Quarantined { .. }));

    if let EpisodeState::Quarantined { reason: r, .. } = state {
        assert_eq!(r.code, "POLICY_VIOLATION");
        assert!(r.description.contains("DENY_EXECUTE"));
    }
}

/// Test quarantine on security incident.
#[tokio::test]
async fn test_quarantine_on_security_incident() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    let reason = QuarantineReason::security_incident("unauthorized access attempt");
    daemon
        .quarantine_episode(&episode_id, reason)
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    assert!(matches!(state, EpisodeState::Quarantined { .. }));

    if let EpisodeState::Quarantined { reason: r, .. } = state {
        assert_eq!(r.code, "SECURITY_INCIDENT");
    }
}

/// Test quarantine with evidence reference.
#[tokio::test]
async fn test_quarantine_with_evidence() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();

    let evidence_hash = [0xABu8; 32];
    let reason = QuarantineReason::crash("crash with evidence").with_evidence(evidence_hash);
    daemon
        .quarantine_episode(&episode_id, reason)
        .await
        .unwrap();

    let state = daemon.observe_episode(&episode_id).await.unwrap();
    if let EpisodeState::Quarantined { reason: r, .. } = state {
        assert_eq!(r.evidence_refs.len(), 1);
        assert_eq!(r.evidence_refs[0], evidence_hash);
    }
}

/// Test quarantine signal through handle.
#[tokio::test]
async fn test_quarantine_signal() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let handle = daemon.start_episode(&episode_id).await.unwrap();

    // Signal quarantine
    daemon
        .signal_episode(
            &episode_id,
            StopSignal::Quarantine {
                reason: "test quarantine signal".to_string(),
            },
        )
        .await
        .unwrap();

    assert!(handle.should_stop());
    let signal = handle.current_stop_signal();
    assert!(signal.requires_quarantine());
    assert!(
        matches!(signal, StopSignal::Quarantine { reason } if reason == "test quarantine signal")
    );
}

/// Test no further transitions from quarantined state.
#[tokio::test]
async fn test_no_transitions_from_quarantined() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();
    daemon
        .quarantine_episode(&episode_id, QuarantineReason::crash("test"))
        .await
        .unwrap();

    // Cannot start
    let result = daemon.start_episode(&episode_id).await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));

    // Cannot stop
    let result = daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));

    // Cannot quarantine again
    let result = daemon
        .quarantine_episode(&episode_id, QuarantineReason::crash("again"))
        .await;
    assert!(matches!(
        result,
        Err(EpisodeError::InvalidTransition { .. })
    ));
}

// =============================================================================
// UT-LF-007: Event Emission Tests
// =============================================================================

/// Test episode.created event.
#[tokio::test]
async fn test_event_episode_created() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let events = daemon.drain_events().await;

    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], EpisodeEvent::Created { .. }));
    assert_eq!(events[0].event_type(), "episode.created");
    assert_eq!(
        events[0].episode_id().unwrap().as_str(),
        episode_id.as_str()
    );
}

/// Test episode.started event.
#[tokio::test]
async fn test_event_episode_started() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.drain_events().await; // Clear create event

    daemon.start_episode(&episode_id).await.unwrap();
    let events = daemon.drain_events().await;

    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], EpisodeEvent::Started { .. }));
    assert_eq!(events[0].event_type(), "episode.started");
}

/// Test episode.stopped event.
#[tokio::test]
async fn test_event_episode_stopped() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();
    daemon.drain_events().await; // Clear previous events

    daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await
        .unwrap();
    let events = daemon.drain_events().await;

    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], EpisodeEvent::Stopped { .. }));
    assert_eq!(events[0].event_type(), "episode.stopped");
}

/// Test episode.quarantined event.
#[tokio::test]
async fn test_event_episode_quarantined() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();
    daemon.drain_events().await; // Clear previous events

    daemon
        .quarantine_episode(&episode_id, QuarantineReason::crash("test"))
        .await
        .unwrap();
    let events = daemon.drain_events().await;

    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], EpisodeEvent::Quarantined { .. }));
    assert_eq!(events[0].event_type(), "episode.quarantined");
}

/// Test full lifecycle event sequence.
#[tokio::test]
async fn test_full_lifecycle_event_sequence() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();
    daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await
        .unwrap();

    let events = daemon.drain_events().await;

    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_type(), "episode.created");
    assert_eq!(events[1].event_type(), "episode.started");
    assert_eq!(events[2].event_type(), "episode.stopped");

    // All events should reference the same episode
    for event in &events {
        assert_eq!(event.episode_id().unwrap().as_str(), episode_id.as_str());
    }
}

/// Test event emission can be disabled.
#[tokio::test]
async fn test_event_emission_disabled() {
    let config = EpisodeRuntimeConfig::default()
        .with_max_concurrent_episodes(100)
        .with_emit_events(false);
    let daemon = TestDaemon::with_config(config);

    let episode_id = daemon.create_episode().await.unwrap();
    daemon.start_episode(&episode_id).await.unwrap();
    daemon
        .stop_episode(&episode_id, TerminationClass::Success)
        .await
        .unwrap();

    // No events should be emitted
    let events = daemon.drain_events().await;
    assert!(events.is_empty());
}

// =============================================================================
// Additional Edge Cases
// =============================================================================

/// Test cleanup of terminal episodes.
#[tokio::test]
async fn test_cleanup_terminal_episodes() {
    let daemon = TestDaemon::start();

    // Create and terminate some episodes
    let ep1 = daemon.create_episode().await.unwrap();
    let ep2 = daemon.create_episode().await.unwrap();
    let ep3 = daemon.create_episode().await.unwrap();

    daemon.start_episode(&ep1).await.unwrap();
    daemon
        .stop_episode(&ep1, TerminationClass::Success)
        .await
        .unwrap();

    daemon.start_episode(&ep2).await.unwrap();
    daemon
        .quarantine_episode(&ep2, QuarantineReason::crash("test"))
        .await
        .unwrap();

    // ep3 is still in Created state
    assert_eq!(daemon.active_count().await, 1);
    assert_eq!(daemon.total_count().await, 3);

    // Cleanup terminal
    let cleaned = daemon.cleanup_terminal().await;
    assert_eq!(cleaned, 2);

    // Only active episode remains
    assert_eq!(daemon.total_count().await, 1);
    assert_eq!(daemon.active_count().await, 1);

    // ep3 should still be observable
    let state = daemon.observe_episode(&ep3).await.unwrap();
    assert!(matches!(state, EpisodeState::Created { .. }));
}

/// Test session handle cloning shares channel.
#[tokio::test]
async fn test_session_handle_clone_shares_channel() {
    let daemon = TestDaemon::start();

    let episode_id = daemon.create_episode().await.unwrap();
    let handle1 = daemon.start_episode(&episode_id).await.unwrap();
    let handle2 = handle1.clone();

    // Signal through one handle
    handle1.signal_stop(StopSignal::Graceful {
        reason: "clone test".to_string(),
    });

    // Both should see the signal
    assert!(handle1.should_stop());
    assert!(handle2.should_stop());
}

/// Test deterministic timestamp advancement.
#[tokio::test]
async fn test_deterministic_timestamps() {
    let daemon = TestDaemon::start();

    let ep_id = daemon.create_episode().await.unwrap();
    let handle = daemon.start_episode(&ep_id).await.unwrap();

    // Initially elapsed time is 0 (current timestamp equals start timestamp)
    let initial_elapsed = handle.elapsed_ns(daemon.current_timestamp_ns());
    assert_eq!(initial_elapsed, 0);

    // Advance time by 100ms
    daemon.advance_time_ms(100);

    // Verify elapsed time is now 100ms
    let elapsed = handle.elapsed_ns(daemon.current_timestamp_ns());
    assert_eq!(elapsed, 100 * 1_000_000);

    // Advance time by another 500ms
    daemon.advance_time_ms(500);

    let new_elapsed = handle.elapsed_ns(daemon.current_timestamp_ns());
    assert_eq!(new_elapsed, 600 * 1_000_000);
    assert_eq!(new_elapsed - elapsed, 500 * 1_000_000);
}
