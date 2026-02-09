//! Integration tests for episode event persistence (TCK-00321).
//!
//! Verifies that:
//! - Episode events are streamed directly to ledger when emitter is configured
//! - Receipt events are emitted atomically at episode completion
//! - CAS-before-event ordering is maintained
//! - Events survive daemon restart (ledger-backed durability)

// TCK-00336: This test uses deprecated methods for backward compatibility
#![allow(deprecated)]

use std::sync::Arc;

use apm2_daemon::episode::{
    EpisodeEvent, EpisodeRuntime, EpisodeRuntimeConfig, EpisodeState, Hash, TerminationClass,
};
use apm2_daemon::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};

/// Test helper to create a test envelope hash.
const fn test_envelope_hash() -> Hash {
    [42u8; 32]
}

/// Test helper to create a test timestamp.
const fn test_timestamp() -> u64 {
    1_704_067_200_000_000_000 // 2024-01-01 00:00:00 UTC in nanoseconds
}

/// Tests that episode events are streamed to ledger when emitter is configured.
#[tokio::test]
async fn test_episode_event_streams_to_ledger() {
    // Create a stub ledger emitter
    let emitter = Arc::new(StubLedgerEventEmitter::new());

    // Create runtime with ledger emitter
    let runtime = EpisodeRuntime::new(
        EpisodeRuntimeConfig::default()
            .with_max_concurrent_episodes(100)
            .with_emit_events(true),
    )
    .with_ledger_emitter(emitter.clone());

    // Create an episode
    let episode_id = runtime
        .create(test_envelope_hash(), test_timestamp())
        .await
        .unwrap();

    // Verify the event was streamed to ledger
    let events = emitter.get_events_by_work_id(episode_id.as_str());
    assert_eq!(events.len(), 1, "episode.created event should be in ledger");
    assert_eq!(events[0].event_type, "episode.created");

    // Also verify it's in the local buffer
    let buffered: Vec<EpisodeEvent> = runtime.drain_events().await;
    assert_eq!(buffered.len(), 1, "event should also be in local buffer");
    assert!(matches!(buffered[0], EpisodeEvent::Created { .. }));
}

/// Tests that episode lifecycle events (created, started, stopped) all stream
/// to ledger.
#[tokio::test]
async fn test_episode_lifecycle_events_stream_to_ledger() {
    let emitter = Arc::new(StubLedgerEventEmitter::new());

    let runtime = EpisodeRuntime::new(
        EpisodeRuntimeConfig::default()
            .with_max_concurrent_episodes(100)
            .with_emit_events(true),
    )
    .with_ledger_emitter(emitter.clone());

    // Create episode
    let episode_id = runtime
        .create(test_envelope_hash(), test_timestamp())
        .await
        .unwrap();

    // Start episode
    let _handle = runtime
        .start(&episode_id, "lease-123", test_timestamp() + 1000)
        .await
        .unwrap();

    // Stop episode
    runtime
        .stop(
            &episode_id,
            TerminationClass::Success,
            test_timestamp() + 2000,
        )
        .await
        .unwrap();

    // Verify all events are in ledger
    let events = emitter.get_events_by_work_id(episode_id.as_str());
    assert_eq!(events.len(), 3, "all lifecycle events should be in ledger");

    let event_types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(event_types.contains(&"episode.created"));
    assert!(event_types.contains(&"episode.started"));
    assert!(event_types.contains(&"episode.stopped"));
}

/// Tests that events are buffered locally even when ledger emitter is
/// configured. This ensures backward compatibility with `drain_events()`.
#[tokio::test]
async fn test_events_buffered_with_ledger_emitter() {
    let emitter = Arc::new(StubLedgerEventEmitter::new());

    let runtime = EpisodeRuntime::new(
        EpisodeRuntimeConfig::default()
            .with_max_concurrent_episodes(100)
            .with_emit_events(true),
    )
    .with_ledger_emitter(emitter.clone());

    // Create episode
    let _episode_id = runtime
        .create(test_envelope_hash(), test_timestamp())
        .await
        .unwrap();

    // Verify events are in both ledger and local buffer
    let buffered: Vec<EpisodeEvent> = runtime.drain_events().await;
    assert_eq!(buffered.len(), 1, "event should be in local buffer");

    // Drain again should be empty
    let buffered2: Vec<EpisodeEvent> = runtime.drain_events().await;
    assert_eq!(buffered2.len(), 0, "buffer should be drained");
}

/// Tests `emit_review_receipt` method for atomic receipt emission.
#[tokio::test]
async fn test_atomic_receipt_emission() {
    let emitter = Arc::new(StubLedgerEventEmitter::new());

    // Emit a review receipt
    let episode_id = "ep-test-123";
    let receipt_id = "rcpt-456";
    let changeset_digest = [0x42u8; 32];
    let artifact_bundle_hash = [0x43u8; 32];
    let reviewer_actor_id = "reviewer-agent";
    let timestamp_ns = test_timestamp();

    let identity_proof_hash = [0x99u8; 32];
    let signed_event = emitter
        .emit_review_receipt(
            episode_id,
            receipt_id,
            &changeset_digest,
            &artifact_bundle_hash,
            reviewer_actor_id,
            timestamp_ns,
            &identity_proof_hash,
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();

    // Verify the receipt event was persisted
    assert_eq!(signed_event.event_type, "review_receipt_recorded");
    assert_eq!(signed_event.work_id, episode_id);
    assert_eq!(signed_event.actor_id, reviewer_actor_id);

    // Verify it can be queried
    let events = emitter.get_events_by_work_id(episode_id);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "review_receipt_recorded");

    // Verify the receipt_id is in the payload
    let payload: serde_json::Value = serde_json::from_slice(&events[0].payload).unwrap();
    assert_eq!(payload["receipt_id"], receipt_id);

    // SECURITY: Verify timestamp_ns is included in signed payload (LAW-09, RS-40)
    // This prevents temporal malleability attacks
    assert_eq!(
        payload["timestamp_ns"].as_u64().unwrap(),
        timestamp_ns,
        "timestamp_ns must be included in signed payload for temporal binding"
    );
}

/// Tests `emit_episode_event` method for episode event streaming.
#[tokio::test]
async fn test_emit_episode_event() {
    let emitter = Arc::new(StubLedgerEventEmitter::new());

    let episode_id = "ep-test-789";
    let event_type = "episode.created";
    let payload = serde_json::json!({
        "episode_id": episode_id,
        "envelope_hash": "0x424242",
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp_ns = test_timestamp();

    let signed_event = emitter
        .emit_episode_event(episode_id, event_type, &payload_bytes, timestamp_ns)
        .unwrap();

    // Verify event was persisted
    assert_eq!(signed_event.event_type, event_type);
    assert_eq!(signed_event.work_id, episode_id);
    assert_eq!(signed_event.actor_id, "daemon");

    // Verify it can be queried
    let events = emitter.get_events_by_work_id(episode_id);
    assert_eq!(events.len(), 1);

    // SECURITY: Verify timestamp_ns is included in signed payload (LAW-09, RS-40)
    let payload: serde_json::Value = serde_json::from_slice(&events[0].payload).unwrap();
    assert_eq!(
        payload["timestamp_ns"].as_u64().unwrap(),
        timestamp_ns,
        "timestamp_ns must be included in signed payload for temporal binding"
    );
}

/// Tests that runtime works without ledger emitter (backward compatibility).
#[tokio::test]
async fn test_runtime_without_ledger_emitter() {
    // Create runtime WITHOUT ledger emitter
    let runtime = EpisodeRuntime::new(
        EpisodeRuntimeConfig::default()
            .with_max_concurrent_episodes(100)
            .with_emit_events(true),
    );

    // Verify ledger_emitter is None
    assert!(runtime.ledger_emitter().is_none());

    // Create episode
    let episode_id = runtime
        .create(test_envelope_hash(), test_timestamp())
        .await
        .unwrap();

    // Events should still be buffered locally
    let buffered: Vec<EpisodeEvent> = runtime.drain_events().await;
    assert_eq!(buffered.len(), 1);
    assert!(matches!(buffered[0], EpisodeEvent::Created { .. }));

    // Verify episode was created
    let state: EpisodeState = runtime.observe(&episode_id).await.unwrap();
    assert!(matches!(state, EpisodeState::Created { .. }));
}

/// Tests that events survive simulated restart (ledger-backed durability).
///
/// This test verifies that events persisted to the ledger can be queried
/// after the runtime is dropped, simulating a daemon restart.
#[tokio::test]
async fn test_events_survive_restart_simulation() {
    let emitter = Arc::new(StubLedgerEventEmitter::new());
    let episode_id: String;

    // Scope 1: Create runtime, emit events, drop runtime
    {
        let runtime = EpisodeRuntime::new(
            EpisodeRuntimeConfig::default()
                .with_max_concurrent_episodes(100)
                .with_emit_events(true),
        )
        .with_ledger_emitter(emitter.clone());

        let id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        episode_id = id.as_str().to_string();

        // Runtime drops here
    }

    // Scope 2: Query ledger after "restart"
    // In a real scenario, this would be a new process with a fresh runtime
    // but the same SQLite database.
    let events = emitter.get_events_by_work_id(&episode_id);
    assert_eq!(
        events.len(),
        1,
        "events should survive runtime drop (simulated restart)"
    );
    assert_eq!(events[0].event_type, "episode.created");
}
