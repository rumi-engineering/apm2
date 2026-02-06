//! TCK-00290: Session dispatcher viability - `RequestTool` execution + real
//! `EmitEvent`/`PublishEvidence`
//!
//! This test module verifies the session dispatcher's viability with:
//! - `RequestTool` execution via manifest validation (no stub Allow path)
//! - `EmitEvent` persistence to ledger (no stub response)
//! - `PublishEvidence` storage in CAS (real hashes)
//! - `StreamTelemetry` fail-closed (`SESSION_ERROR_NOT_IMPLEMENTED`)
//!
//! # Verification Commands
//!
//! - IT-00290-01: `cargo test -p apm2-daemon session_request_tool_exec`
//! - IT-00290-02: `cargo test -p apm2-daemon session_event_evidence_persist`
//!
//! # Security Properties
//!
//! Per RFC-0018 and SEC-CTRL-FAC-0015:
//! - All handlers are fail-closed (no stub responses)
//! - Manifest store, ledger, and CAS must be configured for success
//! - Missing configuration returns appropriate error codes

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use apm2_daemon::cas::{DurableCas, DurableCasConfig};
use apm2_daemon::episode::executor::ContentAddressedStore;
use apm2_daemon::episode::{
    Capability, CapabilityManifestBuilder, CapabilityScope, RiskTier, ToolClass,
};
use apm2_daemon::htf::{ClockConfig, HolonicClock};
use apm2_daemon::protocol::LedgerEventEmitter;
use apm2_daemon::protocol::credentials::PeerCredentials;
use apm2_daemon::protocol::dispatch::{ConnectionContext, StubLedgerEventEmitter};
use apm2_daemon::protocol::messages::{
    EmitEventRequest, EvidenceKind, PublishEvidenceRequest, RequestToolRequest, RetentionHint,
    SessionErrorCode, StreamTelemetryRequest, TelemetryFrame,
};
use apm2_daemon::protocol::session_dispatch::{
    InMemoryManifestStore, SessionDispatcher, SessionResponse, encode_emit_event_request,
    encode_publish_evidence_request, encode_request_tool_request, encode_stream_telemetry_request,
};
use apm2_daemon::protocol::session_token::TokenMinter;
use secrecy::SecretString;
use tempfile::TempDir;

// =============================================================================
// Test Helpers
// =============================================================================

fn test_minter() -> TokenMinter {
    TokenMinter::new(SecretString::from("test-daemon-secret-key-32bytes!!"))
}

fn test_token(minter: &TokenMinter) -> apm2_daemon::protocol::session_token::SessionToken {
    let spawn_time = SystemTime::now();
    let ttl = Duration::from_secs(3600);
    minter
        .mint("session-001", "lease-001", spawn_time, ttl)
        .unwrap()
}

fn make_session_ctx() -> ConnectionContext {
    ConnectionContext::session(
        Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12346),
        }),
        Some("session-001".to_string()),
    )
}

/// Creates a test clock for session dispatcher tests.
///
/// Per TCK-00290 MAJOR 2 FIX, the session dispatcher now fails-closed when
/// no clock is configured. Tests that use `EmitEvent` must configure a clock.
fn test_clock() -> Arc<HolonicClock> {
    Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("failed to create test clock"))
}

fn make_test_manifest(tools: Vec<ToolClass>) -> apm2_daemon::episode::CapabilityManifest {
    let caps: Vec<Capability> = tools
        .iter()
        .map(|tc| Capability {
            capability_id: format!("cap-{tc}"),
            tool_class: *tc,
            scope: CapabilityScope::default(),
            risk_tier_required: RiskTier::Tier0,
        })
        .collect();

    CapabilityManifestBuilder::new("test-manifest")
        .delegator("test-delegator")
        .capabilities(caps)
        .tool_allowlist(tools)
        .build()
        .expect("manifest build failed")
}

// =============================================================================
// IT-00290-01: RequestTool execution tests
// Verification: cargo test -p apm2-daemon session_request_tool_exec
// =============================================================================

/// Verify `RequestTool` with configured manifest store returns fail-closed
/// error when tool broker is unavailable.
///
/// TCK-00335: Legacy manifest store validation removed; tool broker required.
#[test]
fn session_request_tool_exec_allow_with_manifest() {
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());

    // Register manifest with Read allowed
    let manifest = make_test_manifest(vec![ToolClass::Read, ToolClass::Write]);
    store.register("session-001", manifest);

    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let request = RequestToolRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        tool_id: "read".to_string(),
        arguments: vec![1, 2, 3],
        dedupe_key: "key-001".to_string(),
    };
    let frame = encode_request_tool_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorToolNotAllowed as i32,
                "Expected TOOL_NOT_ALLOWED error code (fail-closed)"
            );
            assert!(
                err.message.contains("broker unavailable"),
                "Error message should indicate broker unavailable: {}",
                err.message
            );
        },
        _ => panic!("Expected Error response, got: {response:?}"),
    }
}

/// Verify `RequestTool` returns fail-closed error when tool broker unavailable.
///
/// TCK-00335: Legacy manifest store validation removed; tool broker required.
#[test]
fn session_request_tool_exec_deny_not_in_allowlist() {
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());

    // Register manifest with only Read allowed (no Execute)
    let manifest = make_test_manifest(vec![ToolClass::Read]);
    store.register("session-001", manifest);

    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let request = RequestToolRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        tool_id: "execute".to_string(), // Not in allowlist
        arguments: vec![],
        dedupe_key: "key-002".to_string(),
    };
    let frame = encode_request_tool_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorToolNotAllowed as i32,
                "Expected TOOL_NOT_ALLOWED error code (fail-closed)"
            );
            assert!(
                err.message.contains("broker unavailable"),
                "Error message should indicate broker unavailable: {}",
                err.message
            );
        },
        _ => panic!("Expected Error response, got: {response:?}"),
    }
}

/// Verify `RequestTool` denies when session has no manifest (fail-closed).
#[test]
fn session_request_tool_exec_deny_no_manifest_for_session() {
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());

    // Don't register a manifest for session-001 (empty store)
    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let request = RequestToolRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        tool_id: "read".to_string(),
        arguments: vec![],
        dedupe_key: "key-003".to_string(),
    };
    let frame = encode_request_tool_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorToolNotAllowed as i32,
                "Should be TOOL_NOT_ALLOWED for missing manifest"
            );
            assert!(
                err.message.contains("unavailable") || err.message.contains("fail-closed"),
                "Error should mention unavailable or fail-closed: {}",
                err.message
            );
        },
        _ => panic!("Expected error response, got: {response:?}"),
    }
}

/// Verify `RequestTool` with no manifest store configured returns fail-closed
/// error.
#[test]
fn session_request_tool_exec_deny_no_store_configured() {
    let minter = test_minter();
    let dispatcher = SessionDispatcher::new(minter.clone());
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let request = RequestToolRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        tool_id: "read".to_string(),
        arguments: vec![],
        dedupe_key: "key-004".to_string(),
    };
    let frame = encode_request_tool_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorToolNotAllowed as i32,
                "Should be TOOL_NOT_ALLOWED for unconfigured store"
            );
            assert!(
                err.message.contains("fail-closed"),
                "Error should mention fail-closed: {}",
                err.message
            );
        },
        _ => panic!("Expected error response, got: {response:?}"),
    }
}

// =============================================================================
// IT-00290-02: EmitEvent and PublishEvidence persistence tests
// Verification: cargo test -p apm2-daemon session_event_evidence_persist
// =============================================================================

/// Verify `EmitEvent` with configured ledger persists and returns real event
/// ID.
#[test]
fn session_event_evidence_persist_emit_event_success() {
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());
    let ledger = Arc::new(StubLedgerEventEmitter::new());
    let clock = test_clock();

    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store)
        .with_ledger(ledger.clone())
        .with_clock(clock);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let request = EmitEventRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        event_type: "tool_completed".to_string(),
        payload: vec![1, 2, 3, 4, 5],
        correlation_id: "work-001".to_string(),
    };
    let frame = encode_emit_event_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::EmitEvent(resp) => {
            assert!(
                resp.event_id.starts_with("EVT-"),
                "Event ID should have EVT- prefix: {}",
                resp.event_id
            );
            assert!(resp.seq > 0, "Sequence should be positive");
            assert!(resp.timestamp_ns > 0, "Timestamp should be positive");

            // Verify event was actually persisted to ledger
            let persisted_event = ledger.get_event(&resp.event_id);
            assert!(
                persisted_event.is_some(),
                "Event should be persisted in ledger"
            );
        },
        _ => panic!("Expected EmitEvent response, got: {response:?}"),
    }
}

/// Verify `EmitEvent` without ledger returns fail-closed error.
#[test]
fn session_event_evidence_persist_emit_event_no_ledger() {
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());

    // No ledger configured
    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let request = EmitEventRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        event_type: "test_event".to_string(),
        payload: vec![],
        correlation_id: "corr-001".to_string(),
    };
    let frame = encode_emit_event_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorInternal as i32,
                "Should be INTERNAL for missing ledger"
            );
            assert!(
                err.message.contains("fail-closed"),
                "Error should mention fail-closed: {}",
                err.message
            );
        },
        _ => panic!("Expected error response, got: {response:?}"),
    }
}

/// Verify `PublishEvidence` with configured CAS stores and returns real hash.
#[test]
fn session_event_evidence_persist_publish_evidence_success() {
    let temp_dir = TempDir::new().unwrap();
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());
    let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
    let cas: Arc<dyn ContentAddressedStore> = Arc::new(DurableCas::new(cas_config).unwrap());

    let dispatcher =
        SessionDispatcher::with_manifest_store(minter.clone(), store).with_cas(cas.clone());
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let artifact_content = b"test evidence artifact content for TCK-00290";
    let request = PublishEvidenceRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        artifact: artifact_content.to_vec(),
        kind: EvidenceKind::ToolIo.into(),
        retention_hint: RetentionHint::Standard.into(),
    };
    let frame = encode_publish_evidence_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::PublishEvidence(resp) => {
            assert_eq!(
                resp.artifact_hash.len(),
                32,
                "Hash should be 32 bytes (BLAKE3)"
            );
            assert!(
                resp.storage_path.starts_with("evidence/"),
                "Storage path should be under evidence/: {}",
                resp.storage_path
            );
            assert!(resp.ttl_secs > 0, "TTL should be positive");

            // Verify artifact was actually stored in CAS
            let hash: [u8; 32] = resp.artifact_hash.try_into().unwrap();
            let retrieved = cas.retrieve(&hash);
            assert!(
                retrieved.is_some(),
                "Artifact should be retrievable from CAS"
            );
            assert_eq!(
                retrieved.unwrap(),
                artifact_content,
                "Retrieved artifact should match original"
            );
        },
        _ => panic!("Expected PublishEvidence response, got: {response:?}"),
    }
}

/// Verify `PublishEvidence` without CAS returns fail-closed error.
#[test]
fn session_event_evidence_persist_publish_evidence_no_cas() {
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());

    // No CAS configured
    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let request = PublishEvidenceRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        artifact: vec![1, 2, 3, 4, 5],
        kind: EvidenceKind::ToolIo.into(),
        retention_hint: RetentionHint::Standard.into(),
    };
    let frame = encode_publish_evidence_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorInternal as i32,
                "Should be INTERNAL for missing CAS"
            );
            assert!(
                err.message.contains("fail-closed"),
                "Error should mention fail-closed: {}",
                err.message
            );
        },
        _ => panic!("Expected error response, got: {response:?}"),
    }
}

/// Verify `StreamTelemetry` returns `NOT_IMPLEMENTED` (fail-closed).
#[test]
fn session_event_evidence_persist_stream_telemetry_not_implemented() {
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());
    let ledger = Arc::new(StubLedgerEventEmitter::new());

    // Even with all stores configured, StreamTelemetry should be NOT_IMPLEMENTED
    let temp_dir = TempDir::new().unwrap();
    let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
    let cas: Arc<dyn ContentAddressedStore> = Arc::new(DurableCas::new(cas_config).unwrap());

    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store)
        .with_ledger(ledger)
        .with_cas(cas);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let request = StreamTelemetryRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        frame: Some(TelemetryFrame {
            episode_id: "ep-001".to_string(),
            seq: 1,
            ts_mono: 1000,
            cpu_ns: 100,
            mem_rss_bytes: 1024,
            io_read_bytes: 0,
            io_write_bytes: 0,
            cgroup_stats: None,
            o11y_flags: 0,
        }),
    };
    let frame = encode_stream_telemetry_request(&request);

    let response = dispatcher.dispatch(&frame, &ctx).unwrap();
    match response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorNotImplemented as i32,
                "Should be NOT_IMPLEMENTED for StreamTelemetry"
            );
            assert!(
                err.message.contains("not implemented"),
                "Error should mention not implemented: {}",
                err.message
            );
        },
        _ => panic!("Expected NOT_IMPLEMENTED error, got: {response:?}"),
    }
}

/// Verify full dispatcher configuration works for all viable endpoints.
#[test]
fn session_event_evidence_persist_full_config_integration() {
    let temp_dir = TempDir::new().unwrap();
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());
    let ledger = Arc::new(StubLedgerEventEmitter::new());
    let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
    let cas: Arc<dyn ContentAddressedStore> = Arc::new(DurableCas::new(cas_config).unwrap());
    let clock = test_clock();

    // Register manifest
    let manifest = make_test_manifest(vec![ToolClass::Read, ToolClass::Write, ToolClass::Execute]);
    store.register("session-001", manifest);

    // Create fully-configured dispatcher with clock
    let dispatcher =
        SessionDispatcher::with_all_stores(minter.clone(), store, ledger, cas).with_clock(clock);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    // Test RequestTool - TCK-00335: now returns broker unavailable (fail-closed)
    let tool_request = RequestToolRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        tool_id: "write".to_string(),
        arguments: vec![],
        dedupe_key: "full-test-tool".to_string(),
    };
    let tool_frame = encode_request_tool_request(&tool_request);
    let tool_response = dispatcher.dispatch(&tool_frame, &ctx).unwrap();
    match tool_response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorToolNotAllowed as i32,
                "RequestTool should return TOOL_NOT_ALLOWED (broker unavailable)"
            );
            assert!(
                err.message.contains("broker unavailable"),
                "Error message should indicate broker unavailable: {}",
                err.message
            );
        },
        _ => panic!("Expected Error response for RequestTool, got: {tool_response:?}"),
    }

    // Test EmitEvent
    let event_request = EmitEventRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        event_type: "integration_test".to_string(),
        payload: vec![],
        correlation_id: "full-test-event".to_string(),
    };
    let event_frame = encode_emit_event_request(&event_request);
    let event_response = dispatcher.dispatch(&event_frame, &ctx).unwrap();
    assert!(
        matches!(event_response, SessionResponse::EmitEvent(_)),
        "EmitEvent should succeed with full config"
    );

    // Test PublishEvidence
    let evidence_request = PublishEvidenceRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        artifact: b"integration test artifact".to_vec(),
        kind: EvidenceKind::ToolIo.into(),
        retention_hint: RetentionHint::Standard.into(),
    };
    let evidence_frame = encode_publish_evidence_request(&evidence_request);
    let evidence_response = dispatcher.dispatch(&evidence_frame, &ctx).unwrap();
    assert!(
        matches!(evidence_response, SessionResponse::PublishEvidence(_)),
        "PublishEvidence should succeed with full config"
    );

    // StreamTelemetry should still be NOT_IMPLEMENTED even with full config
    let telemetry_request = StreamTelemetryRequest {
        session_token: serde_json::to_string(&token).unwrap(),
        frame: Some(TelemetryFrame::default()),
    };
    let telemetry_frame = encode_stream_telemetry_request(&telemetry_request);
    let telemetry_response = dispatcher.dispatch(&telemetry_frame, &ctx).unwrap();
    match telemetry_response {
        SessionResponse::Error(err) => {
            assert_eq!(
                err.code,
                SessionErrorCode::SessionErrorNotImplemented as i32,
                "StreamTelemetry should be NOT_IMPLEMENTED even with full config"
            );
        },
        _ => panic!("Expected NOT_IMPLEMENTED for StreamTelemetry"),
    }
}

// =============================================================================
// Additional edge case tests
// =============================================================================

/// Verify `EmitEvent` sequence numbers are monotonically increasing.
#[test]
fn session_event_evidence_persist_emit_event_sequence_monotonic() {
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());
    let ledger = Arc::new(StubLedgerEventEmitter::new());
    let clock = test_clock();

    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store)
        .with_ledger(ledger)
        .with_clock(clock);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    let mut prev_seq = 0u64;
    for i in 0..5 {
        let request = EmitEventRequest {
            session_token: serde_json::to_string(&token).unwrap(),
            event_type: format!("event_{i}"),
            payload: vec![],
            correlation_id: format!("seq-test-{i}"),
        };
        let frame = encode_emit_event_request(&request);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            SessionResponse::EmitEvent(resp) => {
                assert!(
                    resp.seq > prev_seq,
                    "Sequence should be monotonically increasing: {} > {}",
                    resp.seq,
                    prev_seq
                );
                prev_seq = resp.seq;
            },
            _ => panic!("Expected EmitEvent response"),
        }
    }
}

/// Verify `PublishEvidence` with different retention hints returns different
/// TTLs.
#[test]
fn session_event_evidence_persist_publish_evidence_retention_hints() {
    let temp_dir = TempDir::new().unwrap();
    let minter = test_minter();
    let store = Arc::new(InMemoryManifestStore::new());
    let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
    let cas: Arc<dyn ContentAddressedStore> = Arc::new(DurableCas::new(cas_config).unwrap());

    let dispatcher = SessionDispatcher::with_manifest_store(minter.clone(), store).with_cas(cas);
    let ctx = make_session_ctx();
    let token = test_token(&minter);

    // Test different retention hints
    let retention_tests = vec![
        (0, 86400),     // Standard: 24 hours
        (1, 604_800),   // Extended: 7 days
        (2, 2_592_000), // Audit: 30 days
        (99, 86400),    // Unknown: defaults to standard
    ];

    for (hint, expected_ttl) in retention_tests {
        let request = PublishEvidenceRequest {
            session_token: serde_json::to_string(&token).unwrap(),
            artifact: format!("artifact for hint {hint}").into_bytes(),
            kind: EvidenceKind::ToolIo.into(),
            retention_hint: hint,
        };
        let frame = encode_publish_evidence_request(&request);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            SessionResponse::PublishEvidence(resp) => {
                assert_eq!(
                    resp.ttl_secs, expected_ttl,
                    "TTL for retention_hint={hint} should be {expected_ttl}"
                );
            },
            _ => panic!("Expected PublishEvidence response for hint={hint}"),
        }
    }
}
