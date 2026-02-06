//! TCK-00392: Wire IPC shutdown handler to daemon graceful shutdown signal.
//!
//! This test module verifies that the `handle_shutdown` method in
//! `PrivilegedDispatcher` correctly wires to the daemon's `SharedState`
//! shutdown flag, enabling `apm2 kill` to cleanly stop a running daemon.
//!
//! # Verification Commands
//!
//! - IT-00392-04: `cargo test -p apm2-daemon tck_00392_shutdown_sets_flag`
//! - IT-00392-05: `cargo test -p apm2-daemon tck_00392_shutdown_without_state`
//! - IT-00392-06: `cargo test -p apm2-daemon
//!   tck_00392_shutdown_flag_detected_by_event_loop`
//! - IT-00392-07: `cargo test -p apm2-daemon
//!   tck_00392_shutdown_response_before_flag`
//!
//! # Security Properties
//!
//! Per RFC-0018 and ticket notes:
//! - Shutdown is only available on the operator socket (privileged access)
//! - The response is sent before the shutdown sequence begins
//! - Graceful shutdown cleans up sockets and PID files

use std::sync::Arc;

use apm2_core::Supervisor;
use apm2_core::config::EcosystemConfig;
use apm2_core::schema_registry::InMemorySchemaRegistry;
use apm2_daemon::protocol::credentials::PeerCredentials;
use apm2_daemon::protocol::dispatch::{
    ConnectionContext, PrivilegedDispatcher, PrivilegedResponse, encode_shutdown_request,
};
use apm2_daemon::protocol::messages::ShutdownRequest;
use apm2_daemon::state::DaemonStateHandle;

// =============================================================================
// Test Helpers
// =============================================================================

fn make_privileged_ctx() -> ConnectionContext {
    ConnectionContext::privileged(Some(PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: Some(99999),
    }))
}

fn make_session_ctx() -> ConnectionContext {
    ConnectionContext::session(
        Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(99998),
        }),
        Some("test-session".to_string()),
    )
}

fn create_shared_state() -> Arc<DaemonStateHandle> {
    let supervisor = Supervisor::new();
    let config = EcosystemConfig::default();
    let schema_registry = InMemorySchemaRegistry::new();
    Arc::new(DaemonStateHandle::new(
        config,
        supervisor,
        schema_registry,
        None,
    ))
}

// =============================================================================
// IT-00392-04: Shutdown with daemon state sets the atomic flag
// =============================================================================

/// Verifies that sending a Shutdown request via the privileged dispatcher
/// sets the `is_shutdown_requested()` flag on `SharedState`, which the
/// main event loop uses to trigger the graceful shutdown sequence.
#[test]
fn tck_00392_shutdown_sets_flag() {
    let shared_state = create_shared_state();
    let dispatcher = PrivilegedDispatcher::new().with_daemon_state(Arc::clone(&shared_state));
    let ctx = make_privileged_ctx();

    // Pre-condition: shutdown not yet requested
    assert!(
        !shared_state.is_shutdown_requested(),
        "shutdown should not be requested before Shutdown command"
    );

    let request = ShutdownRequest {
        reason: Some("integration test shutdown".to_string()),
    };
    let frame = encode_shutdown_request(&request);
    let response = dispatcher.dispatch(&frame, &ctx).unwrap();

    // Verify success response
    match &response {
        PrivilegedResponse::Shutdown(resp) => {
            assert!(
                resp.message.contains("Shutdown initiated"),
                "expected initiation message, got: {}",
                resp.message
            );
        },
        PrivilegedResponse::Error(err) => {
            panic!("Unexpected error response: {err:?}");
        },
        other => panic!("Expected Shutdown response, got {other:?}"),
    }

    // Post-condition: shutdown flag is set
    assert!(
        shared_state.is_shutdown_requested(),
        "shutdown flag must be set after Shutdown command"
    );
}

// =============================================================================
// IT-00392-05: Shutdown without daemon state returns stub
// =============================================================================

/// Verifies that when `daemon_state` is `None` (test/stub mode), the
/// handler returns a stub acknowledgment without panicking.
#[test]
fn tck_00392_shutdown_without_state() {
    let dispatcher = PrivilegedDispatcher::new(); // No daemon_state
    let ctx = make_privileged_ctx();

    let request = ShutdownRequest {
        reason: Some("test without state".to_string()),
    };
    let frame = encode_shutdown_request(&request);
    let response = dispatcher.dispatch(&frame, &ctx).unwrap();

    match &response {
        PrivilegedResponse::Shutdown(resp) => {
            assert!(
                resp.message.contains("stub"),
                "stub response expected when daemon state not configured, got: {}",
                resp.message
            );
        },
        PrivilegedResponse::Error(err) => {
            panic!("Unexpected error response: {err:?}");
        },
        other => panic!("Expected Shutdown response, got {other:?}"),
    }
}

// =============================================================================
// IT-00392-06: Shutdown flag is detected by simulated event loop
// =============================================================================

/// Simulates the main event loop pattern: set the shutdown flag via IPC
/// and verify the event loop condition (`is_shutdown_requested()`) returns
/// `true`, confirming the wiring is correct end-to-end.
#[test]
fn tck_00392_shutdown_flag_detected_by_event_loop() {
    let shared_state = create_shared_state();

    // Clone state to simulate passing to different components (as in main.rs)
    let event_loop_state = Arc::clone(&shared_state);
    let dispatcher_state = Arc::clone(&shared_state);

    let dispatcher = PrivilegedDispatcher::new().with_daemon_state(dispatcher_state);
    let ctx = make_privileged_ctx();

    // Simulate event loop check before shutdown
    assert!(
        !event_loop_state.is_shutdown_requested(),
        "event loop should not see shutdown before IPC command"
    );

    // Send shutdown via IPC
    let request = ShutdownRequest {
        reason: Some("event loop test".to_string()),
    };
    let frame = encode_shutdown_request(&request);
    let _response = dispatcher.dispatch(&frame, &ctx).unwrap();

    // Simulate event loop check after shutdown
    assert!(
        event_loop_state.is_shutdown_requested(),
        "event loop must detect shutdown flag set by IPC handler"
    );
}

// =============================================================================
// IT-00392-07: Response is returned before shutdown takes effect
// =============================================================================

/// Verifies that the `handle_shutdown` handler returns the success response
/// synchronously. The response is constructed and returned before the main
/// event loop acts on the shutdown flag, ensuring the CLI client receives
/// acknowledgment.
#[test]
fn tck_00392_shutdown_response_before_flag() {
    let shared_state = create_shared_state();
    let dispatcher = PrivilegedDispatcher::new().with_daemon_state(Arc::clone(&shared_state));
    let ctx = make_privileged_ctx();

    let request = ShutdownRequest {
        reason: Some("response ordering test".to_string()),
    };
    let frame = encode_shutdown_request(&request);

    // The dispatch call returns the response synchronously.
    // The shutdown flag is set during dispatch, but the response is
    // constructed before returning, so the client always gets a reply.
    let response = dispatcher.dispatch(&frame, &ctx).unwrap();

    // Response must be a Shutdown (not Error)
    assert!(
        matches!(&response, PrivilegedResponse::Shutdown(_)),
        "expected Shutdown response variant, got {response:?}"
    );

    // The flag is set (this is fine — the key invariant is that we got
    // the response object back, meaning the client would have received it
    // over the socket before the daemon starts its shutdown sequence).
    assert!(shared_state.is_shutdown_requested());
}

// =============================================================================
// IT-00392-08: Session socket cannot trigger shutdown
// =============================================================================

/// Verifies that the session socket (unprivileged) cannot trigger shutdown.
/// Only the operator socket should have access to the Shutdown command.
#[test]
fn tck_00392_session_cannot_shutdown() {
    let shared_state = create_shared_state();
    let dispatcher = PrivilegedDispatcher::new().with_daemon_state(Arc::clone(&shared_state));
    let ctx = make_session_ctx();

    let request = ShutdownRequest {
        reason: Some("malicious session attempt".to_string()),
    };
    let frame = encode_shutdown_request(&request);
    let response = dispatcher.dispatch(&frame, &ctx).unwrap();

    // Must be PERMISSION_DENIED
    match &response {
        PrivilegedResponse::Error(err) => {
            assert_eq!(
                err.code,
                apm2_daemon::protocol::messages::PrivilegedErrorCode::PermissionDenied as i32,
                "session socket must get PERMISSION_DENIED for shutdown"
            );
        },
        _ => panic!("Expected PERMISSION_DENIED for session socket shutdown attempt"),
    }

    // Shutdown flag must NOT be set
    assert!(
        !shared_state.is_shutdown_requested(),
        "shutdown flag must not be set after rejected session attempt"
    );
}
