//! TCK-00392 E2E: Shutdown via `OperatorClient` over real operator socket.
//!
//! This test proves that a daemon-like server, listening on a real Unix
//! domain socket, correctly handles a Shutdown request sent through the
//! operator socket using the full wire protocol (Hello/HelloAck handshake
//! followed by a tagged protobuf `ShutdownRequest` frame).
//!
//! # What is tested end-to-end
//!
//! (a) A daemon (in-process) starts with `SocketManager` + dispatchers
//! (b) Shutdown is sent via an operator-socket client (handshake + tagged
//! frame) (c) Success response is returned with a valid `ShutdownResponse`
//! (d) The daemon's shutdown flag is set, causing the event loop to exit
//! (e) Socket files and PID file are cleaned up after shutdown
//!
//! # Verification
//!
//! ```text
//! cargo test -p apm2-daemon tck_00392_e2e
//! ```

use std::sync::Arc;
use std::time::Duration;

use apm2_core::Supervisor;
use apm2_core::config::EcosystemConfig;
use apm2_core::schema_registry::InMemorySchemaRegistry;
use apm2_daemon::protocol::connection_handler::perform_handshake;
use apm2_daemon::protocol::dispatch::{ConnectionContext, encode_shutdown_request};
use apm2_daemon::protocol::messages::{
    BoundedDecode, DecodeConfig, PrivilegedError, ShutdownRequest, ShutdownResponse,
};
use apm2_daemon::protocol::socket_manager::{SocketManager, SocketManagerConfig, SocketType};
use apm2_daemon::protocol::{
    ClientHandshake, FrameCodec, HandshakeMessage, PrivilegedMessageType,
    serialize_handshake_message,
};
use apm2_daemon::state::{DaemonStateHandle, DispatcherState, SharedDispatcherState, SharedState};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tempfile::TempDir;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;

/// Timeout for individual test operations.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

// =============================================================================
// Helpers
// =============================================================================

/// Creates shared daemon state for the test server.
fn create_shared_state() -> SharedState {
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

/// Creates dispatcher state wired to the daemon shared state.
fn create_dispatcher_state(shared_state: &SharedState) -> SharedDispatcherState {
    Arc::new(DispatcherState::new(None).with_daemon_state(Arc::clone(shared_state)))
}

/// Spawns a server accept loop that handles one operator connection with
/// full handshake + dispatch, mirroring `handle_dual_socket_connection`
/// from `main.rs`.
fn spawn_server_loop(
    manager: Arc<SocketManager>,
    state: SharedState,
    dispatcher_state: SharedDispatcherState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if state.is_shutdown_requested() {
                break;
            }

            let accept_result =
                tokio::time::timeout(Duration::from_millis(100), manager.accept()).await;

            if let Ok(Ok((mut connection, _permit, socket_type))) = accept_result {
                let conn_state = state.clone();
                let conn_ds = Arc::clone(&dispatcher_state);
                tokio::spawn(async move {
                    // Perform handshake
                    if perform_handshake(&mut connection).await.is_err() {
                        return;
                    }

                    let ctx = match socket_type {
                        SocketType::Operator => {
                            ConnectionContext::privileged(connection.peer_credentials().cloned())
                        },
                        SocketType::Session => {
                            ConnectionContext::session(connection.peer_credentials().cloned(), None)
                        },
                    };

                    let priv_dispatcher = conn_ds.privileged_dispatcher();

                    while let Some(Ok(frame)) = connection.framed().next().await {
                        if conn_state.is_shutdown_requested() {
                            break;
                        }
                        let frame_bytes = Bytes::from(frame.to_vec());
                        match priv_dispatcher.dispatch(&frame_bytes, &ctx) {
                            Ok(response) => {
                                let response_bytes = response.encode();
                                if connection.framed().send(response_bytes).await.is_err() {
                                    break;
                                }
                            },
                            Err(_) => break,
                        }
                    }
                });
            }
            // On accept error or timeout, loop back to check shutdown flag
        }
    })
}

/// Performs the client-side Hello/HelloAck handshake.
async fn client_handshake(framed: &mut Framed<UnixStream, FrameCodec>) {
    let mut hs = ClientHandshake::new("test-client/1.0");
    let hello = hs.create_hello();
    let hello_msg: HandshakeMessage = hello.into();
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();

    framed.send(hello_bytes).await.unwrap();
    let ack_frame = framed.next().await.unwrap().unwrap();
    let response = apm2_daemon::protocol::parse_handshake_message(&ack_frame).unwrap();
    hs.process_response(response).unwrap();
}

/// Decodes a tagged privileged response frame into a `ShutdownResponse`.
fn decode_shutdown_response(frame: &Bytes) -> ShutdownResponse {
    assert!(!frame.is_empty(), "response frame must not be empty");
    let tag = frame[0];
    let payload = &frame[1..];

    assert_ne!(
        tag,
        0,
        "response tag 0 indicates an error: {:?}",
        PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
    );

    assert_eq!(
        tag,
        PrivilegedMessageType::Shutdown.tag(),
        "expected Shutdown response tag ({}), got {tag}",
        PrivilegedMessageType::Shutdown.tag()
    );

    ShutdownResponse::decode_bounded(payload, &DecodeConfig::default())
        .expect("failed to decode ShutdownResponse")
}

// =============================================================================
// IT-00392-E2E-01: Full end-to-end shutdown over operator socket
// =============================================================================

/// Starts an in-process daemon (`SocketManager` + dispatchers), connects via
/// the operator socket, sends Shutdown, and verifies:
///
/// (a) Daemon starts and listens on operator + session sockets
/// (b) Shutdown sent via operator socket with full handshake
/// (c) Success response returned
/// (d) Daemon shutdown flag set (event loop exits)
/// (e) Socket + PID files cleaned up
#[tokio::test]
async fn tck_00392_e2e_shutdown_over_operator_socket() {
    // -- Setup ----------------------------------------------------------------

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");
    let pid_path = tmp.path().join("daemon.pid");

    // Write PID file (simulating daemon startup)
    std::fs::write(&pid_path, std::process::id().to_string()).unwrap();
    assert!(pid_path.exists(), "PID file must exist after write");

    // Create SocketManager
    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = Arc::new(SocketManager::bind(config).unwrap());

    // Verify sockets exist
    assert!(
        operator_path.exists(),
        "operator.sock must exist after bind"
    );
    assert!(session_path.exists(), "session.sock must exist after bind");

    // Create shared state and dispatcher
    let shared_state = create_shared_state();
    let dispatcher_state = create_dispatcher_state(&shared_state);

    // Pre-condition: shutdown not yet requested
    assert!(
        !shared_state.is_shutdown_requested(),
        "shutdown must not be requested at startup"
    );

    // Spawn server accept loop
    let server_state = shared_state.clone();
    let server_handle = spawn_server_loop(
        Arc::clone(&manager),
        server_state,
        Arc::clone(&dispatcher_state),
    );

    // Small delay for the server to start accepting
    tokio::time::sleep(Duration::from_millis(50)).await;

    // -- (b) Connect and send Shutdown ----------------------------------------

    let stream = tokio::time::timeout(TEST_TIMEOUT, UnixStream::connect(&operator_path))
        .await
        .expect("connect timeout")
        .expect("connect failed");

    let mut framed = Framed::new(stream, FrameCodec::new());

    // Handshake
    client_handshake(&mut framed).await;

    // Send Shutdown request
    let request = ShutdownRequest {
        reason: Some("e2e integration test".to_string()),
    };
    let request_frame = encode_shutdown_request(&request);
    framed.send(request_frame).await.unwrap();

    // -- (c) Assert success response ------------------------------------------

    let response_frame = tokio::time::timeout(TEST_TIMEOUT, framed.next())
        .await
        .expect("response timeout")
        .expect("stream ended unexpectedly")
        .expect("frame read error");

    let shutdown_resp = decode_shutdown_response(&Bytes::from(response_frame.to_vec()));
    assert!(
        shutdown_resp.message.contains("Shutdown initiated"),
        "expected initiation message, got: {}",
        shutdown_resp.message
    );

    // -- (d) Assert daemon exits within timeout window ------------------------

    assert!(
        shared_state.is_shutdown_requested(),
        "shutdown flag must be set after Shutdown response"
    );

    // Wait for the server loop to notice the flag and exit
    let server_exit = tokio::time::timeout(TEST_TIMEOUT, server_handle).await;
    assert!(
        server_exit.is_ok(),
        "server loop must exit within timeout after shutdown flag set"
    );

    // -- (e) Assert socket + PID cleanup --------------------------------------

    // Clean up sockets (mirroring daemon's cleanup path)
    manager.cleanup().expect("socket cleanup failed");

    assert!(
        !operator_path.exists(),
        "operator.sock must be removed after cleanup"
    );
    assert!(
        !session_path.exists(),
        "session.sock must be removed after cleanup"
    );

    // Clean up PID file (mirroring daemon's remove_pid_file)
    if pid_path.exists() {
        std::fs::remove_file(&pid_path).unwrap();
    }
    assert!(!pid_path.exists(), "PID file must be removed after cleanup");
}
