//! RFC-0032::REQ-0146: `OperatorClient` shutdown reaches daemon graceful-stop signal.
//!
//! IT-00392-09 validates that the CLI-side `OperatorClient` can connect to an
//! in-process daemon control plane over the operator socket, send `Shutdown`,
//! receive a success response, and trigger daemon-loop exit within a timeout.

use std::sync::Arc;
use std::time::Duration;

use apm2_core::Supervisor;
use apm2_core::config::EcosystemConfig;
use apm2_core::schema_registry::InMemorySchemaRegistry;
use apm2_daemon::hsi_contract::RiskTier;
use apm2_daemon::protocol::connection_handler::{HandshakeConfig, perform_handshake};
use apm2_daemon::protocol::dispatch::ConnectionContext;
use apm2_daemon::protocol::socket_manager::{SocketManager, SocketManagerConfig, SocketType};
use apm2_daemon::state::{DaemonStateHandle, DispatcherState, SharedDispatcherState, SharedState};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tempfile::TempDir;
use tokio::task::JoinHandle;

#[allow(dead_code)]
#[path = "../src/client/protocol.rs"]
mod protocol_client;

use protocol_client::OperatorClient;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

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

fn create_dispatcher_state(shared_state: &SharedState) -> SharedDispatcherState {
    Arc::new(DispatcherState::new(None).with_daemon_state(Arc::clone(shared_state)))
}

fn spawn_test_server(
    socket_manager: Arc<SocketManager>,
    state: SharedState,
    dispatcher_state: SharedDispatcherState,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if state.is_shutdown_requested() {
                break;
            }

            let accept_result =
                tokio::time::timeout(Duration::from_millis(100), socket_manager.accept()).await;

            let Ok(Ok((mut connection, _permit, socket_type))) = accept_result else {
                continue;
            };

            let conn_state = Arc::clone(&state);
            let conn_dispatcher_state = Arc::clone(&dispatcher_state);

            tokio::spawn(async move {
                let handshake = HandshakeConfig::default().with_risk_tier(RiskTier::Tier1);
                if perform_handshake(&mut connection, &handshake)
                    .await
                    .is_err()
                {
                    return;
                }

                let ctx = match socket_type {
                    SocketType::Operator => ConnectionContext::privileged_session_open(
                        connection.peer_credentials().cloned(),
                    ),
                    SocketType::Session => ConnectionContext::session_open(
                        connection.peer_credentials().cloned(),
                        None,
                    ),
                };

                let dispatcher = conn_dispatcher_state.privileged_dispatcher();

                while let Some(Ok(frame)) = connection.framed().next().await {
                    let response = match dispatcher.dispatch(&Bytes::from(frame.to_vec()), &ctx) {
                        Ok(resp) => resp.encode(),
                        Err(_) => break,
                    };

                    if connection.framed().send(response).await.is_err() {
                        break;
                    }

                    if conn_state.is_shutdown_requested() {
                        break;
                    }
                }
            });
        }
    })
}

/// IT-00392-09: `OperatorClient` shutdown triggers daemon loop exit.
#[tokio::test]
async fn tck_00392_operator_client_shutdown_exits_cleanly() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let operator_socket = temp_dir.path().join("operator.sock");
    let session_socket = temp_dir.path().join("session.sock");

    let socket_manager = Arc::new(
        SocketManager::bind(SocketManagerConfig::new(&operator_socket, &session_socket))
            .expect("failed to bind socket manager"),
    );
    let shared_state = create_shared_state();
    let dispatcher_state = create_dispatcher_state(&shared_state);

    let server_handle = spawn_test_server(
        Arc::clone(&socket_manager),
        Arc::clone(&shared_state),
        dispatcher_state,
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = tokio::time::timeout(TEST_TIMEOUT, OperatorClient::connect(&operator_socket))
        .await
        .expect("operator client connect timed out")
        .expect("operator client connect failed");

    let shutdown_response = tokio::time::timeout(
        TEST_TIMEOUT,
        client.shutdown(Some("IT-00392-09 operator shutdown")),
    )
    .await
    .expect("shutdown request timed out")
    .expect("shutdown request failed");

    assert!(
        shutdown_response.message.contains("Shutdown initiated"),
        "expected shutdown success message, got: {}",
        shutdown_response.message
    );
    assert!(
        shared_state.is_shutdown_requested(),
        "daemon shared state must have shutdown flag set after operator shutdown"
    );

    let join_result = tokio::time::timeout(TEST_TIMEOUT, server_handle)
        .await
        .expect("daemon server loop did not exit within timeout after shutdown");
    join_result.expect("daemon server loop task panicked");

    socket_manager
        .cleanup()
        .expect("failed to clean up socket files");
    assert!(
        !operator_socket.exists(),
        "operator socket should be removed during cleanup"
    );
    assert!(
        !session_socket.exists(),
        "session socket should be removed during cleanup"
    );
}
