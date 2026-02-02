//! Connection handler for dual-socket `ProtocolServer` control plane.
//!
//! This module implements the connection handling logic for the daemon's
//! `ProtocolServer`-only control plane (TCK-00279). It performs the mandatory
//! Hello/HelloAck handshake as specified in DD-001/DD-008 before processing
//! any IPC frames.
//!
//! # Protocol Compliance
//!
//! Per the protocol specification in [`super::handshake`] and DD-001:
//!
//! 1. Client sends `Hello` message with protocol version
//! 2. Server validates and responds with `HelloAck` or `HelloNack`
//! 3. If accepted, connection enters message exchange phase
//! 4. Either party may close the connection
//!
//! Skipping the handshake violates the protocol specification and will cause
//! protocol-compliant clients to hang or fail when connecting.
//!
//! # Security Considerations
//!
//! - Handshake is performed AFTER UID validation (which happens at accept time)
//! - Frame size is limited during handshake to prevent DoS
//! - Invalid handshake terminates the connection
//! - Privilege checks are performed based on socket type before dispatching

use anyhow::{Context, Result};
use apm2_core::ipc::{IpcRequest, IpcResponse};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tracing::{info, warn};

use super::handshake::{
    HandshakeMessage, ServerHandshake, parse_hello, serialize_handshake_message,
};
use super::server::Connection;
use super::socket_manager::SocketType;

/// Server information string for handshake.
///
/// This identifies the daemon to connecting clients during the Hello/HelloAck
/// handshake.
fn server_info() -> String {
    format!("apm2-daemon/{}", env!("CARGO_PKG_VERSION"))
}

/// Result of the handshake phase.
#[derive(Debug)]
pub enum HandshakeResult {
    /// Handshake succeeded, connection is ready for message exchange.
    Success,
    /// Handshake failed (sent `HelloNack`), connection should be closed.
    Failed,
    /// Connection closed during handshake (no frame received).
    ConnectionClosed,
}

/// Perform the mandatory protocol handshake on a connection.
///
/// This function implements the server-side of the Hello/HelloAck handshake
/// protocol as specified in DD-001/DD-008. It MUST be called before processing
/// any IPC frames.
///
/// # Protocol Sequence
///
/// 1. Receive Hello frame from client
/// 2. Validate protocol version
/// 3. Send `HelloAck` (on success) or `HelloNack` (on failure)
/// 4. Upgrade frame size limit for message exchange phase (on success)
///
/// # Arguments
///
/// * `connection` - The connection to handshake
///
/// # Returns
///
/// - `Ok(HandshakeResult::Success)` if handshake completed successfully
/// - `Ok(HandshakeResult::Failed)` if handshake failed (`HelloNack` sent)
/// - `Ok(HandshakeResult::ConnectionClosed)` if client closed connection
/// - `Err(_)` if I/O error occurred
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::protocol::connection_handler::{perform_handshake, HandshakeResult};
///
/// let (mut connection, _permit, socket_type) = socket_manager.accept().await?;
///
/// match perform_handshake(&mut connection).await? {
///     HandshakeResult::Success => {
///         // Connection is ready for message exchange
///         handle_messages(&mut connection, socket_type).await?;
///     }
///     HandshakeResult::Failed | HandshakeResult::ConnectionClosed => {
///         // Connection will be closed
///     }
/// }
/// ```
pub async fn perform_handshake(connection: &mut Connection) -> Result<HandshakeResult> {
    let mut handshake = ServerHandshake::new(server_info());

    // Receive Hello from client
    let frame = match connection.framed().next().await {
        Some(Ok(frame)) => frame,
        Some(Err(e)) => {
            warn!("Failed to receive handshake frame: {e}");
            return Err(e.into());
        },
        None => {
            // Client closed connection before sending Hello
            return Ok(HandshakeResult::ConnectionClosed);
        },
    };

    // Parse the Hello message (enforces handshake frame size limit)
    let hello = match parse_hello(&frame) {
        Ok(hello) => hello,
        Err(e) => {
            warn!("Invalid Hello message: {e}");
            // Send HelloNack for invalid message
            let nack = super::handshake::HelloNack::rejected(format!("invalid Hello: {e}"));
            let nack_bytes = serialize_handshake_message(&HandshakeMessage::HelloNack(nack))
                .context("failed to serialize HelloNack")?;
            connection.framed().send(nack_bytes).await?;
            return Ok(HandshakeResult::Failed);
        },
    };

    // Process the Hello and generate response
    let response = handshake
        .process_hello(&hello)
        .context("failed to process Hello")?;

    // Serialize and send response
    let response_bytes =
        serialize_handshake_message(&response).context("failed to serialize handshake response")?;
    connection.framed().send(response_bytes).await?;

    // Check if handshake succeeded
    if !handshake.is_completed() {
        return Ok(HandshakeResult::Failed);
    }

    // Upgrade to full frame size after successful handshake
    connection
        .upgrade_to_full_frame_size()
        .context("failed to upgrade frame size")?;

    Ok(HandshakeResult::Success)
}

/// Request dispatcher function type.
///
/// This trait-like type allows the connection handler to be decoupled from
/// the specific request dispatcher implementation, enabling testing with
/// mock dispatchers.
pub type RequestDispatcher<S> =
    fn(
        IpcRequest,
        &S,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IpcResponse> + Send + '_>>;

/// Check if a request requires privileged (operator) access.
///
/// TCK-00249: Uses default-deny model. Session socket connections are only
/// allowed to perform a small whitelist of safe operations. All other
/// operations require privileged (operator) connection.
///
/// # Security (Holonic Seclusion)
///
/// Session socket (mode 0660) is accessible to group users. To maintain
/// seclusion, we only allow `Ping` which cannot leak information about
/// processes, credentials, logs, or other sensitive data.
///
/// Operations that would violate seclusion if allowed on session socket:
/// - `TailLogs`: Would expose logs from ALL processes to any group user
/// - `ListProcesses`/`GetProcess`: Would expose process args (may contain
///   secrets)
/// - `ListCredentials`/`GetCredential`: Would expose credential metadata
/// - `Status`: Would expose daemon configuration details
/// - `*Episode*`: Episode state contains sensitive context
pub const fn requires_privilege(request: &IpcRequest) -> bool {
    // Default-deny: only explicitly whitelisted operations are unprivileged
    !matches!(
        request,
        // Session-safe operations (do not leak sensitive information)
        IpcRequest::Ping
    )
}

/// Handle a connection from the dual-socket manager.
///
/// This function implements the full connection lifecycle:
///
/// 1. **Handshake**: Perform mandatory Hello/HelloAck protocol
/// 2. **Message Loop**: Process IPC requests until connection closes
/// 3. **Privilege Checks**: Validate access based on socket type
///
/// # Arguments
///
/// * `connection` - The connection to handle
/// * `socket_type` - The socket type (Operator or Session) for privilege checks
/// * `state` - Shared daemon state for request handling
/// * `dispatcher` - Function to dispatch IPC requests to handlers
///
/// # Protocol Compliance (TCK-00279)
///
/// This function implements the mandatory handshake that was missing in the
/// original implementation. Protocol-compliant clients expect:
///
/// 1. Send `Hello` -> Receive `HelloAck`/`HelloNack`
/// 2. If `HelloAck`: Send IPC requests -> Receive IPC responses
///
/// Without the handshake, clients would hang waiting for `HelloAck`.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::protocol::connection_handler::handle_connection;
///
/// tokio::spawn(async move {
///     if let Err(e) = handle_connection(
///         connection,
///         socket_type,
///         &state,
///         |req, s| Box::pin(handlers::dispatch(req, s)),
///     ).await {
///         warn!("Connection handler error: {e}");
///     }
/// });
/// ```
pub async fn handle_connection<S>(
    mut connection: Connection,
    socket_type: SocketType,
    state: &S,
    dispatcher: RequestDispatcher<S>,
) -> Result<()>
where
    S: Send + Sync,
{
    info!(
        socket_type = %socket_type,
        privileged = connection.is_privileged(),
        "New ProtocolServer connection"
    );

    // Step 1: Perform mandatory handshake
    match perform_handshake(&mut connection).await? {
        HandshakeResult::Success => {
            info!(socket_type = %socket_type, "Handshake completed successfully");
        },
        HandshakeResult::Failed => {
            warn!(socket_type = %socket_type, "Handshake failed, closing connection");
            return Ok(());
        },
        HandshakeResult::ConnectionClosed => {
            info!(socket_type = %socket_type, "Connection closed during handshake");
            return Ok(());
        },
    }

    // Step 2: Process messages
    while let Some(frame_result) = connection.framed().next().await {
        match frame_result {
            Ok(frame) => {
                if frame.is_empty() {
                    // Empty frame signals connection close
                    break;
                }

                // Parse the request
                let request: IpcRequest = match serde_json::from_slice(&frame) {
                    Ok(req) => req,
                    Err(e) => {
                        warn!("Failed to parse request: {e}");
                        continue;
                    },
                };

                // Check privilege level for privileged operations
                if requires_privilege(&request) && !connection.is_privileged() {
                    warn!(
                        "Unprivileged client attempted privileged operation: {:?}",
                        request
                    );
                    let response = IpcResponse::Error {
                        code: apm2_core::ipc::ErrorCode::InvalidRequest,
                        message: "operation requires privileged (operator) connection".to_string(),
                    };
                    let json: Bytes = serde_json::to_vec(&response)?.into();
                    connection.framed().send(json).await?;
                    continue;
                }

                // Dispatch to handler
                let response = dispatcher(request, state).await;

                // Send response
                let json: Bytes = serde_json::to_vec(&response)?.into();
                connection.framed().send(json).await?;
            },
            Err(e) => {
                warn!("Frame error: {e}");
                break;
            },
        }
    }

    info!(socket_type = %socket_type, "Connection closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::time::timeout;

    use super::*;
    use crate::protocol::{
        ClientHandshake, HandshakeMessage, SocketManagerConfig, parse_handshake_message,
        serialize_handshake_message,
    };

    /// Test that handshake succeeds with a valid Hello message.
    #[tokio::test]
    async fn test_perform_handshake_success() {
        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        // Spawn server that performs handshake
        let manager_clone = manager.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn).await
        });

        // Connect as client and perform handshake
        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);
        let mut client_handshake = ClientHandshake::new("test-client/1.0");

        // Send Hello
        let hello = client_handshake.create_hello();
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        // Receive HelloAck
        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();
        client_handshake.process_response(response).unwrap();

        assert!(client_handshake.is_completed());

        // Verify server handshake succeeded
        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake failed");

        assert!(matches!(result, HandshakeResult::Success));
    }

    /// Test that handshake fails with invalid protocol version.
    #[tokio::test]
    async fn test_perform_handshake_version_mismatch() {
        use crate::protocol::handshake::Hello;

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        // Spawn server that performs handshake
        let manager_clone = manager.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn).await
        });

        // Connect as client with invalid version
        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);

        // Send Hello with invalid version
        let bad_hello = Hello::with_version(99, "bad-client/1.0");
        let hello_msg = HandshakeMessage::Hello(bad_hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        // Receive HelloNack
        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();

        assert!(matches!(response, HandshakeMessage::HelloNack(_)));

        // Verify server handshake failed
        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake error");

        assert!(matches!(result, HandshakeResult::Failed));
    }

    /// Test that requires_privilege correctly identifies privileged operations.
    #[test]
    fn test_requires_privilege() {
        // Ping should NOT require privilege
        assert!(!requires_privilege(&IpcRequest::Ping));

        // All other operations should require privilege
        assert!(requires_privilege(&IpcRequest::Status));
        assert!(requires_privilege(&IpcRequest::ListProcesses));
        assert!(requires_privilege(&IpcRequest::Shutdown));
        assert!(requires_privilege(&IpcRequest::GetProcess {
            name: "test".to_string()
        }));
    }

    /// Test full connection handling with handshake and request dispatch.
    #[tokio::test]
    async fn test_handle_connection_full_lifecycle() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        // Simple state that tracks if dispatcher was called
        struct TestState {
            dispatched: AtomicBool,
        }

        let state = Arc::new(TestState {
            dispatched: AtomicBool::new(false),
        });

        // Mock dispatcher that just returns Pong
        fn mock_dispatcher(
            _req: IpcRequest,
            state: &Arc<TestState>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IpcResponse> + Send + '_>> {
            state.dispatched.store(true, Ordering::SeqCst);
            Box::pin(async {
                IpcResponse::Pong {
                    version: "test".to_string(),
                    uptime_secs: 0,
                }
            })
        }

        // Spawn server
        let manager_clone = manager.clone();
        let state_clone = Arc::clone(&state);
        let server_handle = tokio::spawn(async move {
            let (conn, _permit, socket_type) = manager_clone.accept().await.unwrap();
            handle_connection(conn, socket_type, &state_clone, mock_dispatcher).await
        });

        // Connect as client
        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);
        let mut client_handshake = ClientHandshake::new("test-client/1.0");

        // Perform handshake
        let hello = client_handshake.create_hello();
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();
        client_handshake.process_response(response).unwrap();

        assert!(client_handshake.is_completed());

        // Upgrade client frame size
        client_conn.upgrade_to_full_frame_size().unwrap();

        // Send Ping request
        let ping_request = IpcRequest::Ping;
        let request_bytes = serde_json::to_vec(&ping_request).unwrap();
        client_conn
            .framed()
            .send(Bytes::from(request_bytes))
            .await
            .unwrap();

        // Receive Pong response
        let pong_frame = client_conn.framed().next().await.unwrap().unwrap();
        let pong_response: IpcResponse = serde_json::from_slice(&pong_frame).unwrap();

        assert!(matches!(pong_response, IpcResponse::Pong { .. }));

        // Send empty frame to close connection
        client_conn.framed().send(Bytes::new()).await.unwrap();

        // Wait for server to finish
        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked");

        assert!(result.is_ok());
        assert!(state.dispatched.load(Ordering::SeqCst));
    }

    /// Test that unprivileged client cannot perform privileged operations.
    #[tokio::test]
    async fn test_handle_connection_privilege_check() {
        use std::sync::Arc;

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        struct TestState;

        fn mock_dispatcher(
            _req: IpcRequest,
            _state: &Arc<TestState>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IpcResponse> + Send + '_>> {
            Box::pin(async {
                // Should not be called for privileged operations on session socket
                panic!("dispatcher should not be called for unprivileged client");
            })
        }

        let state = Arc::new(TestState);

        // Spawn server
        let manager_clone = manager.clone();
        let state_clone = Arc::clone(&state);
        let server_handle = tokio::spawn(async move {
            let (conn, _permit, socket_type) = manager_clone.accept().await.unwrap();
            handle_connection(conn, socket_type, &state_clone, mock_dispatcher).await
        });

        // Connect to SESSION socket (unprivileged)
        let stream = tokio::net::UnixStream::connect(&session_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);
        let mut client_handshake = ClientHandshake::new("test-client/1.0");

        // Perform handshake
        let hello = client_handshake.create_hello();
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();
        client_handshake.process_response(response).unwrap();

        client_conn.upgrade_to_full_frame_size().unwrap();

        // Try to send Status request (privileged operation) on session socket
        let status_request = IpcRequest::Status;
        let request_bytes = serde_json::to_vec(&status_request).unwrap();
        client_conn
            .framed()
            .send(Bytes::from(request_bytes))
            .await
            .unwrap();

        // Should receive error response
        let error_frame = client_conn.framed().next().await.unwrap().unwrap();
        let error_response: IpcResponse = serde_json::from_slice(&error_frame).unwrap();

        match error_response {
            IpcResponse::Error { code, message } => {
                assert_eq!(code, apm2_core::ipc::ErrorCode::InvalidRequest);
                assert!(message.contains("privileged"));
            },
            _ => panic!("expected error response"),
        }

        // Close connection
        client_conn.framed().send(Bytes::new()).await.unwrap();

        // Wait for server
        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked");

        assert!(result.is_ok());
    }
}
