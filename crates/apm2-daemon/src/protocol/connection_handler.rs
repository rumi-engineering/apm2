//! Connection handler for dual-socket `ProtocolServer` control plane.
//!
//! This module implements the connection handling logic for the daemon's
//! `ProtocolServer`-only control plane (TCK-00279/TCK-00281). It performs the
//! mandatory Hello/HelloAck handshake as specified in DD-001/DD-008 before
//! processing any protobuf messages.
//!
//! # Protocol Compliance
//!
//! Per the protocol specification in [`handshake`] and DD-001:
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
//!
//! # TCK-00281: Legacy JSON IPC Removal
//!
//! Per DD-009, legacy JSON IPC (apm2_core::ipc) has been removed. The daemon
//! now only accepts protobuf-encoded messages via PrivilegedDispatcher and
//! SessionDispatcher. This module provides only the handshake functionality;
//! message dispatch is handled by the protobuf dispatchers.

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tracing::warn;

use super::handshake::{
    HandshakeMessage, ServerHandshake, parse_hello, serialize_handshake_message,
};
use super::server::Connection;

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
/// any protobuf frames.
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
///         // Connection is ready for protobuf message exchange
///         handle_protobuf_messages(&mut connection, socket_type).await?;
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

#[cfg(test)]
#[allow(clippy::items_after_statements)]
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
}
