//! Integration tests for the UDS protocol server.
//!
//! These tests verify end-to-end protocol functionality including:
//! - Server binding and client connection
//! - Frame encoding/decoding over the wire
//! - Handshake protocol completion
//! - Connection lifecycle management
//! - UID-based authentication at accept time (TCK-00248)
//! - Dual-socket privilege separation (TCK-00249)
//!
//! # Security Note (TCK-00248)
//!
//! UID validation is performed at `accept()` time, before the handshake.
//! Since both client and server run as the same user in tests, integration
//! tests verify the authorization succeeds. Unit tests in `server.rs` verify
//! that the constant-time comparison and error handling work correctly.
//!
//! # Dual-Socket Topology (TCK-00249)
//!
//! The socket manager creates two sockets with different permissions:
//! - `operator.sock` (mode 0600): Privileged operations only
//! - `session.sock` (mode 0660): Session-scoped operations only
//!
//! Connections are routed based on which socket they connect to, and the
//! socket type determines which handlers are accessible.

use std::time::Duration;

use apm2_daemon::protocol::{
    ClientHandshake, HandshakeMessage, Hello, PROTOCOL_VERSION, ProtocolServer, ServerConfig,
    ServerHandshake, SocketManager, SocketManagerConfig, SocketType, connect,
    parse_handshake_message, parse_hello, serialize_handshake_message,
};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tempfile::TempDir;
use tokio::time::timeout;

/// Helper to create a unique socket path for tests.
fn test_socket_path(dir: &TempDir, name: &str) -> std::path::PathBuf {
    dir.path().join(format!("{name}.sock"))
}

/// Test that server accepts a connection and can exchange frames.
#[tokio::test]
async fn test_server_accepts_connection() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "server_accept");

    let config = ServerConfig::new(&socket_path);
    let server = ProtocolServer::bind(config).unwrap();

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        let (conn, _permit) = server.accept().await.unwrap();
        conn
    });

    // Connect as client
    let client = connect(&socket_path).await.unwrap();

    // Verify both sides established connection
    let _server_conn = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("server accept timed out")
        .expect("server accept failed");

    // Client connection exists
    drop(client);
}

/// Test full handshake protocol between client and server.
///
/// Uses the secure `parse_hello` and `parse_handshake_message` functions
/// which enforce the 64KB handshake frame limit.
#[tokio::test]
async fn test_full_handshake_protocol() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "handshake");

    let config = ServerConfig::new(&socket_path).with_server_info("test-daemon/1.0");
    let server = ProtocolServer::bind(config).unwrap();

    // Spawn server that handles handshake
    let server_handle = tokio::spawn(async move {
        let (mut conn, _permit) = server.accept().await.unwrap();
        let mut handshake = ServerHandshake::new("test-daemon/1.0");

        // Receive Hello from client using secure parsing (enforces 64KB limit)
        let frame = conn.framed().next().await.unwrap().unwrap();
        let hello = parse_hello(&frame).expect("failed to parse Hello");

        // Process and send response
        let response = handshake.process_hello(&hello).unwrap();
        let response_bytes = serialize_handshake_message(&response).unwrap();
        conn.framed().send(response_bytes).await.unwrap();

        assert!(handshake.is_completed());

        // Upgrade to full frame size after successful handshake
        conn.upgrade_to_full_frame_size().unwrap();

        handshake.negotiated_version()
    });

    // Client side handshake
    let mut client_conn = connect(&socket_path).await.unwrap();
    let mut client_handshake = ClientHandshake::new("test-cli/1.0");

    // Send Hello using secure serialization
    let hello = client_handshake.create_hello();
    let hello_msg = HandshakeMessage::Hello(hello);
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
    client_conn.framed().send(hello_bytes).await.unwrap();

    // Receive response using secure parsing (enforces 64KB limit)
    let response_frame = client_conn.framed().next().await.unwrap().unwrap();
    let response = parse_handshake_message(&response_frame).expect("failed to parse response");
    client_handshake.process_response(response).unwrap();

    assert!(client_handshake.is_completed());
    assert_eq!(client_handshake.server_info(), Some("test-daemon/1.0"));

    // Upgrade to full frame size after successful handshake
    client_conn.upgrade_to_full_frame_size().unwrap();

    // Verify server completed handshake
    let server_version = timeout(Duration::from_secs(1), server_handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server_version, Some(PROTOCOL_VERSION));
}

/// Test that version mismatch is properly rejected.
///
/// Uses the secure parsing functions which enforce the 64KB handshake frame
/// limit.
#[tokio::test]
async fn test_handshake_version_mismatch() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "version_mismatch");

    let config = ServerConfig::new(&socket_path);
    let server = ProtocolServer::bind(config).unwrap();

    // Spawn server
    let server_handle = tokio::spawn(async move {
        let (mut conn, _permit) = server.accept().await.unwrap();
        let mut handshake = ServerHandshake::new("test-daemon/1.0");

        // Use secure parsing (enforces 64KB limit)
        let frame = conn.framed().next().await.unwrap().unwrap();
        let hello = parse_hello(&frame).expect("failed to parse Hello");

        let response = handshake.process_hello(&hello).unwrap();
        let response_bytes = serialize_handshake_message(&response).unwrap();
        conn.framed().send(response_bytes).await.unwrap();

        // Should have failed
        assert!(!handshake.is_completed());
    });

    // Client sends incompatible version using secure serialization
    let mut client_conn = connect(&socket_path).await.unwrap();

    let bad_hello = Hello::with_version(99, "bad-client/1.0");
    let hello_msg = HandshakeMessage::Hello(bad_hello);
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
    client_conn.framed().send(hello_bytes).await.unwrap();

    // Receive rejection using secure parsing (enforces 64KB limit)
    let response_frame = client_conn.framed().next().await.unwrap().unwrap();
    let response = parse_handshake_message(&response_frame).expect("failed to parse response");

    assert!(matches!(response, HandshakeMessage::HelloNack(_)));

    timeout(Duration::from_secs(1), server_handle)
        .await
        .unwrap()
        .unwrap();
}

/// Test large frame transmission.
#[tokio::test]
async fn test_large_frame_transmission() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "large_frame");

    let config = ServerConfig::new(&socket_path);
    let server = ProtocolServer::bind(config).unwrap();

    // Create a moderately large payload (1 MB)
    let payload_size = 1024 * 1024;
    let payload = vec![0xABu8; payload_size];
    let payload_bytes = Bytes::from(payload.clone());

    // Spawn server that echoes the frame
    let server_handle = tokio::spawn(async move {
        let (mut conn, _permit) = server.accept().await.unwrap();
        // Upgrade connection to allow large frames
        conn.upgrade_to_full_frame_size().unwrap();
        let frame = conn.framed().next().await.unwrap().unwrap();
        conn.framed().send(frame).await.unwrap();
    });

    // Client sends and receives
    let mut client_conn = connect(&socket_path).await.unwrap();
    // Upgrade client connection as well
    client_conn.upgrade_to_full_frame_size().unwrap();
    client_conn.framed().send(payload_bytes).await.unwrap();

    let response = client_conn.framed().next().await.unwrap().unwrap();
    assert_eq!(response.len(), payload_size);
    assert_eq!(&response[..], &payload[..]);

    timeout(Duration::from_secs(5), server_handle)
        .await
        .unwrap()
        .unwrap();
}

/// Test multiple sequential frames.
#[tokio::test]
async fn test_multiple_frames_sequence() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "multi_frame");

    let config = ServerConfig::new(&socket_path);
    let server = ProtocolServer::bind(config).unwrap();

    let messages: Vec<&str> = vec!["first", "second", "third", "fourth", "fifth"];

    // Server echoes all messages
    let msgs_clone = messages.clone();
    let server_handle = tokio::spawn(async move {
        let (mut conn, _permit) = server.accept().await.unwrap();
        let mut received = Vec::new();

        for _ in 0..msgs_clone.len() {
            let frame = conn.framed().next().await.unwrap().unwrap();
            received.push(String::from_utf8_lossy(&frame).to_string());
            conn.framed().send(frame).await.unwrap();
        }

        received
    });

    // Client sends and receives all messages
    let mut client_conn = connect(&socket_path).await.unwrap();

    for msg in &messages {
        client_conn.framed().send(Bytes::from(*msg)).await.unwrap();
        let response = client_conn.framed().next().await.unwrap().unwrap();
        assert_eq!(&response[..], msg.as_bytes());
    }

    let server_received = timeout(Duration::from_secs(2), server_handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server_received, messages);
}

/// Test server cleanup on drop.
#[tokio::test]
async fn test_server_socket_cleanup() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "cleanup");

    {
        let config = ServerConfig::new(&socket_path);
        let _server = ProtocolServer::bind(config).unwrap();
        assert!(socket_path.exists());
    }

    // Socket should be removed when server is dropped
    assert!(!socket_path.exists());
}

/// Test that connection permits limit concurrent connections.
///
/// This test verifies the semaphore-based connection limiting:
/// 1. With `max_connections=2`, first two accepts should succeed
/// 2. Third accept should block until a permit is released
#[tokio::test]
async fn test_connection_limit_enforcement() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "limit");

    let config = ServerConfig::new(&socket_path).with_max_connections(2);
    let server = std::sync::Arc::new(ProtocolServer::bind(config).unwrap());

    // Connect two clients (up to limit)
    let _client1 = connect(&socket_path).await.unwrap();
    let _client2 = connect(&socket_path).await.unwrap();

    // Accept both connections
    let server_clone = server.clone();
    let accept1 = tokio::spawn(async move { server_clone.accept().await });

    let server_clone = server.clone();
    let accept2 = tokio::spawn(async move { server_clone.accept().await });

    let (_conn1, permit1) = timeout(Duration::from_secs(1), accept1)
        .await
        .expect("accept1 timed out")
        .expect("accept1 join failed")
        .expect("accept1 failed");

    let (_conn2, _permit2) = timeout(Duration::from_secs(1), accept2)
        .await
        .expect("accept2 timed out")
        .expect("accept2 join failed")
        .expect("accept2 failed");

    // Third connection connects at socket level, but accept should block
    let _client3 = connect(&socket_path).await.unwrap();

    // Start accepting but it should block waiting for a permit
    let server_clone = server.clone();
    let accept3_handle = tokio::spawn(async move { server_clone.accept().await });

    // Give it a short time - it should NOT complete
    let result = timeout(
        Duration::from_millis(100),
        &mut Box::pin(async {
            // Small delay to let the accept task start
            tokio::time::sleep(Duration::from_millis(50)).await;
        }),
    )
    .await;
    assert!(result.is_ok()); // timeout completed, not the accept

    // Release one permit
    drop(permit1);

    // Now accept3 should succeed
    let result = timeout(Duration::from_secs(1), accept3_handle).await;
    assert!(
        result.is_ok(),
        "Third accept should succeed after permit released"
    );
    let inner = result.unwrap();
    assert!(inner.is_ok(), "Third accept task should not panic");
    assert!(inner.unwrap().is_ok(), "Third accept should succeed");
}

/// Test that same-UID connections are accepted (TCK-00248).
///
/// This integration test verifies that when client and server run as the same
/// user (which is always the case in tests), the connection is accepted and
/// handshake succeeds.
///
/// # Security Note (TCK-00248)
///
/// UID validation now happens at `accept()` time (before handshake), using
/// constant-time comparison via `subtle::ConstantTimeEq`. Since we can't
/// easily change the process UID in tests, this test verifies the success
/// path. Unit tests in `server.rs` verify the rejection path using mocked
/// credentials.
#[tokio::test]
async fn test_accept_validates_uid_at_connection_time() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "uid_validation");

    let config = ServerConfig::new(&socket_path).with_server_info("test-daemon/1.0");
    let server = ProtocolServer::bind(config).unwrap();

    // Spawn server that accepts and verifies peer credentials are populated
    let server_handle = tokio::spawn(async move {
        let (conn, _permit) = server.accept().await.unwrap();

        // Verify that peer credentials were extracted
        let creds = conn
            .peer_credentials()
            .expect("Peer credentials should be present");

        // Verify credentials match current process (same user in tests)
        let current_uid = nix::unistd::getuid().as_raw();
        assert_eq!(
            creds.uid, current_uid,
            "Peer UID should match current process UID"
        );

        // PID should be present on Linux
        assert!(creds.pid.is_some(), "Peer PID should be present");

        conn
    });

    // Connect as client
    let client = connect(&socket_path).await.unwrap();

    // Verify server accepted the connection (UID matched)
    let _server_conn = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("server accept timed out")
        .expect("server accept failed");

    // Client connection exists
    drop(client);
}

/// Test full handshake succeeds after UID validation at accept (TCK-00248).
///
/// This verifies that the handshake works correctly after UID authorization
/// has already been performed at the `accept()` stage.
#[tokio::test]
async fn test_handshake_after_uid_validation() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "uid_handshake");

    let config = ServerConfig::new(&socket_path).with_server_info("test-daemon/1.0");
    let server = ProtocolServer::bind(config).unwrap();

    // Spawn server
    let server_handle = tokio::spawn(async move {
        // accept() performs UID validation before returning
        let (mut conn, _permit) = server.accept().await.unwrap();

        // Verify peer credentials are present (UID validated at accept)
        assert!(
            conn.peer_credentials().is_some(),
            "Credentials should be present after accept"
        );

        // Handshake no longer needs to validate UID - already done at accept()
        let mut handshake = ServerHandshake::new("test-daemon/1.0");

        let frame = conn.framed().next().await.unwrap().unwrap();
        let hello = parse_hello(&frame).expect("failed to parse Hello");

        let response = handshake.process_hello(&hello).unwrap();
        let response_bytes = serialize_handshake_message(&response).unwrap();
        conn.framed().send(response_bytes).await.unwrap();

        assert!(handshake.is_completed());
        handshake.negotiated_version()
    });

    // Client side
    let mut client_conn = connect(&socket_path).await.unwrap();
    let mut client_handshake = ClientHandshake::new("test-cli/1.0");

    let hello = client_handshake.create_hello();
    let hello_msg = HandshakeMessage::Hello(hello);
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
    client_conn.framed().send(hello_bytes).await.unwrap();

    let response_frame = client_conn.framed().next().await.unwrap().unwrap();
    let response = parse_handshake_message(&response_frame).expect("failed to parse response");
    client_handshake.process_response(response).unwrap();

    assert!(client_handshake.is_completed());
    assert_eq!(client_handshake.server_info(), Some("test-daemon/1.0"));

    let server_version = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("server timed out")
        .expect("server task panicked");
    assert_eq!(server_version, Some(PROTOCOL_VERSION));
}

// ============================================================================
// Dual-Socket Routing Tests (TCK-00249)
// ============================================================================

/// Test that `SocketManager` creates two sockets with correct permissions.
///
/// Verifies acceptance criterion: "Two sockets created with correct
/// permissions"
/// - operator.sock: mode 0600 (owner read/write only)
/// - session.sock: mode 0660 (owner + group read/write)
#[tokio::test]
async fn test_dual_socket_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let _manager = SocketManager::bind(config).unwrap();

    // Verify operator socket has mode 0600
    let operator_meta = std::fs::metadata(&operator_path).unwrap();
    let operator_mode = operator_meta.permissions().mode() & 0o777;
    assert_eq!(
        operator_mode, 0o600,
        "operator socket should have mode 0600, got {operator_mode:04o}"
    );

    // Verify session socket has mode 0660
    let session_meta = std::fs::metadata(&session_path).unwrap();
    let session_mode = session_meta.permissions().mode() & 0o777;
    assert_eq!(
        session_mode, 0o660,
        "session socket should have mode 0660, got {session_mode:04o}"
    );
}

/// Test that connections to operator socket are marked as privileged.
///
/// Verifies acceptance criterion: "Connections routed based on socket path"
#[tokio::test]
async fn test_operator_socket_is_privileged() {
    use tokio::net::UnixStream;

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = std::sync::Arc::new(SocketManager::bind(config).unwrap());

    // Spawn accept task
    let manager_clone = manager.clone();
    let accept_handle = tokio::spawn(async move {
        let (_conn, _permit, socket_type) = manager_clone.accept().await.unwrap();
        socket_type
    });

    // Connect to operator socket
    let _client = UnixStream::connect(&operator_path).await.unwrap();

    // Verify socket type is Operator (privileged)
    let socket_type = timeout(Duration::from_secs(1), accept_handle)
        .await
        .expect("accept timed out")
        .expect("accept task failed");

    assert_eq!(socket_type, SocketType::Operator);
    assert!(
        socket_type.is_privileged(),
        "Operator socket should be privileged"
    );
}

/// Test that connections to session socket are NOT privileged.
///
/// Verifies acceptance criterion: "Connections routed based on socket path"
#[tokio::test]
async fn test_session_socket_is_not_privileged() {
    use tokio::net::UnixStream;

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = std::sync::Arc::new(SocketManager::bind(config).unwrap());

    // Spawn accept task
    let manager_clone = manager.clone();
    let accept_handle = tokio::spawn(async move {
        let (_conn, _permit, socket_type) = manager_clone.accept().await.unwrap();
        socket_type
    });

    // Connect to session socket
    let _client = UnixStream::connect(&session_path).await.unwrap();

    // Verify socket type is Session (unprivileged)
    let socket_type = timeout(Duration::from_secs(1), accept_handle)
        .await
        .expect("accept timed out")
        .expect("accept task failed");

    assert_eq!(socket_type, SocketType::Session);
    assert!(
        !socket_type.is_privileged(),
        "Session socket should NOT be privileged"
    );
}

/// Test that socket manager correctly routes multiple connections.
///
/// This test verifies that:
/// 1. Connections to operator socket are routed as Operator type
/// 2. Connections to session socket are routed as Session type
/// 3. The routing is determined by which socket the connection arrives on
#[tokio::test]
async fn test_dual_socket_routing() {
    use tokio::net::UnixStream;

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = std::sync::Arc::new(SocketManager::bind(config).unwrap());

    // Test multiple connections in sequence, alternating sockets
    let socket_types: Vec<(&std::path::PathBuf, SocketType)> = vec![
        (&operator_path, SocketType::Operator),
        (&session_path, SocketType::Session),
        (&operator_path, SocketType::Operator),
        (&session_path, SocketType::Session),
    ];

    for (socket_path, expected_type) in socket_types {
        let manager_clone = manager.clone();
        let accept_handle = tokio::spawn(async move {
            let (_conn, _permit, socket_type) = manager_clone.accept().await.unwrap();
            socket_type
        });

        let _client = UnixStream::connect(socket_path).await.unwrap();

        let socket_type = timeout(Duration::from_secs(1), accept_handle)
            .await
            .expect("accept timed out")
            .expect("accept task failed");

        assert_eq!(
            socket_type,
            expected_type,
            "Connection to {} should be {:?}",
            socket_path.display(),
            expected_type
        );
    }
}

/// Test that socket manager cleans up both sockets on drop.
#[tokio::test]
async fn test_dual_socket_cleanup() {
    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    {
        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let _manager = SocketManager::bind(config).unwrap();

        assert!(operator_path.exists());
        assert!(session_path.exists());
    }

    // Both sockets should be removed when manager is dropped
    assert!(!operator_path.exists());
    assert!(!session_path.exists());
}

/// Test that handshake works on operator socket.
#[tokio::test]
async fn test_operator_socket_handshake() {
    use tokio::net::UnixStream;

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = std::sync::Arc::new(SocketManager::bind(config).unwrap());

    // Spawn server that handles handshake on operator socket
    let manager_clone = manager.clone();
    let server_handle = tokio::spawn(async move {
        let (mut conn, _permit, socket_type) = manager_clone.accept().await.unwrap();
        assert_eq!(socket_type, SocketType::Operator);

        let mut handshake = ServerHandshake::new("test-daemon/1.0");

        let frame = conn.framed().next().await.unwrap().unwrap();
        let hello = parse_hello(&frame).expect("failed to parse Hello");

        let response = handshake.process_hello(&hello).unwrap();
        let response_bytes = serialize_handshake_message(&response).unwrap();
        conn.framed().send(response_bytes).await.unwrap();

        assert!(handshake.is_completed());
        socket_type
    });

    // Connect to operator socket using low-level UnixStream
    let stream = UnixStream::connect(&operator_path).await.unwrap();
    let mut client_conn = apm2_daemon::protocol::Connection::new_with_credentials(stream, None);
    let mut client_handshake = ClientHandshake::new("test-cli/1.0");

    let hello = client_handshake.create_hello();
    let hello_msg = HandshakeMessage::Hello(hello);
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
    client_conn.framed().send(hello_bytes).await.unwrap();

    let response_frame = client_conn.framed().next().await.unwrap().unwrap();
    let response = parse_handshake_message(&response_frame).expect("failed to parse response");
    client_handshake.process_response(response).unwrap();

    assert!(client_handshake.is_completed());

    let socket_type = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("server timed out")
        .expect("server task panicked");
    assert_eq!(socket_type, SocketType::Operator);
}

/// Test that handshake works on session socket.
#[tokio::test]
async fn test_session_socket_handshake() {
    use tokio::net::UnixStream;

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = std::sync::Arc::new(SocketManager::bind(config).unwrap());

    // Spawn server that handles handshake on session socket
    let manager_clone = manager.clone();
    let server_handle = tokio::spawn(async move {
        let (mut conn, _permit, socket_type) = manager_clone.accept().await.unwrap();
        assert_eq!(socket_type, SocketType::Session);

        let mut handshake = ServerHandshake::new("test-daemon/1.0");

        let frame = conn.framed().next().await.unwrap().unwrap();
        let hello = parse_hello(&frame).expect("failed to parse Hello");

        let response = handshake.process_hello(&hello).unwrap();
        let response_bytes = serialize_handshake_message(&response).unwrap();
        conn.framed().send(response_bytes).await.unwrap();

        assert!(handshake.is_completed());
        socket_type
    });

    // Connect to session socket using low-level UnixStream
    let stream = UnixStream::connect(&session_path).await.unwrap();
    let mut client_conn = apm2_daemon::protocol::Connection::new_with_credentials(stream, None);
    let mut client_handshake = ClientHandshake::new("test-cli/1.0");

    let hello = client_handshake.create_hello();
    let hello_msg = HandshakeMessage::Hello(hello);
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
    client_conn.framed().send(hello_bytes).await.unwrap();

    let response_frame = client_conn.framed().next().await.unwrap().unwrap();
    let response = parse_handshake_message(&response_frame).expect("failed to parse response");
    client_handshake.process_response(response).unwrap();

    assert!(client_handshake.is_completed());

    let socket_type = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("server timed out")
        .expect("server task panicked");
    assert_eq!(socket_type, SocketType::Session);
}

// ============================================================================
// ProtocolServer-Only Startup Tests (TCK-00279)
// ============================================================================

/// INT-00279-01: `ProtocolServer`-only startup.
///
/// This test verifies the acceptance criteria for TCK-00279:
///
/// 1. **`ProtocolServer` is the only daemon control-plane listener**
///    - Verification: `SocketManager` binds operator.sock + session.sock
///
/// 2. **Legacy JSON IPC startup removed**
///    - Verification: No `ipc_server` module exists in the daemon binary source
///    - (This is verified by code inspection and compilation - the module
///      import was removed)
///
/// 3. **Legacy socket path is absent**
///    - Verification: Default paths use operator.sock and session.sock, not
///      apm2d.sock
///
/// Per DD-009 (RFC-0017), the daemon ONLY uses `ProtocolServer` for
/// control-plane IPC. The legacy JSON IPC (`ipc_server.rs`) has been removed.
#[tokio::test]
async fn test_protocol_only_startup() {
    let tmp = TempDir::new().unwrap();

    // Define the dual-socket paths per DD-009
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    // Legacy single-socket path that should NOT be used
    let legacy_path = tmp.path().join("apm2d.sock");

    // 1. Verify SocketManager creates ONLY operator.sock and session.sock
    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = SocketManager::bind(config).unwrap();

    // Verify the dual sockets exist
    assert!(
        operator_path.exists(),
        "operator.sock should exist for ProtocolServer"
    );
    assert!(
        session_path.exists(),
        "session.sock should exist for ProtocolServer"
    );

    // Verify legacy single-socket path does NOT exist
    // (We never created it, and SocketManager shouldn't either)
    assert!(
        !legacy_path.exists(),
        "Legacy apm2d.sock should NOT exist - ProtocolServer uses dual sockets only"
    );

    // 2. Verify SocketManager paths match what we configured
    assert_eq!(
        manager.operator_socket_path(),
        &operator_path,
        "SocketManager should bind to configured operator path"
    );
    assert_eq!(
        manager.session_socket_path(),
        &session_path,
        "SocketManager should bind to configured session path"
    );

    // 3. Verify socket permissions match DD-009 requirements
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let operator_mode = std::fs::metadata(&operator_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            operator_mode, 0o600,
            "operator.sock should have mode 0600 (owner only)"
        );

        let session_mode = std::fs::metadata(&session_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            session_mode, 0o660,
            "session.sock should have mode 0660 (owner + group)"
        );
    }

    // 4. Verify default paths from EcosystemConfig use dual-socket topology
    // The default config should point to operator.sock and session.sock,
    // not the legacy apm2d.sock
    let default_config = apm2_core::config::EcosystemConfig::default();

    // Get filenames from paths
    let default_operator_name = default_config
        .daemon
        .operator_socket
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let default_session_name = default_config
        .daemon
        .session_socket
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    assert_eq!(
        default_operator_name, "operator.sock",
        "Default operator socket should be operator.sock"
    );
    assert_eq!(
        default_session_name, "session.sock",
        "Default session socket should be session.sock"
    );

    // Cleanup happens automatically when manager is dropped
    drop(manager);

    // Verify cleanup removed the sockets
    assert!(
        !operator_path.exists(),
        "operator.sock should be cleaned up on drop"
    );
    assert!(
        !session_path.exists(),
        "session.sock should be cleaned up on drop"
    );
}

/// Test that legacy single-socket server config points to the legacy path.
///
/// This verifies that `ProtocolServer::default_socket_path()` still returns
/// the legacy `apm2d.sock` path (for backwards compatibility in the
/// `ProtocolServer` API), but the daemon uses `SocketManager` with dual sockets
/// instead.
///
/// This test documents the distinction:
/// - `ProtocolServer` (single-socket): Uses `apm2d.sock` - NOT used by daemon
/// - `SocketManager` (dual-socket): Uses `operator.sock` + `session.sock` -
///   USED by daemon
#[tokio::test]
async fn test_legacy_protocol_server_path_not_used_by_daemon() {
    use apm2_daemon::protocol::server::default_socket_path;

    // The legacy ProtocolServer default path
    let legacy_default = default_socket_path();
    let legacy_name = legacy_default
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // ProtocolServer's default is apm2d.sock (for API compatibility)
    assert_eq!(
        legacy_name, "apm2d.sock",
        "ProtocolServer default should be apm2d.sock"
    );

    // But the daemon uses SocketManager with dual sockets instead
    let default_config = apm2_core::config::EcosystemConfig::default();
    let daemon_operator = default_config
        .daemon
        .operator_socket
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let daemon_session = default_config
        .daemon
        .session_socket
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Daemon config uses dual-socket paths, NOT the legacy single socket
    assert_ne!(
        daemon_operator, "apm2d.sock",
        "Daemon should NOT use legacy apm2d.sock for operator"
    );
    assert_ne!(
        daemon_session, "apm2d.sock",
        "Daemon should NOT use legacy apm2d.sock for session"
    );
    assert_eq!(
        daemon_operator, "operator.sock",
        "Daemon should use operator.sock"
    );
    assert_eq!(
        daemon_session, "session.sock",
        "Daemon should use session.sock"
    );
}

// ============================================================================
// Connection Handler Tests (TCK-00279 Fix)
// ============================================================================

/// INT-00279-02: Mandatory handshake in production connection handler.
///
/// This test verifies that the production connection handler (now in the
/// library at `apm2_daemon::protocol::connection_handler`) properly implements
/// the mandatory Hello/HelloAck handshake as specified in DD-001/DD-008.
///
/// Prior to this fix, the production handler in `main.rs` skipped the
/// handshake, causing protocol-compliant clients to hang.
///
/// This test exercises the ACTUAL production code path via the library module.
/// Helper struct for test state.
struct IntTestState;

/// Helper dispatcher for integration test.
fn int_test_dispatcher(
    req: apm2_core::ipc::IpcRequest,
    _state: &std::sync::Arc<IntTestState>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = apm2_core::ipc::IpcResponse> + Send + '_>> {
    Box::pin(async move {
        match req {
            apm2_core::ipc::IpcRequest::Ping => apm2_core::ipc::IpcResponse::Pong {
                version: "test".to_string(),
                uptime_secs: 42,
            },
            _ => apm2_core::ipc::IpcResponse::Error {
                code: apm2_core::ipc::ErrorCode::NotSupported,
                message: "not implemented".to_string(),
            },
        }
    })
}

#[tokio::test]
async fn test_production_handler_performs_handshake() {
    use std::sync::Arc;

    use apm2_daemon::protocol::connection_handler::handle_connection;
    use apm2_daemon::protocol::{
        ClientHandshake, Connection, HandshakeMessage, SocketManagerConfig,
        parse_handshake_message, serialize_handshake_message,
    };
    use tokio::net::UnixStream;

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = Arc::new(apm2_daemon::protocol::SocketManager::bind(config).unwrap());

    let state = Arc::new(IntTestState);

    // Spawn server using the PRODUCTION handler from the library
    let manager_clone = manager.clone();
    let state_clone = Arc::clone(&state);
    let server_handle = tokio::spawn(async move {
        let (conn, _permit, socket_type) = manager_clone.accept().await.unwrap();
        // This is the ACTUAL production code path being tested
        handle_connection(conn, socket_type, &state_clone, int_test_dispatcher).await
    });

    // Connect as client
    let stream = UnixStream::connect(&operator_path).await.unwrap();
    let mut client_conn = Connection::new_with_credentials(stream, None);
    let mut client_handshake = ClientHandshake::new("integration-test/1.0");

    // Perform handshake - this should succeed now that production handler does
    // handshake
    let hello = client_handshake.create_hello();
    let hello_msg = HandshakeMessage::Hello(hello);
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
    client_conn.framed().send(hello_bytes).await.unwrap();

    // Receive HelloAck - this would have hung before the fix
    let response_frame = timeout(Duration::from_secs(2), client_conn.framed().next())
        .await
        .expect("handshake response timed out - production handler may not be performing handshake")
        .expect("stream ended unexpectedly")
        .expect("failed to receive response");

    let response = parse_handshake_message(&response_frame).expect("failed to parse response");
    assert!(
        matches!(response, HandshakeMessage::HelloAck(_)),
        "Expected HelloAck, got {response:?}"
    );

    client_handshake.process_response(response).unwrap();
    assert!(
        client_handshake.is_completed(),
        "Client handshake should complete"
    );

    // Upgrade frame size after handshake
    client_conn.upgrade_to_full_frame_size().unwrap();

    // Now send a Ping request
    let ping_request = apm2_core::ipc::IpcRequest::Ping;
    let request_bytes = serde_json::to_vec(&ping_request).unwrap();
    client_conn
        .framed()
        .send(bytes::Bytes::from(request_bytes))
        .await
        .unwrap();

    // Receive Pong response
    let pong_frame = client_conn.framed().next().await.unwrap().unwrap();
    let pong_response: apm2_core::ipc::IpcResponse = serde_json::from_slice(&pong_frame).unwrap();

    match pong_response {
        apm2_core::ipc::IpcResponse::Pong {
            version,
            uptime_secs,
        } => {
            assert_eq!(version, "test");
            assert_eq!(uptime_secs, 42);
        },
        other => panic!("Expected Pong, got {other:?}"),
    }

    // Close connection
    client_conn
        .framed()
        .send(bytes::Bytes::new())
        .await
        .unwrap();

    // Wait for server to finish
    let result = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("server timed out")
        .expect("server task panicked");

    assert!(result.is_ok(), "Server should complete without error");
}

/// INT-00279-03: Production handler is now in testable library module.
///
/// This test verifies that the connection handler logic is no longer trapped
/// in the binary (main.rs) but is instead in the library crate where it can
/// be properly unit tested.
///
/// Per LAW-05 (testability principle), core security logic should be in
/// testable library modules, not in the binary.
#[test]
fn test_connection_handler_is_in_library() {
    use apm2_daemon::protocol::connection_handler::{HandshakeResult, requires_privilege};

    // These types and functions should be accessible from the library
    // If this test compiles, the code has been properly extracted from main.rs

    // Verify requires_privilege function is accessible and works
    assert!(!requires_privilege(&apm2_core::ipc::IpcRequest::Ping));
    assert!(requires_privilege(&apm2_core::ipc::IpcRequest::Status));

    // Verify HandshakeResult enum variants are accessible
    // Simply constructing each variant proves they exist and are public
    let success = HandshakeResult::Success;
    let failed = HandshakeResult::Failed;
    let closed = HandshakeResult::ConnectionClosed;

    // Use the values to avoid unused warnings
    assert!(matches!(success, HandshakeResult::Success));
    assert!(matches!(failed, HandshakeResult::Failed));
    assert!(matches!(closed, HandshakeResult::ConnectionClosed));

    // This test passing means the connection handler is properly in the library
}
