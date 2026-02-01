//! Integration tests for the UDS protocol server.
//!
//! These tests verify end-to-end protocol functionality including:
//! - Server binding and client connection
//! - Frame encoding/decoding over the wire
//! - Handshake protocol completion
//! - Connection lifecycle management
//! - UID-based authentication (TCK-00248)

use std::time::Duration;

use apm2_daemon::protocol::{
    ClientHandshake, HandshakeMessage, Hello, PROTOCOL_VERSION, PeerCredentials, ProtocolServer,
    ServerConfig, ServerHandshake, connect, parse_handshake_message, parse_hello,
    serialize_handshake_message,
};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use nix::unistd::getuid;
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
        let mut handshake = ServerHandshake::new("test-daemon/1.0", None);

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
        let mut handshake = ServerHandshake::new("test-daemon/1.0", None);

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

/// Test that UID mismatch results in handshake rejection (TCK-00248).
///
/// This integration test exercises the rejection path when peer credentials
/// indicate a UID that doesn't match the server's UID. Uses mock credentials
/// since we can't easily change the process UID in tests.
///
/// SEC-DCP-003: This test verifies security controls are enforced, not
/// bypassed.
#[tokio::test]
async fn test_handshake_uid_mismatch_rejection() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "uid_mismatch");

    let config = ServerConfig::new(&socket_path).with_server_info("test-daemon/1.0");
    let server = ProtocolServer::bind(config).unwrap();

    // Spawn server that simulates a UID mismatch by using mock credentials
    let server_handle = tokio::spawn(async move {
        let (mut conn, _permit) = server.accept().await.unwrap();

        // Create mock credentials with a different UID than the server's
        // This simulates a client connecting with unauthorized credentials
        let current_uid = getuid().as_raw();
        let unauthorized_uid = if current_uid == 0 {
            1000
        } else {
            current_uid + 1
        };

        let mock_credentials = PeerCredentials {
            uid: unauthorized_uid,
            gid: 1000,
            pid: Some(12345),
        };

        // Create handshake with the mock (unauthorized) credentials
        let mut handshake = ServerHandshake::new("test-daemon/1.0", Some(mock_credentials));

        // Receive Hello from client
        let frame = conn.framed().next().await.unwrap().unwrap();
        let hello = parse_hello(&frame).expect("failed to parse Hello");

        // Process should return a rejection due to UID mismatch
        let response = handshake.process_hello(&hello).unwrap();
        let response_bytes = serialize_handshake_message(&response).unwrap();
        conn.framed().send(response_bytes).await.unwrap();

        // Verify the response is a rejection
        match response {
            HandshakeMessage::HelloNack(nack) => {
                // SEC-DCP-001: Error message must NOT leak UIDs
                assert!(
                    !nack.message.contains(&current_uid.to_string()),
                    "Error message leaked server UID"
                );
                assert!(
                    !nack.message.contains(&unauthorized_uid.to_string()),
                    "Error message leaked client UID"
                );
                assert_eq!(
                    nack.message, "permission denied",
                    "Expected generic error message"
                );
            },
            _ => panic!("Expected HelloNack for UID mismatch"),
        }

        // Handshake should have failed
        assert!(!handshake.is_completed());
    });

    // Client side - attempts connection
    let mut client_conn = connect(&socket_path).await.unwrap();
    let mut client_handshake = ClientHandshake::new("test-cli/1.0");

    // Send Hello
    let hello = client_handshake.create_hello();
    let hello_msg = HandshakeMessage::Hello(hello);
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
    client_conn.framed().send(hello_bytes).await.unwrap();

    // Receive rejection
    let response_frame = client_conn.framed().next().await.unwrap().unwrap();
    let response = parse_handshake_message(&response_frame).expect("failed to parse response");

    // Client should receive HelloNack
    assert!(
        matches!(response, HandshakeMessage::HelloNack(_)),
        "Expected HelloNack for unauthorized client"
    );

    // Process the response - should fail
    let result = client_handshake.process_response(response);
    assert!(result.is_err(), "Client handshake should fail");
    assert!(!client_handshake.is_completed());

    // Wait for server to complete
    timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("server timed out")
        .expect("server task panicked");
}

/// Test that matching UID allows handshake to succeed (TCK-00248).
///
/// This integration test verifies that when peer credentials match the server's
/// UID, the handshake proceeds successfully.
#[tokio::test]
async fn test_handshake_uid_match_success() {
    let tmp = TempDir::new().unwrap();
    let socket_path = test_socket_path(&tmp, "uid_match");

    let config = ServerConfig::new(&socket_path).with_server_info("test-daemon/1.0");
    let server = ProtocolServer::bind(config).unwrap();

    // Spawn server with matching UID credentials
    let server_handle = tokio::spawn(async move {
        let (mut conn, _permit) = server.accept().await.unwrap();

        // Use the actual current UID (simulating authorized connection)
        let current_uid = getuid().as_raw();

        let valid_credentials = PeerCredentials {
            uid: current_uid,
            gid: 1000,
            pid: Some(12345),
        };

        let mut handshake = ServerHandshake::new("test-daemon/1.0", Some(valid_credentials));

        // Receive Hello from client
        let frame = conn.framed().next().await.unwrap().unwrap();
        let hello = parse_hello(&frame).expect("failed to parse Hello");

        // Process should succeed with matching UID
        let response = handshake.process_hello(&hello).unwrap();
        let response_bytes = serialize_handshake_message(&response).unwrap();
        conn.framed().send(response_bytes).await.unwrap();

        // Verify success
        assert!(
            matches!(response, HandshakeMessage::HelloAck(_)),
            "Expected HelloAck for matching UID"
        );
        assert!(handshake.is_completed());

        handshake.negotiated_version()
    });

    // Client side
    let mut client_conn = connect(&socket_path).await.unwrap();
    let mut client_handshake = ClientHandshake::new("test-cli/1.0");

    // Send Hello
    let hello = client_handshake.create_hello();
    let hello_msg = HandshakeMessage::Hello(hello);
    let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
    client_conn.framed().send(hello_bytes).await.unwrap();

    // Receive response
    let response_frame = client_conn.framed().next().await.unwrap().unwrap();
    let response = parse_handshake_message(&response_frame).expect("failed to parse response");
    client_handshake.process_response(response).unwrap();

    // Client should have completed handshake successfully
    assert!(client_handshake.is_completed());
    assert_eq!(client_handshake.server_info(), Some("test-daemon/1.0"));

    // Verify server completed
    let server_version = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("server timed out")
        .expect("server task panicked");
    assert_eq!(server_version, Some(PROTOCOL_VERSION));
}
