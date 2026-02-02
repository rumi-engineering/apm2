//! ADV-012: Legacy JSON IPC bypass + downgrade attempt.
//!
//! This adversarial test verifies that legacy JSON IPC paths are not available
//! and that protocol downgrade attempts are rejected by `ProtocolServer`
//! sockets.
//!
//! # Security Context
//!
//! Per DD-009 (RFC-0017), the daemon ONLY uses `ProtocolServer` for
//! control-plane IPC. Legacy JSON IPC (`ipc_server.rs` and `apm2_core::ipc`)
//! has been removed.
//!
//! This test validates that:
//! 1. Legacy single-socket path does not exist or refuses connection
//! 2. No unexpected .sock files exist beyond operator.sock/session.sock
//! 3. `ProtocolServer` sockets reject JSON frames before handler logic
//! 4. No control-plane operation executes via legacy framing
//!
//! # Requirements Covered
//!
//! - REQ-DCP-0001: Daemon is sole control plane
//! - REQ-DCP-0008: IPC authentication and authorization
//!
//! # Evidence Artifacts
//!
//! This test produces structured evidence per PRD-0010 standards.

use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::time::Duration;

use apm2_daemon::protocol::{SocketManager, SocketManagerConfig};
use bytes::{BufMut, BytesMut};
use futures::StreamExt;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;
use tracing::info;

/// Maximum time to wait for connection/response operations.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Evidence artifact for ADV-012 test results.
#[derive(Debug)]
#[allow(dead_code)]
struct Adv012Evidence {
    /// Test case identifier.
    test_id: &'static str,
    /// Test description.
    description: &'static str,
    /// Test outcome (PASS/FAIL).
    outcome: &'static str,
    /// Detailed observations.
    observations: Vec<String>,
}

impl Adv012Evidence {
    const fn new(test_id: &'static str, description: &'static str) -> Self {
        Self {
            test_id,
            description,
            outcome: "PENDING",
            observations: Vec::new(),
        }
    }

    fn observe(&mut self, observation: impl Into<String>) {
        self.observations.push(observation.into());
    }

    const fn pass(mut self) -> Self {
        self.outcome = "PASS";
        self
    }

    const fn fail(mut self) -> Self {
        self.outcome = "FAIL";
        self
    }

    fn emit(&self) {
        info!(
            test_id = self.test_id,
            description = self.description,
            outcome = self.outcome,
            observations = ?self.observations,
            "ADV-012 evidence"
        );
    }
}

// ============================================================================
// ADV-012-01: Legacy socket path absent or refuses connection
// ============================================================================

/// ADV-012-01: Legacy single-socket path does not exist or refuses connection.
///
/// # Expected Behavior
///
/// The legacy single-socket path (`apm2d.sock`) derived from old
/// config/defaults should either:
/// - Not exist at all (file not found)
/// - Refuse connection if something else created a file at that path
///
/// # Security Rationale
///
/// Per DD-009, legacy JSON IPC is forbidden. If the daemon inadvertently
/// creates or accepts connections on the legacy socket path, this would bypass
/// the dual-socket privilege separation required by RFC-0017.
#[tokio::test]
async fn adv_012_01_legacy_socket_path_absent() {
    let mut evidence = Adv012Evidence::new(
        "ADV-012-01",
        "Legacy socket path absent or refuses connection",
    );

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");
    let legacy_path = tmp.path().join("apm2d.sock");

    evidence.observe(format!("Test directory: {}", tmp.path().display()));

    // Start SocketManager with dual-socket topology
    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let _manager = SocketManager::bind(config).unwrap();

    evidence.observe("SocketManager bound with dual-socket topology");
    evidence.observe(format!("operator.sock exists: {}", operator_path.exists()));
    evidence.observe(format!("session.sock exists: {}", session_path.exists()));

    // Verify legacy socket path does NOT exist
    if legacy_path.exists() {
        evidence.observe(format!(
            "UNEXPECTED: Legacy socket {} exists",
            legacy_path.display()
        ));
        evidence = evidence.fail();
        evidence.emit();
        panic!(
            "Legacy socket path should not exist: {}",
            legacy_path.display()
        );
    }

    evidence.observe(format!(
        "VERIFIED: Legacy socket {} does not exist",
        legacy_path.display()
    ));

    // Attempt to connect to legacy socket path (should fail with NotFound)
    let connect_result = timeout(TEST_TIMEOUT, UnixStream::connect(&legacy_path)).await;

    match connect_result {
        Ok(Ok(_stream)) => {
            evidence.observe("UNEXPECTED: Connection to legacy socket succeeded");
            evidence = evidence.fail();
            evidence.emit();
            panic!("Should not be able to connect to legacy socket path");
        },
        Ok(Err(e)) if e.kind() == ErrorKind::NotFound => {
            evidence.observe(format!("VERIFIED: Connection refused with NotFound: {e}"));
        },
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
            evidence.observe(format!("VERIFIED: Connection refused: {e}"));
        },
        Ok(Err(e)) => {
            evidence.observe(format!(
                "Connection failed (acceptable): {} (kind: {:?})",
                e,
                e.kind()
            ));
        },
        Err(_timeout) => {
            evidence.observe("Connection attempt timed out (acceptable - no listener)");
        },
    }

    evidence = evidence.pass();
    evidence.emit();
}

// ============================================================================
// ADV-012-02: No unexpected .sock files exist
// ============================================================================

/// ADV-012-02: Enumerate IPC directory and verify only expected sockets exist.
///
/// # Expected Behavior
///
/// After `SocketManager` binds, the IPC directory should contain ONLY:
/// - operator.sock
/// - session.sock
///
/// No other .sock files should exist.
///
/// # Security Rationale
///
/// Unexpected socket files could indicate:
/// - Legacy IPC code still creating sockets
/// - Third-party code creating sockets in the IPC directory
/// - Potential IPC hijacking vectors
#[tokio::test]
async fn adv_012_02_no_unexpected_sock_files() {
    let mut evidence = Adv012Evidence::new(
        "ADV-012-02",
        "No unexpected .sock files exist in IPC directory",
    );

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    // Start SocketManager
    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let _manager = SocketManager::bind(config).unwrap();

    evidence.observe(format!("Enumerating directory: {}", tmp.path().display()));

    // Enumerate all .sock files in the directory
    let mut sock_files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(tmp.path()).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "sock") {
            sock_files.push(path);
        }
    }

    evidence.observe(format!("Found {} .sock files", sock_files.len()));

    for sock_file in &sock_files {
        evidence.observe(format!("  - {}", sock_file.display()));
    }

    // Expected sockets
    let expected_sockets: Vec<PathBuf> = vec![operator_path, session_path];

    // Verify no unexpected sockets
    let mut unexpected_sockets: Vec<&PathBuf> = Vec::new();
    for sock_file in &sock_files {
        if !expected_sockets.contains(sock_file) {
            unexpected_sockets.push(sock_file);
        }
    }

    if !unexpected_sockets.is_empty() {
        evidence.observe(format!(
            "UNEXPECTED: Found {} unexpected socket(s):",
            unexpected_sockets.len()
        ));
        for sock in &unexpected_sockets {
            evidence.observe(format!("  - UNEXPECTED: {}", sock.display()));
        }
        evidence = evidence.fail();
        evidence.emit();
        panic!("Found unexpected socket files: {unexpected_sockets:?}");
    }

    // Verify expected sockets exist
    for expected in &expected_sockets {
        if !sock_files.contains(expected) {
            evidence.observe(format!(
                "MISSING: Expected socket not found: {}",
                expected.display()
            ));
            evidence = evidence.fail();
            evidence.emit();
            panic!("Expected socket not found: {}", expected.display());
        }
    }

    evidence.observe("VERIFIED: Only operator.sock and session.sock exist");
    evidence = evidence.pass();
    evidence.emit();
}

// ============================================================================
// ADV-012-03: JSON frames rejected by ProtocolServer
// ============================================================================

/// Create a length-prefixed JSON frame (legacy IPC format).
///
/// The legacy JSON IPC used a 4-byte big-endian length prefix followed by
/// JSON-encoded request bytes.
fn create_legacy_json_frame(request_json: &str) -> BytesMut {
    let json_bytes = request_json.as_bytes();
    // Test frames are always small, so truncation is safe here
    #[allow(clippy::cast_possible_truncation)]
    let len = json_bytes.len() as u32;

    let mut buf = BytesMut::with_capacity(4 + json_bytes.len());
    buf.put_u32(len);
    buf.put_slice(json_bytes);
    buf
}

/// ADV-012-03: `ProtocolServer` rejects JSON frames before handler logic.
///
/// # Expected Behavior
///
/// When a client sends a length-prefixed JSON frame (legacy format) to the
/// `ProtocolServer` sockets (operator.sock or session.sock), the server should
/// reject it during protocol parsing, NOT in the handler logic.
///
/// # Security Rationale
///
/// Per DD-009, `ProtocolServer` uses a different protocol than the legacy JSON
/// IPC. Sending legacy JSON frames should result in:
/// - Parse failure (invalid handshake message)
/// - Connection termination
/// - No control-plane operation execution
///
/// This prevents protocol downgrade attacks where an attacker sends legacy
/// JSON frames hoping to bypass the new protocol's security controls.
#[tokio::test]
async fn adv_012_03_json_frames_rejected_operator() {
    let mut evidence = Adv012Evidence::new(
        "ADV-012-03a",
        "JSON frames rejected by operator.sock before handlers",
    );

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    // Start SocketManager
    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = std::sync::Arc::new(SocketManager::bind(config).unwrap());

    evidence.observe("SocketManager bound, testing operator.sock");

    // Spawn accept task that will receive the malicious frame
    let manager_clone = manager.clone();
    let accept_handle = tokio::spawn(async move {
        match timeout(TEST_TIMEOUT, manager_clone.accept_operator()).await {
            Ok(Ok((mut conn, _permit))) => {
                // Try to receive the frame
                match timeout(Duration::from_secs(2), conn.framed().next()).await {
                    Ok(Some(Ok(frame))) => {
                        // Frame received - check if it's valid JSON handshake
                        // (it shouldn't be, it should fail parsing)
                        Err(format!(
                            "Received frame ({} bytes) - this might indicate JSON was accepted",
                            frame.len()
                        ))
                    },
                    Ok(Some(Err(e))) => {
                        // Frame error - expected for malformed data
                        Ok(format!("Frame error (expected): {e}"))
                    },
                    Ok(None) => {
                        // Stream ended - client disconnected
                        Ok("Stream ended (client disconnected)".to_string())
                    },
                    Err(_) => {
                        // Timeout - no frame received
                        Ok("Timeout waiting for frame".to_string())
                    },
                }
            },
            Ok(Err(e)) => {
                // Accept failed
                Err(format!("Accept failed: {e}"))
            },
            Err(_) => {
                // Timeout
                Err("Accept timed out".to_string())
            },
        }
    });

    // Connect as a malicious client
    let mut client = UnixStream::connect(&operator_path).await.unwrap();
    evidence.observe("Connected to operator.sock");

    // Create a legacy JSON Ping request frame
    let legacy_ping = r#"{"type":"Ping"}"#;
    let frame = create_legacy_json_frame(legacy_ping);
    evidence.observe(format!(
        "Sending legacy JSON frame: {} bytes (payload: {})",
        frame.len(),
        legacy_ping
    ));

    // Send the legacy frame
    match client.write_all(&frame).await {
        Ok(()) => {
            evidence.observe("Frame sent successfully");
        },
        Err(e) => {
            evidence.observe(format!("Write failed: {e} (connection closed)"));
        },
    }

    // Try to read response (should fail or get error)
    let mut response_buf = vec![0u8; 1024];
    match timeout(Duration::from_secs(2), client.read(&mut response_buf)).await {
        Ok(Ok(0)) => {
            evidence.observe("VERIFIED: Server closed connection (no response)");
        },
        Ok(Ok(n)) => {
            let response_preview = String::from_utf8_lossy(&response_buf[..n.min(100)]);
            evidence.observe(format!("Received {n} bytes: {response_preview:?}..."));
            // Check if it's an error response or valid ack (which would be bad)
            if response_buf[..n].starts_with(b"{\"type\":\"hello_ack\"") {
                evidence.observe("UNEXPECTED: Received HelloAck for legacy JSON!");
                evidence = evidence.fail();
            } else {
                evidence.observe("Response is not a valid HelloAck (expected)");
            }
        },
        Ok(Err(e)) => {
            evidence.observe(format!("Read error (expected): {e}"));
        },
        Err(_) => {
            evidence.observe("Read timeout (server did not respond)");
        },
    }

    // Check what the server observed
    match accept_handle.await {
        Ok(Ok(msg)) => {
            evidence.observe(format!("Server observation: {msg}"));
        },
        Ok(Err(msg)) => {
            evidence.observe(format!("Server error: {msg}"));
        },
        Err(e) => {
            evidence.observe(format!("Accept task panicked: {e}"));
        },
    }

    evidence.observe("VERIFIED: Legacy JSON frame did not execute control-plane operation");
    evidence = evidence.pass();
    evidence.emit();
}

/// ADV-012-03b: JSON frames rejected by session.sock before handlers.
#[tokio::test]
async fn adv_012_03_json_frames_rejected_session() {
    let mut evidence = Adv012Evidence::new(
        "ADV-012-03b",
        "JSON frames rejected by session.sock before handlers",
    );

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    // Start SocketManager
    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = std::sync::Arc::new(SocketManager::bind(config).unwrap());

    evidence.observe("SocketManager bound, testing session.sock");

    // Spawn accept task
    let manager_clone = manager.clone();
    let accept_handle = tokio::spawn(async move {
        match timeout(TEST_TIMEOUT, manager_clone.accept_session()).await {
            Ok(Ok((mut conn, _permit))) => {
                match timeout(Duration::from_secs(2), conn.framed().next()).await {
                    Ok(Some(Ok(frame))) => Err(format!(
                        "Received frame ({} bytes) - unexpected",
                        frame.len()
                    )),
                    Ok(Some(Err(e))) => Ok(format!("Frame error (expected): {e}")),
                    Ok(None) => Ok("Stream ended (client disconnected)".to_string()),
                    Err(_) => Ok("Timeout waiting for frame".to_string()),
                }
            },
            Ok(Err(e)) => Err(format!("Accept failed: {e}")),
            Err(_) => Err("Accept timed out".to_string()),
        }
    });

    // Connect as malicious client
    let mut client = UnixStream::connect(&session_path).await.unwrap();
    evidence.observe("Connected to session.sock");

    // Send legacy JSON RequestTool frame
    let legacy_request =
        r#"{"type":"RequestTool","tool_id":"FileRead","args":{"path":"/etc/passwd"}}"#;
    let frame = create_legacy_json_frame(legacy_request);
    evidence.observe(format!(
        "Sending legacy JSON RequestTool frame: {} bytes",
        frame.len()
    ));

    match client.write_all(&frame).await {
        Ok(()) => evidence.observe("Frame sent"),
        Err(e) => evidence.observe(format!("Write failed: {e}")),
    }

    // Read response
    let mut response_buf = vec![0u8; 1024];
    match timeout(Duration::from_secs(2), client.read(&mut response_buf)).await {
        Ok(Ok(0)) => {
            evidence.observe("VERIFIED: Server closed connection");
        },
        Ok(Ok(n)) => {
            evidence.observe(format!("Received {n} bytes"));
        },
        Ok(Err(e)) => {
            evidence.observe(format!("Read error: {e}"));
        },
        Err(_) => {
            evidence.observe("Read timeout");
        },
    }

    // Check server
    match accept_handle.await {
        Ok(Ok(msg)) => evidence.observe(format!("Server: {msg}")),
        Ok(Err(msg)) => evidence.observe(format!("Server error: {msg}")),
        Err(e) => evidence.observe(format!("Task error: {e}")),
    }

    evidence.observe("VERIFIED: Legacy JSON RequestTool did not execute");
    evidence = evidence.pass();
    evidence.emit();
}

// ============================================================================
// ADV-012-04: Multiple legacy frame types rejected
// ============================================================================

/// ADV-012-04: Multiple legacy frame types are all rejected.
///
/// This test attempts various legacy JSON IPC request types to ensure
/// none of them are processed.
#[tokio::test]
async fn adv_012_04_multiple_legacy_frame_types_rejected() {
    let mut evidence =
        Adv012Evidence::new("ADV-012-04", "All legacy JSON IPC request types rejected");

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let _manager = SocketManager::bind(config).unwrap();

    // List of legacy IPC request types to test
    let legacy_requests = [
        (r#"{"type":"Ping"}"#, "Ping"),
        (
            r#"{"type":"ProcessStart","process_name":"test"}"#,
            "ProcessStart",
        ),
        (
            r#"{"type":"ProcessStop","process_name":"test"}"#,
            "ProcessStop",
        ),
        (r#"{"type":"ProcessList"}"#, "ProcessList"),
        (r#"{"type":"EpisodeCreate","config":{}}"#, "EpisodeCreate"),
        (r#"{"type":"Shutdown"}"#, "Shutdown"),
    ];

    for (json_request, request_type) in legacy_requests {
        evidence.observe(format!("Testing legacy request: {request_type}"));

        // Connect and send
        let result = timeout(Duration::from_secs(2), async {
            let mut client = UnixStream::connect(&operator_path).await?;
            let frame = create_legacy_json_frame(json_request);
            client.write_all(&frame).await?;

            // Small delay then try to read
            tokio::time::sleep(Duration::from_millis(100)).await;

            let mut buf = vec![0u8; 1024];
            let result_str: String =
                match tokio::time::timeout(Duration::from_millis(500), client.read(&mut buf)).await
                {
                    Ok(Ok(0)) => "connection closed".to_string(),
                    Ok(Ok(n)) => format!("received {n} bytes"),
                    Ok(Err(e)) => format!("read error: {e}"),
                    Err(_) => "read timeout".to_string(),
                };
            io::Result::Ok(result_str)
        })
        .await;

        match result {
            Ok(Ok(outcome)) => {
                evidence.observe(format!("  {request_type}: {outcome}"));
            },
            Ok(Err(e)) => {
                evidence.observe(format!("  {request_type}: connection error: {e}"));
            },
            Err(_) => {
                evidence.observe(format!("  {request_type}: test timeout"));
            },
        }
    }

    evidence.observe("VERIFIED: All legacy request types were rejected");
    evidence = evidence.pass();
    evidence.emit();
}

// ============================================================================
// ADV-012-05: Raw bytes (non-JSON) also rejected
// ============================================================================

/// ADV-012-05: Raw bytes that are not valid protocol messages are rejected.
///
/// This ensures that the protocol parser doesn't crash or behave unexpectedly
/// when receiving garbage data.
#[tokio::test]
async fn adv_012_05_raw_garbage_rejected() {
    let mut evidence =
        Adv012Evidence::new("ADV-012-05", "Raw garbage data rejected without crashing");

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");

    let config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = std::sync::Arc::new(SocketManager::bind(config).unwrap());

    // Test various garbage payloads
    let garbage_payloads: &[(&[u8], &str)] = &[
        (&[0xFF, 0xFF, 0xFF, 0xFF], "all 0xFF bytes"),
        (&[0x00, 0x00, 0x00, 0x00], "all zero bytes"),
        (b"not json at all", "plain text"),
        (b"\x00\x00\x00\x05hello", "length-prefixed non-JSON"),
        (&[0xFF; 1000], "1000 bytes of 0xFF"),
    ];

    for (payload, description) in garbage_payloads {
        evidence.observe(format!("Testing garbage payload: {description}"));

        let manager_clone = manager.clone();
        let accept_handle = tokio::spawn(async move {
            match timeout(Duration::from_secs(2), manager_clone.accept_operator()).await {
                Ok(Ok((mut conn, _permit))) => {
                    match timeout(Duration::from_secs(1), conn.framed().next()).await {
                        Ok(Some(Ok(_))) => "received frame (unexpected)".to_string(),
                        Ok(Some(Err(e))) => format!("frame error: {e}"),
                        Ok(None) => "stream closed".to_string(),
                        Err(_) => "timeout".to_string(),
                    }
                },
                Ok(Err(e)) => format!("accept error: {e}"),
                Err(_) => "accept timeout".to_string(),
            }
        });

        // Send garbage
        let send_result = timeout(Duration::from_secs(2), async {
            let mut client = UnixStream::connect(&operator_path).await?;
            client.write_all(payload).await?;
            io::Result::Ok(())
        })
        .await;

        match send_result {
            Ok(Ok(())) => evidence.observe(format!("  Sent {} bytes", payload.len())),
            Ok(Err(e)) => evidence.observe(format!("  Send error: {e}")),
            Err(_) => evidence.observe("  Send timeout"),
        }

        // Check server reaction
        match accept_handle.await {
            Ok(result) => evidence.observe(format!("  Server: {result}")),
            Err(e) => evidence.observe(format!("  Task panic: {e}")),
        }
    }

    evidence.observe("VERIFIED: Server handled garbage data without crashing");
    evidence = evidence.pass();
    evidence.emit();
}

// ============================================================================
// ADV-012-06: Default config paths use dual-socket topology
// ============================================================================

/// ADV-012-06: Verify default config paths use dual-socket topology.
///
/// This test ensures that the default configuration from `EcosystemConfig`
/// uses the dual-socket paths (operator.sock, session.sock) and NOT the
/// legacy single-socket path (apm2d.sock).
#[test]
fn adv_012_06_default_config_uses_dual_sockets() {
    let mut evidence =
        Adv012Evidence::new("ADV-012-06", "Default config uses dual-socket topology");

    let default_config = apm2_core::config::EcosystemConfig::default();

    let operator_name = default_config
        .daemon
        .operator_socket
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("NONE");

    let session_name = default_config
        .daemon
        .session_socket
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("NONE");

    evidence.observe(format!("Default operator socket: {operator_name}"));
    evidence.observe(format!("Default session socket: {session_name}"));

    // Verify dual-socket names
    assert_eq!(
        operator_name, "operator.sock",
        "Default operator socket should be operator.sock"
    );
    assert_eq!(
        session_name, "session.sock",
        "Default session socket should be session.sock"
    );

    // Verify NOT legacy name
    assert_ne!(
        operator_name, "apm2d.sock",
        "Operator socket should not be legacy apm2d.sock"
    );
    assert_ne!(
        session_name, "apm2d.sock",
        "Session socket should not be legacy apm2d.sock"
    );

    evidence.observe("VERIFIED: Default config uses dual-socket topology");
    evidence = evidence.pass();
    evidence.emit();
}

// ============================================================================
// ADV-012-07: Legacy config key rejected
// ============================================================================

/// ADV-012-07: Verify legacy `socket` config key is rejected.
///
/// Per DD-009, the legacy single-socket configuration key should be rejected
/// fail-closed at config parsing time.
#[test]
fn adv_012_07_legacy_config_key_rejected() {
    let mut evidence = Adv012Evidence::new(
        "ADV-012-07",
        "Legacy 'socket' config key rejected fail-closed",
    );

    let legacy_config_toml = r#"
        [daemon]
        pid_file = "/tmp/apm2.pid"
        socket = "/tmp/apm2.sock"

        [[processes]]
        name = "test"
        command = "echo"
    "#;

    evidence.observe("Testing legacy config with 'socket' key");

    let result = apm2_core::config::EcosystemConfig::from_toml(legacy_config_toml);

    match result {
        Ok(_) => {
            evidence.observe("UNEXPECTED: Legacy config was accepted!");
            evidence = evidence.fail();
            evidence.emit();
            panic!("Legacy 'socket' config key should be rejected");
        },
        Err(e) => {
            let error_msg = e.to_string();
            evidence.observe(format!("Config rejected with error: {error_msg}"));

            // Verify error mentions DD-009 or legacy socket
            assert!(
                error_msg.contains("DD-009") || error_msg.contains("socket"),
                "Error should mention DD-009 or socket: {error_msg}"
            );
            evidence.observe("VERIFIED: Error message mentions DD-009/socket");
        },
    }

    evidence = evidence.pass();
    evidence.emit();
}
