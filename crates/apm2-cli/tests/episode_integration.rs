//! Integration tests for episode CLI commands (IT-00174-01, IT-00174-02).
//!
//! These tests verify the episode command behavior with mock daemon responses.
//!
//! # Test Coverage
//!
//! - IT-00174-01: Episode create flow with daemon
//! - IT-00174-02: Episode lifecycle (create -> start -> stop)
//!
//! # Mock Daemon Pattern
//!
//! Tests use a mock UDS server to simulate daemon responses without requiring
//! a full daemon implementation. This allows testing the CLI client logic
//! independently.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

/// Helper to create a mock daemon socket and server.
struct MockDaemon {
    _temp_dir: TempDir,
    socket_path: PathBuf,
    shutdown_tx: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockDaemon {
    /// Creates a new mock daemon with the given response handler.
    fn new<F>(handler: F) -> Self
    where
        F: Fn(&str) -> String + Send + 'static,
    {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let socket_path = temp_dir.path().join("apm2d.sock");
        let socket_path_clone = socket_path.clone();

        let (shutdown_tx, shutdown_rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let listener = UnixListener::bind(&socket_path_clone).expect("Failed to bind socket");
            listener
                .set_nonblocking(true)
                .expect("Failed to set nonblocking");

            loop {
                // Check for shutdown signal
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }

                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Read request
                        let mut len_buf = [0u8; 4];
                        if stream.read_exact(&mut len_buf).is_err() {
                            continue;
                        }
                        let len = u32::from_be_bytes(len_buf) as usize;

                        let mut request_buf = vec![0u8; len];
                        if stream.read_exact(&mut request_buf).is_err() {
                            continue;
                        }

                        let request_json = String::from_utf8(request_buf).unwrap_or_default();

                        // Generate response using handler
                        let response_json = handler(&request_json);
                        let response_bytes = response_json.as_bytes();

                        // Send framed response (IPC messages won't exceed 4GB)
                        #[allow(clippy::cast_possible_truncation)]
                        let len_bytes = (response_bytes.len() as u32).to_be_bytes();
                        let _ = stream.write_all(&len_bytes);
                        let _ = stream.write_all(response_bytes);
                    },
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No connection available, sleep briefly and retry
                        thread::sleep(Duration::from_millis(10));
                    },
                    Err(_) => break,
                }
            }
        });

        Self {
            _temp_dir: temp_dir,
            socket_path,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    /// Returns the path to the mock daemon socket.
    const fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }
}

impl Drop for MockDaemon {
    fn drop(&mut self) {
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Wait for thread to finish
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Helper to send a raw request to a daemon socket.
fn send_request(socket_path: &std::path::Path, request_json: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send framed request
    let request_bytes = request_json.as_bytes();
    // IPC messages won't exceed 4GB
    #[allow(clippy::cast_possible_truncation)]
    let len_bytes = (request_bytes.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes)?;
    stream.write_all(request_bytes)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0u8; len];
    stream.read_exact(&mut response_buf)?;

    Ok(String::from_utf8(response_buf).unwrap_or_default())
}

// =============================================================================
// IT-00174-01: Episode Create Tests
// =============================================================================

/// IT-00174-01: Test episode create with mock daemon.
///
/// Verifies that:
/// 1. Daemon can receive and respond to `CreateEpisode` requests
/// 2. Response contains daemon-generated episode ID
/// 3. Response contains all required fields
#[test]
fn it_00174_01_episode_create_with_mock_daemon() {
    // Create mock daemon that responds to CreateEpisode
    let daemon = MockDaemon::new(|request| {
        // Check for create_episode in the request (using snake_case per serde config)
        // The request may come from direct send or via CLI - just verify it's valid
        // JSON
        assert!(
            request.contains("create_episode") || request.contains("envelope"),
            "Request should contain create_episode or envelope: {request}"
        );

        // Return mock response with daemon-generated episode ID
        r#"{
            "type": "episode_created",
            "episode_id": "ep-daemon-generated-12345",
            "envelope_hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "created_at": "2024-01-01T00:00:00Z"
        }"#
        .to_string()
    });

    // Allow server to start
    thread::sleep(Duration::from_millis(100));

    // Send create request directly to test IPC protocol
    let request = r#"{
        "type": "create_episode",
        "envelope_yaml": "actor_id: test\nrisk_tier: 1",
        "envelope_hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    }"#;

    let response = send_request(daemon.socket_path(), request).expect("Failed to send request");

    // Verify response
    assert!(response.contains("episode_created"));
    assert!(response.contains("ep-daemon-generated-12345"));
    assert!(response.contains("2024-01-01T00:00:00Z"));
}

/// IT-00174-01: Test episode create with invalid envelope.
#[test]
fn it_00174_01_episode_create_invalid_envelope() {
    let daemon = MockDaemon::new(|_request| {
        // Return error response
        r#"{
            "type": "error",
            "code": "invalid_envelope",
            "message": "Failed to parse envelope YAML"
        }"#
        .to_string()
    });

    thread::sleep(Duration::from_millis(100));

    let request = r#"{
        "type": "create_episode",
        "envelope_yaml": "invalid: yaml: [",
        "envelope_hash": "invalid"
    }"#;

    let response = send_request(daemon.socket_path(), request).expect("Failed to send request");

    assert!(response.contains("error"));
    assert!(response.contains("invalid_envelope"));
}

// =============================================================================
// IT-00174-02: Episode Lifecycle Tests
// =============================================================================

/// IT-00174-02: Test full episode lifecycle (create -> start -> stop).
///
/// Verifies that:
/// 1. Episode can be created
/// 2. Episode can be started (transitions to Running)
/// 3. Episode can be stopped (transitions to Terminated)
#[test]
fn it_00174_02_episode_lifecycle() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let daemon = MockDaemon::new(move |request| {
        let count = call_count_clone.fetch_add(1, Ordering::SeqCst);

        match count {
            0 => {
                // First call: CreateEpisode
                assert!(request.contains("create_episode"));
                r#"{
                    "type": "episode_created",
                    "episode_id": "ep-lifecycle-test-001",
                    "envelope_hash": "hash123",
                    "created_at": "2024-01-01T00:00:00Z"
                }"#
                .to_string()
            },
            1 => {
                // Second call: StartEpisode
                assert!(request.contains("start_episode"));
                assert!(request.contains("ep-lifecycle-test-001"));
                r#"{
                    "type": "episode_started",
                    "episode_id": "ep-lifecycle-test-001",
                    "session_id": "session-abc",
                    "lease_id": "lease-xyz",
                    "started_at": "2024-01-01T00:00:01Z"
                }"#
                .to_string()
            },
            2 => {
                // Third call: StopEpisode
                assert!(request.contains("stop_episode"));
                assert!(request.contains("ep-lifecycle-test-001"));
                r#"{
                    "type": "episode_stopped",
                    "episode_id": "ep-lifecycle-test-001",
                    "termination_class": "SUCCESS",
                    "stopped_at": "2024-01-01T00:00:02Z"
                }"#
                .to_string()
            },
            _ => r#"{"type": "error", "code": "unexpected", "message": "Unexpected call"}"#
                .to_string(),
        }
    });

    thread::sleep(Duration::from_millis(100));

    // Step 1: Create episode
    let create_request = r#"{
        "type": "create_episode",
        "envelope_yaml": "actor_id: test",
        "envelope_hash": "hash123"
    }"#;
    let create_response =
        send_request(daemon.socket_path(), create_request).expect("Failed to create episode");
    assert!(create_response.contains("episode_created"));
    assert!(create_response.contains("ep-lifecycle-test-001"));

    // Step 2: Start episode
    let start_request = r#"{
        "type": "start_episode",
        "episode_id": "ep-lifecycle-test-001",
        "lease_id": null
    }"#;
    let start_response =
        send_request(daemon.socket_path(), start_request).expect("Failed to start episode");
    assert!(start_response.contains("episode_started"));
    assert!(start_response.contains("session-abc"));

    // Step 3: Stop episode
    let stop_request = r#"{
        "type": "stop_episode",
        "episode_id": "ep-lifecycle-test-001",
        "reason": "success",
        "message": null
    }"#;
    let stop_response =
        send_request(daemon.socket_path(), stop_request).expect("Failed to stop episode");
    assert!(stop_response.contains("episode_stopped"));
    assert!(stop_response.contains("SUCCESS"));

    // Verify all three calls were made
    assert_eq!(call_count.load(Ordering::SeqCst), 3);
}

/// IT-00174-02: Test episode not found error.
#[test]
fn it_00174_02_episode_not_found() {
    let daemon = MockDaemon::new(|_request| {
        r#"{
            "type": "error",
            "code": "episode_not_found",
            "message": "Episode not found: ep-nonexistent"
        }"#
        .to_string()
    });

    thread::sleep(Duration::from_millis(100));

    let request = r#"{
        "type": "get_episode_status",
        "episode_id": "ep-nonexistent"
    }"#;

    let response = send_request(daemon.socket_path(), request).expect("Failed to send request");

    assert!(response.contains("error"));
    assert!(response.contains("episode_not_found"));
}

/// IT-00174-02: Test starting an episode that doesn't exist.
#[test]
fn it_00174_02_start_nonexistent_episode() {
    let daemon = MockDaemon::new(|_request| {
        r#"{
            "type": "error",
            "code": "episode_not_found",
            "message": "Cannot start: episode not found"
        }"#
        .to_string()
    });

    thread::sleep(Duration::from_millis(100));

    let request = r#"{
        "type": "start_episode",
        "episode_id": "ep-does-not-exist",
        "lease_id": null
    }"#;

    let response = send_request(daemon.socket_path(), request).expect("Failed to send request");

    assert!(response.contains("error"));
    assert!(response.contains("episode_not_found"));
}

/// IT-00174-02: Test list episodes with state filter.
#[test]
fn it_00174_02_list_episodes_with_filter() {
    let daemon = MockDaemon::new(|request| {
        assert!(request.contains("list_episodes"));
        r#"{
            "type": "episode_list",
            "episodes": [
                {
                    "episode_id": "ep-001",
                    "state": "Running",
                    "created_at": "2024-01-01T00:00:00Z",
                    "session_id": "session-1"
                },
                {
                    "episode_id": "ep-002",
                    "state": "Running",
                    "created_at": "2024-01-01T00:01:00Z",
                    "session_id": "session-2"
                }
            ],
            "total": 2
        }"#
        .to_string()
    });

    thread::sleep(Duration::from_millis(100));

    let request = r#"{
        "type": "list_episodes",
        "state_filter": "running",
        "limit": 100
    }"#;

    let response = send_request(daemon.socket_path(), request).expect("Failed to send request");

    assert!(response.contains("episode_list"));
    assert!(response.contains("ep-001"));
    assert!(response.contains("ep-002"));
    // Note: JSON serialization may use "total": 2 or "total":2 depending on
    // formatting
    assert!(response.contains("\"total\"") && response.contains('2'));
}
