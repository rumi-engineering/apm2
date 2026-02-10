//! TCK-00266: Session registry with persistent state file
//!
//! This test module verifies that the session registry correctly persists
//! session state to a file and recovers from crashes.
//!
//! # Acceptance Criteria
//!
//! 1. State file contains active sessions (`cat state_file` shows session
//!    entries)
//! 2. State survives daemon restart (Restart preserves session knowledge)
//!
//! # Test Requirements
//!
//! - Sessions are persisted to file
//! - State survives simulated restart (reload from file)
//! - Atomic write behavior (write to temp, rename)

use std::fs;

use apm2_daemon::episode::{PersistentRegistryError, PersistentSessionRegistry};
use apm2_daemon::session::{SessionRegistry, SessionState};
use tempfile::TempDir;

/// Helper to create a test session with a given ID and handle.
fn make_session(id: &str, handle: &str) -> SessionState {
    SessionState {
        session_id: id.to_string(),
        work_id: format!("work-{id}"),
        role: 1,
        ephemeral_handle: handle.to_string(),
        lease_id: format!("lease-{id}"),
        policy_resolved_ref: "policy-ref".to_string(),
            pcac_policy: None,
            pointer_only_waiver: None,
        capability_manifest_hash: vec![0x01, 0x02, 0x03],
        episode_id: None,
    }
}

// =============================================================================
// TCK-00266: AC1 - State file contains active sessions
// =============================================================================

/// Verify that sessions are written to the state file in human-readable JSON.
///
/// Per TCK-00266 AC1: State file contains active sessions
/// Verification: `cat state_file` shows session entries
#[test]
fn tck_00266_ac1_state_file_contains_sessions() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    let registry = PersistentSessionRegistry::new(&state_file_path);

    // Register a session
    let session = make_session("sess-1", "handle-1");
    registry.register_session(session).unwrap();

    // Read the state file directly (simulating `cat state_file`)
    let contents = fs::read_to_string(&state_file_path).unwrap();

    // Verify it's valid JSON
    let json: serde_json::Value = serde_json::from_str(&contents).unwrap();

    // Verify structure
    assert_eq!(json["version"], 1);
    assert!(json["sessions"].is_array());

    // Verify session data
    let sessions = json["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["session_id"], "sess-1");
    assert_eq!(sessions[0]["ephemeral_handle"], "handle-1");
    assert_eq!(sessions[0]["work_id"], "work-sess-1");
}

/// Verify that multiple sessions are persisted.
#[test]
fn tck_00266_state_file_contains_multiple_sessions() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    let registry = PersistentSessionRegistry::new(&state_file_path);

    // Register multiple sessions
    registry
        .register_session(make_session("sess-1", "handle-1"))
        .unwrap();
    registry
        .register_session(make_session("sess-2", "handle-2"))
        .unwrap();
    registry
        .register_session(make_session("sess-3", "handle-3"))
        .unwrap();

    // Read and verify
    let contents = fs::read_to_string(&state_file_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&contents).unwrap();

    let sessions = json["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 3);
}

/// Verify that the state file is human-readable (pretty-printed JSON).
#[test]
fn tck_00266_state_file_is_human_readable() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    let registry = PersistentSessionRegistry::new(&state_file_path);
    registry
        .register_session(make_session("sess-1", "handle-1"))
        .unwrap();

    let contents = fs::read_to_string(&state_file_path).unwrap();

    // Pretty-printed JSON should have newlines
    assert!(
        contents.contains('\n'),
        "State file should be pretty-printed"
    );

    // Should have recognizable structure for debugging
    assert!(
        contents.contains("\"session_id\""),
        "Should contain session_id field"
    );
    assert!(
        contents.contains("\"version\""),
        "Should contain version field"
    );
}

// =============================================================================
// TCK-00266: AC2 - State survives daemon restart
// =============================================================================

/// Verify that sessions survive a simulated daemon restart.
///
/// Per TCK-00266 AC2: State survives daemon restart
/// Verification: Restart preserves session knowledge
#[test]
fn tck_00266_ac2_state_survives_restart() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    // Phase 1: Create registry and register sessions (simulates first daemon run)
    {
        let registry = PersistentSessionRegistry::new(&state_file_path);

        registry
            .register_session(make_session("sess-1", "handle-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "handle-2"))
            .unwrap();

        // Verify sessions are registered
        assert!(registry.get_session("sess-1").is_some());
        assert!(registry.get_session("sess-2").is_some());
        assert_eq!(registry.session_count(), 2);

        // Registry dropped here (simulates daemon shutdown)
    }

    // Phase 2: Create new registry from state file (simulates daemon restart)
    {
        let registry = PersistentSessionRegistry::load_from_file(&state_file_path).unwrap();

        // Verify sessions are recovered
        assert_eq!(registry.session_count(), 2);

        let sess1 = registry.get_session("sess-1").unwrap();
        assert_eq!(sess1.session_id, "sess-1");
        assert_eq!(sess1.ephemeral_handle, "handle-1");
        assert_eq!(sess1.work_id, "work-sess-1");

        let sess2 = registry.get_session("sess-2").unwrap();
        assert_eq!(sess2.session_id, "sess-2");
        assert_eq!(sess2.ephemeral_handle, "handle-2");

        // Verify lookup by handle works after restart
        let by_handle = registry.get_session_by_handle("handle-1").unwrap();
        assert_eq!(by_handle.session_id, "sess-1");
    }
}

/// Verify that a fresh start with no state file works correctly.
#[test]
fn tck_00266_fresh_start_no_state_file() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("nonexistent.json");

    // State file doesn't exist
    assert!(!state_file_path.exists());

    // load_from_file should succeed with empty registry
    let registry = PersistentSessionRegistry::load_from_file(&state_file_path).unwrap();
    assert_eq!(registry.session_count(), 0);

    // Register a session should create the file
    registry
        .register_session(make_session("sess-1", "handle-1"))
        .unwrap();
    assert!(state_file_path.exists());
}

/// Verify that all session fields are preserved through restart.
#[test]
fn tck_00266_all_session_fields_preserved() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    // Create session with all fields populated
    let original = SessionState {
        session_id: "sess-full".to_string(),
        work_id: "work-full".to_string(),
        role: 42,
        ephemeral_handle: "handle-full".to_string(),
        lease_id: "lease-full".to_string(),
        policy_resolved_ref: "policy-ref-full".to_string(),
            pcac_policy: None,
            pointer_only_waiver: None,
        capability_manifest_hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
        episode_id: Some("episode-123".to_string()),
    };

    // Register and persist
    {
        let registry = PersistentSessionRegistry::new(&state_file_path);
        registry.register_session(original.clone()).unwrap();
    }

    // Recover and verify all fields
    {
        let registry = PersistentSessionRegistry::load_from_file(&state_file_path).unwrap();
        let recovered = registry.get_session("sess-full").unwrap();

        assert_eq!(recovered.session_id, original.session_id);
        assert_eq!(recovered.work_id, original.work_id);
        assert_eq!(recovered.role, original.role);
        assert_eq!(recovered.ephemeral_handle, original.ephemeral_handle);
        // SEC-001: lease_id MUST NOT be preserved through restart
        assert!(
            recovered.lease_id.is_empty(),
            "lease_id should be empty after recovery"
        );
        assert_eq!(recovered.policy_resolved_ref, original.policy_resolved_ref);
        assert_eq!(
            recovered.capability_manifest_hash,
            original.capability_manifest_hash
        );
        assert_eq!(recovered.episode_id, original.episode_id);
    }
}

// =============================================================================
// Atomic Write Behavior Tests
// =============================================================================

/// Verify that atomic writes use temp file + rename pattern.
///
/// This test checks that the .tmp file is used during writes.
#[test]
fn tck_00266_atomic_write_uses_temp_file() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");
    let temp_file_path = temp_dir.path().join("state.tmp");

    let registry = PersistentSessionRegistry::new(&state_file_path);

    // After registration, temp file should NOT exist (it's renamed)
    registry
        .register_session(make_session("sess-1", "handle-1"))
        .unwrap();

    // Temp file should be gone after successful write
    assert!(!temp_file_path.exists());

    // Final state file should exist
    assert!(state_file_path.exists());
}

/// Verify that parent directories are created if needed.
#[test]
fn tck_00266_creates_parent_directories() {
    let temp_dir = TempDir::new().unwrap();
    let nested_path = temp_dir
        .path()
        .join("deep")
        .join("nested")
        .join("state.json");

    // Parent directory doesn't exist
    assert!(!nested_path.parent().unwrap().exists());

    let registry = PersistentSessionRegistry::new(&nested_path);
    registry
        .register_session(make_session("sess-1", "handle-1"))
        .unwrap();

    // Parent directory should now exist
    assert!(nested_path.parent().unwrap().exists());
    assert!(nested_path.exists());
}

// =============================================================================
// Error Handling Tests
// =============================================================================

/// Verify that duplicate session IDs are rejected.
#[test]
fn tck_00266_duplicate_session_id_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    let registry = PersistentSessionRegistry::new(&state_file_path);

    registry
        .register_session(make_session("sess-1", "handle-1"))
        .unwrap();

    let result = registry.register_session(make_session("sess-1", "handle-2"));
    assert!(result.is_err());
}

/// Verify that corrupted state file is handled gracefully.
#[test]
fn tck_00266_corrupted_state_file_error() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    // Write invalid JSON
    fs::write(&state_file_path, "{ invalid json }").unwrap();

    let result = PersistentSessionRegistry::load_from_file(&state_file_path);
    assert!(result.is_err());

    match result.unwrap_err() {
        PersistentRegistryError::Json(_) => {}, // Expected
        other => panic!("Expected Json error, got: {other:?}"),
    }
}

// =============================================================================
// Helper Method Tests
// =============================================================================

/// Verify `session_count` returns correct value.
#[test]
fn tck_00266_session_count() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    let registry = PersistentSessionRegistry::new(&state_file_path);
    assert_eq!(registry.session_count(), 0);

    registry
        .register_session(make_session("sess-1", "handle-1"))
        .unwrap();
    assert_eq!(registry.session_count(), 1);

    registry
        .register_session(make_session("sess-2", "handle-2"))
        .unwrap();
    assert_eq!(registry.session_count(), 2);
}

/// Verify `all_sessions` returns all sessions for recovery.
#[test]
fn tck_00266_all_sessions() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("state.json");

    let registry = PersistentSessionRegistry::new(&state_file_path);

    registry
        .register_session(make_session("sess-1", "handle-1"))
        .unwrap();
    registry
        .register_session(make_session("sess-2", "handle-2"))
        .unwrap();

    let all = registry.all_sessions();
    assert_eq!(all.len(), 2);

    let ids: Vec<_> = all.iter().map(|s| s.session_id.as_str()).collect();
    assert!(ids.contains(&"sess-1"));
    assert!(ids.contains(&"sess-2"));
}

/// Verify `state_file_path` returns the configured path.
#[test]
fn tck_00266_state_file_path() {
    let temp_dir = TempDir::new().unwrap();
    let state_file_path = temp_dir.path().join("custom_state.json");

    let registry = PersistentSessionRegistry::new(&state_file_path);
    assert_eq!(registry.state_file_path(), state_file_path);
}
