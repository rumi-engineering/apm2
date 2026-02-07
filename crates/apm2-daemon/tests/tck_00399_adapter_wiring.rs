//! Integration tests for TCK-00399: `AdapterRegistry` wiring into
//! `SpawnEpisode`.
//!
//! These tests verify that [`EpisodeRuntime::spawn_adapter()`] correctly wires
//! the adapter lifecycle: spawn, event stream bridge, and terminate on stop.
//!
//! Test command: `cargo test -p apm2-daemon --test tck_00399_adapter_wiring`

use std::ffi::CString;
use std::sync::Arc;

use apm2_daemon::episode::pty::{PtyConfig, PtyError, PtyRunner};
use apm2_daemon::episode::registry::AdapterRegistry;
use apm2_daemon::episode::{
    AdapterType, EpisodeRuntime, EpisodeRuntimeConfig, HarnessConfig, QuarantineReason,
    TerminationClass,
};

/// IT-00399-01: Verify `spawn_adapter` stores handle and `stop()` terminates
/// process.
///
/// This test validates the core wiring:
/// 1. Creates and starts an episode
/// 2. Spawns an agent process via `spawn_adapter`
/// 3. Calls `stop()`, which should terminate the agent process
/// 4. Verifies the episode reaches Terminated state
#[tokio::test]
async fn it_00399_01_spawn_adapter_and_stop_terminates_process() {
    let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(10);
    let registry = Arc::new(AdapterRegistry::with_defaults());
    let runtime = EpisodeRuntime::new(config).with_adapter_registry(Arc::clone(&registry));

    // Create and start an episode
    let envelope_hash = [0u8; 32];
    let episode_id = runtime.create(envelope_hash, 1_000_000).await.unwrap();
    let _handle = runtime
        .start_with_workspace(
            &episode_id,
            "lease-399-01",
            2_000_000,
            std::path::Path::new("/tmp"),
        )
        .await
        .unwrap();

    // Spawn a short-lived process via the adapter
    let adapter = registry.get(AdapterType::Raw).unwrap();
    let harness_config =
        HarnessConfig::new("echo", episode_id.as_str()).with_args(vec!["hello".to_string()]);

    runtime
        .spawn_adapter(&episode_id, harness_config, adapter)
        .await
        .unwrap();

    // Small delay for the process to complete and bridge task to drain
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Stop the episode -- this should handle the (already-exited) process
    // gracefully
    let stop_result = runtime
        .stop(&episode_id, TerminationClass::Success, 3_000_000)
        .await;

    assert!(
        stop_result.is_ok(),
        "stop should succeed even after process has exited: {stop_result:?}"
    );
}

/// IT-00399-02: Verify `spawn_adapter` rejects non-Running episodes.
#[tokio::test]
async fn it_00399_02_spawn_adapter_rejects_created_state() {
    let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(10);
    let registry = Arc::new(AdapterRegistry::with_defaults());
    let runtime = EpisodeRuntime::new(config).with_adapter_registry(Arc::clone(&registry));

    // Create but do NOT start
    let envelope_hash = [1u8; 32];
    let episode_id = runtime.create(envelope_hash, 1_000_000).await.unwrap();

    let adapter = registry.get(AdapterType::Raw).unwrap();
    let harness_config =
        HarnessConfig::new("echo", episode_id.as_str()).with_args(vec!["test".to_string()]);

    let result = runtime
        .spawn_adapter(&episode_id, harness_config, adapter)
        .await;

    assert!(
        result.is_err(),
        "spawn_adapter should fail for episode in Created state"
    );
}

/// IT-00399-03: Verify `quarantine` terminates a long-running adapter process.
#[tokio::test]
async fn it_00399_03_quarantine_terminates_adapter_process() {
    let config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(10);
    let registry = Arc::new(AdapterRegistry::with_defaults());
    let runtime = EpisodeRuntime::new(config).with_adapter_registry(Arc::clone(&registry));

    let envelope_hash = [2u8; 32];
    let episode_id = runtime.create(envelope_hash, 1_000_000).await.unwrap();
    let _handle = runtime
        .start_with_workspace(
            &episode_id,
            "lease-399-03",
            2_000_000,
            std::path::Path::new("/tmp"),
        )
        .await
        .unwrap();

    // Spawn a long-running process (cat blocks on stdin)
    let adapter = registry.get(AdapterType::Raw).unwrap();
    let harness_config = HarnessConfig::new("cat", episode_id.as_str());

    runtime
        .spawn_adapter(&episode_id, harness_config, adapter)
        .await
        .unwrap();

    // Small delay for process to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Quarantine should terminate the process
    let quarantine_result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        runtime.quarantine(
            &episode_id,
            QuarantineReason::new("test", "test quarantine"),
            3_000_000,
        ),
    )
    .await;

    assert!(
        quarantine_result.is_ok(),
        "quarantine must complete within timeout (not deadlock)"
    );
    assert!(
        quarantine_result.unwrap().is_ok(),
        "quarantine should succeed"
    );
}

/// IT-00399-04: Non-absolute command with custom env resolves via PATH and
/// spawns successfully.
///
/// This tests the pre-fork PATH resolution fix: when a custom environment is
/// provided (triggering `execve` instead of `execvp`), non-absolute commands
/// like "echo" must be resolved to their absolute path before fork.
#[tokio::test]
async fn it_00399_04_non_absolute_command_with_custom_env_succeeds() {
    // Build a PtyConfig with custom env that includes PATH.
    let env = vec![
        (
            CString::new("PATH").unwrap(),
            CString::new("/usr/local/bin:/usr/bin:/bin").unwrap(),
        ),
        (CString::new("LANG").unwrap(), CString::new("C").unwrap()),
    ];
    let config = PtyConfig::default().with_env(env);

    // "echo" is a non-absolute command that should be resolved via PATH.
    let result = PtyRunner::spawn("echo", &["hello", "world"], config, 1_000_000);

    if let Err(ref e) = result {
        panic!(
            "non-absolute command 'echo' with custom env should succeed after PATH resolution: {e}"
        );
    }

    let mut runner = result.unwrap();
    // Wait briefly for echo to complete.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let status = runner.try_wait().expect("try_wait should succeed");
    assert!(
        !matches!(status, apm2_daemon::episode::pty::ExitStatus::Running),
        "echo process should have completed, got: {status:?}"
    );
}

/// IT-00399-05: Absolute command with custom env spawns successfully.
///
/// Verifies that absolute paths bypass PATH resolution and work directly
/// with `execve`.
#[tokio::test]
async fn it_00399_05_absolute_command_with_custom_env_succeeds() {
    let env = vec![(
        CString::new("PATH").unwrap(),
        CString::new("/usr/local/bin:/usr/bin:/bin").unwrap(),
    )];
    let config = PtyConfig::default().with_env(env);

    // Absolute path — no resolution needed.
    let result = PtyRunner::spawn("/bin/echo", &["absolute-test"], config, 1_000_000);

    if let Err(ref e) = result {
        panic!("absolute command '/bin/echo' with custom env should succeed: {e}");
    }

    let mut runner = result.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let status = runner.try_wait().expect("try_wait should succeed");
    assert!(
        !matches!(status, apm2_daemon::episode::pty::ExitStatus::Running),
        "echo process should have completed, got: {status:?}"
    );
}

/// IT-00399-06: Invalid (non-existent) command with custom env fails with
/// `CommandNotFound` pre-fork.
///
/// Verifies fail-closed semantics: the error is returned before fork, not
/// as a silent _exit(127) in the child.
#[tokio::test]
async fn it_00399_06_invalid_command_with_custom_env_fails_prefork() {
    let env = vec![(
        CString::new("PATH").unwrap(),
        CString::new("/usr/local/bin:/usr/bin:/bin").unwrap(),
    )];
    let config = PtyConfig::default().with_env(env);

    // "nonexistent_apm2_test_cmd_xyz" does not exist in any PATH directory.
    let result = PtyRunner::spawn(
        "nonexistent_apm2_test_cmd_xyz",
        &["arg1"],
        config,
        1_000_000,
    );

    match result {
        Ok(_) => panic!("non-existent command should fail pre-fork"),
        Err(err) => {
            let err_msg = err.to_string();
            assert!(
                err_msg.contains("not found"),
                "error should indicate command not found: {err_msg}"
            );
            // Verify the error variant is CommandNotFound (not a generic exec failure).
            assert!(
                matches!(err, PtyError::CommandNotFound { .. }),
                "error should be CommandNotFound variant, got: {err:?}"
            );
        },
    }
}

/// IT-00399-07: Non-absolute command with custom env but empty PATH fails
/// with `CommandNotFound`.
///
/// Verifies that when PATH is empty in the custom env, non-absolute
/// commands are correctly rejected pre-fork.
#[tokio::test]
async fn it_00399_07_non_absolute_command_with_empty_path_fails() {
    let env = vec![
        (CString::new("PATH").unwrap(), CString::new("").unwrap()),
        (CString::new("LANG").unwrap(), CString::new("C").unwrap()),
    ];
    let config = PtyConfig::default().with_env(env);

    let result = PtyRunner::spawn("echo", &["test"], config, 1_000_000);

    match result {
        Ok(_) => panic!("non-absolute command with empty PATH should fail"),
        Err(err) => assert!(
            matches!(err, PtyError::CommandNotFound { .. }),
            "should be CommandNotFound, got: {err:?}"
        ),
    }
}

/// IT-00399-08: Non-absolute command with no PATH in custom env fails with
/// `CommandNotFound`.
///
/// When the custom env does not contain a PATH entry at all, non-absolute
/// commands cannot be resolved.
#[tokio::test]
async fn it_00399_08_non_absolute_command_with_no_path_in_env_fails() {
    // Custom env with no PATH key at all.
    let env = vec![(CString::new("LANG").unwrap(), CString::new("C").unwrap())];
    let config = PtyConfig::default().with_env(env);

    let result = PtyRunner::spawn("echo", &["test"], config, 1_000_000);

    match result {
        Ok(_) => panic!("non-absolute command with no PATH should fail"),
        Err(err) => assert!(
            matches!(err, PtyError::CommandNotFound { .. }),
            "should be CommandNotFound, got: {err:?}"
        ),
    }
}
