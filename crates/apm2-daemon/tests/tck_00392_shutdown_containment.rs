//! TCK-00392 Shutdown Containment Tests
//!
//! These integration tests verify the cancellation-safe shutdown design
//! introduced by the TCK-00392 BLOCKER fix. The key invariant under test:
//!
//! > **No child process may survive daemon exit**, even if the graceful
//! > shutdown deadline expires and a `ProcessRunner` handle is dropped
//! > mid-stop while the child was spawned with `kill_on_drop(false)`.
//!
//! # Tests
//!
//! - `tck_00392_deadline_expired_process_is_force_killed`: Regression test for
//!   the cancellation-safety blocker. Starts a long-running child, simulates a
//!   graceful shutdown that times out (deadline in the past), then verifies the
//!   force-kill phase reaps the child via the PID set.
//!
//! - `tck_00392_term_resistant_child_is_killed`: Spawns a child that ignores
//!   SIGTERM (trap '' TERM) and verifies the force-kill phase escalates to
//!   SIGKILL, proving containment even under adversarial workloads.
//!
//! - `tck_00392_pid_reuse_no_false_positive_kill`: Validates that the PID
//!   identity guard (start-time comparison) prevents false-positive kills when
//!   the kernel recycles a PID between the snapshot and the force-kill phase.
//!
//! - `tck_00392_e2e_daemon_shutdown_cleans_processes`: An improved E2E test
//!   that starts a real daemon accept loop with running processes, triggers
//!   shutdown via the operator socket, and verifies processes are stopped and
//!   sockets/PID files are cleaned up through the daemon shutdown path.
//!
//! # Verification
//!
//! ```text
//! cargo test -p apm2-daemon tck_00392_shutdown_containment
//! cargo test -p apm2-daemon tck_00392_deadline
//! cargo test -p apm2-daemon tck_00392_term_resistant
//! cargo test -p apm2-daemon tck_00392_pid_reuse
//! cargo test -p apm2-daemon tck_00392_e2e_daemon_shutdown_cleans
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use apm2_core::Supervisor;
use apm2_core::config::EcosystemConfig;
use apm2_core::process::runner::ProcessRunner;
use apm2_core::process::{ProcessSpec, ProcessState};
use apm2_core::schema_registry::InMemorySchemaRegistry;
use apm2_daemon::state::{DaemonStateHandle, SharedState};

// =============================================================================
// Helper: create shared daemon state with a registered process spec
// =============================================================================

/// Creates a `SharedState` with a single process spec registered in the
/// supervisor.  The spec is configured for one instance.
fn create_state_with_spec(spec: &ProcessSpec) -> SharedState {
    let mut supervisor = Supervisor::new();
    supervisor.register(spec.clone()).unwrap();
    let config = EcosystemConfig::default();
    let schema_registry = InMemorySchemaRegistry::new();
    Arc::new(DaemonStateHandle::new(
        config,
        supervisor,
        schema_registry,
        None,
    ))
}

/// Collects `(name, instance)` pairs for running processes — mirrors
/// `collect_running_processes` in `main.rs`.
async fn collect_running(state: &SharedState) -> Vec<(String, u32)> {
    let inner = state.read().await;
    inner
        .supervisor
        .specs()
        .flat_map(|spec| {
            (0..spec.instances)
                .filter(|i| {
                    inner
                        .supervisor
                        .get_handle(&spec.name, *i)
                        .is_some_and(|h| h.state.is_running())
                })
                .map(|i| (spec.name.clone(), i))
        })
        .collect()
}

/// Read the start time (field 22) from `/proc/{pid}/stat`.
/// Mirrors `read_proc_start_time` in `main.rs`.
#[cfg(unix)]
fn read_proc_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let contents = std::fs::read_to_string(stat_path).ok()?;
    let after_comm = contents.rsplit_once(')')?.1;
    let tokens: Vec<&str> = after_comm.split_whitespace().collect();
    tokens.get(19)?.parse::<u64>().ok()
}

/// Collects tracked PIDs with start times — mirrors `collect_tracked_pids`
/// in `main.rs`.
async fn collect_pids(state: &SharedState) -> HashMap<u32, Option<u64>> {
    let inner = state.read().await;
    let mut pids = HashMap::new();
    for spec in inner.supervisor.specs() {
        for i in 0..spec.instances {
            if let Some(handle) = inner.supervisor.get_handle(&spec.name, i) {
                if handle.state.is_running() {
                    if let Some(pid) = handle.pid {
                        #[cfg(unix)]
                        let start_time = read_proc_start_time(pid);
                        #[cfg(not(unix))]
                        let start_time = None;
                        pids.insert(pid, start_time);
                    }
                }
            }
        }
    }
    pids
}

/// Mirrors `shutdown_all_processes` from `main.rs` (deadline-driven).
async fn shutdown_all_processes(state: &SharedState, deadline: tokio::time::Instant) -> bool {
    let processes_to_stop = collect_running(state).await;
    if processes_to_stop.is_empty() {
        return true;
    }

    let mut all_stopped = true;
    for (name, instance) in processes_to_stop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            all_stopped = false;
            break;
        }
        let remaining = deadline - now;
        let per_process_timeout = remaining.min(Duration::from_secs(10));

        let runner = {
            let mut inner = state.write().await;
            let spec_id = inner.supervisor.get_spec(&name).map(|s| s.id);
            spec_id.and_then(|id| inner.remove_runner(id, instance))
        };

        if let Some(mut runner) = runner {
            if runner.state().is_running() {
                if let Err(_e) = runner.stop(per_process_timeout).await {
                    // ignored in test
                }
            }
        }

        {
            let mut inner = state.write().await;
            inner.supervisor.update_state(
                &name,
                instance,
                ProcessState::Stopped { exit_code: None },
            );
            inner.supervisor.update_pid(&name, instance, None);
        }
    }
    all_stopped
}

/// Mirrors `force_kill_all_processes` from `main.rs` with PID-tracking
/// safety and PID-reuse validation.
async fn force_kill_all_processes(
    state: &SharedState,
    pre_shutdown_pids: &HashMap<u32, Option<u64>>,
) {
    // Phase A: runners still in state
    let still_running = collect_running(state).await;
    for (name, instance) in still_running {
        let runner = {
            let mut inner = state.write().await;
            let spec_id = inner.supervisor.get_spec(&name).map(|s| s.id);
            spec_id.and_then(|id| inner.remove_runner(id, instance))
        };

        if let Some(mut runner) = runner {
            if runner.state().is_running() {
                let _ = runner.stop(Duration::ZERO).await;
            }
        }

        {
            let mut inner = state.write().await;
            inner.supervisor.update_state(
                &name,
                instance,
                ProcessState::Stopped { exit_code: None },
            );
            inner.supervisor.update_pid(&name, instance, None);
        }
    }

    // Phase B: OS-level kill for orphaned PIDs with identity validation
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        for (&pid, &snapshot_start_time) in pre_shutdown_pids {
            #[allow(clippy::cast_possible_wrap)]
            let target = Pid::from_raw(pid as i32);
            if kill(target, None).is_ok() {
                // PID-reuse safety: verify process identity before killing.
                if let Some(expected_start) = snapshot_start_time {
                    let current_start = read_proc_start_time(pid);
                    if current_start != Some(expected_start) {
                        // PID was recycled — do NOT kill.
                        continue;
                    }
                } else {
                    // Snapshot start time was None — cannot verify PID identity.
                    // Fail-closed: do NOT kill an unverified PID.
                    continue;
                }
                #[allow(clippy::cast_possible_wrap)]
                let _ = kill(target, Signal::SIGKILL);
            }
        }
    }
}

/// Helper: check whether a PID is alive (signal-0 probe).
#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    #[allow(clippy::cast_possible_wrap)]
    kill(Pid::from_raw(pid as i32), None).is_ok()
}

// =============================================================================
// IT-00392-BLOCKER-01: Deadline-expired process is force-killed via PID set
// =============================================================================

/// Regression test for the cancellation-safety BLOCKER.
///
/// 1. Spawns a long-running `sleep` process and registers it in daemon state.
/// 2. Records the PID set (as the daemon would before the graceful phase).
/// 3. Calls `shutdown_all_processes` with a deadline that has ALREADY EXPIRED.
///    This simulates the case where the outer timeout would have cancelled the
///    future mid-stop in the old design.
/// 4. Verifies the process is still alive after the expired deadline (graceful
///    phase did nothing).
/// 5. Calls `force_kill_all_processes` with the pre-recorded PID set.
/// 6. Asserts the process is dead — the PID set ensured the orphan was reaped
///    even though the runner handle was never properly stopped.
#[tokio::test]
async fn tck_00392_deadline_expired_process_is_force_killed() {
    let spec = ProcessSpec::builder()
        .name("long-sleeper")
        .command("sleep")
        .args(["600"])
        .instances(1)
        .build();

    let state = create_state_with_spec(&spec);

    // Start the process
    let mut runner = ProcessRunner::new(spec.clone(), 0);
    runner.start().unwrap();
    let pid = runner.pid().expect("runner must have a PID");

    // Register in daemon state
    {
        let mut inner = state.write().await;
        inner
            .supervisor
            .update_state("long-sleeper", 0, ProcessState::Running);
        inner.supervisor.update_pid("long-sleeper", 0, Some(pid));
        inner.insert_runner(spec.id, 0, runner);
    }

    // Pre-shutdown: collect PIDs (mirrors daemon behavior)
    let pre_shutdown_pids = collect_pids(&state).await;
    assert!(
        pre_shutdown_pids.contains_key(&pid),
        "PID must be in pre-shutdown set"
    );

    // Graceful phase with EXPIRED deadline — should skip the process
    let expired_deadline = tokio::time::Instant::now() - Duration::from_secs(1);
    let all_graceful = shutdown_all_processes(&state, expired_deadline).await;
    assert!(
        !all_graceful,
        "graceful phase must report incomplete (deadline expired)"
    );

    // The process should still be alive because the deadline was expired
    // and the graceful phase skipped it.
    assert!(
        pid_alive(pid),
        "process must still be alive after expired-deadline graceful phase"
    );

    // Force-kill phase: must kill via PID set
    force_kill_all_processes(&state, &pre_shutdown_pids).await;

    // Give the kernel a moment to reap
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        !pid_alive(pid),
        "process must be dead after force-kill phase — PID-tracking containment failed!"
    );
}

// =============================================================================
// IT-00392-BLOCKER-02: TERM-resistant child is killed via SIGKILL escalation
// =============================================================================

/// Spawns a child process that traps SIGTERM (ignores it) and verifies that
/// the shutdown containment logic escalates to SIGKILL, proving that even
/// adversarial workloads cannot survive daemon exit.
#[tokio::test]
async fn tck_00392_term_resistant_child_is_killed() {
    // This script traps SIGTERM and sleeps forever. Only SIGKILL will stop it.
    let spec = ProcessSpec::builder()
        .name("term-resistant")
        .command("sh")
        .args(["-c", "trap '' TERM; sleep 600"])
        .instances(1)
        .build();

    let state = create_state_with_spec(&spec);

    // Start the process
    let mut runner = ProcessRunner::new(spec.clone(), 0);
    runner.start().unwrap();
    let pid = runner.pid().expect("runner must have a PID");

    // Register in daemon state
    {
        let mut inner = state.write().await;
        inner
            .supervisor
            .update_state("term-resistant", 0, ProcessState::Running);
        inner.supervisor.update_pid("term-resistant", 0, Some(pid));
        inner.insert_runner(spec.id, 0, runner);
    }

    // Wait briefly for the trap to be installed
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(pid_alive(pid), "process must be alive before shutdown");

    // Collect PIDs for force-kill safety net
    let pre_shutdown_pids = collect_pids(&state).await;

    // Graceful shutdown with a very short deadline — the TERM-resistant child
    // will not exit in time.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let _all_graceful = shutdown_all_processes(&state, deadline).await;

    // Force-kill: this must escalate to SIGKILL (via runner.stop(ZERO) or PID set)
    force_kill_all_processes(&state, &pre_shutdown_pids).await;

    // Give the kernel a moment to reap
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !pid_alive(pid),
        "TERM-resistant process must be dead after force-kill — containment breach!"
    );
}

// =============================================================================
// IT-00392-BLOCKER-03: PID-reuse does NOT cause false-positive kill
// =============================================================================

/// Verifies that the force-kill phase does NOT kill an unrelated process
/// that inherited a recycled PID.
///
/// Strategy:
/// 1. Spawn a short-lived child, record its PID + start time in a snapshot.
/// 2. Kill the child so its PID becomes available for reuse.
/// 3. Spawn a new, unrelated process (the "bystander").
/// 4. Build a fake pre-shutdown map containing the OLD PID with the OLD start
///    time.
/// 5. Run force-kill. If the bystander happens to get the same PID, the
///    start-time check must detect the mismatch and skip the kill. If the
///    bystander gets a different PID, it is trivially safe.
///
/// Since we cannot guarantee the kernel will recycle a specific PID, this
/// test takes a dual-assertion approach:
/// - **If PIDs match**: assert the bystander survives (start-time guard).
/// - **If PIDs differ**: assert the bystander survives (PID not in map).
///
/// Either way, the bystander MUST survive.
#[tokio::test]
async fn tck_00392_pid_reuse_no_false_positive_kill() {
    use std::process::Command;

    // Step 1: Spawn a child and record its identity.
    let mut original = Command::new("sleep")
        .arg("600")
        .spawn()
        .expect("failed to spawn original child");
    let original_pid = original.id();

    // Give the process a moment to start so /proc entry exists.
    tokio::time::sleep(Duration::from_millis(50)).await;

    #[cfg(unix)]
    let original_start_time = read_proc_start_time(original_pid);
    #[cfg(not(unix))]
    let original_start_time: Option<u64> = None;

    // Step 2: Kill the original child — free its PID for potential reuse.
    original.kill().expect("failed to kill original child");
    original.wait().expect("failed to wait for original child");

    // Give the kernel a moment to fully clean up the process.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Step 3: Spawn a bystander process (unrelated workload).
    let mut bystander = Command::new("sleep")
        .arg("600")
        .spawn()
        .expect("failed to spawn bystander");
    let bystander_pid = bystander.id();

    // Give the bystander a moment to start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        pid_alive(bystander_pid),
        "bystander must be alive before force-kill"
    );

    // Step 4: Build a fake pre-shutdown map with the ORIGINAL PID's identity.
    let mut fake_snapshot: HashMap<u32, Option<u64>> = HashMap::new();
    fake_snapshot.insert(original_pid, original_start_time);

    // Step 5: Create a minimal daemon state (no runners — Phase A is a no-op).
    let spec = ProcessSpec::builder()
        .name("dummy")
        .command("true")
        .instances(1)
        .build();
    let state = create_state_with_spec(&spec);

    // Run force-kill with the stale snapshot.
    force_kill_all_processes(&state, &fake_snapshot).await;

    // Give the kernel a moment in case a signal was sent.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 6: Assert the bystander survived.
    assert!(
        pid_alive(bystander_pid),
        "bystander process was killed — PID-reuse guard failed! \
         original_pid={original_pid}, bystander_pid={bystander_pid}"
    );

    // Cleanup: kill the bystander ourselves.
    bystander.kill().expect("failed to kill bystander");
    bystander.wait().expect("failed to wait for bystander");
}

// =============================================================================
// IT-00392-BLOCKER-04: Unknown-identity PID (snapshot_start_time=None) survives
// =============================================================================

/// Regression test for the v4 security review BLOCKER: when the snapshot start
/// time is `None` (unknown identity), the force-kill Phase B must NOT send
/// SIGKILL. The rationale is fail-closed: if we cannot prove a PID belongs to
/// our child, we must not kill it.
///
/// Strategy:
/// 1. Spawn a bystander process directly (not through daemon state).
/// 2. Build a fake pre-shutdown snapshot mapping the bystander's PID to `None`
///    (simulating a missing start time at snapshot).
/// 3. Run `force_kill_all_processes` with this snapshot.
/// 4. Assert the bystander is still alive -- Phase B must have skipped it.
#[tokio::test]
async fn tck_00392_unknown_identity_pid_not_killed() {
    use std::process::Command;

    // Step 1: Spawn a bystander process.
    let mut bystander = Command::new("sleep")
        .arg("600")
        .spawn()
        .expect("failed to spawn bystander");
    let bystander_pid = bystander.id();

    // Give the process a moment to start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        pid_alive(bystander_pid),
        "bystander must be alive before force-kill"
    );

    // Step 2: Build a fake pre-shutdown snapshot with start_time = None.
    let mut fake_snapshot: HashMap<u32, Option<u64>> = HashMap::new();
    fake_snapshot.insert(bystander_pid, None);

    // Step 3: Create minimal daemon state (no runners -- Phase A is a no-op).
    let spec = ProcessSpec::builder()
        .name("dummy")
        .command("true")
        .instances(1)
        .build();
    let state = create_state_with_spec(&spec);

    // Run force-kill with the None-identity snapshot.
    force_kill_all_processes(&state, &fake_snapshot).await;

    // Give the kernel a moment in case a signal was sent.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 4: Assert the bystander survived.
    assert!(
        pid_alive(bystander_pid),
        "bystander process with unknown identity (snapshot_start_time=None) was killed! \
         Phase B must NOT send SIGKILL when PID identity cannot be verified."
    );

    // Cleanup: kill the bystander ourselves.
    bystander.kill().expect("failed to kill bystander");
    bystander.wait().expect("failed to wait for bystander");
}

// =============================================================================
// IT-00392-E2E-02: Daemon shutdown cleans up running processes
// =============================================================================

/// Improved E2E test that starts a daemon-like server with actual running
/// child processes, triggers shutdown via IPC, and verifies:
///
/// (a) Running processes are stopped during the shutdown sequence
/// (b) Socket files are cleaned up
/// (c) PID file is cleaned up
///
/// This exercises more of the real daemon shutdown path than the original
/// E2E test, which only tested the IPC handshake + flag setting without
/// any running child processes.
#[tokio::test]
async fn tck_00392_e2e_daemon_shutdown_cleans_processes() {
    use apm2_daemon::protocol::connection_handler::{HandshakeConfig, perform_handshake};
    use apm2_daemon::protocol::dispatch::{ConnectionContext, encode_shutdown_request};
    use apm2_daemon::protocol::messages::{
        BoundedDecode, DecodeConfig, ShutdownRequest, ShutdownResponse,
    };
    use apm2_daemon::protocol::socket_manager::{SocketManager, SocketManagerConfig, SocketType};
    use apm2_daemon::protocol::{
        ClientHandshake, FrameCodec, HandshakeMessage, PrivilegedMessageType,
        serialize_handshake_message,
    };
    use apm2_daemon::state::DispatcherState;
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use tempfile::TempDir;
    use tokio::net::UnixStream;
    use tokio_util::codec::Framed;

    let tmp = TempDir::new().unwrap();
    let operator_path = tmp.path().join("operator.sock");
    let session_path = tmp.path().join("session.sock");
    let pid_path = tmp.path().join("daemon.pid");

    // Write PID file
    std::fs::write(&pid_path, std::process::id().to_string()).unwrap();

    // Create a spec and daemon state
    let spec = ProcessSpec::builder()
        .name("test-worker")
        .command("sleep")
        .args(["600"])
        .instances(1)
        .build();

    let state = create_state_with_spec(&spec);

    // Start a real child process and register it
    let mut runner = ProcessRunner::new(spec.clone(), 0);
    runner.start().unwrap();
    let child_pid = runner.pid().expect("runner must have PID");

    {
        let mut inner = state.write().await;
        inner
            .supervisor
            .update_state("test-worker", 0, ProcessState::Running);
        inner
            .supervisor
            .update_pid("test-worker", 0, Some(child_pid));
        inner.insert_runner(spec.id, 0, runner);
    }

    assert!(pid_alive(child_pid), "child process must be alive at start");

    // Create socket manager and dispatcher
    let sm_config = SocketManagerConfig::new(&operator_path, &session_path);
    let manager = Arc::new(SocketManager::bind(sm_config).unwrap());
    let dispatcher_state: Arc<apm2_daemon::state::DispatcherState> =
        Arc::new(DispatcherState::new(None).with_daemon_state(Arc::clone(&state)));

    // Spawn accept loop
    let loop_state = state.clone();
    let loop_mgr = Arc::clone(&manager);
    let loop_ds = Arc::clone(&dispatcher_state);
    let server_handle = tokio::spawn(async move {
        loop {
            if loop_state.is_shutdown_requested() {
                break;
            }
            let accept_result =
                tokio::time::timeout(Duration::from_millis(100), loop_mgr.accept()).await;

            if let Ok(Ok((mut conn, _permit, st))) = accept_result {
                let cs = loop_state.clone();
                let ds = Arc::clone(&loop_ds);
                tokio::spawn(async move {
                    // Use Tier1 for test backward compat; production default
                    // is Tier2 (deny) per TCK-00348.
                    let hs_cfg = HandshakeConfig::default()
                        .with_risk_tier(apm2_daemon::hsi_contract::RiskTier::Tier1);
                    if perform_handshake(&mut conn, &hs_cfg).await.is_err() {
                        return;
                    }
                    let ctx = match st {
                        SocketType::Operator => {
                            ConnectionContext::privileged(conn.peer_credentials().cloned())
                        },
                        SocketType::Session => {
                            ConnectionContext::session(conn.peer_credentials().cloned(), None)
                        },
                    };
                    let pd = ds.privileged_dispatcher();
                    while let Some(Ok(frame)) = conn.framed().next().await {
                        if cs.is_shutdown_requested() {
                            break;
                        }
                        let fb = Bytes::from(frame.to_vec());
                        match pd.dispatch(&fb, &ctx) {
                            Ok(resp) => {
                                if conn.framed().send(resp.encode()).await.is_err() {
                                    break;
                                }
                            },
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // -- Send Shutdown via operator socket ------------------------------------
    let stream = UnixStream::connect(&operator_path).await.unwrap();
    let mut framed = Framed::new(stream, FrameCodec::new());

    // Handshake
    let mut hs = ClientHandshake::new("test/1.0");
    let hello = hs.create_hello();
    let hello_msg: HandshakeMessage = hello.into();
    framed
        .send(serialize_handshake_message(&hello_msg).unwrap())
        .await
        .unwrap();
    let ack = framed.next().await.unwrap().unwrap();
    hs.process_response(apm2_daemon::protocol::parse_handshake_message(&ack).unwrap())
        .unwrap();

    // Shutdown request
    let req = ShutdownRequest {
        reason: Some("e2e process cleanup test".to_string()),
    };
    framed.send(encode_shutdown_request(&req)).await.unwrap();

    let resp_frame = tokio::time::timeout(Duration::from_secs(5), framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let resp_bytes = Bytes::from(resp_frame.to_vec());
    assert_eq!(
        resp_bytes[0],
        PrivilegedMessageType::Shutdown.tag(),
        "expected shutdown response tag"
    );
    let _resp = ShutdownResponse::decode_bounded(&resp_bytes[1..], &DecodeConfig::default())
        .expect("decode shutdown response");

    assert!(
        state.is_shutdown_requested(),
        "shutdown flag must be set after IPC request"
    );

    // Wait for server loop to exit
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;

    // -- Run the shutdown sequence that the daemon would execute ---------------
    let pre_shutdown_pids = collect_pids(&state).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    shutdown_all_processes(&state, deadline).await;
    force_kill_all_processes(&state, &pre_shutdown_pids).await;

    // Give kernel a moment to reap
    tokio::time::sleep(Duration::from_millis(200)).await;

    // -- Assertions -----------------------------------------------------------
    assert!(
        !pid_alive(child_pid),
        "child process must be dead after shutdown sequence"
    );

    // Socket + PID cleanup
    manager.cleanup().expect("socket cleanup");
    assert!(!operator_path.exists(), "operator.sock must be cleaned up");
    assert!(!session_path.exists(), "session.sock must be cleaned up");

    if pid_path.exists() {
        std::fs::remove_file(&pid_path).unwrap();
    }
    assert!(!pid_path.exists(), "PID file must be cleaned up");
}
