//! Integration tests for seccomp sandbox enforcement.
//!
//! These tests verify that the seccomp filter is actually applied to child
//! processes and that blocked syscalls result in process termination.
//!
//! # Test Strategy
//!
//! We spawn a child process with a seccomp profile and have it attempt a
//! blocked syscall. If the filter is properly applied, the process should be
//! terminated with SIGSYS (signal 31 on Linux).
//!
//! # Platform Support
//!
//! These tests only run on Linux `x86_64` systems where seccomp-bpf is
//! available.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::time::Duration;

use apm2_core::adapter::{AdapterEventPayload, BlackBoxAdapter, BlackBoxConfig, SeccompProfile};

/// SIGSYS signal number on Linux (sent when seccomp blocks a syscall).
const SIGSYS: i32 = 31;

/// Helper to run an adapter and wait for process exit, returning the exit
/// status info.
async fn run_adapter_to_exit(mut adapter: BlackBoxAdapter) -> (Option<i32>, Option<i32>) {
    adapter.start().await.expect("adapter should start");

    // Poll until process exits
    let mut exit_code = None;
    let mut signal = None;

    for _ in 0..200 {
        match adapter.poll().await {
            Ok(Some(event)) => {
                if let AdapterEventPayload::ProcessExited(exited) = event.payload {
                    exit_code = exited.exit_code;
                    signal = exited.signal;
                    break;
                }
            },
            Ok(None) => {
                if !adapter.is_running() {
                    // Process exited but we may have missed the event
                    // Try to get exit info from the adapter
                    exit_code = adapter.exit_code();
                    signal = adapter.exit_signal();
                    break;
                }
            },
            Err(e) => panic!("poll error: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // If we still have no info, the process may have exited immediately
    // Poll one more time to ensure we catch the exit
    if exit_code.is_none() && signal.is_none() {
        for _ in 0..10 {
            match adapter.poll().await {
                Ok(Some(event)) => {
                    if let AdapterEventPayload::ProcessExited(exited) = event.payload {
                        exit_code = exited.exit_code;
                        signal = exited.signal;
                        break;
                    }
                },
                Ok(None) => {
                    exit_code = adapter.exit_code();
                    signal = adapter.exit_signal();
                    if exit_code.is_some() || signal.is_some() {
                        break;
                    }
                },
                Err(_) => break,
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    (exit_code, signal)
}

/// Test that a process with no seccomp profile runs normally.
///
/// This is a baseline test to ensure our test infrastructure works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_seccomp_process_exits_normally() {
    let config = BlackBoxConfig::new("test-no-seccomp", "echo").with_args(["hello"]);
    // Default: no seccomp
    assert!(!config.seccomp.is_enforced());

    let adapter = BlackBoxAdapter::new(config);
    let (exit_code, signal) = run_adapter_to_exit(adapter).await;

    assert_eq!(exit_code, Some(0), "echo should exit with code 0");
    assert_eq!(signal, None, "echo should not be killed by signal");
}

/// Test that a process with Restricted seccomp profile is killed when
/// attempting to create a socket (blocked syscall).
///
/// This test uses Python to attempt a `socket()` syscall because:
/// 1. Python is widely available
/// 2. It's easy to trigger specific syscalls
/// 3. The test is deterministic
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_restricted_seccomp_blocks_socket() {
    // First check if python3 is available
    let python_check = std::process::Command::new("which").arg("python3").output();

    if python_check.is_err() || !python_check.unwrap().status.success() {
        eprintln!("Skipping test: python3 not available");
        return;
    }

    let config = BlackBoxConfig::new("test-seccomp-socket", "python3")
        .with_args(["-c", "import socket; socket.socket()"])
        .with_seccomp(SeccompProfile::restricted());

    assert!(config.seccomp.is_enforced(), "seccomp should be enforced");

    let adapter = BlackBoxAdapter::new(config);
    let (exit_code, signal) = run_adapter_to_exit(adapter).await;

    // The process should be killed by SIGSYS (or SIGTRAP if log_violations is true)
    // When log_violations is true (default), SECCOMP_RET_TRAP sends SIGSYS
    assert!(
        signal == Some(SIGSYS) || signal == Some(libc::SIGTRAP),
        "Process should be killed by SIGSYS or SIGTRAP, got exit_code={exit_code:?}, signal={signal:?}"
    );
}

/// Test that a process with Baseline seccomp profile can still perform
/// basic operations.
///
/// Note: The Restricted profile blocks setuid/setgid syscalls which many
/// programs (including busybox) call during initialization even when not
/// actually changing privileges. Baseline is less restrictive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_baseline_seccomp_allows_basic_programs() {
    // Use /bin/true which is minimal and doesn't call setuid/setgid
    let config = BlackBoxConfig::new("test-seccomp-baseline", "/bin/true")
        .with_seccomp(SeccompProfile::baseline());

    let adapter = BlackBoxAdapter::new(config);
    let (exit_code, signal) = run_adapter_to_exit(adapter).await;

    // Baseline profile should allow /bin/true to run
    assert_eq!(
        signal, None,
        "/bin/true should not be killed by seccomp at Baseline level"
    );
    assert_eq!(
        exit_code,
        Some(0),
        "/bin/true should exit normally with Baseline seccomp"
    );
}

/// Test that Baseline profile allows socket syscalls but blocks ptrace.
///
/// Note: We can't easily test ptrace blocking without privilege escalation,
/// so we verify that `socket()` works at Baseline level.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_baseline_seccomp_allows_socket() {
    // First check if python3 is available
    let python_check = std::process::Command::new("which").arg("python3").output();

    if python_check.is_err() || !python_check.unwrap().status.success() {
        eprintln!("Skipping test: python3 not available");
        return;
    }

    let config = BlackBoxConfig::new("test-baseline-socket", "python3")
        .with_args([
            "-c",
            "import socket; s = socket.socket(); s.close(); print('ok')",
        ])
        .with_seccomp(SeccompProfile::baseline());

    let adapter = BlackBoxAdapter::new(config);
    let (exit_code, signal) = run_adapter_to_exit(adapter).await;

    // Baseline allows socket syscalls
    assert_eq!(
        exit_code,
        Some(0),
        "socket should be allowed at Baseline level"
    );
    assert_eq!(signal, None, "process should not be killed");
}

/// Test that Strict profile blocks fork/exec syscalls.
///
/// This uses bash with a subcommand which requires `fork()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_strict_seccomp_blocks_fork() {
    // Use bash to try to fork a subshell
    let config = BlackBoxConfig::new("test-strict-fork", "bash")
        .with_args(["-c", "echo before; (echo inside); echo after"])
        .with_seccomp(SeccompProfile::strict());

    let adapter = BlackBoxAdapter::new(config);
    let (exit_code, signal) = run_adapter_to_exit(adapter).await;

    // The process should be killed when trying to fork
    // Note: bash itself may use fork during initialization, so this might fail
    // early
    assert!(
        signal == Some(SIGSYS) || signal == Some(libc::SIGTRAP) || exit_code != Some(0),
        "Process should fail when fork is blocked, got exit_code={exit_code:?}, signal={signal:?}"
    );
}

/// Test the `with_seccomp_sandbox()` convenience method.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_with_seccomp_sandbox_convenience() {
    // First check if python3 is available
    let python_check = std::process::Command::new("which").arg("python3").output();

    if python_check.is_err() || !python_check.unwrap().status.success() {
        eprintln!("Skipping test: python3 not available");
        return;
    }

    // Use the convenience method instead of explicit SeccompProfile
    let config = BlackBoxConfig::new("test-convenience", "python3")
        .with_args(["-c", "import socket; socket.socket()"])
        .with_seccomp_sandbox(); // Equivalent to with_seccomp(SeccompProfile::restricted())

    let adapter = BlackBoxAdapter::new(config);
    let (exit_code, signal) = run_adapter_to_exit(adapter).await;

    // Should be killed by seccomp
    assert!(
        signal == Some(SIGSYS) || signal == Some(libc::SIGTRAP),
        "Process should be killed when socket is blocked, got exit_code={exit_code:?}, signal={signal:?}"
    );
}
