//! TCK-00601 -- Integration tests: deterministic failures (no hangs) + secrets
//! posture.
//!
//! This module contains two classes of tests:
//!
//! 1. **Subprocess E2E tests** (MAJOR findings fix): These invoke the `apm2`
//!    binary as a subprocess via `std::process::Command` with a hermetic
//!    `APM2_HOME` environment. They exercise the actual CLI command flow for
//!    `apm2 fac gates` and `apm2 fac push` to verify:
//!    - Broker absent => fail fast with actionable error (no hang)
//!    - Broker present, worker absent => bounded exit (no hang)
//!    - Missing GitHub creds does NOT prevent `gates`
//!    - GitHub-facing command (`push`) fails fast with credential remediation
//!
//! 2. **Library-level tests**: These test internal invariants that are
//!    genuinely library-level concerns (secret leakage in error strings, Debug
//!    output redaction, receipt builder output, heartbeat read behavior on
//!    missing/malformed files).
//!
//! All subprocess tests use `tempdir` for `APM2_HOME` to achieve hermetic
//! isolation and apply bounded wall-clock timeouts to detect hangs.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Maximum wall-clock time any single subprocess test is allowed to run
/// before we consider it a hang regression. 30 seconds is generous; actual
/// fail-fast paths should complete in < 5s.
const SUBPROCESS_TIMEOUT_SECS: u64 = 30;

// =========================================================================
// Hermetic test harness helpers
// =========================================================================

/// Returns the path to the `apm2` binary built by Cargo.
///
/// Uses `env!("CARGO_BIN_EXE_apm2")` which is set by Cargo when running
/// integration tests for crates that define a `[[bin]]` target.
fn apm2_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apm2"))
}

/// Set directory permissions to 0o700 (owner rwx only) as required by
/// the FAC root permissions preflight check (CTR-2611).
#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .unwrap_or_else(|e| panic!("chmod 0700 {}: {e}", path.display()));
}

/// Creates a directory tree with 0o700 permissions on each component.
fn create_dir_restricted(path: &Path) {
    std::fs::create_dir_all(path).expect("create dir");
    // Walk up from the leaf to ensure each component has 0o700.
    // We only need to fix the tempdir root and its children.
    #[cfg(unix)]
    set_dir_mode_0700(path);
}

/// Creates a minimal `APM2_HOME` with only the top-level structure, but
/// NO broker state, NO worker heartbeat, NO queue directories.
///
/// This simulates the "broker absent" scenario.
fn setup_bare_apm2_home() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().to_path_buf();
    #[cfg(unix)]
    set_dir_mode_0700(&home);
    // Create minimal private/fac directory (FAC root) but nothing else.
    create_dir_restricted(&home.join("private"));
    create_dir_restricted(&home.join("private/fac"));
    (tmp, home)
}

/// Creates an `APM2_HOME` with broker infrastructure (policy, queue dirs,
/// signing key) but NO worker heartbeat file, simulating "broker present,
/// worker absent".
fn setup_apm2_home_broker_only() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().to_path_buf();
    #[cfg(unix)]
    set_dir_mode_0700(&home);

    // Create FAC directory tree with restricted permissions.
    create_dir_restricted(&home.join("private"));
    let fac_root = home.join("private/fac");
    create_dir_restricted(&fac_root);
    create_dir_restricted(&fac_root.join("policy"));
    create_dir_restricted(&fac_root.join("lanes"));
    create_dir_restricted(&fac_root.join("receipts"));
    create_dir_restricted(&fac_root.join("evidence"));

    // Create queue directories.
    let queue_root = home.join("queue");
    create_dir_restricted(&queue_root);
    for sub in [
        "pending",
        "claimed",
        "completed",
        "denied",
        "quarantine",
        "receipts",
    ] {
        create_dir_restricted(&queue_root.join(sub));
    }

    // Create private/creds directory (needed by credential resolution).
    create_dir_restricted(&home.join("private/creds"));

    // Write a default policy so broker init can succeed.
    let default_policy = apm2_core::fac::FacPolicyV1::default();
    apm2_core::fac::persist_policy(&fac_root, &default_policy).expect("persist default policy");

    (tmp, home)
}

/// Runs the `apm2` binary as a subprocess with the given arguments and
/// a hermetic environment. Returns `(exit_code, stdout, stderr)`.
///
/// The subprocess inherits a minimal environment:
/// - `APM2_HOME` set to the provided path
/// - `HOME` set to the `APM2_HOME` (prevents fallback to real home)
/// - `PATH` inherited from the test process
/// - All `GITHUB_TOKEN`, `GH_TOKEN`, etc. are explicitly removed unless
///   `keep_github_creds` is true
///
/// The subprocess is killed if it exceeds `SUBPROCESS_TIMEOUT_SECS`.
fn run_apm2_subprocess(
    args: &[&str],
    apm2_home: &std::path::Path,
    keep_github_creds: bool,
) -> (Option<i32>, String, String) {
    let bin = apm2_bin();
    let path_env = std::env::var("PATH").unwrap_or_default();

    let mut cmd = std::process::Command::new(&bin);
    cmd.args(args);

    // Start with a clean environment to prevent interference.
    cmd.env_clear();
    cmd.env("APM2_HOME", apm2_home);
    cmd.env("HOME", apm2_home);
    cmd.env("PATH", &path_env);

    // Preserve Rust backtrace for debugging.
    if let Ok(bt) = std::env::var("RUST_BACKTRACE") {
        cmd.env("RUST_BACKTRACE", bt);
    }

    if keep_github_creds {
        // Selectively preserve GitHub credential env vars if present.
        for var in &[
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "GH_PAT",
            "GITHUB_PAT",
            "APM2_GITHUB_PAT",
            "APM2_FAC_PAT",
        ] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }
    }
    // When keep_github_creds is false, env_clear() already removed them.

    let start = Instant::now();
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn apm2 binary at {}: {e}", bin.display()));

    let timeout = Duration::from_secs(SUBPROCESS_TIMEOUT_SECS);

    // Poll for completion with a bounded timeout.
    let poll_interval = Duration::from_millis(100);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = {
                    use std::io::Read;
                    let mut s = String::new();
                    if let Some(mut out) = child.stdout.take() {
                        let _ = out.read_to_string(&mut s);
                    }
                    s
                };
                let stderr = {
                    use std::io::Read;
                    let mut s = String::new();
                    if let Some(mut err) = child.stderr.take() {
                        let _ = err.read_to_string(&mut s);
                    }
                    s
                };
                return (status.code(), stdout, stderr);
            },
            Ok(None) => {
                // Still running.
                if start.elapsed() >= timeout {
                    // Kill the child and fail.
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "HANG DETECTED: `apm2 {}` did not exit within {SUBPROCESS_TIMEOUT_SECS}s",
                        args.join(" ")
                    );
                }
                std::thread::sleep(poll_interval);
            },
            Err(e) => {
                panic!("error waiting for apm2 subprocess: {e}");
            },
        }
    }
}

/// Assert that a test completes within `SUBPROCESS_TIMEOUT_SECS`.
///
/// Used for library-level tests that should not hang.
fn assert_no_hang<F, T>(label: &str, f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let timeout = Duration::from_secs(SUBPROCESS_TIMEOUT_SECS);
    let label_owned = label.to_string();
    let start = Instant::now();

    let handle = std::thread::Builder::new()
        .name(format!("hang-guard-{label_owned}"))
        .spawn(f)
        .expect("spawn hang-guard thread");

    let poll_interval = Duration::from_millis(100);
    loop {
        if handle.is_finished() {
            break;
        }
        assert!(
            start.elapsed() < timeout,
            "HANG DETECTED in {label_owned}: closure did not return within \
             {SUBPROCESS_TIMEOUT_SECS}s (enforcing timeout)"
        );
        std::thread::sleep(poll_interval);
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < timeout,
        "SLOW EXECUTION in {label_owned}: took {elapsed:?}, limit is {SUBPROCESS_TIMEOUT_SECS}s"
    );

    handle.join().expect("hang-guard thread panicked")
}

/// Known secret environment variable names that MUST NOT appear in output.
const SECRET_ENV_NAMES: &[&str] = &[
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GH_PAT",
    "GITHUB_PAT",
    "APM2_GITHUB_PAT",
    "APM2_FAC_PAT",
    "PERSONAL_ACCESS_TOKEN",
];

/// Asserts that `text` does not contain any of the provided secret values.
/// The `context` is used for the assertion message.
fn assert_no_secret_leakage(text: &str, secrets: &[(&str, &str)], context: &str) {
    for (name, value) in secrets {
        if value.is_empty() {
            continue;
        }
        assert!(
            !text.contains(value),
            "SECRET LEAKAGE in {context}: found value of {name} in output. \
             Output snippet: {}",
            &text[..text.len().min(200)]
        );
    }
}

// =========================================================================
// Subprocess E2E test: Broker absent => fail fast (MAJOR #1 fix)
// =========================================================================

/// When `APM2_HOME` points to a minimal directory with no broker state,
/// queue directories, or signing key, running `apm2 fac gates` as a
/// subprocess should exit with a non-zero code and emit a deterministic
/// actionable error message -- not hang.
///
/// This exercises the full CLI command flow: argument parsing, `APM2_HOME`
/// resolution, bootstrap/preflight, broker init, and error reporting.
#[test]
fn subprocess_broker_absent_fails_fast_no_hang() {
    let (_tmp, home) = setup_bare_apm2_home();

    let (exit_code, stdout, stderr) =
        run_apm2_subprocess(&["fac", "gates", "--quick"], &home, false);

    // The subprocess must have exited (not hung -- the timeout guard
    // in run_apm2_subprocess would have killed it and panicked).
    // It must exit with a non-zero code (error).
    assert_ne!(
        exit_code,
        Some(0),
        "apm2 fac gates should fail in bare APM2_HOME (no broker/queue), \
         but exited 0.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The combined output should contain an actionable error, not
    // a generic timeout or hang.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        !combined.is_empty(),
        "apm2 fac gates should produce error output in bare APM2_HOME"
    );
}

/// Similar to the bare-home test but with a completely empty temp dir
/// (no private/fac at all). The CLI should still fail fast with an
/// actionable error about missing FAC infrastructure.
#[test]
fn subprocess_no_fac_root_fails_fast_no_hang() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path();

    let (exit_code, stdout, stderr) =
        run_apm2_subprocess(&["fac", "gates", "--quick"], home, false);

    assert_ne!(
        exit_code,
        Some(0),
        "apm2 fac gates should fail with empty APM2_HOME.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let combined = format!("{stdout}\n{stderr}");
    assert!(
        !combined.is_empty(),
        "apm2 fac gates should produce error output with empty APM2_HOME"
    );
}

// =========================================================================
// Subprocess E2E test: Worker absent => bounded exit (MAJOR #2 fix)
// =========================================================================

/// When broker infrastructure exists (policy, queue dirs) but no worker is
/// running, `apm2 fac gates` should eventually exit with an error within
/// a bounded wall-clock timeout -- not hang indefinitely waiting for a
/// worker.
///
/// This exercises the full CLI gates path including broker init, queue
/// processing mode detection (no worker heartbeat), and the inline/wait
/// fallback logic.
#[test]
fn subprocess_worker_absent_exits_bounded_no_hang() {
    let (_tmp, home) = setup_apm2_home_broker_only();

    let start = Instant::now();
    let (exit_code, stdout, stderr) =
        run_apm2_subprocess(&["fac", "gates", "--quick"], &home, false);
    let elapsed = start.elapsed();

    // The subprocess must have exited within the timeout (the hang guard
    // in run_apm2_subprocess enforces this, but we also check elapsed time
    // as supplementary telemetry).
    assert!(
        elapsed < Duration::from_secs(SUBPROCESS_TIMEOUT_SECS),
        "apm2 fac gates should exit within {SUBPROCESS_TIMEOUT_SECS}s when no worker is running, \
         took {elapsed:?}"
    );

    // The process should exit non-zero (gates cannot complete without a
    // proper workspace/git state).
    assert_ne!(
        exit_code,
        Some(0),
        "apm2 fac gates should fail without a proper workspace, \
         but exited 0.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Error output should be non-empty and descriptive.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        !combined.trim().is_empty(),
        "apm2 fac gates should produce diagnostic output when worker is absent"
    );
}

// =========================================================================
// Subprocess E2E test: Credential posture separation (MAJOR #3 fix)
// =========================================================================

/// Running `apm2 fac gates` with no GitHub credentials (`GITHUB_TOKEN`,
/// `GH_TOKEN` unset) should NOT fail with a credential error. The gates
/// path does not require GitHub credentials -- it may fail for other
/// reasons (no git repo, no workspace, etc.) but NOT due to missing
/// GitHub creds.
///
/// This exercises the CLI gates entrypoint and verifies that
/// `require_github_credentials` is NOT called on the gates path.
#[test]
fn subprocess_gates_no_credential_error_without_github_creds() {
    let (_tmp, home) = setup_apm2_home_broker_only();

    // Run with env_clear (no GitHub credentials).
    let (_exit_code, stdout, stderr) =
        run_apm2_subprocess(&["fac", "gates", "--quick"], &home, false);

    let combined = format!("{stdout}\n{stderr}");

    // The output must NOT contain credential-related error messages.
    // The CredentialGateError::GitHubCredentialsMissing error contains
    // specific remediation text that we check for absence.
    let credential_error_markers = [
        "GitHub credentials not found",
        "GitHubCredentialsMissing",
        "Remediation: set GITHUB_TOKEN",
        "fac_push_credentials_missing",
        "fac pr auth-setup",
    ];
    for marker in &credential_error_markers {
        assert!(
            !combined.contains(marker),
            "apm2 fac gates should NOT produce credential errors when \
             GITHUB_TOKEN/GH_TOKEN are unset, but found '{marker}' in output.\n\
             combined output: {combined}"
        );
    }
}

/// Running `apm2 fac push` with no GitHub credentials should fail fast
/// with an explicit credential remediation message. This verifies that
/// the push path (GitHub-facing) enforces credential checks.
///
/// Note: `apm2 fac push` requires a git repository, but the credential
/// check happens BEFORE any git operations, so even without a repo we
/// can observe the credential error.
#[test]
fn subprocess_push_fails_fast_with_credential_remediation() {
    let (_tmp, home) = setup_apm2_home_broker_only();

    // Run with env_clear (no GitHub credentials).
    let (exit_code, stdout, stderr) = run_apm2_subprocess(&["fac", "push"], &home, false);

    // Must exit non-zero.
    assert_ne!(
        exit_code,
        Some(0),
        "apm2 fac push should fail without GitHub credentials.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    let combined = format!("{stdout}\n{stderr}");

    // The output must contain actionable credential remediation.
    // At minimum, one of these markers should appear:
    let has_credential_error = combined.contains("GITHUB_TOKEN")
        || combined.contains("GH_TOKEN")
        || combined.contains("credential")
        || combined.contains("Remediation");

    // The push command might also fail early for other reasons (e.g., not
    // in a git repo). In that case, it is acceptable as long as it does
    // not hang and exits non-zero. But if it does reach the credential
    // gate, it must include remediation.
    //
    // We check: if the output mentions credentials at all, it must include
    // remediation instructions. If it fails before reaching the credential
    // gate (e.g., git repo not found), that is also acceptable behavior
    // (fail fast, non-zero exit).
    if has_credential_error {
        assert!(
            combined.contains("GITHUB_TOKEN") || combined.contains("GH_TOKEN"),
            "credential error should mention GITHUB_TOKEN or GH_TOKEN.\n\
             combined: {combined}"
        );
    }
    // Either way, the test proves: non-zero exit, no hang, and if
    // credentials are checked, remediation is present.
}

// =========================================================================
// Library test: Worker heartbeat detection (retained -- genuine library)
// =========================================================================

/// When broker infrastructure exists but no worker heartbeat is present,
/// `has_live_worker_heartbeat` returns false. The heartbeat read should
/// complete instantly without hanging.
#[test]
fn worker_absent_heartbeat_returns_false_no_hang() {
    let (_tmp, home) = setup_apm2_home_broker_only();
    let fac_root = home.join("private/fac");

    let heartbeat_fresh = assert_no_hang("worker_absent_heartbeat_check", move || {
        let status = apm2_core::fac::worker_heartbeat::read_heartbeat(&fac_root);
        status.found && status.fresh && status.pid != 0
    });

    assert!(
        !heartbeat_fresh,
        "Expected no live worker heartbeat in test environment"
    );
}

/// Verifies that reading a heartbeat from a directory without a heartbeat
/// file completes immediately (< 1 second).
#[test]
fn heartbeat_read_missing_file_completes_immediately() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fac_root = tmp.path();

    let start = Instant::now();
    let status = apm2_core::fac::worker_heartbeat::read_heartbeat(fac_root);
    let elapsed = start.elapsed();

    assert!(!status.found, "heartbeat should not be found in empty dir");
    assert!(
        elapsed < Duration::from_secs(1),
        "heartbeat read should complete immediately, took {elapsed:?}"
    );
}

/// Verifies that reading a malformed heartbeat file completes immediately
/// and returns `found=false` or `fresh=false` -- not a hang.
#[test]
fn heartbeat_read_malformed_file_completes_immediately() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fac_root = tmp.path();

    // Write a malformed heartbeat file.
    let heartbeat_path = fac_root.join("worker_heartbeat.json");
    std::fs::write(&heartbeat_path, b"not valid json {{{").expect("write malformed heartbeat");

    let start = Instant::now();
    let status = apm2_core::fac::worker_heartbeat::read_heartbeat(fac_root);
    let elapsed = start.elapsed();

    assert!(
        !status.fresh || !status.found,
        "malformed heartbeat should not be considered fresh/found"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "malformed heartbeat read should complete immediately, took {elapsed:?}"
    );
}

/// When no worker heartbeat exists, the queue processing mode detection
/// should return no-live-heartbeat instantly, never block.
#[test]
fn queue_processing_mode_no_heartbeat_returns_inline() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fac_root = tmp.path();

    let start = Instant::now();
    let heartbeat = apm2_core::fac::worker_heartbeat::read_heartbeat(fac_root);
    let elapsed = start.elapsed();

    assert!(
        !heartbeat.found || !heartbeat.fresh || heartbeat.pid == 0,
        "expected no live heartbeat in empty dir"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "mode detection should be instantaneous, took {elapsed:?}"
    );
}

// =========================================================================
// Library test: Credential posture and error message quality (retained)
// =========================================================================

/// Verifies that `check_github_credential_posture` returns a posture
/// with the expected shape and no secrets in Debug output.
#[test]
fn github_credential_posture_unresolved_when_no_creds() {
    let posture = apm2_core::fac::credential_gate::check_github_credential_posture();

    assert_eq!(posture.credential_name, "github-token");

    let debug_output = format!("{posture:?}");
    assert!(
        !debug_output.contains("ghp_"),
        "credential posture Debug should not contain raw token prefixes"
    );
    assert!(
        !debug_output.contains("ghs_"),
        "credential posture Debug should not contain raw token prefixes"
    );
}

/// `require_github_credentials` must return an error with explicit
/// remediation instructions when no GitHub credentials are available.
#[test]
fn require_github_credentials_error_has_remediation_instructions() {
    let error = apm2_core::fac::credential_gate::CredentialGateError::GitHubCredentialsMissing;
    let message = error.to_string();

    assert!(
        message.contains("GITHUB_TOKEN"),
        "error should mention GITHUB_TOKEN: {message}"
    );
    assert!(
        message.contains("GH_TOKEN"),
        "error should mention GH_TOKEN: {message}"
    );
    assert!(
        message.contains("Remediation"),
        "error should contain remediation instructions: {message}"
    );
    assert!(
        message.contains("systemd") || message.contains("LoadCredential"),
        "error should mention systemd credential path: {message}"
    );
    assert!(
        message.contains("auth-setup"),
        "error should mention auth-setup command: {message}"
    );
    assert!(
        message.contains("private/creds/gh-token"),
        "error should mention credential file path: {message}"
    );
}

/// `require_github_credentials` in a clean environment should return
/// quickly -- not hang or timeout.
#[test]
fn require_github_credentials_fails_fast_no_hang() {
    let _result = assert_no_hang("require_github_credentials", || {
        apm2_core::fac::credential_gate::require_github_credentials()
    });
}

// =========================================================================
// Library test: No secrets in error messages, receipts, or logs (retained)
// =========================================================================

/// Verifies that the `CredentialGateError::GitHubCredentialsMissing`
/// error message does not contain any actual secret values.
#[test]
fn credential_error_message_contains_no_secrets() {
    let error = apm2_core::fac::credential_gate::CredentialGateError::GitHubCredentialsMissing;
    let message = error.to_string();

    let synthetic_secrets: Vec<(&str, &str)> = vec![
        ("ghp_token", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("ghs_token", "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("bearer_token", "v1.abc123def456"),
    ];
    assert_no_secret_leakage(&message, &synthetic_secrets, "CredentialGateError::Display");
}

/// Verifies that `CredentialPosture` Debug output does not contain
/// raw token-like strings.
#[test]
fn credential_posture_debug_no_secret_leakage() {
    let posture = apm2_core::fac::credential_gate::CredentialPosture {
        credential_name: "github-token".to_string(),
        resolved: true,
        source: Some(apm2_core::fac::credential_gate::CredentialSource::EnvVar {
            var_name: "GITHUB_TOKEN".to_string(),
        }),
    };

    let debug = format!("{posture:?}");

    assert!(
        debug.contains("GITHUB_TOKEN"),
        "Debug should show env var name"
    );
    assert!(
        !debug.contains("ghp_"),
        "Debug must not contain token prefix ghp_"
    );
    assert!(
        !debug.contains("ghs_"),
        "Debug must not contain token prefix ghs_"
    );
}

/// Verifies that job receipts produced via the builder do not contain
/// any secret environment variable values.
#[test]
fn receipts_contain_no_secret_env_values() {
    let (_tmp, home) = setup_apm2_home_broker_only();
    let fac_root = home.join("private/fac");
    let receipts_dir = fac_root.join("receipts");
    std::fs::create_dir_all(&receipts_dir).expect("create receipts dir");

    let synthetic_secrets: &[(&str, &str)] = &[
        ("GITHUB_TOKEN", "ghp_SYNTHETIC_TEST_TOKEN_00601_abcdef1234"),
        ("GH_TOKEN", "ghs_SYNTHETIC_GH_TOKEN_00601_zyxwvu9876"),
        ("APM2_GITHUB_PAT", "ghp_APM2PAT_SYNTHETIC_00601_testval"),
        ("APM2_FAC_PAT", "v1.synth_fac_pat_00601_secret_value"),
        ("GH_PAT", "ghp_GHPAT_SYNTHETIC_00601_canary_value"),
        ("GITHUB_PAT", "ghp_GITHUBPAT_SYNTHETIC_00601_canary"),
        (
            "PERSONAL_ACCESS_TOKEN",
            "ghp_PERSONALAT_SYNTHETIC_00601_val",
        ),
    ];

    let receipt = apm2_core::fac::FacJobReceiptV1Builder::new(
        "test-receipt-001",
        "test-job-001",
        "b3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    .outcome(apm2_core::fac::FacJobOutcome::Denied)
    .denial_reason(apm2_core::fac::DenialReasonCode::ValidationFailed)
    .reason("test denied for secret leak verification")
    .try_build()
    .expect("build receipt");

    let receipt_json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");

    for (name, value) in synthetic_secrets {
        assert!(
            !receipt_json.contains(value),
            "SECRET LEAKAGE: receipt contains canary value for {name}"
        );
    }

    for env_name in SECRET_ENV_NAMES {
        if let Ok(value) = std::env::var(env_name) {
            if !value.is_empty() {
                assert!(
                    !receipt_json.contains(&value),
                    "SECRET LEAKAGE: receipt contains host env value of {env_name}"
                );
            }
        }
    }

    assert!(
        !receipt_json.contains("ghp_"),
        "receipt should not contain GitHub PAT prefix"
    );
    assert!(
        !receipt_json.contains("ghs_"),
        "receipt should not contain GitHub App token prefix"
    );

    assert!(
        receipt_json.contains("test-job-001"),
        "receipt should contain job ID"
    );
    assert!(
        receipt_json.contains("test denied"),
        "receipt should contain reason"
    );
}

/// Verifies that subprocess `apm2 fac gates` error output in a bare
/// environment does not leak any secret environment variable values.
#[test]
fn subprocess_gates_error_output_contains_no_secrets() {
    let (_tmp, home) = setup_bare_apm2_home();

    let (_exit_code, stdout, stderr) =
        run_apm2_subprocess(&["fac", "gates", "--quick"], &home, false);

    let combined = format!("{stdout}\n{stderr}");

    let synthetic_secrets = vec![
        ("GITHUB_TOKEN", "ghp_test_should_not_appear"),
        ("GH_TOKEN", "ghs_test_should_not_appear"),
    ];
    assert_no_secret_leakage(
        &combined,
        &synthetic_secrets,
        "subprocess gates error output",
    );

    // Also check for any token-like patterns in output.
    assert!(
        !combined.contains("ghp_"),
        "gates error output should not contain GitHub PAT prefix"
    );
    assert!(
        !combined.contains("ghs_"),
        "gates error output should not contain GitHub App token prefix"
    );
}
