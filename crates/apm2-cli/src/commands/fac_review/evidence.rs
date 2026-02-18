//! Evidence gates (fmt, clippy, doc, test, native checks) for FAC push
//! pipeline.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apm2_core::fac::{
    FacPolicyV1, LaneLockGuard, LaneManager, apply_lane_env_overrides, build_job_environment,
    compute_test_env_for_parallelism, ensure_lane_env_dirs,
};
use blake3;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::bounded_test_runner::{
    BoundedTestLimits, build_bounded_gate_command as build_systemd_bounded_gate_command,
    build_bounded_test_command as build_systemd_bounded_test_command,
};
use super::ci_status::{CiStatus, PrBodyStatusUpdater};
use super::gate_attestation::{
    GateResourcePolicy, build_nextest_command, compute_gate_attestation,
    gate_command_for_attestation, short_digest,
};
use super::gate_cache::{GateCache, ReuseDecision};
use super::gate_checks;
use super::merge_conflicts::{
    check_merge_conflicts_against_main, render_merge_conflict_log, render_merge_conflict_summary,
};
use super::timeout_policy::{
    DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS, DEFAULT_TEST_MEMORY_MAX, TEST_TIMEOUT_SLA_MESSAGE,
    max_memory_bytes, parse_memory_limit, resolve_bounded_test_timeout,
};
use super::types::now_iso8601;

/// Env var keys unconditionally stripped from ALL gate phases as
/// defense-in-depth against wrapper injection (TCK-00526, TCK-00548). These are
/// stripped by `build_job_environment` at the policy level AND by
/// `env_remove()` on the spawned `Command` for belt-and-suspenders containment.
const WRAPPER_STRIP_KEYS: &[&str] = &["RUSTC_WRAPPER"];

/// Prefix for env vars unconditionally stripped from ALL gate phases.
const WRAPPER_STRIP_PREFIXES: &[&str] = &["SCCACHE_"];

/// Compute the full set of wrapper-stripping `env_remove_keys` by combining the
/// static `WRAPPER_STRIP_KEYS` with any variables matching
/// `WRAPPER_STRIP_PREFIXES` discovered from both the ambient process
/// environment AND the provided policy-filtered environment. This ensures that
/// variables introduced by `env_set` in the policy (not present in the ambient
/// env) are also stripped as defense-in-depth.
fn compute_gate_env_remove_keys(policy_env: Option<&[(String, String)]>) -> Vec<String> {
    let mut keys: Vec<String> = WRAPPER_STRIP_KEYS
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    // Scan the ambient process environment.
    for (key, _) in std::env::vars() {
        if WRAPPER_STRIP_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
            && !keys.contains(&key)
        {
            keys.push(key);
        }
    }
    // Also scan the policy-filtered environment for policy-introduced variables
    // that were not in the ambient environment.
    if let Some(envs) = policy_env {
        for (key, _) in envs {
            if WRAPPER_STRIP_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
                && !keys.contains(key)
            {
                keys.push(key.clone());
            }
        }
    }
    keys
}

/// Progress events emitted throughout evidence gate execution.
///
/// Callers can provide a callback via [`EvidenceGateOptions::on_gate_progress`]
/// to receive these events in real time — enabling JSONL streaming of per-gate
/// lifecycle events during execution rather than after all gates complete.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Callback consumers are optional; fields remain part of the streaming contract.
pub enum GateProgressEvent {
    /// Emitted immediately before a gate starts executing.
    Started { gate_name: String },
    /// Emitted periodically while a gate is still running.
    Progress {
        gate_name: String,
        elapsed_secs: u64,
        bytes_streamed: u64,
    },
    /// Emitted immediately after a gate finishes executing.
    Completed {
        gate_name: String,
        passed: bool,
        duration_secs: u64,
        log_path: Option<String>,
        bytes_written: Option<u64>,
        bytes_total: Option<u64>,
        was_truncated: Option<bool>,
        log_bundle_hash: Option<String>,
        error_hint: Option<String>,
    },
}

/// Options for customizing evidence gate execution.
#[allow(dead_code)] // TCK-00540: allow_legacy_cache is wired for future cache-reuse in CLI path.
#[allow(clippy::struct_excessive_bools)]
pub struct EvidenceGateOptions {
    /// Override command for the test phase. When `Some`, the test gate uses
    /// this command instead of `cargo nextest run ...`.
    pub test_command: Option<Vec<String>>,
    /// Extra environment variables applied when invoking a bounded test runner.
    pub test_command_environment: Vec<(String, String)>,
    /// Env var keys to remove from the spawned test process environment.
    /// Prevents parent process env inheritance of `sccache`/`RUSTC_WRAPPER`
    /// keys that could bypass cgroup containment (TCK-00548).
    pub env_remove_keys: Vec<String>,
    /// Skip the heavyweight test gate for quick inner-loop validation.
    pub skip_test_gate: bool,
    /// Skip merge-conflict gate when caller already pre-validated it.
    pub skip_merge_conflict_gate: bool,
    /// Emit human-oriented status/heartbeat lines to stderr.
    /// JSON streaming callers should set this to `false`.
    pub emit_human_logs: bool,
    /// Optional callback invoked throughout gate execution.
    ///
    /// When set, this callback receives [`GateProgressEvent::Started`] before
    /// each gate begins, [`GateProgressEvent::Progress`] heartbeats while a
    /// gate is running, and [`GateProgressEvent::Completed`] after each gate
    /// finishes. This enables real-time JSONL streaming of per-gate lifecycle
    /// progress instead of buffering all events until `run_evidence_gates`
    /// returns.
    pub on_gate_progress: Option<Box<dyn Fn(GateProgressEvent) + Send>>,
    /// TCK-00540: When `true`, permit reuse of legacy gate cache entries that
    /// lack RFC-0028/0029 receipt bindings. This is an **unsafe** escape hatch
    /// for migration; default-deny is the fail-closed posture.
    pub allow_legacy_cache: bool,
}

/// Result of a single evidence gate execution.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // Streaming-stats fields are populated for future observability consumers.
pub struct EvidenceGateResult {
    pub gate_name: String,
    pub passed: bool,
    pub duration_secs: u64,
    pub log_path: Option<PathBuf>,
    pub bytes_written: Option<u64>,
    pub bytes_total: Option<u64>,
    pub was_truncated: Option<bool>,
    pub log_bundle_hash: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct StreamStats {
    bytes_written: u64,
    bytes_total: u64,
    was_truncated: bool,
}

/// Emit a gate-started progress event via the optional callback in
/// [`EvidenceGateOptions`].
fn emit_gate_started(opts: Option<&EvidenceGateOptions>, gate_name: &str) {
    if let Some(opts) = opts {
        if let Some(ref cb) = opts.on_gate_progress {
            cb(GateProgressEvent::Started {
                gate_name: gate_name.to_string(),
            });
        }
    }
}

/// Emit a gate-completed progress event via the optional callback in
/// [`EvidenceGateOptions`].
fn emit_gate_completed(opts: Option<&EvidenceGateOptions>, result: &EvidenceGateResult) {
    if let Some(opts) = opts {
        if let Some(ref cb) = opts.on_gate_progress {
            emit_gate_completed_via_cb(&**cb, result);
        }
    }
}

/// Emit a gate-started progress event via a bare callback reference.
fn emit_gate_started_cb(cb: Option<&dyn Fn(GateProgressEvent)>, gate_name: &str) {
    if let Some(cb) = cb {
        cb(GateProgressEvent::Started {
            gate_name: gate_name.to_string(),
        });
    }
}

/// Emit a gate-progress heartbeat event via a bare callback reference.
fn emit_gate_progress_cb(
    cb: Option<&dyn Fn(GateProgressEvent)>,
    gate_name: &str,
    elapsed_secs: u64,
    bytes_streamed: u64,
) {
    if let Some(cb) = cb {
        cb(GateProgressEvent::Progress {
            gate_name: gate_name.to_string(),
            elapsed_secs,
            bytes_streamed,
        });
    }
}

/// Emit a gate-completed progress event via a bare callback reference.
fn emit_gate_completed_cb(cb: Option<&dyn Fn(GateProgressEvent)>, result: &EvidenceGateResult) {
    if let Some(cb) = cb {
        emit_gate_completed_via_cb(cb, result);
    }
}

/// Shared implementation for emitting a gate-completed event.
fn emit_gate_completed_via_cb(cb: &dyn Fn(GateProgressEvent), result: &EvidenceGateResult) {
    let error_hint = if result.passed {
        None
    } else {
        result
            .log_path
            .as_deref()
            .and_then(super::jsonl::read_log_error_hint)
    };
    cb(GateProgressEvent::Completed {
        gate_name: result.gate_name.clone(),
        passed: result.passed,
        duration_secs: result.duration_secs,
        log_path: result
            .log_path
            .as_ref()
            .and_then(|p| p.to_str())
            .map(str::to_string),
        bytes_written: result.bytes_written,
        bytes_total: result.bytes_total,
        was_truncated: result.was_truncated,
        log_bundle_hash: result.log_bundle_hash.clone(),
        error_hint,
    });
}

/// Canonical list of lane-scoped evidence gate names used by the FAC pipeline.
///
/// Shared across evidence collection, log discovery, and push projection so
/// the gate list is defined in a single place.
pub const LANE_EVIDENCE_GATES: &[&str] = &[
    "merge_conflict_main",
    "rustfmt",
    "clippy",
    "doc",
    "test",
    "test_safety_guard",
    "workspace_integrity",
    "review_artifact_lint",
];

const SHORT_TEST_OUTPUT_HINT_THRESHOLD_BYTES: usize = 1024;
const LOG_STREAM_MAX_BYTES: u64 = 4 * 1024 * 1024;
const LOG_STREAM_CHUNK_BYTES: usize = 16 * 1024;
const LOG_BUNDLE_SCHEMA: &str = "apm2.fac.log_bundle.v1";
// Observability-only monotonic pulse cadence (not HTF authority time).
const MONOTONIC_HEARTBEAT_TICK_SECS: u64 = 10;
const GATE_WAIT_POLL_MILLIS: u64 = 250;
const MERGE_CONFLICT_GATE_NAME: &str = "merge_conflict_main";
const DEFAULT_TEST_PIDS_MAX: u64 = 1536;
const DEFAULT_TEST_KILL_AFTER_SECONDS: u64 = 20;

struct GateCommandOutput {
    status: ExitStatus,
    stream_stats: StreamStats,
}

fn sha256_file_hex(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

fn gate_attestation_digest(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    test_command_override: Option<&[String]>,
    policy: &GateResourcePolicy,
) -> Option<String> {
    let command = gate_command_for_attestation(workspace_root, gate_name, test_command_override)?;
    compute_gate_attestation(workspace_root, sha, gate_name, &command, policy)
        .ok()
        .map(|attestation| attestation.attestation_digest)
}

fn reuse_decision_for_gate(
    cache: Option<&GateCache>,
    gate_name: &str,
    attestation_digest: Option<&str>,
    verifying_key: Option<&apm2_core::crypto::VerifyingKey>,
    allow_legacy_cache: bool,
) -> ReuseDecision {
    cache.map_or_else(
        || ReuseDecision::miss("no_record"),
        |cached| {
            cached.check_reuse(
                gate_name,
                attestation_digest,
                true,
                verifying_key,
                allow_legacy_cache,
            )
        },
    )
}

fn stream_pipe_to_file<R: Read>(
    mut pipe: R,
    output_file: &Arc<Mutex<File>>,
    shared_bytes: &Arc<AtomicU64>,
    stream_prefix: &str,
) -> std::io::Result<StreamStats> {
    {
        let mut output = output_file
            .lock()
            .map_err(|_| std::io::Error::other("log file mutex poisoned"))?;
        output.write_all(stream_prefix.as_bytes())?;
        output.write_all(b"\n")?;
    }

    let mut stats = StreamStats::default();
    let mut buffer = [0_u8; LOG_STREAM_CHUNK_BYTES];
    loop {
        let bytes_read = pipe.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let chunk_bytes = u64::try_from(bytes_read).unwrap_or(u64::MAX);
        let total_before = shared_bytes.fetch_add(chunk_bytes, Ordering::SeqCst);
        stats.bytes_total += chunk_bytes;

        if total_before >= LOG_STREAM_MAX_BYTES {
            stats.was_truncated = true;
            continue;
        }

        let remaining_cap = LOG_STREAM_MAX_BYTES.saturating_sub(total_before);
        if remaining_cap == 0 {
            stats.was_truncated = true;
            continue;
        }

        let write_len = usize::try_from(
            remaining_cap
                .min(chunk_bytes)
                .min(LOG_STREAM_CHUNK_BYTES as u64),
        )
        .map_err(|_| std::io::Error::other("stream read chunk exceeds platform limit"))?;
        if write_len > 0 {
            let mut output = output_file
                .lock()
                .map_err(|_| std::io::Error::other("log file mutex poisoned"))?;
            output.write_all(&buffer[..write_len])?;
            stats.bytes_written += write_len as u64;
        }

        if write_len as u64 != chunk_bytes {
            stats.was_truncated = true;
        }
    }

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn run_gate_command_with_heartbeat(
    workspace_root: &Path,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    extra_env: Option<&[(String, String)]>,
    env_remove_keys: Option<&[String]>,
    emit_human_logs: bool,
    on_gate_progress: Option<&dyn Fn(GateProgressEvent)>,
) -> std::io::Result<GateCommandOutput> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .current_dir(workspace_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // TCK-00526: When a policy-filtered environment is provided, clear
    // the inherited environment first (default-deny) and then apply only
    // the policy-approved variables. Without env_clear(), Command::env()
    // adds to the inherited environment, leaking ambient secrets into
    // gate processes.
    if let Some(envs) = extra_env {
        command.env_clear();
        for (key, value) in envs {
            command.env(key, value);
        }
    }

    // Strip env vars that must not be inherited by the bounded test
    // process (e.g. RUSTC_WRAPPER, SCCACHE_* — TCK-00548).
    // When env_clear() is active this is defense-in-depth; when extra_env
    // is None (legacy callers) it prevents specific keys from leaking.
    if let Some(keys) = env_remove_keys {
        for key in keys {
            command.env_remove(key);
        }
    }

    let mut child = command.spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stdout for evidence gate"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stderr for evidence gate"))?;

    crate::commands::fac_permissions::write_fac_file_with_mode(log_path, b"").map_err(|err| {
        std::io::Error::other(format!(
            "failed to initialize evidence gate log {}: {err}",
            log_path.display()
        ))
    })?;

    let output_file = crate::commands::fac_permissions::append_fac_file_with_mode(log_path)
        .map_err(|err| {
            std::io::Error::other(format!(
                "failed to open evidence gate log {}: {err}",
                log_path.display()
            ))
        })?;
    let output_file = Arc::new(Mutex::new(output_file));
    let shared_bytes = Arc::new(AtomicU64::new(0));

    let stdout_handle = {
        let output_file = Arc::clone(&output_file);
        let shared_bytes = Arc::clone(&shared_bytes);
        thread::spawn(move || {
            stream_pipe_to_file(stdout, &output_file, &shared_bytes, "=== stdout ===")
        })
    };
    let stderr_handle = {
        let output_file = Arc::clone(&output_file);
        let shared_bytes = Arc::clone(&shared_bytes);
        thread::spawn(move || {
            stream_pipe_to_file(stderr, &output_file, &shared_bytes, "=== stderr ===")
        })
    };

    let started = Instant::now();
    let heartbeat_interval = Duration::from_secs(MONOTONIC_HEARTBEAT_TICK_SECS);
    let mut next_heartbeat = heartbeat_interval;

    let exit_status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        let elapsed = started.elapsed();
        if elapsed >= next_heartbeat {
            let elapsed_secs = elapsed.as_secs();
            let bytes_streamed = shared_bytes.load(Ordering::SeqCst);
            emit_gate_progress_cb(on_gate_progress, gate_name, elapsed_secs, bytes_streamed);
            if emit_human_logs {
                eprintln!(
                    "ts={} gate={} status=RUNNING tick={} elapsed_secs={}",
                    now_iso8601(),
                    gate_name,
                    elapsed_secs / MONOTONIC_HEARTBEAT_TICK_SECS,
                    elapsed_secs,
                );
            }
            // Keep heartbeat ticks aligned to fixed wall intervals.
            while elapsed >= next_heartbeat {
                next_heartbeat += heartbeat_interval;
            }
        }

        thread::sleep(Duration::from_millis(GATE_WAIT_POLL_MILLIS));
    };

    let stdout_stats = stdout_handle
        .join()
        .map_err(|_| std::io::Error::other("stdout stream thread panicked"))??;
    let stderr_stats = stderr_handle
        .join()
        .map_err(|_| std::io::Error::other("stderr stream thread panicked"))??;

    let mut stream_stats = StreamStats {
        bytes_written: stdout_stats.bytes_written + stderr_stats.bytes_written,
        bytes_total: stdout_stats.bytes_total + stderr_stats.bytes_total,
        was_truncated: stdout_stats.was_truncated || stderr_stats.was_truncated,
    };
    if stream_stats.bytes_written >= LOG_STREAM_MAX_BYTES {
        stream_stats.was_truncated = true;
    }

    Ok(GateCommandOutput {
        status: exit_status,
        stream_stats,
    })
}

/// Format and emit a single evidence line to stderr and an optional projection
/// log.
pub fn emit_evidence_line(
    sha: &str,
    gate: &str,
    status: &str,
    duration_secs: u64,
    log_path: &Path,
    projection_log: Option<&mut File>,
    emit_to_stderr: bool,
) {
    let ts = now_iso8601();
    let line = format!(
        "ts={ts} sha={sha} gate={gate} status={status} duration_secs={duration_secs} log={}",
        log_path.display()
    );
    if emit_to_stderr {
        eprintln!("{line}");
    }
    if let Some(file) = projection_log {
        let _ = writeln!(file, "{line}");
    }
}

fn append_short_test_failure_hint(log_path: &Path, combined_output_bytes: usize) {
    if combined_output_bytes >= SHORT_TEST_OUTPUT_HINT_THRESHOLD_BYTES {
        return;
    }

    let Ok(mut file) = crate::commands::fac_permissions::append_fac_file_with_mode(log_path) else {
        return;
    };

    let _ = writeln!(file);
    let _ = writeln!(file, "--- fac diagnostic ---");
    let _ = writeln!(
        file,
        "Test gate failed with minimal output ({combined_output_bytes} bytes). This usually indicates the process was killed by an OOM or timeout before tests could run."
    );
    let _ = writeln!(file, "{TEST_TIMEOUT_SLA_MESSAGE}");
    let _ = writeln!(file, "Check:");
    let _ = writeln!(file, "  journalctl --user --since '10 minutes ago'");
    let _ = writeln!(
        file,
        "  apm2 fac gates --memory-max 48G  # default is 48G; increase if needed"
    );
}

fn run_merge_conflict_gate(
    workspace_root: &Path,
    sha: &str,
    log_path: &Path,
    emit_human_logs: bool,
) -> (bool, u64, String, StreamStats) {
    let gate_name = MERGE_CONFLICT_GATE_NAME;
    let started = Instant::now();

    match check_merge_conflicts_against_main(workspace_root, sha) {
        Ok(report) => {
            let duration = started.elapsed().as_secs();
            let passed = !report.has_conflicts();
            let log = render_merge_conflict_log(&report);
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                log.as_bytes(),
            );
            let stats = StreamStats {
                bytes_written: log.len() as u64,
                bytes_total: log.len() as u64,
                was_truncated: false,
            };
            if emit_human_logs && !passed {
                eprintln!("{}", render_merge_conflict_summary(&report));
            }
            let gate_status = if passed { "PASS" } else { "FAIL" };
            emit_evidence_line(
                sha,
                gate_name,
                gate_status,
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            let ts = now_iso8601();
            (
                passed,
                duration,
                format!(
                    "ts={ts} sha={sha} gate={gate_name} status={gate_status} log={}",
                    log_path.display()
                ),
                stats,
            )
        },
        Err(err) => {
            let duration = started.elapsed().as_secs();
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!("merge conflict gate execution error: {err}\n").as_bytes(),
            );
            let message = format!("merge conflict gate execution error: {err}\n");
            let stats = StreamStats {
                bytes_written: message.len() as u64,
                bytes_total: message.len() as u64,
                was_truncated: false,
            };
            emit_evidence_line(
                sha,
                gate_name,
                "FAIL",
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            if emit_human_logs {
                eprintln!("merge_conflict_main: FAIL reason={err}");
            }
            let ts = now_iso8601();
            let sanitized_err = err.split_whitespace().collect::<Vec<_>>().join("_");
            (
                false,
                duration,
                format!(
                    "ts={ts} sha={sha} gate={gate_name} status=FAIL log={} error={}",
                    log_path.display(),
                    sanitized_err
                ),
                stats,
            )
        },
    }
}

/// Run a single evidence gate and emit the result.
///
/// NOTE: Production callers should prefer `run_single_evidence_gate_with_env`
/// with a policy-filtered environment. This wrapper passes `None` for env
/// (inheriting ambient) and is retained for test use.
#[allow(dead_code)] // Used by integration tests in this module.
pub fn run_single_evidence_gate(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    emit_human_logs: bool,
) -> (bool, StreamStats) {
    run_single_evidence_gate_with_env(
        workspace_root,
        sha,
        gate_name,
        cmd,
        args,
        log_path,
        None,
        None,
        emit_human_logs,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_single_evidence_gate_with_env(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    extra_env: Option<&[(String, String)]>,
    env_remove_keys: Option<&[String]>,
    emit_human_logs: bool,
) -> (bool, StreamStats) {
    run_single_evidence_gate_with_env_and_progress(
        workspace_root,
        sha,
        gate_name,
        cmd,
        args,
        log_path,
        extra_env,
        env_remove_keys,
        emit_human_logs,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_single_evidence_gate_with_env_and_progress(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    extra_env: Option<&[(String, String)]>,
    env_remove_keys: Option<&[String]>,
    emit_human_logs: bool,
    on_gate_progress: Option<&dyn Fn(GateProgressEvent)>,
) -> (bool, StreamStats) {
    let started = Instant::now();
    let output = run_gate_command_with_heartbeat(
        workspace_root,
        gate_name,
        cmd,
        args,
        log_path,
        extra_env,
        env_remove_keys,
        emit_human_logs,
        on_gate_progress,
    );
    let duration = started.elapsed().as_secs();
    match output {
        Ok(out) => {
            let passed = out.status.success();
            if !passed && gate_name == "test" {
                let combined_output_bytes =
                    usize::try_from(out.stream_stats.bytes_total).unwrap_or(usize::MAX);
                append_short_test_failure_hint(log_path, combined_output_bytes);
            }
            let status = if passed { "PASS" } else { "FAIL" };
            emit_evidence_line(
                sha,
                gate_name,
                status,
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            (passed, out.stream_stats)
        },
        Err(e) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!("execution error: {e}\n").as_bytes(),
            );
            emit_evidence_line(
                sha,
                gate_name,
                "FAIL",
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            (
                false,
                StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                },
            )
        },
    }
}

fn run_native_evidence_gate(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    log_path: &Path,
    emit_human_logs: bool,
) -> (bool, StreamStats) {
    let started = Instant::now();
    let execution = match gate_name {
        "test_safety_guard" => gate_checks::run_test_safety_guard(workspace_root),
        "review_artifact_lint" => gate_checks::run_review_artifact_lint(workspace_root),
        _ => Err(format!("unknown native evidence gate `{gate_name}`")),
    };
    let duration = started.elapsed().as_secs();

    match execution {
        Ok(check) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                check.output.as_bytes(),
            );
            let bytes = u64::try_from(check.output.len()).unwrap_or(u64::MAX);
            emit_evidence_line(
                sha,
                gate_name,
                if check.passed { "PASS" } else { "FAIL" },
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            (
                check.passed,
                StreamStats {
                    bytes_written: bytes,
                    bytes_total: bytes,
                    was_truncated: false,
                },
            )
        },
        Err(err) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!("execution error: {err}\n").as_bytes(),
            );
            emit_evidence_line(
                sha,
                gate_name,
                "FAIL",
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            (
                false,
                StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                },
            )
        },
    }
}

/// Snapshot file path for workspace integrity (stored under target/ci/).
fn workspace_integrity_snapshot(workspace_root: &Path) -> PathBuf {
    workspace_root.join(gate_checks::WORKSPACE_INTEGRITY_SNAPSHOT_REL_PATH)
}

/// Take a baseline workspace integrity snapshot before test execution.
/// Returns `true` if snapshot was created successfully.
fn snapshot_workspace_integrity(workspace_root: &Path) -> bool {
    let snapshot = workspace_integrity_snapshot(workspace_root);
    gate_checks::snapshot_workspace_integrity(workspace_root, &snapshot).is_ok()
}

/// Verify workspace integrity against a previously captured snapshot.
fn verify_workspace_integrity_gate(
    workspace_root: &Path,
    sha: &str,
    log_path: &Path,
    emit_human_logs: bool,
) -> (bool, String, StreamStats) {
    let snapshot = workspace_integrity_snapshot(workspace_root);
    let log_path = log_path.to_path_buf();
    let gate_name = "workspace_integrity";
    let started = Instant::now();
    let execution = gate_checks::verify_workspace_integrity(workspace_root, &snapshot, None);
    let duration = started.elapsed().as_secs();

    let (passed, stream_stats) = match execution {
        Ok(check) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                &log_path,
                check.output.as_bytes(),
            );
            let bytes = u64::try_from(check.output.len()).unwrap_or(u64::MAX);
            emit_evidence_line(
                sha,
                gate_name,
                if check.passed { "PASS" } else { "FAIL" },
                duration,
                &log_path,
                None,
                emit_human_logs,
            );
            (
                check.passed,
                StreamStats {
                    bytes_written: bytes,
                    bytes_total: bytes,
                    was_truncated: false,
                },
            )
        },
        Err(err) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                &log_path,
                format!("execution error: {err}\n").as_bytes(),
            );
            emit_evidence_line(
                sha,
                gate_name,
                "FAIL",
                duration,
                &log_path,
                None,
                emit_human_logs,
            );
            (
                false,
                StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                },
            )
        },
    };

    let ts = now_iso8601();
    let status = if passed { "PASS" } else { "FAIL" };
    let line = format!(
        "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
        log_path.display()
    );
    (passed, line, stream_stats)
}

#[derive(Debug)]
struct PipelineTestCommand {
    command: Vec<String>,
    bounded_runner: bool,
    effective_timeout_seconds: u64,
    gate_profile: super::gates::GateThroughputProfile,
    effective_cpu_quota: String,
    effective_test_parallelism: u32,
    test_env: Vec<(String, String)>,
    /// Env var keys to remove from the spawned process environment.
    /// Prevents parent env inheritance of `sccache`/`RUSTC_WRAPPER` keys
    /// that could bypass the bounded test's cgroup containment (TCK-00548).
    env_remove_keys: Vec<String>,
    /// BLAKE3 hex hash of the effective `SandboxHardeningProfile` used for
    /// bounded test execution. Carried through so attestation binds to the
    /// actual policy-driven profile, not a default (TCK-00573 MAJOR-1 fix).
    sandbox_hardening_hash: String,
    /// BLAKE3 hex hash of the effective `NetworkPolicy` used for gate
    /// execution. Carried through so attestation binds to the actual
    /// policy-driven network posture, preventing cache reuse across
    /// policy drift (TCK-00574 MAJOR-1 fix).
    network_policy_hash: String,
}

/// Build the pipeline test command with policy-filtered environment.
///
/// # Arguments
///
/// * `workspace_root` - The workspace root directory.
/// * `lane_dir` - The lane directory from the actually-locked lane (returned by
///   `allocate_lane_job_logs_dir`). This MUST correspond to the lane protected
///   by the caller's `LaneLockGuard` to maintain lock/env coupling and prevent
///   concurrent access races.
fn build_pipeline_test_command(
    workspace_root: &Path,
    lane_dir: &Path,
) -> Result<PipelineTestCommand, String> {
    let memory_max_bytes = parse_memory_limit(DEFAULT_TEST_MEMORY_MAX)?;
    if memory_max_bytes > max_memory_bytes() {
        return Err(format!(
            "--memory-max {} exceeds FAC cap {}",
            DEFAULT_TEST_MEMORY_MAX,
            max_memory_bytes()
        ));
    }

    // Derive roots from the locked lane path to avoid ambient env races.
    let (apm2_home, fac_root) = resolve_pipeline_roots_from_lane_dir(lane_dir)?;
    let policy = load_or_create_pipeline_policy(&fac_root)?;

    // Ensure managed CARGO_HOME exists when policy denies ambient.
    if let Some(cargo_home) = policy.resolve_cargo_home(&apm2_home) {
        ensure_pipeline_managed_cargo_home(&cargo_home)?;
    }

    let timeout_decision =
        resolve_bounded_test_timeout(workspace_root, DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS);
    let gate_profile = super::gates::GateThroughputProfile::Throughput;
    // Throughput profile is intentionally host-aware and unconstrained by lane
    // count. Concurrency is controlled by queue admission rather than
    // per-lane CPU throttling so a single active pipeline can use full machine
    // capacity.
    let execution_profile = super::gates::resolve_gate_execution_profile(gate_profile);
    let effective_cpu_quota = format!("{}%", execution_profile.cpu_quota_percent);
    let lane_env = compute_test_env_for_parallelism(execution_profile.test_parallelism);

    // TCK-00526: Build policy-filtered environment.
    let ambient: Vec<(String, String)> = std::env::vars().collect();
    let mut policy_env = build_job_environment(&policy, &ambient, &apm2_home);

    // TCK-00575: Apply per-lane env isolation (HOME, TMPDIR, XDG_CACHE_HOME,
    // XDG_CONFIG_HOME). Uses the lane directory from the actually-locked lane
    // to maintain lock/env coupling (round 2 fix: was previously hardcoded
    // to lane-00).
    ensure_lane_env_dirs(lane_dir)?;
    apply_lane_env_overrides(&mut policy_env, lane_dir);

    for (key, value) in &lane_env {
        policy_env.insert(key.clone(), value.clone());
    }
    let mut test_env: Vec<(String, String)> = policy_env.into_iter().collect();

    // TCK-00573 MAJOR-1 fix: compute the effective sandbox hardening hash
    // BEFORE the profile is moved into build_systemd_bounded_test_command,
    // so attestation binds to the actual policy-driven profile.
    let sandbox_hardening_hash = policy.sandbox_hardening.content_hash_hex();

    // TCK-00574: Resolve network policy for evidence gates with operator override.
    // Compute the hash BEFORE the policy is moved into the bounded test command
    // builder, so attestation binds to the actual policy-driven network posture
    // (MAJOR-1 fix: attestation digest must change when network policy changes).
    let evidence_network_policy =
        apm2_core::fac::resolve_network_policy("gates", policy.network_policy.as_ref());
    let network_policy_hash = evidence_network_policy.content_hash_hex();
    let bounded_spec = build_systemd_bounded_test_command(
        workspace_root,
        BoundedTestLimits {
            timeout_seconds: timeout_decision.effective_seconds,
            kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
            memory_max: DEFAULT_TEST_MEMORY_MAX,
            pids_max: DEFAULT_TEST_PIDS_MAX,
            cpu_quota: &effective_cpu_quota,
        },
        &build_nextest_command(),
        &test_env,
        policy.sandbox_hardening,
        evidence_network_policy,
    )
    .map_err(|err| format!("bounded test runner unavailable for FAC pipeline: {err}"))?;
    test_env.extend(bounded_spec.environment);
    test_env.extend(bounded_spec.setenv_pairs);

    Ok(PipelineTestCommand {
        command: bounded_spec.command,
        bounded_runner: true,
        effective_timeout_seconds: timeout_decision.effective_seconds,
        gate_profile,
        effective_cpu_quota,
        effective_test_parallelism: execution_profile.test_parallelism,
        test_env,
        env_remove_keys: bounded_spec.env_remove_keys,
        sandbox_hardening_hash,
        network_policy_hash,
    })
}

fn resolve_pipeline_roots_from_lane_dir(lane_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let lane_parent = lane_dir.parent().ok_or_else(|| {
        format!(
            "invalid lane dir {}: missing parent lanes directory",
            lane_dir.display()
        )
    })?;
    if lane_parent.file_name() != Some(OsStr::new("lanes")) {
        return Err(format!(
            "invalid lane dir {}: expected parent directory named 'lanes'",
            lane_dir.display()
        ));
    }
    let fac_root = lane_parent.parent().ok_or_else(|| {
        format!(
            "invalid lane dir {}: missing FAC root ancestor",
            lane_dir.display()
        )
    })?;
    if fac_root.file_name() != Some(OsStr::new("fac")) {
        return Err(format!(
            "invalid lane dir {}: expected FAC root ancestor named 'fac'",
            lane_dir.display()
        ));
    }
    let private_dir = fac_root.parent().ok_or_else(|| {
        format!(
            "invalid lane dir {}: missing private directory ancestor",
            lane_dir.display()
        )
    })?;
    if private_dir.file_name() != Some(OsStr::new("private")) {
        return Err(format!(
            "invalid lane dir {}: expected private ancestor named 'private'",
            lane_dir.display()
        ));
    }
    let apm2_home = private_dir.parent().ok_or_else(|| {
        format!(
            "invalid lane dir {}: missing APM2 home ancestor",
            lane_dir.display()
        )
    })?;
    Ok((apm2_home.to_path_buf(), fac_root.to_path_buf()))
}

fn resolve_evidence_test_command_override(test_command_override: Option<&[String]>) -> Vec<String> {
    test_command_override.map_or_else(build_nextest_command, <[_]>::to_vec)
}

fn resolve_evidence_test_command_environment(
    opts: Option<&EvidenceGateOptions>,
) -> Option<&[(String, String)]> {
    opts.and_then(|o| {
        (!o.test_command_environment.is_empty()).then_some(o.test_command_environment.as_slice())
    })
}

fn resolve_evidence_env_remove_keys(opts: Option<&EvidenceGateOptions>) -> Option<&[String]> {
    opts.and_then(|o| (!o.env_remove_keys.is_empty()).then_some(o.env_remove_keys.as_slice()))
}

fn resolve_evidence_gate_progress_callback(
    opts: Option<&EvidenceGateOptions>,
) -> Option<&dyn Fn(GateProgressEvent)> {
    opts.and_then(|o| {
        o.on_gate_progress
            .as_deref()
            .map(|cb| cb as &dyn Fn(GateProgressEvent))
    })
}

/// Build a policy-filtered environment for all evidence gates (not just
/// the test gate). Enforces default-deny by starting from an empty
/// environment and inheriting only allowlisted variables per
/// `FacPolicyV1`.
///
/// TCK-00526: Previously only the test gate received a policy-filtered
/// environment. This function is used by `run_evidence_gates` and
/// `run_evidence_gates_with_status` to apply the same policy to
/// fmt/clippy/doc and script gates.
///
/// TCK-00575: Applies per-lane env isolation (`HOME`, `TMPDIR`,
/// `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`) so every FAC gate phase runs with
/// deterministic lane-local values, preventing writes to ambient user
/// locations.
///
/// # Arguments
///
/// * `lane_dir` - The lane directory from the actually-locked lane (returned by
///   `allocate_lane_job_logs_dir`). This MUST correspond to the lane protected
///   by the caller's `LaneLockGuard` to maintain lock/env coupling and prevent
///   concurrent access races (e.g., with `apm2 fac lane reset`).
fn build_gate_policy_env(lane_dir: &Path) -> Result<Vec<(String, String)>, String> {
    let apm2_home = apm2_core::github::resolve_apm2_home()
        .ok_or_else(|| "cannot resolve APM2_HOME for gate env policy enforcement".to_string())?;
    let fac_root = apm2_home.join("private/fac");
    let policy = load_or_create_pipeline_policy(&fac_root)?;

    if let Some(cargo_home) = policy.resolve_cargo_home(&apm2_home) {
        ensure_pipeline_managed_cargo_home(&cargo_home)?;
    }

    let ambient: Vec<(String, String)> = std::env::vars().collect();
    let mut policy_env = build_job_environment(&policy, &ambient, &apm2_home);

    // TCK-00575: Apply per-lane env isolation for all evidence gate phases.
    // Uses the lane directory from the actually-locked lane to maintain
    // lock/env coupling (round 2 fix: was previously hardcoded to lane-00).
    ensure_lane_env_dirs(lane_dir)?;
    apply_lane_env_overrides(&mut policy_env, lane_dir);

    Ok(policy_env.into_iter().collect())
}

/// Load or create FAC policy. Delegates to the shared `policy_loader` module
/// for bounded I/O and deduplication (TCK-00526).
fn load_or_create_pipeline_policy(fac_root: &Path) -> Result<FacPolicyV1, String> {
    super::policy_loader::load_or_create_fac_policy(fac_root)
}

/// Ensure managed `CARGO_HOME` directory exists. Delegates to the shared
/// `policy_loader` module (TCK-00526).
fn ensure_pipeline_managed_cargo_home(cargo_home: &Path) -> Result<(), String> {
    super::policy_loader::ensure_managed_cargo_home(cargo_home)
}

/// Result of lane allocation: logs directory, the lane's root directory,
/// and the lock guard that must be held for the lifetime of the job.
pub(super) struct EvidenceLaneContext {
    /// Path to the job-specific logs directory within the lane.
    logs_dir: PathBuf,
    /// Path to the lane's root directory
    /// (`$APM2_HOME/private/fac/lanes/<lane_id>`). Used to derive per-lane
    /// env isolation directories (`HOME`, `TMPDIR`, `XDG_CACHE_HOME`,
    /// `XDG_CONFIG_HOME`) via `ensure_lane_env_dirs` +
    /// `apply_lane_env_overrides`.
    ///
    /// SAFETY: This `lane_dir` corresponds to the lane protected by
    /// `_lane_guard`. Callers MUST use this `lane_dir` (not a hardcoded
    /// `lane-00`) for env overrides to maintain lock/env coupling.
    lane_dir: PathBuf,
    /// Exclusive lock guard for the allocated lane. Must be held for the
    /// entire duration of lane usage to prevent concurrent access (e.g.,
    /// `apm2 fac lane reset` racing with env dir creation).
    _lane_guard: LaneLockGuard,
}

pub(super) fn allocate_evidence_lane_context(
    lane_manager: &LaneManager,
    lane_id: &str,
    lane_lock: LaneLockGuard,
) -> Result<EvidenceLaneContext, String> {
    let lane_dir = lane_manager.lane_dir(lane_id);
    let logs_dir = lane_dir.join("logs").join(Uuid::new_v4().to_string());
    crate::commands::fac_permissions::ensure_dir_with_mode(&logs_dir)
        .map_err(|err| format!("failed to create job log dir {}: {err}", logs_dir.display()))?;
    Ok(EvidenceLaneContext {
        logs_dir,
        lane_dir,
        _lane_guard: lane_lock,
    })
}

fn allocate_lane_job_logs_dir() -> Result<EvidenceLaneContext, String> {
    let lane_manager = LaneManager::from_default_home()
        .map_err(|err| format!("failed to resolve lane manager: {err}"))?;
    lane_manager
        .ensure_directories()
        .map_err(|err| format!("failed to ensure FAC lane directories: {err}"))?;

    for lane_id in LaneManager::default_lane_ids() {
        match lane_manager.try_lock(&lane_id) {
            Ok(Some(guard)) => {
                return allocate_evidence_lane_context(&lane_manager, &lane_id, guard);
            },
            Ok(None) => {},
            Err(err) => {
                return Err(format!("failed to inspect lane {lane_id}: {err}"));
            },
        }
    }

    Err("no free FAC lane available for evidence gates".to_string())
}

fn build_evidence_gate_result(
    gate_name: &str,
    passed: bool,
    duration_secs: u64,
    log_path: Option<&Path>,
    stream_stats: Option<&StreamStats>,
) -> EvidenceGateResult {
    EvidenceGateResult {
        gate_name: gate_name.to_string(),
        passed,
        duration_secs,
        log_path: log_path.map(PathBuf::from),
        bytes_written: stream_stats.map(|stats| stats.bytes_written),
        bytes_total: stream_stats.map(|stats| stats.bytes_total),
        was_truncated: stream_stats.map(|stats| stats.was_truncated),
        log_bundle_hash: None,
    }
}

fn write_cached_gate_log_marker(
    log_path: &Path,
    gate_name: &str,
    reuse_reason: &str,
    attestation_digest: Option<&str>,
) -> StreamStats {
    let marker = format!(
        "info: gate={gate_name} result reused from cache (reason={reuse_reason}) attestation_digest={}\n",
        attestation_digest.unwrap_or("unknown")
    );
    let _ = crate::commands::fac_permissions::write_fac_file_with_mode(log_path, marker.as_bytes());
    StreamStats {
        bytes_written: marker.len() as u64,
        bytes_total: marker.len() as u64,
        was_truncated: false,
    }
}

fn attach_log_bundle_hash(
    gate_results: &mut [EvidenceGateResult],
    logs_dir: &Path,
) -> Result<(), String> {
    let log_bundle_hash = compute_log_bundle_hash(logs_dir)?;
    for result in gate_results {
        result.log_bundle_hash = Some(log_bundle_hash.clone());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finalize_status_gate_run(
    projection_log: Option<&mut File>,
    evidence_lines: &[String],
    gate_results: &mut [EvidenceGateResult],
    logs_dir: &Path,
    gate_cache: &mut GateCache,
    updater: &PrBodyStatusUpdater,
    status: &CiStatus,
    signer: &apm2_core::crypto::Signer,
) -> Result<(), String> {
    attach_log_bundle_hash(gate_results, logs_dir)?;

    // Backfill truncation and log-bundle metadata into durable gate receipts
    // so the persisted cache carries the same observability data as the
    // in-memory EvidenceGateResult.
    for result in gate_results {
        gate_cache.backfill_evidence_metadata(
            &result.gate_name,
            result.log_bundle_hash.as_deref(),
            result.bytes_written,
            result.bytes_total,
            result.was_truncated,
            result.log_path.as_ref().and_then(|p| p.to_str()),
        );
    }

    // Force a final update to ensure all gate results are posted.
    updater.force_update(status);

    // TCK-00576: Sign all gate cache entries before persisting.
    gate_cache.sign_all(signer);

    // Persist gate cache so future pipeline runs can reuse results.
    gate_cache
        .save()
        .map_err(|err| format!("failed to persist attested gate cache: {err}"))?;

    if let Some(file) = projection_log {
        for line in evidence_lines {
            let _ = writeln!(file, "{line}");
        }
    }

    Ok(())
}

/// Maximum bytes to read from a single log file during bundle hashing.
/// Slightly larger than `LOG_STREAM_MAX_BYTES` to account for stream prefixes
/// (`=== stdout ===\n`, `=== stderr ===\n`) and any separator overhead that the
/// log writer prepends outside the payload byte counter.
const LOG_BUNDLE_PER_FILE_MAX_BYTES: u64 = LOG_STREAM_MAX_BYTES + 4096;

/// Open a file for reading with `O_NOFOLLOW` to atomically reject symlinks at
/// the kernel level. This eliminates TOCTOU races between metadata checks and
/// file opens — the kernel refuses to follow symlinks in a single syscall.
pub(super) fn open_nofollow(path: &Path) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|err| format!("failed to open {}: {err}", path.display()))
}

fn compute_log_bundle_hash(logs_dir: &Path) -> Result<String, String> {
    let mut log_paths: Vec<PathBuf> = fs::read_dir(logs_dir)
        .map_err(|err| {
            format!(
                "failed to read evidence log directory {}: {err}",
                logs_dir.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            // Pre-filter using symlink_metadata as defense-in-depth to avoid
            // attempting O_NOFOLLOW opens on entries that are obviously not
            // regular files (directories, sockets, etc.).  The actual open
            // below uses O_NOFOLLOW so even if the entry is swapped between
            // this check and the open the kernel will reject the symlink.
            fs::symlink_metadata(path).is_ok_and(|meta| {
                let ft = meta.file_type();
                ft.is_file() && !ft.is_symlink()
            })
        })
        .collect();

    log_paths.sort_by_key(|path| path.file_name().map(std::ffi::OsStr::to_owned));
    let bounded = log_paths.into_iter().take(128);

    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_BUNDLE_SCHEMA.as_bytes());
    hasher.update(b"\0");

    for path in bounded {
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");

        // Open with O_NOFOLLOW to atomically reject symlinks at the kernel
        // level, eliminating the TOCTOU window between the symlink_metadata
        // filter above and this open.
        let file = open_nofollow(&path)
            .map_err(|err| format!("failed to open evidence log file {}: {err}", path.display()))?;
        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if file_size > LOG_BUNDLE_PER_FILE_MAX_BYTES {
            return Err(format!(
                "evidence log file {} exceeds per-file cap ({} > {} bytes)",
                path.display(),
                file_size,
                LOG_BUNDLE_PER_FILE_MAX_BYTES,
            ));
        }
        let mut bytes = Vec::new();
        file.take(LOG_BUNDLE_PER_FILE_MAX_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|err| format!("failed to read evidence log file {}: {err}", path.display()))?;

        let filename_len = u32::try_from(filename.len())
            .map_err(|_| "log filename too long for serialization".to_string())?;
        let content_len = u32::try_from(bytes.len())
            .map_err(|_| "log content too long for serialization".to_string())?;
        hasher.update(&filename_len.to_be_bytes());
        hasher.update(filename.as_bytes());
        hasher.update(&content_len.to_be_bytes());
        hasher.update(&bytes);
    }

    let digest = hasher.finalize();
    Ok(format!("b3-256:{}", hex::encode(digest.as_bytes())))
}

/// Run evidence gates (cargo fmt check, clippy, doc, test, native gate checks).
/// Returns `Ok((all_passed, per_gate_results))`.
/// Fail-closed: any error running a gate counts as failure.
///
/// When `opts` is provided, `test_command` overrides the default
/// `cargo nextest run --workspace` invocation (e.g., to use a bounded runner).
#[allow(dead_code)]
pub fn run_evidence_gates(
    workspace_root: &Path,
    sha: &str,
    projection_log: Option<&mut File>,
    opts: Option<&EvidenceGateOptions>,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let lane_context = allocate_lane_job_logs_dir()?;
    run_evidence_gates_with_lane_context(workspace_root, sha, projection_log, opts, lane_context)
}

pub(super) fn run_evidence_gates_with_lane_context(
    workspace_root: &Path,
    sha: &str,
    projection_log: Option<&mut File>,
    opts: Option<&EvidenceGateOptions>,
    lane_context: EvidenceLaneContext,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let emit_human_logs = opts.is_none_or(|o| o.emit_human_logs);
    let on_gate_progress = resolve_evidence_gate_progress_callback(opts);
    let logs_dir = lane_context.logs_dir;

    // TCK-00526: Build policy-filtered environment for ALL gates (not just
    // the test gate). This enforces default-deny on fmt, clippy, doc, and
    // native gate checks, preventing ambient secret leakage.
    // TCK-00575 round 2: Use the lane_dir from the actually-locked lane
    // (not hardcoded lane-00) to maintain lock/env coupling.
    let gate_env = build_gate_policy_env(&lane_context.lane_dir)?;

    // TCK-00526: Compute wrapper-stripping keys once for ALL gate phases.
    // build_job_environment already strips these at the policy level, but
    // env_remove on the spawned Command provides defense-in-depth against
    // parent process env inheritance. Pass the policy-filtered environment
    // so policy-introduced SCCACHE_* variables are also discovered.
    let gate_wrapper_strip = compute_gate_env_remove_keys(Some(&gate_env));
    let gate_wrapper_strip_ref: Option<&[String]> = if gate_wrapper_strip.is_empty() {
        None
    } else {
        Some(&gate_wrapper_strip)
    };

    let gates: &[(&str, &[&str])] = &[
        ("rustfmt", &["cargo", "fmt", "--all", "--check"]),
        (
            "clippy",
            &[
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("doc", &["cargo", "doc", "--workspace", "--no-deps"]),
    ];

    // Native gates that run BEFORE tests (no ordering dependency on test).
    let pre_test_native_gates: &[&str] = &["test_safety_guard"];

    // Native gates that run AFTER tests (ordering dependency on test).
    let post_test_native_gates: &[&str] = &["review_artifact_lint"];

    let mut evidence_lines = Vec::new();
    let mut gate_results = Vec::new();

    let skip_merge_conflict_gate = opts.is_some_and(|o| o.skip_merge_conflict_gate);
    if !skip_merge_conflict_gate {
        // Phase 0: merge conflict gate (always first, including quick mode).
        let merge_log_path = logs_dir.join(format!("{MERGE_CONFLICT_GATE_NAME}.log"));
        emit_gate_started(opts, MERGE_CONFLICT_GATE_NAME);
        let (merge_passed, merge_duration, merge_line, merge_stats) =
            run_merge_conflict_gate(workspace_root, sha, &merge_log_path, emit_human_logs);
        let merge_result = build_evidence_gate_result(
            MERGE_CONFLICT_GATE_NAME,
            merge_passed,
            merge_duration,
            Some(&merge_log_path),
            Some(&merge_stats),
        );
        emit_gate_completed(opts, &merge_result);
        gate_results.push(merge_result);
        evidence_lines.push(merge_line);
        if !merge_passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    // Phase 1: cargo fmt/clippy/doc — all receive the policy-filtered env
    // and wrapper-stripping keys (TCK-00526: defense-in-depth for all gates).
    //
    // TCK-00574 BLOCKER fix: In full (non-quick) mode, wrap non-test gates
    // in systemd-run with network policy isolation directives to enforce
    // default-deny network posture for ALL evidence gate phases (not just test).
    // Quick mode skips network isolation (development shortcut, same as test skip).
    let skip_test_gate = opts.is_some_and(|o| o.skip_test_gate);
    #[allow(clippy::type_complexity)]
    let bounded_gate_specs: Option<Vec<(&str, Vec<String>, Vec<(String, String)>)>> =
        if skip_test_gate {
            None
        } else {
            // Load the policy to resolve network policy and sandbox hardening
            // for non-test gate phases (TCK-00574 BLOCKER fix).
            let apm2_home = apm2_core::github::resolve_apm2_home().ok_or_else(|| {
                "cannot resolve APM2_HOME for gate network policy enforcement".to_string()
            })?;
            let fac_root = apm2_home.join("private/fac");
            let policy = load_or_create_pipeline_policy(&fac_root)?;
            let gate_network_policy =
                apm2_core::fac::resolve_network_policy("gates", policy.network_policy.as_ref());
            let mut specs = Vec::new();
            for &(gate_name, cmd_args) in gates {
                let gate_cmd: Vec<String> = cmd_args.iter().map(|s| (*s).to_string()).collect();
                let bounded = build_systemd_bounded_gate_command(
                    workspace_root,
                    BoundedTestLimits {
                        timeout_seconds: DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS,
                        kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
                        memory_max: DEFAULT_TEST_MEMORY_MAX,
                        pids_max: DEFAULT_TEST_PIDS_MAX,
                        cpu_quota: "200%",
                    },
                    &gate_cmd,
                    &gate_env,
                    policy.sandbox_hardening.clone(),
                    gate_network_policy.clone(),
                )
                .map_err(|err| {
                    format!(
                        "bounded gate runner unavailable for {gate_name} \
                         (network deny enforcement requires systemd-run): {err}"
                    )
                })?;
                specs.push((gate_name, bounded.command, bounded.environment));
            }
            Some(specs)
        };

    for (idx, &(gate_name, cmd_args)) in gates.iter().enumerate() {
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        emit_gate_started(opts, gate_name);
        let started = Instant::now();

        // TCK-00574: Use bounded gate command (with network isolation) in
        // full mode; fall back to bare command in quick mode.
        let (passed, stream_stats) = if let Some(ref specs) = bounded_gate_specs {
            let (_, ref bounded_cmd, ref bounded_env) = specs[idx];
            let (bcmd, bargs) = bounded_cmd
                .split_first()
                .ok_or_else(|| format!("bounded gate command is empty for {gate_name}"))?;
            // The outer env includes D-Bus runtime variables needed by
            // systemd-run; the inner unit gets env via --setenv.
            let mut outer_env = gate_env.clone();
            outer_env.extend(bounded_env.iter().cloned());
            run_single_evidence_gate_with_env_and_progress(
                workspace_root,
                sha,
                gate_name,
                bcmd,
                &bargs.iter().map(String::as_str).collect::<Vec<_>>(),
                &log_path,
                Some(&outer_env),
                gate_wrapper_strip_ref,
                emit_human_logs,
                on_gate_progress,
            )
        } else {
            run_single_evidence_gate_with_env_and_progress(
                workspace_root,
                sha,
                gate_name,
                cmd_args[0],
                &cmd_args[1..],
                &log_path,
                Some(&gate_env),
                gate_wrapper_strip_ref,
                emit_human_logs,
                on_gate_progress,
            )
        };

        let duration = started.elapsed().as_secs();
        let result = build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        );
        emit_gate_completed(opts, &result);
        gate_results.push(result);
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
            log_path.display()
        ));
        if !passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    // Phase 2: pre-test native gates.
    for gate_name in pre_test_native_gates {
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        emit_gate_started(opts, gate_name);
        let started = Instant::now();
        let (passed, stream_stats) =
            run_native_evidence_gate(workspace_root, sha, gate_name, &log_path, emit_human_logs);
        let duration = started.elapsed().as_secs();
        let result = build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        );
        emit_gate_completed(opts, &result);
        gate_results.push(result);
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
            log_path.display()
        ));
        if !passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    // Phase 3: workspace integrity snapshot → test (optional) → verify.
    snapshot_workspace_integrity(workspace_root);

    let skip_test_gate = opts.is_some_and(|o| o.skip_test_gate);
    let test_log = logs_dir.join("test.log");
    if skip_test_gate {
        let skip_msg = b"quick mode enabled: skipped heavyweight test gate\n";
        let _ = crate::commands::fac_permissions::write_fac_file_with_mode(&test_log, skip_msg);
        let ts = now_iso8601();
        if emit_human_logs {
            eprintln!(
                "ts={ts} sha={sha} gate=test status=SKIP reason=quick_mode log={}",
                test_log.display()
            );
        }
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate=test status=SKIP reason=quick_mode log={}",
            test_log.display()
        ));
        let test_result = build_evidence_gate_result(
            "test",
            true,
            0,
            Some(&test_log),
            Some(&StreamStats {
                bytes_written: skip_msg.len() as u64,
                bytes_total: skip_msg.len() as u64,
                was_truncated: false,
            }),
        );
        emit_gate_completed(opts, &test_result);
        gate_results.push(test_result);
    } else {
        emit_gate_started(opts, "test");
        let test_started = Instant::now();
        let test_command =
            resolve_evidence_test_command_override(opts.and_then(|o| o.test_command.as_deref()));
        // TCK-00526: Use caller-provided test env if available (gates.rs
        // pre-computes policy env + bounded runner env), otherwise fall
        // back to the policy-filtered gate env.
        let caller_test_env = resolve_evidence_test_command_environment(opts);
        let test_env: Option<&[(String, String)]> = caller_test_env.or(Some(&gate_env));
        // TCK-00526: Use caller-provided env_remove_keys if available
        // (bounded test runner computes these), otherwise fall back to the
        // gate-level wrapper strip keys for defense-in-depth.
        let env_remove = resolve_evidence_env_remove_keys(opts).or(gate_wrapper_strip_ref);
        let (test_cmd, test_args) = test_command
            .split_first()
            .ok_or_else(|| "test command is empty".to_string())?;
        let (passed, stream_stats) = run_single_evidence_gate_with_env_and_progress(
            workspace_root,
            sha,
            "test",
            test_cmd,
            &test_args.iter().map(String::as_str).collect::<Vec<_>>(),
            &test_log,
            test_env,
            env_remove,
            emit_human_logs,
            on_gate_progress,
        );
        let test_duration = test_started.elapsed().as_secs();
        let test_result = build_evidence_gate_result(
            "test",
            passed,
            test_duration,
            Some(&test_log),
            Some(&stream_stats),
        );
        emit_gate_completed(opts, &test_result);
        gate_results.push(test_result);
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate=test status={status} log={}",
            test_log.display()
        ));
        if !passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    emit_gate_started(opts, "workspace_integrity");
    let wi_started = Instant::now();
    let wi_log_path = logs_dir.join("workspace_integrity.log");
    let (wi_passed, wi_line, wi_stream_stats) =
        verify_workspace_integrity_gate(workspace_root, sha, &wi_log_path, emit_human_logs);
    let wi_duration = wi_started.elapsed().as_secs();
    let wi_result = build_evidence_gate_result(
        "workspace_integrity",
        wi_passed,
        wi_duration,
        Some(&wi_log_path),
        Some(&wi_stream_stats),
    );
    emit_gate_completed(opts, &wi_result);
    gate_results.push(wi_result);
    evidence_lines.push(wi_line);
    if !wi_passed {
        if let Some(file) = projection_log {
            for line in &evidence_lines {
                let _ = writeln!(file, "{line}");
            }
        }
        attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
        return Ok((false, gate_results));
    }

    // Phase 4: post-test native gates.
    for gate_name in post_test_native_gates {
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        emit_gate_started(opts, gate_name);
        let started = Instant::now();
        let (passed, stream_stats) =
            run_native_evidence_gate(workspace_root, sha, gate_name, &log_path, emit_human_logs);
        let duration = started.elapsed().as_secs();
        let result = build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        );
        emit_gate_completed(opts, &result);
        gate_results.push(result);
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
            log_path.display()
        ));
        if !passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    if let Some(file) = projection_log {
        for line in &evidence_lines {
            let _ = writeln!(file, "{line}");
        }
    }

    attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
    Ok((true, gate_results))
}

/// Run evidence gates with PR-body gate status updates.
///
/// Same as [`run_evidence_gates`] but also updates the PR body gate section
/// after each gate completes. Checks the per-SHA gate cache before each gate
/// and skips execution if the gate already passed for this SHA.
#[allow(clippy::too_many_arguments)]
pub fn run_evidence_gates_with_status(
    workspace_root: &Path,
    sha: &str,
    owner_repo: &str,
    pr_number: u32,
    projection_log: Option<&mut File>,
    emit_human_logs: bool,
    on_gate_progress: Option<&dyn Fn(GateProgressEvent)>,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let lane_context = allocate_lane_job_logs_dir()?;
    run_evidence_gates_with_status_with_lane_context(
        workspace_root,
        sha,
        owner_repo,
        pr_number,
        projection_log,
        emit_human_logs,
        on_gate_progress,
        lane_context,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_evidence_gates_with_status_with_lane_context(
    workspace_root: &Path,
    sha: &str,
    owner_repo: &str,
    pr_number: u32,
    projection_log: Option<&mut File>,
    emit_human_logs: bool,
    on_gate_progress: Option<&dyn Fn(GateProgressEvent)>,
    lane_context: EvidenceLaneContext,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let logs_dir = lane_context.logs_dir;
    // TCK-00540: Pipeline path always enforces fail-closed legacy cache deny.
    // The `--allow-legacy-cache` unsafe override is only available via the
    // `apm2 fac gates` CLI path (not the PR pipeline).
    let allow_legacy_cache = false;

    // TCK-00526: Build policy-filtered environment for ALL gates.
    // TCK-00575 round 2: Use the lane_dir from the actually-locked lane
    // (not hardcoded lane-00) to maintain lock/env coupling.
    let gate_env = build_gate_policy_env(&lane_context.lane_dir)?;

    // TCK-00526: Compute wrapper-stripping keys once for ALL gate phases.
    // Pass the policy-filtered environment so policy-introduced SCCACHE_*
    // variables are also discovered for defense-in-depth stripping.
    let gate_wrapper_strip = compute_gate_env_remove_keys(Some(&gate_env));
    let gate_wrapper_strip_ref: Option<&[String]> = if gate_wrapper_strip.is_empty() {
        None
    } else {
        Some(&gate_wrapper_strip)
    };

    let mut status = CiStatus::new(sha, pr_number);
    let updater = PrBodyStatusUpdater::new(owner_repo, pr_number);

    // TCK-00576: Load the persistent signer for gate cache signature
    // verification (reuse decisions) and signing (new cache entries).
    let fac_signer = {
        let apm2_home = apm2_core::github::resolve_apm2_home()
            .ok_or_else(|| "cannot resolve APM2_HOME for gate cache signing".to_string())?;
        let fac_root = apm2_home.join("private/fac");
        crate::commands::fac_key_material::load_or_generate_persistent_signer(&fac_root)
            .map_err(|e| format!("cannot load signing key for gate cache: {e}"))?
    };
    let fac_verifying_key = fac_signer.verifying_key();

    // Load attested gate cache for this SHA (typically populated by `fac gates`).
    let cache = GateCache::load(sha);
    let mut gate_cache = GateCache::new(sha);
    let pipeline_test_command =
        build_pipeline_test_command(workspace_root, &lane_context.lane_dir)?;
    // TCK-00573 MAJOR-3: Include sandbox hardening hash in gate attestation
    // to prevent stale gate results from insecure environments being reused.
    // Uses the effective policy-driven profile carried through
    // PipelineTestCommand (MAJOR-1 fix: was previously default()).
    let sandbox_hardening_hash = &pipeline_test_command.sandbox_hardening_hash;
    // TCK-00574 MAJOR-1: Include network policy hash in gate attestation
    // to prevent cache reuse across network policy drift.
    let network_policy_hash = &pipeline_test_command.network_policy_hash;
    let policy = GateResourcePolicy::from_cli(
        false,
        pipeline_test_command.effective_timeout_seconds,
        DEFAULT_TEST_MEMORY_MAX,
        DEFAULT_TEST_PIDS_MAX,
        &pipeline_test_command.effective_cpu_quota,
        pipeline_test_command.bounded_runner,
        Some(pipeline_test_command.gate_profile.as_str()),
        Some(pipeline_test_command.effective_test_parallelism),
        Some(sandbox_hardening_hash.as_str()),
        Some(network_policy_hash.as_str()),
    );
    if emit_human_logs {
        eprintln!(
            "FAC pipeline test throughput: profile={} cpu_quota={} test_parallelism={}",
            pipeline_test_command.gate_profile.as_str(),
            pipeline_test_command.effective_cpu_quota,
            pipeline_test_command.effective_test_parallelism
        );
    }

    let gates: &[(&str, &[&str])] = &[
        ("rustfmt", &["cargo", "fmt", "--all", "--check"]),
        (
            "clippy",
            &[
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("doc", &["cargo", "doc", "--workspace", "--no-deps"]),
    ];

    let pre_test_native_gates: &[&str] = &["test_safety_guard"];

    // Native gates that run AFTER tests (ordering dependency on test).
    let post_test_native_gates: &[&str] = &["review_artifact_lint"];

    let mut evidence_lines = Vec::new();
    let mut gate_results = Vec::new();

    // Phase 0: merge conflict gate (always first, always recomputed).
    {
        let gate_name = MERGE_CONFLICT_GATE_NAME;
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);

        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let (passed, duration, line, stream_stats) =
            run_merge_conflict_gate(workspace_root, sha, &log_path, emit_human_logs);
        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        let merge_result = build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        );
        emit_gate_completed_cb(on_gate_progress, &merge_result);
        gate_results.push(merge_result);
        evidence_lines.push(line);
        let merge_digest = sha256_file_hex(&log_path);
        let merge_attestation =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            merge_attestation,
            false,
            merge_digest,
            log_path.to_str().map(str::to_string),
        );
        if !passed {
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
            )?;
            return Ok((false, gate_results));
        }
    }

    // TCK-00574 BLOCKER fix: Build bounded gate commands for non-test gates
    // to enforce network-deny in the pipeline path (always full mode).
    #[allow(clippy::type_complexity)]
    let pipeline_bounded_gate_specs: Vec<(&str, Vec<String>, Vec<(String, String)>)> = {
        let apm2_home = apm2_core::github::resolve_apm2_home().ok_or_else(|| {
            "cannot resolve APM2_HOME for pipeline gate network policy enforcement".to_string()
        })?;
        let fac_root = apm2_home.join("private/fac");
        let fac_policy = load_or_create_pipeline_policy(&fac_root)?;
        let gate_network_policy =
            apm2_core::fac::resolve_network_policy("gates", fac_policy.network_policy.as_ref());
        let mut specs = Vec::new();
        for &(gate_name, cmd_args) in gates {
            let gate_cmd: Vec<String> = cmd_args.iter().map(|s| (*s).to_string()).collect();
            let bounded = build_systemd_bounded_gate_command(
                workspace_root,
                BoundedTestLimits {
                    timeout_seconds: DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS,
                    kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
                    memory_max: DEFAULT_TEST_MEMORY_MAX,
                    pids_max: DEFAULT_TEST_PIDS_MAX,
                    cpu_quota: "200%",
                },
                &gate_cmd,
                &gate_env,
                fac_policy.sandbox_hardening.clone(),
                gate_network_policy.clone(),
            )
            .map_err(|err| {
                format!(
                    "bounded gate runner unavailable for {gate_name} \
                     (network deny enforcement requires systemd-run): {err}"
                )
            })?;
            specs.push((gate_name, bounded.command, bounded.environment));
        }
        specs
    };

    // Phase 1: cargo fmt/clippy/doc.
    for (idx, &(gate_name, _cmd_args)) in gates.iter().enumerate() {
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let reuse = reuse_decision_for_gate(
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            allow_legacy_cache,
        );
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                emit_gate_started_cb(on_gate_progress, gate_name);
                status.set_running(gate_name);
                updater.update(&status);
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                    cached.log_path.clone(),
                );
                // TCK-00540 fix round 2: preserve override audit trail.
                if reuse.reason == "legacy_cache_override_unsafe" {
                    gate_cache.mark_legacy_override(gate_name);
                }
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                    .map_or_else(|| "unknown".to_string(), short_digest),
                ));
                continue;
            }
            emit_gate_started_cb(on_gate_progress, gate_name);
            status.set_running(gate_name);
            updater.update(&status);
            status.set_result(gate_name, false, 0);
            updater.update(&status);
            let fail_result = build_evidence_gate_result(
                gate_name,
                false,
                0,
                Some(&log_path),
                Some(&StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                }),
            );
            emit_gate_completed_cb(on_gate_progress, &fail_result);
            gate_results.push(fail_result);
            gate_cache.set_with_attestation(
                gate_name,
                false,
                0,
                attestation_digest,
                false,
                None,
                log_path.to_str().map(str::to_string),
            );
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                now_iso8601(),
                sha,
                gate_name
            ));
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
            )?;
            return Ok((false, gate_results));
        }

        if emit_human_logs {
            eprintln!(
                "ts={} sha={} gate={} reuse_status=miss reuse_reason={} attestation_digest={}",
                now_iso8601(),
                sha,
                gate_name,
                reuse.reason,
                attestation_digest
                    .as_deref()
                    .map_or_else(|| "unknown".to_string(), short_digest),
            );
        }
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        let started = Instant::now();
        // TCK-00574: Use bounded gate command with network isolation.
        let (_bounded_name, bounded_cmd, bounded_env) = &pipeline_bounded_gate_specs[idx];
        let (bcmd, bargs) = bounded_cmd
            .split_first()
            .ok_or_else(|| format!("bounded gate command is empty for {gate_name}"))?;
        let mut outer_env = gate_env.clone();
        outer_env.extend(bounded_env.iter().cloned());
        let (passed, stream_stats) = run_single_evidence_gate_with_env_and_progress(
            workspace_root,
            sha,
            gate_name,
            bcmd,
            &bargs.iter().map(String::as_str).collect::<Vec<_>>(),
            &log_path,
            Some(&outer_env),
            gate_wrapper_strip_ref,
            emit_human_logs,
            on_gate_progress,
        );
        let duration = started.elapsed().as_secs();

        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        let exec_result = build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        );
        emit_gate_completed_cb(on_gate_progress, &exec_result);
        gate_results.push(exec_result);
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            attestation_digest.clone(),
            false,
            sha256_file_hex(&log_path),
            log_path.to_str().map(str::to_string),
        );
        let gate_status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
            now_iso8601(),
            sha,
            gate_name,
            gate_status,
            log_path.display(),
            reuse.reason,
        ));
        if !passed {
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
            )?;
            return Ok((false, gate_results));
        }
    }

    // Phase 2: pre-test native gates.
    for gate_name in pre_test_native_gates {
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse = reuse_decision_for_gate(
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            allow_legacy_cache,
        );
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                emit_gate_started_cb(on_gate_progress, gate_name);
                status.set_running(gate_name);
                updater.update(&status);
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                    cached.log_path.clone(),
                );
                // TCK-00540 fix round 2: preserve override audit trail.
                if reuse.reason == "legacy_cache_override_unsafe" {
                    gate_cache.mark_legacy_override(gate_name);
                }
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                    .map_or_else(|| "unknown".to_string(), short_digest),
                ));
                continue;
            }
            emit_gate_started_cb(on_gate_progress, gate_name);
            status.set_running(gate_name);
            updater.update(&status);
            status.set_result(gate_name, false, 0);
            updater.update(&status);
            let fail_result = build_evidence_gate_result(
                gate_name,
                false,
                0,
                Some(&log_path),
                Some(&StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                }),
            );
            emit_gate_completed_cb(on_gate_progress, &fail_result);
            gate_results.push(fail_result);
            gate_cache.set_with_attestation(
                gate_name,
                false,
                0,
                attestation_digest,
                false,
                None,
                log_path.to_str().map(str::to_string),
            );
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                now_iso8601(),
                sha,
                gate_name
            ));
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
            )?;
            return Ok((false, gate_results));
        }

        if emit_human_logs {
            eprintln!(
                "ts={} sha={} gate={} reuse_status=miss reuse_reason={} attestation_digest={}",
                now_iso8601(),
                sha,
                gate_name,
                reuse.reason,
                attestation_digest
                    .as_deref()
                    .map_or_else(|| "unknown".to_string(), short_digest),
            );
        }
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        let started = Instant::now();
        let (passed, stream_stats) =
            run_native_evidence_gate(workspace_root, sha, gate_name, &log_path, emit_human_logs);
        let duration = started.elapsed().as_secs();

        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        let exec_result = build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        );
        emit_gate_completed_cb(on_gate_progress, &exec_result);
        gate_results.push(exec_result);
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            attestation_digest.clone(),
            false,
            sha256_file_hex(&log_path),
            log_path.to_str().map(str::to_string),
        );
        let gate_status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
            now_iso8601(),
            sha,
            gate_name,
            gate_status,
            log_path.display(),
            reuse.reason,
        ));
        if !passed {
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
            )?;
            return Ok((false, gate_results));
        }
    }

    // Phase 3: workspace integrity snapshot → test → verify.
    snapshot_workspace_integrity(workspace_root);

    {
        let gate_name = "test";
        let attestation_digest = gate_attestation_digest(
            workspace_root,
            sha,
            gate_name,
            Some(pipeline_test_command.command.as_slice()),
            &policy,
        );
        let reuse = reuse_decision_for_gate(
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            allow_legacy_cache,
        );
        let log_path = logs_dir.join("test.log");
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                    cached.log_path.clone(),
                );
                // TCK-00540 fix round 2: preserve override audit trail.
                if reuse.reason == "legacy_cache_override_unsafe" {
                    gate_cache.mark_legacy_override(gate_name);
                }
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                ));
            } else {
                status.set_result(gate_name, false, 0);
                updater.update(&status);
                let fail_result = build_evidence_gate_result(
                    gate_name,
                    false,
                    0,
                    Some(&log_path),
                    Some(&StreamStats {
                        bytes_written: 0,
                        bytes_total: 0,
                        was_truncated: false,
                    }),
                );
                emit_gate_completed_cb(on_gate_progress, &fail_result);
                gate_results.push(fail_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    false,
                    0,
                    attestation_digest,
                    false,
                    None,
                    log_path.to_str().map(str::to_string),
                );
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                    now_iso8601(),
                    sha,
                    gate_name
                ));
                finalize_status_gate_run(
                    projection_log,
                    &evidence_lines,
                    &mut gate_results,
                    &logs_dir,
                    &mut gate_cache,
                    &updater,
                    &status,
                    &fac_signer,
                )?;
                return Ok((false, gate_results));
            }
        } else {
            if emit_human_logs {
                eprintln!(
                    "ts={} sha={} gate={} reuse_status=miss reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                );
            }
            let started = Instant::now();
            let (test_cmd, test_args) = pipeline_test_command
                .command
                .split_first()
                .ok_or_else(|| "pipeline test command is empty".to_string())?;
            let pipeline_env_remove = if pipeline_test_command.env_remove_keys.is_empty() {
                None
            } else {
                Some(pipeline_test_command.env_remove_keys.as_slice())
            };
            let (passed, stream_stats) = run_single_evidence_gate_with_env_and_progress(
                workspace_root,
                sha,
                gate_name,
                test_cmd,
                &test_args.iter().map(String::as_str).collect::<Vec<_>>(),
                &log_path,
                Some(&pipeline_test_command.test_env),
                pipeline_env_remove,
                emit_human_logs,
                on_gate_progress,
            );
            let duration = started.elapsed().as_secs();
            status.set_result(gate_name, passed, duration);
            updater.update(&status);
            let test_result = build_evidence_gate_result(
                gate_name,
                passed,
                duration,
                Some(&log_path),
                Some(&stream_stats),
            );
            emit_gate_completed_cb(on_gate_progress, &test_result);
            gate_results.push(test_result);
            gate_cache.set_with_attestation(
                gate_name,
                passed,
                duration,
                attestation_digest,
                false,
                sha256_file_hex(&log_path),
                log_path.to_str().map(str::to_string),
            );
            let gate_status = if passed { "PASS" } else { "FAIL" };
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
                now_iso8601(),
                sha,
                gate_name,
                gate_status,
                log_path.display(),
                reuse.reason,
            ));
            if !passed {
                finalize_status_gate_run(
                    projection_log,
                    &evidence_lines,
                    &mut gate_results,
                    &logs_dir,
                    &mut gate_cache,
                    &updater,
                    &status,
                    &fac_signer,
                )?;
                return Ok((false, gate_results));
            }
        }
    }

    {
        let gate_name = "workspace_integrity";
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse = reuse_decision_for_gate(
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            allow_legacy_cache,
        );
        let log_path = logs_dir.join("workspace_integrity.log");
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                    cached.log_path.clone(),
                );
                // TCK-00540 fix round 2: preserve override audit trail.
                if reuse.reason == "legacy_cache_override_unsafe" {
                    gate_cache.mark_legacy_override(gate_name);
                }
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                ));
            } else {
                status.set_result(gate_name, false, 0);
                updater.update(&status);
                let fail_result = build_evidence_gate_result(
                    gate_name,
                    false,
                    0,
                    Some(&log_path),
                    Some(&StreamStats {
                        bytes_written: 0,
                        bytes_total: 0,
                        was_truncated: false,
                    }),
                );
                emit_gate_completed_cb(on_gate_progress, &fail_result);
                gate_results.push(fail_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    false,
                    0,
                    attestation_digest,
                    false,
                    None,
                    log_path.to_str().map(str::to_string),
                );
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                    now_iso8601(),
                    sha,
                    gate_name
                ));
                finalize_status_gate_run(
                    projection_log,
                    &evidence_lines,
                    &mut gate_results,
                    &logs_dir,
                    &mut gate_cache,
                    &updater,
                    &status,
                    &fac_signer,
                )?;
                return Ok((false, gate_results));
            }
        } else {
            let started = Instant::now();
            let (passed, line, stream_stats) =
                verify_workspace_integrity_gate(workspace_root, sha, &log_path, emit_human_logs);
            let duration = started.elapsed().as_secs();
            status.set_result(gate_name, passed, duration);
            updater.update(&status);
            let wi_result = build_evidence_gate_result(
                gate_name,
                passed,
                duration,
                Some(&log_path),
                Some(&stream_stats),
            );
            emit_gate_completed_cb(on_gate_progress, &wi_result);
            gate_results.push(wi_result);
            gate_cache.set_with_attestation(
                gate_name,
                passed,
                duration,
                attestation_digest,
                false,
                sha256_file_hex(&log_path),
                log_path.to_str().map(str::to_string),
            );
            evidence_lines.push(format!(
                "{} reuse_status=miss reuse_reason={}",
                line, reuse.reason
            ));
            if !passed {
                finalize_status_gate_run(
                    projection_log,
                    &evidence_lines,
                    &mut gate_results,
                    &logs_dir,
                    &mut gate_cache,
                    &updater,
                    &status,
                    &fac_signer,
                )?;
                return Ok((false, gate_results));
            }
        }
    }

    // Phase 4: post-test native gates.
    for gate_name in post_test_native_gates {
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse = reuse_decision_for_gate(
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            allow_legacy_cache,
        );
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                emit_gate_started_cb(on_gate_progress, gate_name);
                status.set_running(gate_name);
                updater.update(&status);
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                    cached.log_path.clone(),
                );
                // TCK-00540 fix round 2: preserve override audit trail.
                if reuse.reason == "legacy_cache_override_unsafe" {
                    gate_cache.mark_legacy_override(gate_name);
                }
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                ));
                continue;
            }
            emit_gate_started_cb(on_gate_progress, gate_name);
            status.set_running(gate_name);
            updater.update(&status);
            status.set_result(gate_name, false, 0);
            updater.update(&status);
            let fail_result = build_evidence_gate_result(
                gate_name,
                false,
                0,
                Some(&log_path),
                Some(&StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                }),
            );
            emit_gate_completed_cb(on_gate_progress, &fail_result);
            gate_results.push(fail_result);
            gate_cache.set_with_attestation(
                gate_name,
                false,
                0,
                attestation_digest,
                false,
                None,
                log_path.to_str().map(str::to_string),
            );
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                now_iso8601(),
                sha,
                gate_name
            ));
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
            )?;
            return Ok((false, gate_results));
        }

        if emit_human_logs {
            eprintln!(
                "ts={} sha={} gate={} reuse_status=miss reuse_reason={} attestation_digest={}",
                now_iso8601(),
                sha,
                gate_name,
                reuse.reason,
                attestation_digest
                    .as_deref()
                    .map_or_else(|| "unknown".to_string(), short_digest),
            );
        }
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        let started = Instant::now();
        let (passed, stream_stats) =
            run_native_evidence_gate(workspace_root, sha, gate_name, &log_path, emit_human_logs);
        let duration = started.elapsed().as_secs();
        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        let exec_result = build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        );
        emit_gate_completed_cb(on_gate_progress, &exec_result);
        gate_results.push(exec_result);
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            attestation_digest.clone(),
            false,
            sha256_file_hex(&log_path),
            log_path.to_str().map(str::to_string),
        );
        let gate_status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
            now_iso8601(),
            sha,
            gate_name,
            gate_status,
            log_path.display(),
            reuse.reason,
        ));
        if !passed {
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
            )?;
            return Ok((false, gate_results));
        }
    }
    finalize_status_gate_run(
        projection_log,
        &evidence_lines,
        &mut gate_results,
        &logs_dir,
        &mut gate_cache,
        &updater,
        &status,
        &fac_signer,
    )?;
    Ok((true, gate_results))
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_log_path(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "apm2-evidence-tests-{test_name}-{}-{nonce}",
            std::process::id()
        ));
        crate::commands::fac_permissions::ensure_dir_with_mode(&dir).expect("create temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("set temp dir permissions");
        }
        dir.join("test.log")
    }

    #[test]
    fn short_test_failure_hint_is_appended() {
        let log_path = temp_log_path("short");
        fs::write(&log_path, "=== stdout ===\n\n=== stderr ===\n\n").expect("write seed log");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))
                .expect("set log file mode");
        }

        append_short_test_failure_hint(&log_path, 128);

        let content = fs::read_to_string(&log_path).expect("read updated log");
        assert!(content.contains("--- fac diagnostic ---"));
        assert!(content.contains("minimal output (128 bytes)"));
    }

    #[test]
    fn short_test_failure_hint_is_skipped_for_large_output() {
        let log_path = temp_log_path("large");
        fs::write(&log_path, "=== stdout ===\n\n=== stderr ===\n\n").expect("write seed log");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))
                .expect("set log file mode");
        }

        append_short_test_failure_hint(&log_path, SHORT_TEST_OUTPUT_HINT_THRESHOLD_BYTES);

        let content = fs::read_to_string(&log_path).expect("read updated log");
        assert!(!content.contains("--- fac diagnostic ---"));
    }

    #[test]
    fn default_evidence_test_command_uses_nextest() {
        let command = resolve_evidence_test_command_override(None);
        let joined = command.join(" ");
        assert!(joined.contains("cargo nextest run --workspace"));
        assert!(!joined.contains("cargo test --workspace"));
    }

    #[test]
    fn pipeline_test_command_uses_rust_bounded_runner_or_surfaces_preflight_error() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let lane_dir = temp_dir
            .path()
            .join("apm2-home/private/fac/lanes/lane-test");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");
        match build_pipeline_test_command(temp_dir.path(), &lane_dir) {
            Ok(command) => {
                let joined = command.command.join(" ");
                assert!(joined.contains("systemd-run"));
                assert!(joined.contains("cargo nextest run --workspace"));
                assert!(!joined.contains(".sh"));
                assert_eq!(
                    command.gate_profile,
                    crate::commands::fac_review::GateThroughputProfile::Throughput
                );
                let host_parallelism = apm2_core::fac::resolve_host_test_parallelism();
                assert!(command.effective_test_parallelism >= 1);
                assert!(command.effective_cpu_quota.ends_with('%'));
                assert_eq!(command.effective_test_parallelism, host_parallelism);
                assert_eq!(
                    command.effective_cpu_quota,
                    format!("{}%", host_parallelism.saturating_mul(100).max(100))
                );
                let threads = command
                    .test_env
                    .iter()
                    .find(|(k, _)| k == "NEXTEST_TEST_THREADS")
                    .and_then(|(_, v)| v.parse::<u32>().ok())
                    .unwrap_or(0);
                let build_jobs = command
                    .test_env
                    .iter()
                    .find(|(k, _)| k == "CARGO_BUILD_JOBS")
                    .and_then(|(_, v)| v.parse::<u32>().ok())
                    .unwrap_or(0);
                assert_eq!(threads, command.effective_test_parallelism);
                assert_eq!(threads, build_jobs);
            },
            Err(err) => {
                assert!(
                    err.contains("bounded test runner unavailable")
                        || err.contains("systemd-run not found")
                        || err.contains("cgroup v2")
                        || err.contains("D-Bus socket"),
                    "unexpected error: {err}"
                );
            },
        }
    }

    #[test]
    fn pipeline_test_command_carries_env_remove_keys() {
        // BLOCKER-2 regression: build_pipeline_test_command must propagate
        // env_remove_keys from bounded_spec so the pipeline/restart path
        // strips sccache env vars.
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let lane_dir = temp_dir
            .path()
            .join("apm2-home/private/fac/lanes/lane-test");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");
        if let Ok(command) = build_pipeline_test_command(temp_dir.path(), &lane_dir) {
            // The bounded test runner always strips at least RUSTC_WRAPPER.
            assert!(
                command
                    .env_remove_keys
                    .contains(&"RUSTC_WRAPPER".to_string()),
                "pipeline test command must carry RUSTC_WRAPPER in env_remove_keys, got: {:?}",
                command.env_remove_keys
            );
        }
        // If the bounded runner is unavailable (Err), the test cannot
        // verify this assertion — skip gracefully.
    }

    /// Helper: create a temporary directory with 0o700 permissions for test
    /// isolation, returning the directory path itself (not a file inside it).
    fn temp_test_dir(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "apm2-evidence-tests-{test_name}-{}-{nonce}",
            std::process::id()
        ));
        crate::commands::fac_permissions::ensure_dir_with_mode(&dir).expect("create temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("set temp dir permissions");
        }
        dir
    }

    /// BLOCKER 1: Prove that >=3 concurrent evidence gate runs produce unique,
    /// non-overlapping log files via lane-scoped namespacing.
    ///
    /// Each thread runs `run_single_evidence_gate` with a trivially-fast
    /// command (`echo`), writing to a unique log path. The test asserts:
    ///   - All 3 runs succeed.
    ///   - Each produces a distinct log file path.
    ///   - No log file content is empty or duplicated across runs.
    #[test]
    fn concurrent_evidence_runs_produce_unique_logs() {
        let workspace_root = temp_test_dir("concurrent");
        let num_concurrent = 3;
        let sha = "deadbeef_concurrent_test";

        let handles: Vec<_> = (0..num_concurrent)
            .map(|idx| {
                let ws = workspace_root.clone();
                thread::spawn(move || {
                    let gate_name = format!("echo_gate_{idx}");
                    let log_dir = ws.join(format!("lane-{idx}"));
                    crate::commands::fac_permissions::ensure_dir_with_mode(&log_dir)
                        .expect("create lane dir");
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;

                        fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700))
                            .expect("set lane dir permissions");
                    }
                    let log_path = log_dir.join(format!("{gate_name}.log"));

                    let (passed, _stream_stats) = run_single_evidence_gate(
                        &ws,
                        sha,
                        &gate_name,
                        "echo",
                        &[&format!("hello from lane {idx}")],
                        &log_path,
                        true,
                    );
                    (passed, log_path)
                })
            })
            .collect();

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().expect("thread should not panic"));
        }

        // All runs must succeed.
        for (idx, (passed, _)) in results.iter().enumerate() {
            assert!(passed, "concurrent run {idx} should pass");
        }

        // All log paths must be unique.
        let paths: Vec<String> = results
            .iter()
            .map(|(_, p)| p.display().to_string())
            .collect();
        let unique_paths: std::collections::HashSet<&String> = paths.iter().collect();
        assert_eq!(
            unique_paths.len(),
            num_concurrent,
            "each concurrent run must produce a unique log path"
        );

        // No log file content should be empty or identical to another.
        let contents: Vec<String> = results
            .iter()
            .map(|(_, p)| fs::read_to_string(p).expect("log file should be readable"))
            .collect();
        for (idx, content) in contents.iter().enumerate() {
            assert!(!content.is_empty(), "log {idx} should not be empty");
        }
        let unique_contents: std::collections::HashSet<&String> = contents.iter().collect();
        assert_eq!(
            unique_contents.len(),
            num_concurrent,
            "log file contents must be unique across concurrent runs"
        );
    }

    /// BLOCKER 2: Prove that log caps prevent disk blowup without deadlocking
    /// child processes.
    ///
    /// Launches a child that emits well beyond the 4 MB cap on both stdout
    /// and stderr. Asserts:
    ///   - The child process completes (no deadlock).
    ///   - `bytes_written` is bounded (<= 4 MB + chunk overhead).
    ///   - `was_truncated` metadata is `true`.
    #[test]
    fn log_cap_prevents_blowup_without_deadlock() {
        let workspace_root = temp_test_dir("log_cap");
        let sha = "deadbeef_logcap_test";
        let gate_name = "logcap_gate";
        let log_path = workspace_root.join(format!("{gate_name}.log"));

        // Generate ~8 MB on stdout and ~8 MB on stderr (well beyond 4 MB cap).
        // Use a bash one-liner that writes to both streams.
        let emit_bytes = 8 * 1024 * 1024; // 8 MB per stream
        let script = format!(
            "dd if=/dev/zero bs=4096 count={stdout_blocks} 2>/dev/null; \
             dd if=/dev/zero bs=4096 count={stderr_blocks} >&2 2>/dev/null",
            stdout_blocks = emit_bytes / 4096,
            stderr_blocks = emit_bytes / 4096,
        );

        let (passed, stream_stats) = run_single_evidence_gate(
            &workspace_root,
            sha,
            gate_name,
            "bash",
            &["-c", &script],
            &log_path,
            true,
        );

        // The command itself succeeds (dd returns 0).
        assert!(passed, "log cap gate should pass (child exited 0)");

        // bytes_written must be bounded by LOG_STREAM_MAX_BYTES + chunk overhead.
        // We allow one extra chunk per stream thread (2 * chunk size) as
        // overhead since the atomic counter is checked after the fetch_add.
        let max_expected = LOG_STREAM_MAX_BYTES + 2 * LOG_STREAM_CHUNK_BYTES as u64;
        assert!(
            stream_stats.bytes_written <= max_expected,
            "bytes_written ({}) should be bounded by {} (4 MB + 2 chunks)",
            stream_stats.bytes_written,
            max_expected,
        );

        // Total bytes emitted should exceed the cap (proving truncation occurred).
        assert!(
            stream_stats.bytes_total > LOG_STREAM_MAX_BYTES,
            "bytes_total ({}) should exceed 4 MB cap to prove truncation",
            stream_stats.bytes_total,
        );

        // was_truncated must be true.
        assert!(
            stream_stats.was_truncated,
            "was_truncated should be true when output exceeds cap"
        );

        // The log file on disk should also be bounded.
        let log_size = fs::metadata(&log_path)
            .expect("log file should exist")
            .len();
        assert!(
            log_size <= max_expected,
            "on-disk log size ({log_size}) should be bounded by {max_expected}"
        );
    }
}
