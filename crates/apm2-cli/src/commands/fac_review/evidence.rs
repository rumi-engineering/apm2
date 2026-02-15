//! Evidence gates (fmt, clippy, doc, test, CI scripts) for FAC push pipeline.

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

use apm2_core::fac::{LaneLockGuard, LaneManager, LaneProfileV1, compute_test_env};
use blake3;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::bounded_test_runner::{
    BoundedTestLimits, build_bounded_test_command as build_systemd_bounded_test_command,
};
use super::ci_status::{CiStatus, ThrottledUpdater};
use super::gate_attestation::{
    GateResourcePolicy, build_nextest_command, compute_gate_attestation,
    gate_command_for_attestation, short_digest,
};
use super::gate_cache::{GateCache, ReuseDecision};
use super::merge_conflicts::{
    check_merge_conflicts_against_main, render_merge_conflict_log, render_merge_conflict_summary,
};
use super::timeout_policy::{
    DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS, DEFAULT_TEST_MEMORY_MAX, TEST_TIMEOUT_SLA_MESSAGE,
    max_memory_bytes, parse_memory_limit, resolve_bounded_test_timeout,
};
use super::types::now_iso8601;

/// Options for customizing evidence gate execution.
pub struct EvidenceGateOptions {
    /// Override command for the test phase. When `Some`, the test gate uses
    /// this command instead of `cargo nextest run ...`.
    pub test_command: Option<Vec<String>>,
    /// Extra environment variables applied when invoking a bounded test runner.
    pub test_command_environment: Vec<(String, String)>,
    /// Skip the heavyweight test gate for quick inner-loop validation.
    pub skip_test_gate: bool,
    /// Skip merge-conflict gate when caller already pre-validated it.
    pub skip_merge_conflict_gate: bool,
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
const DEFAULT_TEST_CPU_QUOTA: &str = "200%";
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
) -> ReuseDecision {
    cache.map_or_else(
        || ReuseDecision::miss("no_record"),
        |cached| cached.check_reuse(gate_name, attestation_digest, true),
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

fn run_gate_command_with_heartbeat(
    workspace_root: &Path,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    extra_env: Option<&[(String, String)]>,
) -> std::io::Result<GateCommandOutput> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .current_dir(workspace_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(envs) = extra_env {
        for (key, value) in envs {
            command.env(key, value);
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
            eprintln!(
                "ts={} gate={} status=RUNNING tick={} elapsed_secs={}",
                now_iso8601(),
                gate_name,
                elapsed_secs / MONOTONIC_HEARTBEAT_TICK_SECS,
                elapsed_secs,
            );
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
) {
    let ts = now_iso8601();
    let line = format!(
        "ts={ts} sha={sha} gate={gate} status={status} duration_secs={duration_secs} log={}",
        log_path.display()
    );
    eprintln!("{line}");
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
        "  apm2 fac gates --memory-max 24G  # default is 24G; increase if needed"
    );
}

fn run_merge_conflict_gate(
    workspace_root: &Path,
    sha: &str,
    log_path: &Path,
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
            if !passed {
                eprintln!("{}", render_merge_conflict_summary(&report));
            }
            let gate_status = if passed { "PASS" } else { "FAIL" };
            emit_evidence_line(sha, gate_name, gate_status, duration, log_path, None);
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
            emit_evidence_line(sha, gate_name, "FAIL", duration, log_path, None);
            eprintln!("merge_conflict_main: FAIL reason={err}");
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
pub fn run_single_evidence_gate(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
) -> (bool, StreamStats) {
    run_single_evidence_gate_with_env(workspace_root, sha, gate_name, cmd, args, log_path, None)
}

fn run_single_evidence_gate_with_env(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    extra_env: Option<&[(String, String)]>,
) -> (bool, StreamStats) {
    let started = Instant::now();
    let output =
        run_gate_command_with_heartbeat(workspace_root, gate_name, cmd, args, log_path, extra_env);
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
            emit_evidence_line(sha, gate_name, status, duration, log_path, None);
            (passed, out.stream_stats)
        },
        Err(e) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!("execution error: {e}\n").as_bytes(),
            );
            emit_evidence_line(sha, gate_name, "FAIL", duration, log_path, None);
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
    workspace_root.join("target/ci/workspace_integrity.snapshot.tsv")
}

/// Take a baseline workspace integrity snapshot before test execution.
/// Returns `true` if snapshot was created successfully.
fn snapshot_workspace_integrity(workspace_root: &Path) -> bool {
    let script = workspace_root.join("scripts/ci/workspace_integrity_guard.sh");
    if !script.exists() {
        return true; // No script → nothing to snapshot.
    }
    let snapshot = workspace_integrity_snapshot(workspace_root);
    let snapshot_str = snapshot.to_str().unwrap_or("");
    Command::new("bash")
        .args([
            script.to_str().unwrap_or(""),
            "snapshot",
            "--snapshot-file",
            snapshot_str,
        ])
        .current_dir(workspace_root)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Verify workspace integrity against a previously captured snapshot.
fn verify_workspace_integrity_gate(
    workspace_root: &Path,
    sha: &str,
    log_path: &Path,
) -> (bool, String, StreamStats) {
    let script = workspace_root.join("scripts/ci/workspace_integrity_guard.sh");
    let snapshot = workspace_integrity_snapshot(workspace_root);
    let log_path = log_path.to_path_buf();
    let gate_name = "workspace_integrity";

    if !script.exists() || !snapshot.exists() {
        let msg = if script.exists() {
            "snapshot file not found — skipped (no pre-test snapshot?)"
        } else {
            "workspace_integrity_guard.sh not found — skipped"
        };
        let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
            &log_path,
            format!("{msg}\n").as_bytes(),
        );
        let bytes_total = msg.len() as u64;
        let ts = now_iso8601();
        let line = format!(
            "ts={ts} sha={sha} gate={gate_name} status=PASS log={}",
            log_path.display()
        );
        return (
            true,
            line,
            StreamStats {
                bytes_written: bytes_total,
                bytes_total,
                was_truncated: false,
            },
        );
    }

    let snapshot_str = snapshot.to_str().unwrap_or("");
    let passed = run_single_evidence_gate(
        workspace_root,
        sha,
        gate_name,
        "bash",
        &[
            script.to_str().unwrap_or(""),
            "verify",
            "--snapshot-file",
            snapshot_str,
        ],
        &log_path,
    );
    let stream_stats = passed.1;
    let passed = passed.0;
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
    test_env: Vec<(String, String)>,
}

fn build_pipeline_test_command(workspace_root: &Path) -> Result<PipelineTestCommand, String> {
    let memory_max_bytes = parse_memory_limit(DEFAULT_TEST_MEMORY_MAX)?;
    if memory_max_bytes > max_memory_bytes() {
        return Err(format!(
            "--memory-max {} exceeds FAC cap {}",
            DEFAULT_TEST_MEMORY_MAX,
            max_memory_bytes()
        ));
    }

    let timeout_decision =
        resolve_bounded_test_timeout(workspace_root, DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS);
    let profile = LaneProfileV1::new("lane-00", "b3-256:fac-review", "boundary-00")
        .map_err(|err| format!("failed to construct FAC pipeline lane profile: {err}"))?;
    let mut test_env = compute_test_env(&profile);
    let bounded_spec = build_systemd_bounded_test_command(
        workspace_root,
        BoundedTestLimits {
            timeout_seconds: timeout_decision.effective_seconds,
            kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
            memory_max: DEFAULT_TEST_MEMORY_MAX,
            pids_max: DEFAULT_TEST_PIDS_MAX,
            cpu_quota: DEFAULT_TEST_CPU_QUOTA,
        },
        &build_nextest_command(),
        &test_env,
    )
    .map_err(|err| format!("bounded test runner unavailable for FAC pipeline: {err}"))?;
    test_env.extend(bounded_spec.environment);

    Ok(PipelineTestCommand {
        command: bounded_spec.command,
        bounded_runner: true,
        effective_timeout_seconds: timeout_decision.effective_seconds,
        test_env,
    })
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

fn allocate_lane_job_logs_dir() -> Result<(PathBuf, LaneLockGuard), String> {
    let lane_manager = LaneManager::from_default_home()
        .map_err(|err| format!("failed to resolve lane manager: {err}"))?;
    lane_manager
        .ensure_directories()
        .map_err(|err| format!("failed to ensure FAC lane directories: {err}"))?;

    let job_id = Uuid::new_v4().to_string();

    for lane_id in LaneManager::default_lane_ids() {
        match lane_manager.try_lock(&lane_id) {
            Ok(Some(guard)) => {
                let logs_dir = lane_manager.lane_dir(&lane_id).join("logs").join(&job_id);
                crate::commands::fac_permissions::ensure_dir_with_mode(&logs_dir).map_err(
                    |err| format!("failed to create job log dir {}: {err}", logs_dir.display()),
                )?;
                return Ok((logs_dir, guard));
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

/// Maximum bytes to read from a single log file during bundle hashing.
/// Slightly larger than `LOG_STREAM_MAX_BYTES` to account for stream prefixes
/// (`=== stdout ===\n`, `=== stderr ===\n`) and any separator overhead that the
/// log writer prepends outside the payload byte counter.
const LOG_BUNDLE_PER_FILE_MAX_BYTES: u64 = LOG_STREAM_MAX_BYTES + 4096;

/// Open a file for reading with `O_NOFOLLOW` to atomically reject symlinks at
/// the kernel level. This eliminates TOCTOU races between metadata checks and
/// file opens — the kernel refuses to follow symlinks in a single syscall.
fn open_nofollow(path: &Path) -> Result<fs::File, String> {
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

/// Run evidence gates (cargo fmt check, clippy, doc, test, CI scripts).
/// Returns `Ok((all_passed, per_gate_results))`.
/// Fail-closed: any error running a gate counts as failure.
///
/// When `opts` is provided, `test_command` overrides the default
/// `cargo nextest run --workspace` invocation (e.g., to use a bounded runner).
pub fn run_evidence_gates(
    workspace_root: &Path,
    sha: &str,
    projection_log: Option<&mut File>,
    opts: Option<&EvidenceGateOptions>,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let (logs_dir, _lane_guard) = allocate_lane_job_logs_dir()?;

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

    // Script gates that run BEFORE tests (no ordering dependency on test).
    let pre_test_script_gates: &[(&str, &str)] =
        &[("test_safety_guard", "scripts/ci/test_safety_guard.sh")];

    // Script gates that run AFTER tests (ordering dependency on test).
    let post_test_script_gates: &[(&str, &str)] =
        &[("review_artifact_lint", "scripts/ci/review_artifact_lint.sh")];

    let mut all_passed = true;
    let mut evidence_lines = Vec::new();
    let mut gate_results = Vec::new();

    let skip_merge_conflict_gate = opts.is_some_and(|o| o.skip_merge_conflict_gate);
    if !skip_merge_conflict_gate {
        // Phase 0: merge conflict gate (always first, including quick mode).
        let merge_log_path = logs_dir.join(format!("{MERGE_CONFLICT_GATE_NAME}.log"));
        let (merge_passed, merge_duration, merge_line, merge_stats) =
            run_merge_conflict_gate(workspace_root, sha, &merge_log_path);
        gate_results.push(build_evidence_gate_result(
            MERGE_CONFLICT_GATE_NAME,
            merge_passed,
            merge_duration,
            Some(&merge_log_path),
            Some(&merge_stats),
        ));
        if !merge_passed {
            all_passed = false;
        }
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

    // Phase 1: cargo fmt/clippy/doc.
    for &(gate_name, cmd_args) in gates {
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let (passed, stream_stats) = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            cmd_args[0],
            &cmd_args[1..],
            &log_path,
        );
        let duration = started.elapsed().as_secs();
        gate_results.push(build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        ));
        if !passed {
            all_passed = false;
        }
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
            log_path.display()
        ));
    }

    // Phase 2: pre-test script gates.
    for &(gate_name, script_path) in pre_test_script_gates {
        let full_path = workspace_root.join(script_path);
        if !full_path.exists() {
            continue;
        }
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let (passed, stream_stats) = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            "bash",
            &[full_path.to_str().unwrap_or("")],
            &log_path,
        );
        let duration = started.elapsed().as_secs();
        gate_results.push(build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        ));
        if !passed {
            all_passed = false;
        }
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
            log_path.display()
        ));
    }

    // Phase 3: workspace integrity snapshot → test (optional) → verify.
    snapshot_workspace_integrity(workspace_root);

    let skip_test_gate = opts.is_some_and(|o| o.skip_test_gate);
    let test_log = logs_dir.join("test.log");
    if skip_test_gate {
        let skip_msg = b"quick mode enabled: skipped heavyweight test gate\n";
        let _ = crate::commands::fac_permissions::write_fac_file_with_mode(&test_log, skip_msg);
        let ts = now_iso8601();
        eprintln!(
            "ts={ts} sha={sha} gate=test status=SKIP reason=quick_mode log={}",
            test_log.display()
        );
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate=test status=SKIP reason=quick_mode log={}",
            test_log.display()
        ));
        gate_results.push(build_evidence_gate_result(
            "test",
            true,
            0,
            Some(&test_log),
            Some(&StreamStats {
                bytes_written: skip_msg.len() as u64,
                bytes_total: skip_msg.len() as u64,
                was_truncated: false,
            }),
        ));
    } else {
        let test_started = Instant::now();
        let test_command =
            resolve_evidence_test_command_override(opts.and_then(|o| o.test_command.as_deref()));
        let test_env = resolve_evidence_test_command_environment(opts);
        let (test_cmd, test_args) = test_command
            .split_first()
            .ok_or_else(|| "test command is empty".to_string())?;
        let (passed, stream_stats) = run_single_evidence_gate_with_env(
            workspace_root,
            sha,
            "test",
            test_cmd,
            &test_args.iter().map(String::as_str).collect::<Vec<_>>(),
            &test_log,
            test_env,
        );
        let test_duration = test_started.elapsed().as_secs();
        gate_results.push(build_evidence_gate_result(
            "test",
            passed,
            test_duration,
            Some(&test_log),
            Some(&stream_stats),
        ));
        if !passed {
            all_passed = false;
        }
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate=test status={status} log={}",
            test_log.display()
        ));
    }

    let wi_started = Instant::now();
    let wi_log_path = logs_dir.join("workspace_integrity.log");
    let (wi_passed, wi_line, wi_stream_stats) =
        verify_workspace_integrity_gate(workspace_root, sha, &wi_log_path);
    let wi_duration = wi_started.elapsed().as_secs();
    gate_results.push(build_evidence_gate_result(
        "workspace_integrity",
        wi_passed,
        wi_duration,
        Some(&wi_log_path),
        Some(&wi_stream_stats),
    ));
    if !wi_passed {
        all_passed = false;
    }
    evidence_lines.push(wi_line);

    // Phase 4: post-test script gates.
    for &(gate_name, script_path) in post_test_script_gates {
        let full_path = workspace_root.join(script_path);
        if !full_path.exists() {
            continue;
        }
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let (passed, stream_stats) = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            "bash",
            &[full_path.to_str().unwrap_or("")],
            &log_path,
        );
        let duration = started.elapsed().as_secs();
        gate_results.push(build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        ));
        if !passed {
            all_passed = false;
        }
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
            log_path.display()
        ));
    }

    if let Some(file) = projection_log {
        for line in &evidence_lines {
            let _ = writeln!(file, "{line}");
        }
    }

    attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
    Ok((all_passed, gate_results))
}

/// Run evidence gates with CI status comment updates.
///
/// Same as [`run_evidence_gates`] but also updates a PR CI status comment
/// after each gate completes. Checks the per-SHA gate cache before each gate
/// and skips execution if the gate already passed for this SHA.
pub fn run_evidence_gates_with_status(
    workspace_root: &Path,
    sha: &str,
    owner_repo: &str,
    pr_number: u32,
    projection_log: Option<&mut File>,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let (logs_dir, _lane_guard) = allocate_lane_job_logs_dir()?;

    let mut status = CiStatus::new(sha, pr_number);
    let updater = ThrottledUpdater::new(owner_repo, pr_number);

    // Load attested gate cache for this SHA (typically populated by `fac gates`).
    let cache = GateCache::load(sha);
    let mut gate_cache = GateCache::new(sha);
    let pipeline_test_command = build_pipeline_test_command(workspace_root)?;
    let policy = GateResourcePolicy::from_cli(
        false,
        pipeline_test_command.effective_timeout_seconds,
        DEFAULT_TEST_MEMORY_MAX,
        DEFAULT_TEST_PIDS_MAX,
        DEFAULT_TEST_CPU_QUOTA,
        pipeline_test_command.bounded_runner,
    );

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

    let pre_test_script_gates: &[(&str, &str)] =
        &[("test_safety_guard", "scripts/ci/test_safety_guard.sh")];

    // Script gates that run AFTER tests (ordering dependency on test).
    let post_test_script_gates: &[(&str, &str)] =
        &[("review_artifact_lint", "scripts/ci/review_artifact_lint.sh")];

    let mut all_passed = true;
    let mut evidence_lines = Vec::new();
    let mut gate_results = Vec::new();

    // Phase 0: merge conflict gate (always first, always recomputed).
    {
        let gate_name = MERGE_CONFLICT_GATE_NAME;
        status.set_running(gate_name);
        updater.update(&status);

        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let (passed, duration, line, stream_stats) =
            run_merge_conflict_gate(workspace_root, sha, &log_path);
        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        gate_results.push(build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        ));
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
        );
        if !passed {
            updater.force_update(&status);
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            for result in &gate_results {
                gate_cache.backfill_evidence_metadata(
                    &result.gate_name,
                    result.log_bundle_hash.as_deref(),
                    result.bytes_written,
                    result.bytes_total,
                    result.was_truncated,
                );
            }
            let _ = gate_cache.save();
            return Ok((false, gate_results));
        }
    }

    // Phase 1: cargo fmt/clippy/doc.
    for &(gate_name, cmd_args) in gates {
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
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
                gate_results.push(build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                ));
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                );
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
            status.set_running(gate_name);
            updater.update(&status);
            status.set_result(gate_name, false, 0);
            updater.update(&status);
            gate_results.push(build_evidence_gate_result(
                gate_name,
                false,
                0,
                Some(&log_path),
                Some(&StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                }),
            ));
            gate_cache.set_with_attestation(
                gate_name,
                false,
                0,
                attestation_digest.clone(),
                false,
                None,
            );
            all_passed = false;
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                now_iso8601(),
                sha,
                gate_name
            ));
            continue;
        }

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
        status.set_running(gate_name);
        updater.update(&status);
        let started = Instant::now();
        let (passed, stream_stats) = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            cmd_args[0],
            &cmd_args[1..],
            &log_path,
        );
        let duration = started.elapsed().as_secs();

        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        gate_results.push(build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        ));
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            attestation_digest.clone(),
            false,
            sha256_file_hex(&log_path),
        );
        if !passed {
            all_passed = false;
        }
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
    }

    // Phase 2: pre-test script gates.
    for &(gate_name, script_path) in pre_test_script_gates {
        let full_path = workspace_root.join(script_path);
        if !full_path.exists() {
            continue;
        }

        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
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
                gate_results.push(build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                ));
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                );
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
            status.set_running(gate_name);
            updater.update(&status);
            status.set_result(gate_name, false, 0);
            updater.update(&status);
            gate_results.push(build_evidence_gate_result(
                gate_name,
                false,
                0,
                Some(&log_path),
                Some(&StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                }),
            ));
            gate_cache.set_with_attestation(
                gate_name,
                false,
                0,
                attestation_digest.clone(),
                false,
                None,
            );
            all_passed = false;
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                now_iso8601(),
                sha,
                gate_name
            ));
            continue;
        }

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
        status.set_running(gate_name);
        updater.update(&status);
        let started = Instant::now();
        let (passed, stream_stats) = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            "bash",
            &[full_path.to_str().unwrap_or("")],
            &log_path,
        );
        let duration = started.elapsed().as_secs();

        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        gate_results.push(build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        ));
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            attestation_digest.clone(),
            false,
            sha256_file_hex(&log_path),
        );
        if !passed {
            all_passed = false;
        }
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
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        let log_path = logs_dir.join("test.log");
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
                gate_results.push(build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                ));
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                );
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
                gate_results.push(build_evidence_gate_result(
                    gate_name,
                    false,
                    0,
                    Some(&log_path),
                    Some(&StreamStats {
                        bytes_written: 0,
                        bytes_total: 0,
                        was_truncated: false,
                    }),
                ));
                gate_cache.set_with_attestation(
                    gate_name,
                    false,
                    0,
                    attestation_digest,
                    false,
                    None,
                );
                all_passed = false;
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                    now_iso8601(),
                    sha,
                    gate_name
                ));
            }
        } else {
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
            let started = Instant::now();
            let (test_cmd, test_args) = pipeline_test_command
                .command
                .split_first()
                .ok_or_else(|| "pipeline test command is empty".to_string())?;
            let (passed, stream_stats) = run_single_evidence_gate_with_env(
                workspace_root,
                sha,
                gate_name,
                test_cmd,
                &test_args.iter().map(String::as_str).collect::<Vec<_>>(),
                &log_path,
                Some(&pipeline_test_command.test_env),
            );
            let duration = started.elapsed().as_secs();
            status.set_result(gate_name, passed, duration);
            updater.update(&status);
            gate_results.push(build_evidence_gate_result(
                gate_name,
                passed,
                duration,
                Some(&log_path),
                Some(&stream_stats),
            ));
            gate_cache.set_with_attestation(
                gate_name,
                passed,
                duration,
                attestation_digest,
                false,
                sha256_file_hex(&log_path),
            );
            if !passed {
                all_passed = false;
            }
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
        }
    }

    {
        let gate_name = "workspace_integrity";
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        let log_path = logs_dir.join("workspace_integrity.log");
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
                gate_results.push(build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                ));
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                );
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
                gate_results.push(build_evidence_gate_result(
                    gate_name,
                    false,
                    0,
                    Some(&log_path),
                    Some(&StreamStats {
                        bytes_written: 0,
                        bytes_total: 0,
                        was_truncated: false,
                    }),
                ));
                gate_cache.set_with_attestation(
                    gate_name,
                    false,
                    0,
                    attestation_digest,
                    false,
                    None,
                );
                all_passed = false;
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                    now_iso8601(),
                    sha,
                    gate_name
                ));
            }
        } else {
            let started = Instant::now();
            let (passed, line, stream_stats) =
                verify_workspace_integrity_gate(workspace_root, sha, &log_path);
            let duration = started.elapsed().as_secs();
            status.set_result(gate_name, passed, duration);
            updater.update(&status);
            gate_results.push(build_evidence_gate_result(
                gate_name,
                passed,
                duration,
                Some(&log_path),
                Some(&stream_stats),
            ));
            gate_cache.set_with_attestation(
                gate_name,
                passed,
                duration,
                attestation_digest,
                false,
                sha256_file_hex(&log_path),
            );
            if !passed {
                all_passed = false;
            }
            evidence_lines.push(format!(
                "{} reuse_status=miss reuse_reason={}",
                line, reuse.reason
            ));
        }
    }

    // Phase 4: post-test script gates.
    for &(gate_name, script_path) in post_test_script_gates {
        let full_path = workspace_root.join(script_path);
        if !full_path.exists() {
            continue;
        }

        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
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
                gate_results.push(build_evidence_gate_result(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                ));
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest.clone(),
                );
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
            status.set_running(gate_name);
            updater.update(&status);
            status.set_result(gate_name, false, 0);
            updater.update(&status);
            gate_results.push(build_evidence_gate_result(
                gate_name,
                false,
                0,
                Some(&log_path),
                Some(&StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                }),
            ));
            gate_cache.set_with_attestation(
                gate_name,
                false,
                0,
                attestation_digest.clone(),
                false,
                None,
            );
            all_passed = false;
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                now_iso8601(),
                sha,
                gate_name
            ));
            continue;
        }

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
        status.set_running(gate_name);
        updater.update(&status);
        let started = Instant::now();
        let (passed, stream_stats) = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            "bash",
            &[full_path.to_str().unwrap_or("")],
            &log_path,
        );
        let duration = started.elapsed().as_secs();
        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        gate_results.push(build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        ));
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            attestation_digest.clone(),
            false,
            sha256_file_hex(&log_path),
        );
        if !passed {
            all_passed = false;
        }
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
    }

    attach_log_bundle_hash(&mut gate_results, &logs_dir)?;

    // Backfill truncation and log-bundle metadata into durable gate receipts
    // so the persisted cache carries the same observability data as the
    // in-memory EvidenceGateResult.
    for result in &gate_results {
        gate_cache.backfill_evidence_metadata(
            &result.gate_name,
            result.log_bundle_hash.as_deref(),
            result.bytes_written,
            result.bytes_total,
            result.was_truncated,
        );
    }

    // Force a final update to ensure all gate results are posted.
    updater.force_update(&status);

    // Persist gate cache so future pipeline runs can reuse results.
    gate_cache
        .save()
        .map_err(|err| format!("failed to persist attested gate cache: {err}"))?;

    if let Some(file) = projection_log {
        for line in &evidence_lines {
            let _ = writeln!(file, "{line}");
        }
    }

    Ok((all_passed, gate_results))
}

// #[cfg(test)]
// mod tests {
// eprintln!(
// "ts={} sha={} gate={} reuse_status=hit reuse_reason={}
// attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// );
// status.set_result(gate_name, true, cached.duration_secs);
// updater.update(&status);
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit
// reuse_reason={} attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// ));
// let log_path = logs_dir.join(format!("{gate_name}.log"));
// gate_results.push(build_evidence_gate_result(
// gate_name,
// true,
// cached.duration_secs,
// Some(&log_path),
// None,
// ));
// gate_cache.set_with_attestation(
// gate_name,
// true,
// cached.duration_secs,
// attestation_digest,
// false,
// cached.evidence_log_digest.clone(),
// );
// continue;
// }
// }
//
// eprintln!(
// "ts={} sha={} gate={} reuse_status=miss reuse_reason={}
// attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// );
// status.set_running(gate_name);
// updater.update(&status);
//
// let log_path = logs_dir.join(format!("{gate_name}.log"));
// let started = Instant::now();
// let passed = run_single_evidence_gate(
// workspace_root,
// sha,
// gate_name,
// cmd_args[0],
// &cmd_args[1..],
// &log_path,
// );
// let duration = started.elapsed().as_secs();
//
// status.set_result(gate_name, passed, duration);
// updater.update(&status);
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed,
// duration_secs: duration,
// });
// gate_cache.set_with_attestation(
// gate_name,
// passed,
// duration,
// attestation_digest,
// false,
// sha256_file_hex(&log_path),
// );
//
// if !passed {
// all_passed = false;
// }
// let gate_status = if passed { "PASS" } else { "FAIL" };
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
// now_iso8601(),
// sha,
// gate_name,
// gate_status,
// log_path.display(),
// reuse.reason,
// ));
// }
//
// Phase 2: pre-test script gates.
// for &(gate_name, script_path) in pre_test_script_gates {
// let full_path = workspace_root.join(script_path);
// if !full_path.exists() {
// continue;
// }
//
// let attestation_digest =
// gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
// let reuse =
// reuse_decision_for_gate(cache.as_ref(), gate_name,
// attestation_digest.as_deref()); if reuse.reusable {
// if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
// status.set_result(gate_name, true, cached.duration_secs);
// updater.update(&status);
// eprintln!(
// "ts={} sha={} gate={} reuse_status=hit reuse_reason={}
// attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// );
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit
// reuse_reason={} attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// ));
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed: true,
// duration_secs: cached.duration_secs,
// });
// gate_cache.set_with_attestation(
// gate_name,
// true,
// cached.duration_secs,
// attestation_digest,
// false,
// cached.evidence_log_digest.clone(),
// );
// continue;
// }
// }
//
// eprintln!(
// "ts={} sha={} gate={} reuse_status=miss reuse_reason={}
// attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// );
// status.set_running(gate_name);
// updater.update(&status);
//
// let log_path = evidence_dir.join(format!("{gate_name}.log"));
// let started = Instant::now();
// let passed = run_single_evidence_gate(
// workspace_root,
// sha,
// gate_name,
// "bash",
// &[full_path.to_str().unwrap_or("")],
// &log_path,
// );
// let duration = started.elapsed().as_secs();
//
// status.set_result(gate_name, passed, duration);
// updater.update(&status);
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed,
// duration_secs: duration,
// });
// gate_cache.set_with_attestation(
// gate_name,
// passed,
// duration,
// attestation_digest,
// false,
// sha256_file_hex(&log_path),
// );
//
// if !passed {
// all_passed = false;
// }
// let gate_status = if passed { "PASS" } else { "FAIL" };
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
// now_iso8601(),
// sha,
// gate_name,
// gate_status,
// log_path.display(),
// reuse.reason,
// ));
// }
//
// Phase 3: workspace integrity snapshot → test → verify.
// snapshot_workspace_integrity(workspace_root);
//
// {
// let gate_name = "test";
// let attestation_digest = gate_attestation_digest(
// workspace_root,
// sha,
// gate_name,
// Some(pipeline_test_command.command.as_slice()),
// &policy,
// );
// let reuse =
// reuse_decision_for_gate(cache.as_ref(), gate_name,
// attestation_digest.as_deref()); if reuse.reusable {
// if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
// status.set_result(gate_name, true, cached.duration_secs);
// updater.update(&status);
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit
// reuse_reason={} attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// ));
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed: true,
// duration_secs: cached.duration_secs,
// });
// gate_cache.set_with_attestation(
// gate_name,
// true,
// cached.duration_secs,
// attestation_digest,
// false,
// cached.evidence_log_digest.clone(),
// );
// } else {
// eprintln!(
// "ts={} sha={} gate={} reuse_status=miss
// reuse_reason=inconsistent_cache_entry", now_iso8601(),
// sha,
// gate_name
// );
// status.set_result(gate_name, false, 0);
// updater.update(&status);
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed: false,
// duration_secs: 0,
// });
// all_passed = false;
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status=FAIL reuse_status=miss
// reuse_reason=inconsistent_cache_entry", now_iso8601(),
// sha,
// gate_name,
// ));
// }
// } else {
// eprintln!(
// "ts={} sha={} gate={} reuse_status=miss reuse_reason={}
// attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// );
// status.set_running(gate_name);
// updater.update(&status);
//
// let log_path = evidence_dir.join("test.log");
// let started = Instant::now();
// let (test_cmd, test_args) = pipeline_test_command
// .command
// .split_first()
// .ok_or_else(|| "pipeline test command is empty".to_string())?;
// let passed = run_single_evidence_gate_with_env(
// workspace_root,
// sha,
// gate_name,
// test_cmd,
// &test_args.iter().map(String::as_str).collect::<Vec<_>>(),
// &log_path,
// Some(&pipeline_test_command.test_env),
// );
// let duration = started.elapsed().as_secs();
//
// status.set_result(gate_name, passed, duration);
// updater.update(&status);
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed,
// duration_secs: duration,
// });
// gate_cache.set_with_attestation(
// gate_name,
// passed,
// duration,
// attestation_digest,
// false,
// sha256_file_hex(&log_path),
// );
//
// if !passed {
// all_passed = false;
// }
// let gate_status = if passed { "PASS" } else { "FAIL" };
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
// now_iso8601(),
// sha,
// gate_name,
// gate_status,
// log_path.display(),
// reuse.reason
// ));
// }
// }
//
// {
// let gate_name = "workspace_integrity";
// let attestation_digest =
// gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
// let reuse =
// reuse_decision_for_gate(cache.as_ref(), gate_name,
// attestation_digest.as_deref()); if reuse.reusable {
// if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
// status.set_result(gate_name, true, cached.duration_secs);
// updater.update(&status);
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit
// reuse_reason={} attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// ));
// let log_path = logs_dir.join(format!("{gate_name}.log"));
// gate_results.push(build_evidence_gate_result(
// gate_name,
// true,
// cached.duration_secs,
// Some(&log_path),
// None,
// ));
// gate_cache.set_with_attestation(
// gate_name,
// true,
// cached.duration_secs,
// attestation_digest,
// false,
// cached.evidence_log_digest.clone(),
// );
// }
// } else {
// status.set_running(gate_name);
// updater.update(&status);
//
// let started = Instant::now();
// let (passed, line) =
// verify_workspace_integrity_gate(workspace_root, sha, &evidence_dir);
// let duration = started.elapsed().as_secs();
//
// status.set_result(gate_name, passed, duration);
// updater.update(&status);
// let log_path = evidence_dir.join("workspace_integrity.log");
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed,
// duration_secs: duration,
// });
// gate_cache.set_with_attestation(
// gate_name,
// passed,
// duration,
// attestation_digest,
// false,
// sha256_file_hex(&log_path),
// );
//
// if !passed {
// all_passed = false;
// }
// evidence_lines.push(format!(
// "{} reuse_status=miss reuse_reason={}",
// line, reuse.reason
// ));
// }
// }
//
// Phase 4: post-test script gates.
// for &(gate_name, script_path) in post_test_script_gates {
// let full_path = workspace_root.join(script_path);
// if !full_path.exists() {
// continue;
// }
//
// let attestation_digest =
// gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
// let reuse =
// reuse_decision_for_gate(cache.as_ref(), gate_name,
// attestation_digest.as_deref()); if reuse.reusable {
// if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
// status.set_result(gate_name, true, cached.duration_secs);
// updater.update(&status);
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit
// reuse_reason={} attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// ));
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed: true,
// duration_secs: cached.duration_secs,
// });
// gate_cache.set_with_attestation(
// gate_name,
// true,
// cached.duration_secs,
// attestation_digest,
// false,
// cached.evidence_log_digest.clone(),
// );
// continue;
// }
// }
//
// eprintln!(
// "ts={} sha={} gate={} reuse_status=miss reuse_reason={}
// attestation_digest={}", now_iso8601(),
// sha,
// gate_name,
// reuse.reason,
// attestation_digest
// .as_deref()
// .map_or_else(|| "unknown".to_string(), short_digest),
// );
// status.set_running(gate_name);
// updater.update(&status);
//
// let log_path = logs_dir.join(format!("{gate_name}.log"));
// let started = Instant::now();
// let passed = run_single_evidence_gate(
// workspace_root,
// sha,
// gate_name,
// "bash",
// &[full_path.to_str().unwrap_or("")],
// &log_path,
// );
// let duration = started.elapsed().as_secs();
//
// status.set_result(gate_name, passed, duration);
// updater.update(&status);
// gate_results.push(EvidenceGateResult {
// gate_name: gate_name.to_string(),
// passed,
// duration_secs: duration,
// });
// gate_cache.set_with_attestation(
// gate_name,
// passed,
// duration,
// attestation_digest,
// false,
// sha256_file_hex(&log_path),
// );
//
// if !passed {
// all_passed = false;
// }
// let gate_status = if passed { "PASS" } else { "FAIL" };
// evidence_lines.push(format!(
// "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
// now_iso8601(),
// sha,
// gate_name,
// gate_status,
// log_path.display(),
// reuse.reason,
// ));
// }
//
// Force a final update to ensure all gate results are posted.
// updater.force_update(&status);
//
// Persist gate cache so future pipeline runs can reuse results.
// gate_cache
// .save()
// .map_err(|err| format!("failed to persist attested gate cache: {err}"))?;
//
// if let Some(file) = projection_log {
// for line in &evidence_lines {
// let _ = writeln!(file, "{line}");
// }
// }
//
// Ok((all_passed, gate_results))
// }
//

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
        match build_pipeline_test_command(temp_dir.path()) {
            Ok(command) => {
                let joined = command.command.join(" ");
                assert!(joined.contains("systemd-run"));
                assert!(joined.contains("cargo nextest run --workspace"));
                assert!(!joined.contains("run_bounded_tests.sh"));
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
}
