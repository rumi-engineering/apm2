// AGENT-AUTHORED (TCK-00552)
//! `apm2 fac bench` -- standardized benchmark harness for cold/warm gate times,
//! disk footprint collapse, and concurrency stability.
//!
//! Runs a reproducible sequence:
//! 1. Measure cold-start gate times
//! 2. Warm the build caches
//! 3. Measure warm gate times
//! 4. Measure multi-concurrent gate times
//! 5. Measure target directory disk footprint
//!
//! Produces a content-addressed `BenchReportV1` artifact under
//! `$APM2_HOME/private/fac/bench/` for cross-commit comparison.
//!
//! # Invariants
//!
//! - \[INV-BENCH-001\] All timing uses monotonic `Instant` (INV-2501).
//! - \[INV-BENCH-002\] Disk measurement uses bounded directory traversal
//!   (`MAX_DIR_WALK_DEPTH`, `MAX_DIR_WALK_ENTRIES`).
//! - \[INV-BENCH-003\] Concurrency is bounded by `MAX_CONCURRENCY`.
//! - \[INV-BENCH-004\] Report persistence uses atomic write (temp+rename,
//!   CTR-2607).
//! - \[INV-BENCH-005\] All collections are bounded by hard `MAX_*` constants.

use std::env;
use std::fs;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::commands::fac_warm::run_fac_warm;
use crate::exit_codes::codes as exit_codes;

// ---------------------------------------------------------------------------
// Constants (INV-BENCH-002, INV-BENCH-003, INV-BENCH-005)
// ---------------------------------------------------------------------------

/// Maximum depth for directory traversal during disk measurement.
const MAX_DIR_WALK_DEPTH: u32 = 64;

/// Maximum directory entries per level during disk measurement.
const MAX_DIR_WALK_ENTRIES: usize = 100_000;

/// Maximum concurrency for multi-concurrent gate runs.
const MAX_CONCURRENCY: u8 = 8;

/// Maximum number of gate phases per run in a report.
const MAX_GATE_PHASES: usize = 32;

/// Maximum number of runs in a single bench report.
const MAX_BENCH_RUNS: usize = 16;

/// Maximum bytes to retain from child process output.
const MAX_CHILD_OUTPUT_BYTES: usize = 1_048_576;

/// Maximum directory candidates when inferring many-worktree baselines.
const MAX_MANY_WORKTREE_ENTRIES: usize = 512;

/// Schema identifier for bench report.
const BENCH_REPORT_SCHEMA: &str = "apm2.fac.bench_report.v1";

// ---------------------------------------------------------------------------
// Report Types
// ---------------------------------------------------------------------------

/// A single phase timing within a gate run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatePhaseTiming {
    /// Phase name (e.g., "fmt", "clippy", "doc", "test").
    pub name: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the phase passed.
    pub passed: bool,
}

/// A single gate run measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRunMeasurement {
    /// Label for this run (e.g., "cold", "warm", "concurrent-0").
    pub label: String,
    /// Total wall-clock duration in milliseconds.
    pub total_duration_ms: u64,
    /// Whether all gates passed.
    pub all_passed: bool,
    /// Per-phase timings.
    pub phases: Vec<GatePhaseTiming>,
}

/// Disk footprint measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskFootprint {
    /// Path measured.
    pub path: String,
    /// Total size in bytes.
    pub size_bytes: u64,
    /// Number of files counted.
    pub file_count: u64,
    /// Number of directories counted.
    pub dir_count: u64,
}

/// Headline deltas comparing cold vs warm performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlineDeltas {
    /// Cold gate total duration in milliseconds.
    pub cold_total_ms: u64,
    /// Warm gate total duration in milliseconds.
    pub warm_total_ms: u64,
    /// Speedup factor (cold / warm). E.g., 10.0 means 10x faster.
    pub speedup_factor: f64,
    /// Aggregate size of target directories across sibling worktrees.
    pub many_worktrees_target_baseline_bytes: u64,
    /// Target directory size after warm (bytes).
    pub warm_target_size_bytes: u64,
    /// Reduction factor for many-worktree baseline vs warm target.
    pub target_collapse_factor: f64,
    /// Reduction percentage for many-worktree baseline vs warm target.
    pub target_collapse_percent: f64,
    /// Number of concurrent runs that passed.
    pub concurrent_passed: u32,
    /// Number of concurrent runs total.
    pub concurrent_total: u32,
    /// Denial rate across all runs (0.0 = no denials, 1.0 = all denied).
    pub denial_rate: f64,
}

/// The top-level bench report artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReportV1 {
    /// Schema identifier.
    pub schema_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Git HEAD SHA at the time of benchmarking.
    pub head_sha: String,
    /// Unix timestamp (seconds) when the benchmark started.
    pub started_at_unix: u64,
    /// Total benchmark wall-clock duration in milliseconds.
    pub total_duration_ms: u64,
    /// Individual gate run measurements.
    pub runs: Vec<GateRunMeasurement>,
    /// Disk footprint measurements.
    pub disk_footprints: Vec<DiskFootprint>,
    /// Computed headline deltas.
    pub deltas: HeadlineDeltas,
    /// SHA-256 content hash of the report (excluding this field).
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run `apm2 fac bench`.
///
/// Returns an exit code.
#[allow(clippy::too_many_arguments)]
pub fn run_fac_bench(
    concurrency: u8,
    skip_warm: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    json_output: bool,
) -> u8 {
    let overall_start = Instant::now();

    // Validate concurrency bound (INV-BENCH-003).
    let effective_concurrency = concurrency.max(1).min(MAX_CONCURRENCY);
    if concurrency != effective_concurrency {
        emit_warn(
            json_output,
            &format!(
                "concurrency clamped from {concurrency} to {effective_concurrency} (MAX_CONCURRENCY)"
            ),
        );
    }

    let many_worktrees_target_baseline_bytes = measure_many_worktrees_target_baseline();

    // Resolve HEAD SHA.
    let head_sha = match resolve_head_sha() {
        Ok(sha) => sha,
        Err(msg) => {
            return output_error(
                json_output,
                "head_sha_resolve_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let started_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    emit_event(
        json_output,
        "bench_started",
        &serde_json::json!({
            "head_sha": head_sha,
            "concurrency": effective_concurrency,
            "skip_warm": skip_warm,
            "timeout_seconds": timeout_seconds,
        }),
    );

    let mut runs: Vec<GateRunMeasurement> = Vec::new();

    // -----------------------------------------------------------------------
    // Phase 1: Cold gates
    // -----------------------------------------------------------------------
    emit_event(
        json_output,
        "phase_started",
        &serde_json::json!({"phase": "cold_gates"}),
    );
    let cold_run = run_gate_measurement(
        "cold",
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        json_output,
    );
    emit_event(
        json_output,
        "phase_completed",
        &serde_json::json!({
            "phase": "cold_gates",
            "duration_ms": cold_run.total_duration_ms,
            "passed": cold_run.all_passed,
        }),
    );
    runs.push(cold_run);

    // -----------------------------------------------------------------------
    // Phase 2: Warm
    // -----------------------------------------------------------------------
    if !skip_warm {
        emit_event(
            json_output,
            "phase_started",
            &serde_json::json!({"phase": "warm"}),
        );
        let warm_start = Instant::now();
        let warm_ok = run_warm_phase(timeout_seconds, json_output);
        let warm_dur = millis_from_elapsed(&warm_start);
        emit_event(
            json_output,
            "phase_completed",
            &serde_json::json!({
                "phase": "warm",
                "duration_ms": warm_dur,
                "passed": warm_ok,
            }),
        );
        if !warm_ok {
            return output_error(
                json_output,
                "warm_phase_failed",
                "warm phase failed; refusing to proceed without FAC containment",
                exit_codes::GENERIC_ERROR,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Phase 3: Warm gates
    // -----------------------------------------------------------------------
    emit_event(
        json_output,
        "phase_started",
        &serde_json::json!({"phase": "warm_gates"}),
    );
    let warm_run = run_gate_measurement(
        "warm",
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        json_output,
    );
    emit_event(
        json_output,
        "phase_completed",
        &serde_json::json!({
            "phase": "warm_gates",
            "duration_ms": warm_run.total_duration_ms,
            "passed": warm_run.all_passed,
        }),
    );
    runs.push(warm_run);

    // -----------------------------------------------------------------------
    // Phase 4: Concurrent gates
    // -----------------------------------------------------------------------
    if effective_concurrency > 1 {
        emit_event(
            json_output,
            "phase_started",
            &serde_json::json!({
                "phase": "concurrent_gates",
                "concurrency": effective_concurrency,
            }),
        );
        let concurrent_start = Instant::now();
        let concurrent_runs = run_concurrent_gates(
            effective_concurrency,
            timeout_seconds,
            memory_max,
            pids_max,
            cpu_quota,
        );
        let concurrent_dur = millis_from_elapsed(&concurrent_start);
        let concurrent_passed = concurrent_runs.iter().filter(|r| r.all_passed).count();
        emit_event(
            json_output,
            "phase_completed",
            &serde_json::json!({
                "phase": "concurrent_gates",
                "duration_ms": concurrent_dur,
                "passed": concurrent_passed,
                "total": concurrent_runs.len(),
            }),
        );
        // Bounded push (INV-BENCH-005).
        for r in concurrent_runs {
            if runs.len() >= MAX_BENCH_RUNS {
                break;
            }
            runs.push(r);
        }
    }

    // -----------------------------------------------------------------------
    // Phase 5: Disk footprint measurement
    // -----------------------------------------------------------------------
    emit_event(
        json_output,
        "phase_started",
        &serde_json::json!({"phase": "disk_footprint"}),
    );
    let disk_footprints = measure_disk_footprints();
    emit_event(
        json_output,
        "phase_completed",
        &serde_json::json!({
            "phase": "disk_footprint",
            "measurements": disk_footprints.len(),
        }),
    );

    // -----------------------------------------------------------------------
    // Compute headline deltas
    // -----------------------------------------------------------------------
    let cold_ms = runs
        .iter()
        .find(|r| r.label == "cold")
        .map_or(1, |r| r.total_duration_ms);
    let warm_ms = runs
        .iter()
        .find(|r| r.label == "warm")
        .map_or(1, |r| r.total_duration_ms);

    // Avoid division by zero (INV-2504). Use u32 intermediates for f64
    // conversion to avoid clippy::cast_precision_loss on u64.
    #[allow(clippy::cast_precision_loss)]
    let speedup_factor = if warm_ms > 0 {
        // Saturate to u32::MAX (~4 billion ms = ~49 days) which is well
        // beyond any plausible gate duration and avoids precision loss.
        let cold_clamped = u32::try_from(cold_ms).unwrap_or(u32::MAX);
        let warm_clamped = u32::try_from(warm_ms).unwrap_or(u32::MAX);
        f64::from(cold_clamped) / f64::from(warm_clamped)
    } else {
        0.0
    };

    let concurrent_runs_data: Vec<&GateRunMeasurement> = runs
        .iter()
        .filter(|r| r.label.starts_with("concurrent-"))
        .collect();
    let concurrent_total = u32::try_from(concurrent_runs_data.len()).unwrap_or(u32::MAX);
    let concurrent_passed =
        u32::try_from(concurrent_runs_data.iter().filter(|r| r.all_passed).count())
            .unwrap_or(u32::MAX);
    let total_runs = u32::try_from(runs.len()).unwrap_or(u32::MAX);
    let total_failed =
        u32::try_from(runs.iter().filter(|r| !r.all_passed).count()).unwrap_or(u32::MAX);
    let denial_rate = if total_runs > 0 {
        f64::from(total_failed) / f64::from(total_runs)
    } else {
        0.0
    };

    let warm_target_size_bytes = disk_footprints
        .iter()
        .find(|d| d.path.contains("target"))
        .map_or(0, |d| d.size_bytes);

    let (target_collapse_factor, target_collapse_percent) = compute_target_collapse_metrics(
        many_worktrees_target_baseline_bytes,
        warm_target_size_bytes,
    );

    let deltas = HeadlineDeltas {
        cold_total_ms: cold_ms,
        warm_total_ms: warm_ms,
        speedup_factor,
        many_worktrees_target_baseline_bytes,
        warm_target_size_bytes,
        target_collapse_factor,
        target_collapse_percent,
        concurrent_passed,
        concurrent_total,
        denial_rate,
    };

    // -----------------------------------------------------------------------
    // Build and persist report
    // -----------------------------------------------------------------------
    let total_duration_ms = millis_from_elapsed(&overall_start);

    // Build report without content_hash first, then compute it.
    let mut report = BenchReportV1 {
        schema_id: BENCH_REPORT_SCHEMA.to_string(),
        schema_version: "1.0.0".to_string(),
        head_sha,
        started_at_unix,
        total_duration_ms,
        runs,
        disk_footprints,
        deltas,
        content_hash: String::new(),
    };
    report.content_hash = compute_report_content_hash(&report);

    // Persist the report artifact (INV-BENCH-004).
    match persist_bench_report(&report) {
        Ok(path) => {
            emit_event(
                json_output,
                "report_persisted",
                &serde_json::json!({
                    "path": path.display().to_string(),
                    "content_hash": report.content_hash,
                }),
            );
        },
        Err(msg) => {
            emit_warn(
                json_output,
                &format!("failed to persist bench report: {msg}"),
            );
        },
    }

    // Emit final summary.
    let report_json = serde_json::to_value(&report).unwrap_or_else(|_| serde_json::json!({}));
    emit_event(json_output, "bench_completed", &report_json);

    // Print the report.
    match serde_json::to_string_pretty(&report) {
        Ok(s) => println!("{s}"),
        Err(_) => {
            return output_error(
                json_output,
                "serialization_failed",
                "failed to serialize bench report",
                exit_codes::GENERIC_ERROR,
            );
        },
    }

    if report.deltas.denial_rate > 0.5 {
        exit_codes::GENERIC_ERROR
    } else {
        exit_codes::SUCCESS
    }
}

// ---------------------------------------------------------------------------
// Gate measurement
// ---------------------------------------------------------------------------

/// Run gates and capture timing, returning a `GateRunMeasurement`.
fn run_gate_measurement(
    label: &str,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    json_output: bool,
) -> GateRunMeasurement {
    let overall = Instant::now();

    // Resolve the active CLI binary path to avoid PATH-based resolution.
    let exe = match env::current_exe() {
        Ok(path) => path,
        Err(_) => {
            return GateRunMeasurement {
                label: label.to_string(),
                total_duration_ms: millis_from_elapsed(&overall),
                all_passed: false,
                phases: vec![GatePhaseTiming {
                    name: "exe_resolve_error".to_string(),
                    duration_ms: 0,
                    passed: false,
                }],
            };
        },
    };

    // Run gates via the active CLI binary to get an isolated measurement.
    // We parse the JSON output to extract per-phase timings.
    let mut cmd = Command::new(exe);
    cmd.args([
        "fac",
        "gates",
        "--quick",
        "--timeout-seconds",
        &timeout_seconds.to_string(),
        "--memory-max",
        memory_max,
        "--pids-max",
        &pids_max.to_string(),
        "--cpu-quota",
        cpu_quota,
    ]);

    let total_duration_ms = millis_from_elapsed(&overall);
    let output_result = run_command_with_bounded_output(cmd, MAX_CHILD_OUTPUT_BYTES, Stdio::null());

    match output_result {
        Ok((status, output, output_truncated)) => {
            if output_truncated && json_output {
                emit_event(
                    json_output,
                    "command_output_truncated",
                    &serde_json::json!({
                        "command": "fac gates",
                        "label": label,
                        "stdout": true,
                        "truncated": output_truncated,
                    }),
                );
            }

            let stdout = String::from_utf8_lossy(&output);
            let all_passed = status.success();
            let phases = parse_gate_phases(&stdout);
            GateRunMeasurement {
                label: label.to_string(),
                total_duration_ms,
                all_passed,
                phases,
            }
        },
        Err(_) => GateRunMeasurement {
            label: label.to_string(),
            total_duration_ms,
            all_passed: false,
            phases: vec![GatePhaseTiming {
                name: "spawn_error".to_string(),
                duration_ms: total_duration_ms,
                passed: false,
            }],
        },
    }
}

/// Parse gate phase timings from the JSONL/JSON output of `apm2 fac gates`.
fn parse_gate_phases(stdout: &str) -> Vec<GatePhaseTiming> {
    let mut phases = Vec::new();

    // The gates output is JSONL with `gate_completed` events.
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // Look for `gate_completed` events.
        if val.get("event").and_then(serde_json::Value::as_str) == Some("gate_completed") {
            let name = val
                .get("gate")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let duration_secs = val
                .get("duration_secs")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            let status = val
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("fail");
            let passed = status == "pass";

            if phases.len() < MAX_GATE_PHASES {
                phases.push(GatePhaseTiming {
                    name,
                    duration_ms: secs_f64_to_millis(duration_secs),
                    passed,
                });
            }
        }
        // Also try `gates_summary` which has a gates array.
        if val.get("event").and_then(serde_json::Value::as_str) == Some("gates_summary") {
            if let Some(extra) = val.get("extra") {
                if let Some(gates) = extra.get("gates").and_then(serde_json::Value::as_array) {
                    for gate in gates {
                        if phases.len() >= MAX_GATE_PHASES {
                            break;
                        }
                        let name = gate
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unknown")
                            .to_string();
                        let dur = gate
                            .get("duration_secs")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(0);
                        let status = gate
                            .get("status")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("fail");
                        phases.push(GatePhaseTiming {
                            name,
                            duration_ms: dur.saturating_mul(1000),
                            passed: status == "pass",
                        });
                    }
                }
            }
        }
    }

    // If no JSONL events were found, try parsing the entire output as a single
    // JSON object (non-JSONL mode).
    if phases.is_empty() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(stdout) {
            if let Some(gates) = val.get("gates").and_then(serde_json::Value::as_array) {
                for gate in gates {
                    if phases.len() >= MAX_GATE_PHASES {
                        break;
                    }
                    let name = gate
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown")
                        .to_string();
                    let dur = gate
                        .get("duration_secs")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    let status = gate
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("fail");
                    phases.push(GatePhaseTiming {
                        name,
                        duration_ms: dur.saturating_mul(1000),
                        passed: status == "pass",
                    });
                }
            }
        }
    }

    phases
}

// ---------------------------------------------------------------------------
// Warm phase
// ---------------------------------------------------------------------------

/// Read from a stream with a strict upper bound.
///
/// Returns collected bytes (capped), and whether truncation occurred.
fn read_stream_with_cap(mut reader: impl Read, max_bytes: usize) -> Result<(Vec<u8>, bool), String> {
    let mut output = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 8192];

    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| format!("read stream failed: {e}"))?;
        if n == 0 {
            break;
        }

        if !truncated {
            let remaining = max_bytes.saturating_sub(output.len());
            if n <= remaining {
                output.extend_from_slice(&chunk[..n]);
            } else {
                output.extend_from_slice(&chunk[..remaining]);
                truncated = true;
            }
        }

        if output.len() >= max_bytes {
            truncated = true;
            output.truncate(max_bytes);
        }
    }

    Ok((output, truncated))
}

/// Run a command and read bounded output with bounded buffering.
///
/// Redirects stderr to the supplied target and caps stdout bytes.
fn run_command_with_bounded_output(
    mut cmd: Command,
    max_stdout_bytes: usize,
    stderr: Stdio,
) -> Result<(std::process::ExitStatus, Vec<u8>, bool), String> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .map_err(|e| format!("spawn failed: {e}"))?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "missing stdout pipe".to_string())?;

    let (stdout, truncated) = read_stream_with_cap(&mut stdout, max_stdout_bytes)?;
    let status = child
        .wait()
        .map_err(|e| format!("wait failed: {e}"))?;

    Ok((status, stdout, truncated))
}

/// Compute target collapse metrics from many-worktree baseline and warm target.
fn compute_target_collapse_metrics(baseline_bytes: u64, warm_bytes: u64) -> (f64, f64) {
    if baseline_bytes == 0 || warm_bytes == 0 {
        return (0.0, 0.0);
    }

    let factor = baseline_bytes as f64 / warm_bytes as f64;
    let percent =
        ((baseline_bytes as f64 - warm_bytes as f64) / baseline_bytes as f64) * 100.0;

    (factor, percent)
}

/// Sum target directory sizes for sibling worktrees.
///
/// This approximates the "many worktree" baseline by scanning the repo
/// parent directory for sibling trees and summing any immediate `target`
/// directories that look like git worktree roots.
fn measure_many_worktrees_target_baseline() -> u64 {
    let Some(repo_root) = find_repo_root_from_cwd() else {
        return 0;
    };

    let Some(parent) = repo_root.parent() else {
        return 0;
    };

    let Ok(entries) = fs::read_dir(parent) else {
        return 0;
    };

    let mut total = 0u64;
    let mut entries_scanned = 0usize;
    for entry in entries.flatten() {
        if entries_scanned >= MAX_MANY_WORKTREE_ENTRIES {
            break;
        }
        entries_scanned = entries_scanned.saturating_add(1);

        let Ok(meta) = entry.symlink_metadata() else {
            continue;
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }

        let candidate = entry.path();
        if !is_worktree_root(&candidate) {
            continue;
        }

        let target = candidate.join("target");
        let Ok(target_meta) = target.symlink_metadata() else {
            continue;
        };
        if !target_meta.is_dir() || target_meta.file_type().is_symlink() {
            continue;
        }
        total = total.saturating_add(measure_directory(&target).size_bytes);
    }

    total
}

fn is_worktree_root(path: &Path) -> bool {
    let git_path = path.join(".git");
    git_path
        .symlink_metadata()
        .map(|m| {
            let ty = m.file_type();
            !ty.is_symlink() && (ty.is_file() || ty.is_dir())
        })
        .unwrap_or(false)
}

fn find_repo_root_from_cwd() -> Option<PathBuf> {
    let mut current = env::current_dir().ok()?;
    loop {
        let git_path = current.join(".git");
        if git_path.symlink_metadata().is_ok() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Run the warm phase to pre-populate build caches.
///
/// Returns `true` if warm succeeded.
fn run_warm_phase(timeout_seconds: u64, json_output: bool) -> bool {
    let status = run_fac_warm(&None, &None, true, timeout_seconds, json_output);
    status == exit_codes::SUCCESS
}

// ---------------------------------------------------------------------------
// Concurrent gates
// ---------------------------------------------------------------------------

/// Run multiple gate runs concurrently and return their measurements.
///
/// Bounded by `MAX_CONCURRENCY` (INV-BENCH-003).
fn run_concurrent_gates(
    concurrency: u8,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
) -> Vec<GateRunMeasurement> {
    use std::thread;

    let mut handles = Vec::new();

    for i in 0..concurrency {
        let label = format!("concurrent-{i}");
        let timeout = timeout_seconds;
        let mem = memory_max.to_string();
        let pids = pids_max;
        let cpu = cpu_quota.to_string();

        let handle =
            thread::spawn(move || run_gate_measurement(&label, timeout, &mem, pids, &cpu, false));
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(measurement) => {
                if results.len() < MAX_BENCH_RUNS {
                    results.push(measurement);
                }
            },
            Err(_) => {
                if results.len() < MAX_BENCH_RUNS {
                    results.push(GateRunMeasurement {
                        label: "concurrent-panicked".to_string(),
                        total_duration_ms: 0,
                        all_passed: false,
                        phases: Vec::new(),
                    });
                }
            },
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Disk footprint measurement (INV-BENCH-002)
// ---------------------------------------------------------------------------

/// Measure disk footprints of the target directory and workspace.
fn measure_disk_footprints() -> Vec<DiskFootprint> {
    let mut footprints = Vec::new();

    // Measure ./target if it exists.
    let target = PathBuf::from("target");
    if target.is_dir() {
        footprints.push(measure_directory(&target));
    }

    // Measure FAC managed cargo home if it exists.
    if let Some(home) = apm2_core::github::resolve_apm2_home() {
        let cargo_home = home.join("private").join("fac").join("cargo_home");
        if cargo_home.is_dir() {
            footprints.push(measure_directory(&cargo_home));
        }
    }

    footprints
}

/// Recursively measure directory size with bounded traversal.
///
/// Uses iterative BFS to avoid stack overflow (INV-BENCH-002).
fn measure_directory(root: &Path) -> DiskFootprint {
    let mut size_bytes: u64 = 0;
    let mut file_count: u64 = 0;
    let mut dir_count: u64 = 0;
    let mut total_entries: usize = 0;

    // BFS with bounded depth.
    let mut queue: Vec<(PathBuf, u32)> = vec![(root.to_path_buf(), 0)];

    while let Some((dir, depth)) = queue.pop() {
        if depth > MAX_DIR_WALK_DEPTH {
            continue;
        }

        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries {
            total_entries = total_entries.saturating_add(1);
            if total_entries > MAX_DIR_WALK_ENTRIES {
                return DiskFootprint {
                    path: root.display().to_string(),
                    size_bytes,
                    file_count,
                    dir_count,
                };
            }

            let Ok(entry) = entry else {
                continue;
            };

            let Ok(meta) = entry.symlink_metadata() else {
                continue;
            };

            let file_type = meta.file_type();
            if file_type.is_symlink() {
                continue;
            }

            if meta.is_dir() {
                dir_count = dir_count.saturating_add(1);
                queue.push((entry.path(), depth + 1));
            } else if meta.is_file() {
                file_count = file_count.saturating_add(1);
                size_bytes = size_bytes.saturating_add(meta.len());
            }
            // Skip symlinks and special files.
        }
    }

    DiskFootprint {
        path: root.display().to_string(),
        size_bytes,
        file_count,
        dir_count,
    }
}

// ---------------------------------------------------------------------------
// Report persistence (INV-BENCH-004)
// ---------------------------------------------------------------------------

/// Persist the bench report as an atomic JSON file under the bench artifacts
/// directory.
fn persist_bench_report(report: &BenchReportV1) -> Result<PathBuf, String> {
    let home = apm2_core::github::resolve_apm2_home().ok_or("cannot resolve APM2 home")?;
    let bench_dir = home.join("private").join("fac").join("bench");

    // Create dir with 0o700 (CTR-2611).
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(&bench_dir)
            .map_err(|e| format!("mkdir: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(&bench_dir).map_err(|e| format!("mkdir: {e}"))?;
    }

    let json = serde_json::to_string_pretty(report).map_err(|e| format!("serialize: {e}"))?;

    // Use checked slicing to avoid panic on short SHA (RSK-0701).
    let sha_prefix_end = report.head_sha.len().min(8);
    let sha_prefix = &report.head_sha[..sha_prefix_end];
    let filename = format!("bench_{sha_prefix}_{}.json", report.started_at_unix);
    let target_path = bench_dir.join(&filename);

    // Atomic write: temp file + rename (CTR-2607).
    let temp_path = bench_dir.join(format!(".bench_tmp_{}", std::process::id()));
    {
        let mut f = fs::File::create(&temp_path).map_err(|e| format!("create temp: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        f.write_all(json.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;
    }

    fs::rename(&temp_path, &target_path).map_err(|e| {
        // Best-effort cleanup of temp file.
        let _ = fs::remove_file(&temp_path);
        format!("rename: {e}")
    })?;

    Ok(target_path)
}

// ---------------------------------------------------------------------------
// Content hash
// ---------------------------------------------------------------------------

/// Compute a SHA-256 content hash over the report fields (excluding
/// `content_hash` itself).
fn compute_report_content_hash(report: &BenchReportV1) -> String {
    let mut hasher = Sha256::new();

    // Domain separator.
    hasher.update(b"apm2.fac.bench_report.content_hash.v1\0");

    // Schema fields.
    hasher.update(report.schema_id.as_bytes());
    hasher.update(report.schema_version.as_bytes());
    hasher.update(report.head_sha.as_bytes());
    hasher.update(report.started_at_unix.to_le_bytes());
    hasher.update(report.total_duration_ms.to_le_bytes());

    // Runs (length-prefixed, INV-BENCH-005).
    hasher.update((report.runs.len() as u64).to_le_bytes());
    for run in &report.runs {
        hasher.update(run.label.as_bytes());
        hasher.update(run.total_duration_ms.to_le_bytes());
        hasher.update(if run.all_passed { [1u8] } else { [0u8] });
        hasher.update((run.phases.len() as u64).to_le_bytes());
        for phase in &run.phases {
            hasher.update(phase.name.as_bytes());
            hasher.update(phase.duration_ms.to_le_bytes());
            hasher.update(if phase.passed { [1u8] } else { [0u8] });
        }
    }

    // Disk footprints.
    hasher.update((report.disk_footprints.len() as u64).to_le_bytes());
    for fp in &report.disk_footprints {
        hasher.update(fp.path.as_bytes());
        hasher.update(fp.size_bytes.to_le_bytes());
        hasher.update(fp.file_count.to_le_bytes());
        hasher.update(fp.dir_count.to_le_bytes());
    }

    // Deltas.
    hasher.update(report.deltas.cold_total_ms.to_le_bytes());
    hasher.update(report.deltas.warm_total_ms.to_le_bytes());
    hasher.update(report.deltas.speedup_factor.to_le_bytes());
    hasher.update(report.deltas.many_worktrees_target_baseline_bytes.to_le_bytes());
    hasher.update(report.deltas.warm_target_size_bytes.to_le_bytes());
    hasher.update(report.deltas.target_collapse_factor.to_le_bytes());
    hasher.update(report.deltas.target_collapse_percent.to_le_bytes());
    hasher.update(report.deltas.concurrent_passed.to_le_bytes());
    hasher.update(report.deltas.concurrent_total.to_le_bytes());
    hasher.update(report.deltas.denial_rate.to_le_bytes());

    let hash = hasher.finalize();
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the current HEAD SHA.
fn resolve_head_sha() -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| format!("git rev-parse failed: {e}"))?;

    if !output.status.success() {
        return Err("git rev-parse HEAD returned non-zero".to_string());
    }

    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.len() < 7 || sha.len() > 64 {
        return Err(format!("unexpected SHA length: {}", sha.len()));
    }
    Ok(sha)
}

/// Convert elapsed time from an `Instant` to milliseconds as `u64`.
///
/// Saturates at `u64::MAX` for durations exceeding ~584 million years.
fn millis_from_elapsed(start: &Instant) -> u64 {
    let ms = start.elapsed().as_millis();
    u64::try_from(ms).unwrap_or(u64::MAX)
}

/// Convert `f64` seconds to `u64` milliseconds.
///
/// Negative or `NaN` values map to 0; values above `u64::MAX` saturate.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn secs_f64_to_millis(secs: f64) -> u64 {
    if secs.is_nan() || secs < 0.0 {
        return 0;
    }
    let ms = secs * 1000.0;
    // u64::MAX as f64 loses precision but the comparison is conservative:
    // any f64 >= the rounded value is certainly above u64::MAX.
    if ms >= u64::MAX as f64 {
        u64::MAX
    } else {
        ms as u64
    }
}

fn emit_event(json_output: bool, event: &str, extra: &serde_json::Value) {
    if json_output {
        let obj = serde_json::json!({
            "event": event,
            "ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            "extra": extra,
        });
        if let Ok(s) = serde_json::to_string(&obj) {
            println!("{s}");
        }
    }
}

fn emit_warn(json_output: bool, msg: &str) {
    if json_output {
        emit_event(
            json_output,
            "bench_warning",
            &serde_json::json!({"message": msg}),
        );
    } else {
        eprintln!("bench: WARN: {msg}");
    }
}

fn output_error(json_output: bool, code: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let output = serde_json::json!({
            "status": "error",
            "error_code": code,
            "message": message,
        });
        println!("{}", serde_json::to_string(&output).unwrap_or_default());
    } else {
        eprintln!("bench: ERROR: [{code}] {message}");
    }
    exit_code
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash_deterministic() {
        let report = BenchReportV1 {
            schema_id: BENCH_REPORT_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            head_sha: "abc1234".to_string(),
            started_at_unix: 1000,
            total_duration_ms: 5000,
            runs: vec![GateRunMeasurement {
                label: "cold".to_string(),
                total_duration_ms: 3000,
                all_passed: true,
                phases: vec![GatePhaseTiming {
                    name: "fmt".to_string(),
                    duration_ms: 100,
                    passed: true,
                }],
            }],
            disk_footprints: vec![DiskFootprint {
                path: "target".to_string(),
                size_bytes: 1024,
                file_count: 10,
                dir_count: 3,
            }],
            deltas: HeadlineDeltas {
                cold_total_ms: 3000,
                warm_total_ms: 300,
                speedup_factor: 10.0,
                many_worktrees_target_baseline_bytes: 1024,
                target_collapse_factor: 2.0,
                target_collapse_percent: 50.0,
                warm_target_size_bytes: 1024,
                concurrent_passed: 2,
                concurrent_total: 2,
                denial_rate: 0.0,
            },
            content_hash: String::new(),
        };

        let hash1 = compute_report_content_hash(&report);
        let hash2 = compute_report_content_hash(&report);
        assert_eq!(hash1, hash2, "content hash must be deterministic");
        assert!(!hash1.is_empty(), "content hash must not be empty");
        assert_eq!(hash1.len(), 64, "SHA-256 hex must be 64 chars");
    }

    #[test]
    fn test_content_hash_changes_on_mutation() {
        let mut report = BenchReportV1 {
            schema_id: BENCH_REPORT_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            head_sha: "abc1234".to_string(),
            started_at_unix: 1000,
            total_duration_ms: 5000,
            runs: Vec::new(),
            disk_footprints: Vec::new(),
            deltas: HeadlineDeltas {
                cold_total_ms: 3000,
                warm_total_ms: 300,
                speedup_factor: 10.0,
                many_worktrees_target_baseline_bytes: 0,
                target_collapse_factor: 0.0,
                target_collapse_percent: 0.0,
                warm_target_size_bytes: 0,
                concurrent_passed: 0,
                concurrent_total: 0,
                denial_rate: 0.0,
            },
            content_hash: String::new(),
        };

        let hash1 = compute_report_content_hash(&report);
        report.head_sha = "def5678".to_string();
        let hash2 = compute_report_content_hash(&report);
        assert_ne!(
            hash1, hash2,
            "different inputs must produce different hashes"
        );
    }

    #[test]
    fn test_parse_gate_phases_jsonl() {
        let stdout = concat!(
            r#"{"event":"gate_completed","gate":"fmt","status":"pass","duration_secs":1.5,"ts":0}"#,
            "\n",
            r#"{"event":"gate_completed","gate":"clippy","status":"fail","duration_secs":3.2,"ts":0}"#,
            "\n",
        );
        let phases = parse_gate_phases(stdout);
        assert_eq!(phases.len(), 2);
        assert_eq!(phases[0].name, "fmt");
        assert!(phases[0].passed);
        assert_eq!(phases[0].duration_ms, 1500);
        assert_eq!(phases[1].name, "clippy");
        assert!(!phases[1].passed);
    }

    #[test]
    fn test_parse_gate_phases_bounded() {
        // Verify we never collect more than MAX_GATE_PHASES.
        use std::fmt::Write as _;
        let mut lines = String::new();
        for i in 0..50 {
            let _ = write!(
                lines,
                r#"{{"event":"gate_completed","gate":"gate-{i}","status":"pass","duration_secs":1,"ts":0}}"#
            );
            lines.push('\n');
        }
        let phases = parse_gate_phases(&lines);
        assert!(
            phases.len() <= MAX_GATE_PHASES,
            "phases must be bounded by MAX_GATE_PHASES"
        );
    }

    #[test]
    fn test_measure_directory_bounded() {
        // Measure a known-small directory to verify the function works.
        let temp = tempfile::tempdir().expect("create temp dir");
        let dir = temp.path();

        // Create a few files.
        for i in 0..5 {
            let file = dir.join(format!("file_{i}.txt"));
            fs::write(&file, format!("content-{i}")).expect("write test file");
        }

        let fp = measure_directory(dir);
        assert_eq!(fp.file_count, 5);
        assert!(fp.size_bytes > 0);
        assert_eq!(fp.dir_count, 0); // No subdirectories.
    }

    #[test]
    fn test_headline_deltas_no_division_by_zero() {
        // Verify that speedup_factor handles zero warm_ms gracefully.
        let warm_ms: u64 = 0;
        let cold_ms: u64 = 1000;
        let speedup = if warm_ms > 0 {
            let cold_clamped = u32::try_from(cold_ms).unwrap_or(u32::MAX);
            let warm_clamped = u32::try_from(warm_ms).unwrap_or(u32::MAX);
            f64::from(cold_clamped) / f64::from(warm_clamped)
        } else {
            0.0
        };
        assert!(
            (speedup - 0.0).abs() < f64::EPSILON,
            "speedup must be 0.0 when warm_ms is 0"
        );
    }

    #[test]
    fn test_max_concurrency_clamp() {
        let requested: u8 = 20;
        let effective = requested.max(1).min(MAX_CONCURRENCY);
        assert_eq!(effective, MAX_CONCURRENCY);

        let zero_requested: u8 = 0;
        let zero_effective = zero_requested.max(1).min(MAX_CONCURRENCY);
        assert_eq!(zero_effective, 1);
    }

    #[test]
    fn test_target_collapse_metrics() {
        let (factor, percent) = compute_target_collapse_metrics(1_000, 250);
        assert!((factor - 4.0).abs() < f64::EPSILON);
        assert!((percent - 75.0).abs() < f64::EPSILON);

        let (factor_zero, percent_zero) = compute_target_collapse_metrics(0, 100);
        assert_eq!(factor_zero, 0.0);
        assert_eq!(percent_zero, 0.0);
    }

    #[test]
    fn test_find_repo_root_from_cwd_none_if_missing() {
        // If no .git is reachable in ancestors, baseline inference should be None.
        let original = env::current_dir().expect("capture cwd");
        let tmp = tempfile::tempdir().expect("temp dir");
        assert!(env::set_current_dir(tmp.path()).is_ok());
        assert!(find_repo_root_from_cwd().is_none());
        assert!(env::set_current_dir(original).is_ok());
    }

    #[test]
    fn test_bench_report_serialization_roundtrip() {
        let report = BenchReportV1 {
            schema_id: BENCH_REPORT_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            head_sha: "abc1234".to_string(),
            started_at_unix: 1000,
            total_duration_ms: 5000,
            runs: vec![],
            disk_footprints: vec![],
            deltas: HeadlineDeltas {
                cold_total_ms: 3000,
                warm_total_ms: 300,
                speedup_factor: 10.0,
                many_worktrees_target_baseline_bytes: 0,
                target_collapse_factor: 0.0,
                target_collapse_percent: 0.0,
                warm_target_size_bytes: 0,
                concurrent_passed: 0,
                concurrent_total: 0,
                denial_rate: 0.0,
            },
            content_hash: "deadbeef".to_string(),
        };

        let json = serde_json::to_string(&report).expect("serialize");
        let deserialized: BenchReportV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.schema_id, report.schema_id);
        assert_eq!(deserialized.head_sha, report.head_sha);
        assert_eq!(deserialized.content_hash, report.content_hash);
    }

    #[test]
    fn test_secs_f64_to_millis() {
        assert_eq!(secs_f64_to_millis(1.5), 1500);
        assert_eq!(secs_f64_to_millis(0.0), 0);
        assert_eq!(secs_f64_to_millis(-1.0), 0);
        assert_eq!(secs_f64_to_millis(f64::NAN), 0);
        assert_eq!(secs_f64_to_millis(f64::INFINITY), u64::MAX);
    }

    #[test]
    fn test_millis_from_elapsed() {
        let start = Instant::now();
        // Should return 0 or a very small number.
        let ms = millis_from_elapsed(&start);
        assert!(ms < 1000, "elapsed should be less than 1 second");
    }
}
