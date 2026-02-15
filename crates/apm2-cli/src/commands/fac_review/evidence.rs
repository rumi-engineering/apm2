//! Evidence gates (fmt, clippy, doc, test, CI scripts) for FAC push pipeline.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use apm2_core::fac::{LaneProfileV1, compute_test_env};
use sha2::{Digest, Sha256};

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
use super::types::{apm2_home_dir, now_iso8601};

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
#[derive(Debug, Clone)]
pub struct EvidenceGateResult {
    pub gate_name: String,
    pub passed: bool,
    pub duration_secs: u64,
}

const SHORT_TEST_OUTPUT_HINT_THRESHOLD_BYTES: usize = 1024;
// Observability-only monotonic pulse cadence (not HTF authority time).
const MONOTONIC_HEARTBEAT_TICK_SECS: u64 = 10;
const GATE_WAIT_POLL_MILLIS: u64 = 250;
const MERGE_CONFLICT_GATE_NAME: &str = "merge_conflict_main";
const DEFAULT_TEST_PIDS_MAX: u64 = 1536;
const DEFAULT_TEST_CPU_QUOTA: &str = "200%";
const DEFAULT_TEST_KILL_AFTER_SECONDS: u64 = 20;

struct GateCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
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

fn run_gate_command_with_heartbeat(
    workspace_root: &Path,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
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

    let stdout_reader = thread::spawn(move || {
        let mut reader = stdout;
        let mut buffer = Vec::new();
        let _ = reader.read_to_end(&mut buffer);
        buffer
    });
    let stderr_reader = thread::spawn(move || {
        let mut reader = stderr;
        let mut buffer = Vec::new();
        let _ = reader.read_to_end(&mut buffer);
        buffer
    });

    let started = Instant::now();
    let heartbeat_interval = Duration::from_secs(MONOTONIC_HEARTBEAT_TICK_SECS);
    let mut next_heartbeat = heartbeat_interval;

    let status = loop {
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

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();

    Ok(GateCommandOutput {
        status,
        stdout,
        stderr,
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
        "  apm2 fac gates --memory-max 48G  # default is 48G; increase if needed"
    );
}

fn run_merge_conflict_gate(
    workspace_root: &Path,
    sha: &str,
    evidence_dir: &Path,
) -> (bool, u64, String) {
    let gate_name = MERGE_CONFLICT_GATE_NAME;
    let log_path = evidence_dir.join(format!("{gate_name}.log"));
    let started = Instant::now();

    match check_merge_conflicts_against_main(workspace_root, sha) {
        Ok(report) => {
            let duration = started.elapsed().as_secs();
            let passed = !report.has_conflicts();
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                &log_path,
                render_merge_conflict_log(&report).as_bytes(),
            );
            if !passed {
                eprintln!("{}", render_merge_conflict_summary(&report));
            }
            let status = if passed { "PASS" } else { "FAIL" };
            emit_evidence_line(sha, gate_name, status, duration, &log_path, None);
            let ts = now_iso8601();
            (
                passed,
                duration,
                format!(
                    "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
                    log_path.display()
                ),
            )
        },
        Err(err) => {
            let duration = started.elapsed().as_secs();
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                &log_path,
                format!("merge conflict gate execution error: {err}\n").as_bytes(),
            );
            emit_evidence_line(sha, gate_name, "FAIL", duration, &log_path, None);
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
) -> bool {
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
) -> bool {
    let started = Instant::now();
    let output = run_gate_command_with_heartbeat(workspace_root, gate_name, cmd, args, extra_env);
    let duration = started.elapsed().as_secs();
    match output {
        Ok(out) => {
            let combined_output_bytes = out.stdout.len() + out.stderr.len();
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!(
                    "=== stdout ===\n{}\n=== stderr ===\n{}\n",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
                .as_bytes(),
            );
            let passed = out.status.success();
            if !passed && gate_name == "test" {
                append_short_test_failure_hint(log_path, combined_output_bytes);
            }
            let status = if passed { "PASS" } else { "FAIL" };
            emit_evidence_line(sha, gate_name, status, duration, log_path, None);
            passed
        },
        Err(e) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!("execution error: {e}\n").as_bytes(),
            );
            emit_evidence_line(sha, gate_name, "FAIL", duration, log_path, None);
            false
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
    evidence_dir: &Path,
) -> (bool, String) {
    let script = workspace_root.join("scripts/ci/workspace_integrity_guard.sh");
    let snapshot = workspace_integrity_snapshot(workspace_root);
    let log_path = evidence_dir.join("workspace_integrity.log");
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
        let ts = now_iso8601();
        let line = format!(
            "ts={ts} sha={sha} gate={gate_name} status=PASS log={}",
            log_path.display()
        );
        return (true, line);
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
    let ts = now_iso8601();
    let status = if passed { "PASS" } else { "FAIL" };
    let line = format!(
        "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
        log_path.display()
    );
    (passed, line)
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
    test_env.extend(bounded_spec.setenv_pairs);

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
    let evidence_dir = apm2_home_dir()?.join("private/fac/evidence");
    // TCK-00536: create evidence directory with mode 0700 at create-time.
    crate::commands::fac_permissions::ensure_dir_with_mode(&evidence_dir)
        .map_err(|e| format!("failed to create evidence directory: {e}"))?;

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
        let (merge_passed, merge_duration, merge_line) =
            run_merge_conflict_gate(workspace_root, sha, &evidence_dir);
        gate_results.push(EvidenceGateResult {
            gate_name: MERGE_CONFLICT_GATE_NAME.to_string(),
            passed: merge_passed,
            duration_secs: merge_duration,
        });
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
            return Ok((false, gate_results));
        }
    }

    // Phase 1: cargo fmt/clippy/doc.
    for &(gate_name, cmd_args) in gates {
        let log_path = evidence_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let passed = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            cmd_args[0],
            &cmd_args[1..],
            &log_path,
        );
        let duration = started.elapsed().as_secs();
        gate_results.push(EvidenceGateResult {
            gate_name: gate_name.to_string(),
            passed,
            duration_secs: duration,
        });
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
        let log_path = evidence_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let passed = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            "bash",
            &[full_path.to_str().unwrap_or("")],
            &log_path,
        );
        let duration = started.elapsed().as_secs();
        gate_results.push(EvidenceGateResult {
            gate_name: gate_name.to_string(),
            passed,
            duration_secs: duration,
        });
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
    let test_log = evidence_dir.join("test.log");
    if skip_test_gate {
        let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
            &test_log,
            b"quick mode enabled: skipped heavyweight test gate\n",
        );
        let ts = now_iso8601();
        eprintln!(
            "ts={ts} sha={sha} gate=test status=SKIP reason=quick_mode log={}",
            test_log.display()
        );
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate=test status=SKIP reason=quick_mode log={}",
            test_log.display()
        ));
    } else {
        let test_started = Instant::now();
        let test_command =
            resolve_evidence_test_command_override(opts.and_then(|o| o.test_command.as_deref()));
        let test_env = resolve_evidence_test_command_environment(opts);
        let (test_cmd, test_args) = test_command
            .split_first()
            .ok_or_else(|| "test command is empty".to_string())?;
        let passed = run_single_evidence_gate_with_env(
            workspace_root,
            sha,
            "test",
            test_cmd,
            &test_args.iter().map(String::as_str).collect::<Vec<_>>(),
            &test_log,
            test_env,
        );
        let test_duration = test_started.elapsed().as_secs();
        gate_results.push(EvidenceGateResult {
            gate_name: "test".to_string(),
            passed,
            duration_secs: test_duration,
        });
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
    let (wi_passed, wi_line) = verify_workspace_integrity_gate(workspace_root, sha, &evidence_dir);
    let wi_duration = wi_started.elapsed().as_secs();
    gate_results.push(EvidenceGateResult {
        gate_name: "workspace_integrity".to_string(),
        passed: wi_passed,
        duration_secs: wi_duration,
    });
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
        let log_path = evidence_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let passed = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            "bash",
            &[full_path.to_str().unwrap_or("")],
            &log_path,
        );
        let duration = started.elapsed().as_secs();
        gate_results.push(EvidenceGateResult {
            gate_name: gate_name.to_string(),
            passed,
            duration_secs: duration,
        });
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
    let evidence_dir = apm2_home_dir()?.join("private/fac/evidence");
    // TCK-00536: create evidence directory with mode 0700 at create-time.
    crate::commands::fac_permissions::ensure_dir_with_mode(&evidence_dir)
        .map_err(|e| format!("failed to create evidence directory: {e}"))?;

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

        let (passed, duration, line) = run_merge_conflict_gate(workspace_root, sha, &evidence_dir);
        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        gate_results.push(EvidenceGateResult {
            gate_name: gate_name.to_string(),
            passed,
            duration_secs: duration,
        });
        evidence_lines.push(line);
        let merge_log = evidence_dir.join(format!("{gate_name}.log"));
        let merge_digest = sha256_file_hex(&merge_log);
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
            let _ = gate_cache.save();
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            return Ok((false, gate_results));
        }
    }

    // Phase 1: cargo fmt/clippy/doc.
    for &(gate_name, cmd_args) in gates {
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                eprintln!(
                    "ts={} sha={} gate={} reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
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
                gate_results.push(EvidenceGateResult {
                    gate_name: gate_name.to_string(),
                    passed: true,
                    duration_secs: cached.duration_secs,
                });
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest,
                    false,
                    cached.evidence_log_digest.clone(),
                );
                continue;
            }
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

        let log_path = evidence_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let passed = run_single_evidence_gate(
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
        gate_results.push(EvidenceGateResult {
            gate_name: gate_name.to_string(),
            passed,
            duration_secs: duration,
        });
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

    // Phase 2: pre-test script gates.
    for &(gate_name, script_path) in pre_test_script_gates {
        let full_path = workspace_root.join(script_path);
        if !full_path.exists() {
            continue;
        }

        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                eprintln!(
                    "ts={} sha={} gate={} reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
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
                gate_results.push(EvidenceGateResult {
                    gate_name: gate_name.to_string(),
                    passed: true,
                    duration_secs: cached.duration_secs,
                });
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest,
                    false,
                    cached.evidence_log_digest.clone(),
                );
                continue;
            }
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

        let log_path = evidence_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let passed = run_single_evidence_gate(
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
        gate_results.push(EvidenceGateResult {
            gate_name: gate_name.to_string(),
            passed,
            duration_secs: duration,
        });
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
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
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
                gate_results.push(EvidenceGateResult {
                    gate_name: gate_name.to_string(),
                    passed: true,
                    duration_secs: cached.duration_secs,
                });
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest,
                    false,
                    cached.evidence_log_digest.clone(),
                );
            } else {
                eprintln!(
                    "ts={} sha={} gate={} reuse_status=miss reuse_reason=inconsistent_cache_entry",
                    now_iso8601(),
                    sha,
                    gate_name
                );
                status.set_result(gate_name, false, 0);
                updater.update(&status);
                gate_results.push(EvidenceGateResult {
                    gate_name: gate_name.to_string(),
                    passed: false,
                    duration_secs: 0,
                });
                all_passed = false;
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                    now_iso8601(),
                    sha,
                    gate_name,
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
            status.set_running(gate_name);
            updater.update(&status);

            let log_path = evidence_dir.join("test.log");
            let started = Instant::now();
            let (test_cmd, test_args) = pipeline_test_command
                .command
                .split_first()
                .ok_or_else(|| "pipeline test command is empty".to_string())?;
            let passed = run_single_evidence_gate_with_env(
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
            gate_results.push(EvidenceGateResult {
                gate_name: gate_name.to_string(),
                passed,
                duration_secs: duration,
            });
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
                reuse.reason
            ));
        }
    }

    {
        let gate_name = "workspace_integrity";
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
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
                gate_results.push(EvidenceGateResult {
                    gate_name: gate_name.to_string(),
                    passed: true,
                    duration_secs: cached.duration_secs,
                });
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest,
                    false,
                    cached.evidence_log_digest.clone(),
                );
            }
        } else {
            status.set_running(gate_name);
            updater.update(&status);

            let started = Instant::now();
            let (passed, line) =
                verify_workspace_integrity_gate(workspace_root, sha, &evidence_dir);
            let duration = started.elapsed().as_secs();

            status.set_result(gate_name, passed, duration);
            updater.update(&status);
            let log_path = evidence_dir.join("workspace_integrity.log");
            gate_results.push(EvidenceGateResult {
                gate_name: gate_name.to_string(),
                passed,
                duration_secs: duration,
            });
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

        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let reuse =
            reuse_decision_for_gate(cache.as_ref(), gate_name, attestation_digest.as_deref());
        if reuse.reusable {
            if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
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
                gate_results.push(EvidenceGateResult {
                    gate_name: gate_name.to_string(),
                    passed: true,
                    duration_secs: cached.duration_secs,
                });
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest,
                    false,
                    cached.evidence_log_digest.clone(),
                );
                continue;
            }
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

        let log_path = evidence_dir.join(format!("{gate_name}.log"));
        let started = Instant::now();
        let passed = run_single_evidence_gate(
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
        gate_results.push(EvidenceGateResult {
            gate_name: gate_name.to_string(),
            passed,
            duration_secs: duration,
        });
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
