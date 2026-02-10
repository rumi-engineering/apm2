//! Evidence gates (fmt, clippy, doc, test, CI scripts) for FAC push pipeline.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use super::ci_status::{CiStatus, ThrottledUpdater};
use super::gate_cache::GateCache;
use super::types::{apm2_home_dir, now_iso8601};

/// Options for customizing evidence gate execution.
pub struct EvidenceGateOptions {
    /// Override command for the test phase. When `Some`, the test gate uses
    /// this command instead of `cargo test --workspace`.
    pub test_command: Option<Vec<String>>,
}

/// Result of a single evidence gate execution.
#[derive(Debug, Clone)]
pub struct EvidenceGateResult {
    pub gate_name: String,
    pub passed: bool,
    pub duration_secs: u64,
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

/// Run a single evidence gate and emit the result.
pub fn run_single_evidence_gate(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
) -> bool {
    let started = Instant::now();
    let log_file = match File::create(log_path) {
        Ok(f) => f,
        Err(e) => {
            let duration = started.elapsed().as_secs();
            eprintln!("failed to create log file {}: {e}", log_path.display());
            emit_evidence_line(sha, gate_name, "FAIL", duration, log_path, None);
            return false;
        },
    };
    let stderr_file = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            let duration = started.elapsed().as_secs();
            let _ = fs::write(log_path, format!("failed to clone log handle: {e}\n"));
            emit_evidence_line(sha, gate_name, "FAIL", duration, log_path, None);
            return false;
        },
    };
    let result = Command::new(cmd)
        .args(args)
        .current_dir(workspace_root)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_file))
        .status();
    let duration = started.elapsed().as_secs();
    match result {
        Ok(exit_status) => {
            let passed = exit_status.success();
            let status = if passed { "PASS" } else { "FAIL" };
            emit_evidence_line(sha, gate_name, status, duration, log_path, None);
            passed
        },
        Err(e) => {
            let _ = fs::write(log_path, format!("execution error: {e}\n"));
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
        let _ = fs::write(&log_path, format!("{msg}\n"));
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

/// Run evidence gates (cargo fmt check, clippy, doc, test, CI scripts).
/// Returns `Ok((all_passed, per_gate_results))`.
/// Fail-closed: any error running a gate counts as failure.
///
/// When `opts` is provided, `test_command` overrides the default
/// `cargo test --workspace` invocation (e.g., to use a bounded runner).
pub fn run_evidence_gates(
    workspace_root: &Path,
    sha: &str,
    projection_log: Option<&mut File>,
    opts: Option<&EvidenceGateOptions>,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let evidence_dir = apm2_home_dir()?.join("private/fac/evidence");
    fs::create_dir_all(&evidence_dir)
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

    // Script gates that run AFTER tests.
    let post_test_script_gates: &[(&str, &str)] =
        &[("review_artifact_lint", "scripts/ci/review_artifact_lint.sh")];

    let mut all_passed = true;
    let mut evidence_lines = Vec::new();
    let mut gate_results = Vec::new();

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

    // Phase 3: workspace integrity snapshot → test → verify.
    snapshot_workspace_integrity(workspace_root);

    let test_log = evidence_dir.join("test.log");
    let test_started = Instant::now();
    let test_passed = opts.and_then(|o| o.test_command.as_ref()).map_or_else(
        || {
            run_single_evidence_gate(
                workspace_root,
                sha,
                "test",
                "cargo",
                &["test", "--workspace"],
                &test_log,
            )
        },
        |cmd| {
            run_single_evidence_gate(
                workspace_root,
                sha,
                "test",
                &cmd[0],
                &cmd[1..].iter().map(String::as_str).collect::<Vec<_>>(),
                &test_log,
            )
        },
    );
    let test_duration = test_started.elapsed().as_secs();
    gate_results.push(EvidenceGateResult {
        gate_name: "test".to_string(),
        passed: test_passed,
        duration_secs: test_duration,
    });
    if !test_passed {
        all_passed = false;
    }
    let ts = now_iso8601();
    let status = if test_passed { "PASS" } else { "FAIL" };
    evidence_lines.push(format!(
        "ts={ts} sha={sha} gate=test status={status} log={}",
        test_log.display()
    ));

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
) -> Result<bool, String> {
    let evidence_dir = apm2_home_dir()?.join("private/fac/evidence");
    fs::create_dir_all(&evidence_dir)
        .map_err(|e| format!("failed to create evidence directory: {e}"))?;

    let mut status = CiStatus::new(sha, pr_number);
    let updater = ThrottledUpdater::new(owner_repo, pr_number);

    // Load gate cache for this SHA (populated by `fac gates`).
    let cache = GateCache::load(sha);
    let mut gate_cache = GateCache::new(sha);

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

    let post_test_script_gates: &[(&str, &str)] =
        &[("review_artifact_lint", "scripts/ci/review_artifact_lint.sh")];

    let mut all_passed = true;
    let mut evidence_lines = Vec::new();

    // Phase 1: cargo fmt/clippy/doc.
    for &(gate_name, cmd_args) in gates {
        // Check cache: skip if already passed for this SHA.
        if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
            if cached.status == "PASS" {
                eprintln!(
                    "cache-hit: {gate_name} PASS (cached, {:.0}s)",
                    cached.duration_secs
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let ts = now_iso8601();
                evidence_lines.push(format!(
                    "ts={ts} sha={sha} gate={gate_name} status=PASS cached=true"
                ));
                gate_cache.set(gate_name, true, cached.duration_secs);
                continue;
            }
        }

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
        gate_cache.set(gate_name, passed, duration);

        if !passed {
            all_passed = false;
        }
        let ts = now_iso8601();
        let gate_status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={gate_status} log={}",
            log_path.display()
        ));
    }

    // Phase 2: pre-test script gates.
    for &(gate_name, script_path) in pre_test_script_gates {
        let full_path = workspace_root.join(script_path);
        if !full_path.exists() {
            continue;
        }

        if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
            if cached.status == "PASS" {
                eprintln!(
                    "cache-hit: {gate_name} PASS (cached, {:.0}s)",
                    cached.duration_secs
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let ts = now_iso8601();
                evidence_lines.push(format!(
                    "ts={ts} sha={sha} gate={gate_name} status=PASS cached=true"
                ));
                gate_cache.set(gate_name, true, cached.duration_secs);
                continue;
            }
        }

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
        gate_cache.set(gate_name, passed, duration);

        if !passed {
            all_passed = false;
        }
        let ts = now_iso8601();
        let gate_status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={gate_status} log={}",
            log_path.display()
        ));
    }

    // Phase 3: workspace integrity snapshot → cargo test → verify.
    snapshot_workspace_integrity(workspace_root);

    {
        let gate_name = "test";
        if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
            if cached.status == "PASS" {
                eprintln!(
                    "cache-hit: {gate_name} PASS (cached, {:.0}s)",
                    cached.duration_secs
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let ts = now_iso8601();
                evidence_lines.push(format!(
                    "ts={ts} sha={sha} gate={gate_name} status=PASS cached=true"
                ));
                gate_cache.set(gate_name, true, cached.duration_secs);
            } else {
                status.set_running(gate_name);
                updater.update(&status);

                let log_path = evidence_dir.join("test.log");
                let started = Instant::now();
                let passed = run_single_evidence_gate(
                    workspace_root,
                    sha,
                    gate_name,
                    "cargo",
                    &["test", "--workspace"],
                    &log_path,
                );
                let duration = started.elapsed().as_secs();

                status.set_result(gate_name, passed, duration);
                updater.update(&status);
                gate_cache.set(gate_name, passed, duration);

                if !passed {
                    all_passed = false;
                }
                let ts = now_iso8601();
                let gate_status = if passed { "PASS" } else { "FAIL" };
                evidence_lines.push(format!(
                    "ts={ts} sha={sha} gate={gate_name} status={gate_status} log={}",
                    log_path.display()
                ));
            }
        } else {
            status.set_running(gate_name);
            updater.update(&status);

            let log_path = evidence_dir.join("test.log");
            let started = Instant::now();
            let passed = run_single_evidence_gate(
                workspace_root,
                sha,
                gate_name,
                "cargo",
                &["test", "--workspace"],
                &log_path,
            );
            let duration = started.elapsed().as_secs();

            status.set_result(gate_name, passed, duration);
            updater.update(&status);
            gate_cache.set(gate_name, passed, duration);

            if !passed {
                all_passed = false;
            }
            let ts = now_iso8601();
            let gate_status = if passed { "PASS" } else { "FAIL" };
            evidence_lines.push(format!(
                "ts={ts} sha={sha} gate={gate_name} status={gate_status} log={}",
                log_path.display()
            ));
        }
    }

    {
        let gate_name = "workspace_integrity";
        if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
            if cached.status == "PASS" {
                eprintln!(
                    "cache-hit: {gate_name} PASS (cached, {:.0}s)",
                    cached.duration_secs
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let ts = now_iso8601();
                evidence_lines.push(format!(
                    "ts={ts} sha={sha} gate={gate_name} status=PASS cached=true"
                ));
                gate_cache.set(gate_name, true, cached.duration_secs);
            } else {
                status.set_running(gate_name);
                updater.update(&status);

                let started = Instant::now();
                let (passed, line) =
                    verify_workspace_integrity_gate(workspace_root, sha, &evidence_dir);
                let duration = started.elapsed().as_secs();

                status.set_result(gate_name, passed, duration);
                updater.update(&status);
                gate_cache.set(gate_name, passed, duration);

                if !passed {
                    all_passed = false;
                }
                evidence_lines.push(line);
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
            gate_cache.set(gate_name, passed, duration);

            if !passed {
                all_passed = false;
            }
            evidence_lines.push(line);
        }
    }

    // Phase 4: post-test script gates.
    for &(gate_name, script_path) in post_test_script_gates {
        let full_path = workspace_root.join(script_path);
        if !full_path.exists() {
            continue;
        }

        if let Some(cached) = cache.as_ref().and_then(|c| c.get(gate_name)) {
            if cached.status == "PASS" {
                eprintln!(
                    "cache-hit: {gate_name} PASS (cached, {:.0}s)",
                    cached.duration_secs
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let ts = now_iso8601();
                evidence_lines.push(format!(
                    "ts={ts} sha={sha} gate={gate_name} status=PASS cached=true"
                ));
                gate_cache.set(gate_name, true, cached.duration_secs);
                continue;
            }
        }

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
        gate_cache.set(gate_name, passed, duration);

        if !passed {
            all_passed = false;
        }
        let ts = now_iso8601();
        let gate_status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={gate_status} log={}",
            log_path.display()
        ));
    }

    // Force a final update to ensure all gate results are posted.
    updater.force_update(&status);

    // Persist gate cache so future pipeline runs can reuse results.
    if let Err(e) = gate_cache.save() {
        eprintln!("WARNING: gate cache save failed: {e}");
    }

    if let Some(file) = projection_log {
        for line in &evidence_lines {
            let _ = writeln!(file, "{line}");
        }
    }

    Ok(all_passed)
}
