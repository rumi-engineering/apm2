//! Evidence gates (fmt, clippy, doc, test, CI scripts) for FAC push pipeline.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use super::types::{apm2_home_dir, now_iso8601};

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
    let output = Command::new(cmd)
        .args(args)
        .current_dir(workspace_root)
        .output();
    let duration = started.elapsed().as_secs();
    match output {
        Ok(out) => {
            let _ = fs::write(
                log_path,
                format!(
                    "=== stdout ===\n{}\n=== stderr ===\n{}\n",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
            );
            let passed = out.status.success();
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

/// Run evidence gates (cargo fmt check, clippy, doc, test, CI scripts).
/// Returns `Ok(true)` if all gates passed, `Ok(false)` if any failed.
/// Fail-closed: any error running a gate counts as failure.
pub fn run_evidence_gates(
    workspace_root: &Path,
    sha: &str,
    projection_log: Option<&mut File>,
) -> Result<bool, String> {
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
        ("test", &["cargo", "test", "--workspace"]),
    ];

    let script_gates: &[(&str, &str)] = &[
        ("test_safety_guard", "scripts/ci/test_safety_guard.sh"),
        (
            "workspace_integrity",
            "scripts/ci/workspace_integrity_guard.sh",
        ),
        ("review_artifact_lint", "scripts/ci/review_artifact_lint.sh"),
    ];

    let mut all_passed = true;
    let mut evidence_lines = Vec::new();

    for &(gate_name, cmd_args) in gates {
        let log_path = evidence_dir.join(format!("{gate_name}.log"));
        let passed = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            cmd_args[0],
            &cmd_args[1..],
            &log_path,
        );
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

    for &(gate_name, script_path) in script_gates {
        let full_path = workspace_root.join(script_path);
        if !full_path.exists() {
            continue;
        }
        let log_path = evidence_dir.join(format!("{gate_name}.log"));
        let passed = run_single_evidence_gate(
            workspace_root,
            sha,
            gate_name,
            "bash",
            &[full_path.to_str().unwrap_or("")],
            &log_path,
        );
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

    Ok(all_passed)
}
