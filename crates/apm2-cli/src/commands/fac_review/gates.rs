//! `apm2 fac gates` — unified local evidence gates with bounded test execution.
//!
//! Runs all evidence gates locally, caches results per-SHA so the background
//! pipeline can skip already-validated gates.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use apm2_core::fac::{LaneProfileV1, compute_test_env};
use apm2_daemon::telemetry::is_cgroup_v2_available;
use sha2::{Digest, Sha256};

use super::evidence::{EvidenceGateOptions, run_evidence_gates};
use super::gate_attestation::{
    GateResourcePolicy, build_nextest_command, compute_gate_attestation,
    gate_command_for_attestation,
};
use super::gate_cache::GateCache;
use super::merge_conflicts::{check_merge_conflicts_against_main, render_merge_conflict_summary};
use super::timeout_policy::{
    MAX_MANUAL_TIMEOUT_SECONDS, TEST_TIMEOUT_SLA_MESSAGE, max_memory_bytes, parse_memory_limit,
    resolve_bounded_test_timeout,
};
use super::types::apm2_home_dir;
use crate::exit_codes::codes as exit_codes;

const HTF_TEST_HEARTBEAT_SECONDS: u64 = 10;

/// Run all evidence gates locally with optional bounded test execution.
///
/// 1. Requires clean working tree for full mode (`--quick` bypasses this)
/// 2. Resolves HEAD SHA
/// 3. Runs merge-conflict gate first (always recomputed)
/// 4. Runs evidence gates (with bounded test runner if available)
/// 5. Writes attested gate cache receipts for full runs
/// 6. Prints summary table
pub fn run_gates(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    json_output: bool,
) -> u8 {
    match run_gates_inner(
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
    ) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Gates");
                println!("  SHA:     {}", summary.sha);
                println!(
                    "  Verdict: {}",
                    if summary.passed { "PASS" } else { "FAIL" }
                );
                println!("  Bounded: {}", summary.bounded);
                println!(
                    "  Mode:    {}",
                    if summary.quick { "quick" } else { "full" }
                );
                println!("  Timeout: {}s", summary.effective_timeout_seconds);
                println!("  Cache:   {}", summary.cache_status);
                println!();
                println!("  {:<25} {:<6} {:>8}", "Gate", "Status", "Duration");
                println!("  {}", "-".repeat(43));
                for gate in &summary.gates {
                    println!(
                        "  {:<25} {:<6} {:>7}s",
                        gate.name, gate.status, gate.duration_secs
                    );
                }
                println!();
                if summary.quick {
                    println!("  Cache: not written in quick mode");
                } else {
                    println!(
                        "  Cache: ~/.apm2/private/fac/gate_cache_v2/{}/",
                        &summary.sha
                    );
                }
            }
            if summary.passed {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_gates_failed",
                    "message": err,
                });
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[derive(Debug, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct GatesSummary {
    sha: String,
    passed: bool,
    bounded: bool,
    quick: bool,
    requested_timeout_seconds: u64,
    effective_timeout_seconds: u64,
    cache_status: String,
    gates: Vec<GateResult>,
}

#[derive(Debug, serde::Serialize)]
struct GateResult {
    name: String,
    status: String,
    duration_secs: u64,
}

fn run_gates_inner(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
) -> Result<GatesSummary, String> {
    validate_timeout_seconds(timeout_seconds)?;
    let memory_max_bytes = parse_memory_limit(memory_max)?;
    if memory_max_bytes > max_memory_bytes() {
        return Err(format!(
            "--memory-max {memory_max} exceeds FAC test memory cap of {max_bytes}",
            max_bytes = max_memory_bytes()
        ));
    }

    let workspace_root =
        std::env::current_dir().map_err(|e| format!("failed to resolve cwd: {e}"))?;
    let timeout_decision = resolve_bounded_test_timeout(&workspace_root, timeout_seconds);

    // 1. Require clean working tree for full gates only.
    ensure_clean_working_tree(&workspace_root, quick)?;

    // 2. Resolve HEAD SHA.
    let sha_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&workspace_root)
        .output()
        .map_err(|e| format!("failed to run git rev-parse HEAD: {e}"))?;
    if !sha_output.status.success() {
        return Err("git rev-parse HEAD failed".to_string());
    }
    let sha = String::from_utf8_lossy(&sha_output.stdout)
        .trim()
        .to_string();
    if sha.len() < 7 {
        return Err(format!("unexpected short SHA: {sha}"));
    }

    // 3. Merge-conflict gate always runs first and is never cache-reused.
    let merge_gate = evaluate_merge_conflict_gate(&workspace_root, &sha)?;
    if merge_gate.status == "FAIL" {
        return Ok(GatesSummary {
            sha,
            passed: false,
            bounded: false,
            quick,
            requested_timeout_seconds: timeout_seconds,
            effective_timeout_seconds: timeout_decision.effective_seconds,
            cache_status: "disabled (merge conflicts)".to_string(),
            gates: vec![merge_gate],
        });
    }

    // 4. Build test command override for test execution.
    let bounded_script = workspace_root.join("scripts/ci/run_bounded_tests.sh");
    let cgroup_available = is_cgroup_v2_available();
    let bounded = bounded_script.is_file() && cgroup_available;
    let default_nextest_command = build_nextest_command();
    let test_command_environment = compute_nextest_test_environment()?;

    let test_command = if quick {
        None
    } else if bounded {
        Some(build_bounded_test_command(
            &bounded_script,
            timeout_decision.effective_seconds,
            memory_max,
            pids_max,
            cpu_quota,
            &default_nextest_command,
        ))
    } else {
        Some(default_nextest_command)
    };

    let opts = EvidenceGateOptions {
        test_command,
        test_command_environment,
        skip_test_gate: quick,
        skip_merge_conflict_gate: true,
    };

    // 5. Run evidence gates.
    let started = Instant::now();
    let (passed, gate_results) = run_evidence_gates(&workspace_root, &sha, None, Some(&opts))?;
    let total_secs = started.elapsed().as_secs();

    // 6. Write attested results to gate cache for full runs only.
    if !quick {
        let policy = GateResourcePolicy::from_cli(
            quick,
            timeout_decision.effective_seconds,
            memory_max,
            pids_max,
            cpu_quota,
            bounded,
        );
        let mut cache = GateCache::new(&sha);
        for result in &gate_results {
            let command = gate_command_for_attestation(
                &workspace_root,
                &result.gate_name,
                opts.test_command.as_deref(),
            );
            let attestation_digest = command.and_then(|cmd| {
                compute_gate_attestation(&workspace_root, &sha, &result.gate_name, &cmd, &policy)
                    .ok()
                    .map(|attestation| attestation.attestation_digest)
            });
            let evidence_log_digest = gate_log_digest(&result.gate_name);
            cache.set_with_attestation(
                &result.gate_name,
                result.passed,
                result.duration_secs,
                attestation_digest,
                quick,
                evidence_log_digest,
            );
        }
        cache.save()?;
    }

    let mut gates = vec![merge_gate];
    let mut evidence_gates: Vec<GateResult> = gate_results
        .iter()
        .map(|r| GateResult {
            name: r.gate_name.clone(),
            status: if r.passed { "PASS" } else { "FAIL" }.to_string(),
            duration_secs: r.duration_secs,
        })
        .collect();
    gates.append(&mut evidence_gates);
    if quick {
        // Keep test visible in summary even when skipped for inner-loop runs.
        let insert_index = gates
            .iter()
            .position(|gate| gate.name == "workspace_integrity")
            .unwrap_or(gates.len());
        gates.insert(
            insert_index,
            GateResult {
                name: "test".to_string(),
                status: "SKIP".to_string(),
                duration_secs: 0,
            },
        );
    }

    eprintln!(
        "fac gates (mode={}): completed in {total_secs}s — {}",
        if quick { "quick" } else { "full" },
        if passed { "PASS" } else { "FAIL" }
    );

    Ok(GatesSummary {
        sha,
        passed,
        bounded,
        quick,
        requested_timeout_seconds: timeout_seconds,
        effective_timeout_seconds: timeout_decision.effective_seconds,
        cache_status: if quick {
            "disabled (quick mode)".to_string()
        } else if force {
            "bypass (--force)".to_string()
        } else {
            "write-through".to_string()
        },
        gates,
    })
}

fn gate_log_digest(gate_name: &str) -> Option<String> {
    let path = apm2_home_dir()
        .ok()?
        .join("private/fac/evidence")
        .join(format!("{gate_name}.log"));

    if !path.exists() {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

fn validate_timeout_seconds(timeout_seconds: u64) -> Result<(), String> {
    if timeout_seconds == 0 {
        return Err(format!(
            "--timeout-seconds must be greater than zero (max {MAX_MANUAL_TIMEOUT_SECONDS}). {TEST_TIMEOUT_SLA_MESSAGE}"
        ));
    }
    if timeout_seconds > MAX_MANUAL_TIMEOUT_SECONDS {
        return Err(format!(
            "--timeout-seconds cannot exceed {MAX_MANUAL_TIMEOUT_SECONDS}. {TEST_TIMEOUT_SLA_MESSAGE}"
        ));
    }
    Ok(())
}

fn evaluate_merge_conflict_gate(workspace_root: &Path, sha: &str) -> Result<GateResult, String> {
    let started = Instant::now();
    let report = check_merge_conflicts_against_main(workspace_root, sha)?;
    let duration = started.elapsed().as_secs();
    let passed = !report.has_conflicts();
    if !passed {
        eprintln!("{}", render_merge_conflict_summary(&report));
    }
    Ok(GateResult {
        name: "merge_conflict_main".to_string(),
        status: if passed { "PASS" } else { "FAIL" }.to_string(),
        duration_secs: duration,
    })
}

/// Build the bounded test runner command, mirroring the old `fac check`
/// pattern.
fn build_bounded_test_command(
    bounded_script: &Path,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    nextest_command: &[String],
) -> Vec<String> {
    let mut command = vec![
        bounded_script.display().to_string(),
        "--timeout-seconds".to_string(),
        timeout_seconds.to_string(),
        "--kill-after-seconds".to_string(),
        "20".to_string(),
        "--heartbeat-seconds".to_string(),
        HTF_TEST_HEARTBEAT_SECONDS.to_string(),
        "--memory-max".to_string(),
        memory_max.to_string(),
        "--pids-max".to_string(),
        pids_max.to_string(),
        "--cpu-quota".to_string(),
        cpu_quota.to_string(),
        "--".to_string(),
    ];
    command.extend(nextest_command.iter().cloned());
    command
}

fn compute_nextest_test_environment() -> Result<Vec<(String, String)>, String> {
    let profile = LaneProfileV1::new("lane-00", "b3-256:fac-gates", "boundary-00")
        .map_err(|err| format!("failed to construct FAC gate lane profile: {err}"))?;
    Ok(compute_test_env(&profile))
}

fn ensure_clean_working_tree(workspace_root: &Path, quick: bool) -> Result<(), String> {
    if quick {
        return Ok(());
    }

    let diff_status = Command::new("git")
        .args(["diff", "--exit-code"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git diff: {e}"))?;
    if !diff_status.status.success() {
        return Err(
            "DIRTY TREE: working tree has unstaged changes. ALL changes must be committed before \
             running full gates — build artifacts are SHA-attested and reused as a source of truth. \
             Run `git add -A && git commit` first, or use `apm2 fac gates --quick` for inner-loop development."
                .to_string(),
        );
    }

    let cached_status = Command::new("git")
        .args(["diff", "--cached", "--exit-code"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git diff --cached: {e}"))?;
    if !cached_status.status.success() {
        return Err(
            "DIRTY TREE: working tree has staged but uncommitted changes. ALL changes must be \
             committed before running full gates — build artifacts are SHA-attested and reused \
             as a source of truth. Run `git commit` first, or use `apm2 fac gates --quick` for \
             inner-loop development."
                .to_string(),
        );
    }

    let untracked = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git ls-files --others --exclude-standard: {e}"))?;
    if !untracked.status.success() {
        return Err("failed to evaluate untracked files for clean-tree check".to_string());
    }
    if !String::from_utf8_lossy(&untracked.stdout).trim().is_empty() {
        return Err(
            "DIRTY TREE: working tree has untracked files. ALL files must be committed (or \
             .gitignored) before running full gates — build artifacts are SHA-attested and \
             reused as a source of truth. Run `git add -A && git commit` first, or use \
             `apm2 fac gates --quick` for inner-loop development."
                .to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    #[test]
    fn ensure_clean_working_tree_skips_checks_in_quick_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let result = ensure_clean_working_tree(temp_dir.path(), true);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_clean_working_tree_rejects_unstaged_changes_in_full_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo = temp_dir.path();

        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);

        fs::write(repo.join("sample.txt"), "v1\n").expect("write file");
        run_git(repo, &["add", "sample.txt"]);
        run_git(repo, &["commit", "-m", "init"]);

        fs::write(repo.join("sample.txt"), "v2\n").expect("modify file");

        let err = ensure_clean_working_tree(repo, false).expect_err("dirty tree should fail");
        assert!(err.contains("working tree has unstaged changes"));
    }

    #[test]
    fn ensure_clean_working_tree_rejects_untracked_changes_in_full_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo = temp_dir.path();

        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);

        fs::write(repo.join("tracked.txt"), "v1\n").expect("write tracked file");
        run_git(repo, &["add", "tracked.txt"]);
        run_git(repo, &["commit", "-m", "init"]);

        fs::write(repo.join("untracked.txt"), "new\n").expect("write untracked file");

        let err = ensure_clean_working_tree(repo, false).expect_err("untracked tree should fail");
        assert!(err.contains("working tree has untracked files"));
    }

    #[test]
    fn bounded_test_command_uses_nextest() {
        let command = build_bounded_test_command(
            Path::new("/tmp/run_bounded_tests.sh"),
            120,
            "24G",
            1536,
            "200%",
            &build_nextest_command(),
        );
        let joined = command.join(" ");
        assert!(joined.contains("cargo nextest run --workspace"));
        assert!(!joined.contains("cargo test --workspace"));
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git command should execute");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
