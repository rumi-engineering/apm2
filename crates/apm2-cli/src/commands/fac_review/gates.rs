//! `apm2 fac gates` — unified local evidence gates with bounded test execution.
//!
//! Runs all evidence gates locally, caches results per-SHA so the background
//! pipeline can skip already-validated gates.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use apm2_daemon::telemetry::is_cgroup_v2_available;

use super::evidence::{EvidenceGateOptions, run_evidence_gates};
use super::gate_cache::GateCache;
use crate::exit_codes::codes as exit_codes;

/// Run all evidence gates locally with optional bounded test execution.
///
/// 1. Requires clean working tree
/// 2. Resolves HEAD SHA
/// 3. Checks gate cache (unless `--force`)
/// 4. Runs evidence gates (with bounded test runner if available)
/// 5. Writes results to gate cache
/// 6. Prints summary table
pub fn run_gates(
    force: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    json_output: bool,
) -> u8 {
    match run_gates_inner(force, timeout_seconds, memory_max, pids_max, cpu_quota) {
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
                println!(
                    "  Cache: ~/.apm2/private/fac/gate_cache/{}.yaml",
                    &summary.sha[..std::cmp::min(12, summary.sha.len())]
                );
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
struct GatesSummary {
    sha: String,
    passed: bool,
    bounded: bool,
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
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
) -> Result<GatesSummary, String> {
    // 1. Require clean working tree.
    let diff_status = Command::new("git")
        .args(["diff", "--exit-code"])
        .output()
        .map_err(|e| format!("failed to run git diff: {e}"))?;
    if !diff_status.status.success() {
        return Err("working tree has unstaged changes — commit or stash first".to_string());
    }
    let cached_status = Command::new("git")
        .args(["diff", "--cached", "--exit-code"])
        .output()
        .map_err(|e| format!("failed to run git diff --cached: {e}"))?;
    if !cached_status.status.success() {
        return Err("working tree has staged changes — commit or stash first".to_string());
    }

    // 2. Resolve HEAD SHA.
    let sha_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
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

    // 3. Check gate cache (unless --force).
    if !force {
        if let Some(cached) = GateCache::load(&sha) {
            if cached.all_passed() {
                eprintln!("all gates cached as PASS for {sha} — use --force to re-run");
                let gates = cached
                    .gates
                    .iter()
                    .map(|(name, result)| GateResult {
                        name: name.clone(),
                        status: result.status.clone(),
                        duration_secs: result.duration_secs,
                    })
                    .collect();
                return Ok(GatesSummary {
                    sha,
                    passed: true,
                    bounded: false,
                    gates,
                });
            }
        }
    }

    // 4. Build test command override for bounded execution.
    let workspace_root =
        std::env::current_dir().map_err(|e| format!("failed to resolve cwd: {e}"))?;

    let bounded_script = workspace_root.join("scripts/ci/run_bounded_tests.sh");
    let cgroup_available = is_cgroup_v2_available();
    let bounded = bounded_script.is_file() && cgroup_available;

    let test_command = if bounded {
        Some(build_bounded_test_command(
            &bounded_script,
            timeout_seconds,
            memory_max,
            pids_max,
            cpu_quota,
        ))
    } else {
        None
    };

    let opts = EvidenceGateOptions { test_command };

    // 5. Run evidence gates.
    let started = Instant::now();
    let (passed, gate_results) = run_evidence_gates(&workspace_root, &sha, None, Some(&opts))?;
    let total_secs = started.elapsed().as_secs();

    // 6. Write results to gate cache.
    let mut cache = GateCache::new(&sha);
    for result in &gate_results {
        cache.set(&result.gate_name, result.passed, result.duration_secs);
    }
    cache.save()?;

    let gates = gate_results
        .iter()
        .map(|r| GateResult {
            name: r.gate_name.clone(),
            status: if r.passed { "PASS" } else { "FAIL" }.to_string(),
            duration_secs: r.duration_secs,
        })
        .collect();

    eprintln!(
        "fac gates: completed in {total_secs}s — {}",
        if passed { "PASS" } else { "FAIL" }
    );

    Ok(GatesSummary {
        sha,
        passed,
        bounded,
        gates,
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
) -> Vec<String> {
    vec![
        bounded_script.display().to_string(),
        "--timeout-seconds".to_string(),
        timeout_seconds.to_string(),
        "--kill-after-seconds".to_string(),
        "20".to_string(),
        "--memory-max".to_string(),
        memory_max.to_string(),
        "--pids-max".to_string(),
        pids_max.to_string(),
        "--cpu-quota".to_string(),
        cpu_quota.to_string(),
        "--".to_string(),
        "cargo".to_string(),
        "nextest".to_string(),
        "run".to_string(),
        "--workspace".to_string(),
        "--all-features".to_string(),
        "--config-file".to_string(),
        ".config/nextest.toml".to_string(),
        "--profile".to_string(),
        "ci".to_string(),
    ]
}
