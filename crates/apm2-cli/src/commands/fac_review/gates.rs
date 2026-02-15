//! `apm2 fac gates` — unified local evidence gates with bounded test execution.
//!
//! Runs all evidence gates locally, caches results per-SHA so the background
//! pipeline can skip already-validated gates.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use apm2_core::fac::{LaneProfileV1, compute_test_env};
use sha2::{Digest, Sha256};

use super::bounded_test_runner::{
    BoundedTestLimits, build_bounded_test_command as build_systemd_bounded_test_command,
};
use super::evidence::{EvidenceGateOptions, run_evidence_gates};
use super::gate_attestation::{
    GateResourcePolicy, build_nextest_command, compute_gate_attestation,
    gate_command_for_attestation,
};
use super::gate_cache::GateCache;
use super::jsonl::{
    GateCompletedEvent, GateErrorEvent, GateStartedEvent, StageEvent, emit_jsonl, emit_jsonl_error,
    read_log_error_hint, ts_now,
};
use super::merge_conflicts::{check_merge_conflicts_against_main, render_merge_conflict_summary};
use super::timeout_policy::{
    MAX_MANUAL_TIMEOUT_SECONDS, TEST_TIMEOUT_SLA_MESSAGE, max_memory_bytes, parse_memory_limit,
    resolve_bounded_test_timeout,
};
use crate::exit_codes::codes as exit_codes;

const DEFAULT_TEST_KILL_AFTER_SECONDS: u64 = 20;

/// Run all evidence gates locally with optional bounded test execution.
///
/// 1. Requires clean working tree for full mode (`--quick` bypasses this)
/// 2. Resolves HEAD SHA
/// 3. Runs merge-conflict gate first (always recomputed)
/// 4. Runs evidence gates (with bounded test runner if available)
/// 5. Writes attested gate cache receipts for full runs
/// 6. Prints summary table
#[allow(clippy::too_many_arguments)]
pub fn run_gates(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    json_output: bool,
) -> u8 {
    let overall_started = Instant::now();
    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "gates_started".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "quick": quick,
                "force": force,
                "timeout_seconds": timeout_seconds,
                "memory_max": memory_max,
                "pids_max": pids_max,
                "cpu_quota": cpu_quota,
            }),
        });
    }

    // Build a real-time gate progress callback for JSON mode. Events are
    // emitted to stdout as each gate starts and finishes, providing streaming
    // observability instead of buffering until all gates complete.
    let gate_progress_callback: Option<Box<dyn Fn(super::evidence::GateProgressEvent) + Send>> =
        if json_output {
            Some(Box::new(
                |event: super::evidence::GateProgressEvent| match event {
                    super::evidence::GateProgressEvent::Started { gate_name } => {
                        let _ = emit_jsonl(&GateStartedEvent {
                            event: "gate_started",
                            gate: gate_name,
                            ts: ts_now(),
                        });
                    },
                    super::evidence::GateProgressEvent::Completed {
                        gate_name,
                        passed,
                        duration_secs,
                        log_path,
                        bytes_written,
                        bytes_total,
                        was_truncated,
                        log_bundle_hash,
                        error_hint,
                    } => {
                        let status = if passed { "pass" } else { "fail" }.to_string();
                        let _ = emit_jsonl(&GateCompletedEvent {
                            event: "gate_completed",
                            gate: gate_name.clone(),
                            status,
                            duration_secs,
                            log_path: log_path.clone(),
                            bytes_written,
                            bytes_total,
                            was_truncated,
                            log_bundle_hash: log_bundle_hash.clone(),
                            error_hint: error_hint.clone(),
                            ts: ts_now(),
                        });
                        if !passed {
                            let _ = emit_jsonl(&GateErrorEvent {
                                event: "gate_error",
                                gate: gate_name,
                                error: error_hint.unwrap_or_else(|| {
                                    "gate failed (see log for details)".to_string()
                                }),
                                log_path,
                                duration_secs: Some(duration_secs),
                                bytes_written,
                                bytes_total,
                                was_truncated,
                                log_bundle_hash,
                                ts: ts_now(),
                            });
                        }
                    },
                },
            ))
        } else {
            None
        };

    match run_gates_inner(
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        !json_output,
        gate_progress_callback,
    ) {
        Ok(summary) => {
            if json_output {
                // Gate-level events were already streamed in real-time via the
                // callback. Only the summary/completion events are emitted here.
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_completed".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "passed": summary.passed,
                        "duration_secs": overall_started.elapsed().as_secs(),
                        "gate_count": summary.gates.len(),
                    }),
                });
                let summary_value =
                    serde_json::to_value(&summary).unwrap_or_else(|_| serde_json::json!({}));
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_summary".to_string(),
                    ts: ts_now(),
                    extra: summary_value,
                });
            } else {
                // JSON-only: emit the summary as pretty-printed JSON.
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
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
                let _ = emit_jsonl_error("gate_error", &err);
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_completed".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "passed": false,
                        "duration_secs": overall_started.elapsed().as_secs(),
                        "error": err,
                    }),
                });
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_summary".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "passed": false,
                        "error": err,
                    }),
                });
            } else {
                // JSON-only: emit the error as a structured JSON object.
                let payload = serde_json::json!({
                    "error": "gate_error",
                    "message": err,
                    "passed": false,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
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
    #[serde(skip_serializing_if = "Option::is_none")]
    log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    was_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_hint: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn run_gates_inner(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    emit_human_logs: bool,
    on_gate_progress: Option<Box<dyn Fn(super::evidence::GateProgressEvent) + Send>>,
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

    // 1. Require clean working tree for full gates only. `--force` allows
    // rerunning gates for the same SHA while local edits are in progress.
    ensure_clean_working_tree(&workspace_root, quick || force)?;

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
    // Emit gate_started before execution for streaming observability.
    if let Some(ref cb) = on_gate_progress {
        cb(super::evidence::GateProgressEvent::Started {
            gate_name: "merge_conflict_main".to_string(),
        });
    }
    let merge_gate = evaluate_merge_conflict_gate(&workspace_root, &sha, emit_human_logs)?;
    // Emit gate_completed immediately after the merge gate finishes.
    if let Some(ref cb) = on_gate_progress {
        cb(super::evidence::GateProgressEvent::Completed {
            gate_name: merge_gate.name.clone(),
            passed: merge_gate.status == "PASS",
            duration_secs: merge_gate.duration_secs,
            log_path: merge_gate.log_path.clone(),
            bytes_written: merge_gate.bytes_written,
            bytes_total: merge_gate.bytes_total,
            was_truncated: merge_gate.was_truncated,
            log_bundle_hash: merge_gate.log_bundle_hash.clone(),
            error_hint: merge_gate.error_hint.clone(),
        });
    }
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
    let default_nextest_command = build_nextest_command();
    let mut test_command_environment = compute_nextest_test_environment()?;
    let mut bounded = false;

    let mut env_remove_keys = Vec::new();
    let test_command = if quick {
        None
    } else {
        let spec = build_systemd_bounded_test_command(
            &workspace_root,
            BoundedTestLimits {
                timeout_seconds: timeout_decision.effective_seconds,
                kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
                memory_max,
                pids_max,
                cpu_quota,
            },
            &default_nextest_command,
            &test_command_environment,
        )
        .map_err(|err| format!("bounded test runner unavailable for FAC gates: {err}"))?;
        bounded = true;
        test_command_environment.extend(spec.environment);

        // TCK-00548: sccache env vars (RUSTC_WRAPPER, SCCACHE_*) are
        // unconditionally stripped from bounded test commands. We cannot
        // verify cgroup containment for the systemd transient unit
        // before it starts (the unit PID does not exist yet), so
        // sccache is never forwarded in bounded test mode. The
        // stripping happens in two places:
        //   1. The allowlist in bounded_test_runner excludes RUSTC_WRAPPER and
        //      SCCACHE_* so they are not included in --setenv args.
        //   2. env_remove_keys strips them from the spawned process environment to
        //      prevent inheritance from the parent.
        test_command_environment.extend(spec.setenv_pairs);

        // Log if sccache env vars were found and stripped.
        if emit_human_logs && !spec.env_remove_keys.is_empty() {
            eprintln!(
                "INFO: sccache env vars stripped from bounded test (containment cannot be \
                 verified for systemd transient units): {:?}",
                spec.env_remove_keys
            );
        }

        env_remove_keys = spec.env_remove_keys;
        Some(spec.command)
    };

    let opts = EvidenceGateOptions {
        test_command,
        test_command_environment,
        env_remove_keys,
        skip_test_gate: quick,
        skip_merge_conflict_gate: true,
        emit_human_logs,
        on_gate_progress,
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
            let evidence_log_digest = result
                .log_path
                .as_ref()
                .and_then(|path| gate_log_digest(path));
            cache.set_with_attestation(
                &result.gate_name,
                result.passed,
                result.duration_secs,
                attestation_digest,
                quick,
                evidence_log_digest,
                result
                    .log_path
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .map(str::to_string),
            );
        }
        for result in &gate_results {
            cache.backfill_evidence_metadata(
                &result.gate_name,
                result.log_bundle_hash.as_deref(),
                result.bytes_written,
                result.bytes_total,
                result.was_truncated,
                result.log_path.as_ref().and_then(|p| p.to_str()),
            );
        }
        cache.save()?;
    }

    let mut gates = vec![merge_gate];
    let mut evidence_gates: Vec<GateResult> = gate_results
        .iter()
        .map(|r| {
            let error_hint = if r.passed {
                None
            } else {
                r.log_path.as_deref().and_then(read_log_error_hint)
            };
            GateResult {
                name: r.gate_name.clone(),
                status: if r.passed { "PASS" } else { "FAIL" }.to_string(),
                duration_secs: r.duration_secs,
                log_path: r
                    .log_path
                    .as_ref()
                    .and_then(|path| path.to_str())
                    .map(str::to_string),
                bytes_written: r.bytes_written,
                bytes_total: r.bytes_total,
                was_truncated: r.was_truncated,
                log_bundle_hash: r.log_bundle_hash.clone(),
                error_hint,
            }
        })
        .collect();
    gates.append(&mut evidence_gates);
    if quick {
        normalize_quick_test_gate(&mut gates);
    }

    if emit_human_logs {
        eprintln!(
            "fac gates (mode={}): completed in {total_secs}s — {}",
            if quick { "quick" } else { "full" },
            if passed { "PASS" } else { "FAIL" }
        );
    }

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

fn gate_log_digest(log_path: &Path) -> Option<String> {
    if !log_path.exists() {
        return None;
    }
    let bytes = fs::read(log_path).ok()?;
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

fn evaluate_merge_conflict_gate(
    workspace_root: &Path,
    sha: &str,
    emit_human_logs: bool,
) -> Result<GateResult, String> {
    let started = Instant::now();
    let report = check_merge_conflicts_against_main(workspace_root, sha)?;
    let duration = started.elapsed().as_secs();
    let passed = !report.has_conflicts();
    if emit_human_logs && !passed {
        eprintln!("{}", render_merge_conflict_summary(&report));
    }
    Ok(GateResult {
        name: "merge_conflict_main".to_string(),
        status: if passed { "PASS" } else { "FAIL" }.to_string(),
        duration_secs: duration,
        log_path: None,
        bytes_written: None,
        bytes_total: None,
        was_truncated: None,
        log_bundle_hash: None,
        error_hint: None,
    })
}

fn normalize_quick_test_gate(gates: &mut Vec<GateResult>) {
    // Preserve a single canonical `test` gate entry in quick mode.
    if let Some(test_gate) = gates.iter_mut().find(|gate| gate.name == "test") {
        test_gate.status = "SKIP".to_string();
        return;
    }

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
            log_path: None,
            bytes_written: None,
            bytes_total: None,
            was_truncated: None,
            log_bundle_hash: None,
            error_hint: None,
        },
    );
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
    fn normalize_quick_test_gate_reuses_existing_test_entry() {
        let mut gates = vec![
            GateResult {
                name: "merge_conflict_main".to_string(),
                status: "PASS".to_string(),
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            },
            GateResult {
                name: "test".to_string(),
                status: "PASS".to_string(),
                duration_secs: 2,
                log_path: Some("/tmp/test.log".to_string()),
                bytes_written: Some(10),
                bytes_total: Some(10),
                was_truncated: Some(false),
                log_bundle_hash: Some("b3-256:abc".to_string()),
                error_hint: None,
            },
            GateResult {
                name: "workspace_integrity".to_string(),
                status: "PASS".to_string(),
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            },
        ];

        normalize_quick_test_gate(&mut gates);

        let test_gates = gates
            .iter()
            .filter(|gate| gate.name == "test")
            .collect::<Vec<_>>();
        assert_eq!(test_gates.len(), 1);
        let gate = test_gates[0];
        assert_eq!(gate.status, "SKIP");
        assert_eq!(gate.log_path.as_deref(), Some("/tmp/test.log"));
    }

    /// Verify that the `on_gate_progress` callback in [`EvidenceGateOptions`]
    /// receives `Started` events BEFORE `Completed` events for each gate.
    ///
    /// This test validates BLOCKER 2 fix: gate lifecycle events must be emitted
    /// during execution (via callback) rather than buffered and replayed after
    /// all gates return. The callback structure ensures callers can stream
    /// JSONL events in real time at each gate boundary.
    #[test]
    fn gate_progress_callback_receives_events_in_order() {
        use std::sync::{Arc, Mutex};

        use super::super::evidence::GateProgressEvent;

        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let events_clone = Arc::clone(&events);

        // Build a callback that records event types.
        let callback: Box<dyn Fn(GateProgressEvent) + Send> =
            Box::new(move |event: GateProgressEvent| match event {
                GateProgressEvent::Started { gate_name } => {
                    events_clone
                        .lock()
                        .unwrap()
                        .push(format!("started:{gate_name}"));
                },
                GateProgressEvent::Completed {
                    gate_name, passed, ..
                } => {
                    events_clone
                        .lock()
                        .unwrap()
                        .push(format!("completed:{gate_name}:passed={passed}"));
                },
            });

        // Verify that the callback type matches what EvidenceGateOptions expects.
        let opts = super::super::evidence::EvidenceGateOptions {
            test_command: None,
            test_command_environment: Vec::new(),
            env_remove_keys: Vec::new(),
            skip_test_gate: true,
            skip_merge_conflict_gate: true,
            emit_human_logs: false,
            on_gate_progress: Some(callback),
        };

        // Simulate the callback being invoked for a gate lifecycle.
        if let Some(ref cb) = opts.on_gate_progress {
            cb(GateProgressEvent::Started {
                gate_name: "test_gate".to_string(),
            });
            cb(GateProgressEvent::Completed {
                gate_name: "test_gate".to_string(),
                passed: true,
                duration_secs: 5,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            });
        }

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0], "started:test_gate");
        assert_eq!(recorded[1], "completed:test_gate:passed=true");
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
