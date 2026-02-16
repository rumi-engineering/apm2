//! Background pipeline: evidence gates → CI status → review dispatch.
//!
//! Spawned as a detached process by `apm2 fac push` after creating/updating a
//! PR. Runs evidence gates with CI status comment updates, then dispatches
//! reviews if all gates pass.

use super::dispatch::resolve_worktree_for_sha;
use super::evidence::run_evidence_gates_with_status;
use super::jsonl::{
    GateCompletedEvent, GateErrorEvent, StageEvent, emit_jsonl, emit_jsonl_error,
    read_log_error_hint, ts_now,
};
use crate::exit_codes::codes as exit_codes;

/// Run the full evidence → review pipeline.
///
/// Returns an exit code: 0 on success, 1 if evidence gates fail or an error
/// occurs.
pub fn run_pipeline(repo: &str, pr_number: u32, sha: &str, json_output: bool) -> u8 {
    // TCK-00596: Fail-fast credential gate for GitHub-facing pipeline command.
    if let Err(err) = apm2_core::fac::require_github_credentials() {
        let message = err.to_string();
        eprintln!("ERROR: {message}");
        if json_output {
            let _ = emit_jsonl_error("pipeline_credentials_missing", &message);
        }
        return exit_codes::GENERIC_ERROR;
    }

    match run_pipeline_inner(repo, pr_number, sha, json_output) {
        Ok(passed) => {
            if json_output {
                let _ = emit_jsonl(&StageEvent {
                    event: "pipeline_summary".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "schema": "apm2.fac.pipeline.summary.v1",
                        "repo": repo,
                        "pr_number": pr_number,
                        "sha": sha,
                        "passed": passed,
                    }),
                });
            }
            if passed {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            if json_output {
                let _ = emit_jsonl_error("pipeline_error", &err);
                let _ = emit_jsonl(&StageEvent {
                    event: "pipeline_completed".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "repo": repo,
                        "pr_number": pr_number,
                        "sha": sha,
                        "passed": false,
                        "error": err,
                    }),
                });
                let _ = emit_jsonl(&StageEvent {
                    event: "pipeline_summary".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "schema": "apm2.fac.pipeline.summary.v1",
                        "repo": repo,
                        "pr_number": pr_number,
                        "sha": sha,
                        "passed": false,
                        "error": err,
                    }),
                });
            } else {
                eprintln!("pipeline error: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_pipeline_inner(
    repo: &str,
    pr_number: u32,
    sha: &str,
    json_output: bool,
) -> Result<bool, String> {
    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "pipeline_started".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "repo": repo,
                "pr_number": pr_number,
                "sha": sha,
            }),
        });
    }
    let workspace_root = resolve_worktree_for_sha(sha)?;

    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "gates_started".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "repo": repo,
                "pr_number": pr_number,
                "sha": sha,
            }),
        });
    } else {
        eprintln!("pipeline: running evidence gates for PR #{pr_number} sha={sha}");
    }

    let (passed, gate_results) = match run_evidence_gates_with_status(
        &workspace_root,
        sha,
        repo,
        pr_number,
        None,
        !json_output,
        None,
    ) {
        Ok(value) => value,
        Err(err) => {
            if json_output {
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_completed".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "status": "error",
                        "passed": false,
                        "error": err.as_str(),
                    }),
                });
            }
            return Err(err);
        },
    };

    if json_output {
        for gate in &gate_results {
            let status = if gate.passed { "pass" } else { "fail" }.to_string();
            let error_hint = if gate.passed {
                None
            } else {
                gate.log_path.as_deref().and_then(read_log_error_hint)
            };
            let _ = emit_jsonl(&GateCompletedEvent {
                event: "gate_completed",
                gate: gate.gate_name.clone(),
                status,
                duration_secs: gate.duration_secs,
                log_path: gate
                    .log_path
                    .as_ref()
                    .and_then(|path| path.to_str())
                    .map(str::to_string),
                bytes_written: gate.bytes_written,
                bytes_total: gate.bytes_total,
                was_truncated: gate.was_truncated,
                log_bundle_hash: gate.log_bundle_hash.clone(),
                error_hint: error_hint.clone(),
                ts: ts_now(),
            });
            if !gate.passed {
                let _ = emit_jsonl(&GateErrorEvent {
                    event: "gate_error",
                    gate: gate.gate_name.clone(),
                    error: error_hint.unwrap_or_else(|| "gate failed".to_string()),
                    log_path: gate
                        .log_path
                        .as_ref()
                        .and_then(|path| path.to_str())
                        .map(str::to_string),
                    duration_secs: Some(gate.duration_secs),
                    bytes_written: gate.bytes_written,
                    bytes_total: gate.bytes_total,
                    was_truncated: gate.was_truncated,
                    log_bundle_hash: gate.log_bundle_hash.clone(),
                    ts: ts_now(),
                });
            }
        }
    }

    let failed_gates = gate_results
        .iter()
        .filter(|gate| !gate.passed)
        .map(|gate| gate.gate_name.clone())
        .collect::<Vec<_>>();

    if !passed {
        if json_output {
            let _ = emit_jsonl(&StageEvent {
                event: "gates_completed".to_string(),
                ts: ts_now(),
                extra: serde_json::json!({
                    "passed": false,
                    "failed_gates": failed_gates,
                    "gate_count": gate_results.len(),
                }),
            });
            let _ = emit_jsonl(&StageEvent {
                event: "pipeline_completed".to_string(),
                ts: ts_now(),
                extra: serde_json::json!({
                    "passed": false,
                    "repo": repo,
                    "pr_number": pr_number,
                    "sha": sha,
                }),
            });
        } else {
            eprintln!("pipeline: evidence gates FAILED — skipping review dispatch");
        }
        return Ok(false);
    }

    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "gates_completed".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "passed": true,
                "gate_count": gate_results.len(),
            }),
        });
        let _ = emit_jsonl(&StageEvent {
            event: "dispatch_started".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "repo": repo,
                "pr_number": pr_number,
                "sha": sha,
            }),
        });
    } else {
        eprintln!("pipeline: evidence gates PASSED — dispatching reviews");
    }

    let results = match super::dispatch_reviews_with_lifecycle(repo, pr_number, sha, false) {
        Ok(value) => value,
        Err(err) => {
            if json_output {
                let _ = emit_jsonl(&StageEvent {
                    event: "dispatch_completed".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "status": "error",
                        "error": err.as_str(),
                    }),
                });
            }
            return Err(err);
        },
    };
    for result in results {
        if json_output {
            let _ = emit_jsonl(&StageEvent {
                event: "dispatch_review".to_string(),
                ts: ts_now(),
                extra: serde_json::json!({
                    "review_type": result.review_type,
                    "mode": result.mode,
                    "pid": result.pid,
                    "run_id": result.run_id,
                }),
            });
        } else {
            eprintln!(
                "pipeline: dispatched {} review (mode={}{})",
                result.review_type,
                result.mode,
                result
                    .pid
                    .map_or_else(String::new, |p| format!(", pid={p}")),
            );
        }
    }

    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "dispatch_completed".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "status": "pass",
            }),
        });
        let _ = emit_jsonl(&StageEvent {
            event: "pipeline_completed".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "passed": true,
                "repo": repo,
                "pr_number": pr_number,
                "sha": sha,
            }),
        });
    } else {
        eprintln!("pipeline: complete");
    }
    Ok(true)
}
