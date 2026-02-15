//! Background pipeline: evidence gates → CI status → review dispatch.
//!
//! Spawned as a detached process by `apm2 fac push` after creating/updating a
//! PR. Runs evidence gates with CI status comment updates, then dispatches
//! reviews if all gates pass.

use super::dispatch::resolve_worktree_for_sha;
use super::evidence::run_evidence_gates_with_status;
use super::jsonl::{StageEvent, emit_jsonl, emit_jsonl_error, ts_now};
use crate::exit_codes::codes as exit_codes;

/// Run the full evidence → review pipeline.
///
/// Returns an exit code: 0 on success, 1 if evidence gates fail or an error
/// occurs.
pub fn run_pipeline(repo: &str, pr_number: u32, sha: &str, json_output: bool) -> u8 {
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
            extra: serde_json::json!({}),
        });
    } else {
        eprintln!("pipeline: running evidence gates for PR #{pr_number} sha={sha}");
    }

    let (passed, _) =
        run_evidence_gates_with_status(&workspace_root, sha, repo, pr_number, None, !json_output)?;

    if !passed {
        if json_output {
            let _ = emit_jsonl(&StageEvent {
                event: "gates_completed".to_string(),
                ts: ts_now(),
                extra: serde_json::json!({ "passed": false }),
            });
            let _ = emit_jsonl(&StageEvent {
                event: "pipeline_completed".to_string(),
                ts: ts_now(),
                extra: serde_json::json!({ "passed": false }),
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
            extra: serde_json::json!({ "passed": true }),
        });
        let _ = emit_jsonl(&StageEvent {
            event: "dispatch_started".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({}),
        });
    } else {
        eprintln!("pipeline: evidence gates PASSED — dispatching reviews");
    }

    let results = super::dispatch_reviews_with_lifecycle(repo, pr_number, sha, false)?;
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
            extra: serde_json::json!({}),
        });
        let _ = emit_jsonl(&StageEvent {
            event: "pipeline_completed".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({ "passed": true }),
        });
    } else {
        eprintln!("pipeline: complete");
    }
    Ok(true)
}
