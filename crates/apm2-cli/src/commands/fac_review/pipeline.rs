//! Background pipeline: evidence gates → CI status → review dispatch.
//!
//! Spawned as a detached process by `apm2 fac push` after creating/updating a
//! PR. Runs evidence gates with CI status comment updates, then dispatches
//! reviews if all gates pass.
//!
//! # TCK-00544: mirror-based lane execution
//!
//! Evidence gates execute inside a lane workspace that is cloned from the
//! node-local bare mirror at the exact target SHA. This eliminates the SHA
//! drift and dirty-attests-clean hazards that existed when the pipeline
//! resolved a caller worktree and ran gates there.
//!
//! Execution flow:
//! 1. Ensure bare mirror exists (bootstrap from GitHub URL if needed).
//! 2. Allocate a free lane and acquire exclusive lock.
//! 3. Clone mirror → lane workspace at the target SHA (clean by construction).
//! 4. Run evidence gates inside the lane workspace.
//! 5. Dispatch reviews on success.

use std::path::PathBuf;

use apm2_core::fac::RepoMirrorManager;

use super::evidence::{
    EvidenceLaneContext, allocate_evidence_lane_context,
    run_evidence_gates_with_status_with_lane_context,
};
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

    // TCK-00544: resolve workspace via mirror checkout to an isolated lane,
    // eliminating SHA drift and dirty-attests-clean hazards.
    let (workspace_root, lane_context) = setup_mirror_lane_workspace(repo, sha, json_output)?;

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

    let (passed, gate_results) = match run_evidence_gates_with_status_with_lane_context(
        &workspace_root,
        sha,
        repo,
        pr_number,
        None,
        !json_output,
        None,
        lane_context,
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

// ── TCK-00544: mirror-based lane workspace setup ────────────────────────────

/// Derive the HTTPS remote URL from the `owner/name` repo slug.
///
/// Returns a URL suitable for `git clone --bare` and
/// `RepoMirrorManager::ensure_mirror`.
fn github_remote_url_for_repo(repo: &str) -> Result<String, String> {
    // Validate basic `owner/name` structure.
    let parts: Vec<&str> = repo.splitn(2, '/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(format!("repo must be in owner/name format, got: {repo}"));
    }
    Ok(format!("https://github.com/{repo}.git"))
}

/// Set up an isolated lane workspace by:
/// 1. Ensuring the bare mirror exists (bootstrapping from GitHub URL if
///    needed).
/// 2. Allocating a free lane with exclusive lock.
/// 3. Checking out the exact SHA from the mirror to the lane workspace.
///
/// Returns `(workspace_root, lane_context)` where `workspace_root` points to
/// the clean lane workspace at the target SHA, and `lane_context` holds the
/// exclusive lane lock and logs directory.
///
/// SAFETY: The returned workspace is clean by construction — it is freshly
/// cloned from the bare mirror at the exact target SHA. No caller worktree
/// content can leak into the workspace.
fn setup_mirror_lane_workspace(
    repo: &str,
    sha: &str,
    json_output: bool,
) -> Result<(PathBuf, EvidenceLaneContext), String> {
    use apm2_core::fac::LaneManager;

    let apm2_home = apm2_core::github::resolve_apm2_home().ok_or_else(|| {
        "cannot resolve APM2_HOME for mirror-based pipeline execution".to_string()
    })?;
    let fac_root = apm2_home.join("private/fac");

    // 1. Ensure the bare mirror is available and up-to-date.
    let remote_url = github_remote_url_for_repo(repo)?;
    let mirror_manager = RepoMirrorManager::new(&fac_root);

    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "mirror_ensure_started".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "repo": repo,
                "sha": sha,
            }),
        });
    }

    mirror_manager
        .ensure_mirror(repo, Some(&remote_url))
        .map_err(|err| format!("failed to ensure bare mirror for {repo}: {err}"))?;

    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "mirror_ensure_completed".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "repo": repo,
                "sha": sha,
            }),
        });
    }

    // 2. Allocate a free lane and acquire exclusive lock.
    let lane_manager = LaneManager::from_default_home()
        .map_err(|err| format!("failed to resolve lane manager: {err}"))?;
    lane_manager
        .ensure_directories()
        .map_err(|err| format!("failed to ensure FAC lane directories: {err}"))?;

    let (lane_id, lane_guard) = {
        let mut acquired = None;
        for id in LaneManager::default_lane_ids() {
            match lane_manager.try_lock(&id) {
                Ok(Some(guard)) => {
                    acquired = Some((id, guard));
                    break;
                },
                Ok(None) => {},
                Err(err) => {
                    return Err(format!("failed to inspect lane {id}: {err}"));
                },
            }
        }
        acquired.ok_or_else(|| {
            "no free FAC lane available for pipeline evidence execution".to_string()
        })?
    };

    // 3. Checkout the exact SHA from mirror to lane workspace.
    let lanes_root = fac_root.join("lanes");
    let lane_workspace = lane_manager.lane_dir(&lane_id).join("workspace");

    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "mirror_checkout_started".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "repo": repo,
                "sha": sha,
                "lane_id": lane_id,
            }),
        });
    }

    mirror_manager
        .checkout_to_lane(repo, sha, &lane_workspace, &lanes_root)
        .map_err(|err| format!("failed to checkout sha {sha} to lane {lane_id}: {err}"))?;

    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "mirror_checkout_completed".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "repo": repo,
                "sha": sha,
                "lane_id": lane_id,
                "workspace": lane_workspace.display().to_string(),
            }),
        });
    } else {
        eprintln!(
            "pipeline: checked out sha={sha} to lane workspace {} (lane={lane_id})",
            lane_workspace.display()
        );
    }

    // 4. Build the lane context (logs dir + lane lock guard).
    let lane_context = allocate_evidence_lane_context(&lane_manager, &lane_id, lane_guard)?;

    Ok((lane_workspace, lane_context))
}
