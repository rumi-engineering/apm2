//! Background pipeline: evidence gates → CI status → review dispatch.
//!
//! Spawned as a detached process by `apm2 fac push` after creating/updating a
//! PR. Runs evidence gates with CI status comment updates, then dispatches
//! reviews if all gates pass.

use super::dispatch::dispatch_single_review;
use super::evidence::run_evidence_gates_with_status;
use super::types::ReviewKind;
use crate::exit_codes::codes as exit_codes;

/// Run the full evidence → review pipeline.
///
/// Returns an exit code: 0 on success, 1 if evidence gates fail or an error
/// occurs.
pub fn run_pipeline(repo: &str, pr_number: u32, sha: &str) -> u8 {
    match run_pipeline_inner(repo, pr_number, sha) {
        Ok(passed) => {
            if passed {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            eprintln!("pipeline error: {err}");
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_pipeline_inner(repo: &str, pr_number: u32, sha: &str) -> Result<bool, String> {
    let workspace_root =
        std::env::current_dir().map_err(|e| format!("failed to resolve cwd: {e}"))?;

    eprintln!("pipeline: running evidence gates for PR #{pr_number} sha={sha}");

    let passed = run_evidence_gates_with_status(&workspace_root, sha, repo, pr_number, None)?;

    if !passed {
        eprintln!("pipeline: evidence gates FAILED — skipping review dispatch");
        return Ok(false);
    }

    eprintln!("pipeline: evidence gates PASSED — dispatching reviews");

    let dispatch_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for kind in [ReviewKind::Security, ReviewKind::Quality] {
        match dispatch_single_review(repo, pr_number, kind, sha, dispatch_epoch) {
            Ok(result) => {
                eprintln!(
                    "pipeline: dispatched {} review (mode={}{})",
                    result.review_type,
                    result.mode,
                    result
                        .pid
                        .map_or_else(String::new, |p| format!(", pid={p}")),
                );
            },
            Err(err) => {
                eprintln!(
                    "pipeline: failed to dispatch {} review: {err}",
                    kind.as_str()
                );
                return Err(format!(
                    "review dispatch failed for {}: {err}",
                    kind.as_str()
                ));
            },
        }
    }

    eprintln!("pipeline: complete");
    Ok(true)
}
