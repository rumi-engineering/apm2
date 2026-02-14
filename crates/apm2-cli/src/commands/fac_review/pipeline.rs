//! Background pipeline: evidence gates → CI status → review dispatch.
//!
//! Spawned as a detached process by `apm2 fac push` after creating/updating a
//! PR. Runs evidence gates with CI status comment updates, then dispatches
//! reviews if all gates pass.

use super::dispatch::resolve_worktree_for_sha;
use super::evidence::run_evidence_gates_with_status;
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
    let workspace_root = resolve_worktree_for_sha(sha)?;

    eprintln!("pipeline: running evidence gates for PR #{pr_number} sha={sha}");

    let passed = run_evidence_gates_with_status(&workspace_root, sha, repo, pr_number, None)?;

    if !passed {
        eprintln!("pipeline: evidence gates FAILED — skipping review dispatch");
        return Ok(false);
    }

    eprintln!("pipeline: evidence gates PASSED — dispatching reviews");

    let results = super::dispatch_reviews_with_lifecycle(repo, pr_number, sha, false)?;
    for result in results {
        eprintln!(
            "pipeline: dispatched {} review (mode={}{})",
            result.review_type,
            result.mode,
            result
                .pid
                .map_or_else(String::new, |p| format!(", pid={p}")),
        );
    }

    eprintln!("pipeline: complete");
    Ok(true)
}
