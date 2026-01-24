//! Implementation of the `check` command.
//!
//! This command shows the current ticket and PR status, and suggests the next
//! action based on the current state.
//!
//! # States and Actions
//!
//! | State              | Suggested Action                              |
//! |--------------------|-----------------------------------------------|
//! | Uncommitted changes| `cargo xtask commit '<message>'`              |
//! | No PR exists       | `cargo xtask push`                            |
//! | CI running         | Wait (use `--watch` to poll)                  |
//! | CI failed          | Fix issues, then commit and push              |
//! | Reviews pending    | Wait for reviews (auto-merge enabled)         |
//! | Reviews failed     | Address feedback, commit, re-push             |
//! | All passed         | Wait for auto-merge, then cleanup             |
//! | Already merged     | `cargo xtask finish` to cleanup               |

use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use xshell::{Shell, cmd};

use crate::util::{current_branch, validate_ticket_branch};

/// A single check run from GitHub's API.
///
/// The `gh pr checks --json` command returns these fields:
/// - `state`: PENDING, `IN_PROGRESS`, SUCCESS, FAILURE, etc.
/// - `bucket`: pending, pass, fail
#[derive(Debug, Deserialize)]
struct CheckRun {
    #[allow(dead_code)]
    name: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    bucket: Option<String>,
}

/// Check ticket and PR status.
///
/// This function displays the current state and suggests the next action.
///
/// # Arguments
///
/// * `watch` - If true, continuously poll status every 10 seconds
///
/// # Errors
///
/// Returns an error if:
/// - Not on a valid ticket branch
/// - Git or gh CLI operations fail
pub fn run(watch: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // Get current branch and validate it's a ticket branch
    let branch_name = current_branch(&sh)?;
    let ticket_branch = validate_ticket_branch(&branch_name)?;

    if let Some(rfc_id) = &ticket_branch.rfc_id {
        println!(
            "Checking status for {} (RFC: {})",
            ticket_branch.ticket_id, rfc_id
        );
    } else {
        println!("Checking status for {}", ticket_branch.ticket_id);
    }
    println!();

    if watch {
        loop {
            let status = check_status(&sh, &branch_name)?;
            print_status(&status);

            // If merged, no need to keep watching
            if status.pr_state == Some(PrState::Merged) {
                break;
            }

            println!("\nPolling again in 10 seconds... (Ctrl+C to stop)");
            thread::sleep(Duration::from_secs(10));

            // Clear terminal for next iteration
            print!("\x1B[2J\x1B[1;1H");
            if let Some(rfc_id) = &ticket_branch.rfc_id {
                println!(
                    "Checking status for {} (RFC: {})",
                    ticket_branch.ticket_id, rfc_id
                );
            } else {
                println!("Checking status for {}", ticket_branch.ticket_id);
            }
            println!();
        }
    } else {
        let status = check_status(&sh, &branch_name)?;
        print_status(&status);
    }

    Ok(())
}

/// The overall status of the ticket/PR.
#[derive(Debug)]
struct Status {
    /// Whether there are uncommitted changes
    has_uncommitted_changes: bool,
    /// Whether there are unpushed commits
    has_unpushed_commits: bool,
    /// PR state (if PR exists)
    pr_state: Option<PrState>,
    /// CI check result (if PR exists)
    ci: Option<CiStatus>,
    /// Review result (if PR exists)
    review: Option<ReviewStatus>,
}

/// PR state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PrState {
    Open,
    Merged,
    Closed,
}

/// CI check status.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CiStatus {
    /// Checks are still running
    Pending,
    /// All checks passed
    Success,
    /// One or more checks failed
    Failure,
}

/// Review status.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReviewStatus {
    /// Waiting for reviews
    Pending,
    /// All required reviews approved
    Approved,
    /// Changes requested
    ChangesRequested,
}

/// Check the current status.
fn check_status(sh: &Shell, branch_name: &str) -> Result<Status> {
    let has_uncommitted_changes = check_uncommitted_changes(sh)?;
    let has_unpushed_commits = check_unpushed_commits(sh, branch_name)?;
    let pr_state = get_pr_state(sh, branch_name)?;
    let ci = if pr_state.is_some() {
        Some(get_ci_status(sh, branch_name)?)
    } else {
        None
    };
    let review = if pr_state.is_some() {
        Some(get_review_status(sh, branch_name)?)
    } else {
        None
    };

    Ok(Status {
        has_uncommitted_changes,
        has_unpushed_commits,
        pr_state,
        ci,
        review,
    })
}

/// Check if there are uncommitted changes.
fn check_uncommitted_changes(sh: &Shell) -> Result<bool> {
    let output = cmd!(sh, "git status --porcelain")
        .read()
        .context("Failed to check git status")?;

    Ok(!output.trim().is_empty())
}

/// Check if there are unpushed commits.
fn check_unpushed_commits(sh: &Shell, branch_name: &str) -> Result<bool> {
    // Check if the remote branch exists
    let remote_exists = cmd!(sh, "git ls-remote --heads origin {branch_name}")
        .read()
        .context("Failed to check remote branch")?;

    if remote_exists.trim().is_empty() {
        // Remote branch doesn't exist, so any local commits are unpushed
        let local_commits = cmd!(sh, "git log --oneline -1")
            .ignore_status()
            .read()
            .context("Failed to check local commits")?;
        return Ok(!local_commits.trim().is_empty());
    }

    // Compare local and remote
    let unpushed = cmd!(sh, "git log origin/{branch_name}..HEAD --oneline")
        .read()
        .context("Failed to compare with remote")?;

    Ok(!unpushed.trim().is_empty())
}

/// Get the PR state for a branch.
fn get_pr_state(sh: &Shell, branch_name: &str) -> Result<Option<PrState>> {
    let output = cmd!(sh, "gh pr view {branch_name} --json state --jq .state")
        .ignore_status()
        .read()
        .context("Failed to query PR state")?;

    let state = output.trim();

    if state.is_empty() || state.contains("no pull requests") || state.contains("not found") {
        return Ok(None);
    }

    match state {
        "OPEN" => Ok(Some(PrState::Open)),
        "MERGED" => Ok(Some(PrState::Merged)),
        "CLOSED" => Ok(Some(PrState::Closed)),
        _ => Ok(None),
    }
}

/// Get the CI check status.
fn get_ci_status(sh: &Shell, branch_name: &str) -> Result<CiStatus> {
    // Get all check runs status
    // Note: gh pr checks uses 'state' and 'bucket' fields, not 'conclusion'
    let output = cmd!(sh, "gh pr checks {branch_name} --json name,state,bucket")
        .ignore_status()
        .read()
        .context("Failed to query PR checks")?;

    Ok(parse_ci_status(&output))
}

/// Parse CI status from JSON output.
///
/// This function parses the JSON output from `gh pr checks --json` and
/// determines the overall CI status:
/// - If any check has bucket=pending or state is PENDING/`IN_PROGRESS`: return
///   Pending
/// - If any check has bucket=fail or state is FAILURE: return Failure
/// - Otherwise: return Success
fn parse_ci_status(output: &str) -> CiStatus {
    let trimmed = output.trim();

    // If the output is empty or an error, assume pending
    if trimmed.is_empty() || trimmed.contains("no checks") {
        return CiStatus::Pending;
    }

    // Parse the JSON array of check runs
    let checks: Vec<CheckRun> = match serde_json::from_str(trimmed) {
        Ok(checks) => checks,
        Err(_) => {
            // If parsing fails, fall back to pending (infrastructure error)
            return CiStatus::Pending;
        },
    };

    // If no checks, return pending
    if checks.is_empty() {
        return CiStatus::Pending;
    }

    // Check for any failures first (bucket=fail or state=FAILURE)
    for check in &checks {
        if let Some(bucket) = &check.bucket {
            if bucket == "fail" {
                return CiStatus::Failure;
            }
        }
        if let Some(state) = &check.state {
            let state_upper = state.to_uppercase();
            if state_upper == "FAILURE" {
                return CiStatus::Failure;
            }
        }
    }

    // Check for any pending/in-progress checks
    for check in &checks {
        if let Some(bucket) = &check.bucket {
            if bucket == "pending" {
                return CiStatus::Pending;
            }
        }
        if let Some(state) = &check.state {
            let state_upper = state.to_uppercase();
            if state_upper == "PENDING" || state_upper == "IN_PROGRESS" || state_upper == "QUEUED" {
                return CiStatus::Pending;
            }
        }
    }

    // All checks completed successfully
    CiStatus::Success
}

/// Get the review status.
fn get_review_status(sh: &Shell, branch_name: &str) -> Result<ReviewStatus> {
    // Get review decision from PR
    let output = cmd!(
        sh,
        "gh pr view {branch_name} --json reviewDecision --jq .reviewDecision"
    )
    .ignore_status()
    .read()
    .context("Failed to query PR reviews")?;

    let decision = output.trim();

    match decision {
        "APPROVED" => Ok(ReviewStatus::Approved),
        "CHANGES_REQUESTED" => Ok(ReviewStatus::ChangesRequested),
        // REVIEW_REQUIRED, empty string, or any unknown value means pending
        _ => Ok(ReviewStatus::Pending),
    }
}

/// Print the status and suggested action.
fn print_status(status: &Status) {
    println!("Status:");
    println!("-------");

    // Git status
    if status.has_uncommitted_changes {
        println!("  [!] Uncommitted changes detected");
    } else {
        println!("  [ok] Working directory clean");
    }

    if status.has_unpushed_commits {
        println!("  [!] Unpushed commits");
    }

    // PR status
    match &status.pr_state {
        None => {
            println!("  [!] No PR exists for this branch");
        },
        Some(PrState::Open) => {
            println!("  [ok] PR is open");

            // CI status
            match &status.ci {
                Some(CiStatus::Pending) => println!("  [..] CI checks running"),
                Some(CiStatus::Success) => println!("  [ok] CI checks passed"),
                Some(CiStatus::Failure) => println!("  [X] CI checks failed"),
                None => {},
            }

            // Review status
            match &status.review {
                Some(ReviewStatus::Pending) => println!("  [..] Waiting for reviews"),
                Some(ReviewStatus::Approved) => println!("  [ok] Reviews approved"),
                Some(ReviewStatus::ChangesRequested) => println!("  [X] Changes requested"),
                None => {},
            }
        },
        Some(PrState::Merged) => {
            println!("  [ok] PR has been merged");
        },
        Some(PrState::Closed) => {
            println!("  [X] PR was closed without merging");
        },
    }

    println!();
    println!("Suggested Action:");
    println!("-----------------");

    // Determine suggested action based on priority
    if status.has_uncommitted_changes {
        println!("  Commit your changes:");
        println!("    cargo xtask commit '<message>'");
    } else if status.pr_state.is_none() {
        println!("  Create a PR:");
        println!("    cargo xtask push");
    } else if status.has_unpushed_commits {
        println!("  Push your changes:");
        println!("    cargo xtask push");
    } else {
        match &status.pr_state {
            Some(PrState::Open) => {
                // Check CI first
                if matches!(&status.ci, Some(CiStatus::Failure)) {
                    println!("  Fix CI failures, then commit and push:");
                    println!("    cargo xtask commit '<fix message>'");
                    println!("    cargo xtask push");
                } else if matches!(&status.ci, Some(CiStatus::Pending)) {
                    println!("  Wait for CI to complete.");
                    println!("  Use --watch to poll: cargo xtask check --watch");
                } else if matches!(&status.review, Some(ReviewStatus::ChangesRequested)) {
                    println!("  Address review feedback, then commit and push:");
                    println!("    cargo xtask commit '<address feedback>'");
                    println!("    cargo xtask push --force-review");
                } else if matches!(&status.review, Some(ReviewStatus::Pending)) {
                    println!("  Waiting for reviews. Auto-merge is enabled.");
                    println!("  Use --watch to poll: cargo xtask check --watch");
                } else {
                    // CI passed, reviews approved
                    println!("  All checks passed! Waiting for auto-merge.");
                    println!("  Once merged: cargo xtask finish");
                }
            },
            Some(PrState::Merged) => {
                println!("  PR is merged. Clean up with:");
                println!("    cargo xtask finish");
            },
            Some(PrState::Closed) => {
                println!("  PR was closed. If intentional, delete the branch:");
                println!("    git branch -D <branch>");
            },
            None => {
                // Already handled above
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ci_status_empty_output() {
        assert_eq!(parse_ci_status(""), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_no_checks_message() {
        assert_eq!(parse_ci_status("no checks reported"), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_empty_array() {
        assert_eq!(parse_ci_status("[]"), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_all_success() {
        let json = r#"[
            {"name": "build", "state": "SUCCESS", "bucket": "pass"},
            {"name": "test", "state": "SUCCESS", "bucket": "pass"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Success);
    }

    #[test]
    fn test_parse_ci_status_one_pending() {
        let json = r#"[
            {"name": "build", "state": "SUCCESS", "bucket": "pass"},
            {"name": "test", "state": "PENDING", "bucket": "pending"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_in_progress() {
        let json = r#"[
            {"name": "build", "state": "IN_PROGRESS", "bucket": "pending"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_queued() {
        let json = r#"[
            {"name": "build", "state": "QUEUED", "bucket": "pending"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_one_failure() {
        let json = r#"[
            {"name": "build", "state": "SUCCESS", "bucket": "pass"},
            {"name": "test", "state": "FAILURE", "bucket": "fail"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Failure);
    }

    #[test]
    fn test_parse_ci_status_bucket_fail() {
        let json = r#"[
            {"name": "build", "state": "SUCCESS", "bucket": "fail"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Failure);
    }

    #[test]
    fn test_parse_ci_status_bucket_pending() {
        let json = r#"[
            {"name": "build", "state": "SUCCESS", "bucket": "pending"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_lowercase_state() {
        let json = r#"[
            {"name": "build", "state": "pending", "bucket": "pending"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_failure_state() {
        let json = r#"[
            {"name": "build", "state": "FAILURE", "bucket": "fail"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Failure);
    }

    #[test]
    fn test_parse_ci_status_missing_fields() {
        // Check with missing optional fields
        let json = r#"[{"name": "build"}]"#;
        // Missing state/bucket means no pending or failure detected, so success
        assert_eq!(parse_ci_status(json), CiStatus::Success);
    }

    #[test]
    fn test_parse_ci_status_invalid_json() {
        assert_eq!(parse_ci_status("not valid json"), CiStatus::Pending);
    }

    #[test]
    fn test_parse_ci_status_mixed_states() {
        // If any check is failing, report failure even if others are pending
        let json = r#"[
            {"name": "build", "state": "SUCCESS", "bucket": "pass"},
            {"name": "lint", "state": "IN_PROGRESS", "bucket": "pending"},
            {"name": "test", "state": "FAILURE", "bucket": "fail"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Failure);
    }

    #[test]
    fn test_parse_ci_status_real_gh_output() {
        // Test with actual gh pr checks output format
        let json = r#"[
            {"bucket":"pending","name":"Documentation","state":"IN_PROGRESS"},
            {"bucket":"pass","name":"Secret Scan","state":"SUCCESS"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Pending);
    }

    #[test]
    fn test_pr_state_parsing() {
        assert_eq!(PrState::Open, PrState::Open);
        assert_eq!(PrState::Merged, PrState::Merged);
        assert_eq!(PrState::Closed, PrState::Closed);
    }

    #[test]
    fn test_review_status_parsing() {
        assert_eq!(ReviewStatus::Pending, ReviewStatus::Pending);
        assert_eq!(ReviewStatus::Approved, ReviewStatus::Approved);
        assert_eq!(
            ReviewStatus::ChangesRequested,
            ReviewStatus::ChangesRequested
        );
    }

    #[test]
    fn test_status_struct() {
        let status = Status {
            has_uncommitted_changes: false,
            has_unpushed_commits: false,
            pr_state: Some(PrState::Open),
            ci: Some(CiStatus::Success),
            review: Some(ReviewStatus::Approved),
        };

        assert!(!status.has_uncommitted_changes);
        assert!(!status.has_unpushed_commits);
        assert_eq!(status.pr_state, Some(PrState::Open));
        assert_eq!(status.ci, Some(CiStatus::Success));
        assert_eq!(status.review, Some(ReviewStatus::Approved));
    }
}
