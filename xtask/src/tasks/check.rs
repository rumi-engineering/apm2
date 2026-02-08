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

use std::sync::OnceLock;
use std::time::{Duration, Instant};
use std::{fs, thread};

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use xshell::{Shell, cmd};

use crate::reviewer_state::{
    HealthStatus, MAX_RESTART_ATTEMPTS, ORPHAN_CLEANUP_AGE_THRESHOLD_SECS, ReviewerEntry,
    ReviewerSpawner, ReviewerStateFile, acquire_remediation_lock, cleanup_reviewer_temp_files,
    kill_process, select_review_model,
};
use crate::util::{current_branch, validate_ticket_branch};

/// Watch mode timeout in seconds.
const WATCH_TIMEOUT_SECS: u64 = 180;

/// Exit code for watch timeout.
const EXIT_TIMEOUT: u8 = 2;

/// Result of watch mode with exit information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchExitReason {
    /// PR was successfully merged.
    Merged,
    /// PR was closed without merging.
    Closed,
    /// CI failed with the given check names.
    CiFailed(Vec<String>),
    /// Reviewer requested changes.
    ChangesRequested,
    /// Watch mode timed out.
    Timeout,
}

impl WatchExitReason {
    /// Get the exit code for this exit reason.
    ///
    /// Returns:
    /// - 0: Success (merged)
    /// - 1: Failure (closed, CI failed, changes requested)
    /// - 2: Timeout
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Merged => 0,
            Self::Closed | Self::CiFailed(_) | Self::ChangesRequested => 1,
            Self::Timeout => EXIT_TIMEOUT,
        }
    }

    /// Get a human-readable message for this exit reason.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Merged => "PR merged successfully!".to_string(),
            Self::Closed => "PR was closed without merging.".to_string(),
            Self::CiFailed(checks) => format!(
                "CI failed: {}\nFix the failures and push again.",
                checks.join(", ")
            ),
            Self::ChangesRequested => "Changes requested by reviewer.\n\
                 Address feedback and push again."
                .to_string(),
            Self::Timeout => format!(
                "Timeout after {WATCH_TIMEOUT_SECS}s waiting for checks.\n\
                 Suggestion: Manually restart slow checks or investigate CI.",
            ),
        }
    }
}

/// A single check run from GitHub's API.
///
/// The `gh pr checks --json` command returns these fields:
/// - `state`: PENDING, `IN_PROGRESS`, SUCCESS, FAILURE, etc.
/// - `bucket`: pending, pass, fail
#[derive(Debug, Clone, Deserialize)]
struct CheckRun {
    name: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    bucket: Option<String>,
}

/// Clean up orphaned temp files from dead reviewers older than the threshold.
///
/// This function silently cleans up temp files for reviewers that:
/// 1. Have a `Dead` health status (process is no longer running)
/// 2. Were started more than 1 hour ago
///
/// Any errors are logged but do not fail the check command.
fn cleanup_orphaned_temp_files_if_needed() {
    if let Ok(mut state) = ReviewerStateFile::load() {
        match state.cleanup_orphaned_temp_files(ORPHAN_CLEANUP_AGE_THRESHOLD_SECS) {
            Ok(cleaned) if !cleaned.is_empty() => {
                println!(
                    "Cleaned up {} orphaned temp file(s) from dead reviewers.",
                    cleaned.len()
                );
            },
            Ok(_) => {
                // No files cleaned up, nothing to report
            },
            Err(e) => {
                // Log but don't fail
                eprintln!("Warning: Failed to clean up orphaned temp files: {e}");
            },
        }
    }
}

/// Check ticket and PR status.
///
/// This function displays the current state and suggests the next action.
///
/// # Arguments
///
/// * `watch` - If true, continuously poll status every 10 seconds
///
/// # Returns
///
/// Returns `Ok(u8)` with the appropriate exit code:
/// - 0: Normal completion or PR merged
/// - 1: Terminal failure state (closed, CI failed, changes requested)
/// - 2: Watch mode timeout
///
/// # Errors
///
/// Returns an error if:
/// - Not on a valid ticket branch
/// - Git or gh CLI operations fail
pub fn run(watch: bool) -> Result<u8> {
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

    // Clean up orphaned temp files from dead reviewers older than 1 hour
    cleanup_orphaned_temp_files_if_needed();

    if watch {
        let start = Instant::now();

        loop {
            let status = check_status(&sh, &branch_name)?;
            print_status(&status);
            display_reviewer_health(&sh)?;

            // Check for terminal states and exit appropriately
            if status.pr_state == Some(PrState::Merged) {
                let reason = WatchExitReason::Merged;
                println!("\n{}", reason.message());
                return Ok(reason.exit_code());
            }

            if status.pr_state == Some(PrState::Closed) {
                let reason = WatchExitReason::Closed;
                println!("\n{}", reason.message());
                return Ok(reason.exit_code());
            }

            if let Some(CiStatus::Failure(ref checks)) = status.ci {
                let reason = WatchExitReason::CiFailed(checks.clone());
                println!("\n{}", reason.message());
                return Ok(reason.exit_code());
            }

            if status.review == Some(ReviewStatus::ChangesRequested) {
                let reason = WatchExitReason::ChangesRequested;
                println!("\n{}", reason.message());
                return Ok(reason.exit_code());
            }

            // Check for timeout
            if start.elapsed().as_secs() >= WATCH_TIMEOUT_SECS {
                let reason = WatchExitReason::Timeout;
                println!("\n{}", reason.message());
                return Ok(reason.exit_code());
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
        display_reviewer_health(&sh)?;
    }

    Ok(0)
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
    /// One or more checks failed, with the names of failed checks
    Failure(Vec<String>),
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

/// Get the remediation command for a specific check type.
///
/// Returns `Some(command)` if a known remediation command exists for the check
/// name, or `None` if no specific fix is known.
fn get_remediation_command(check_name: &str) -> Option<&'static str> {
    // Normalize the check name for case-insensitive matching
    let name_lower = check_name.to_lowercase();

    // Match against known check types
    if name_lower.contains("clippy") {
        Some("cargo clippy --fix --allow-dirty")
    } else if name_lower.contains("fmt") || name_lower.contains("format") {
        Some("cargo fmt")
    } else if name_lower.contains("test") {
        Some("cargo test --workspace")
    } else if name_lower.contains("review")
        && (name_lower.contains("security") || name_lower.contains("quality"))
    {
        // Both security and quality review failures have the same fix
        Some("cargo xtask push --force-review")
    } else if name_lower.contains("semver") {
        Some("cargo semver-checks")
    } else {
        None
    }
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
/// - If any check has bucket=fail or state is FAILURE: return Failure with
///   names
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

    // Collect failed check names
    // Per gh pr checks --help: bucket can be pass, fail, pending, skipping, or
    // cancel
    let failed_checks: Vec<String> = checks
        .iter()
        .filter(|check| {
            check.bucket.as_ref().is_some_and(|bucket| {
                // Both "fail" and "cancel" should be treated as failures
                bucket == "fail" || bucket == "cancel"
            }) || check
                .state
                .as_ref()
                .is_some_and(|state| state.to_uppercase() == "FAILURE")
        })
        .map(|check| check.name.clone())
        .collect();

    // If any failures found, return Failure with the check names
    if !failed_checks.is_empty() {
        return CiStatus::Failure(failed_checks);
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
                Some(CiStatus::Failure(failed_checks)) => {
                    // Display each failed check with its remediation hint
                    for check_name in failed_checks {
                        println!("  [X] {check_name} failed");
                        if let Some(fix_cmd) = get_remediation_command(check_name) {
                            println!("      Fix: {fix_cmd}");
                        }
                    }
                },
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
                if matches!(&status.ci, Some(CiStatus::Failure(_))) {
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

/// Display the health status of active reviewers and auto-remediate if needed.
///
/// For each active reviewer in the state file, this function:
/// 1. Checks the health status (Healthy, Stale, or Dead)
/// 2. Displays the status with PID, last activity elapsed time
/// 3. Auto-remediates unhealthy reviewers (Stale or Dead) by killing the
///    process and restarting the review
fn display_reviewer_health(sh: &Shell) -> Result<()> {
    let state = ReviewerStateFile::load()?;

    if state.reviewers.is_empty() {
        return Ok(());
    }

    println!();
    println!("Reviewer Health:");
    println!("----------------");

    // Process reviewers in a consistent order (security first, then quality)
    let reviewer_order = ["security", "quality"];

    for reviewer_type in &reviewer_order {
        if let Some(entry) = state.reviewers.get(*reviewer_type) {
            let health = entry.check_health();
            let elapsed = entry
                .get_log_mtime_elapsed()
                .map_or_else(|| "unknown".to_string(), |s| format!("{s}s"));

            let status_display = match health {
                HealthStatus::Healthy => format!(
                    "  [ok] {}: PID {} | Last activity: {} ago | Status: {}",
                    capitalize(reviewer_type),
                    entry.pid,
                    elapsed,
                    health.as_str()
                ),
                HealthStatus::Stale | HealthStatus::Dead => format!(
                    "  [!] {}: PID {} | Last activity: {} ago | Status: {}",
                    capitalize(reviewer_type),
                    entry.pid,
                    elapsed,
                    health.as_str()
                ),
            };
            println!("{status_display}");

            // Auto-remediate unhealthy reviewers
            if health != HealthStatus::Healthy {
                remediate_reviewer(sh, reviewer_type, entry, health)?;
            }
        }
    }

    Ok(())
}

/// Capitalize the first letter of a string.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Remediate an unhealthy reviewer by killing it and restarting the review.
fn remediate_reviewer(
    sh: &Shell,
    reviewer_type: &str,
    entry: &ReviewerEntry,
    health: HealthStatus,
) -> Result<()> {
    // Try to acquire lock to prevent concurrent remediation
    let Ok(_lock) = acquire_remediation_lock() else {
        println!("      Skipping remediation (another remediation in progress)");
        return Ok(());
    };

    // IMPORTANT: Reload state after acquiring lock to avoid race conditions
    // Between reading state in display_reviewer_health and acquiring the lock,
    // another process may have already remediated this reviewer
    let mut state = ReviewerStateFile::load()?;
    let Some(current_entry) = state.get_reviewer(reviewer_type) else {
        // Entry was already removed by another process
        println!(
            "      {} reviewer already cleaned up",
            capitalize(reviewer_type)
        );
        return Ok(());
    };

    // Verify the PID matches to ensure we're acting on the right entry
    if current_entry.pid != entry.pid {
        println!(
            "      {} reviewer PID changed ({}->{}), skipping",
            capitalize(reviewer_type),
            entry.pid,
            current_entry.pid
        );
        return Ok(());
    }

    // Check if the reviewer has already posted a machine-readable review
    // artifact bound to the recorded HEAD SHA. If so, the reviewer finished
    // and we don't need to restart.
    if is_review_completed_by_comment(
        sh,
        &current_entry.pr_url,
        &current_entry.head_sha,
        reviewer_type,
    ) {
        // Review completed. If we have captured output, validate it before
        // cleaning up so shallow/non-compliant reviews are automatically
        // re-run (bounded by restart_count).
        if let Some(path) = current_entry.last_message_file.as_ref() {
            match validate_reviewer_last_message(reviewer_type, &current_entry.head_sha, path) {
                Ok(()) => {
                    let cleaned = cleanup_reviewer_temp_files(&mut state, reviewer_type);
                    state.save()?;
                    if cleaned.is_empty() {
                        println!(
                            "      {} review completed, cleaning up state",
                            capitalize(reviewer_type)
                        );
                    } else {
                        println!(
                            "      {} review completed, cleaned up {} temp file(s)",
                            capitalize(reviewer_type),
                            cleaned.len()
                        );
                    }
                    return Ok(());
                },
                Err(reasons) => {
                    println!(
                        "      {} review completed, but output failed validation (will restart):",
                        capitalize(reviewer_type)
                    );
                    for reason in reasons {
                        println!("        - {reason}");
                    }
                    // Continue to restart logic below (do NOT clean up yet).
                },
            }
        } else {
            // No capture file (older state entries). Clean up as before.
            let cleaned = cleanup_reviewer_temp_files(&mut state, reviewer_type);
            state.save()?;
            println!(
                "      {} review completed (no capture file), cleaned up {} temp file(s)",
                capitalize(reviewer_type),
                cleaned.len()
            );
            return Ok(());
        }
    }

    // Check restart count limit
    if current_entry.restart_count >= MAX_RESTART_ATTEMPTS {
        println!(
            "      {} reviewer exceeded max restart attempts ({}), giving up",
            capitalize(reviewer_type),
            MAX_RESTART_ATTEMPTS
        );
        // Clean up all temp files but don't restart
        let _ = cleanup_reviewer_temp_files(&mut state, reviewer_type);
        state.save()?;
        return Ok(());
    }

    let elapsed = current_entry
        .get_log_mtime_elapsed()
        .map_or_else(|| "unknown".to_string(), |s| format!("{s}s"));

    println!(
        "      {} reviewer {} ({}), restarting (attempt {}/{})...",
        capitalize(reviewer_type),
        if health == HealthStatus::Stale {
            "stale"
        } else {
            "dead"
        },
        elapsed,
        current_entry.restart_count + 1,
        MAX_RESTART_ATTEMPTS
    );

    // Kill the stale/dead process
    if health == HealthStatus::Stale {
        let killed = kill_process(current_entry.pid);
        if killed {
            println!("      Killed process {}", current_entry.pid);
        }
    }

    // Save the PR URL and HEAD SHA before removing the entry
    let pr_url = current_entry.pr_url.clone();
    let head_sha = current_entry.head_sha.clone();
    let restart_count = current_entry.restart_count + 1;

    // Clean up old temp files and remove entry
    let _ = cleanup_reviewer_temp_files(&mut state, reviewer_type);
    state.save()?;

    // Re-trigger the review using the saved PR URL and HEAD SHA
    restart_review(sh, reviewer_type, &pr_url, &head_sha, restart_count)?;

    Ok(())
}

/// Check if a reviewer has already posted a machine-readable review artifact
/// bound to `head_sha`.
///
/// This deliberately does **not** rely on legacy commit statuses. The
/// authoritative signal is the comment artifact containing:
/// - the category marker (security/code-quality)
/// - the exact 40-hex head SHA
fn is_review_completed_by_comment(
    sh: &Shell,
    pr_url: &str,
    head_sha: &str,
    reviewer_type: &str,
) -> bool {
    // Align with `xtask review-gate` (MAX_COMMENT_PAGES) to avoid reviewer
    // churn on high-comment PRs.
    const MAX_PAGES: u32 = 50;

    let category = match reviewer_type {
        "security" => crate::tasks::review_gate::ReviewCategory::Security,
        "quality" => crate::tasks::review_gate::ReviewCategory::CodeQuality,
        _ => return false,
    };

    let Some((owner_repo, pr_number)) = parse_pr_url_for_check(pr_url) else {
        return false;
    };

    let Ok(trusted_reviewers) = crate::tasks::review_gate::load_trusted_reviewers_map(
        std::path::Path::new(".github/review-gate/trusted-reviewers.json"),
    ) else {
        return false; // fail-closed: cannot validate trust
    };

    for page in 1..=MAX_PAGES {
        let endpoint =
            format!("/repos/{owner_repo}/issues/{pr_number}/comments?per_page=100&page={page}");
        let output = cmd!(sh, "gh api {endpoint}").ignore_status().read().ok();

        let Some(payload) = output else {
            return false; // couldn't check, assume not completed
        };

        let comments: Vec<GithubIssueCommentForCheck> = match serde_json::from_str(&payload) {
            Ok(comments) => comments,
            Err(_) => return false,
        };

        if comments.is_empty() {
            break;
        }

        for comment in comments {
            let Some(body) = comment.body else {
                continue;
            };

            if crate::tasks::review_gate::is_authoritative_review_artifact_for_head(
                &body,
                category,
                pr_number.into(),
                head_sha,
                &trusted_reviewers,
                &comment.user.login,
            ) {
                return true;
            }
        }
    }

    false
}

#[derive(Debug, Deserialize)]
struct GithubIssueCommentForCheck {
    body: Option<String>,
    user: GithubIssueCommentUserForCheck,
}

#[derive(Debug, Deserialize)]
struct GithubIssueCommentUserForCheck {
    login: String,
}

fn parse_pr_url_for_check(pr_url: &str) -> Option<(String, u32)> {
    let url = pr_url.trim();
    let path = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let path = path.strip_prefix("github.com/")?;

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 4 || parts[2] != "pull" {
        return None;
    }

    let owner = parts[0];
    let repo = parts[1];
    let pr_number: u32 = parts[3].parse().ok()?;
    Some((format!("{owner}/{repo}"), pr_number))
}

/// Restart a review using the PR URL and HEAD SHA from the state file.
fn restart_review(
    sh: &Shell,
    reviewer_type: &str,
    pr_url: &str,
    head_sha: &str,
    restart_count: u32,
) -> Result<()> {
    let repo_root = cmd!(sh, "git rev-parse --show-toplevel")
        .read()
        .context("Failed to get repository root")?
        .trim()
        .to_string();

    let prompt_path = match reviewer_type {
        "security" => format!("{repo_root}/documents/reviews/SECURITY_REVIEW_PROMPT.md"),
        "quality" => format!("{repo_root}/documents/reviews/CODE_QUALITY_PROMPT.md"),
        _ => return Ok(()),
    };

    let prompt_path_ref = std::path::Path::new(&prompt_path);
    if !prompt_path_ref.exists() {
        println!("      Warning: Review prompt not found at {prompt_path}");
        return Ok(());
    }

    // Use ReviewerSpawner for centralized spawn logic
    let spawner = ReviewerSpawner::new(reviewer_type, pr_url, head_sha)
        .with_prompt_file(prompt_path_ref)?
        .with_model(select_review_model())
        .with_restart_count(restart_count);

    match spawner.spawn_background() {
        Some(result) => {
            println!(
                "      Restarted {} review (PID: {})",
                capitalize(reviewer_type),
                result.entry.pid
            );
        },
        None => {
            println!("      Failed to restart review");
        },
    }

    Ok(())
}

fn validate_reviewer_last_message(
    reviewer_type: &str,
    expected_head_sha: &str,
    path: &std::path::Path,
) -> std::result::Result<(), Vec<String>> {
    let mut reasons = Vec::new();

    let content = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(e) => {
            reasons.push(format!(
                "Could not read last-message capture file {}: {e}",
                path.display()
            ));
            return Err(reasons);
        },
    };

    let trimmed = content.trim();
    if trimmed.is_empty() {
        reasons.push("Last-message capture file is empty".to_string());
        return Err(reasons);
    }

    // Minimal size threshold: shallow reviews tend to be tiny and omit
    // required sections. Keep this conservative to avoid false restarts on
    // small PRs.
    if trimmed.len() < 800 {
        reasons.push(format!(
            "Review output too short ({} chars); expected a structured review comment",
            trimmed.len()
        ));
    }

    let (banner_prefix, marker, required_sections): (&str, &str, &[&str]) = match reviewer_type {
        "security" => (
            "## Security Review:",
            "<!-- apm2-review-metadata:v1:security -->",
            &[
                "Summary",
                "SCP Determination",
                "Markov Blanket",
                "Machine-Readable Metadata",
            ],
        ),
        "quality" => (
            "## Code Quality Review:",
            "<!-- apm2-review-metadata:v1:code-quality -->",
            &[
                "Summary",
                "Quality Analysis",
                "Lenses Applied",
                "Machine-Readable Metadata",
            ],
        ),
        _ => (
            "##",
            "<!-- apm2-review-metadata:v1:",
            &["Machine-Readable Metadata"],
        ),
    };

    if !trimmed.contains(banner_prefix) {
        reasons.push(format!(
            "Missing required verdict banner starting with `{banner_prefix}`"
        ));
    }

    if !trimmed.contains(marker) {
        reasons.push(format!("Missing required metadata marker `{marker}`"));
    }

    if !trimmed
        .to_ascii_lowercase()
        .contains(&expected_head_sha.to_ascii_lowercase())
    {
        reasons.push(format!(
            "Missing expected head SHA {expected_head_sha} in output (gate requires SHA binding)"
        ));
    }

    for section in required_sections {
        if !trimmed.contains(section) {
            reasons.push(format!("Missing required section keyword `{section}`"));
        }
    }

    let file_refs = count_file_references(trimmed);
    if file_refs < 5 {
        reasons.push(format!(
            "Too few file references ({file_refs}); expected at least 5 concrete file paths"
        ));
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

fn file_reference_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Conservative file reference matcher for APM2-style reviews.
        Regex::new(
            r"(?m)\b[\w./@-]+\.(?:rs|toml|yml|yaml|md|sh|json|proto|lock)(?::\d+(?::\d+)?)?\b",
        )
        .expect("file reference regex must compile")
    })
}

fn count_file_references(text: &str) -> usize {
    file_reference_regex().find_iter(text).count()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

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
        assert_eq!(
            parse_ci_status(json),
            CiStatus::Failure(vec!["test".to_string()])
        );
    }

    #[test]
    fn test_parse_ci_status_bucket_fail() {
        let json = r#"[
            {"name": "build", "state": "SUCCESS", "bucket": "fail"}
        ]"#;
        assert_eq!(
            parse_ci_status(json),
            CiStatus::Failure(vec!["build".to_string()])
        );
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
        assert_eq!(
            parse_ci_status(json),
            CiStatus::Failure(vec!["build".to_string()])
        );
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
        assert_eq!(
            parse_ci_status(json),
            CiStatus::Failure(vec!["test".to_string()])
        );
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
    fn test_parse_ci_status_cancelled() {
        // Per gh pr checks --help, "cancel" bucket indicates cancelled check
        let json = r#"[
            {"name": "build", "state": "COMPLETED", "bucket": "cancel"}
        ]"#;
        assert_eq!(
            parse_ci_status(json),
            CiStatus::Failure(vec!["build".to_string()])
        );
    }

    #[test]
    fn test_parse_ci_status_skipping() {
        // "skipping" bucket should be treated as success (not blocking)
        let json = r#"[
            {"name": "optional-check", "state": "COMPLETED", "bucket": "skipping"}
        ]"#;
        assert_eq!(parse_ci_status(json), CiStatus::Success);
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

    #[test]
    fn test_get_remediation_command_clippy() {
        assert_eq!(
            get_remediation_command("Clippy"),
            Some("cargo clippy --fix --allow-dirty")
        );
        assert_eq!(
            get_remediation_command("clippy-checks"),
            Some("cargo clippy --fix --allow-dirty")
        );
        assert_eq!(
            get_remediation_command("Run Clippy"),
            Some("cargo clippy --fix --allow-dirty")
        );
    }

    #[test]
    fn test_get_remediation_command_fmt() {
        assert_eq!(get_remediation_command("Fmt"), Some("cargo fmt"));
        assert_eq!(get_remediation_command("Format Check"), Some("cargo fmt"));
        assert_eq!(get_remediation_command("rust-fmt"), Some("cargo fmt"));
    }

    #[test]
    fn test_get_remediation_command_test() {
        assert_eq!(
            get_remediation_command("Test"),
            Some("cargo test --workspace")
        );
        assert_eq!(
            get_remediation_command("Unit Tests"),
            Some("cargo test --workspace")
        );
        assert_eq!(
            get_remediation_command("integration-test"),
            Some("cargo test --workspace")
        );
    }

    #[test]
    fn test_get_remediation_command_security_review() {
        assert_eq!(
            get_remediation_command("Security Review"),
            Some("cargo xtask push --force-review")
        );
        assert_eq!(
            get_remediation_command("security-review-check"),
            Some("cargo xtask push --force-review")
        );
    }

    #[test]
    fn test_get_remediation_command_quality_review() {
        assert_eq!(
            get_remediation_command("Quality Review"),
            Some("cargo xtask push --force-review")
        );
        assert_eq!(
            get_remediation_command("code-quality-review"),
            Some("cargo xtask push --force-review")
        );
    }

    #[test]
    fn test_get_remediation_command_semver() {
        assert_eq!(
            get_remediation_command("SemverCheck"),
            Some("cargo semver-checks")
        );
        assert_eq!(
            get_remediation_command("semver-checks"),
            Some("cargo semver-checks")
        );
    }

    #[test]
    fn test_get_remediation_command_unknown() {
        assert_eq!(get_remediation_command("Unknown Check"), None);
        assert_eq!(get_remediation_command("build"), None);
        assert_eq!(get_remediation_command("deploy"), None);
    }

    #[test]
    fn test_parse_ci_status_multiple_failures() {
        let json = r#"[
            {"name": "Clippy", "state": "FAILURE", "bucket": "fail"},
            {"name": "Test", "state": "FAILURE", "bucket": "fail"}
        ]"#;
        let result = parse_ci_status(json);
        match result {
            CiStatus::Failure(failed) => {
                assert_eq!(failed.len(), 2);
                assert!(failed.contains(&"Clippy".to_string()));
                assert!(failed.contains(&"Test".to_string()));
            },
            _ => panic!("Expected CiStatus::Failure"),
        }
    }

    // Tests for WatchExitReason

    #[test]
    fn test_watch_exit_reason_merged_exit_code() {
        let reason = WatchExitReason::Merged;
        assert_eq!(reason.exit_code(), 0);
    }

    #[test]
    fn test_watch_exit_reason_closed_exit_code() {
        let reason = WatchExitReason::Closed;
        assert_eq!(reason.exit_code(), 1);
    }

    #[test]
    fn test_watch_exit_reason_ci_failed_exit_code() {
        let reason = WatchExitReason::CiFailed(vec!["test".to_string()]);
        assert_eq!(reason.exit_code(), 1);
    }

    #[test]
    fn test_watch_exit_reason_changes_requested_exit_code() {
        let reason = WatchExitReason::ChangesRequested;
        assert_eq!(reason.exit_code(), 1);
    }

    #[test]
    fn test_watch_exit_reason_timeout_exit_code() {
        let reason = WatchExitReason::Timeout;
        assert_eq!(reason.exit_code(), 2);
    }

    #[test]
    fn test_watch_exit_reason_merged_message() {
        let reason = WatchExitReason::Merged;
        assert_eq!(reason.message(), "PR merged successfully!");
    }

    #[test]
    fn test_watch_exit_reason_closed_message() {
        let reason = WatchExitReason::Closed;
        assert_eq!(reason.message(), "PR was closed without merging.");
    }

    #[test]
    fn test_watch_exit_reason_ci_failed_message() {
        let reason = WatchExitReason::CiFailed(vec!["test".to_string(), "lint".to_string()]);
        let msg = reason.message();
        assert!(msg.contains("CI failed: test, lint"));
        assert!(msg.contains("Fix the failures and push again."));
    }

    #[test]
    fn test_watch_exit_reason_changes_requested_message() {
        let reason = WatchExitReason::ChangesRequested;
        let msg = reason.message();
        assert!(msg.contains("Changes requested by reviewer."));
        assert!(msg.contains("Address feedback and push again."));
    }

    #[test]
    fn test_watch_exit_reason_timeout_message() {
        let reason = WatchExitReason::Timeout;
        let msg = reason.message();
        assert!(msg.contains("Timeout after 180s waiting for checks."));
        assert!(msg.contains("Suggestion: Manually restart slow checks or investigate CI."));
    }

    #[test]
    fn test_watch_timeout_constant() {
        // Verify the timeout constant is 180 seconds as required
        assert_eq!(WATCH_TIMEOUT_SECS, 180);
    }

    #[test]
    fn test_exit_timeout_constant() {
        // Verify the timeout exit code is 2 as required
        assert_eq!(EXIT_TIMEOUT, 2);
    }

    #[test]
    fn test_parse_pr_url_for_check_accepts_valid_urls() {
        assert_eq!(
            parse_pr_url_for_check("https://github.com/guardian-intelligence/apm2/pull/502"),
            Some(("guardian-intelligence/apm2".to_string(), 502))
        );
        assert_eq!(
            parse_pr_url_for_check("http://github.com/guardian-intelligence/apm2/pull/1"),
            Some(("guardian-intelligence/apm2".to_string(), 1))
        );
        assert_eq!(
            parse_pr_url_for_check("github.com/guardian-intelligence/apm2/pull/999"),
            Some(("guardian-intelligence/apm2".to_string(), 999))
        );
    }

    #[test]
    fn test_parse_pr_url_for_check_rejects_invalid_urls() {
        assert_eq!(parse_pr_url_for_check(""), None);
        assert_eq!(
            parse_pr_url_for_check("https://example.com/x/y/pull/1"),
            None
        );
        assert_eq!(
            parse_pr_url_for_check("https://github.com/guardian-intelligence/apm2/issues/1"),
            None
        );
        assert_eq!(
            parse_pr_url_for_check(
                "https://github.com/guardian-intelligence/apm2/pull/not-a-number"
            ),
            None
        );
    }

    #[test]
    fn test_count_file_references_counts_paths_and_line_numbers() {
        let text = r"
Some findings:
- crates/apm2-cli/src/commands/ci.rs:42
- .github/workflows/ci.yml:12:3
- documents/reviews/CI_EXPECTATIONS.md
- scripts/ci/run_bounded_tests.sh:216
- proto/kernel_events.proto:1
";
        assert_eq!(count_file_references(text), 5);
    }

    #[test]
    fn test_validate_reviewer_last_message_quality_happy_path() {
        let sha = "a".repeat(40);
        let mut file = NamedTempFile::new().expect("temp file");

        // Ensure output is large enough to avoid "too short" restarts.
        let filler = "x".repeat(900);
        let body = format!(
            r#"## Code Quality Review: PASS

Summary
This is a synthetic review body for testing.

Quality Analysis
Notes.

Lenses Applied
Notes.

Machine-Readable Metadata

Evidence references:
- crates/apm2-cli/src/commands/ci.rs:42
- .github/workflows/ci.yml:12
- documents/reviews/CI_EXPECTATIONS.md:31
- scripts/ci/run_bounded_tests.sh:216
- proto/kernel_events.proto:1

{sha}

<!-- apm2-review-metadata:v1:code-quality -->
```json
{{"schema":"apm2.review.metadata.v1","review_type":"code-quality","pr_number":1,"head_sha":"{sha}","verdict":"PASS","severity_counts":{{"blocker":0,"major":0,"minor":0,"nit":0}},"reviewer_id":"apm2-codex-quality"}}
```

{filler}
"#
        );
        file.write_all(body.as_bytes()).expect("write body");

        let result = validate_reviewer_last_message("quality", &sha, file.path());
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn test_validate_reviewer_last_message_quality_missing_sections() {
        let sha = "b".repeat(40);
        let mut file = NamedTempFile::new().expect("temp file");

        let body = format!(
            r#"## Code Quality Review: PASS

Summary
Only summary present.

{sha}

<!-- apm2-review-metadata:v1:code-quality -->
```json
{{"schema":"apm2.review.metadata.v1","review_type":"code-quality","pr_number":1,"head_sha":"{sha}","verdict":"PASS","severity_counts":{{"blocker":0,"major":0,"minor":0,"nit":0}},"reviewer_id":"apm2-codex-quality"}}
```

crates/apm2-cli/src/commands/ci.rs:42
.github/workflows/ci.yml:12
documents/reviews/CI_EXPECTATIONS.md:31
scripts/ci/run_bounded_tests.sh:216
proto/kernel_events.proto:1

{}
"#,
            "x".repeat(900)
        );
        file.write_all(body.as_bytes()).expect("write body");

        let result = validate_reviewer_last_message("quality", &sha, file.path());
        let Err(reasons) = result else {
            panic!("expected Err for missing sections");
        };

        // We should detect missing key sections.
        let joined = reasons.join("\n");
        assert!(joined.contains("Missing required section keyword `Quality Analysis`"));
        assert!(joined.contains("Missing required section keyword `Lenses Applied`"));
        assert!(joined.contains("Missing required section keyword `Machine-Readable Metadata`"));
    }
}
