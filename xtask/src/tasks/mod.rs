//! Task implementations for xtask commands.
//!
//! Each function corresponds to a subcommand in the CLI.
//! Implemented commands have their own modules; stubs remain for unimplemented
//! ones.

mod check;
mod commit;
mod finish;
mod push;
mod review;
mod security_review_exec;
mod start_ticket;

use anyhow::Result;

/// Start work on the next unblocked ticket for an RFC.
///
/// Delegates to the `start_ticket` module for the actual implementation.
///
/// # Arguments
///
/// * `rfc_id` - The RFC ID (e.g., "RFC-0002")
/// * `print_path_only` - If true, only print the worktree path (for scripting)
///
/// # Errors
///
/// Returns an error if the setup fails. See [`start_ticket::run`] for details.
pub fn start_ticket(rfc_id: &str, print_path_only: bool) -> Result<()> {
    start_ticket::run(rfc_id, print_path_only)
}

/// Run checks and create a commit.
///
/// Delegates to the commit module for the actual implementation.
///
/// # Errors
///
/// Returns an error if the checks or commit fail. See [`commit::run`] for
/// details.
pub fn commit(message: &str) -> Result<()> {
    commit::run(message)
}

/// Push branch and create PR with AI reviews.
///
/// Delegates to the push module for the actual implementation.
///
/// # Errors
///
/// Returns an error if the push fails. See [`push::run`] for details.
pub fn push() -> Result<()> {
    push::run()
}

/// Show ticket and PR status.
///
/// Delegates to the check module for the actual implementation.
///
/// # Arguments
///
/// * `watch` - If true, continuously poll status every 10 seconds
///
/// # Errors
///
/// Returns an error if the status check fails. See [`check::run`] for details.
pub fn check(watch: bool) -> Result<()> {
    check::run(watch)
}

/// Clean up after PR merge.
///
/// Delegates to the finish module for the actual implementation.
///
/// # Errors
///
/// Returns an error if the cleanup fails. See [`finish::run`] for details.
pub fn finish() -> Result<()> {
    finish::run()
}

/// Run a security review for a PR.
///
/// Delegates to the review module for the actual implementation.
///
/// # Errors
///
/// Returns an error if the review fails. See [`review::run_security`] for
/// details.
pub fn review_security(pr_url: &str) -> Result<()> {
    review::run_security(pr_url)
}

/// Run a code quality review for a PR.
///
/// Delegates to the review module for the actual implementation.
///
/// # Errors
///
/// Returns an error if the review fails. See [`review::run_quality`] for
/// details.
pub fn review_quality(pr_url: &str) -> Result<()> {
    review::run_quality(pr_url)
}

/// Run a UAT sign-off for a PR.
///
/// Delegates to the review module for the actual implementation.
///
/// # Errors
///
/// Returns an error if the review fails. See [`review::run_uat`] for details.
pub fn review_uat(pr_url: &str) -> Result<()> {
    review::run_uat(pr_url)
}

/// Approve a PR after security review.
///
/// Delegates to the `security_review_exec` module.
///
/// # Arguments
///
/// * `pr_url` - The GitHub PR URL
/// * `dry_run` - If true, preview without making API calls
///
/// # Errors
///
/// Returns an error if the PR is invalid or the API calls fail.
/// See [`security_review_exec::approve`] for details.
pub fn security_review_exec_approve(pr_url: &str, dry_run: bool) -> Result<()> {
    security_review_exec::approve(pr_url, dry_run)
}

/// Deny a PR with a required reason.
///
/// Delegates to the `security_review_exec` module.
///
/// # Arguments
///
/// * `pr_url` - The GitHub PR URL
/// * `reason` - The reason for denial
/// * `dry_run` - If true, preview without making API calls
///
/// # Errors
///
/// Returns an error if the PR is invalid or the API calls fail.
/// See [`security_review_exec::deny`] for details.
pub fn security_review_exec_deny(pr_url: &str, reason: &str, dry_run: bool) -> Result<()> {
    security_review_exec::deny(pr_url, reason, dry_run)
}

/// Show required reading for security reviewers.
///
/// Delegates to the `security_review_exec` module.
///
/// # Errors
///
/// Returns an error if output fails. See [`security_review_exec::onboard`] for
/// details.
pub fn security_review_exec_onboard() -> Result<()> {
    security_review_exec::onboard()
}
