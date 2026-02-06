//! Task implementations for xtask commands.
//!
//! Each function corresponds to a subcommand in the CLI.
//! Implemented commands have their own modules; stubs remain for unimplemented
//! ones.

mod aat;
pub mod capabilities;
mod check;
mod commit;
mod finish;
pub mod lint;
mod push;
mod review;
mod security_review_exec;
pub mod selftest;
mod start_ticket;

use anyhow::Result;

/// Start work on the next unblocked ticket.
///
/// Delegates to the `start_ticket` module for the actual implementation.
///
/// # Arguments
///
/// * `target` - Optional RFC ID (RFC-XXXX), ticket ID (TCK-XXXXX), or None for
///   earliest unblocked globally
/// * `print_path_only` - If true, only print the worktree path (for scripting)
/// * `force` - If true, auto-cleanup remediable worktree issues
///
/// # Errors
///
/// Returns an error if the setup fails. See [`start_ticket::run`] for details.
pub fn start_ticket(target: Option<&str>, print_path_only: bool, force: bool) -> Result<()> {
    start_ticket::run(target, print_path_only, force)
}

/// Run checks and create a commit.
///
/// Delegates to the commit module for the actual implementation.
///
/// # Arguments
///
/// * `message` - The commit message
/// * `skip_checks` - If true, skip all pre-commit checks (fmt, clippy, test)
///
/// # Errors
///
/// Returns an error if the checks or commit fail. See [`commit::run`] for
/// details.
pub fn commit(message: &str, skip_checks: bool) -> Result<()> {
    commit::run(message, skip_checks)
}

/// Push branch and create PR with AI reviews.
///
/// Delegates to the push module for the actual implementation.
///
/// # Arguments
///
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
///
/// # Errors
///
/// Returns an error if the push fails. See [`push::run`] for details.
pub fn push(emit_receipt_only: bool, allow_github_write: bool) -> Result<()> {
    push::run(emit_receipt_only, allow_github_write)
}

/// Show ticket and PR status.
///
/// Delegates to the check module for the actual implementation.
///
/// # Arguments
///
/// * `watch` - If true, continuously poll status every 10 seconds
///
/// # Returns
///
/// Returns `Ok(())` but may call `std::process::exit()` with appropriate exit
/// code in watch mode:
/// - 0: Normal completion or PR merged
/// - 1: Terminal failure state (closed, CI failed, changes requested)
/// - 2: Watch mode timeout
///
/// # Errors
///
/// Returns an error if the status check fails. See [`check::run`] for details.
pub fn check(watch: bool) -> Result<()> {
    let exit_code = check::run(watch)?;
    // Exit with the appropriate code if not success
    if exit_code != 0 {
        std::process::exit(i32::from(exit_code));
    }
    Ok(())
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
/// # Arguments
///
/// * `pr_url` - GitHub PR URL
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
///
/// # Errors
///
/// Returns an error if the review fails. See [`review::run_security`] for
/// details.
pub fn review_security(
    pr_url: &str,
    emit_internal: bool,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    review::run_security(pr_url, emit_internal, emit_receipt_only, allow_github_write)
}

/// Run a code quality review for a PR.
///
/// Delegates to the review module for the actual implementation.
///
/// # Arguments
///
/// * `pr_url` - GitHub PR URL
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
///
/// # Errors
///
/// Returns an error if the review fails. See [`review::run_quality`] for
/// details.
pub fn review_quality(
    pr_url: &str,
    emit_internal: bool,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    review::run_quality(pr_url, emit_internal, emit_receipt_only, allow_github_write)
}

/// Run a UAT sign-off for a PR.
///
/// Delegates to the review module for the actual implementation.
///
/// # Arguments
///
/// * `pr_url` - GitHub PR URL
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
///
/// # Errors
///
/// Returns an error if the review fails. See [`review::run_uat`] for details.
pub fn review_uat(
    pr_url: &str,
    emit_internal: bool,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    review::run_uat(pr_url, emit_internal, emit_receipt_only, allow_github_write)
}

/// Approve a PR after security review.
///
/// Delegates to the `security_review_exec` module.
///
/// # Arguments
///
/// * `ticket_id` - Optional ticket ID. If None, uses current branch.
/// * `dry_run` - If true, preview without making API calls
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
///
/// # Errors
///
/// Returns an error if the PR is invalid or the API calls fail.
/// See [`security_review_exec::approve`] for details.
pub fn security_review_exec_approve(
    ticket_id: Option<&str>,
    dry_run: bool,
    emit_internal: bool,
) -> Result<()> {
    security_review_exec::approve(ticket_id, dry_run, emit_internal)
}

/// Deny a PR with a required reason.
///
/// Delegates to the `security_review_exec` module.
///
/// # Arguments
///
/// * `ticket_id` - Optional ticket ID. If None, uses current branch.
/// * `reason` - The reason for denial
/// * `dry_run` - If true, preview without making API calls
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
///
/// # Errors
///
/// Returns an error if the PR is invalid or the API calls fail.
/// See [`security_review_exec::deny`] for details.
pub fn security_review_exec_deny(
    ticket_id: Option<&str>,
    reason: &str,
    dry_run: bool,
    emit_internal: bool,
) -> Result<()> {
    security_review_exec::deny(ticket_id, reason, dry_run, emit_internal)
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

/// Run Agent Acceptance Testing (AAT) on a PR.
///
/// Delegates to the `aat` module for the actual implementation.
///
/// # Arguments
///
/// * `pr_url` - GitHub PR URL
/// * `dry_run` - If true, don't set status check or write evidence
/// * `ai_tool_override` - Optional AI tool override from CLI flag
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
///
/// # Returns
///
/// Returns `Ok(())` on completion. The verdict is printed to stdout.
/// The process exits with appropriate code:
/// - 0: Success (PASSED verdict)
/// - 1: Failure (FAILED verdict)
/// - 2: Invalid arguments or `NEEDS_ADJUDICATION`
///
/// # Errors
///
/// Returns an error if the AAT process fails. See [`aat::run`] for details.
pub fn aat(
    pr_url: &str,
    dry_run: bool,
    ai_tool_override: Option<crate::aat::tool_config::AiTool>,
    emit_internal: bool,
) -> Result<()> {
    let result = aat::run(pr_url, dry_run, ai_tool_override, emit_internal)?;
    // Exit with appropriate code based on verdict
    match result.verdict {
        crate::aat::types::Verdict::Passed => Ok(()),
        crate::aat::types::Verdict::Failed => std::process::exit(1),
        crate::aat::types::Verdict::NeedsAdjudication => std::process::exit(2),
    }
}
