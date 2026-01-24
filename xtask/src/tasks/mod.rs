//! Task implementations for xtask commands.
//!
//! Each function corresponds to a subcommand in the CLI.
//! Implemented commands have their own modules; stubs remain for unimplemented
//! ones.

mod check;
mod commit;
mod finish;
mod push;
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
