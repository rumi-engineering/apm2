//! Task implementations for xtask commands.
//!
//! Each function corresponds to a subcommand in the CLI.
//! Implemented commands have their own modules; stubs remain for unimplemented
//! ones.

mod check;
mod finish;

use anyhow::{Result, bail};

/// Start work on the next unblocked ticket for an RFC.
///
/// # Errors
///
/// Returns an error as this is not yet implemented.
pub fn start_ticket(rfc_id: &str) -> Result<()> {
    bail!(
        "start-ticket command not yet implemented (RFC: {rfc_id})\n\
         This will be implemented in TCK-00030."
    );
}

/// Run checks and create a commit.
///
/// # Errors
///
/// Returns an error as this is not yet implemented.
pub fn commit(message: &str) -> Result<()> {
    bail!(
        "commit command not yet implemented (message: {message:?})\n\
         This will be implemented in TCK-00031."
    );
}

/// Push branch and create PR with AI reviews.
///
/// # Errors
///
/// Returns an error as this is not yet implemented.
pub fn push() -> Result<()> {
    bail!(
        "push command not yet implemented\n\
         This will be implemented in TCK-00032."
    );
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
