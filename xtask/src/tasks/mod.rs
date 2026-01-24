//! Task implementations for xtask commands.
//!
//! Each function corresponds to a subcommand in the CLI.
//! These are stubs that will be implemented in subsequent tickets.

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
/// # Errors
///
/// Returns an error as this is not yet implemented.
pub fn check() -> Result<()> {
    bail!(
        "check command not yet implemented\n\
         This will be implemented in TCK-00029."
    );
}

/// Clean up after PR merge.
///
/// # Errors
///
/// Returns an error as this is not yet implemented.
pub fn finish() -> Result<()> {
    bail!(
        "finish command not yet implemented\n\
         This will be implemented in TCK-00028."
    );
}
