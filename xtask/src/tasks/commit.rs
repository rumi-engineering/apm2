//! Implementation of the `commit` command.
//!
//! This command runs checks and creates a commit:
//! - Validates we're on a ticket branch
//! - Runs cargo fmt --check
//! - Runs cargo clippy with all warnings as errors
//! - Runs cargo test for xtask crate
//! - Stages all changes and creates a commit

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::util::{current_branch, validate_ticket_branch};

/// Run checks and create a commit.
///
/// This function:
/// 1. Validates we're on a ticket branch
/// 2. Runs cargo fmt --check
/// 3. Runs cargo clippy --all-targets -- -D warnings
/// 4. Runs cargo test -p xtask
/// 5. Stages all changes and creates a commit
///
/// # Arguments
///
/// * `message` - The commit message
///
/// # Errors
///
/// Returns an error if:
/// - Not on a valid ticket branch
/// - Any of the checks fail (fmt, clippy, test)
/// - No changes to commit
/// - Git operations fail
pub fn run(message: &str) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // Get current branch and validate it's a ticket branch
    let branch_name = current_branch(&sh)?;
    let ticket_branch = validate_ticket_branch(&branch_name)?;

    // Check if there are any changes to commit (before running expensive checks)
    let status = cmd!(sh, "git status --porcelain")
        .read()
        .context("Failed to check git status")?;

    if status.trim().is_empty() {
        bail!("No changes to commit. Make some changes first.");
    }

    println!(
        "Running checks for ticket {} (RFC: {})",
        ticket_branch.ticket_id, ticket_branch.rfc_id
    );

    // Run cargo fmt --check
    println!("\n[1/3] Running cargo fmt --check...");
    cmd!(sh, "cargo fmt --check")
        .run()
        .context("cargo fmt --check failed. Run 'cargo fmt' to fix formatting.")?;
    println!("  Formatting check passed.");

    // Run cargo clippy
    println!("\n[2/3] Running cargo clippy...");
    cmd!(sh, "cargo clippy --all-targets -- -D warnings")
        .run()
        .context("cargo clippy found warnings or errors. Fix them before committing.")?;
    println!("  Clippy check passed.");

    // Run cargo test for xtask
    println!("\n[3/3] Running cargo test -p xtask...");
    cmd!(sh, "cargo test -p xtask")
        .run()
        .context("cargo test -p xtask failed. Fix the tests before committing.")?;
    println!("  Tests passed.");

    println!("\nAll checks passed. Creating commit...");

    // Stage modified and deleted tracked files only (not untracked files to avoid
    // staging secrets)
    cmd!(sh, "git add -u")
        .run()
        .context("Failed to stage changes")?;

    // Create the commit with the ticket ID prefix
    let commit_message = format!("feat({}): {}", ticket_branch.ticket_id, message);

    cmd!(sh, "git commit -m {commit_message}")
        .run()
        .context("Failed to create commit")?;

    println!("\nCommit created: {commit_message}");

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_commit_message_format() {
        // Test that commit message format is as expected
        let ticket_id = "TCK-00031";
        let message = "implement commit command";
        let commit_message = format!("feat({ticket_id}): {message}");
        assert_eq!(commit_message, "feat(TCK-00031): implement commit command");
    }
}
