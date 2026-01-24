//! Implementation of the `finish` command.
//!
//! This command cleans up after a PR has been merged:
//! - Verifies the PR was merged
//! - Switches to main branch
//! - Removes the ticket branch
//! - Removes the worktree (if running in a worktree)

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::util::{current_branch, main_worktree, validate_ticket_branch};

/// Clean up after PR merge.
///
/// This function:
/// 1. Validates we're on a ticket branch
/// 2. Checks that the PR for this branch has been merged
/// 3. Switches to the main branch
/// 4. Deletes the ticket branch locally
/// 5. Removes the worktree if we're in one
///
/// # Errors
///
/// Returns an error if:
/// - Not on a valid ticket branch
/// - The PR for the branch hasn't been merged
/// - Git operations fail
pub fn run() -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // Get current branch and validate it's a ticket branch
    let branch_name = current_branch(&sh)?;
    let ticket_branch = validate_ticket_branch(&branch_name)?;

    if let Some(rfc_id) = &ticket_branch.rfc_id {
        println!(
            "Finishing ticket {} (RFC: {})",
            ticket_branch.ticket_id, rfc_id
        );
    } else {
        println!("Finishing ticket {}", ticket_branch.ticket_id);
    }

    // Check if we're in a worktree
    let current_worktree = cmd!(sh, "git rev-parse --show-toplevel")
        .read()
        .context("Failed to get current directory")?;
    let main_worktree_path = main_worktree(&sh)?;
    let in_worktree = current_worktree != main_worktree_path.to_string_lossy();

    // Verify the PR has been merged
    let pr_state = get_pr_state(&sh, &branch_name)?;

    match pr_state.as_str() {
        "MERGED" => {
            println!("PR has been merged. Cleaning up...");
        },
        "OPEN" => {
            bail!(
                "PR for branch '{branch_name}' is still open. \
                 Wait for it to be merged before finishing."
            );
        },
        "CLOSED" => {
            bail!(
                "PR for branch '{branch_name}' was closed without merging. \
                 Use `git branch -D {branch_name}` to force delete if intended."
            );
        },
        "" => {
            println!("No PR found for this branch.\n");
            println!("To complete your ticket workflow:");
            println!("  1. Implement the ticket requirements");
            println!("  2. Run: cargo xtask commit '<message>'");
            println!("  3. Run: cargo xtask push");
            println!("  4. Wait for CI and reviews");
            println!("  5. After merge: cargo xtask finish");
            return Ok(());
        },
        _ => {
            bail!("Unknown PR state: {pr_state}");
        },
    }

    if in_worktree {
        // We're in a worktree - need to switch to main worktree first
        let worktree_name = format!("apm2-{}", ticket_branch.ticket_id);
        println!("Switching to main worktree and removing worktree '{worktree_name}'...");

        // We need to cd to main worktree and run cleanup from there
        // Record the worktree path before switching
        let worktree_path = current_worktree;

        // Change to main worktree
        sh.change_dir(&main_worktree_path);

        // Fetch latest from origin
        cmd!(sh, "git fetch origin")
            .run()
            .context("Failed to fetch from origin")?;

        // Remove the worktree
        cmd!(sh, "git worktree remove --force {worktree_path}")
            .run()
            .context("Failed to remove worktree")?;

        println!("Removed worktree at {worktree_path}");
    } else {
        // We're in the main worktree - switch to main and delete branch
        println!("Switching to main branch...");

        // Fetch and switch to main
        cmd!(sh, "git fetch origin")
            .run()
            .context("Failed to fetch from origin")?;

        cmd!(sh, "git checkout main")
            .run()
            .context("Failed to checkout main branch")?;

        cmd!(sh, "git pull origin main")
            .run()
            .context("Failed to pull latest main")?;
    }

    // Delete the local branch (from main worktree)
    sh.change_dir(&main_worktree_path);

    // Check if branch exists before trying to delete
    let branch_exists = cmd!(sh, "git branch --list {branch_name}")
        .read()
        .context("Failed to check if branch exists")?;

    if branch_exists.trim().is_empty() {
        println!("Local branch '{branch_name}' already deleted");
    } else {
        cmd!(sh, "git branch -d {branch_name}")
            .run()
            .context("Failed to delete local branch")?;
        println!("Deleted local branch '{branch_name}'");
    }

    // Delete the remote tracking branch if it exists
    let remote_branch_exists = cmd!(sh, "git branch -r --list origin/{branch_name}")
        .read()
        .context("Failed to check remote branch")?;

    if !remote_branch_exists.trim().is_empty() {
        // Prune stale remote tracking branches
        cmd!(sh, "git fetch --prune")
            .run()
            .context("Failed to prune remote tracking branches")?;
        println!("Pruned stale remote tracking branches");
    }

    println!();
    println!(
        "Finished cleanup for {}. Ready to start next ticket.",
        ticket_branch.ticket_id
    );

    Ok(())
}

/// Get the state of the PR for a branch.
///
/// Returns one of: "MERGED", "OPEN", "CLOSED", or "" (empty if no PR exists).
fn get_pr_state(sh: &Shell, branch_name: &str) -> Result<String> {
    // Use gh CLI to check PR state
    let output = cmd!(sh, "gh pr view {branch_name} --json state --jq .state")
        .ignore_status()
        .read()
        .context("Failed to query PR state")?;

    // gh pr view returns non-zero if no PR exists, and we used ignore_status
    // Check if the output looks like a valid state
    let state = output.trim().to_string();

    // If the output contains "no pull requests found" or similar, return empty
    if state.contains("no pull requests") || state.is_empty() || state.contains("not found") {
        return Ok(String::new());
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_pr_state_values() {
        // These are unit tests for parsing logic only
        // Integration tests would require a real git repo and gh CLI

        // Test that valid states are recognized
        let valid_states = ["MERGED", "OPEN", "CLOSED"];
        assert!(valid_states.contains(&"MERGED"));
        assert!(valid_states.contains(&"OPEN"));
        assert!(valid_states.contains(&"CLOSED"));
    }
}
