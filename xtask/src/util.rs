//! Shared utilities for xtask commands.
//!
//! This module provides common functions used across multiple commands:
//! - Branch validation and parsing
//! - Worktree path finding
//! - Ticket YAML path construction

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use xshell::{Shell, cmd};

/// Regex pattern for validating ticket branch names.
///
/// Valid format: `ticket/RFC-XXXX/TCK-XXXXX`
/// Where XXXX is 4 digits and XXXXX is 5 digits.
static TICKET_BRANCH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^ticket/(RFC-\d{4})/(TCK-\d{5})$")
        .expect("Invalid regex pattern for ticket branch")
});

/// Parsed ticket branch information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketBranch {
    /// The RFC ID (e.g., "RFC-0002")
    pub rfc_id: String,
    /// The ticket ID (e.g., "TCK-00027")
    pub ticket_id: String,
}

/// Validates a branch name and extracts RFC and ticket IDs.
///
/// # Arguments
///
/// * `branch_name` - The git branch name to validate
///
/// # Returns
///
/// Returns `Ok(TicketBranch)` with the parsed IDs if the branch name matches
/// the expected format `ticket/RFC-XXXX/TCK-XXXXX`.
///
/// # Errors
///
/// Returns an error if the branch name does not match the expected format.
///
/// # Examples
///
/// ```
/// # use xtask::util::validate_ticket_branch;
/// let result = validate_ticket_branch("ticket/RFC-0002/TCK-00027");
/// assert!(result.is_ok());
/// let branch = result.unwrap();
/// assert_eq!(branch.rfc_id, "RFC-0002");
/// assert_eq!(branch.ticket_id, "TCK-00027");
/// ```
pub fn validate_ticket_branch(branch_name: &str) -> Result<TicketBranch> {
    let captures = TICKET_BRANCH_REGEX.captures(branch_name).with_context(|| {
        format!(
            "Invalid branch name: '{branch_name}'\n\
                 Expected format: ticket/RFC-XXXX/TCK-XXXXX\n\
                 Example: ticket/RFC-0002/TCK-00027"
        )
    })?;

    Ok(TicketBranch {
        rfc_id: captures
            .get(1)
            .expect("RFC ID capture group missing")
            .as_str()
            .to_string(),
        ticket_id: captures
            .get(2)
            .expect("Ticket ID capture group missing")
            .as_str()
            .to_string(),
    })
}

/// Finds the path to the main worktree from any worktree.
///
/// Uses `git worktree list` to find all worktrees and returns the path
/// to the main (bare) worktree, which is always listed first.
///
/// # Arguments
///
/// * `sh` - The xshell Shell instance
///
/// # Returns
///
/// Returns the absolute path to the main worktree.
///
/// # Errors
///
/// Returns an error if:
/// - Not in a git repository
/// - Cannot parse the output of `git worktree list`
pub fn main_worktree(sh: &Shell) -> Result<PathBuf> {
    let output = cmd!(sh, "git worktree list --porcelain")
        .read()
        .context("Failed to list git worktrees")?;

    // The first "worktree" line in porcelain output is the main worktree
    for line in output.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            return Ok(PathBuf::from(path));
        }
    }

    bail!("Could not find main worktree in git worktree list output")
}

/// Constructs the path to a ticket's YAML metadata file.
///
/// # Arguments
///
/// * `main_worktree_path` - Path to the main worktree
/// * `ticket_id` - The ticket ID (e.g., "TCK-00027")
///
/// # Returns
///
/// Returns the path to the ticket YAML file.
///
/// # Examples
///
/// ```
/// # use std::path::Path;
/// # use xtask::util::ticket_yaml_path;
/// let main = Path::new("/home/user/project");
/// let path = ticket_yaml_path(main, "TCK-00027");
/// assert_eq!(
///     path.to_str().unwrap(),
///     "/home/user/project/documents/work/tickets/TCK-00027.yaml"
/// );
/// ```
#[must_use]
pub fn ticket_yaml_path(main_worktree_path: &Path, ticket_id: &str) -> PathBuf {
    main_worktree_path
        .join("documents")
        .join("work")
        .join("tickets")
        .join(format!("{ticket_id}.yaml"))
}

/// Gets the current git branch name.
///
/// # Arguments
///
/// * `sh` - The xshell Shell instance
///
/// # Returns
///
/// Returns the name of the current branch.
///
/// # Errors
///
/// Returns an error if not on a branch (e.g., detached HEAD) or not in a git
/// repo.
pub fn current_branch(sh: &Shell) -> Result<String> {
    let branch = cmd!(sh, "git rev-parse --abbrev-ref HEAD")
        .read()
        .context("Failed to get current branch name")?;

    if branch == "HEAD" {
        bail!("Not on a branch (detached HEAD state)");
    }

    Ok(branch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ticket_branch_valid() {
        let result = validate_ticket_branch("ticket/RFC-0002/TCK-00027");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, "RFC-0002");
        assert_eq!(branch.ticket_id, "TCK-00027");
    }

    #[test]
    fn test_validate_ticket_branch_valid_different_ids() {
        let result = validate_ticket_branch("ticket/RFC-0001/TCK-00001");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, "RFC-0001");
        assert_eq!(branch.ticket_id, "TCK-00001");
    }

    #[test]
    fn test_validate_ticket_branch_valid_high_numbers() {
        let result = validate_ticket_branch("ticket/RFC-9999/TCK-99999");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, "RFC-9999");
        assert_eq!(branch.ticket_id, "TCK-99999");
    }

    #[test]
    fn test_validate_ticket_branch_invalid_missing_prefix() {
        let result = validate_ticket_branch("RFC-0002/TCK-00027");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid branch name"));
    }

    #[test]
    fn test_validate_ticket_branch_invalid_wrong_rfc_format() {
        let result = validate_ticket_branch("ticket/RFC-02/TCK-00027");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_wrong_ticket_format() {
        let result = validate_ticket_branch("ticket/RFC-0002/TCK-027");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_main_branch() {
        let result = validate_ticket_branch("main");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_feature_branch() {
        let result = validate_ticket_branch("feature/add-logging");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_extra_suffix() {
        let result = validate_ticket_branch("ticket/RFC-0002/TCK-00027/extra");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_lowercase() {
        let result = validate_ticket_branch("ticket/rfc-0002/tck-00027");
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_yaml_path() {
        let main = PathBuf::from("/home/user/project");
        let path = ticket_yaml_path(&main, "TCK-00027");
        assert_eq!(
            path,
            PathBuf::from("/home/user/project/documents/work/tickets/TCK-00027.yaml")
        );
    }

    #[test]
    fn test_ticket_yaml_path_different_ticket() {
        let main = PathBuf::from("/opt/apm2");
        let path = ticket_yaml_path(&main, "TCK-00001");
        assert_eq!(
            path,
            PathBuf::from("/opt/apm2/documents/work/tickets/TCK-00001.yaml")
        );
    }

    // Integration tests that require a real git repo
    #[test]
    fn test_main_worktree_in_git_repo() {
        let sh = Shell::new().expect("Failed to create shell");
        // This test assumes we're running in a git repo
        // Should succeed in the xtask crate directory
        if let Ok(path) = main_worktree(&sh) {
            assert!(path.exists(), "Main worktree path should exist");
        }
        // If not in a git repo, the test passes (CI might not have a repo)
    }

    #[test]
    fn test_current_branch_in_git_repo() {
        let sh = Shell::new().expect("Failed to create shell");
        // Should succeed if we're in a git repo on a branch
        if let Ok(branch) = current_branch(&sh) {
            assert!(!branch.is_empty(), "Branch name should not be empty");
        }
    }
}
