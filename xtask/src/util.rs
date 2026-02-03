//! Shared utilities for xtask commands.
//!
//! This module provides common functions used across multiple commands:
//! - Branch validation and parsing
//! - Worktree path finding
//! - Ticket YAML path construction
//! - Non-authoritative banner display

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use xshell::{Shell, cmd};

// =============================================================================
// HEF Projection Feature Flag (TCK-00309)
// =============================================================================

/// Name of the environment variable gating HEF projection logic.
pub const USE_HEF_PROJECTION_ENV: &str = "USE_HEF_PROJECTION";

/// Checks if HEF projection logic is enabled.
///
/// Returns `true` if the `USE_HEF_PROJECTION` environment variable is set to
/// "true" (case-insensitive).
///
/// Per TCK-00309, this flag defaults to `false`. When `true`, xtask must NOT
/// write status checks directly to GitHub, as these should be handled by the
/// daemon's projection logic.
pub fn use_hef_projection() -> bool {
    std::env::var(USE_HEF_PROJECTION_ENV)
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

// =============================================================================
// Non-Authoritative Banner
// =============================================================================

/// NON-AUTHORITATIVE banner text for xtask status-writing operations.
///
/// This banner must be printed before any GitHub status check writes to make
/// clear that xtask outputs are development scaffolding, NOT the source of
/// truth for the HEF (Holonic Evidence Framework) pipeline.
///
/// Per RFC-0018 REQ-HEF-0001: "Pulse plane is non-authoritative" - status
/// writes from xtask are hints only and must never be used as authoritative
/// admission, gate, lease, or secret-backed decision signals.
///
/// See: TCK-00294 (Stage X0 of xtask authority reduction)
pub const NON_AUTHORITATIVE_BANNER: &str = r"
================================================================================
                          NON-AUTHORITATIVE OUTPUT
================================================================================
  This xtask command writes GitHub status checks as DEVELOPMENT SCAFFOLDING.
  These statuses are NOT the source of truth for the HEF evidence pipeline.

  Per RFC-0018: Pulse-plane signals are lossy hints only. Consumers must verify
  via ledger+CAS before acting on any gate, admission, or authorization decision.

  For authoritative evidence, use the daemon's projection system (when available).
================================================================================
";

/// Print the NON-AUTHORITATIVE banner to stdout.
///
/// Call this function before any GitHub status check API writes to ensure
/// operators understand that xtask outputs are non-authoritative scaffolding.
///
/// # Example
///
/// ```ignore
/// use crate::util::print_non_authoritative_banner;
///
/// // Before writing status checks
/// print_non_authoritative_banner();
/// set_status_check(&sh, &pr_info, &sha, "success", "All checks passed", None)?;
/// ```
pub fn print_non_authoritative_banner() {
    eprintln!("{NON_AUTHORITATIVE_BANNER}");
}

/// Regex pattern for validating ticket branch names.
///
/// Valid formats:
/// - `ticket/RFC-XXXX/TCK-XXXXX` (with RFC)
/// - `ticket/TCK-XXXXX` (standalone ticket)
///
/// Where XXXX is 4 digits and XXXXX is 5 digits.
static TICKET_BRANCH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Two separate patterns:
    // 1. ticket/ branches require strict TCK-XXXXX format (with optional RFC-XXXX/)
    // 2. feat/ branches allow any word/hyphen characters
    Regex::new(r"^(?:ticket/(?:(RFC-\d{4})/)?(TCK-\d{5})|feat/([\w\-]+))$")
        .expect("Invalid regex pattern for ticket branch")
});

/// Parsed ticket branch information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketBranch {
    /// The RFC ID (e.g., "RFC-0002"), if present.
    /// None for standalone tickets without an RFC.
    pub rfc_id: Option<String>,
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
/// one of the expected formats:
/// - `ticket/RFC-XXXX/TCK-XXXXX` (with RFC)
/// - `ticket/TCK-XXXXX` (standalone ticket)
///
/// # Errors
///
/// Returns an error if the branch name does not match the expected format.
///
/// # Examples
///
/// ```
/// # use xtask::util::validate_ticket_branch;
/// // With RFC
/// let result = validate_ticket_branch("ticket/RFC-0002/TCK-00027");
/// assert!(result.is_ok());
/// let branch = result.unwrap();
/// assert_eq!(branch.rfc_id, Some("RFC-0002".to_string()));
/// assert_eq!(branch.ticket_id, "TCK-00027");
///
/// // Standalone ticket (no RFC)
/// let result = validate_ticket_branch("ticket/TCK-00049");
/// assert!(result.is_ok());
/// let branch = result.unwrap();
/// assert_eq!(branch.rfc_id, None);
/// assert_eq!(branch.ticket_id, "TCK-00049");
/// ```
pub fn validate_ticket_branch(branch_name: &str) -> Result<TicketBranch> {
    let captures = TICKET_BRANCH_REGEX.captures(branch_name).with_context(|| {
        format!(
            "Invalid branch name: '{branch_name}'\n\
                 Expected format: ticket/RFC-XXXX/TCK-XXXXX or ticket/TCK-XXXXX\n\
                 Examples: ticket/RFC-0002/TCK-00027, ticket/TCK-00049"
        )
    })?;

    Ok(TicketBranch {
        rfc_id: captures.get(1).map(|m| m.as_str().to_string()),
        // Group 2 captures TCK-XXXXX for ticket/ branches
        // Group 3 captures the name for feat/ branches
        ticket_id: captures
            .get(2)
            .or_else(|| captures.get(3))
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
    fn test_validate_ticket_branch_valid_with_rfc() {
        let result = validate_ticket_branch("ticket/RFC-0002/TCK-00027");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, Some("RFC-0002".to_string()));
        assert_eq!(branch.ticket_id, "TCK-00027");
    }

    #[test]
    fn test_validate_ticket_branch_valid_standalone() {
        let result = validate_ticket_branch("ticket/TCK-00049");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, None);
        assert_eq!(branch.ticket_id, "TCK-00049");
    }

    #[test]
    fn test_validate_ticket_branch_valid_different_ids() {
        let result = validate_ticket_branch("ticket/RFC-0001/TCK-00001");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, Some("RFC-0001".to_string()));
        assert_eq!(branch.ticket_id, "TCK-00001");
    }

    #[test]
    fn test_validate_ticket_branch_valid_high_numbers() {
        let result = validate_ticket_branch("ticket/RFC-9999/TCK-99999");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, Some("RFC-9999".to_string()));
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
    fn test_validate_ticket_branch_standalone_high_number() {
        let result = validate_ticket_branch("ticket/TCK-99999");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, None);
        assert_eq!(branch.ticket_id, "TCK-99999");
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

    // =============================================================================
    // HEF Projection Feature Flag Tests (TCK-00309)
    // =============================================================================

    #[test]
    #[allow(unsafe_code)]
    fn test_use_hef_projection_env_var() {
        // SERIAL TEST: Modifies environment variables, must be single test

        // 1. Default (unset) -> false
        unsafe { std::env::remove_var(USE_HEF_PROJECTION_ENV) };
        assert!(!use_hef_projection(), "Default should be false");

        // 2. "TRUE" -> true
        unsafe { std::env::set_var(USE_HEF_PROJECTION_ENV, "TRUE") };
        assert!(use_hef_projection(), "TRUE should be true");

        // 3. "true" -> true
        unsafe { std::env::set_var(USE_HEF_PROJECTION_ENV, "true") };
        assert!(use_hef_projection(), "true should be true");

        // 4. "false" -> false
        unsafe { std::env::set_var(USE_HEF_PROJECTION_ENV, "false") };
        assert!(!use_hef_projection(), "false should be false");

        // 5. "0" -> false
        unsafe { std::env::set_var(USE_HEF_PROJECTION_ENV, "0") };
        assert!(!use_hef_projection(), "0 should be false");

        // Cleanup
        unsafe { std::env::remove_var(USE_HEF_PROJECTION_ENV) };
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

    // =============================================================================
    // NON-AUTHORITATIVE Banner Tests (TCK-00294)
    // =============================================================================

    #[test]
    fn test_non_authoritative_banner_contains_key_phrases() {
        // Verify the banner contains all required warning phrases
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("NON-AUTHORITATIVE"),
            "Banner must contain 'NON-AUTHORITATIVE'"
        );
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("DEVELOPMENT SCAFFOLDING"),
            "Banner must mention 'DEVELOPMENT SCAFFOLDING'"
        );
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("RFC-0018"),
            "Banner must reference RFC-0018"
        );
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("ledger+CAS"),
            "Banner must mention ledger+CAS verification"
        );
    }

    #[test]
    fn test_non_authoritative_banner_is_not_empty() {
        assert!(
            !NON_AUTHORITATIVE_BANNER.is_empty(),
            "Banner must not be empty"
        );
        // Should be a substantial warning, at least 200 characters
        assert!(
            NON_AUTHORITATIVE_BANNER.len() > 200,
            "Banner should be a substantial warning"
        );
    }
}
