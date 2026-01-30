//! Worktree health diagnostics for the `start-ticket` command.
//!
//! This module provides health checking for git worktrees, detecting various
//! issues like orphaned directories, uncommitted changes, merge conflicts, etc.
//! Each issue includes remediation instructions and indicates whether it can
//! be auto-fixed with `--force`.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use xshell::{Shell, cmd};

/// Severity level for worktree issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational - worktree works but could be improved
    Info,
    /// Warning - worktree has issues that may cause problems
    Warning,
    /// Critical - worktree is in a broken state
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Specific issue types that can affect a worktree.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Variants are part of public API for comprehensive diagnostics
pub enum WorktreeIssue {
    /// Worktree directory was deleted but git still tracks it
    Orphaned,
    /// HEAD is detached (not on a branch)
    DetachedHead { head_commit: String },
    /// The branch that should exist has been deleted
    BranchDeleted { expected_branch: String },
    /// Worktree is behind main/origin
    OutOfSync { commits_behind: u32 },
    /// Worktree has uncommitted changes
    Dirty {
        changed_files: u32,
        untracked_files: u32,
    },
    /// Worktree has unresolved merge conflicts
    MergeConflicts { conflicted_files: u32 },
    /// Worktree is locked
    Locked { reason: Option<String> },
}

impl WorktreeIssue {
    /// Human-readable description of the issue.
    pub fn description(&self) -> String {
        match self {
            Self::Orphaned => "Worktree directory has been deleted but git still tracks it".into(),
            Self::DetachedHead { head_commit } => {
                format!("HEAD is detached at commit {head_commit}")
            },
            Self::BranchDeleted { expected_branch } => {
                format!("Branch '{expected_branch}' has been deleted")
            },
            Self::OutOfSync { commits_behind } => {
                format!("Worktree is {commits_behind} commits behind main")
            },
            Self::Dirty {
                changed_files,
                untracked_files,
            } => {
                format!(
                    "Worktree has uncommitted changes ({changed_files} modified, {untracked_files} untracked)"
                )
            },
            Self::MergeConflicts { conflicted_files } => {
                format!("Worktree has {conflicted_files} unresolved merge conflict(s)")
            },
            Self::Locked { reason } => reason.as_ref().map_or_else(
                || "Worktree is locked".into(),
                |r| format!("Worktree is locked: {r}"),
            ),
        }
    }

    /// Suggested fix commands for the issue.
    pub fn remediation(&self, path: &Path) -> Vec<String> {
        let path_str = path.display();
        match self {
            Self::Orphaned => vec!["git worktree prune".into()],
            Self::DetachedHead { .. } => {
                vec![format!(
                    "cd {path_str} && git checkout <branch-name>  # Attach to a branch"
                )]
            },
            Self::BranchDeleted { expected_branch } => vec![
                format!(
                    "cd {path_str} && git checkout -b {expected_branch}  # Recreate the branch"
                ),
                "Or use --force to remove and recreate fresh".into(),
            ],
            Self::OutOfSync { .. } => vec![
                format!("cd {path_str} && git fetch && git rebase origin/main"),
                "Or use --force to remove and recreate fresh".into(),
            ],
            Self::Dirty { .. } => vec![
                format!("cd {path_str} && git stash  # Stash changes"),
                format!("cd {path_str} && git add -A && git commit -m 'WIP'  # Commit changes"),
                format!("cd {path_str} && git checkout .  # Discard changes"),
            ],
            Self::MergeConflicts { .. } => vec![
                format!("cd {path_str} && git status  # See conflicted files"),
                format!("cd {path_str} && git merge --abort  # Abort the merge"),
                format!("cd {path_str} && git rebase --abort  # Abort rebase if applicable"),
            ],
            Self::Locked { .. } => vec![format!("git worktree unlock {path_str}")],
        }
    }

    /// Whether this issue can be auto-fixed with `--force`.
    pub const fn is_auto_remediable(&self) -> bool {
        match self {
            Self::Orphaned
            | Self::DetachedHead { .. }
            | Self::BranchDeleted { .. }
            | Self::OutOfSync { .. }
            | Self::Locked { .. } => true,
            Self::Dirty { .. } | Self::MergeConflicts { .. } => false,
        }
    }

    /// Severity level of this issue.
    pub const fn severity(&self) -> Severity {
        match self {
            Self::Orphaned | Self::MergeConflicts { .. } => Severity::Critical,
            Self::DetachedHead { .. }
            | Self::BranchDeleted { .. }
            | Self::Dirty { .. }
            | Self::Locked { .. } => Severity::Warning,
            Self::OutOfSync { .. } => Severity::Info,
        }
    }
}

/// Health status of a worktree.
#[derive(Debug)]
pub struct WorktreeHealth {
    /// Path to the worktree
    pub path: PathBuf,
    /// Ticket ID if derivable from path
    #[allow(dead_code)] // Used for display/reporting
    pub ticket_id: Option<String>,
    /// Current branch name (if on a branch)
    #[allow(dead_code)] // Used for display/reporting
    pub branch: Option<String>,
    /// List of detected issues
    pub issues: Vec<WorktreeIssue>,
}

impl WorktreeHealth {
    /// Whether this worktree has any issues.
    pub fn has_issues(&self) -> bool {
        !self.issues.is_empty()
    }

    /// Get issues that require manual intervention.
    pub fn manual_issues(&self) -> Vec<&WorktreeIssue> {
        self.issues
            .iter()
            .filter(|issue| !issue.is_auto_remediable())
            .collect()
    }

    /// Get issues that can be auto-fixed with --force.
    #[allow(dead_code)] // Part of public API
    pub fn auto_remediable_issues(&self) -> Vec<&WorktreeIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.is_auto_remediable())
            .collect()
    }
}

/// Diagnose the health of a worktree at the given path.
///
/// This function checks for various issues:
/// - Orphaned worktree (directory deleted)
/// - Detached HEAD
/// - Deleted branch
/// - Out of sync with main
/// - Dirty working directory
/// - Merge conflicts
/// - Locked worktree
///
/// # Arguments
///
/// * `sh` - Shell instance for running git commands
/// * `path` - Path to the worktree to diagnose
///
/// # Returns
///
/// Returns a `WorktreeHealth` struct with all detected issues.
pub fn diagnose_worktree(sh: &Shell, path: &Path) -> Result<WorktreeHealth> {
    let mut issues = Vec::new();

    // Extract ticket ID from path (e.g., /path/to/apm2-TCK-00200 -> TCK-00200)
    let ticket_id = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("apm2-"))
        .map(String::from);

    // Check if directory exists (orphaned check)
    if !path.exists() {
        issues.push(WorktreeIssue::Orphaned);
        return Ok(WorktreeHealth {
            path: path.to_path_buf(),
            ticket_id,
            branch: None,
            issues,
        });
    }

    // Check for locked worktree via git worktree list --porcelain
    if let Some(lock_issue) = check_locked(sh, path)? {
        issues.push(lock_issue);
    }

    // Get current branch
    let branch = get_current_branch(sh, path)?;

    // Check for detached HEAD
    if branch.is_none() {
        let head_commit = cmd!(sh, "git -C {path} rev-parse --short HEAD")
            .read()
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        issues.push(WorktreeIssue::DetachedHead { head_commit });
    }

    // Check for dirty working directory
    if let Some(dirty_issue) = check_dirty(sh, path)? {
        issues.push(dirty_issue);
    }

    // Check for merge conflicts
    if let Some(conflict_issue) = check_merge_conflicts(sh, path)? {
        issues.push(conflict_issue);
    }

    // Check if out of sync with main
    if let Some(sync_issue) = check_out_of_sync(sh, path) {
        issues.push(sync_issue);
    }

    // Sort issues by severity (critical first)
    issues.sort_by_key(|issue| std::cmp::Reverse(issue.severity()));

    Ok(WorktreeHealth {
        path: path.to_path_buf(),
        ticket_id,
        branch,
        issues,
    })
}

/// Get the current branch name, or None if HEAD is detached.
fn get_current_branch(sh: &Shell, path: &Path) -> Result<Option<String>> {
    let output = cmd!(sh, "git -C {path} rev-parse --abbrev-ref HEAD")
        .read()
        .context("Failed to get current branch")?;

    let branch = output.trim();
    if branch == "HEAD" {
        Ok(None)
    } else {
        Ok(Some(branch.to_string()))
    }
}

/// Check if the worktree is locked.
fn check_locked(sh: &Shell, path: &Path) -> Result<Option<WorktreeIssue>> {
    let output = cmd!(sh, "git worktree list --porcelain")
        .read()
        .context("Failed to list worktrees")?;

    let path_str = path.to_string_lossy();
    let mut in_target_worktree = false;
    let mut lock_reason = None;

    for line in output.lines() {
        if line.starts_with("worktree ") {
            let worktree_path = line.strip_prefix("worktree ").unwrap_or("");
            in_target_worktree = worktree_path == path_str;
        } else if in_target_worktree && line.starts_with("locked") {
            // Format is either "locked" or "locked <reason>"
            lock_reason = Some(line.strip_prefix("locked").unwrap_or("").trim().to_string());
            break;
        }
    }

    Ok(lock_reason.map(|reason| WorktreeIssue::Locked {
        reason: if reason.is_empty() {
            None
        } else {
            Some(reason)
        },
    }))
}

/// Check if the worktree has uncommitted changes.
fn check_dirty(sh: &Shell, path: &Path) -> Result<Option<WorktreeIssue>> {
    let output = cmd!(sh, "git -C {path} status --porcelain")
        .read()
        .context("Failed to check worktree status")?;

    if output.trim().is_empty() {
        return Ok(None);
    }

    let mut changed_files = 0u32;
    let mut untracked_files = 0u32;

    for line in output.lines() {
        if line.starts_with("??") {
            untracked_files += 1;
        } else if !line.trim().is_empty() {
            changed_files += 1;
        }
    }

    if changed_files > 0 || untracked_files > 0 {
        Ok(Some(WorktreeIssue::Dirty {
            changed_files,
            untracked_files,
        }))
    } else {
        Ok(None)
    }
}

/// Check if the worktree has unresolved merge conflicts.
fn check_merge_conflicts(sh: &Shell, path: &Path) -> Result<Option<WorktreeIssue>> {
    let output = cmd!(sh, "git -C {path} ls-files -u")
        .read()
        .context("Failed to check for merge conflicts")?;

    if output.trim().is_empty() {
        return Ok(None);
    }

    // Each conflicted file appears multiple times (once per stage), count unique
    // files
    let conflicted_files: std::collections::HashSet<&str> = output
        .lines()
        .filter_map(|line| {
            // Format: <mode> <hash> <stage> <filename>
            line.split_whitespace().nth(3)
        })
        .collect();

    #[allow(clippy::cast_possible_truncation)] // Files count won't exceed u32::MAX
    let count = conflicted_files.len() as u32;
    if count > 0 {
        Ok(Some(WorktreeIssue::MergeConflicts {
            conflicted_files: count,
        }))
    } else {
        Ok(None)
    }
}

/// Check if the worktree is out of sync with origin/main.
fn check_out_of_sync(sh: &Shell, path: &Path) -> Option<WorktreeIssue> {
    // First, try to fetch to ensure we have latest refs
    // Ignore errors (e.g., offline mode)
    let _ = cmd!(sh, "git -C {path} fetch origin main")
        .ignore_status()
        .ignore_stdout()
        .ignore_stderr()
        .run();

    // Count commits behind origin/main
    let output = cmd!(sh, "git -C {path} rev-list --count HEAD..origin/main")
        .ignore_status()
        .read()
        .unwrap_or_default();

    let commits_behind: u32 = output.trim().parse().unwrap_or(0);

    if commits_behind > 0 {
        Some(WorktreeIssue::OutOfSync { commits_behind })
    } else {
        None
    }
}

/// Print a formatted health report to stdout.
pub fn print_health_report(health: &WorktreeHealth) {
    println!();
    println!("Worktree at {} has issues:", health.path.display());
    println!();

    for issue in &health.issues {
        let severity = issue.severity();
        let description = issue.description();
        let auto_fix = if issue.is_auto_remediable() {
            ""
        } else {
            " (requires manual intervention)"
        };

        println!("  [{severity}] {description}{auto_fix}");

        // Show remediation
        let remediations = issue.remediation(&health.path);
        if !remediations.is_empty() {
            println!("    Suggested fix:");
            for cmd in &remediations {
                println!("      $ {cmd}");
            }
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    #[test]
    fn test_issue_auto_remediable() {
        assert!(WorktreeIssue::Orphaned.is_auto_remediable());
        assert!(
            WorktreeIssue::DetachedHead {
                head_commit: "abc123".into()
            }
            .is_auto_remediable()
        );
        assert!(
            WorktreeIssue::BranchDeleted {
                expected_branch: "feature".into()
            }
            .is_auto_remediable()
        );
        assert!(WorktreeIssue::OutOfSync { commits_behind: 5 }.is_auto_remediable());
        assert!(WorktreeIssue::Locked { reason: None }.is_auto_remediable());

        assert!(
            !WorktreeIssue::Dirty {
                changed_files: 1,
                untracked_files: 0
            }
            .is_auto_remediable()
        );
        assert!(
            !WorktreeIssue::MergeConflicts {
                conflicted_files: 2
            }
            .is_auto_remediable()
        );
    }

    #[test]
    fn test_issue_severity() {
        assert_eq!(WorktreeIssue::Orphaned.severity(), Severity::Critical);
        assert_eq!(
            WorktreeIssue::MergeConflicts {
                conflicted_files: 1
            }
            .severity(),
            Severity::Critical
        );
        assert_eq!(
            WorktreeIssue::DetachedHead {
                head_commit: "abc".into()
            }
            .severity(),
            Severity::Warning
        );
        assert_eq!(
            WorktreeIssue::Dirty {
                changed_files: 1,
                untracked_files: 0
            }
            .severity(),
            Severity::Warning
        );
        assert_eq!(
            WorktreeIssue::OutOfSync { commits_behind: 10 }.severity(),
            Severity::Info
        );
    }

    #[test]
    fn test_worktree_health_has_issues() {
        let health_with_issues = WorktreeHealth {
            path: PathBuf::from("/test"),
            ticket_id: None,
            branch: None,
            issues: vec![WorktreeIssue::Orphaned],
        };
        assert!(health_with_issues.has_issues());

        let health_no_issues = WorktreeHealth {
            path: PathBuf::from("/test"),
            ticket_id: None,
            branch: Some("main".into()),
            issues: vec![],
        };
        assert!(!health_no_issues.has_issues());
    }

    #[test]
    fn test_worktree_health_manual_issues() {
        let health = WorktreeHealth {
            path: PathBuf::from("/test"),
            ticket_id: None,
            branch: None,
            issues: vec![
                WorktreeIssue::Orphaned,
                WorktreeIssue::Dirty {
                    changed_files: 2,
                    untracked_files: 1,
                },
                WorktreeIssue::OutOfSync { commits_behind: 5 },
            ],
        };

        let manual = health.manual_issues();
        assert_eq!(manual.len(), 1);
        assert!(matches!(manual[0], WorktreeIssue::Dirty { .. }));
    }

    #[test]
    fn test_issue_description() {
        assert!(WorktreeIssue::Orphaned.description().contains("deleted"));
        assert!(
            WorktreeIssue::DetachedHead {
                head_commit: "abc123".into()
            }
            .description()
            .contains("abc123")
        );
        assert!(
            WorktreeIssue::OutOfSync { commits_behind: 47 }
                .description()
                .contains("47")
        );
    }

    #[test]
    fn test_issue_remediation_contains_path() {
        let path = Path::new("/home/user/apm2-TCK-00200");
        let remediation = WorktreeIssue::Dirty {
            changed_files: 1,
            untracked_files: 0,
        }
        .remediation(path);

        assert!(
            remediation
                .iter()
                .any(|s| s.contains("/home/user/apm2-TCK-00200"))
        );
    }
}
