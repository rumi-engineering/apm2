//! Worktree discovery helpers for SHA-bound FAC review dispatch.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::types::validate_expected_head_sha;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorktreeEntry {
    pub path: PathBuf,
    pub head_sha: String,
    pub branch: Option<String>,
}

fn finalize_entry(
    entries: &mut Vec<WorktreeEntry>,
    path: &mut Option<PathBuf>,
    head_sha: &mut Option<String>,
    branch: &mut Option<String>,
) -> Result<(), String> {
    if path.is_none() && head_sha.is_none() && branch.is_none() {
        return Ok(());
    }

    let Some(entry_path) = path.take() else {
        return Err("invalid worktree porcelain: missing `worktree` field".to_string());
    };
    let Some(entry_head_sha) = head_sha.take() else {
        return Err(format!(
            "invalid worktree porcelain: missing `HEAD` field for {}",
            entry_path.display()
        ));
    };
    validate_expected_head_sha(&entry_head_sha)?;
    entries.push(WorktreeEntry {
        path: entry_path,
        head_sha: entry_head_sha.to_ascii_lowercase(),
        branch: branch.take(),
    });
    Ok(())
}

pub(super) fn parse_worktree_list(porcelain: &str) -> Result<Vec<WorktreeEntry>, String> {
    let mut entries = Vec::new();
    let mut path: Option<PathBuf> = None;
    let mut head_sha: Option<String> = None;
    let mut branch: Option<String> = None;

    for raw_line in porcelain.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() {
            finalize_entry(&mut entries, &mut path, &mut head_sha, &mut branch)?;
            continue;
        }

        if let Some(value) = line.strip_prefix("worktree ") {
            if path.is_some() || head_sha.is_some() || branch.is_some() {
                finalize_entry(&mut entries, &mut path, &mut head_sha, &mut branch)?;
            }
            path = Some(PathBuf::from(value.trim()));
        } else if let Some(value) = line.strip_prefix("HEAD ") {
            head_sha = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("branch ") {
            let normalized = value
                .trim()
                .strip_prefix("refs/heads/")
                .unwrap_or_else(|| value.trim())
                .to_string();
            branch = Some(normalized);
        }

        // Optional porcelain fields intentionally ignored for dispatch
        // selection: bare, detached, locked, prunable.
    }

    finalize_entry(&mut entries, &mut path, &mut head_sha, &mut branch)?;
    Ok(entries)
}

fn resolve_head_for_path(path: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| {
            format!(
                "failed to execute git rev-parse HEAD in {}: {err}",
                path.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed in {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    validate_expected_head_sha(&sha)?;
    Ok(sha.to_ascii_lowercase())
}

pub(super) fn resolve_worktree_for_sha(expected_sha: &str) -> Result<PathBuf, String> {
    validate_expected_head_sha(expected_sha)?;
    let expected_sha = expected_sha.to_ascii_lowercase();

    let output = Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .output()
        .map_err(|err| format!("failed to execute `git worktree list --porcelain`: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "`git worktree list --porcelain` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let porcelain = String::from_utf8(output.stdout)
        .map_err(|err| format!("git worktree output is not valid UTF-8: {err}"))?;
    let entries = parse_worktree_list(&porcelain)?;
    if let Some(entry) = entries
        .iter()
        .find(|entry| entry.head_sha.eq_ignore_ascii_case(&expected_sha))
    {
        return Ok(entry.path.clone());
    }

    let cwd = std::env::current_dir().map_err(|err| format!("failed to resolve cwd: {err}"))?;
    let cwd_head_sha = resolve_head_for_path(&cwd)?;
    if cwd_head_sha.eq_ignore_ascii_case(&expected_sha) {
        eprintln!(
            "WARNING: no matching worktree found for sha={expected_sha}; falling back to cwd {}",
            cwd.display()
        );
        return Ok(cwd);
    }

    Err(format!(
        "no worktree matches head sha {expected_sha}; cwd {} is at {cwd_head_sha}",
        cwd.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_worktree_list;

    #[test]
    fn parse_worktree_list_parses_main_linked_bare_and_detached_entries() {
        let input = r"worktree /repo
HEAD 0123456789abcdef0123456789abcdef01234567
branch refs/heads/main

worktree /repo/.worktrees/ticket
HEAD 1111111111111111111111111111111111111111
branch refs/heads/ticket/RFC-0019/TCK-00503

worktree /repo/.worktrees/bare
HEAD 2222222222222222222222222222222222222222
bare

worktree /repo/.worktrees/detached
HEAD 3333333333333333333333333333333333333333
detached
";
        let entries = parse_worktree_list(input).expect("parse");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].path.to_string_lossy(), "/repo");
        assert_eq!(
            entries[0].head_sha,
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(entries[0].branch.as_deref(), Some("main"));
        assert_eq!(
            entries[1].branch.as_deref(),
            Some("ticket/RFC-0019/TCK-00503")
        );
        assert_eq!(entries[2].branch, None);
        assert_eq!(entries[3].branch, None);
    }

    #[test]
    fn parse_worktree_list_rejects_missing_head() {
        let input = r"worktree /repo
branch refs/heads/main
";
        let err = parse_worktree_list(input).expect_err("missing head must fail");
        assert!(err.contains("missing `HEAD` field"));
    }

    #[test]
    fn parse_worktree_list_rejects_missing_worktree_path() {
        let input = r"HEAD 0123456789abcdef0123456789abcdef01234567
";
        let err = parse_worktree_list(input).expect_err("missing worktree path must fail");
        assert!(err.contains("missing `worktree` field"));
    }
}
