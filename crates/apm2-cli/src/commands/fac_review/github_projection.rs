//! Dedicated GitHub projection layer for FAC review CLI commands.
//!
//! This module is the write boundary for GitHub projection operations.
//! All `gh` CLI calls use [`apm2_core::fac::gh_command`] for non-interactive,
//! lane-scoped auth (TCK-00597).

use std::io::Write;

use apm2_core::fac::gh_command;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct IssueCommentResponse {
    pub(super) id: u64,
    pub(super) html_url: String,
}

pub(super) fn create_issue_comment(
    owner_repo: &str,
    pr_number: u32,
    body: &str,
) -> Result<IssueCommentResponse, String> {
    let mut payload_file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("failed to create temp payload for issue comment: {err}"))?;
    let payload = serde_json::json!({ "body": body });
    let payload_text = serde_json::to_string(&payload)
        .map_err(|err| format!("failed to serialize issue comment payload: {err}"))?;
    payload_file
        .write_all(payload_text.as_bytes())
        .map_err(|err| format!("failed to write issue comment payload: {err}"))?;
    payload_file
        .flush()
        .map_err(|err| format!("failed to flush issue comment payload: {err}"))?;

    let endpoint = format!("/repos/{owner_repo}/issues/{pr_number}/comments");
    let output = gh_command()
        .args([
            "api",
            &endpoint,
            "--method",
            "POST",
            "--input",
            &payload_file.path().display().to_string(),
        ])
        .output()
        .map_err(|err| format!("failed to execute gh api for issue comment create: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed creating issue comment: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    serde_json::from_slice::<IssueCommentResponse>(&output.stdout)
        .map_err(|err| format!("failed to parse issue comment create response: {err}"))
}

pub(super) fn update_issue_comment(
    owner_repo: &str,
    comment_id: u64,
    body: &str,
) -> Result<(), String> {
    let mut payload_file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("failed to create temp payload for issue comment patch: {err}"))?;
    let payload = serde_json::json!({ "body": body });
    let payload_text = serde_json::to_string(&payload)
        .map_err(|err| format!("failed to serialize issue comment patch payload: {err}"))?;
    payload_file
        .write_all(payload_text.as_bytes())
        .map_err(|err| format!("failed to write issue comment patch payload: {err}"))?;
    payload_file
        .flush()
        .map_err(|err| format!("failed to flush issue comment patch payload: {err}"))?;

    let endpoint = format!("/repos/{owner_repo}/issues/comments/{comment_id}");
    let output = gh_command()
        .args([
            "api",
            &endpoint,
            "--method",
            "PATCH",
            "--input",
            &payload_file.path().display().to_string(),
        ])
        .output()
        .map_err(|err| format!("failed to execute gh api for issue comment patch: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed patching issue comment {comment_id}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

#[allow(dead_code)]
pub(super) fn patch_issue_comment_body(
    owner_repo: &str,
    comment_id: u64,
    body: &str,
) -> Result<(), String> {
    update_issue_comment(owner_repo, comment_id, body)
}

#[allow(dead_code)]
pub(super) fn fetch_pr_body(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    let output = gh_command()
        .arg("pr")
        .arg("view")
        .arg(pr_number.to_string())
        .args(["--repo", owner_repo, "--json", "body", "--jq", ".body"])
        .output()
        .map_err(|err| format!("failed to execute gh pr view for PR body: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh pr view failed fetching PR body: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(super) fn edit_pr_body(owner_repo: &str, pr_number: u32, body: &str) -> Result<(), String> {
    let output = gh_command()
        .arg("pr")
        .arg("edit")
        .arg(pr_number.to_string())
        .args(["--repo", owner_repo, "--body", body])
        .output()
        .map_err(|err| format!("failed to execute gh pr edit for body sync: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh pr edit failed syncing PR body: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

pub(super) fn find_pr_for_branch(repo: &str, branch: &str) -> Result<Option<u32>, String> {
    let output = gh_command()
        .args([
            "pr",
            "list",
            "--repo",
            repo,
            "--head",
            branch,
            "--json",
            "number",
            "--jq",
            ".[0].number",
        ])
        .output()
        .map_err(|err| format!("failed to find PR for branch {branch}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh pr list failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let num_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if num_str.is_empty() || num_str == "null" {
        return Ok(None);
    }
    let value = num_str
        .parse::<u32>()
        .map_err(|_| format!("invalid PR number from gh output `{num_str}`"))?;
    Ok(Some(value))
}

pub(super) fn create_pr(repo: &str, title: &str, body: &str) -> Result<u32, String> {
    let output = gh_command()
        .args([
            "pr", "create", "--repo", repo, "--title", title, "--body", body, "--base", "main",
        ])
        .output()
        .map_err(|err| format!("failed to execute gh pr create: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "gh pr create failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    url.rsplit('/')
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| format!("could not parse PR number from gh output: {url}"))
}

pub(super) fn update_pr(repo: &str, pr_number: u32, title: &str, body: &str) -> Result<(), String> {
    let pr_ref = pr_number.to_string();
    let output = gh_command()
        .args([
            "pr", "edit", &pr_ref, "--repo", repo, "--title", title, "--body", body,
        ])
        .output()
        .map_err(|err| format!("failed to execute gh pr edit: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "gh pr edit failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

fn run_enable_auto_merge_with_strategy(
    repo: &str,
    pr_ref: &str,
    strategy_flag: &str,
) -> Result<(), String> {
    let output = gh_command()
        .args([
            "pr",
            "merge",
            pr_ref,
            "--repo",
            repo,
            "--auto",
            strategy_flag,
        ])
        .output()
        .map_err(|err| format!("failed to execute gh pr merge --auto {strategy_flag}: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(render_gh_output_error(&output))
}

fn render_gh_output_error(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match (stderr.is_empty(), stdout.is_empty()) {
        (true, true) => "unknown gh error".to_string(),
        (false, true) => stderr,
        (true, false) => stdout,
        (false, false) => format!("{stderr}; {stdout}"),
    }
}

fn strategy_rejected_by_repo_policy(stderr: &str, strategy_flag: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    let (strategy_markers, strategy_keyword) = match strategy_flag {
        "--merge" => (&["merge commits", "merge merges"][..], "merge"),
        "--squash" => (&["squash merges", "squash commits"][..], "squash"),
        "--rebase" => (&["rebase merges", "rebase commits"][..], "rebase"),
        _ => return false,
    };
    let has_policy_rejection = [
        "not allowed",
        "disabled",
        "not enabled",
        "not permitted",
        "unavailable",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let merge_method_selectors = [
        format!("merge method {strategy_keyword}"),
        format!("merge method: {strategy_keyword}"),
        format!("merge method `{strategy_keyword}`"),
        format!("merge method: `{strategy_keyword}`"),
    ];
    let strategy_mentioned = strategy_markers.iter().any(|marker| lower.contains(marker))
        || merge_method_selectors
            .iter()
            .any(|selector| lower.contains(selector));

    strategy_mentioned && has_policy_rejection
}

fn auto_merge_already_enabled(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("auto-merge is already enabled")
        || lower.contains("already in the merge queue")
        || lower.contains("already added to the merge queue")
        || lower.contains("pull request is already merged")
}

pub(super) fn enable_auto_merge(repo: &str, pr_number: u32) -> Result<(), String> {
    let pr_ref = pr_number.to_string();
    let strategies = ["--merge", "--squash", "--rebase"];
    let mut strategy_rejections = Vec::new();

    for strategy in strategies {
        match run_enable_auto_merge_with_strategy(repo, &pr_ref, strategy) {
            Ok(()) => return Ok(()),
            Err(stderr) => {
                if auto_merge_already_enabled(&stderr) {
                    return Ok(());
                }
                if strategy_rejected_by_repo_policy(&stderr, strategy) {
                    strategy_rejections.push(format!("{strategy}: {stderr}"));
                    continue;
                }
                return Err(stderr);
            },
        }
    }

    if !strategy_rejections.is_empty() {
        return Err(format!(
            "failed to enable GitHub auto-merge for PR #{pr_number}: no allowed merge strategies ({})",
            strategy_rejections.join("; ")
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{auto_merge_already_enabled, strategy_rejected_by_repo_policy};

    #[test]
    fn strategy_rejected_by_repo_policy_detects_merge_disabled() {
        let err = "GraphQL: Merge commits are not allowed on this repository.";
        assert!(strategy_rejected_by_repo_policy(err, "--merge"));
        assert!(!strategy_rejected_by_repo_policy(err, "--squash"));
    }

    #[test]
    fn strategy_rejected_by_repo_policy_detects_squash_disabled() {
        let err = "GraphQL: Squash merges are disabled for this repository.";
        assert!(strategy_rejected_by_repo_policy(err, "--squash"));
        assert!(!strategy_rejected_by_repo_policy(err, "--rebase"));
    }

    #[test]
    fn strategy_rejected_by_repo_policy_detects_squash_commits_not_allowed() {
        let err = "GraphQL: Squash commits are not allowed on this repository.";
        assert!(strategy_rejected_by_repo_policy(err, "--squash"));
        assert!(!strategy_rejected_by_repo_policy(err, "--merge"));
    }

    #[test]
    fn strategy_rejected_by_repo_policy_detects_rebase_commits_disabled() {
        let err = "GraphQL: Rebase commits are disabled for this repository.";
        assert!(strategy_rejected_by_repo_policy(err, "--rebase"));
        assert!(!strategy_rejected_by_repo_policy(err, "--squash"));
    }

    #[test]
    fn strategy_rejected_by_repo_policy_detects_merge_method_not_enabled() {
        let err = "GraphQL: merge method merge is not enabled for this repository.";
        assert!(strategy_rejected_by_repo_policy(err, "--merge"));
        assert!(!strategy_rejected_by_repo_policy(err, "--rebase"));
    }

    #[test]
    fn strategy_rejected_by_repo_policy_detects_merge_method_not_permitted() {
        let err = "GraphQL: merge method squash is not permitted on this repository.";
        assert!(strategy_rejected_by_repo_policy(err, "--squash"));
        assert!(!strategy_rejected_by_repo_policy(err, "--merge"));
    }

    #[test]
    fn strategy_rejected_by_repo_policy_detects_backticked_merge_method_unavailable() {
        let err = "GraphQL: merge method: `rebase` unavailable for this repository.";
        assert!(strategy_rejected_by_repo_policy(err, "--rebase"));
        assert!(!strategy_rejected_by_repo_policy(err, "--squash"));
    }

    #[test]
    fn auto_merge_already_enabled_detects_idempotent_errors() {
        assert!(auto_merge_already_enabled(
            "GraphQL: Auto-merge is already enabled for this pull request"
        ));
        assert!(auto_merge_already_enabled(
            "GraphQL: Pull request is already in the merge queue"
        ));
        assert!(auto_merge_already_enabled(
            "GraphQL: Pull request is already added to the merge queue"
        ));
    }
}
