//! Dedicated GitHub projection layer for FAC review CLI commands.
//!
//! This module is the write boundary for GitHub projection operations.

use std::io::Write;
use std::process::Command;

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
    let output = Command::new("gh")
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
    let output = Command::new("gh")
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

pub(super) fn find_latest_issue_comment_id_with_marker(
    owner_repo: &str,
    pr_number: u32,
    marker: &str,
) -> Result<Option<u64>, String> {
    let endpoint = format!("/repos/{owner_repo}/issues/{pr_number}/comments?per_page=100");
    let output = Command::new("gh")
        .args(["api", "--paginate", "--slurp", &endpoint])
        .output()
        .map_err(|err| format!("failed to execute gh api for issue comment discovery: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed listing issue comments for PR #{pr_number}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse issue comments response: {err}"))?;

    let mut max_id = None::<u64>;
    let mut scan_comments = |comments: &[serde_json::Value]| {
        for comment in comments {
            let Some(id) = comment.get("id").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let body = comment
                .get("body")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if !body.contains(marker) {
                continue;
            }
            max_id = Some(max_id.map_or(id, |current| current.max(id)));
        }
    };

    if let Some(items) = value.as_array() {
        let is_comment_list = items.first().is_some_and(|entry| entry.get("id").is_some());
        if is_comment_list {
            scan_comments(items);
        } else {
            for page in items {
                if let Some(comments) = page.as_array() {
                    scan_comments(comments);
                }
            }
        }
    }
    Ok(max_id)
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
    let output = Command::new("gh")
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
    let output = Command::new("gh")
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
    let output = Command::new("gh")
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
    let output = Command::new("gh")
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
    let output = Command::new("gh")
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

pub(super) fn enable_auto_merge(repo: &str, pr_number: u32) -> Result<(), String> {
    let pr_ref = pr_number.to_string();
    let output = Command::new("gh")
        .args(["pr", "merge", &pr_ref, "--repo", repo, "--auto", "--squash"])
        .output()
        .map_err(|err| format!("failed to execute gh pr merge --auto: {err}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(())
}
