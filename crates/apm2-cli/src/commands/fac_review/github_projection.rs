//! Dedicated GitHub projection layer for FAC review CLI commands.
//!
//! This module is the write boundary for GitHub projection operations.
//! All `gh` CLI calls use [`apm2_core::fac::gh_command`] for non-interactive,
//! lane-scoped auth (TCK-00597).

use std::io::Write;

use apm2_core::fac::gh_command;
use serde::Deserialize;

const MAX_COMMIT_STATUS_DESCRIPTION_CHARS: usize = 140;
const VERDICT_MARKER: &str = "apm2-review-verdict:v1";
const VERDICT_TOMBSTONE_MARKER: &str = "apm2-review-verdict:tombstone:v1";

#[derive(Debug, Clone, Deserialize)]
pub(super) struct IssueCommentResponse {
    pub(super) id: u64,
    pub(super) html_url: String,
    #[serde(default)]
    pub(super) body: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PullRequestStateResponse {
    state: String,
    merged: bool,
}

fn parse_commit_sha(sha: &str) -> Result<String, String> {
    let normalized = sha.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("merge projection requires non-empty sha".to_string());
    }
    if normalized.len() != 40 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "merge projection requires 40-char hex sha, found `{sha}`"
        ));
    }
    Ok(normalized)
}

fn load_pr_state(repo: &str, pr_number: u32) -> Result<PullRequestStateResponse, String> {
    let endpoint = format!("/repos/{repo}/pulls/{pr_number}");
    let output = gh_command()
        .args(["api", &endpoint, "--method", "GET"])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR state lookup: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed reading PR #{pr_number} state: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    serde_json::from_slice::<PullRequestStateResponse>(&output.stdout)
        .map_err(|err| format!("failed to parse PR #{pr_number} state response: {err}"))
}

fn clamp_commit_status_description(description: &str) -> String {
    description
        .chars()
        .take(MAX_COMMIT_STATUS_DESCRIPTION_CHARS)
        .collect()
}

fn validate_commit_status_state(state: &str) -> Result<&'static str, String> {
    match state {
        "error" => Ok("error"),
        "failure" => Ok("failure"),
        "pending" => Ok("pending"),
        "success" => Ok("success"),
        other => Err(format!(
            "invalid commit status state `{other}` (expected error|failure|pending|success)"
        )),
    }
}

pub(super) fn upsert_commit_status(
    owner_repo: &str,
    head_sha: &str,
    context: &str,
    state: &str,
    description: &str,
    target_url: Option<&str>,
) -> Result<(), String> {
    let state = validate_commit_status_state(state)?;
    let context = context.trim();
    if context.is_empty() {
        return Err("commit status context cannot be empty".to_string());
    }
    let head_sha = head_sha.trim();
    if head_sha.is_empty() {
        return Err("commit status head_sha cannot be empty".to_string());
    }

    let description = clamp_commit_status_description(description);
    if description.is_empty() {
        return Err("commit status description cannot be empty".to_string());
    }

    let mut payload = serde_json::Map::new();
    payload.insert(
        "state".to_string(),
        serde_json::Value::String(state.to_string()),
    );
    payload.insert(
        "context".to_string(),
        serde_json::Value::String(context.to_string()),
    );
    payload.insert(
        "description".to_string(),
        serde_json::Value::String(description),
    );
    if let Some(target_url) = target_url.map(str::trim).filter(|value| !value.is_empty()) {
        payload.insert(
            "target_url".to_string(),
            serde_json::Value::String(target_url.to_string()),
        );
    }

    let mut payload_file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("failed to create temp payload for commit status: {err}"))?;
    let payload_text = serde_json::to_string(&serde_json::Value::Object(payload))
        .map_err(|err| format!("failed to serialize commit status payload: {err}"))?;
    payload_file
        .write_all(payload_text.as_bytes())
        .map_err(|err| format!("failed to write commit status payload: {err}"))?;
    payload_file
        .flush()
        .map_err(|err| format!("failed to flush commit status payload: {err}"))?;

    let endpoint = format!("/repos/{owner_repo}/statuses/{head_sha}");
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
        .map_err(|err| format!("failed to execute gh api for commit status projection: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed setting commit status `{context}` on {head_sha}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
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

pub(super) fn fetch_issue_comment(
    owner_repo: &str,
    comment_id: u64,
) -> Result<Option<IssueCommentResponse>, String> {
    let endpoint = format!("/repos/{owner_repo}/issues/comments/{comment_id}");
    let output = gh_command()
        .args(["api", &endpoint, "--method", "GET"])
        .output()
        .map_err(|err| format!("failed to execute gh api for issue comment get: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let normalized = stderr.to_ascii_lowercase();
        if normalized.contains("404") || normalized.contains("not found") {
            return Ok(None);
        }
        return Err(format!(
            "gh api failed fetching issue comment {comment_id}: {stderr}"
        ));
    }

    let response = serde_json::from_slice::<IssueCommentResponse>(&output.stdout)
        .map_err(|err| format!("failed to parse issue comment get response: {err}"))?;
    Ok(Some(response))
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

pub(super) fn fetch_latest_live_verdict_comment_id(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<u64>, String> {
    let endpoint = format!("/repos/{owner_repo}/issues/{pr_number}/comments?per_page=100");
    let jq = format!(
        ".[] | select((.body // \"\") | contains(\"{VERDICT_MARKER}\")) | select(((.body // \"\") | contains(\"{VERDICT_TOMBSTONE_MARKER}\")) | not) | .id"
    );
    let output = gh_command()
        .args(["api", "--paginate", &endpoint, "--jq", &jq])
        .output()
        .map_err(|err| format!("failed to execute gh api for issue comment list: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed listing issue comments: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let mut max_id = None::<u64>;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed = trimmed
            .parse::<u64>()
            .map_err(|_| format!("invalid issue comment id `{trimmed}` in gh api response"))?;
        max_id = Some(max_id.map_or(parsed, |value| value.max(parsed)));
    }
    Ok(max_id)
}
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
    let mut payload_file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("failed to create temp payload for pr body sync: {err}"))?;
    payload_file
        .write_all(body.as_bytes())
        .map_err(|err| format!("failed to write pr body sync payload: {err}"))?;
    payload_file
        .flush()
        .map_err(|err| format!("failed to flush pr body sync payload: {err}"))?;

    let output = gh_command()
        .arg("pr")
        .arg("edit")
        .arg(pr_number.to_string())
        .args([
            "--repo",
            owner_repo,
            "--body-file",
            &payload_file.path().display().to_string(),
        ])
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

pub(super) fn merge_pr_on_github(repo: &str, pr_number: u32, sha: &str) -> Result<(), String> {
    let sha = parse_commit_sha(sha)?;
    let state = load_pr_state(repo, pr_number)?;
    let pr_state = state.state.trim().to_ascii_lowercase();
    if state.merged || pr_state != "open" {
        return Ok(());
    }

    let mut payload_file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("failed to create temp payload for PR merge: {err}"))?;
    let payload = serde_json::json!({
        "sha": sha,
        "merge_method": "merge",
    });
    let payload_text = serde_json::to_string(&payload)
        .map_err(|err| format!("failed to serialize PR merge payload: {err}"))?;
    payload_file
        .write_all(payload_text.as_bytes())
        .map_err(|err| format!("failed to write PR merge payload: {err}"))?;
    payload_file
        .flush()
        .map_err(|err| format!("failed to flush PR merge payload: {err}"))?;

    let endpoint = format!("/repos/{repo}/pulls/{pr_number}/merge");
    let output = gh_command()
        .args([
            "api",
            &endpoint,
            "--method",
            "PUT",
            "--input",
            &payload_file.path().display().to_string(),
        ])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR merge projection: {err}"))?;
    if output.status.success() {
        return Ok(());
    }

    // Idempotent race guard: another actor may have merged/closed between
    // our state read and merge API call.
    if let Ok(state_after) = load_pr_state(repo, pr_number) {
        let state_after_name = state_after.state.trim().to_ascii_lowercase();
        if state_after.merged || state_after_name != "open" {
            return Ok(());
        }
    }

    Err(format!(
        "gh api failed merging PR #{pr_number} with sha {sha}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_COMMIT_STATUS_DESCRIPTION_CHARS, clamp_commit_status_description, parse_commit_sha,
        validate_commit_status_state,
    };

    #[test]
    fn commit_status_description_is_truncated_to_github_limit() {
        let input = "x".repeat(MAX_COMMIT_STATUS_DESCRIPTION_CHARS + 32);
        let output = clamp_commit_status_description(&input);
        assert_eq!(output.chars().count(), MAX_COMMIT_STATUS_DESCRIPTION_CHARS);
    }

    #[test]
    fn commit_status_state_rejects_unknown_values() {
        let err =
            validate_commit_status_state("flaky").expect_err("invalid state should be rejected");
        assert!(err.contains("expected error|failure|pending|success"));
    }

    #[test]
    fn merge_sha_parser_rejects_invalid_values() {
        let err = parse_commit_sha("not-a-sha").expect_err("invalid sha should be rejected");
        assert!(err.contains("40-char hex sha"));
    }
}
