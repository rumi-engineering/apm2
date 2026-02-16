//! GitHub read-only API helpers for FAC projection flows.

use apm2_core::fac::gh_command;

pub(super) fn fetch_default_branch(repo: &str) -> Result<String, String> {
    let output = gh_command()
        .args(["api", &format!("/repos/{repo}")])
        .output()
        .map_err(|err| format!("failed to execute gh api for default branch: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving default branch: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from default branch API response: {err}"))?;
    value
        .get("default_branch")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "default_branch missing from repository API response".to_string())
}

pub(super) fn fetch_pr_data(repo: &str, pr_number: u32) -> Result<serde_json::Value, String> {
    let output = gh_command()
        .args(["api", &format!("/repos/{repo}/pulls/{pr_number}")])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR metadata: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving PR #{pr_number}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from PR metadata API response: {err}"))
}

pub(super) fn resolve_actor_permission(repo: &str, actor: &str) -> Result<String, String> {
    if actor.is_empty() || actor == "unknown" {
        return Ok("none".to_string());
    }
    let output = gh_command()
        .args([
            "api",
            &format!("/repos/{repo}/collaborators/{actor}/permission"),
        ])
        .output()
        .map_err(|err| format!("failed to execute gh api for actor permission: {err}"))?;
    if !output.status.success() {
        return Ok("none".to_string());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from actor permission API response: {err}"))?;
    Ok(value
        .get("permission")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("none")
        .to_string())
}

pub(super) fn fetch_pr_head_sha(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = gh_command()
        .args(["api", &endpoint, "--jq", ".head.sha"])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR head SHA: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving PR head SHA: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.is_empty() {
        return Err("gh api returned empty head sha".to_string());
    }
    Ok(sha)
}
