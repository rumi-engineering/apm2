//! GitHub read-only API helpers for FAC projection flows.

use apm2_core::fac::gh_command;

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

/// Check whether a pull request has been merged on GitHub.
///
/// Returns `Ok(Some(merged_at))` when the PR is merged, `Ok(None)` when it
/// is still open/closed-without-merge, or `Err` on API failure.
///
/// BF-002 (TCK-00626): Used by the doctor wait loop to detect externally-
/// merged PRs that the local lifecycle projection has not yet observed.
pub(super) fn fetch_pr_merged_at(
    owner_repo: &str,
    pr_number: u32,
) -> Result<Option<String>, String> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = gh_command()
        .args(["api", &endpoint, "--jq", ".merged_at"])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR merged_at: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving PR merged_at: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() || value == "null" {
        return Ok(None);
    }
    Ok(Some(value))
}

/// Fetch the base branch SHA for a pull request from the GitHub API.
///
/// Returns `pr.base.sha` — the tip of the base branch at the time the PR was
/// last updated.  Unlike the local `origin/main` ref, this value is stable
/// after merge: GitHub preserves it on the PR object even once the branch is
/// fast-forwarded into main.  Using this as the diff base in `prepare` ensures
/// reviewers always see the full PR diff regardless of local ref state.
pub(super) fn fetch_pr_base_sha(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = gh_command()
        .args(["api", &endpoint, "--jq", ".base.sha"])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR base SHA: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving PR base SHA: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.is_empty() {
        return Err("gh api returned empty base sha".to_string());
    }
    Ok(sha)
}
