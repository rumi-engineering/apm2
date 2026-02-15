//! Shared pull-request target resolution helpers for FAC review commands.

use std::process::Command;

use super::projection_store;
use super::types::validate_expected_head_sha;

pub fn resolve_pr_target(repo: &str, pr_number: Option<u32>) -> Result<(String, u32), String> {
    let resolved = if let Some(number) = pr_number {
        (repo.to_string(), number)
    } else {
        let branch = current_branch()?;

        if let Some(identity) = projection_store::load_branch_identity(repo, &branch)? {
            return Ok((identity.owner_repo, identity.pr_number));
        }

        return Err(format!(
            "no local PR mapping found for branch `{branch}` in repo `{repo}`; pass --pr <N> to run explicitly"
        ));
    };

    Ok(resolved)
}

pub fn derive_repo_from_origin() -> Result<String, String> {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .map_err(|err| format!("failed to derive repository from git remote origin: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed to derive repository from git remote origin: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let (owner, repo) = apm2_core::github::parse_github_remote_url(&remote).ok_or_else(|| {
        format!("unsupported origin remote URL format for repository derivation: `{remote}`")
    })?;
    Ok(format!("{owner}/{repo}"))
}

pub fn current_branch() -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .map_err(|e| format!("failed to resolve current branch: {e}"))?;
    if !output.status.success() {
        return Err("git rev-parse --abbrev-ref HEAD failed".to_string());
    }
    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() || branch == "HEAD" {
        return Err("could not determine current branch (detached HEAD?)".to_string());
    }
    Ok(branch)
}

pub(super) fn current_head_sha() -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| format!("failed to resolve HEAD sha: {e}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed".to_string());
    }
    let sha = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    validate_expected_head_sha(&sha)?;
    Ok(sha)
}

#[cfg(test)]
mod tests {
    use super::resolve_pr_target;

    #[test]
    fn resolve_pr_target_accepts_pr_only() {
        let (repo, pr) = resolve_pr_target("owner/repo", Some(42)).expect("target");
        assert_eq!(repo, "owner/repo");
        assert_eq!(pr, 42);
    }

    // URL parsing tests are covered by
    // apm2_core::github::parse_github_remote_url tests.
}
