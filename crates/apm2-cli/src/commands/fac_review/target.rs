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

    let _ = persist_identity_hint(&resolved.0, resolved.1);
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
    parse_owner_repo_from_remote_url(&remote).ok_or_else(|| {
        format!("unsupported origin remote URL format for repository derivation: `{remote}`")
    })
}

fn parse_owner_repo_from_remote_url(remote: &str) -> Option<String> {
    let trimmed = remote.trim().trim_end_matches('/');
    let path = if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("http://github.com/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("ssh://git@github.com/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        rest
    } else {
        return None;
    };
    let normalized = path.trim_end_matches(".git").trim_end_matches('/');
    let mut parts = normalized.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
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

fn persist_identity_hint(owner_repo: &str, pr_number: u32) -> Result<(), String> {
    let head_sha = current_head_sha()?;
    projection_store::save_identity_with_context(owner_repo, pr_number, &head_sha, "target")
}

#[cfg(test)]
mod tests {
    use super::{parse_owner_repo_from_remote_url, resolve_pr_target};

    #[test]
    fn resolve_pr_target_accepts_pr_only() {
        let (repo, pr) = resolve_pr_target("owner/repo", Some(42)).expect("target");
        assert_eq!(repo, "owner/repo");
        assert_eq!(pr, 42);
    }

    #[test]
    fn parse_owner_repo_from_remote_url_accepts_https() {
        assert_eq!(
            parse_owner_repo_from_remote_url("https://github.com/test-org/test-repo.git"),
            Some("test-org/test-repo".to_string())
        );
    }

    #[test]
    fn parse_owner_repo_from_remote_url_accepts_ssh() {
        assert_eq!(
            parse_owner_repo_from_remote_url("git@github.com:test-org/test-repo.git"),
            Some("test-org/test-repo".to_string())
        );
    }

    #[test]
    fn parse_owner_repo_from_remote_url_rejects_non_github() {
        assert_eq!(
            parse_owner_repo_from_remote_url("https://example.com/test-org/test-repo.git"),
            None
        );
    }
}
