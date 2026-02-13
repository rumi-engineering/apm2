//! Shared pull-request target resolution helpers for FAC review commands.

use std::process::Command;

use super::projection_store;
use super::types::{parse_pr_url, validate_expected_head_sha};

pub fn resolve_pr_target(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
) -> Result<(String, u32), String> {
    let from_url = pr_url.map(parse_pr_url).transpose()?;
    let resolved = match (pr_number, from_url) {
        (Some(number), Some((owner_repo, url_number))) => {
            if number != url_number {
                return Err(format!(
                    "review target mismatch: --pr={number} but --pr-url resolves to #{url_number}"
                ));
            }
            (owner_repo, number)
        },
        (Some(number), None) => (repo.to_string(), number),
        (None, Some((owner_repo, number))) => (owner_repo, number),
        (None, None) => {
            let branch = current_branch()?;

            if let Some(identity) = projection_store::load_branch_identity(repo, &branch)? {
                return Ok((identity.owner_repo, identity.pr_number));
            }

            return Err(format!(
                "no local PR mapping found for branch `{branch}` in repo `{repo}`; pass --pr <N> or --pr-url <URL> to run explicitly"
            ));
        },
    };

    let _ = persist_identity_hint(&resolved.0, resolved.1);
    Ok(resolved)
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

fn current_head_sha() -> Result<String, String> {
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
    use super::resolve_pr_target;

    #[test]
    fn resolve_pr_target_accepts_pr_only() {
        let (repo, pr) = resolve_pr_target("owner/repo", Some(42), None).expect("target");
        assert_eq!(repo, "owner/repo");
        assert_eq!(pr, 42);
    }

    #[test]
    fn resolve_pr_target_accepts_pr_url_only() {
        let (repo, pr) = resolve_pr_target(
            "owner/repo",
            None,
            Some("https://github.com/test-org/test-repo/pull/42"),
        )
        .expect("target");
        assert_eq!(repo, "test-org/test-repo");
        assert_eq!(pr, 42);
    }

    #[test]
    fn resolve_pr_target_rejects_mismatched_pr_and_url() {
        let err = resolve_pr_target(
            "owner/repo",
            Some(100),
            Some("https://github.com/test-org/test-repo/pull/99"),
        )
        .expect_err("mismatch should fail");
        assert!(err.contains("--pr=100"));
        assert!(err.contains("#99"));
    }
}
