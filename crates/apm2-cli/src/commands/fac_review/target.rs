//! Shared pull-request target resolution helpers for FAC review commands.

use std::process::Command;

use super::types::parse_pr_url;

pub fn resolve_pr_target(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
) -> Result<(String, u32), String> {
    let from_url = pr_url.map(parse_pr_url).transpose()?;
    match (pr_number, from_url) {
        (Some(number), Some((owner_repo, url_number))) => {
            if number != url_number {
                return Err(format!(
                    "review target mismatch: --pr={number} but --pr-url resolves to #{url_number}"
                ));
            }
            Ok((owner_repo, number))
        },
        (Some(number), None) => Ok((repo.to_string(), number)),
        (None, Some((owner_repo, number))) => Ok((owner_repo, number)),
        (None, None) => {
            let branch = current_branch()?;
            let number = find_pr_for_branch(repo, &branch).map_err(|err| {
                format!("{err}. pass --pr <N> or --pr-url <URL> to override auto-detection")
            })?;
            Ok((repo.to_string(), number))
        },
    }
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

pub fn find_pr_for_branch(repo: &str, branch: &str) -> Result<u32, String> {
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
        .map_err(|e| format!("failed to find PR for branch {branch}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh pr list failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let num_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    num_str
        .parse::<u32>()
        .map_err(|_| format!("no open PR found for branch {branch} in {repo}"))
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
            Some("https://github.com/guardian-intelligence/apm2/pull/123"),
        )
        .expect("target");
        assert_eq!(repo, "guardian-intelligence/apm2");
        assert_eq!(pr, 123);
    }

    #[test]
    fn resolve_pr_target_rejects_mismatched_pr_and_url() {
        let err = resolve_pr_target(
            "owner/repo",
            Some(100),
            Some("https://github.com/guardian-intelligence/apm2/pull/101"),
        )
        .expect_err("mismatch should fail");
        assert!(err.contains("--pr=100"));
        assert!(err.contains("#101"));
    }
}
