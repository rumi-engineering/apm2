//! Shared pull-request target resolution helpers for FAC review commands.

use std::process::Command;

use super::projection_store;
use super::types::validate_expected_head_sha;

pub(super) const REVIEW_CTX_OWNER_REPO_ENV: &str = "APM2_FAC_OWNER_REPO";
pub(super) const REVIEW_CTX_PR_NUMBER_ENV: &str = "APM2_FAC_PR_NUMBER";
pub(super) const REVIEW_CTX_HEAD_SHA_ENV: &str = "APM2_FAC_HEAD_SHA";
pub(super) const REVIEW_CTX_REVIEW_TYPE_ENV: &str = "APM2_FAC_REVIEW_TYPE";
pub(super) const REVIEW_CTX_RUN_ID_ENV: &str = "APM2_FAC_RUN_ID";

pub fn resolve_pr_target(repo: &str, pr_number: Option<u32>) -> Result<(String, u32), String> {
    resolve_pr_target_with(
        repo,
        pr_number,
        resolve_env_target,
        current_branch,
        resolve_branch_hint_target,
        current_head_sha,
        resolve_head_hint_target,
    )
}

fn resolve_pr_target_with<FEnv, FBranch, FBranchHint, FHead, FHeadHint>(
    repo: &str,
    pr_number: Option<u32>,
    mut resolve_env_target_fn: FEnv,
    mut current_branch_fn: FBranch,
    mut resolve_branch_hint_target_fn: FBranchHint,
    mut current_head_sha_fn: FHead,
    mut resolve_head_hint_target_fn: FHeadHint,
) -> Result<(String, u32), String>
where
    FEnv: FnMut(&str) -> Result<Option<(String, u32)>, String>,
    FBranch: FnMut() -> Result<String, String>,
    FBranchHint: FnMut(&str, &str) -> Result<Option<(String, u32)>, String>,
    FHead: FnMut() -> Result<String, String>,
    FHeadHint: FnMut(&str, &str) -> Result<Option<(String, u32)>, String>,
{
    if let Some(number) = pr_number {
        return Ok((repo.to_string(), number));
    }

    if let Some(env_target) = resolve_env_target_fn(repo)? {
        return Ok(env_target);
    }

    let branch = current_branch_fn()?;
    if let Some(branch_target) = resolve_branch_hint_target_fn(repo, &branch)? {
        return Ok(branch_target);
    }

    if let Ok(head_sha) = current_head_sha_fn()
        && let Some(head_target) = resolve_head_hint_target_fn(repo, &head_sha)?
    {
        return Ok(head_target);
    }

    Err(format!(
        "no local PR mapping found for branch `{branch}` (repo `{repo}`); tried reviewer env context and head-sha projection lookup; pass --pr <N> to run explicitly"
    ))
}

fn resolve_env_target(repo: &str) -> Result<Option<(String, u32)>, String> {
    let owner_repo = std::env::var(REVIEW_CTX_OWNER_REPO_ENV).ok();
    let pr_number = std::env::var(REVIEW_CTX_PR_NUMBER_ENV).ok();
    let Some(owner_repo) = owner_repo else {
        return Ok(None);
    };
    let Some(pr_number_raw) = pr_number else {
        eprintln!(
            "warn: ignoring partial reviewer context env (missing {REVIEW_CTX_PR_NUMBER_ENV})"
        );
        return Ok(None);
    };
    if !owner_repo.eq_ignore_ascii_case(repo) {
        eprintln!(
            "warn: ignoring reviewer context env repo `{owner_repo}` because command repo is `{repo}`"
        );
        return Ok(None);
    }
    let pr_number = pr_number_raw.parse::<u32>().map_err(|err| {
        format!("invalid {REVIEW_CTX_PR_NUMBER_ENV} value `{pr_number_raw}`: {err}")
    })?;
    if pr_number == 0 {
        return Err(format!(
            "invalid {REVIEW_CTX_PR_NUMBER_ENV} value `{pr_number_raw}`: PR number must be > 0"
        ));
    }
    Ok(Some((repo.to_string(), pr_number)))
}

fn resolve_branch_hint_target(repo: &str, branch: &str) -> Result<Option<(String, u32)>, String> {
    Ok(projection_store::load_branch_identity(repo, branch)?
        .map(|identity| (identity.owner_repo, identity.pr_number)))
}

fn resolve_head_hint_target(repo: &str, head_sha: &str) -> Result<Option<(String, u32)>, String> {
    Ok(
        projection_store::load_pr_identity_by_head_sha(repo, head_sha)?
            .map(|identity| (identity.owner_repo, identity.pr_number)),
    )
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
    use super::resolve_pr_target_with;

    #[test]
    fn resolve_pr_target_accepts_pr_only() {
        let (repo, pr) = resolve_pr_target_with(
            "owner/repo",
            Some(42),
            |_repo| panic!("env target should not be resolved"),
            || panic!("branch should not be resolved"),
            |_repo, _branch| panic!("branch hint should not be resolved"),
            || panic!("head should not be resolved"),
            |_repo, _head| panic!("head hint should not be resolved"),
        )
        .expect("target");
        assert_eq!(repo, "owner/repo");
        assert_eq!(pr, 42);
    }

    #[test]
    fn resolve_pr_target_prefers_env_context_over_branch_hint() {
        let (repo, pr) = resolve_pr_target_with(
            "owner/repo",
            None,
            |_repo| Ok(Some(("owner/repo".to_string(), 111))),
            || Ok("ticket/TCK-00640".to_string()),
            |_repo, _branch| Ok(Some(("owner/repo".to_string(), 222))),
            || Ok("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            |_repo, _head| Ok(Some(("owner/repo".to_string(), 333))),
        )
        .expect("resolved from env");
        assert_eq!(repo, "owner/repo");
        assert_eq!(pr, 111);
    }

    #[test]
    fn resolve_pr_target_falls_back_to_head_hint_when_branch_hint_missing() {
        let (repo, pr) = resolve_pr_target_with(
            "owner/repo",
            None,
            |_repo| Ok(None),
            || Ok("ticket/TCK-00640".to_string()),
            |_repo, _branch| Ok(None),
            || Ok("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            |_repo, _head| Ok(Some(("owner/repo".to_string(), 640))),
        )
        .expect("resolved from head hint");
        assert_eq!(repo, "owner/repo");
        assert_eq!(pr, 640);
    }

    #[test]
    fn resolve_pr_target_errors_when_all_fallbacks_miss() {
        let err = resolve_pr_target_with(
            "owner/repo",
            None,
            |_repo| Ok(None),
            || Ok("ticket/TCK-00640".to_string()),
            |_repo, _branch| Ok(None),
            || Ok("cccccccccccccccccccccccccccccccccccccccc".to_string()),
            |_repo, _head| Ok(None),
        )
        .expect_err("missing mapping must error");
        assert!(err.contains("no local PR mapping found"));
        assert!(err.contains("head-sha projection lookup"));
    }
}
