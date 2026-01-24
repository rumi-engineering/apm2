//! Implementation of the `security-review-exec` command.
//!
//! This command provides execution tools for security reviewers:
//! - `cargo xtask security-review-exec approve <PR_URL>` - Approve PR after
//!   security review
//! - `cargo xtask security-review-exec deny <PR_URL> --reason <reason>` - Deny
//!   PR with reason
//! - `cargo xtask security-review-exec onboard` - Show required reading for
//!   reviewers
//!
//! All commands support `--dry-run` to preview actions without making API
//! calls.

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

/// Required reading paths for security reviewers.
pub const REQUIRED_READING: &[&str] = &[
    "documents/security/SECURITY_POLICY.md",
    "documents/security/CI_SECURITY_GATES.md",
    "documents/security/THREAT_MODEL.md",
    "documents/security/SECRETS_MANAGEMENT.md",
];

const STATUS_CONTEXT: &str = "ai-review/security";

/// Approval comment template.
const APPROVE_COMMENT: &str = r"## Security Review

**Status:** ✅ APPROVED

This PR has passed security review. No security issues were identified.

---
*Posted via `cargo xtask security-review-exec approve`*";

/// Generate denial comment with reason.
fn denial_comment(reason: &str) -> String {
    format!(
        r"## Security Review

**Status:** ❌ DENIED

### Reason
{reason}

Please address the security concerns above before this PR can be approved.

---
*Posted via `cargo xtask security-review-exec deny`*"
    )
}

/// Approve a PR after security review passes.
///
/// # Arguments
///
/// * `pr_url` - The GitHub PR URL
/// * `dry_run` - If true, preview without making API calls
///
/// # Errors
///
/// Returns an error if:
/// - The PR URL is invalid
/// - The PR is not open (closed/merged/missing)
/// - The API calls fail
pub fn approve(pr_url: &str, dry_run: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    println!("Security Review: APPROVE");
    println!("  PR: {pr_url}");
    if dry_run {
        println!("  Mode: DRY RUN (no API calls will be made)");
    }
    println!();

    // Parse PR URL
    let (owner_repo, pr_number) = parse_pr_url(pr_url)?;
    println!("[1/4] Parsed PR URL");
    println!("  Repository: {owner_repo}");
    println!("  PR Number: {pr_number}");

    // Validate PR is open
    println!("\n[2/4] Validating PR state...");
    validate_pr_is_open(&sh, &owner_repo, pr_number)?;
    println!("  PR is open.");

    // Get HEAD SHA
    println!("\n[3/4] Getting HEAD SHA...");
    let head_sha = get_pr_head_sha(&sh, &owner_repo, pr_number)?;
    println!("  HEAD SHA: {head_sha}");

    if dry_run {
        println!("\n[4/4] DRY RUN - Would perform:");
        println!("  - Post approval comment to PR #{pr_number}");
        println!("  - Update status {STATUS_CONTEXT} to 'success' on {head_sha}");
        println!("\nDry run complete. No changes were made.");
    } else {
        println!("\n[4/4] Posting approval...");

        // Post approval comment
        cmd!(sh, "gh pr comment {pr_url} --body {APPROVE_COMMENT}")
            .run()
            .context("Failed to post approval comment")?;
        println!("  Comment posted.");

        // Update status to success
        update_status(&sh, &owner_repo, &head_sha, true, "Approved")?;

        println!("\nSecurity review approval complete!");
        println!("  Status: {STATUS_CONTEXT} = success");
    }

    Ok(())
}

/// Deny a PR with a required reason.
///
/// # Arguments
///
/// * `pr_url` - The GitHub PR URL
/// * `reason` - The reason for denial
/// * `dry_run` - If true, preview without making API calls
///
/// # Errors
///
/// Returns an error if:
/// - The PR URL is invalid
/// - The PR is not open (closed/merged/missing)
/// - The API calls fail
pub fn deny(pr_url: &str, reason: &str, dry_run: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    println!("Security Review: DENY");
    println!("  PR: {pr_url}");
    println!("  Reason: {reason}");
    if dry_run {
        println!("  Mode: DRY RUN (no API calls will be made)");
    }
    println!();

    // Parse PR URL
    let (owner_repo, pr_number) = parse_pr_url(pr_url)?;
    println!("[1/4] Parsed PR URL");
    println!("  Repository: {owner_repo}");
    println!("  PR Number: {pr_number}");

    // Validate PR is open
    println!("\n[2/4] Validating PR state...");
    validate_pr_is_open(&sh, &owner_repo, pr_number)?;
    println!("  PR is open.");

    // Get HEAD SHA
    println!("\n[3/4] Getting HEAD SHA...");
    let head_sha = get_pr_head_sha(&sh, &owner_repo, pr_number)?;
    println!("  HEAD SHA: {head_sha}");

    if dry_run {
        println!("\n[4/4] DRY RUN - Would perform:");
        println!("  - Post denial comment to PR #{pr_number}");
        println!("  - Update status {STATUS_CONTEXT} to 'failure' on {head_sha}");
        println!("\nDry run complete. No changes were made.");
    } else {
        println!("\n[4/4] Posting denial...");

        // Post denial comment
        let comment = denial_comment(reason);
        cmd!(sh, "gh pr comment {pr_url} --body {comment}")
            .run()
            .context("Failed to post denial comment")?;
        println!("  Comment posted.");

        // Update status to failure
        update_status(&sh, &owner_repo, &head_sha, false, "Denied")?;

        println!("\nSecurity review denial complete!");
        println!("  Status: {STATUS_CONTEXT} = failure");
    }

    Ok(())
}

/// Show required reading for security reviewers.
///
/// Prints each required reading file path.
#[allow(clippy::unnecessary_wraps)]
pub fn onboard() -> Result<()> {
    println!("Security Reviewer Onboarding");
    println!("============================");
    println!();
    println!("Please read the following documents before conducting security reviews:");
    println!();

    for path in REQUIRED_READING {
        println!("  {path}");
    }

    println!();
    println!("After reading these documents, you will be prepared to:");
    println!("  - Evaluate PRs for security vulnerabilities");
    println!("  - Use `cargo xtask security-review-exec approve <PR_URL>` to approve");
    println!("  - Use `cargo xtask security-review-exec deny <PR_URL> --reason <reason>` to deny");

    Ok(())
}

/// Parse a GitHub PR URL to extract owner/repo and PR number.
///
/// Handles URLs like:
/// - `https://github.com/owner/repo/pull/123`
/// - `github.com/owner/repo/pull/123`
fn parse_pr_url(pr_url: &str) -> Result<(String, u32)> {
    let url = pr_url.trim();

    // Remove protocol if present
    let path = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Remove github.com prefix
    let path = path
        .strip_prefix("github.com/")
        .ok_or_else(|| anyhow::anyhow!("Invalid PR URL: must be a GitHub URL"))?;

    // Split into parts: owner/repo/pull/number
    let parts: Vec<&str> = path.split('/').collect();

    if parts.len() < 4 || parts[2] != "pull" {
        bail!(
            "Invalid PR URL format. Expected: https://github.com/owner/repo/pull/123\n\
             Got: {pr_url}"
        );
    }

    let owner = parts[0];
    let repo = parts[1];
    let pr_number: u32 = parts[3].parse().context("Invalid PR number in URL")?;

    Ok((format!("{owner}/{repo}"), pr_number))
}

/// Validate that a PR is open (not closed or merged).
fn validate_pr_is_open(sh: &Shell, owner_repo: &str, pr_number: u32) -> Result<()> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = cmd!(sh, "gh api {endpoint} --jq .state")
        .read()
        .context("Failed to get PR state - does the PR exist?")?;

    let state = output.trim();
    match state {
        "open" => Ok(()),
        "closed" => bail!("PR #{pr_number} is closed. Cannot update status on closed PRs."),
        _ => bail!("PR #{pr_number} has unexpected state: {state}"),
    }
}

/// Get the HEAD SHA of a PR.
fn get_pr_head_sha(sh: &Shell, owner_repo: &str, pr_number: u32) -> Result<String> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = cmd!(sh, "gh api {endpoint} --jq .head.sha")
        .read()
        .context("Failed to get PR HEAD SHA")?;

    let sha = output.trim().to_string();
    if sha.is_empty() {
        bail!("Could not get HEAD SHA for PR #{pr_number}");
    }

    Ok(sha)
}

/// Update the status check for security review.
fn update_status(
    sh: &Shell,
    owner_repo: &str,
    head_sha: &str,
    success: bool,
    description: &str,
) -> Result<()> {
    let state = if success { "success" } else { "failure" };
    let endpoint = format!("/repos/{owner_repo}/statuses/{head_sha}");

    cmd!(
        sh,
        "gh api --method POST {endpoint} -f state={state} -f context={STATUS_CONTEXT} -f description={description}"
    )
    .run()
    .context("Failed to update status check")?;

    println!("  Updated status: {STATUS_CONTEXT} = {state}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn test_required_reading_files_exist() {
        let repo_root = std::env::var("CARGO_MANIFEST_DIR")
            .map(|p| Path::new(&p).parent().unwrap().to_path_buf())
            .unwrap();

        for path in REQUIRED_READING {
            let full_path = repo_root.join(path);
            assert!(full_path.exists(), "Required reading file missing: {path}");
        }
    }

    #[test]
    fn test_parse_pr_url_https() {
        let (owner_repo, pr_number) =
            parse_pr_url("https://github.com/owner/repo/pull/123").unwrap();
        assert_eq!(owner_repo, "owner/repo");
        assert_eq!(pr_number, 123);
    }

    #[test]
    fn test_parse_pr_url_no_protocol() {
        let (owner_repo, pr_number) = parse_pr_url("github.com/owner/repo/pull/456").unwrap();
        assert_eq!(owner_repo, "owner/repo");
        assert_eq!(pr_number, 456);
    }

    #[test]
    fn test_parse_pr_url_with_trailing_path() {
        let (owner_repo, pr_number) =
            parse_pr_url("https://github.com/owner/repo/pull/789/files").unwrap();
        assert_eq!(owner_repo, "owner/repo");
        assert_eq!(pr_number, 789);
    }

    #[test]
    fn test_parse_pr_url_invalid_not_github() {
        let result = parse_pr_url("https://gitlab.com/owner/repo/pull/123");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pr_url_invalid_not_pull() {
        let result = parse_pr_url("https://github.com/owner/repo/issues/123");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pr_url_invalid_no_number() {
        let result = parse_pr_url("https://github.com/owner/repo/pull/");
        assert!(result.is_err());
    }

    #[test]
    fn test_denial_comment_includes_reason() {
        let comment = denial_comment("XSS vulnerability in input handling");
        assert!(comment.contains("XSS vulnerability in input handling"));
        assert!(comment.contains("DENIED"));
    }

    #[test]
    fn test_approve_comment_format() {
        assert!(APPROVE_COMMENT.contains("APPROVED"));
        assert!(APPROVE_COMMENT.contains("security-review-exec approve"));
    }
}
