//! Implementation of the `security-review-exec` command.
//!
//! This command provides execution tools for security reviewers:
//! - `cargo xtask security-review-exec approve [TCK-XXXXX]` - Approve PR after
//!   security review
//! - `cargo xtask security-review-exec deny [TCK-XXXXX] --reason <reason>` -
//!   Deny PR with reason
//! - `cargo xtask security-review-exec onboard` - Show required reading for
//!   reviewers
//!
//! If no ticket ID is provided, the commands use the current branch.
//! All commands support `--dry-run` to preview actions without making API
//! calls.

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::util::{current_branch, validate_ticket_branch};

/// Required reading paths for security reviewers.
pub const REQUIRED_READING: &[&str] = &[
    "documents/security/SECURITY_POLICY.md",
    "documents/security/CI_SECURITY_GATES.md",
    "documents/security/THREAT_MODEL.md",
    "documents/security/SECRETS_MANAGEMENT.md",
    "documents/skills/rust-standards/SKILL.md",
    
    "documents/skills/laws-of-holonic-agent-systems/references/agent-native-software/SKILL.md",
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

/// Resolved PR information.
struct ResolvedPr {
    owner_repo: String,
    pr_number: u32,
    ticket_id: String,
    pr_url: String,
}

/// Resolve ticket ID (or current branch) to PR information.
///
/// If `ticket_id` is provided, finds the branch for that ticket.
/// If None, uses the current branch and validates it's a ticket branch.
fn resolve_ticket_pr(sh: &Shell, ticket_id: Option<&str>) -> Result<ResolvedPr> {
    let (branch_name, resolved_ticket_id) = if let Some(id) = ticket_id {
        // Find the branch for this ticket
        let branch = find_branch_for_ticket(sh, id)?;
        (branch, id.to_string())
    } else {
        // Use current branch
        let branch = current_branch(sh)?;
        let ticket_branch = validate_ticket_branch(&branch)?;
        (branch, ticket_branch.ticket_id)
    };

    // Get PR number for the branch
    let pr_number_output = cmd!(sh, "gh pr view {branch_name} --json number --jq .number")
        .read()
        .with_context(|| format!("No PR found for branch '{branch_name}'"))?;

    let pr_number: u32 = pr_number_output
        .trim()
        .parse()
        .with_context(|| format!("Invalid PR number: {}", pr_number_output.trim()))?;

    // Get PR URL
    let pr_url = cmd!(sh, "gh pr view {branch_name} --json url --jq .url")
        .read()
        .context("Failed to get PR URL")?
        .trim()
        .to_string();

    // Get owner/repo from git remote
    let remote_url = cmd!(sh, "git remote get-url origin")
        .read()
        .context("Failed to get remote URL")?;

    let owner_repo = parse_owner_repo(&remote_url)?;

    Ok(ResolvedPr {
        owner_repo,
        pr_number,
        ticket_id: resolved_ticket_id,
        pr_url,
    })
}

/// Find the branch name for a given ticket ID.
///
/// Searches local and remote branches for patterns:
/// - `ticket/RFC-XXXX/{ticket_id}`
/// - `ticket/{ticket_id}`
fn find_branch_for_ticket(sh: &Shell, ticket_id: &str) -> Result<String> {
    // First try local branches
    let local_branches = cmd!(sh, "git branch --list *{ticket_id}*")
        .read()
        .context("Failed to list local branches")?;

    for line in local_branches.lines() {
        let branch = line
            .trim()
            .trim_start_matches("* ")
            .trim_start_matches("+ ");
        if branch.contains(ticket_id) && branch.starts_with("ticket/") {
            return Ok(branch.to_string());
        }
    }

    // Try remote branches
    let remote_branches = cmd!(sh, "git branch -r --list *{ticket_id}*")
        .read()
        .context("Failed to list remote branches")?;

    for line in remote_branches.lines() {
        let branch = line.trim().trim_start_matches("origin/");
        if branch.contains(ticket_id) && branch.starts_with("ticket/") {
            return Ok(branch.to_string());
        }
    }

    bail!(
        "No branch found for ticket {ticket_id}.\n\
         Expected branch format: ticket/RFC-XXXX/{ticket_id} or ticket/{ticket_id}"
    )
}

/// Parse owner/repo from a GitHub remote URL.
fn parse_owner_repo(remote_url: &str) -> Result<String> {
    let url = remote_url.trim();

    if !url.contains("github.com") {
        bail!("Remote URL is not a GitHub URL: {url}");
    }

    let path = url
        .trim_end_matches(".git")
        .split("github.com")
        .last()
        .ok_or_else(|| anyhow::anyhow!("Invalid GitHub URL format"))?
        .trim_start_matches(['/', ':']);

    Ok(path.to_string())
}

/// Approve a PR after security review passes.
///
/// # Arguments
///
/// * `ticket_id` - Optional ticket ID. If None, uses current branch.
/// * `dry_run` - If true, preview without making API calls
///
/// # Errors
///
/// Returns an error if:
/// - The ticket/branch has no PR
/// - The PR is not open (closed/merged/missing)
/// - The API calls fail
pub fn approve(ticket_id: Option<&str>, dry_run: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    println!("Security Review: APPROVE");
    if let Some(id) = ticket_id {
        println!("  Ticket: {id}");
    } else {
        println!("  Using current branch");
    }
    if dry_run {
        println!("  Mode: DRY RUN (no API calls will be made)");
    }
    println!();

    // Resolve ticket to PR
    println!("[1/4] Resolving ticket to PR...");
    let pr = resolve_ticket_pr(&sh, ticket_id)?;
    println!("  Ticket: {}", pr.ticket_id);
    println!("  Repository: {}", pr.owner_repo);
    println!("  PR Number: {}", pr.pr_number);
    println!("  PR URL: {}", pr.pr_url);

    // Validate PR is open
    println!("\n[2/4] Validating PR state...");
    validate_pr_is_open(&sh, &pr.owner_repo, pr.pr_number)?;
    println!("  PR is open.");

    // Get HEAD SHA
    println!("\n[3/4] Getting HEAD SHA...");
    let head_sha = get_pr_head_sha(&sh, &pr.owner_repo, pr.pr_number)?;
    println!("  HEAD SHA: {head_sha}");

    if dry_run {
        println!("\n[4/4] DRY RUN - Would perform:");
        println!("  - Post approval comment to PR #{}", pr.pr_number);
        println!("  - Update status {STATUS_CONTEXT} to 'success' on {head_sha}");
        println!("\nDry run complete. No changes were made.");
    } else {
        println!("\n[4/4] Posting approval...");

        // Post approval comment
        let pr_url = &pr.pr_url;
        cmd!(sh, "gh pr comment {pr_url} --body {APPROVE_COMMENT}")
            .run()
            .context("Failed to post approval comment")?;
        println!("  Comment posted.");

        // Update status to success
        update_status(&sh, &pr.owner_repo, &head_sha, true, "Approved")?;

        println!("\nSecurity review approval complete!");
        println!("  Status: {STATUS_CONTEXT} = success");
    }

    Ok(())
}

/// Deny a PR with a required reason.
///
/// # Arguments
///
/// * `ticket_id` - Optional ticket ID. If None, uses current branch.
/// * `reason` - The reason for denial
/// * `dry_run` - If true, preview without making API calls
///
/// # Errors
///
/// Returns an error if:
/// - The ticket/branch has no PR
/// - The PR is not open (closed/merged/missing)
/// - The API calls fail
pub fn deny(ticket_id: Option<&str>, reason: &str, dry_run: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    println!("Security Review: DENY");
    if let Some(id) = ticket_id {
        println!("  Ticket: {id}");
    } else {
        println!("  Using current branch");
    }
    println!("  Reason: {reason}");
    if dry_run {
        println!("  Mode: DRY RUN (no API calls will be made)");
    }
    println!();

    // Resolve ticket to PR
    println!("[1/4] Resolving ticket to PR...");
    let pr = resolve_ticket_pr(&sh, ticket_id)?;
    println!("  Ticket: {}", pr.ticket_id);
    println!("  Repository: {}", pr.owner_repo);
    println!("  PR Number: {}", pr.pr_number);
    println!("  PR URL: {}", pr.pr_url);

    // Validate PR is open
    println!("\n[2/4] Validating PR state...");
    validate_pr_is_open(&sh, &pr.owner_repo, pr.pr_number)?;
    println!("  PR is open.");

    // Get HEAD SHA
    println!("\n[3/4] Getting HEAD SHA...");
    let head_sha = get_pr_head_sha(&sh, &pr.owner_repo, pr.pr_number)?;
    println!("  HEAD SHA: {head_sha}");

    if dry_run {
        println!("\n[4/4] DRY RUN - Would perform:");
        println!("  - Post denial comment to PR #{}", pr.pr_number);
        println!("  - Update status {STATUS_CONTEXT} to 'failure' on {head_sha}");
        println!("\nDry run complete. No changes were made.");
    } else {
        println!("\n[4/4] Posting denial...");

        // Post denial comment
        let comment = denial_comment(reason);
        let pr_url = &pr.pr_url;
        cmd!(sh, "gh pr comment {pr_url} --body {comment}")
            .run()
            .context("Failed to post denial comment")?;
        println!("  Comment posted.");

        // Update status to failure
        update_status(&sh, &pr.owner_repo, &head_sha, false, "Denied")?;

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
    println!("Finding Associated RFC Design Decisions:");
    println!("---------------------------------------");
    println!("When reviewing a PR, you should locate the associated RFC design decisions");
    println!("to understand the architectural constraints and normative justifications.");
    println!("1. Extract the RFC ID (e.g., RFC-0013) from the PR title or body.");
    println!("2. The design decisions file is located at:");
    println!("   documents/rfcs/RFC-XXXX/02_design_decisions.yaml");

    println!();
    println!("After reading these documents, you will be prepared to:");
    println!("  - Evaluate PRs for security vulnerabilities");
    println!("  - Use `cargo xtask security-review-exec approve [TCK-XXXXX]` to approve");
    println!(
        "  - Use `cargo xtask security-review-exec deny [TCK-XXXXX] --reason <reason>` to deny"
    );
    println!();
    println!("If no ticket ID is provided, the current branch will be used.");

    Ok(())
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
    fn test_parse_owner_repo_https() {
        let owner_repo = parse_owner_repo("https://github.com/owner/repo.git").unwrap();
        assert_eq!(owner_repo, "owner/repo");
    }

    #[test]
    fn test_parse_owner_repo_https_no_git_suffix() {
        let owner_repo = parse_owner_repo("https://github.com/owner/repo").unwrap();
        assert_eq!(owner_repo, "owner/repo");
    }

    #[test]
    fn test_parse_owner_repo_ssh() {
        let owner_repo = parse_owner_repo("git@github.com:owner/repo.git").unwrap();
        assert_eq!(owner_repo, "owner/repo");
    }

    #[test]
    fn test_parse_owner_repo_ssh_no_git_suffix() {
        let owner_repo = parse_owner_repo("git@github.com:owner/repo").unwrap();
        assert_eq!(owner_repo, "owner/repo");
    }

    #[test]
    fn test_parse_owner_repo_invalid_not_github() {
        let result = parse_owner_repo("https://gitlab.com/owner/repo.git");
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
