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
    "documents/security/AGENTS.cac.json",
    "documents/security/SECURITY_POLICY.cac.json",
    "documents/security/THREAT_MODEL.cac.json",
    "documents/security/INCIDENT_RESPONSE.cac.json",
    "documents/security/SECURITY_CHECKLIST.cac.json",
    "documents/security/SECRETS_MANAGEMENT.cac.json",
    "documents/security/NETWORK_DEFENSE.cac.json",
    "documents/security/SIGNING_AND_VERIFICATION.cac.json",
    "documents/security/RELEASE_PROCEDURE.cac.json",
    "documents/security/consensus-runbook.cac.json",
    "documents/skills/rust-standards/SKILL.md",
    "documents/theory/glossary/glossary.json",
    "documents/theory/AGENTS.md",
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
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
///
/// # Errors
///
/// Returns an error if:
/// - The ticket/branch has no PR
/// - The PR is not open (closed/merged/missing)
/// - The API calls fail
pub fn approve(ticket_id: Option<&str>, dry_run: bool, emit_internal: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // TCK-00295: Check if internal emission is enabled (flag or env var)
    let should_emit_internal = emit_internal || crate::util::emit_internal_from_env();
    if should_emit_internal {
        println!("  [TCK-00295] Internal receipt emission enabled");
    }

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

        // TCK-00295: Optionally emit internal receipt (non-blocking)
        if should_emit_internal {
            println!("\n  [EMIT_INTERNAL] Attempting internal receipt emission...");
            let payload = serde_json::json!({
                "ticket_id": pr.ticket_id,
                "pr_url": pr.pr_url,
                "owner_repo": pr.owner_repo,
                "pr_number": pr.pr_number,
                "head_sha": head_sha,
                "verdict": "approved",
                "non_authoritative": true,
            });
            let correlation_id = format!("security-approve-{}-{}", pr.pr_number, head_sha);

            // Non-blocking: errors are logged but don't fail the command
            if let Err(e) = crate::util::try_emit_internal_receipt(
                "security.review.approved",
                payload.to_string().as_bytes(),
                &correlation_id,
            ) {
                eprintln!("  [EMIT_INTERNAL] Warning: Failed to emit internal receipt: {e}");
            }
        }
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
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
///
/// # Errors
///
/// Returns an error if:
/// - The ticket/branch has no PR
/// - The PR is not open (closed/merged/missing)
/// - The API calls fail
pub fn deny(
    ticket_id: Option<&str>,
    reason: &str,
    dry_run: bool,
    emit_internal: bool,
) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // TCK-00295: Check if internal emission is enabled (flag or env var)
    let should_emit_internal = emit_internal || crate::util::emit_internal_from_env();

    // If reason is "-", read from stdin [SECURITY: CTR-2616 - Safe Piping]
    let actual_reason = if reason == "-" {
        use std::io::Read;
        println!("Reading denial reason from stdin...");
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .context("Failed to read reason from stdin")?;
        buffer
    } else {
        reason.to_string()
    };

    println!("Security Review: DENY");
    if let Some(id) = ticket_id {
        println!("  Ticket: {id}");
    } else {
        println!("  Using current branch");
    }

    if reason == "-" {
        println!("  Reason: (read from stdin)");
    } else {
        println!("  Reason: {actual_reason}");
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
        println!("  - Post denial comment to PR #{}", pr.pr_number);
        println!("  - Update status {STATUS_CONTEXT} to 'failure' on {head_sha}");
        println!("\nDry run complete. No changes were made.");
    } else {
        println!("\n[4/4] Posting denial...");

        // Post denial comment
        let comment = denial_comment(&actual_reason);
        let pr_url = &pr.pr_url;
        cmd!(sh, "gh pr comment {pr_url} --body {comment}")
            .run()
            .context("Failed to post denial comment")?;
        println!("  Comment posted.");

        // Update status to failure
        update_status(&sh, &pr.owner_repo, &head_sha, false, "Denied")?;

        println!("\nSecurity review denial complete!");
        println!("  Status: {STATUS_CONTEXT} = failure");

        // TCK-00295: Optionally emit internal receipt (non-blocking)
        if should_emit_internal {
            println!("\n  [EMIT_INTERNAL] Attempting internal receipt emission...");
            let payload = serde_json::json!({
                "ticket_id": pr.ticket_id,
                "pr_url": pr.pr_url,
                "owner_repo": pr.owner_repo,
                "pr_number": pr.pr_number,
                "head_sha": head_sha,
                "verdict": "denied",
                "reason": actual_reason,
                "non_authoritative": true,
            });
            let correlation_id = format!("security-deny-{}-{}", pr.pr_number, head_sha);

            // Non-blocking: errors are logged but don't fail the command
            if let Err(e) = crate::util::try_emit_internal_receipt(
                "security.review.denied",
                payload.to_string().as_bytes(),
                &correlation_id,
            ) {
                eprintln!("  [EMIT_INTERNAL] Warning: Failed to emit internal receipt: {e}");
            }
        }
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

/// Log that the security review status check would have been updated (writes
/// are removed).
///
/// # TCK-00297 (Stage X3): Status writes permanently removed
///
/// Per RFC-0018, direct GitHub status writes from xtask have been removed.
/// This function logs what the status would have been for diagnostic purposes
/// and returns `Ok(())`. The `_sh` parameter is retained for call-site
/// compatibility.
fn update_status(
    _sh: &Shell,
    owner_repo: &str,
    head_sha: &str,
    success: bool,
    description: &str,
) -> Result<()> {
    use crate::util::{
        StatusWriteDecision, check_status_write_allowed, emit_projection_request_receipt,
    };

    let state = if success { "success" } else { "failure" };

    // TCK-00297 (Stage X3): Status writes are permanently removed.
    match check_status_write_allowed() {
        StatusWriteDecision::Removed => {
            println!(
                "  [TCK-00297] GitHub status write removed. Would have set on {owner_repo}@{head_sha}:"
            );
            println!("    context: {STATUS_CONTEXT}");
            println!("    state:   {state}");
            println!("    desc:    {description}");
            crate::util::print_status_writes_removed_notice();
            Ok(())
        },
        // Legacy variants preserved for backwards compatibility but never returned.
        StatusWriteDecision::SkipHefProjection => {
            println!("  [HEF] Skipping direct GitHub status write (USE_HEF_PROJECTION=true)");
            println!("  [HEF] Status would be: {STATUS_CONTEXT} = {success} - {description}");
            Ok(())
        },
        StatusWriteDecision::EmitReceiptOnly => {
            // TCK-00324: Emit receipt only, no direct GitHub write
            let state = if success { "success" } else { "failure" };
            let payload = serde_json::json!({
                "context": STATUS_CONTEXT,
                "state": state,
                "description": description
            });
            let correlation_id = format!("security-exec-{head_sha}");
            emit_projection_request_receipt(
                "status_write",
                owner_repo,
                head_sha,
                &payload.to_string(),
                &correlation_id,
            )?;
            println!(
                "  [CUTOVER] Security review status receipt emitted: {STATUS_CONTEXT} = {state}"
            );
            return Ok(());
        },
        StatusWriteDecision::BlockStrictMode => {
            bail!(
                "Status writes blocked in strict mode.\n\
                 Status would be: {STATUS_CONTEXT} = {success} - {description}"
            );
        },
        StatusWriteDecision::Proceed => {
            // TCK-00297: Even if somehow reached, do not write.
            println!(
                "  [TCK-00297] GitHub status writes removed. Status would be: {STATUS_CONTEXT} = {state} - {description}"
            );
            Ok(())
        },
    }
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
