//! Implementation of the `review` command.
//!
//! This command provides manual invocation of AI reviews:
//! - `cargo xtask review security <PR_URL>` - Run security review
//! - `cargo xtask review quality <PR_URL>` - Run code quality review
//! - `cargo xtask review uat <PR_URL>` - Run UAT sign-off
//!
//! Each command:
//! 1. Reads the appropriate review prompt
//! 2. Runs the review (via AI tool or manual)
//! 3. Posts a PR comment with findings
//! 4. Updates the status check to success/failure

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use tempfile::NamedTempFile;
use xshell::{Shell, cmd};

/// Review type determines which prompt and status check to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewType {
    /// Security review using Gemini and `SECURITY_REVIEW_PROMPT.md`
    Security,
    /// Code quality review using Codex and `CODE_QUALITY_PROMPT.md`
    Quality,
    /// User acceptance testing (manual sign-off)
    Uat,
}

impl ReviewType {
    /// Get the status check context name for this review type.
    pub const fn status_context(self) -> &'static str {
        match self {
            Self::Security => "ai-review/security",
            Self::Quality => "ai-review/code-quality",
            Self::Uat => "ai-review/uat",
        }
    }

    /// Get the display name for this review type.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Security => "Security",
            Self::Quality => "Code Quality",
            Self::Uat => "UAT",
        }
    }

    /// Get the prompt file path relative to repo root.
    pub const fn prompt_path(self) -> Option<&'static str> {
        match self {
            Self::Security => Some("documents/reviews/SECURITY_REVIEW_PROMPT.md"),
            Self::Quality => Some("documents/reviews/CODE_QUALITY_PROMPT.md"),
            Self::Uat => None, // UAT is manual
        }
    }

    /// Get the AI tool command for this review type.
    pub const fn ai_tool(self) -> Option<&'static str> {
        match self {
            Self::Security => Some("gemini"),
            Self::Quality => Some("codex"),
            Self::Uat => None, // UAT is manual
        }
    }
}

/// Run a security review for a PR.
///
/// This function:
/// 1. Parses the PR URL to extract owner/repo and PR number
/// 2. Gets the HEAD SHA of the PR
/// 3. Reads the security review prompt
/// 4. Spawns Gemini to run the review (if available)
/// 5. The AI reviewer will post comments and update the status
///
/// # Errors
///
/// Returns an error if:
/// - The PR URL is invalid
/// - The PR cannot be found
/// - The review prompt is missing
pub fn run_security(pr_url: &str) -> Result<()> {
    run_review(pr_url, ReviewType::Security)
}

/// Run a code quality review for a PR.
///
/// This function:
/// 1. Parses the PR URL to extract owner/repo and PR number
/// 2. Gets the HEAD SHA of the PR
/// 3. Reads the code quality review prompt
/// 4. Spawns Codex to run the review (if available)
/// 5. The AI reviewer will post comments and update the status
///
/// # Errors
///
/// Returns an error if:
/// - The PR URL is invalid
/// - The PR cannot be found
/// - The review prompt is missing
pub fn run_quality(pr_url: &str) -> Result<()> {
    run_review(pr_url, ReviewType::Quality)
}

/// Run a UAT (User Acceptance Testing) sign-off for a PR.
///
/// This is a manual sign-off that:
/// 1. Parses the PR URL
/// 2. Posts a UAT approval comment
/// 3. Updates the ai-review/uat status to success
///
/// # Errors
///
/// Returns an error if:
/// - The PR URL is invalid
/// - The status update fails
pub fn run_uat(pr_url: &str) -> Result<()> {
    run_review(pr_url, ReviewType::Uat)
}

/// Run a review of the specified type.
fn run_review(pr_url: &str, review_type: ReviewType) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    println!(
        "Running {} review for: {}",
        review_type.display_name(),
        pr_url
    );

    // Parse PR URL to get owner/repo and PR number
    let (owner_repo, pr_number) = parse_pr_url(pr_url)?;
    println!("  Repository: {owner_repo}");
    println!("  PR Number: {pr_number}");

    // Get the HEAD SHA of the PR
    let head_sha = get_pr_head_sha(&sh, &owner_repo, pr_number)?;
    println!("  HEAD SHA: {head_sha}");

    // Get repository root for prompt files
    let repo_root = cmd!(sh, "git rev-parse --show-toplevel")
        .read()
        .context("Failed to get repository root")?
        .trim()
        .to_string();

    match review_type {
        ReviewType::Uat => {
            // UAT is a manual sign-off
            run_uat_signoff(&sh, pr_url, &owner_repo, &head_sha)?;
        },
        ReviewType::Security | ReviewType::Quality => {
            // AI reviews use prompts and tools
            run_ai_review(&sh, pr_url, &owner_repo, &head_sha, &repo_root, review_type)?;
        },
    }

    Ok(())
}

/// Run UAT sign-off.
fn run_uat_signoff(sh: &Shell, pr_url: &str, owner_repo: &str, head_sha: &str) -> Result<()> {
    println!("\n[1/2] Posting UAT approval comment...");

    let comment_body = "## UAT Review\n\n\
        **Status:** APPROVED\n\n\
        User acceptance testing has been completed and approved.\n\n\
        ---\n\
        *Signed off via `cargo xtask review uat`*";

    cmd!(sh, "gh pr comment {pr_url} --body {comment_body}")
        .run()
        .context("Failed to post UAT comment")?;

    println!("  Comment posted.");

    println!("\n[2/2] Updating status check...");
    update_status(
        sh,
        owner_repo,
        head_sha,
        ReviewType::Uat,
        true,
        "UAT approved",
    )?;

    println!("\nUAT review complete!");
    println!("  Status: ai-review/uat = success");

    Ok(())
}

/// Run an AI-powered review (security or quality).
fn run_ai_review(
    sh: &Shell,
    pr_url: &str,
    owner_repo: &str,
    head_sha: &str,
    repo_root: &str,
    review_type: ReviewType,
) -> Result<()> {
    let prompt_path = review_type
        .prompt_path()
        .expect("AI review types have prompt paths");
    let ai_tool = review_type
        .ai_tool()
        .expect("AI review types have AI tools");

    let full_prompt_path = format!("{repo_root}/{prompt_path}");

    // Check if prompt file exists
    if !Path::new(&full_prompt_path).exists() {
        bail!(
            "{} review prompt not found at: {}\n\
             Please create the prompt file first.",
            review_type.display_name(),
            full_prompt_path
        );
    }

    // Check if AI tool is available
    let tool_available = cmd!(sh, "which {ai_tool}")
        .ignore_status()
        .read()
        .is_ok_and(|output| !output.trim().is_empty());

    if !tool_available {
        bail!(
            "{ai_tool} CLI not found.\n\
             Please install {ai_tool} to run {} reviews, or run the review manually.",
            review_type.display_name()
        );
    }

    println!("\n[1/2] Reading review prompt...");
    let prompt_content =
        std::fs::read_to_string(&full_prompt_path).context("Failed to read review prompt")?;

    // Substitute variables in the prompt
    let prompt = prompt_content
        .replace("$PR_URL", pr_url)
        .replace("$HEAD_SHA", head_sha)
        .replace("{owner}", owner_repo.split('/').next().unwrap_or(""))
        .replace("{repo}", owner_repo.split('/').nth(1).unwrap_or(""));

    println!("  Prompt loaded from: {full_prompt_path}");

    println!(
        "\n[2/2] Running {} review with {ai_tool}...",
        review_type.display_name()
    );

    // Run the AI tool synchronously (not in background)
    // The AI tool is responsible for:
    // 1. Posting the review comment
    // 2. Updating the status check
    match review_type {
        ReviewType::Security => {
            // Spawn Gemini with pseudo-TTY for full tool access.
            // Using script -qec gives Gemini a headed environment where all tools
            // (including run_shell_command) are available. Without this, headless mode
            // filters out shell tools causing "Tool not found in registry" errors.
            //
            // We write the prompt to a secure temp file (via tempfile crate) to:
            // 1. Avoid shell escaping issues with complex markdown
            // 2. Use random filenames to prevent symlink/TOCTOU attacks
            // 3. Create with restrictive permissions (0600)
            // 4. Auto-cleanup when NamedTempFile is dropped
            // temp_file is auto-deleted when dropped at end of closure
            let result = NamedTempFile::new().and_then(|mut temp_file| {
                temp_file.write_all(prompt.as_bytes())?;
                let prompt_path = temp_file.path().display().to_string();
                let shell_cmd =
                    format!("script -qec \"gemini --yolo < '{prompt_path}'\" /dev/null");
                std::process::Command::new("sh")
                    .args(["-c", &shell_cmd])
                    .status()
            });

            match result {
                Ok(status) if status.success() => {
                    println!("  Gemini security review completed.");
                    println!(
                        "\n  Note: Gemini should have posted a comment and updated the status."
                    );
                    println!("  If not, you may need to update the status manually:");
                    println!("    gh api --method POST /repos/{owner_repo}/statuses/{head_sha} \\");
                    println!("      -f state=success -f context=ai-review/security \\");
                    println!("      -f description=\"Security review passed\"");
                },
                Ok(status) => {
                    println!("  Warning: Gemini exited with status: {status}");
                    println!("  You may need to run the review manually or check the output.");
                },
                Err(e) => {
                    println!("  Warning: Failed to run Gemini: {e}");
                    println!("  You may need to run the review manually or check the output.");
                },
            }
        },
        ReviewType::Quality => {
            // Codex uses the 'review' subcommand to review changes against base branch.
            // The review subcommand runs non-interactively by default.
            let result = std::process::Command::new("codex")
                .args(["review", "--base", "main"])
                .status();

            match result {
                Ok(status) if status.success() => {
                    println!("  Codex code quality review completed.");
                    println!(
                        "\n  Note: Codex should have posted a comment and updated the status."
                    );
                    println!("  If not, you may need to update the status manually:");
                    println!("    gh api --method POST /repos/{owner_repo}/statuses/{head_sha} \\");
                    println!("      -f state=success -f context=ai-review/code-quality \\");
                    println!("      -f description=\"Code quality review passed\"");
                },
                Ok(status) => {
                    println!("  Warning: Codex exited with status: {status}");
                    println!("  You may need to run the review manually or check the output.");
                },
                Err(e) => {
                    println!("  Warning: Failed to run Codex: {e}");
                    println!("  You may need to run the review manually or check the output.");
                },
            }
        },
        ReviewType::Uat => unreachable!("UAT is handled separately"),
    }

    println!("\n{} review complete!", review_type.display_name());

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

/// Update the status check for a review.
fn update_status(
    sh: &Shell,
    owner_repo: &str,
    head_sha: &str,
    review_type: ReviewType,
    success: bool,
    description: &str,
) -> Result<()> {
    let context = review_type.status_context();
    let state = if success { "success" } else { "failure" };
    let endpoint = format!("/repos/{owner_repo}/statuses/{head_sha}");

    cmd!(
        sh,
        "gh api --method POST {endpoint} -f state={state} -f context={context} -f description={description}"
    )
    .run()
    .context("Failed to update status check")?;

    println!("  Updated status: {context} = {state}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_review_type_status_context() {
        assert_eq!(ReviewType::Security.status_context(), "ai-review/security");
        assert_eq!(
            ReviewType::Quality.status_context(),
            "ai-review/code-quality"
        );
        assert_eq!(ReviewType::Uat.status_context(), "ai-review/uat");
    }

    #[test]
    fn test_review_type_display_name() {
        assert_eq!(ReviewType::Security.display_name(), "Security");
        assert_eq!(ReviewType::Quality.display_name(), "Code Quality");
        assert_eq!(ReviewType::Uat.display_name(), "UAT");
    }

    #[test]
    fn test_review_type_prompt_path() {
        assert!(ReviewType::Security.prompt_path().is_some());
        assert!(ReviewType::Quality.prompt_path().is_some());
        assert!(ReviewType::Uat.prompt_path().is_none());
    }

    #[test]
    fn test_review_type_ai_tool() {
        assert_eq!(ReviewType::Security.ai_tool(), Some("gemini"));
        assert_eq!(ReviewType::Quality.ai_tool(), Some("codex"));
        assert_eq!(ReviewType::Uat.ai_tool(), None);
    }
}
