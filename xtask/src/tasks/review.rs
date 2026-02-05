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

use std::path::Path;

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::reviewer_state::{ReviewerSpawner, select_review_model};
use crate::util::print_non_authoritative_banner;

/// Review type determines which prompt and status check to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewType {
    /// Security review using Gemini and `SECURITY_REVIEW_PROMPT.md`
    Security,
    /// Code quality review using Gemini and `CODE_QUALITY_PROMPT.md`
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
            Self::Security | Self::Quality => Some("gemini"),
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
/// # Arguments
///
/// * `pr_url` - GitHub PR URL
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
///
/// # Errors
///
/// Returns an error if:
/// - The PR URL is invalid
/// - The PR cannot be found
/// - The review prompt is missing
pub fn run_security(
    pr_url: &str,
    emit_internal: bool,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    run_review(
        pr_url,
        ReviewType::Security,
        emit_internal,
        emit_receipt_only,
        allow_github_write,
    )
}

/// Run a code quality review for a PR.
///
/// This function:
/// 1. Parses the PR URL to extract owner/repo and PR number
/// 2. Gets the HEAD SHA of the PR
/// 3. Reads the code quality review prompt
/// 4. Spawns Gemini to run the review (if available)
/// 5. The AI reviewer will post comments and update the status
///
/// # Arguments
///
/// * `pr_url` - GitHub PR URL
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
///
/// # Errors
///
/// Returns an error if:
/// - The PR URL is invalid
/// - The PR cannot be found
/// - The review prompt is missing
pub fn run_quality(
    pr_url: &str,
    emit_internal: bool,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    run_review(
        pr_url,
        ReviewType::Quality,
        emit_internal,
        emit_receipt_only,
        allow_github_write,
    )
}

/// Run a UAT (User Acceptance Testing) sign-off for a PR.
///
/// This is a manual sign-off that:
/// 1. Parses the PR URL
/// 2. Posts a UAT approval comment
/// 3. Updates the ai-review/uat status to success
///
/// # Arguments
///
/// * `pr_url` - GitHub PR URL
/// * `emit_internal` - If true, emit internal receipts to daemon (TCK-00295)
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
///
/// # Errors
///
/// Returns an error if:
/// - The PR URL is invalid
/// - The status update fails
pub fn run_uat(
    pr_url: &str,
    emit_internal: bool,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    run_review(
        pr_url,
        ReviewType::Uat,
        emit_internal,
        emit_receipt_only,
        allow_github_write,
    )
}

/// Run a review of the specified type.
fn run_review(
    pr_url: &str,
    review_type: ReviewType,
    emit_internal: bool,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // TCK-00295: Check if internal emission is enabled (flag or env var)
    let should_emit_internal = emit_internal || crate::util::emit_internal_from_env();
    if should_emit_internal {
        println!("  [TCK-00295] Internal receipt emission enabled");
    }

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
            run_uat_signoff(
                &sh,
                pr_url,
                &owner_repo,
                &head_sha,
                emit_receipt_only,
                allow_github_write,
            )?;
        },
        ReviewType::Security | ReviewType::Quality => {
            // AI reviews use prompts and tools
            run_ai_review(
                &sh,
                pr_url,
                &owner_repo,
                &head_sha,
                &repo_root,
                review_type,
                emit_receipt_only,
                allow_github_write,
            )?;
        },
    }

    // TCK-00295: Optionally emit internal receipt (non-blocking)
    if should_emit_internal {
        println!("\n  [EMIT_INTERNAL] Attempting internal receipt emission...");
        let event_type = match review_type {
            ReviewType::Security => "review.security.completed",
            ReviewType::Quality => "review.quality.completed",
            ReviewType::Uat => "review.uat.completed",
        };
        let payload = serde_json::json!({
            "pr_url": pr_url,
            "owner_repo": owner_repo,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "review_type": review_type.display_name(),
            "status": "completed",
            "non_authoritative": true,
        });
        let correlation_id = format!("review-{pr_number}-{head_sha}");

        // Non-blocking: errors are logged but don't fail the command
        if let Err(e) = crate::util::try_emit_internal_receipt(
            event_type,
            payload.to_string().as_bytes(),
            &correlation_id,
        ) {
            eprintln!("  [EMIT_INTERNAL] Warning: Failed to emit internal receipt: {e}");
        }
    }

    Ok(())
}

/// Run UAT sign-off.
fn run_uat_signoff(
    sh: &Shell,
    pr_url: &str,
    owner_repo: &str,
    head_sha: &str,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    use crate::util::{
        StatusWriteDecision, check_status_write_with_flags, emit_projection_request_receipt,
    };

    // TCK-00324: Check status write gating with CLI flags
    match check_status_write_with_flags(emit_receipt_only, allow_github_write) {
        StatusWriteDecision::EmitReceiptOnly => {
            // Emit receipt only, no direct GitHub write
            let payload = serde_json::json!({
                "comment": {
                    "body": "## UAT Review\n\n**Status:** APPROVED\n\nUser acceptance testing has been completed and approved.\n\n---\n*Signed off via `cargo xtask review uat`*"
                },
                "status": {
                    "context": "ai-review/uat",
                    "state": "success",
                    "description": "UAT approved"
                }
            });
            let correlation_id = format!("uat-signoff-{head_sha}");
            emit_projection_request_receipt(
                "uat_signoff",
                owner_repo,
                head_sha,
                &payload.to_string(),
                &correlation_id,
            )?;
            println!("\nUAT review receipt emitted (no direct write).");
            return Ok(());
        },
        StatusWriteDecision::SkipHefProjection => {
            println!("  [HEF] Skipping UAT signoff (USE_HEF_PROJECTION=true)");
            return Ok(());
        },
        StatusWriteDecision::BlockStrictMode => {
            anyhow::bail!(
                "Status writes blocked in strict mode. Set XTASK_ALLOW_STATUS_WRITES=true to allow."
            );
        },
        StatusWriteDecision::Proceed => {
            // Continue with direct write
        },
    }

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
        emit_receipt_only,
        allow_github_write,
    )?;

    println!("\nUAT review complete!");
    println!("  Status: ai-review/uat = success");

    Ok(())
}

/// Run an AI-powered review (security or quality).
#[allow(clippy::too_many_arguments)]
fn run_ai_review(
    sh: &Shell,
    pr_url: &str,
    owner_repo: &str,
    head_sha: &str,
    repo_root: &str,
    review_type: ReviewType,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    // Note: AI reviews spawn background processes that write their own status.
    // The cutover flags are checked in update_status when the AI reviewer
    // completes. For now, we just log that the flags are set.
    if emit_receipt_only && !allow_github_write {
        eprintln!(
            "  [TCK-00324] Note: emit-receipt-only mode active. AI reviewer will handle cutover."
        );
    }
    // Store flags for use in manual status update hint
    let _ = (emit_receipt_only, allow_github_write);

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

    // Determine the reviewer type key for state tracking
    let reviewer_type_key = match review_type {
        ReviewType::Security => "security",
        ReviewType::Quality => "quality",
        ReviewType::Uat => unreachable!("UAT is handled separately"),
    };

    // Read the prompt and substitute additional variables (owner/repo)
    let prompt_content =
        std::fs::read_to_string(&full_prompt_path).context("Failed to read review prompt")?;

    // Substitute all variables including owner/repo
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

    // Use ReviewerSpawner for centralized spawn logic (synchronous mode)
    let spawner = ReviewerSpawner::new(reviewer_type_key, pr_url, head_sha)
        .with_prompt_content(&prompt)
        .with_model(select_review_model());

    let status_context = review_type.status_context();
    match spawner.spawn_sync() {
        Ok(result) if result.status.success() => {
            println!(
                "  Gemini {} review completed.",
                review_type.display_name().to_lowercase()
            );
            println!("\n  Note: Gemini should have posted a comment and updated the status.");
            println!("  If not, you may need to update the status manually:");
            println!("    gh api --method POST /repos/{owner_repo}/statuses/{head_sha} \\");
            println!("      -f state=success -f context={status_context} \\");
            println!(
                "      -f description=\"{} review passed\"",
                review_type.display_name()
            );
        },
        Ok(result) => {
            println!("  Warning: Gemini exited with status: {}", result.status);
            println!("  You may need to run the review manually or check the output.");
        },
        Err(e) => {
            println!("  Warning: Failed to run Gemini: {e}");
            println!("  You may need to run the review manually or check the output.");
        },
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
///
/// # NON-AUTHORITATIVE OUTPUT
///
/// This function writes GitHub status checks as DEVELOPMENT SCAFFOLDING only.
/// Per RFC-0018 REQ-HEF-0001, these statuses are NOT the source of truth for
/// the HEF evidence pipeline.
///
/// # Arguments
///
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
#[allow(clippy::too_many_arguments)]
fn update_status(
    sh: &Shell,
    owner_repo: &str,
    head_sha: &str,
    review_type: ReviewType,
    success: bool,
    description: &str,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
    use crate::util::{
        StatusWriteDecision, check_status_write_with_flags, emit_projection_request_receipt,
    };

    let context = review_type.status_context();

    // TCK-00324: Check status write gating with CLI flags
    match check_status_write_with_flags(emit_receipt_only, allow_github_write) {
        StatusWriteDecision::SkipHefProjection => {
            println!("  [HEF] Skipping direct GitHub status write (USE_HEF_PROJECTION=true)");
            println!("  [HEF] Status would be: {context} = {success} - {description}");
            return Ok(());
        },
        StatusWriteDecision::EmitReceiptOnly => {
            // TCK-00324: Emit receipt only, no direct GitHub write
            let state = if success { "success" } else { "failure" };
            let payload = serde_json::json!({
                "context": context,
                "state": state,
                "description": description
            });
            let correlation_id = format!("status-{context}-{head_sha}");
            emit_projection_request_receipt(
                "status_write",
                owner_repo,
                head_sha,
                &payload.to_string(),
                &correlation_id,
            )?;
            println!("  [CUTOVER] Status update receipt emitted: {context} = {state}");
            return Ok(());
        },
        StatusWriteDecision::BlockStrictMode => {
            bail!(
                "Status writes blocked in strict mode.\n\
                 Set XTASK_ALLOW_STATUS_WRITES=true to allow.\n\
                 Status would be: {context} = {success} - {description}"
            );
        },
        StatusWriteDecision::Proceed => {
            // TCK-00296: Print non-strict mode warning
            crate::util::print_non_strict_mode_warning();
        },
    }

    // TCK-00294: Print NON-AUTHORITATIVE banner before status writes
    print_non_authoritative_banner();

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
    use std::os::unix::fs::PermissionsExt;

    use tempfile::NamedTempFile;

    use super::*;

    /// Test that `NamedTempFile` creates files with secure properties.
    ///
    /// Verifies:
    /// 1. Permissions are 0600 (owner read/write only)
    /// 2. Paths are unpredictable (different for each file)
    /// 3. Files are cleaned up after drop
    #[test]
    fn test_temp_file_security() {
        // Test 1: Verify permissions are 0600
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let metadata = temp_file
            .as_file()
            .metadata()
            .expect("Failed to get metadata");
        let mode = metadata.permissions().mode();

        // On Unix, mode includes file type bits. We only care about permission bits
        // (0o777 mask)
        let permission_bits = mode & 0o777;
        assert_eq!(
            permission_bits, 0o600,
            "Temp file should have 0600 permissions, got {permission_bits:o}"
        );

        // Test 2: Verify paths are unpredictable (different for each file)
        let temp_file1 = NamedTempFile::new().expect("Failed to create temp file 1");
        let temp_file2 = NamedTempFile::new().expect("Failed to create temp file 2");
        let path1 = temp_file1.path().to_path_buf();
        let path2 = temp_file2.path().to_path_buf();

        assert_ne!(
            path1, path2,
            "Temp file paths should be different (unpredictable)"
        );

        // Both paths should be in the system temp directory, not a fixed location
        let temp_dir = std::env::temp_dir();
        assert!(
            path1.starts_with(&temp_dir),
            "Temp file should be in system temp directory"
        );
        assert!(
            path2.starts_with(&temp_dir),
            "Temp file should be in system temp directory"
        );

        // Test 3: Verify cleanup after drop
        let path_to_check = temp_file.path().to_path_buf();
        assert!(path_to_check.exists(), "Temp file should exist before drop");
        drop(temp_file);
        assert!(
            !path_to_check.exists(),
            "Temp file should be cleaned up after drop"
        );
    }

    /// Test that script command format is valid for PTY allocation.
    ///
    /// Verifies:
    /// 1. Script command format includes PTY allocation via `script -qec`
    /// 2. Input redirection uses correct `<` syntax
    /// 3. Command properly quotes paths
    ///
    /// Note: These tests use the `shell_escape` module for secure path quoting.
    #[test]
    fn test_script_command_format() {
        use std::path::Path;

        use crate::shell_escape::build_script_command;

        // Test with a simple path (no log - uses -qec)
        let prompt_path = Path::new("/tmp/test_prompt.txt");
        let shell_cmd = build_script_command(prompt_path, None, None);

        // Verify command includes PTY allocation
        assert!(
            shell_cmd.contains("script -qec"),
            "Command should use script -qec for PTY allocation: {shell_cmd}"
        );

        // Verify input redirection syntax
        assert!(
            shell_cmd.contains("< "),
            "Command should use < for input redirection: {shell_cmd}"
        );

        // Verify /dev/null is used as typescript output
        assert!(
            shell_cmd.ends_with("/dev/null"),
            "Command should redirect script output to /dev/null: {shell_cmd}"
        );

        // Test with a path containing spaces - must be properly quoted
        let special_path = Path::new("/tmp/test file.txt");
        let special_cmd = build_script_command(special_path, None, None);

        // Verify the command is well-formed
        assert!(
            special_cmd.contains("script -qec"),
            "Command with spaces should still use script -qec: {special_cmd}"
        );
        // Path with spaces should be quoted (single quotes)
        assert!(
            special_cmd.contains('\''),
            "Path with spaces should be quoted: {special_cmd}"
        );
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
        assert_eq!(ReviewType::Quality.ai_tool(), Some("gemini"));
        assert_eq!(ReviewType::Uat.ai_tool(), None);
    }

    #[test]
    fn test_prompts_contain_placeholders() {
        let repo_root = std::env::var("CARGO_MANIFEST_DIR")
            .map(|p| std::path::Path::new(&p).parent().unwrap().to_path_buf())
            .unwrap();

        for review_type in [ReviewType::Security, ReviewType::Quality] {
            let prompt_path = review_type.prompt_path().unwrap();
            let full_path = repo_root.join(prompt_path);
            let content = std::fs::read_to_string(&full_path)
                .unwrap_or_else(|_| panic!("Failed to read prompt: {prompt_path}"));

            assert!(
                content.contains("$PR_URL"),
                "Prompt {prompt_path} missing $PR_URL placeholder"
            );
            assert!(
                content.contains("$HEAD_SHA"),
                "Prompt {prompt_path} missing $HEAD_SHA placeholder"
            );
        }
    }
}
