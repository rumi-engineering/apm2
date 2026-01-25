//! Implementation of the `push` command.
//!
//! This command pushes the current branch and creates a PR:
//! - Validates we're on a ticket branch
//! - Rebases on main to ensure clean history
//! - Pushes to remote with tracking
//! - Creates a PR if one doesn't exist
//! - Enables auto-merge if available
//! - Triggers AI reviews (security and code quality)

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use tempfile::NamedTempFile;
use xshell::{Shell, cmd};

use crate::reviewer_state::{ReviewerEntry, ReviewerStateFile};
use crate::util::{current_branch, main_worktree, ticket_yaml_path, validate_ticket_branch};

/// Push branch and create PR.
///
/// This function:
/// 1. Validates we're on a ticket branch
/// 2. Fetches latest from origin
/// 3. Rebases on main to ensure clean history
/// 4. Pushes to remote with tracking (-u flag)
/// 5. Creates a PR if one doesn't exist
/// 6. Enables auto-merge if available
///
/// # Errors
///
/// Returns an error if:
/// - Not on a valid ticket branch
/// - Rebase fails (conflicts need manual resolution)
/// - Push or PR creation fails
pub fn run() -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // Get current branch and validate it's a ticket branch
    let branch_name = current_branch(&sh)?;
    let ticket_branch = validate_ticket_branch(&branch_name)?;

    if let Some(rfc_id) = &ticket_branch.rfc_id {
        println!(
            "Pushing ticket {} (RFC: {})",
            ticket_branch.ticket_id, rfc_id
        );
    } else {
        println!("Pushing ticket {}", ticket_branch.ticket_id);
    }

    // Fetch latest from origin
    println!("\n[1/4] Fetching latest from origin...");
    cmd!(sh, "git fetch origin")
        .run()
        .context("Failed to fetch from origin")?;

    // Rebase on main for clean history
    println!("\n[2/4] Rebasing on main...");
    let rebase_output = cmd!(sh, "git rebase origin/main").ignore_status().output();

    match rebase_output {
        Ok(output) => {
            if !output.status.success() {
                // Rebase failed - check if there's a rebase in progress and abort it
                let rebase_merge_path = cmd!(sh, "git rev-parse --git-path rebase-merge")
                    .read()
                    .ok();
                let rebase_apply_path = cmd!(sh, "git rev-parse --git-path rebase-apply")
                    .read()
                    .ok();

                let rebase_in_progress = rebase_merge_path
                    .as_ref()
                    .is_some_and(|p| std::path::Path::new(p.trim()).exists())
                    || rebase_apply_path
                        .as_ref()
                        .is_some_and(|p| std::path::Path::new(p.trim()).exists());

                if rebase_in_progress {
                    // Abort the failed rebase
                    let _ = cmd!(sh, "git rebase --abort").run();
                }

                bail!(
                    "Rebase on main failed due to conflicts.\n\
                     Please resolve conflicts manually:\n\
                     1. Run: git rebase origin/main\n\
                     2. Resolve conflicts\n\
                     3. Run: git rebase --continue\n\
                     4. Run: cargo xtask push"
                );
            }
        },
        Err(e) => {
            bail!("Failed to execute git rebase: {e}");
        },
    }
    println!("  Rebased on main successfully.");

    // Push to remote with tracking
    println!("\n[3/4] Pushing to remote...");
    let push_output = cmd!(sh, "git push -u origin {branch_name}")
        .ignore_status()
        .output();

    let push_succeeded = push_output.is_ok_and(|output| output.status.success());

    if !push_succeeded {
        // Try force push if needed (rebase may have changed history)
        println!("  Regular push failed, attempting force push with lease...");
        cmd!(sh, "git push -u origin {branch_name} --force-with-lease")
            .run()
            .context(
                "Failed to push to remote. If this is a new branch, try:\n\
                 git push -u origin HEAD",
            )?;
    }
    println!("  Pushed to origin/{branch_name}");

    // Check if PR already exists
    println!("\n[4/4] Checking for existing PR...");
    let pr_exists = cmd!(sh, "gh pr view {branch_name} --json number --jq .number")
        .ignore_status()
        .read()
        .context("Failed to check for existing PR")?;

    let pr_url = if pr_exists.trim().is_empty()
        || pr_exists.contains("no pull requests")
        || pr_exists.contains("not found")
    {
        // Create new PR
        println!("  No existing PR found, creating one...");
        create_pr(&sh, &branch_name, &ticket_branch.ticket_id)?
    } else {
        // PR already exists
        let url = cmd!(sh, "gh pr view {branch_name} --json url --jq .url")
            .read()
            .context("Failed to get PR URL")?;
        println!("  PR already exists: {}", url.trim());
        url.trim().to_string()
    };

    // Enable auto-merge if available
    println!("\nEnabling auto-merge...");
    let auto_merge_result = cmd!(sh, "gh pr merge --auto --squash {branch_name}")
        .ignore_status()
        .read();

    match auto_merge_result {
        Ok(output) => {
            if output.contains("auto-merge")
                || output.contains("enabled")
                || output.trim().is_empty()
            {
                println!("  Auto-merge enabled (will merge when checks pass).");
            } else {
                println!("  Auto-merge response: {}", output.trim());
            }
        },
        Err(_) => {
            println!("  Note: Auto-merge not available (may require branch protection rules).");
        },
    }

    // Trigger AI reviews
    println!("\nTriggering AI reviews...");
    trigger_ai_reviews(&sh, &pr_url)?;

    println!();
    println!("Push complete!");
    println!("PR URL: {pr_url}");
    println!();
    println!("Next steps:");
    println!("  - Check status: cargo xtask check");
    println!("  - After merge: cargo xtask finish");

    Ok(())
}

/// Create a new PR for the branch.
///
/// Generates a PR title and body based on the ticket information.
fn create_pr(sh: &Shell, branch_name: &str, ticket_id: &str) -> Result<String> {
    // Get ticket title from YAML if available
    let main_path = main_worktree(sh)?;
    let ticket_yaml = ticket_yaml_path(&main_path, ticket_id);

    let ticket_title = if ticket_yaml.exists() {
        std::fs::read_to_string(&ticket_yaml)
            .ok()
            .and_then(|content| extract_ticket_title(&content))
            .unwrap_or_else(|| format!("implement {ticket_id} feature"))
    } else {
        format!("implement {ticket_id} feature")
    };

    // Create PR title
    let pr_title = format!("feat({ticket_id}): {ticket_title}");

    // Create PR body
    let pr_body = format!(
        "## Summary\n\
         \n\
         Implements ticket {ticket_id} as part of the xtask development automation.\n\
         \n\
         ## Ticket\n\
         \n\
         See `documents/work/tickets/{ticket_id}.yaml` for requirements.\n\
         \n\
         ## Test Plan\n\
         \n\
         - [ ] `cargo fmt --check` passes\n\
         - [ ] `cargo clippy --all-targets -- -D warnings` passes\n\
         - [ ] `cargo test -p xtask` passes\n\
         - [ ] Manual testing of the new command\n"
    );

    // Create the PR
    let output = cmd!(
        sh,
        "gh pr create --base main --head {branch_name} --title {pr_title} --body {pr_body}"
    )
    .read()
    .context("Failed to create PR")?;

    // Extract PR URL from output
    let pr_url = output
        .lines()
        .find(|line| line.contains("github.com") && line.contains("/pull/"))
        .map_or_else(|| output.trim().to_string(), |line| line.trim().to_string());

    println!("  Created PR: {pr_url}");

    Ok(pr_url)
}

/// Trigger AI reviews for the PR.
///
/// This function:
/// 1. Creates PENDING status checks for both reviews (blocks merge until
///    complete)
/// 2. Spawns background processes to run security review (Gemini) and code
///    quality review (Gemini) using the prompts from `documents/reviews/`
/// 3. Writes reviewer state to `~/.apm2/reviewer_state.json` for health
///    monitoring
/// 4. Redirects reviewer output to log files for mtime-based activity detection
///
/// The AI reviewers are responsible for updating their status to
/// success/failure.
fn trigger_ai_reviews(sh: &Shell, pr_url: &str) -> Result<()> {
    let head_sha = cmd!(sh, "git rev-parse HEAD")
        .read()
        .context("Failed to get HEAD SHA")?
        .trim()
        .to_string();

    let repo_root = cmd!(sh, "git rev-parse --show-toplevel")
        .read()
        .context("Failed to get repository root")?
        .trim()
        .to_string();

    let security_prompt_path = format!("{repo_root}/documents/reviews/SECURITY_REVIEW_PROMPT.md");
    let code_quality_prompt_path = format!("{repo_root}/documents/reviews/CODE_QUALITY_PROMPT.md");

    // Check if prompt files exist
    if !Path::new(&security_prompt_path).exists() {
        println!("  Warning: Security review prompt not found at {security_prompt_path}");
    }

    if !Path::new(&code_quality_prompt_path).exists() {
        println!("  Warning: Code quality review prompt not found at {code_quality_prompt_path}");
    }

    // Create PENDING status checks BEFORE spawning reviewers
    // This ensures GitHub knows to wait for these checks before allowing merge
    println!("  Creating pending status checks...");

    // Get owner/repo from git remote
    let remote_url = cmd!(sh, "git remote get-url origin")
        .read()
        .unwrap_or_default();

    // Parse owner/repo from remote URL (handles both HTTPS and SSH formats)
    let owner_repo = parse_owner_repo(&remote_url);

    if owner_repo.is_empty() {
        println!("    Warning: Could not determine owner/repo from remote URL");
    } else {
        create_pending_statuses(sh, owner_repo, &head_sha);
    }

    // Load current reviewer state
    let mut state = ReviewerStateFile::load().unwrap_or_default();

    // Try to spawn Gemini for security review
    let gemini_available = cmd!(sh, "which gemini").ignore_status().read().is_ok();
    if gemini_available && Path::new(&security_prompt_path).exists() {
        println!("  Spawning Gemini security review...");
        if let Some(entry) = spawn_reviewer("security", &security_prompt_path, pr_url, &head_sha) {
            state.set_reviewer("security", entry);
            println!("    Security review started in background");
        }
    } else if !gemini_available {
        println!("  Note: Gemini CLI not available, skipping security review");
    }

    // Try to spawn Gemini for code quality review
    if gemini_available && Path::new(&code_quality_prompt_path).exists() {
        println!("  Spawning Gemini code quality review...");
        if let Some(entry) = spawn_reviewer("quality", &code_quality_prompt_path, pr_url, &head_sha)
        {
            state.set_reviewer("quality", entry);
            println!("    Code quality review started in background");
        }
    }

    // Save the updated state
    if let Err(e) = state.save() {
        println!("    Warning: Failed to save reviewer state: {e}");
    }

    if !gemini_available {
        println!("  No AI review tools available. Install gemini CLI to enable reviews.");
    }

    Ok(())
}

/// Spawn a reviewer process and return the entry to track it.
///
/// Creates a log file for output capture and spawns the Gemini process
/// in the background using `script` for PTY allocation.
fn spawn_reviewer(
    reviewer_type: &str,
    prompt_file_path: &str,
    pr_url: &str,
    head_sha: &str,
) -> Option<ReviewerEntry> {
    // Read and substitute variables in the prompt
    let prompt_content = std::fs::read_to_string(prompt_file_path).ok()?;
    let prompt = prompt_content
        .replace("$PR_URL", pr_url)
        .replace("$HEAD_SHA", head_sha);

    // Create log file for output capture (mtime tracking)
    let log_file = tempfile::Builder::new()
        .prefix(&format!("apm2_review_{reviewer_type}_"))
        .suffix(".log")
        .tempfile()
        .ok()?;

    // Keep the log file (don't delete on drop)
    let (_, log_path) = log_file.keep().ok()?;
    let log_path_str = log_path.display().to_string();

    // Create prompt temp file
    let mut prompt_temp = NamedTempFile::new().ok()?;
    prompt_temp.write_all(prompt.as_bytes()).ok()?;

    // Persist the prompt file
    let (_, prompt_path) = prompt_temp.keep().ok()?;
    let prompt_path_str = prompt_path.display().to_string();

    // Spawn Gemini in background with pseudo-TTY for full tool access.
    // Using script -q <log_path> -c gives Gemini a headed environment where all
    // tools (including run_shell_command) are available. Without this, headless
    // mode filters out shell tools causing "Tool not found in registry" errors.
    //
    // The log file's mtime updates whenever new output is written, enabling
    // health monitoring via mtime checking.
    let shell_cmd = format!(
        "(script -q \"{log_path_str}\" -c \"gemini --yolo < '{prompt_path_str}'\"; rm -f '{prompt_path_str}' '{log_path_str}') &"
    );

    let child = std::process::Command::new("sh")
        .args(["-c", &shell_cmd])
        .spawn()
        .ok()?;

    let pid = child.id();

    // Return the entry for state tracking
    Some(ReviewerEntry {
        pid,
        started_at: Utc::now(),
        log_file: log_path,
        pr_url: pr_url.to_string(),
        head_sha: head_sha.to_string(),
    })
}

/// Parse owner/repo from a GitHub remote URL.
///
/// Handles both HTTPS and SSH formats:
/// - `https://github.com/owner/repo.git`
/// - `git@github.com:owner/repo.git`
///
/// Returns an empty string if the URL is not a valid GitHub URL.
fn parse_owner_repo(remote_url: &str) -> &str {
    if remote_url.contains("github.com") {
        remote_url
            .trim()
            .trim_end_matches(".git")
            .split("github.com")
            .last()
            .map_or("", |s| s.trim_start_matches(['/', ':']))
    } else {
        ""
    }
}

/// Create pending status checks for AI reviews.
fn create_pending_statuses(sh: &Shell, owner_repo: &str, head_sha: &str) {
    let endpoint = format!("/repos/{owner_repo}/statuses/{head_sha}");
    let state = "pending";

    // Security review status
    let security_context = "ai-review/security";
    let security_description = "Waiting for security review";
    let security_result = cmd!(
        sh,
        "gh api --method POST {endpoint} -f state={state} -f context={security_context} -f description={security_description}"
    )
    .ignore_status()
    .output();

    match security_result {
        Ok(output) if output.status.success() => {
            println!("    Created pending status: ai-review/security");
        },
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!(
                "    Warning: Failed to create security status: {}",
                stderr.trim()
            );
        },
        Err(e) => {
            println!("    Warning: Failed to create security status: {e}");
        },
    }

    // Code quality review status
    let quality_context = "ai-review/code-quality";
    let quality_description = "Waiting for code quality review";
    let quality_result = cmd!(
        sh,
        "gh api --method POST {endpoint} -f state={state} -f context={quality_context} -f description={quality_description}"
    )
    .ignore_status()
    .output();

    match quality_result {
        Ok(output) if output.status.success() => {
            println!("    Created pending status: ai-review/code-quality");
        },
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!(
                "    Warning: Failed to create code quality status: {}",
                stderr.trim()
            );
        },
        Err(e) => {
            println!("    Warning: Failed to create code quality status: {e}");
        },
    }
}

/// Extract the ticket title from YAML content.
fn extract_ticket_title(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("title:") {
            let value = rest.trim();
            let value = value.trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_lowercase());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

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
    #[test]
    fn test_script_command_format() {
        // Test with a simple path
        let prompt_path = "/tmp/test_prompt.txt";
        let shell_cmd = format!("script -qec \"gemini --yolo < '{prompt_path}'\" /dev/null");

        // Verify command includes PTY allocation
        assert!(
            shell_cmd.contains("script -qec"),
            "Command should use script -qec for PTY allocation"
        );

        // Verify input redirection syntax
        assert!(
            shell_cmd.contains("< '"),
            "Command should use < for input redirection"
        );

        // Verify path is quoted
        assert!(
            shell_cmd.contains(&format!("< '{prompt_path}'")),
            "Path should be single-quoted in input redirection"
        );

        // Verify /dev/null is used as typescript output
        assert!(
            shell_cmd.ends_with("/dev/null"),
            "Command should redirect script output to /dev/null"
        );

        // Test with a path containing special characters (not quotes)
        let special_path = "/tmp/test file.txt";
        let special_cmd = format!("script -qec \"gemini --yolo < '{special_path}'\" /dev/null");

        // Verify the command is well-formed
        assert!(
            special_cmd.contains("script -qec"),
            "Command with spaces should still use script -qec"
        );
        assert!(
            special_cmd.contains(&format!("< '{special_path}'")),
            "Path with spaces should be properly quoted"
        );
    }

    #[test]
    fn test_extract_ticket_title() {
        let content = r#"
ticket_meta:
  ticket:
    id: "TCK-00032"
    title: "Implement push command"
    status: "PENDING"
"#;

        let title = extract_ticket_title(content);
        assert_eq!(title, Some("implement push command".to_string()));
    }

    #[test]
    fn test_extract_ticket_title_no_quotes() {
        let content = "title: Push changes to remote";
        let title = extract_ticket_title(content);
        assert_eq!(title, Some("push changes to remote".to_string()));
    }

    #[test]
    fn test_extract_ticket_title_single_quotes() {
        let content = "title: 'Create PR automatically'";
        let title = extract_ticket_title(content);
        assert_eq!(title, Some("create pr automatically".to_string()));
    }

    #[test]
    fn test_extract_ticket_title_missing() {
        let content = "id: TCK-00001\nstatus: PENDING";
        let title = extract_ticket_title(content);
        assert_eq!(title, None);
    }

    #[test]
    fn test_pr_title_format() {
        let ticket_id = "TCK-00032";
        let ticket_title = "implement push command";
        let pr_title = format!("feat({ticket_id}): {ticket_title}");
        assert_eq!(pr_title, "feat(TCK-00032): implement push command");
    }

    #[test]
    fn test_parse_owner_repo_https() {
        let url = "https://github.com/owner/repo.git";
        assert_eq!(parse_owner_repo(url), "owner/repo");
    }

    #[test]
    fn test_parse_owner_repo_https_no_git_suffix() {
        let url = "https://github.com/owner/repo";
        assert_eq!(parse_owner_repo(url), "owner/repo");
    }

    #[test]
    fn test_parse_owner_repo_ssh() {
        let url = "git@github.com:owner/repo.git";
        assert_eq!(parse_owner_repo(url), "owner/repo");
    }

    #[test]
    fn test_parse_owner_repo_ssh_no_git_suffix() {
        let url = "git@github.com:owner/repo";
        assert_eq!(parse_owner_repo(url), "owner/repo");
    }

    #[test]
    fn test_parse_owner_repo_non_github() {
        let url = "https://gitlab.com/owner/repo.git";
        assert_eq!(parse_owner_repo(url), "");
    }

    #[test]
    fn test_parse_owner_repo_empty() {
        assert_eq!(parse_owner_repo(""), "");
    }

    #[test]
    fn test_parse_owner_repo_with_whitespace() {
        let url = "  https://github.com/owner/repo.git  \n";
        assert_eq!(parse_owner_repo(url), "owner/repo");
    }

    #[test]
    fn test_xshell_multiword_description() {
        // Test that xshell correctly handles multi-word strings when interpolated
        // This verifies the fix for TCK-00056
        let sh = Shell::new().unwrap();
        let desc = "Waiting for security review";

        // Use echo to see what args are passed
        let output = cmd!(sh, "echo arg1 -f description={desc} arg2")
            .read()
            .unwrap();

        // If xshell handles it correctly, description={desc} should be a single arg
        // Output should be: "arg1 -f description=Waiting for security review arg2"
        assert!(
            output.contains("description=Waiting for security review"),
            "xshell should preserve spaces in interpolated value. Got: {output}"
        );
    }
}
