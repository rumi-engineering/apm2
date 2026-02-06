//! Implementation of the `push` command.
//!
//! This command pushes the current branch and creates a PR:
//! - Validates we're on a ticket branch
//! - Rebases on main to ensure clean history
//! - Pushes to remote with tracking
//! - Creates a PR if one doesn't exist
//! - Enables auto-merge if available
//! - Triggers AI reviews (security and code quality)

use std::path::Path;

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::reviewer_state::{ReviewerSpawner, select_review_model};
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
/// # Arguments
///
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
///
/// # Errors
///
/// Returns an error if:
/// - Not on a valid ticket branch
/// - Rebase fails (conflicts need manual resolution)
/// - Push or PR creation fails
pub fn run(emit_receipt_only: bool, allow_github_write: bool) -> Result<()> {
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
    trigger_ai_reviews(&sh, &pr_url, emit_receipt_only, allow_github_write)?;

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
/// 2. Spawns background processes to run security review (Codex) and code
///    quality review (Codex) using the prompts from `documents/reviews/`
/// 3. Writes reviewer state to `~/.apm2/reviewer_state.json` for health
///    monitoring
/// 4. Redirects reviewer output to log files for mtime-based activity detection
///
/// The AI reviewers are responsible for updating their status to
/// success/failure.
///
/// # Arguments
///
/// * `emit_receipt_only` - If true, emit receipt only (TCK-00324 cutover)
/// * `allow_github_write` - If true, allow direct GitHub writes
fn trigger_ai_reviews(
    sh: &Shell,
    pr_url: &str,
    emit_receipt_only: bool,
    allow_github_write: bool,
) -> Result<()> {
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
        create_pending_statuses(
            sh,
            owner_repo,
            &head_sha,
            emit_receipt_only,
            allow_github_write,
        );
    }

    // Try to spawn Codex for security review
    let codex_available = cmd!(sh, "which codex").ignore_status().read().is_ok();
    if codex_available && Path::new(&security_prompt_path).exists() {
        println!("  Spawning Codex security review...");
        let spawner = ReviewerSpawner::new("security", pr_url, &head_sha)
            .with_prompt_file(Path::new(&security_prompt_path))
            .map(|s| s.with_model(select_review_model()))
            .ok();

        if let Some(spawner) = spawner {
            if spawner.spawn_background().is_some() {
                println!("    Security review started in background");
            }
        }
    } else if !codex_available {
        println!("  Note: Codex CLI not available, skipping security review");
    }

    // Try to spawn Codex for code quality review
    if codex_available && Path::new(&code_quality_prompt_path).exists() {
        println!("  Spawning Codex code quality review...");
        let spawner = ReviewerSpawner::new("quality", pr_url, &head_sha)
            .with_prompt_file(Path::new(&code_quality_prompt_path))
            .map(|s| s.with_model(select_review_model()))
            .ok();

        if let Some(spawner) = spawner {
            if spawner.spawn_background().is_some() {
                println!("    Code quality review started in background");
            }
        }
    }

    if !codex_available {
        println!("  No AI review tools available. Install codex CLI to enable reviews.");
    }

    Ok(())
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

/// Log that pending status checks would have been created (writes are removed).
///
/// # TCK-00297 (Stage X3): Status writes permanently removed
///
/// Per RFC-0018, direct GitHub status writes from xtask have been removed.
/// This function logs what statuses would have been created for diagnostic
/// purposes. The `_sh` parameter is retained for call-site compatibility.
/// The `_emit_receipt_only` and `_allow_github_write` parameters are retained
/// for call-site compatibility with TCK-00324 callers but are ignored.
fn create_pending_statuses(
    _sh: &Shell,
    owner_repo: &str,
    head_sha: &str,
    _emit_receipt_only: bool,
    _allow_github_write: bool,
) {
    use crate::util::{StatusWriteDecision, check_status_write_with_flags};

    // TCK-00297 (Stage X3): Status writes are permanently removed.
    // check_status_write_with_flags always returns Removed as of TCK-00297.
    match check_status_write_with_flags(_emit_receipt_only, _allow_github_write) {
        StatusWriteDecision::Removed => {
            println!(
                "    [TCK-00297] GitHub status writes removed. Would have created pending statuses on {owner_repo}@{head_sha}:"
            );
            println!("      - ai-review/security  = pending (Waiting for security review)");
            println!(
                "      - ai-review/code-quality = pending (Waiting for code quality review)"
            );
            crate::util::print_status_writes_removed_notice();
        },
        // Legacy variants preserved for backwards compatibility but never returned.
        StatusWriteDecision::SkipHefProjection => {
            println!("    [HEF] Skipping pending status creation (USE_HEF_PROJECTION=true)");
        },
        StatusWriteDecision::EmitReceiptOnly => {
            println!("    [TCK-00297] Status writes removed (emit-receipt-only path disabled).");
        },
        StatusWriteDecision::BlockStrictMode => {
            println!("    [STRICT] Status writes blocked.");
        },
        StatusWriteDecision::Proceed => {
            // TCK-00297: Even if somehow reached, do not write.
            println!("    [TCK-00297] GitHub status writes removed. Pending statuses not created.");
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
    /// 1. Script command format includes PTY allocation via `script`
    /// 2. Input redirection uses correct `<` syntax
    /// 3. Command properly quotes paths
    ///
    /// Note: These tests use the `shell_escape` module for secure path quoting.
    #[test]
    fn test_script_command_format() {
        use std::path::Path;

        use crate::shell_escape::build_script_command;

        // Test with a simple path (no log)
        let prompt_path = Path::new("/tmp/test_prompt.txt");
        let shell_cmd = build_script_command(prompt_path, None, None);

        // Verify command includes PTY allocation
        if cfg!(target_os = "macos") {
            assert!(
                shell_cmd.contains("script -q /dev/null sh -c"),
                "Command should use macOS script invocation for PTY allocation: {shell_cmd}"
            );
        } else {
            assert!(
                shell_cmd.contains("script -qec"),
                "Command should use Linux script invocation for PTY allocation: {shell_cmd}"
            );
        }

        // Verify input redirection syntax
        assert!(
            shell_cmd.contains("< "),
            "Command should use < for input redirection: {shell_cmd}"
        );

        // Verify /dev/null is used as typescript output/sink
        assert!(
            shell_cmd.contains("/dev/null"),
            "Command should reference /dev/null: {shell_cmd}"
        );

        // Test with a path containing spaces - must be properly quoted
        let special_path = Path::new("/tmp/test file.txt");
        let special_cmd = build_script_command(special_path, None, None);

        // Verify the command is well-formed
        if cfg!(target_os = "macos") {
            assert!(
                special_cmd.contains("script -q /dev/null sh -c"),
                "Command with spaces should use macOS script invocation: {special_cmd}"
            );
        } else {
            assert!(
                special_cmd.contains("script -qec"),
                "Command with spaces should use Linux script invocation: {special_cmd}"
            );
        }
        // Path with spaces should be quoted (single quotes)
        assert!(
            special_cmd.contains('\''),
            "Path with spaces should be quoted: {special_cmd}"
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
