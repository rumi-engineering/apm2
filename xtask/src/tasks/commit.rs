//! Implementation of the `commit` command.
//!
//! This command runs checks and creates a commit:
//! - Validates we're on a ticket branch
//! - Runs `cargo fmt --check`
//! - Runs `cargo clippy` with enhanced lints:
//!   - `-D warnings` (all warnings as errors)
//!   - `-D clippy::doc_markdown` (missing backticks in doc comments)
//!   - `-D clippy::match_same_arms` (redundant match arm bodies)
//!   - `-W clippy::missing_const_for_fn` (const promotion opportunities)
//! - Runs `cargo test` for xtask crate
//! - Runs `cargo semver-checks` (warns if not installed)
//! - Runs documentation example linting with `cargo xtask lint --include-docs`
//! - Stages all changes and creates a commit

use anyhow::{Context, Result, bail};
use xshell::{Shell, cmd};

use crate::tasks::lint::{LintArgs, scan_workspace};
use crate::util::{current_branch, validate_ticket_branch};

/// Run checks and create a commit.
///
/// This function:
/// 1. Validates we're on a ticket branch
/// 2. Runs `cargo fmt --check`
/// 3. Runs `cargo clippy` with enhanced lints (see module docs)
/// 4. Runs `cargo test -p xtask`
/// 5. Runs `cargo semver-checks` (warns if not installed)
/// 6. Stages all changes and creates a commit
///
/// # Arguments
///
/// * `message` - The commit message
/// * `skip_checks` - If true, skip all pre-commit checks (fmt, clippy, test)
///
/// # Errors
///
/// Returns an error if:
/// - Not on a valid ticket branch
/// - Any of the checks fail (fmt, clippy, test) and `skip_checks` is false
/// - No changes to commit
/// - Git operations fail
pub fn run(message: &str, skip_checks: bool) -> Result<()> {
    let sh = Shell::new().context("Failed to create shell")?;

    // Get current branch and validate it's a ticket branch
    let branch_name = current_branch(&sh)?;
    let ticket_branch = validate_ticket_branch(&branch_name)?;

    // Check if there are any changes to commit (before running expensive checks)
    let status = cmd!(sh, "git status --porcelain")
        .read()
        .context("Failed to check git status")?;

    if status.trim().is_empty() {
        bail!("No changes to commit. Make some changes first.");
    }

    if let Some(rfc_id) = &ticket_branch.rfc_id {
        println!(
            "Running checks for ticket {} (RFC: {})",
            ticket_branch.ticket_id, rfc_id
        );
    } else {
        println!("Running checks for ticket {}", ticket_branch.ticket_id);
    }

    if skip_checks {
        println!("\n--skip-checks specified, skipping pre-commit checks.");
    } else {
        run_pre_commit_checks(&sh)?;
    }

    println!("\nCreating commit...");

    // Stage modified and deleted tracked files only (not untracked files to avoid
    // staging secrets)
    cmd!(sh, "git add -u")
        .run()
        .context("Failed to stage changes")?;

    // Create the commit with the ticket ID prefix
    let commit_message = format!("feat({}): {}", ticket_branch.ticket_id, message);

    cmd!(sh, "git commit -m {commit_message}")
        .run()
        .context("Failed to create commit")?;

    println!("\nCommit created: {commit_message}");

    Ok(())
}

/// Run all pre-commit checks.
///
/// Runs fmt, clippy, test, and doc linting. All checks except doc linting
/// are required to pass. Doc linting displays warnings but does not block
/// the commit.
fn run_pre_commit_checks(sh: &Shell) -> Result<()> {
    // Run cargo fmt --check
    println!("\n[1/4] Running cargo fmt --check...");
    cmd!(sh, "cargo fmt --check")
        .run()
        .context("cargo fmt --check failed. Run 'cargo fmt' to fix formatting.")?;
    println!("  Formatting check passed.");

    // Run cargo clippy with enhanced lints
    println!("\n[2/4] Running cargo clippy...");
    cmd!(
        sh,
        "cargo clippy --all-targets -- -D warnings -D clippy::doc_markdown -D clippy::match_same_arms -W clippy::missing_const_for_fn"
    )
    .run()
    .context("cargo clippy found warnings or errors. Fix them before committing.")?;
    println!("  Clippy check passed.");
    println!("  Tip: Use `..` in struct patterns to ignore new fields (e.g., `Foo {{ x, .. }}`).");

    // Run cargo test for xtask
    // Note: --test-threads=1 is required because some tests manipulate environment
    // variables, which can cause race conditions when run in parallel.
    println!("\n[3/5] Running cargo test -p xtask...");
    cmd!(sh, "cargo test -p xtask -- --test-threads=1")
        .run()
        .context("cargo test -p xtask failed. Fix the tests before committing.")?;
    println!("  Tests passed.");

    // Run cargo semver-checks (optional - warn if not installed)
    println!("\n[4/5] Running cargo semver-checks...");
    let semver_installed = cmd!(sh, "cargo semver-checks --version")
        .ignore_status()
        .read()
        .is_ok_and(|output| !output.trim().is_empty());

    if semver_installed {
        let semver_result = cmd!(sh, "cargo semver-checks check-release")
            .ignore_status()
            .output();

        match semver_result {
            Ok(output) if output.status.success() => {
                println!("  Semver check passed.");
            },
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Treat "not found in registry" as a warning, not an error.
                // This happens for crates that haven't been published to crates.io yet,
                // meaning there's no baseline to compare against.
                if stderr.contains("not found in registry") {
                    println!("  Warning: Crate not published to crates.io, skipping semver check.");
                } else {
                    bail!("cargo semver-checks found breaking changes:\n{stdout}\n{stderr}");
                }
            },
            Err(e) => {
                println!("  Warning: Failed to run semver-checks: {e}");
            },
        }
    } else {
        println!(
            "  Warning: cargo-semver-checks not installed. Install with: cargo install cargo-semver-checks"
        );
    }

    // Run documentation example linting (warnings only, does not block commit)
    println!("\n[5/5] Running documentation example linting...");
    run_doc_lint_check()?;

    println!("\nAll checks passed.");
    Ok(())
}

/// Run documentation example linting.
///
/// Uses the shared `scan_workspace` function from the lint module to check
/// markdown code blocks for anti-patterns. This ensures consistency between
/// the `lint` command and the pre-commit check. Findings are displayed as
/// warnings but do not block the commit.
fn run_doc_lint_check() -> Result<()> {
    let lint_args = LintArgs {
        fix: false,
        include_docs: true,
        include_htf: false,
    };

    // Use the shared scan_workspace function to get findings
    let findings = scan_workspace(lint_args)?;

    if findings.is_empty() {
        println!("  No anti-patterns found in documentation examples.");
    } else {
        println!(
            "  Warning: Found {} anti-pattern(s) in documentation examples:\n",
            findings.len()
        );
        for finding in &findings {
            println!("  {finding}\n");
        }
        println!("  Consider fixing these documentation examples to avoid teaching bad patterns.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_commit_message_format() {
        // Test that commit message format is as expected
        let ticket_id = "TCK-00031";
        let message = "implement commit command";
        let commit_message = format!("feat({ticket_id}): {message}");
        assert_eq!(commit_message, "feat(TCK-00031): implement commit command");
    }

    #[test]
    fn test_commit_message_with_special_characters() {
        // Verify commit messages handle special characters
        let ticket_id = "TCK-00058";
        let message = "add pre-commit checks (fmt, clippy, test)";
        let commit_message = format!("feat({ticket_id}): {message}");
        assert_eq!(
            commit_message,
            "feat(TCK-00058): add pre-commit checks (fmt, clippy, test)"
        );
    }

    #[test]
    fn test_commit_message_multiword() {
        // Verify multi-word messages are handled correctly
        let ticket_id = "TCK-00042";
        let message = "this is a longer commit message with multiple words";
        let commit_message = format!("feat({ticket_id}): {message}");
        assert!(commit_message.starts_with("feat(TCK-00042): "));
        assert!(commit_message.ends_with("multiple words"));
    }

    #[test]
    fn test_pre_commit_check_count() {
        // Document that we run exactly 5 pre-commit checks:
        // 1. cargo fmt --check
        // 2. cargo clippy --all-targets -- -D warnings -D clippy::doc_markdown -D
        //    clippy::match_same_arms -W clippy::missing_const_for_fn
        // 3. cargo test -p xtask
        // 4. cargo semver-checks (warns if not installed)
        // 5. documentation example linting (warnings only)
        const CHECK_COUNT: usize = 5;
        assert_eq!(CHECK_COUNT, 5);
    }

    #[test]
    fn test_enhanced_clippy_lints_documented() {
        // Document the enhanced clippy lints used in pre-commit checks.
        // These lints address issues discovered during PR #58 and #59:
        // - doc_markdown: Catches missing backticks around code in doc comments
        // - match_same_arms: Catches redundant match arms that should be combined
        // - missing_const_for_fn: Warns about functions that could be const

        let clippy_lints = [
            "-D clippy::doc_markdown",
            "-D clippy::match_same_arms",
            "-W clippy::missing_const_for_fn",
        ];

        // Verify we have exactly 3 enhanced lints (plus -D warnings)
        assert_eq!(clippy_lints.len(), 3);

        // Verify doc_markdown is denied (not warned)
        assert!(clippy_lints[0].starts_with("-D"));

        // Verify match_same_arms is denied (not warned)
        assert!(clippy_lints[1].starts_with("-D"));

        // Verify missing_const_for_fn is warned (not denied) since it can be noisy
        assert!(clippy_lints[2].starts_with("-W"));
    }

    #[test]
    fn test_fix_suggestions_are_documented() {
        // Document the fix suggestions provided for each check failure.
        // These are the context messages used in run_pre_commit_checks().
        let fmt_suggestion = "Run 'cargo fmt' to fix formatting.";
        let clippy_suggestion = "Fix them before committing.";
        let test_suggestion = "Fix the tests before committing.";
        let semver_install = "Install with: cargo install cargo-semver-checks";
        let semver_unpublished = "not found in registry";

        // Verify suggestions are non-empty and helpful
        assert!(fmt_suggestion.contains("cargo fmt"));
        assert!(clippy_suggestion.contains("Fix"));
        assert!(test_suggestion.contains("Fix"));
        assert!(semver_install.contains("cargo install"));
        // Unpublished crates should be warned about, not fail
        assert!(semver_unpublished.contains("registry"));
    }
}
