//! Development automation tasks for apm2.
//!
//! This crate provides typesafe implementations of the development workflow
//! scripts, replacing the bash scripts in `scripts/dev/`.
//!
//! # Usage
//!
//! ```bash
//! cargo xtask <command> [options]
//! ```
//!
//! # Commands
//!
//! - `start-ticket <RFC_ID>` - Start work on the next unblocked ticket
//! - `commit <message>` - Run checks and create a commit
//! - `push` - Push branch, create PR, and request reviews
//! - `check` - Show ticket and PR status
//! - `finish` - Clean up after PR merge
//! - `review security <PR_URL>` - Run security review for a PR
//! - `review quality <PR_URL>` - Run code quality review for a PR
//! - `review uat <PR_URL>` - Run UAT sign-off for a PR

use anyhow::Result;
use clap::{Parser, Subcommand};

mod tasks;
pub mod util;

/// Development automation for apm2.
#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Development automation tasks for apm2", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available xtask commands.
#[derive(Subcommand)]
enum Commands {
    /// Start work on the next unblocked ticket for an RFC.
    ///
    /// Creates a worktree and branch for the next pending ticket
    /// that has all dependencies completed.
    #[command(name = "start-ticket")]
    StartTicket {
        /// The RFC ID (e.g., RFC-0001)
        rfc_id: String,

        /// Only print the worktree path (for scripting)
        #[arg(short = 'p', long = "print-path")]
        print_path: bool,
    },

    /// Run checks and create a commit.
    ///
    /// Runs cargo fmt, clippy, and test, then rebases on main
    /// and creates a commit with the given message.
    Commit {
        /// The commit message
        message: String,
    },

    /// Push branch and create PR with AI reviews.
    ///
    /// Pushes the current branch, creates a PR if needed,
    /// requests AI reviews, and enables auto-merge.
    Push,

    /// Show ticket and PR status.
    ///
    /// Displays the current ticket status, PR checks,
    /// and review status.
    Check {
        /// Continuously poll status every 10 seconds
        #[arg(short, long)]
        watch: bool,
    },

    /// Clean up after PR merge.
    ///
    /// Removes the worktree and local branch after
    /// verifying the PR has been merged.
    Finish,

    /// Run or re-run AI reviews for a PR.
    ///
    /// Manually invoke AI reviews. Useful for re-running failed reviews
    /// or running reviews from a different machine.
    Review {
        #[command(subcommand)]
        review_type: ReviewCommands,
    },

    /// Security review execution commands for human/AI reviewers.
    ///
    /// Provides commands to approve or deny PRs after security review,
    /// with robust validation and dry-run support.
    #[command(name = "security-review-exec")]
    SecurityReviewExec {
        #[command(subcommand)]
        action: SecurityReviewExecCommands,
    },
}

/// Security review exec subcommands.
#[derive(Subcommand)]
enum SecurityReviewExecCommands {
    /// Approve the PR (set ai-review/security to success).
    ///
    /// Posts an approval comment and updates the status check.
    Approve {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
        /// Preview what would happen without making API calls
        #[arg(long)]
        dry_run: bool,
    },
    /// Deny the PR (set ai-review/security to failure).
    ///
    /// Posts a denial comment with the reason and updates the status check.
    Deny {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
        /// Reason for denying the security review (required)
        #[arg(long)]
        reason: String,
        /// Preview what would happen without making API calls
        #[arg(long)]
        dry_run: bool,
    },
    /// Show required reading for security reviewers.
    ///
    /// Prints the file paths that security reviewers should read
    /// before conducting reviews.
    Onboard,
}

/// Review subcommands.
#[derive(Subcommand)]
enum ReviewCommands {
    /// Run security review using Gemini.
    ///
    /// Reads `SECURITY_REVIEW_PROMPT.md`, runs the review,
    /// posts findings as a PR comment, and updates the
    /// ai-review/security status check.
    Security {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
    },

    /// Run code quality review using Codex.
    ///
    /// Reads `CODE_QUALITY_PROMPT.md`, runs the review,
    /// posts findings as a PR comment, and updates the
    /// ai-review/code-quality status check.
    Quality {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
    },

    /// Run UAT (User Acceptance Testing) sign-off.
    ///
    /// Posts an approval comment and updates the
    /// ai-review/uat status check to success.
    Uat {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::StartTicket { rfc_id, print_path } => tasks::start_ticket(&rfc_id, print_path),
        Commands::Commit { message } => tasks::commit(&message),
        Commands::Push => tasks::push(),
        Commands::Check { watch } => tasks::check(watch),
        Commands::Finish => tasks::finish(),
        Commands::Review { review_type } => match review_type {
            ReviewCommands::Security { pr_url } => tasks::review_security(&pr_url),
            ReviewCommands::Quality { pr_url } => tasks::review_quality(&pr_url),
            ReviewCommands::Uat { pr_url } => tasks::review_uat(&pr_url),
        },
        Commands::SecurityReviewExec { action } => match action {
            SecurityReviewExecCommands::Approve { pr_url, dry_run } => {
                tasks::security_review_exec_approve(&pr_url, dry_run)
            },
            SecurityReviewExecCommands::Deny {
                pr_url,
                reason,
                dry_run,
            } => tasks::security_review_exec_deny(&pr_url, &reason, dry_run),
            SecurityReviewExecCommands::Onboard => tasks::security_review_exec_onboard(),
        },
    }
}
