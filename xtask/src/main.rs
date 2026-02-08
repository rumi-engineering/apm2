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
//! - `start-ticket` - Start work on the next unblocked ticket (finds earliest
//!   globally)
//! - `start-ticket RFC-XXXX` - Start work on the next unblocked ticket for an
//!   RFC
//! - `start-ticket TCK-XXXXX` - Start work on a specific ticket
//! - `commit <message>` - Run checks and create a commit
//! - `commit <message> --skip-checks` - Create a commit without running checks
//! - `push` - Push branch, create PR, and request reviews
//! - `check` - Show ticket and PR status
//! - `finish` - Clean up after PR merge
//! - `review security <PR_URL>` - Run security review for a PR
//! - `review quality <PR_URL>` - Run code quality review for a PR
//! - `review uat <PR_URL>` - Run UAT sign-off for a PR
//! - `review-gate --pr-number <N>` - Evaluate authoritative AI review gate
//! - `security-review-exec approve [TCK-XXXXX]` - Approve PR after security
//!   review
//! - `security-review-exec deny [TCK-XXXXX] --reason <reason>` - Deny PR with
//!   reason
//! - `aat <PR_URL>` - Run Agent Acceptance Testing on a PR
//! - `aat <PR_URL> --dry-run` - Preview AAT without emitting status intent
//! - `lint` - Check for anti-patterns (`temp_dir`, shell interpolation)
//! - `lint --fix` - Check for anti-patterns (fix flag placeholder)
//! - `capabilities` - Generate capability manifest for the binary
//! - `capabilities --json` - Output manifest in JSON format
//! - `selftest` - Run CAC capability selftests
//! - `selftest --filter <pattern>` - Run only matching tests

use anyhow::Result;
use clap::{Parser, Subcommand};

pub mod aat;
pub mod reviewer_state;
pub mod shell_escape;

/// Parse an AI tool from a string.
fn parse_ai_tool(s: &str) -> Result<aat::tool_config::AiTool, aat::tool_config::ParseAiToolError> {
    s.parse()
}

mod tasks;
pub mod ticket_status;
pub mod util;
mod worktree_health;

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
    /// Start work on the next unblocked ticket.
    ///
    /// Creates a worktree and branch for the next pending ticket
    /// that has all dependencies completed.
    ///
    /// With no arguments, finds the earliest unblocked ticket across all RFCs.
    /// With an RFC ID (RFC-XXXX), filters to that RFC.
    /// With a ticket ID (TCK-XXXXX), starts that specific ticket.
    #[command(name = "start-ticket")]
    StartTicket {
        /// Optional: RFC ID (RFC-XXXX) to filter, or ticket ID (TCK-XXXXX) to
        /// start directly. If omitted, finds earliest unblocked ticket
        /// across all RFCs.
        target: Option<String>,

        /// Only print the worktree path (for scripting)
        #[arg(short = 'p', long = "print-path")]
        print_path: bool,

        /// Auto-cleanup remediable worktree issues (orphaned, locked, etc.)
        #[arg(short = 'f', long = "force")]
        force: bool,
    },

    /// Run checks and create a commit.
    ///
    /// Runs cargo fmt, clippy, and test, then creates a commit
    /// with the given message.
    Commit {
        /// The commit message
        message: String,
        /// Skip all pre-commit checks (fmt, clippy, test)
        #[arg(long)]
        skip_checks: bool,
    },

    /// Push branch and create PR with AI reviews.
    ///
    /// Pushes the current branch, creates a PR if needed,
    /// requests AI reviews, and enables auto-merge.
    Push {
        /// Emit receipt only, do NOT write directly to GitHub (TCK-00324).
        ///
        /// When enabled, xtask emits a projection request receipt and
        /// relies on the projection worker to perform the actual GitHub
        /// API writes (for example PR comments).
        ///
        /// Also enabled via `XTASK_EMIT_RECEIPT_ONLY=true` environment
        /// variable.
        #[arg(long)]
        emit_receipt_only: bool,

        /// Allow direct GitHub writes (override emit-receipt-only mode).
        ///
        /// When emit-receipt-only is active, this flag provides explicit
        /// opt-in for direct GitHub writes. Useful for development/debugging
        /// when the projection worker is not available.
        ///
        /// Also enabled via `XTASK_ALLOW_GITHUB_WRITE=true` environment
        /// variable.
        #[arg(long)]
        allow_github_write: bool,
    },

    /// Show ticket and PR status.
    ///
    /// Displays the current ticket status, PR checks,
    /// and review status.
    Check {
        /// Continuously poll status every 10 seconds
        #[arg(short, long)]
        watch: bool,
    },

    /// Evaluate authoritative AI review gate for a pull request.
    ///
    /// This command reads machine-readable review metadata from PR comments
    /// and enforces a trusted reviewer allowlist.
    ///
    /// Notes:
    /// - Direct `ai-review/*` commit statuses are not required and are no
    ///   longer authoritative.
    /// - The gate is **pending** until both categories have authoritative
    ///   verdicts for the current PR head SHA.
    /// - The gate **fails** only when an authoritative verdict is `FAIL`.
    #[command(name = "review-gate")]
    ReviewGate {
        /// Pull request number to evaluate
        #[arg(long)]
        pr_number: u64,
        /// Optional owner/repo override (defaults to origin remote)
        #[arg(long)]
        repo: Option<String>,
        /// Optional expected PR head SHA override
        #[arg(long)]
        head_sha: Option<String>,
        /// Optional trusted reviewer allowlist path
        #[arg(long)]
        trusted_reviewers: Option<String>,
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

    /// Run Agent Acceptance Testing (AAT) on a PR.
    ///
    /// Verifies a PR meets acceptance criteria through hypothesis-driven
    /// testing. Parses the PR description, runs anti-gaming analysis,
    /// generates hypotheses, and produces an evidence bundle.
    ///
    /// Records `aat/acceptance` status intent (projection-only) based on the
    /// verdict.
    Aat {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,

        /// Preview without emitting status intent or writing evidence
        #[arg(long)]
        dry_run: bool,

        /// AI tool backend to use for hypothesis generation.
        ///
        /// Overrides the `AAT_AI_TOOL` environment variable.
        /// Supported values: `codex`, `claude-code`.
        #[arg(long, value_parser = parse_ai_tool)]
        ai_tool: Option<aat::tool_config::AiTool>,

        /// Emit internal receipts/events to daemon (TCK-00295).
        ///
        /// When enabled, xtask will attempt to emit internal receipts to the
        /// daemon. If the daemon is unavailable, xtask continues without
        /// blocking.
        ///
        /// Also enabled via `XTASK_EMIT_INTERNAL=true` environment variable.
        ///
        /// NOTE: Internal emission is NON-AUTHORITATIVE scaffolding only.
        /// Per RFC-0018, these events are hints only and must not be used
        /// for admission decisions without ledger+CAS verification.
        #[arg(long)]
        emit_internal: bool,
    },

    /// Check for anti-patterns in the codebase.
    ///
    /// Scans Rust source files for anti-patterns that cannot be caught by
    /// clippy:
    /// - Direct `std::env::temp_dir` usage (use `tempfile` crate instead)
    /// - Shell interpolation patterns (use file-based input instead)
    ///
    /// Findings are reported as warnings (not errors) to allow gradual
    /// adoption.
    Lint(tasks::lint::LintArgs),

    /// Generate capability manifest for this binary.
    ///
    /// Introspects the CLI commands and generates a manifest describing
    /// all available capabilities and their requirements.
    ///
    /// The manifest can be used for capability-based access control (CAC)
    /// to verify that the binary supports required operations.
    Capabilities(tasks::capabilities::CapabilitiesArgs),

    /// Run CAC capability selftests.
    ///
    /// Executes the selftest suite to verify that advertised capabilities
    /// actually work. Produces an AAT receipt that can be used to prove
    /// capability compliance.
    ///
    /// Exit code is 0 if all tests pass, 1 if any test fails.
    Selftest(tasks::selftest::SelftestArgs),
}

/// Security review exec subcommands.
#[derive(Subcommand)]
enum SecurityReviewExecCommands {
    /// Approve the PR (projection-only status semantics).
    ///
    /// Posts (or projects) an approval comment and records security verdict
    /// intent for projection/review-gate handling.
    /// If no ticket ID is provided, uses the current branch.
    Approve {
        /// Ticket ID (e.g., TCK-00049). If omitted, uses current branch.
        ticket_id: Option<String>,
        /// Preview what would happen without making API calls
        #[arg(long)]
        dry_run: bool,
        /// Emit internal receipts/events to daemon (TCK-00295).
        ///
        /// When enabled, xtask will attempt to emit internal receipts to the
        /// daemon. If the daemon is unavailable, xtask continues without
        /// blocking.
        ///
        /// Also enabled via `XTASK_EMIT_INTERNAL=true` environment variable.
        ///
        /// NOTE: Internal emission is NON-AUTHORITATIVE scaffolding only.
        #[arg(long)]
        emit_internal: bool,
    },
    /// Deny the PR (projection-only status semantics).
    ///
    /// Posts (or projects) a denial comment with the reason and records
    /// security verdict intent for projection/review-gate handling.
    /// If no ticket ID is provided, uses the current branch.
    Deny {
        /// Ticket ID (e.g., TCK-00049). If omitted, uses current branch.
        ticket_id: Option<String>,
        /// Reason for denying the security review (required)
        #[arg(long)]
        reason: String,
        /// Preview what would happen without making API calls
        #[arg(long)]
        dry_run: bool,
        /// Emit internal receipts/events to daemon (TCK-00295).
        ///
        /// When enabled, xtask will attempt to emit internal receipts to the
        /// daemon. If the daemon is unavailable, xtask continues without
        /// blocking.
        ///
        /// Also enabled via `XTASK_EMIT_INTERNAL=true` environment variable.
        ///
        /// NOTE: Internal emission is NON-AUTHORITATIVE scaffolding only.
        #[arg(long)]
        emit_internal: bool,
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
    /// Run both security and code quality reviews (best-effort).
    ///
    /// Useful for CI workflows that want to trigger both AI reviewers for a PR
    /// in one command.
    All {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
        /// Expected PR head SHA (40-hex). If provided and the PR head has
        /// moved, the review is skipped to avoid posting stale
        /// artifacts.
        #[arg(long)]
        expected_head_sha: Option<String>,
        /// Emit internal receipts/events to daemon (TCK-00295).
        ///
        /// When enabled, xtask will attempt to emit internal receipts to the
        /// daemon. If the daemon is unavailable, xtask continues without
        /// blocking.
        ///
        /// Also enabled via `XTASK_EMIT_INTERNAL=true` environment variable.
        ///
        /// NOTE: Internal emission is NON-AUTHORITATIVE scaffolding only.
        #[arg(long)]
        emit_internal: bool,
        /// Emit receipt only, do NOT write directly to GitHub (TCK-00324).
        #[arg(long)]
        emit_receipt_only: bool,
        /// Allow direct GitHub writes (override emit-receipt-only mode).
        #[arg(long)]
        allow_github_write: bool,
    },

    /// Run security review using Codex.
    ///
    /// Reads `SECURITY_REVIEW_PROMPT.md`, runs the review,
    /// posts findings as a PR comment, and emits projection-only status intent
    /// (no direct status write).
    Security {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
        /// Expected PR head SHA (40-hex). If provided and the PR head has
        /// moved, the review is skipped to avoid posting stale
        /// artifacts.
        #[arg(long)]
        expected_head_sha: Option<String>,
        /// Emit internal receipts/events to daemon (TCK-00295).
        ///
        /// When enabled, xtask will attempt to emit internal receipts to the
        /// daemon. If the daemon is unavailable, xtask continues without
        /// blocking.
        ///
        /// Also enabled via `XTASK_EMIT_INTERNAL=true` environment variable.
        ///
        /// NOTE: Internal emission is NON-AUTHORITATIVE scaffolding only.
        #[arg(long)]
        emit_internal: bool,
        /// Emit receipt only, do NOT write directly to GitHub (TCK-00324).
        ///
        /// When enabled, xtask emits a projection request receipt and
        /// relies on the projection worker to perform the actual GitHub
        /// API writes.
        #[arg(long)]
        emit_receipt_only: bool,
        /// Allow direct GitHub writes (override emit-receipt-only mode).
        #[arg(long)]
        allow_github_write: bool,
    },

    /// Run code quality review using Codex.
    ///
    /// Reads `CODE_QUALITY_PROMPT.md`, runs the review,
    /// posts findings as a PR comment, and emits projection-only status intent
    /// (no direct status write).
    Quality {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
        /// Expected PR head SHA (40-hex). If provided and the PR head has
        /// moved, the review is skipped to avoid posting stale
        /// artifacts.
        #[arg(long)]
        expected_head_sha: Option<String>,
        /// Emit internal receipts/events to daemon (TCK-00295).
        ///
        /// When enabled, xtask will attempt to emit internal receipts to the
        /// daemon. If the daemon is unavailable, xtask continues without
        /// blocking.
        ///
        /// Also enabled via `XTASK_EMIT_INTERNAL=true` environment variable.
        ///
        /// NOTE: Internal emission is NON-AUTHORITATIVE scaffolding only.
        #[arg(long)]
        emit_internal: bool,
        /// Emit receipt only, do NOT write directly to GitHub (TCK-00324).
        #[arg(long)]
        emit_receipt_only: bool,
        /// Allow direct GitHub writes (override emit-receipt-only mode).
        #[arg(long)]
        allow_github_write: bool,
    },

    /// Run UAT (User Acceptance Testing) sign-off.
    ///
    /// Posts an approval comment and records projection-only status intent for
    /// ai-review/uat.
    Uat {
        /// The GitHub PR URL (e.g., `https://github.com/owner/repo/pull/123`)
        pr_url: String,
        /// Emit internal receipts/events to daemon (TCK-00295).
        ///
        /// When enabled, xtask will attempt to emit internal receipts to the
        /// daemon. If the daemon is unavailable, xtask continues without
        /// blocking.
        ///
        /// Also enabled via `XTASK_EMIT_INTERNAL=true` environment variable.
        ///
        /// NOTE: Internal emission is NON-AUTHORITATIVE scaffolding only.
        #[arg(long)]
        emit_internal: bool,
        /// Emit receipt only, do NOT write directly to GitHub (TCK-00324).
        #[arg(long)]
        emit_receipt_only: bool,
        /// Allow direct GitHub writes (override emit-receipt-only mode).
        #[arg(long)]
        allow_github_write: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::StartTicket {
            target,
            print_path,
            force,
        } => tasks::start_ticket(target.as_deref(), print_path, force),
        Commands::Commit {
            message,
            skip_checks,
        } => tasks::commit(&message, skip_checks),
        Commands::Push {
            emit_receipt_only,
            allow_github_write,
        } => tasks::push(emit_receipt_only, allow_github_write),
        Commands::Check { watch } => tasks::check(watch),
        Commands::ReviewGate {
            pr_number,
            repo,
            head_sha,
            trusted_reviewers,
        } => tasks::review_gate(
            repo.as_deref(),
            pr_number,
            head_sha.as_deref(),
            trusted_reviewers.as_deref(),
        ),
        Commands::Finish => tasks::finish(),
        Commands::Review { review_type } => match review_type {
            ReviewCommands::All {
                pr_url,
                expected_head_sha,
                emit_internal,
                emit_receipt_only,
                allow_github_write,
            } => tasks::review_all(
                &pr_url,
                expected_head_sha.as_deref(),
                emit_internal,
                emit_receipt_only,
                allow_github_write,
            ),
            ReviewCommands::Security {
                pr_url,
                expected_head_sha,
                emit_internal,
                emit_receipt_only,
                allow_github_write,
            } => tasks::review_security(
                &pr_url,
                expected_head_sha.as_deref(),
                emit_internal,
                emit_receipt_only,
                allow_github_write,
            ),
            ReviewCommands::Quality {
                pr_url,
                expected_head_sha,
                emit_internal,
                emit_receipt_only,
                allow_github_write,
            } => tasks::review_quality(
                &pr_url,
                expected_head_sha.as_deref(),
                emit_internal,
                emit_receipt_only,
                allow_github_write,
            ),
            ReviewCommands::Uat {
                pr_url,
                emit_internal,
                emit_receipt_only,
                allow_github_write,
            } => tasks::review_uat(
                &pr_url,
                emit_internal,
                emit_receipt_only,
                allow_github_write,
            ),
        },
        Commands::SecurityReviewExec { action } => match action {
            SecurityReviewExecCommands::Approve {
                ticket_id,
                dry_run,
                emit_internal,
            } => tasks::security_review_exec_approve(ticket_id.as_deref(), dry_run, emit_internal),
            SecurityReviewExecCommands::Deny {
                ticket_id,
                reason,
                dry_run,
                emit_internal,
            } => tasks::security_review_exec_deny(
                ticket_id.as_deref(),
                &reason,
                dry_run,
                emit_internal,
            ),
            SecurityReviewExecCommands::Onboard => tasks::security_review_exec_onboard(),
        },
        Commands::Aat {
            pr_url,
            dry_run,
            ai_tool,
            emit_internal,
        } => tasks::aat(&pr_url, dry_run, ai_tool, emit_internal),
        Commands::Lint(args) => tasks::lint::run(args),
        Commands::Capabilities(args) => tasks::capabilities::run(args),
        Commands::Selftest(args) => tasks::selftest::run(&args),
    }
}
