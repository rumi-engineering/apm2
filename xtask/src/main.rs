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

use anyhow::Result;
use clap::{Parser, Subcommand};

mod tasks;

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
    Check,

    /// Clean up after PR merge.
    ///
    /// Removes the worktree and local branch after
    /// verifying the PR has been merged.
    Finish,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::StartTicket { rfc_id } => tasks::start_ticket(&rfc_id),
        Commands::Commit { message } => tasks::commit(&message),
        Commands::Push => tasks::push(),
        Commands::Check => tasks::check(),
        Commands::Finish => tasks::finish(),
    }
}
