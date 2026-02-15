//! `apm2 fac pr` — GitHub App credential management and PR operations.
//!
//! This module provides the `auth-setup` and `auth-check` subcommands for
//! bootstrapping and verifying GitHub App credentials on headless Linux
//! systems where the OS keyring is session-scoped.

use clap::{Args, Subcommand};
use serde::Serialize;

pub mod types;

mod auth_check;
mod auth_setup;

// Re-export for potential external callers.
#[allow(unused_imports)]
pub use types::AuthInfo;

// ── Error output helper ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct PrErrorResponse {
    error: String,
    message: String,
}

fn output_pr_error(json_output: bool, code: &str, message: &str) {
    if json_output {
        let resp = PrErrorResponse {
            error: code.to_string(),
            message: message.to_string(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&PrErrorResponse {
                error: code.to_string(),
                message: message.to_string(),
            })
            .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
    }
}

// ── CLI argument types ─────────────────────────────────────────────────────

/// Arguments for `apm2 fac pr`.
#[derive(Debug, Args)]
pub struct PrArgs {
    #[command(subcommand)]
    pub subcommand: PrSubcommand,
}

/// PR subcommands.
#[derive(Debug, Subcommand)]
pub enum PrSubcommand {
    /// Verify GitHub App authentication.
    AuthCheck(PrAuthCheckCliArgs),
    /// Store GitHub App private key material in OS keyring and write config.
    AuthSetup(PrAuthSetupCliArgs),
}

#[derive(Debug, Args)]
pub struct PrAuthCheckCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PrAuthSetupCliArgs {
    /// GitHub App ID.
    #[arg(long)]
    pub app_id: String,
    /// GitHub installation ID for the repository/org.
    #[arg(long)]
    pub installation_id: String,
    /// PEM private key file path.
    #[arg(long)]
    pub private_key_file: std::path::PathBuf,
    /// Keyring service name.
    #[arg(long, default_value = "apm2.github.app")]
    pub keyring_service: String,
    /// Optional keyring account name (defaults to `app-{app_id}`).
    #[arg(long)]
    pub keyring_account: Option<String>,
    /// Persist and allow PEM file fallback in `github_app.toml`.
    ///
    /// By default, auth material is keyring-first and does not persist a
    /// private key file path.
    #[arg(long, default_value_t = false)]
    pub allow_private_key_file_fallback: bool,
    /// Keep the source key file instead of deleting it.
    #[arg(long, default_value_t = false)]
    pub keep_private_key_file: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

/// Dispatch `apm2 fac pr` subcommands.
pub fn run_pr(args: &PrArgs, parent_json_output: bool) -> u8 {
    let resolve_json = |subcommand_json: bool| -> bool { parent_json_output || subcommand_json };
    match &args.subcommand {
        PrSubcommand::AuthCheck(a) => auth_check::run_pr_auth_check(&a.repo, resolve_json(a.json)),
        PrSubcommand::AuthSetup(a) => auth_setup::run_pr_auth_setup(a, resolve_json(a.json)),
    }
}
