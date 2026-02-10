//! `apm2 fac pr` — projection-boundary hard-deny surface.
//!
//! Per RFC-0028 REQ-0008 and RFC-0029 REQ-0008, agent-runtime direct
//! GitHub API authority is denied. Root/operator workflows can execute
//! out-of-band GitHub operations outside APM2 runtime boundaries.

use clap::{Args, Subcommand};
use serde::Serialize;

pub mod types;

mod auth_check;
mod auth_setup;
mod auto_merge;
mod checks;
mod comment;
mod list;
mod set_status;
mod view;

// Re-export library types for internal callers (used after TCK-00482 refactor).
#[allow(unused_imports)]
pub use types::{
    AuthInfo, CheckStatus, CommentCreateResult, PrComment, PrListArgs, PrListEntry, PrViewData,
};

// ── GitHubPrClient ─────────────────────────────────────────────────────────

/// Client module exposing the `GitHubPrClient` struct.
#[allow(dead_code)]
pub mod client {
    use apm2_core::forge::{CreatePrArgs, ForgeProvider, UpdatePrArgs};

    /// Typed client for GitHub PR operations.
    pub struct GitHubPrClient {
        repo: String,
        provider: Box<dyn ForgeProvider>,
    }

    impl GitHubPrClient {
        /// Constructs a fail-closed GitHub forge client.
        ///
        /// # Errors
        ///
        /// Returns an error if required GitHub App credentials/config are
        /// unavailable.
        pub fn new(repo: &str) -> Result<Self, String> {
            let provider = build_provider(repo)?;
            Ok(Self {
                repo: repo.to_string(),
                provider,
            })
        }

        /// Returns the repository configured for this client.
        #[must_use]
        pub fn repo(&self) -> &str {
            &self.repo
        }

        pub(super) fn provider(&self) -> &dyn ForgeProvider {
            self.provider.as_ref()
        }

        /// Create a new PR and return the PR number.
        pub fn create_pr(
            &self,
            title: &str,
            body: &str,
            head: &str,
            base: &str,
        ) -> Result<u32, String> {
            self.provider()
                .create_pr(&CreatePrArgs {
                    title: title.to_string(),
                    body: body.to_string(),
                    head: head.to_string(),
                    base: base.to_string(),
                })
                .map_err(|error| error.to_string())
        }

        /// Update an existing PR's title and body.
        pub fn update_pr(&self, pr_number: u32, title: &str, body: &str) -> Result<(), String> {
            self.provider()
                .update_pr(
                    pr_number,
                    &UpdatePrArgs {
                        title: title.to_string(),
                        body: body.to_string(),
                    },
                )
                .map_err(|error| error.to_string())
        }

        /// Fetch PR metadata in the legacy JSON shape used by FAC barrier
        /// logic.
        pub fn fetch_pr_data(&self, pr_number: u32) -> Result<serde_json::Value, String> {
            let detail = self
                .provider()
                .view_pr(pr_number)
                .map_err(|error| error.to_string())?;
            Ok(serde_json::json!({
                "html_url": detail.summary.url,
                "head": { "sha": detail.head_sha },
                "base": { "ref": detail.summary.base_ref },
                "user": { "login": detail.summary.author },
                "author_association": detail.author_association,
            }))
        }

        /// Fetch the repository default branch.
        pub fn fetch_default_branch(&self) -> Result<String, String> {
            self.provider()
                .default_branch()
                .map_err(|error| error.to_string())
        }

        /// Resolve repository permission for an actor.
        pub fn resolve_actor_permission(&self, actor: &str) -> Result<String, String> {
            self.provider()
                .actor_permission(actor)
                .map_err(|error| error.to_string())
        }
    }

    fn build_provider(repo: &str) -> Result<Box<dyn ForgeProvider>, String> {
        let defect = direct_github_surface_denied(repo);
        Err(defect)
    }

    fn direct_github_surface_denied(repo: &str) -> String {
        format!(
            "SECURITY_DEFECT[FAC-GH-DIRECT-DENY]: direct GitHub authority from agent-runtime \
             is forbidden (repo={repo}; controls=RFC-0028::REQ-0008,RFC-0029::REQ-0008; \
             remediation=use projection_worker intent path or out-of-band root/operator GitHub action)"
        )
    }
}

// Re-export GitHubPrClient at module level (used after TCK-00482 refactor).
#[allow(unused_imports)]
pub use client::GitHubPrClient;

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
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        eprintln!("Error: {message}");
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
    /// List pull requests.
    List(PrListCliArgs),
    /// View a single pull request.
    View(PrViewCliArgs),
    /// List CI check statuses for a PR.
    Checks(PrChecksCliArgs),
    /// Enable squash auto-merge on a PR.
    AutoMerge(PrAutoMergeCliArgs),
    /// Post a comment on a PR.
    Comment(PrCommentCliArgs),
    /// Read comments on a PR.
    ReadComments(PrReadCommentsCliArgs),
    /// Set commit status on a SHA.
    SetStatus(PrSetStatusCliArgs),
    /// Verify GitHub App authentication.
    AuthCheck(PrAuthCheckCliArgs),
    /// Store GitHub App private key material in OS keyring.
    AuthSetup(PrAuthSetupCliArgs),
}

#[derive(Debug, Args)]
pub struct PrListCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
    /// PR state filter (open, closed, merged, all).
    #[arg(long)]
    pub state: Option<String>,
    /// Filter by head branch.
    #[arg(long)]
    pub head: Option<String>,
    /// Filter by base branch.
    #[arg(long)]
    pub base: Option<String>,
    /// Maximum number of results.
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Debug, Args)]
pub struct PrViewCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
    /// Pull request number.
    pub pr: u32,
}

#[derive(Debug, Args)]
pub struct PrChecksCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
    /// Pull request number.
    pub pr: u32,
}

#[derive(Debug, Args)]
pub struct PrAutoMergeCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
    /// Pull request number.
    pub pr: u32,
}

#[derive(Debug, Args)]
pub struct PrCommentCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
    /// Pull request number.
    pub pr: u32,
    /// Comment body text.
    #[arg(long)]
    pub body: String,
}

#[derive(Debug, Args)]
pub struct PrReadCommentsCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
    /// Pull request number.
    pub pr: u32,
    /// Maximum number of pages to fetch (100 comments per page).
    #[arg(long, default_value_t = 5)]
    pub max_pages: u32,
}

#[derive(Debug, Args)]
pub struct PrSetStatusCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
    /// Commit SHA to set status on.
    #[arg(long)]
    pub sha: String,
    /// Status state (error, failure, pending, success).
    #[arg(long)]
    pub state: String,
    /// Status context identifier.
    #[arg(long)]
    pub context: String,
    /// Status description.
    #[arg(long, default_value = "")]
    pub description: String,
}

#[derive(Debug, Args)]
pub struct PrAuthCheckCliArgs {
    /// Repository in owner/repo format.
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
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
    /// Keep the source key file instead of deleting it.
    #[arg(long, default_value_t = false)]
    pub keep_private_key_file: bool,
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

/// Dispatch `apm2 fac pr` subcommands.
pub fn run_pr(args: &PrArgs, json_output: bool) -> u8 {
    match &args.subcommand {
        PrSubcommand::List(a) => {
            let lib_args = types::PrListArgs {
                state: a.state.clone(),
                head: a.head.clone(),
                base: a.base.clone(),
                limit: a.limit,
            };
            list::run_pr_list(&a.repo, &lib_args, json_output)
        },
        PrSubcommand::View(a) => view::run_pr_view(&a.repo, a.pr, json_output),
        PrSubcommand::Checks(a) => checks::run_pr_checks(&a.repo, a.pr, json_output),
        PrSubcommand::AutoMerge(a) => auto_merge::run_pr_auto_merge(&a.repo, a.pr, json_output),
        PrSubcommand::Comment(a) => comment::run_pr_comment(&a.repo, a.pr, &a.body, json_output),
        PrSubcommand::ReadComments(a) => {
            comment::run_pr_read_comments(&a.repo, a.pr, a.max_pages, json_output)
        },
        PrSubcommand::SetStatus(a) => set_status::run_pr_set_status(
            &a.repo,
            &a.sha,
            &a.state,
            &a.context,
            &a.description,
            json_output,
        ),
        PrSubcommand::AuthCheck(a) => auth_check::run_pr_auth_check(&a.repo, json_output),
        PrSubcommand::AuthSetup(a) => auth_setup::run_pr_auth_setup(a, json_output),
    }
}
