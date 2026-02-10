//! `apm2 fac pr set-status` — set commit status via forge provider.

use super::client::GitHubPrClient;
use crate::exit_codes::codes as exit_codes;

// ── Library function ───────────────────────────────────────────────────────

impl GitHubPrClient {
    /// Set a commit status (state, context, description) on a SHA.
    pub fn set_status(
        &self,
        sha: &str,
        state: &str,
        context: &str,
        description: &str,
    ) -> Result<(), String> {
        self.provider()
            .set_commit_status(sha, state, context, description)
            .map_err(|error| error.to_string())
    }
}

// ── CLI runner ─────────────────────────────────────────────────────────────

pub fn run_pr_set_status(
    repo: &str,
    sha: &str,
    state: &str,
    context: &str,
    description: &str,
    json_output: bool,
) -> u8 {
    let client = match GitHubPrClient::new(repo) {
        Ok(client) => client,
        Err(error) => {
            super::output_pr_error(json_output, "pr_set_status_failed", &error);
            return exit_codes::GENERIC_ERROR;
        },
    };

    match client.set_status(sha, state, context, description) {
        Ok(()) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "sha": sha,
                        "state": state,
                        "context": context,
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Status set: {state} on {sha} (context={context}).");
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            super::output_pr_error(json_output, "pr_set_status_failed", &error);
            exit_codes::GENERIC_ERROR
        },
    }
}
