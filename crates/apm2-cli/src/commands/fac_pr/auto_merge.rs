//! `apm2 fac pr auto-merge` — enable squash auto-merge on a PR.

use super::client::GitHubPrClient;
use crate::exit_codes::codes as exit_codes;

// ── Library function ───────────────────────────────────────────────────────

impl GitHubPrClient {
    /// Enable squash auto-merge on a PR.
    pub fn auto_merge(&self, pr_number: u32) -> Result<(), String> {
        self.provider()
            .auto_merge(pr_number)
            .map_err(|error| error.to_string())
    }
}

// ── CLI runner ─────────────────────────────────────────────────────────────

pub fn run_pr_auto_merge(repo: &str, pr_number: u32, json_output: bool) -> u8 {
    let client = match GitHubPrClient::new(repo) {
        Ok(client) => client,
        Err(error) => {
            super::output_pr_error(json_output, "pr_auto_merge_failed", &error);
            return exit_codes::GENERIC_ERROR;
        },
    };

    match client.auto_merge(pr_number) {
        Ok(()) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "pr": pr_number,
                        "auto_merge": "enabled"
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Auto-merge enabled on PR #{pr_number} (squash).");
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            super::output_pr_error(json_output, "pr_auto_merge_failed", &error);
            exit_codes::GENERIC_ERROR
        },
    }
}
