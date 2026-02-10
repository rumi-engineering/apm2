//! `apm2 fac pr checks` — list CI check statuses for a PR.

use super::client::GitHubPrClient;
use super::types::CheckStatus;
use crate::exit_codes::codes as exit_codes;

// ── Library function ───────────────────────────────────────────────────────

impl GitHubPrClient {
    /// Get CI check statuses for a PR.
    pub fn checks(&self, pr_number: u32) -> Result<Vec<CheckStatus>, String> {
        let checks = self
            .provider()
            .pr_checks(pr_number)
            .map_err(|error| error.to_string())?;

        Ok(checks
            .into_iter()
            .map(|check| CheckStatus {
                name: check.name,
                status: check.status,
                conclusion: check.conclusion,
                details_url: check.details_url,
            })
            .collect())
    }
}

// ── CLI runner ─────────────────────────────────────────────────────────────

pub fn run_pr_checks(repo: &str, pr_number: u32, json_output: bool) -> u8 {
    let client = match GitHubPrClient::new(repo) {
        Ok(client) => client,
        Err(error) => {
            super::output_pr_error(json_output, "pr_checks_failed", &error);
            return exit_codes::GENERIC_ERROR;
        },
    };

    match client.checks(pr_number) {
        Ok(checks) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&checks).unwrap_or_else(|_| "[]".to_string())
                );
            } else {
                for check in &checks {
                    let conclusion = if check.conclusion.is_empty() {
                        &check.status
                    } else {
                        &check.conclusion
                    };
                    println!("{}\t{}", check.name, conclusion);
                }
                if checks.is_empty() {
                    println!("No checks found.");
                }
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            super::output_pr_error(json_output, "pr_checks_failed", &error);
            exit_codes::GENERIC_ERROR
        },
    }
}
