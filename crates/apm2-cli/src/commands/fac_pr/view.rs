//! `apm2 fac pr view` — view a single pull request.

use apm2_core::forge::PrState;

use super::client::GitHubPrClient;
use super::types::{PrAuthor, PrLabel, PrViewData};
use crate::exit_codes::codes as exit_codes;

// ── Library function ───────────────────────────────────────────────────────

impl GitHubPrClient {
    /// View a single PR by number.
    pub fn view(&self, pr_number: u32) -> Result<PrViewData, String> {
        let detail = self
            .provider()
            .view_pr(pr_number)
            .map_err(|error| error.to_string())?;

        Ok(PrViewData {
            number: detail.summary.number,
            title: detail.summary.title,
            state: pr_state_to_string(detail.summary.state),
            body: detail.body,
            head_ref_name: detail.summary.head_ref,
            base_ref_name: detail.summary.base_ref,
            head_ref_oid: detail.head_sha,
            url: detail.summary.url,
            author_association: detail.author_association,
            author: PrAuthor {
                login: detail.summary.author,
            },
            mergeable: detail.mergeable,
            review_decision: detail.review_decision,
            labels: detail
                .labels
                .into_iter()
                .map(|name| PrLabel { name })
                .collect(),
        })
    }

    /// Get only the HEAD SHA for a PR.
    #[allow(dead_code)]
    pub fn head_sha(&self, pr_number: u32) -> Result<String, String> {
        self.provider()
            .head_sha(pr_number)
            .map_err(|error| error.to_string())
    }
}

fn pr_state_to_string(state: PrState) -> String {
    match state {
        PrState::Open => "OPEN".to_string(),
        PrState::Closed => "CLOSED".to_string(),
        PrState::Merged => "MERGED".to_string(),
    }
}

// ── CLI runner ─────────────────────────────────────────────────────────────

pub fn run_pr_view(repo: &str, pr_number: u32, json_output: bool) -> u8 {
    let client = match GitHubPrClient::new(repo) {
        Ok(client) => client,
        Err(error) => {
            super::output_pr_error(json_output, "pr_view_failed", &error);
            return exit_codes::GENERIC_ERROR;
        },
    };

    match client.view(pr_number) {
        Ok(data) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("PR #{}: {}", data.number, data.title);
                println!("  State:      {}", data.state);
                println!(
                    "  Head:       {} ({})",
                    data.head_ref_name, data.head_ref_oid
                );
                println!("  Base:       {}", data.base_ref_name);
                println!("  Author:     {}", data.author.login);
                println!("  Mergeable:  {}", data.mergeable);
                println!("  Review:     {}", data.review_decision);
                if !data.labels.is_empty() {
                    let labels: Vec<&str> = data
                        .labels
                        .iter()
                        .map(|label| label.name.as_str())
                        .collect();
                    println!("  Labels:     {}", labels.join(", "));
                }
                println!("  URL:        {}", data.url);
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            super::output_pr_error(json_output, "pr_view_failed", &error);
            exit_codes::GENERIC_ERROR
        },
    }
}
