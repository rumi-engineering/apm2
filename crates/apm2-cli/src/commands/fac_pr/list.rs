//! `apm2 fac pr list` — list pull requests.

use apm2_core::forge::{ListPrArgs as ForgeListPrArgs, PrState, PrStateFilter};

use super::client::GitHubPrClient;
use super::types::{PrListArgs, PrListEntry};
use crate::exit_codes::codes as exit_codes;

// ── Library function ───────────────────────────────────────────────────────

impl GitHubPrClient {
    /// List PRs matching the given filters.
    pub fn list(&self, args: &PrListArgs) -> Result<Vec<PrListEntry>, String> {
        let forge_args = ForgeListPrArgs {
            state: parse_state_filter(args.state.as_deref())?,
            head: args.head.clone(),
            base: args.base.clone(),
            limit: args.limit,
        };

        let entries = self
            .provider()
            .list_prs(&forge_args)
            .map_err(|error| error.to_string())?;

        Ok(entries
            .into_iter()
            .map(|entry| PrListEntry {
                number: entry.number,
                title: entry.title,
                state: pr_state_to_string(entry.state),
                head_ref_name: entry.head_ref,
                base_ref_name: entry.base_ref,
                url: entry.url,
            })
            .collect())
    }
}

fn parse_state_filter(value: Option<&str>) -> Result<Option<PrStateFilter>, String> {
    let Some(state) = value else {
        return Ok(None);
    };

    match state.to_ascii_lowercase().as_str() {
        "open" => Ok(Some(PrStateFilter::Open)),
        "closed" => Ok(Some(PrStateFilter::Closed)),
        "merged" => Ok(Some(PrStateFilter::Merged)),
        "all" => Ok(Some(PrStateFilter::All)),
        _ => Err(format!(
            "invalid state filter `{state}` (expected open|closed|merged|all)"
        )),
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

pub fn run_pr_list(repo: &str, args: &PrListArgs, json_output: bool) -> u8 {
    let client = match GitHubPrClient::new(repo) {
        Ok(client) => client,
        Err(error) => {
            super::output_pr_error(json_output, "pr_list_failed", &error);
            return exit_codes::GENERIC_ERROR;
        },
    };

    match client.list(args) {
        Ok(entries) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
                );
            } else {
                for entry in &entries {
                    println!(
                        "#{}\t{}\t{}\t{}",
                        entry.number, entry.state, entry.head_ref_name, entry.title
                    );
                }
                if entries.is_empty() {
                    println!("No matching pull requests found.");
                }
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            super::output_pr_error(json_output, "pr_list_failed", &error);
            exit_codes::GENERIC_ERROR
        },
    }
}
