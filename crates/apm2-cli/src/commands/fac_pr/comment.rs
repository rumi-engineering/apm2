//! `apm2 fac pr comment` — post and read PR comments.

use super::client::GitHubPrClient;
use super::types::{CommentAuthor, CommentCreateResult, PrComment};
use crate::exit_codes::codes as exit_codes;

// ── Library functions ──────────────────────────────────────────────────────

impl GitHubPrClient {
    /// Post a comment on a PR, returning the comment ID.
    pub fn comment(&self, pr_number: u32, body: &str) -> Result<u64, String> {
        self.provider()
            .post_comment(pr_number, body)
            .map_err(|error| error.to_string())
    }

    /// Read PR comments with pagination.
    pub fn read_comments(&self, pr_number: u32, max_pages: u32) -> Result<Vec<PrComment>, String> {
        let comments = self
            .provider()
            .read_comments(pr_number, max_pages)
            .map_err(|error| error.to_string())?;

        Ok(comments
            .into_iter()
            .map(|comment| PrComment {
                id: comment.id,
                body: comment.body,
                author: CommentAuthor {
                    login: comment.author,
                },
                created_at: comment.created_at,
            })
            .collect())
    }
}

// ── CLI runners ────────────────────────────────────────────────────────────

pub fn run_pr_comment(repo: &str, pr_number: u32, body: &str, json_output: bool) -> u8 {
    let client = match GitHubPrClient::new(repo) {
        Ok(client) => client,
        Err(error) => {
            super::output_pr_error(json_output, "pr_comment_failed", &error);
            return exit_codes::GENERIC_ERROR;
        },
    };

    match client.comment(pr_number, body) {
        Ok(id) => {
            if json_output {
                let result = CommentCreateResult { id };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Comment posted (id={id}) on PR #{pr_number}.");
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            super::output_pr_error(json_output, "pr_comment_failed", &error);
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_pr_read_comments(repo: &str, pr_number: u32, max_pages: u32, json_output: bool) -> u8 {
    let client = match GitHubPrClient::new(repo) {
        Ok(client) => client,
        Err(error) => {
            super::output_pr_error(json_output, "pr_read_comments_failed", &error);
            return exit_codes::GENERIC_ERROR;
        },
    };

    match client.read_comments(pr_number, max_pages) {
        Ok(comments) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&comments).unwrap_or_else(|_| "[]".to_string())
                );
            } else {
                for comment in &comments {
                    let preview: String = comment.body.chars().take(80).collect();
                    println!(
                        "#{}\t{}\t{}\t{}",
                        comment.id, comment.author.login, comment.created_at, preview
                    );
                }
                if comments.is_empty() {
                    println!("No comments found.");
                }
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            super::output_pr_error(json_output, "pr_read_comments_failed", &error);
            exit_codes::GENERIC_ERROR
        },
    }
}
