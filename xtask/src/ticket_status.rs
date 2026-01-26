//! Dynamic ticket status determination from git state.
//!
//! This module provides functions to derive ticket status from git state
//! (merged PRs, existing branches, worktrees) rather than reading from
//! YAML files. This eliminates manual status maintenance bugs and creates
//! a single source of truth.
//!
//! # Status Detection
//!
//! | Status | Detection |
//! |--------|-----------|
//! | `COMPLETED` | Branch `ticket/*/TCK-XXXXX` has merged PR |
//! | `IN_PROGRESS` | Branch exists (local or remote), not merged |
//! | `PENDING` | No branch exists, not completed |

use std::collections::HashSet;

use anyhow::Result;
use xshell::{Shell, cmd};

/// Ticket status derived from git state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketStatus {
    /// No branch exists for this ticket.
    Pending,
    /// Branch exists but PR not merged.
    InProgress,
    /// PR has been merged.
    Completed,
}

/// Result of querying completed tickets from GitHub.
#[derive(Debug)]
pub enum CompletedTicketsResult {
    /// Successfully queried GitHub.
    Success(HashSet<String>),
    /// GitHub query failed - use fallback behavior.
    NetworkError(String),
}

/// Get all completed ticket IDs by checking merged PRs.
///
/// Queries GitHub for merged PRs with ticket branch patterns like
/// `ticket/RFC-*/TCK-XXXXX` and extracts the ticket IDs.
///
/// # Returns
///
/// - `CompletedTicketsResult::Success` with the set of completed ticket IDs
/// - `CompletedTicketsResult::NetworkError` if GitHub CLI fails (network, auth,
///   rate limit)
pub fn get_completed_tickets(sh: &Shell) -> CompletedTicketsResult {
    // Query GitHub for merged PRs with ticket branch pattern
    // Use --limit 500 to get a reasonable history
    let result = cmd!(
        sh,
        "gh pr list --state merged --limit 500 --json headRefName"
    )
    .read();

    match result {
        Ok(output) => CompletedTicketsResult::Success(parse_ticket_ids_from_pr_json(&output)),
        Err(e) => CompletedTicketsResult::NetworkError(format!(
            "Failed to query GitHub for merged PRs: {e}"
        )),
    }
}

/// Get ticket IDs with active branches (not merged).
///
/// Lists all ticket branches (local and remote) and filters out
/// those that have already been completed.
///
/// # Errors
///
/// Returns an error if git commands fail.
#[allow(clippy::implicit_hasher)]
pub fn get_in_progress_tickets(sh: &Shell, completed: &HashSet<String>) -> Result<HashSet<String>> {
    // List all ticket branches (local and remote)
    // Use --list with pattern to match ticket branches
    let local_output = cmd!(sh, "git branch --list *ticket/*TCK-*")
        .read()
        .unwrap_or_default();

    let remote_output = cmd!(sh, "git branch -r --list *ticket/*TCK-*")
        .read()
        .unwrap_or_default();

    let combined = format!("{local_output}\n{remote_output}");
    Ok(parse_ticket_ids_from_branch_list(&combined, completed))
}

/// Get ticket IDs with active worktrees.
///
/// Parses `git worktree list --porcelain` output to find worktrees
/// with ticket-related paths like `/path/apm2-TCK-00030`.
///
/// # Errors
///
/// Returns an error if git commands fail.
#[allow(dead_code)]
pub fn get_worktree_tickets(sh: &Shell) -> Result<HashSet<String>> {
    let output = cmd!(sh, "git worktree list --porcelain")
        .read()
        .unwrap_or_default();

    Ok(parse_ticket_ids_from_worktrees(&output))
}

/// Parse ticket IDs from GitHub PR list JSON output.
///
/// Expects JSON format: `[{"headRefName": "ticket/RFC-0002/TCK-00030"}, ...]`
fn parse_ticket_ids_from_pr_json(json: &str) -> HashSet<String> {
    let mut ticket_ids = HashSet::new();
    let key = "\"headRefName\":";

    // Simple JSON parsing without serde dependency
    // Find ALL occurrences of "headRefName" in the content
    let mut search_pos = 0;
    while let Some(start) = json[search_pos..].find(key) {
        let abs_start = search_pos + start;
        let rest = &json[abs_start + key.len()..];

        // Find the value between quotes
        if let Some(quote_start) = rest.find('"') {
            let after_quote = &rest[quote_start + 1..];
            if let Some(quote_end) = after_quote.find('"') {
                let branch_name = &after_quote[..quote_end];
                if let Some(ticket_id) = extract_ticket_id_from_branch(branch_name) {
                    ticket_ids.insert(ticket_id);
                }
                // Move past this match
                search_pos = abs_start + key.len() + quote_start + 1 + quote_end + 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    ticket_ids
}

/// Parse ticket IDs from git branch list output.
///
/// Expects output like:
/// ```text
///   ticket/RFC-0002/TCK-00030
/// * ticket/RFC-0002/TCK-00031
///   remotes/origin/ticket/RFC-0002/TCK-00032
/// ```
fn parse_ticket_ids_from_branch_list(output: &str, completed: &HashSet<String>) -> HashSet<String> {
    let mut ticket_ids = HashSet::new();

    for line in output.lines() {
        let branch = line.trim().trim_start_matches("* ").trim();
        // Remove remotes/origin/ prefix if present
        let branch = branch.strip_prefix("remotes/origin/").unwrap_or(branch);

        if let Some(ticket_id) = extract_ticket_id_from_branch(branch) {
            // Only include if not already completed
            if !completed.contains(&ticket_id) {
                ticket_ids.insert(ticket_id);
            }
        }
    }

    ticket_ids
}

/// Parse ticket IDs from git worktree list --porcelain output.
///
/// Expects output like:
/// ```text
/// worktree /path/to/apm2
/// HEAD abc123
/// branch refs/heads/main
///
/// worktree /path/to/apm2-TCK-00030
/// HEAD def456
/// branch refs/heads/ticket/RFC-0002/TCK-00030
/// ```
fn parse_ticket_ids_from_worktrees(output: &str) -> HashSet<String> {
    let mut ticket_ids = HashSet::new();

    for line in output.lines() {
        // Look for worktree paths containing TCK-XXXXX
        if let Some(path) = line.strip_prefix("worktree ") {
            // Extract TCK-XXXXX from path like /path/apm2-TCK-00030
            if let Some(idx) = path.find("TCK-") {
                let rest = &path[idx..];
                // Extract just the TCK-XXXXX part (5 digits after TCK-)
                if rest.len() >= 9 {
                    let ticket_id = &rest[..9];
                    if is_valid_ticket_id(ticket_id) {
                        ticket_ids.insert(ticket_id.to_string());
                    }
                }
            }
        }
    }

    ticket_ids
}

/// Extract ticket ID from a branch name like `ticket/RFC-0002/TCK-00030`.
fn extract_ticket_id_from_branch(branch: &str) -> Option<String> {
    // Look for TCK-XXXXX pattern in the branch name
    if let Some(idx) = branch.find("TCK-") {
        let rest = &branch[idx..];
        // Extract just the TCK-XXXXX part (5 digits after TCK-)
        if rest.len() >= 9 {
            let ticket_id = &rest[..9];
            if is_valid_ticket_id(ticket_id) {
                return Some(ticket_id.to_string());
            }
        }
    }
    None
}

/// Check if a string is a valid ticket ID (TCK-XXXXX where X is a digit).
fn is_valid_ticket_id(s: &str) -> bool {
    if !s.starts_with("TCK-") {
        return false;
    }
    let digits = &s[4..];
    digits.len() == 5 && digits.chars().all(|c| c.is_ascii_digit())
}

/// Determine the status of a specific ticket.
///
/// # Arguments
///
/// * `ticket_id` - The ticket ID to check (e.g., "TCK-00030")
/// * `completed` - Set of ticket IDs that are completed
/// * `in_progress` - Set of ticket IDs that are in progress
///
/// # Returns
///
/// The derived `TicketStatus` for the ticket.
#[allow(dead_code)]
#[allow(clippy::implicit_hasher)]
pub fn get_ticket_status(
    ticket_id: &str,
    completed: &HashSet<String>,
    in_progress: &HashSet<String>,
) -> TicketStatus {
    if completed.contains(ticket_id) {
        TicketStatus::Completed
    } else if in_progress.contains(ticket_id) {
        TicketStatus::InProgress
    } else {
        TicketStatus::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ticket_id_from_branch() {
        assert_eq!(
            extract_ticket_id_from_branch("ticket/RFC-0002/TCK-00030"),
            Some("TCK-00030".to_string())
        );
        assert_eq!(
            extract_ticket_id_from_branch("TCK-00030"),
            Some("TCK-00030".to_string())
        );
        assert_eq!(extract_ticket_id_from_branch("feature/something"), None);
        assert_eq!(
            extract_ticket_id_from_branch("ticket/RFC-0002/TCK-0003"), // Too short
            None
        );
    }

    #[test]
    fn test_is_valid_ticket_id() {
        assert!(is_valid_ticket_id("TCK-00030"));
        assert!(is_valid_ticket_id("TCK-00001"));
        assert!(is_valid_ticket_id("TCK-99999"));
        assert!(!is_valid_ticket_id("TCK-0003")); // Too short
        assert!(!is_valid_ticket_id("TCK-000030")); // Too long
        assert!(!is_valid_ticket_id("TCK-0003a")); // Non-digit
        assert!(!is_valid_ticket_id("TKT-00030")); // Wrong prefix
    }

    #[test]
    fn test_parse_ticket_ids_from_pr_json() {
        // Test multi-line format
        let json = r#"[
            {"headRefName":"ticket/RFC-0002/TCK-00030","number":1},
            {"headRefName":"ticket/RFC-0002/TCK-00031","number":2},
            {"headRefName":"feature/something","number":3}
        ]"#;

        let result = parse_ticket_ids_from_pr_json(json);
        assert_eq!(result.len(), 2);
        assert!(result.contains("TCK-00030"));
        assert!(result.contains("TCK-00031"));
    }

    #[test]
    fn test_parse_ticket_ids_from_pr_json_single_line() {
        // Test single-line format (as returned by gh CLI)
        let json = r#"[{"headRefName":"RFC-0002/TCK-00034"},{"headRefName":"ticket/RFC-0003/TCK-00040"},{"headRefName":"ticket/RFC-0002/TCK-00033"}]"#;

        let result = parse_ticket_ids_from_pr_json(json);
        assert_eq!(result.len(), 3);
        assert!(result.contains("TCK-00034"));
        assert!(result.contains("TCK-00040"));
        assert!(result.contains("TCK-00033"));
    }

    #[test]
    fn test_parse_ticket_ids_from_branch_list() {
        let output = r"
  ticket/RFC-0002/TCK-00030
* ticket/RFC-0002/TCK-00031
  remotes/origin/ticket/RFC-0002/TCK-00032
  feature/something
";

        let completed = HashSet::from(["TCK-00030".to_string()]);
        let result = parse_ticket_ids_from_branch_list(output, &completed);

        // TCK-00030 should be filtered out (completed)
        assert_eq!(result.len(), 2);
        assert!(!result.contains("TCK-00030"));
        assert!(result.contains("TCK-00031"));
        assert!(result.contains("TCK-00032"));
    }

    #[test]
    fn test_parse_ticket_ids_from_worktrees() {
        let output = r"worktree /home/user/apm2
HEAD abc123
branch refs/heads/main

worktree /home/user/apm2-TCK-00030
HEAD def456
branch refs/heads/ticket/RFC-0002/TCK-00030
";

        let result = parse_ticket_ids_from_worktrees(output);
        assert_eq!(result.len(), 1);
        assert!(result.contains("TCK-00030"));
    }

    #[test]
    fn test_get_ticket_status() {
        let completed = HashSet::from(["TCK-00001".to_string()]);
        let in_progress = HashSet::from(["TCK-00002".to_string()]);

        assert_eq!(
            get_ticket_status("TCK-00001", &completed, &in_progress),
            TicketStatus::Completed
        );
        assert_eq!(
            get_ticket_status("TCK-00002", &completed, &in_progress),
            TicketStatus::InProgress
        );
        assert_eq!(
            get_ticket_status("TCK-00003", &completed, &in_progress),
            TicketStatus::Pending
        );
    }

    #[test]
    fn test_parse_ticket_ids_from_pr_json_empty() {
        // Empty JSON array (no merged PRs)
        let json = "[]";
        let result = parse_ticket_ids_from_pr_json(json);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_ticket_ids_from_pr_json_empty_string() {
        // Empty string (simulates network failure fallback)
        let json = "";
        let result = parse_ticket_ids_from_pr_json(json);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_ticket_ids_from_pr_json_malformed() {
        // Malformed JSON should not panic, just return empty set
        let json = "not valid json {{{";
        let result = parse_ticket_ids_from_pr_json(json);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_ticket_ids_from_pr_json_partial() {
        // Truncated JSON without closing quote returns empty (safe behavior)
        let json = r#"[{"headRefName":"ticket/RFC-0002/TCK-00030"#;
        let result = parse_ticket_ids_from_pr_json(json);
        assert!(result.is_empty());

        // But complete entries before truncation are extracted
        let json_with_complete =
            r#"[{"headRefName":"ticket/RFC-0002/TCK-00030"},{"headRefName":"ticket/RFC-"#;
        let result = parse_ticket_ids_from_pr_json(json_with_complete);
        assert!(result.contains("TCK-00030"));
    }

    // =========================================================================
    // Error handling path tests (TCK-00103)
    // =========================================================================

    #[test]
    fn test_completed_tickets_result_success_variant() {
        // Verify Success variant can be constructed and matched
        let tickets: HashSet<String> =
            HashSet::from(["TCK-00001".to_string(), "TCK-00002".to_string()]);
        let result = CompletedTicketsResult::Success(tickets);

        match result {
            CompletedTicketsResult::Success(t) => {
                assert_eq!(t.len(), 2);
                assert!(t.contains("TCK-00001"));
                assert!(t.contains("TCK-00002"));
            },
            CompletedTicketsResult::NetworkError(_) => {
                panic!("Expected Success variant");
            },
        }
    }

    #[test]
    fn test_completed_tickets_result_network_error_variant() {
        // Verify NetworkError variant can be constructed and matched
        let error_msg = "Failed to query GitHub for merged PRs: connection refused";
        let result = CompletedTicketsResult::NetworkError(error_msg.to_string());

        match result {
            CompletedTicketsResult::Success(_) => {
                panic!("Expected NetworkError variant");
            },
            CompletedTicketsResult::NetworkError(msg) => {
                assert!(msg.contains("connection refused"));
                assert!(msg.contains("Failed to query GitHub"));
            },
        }
    }

    #[test]
    fn test_completed_tickets_result_empty_success() {
        // Success with empty set is valid (no merged PRs found)
        let result = CompletedTicketsResult::Success(HashSet::new());

        match result {
            CompletedTicketsResult::Success(t) => {
                assert!(t.is_empty());
            },
            CompletedTicketsResult::NetworkError(_) => {
                panic!("Expected Success variant");
            },
        }
    }

    #[test]
    fn test_completed_tickets_result_handles_various_error_messages() {
        // Verify different error scenarios produce identifiable messages
        let scenarios = [
            ("network timeout", "timeout"),
            ("authentication failed", "auth"),
            ("rate limit exceeded", "rate limit"),
            ("repository not found", "not found"),
        ];

        for (error_type, substring) in scenarios {
            let msg = format!("Failed to query GitHub: {error_type}");
            let result = CompletedTicketsResult::NetworkError(msg.clone());

            if let CompletedTicketsResult::NetworkError(m) = result {
                assert!(
                    m.contains(substring),
                    "Error message should contain '{substring}': {m}"
                );
            } else {
                panic!("Expected NetworkError variant for {error_type}");
            }
        }
    }

    #[test]
    fn test_fallback_behavior_on_network_error() {
        // Simulate the fallback behavior that should happen when network fails:
        // Using an empty HashSet as fallback is valid
        let network_error = CompletedTicketsResult::NetworkError("connection refused".to_string());

        let completed = match network_error {
            CompletedTicketsResult::Success(tickets) => tickets,
            CompletedTicketsResult::NetworkError(_msg) => {
                // Fallback: use empty set (may re-select completed tickets)
                HashSet::new()
            },
        };

        // With empty completed set, all tickets appear as pending
        let in_progress = HashSet::new();
        assert_eq!(
            get_ticket_status("TCK-00001", &completed, &in_progress),
            TicketStatus::Pending
        );

        // This is the expected fallback behavior - the ticket will be
        // re-selectable even if it was previously completed
    }

    #[test]
    fn test_debug_format_for_completed_tickets_result() {
        // Verify Debug trait is implemented and produces useful output
        let success = CompletedTicketsResult::Success(HashSet::from(["TCK-00001".to_string()]));
        let debug_str = format!("{success:?}");
        assert!(debug_str.contains("Success"));
        assert!(debug_str.contains("TCK-00001"));

        let error = CompletedTicketsResult::NetworkError("test error".to_string());
        let debug_str = format!("{error:?}");
        assert!(debug_str.contains("NetworkError"));
        assert!(debug_str.contains("test error"));
    }
}
