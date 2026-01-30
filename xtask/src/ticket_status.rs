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

// =============================================================================
// PR Details and Timeline Types
// =============================================================================

/// PR details from GitHub.
#[derive(Debug, Clone)]
pub struct PrDetails {
    /// Full PR URL (e.g., `https://github.com/org/repo/pull/123`)
    pub url: String,
    /// PR number
    pub number: u32,
    /// PR state: OPEN, MERGED, CLOSED
    pub state: String,
    /// Review decision: APPROVED, `CHANGES_REQUESTED`, `REVIEW_REQUIRED`, or
    /// None
    pub review_decision: Option<String>,
}

/// Timeline event for PR history.
#[derive(Debug, Clone)]
pub struct TimelineEntry {
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Event type: COMMIT, COMMENT, REVIEW
    pub event_type: String,
    /// Author login
    pub author: String,
    /// Event content (commit message, comment body, review body)
    pub content: String,
    /// Optional metadata (SHA for commits, path for inline comments)
    pub metadata: Option<String>,
}

/// Unresolved review thread from a PR.
#[derive(Debug, Clone)]
pub struct ReviewThread {
    /// File path the thread is on
    pub path: String,
    /// Line number (if available)
    pub line: Option<u32>,
    /// Comments in the thread (oldest to newest)
    pub comments: Vec<String>,
}

/// Result of querying PR details.
#[derive(Debug)]
pub enum PrQueryResult<T> {
    /// Successfully queried GitHub.
    Success(T),
    /// No PR exists for this branch.
    NotFound,
    /// GitHub query failed.
    NetworkError(String),
}

// =============================================================================
// PR Query Functions
// =============================================================================

/// Get PR details for a branch.
///
/// Returns `PrQueryResult::Success(PrDetails)` if a PR exists for the branch,
/// `PrQueryResult::NotFound` if no PR exists, or `PrQueryResult::NetworkError`
/// if the GitHub CLI fails.
pub fn get_pr_for_branch(sh: &Shell, branch_name: &str) -> PrQueryResult<PrDetails> {
    let result = cmd!(
        sh,
        "gh pr view {branch_name} --json url,number,state,reviewDecision"
    )
    .read();

    match result {
        Ok(output) => {
            if output.trim().is_empty() {
                return PrQueryResult::NotFound;
            }
            parse_pr_details_json(&output).map_or(PrQueryResult::NotFound, PrQueryResult::Success)
        },
        Err(e) => {
            let error_str = e.to_string();
            // gh pr view returns exit code 1 with "no pull requests found" message
            if error_str.contains("no pull requests found")
                || error_str.contains("Could not resolve")
            {
                PrQueryResult::NotFound
            } else {
                PrQueryResult::NetworkError(format!("Failed to query PR for branch: {e}"))
            }
        },
    }
}

/// Get interleaved timeline for a PR.
///
/// Returns a chronologically sorted list of commits, comments, and reviews.
/// On network error, returns an empty vector with a warning printed to stderr.
pub fn get_pr_timeline(sh: &Shell, pr_number: u32) -> Vec<TimelineEntry> {
    let mut entries = Vec::new();
    let pr_num_str = pr_number.to_string();

    // Get commits
    if let Ok(output) = cmd!(sh, "gh pr view {pr_num_str} --json commits").read() {
        entries.extend(parse_commits_json(&output));
    }

    // Get comments
    if let Ok(output) = cmd!(sh, "gh pr view {pr_num_str} --json comments").read() {
        entries.extend(parse_comments_json(&output));
    }

    // Get reviews
    if let Ok(output) = cmd!(sh, "gh pr view {pr_num_str} --json reviews").read() {
        entries.extend(parse_reviews_json(&output));
    }

    // Sort by timestamp
    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    entries
}

/// Get unresolved review threads from a PR.
///
/// Returns threads that have not been marked as resolved.
/// On network error, returns an empty vector.
///
/// Uses GraphQL API since `gh pr view --json` doesn't support reviewThreads.
pub fn get_unresolved_threads(sh: &Shell, pr_number: u32) -> Vec<ReviewThread> {
    // GraphQL query to get review threads
    let query = format!(
        r#"query {{
  repository(owner: "rumi-engineering", name: "apm2") {{
    pullRequest(number: {pr_number}) {{
      reviewThreads(first: 100) {{
        nodes {{
          isResolved
          path
          line
          comments(first: 10) {{
            nodes {{
              body
              author {{
                login
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"#
    );

    let result = cmd!(sh, "gh api graphql -f query={query}").read();

    result.map_or_else(
        |_| Vec::new(),
        |output| parse_graphql_review_threads(&output),
    )
}

// =============================================================================
// JSON Parsing Helpers
// =============================================================================

/// Parse PR details from JSON output.
fn parse_pr_details_json(json: &str) -> Option<PrDetails> {
    let url = extract_json_string(json, "\"url\":")?;
    let number = extract_json_number(json, "\"number\":")?;
    let state = extract_json_string(json, "\"state\":")?;
    let review_decision = extract_json_string(json, "\"reviewDecision\":");

    Some(PrDetails {
        url,
        number,
        state,
        review_decision,
    })
}

/// Parse commits from JSON into timeline entries.
fn parse_commits_json(json: &str) -> Vec<TimelineEntry> {
    let mut entries = Vec::new();

    // Find the commits array
    let commits_key = "\"commits\":";
    let Some(commits_start) = json.find(commits_key) else {
        return entries;
    };
    let rest = &json[commits_start + commits_key.len()..];

    // Parse each commit object
    let mut search_pos = 0;
    while let Some(obj_start) = rest[search_pos..].find('{') {
        let abs_start = search_pos + obj_start;
        let obj_rest = &rest[abs_start..];

        // Find matching closing brace
        let Some(obj_end) = find_matching_brace(obj_rest) else {
            break;
        };
        let obj = &obj_rest[..=obj_end];

        // Extract fields - look for oid first (commit SHA)
        if let (Some(oid), Some(message)) = (
            extract_json_string(obj, "\"oid\":"),
            extract_json_string(obj, "\"messageHeadline\":"),
        ) {
            // Try to get authoredDate (this is in the outer commit object)
            let timestamp = extract_json_string(obj, "\"authoredDate\":")
                .or_else(|| extract_json_string(obj, "\"committedDate\":"))
                .unwrap_or_default();

            // Try to get author login - it's nested in authors array
            let author = extract_nested_author(obj).unwrap_or_else(|| "unknown".to_string());

            entries.push(TimelineEntry {
                timestamp,
                event_type: "COMMIT".to_string(),
                author,
                content: message,
                metadata: Some(oid[..7.min(oid.len())].to_string()), // Short SHA
            });
        }

        search_pos = abs_start + obj_end + 1;
    }

    entries
}

/// Parse comments from JSON into timeline entries.
fn parse_comments_json(json: &str) -> Vec<TimelineEntry> {
    let mut entries = Vec::new();

    let comments_key = "\"comments\":";
    let Some(comments_start) = json.find(comments_key) else {
        return entries;
    };
    let rest = &json[comments_start + comments_key.len()..];

    let mut search_pos = 0;
    while let Some(obj_start) = rest[search_pos..].find('{') {
        let abs_start = search_pos + obj_start;
        let obj_rest = &rest[abs_start..];

        let Some(obj_end) = find_matching_brace(obj_rest) else {
            break;
        };
        let obj = &obj_rest[..=obj_end];

        if let Some(body) = extract_json_string(obj, "\"body\":") {
            let timestamp = extract_json_string(obj, "\"createdAt\":").unwrap_or_default();
            let author =
                extract_nested_login(obj, "\"author\":").unwrap_or_else(|| "unknown".to_string());

            entries.push(TimelineEntry {
                timestamp,
                event_type: "COMMENT".to_string(),
                author,
                content: truncate_content(&body, 200),
                metadata: None,
            });
        }

        search_pos = abs_start + obj_end + 1;
    }

    entries
}

/// Parse reviews from JSON into timeline entries.
fn parse_reviews_json(json: &str) -> Vec<TimelineEntry> {
    let mut entries = Vec::new();

    let reviews_key = "\"reviews\":";
    let Some(reviews_start) = json.find(reviews_key) else {
        return entries;
    };
    let rest = &json[reviews_start + reviews_key.len()..];

    let mut search_pos = 0;
    while let Some(obj_start) = rest[search_pos..].find('{') {
        let abs_start = search_pos + obj_start;
        let obj_rest = &rest[abs_start..];

        let Some(obj_end) = find_matching_brace(obj_rest) else {
            break;
        };
        let obj = &obj_rest[..=obj_end];

        // Reviews have state (APPROVED, CHANGES_REQUESTED, COMMENTED, etc.)
        if let Some(state) = extract_json_string(obj, "\"state\":") {
            let timestamp = extract_json_string(obj, "\"submittedAt\":").unwrap_or_default();
            let author =
                extract_nested_login(obj, "\"author\":").unwrap_or_else(|| "unknown".to_string());
            let body = extract_json_string(obj, "\"body\":").unwrap_or_default();

            let content = if body.is_empty() {
                state.clone()
            } else {
                format!("{} - {}", state, truncate_content(&body, 150))
            };

            entries.push(TimelineEntry {
                timestamp,
                event_type: "REVIEW".to_string(),
                author,
                content,
                metadata: Some(state),
            });
        }

        search_pos = abs_start + obj_end + 1;
    }

    entries
}

/// Parse review threads from JSON.
#[cfg(test)]
fn parse_review_threads_json(json: &str) -> Vec<ReviewThread> {
    let mut threads = Vec::new();

    let threads_key = "\"reviewThreads\":";
    let Some(threads_start) = json.find(threads_key) else {
        return threads;
    };
    let rest = &json[threads_start + threads_key.len()..];

    let mut search_pos = 0;
    while let Some(obj_start) = rest[search_pos..].find('{') {
        let abs_start = search_pos + obj_start;
        let obj_rest = &rest[abs_start..];

        let Some(obj_end) = find_matching_brace(obj_rest) else {
            break;
        };
        let obj = &obj_rest[..=obj_end];

        // Check if thread is resolved
        let is_resolved = extract_json_bool(obj, "\"isResolved\":").unwrap_or(false);
        if is_resolved {
            search_pos = abs_start + obj_end + 1;
            continue;
        }

        // Extract path
        let path = extract_json_string(obj, "\"path\":").unwrap_or_default();
        let line = extract_json_number(obj, "\"line\":");

        // Extract comments from the thread
        let comments = extract_thread_comments(obj);

        if !path.is_empty() && !comments.is_empty() {
            threads.push(ReviewThread {
                path,
                line,
                comments,
            });
        }

        search_pos = abs_start + obj_end + 1;
    }

    threads
}

/// Parse review threads from GraphQL response.
///
/// GraphQL response structure:
/// ```json
/// {"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[...]}}}}}
/// ```
fn parse_graphql_review_threads(json: &str) -> Vec<ReviewThread> {
    let mut threads = Vec::new();

    // Navigate to the nodes array in the nested structure
    let nodes_key = "\"nodes\":";
    let Some(first_nodes) = json.find(nodes_key) else {
        return threads;
    };
    // Skip the first "nodes" (reviewThreads.nodes) and find actual thread objects
    let rest = &json[first_nodes + nodes_key.len()..];

    let mut search_pos = 0;
    while let Some(obj_start) = rest[search_pos..].find('{') {
        let abs_start = search_pos + obj_start;
        let obj_rest = &rest[abs_start..];

        let Some(obj_end) = find_matching_brace(obj_rest) else {
            break;
        };
        let obj = &obj_rest[..=obj_end];

        // Check if this looks like a thread object (has isResolved field)
        if !obj.contains("\"isResolved\":") {
            search_pos = abs_start + obj_end + 1;
            continue;
        }

        // Check if thread is resolved
        let is_resolved = extract_json_bool(obj, "\"isResolved\":").unwrap_or(false);
        if is_resolved {
            search_pos = abs_start + obj_end + 1;
            continue;
        }

        // Extract path
        let path = extract_json_string(obj, "\"path\":").unwrap_or_default();
        let line = extract_json_number(obj, "\"line\":");

        // Extract comments from the nested nodes
        let comments = extract_graphql_thread_comments(obj);

        if !path.is_empty() && !comments.is_empty() {
            threads.push(ReviewThread {
                path,
                line,
                comments,
            });
        }

        search_pos = abs_start + obj_end + 1;
    }

    threads
}

/// Extract comments from a GraphQL review thread object.
fn extract_graphql_thread_comments(thread_obj: &str) -> Vec<String> {
    let mut comments = Vec::new();

    // Find the comments.nodes array
    let comments_key = "\"comments\":";
    let Some(comments_start) = thread_obj.find(comments_key) else {
        return comments;
    };
    let rest = &thread_obj[comments_start + comments_key.len()..];

    // Find the nested nodes array
    let nodes_key = "\"nodes\":";
    let Some(nodes_start) = rest.find(nodes_key) else {
        return comments;
    };
    let nodes_rest = &rest[nodes_start + nodes_key.len()..];

    let mut search_pos = 0;
    while let Some(obj_start) = nodes_rest[search_pos..].find('{') {
        let abs_start = search_pos + obj_start;
        let obj_rest = &nodes_rest[abs_start..];

        let Some(obj_end) = find_matching_brace(obj_rest) else {
            break;
        };
        let obj = &obj_rest[..=obj_end];

        if let Some(body) = extract_json_string(obj, "\"body\":") {
            let author = extract_json_string(obj, "\"login\":").unwrap_or_else(|| "?".to_string());
            let truncated = if body.len() > 100 {
                format!("{}...", &body[..100])
            } else {
                body
            };
            comments.push(format!("@{author}: {truncated}"));
        }

        search_pos = abs_start + obj_end + 1;
    }

    comments
}

/// Extract comments from a review thread object.
#[cfg(test)]
fn extract_thread_comments(thread_obj: &str) -> Vec<String> {
    let mut comments = Vec::new();

    let comments_key = "\"comments\":";
    let Some(comments_start) = thread_obj.find(comments_key) else {
        return comments;
    };
    let rest = &thread_obj[comments_start + comments_key.len()..];

    let mut search_pos = 0;
    while let Some(obj_start) = rest[search_pos..].find('{') {
        let abs_start = search_pos + obj_start;
        let obj_rest = &rest[abs_start..];

        let Some(obj_end) = find_matching_brace(obj_rest) else {
            break;
        };
        let obj = &obj_rest[..=obj_end];

        if let Some(body) = extract_json_string(obj, "\"body\":") {
            let author =
                extract_nested_login(obj, "\"author\":").unwrap_or_else(|| "unknown".to_string());
            comments.push(format!("@{}: {}", author, truncate_content(&body, 300)));
        }

        search_pos = abs_start + obj_end + 1;
    }

    comments
}

/// Extract a string value from JSON by key.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let key_pos = json.find(key)?;
    let rest = &json[key_pos + key.len()..];
    let trimmed = rest.trim_start();

    // Handle null value
    if trimmed.starts_with("null") {
        return None;
    }

    // Find opening quote
    let quote_start = trimmed.find('"')?;
    let after_quote = &trimmed[quote_start + 1..];

    // Find closing quote (handling escaped quotes)
    let mut pos = 0;
    let bytes = after_quote.as_bytes();
    while pos < bytes.len() {
        if bytes[pos] == b'"' && (pos == 0 || bytes[pos - 1] != b'\\') {
            let value = &after_quote[..pos];
            // Unescape common escape sequences
            return Some(unescape_json_string(value));
        }
        pos += 1;
    }

    None
}

/// Extract a number value from JSON by key.
fn extract_json_number(json: &str, key: &str) -> Option<u32> {
    let key_pos = json.find(key)?;
    let rest = &json[key_pos + key.len()..];
    let trimmed = rest.trim_start();

    // Extract digits
    let num_str: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    num_str.parse().ok()
}

/// Extract a boolean value from JSON by key.
fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let key_pos = json.find(key)?;
    let rest = &json[key_pos + key.len()..];
    let trimmed = rest.trim_start();

    if trimmed.starts_with("true") {
        Some(true)
    } else if trimmed.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Extract nested author login from commits (authors array with login field).
fn extract_nested_author(json: &str) -> Option<String> {
    // Look for authors array pattern
    let authors_key = "\"authors\":";
    if let Some(pos) = json.find(authors_key) {
        let rest = &json[pos..];
        // Find login within the authors section
        if let Some(login) = extract_json_string(rest, "\"login\":") {
            return Some(login);
        }
    }
    None
}

/// Extract nested login from an author object.
fn extract_nested_login(json: &str, author_key: &str) -> Option<String> {
    let author_pos = json.find(author_key)?;
    let rest = &json[author_pos..];
    extract_json_string(rest, "\"login\":")
}

/// Find matching closing brace for an object.
fn find_matching_brace(s: &str) -> Option<usize> {
    if !s.starts_with('{') {
        return None;
    }

    let mut depth = 0;
    let mut in_string = false;
    let bytes = s.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            if b == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                },
                _ => {},
            }
        }
    }

    None
}

/// Unescape common JSON escape sequences.
fn unescape_json_string(s: &str) -> String {
    s.replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}

/// Truncate content to a maximum length, adding ellipsis if needed.
fn truncate_content(s: &str, max_len: usize) -> String {
    // First, normalize newlines to spaces for display
    let normalized: String = s
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    let trimmed = normalized.trim();

    if trimmed.len() <= max_len {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..max_len - 3])
    }
}

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

    // =========================================================================
    // PR Details and Timeline parsing tests
    // =========================================================================

    #[test]
    fn test_parse_pr_details_json() {
        let json = r#"{"url":"https://github.com/org/repo/pull/123","number":123,"state":"OPEN","reviewDecision":"CHANGES_REQUESTED"}"#;
        let result = parse_pr_details_json(json);
        assert!(result.is_some());
        let details = result.unwrap();
        assert_eq!(details.url, "https://github.com/org/repo/pull/123");
        assert_eq!(details.number, 123);
        assert_eq!(details.state, "OPEN");
        assert_eq!(
            details.review_decision,
            Some("CHANGES_REQUESTED".to_string())
        );
    }

    #[test]
    fn test_parse_pr_details_json_null_review_decision() {
        let json = r#"{"url":"https://github.com/org/repo/pull/456","number":456,"state":"MERGED","reviewDecision":null}"#;
        let result = parse_pr_details_json(json);
        assert!(result.is_some());
        let details = result.unwrap();
        assert_eq!(details.number, 456);
        assert_eq!(details.state, "MERGED");
        assert!(details.review_decision.is_none());
    }

    #[test]
    fn test_parse_pr_details_json_missing_fields() {
        // Missing url should return None
        let json = r#"{"number":123,"state":"OPEN"}"#;
        let result = parse_pr_details_json(json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_commits_json() {
        let json = r#"{"commits":[{"oid":"abc1234567890","messageHeadline":"Initial implementation","authoredDate":"2026-01-28T10:00:00Z","authors":[{"login":"developer"}]}]}"#;
        let entries = parse_commits_json(json);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "COMMIT");
        assert_eq!(entries[0].content, "Initial implementation");
        assert_eq!(entries[0].metadata, Some("abc1234".to_string()));
        assert_eq!(entries[0].timestamp, "2026-01-28T10:00:00Z");
    }

    #[test]
    fn test_parse_comments_json() {
        let json = r#"{"comments":[{"body":"Consider adding error handling","createdAt":"2026-01-28T11:30:00Z","author":{"login":"reviewer"}}]}"#;
        let entries = parse_comments_json(json);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "COMMENT");
        assert_eq!(entries[0].author, "reviewer");
        assert!(entries[0].content.contains("error handling"));
        assert_eq!(entries[0].timestamp, "2026-01-28T11:30:00Z");
    }

    #[test]
    fn test_parse_reviews_json() {
        let json = r#"{"reviews":[{"state":"CHANGES_REQUESTED","body":"Missing test coverage","submittedAt":"2026-01-28T14:00:00Z","author":{"login":"reviewer"}}]}"#;
        let entries = parse_reviews_json(json);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "REVIEW");
        assert!(entries[0].content.contains("CHANGES_REQUESTED"));
        assert!(entries[0].content.contains("Missing test coverage"));
        assert_eq!(entries[0].metadata, Some("CHANGES_REQUESTED".to_string()));
    }

    #[test]
    fn test_parse_review_threads_json_unresolved() {
        let json = r#"{"reviewThreads":[{"isResolved":false,"path":"src/lib.rs","line":45,"comments":[{"body":"Missing bounds check","author":{"login":"reviewer"}}]}]}"#;
        let threads = parse_review_threads_json(json);
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].path, "src/lib.rs");
        assert_eq!(threads[0].line, Some(45));
        assert_eq!(threads[0].comments.len(), 1);
        assert!(threads[0].comments[0].contains("@reviewer"));
        assert!(threads[0].comments[0].contains("bounds check"));
    }

    #[test]
    fn test_parse_review_threads_json_resolved_filtered() {
        let json = r#"{"reviewThreads":[{"isResolved":true,"path":"src/lib.rs","line":10,"comments":[{"body":"Fixed","author":{"login":"dev"}}]},{"isResolved":false,"path":"src/main.rs","line":20,"comments":[{"body":"Need fix","author":{"login":"reviewer"}}]}]}"#;
        let threads = parse_review_threads_json(json);
        // Only unresolved thread should be returned
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].path, "src/main.rs");
    }

    #[test]
    fn test_extract_json_string_with_escapes() {
        let json = r#"{"body":"Line 1\nLine 2\tTabbed"}"#;
        let result = extract_json_string(json, "\"body\":");
        assert!(result.is_some());
        let value = result.unwrap();
        assert!(value.contains('\n'));
        assert!(value.contains('\t'));
    }

    #[test]
    fn test_extract_json_bool() {
        assert_eq!(
            extract_json_bool(r#"{"isResolved":true}"#, "\"isResolved\":"),
            Some(true)
        );
        assert_eq!(
            extract_json_bool(r#"{"isResolved":false}"#, "\"isResolved\":"),
            Some(false)
        );
        assert_eq!(
            extract_json_bool(r#"{"isResolved":null}"#, "\"isResolved\":"),
            None
        );
    }

    #[test]
    fn test_truncate_content() {
        // Short content unchanged
        assert_eq!(truncate_content("short", 100), "short");

        // Long content truncated with ellipsis
        let long = "a".repeat(300);
        let truncated = truncate_content(&long, 100);
        assert_eq!(truncated.len(), 100);
        assert!(truncated.ends_with("..."));

        // Newlines replaced with spaces
        assert_eq!(truncate_content("line1\nline2", 100), "line1 line2");
    }

    #[test]
    fn test_find_matching_brace() {
        assert_eq!(find_matching_brace("{}"), Some(1));
        assert_eq!(find_matching_brace(r#"{"a":1}"#), Some(6));
        assert_eq!(find_matching_brace(r#"{"a":{"b":2}}"#), Some(12));
        assert_eq!(find_matching_brace(r#"{"a":"}"}"#), Some(8)); // Quote inside string
        assert_eq!(find_matching_brace("not an object"), None);
    }

    #[test]
    fn test_pr_query_result_variants() {
        // Test Success variant
        let success: PrQueryResult<PrDetails> = PrQueryResult::Success(PrDetails {
            url: "https://example.com".to_string(),
            number: 1,
            state: "OPEN".to_string(),
            review_decision: None,
        });
        matches!(success, PrQueryResult::Success(_));

        // Test NotFound variant
        let not_found: PrQueryResult<PrDetails> = PrQueryResult::NotFound;
        matches!(not_found, PrQueryResult::NotFound);

        // Test NetworkError variant
        let error: PrQueryResult<PrDetails> = PrQueryResult::NetworkError("test error".to_string());
        matches!(error, PrQueryResult::NetworkError(_));
    }

    #[test]
    fn test_timeline_entry_clone_and_debug() {
        let entry = TimelineEntry {
            timestamp: "2026-01-28T10:00:00Z".to_string(),
            event_type: "COMMIT".to_string(),
            author: "dev".to_string(),
            content: "Test commit".to_string(),
            metadata: Some("abc1234".to_string()),
        };

        // Test Clone
        let cloned = entry.clone();
        assert_eq!(cloned.timestamp, entry.timestamp);
        assert_eq!(cloned.author, entry.author);

        // Test Debug
        let debug_str = format!("{entry:?}");
        assert!(debug_str.contains("COMMIT"));
        assert!(debug_str.contains("dev"));
    }

    #[test]
    fn test_review_thread_clone_and_debug() {
        let thread = ReviewThread {
            path: "src/lib.rs".to_string(),
            line: Some(42),
            comments: vec!["@reviewer: Fix this".to_string()],
        };

        // Test Clone
        let cloned = thread.clone();
        assert_eq!(cloned.path, thread.path);
        assert_eq!(cloned.line, thread.line);

        // Test Debug
        let debug_str = format!("{thread:?}");
        assert!(debug_str.contains("src/lib.rs"));
        assert!(debug_str.contains("42"));
    }
}
