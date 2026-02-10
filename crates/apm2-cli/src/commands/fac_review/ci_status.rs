//! CI status PR comment: single-post updater.
//!
//! Projects all CI gate results to a single machine-readable YAML PR comment
//! with marker `apm2-ci-status:v1`. The comment is created **once** when the
//! pipeline completes — no intermediate edits — to minimise GitHub API calls
//! and avoid rate-limit exhaustion.
//!
//! # Security boundary
//!
//! PR comments are **publicly visible**. Only the following fields are
//! projected:
//!
//! - `sha`: commit hash (already public)
//! - `pr`: PR number (already public)
//! - `updated_at`: ISO-8601 timestamp
//! - `gates.<name>.status`: `RUNNING` / `PASS` / `FAIL`
//! - `gates.<name>.duration_secs`: wall time in seconds
//! - `gates.<name>.tokens_used`: LLM token count (optional)
//! - `gates.<name>.model`: model identifier (optional)
//!
//! **Never** include: local file paths, error output, environment variables,
//! compilation diagnostics, or any runner-local data. All such detail is
//! written to private logs under `~/.apm2/` and surfaced via
//! `apm2 fac logs --pr <N>`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::types::now_iso8601;
use crate::commands::fac_pr::GitHubPrClient;

// ── Marker ───────────────────────────────────────────────────────────────────

const STATUS_MARKER: &str = "apm2-ci-status:v1";

// ── Data types ───────────────────────────────────────────────────────────────

/// Per-gate status entry in the CI status comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Top-level CI status projected into a single PR comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiStatus {
    pub sha: String,
    pub pr: u32,
    pub updated_at: String,
    pub gates: BTreeMap<String, GateStatus>,
}

impl CiStatus {
    /// Create a new empty `CiStatus` for the given SHA and PR.
    pub fn new(sha: &str, pr: u32) -> Self {
        Self {
            sha: sha.to_string(),
            pr,
            updated_at: now_iso8601(),
            gates: BTreeMap::new(),
        }
    }

    /// Set a gate to RUNNING status.
    pub fn set_running(&mut self, gate: &str) {
        self.updated_at = now_iso8601();
        self.gates.insert(
            gate.to_string(),
            GateStatus {
                status: "RUNNING".to_string(),
                duration_secs: None,
                tokens_used: None,
                model: None,
            },
        );
    }

    /// Set a gate to PASS or FAIL with duration.
    pub fn set_result(&mut self, gate: &str, passed: bool, duration_secs: u64) {
        self.updated_at = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        self.gates.insert(
            gate.to_string(),
            GateStatus {
                status: status.to_string(),
                duration_secs: Some(duration_secs),
                tokens_used: None,
                model: None,
            },
        );
    }

    /// Set a review gate status with optional token count and model.
    #[allow(dead_code)]
    pub fn set_review_status(
        &mut self,
        gate: &str,
        status: &str,
        duration_secs: Option<u64>,
        tokens_used: Option<u64>,
        model: Option<&str>,
    ) {
        self.updated_at = now_iso8601();
        self.gates.insert(
            gate.to_string(),
            GateStatus {
                status: status.to_string(),
                duration_secs,
                tokens_used,
                model: model.map(String::from),
            },
        );
    }

    /// Serialize to the YAML block used in PR comments.
    fn to_comment_body(&self) -> String {
        let yaml = serde_yaml::to_string(self).unwrap_or_else(|_| "# serialization error\n".into());
        format!("<!-- {STATUS_MARKER} -->\n```yaml\n# {STATUS_MARKER}\n{yaml}```\n")
    }
}

// ── Comment CRUD ─────────────────────────────────────────────────────────────

/// Find an existing CI status comment for the given SHA, returning
/// (`comment_id`, parsed [`CiStatus`]).
pub fn find_status_comment(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
) -> Result<Option<(u64, CiStatus)>, String> {
    let client = GitHubPrClient::new(owner_repo)?;
    let comments = client.read_comments(pr_number, 1)?;

    let marker_tag = format!("<!-- {STATUS_MARKER} -->");
    for comment in comments {
        if !comment.body.contains(&marker_tag) {
            continue;
        }
        // Extract YAML block between ```yaml and ```.
        if let Some(yaml_str) = extract_yaml_block(&comment.body) {
            if let Ok(status) = serde_yaml::from_str::<CiStatus>(yaml_str) {
                if status.sha == sha {
                    return Ok(Some((comment.id, status)));
                }
            }
        }
    }

    Ok(None)
}

/// Post a single CI status comment on a PR (no find+edit, just POST).
pub fn create_status_comment(
    owner_repo: &str,
    pr_number: u32,
    status: &CiStatus,
) -> Result<(), String> {
    let body = status.to_comment_body();
    let client = GitHubPrClient::new(owner_repo)?;
    client.comment(pr_number, &body).map(|_| ())
}

/// Extract the YAML content from a fenced code block in a comment body.
fn extract_yaml_block(body: &str) -> Option<&str> {
    let start_marker = "```yaml\n";
    let end_marker = "\n```";

    let start = body.find(start_marker)?;
    let yaml_start = start + start_marker.len();

    // Skip the `# apm2-ci-status:v1` comment line if present.
    let remaining = &body[yaml_start..];
    let yaml_content_start = if remaining.starts_with("# ") {
        remaining.find('\n').map(|i| yaml_start + i + 1)?
    } else {
        yaml_start
    };

    let end = body[yaml_content_start..].find(end_marker)?;
    Some(&body[yaml_content_start..yaml_content_start + end])
}

// ── Deferred updater ─────────────────────────────────────────────────────────

/// Deferred single-post wrapper around `create_status_comment`.
///
/// `update()` is a no-op that only records the latest status in memory.
/// `force_update()` posts one comment with the final state — this is the
/// only call that touches the GitHub API, avoiding rate-limit exhaustion
/// from repeated find+edit cycles.
pub struct ThrottledUpdater {
    owner_repo: String,
    pr_number: u32,
}

impl ThrottledUpdater {
    /// Create a new updater for the given repo and PR.
    pub fn new(owner_repo: &str, pr_number: u32) -> Self {
        Self {
            owner_repo: owner_repo.to_string(),
            pr_number,
        }
    }

    /// Record latest status locally (no API call).
    ///
    /// Callers still pass their `CiStatus` here so the call-sites don't
    /// need to change — the status struct itself is the in-memory
    /// accumulator.
    #[allow(clippy::unused_self, clippy::missing_const_for_fn)]
    pub fn update(&self, _status: &CiStatus) -> bool {
        // No-op: we post once at the end via force_update().
        false
    }

    /// Post the final CI status comment (single POST, no find+edit).
    pub fn force_update(&self, status: &CiStatus) -> bool {
        match create_status_comment(&self.owner_repo, self.pr_number, status) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("WARNING: ci_status final post failed: {e}");
                false
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CiStatus data model ─────────────────────────────────────────────

    #[test]
    fn test_ci_status_new_is_empty() {
        let s = CiStatus::new("abc123", 42);
        assert_eq!(s.sha, "abc123");
        assert_eq!(s.pr, 42);
        assert!(s.gates.is_empty());
    }

    #[test]
    fn test_set_running() {
        let mut s = CiStatus::new("abc", 1);
        s.set_running("clippy");
        let g = s.gates.get("clippy").expect("gate should exist");
        assert_eq!(g.status, "RUNNING");
        assert!(g.duration_secs.is_none());
    }

    #[test]
    fn test_set_result_pass() {
        let mut s = CiStatus::new("abc", 1);
        s.set_result("fmt", true, 3);
        let g = s.gates.get("fmt").unwrap();
        assert_eq!(g.status, "PASS");
        assert_eq!(g.duration_secs, Some(3));
    }

    #[test]
    fn test_set_result_fail() {
        let mut s = CiStatus::new("abc", 1);
        s.set_result("test", false, 120);
        let g = s.gates.get("test").unwrap();
        assert_eq!(g.status, "FAIL");
        assert_eq!(g.duration_secs, Some(120));
    }

    #[test]
    fn test_set_review_status_with_tokens_and_model() {
        let mut s = CiStatus::new("abc", 1);
        s.set_review_status("security", "PASS", Some(45), Some(8000), Some("opus-4"));
        let g = s.gates.get("security").unwrap();
        assert_eq!(g.status, "PASS");
        assert_eq!(g.tokens_used, Some(8000));
        assert_eq!(g.model.as_deref(), Some("opus-4"));
    }

    // ── Comment body format ─────────────────────────────────────────────

    #[test]
    fn test_comment_body_contains_marker() {
        let s = CiStatus::new("deadbeef", 99);
        let body = s.to_comment_body();
        assert!(
            body.contains("<!-- apm2-ci-status:v1 -->"),
            "must contain HTML marker"
        );
        assert!(
            body.contains("# apm2-ci-status:v1"),
            "must contain YAML comment marker"
        );
    }

    #[test]
    fn test_comment_body_roundtrip_via_extract_yaml() {
        let mut s = CiStatus::new("abc123full", 7);
        s.set_result("fmt", true, 2);
        s.set_result("clippy", false, 30);

        let body = s.to_comment_body();
        let yaml_str = extract_yaml_block(&body).expect("should find YAML block");
        let restored: CiStatus = serde_yaml::from_str(yaml_str).expect("should parse YAML");

        assert_eq!(restored.sha, "abc123full");
        assert_eq!(restored.pr, 7);
        assert_eq!(restored.gates.len(), 2);
        assert_eq!(restored.gates["fmt"].status, "PASS");
        assert_eq!(restored.gates["clippy"].status, "FAIL");
    }

    // ── extract_yaml_block ──────────────────────────────────────────────

    #[test]
    fn test_extract_yaml_block_returns_none_for_empty() {
        assert!(extract_yaml_block("").is_none());
        assert!(extract_yaml_block("no yaml here").is_none());
    }

    #[test]
    fn test_extract_yaml_block_skips_comment_line() {
        let body = "<!-- m -->\n```yaml\n# apm2-ci-status:v1\nsha: abc\npr: 1\n```\n";
        let yaml = extract_yaml_block(body).unwrap();
        assert!(yaml.starts_with("sha:"), "should skip # comment line");
    }

    // ── ThrottledUpdater contract ───────────────────────────────────────

    #[test]
    fn test_update_never_makes_api_call() {
        // update() must always return false (no-op).
        let updater = ThrottledUpdater::new("owner/repo", 1);
        let s = CiStatus::new("abc", 1);
        assert!(!updater.update(&s), "update() must be a no-op");
        assert!(
            !updater.update(&s),
            "update() must remain a no-op on repeat"
        );
    }

    #[test]
    fn test_update_is_idempotent_no_side_effects() {
        // Call update() many times — must never panic or change behavior.
        let updater = ThrottledUpdater::new("owner/repo", 42);
        let mut s = CiStatus::new("sha123", 42);
        for i in 0..100 {
            s.set_result(&format!("gate_{i}"), true, i);
            assert!(!updater.update(&s));
        }
    }

    // ── Security boundary: no sensitive data in comment body ────────────

    #[test]
    fn test_comment_body_contains_no_paths() {
        let mut s = CiStatus::new("abc", 1);
        s.set_result("test", true, 5);
        let body = s.to_comment_body();
        assert!(
            !body.contains("/home"),
            "comment must not contain local paths"
        );
        assert!(
            !body.contains(".apm2"),
            "comment must not contain private dir references"
        );
    }
}
