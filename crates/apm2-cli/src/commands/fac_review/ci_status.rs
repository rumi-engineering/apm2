//! CI status PR comment: synced projection updater.
//!
//! Projects all CI gate results to a single machine-readable YAML PR comment
//! with marker `apm2-ci-status:v1`. The comment is created on first update and
//! then patched in place so orchestrators can observe gate progress and
//! terminal failures from GitHub projections.
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

use std::cell::Cell;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::types::now_iso8601;
use super::{fenced_yaml, github_projection, projection_store};

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
        fenced_yaml::render_marked_yaml_comment(STATUS_MARKER, self).unwrap_or_else(|_| {
            format!(
                "<!-- {STATUS_MARKER} -->\n```yaml\n# {STATUS_MARKER}\nerror: serialization_failure\n```\n"
            )
        })
    }
}

// ── Comment CRUD ─────────────────────────────────────────────────────────────

/// Post a single CI status comment on a PR and return the created comment id.
pub fn create_status_comment(
    owner_repo: &str,
    pr_number: u32,
    status: &CiStatus,
) -> Result<(u64, String), String> {
    let body = status.to_comment_body();
    github_projection::create_issue_comment(owner_repo, pr_number, &body)
        .map(|response| (response.id, response.html_url))
        .map_err(|err| format!("status comment POST failed: {err}"))
}

/// Update an existing CI status comment in place.
pub fn update_status_comment(
    owner_repo: &str,
    comment_id: u64,
    status: &CiStatus,
) -> Result<(), String> {
    let body = status.to_comment_body();
    github_projection::update_issue_comment(owner_repo, comment_id, &body)
        .map_err(|err| format!("status comment PATCH failed: {err}"))
}

fn find_cached_status_comment_id(owner_repo: &str, pr_number: u32) -> Option<u64> {
    let comments =
        projection_store::load_issue_comments_cache::<serde_json::Value>(owner_repo, pr_number)
            .ok()
            .flatten()?;
    comments.iter().rev().find_map(|comment| {
        let body = comment.get("body").and_then(serde_json::Value::as_str)?;
        if !body.contains(STATUS_MARKER) {
            return None;
        }
        comment.get("id").and_then(serde_json::Value::as_u64)
    })
}

fn cache_status_comment(
    owner_repo: &str,
    pr_number: u32,
    comment_id: u64,
    status: &CiStatus,
    html_url: &str,
) {
    let body = status.to_comment_body();
    let _ = projection_store::upsert_issue_comment_cache_entry(
        owner_repo,
        pr_number,
        comment_id,
        html_url,
        &body,
        "apm2-fac-ci-status",
    );
}

// ── Deferred updater ─────────────────────────────────────────────────────────

/// Synced update wrapper around CI status projection comments.
///
/// `update()` ensures a per-SHA status comment exists and then patches it with
/// the latest gate projection state. `force_update()` performs the same sync
/// operation and is kept for call-site readability at terminal boundaries.
pub struct ThrottledUpdater {
    owner_repo: String,
    pr_number: u32,
    comment_id: Cell<Option<u64>>,
}

impl ThrottledUpdater {
    /// Create a new updater for the given repo and PR.
    pub fn new(owner_repo: &str, pr_number: u32) -> Self {
        Self {
            owner_repo: owner_repo.to_string(),
            pr_number,
            comment_id: Cell::new(None),
        }
    }

    fn sync_status_comment(&self, status: &CiStatus) -> Result<(), String> {
        let cached_id = self
            .comment_id
            .get()
            .or_else(|| find_cached_status_comment_id(&self.owner_repo, self.pr_number))
            .or_else(|| {
                match github_projection::find_latest_issue_comment_id_with_marker(
                    &self.owner_repo,
                    self.pr_number,
                    STATUS_MARKER,
                ) {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!(
                            "WARNING: ci_status remote status-comment discovery failed: {err}"
                        );
                        None
                    },
                }
            });

        if let Some(comment_id) = cached_id {
            match update_status_comment(&self.owner_repo, comment_id, status) {
                Ok(()) => {
                    self.comment_id.set(Some(comment_id));
                    let html_url = format!(
                        "https://github.com/{}/pull/{}#issuecomment-{}",
                        self.owner_repo, self.pr_number, comment_id
                    );
                    cache_status_comment(
                        &self.owner_repo,
                        self.pr_number,
                        comment_id,
                        status,
                        &html_url,
                    );
                    return Ok(());
                },
                Err(err) => {
                    eprintln!(
                        "WARNING: ci_status patch for comment {comment_id} failed; creating replacement status comment: {err}"
                    );
                },
            }
        }

        let (created_id, created_url) =
            create_status_comment(&self.owner_repo, self.pr_number, status)?;
        self.comment_id.set(Some(created_id));
        cache_status_comment(
            &self.owner_repo,
            self.pr_number,
            created_id,
            status,
            &created_url,
        );
        Ok(())
    }

    /// Sync the current status projection to GitHub.
    pub fn update(&self, status: &CiStatus) -> bool {
        match self.sync_status_comment(status) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("WARNING: ci_status update failed: {e}");
                false
            },
        }
    }

    /// Sync the final CI status projection to GitHub.
    pub fn force_update(&self, status: &CiStatus) -> bool {
        match self.sync_status_comment(status) {
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
    use super::{fenced_yaml, *};

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
    fn test_comment_body_roundtrip_yaml_payload() {
        let mut s = CiStatus::new("abc123full", 7);
        s.set_result("fmt", true, 2);
        s.set_result("clippy", false, 30);

        let body = s.to_comment_body();
        let yaml_payload =
            fenced_yaml::parse::extract_fenced_yaml(&body).expect("yaml block payload");
        let yaml_str = yaml_payload
            .strip_prefix("# apm2-ci-status:v1\n")
            .unwrap_or(yaml_payload);
        let restored: CiStatus = serde_yaml::from_str(yaml_str).expect("should parse YAML");

        assert_eq!(restored.sha, "abc123full");
        assert_eq!(restored.pr, 7);
        assert_eq!(restored.gates.len(), 2);
        assert_eq!(restored.gates["fmt"].status, "PASS");
        assert_eq!(restored.gates["clippy"].status, "FAIL");
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
