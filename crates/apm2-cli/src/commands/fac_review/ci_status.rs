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
use std::process::Command;

use serde::{Deserialize, Serialize};

use super::barrier::resolve_authenticated_gh_login;
use super::types::now_iso8601;

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
    expected_author_login: Option<&str>,
) -> Result<Option<(u64, CiStatus)>, String> {
    let endpoint = format!("/repos/{owner_repo}/issues/{pr_number}/comments?per_page=100");
    let output = Command::new("gh")
        .args(["api", &endpoint])
        .output()
        .map_err(|e| format!("failed to fetch PR comments: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gh api failed: {stderr}"));
    }

    let comments: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse comment response: {e}"))?;

    Ok(latest_status_comment_for_sha(
        &comments,
        sha,
        expected_author_login,
    ))
}

fn latest_status_comment_for_sha(
    comments: &[serde_json::Value],
    sha: &str,
    expected_author_login: Option<&str>,
) -> Option<(u64, CiStatus)> {
    let mut latest_match: Option<(u64, CiStatus)> = None;
    let expected_author_lower = expected_author_login.map(str::to_ascii_lowercase);

    for comment in comments {
        if let Some(expected_author) = expected_author_lower.as_deref() {
            let author = comment
                .get("user")
                .and_then(|value| value.get("login"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            if author != expected_author {
                continue;
            }
        }

        let body = comment
            .get("body")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !body.contains(&format!("<!-- {STATUS_MARKER} -->")) {
            continue;
        }

        let Some(yaml_str) = extract_yaml_block(body) else {
            continue;
        };
        let Ok(status) = serde_yaml::from_str::<CiStatus>(yaml_str) else {
            continue;
        };
        if status.sha != sha {
            continue;
        }

        let comment_id = comment
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        latest_match = Some((comment_id, status));
    }

    latest_match
}

/// Post a single CI status comment on a PR and return the created comment id.
pub fn create_status_comment(
    owner_repo: &str,
    pr_number: u32,
    status: &CiStatus,
) -> Result<u64, String> {
    let body = status.to_comment_body();
    let endpoint = format!("/repos/{owner_repo}/issues/{pr_number}/comments");

    let output = Command::new("gh")
        .args([
            "api",
            "-X",
            "POST",
            &endpoint,
            "-f",
            &format!("body={body}"),
        ])
        .output()
        .map_err(|e| format!("failed to POST status comment: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("status comment POST failed: {stderr}"));
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse status comment POST response: {e}"))?;
    let comment_id = value
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "status comment POST response missing id".to_string())?;
    Ok(comment_id)
}

/// Update an existing CI status comment in place.
pub fn update_status_comment(
    owner_repo: &str,
    comment_id: u64,
    status: &CiStatus,
) -> Result<(), String> {
    let body = status.to_comment_body();
    let endpoint = format!("/repos/{owner_repo}/issues/comments/{comment_id}");

    let output = Command::new("gh")
        .args([
            "api",
            "-X",
            "PATCH",
            &endpoint,
            "-f",
            &format!("body={body}"),
        ])
        .output()
        .map_err(|e| format!("failed to PATCH status comment: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("status comment PATCH failed: {stderr}"));
    }
    Ok(())
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

/// Synced update wrapper around CI status projection comments.
///
/// `update()` ensures a per-SHA status comment exists and then patches it with
/// the latest gate projection state. `force_update()` performs the same sync
/// operation and is kept for call-site readability at terminal boundaries.
pub struct ThrottledUpdater {
    owner_repo: String,
    pr_number: u32,
    comment_id: Cell<Option<u64>>,
    expected_author_login: Option<String>,
}

impl ThrottledUpdater {
    /// Create a new updater for the given repo and PR.
    pub fn new(owner_repo: &str, pr_number: u32) -> Self {
        Self {
            owner_repo: owner_repo.to_string(),
            pr_number,
            comment_id: Cell::new(None),
            expected_author_login: resolve_authenticated_gh_login(),
        }
    }

    fn sync_status_comment(&self, status: &CiStatus) -> Result<(), String> {
        let comment_id = if let Some(id) = self.comment_id.get() {
            id
        } else {
            let maybe_existing =
                if let Some(expected_author) = self.expected_author_login.as_deref() {
                    find_status_comment(
                        &self.owner_repo,
                        self.pr_number,
                        &status.sha,
                        Some(expected_author),
                    )?
                } else {
                    None
                };

            if let Some((existing_id, _existing_status)) = maybe_existing {
                self.comment_id.set(Some(existing_id));
                existing_id
            } else {
                let created_id = create_status_comment(&self.owner_repo, self.pr_number, status)?;
                self.comment_id.set(Some(created_id));
                return Ok(());
            }
        };

        if comment_id == 0 {
            let created_id = create_status_comment(&self.owner_repo, self.pr_number, status)?;
            self.comment_id.set(Some(created_id));
            return Ok(());
        }

        update_status_comment(&self.owner_repo, comment_id, status)
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

    #[test]
    fn test_latest_status_comment_for_sha_returns_latest_match() {
        let c1 = serde_json::json!({
            "id": 100_u64,
            "user": { "login": "fac-bot" },
            "body": "<!-- apm2-ci-status:v1 -->\n```yaml\n# apm2-ci-status:v1\nsha: deadbeef\npr: 7\nupdated_at: 2026-02-11T00:00:00Z\ngates:\n  rustfmt:\n    status: PASS\n    duration_secs: 1\n```\n"
        });
        let c2 = serde_json::json!({
            "id": 101_u64,
            "user": { "login": "fac-bot" },
            "body": "<!-- apm2-ci-status:v1 -->\n```yaml\n# apm2-ci-status:v1\nsha: other-sha\npr: 7\nupdated_at: 2026-02-11T00:00:01Z\ngates:\n  rustfmt:\n    status: FAIL\n    duration_secs: 1\n```\n"
        });
        let c3 = serde_json::json!({
            "id": 102_u64,
            "user": { "login": "fac-bot" },
            "body": "<!-- apm2-ci-status:v1 -->\n```yaml\n# apm2-ci-status:v1\nsha: deadbeef\npr: 7\nupdated_at: 2026-02-11T00:00:02Z\ngates:\n  rustfmt:\n    status: FAIL\n    duration_secs: 2\n```\n"
        });

        let comments = vec![c1, c2, c3];
        let (id, status) = latest_status_comment_for_sha(&comments, "deadbeef", None)
            .expect("should find latest status comment");
        assert_eq!(id, 102);
        assert_eq!(status.gates["rustfmt"].status, "FAIL");
        assert_eq!(status.gates["rustfmt"].duration_secs, Some(2));
    }

    #[test]
    fn test_latest_status_comment_for_sha_ignores_invalid_entries() {
        let missing_marker = serde_json::json!({
            "id": 10_u64,
            "user": { "login": "fac-bot" },
            "body": "```yaml\nsha: deadbeef\n```\n"
        });
        let invalid_yaml = serde_json::json!({
            "id": 11_u64,
            "user": { "login": "fac-bot" },
            "body": "<!-- apm2-ci-status:v1 -->\n```yaml\nthis: is: not: valid: yaml\n```\n"
        });

        let comments = vec![missing_marker, invalid_yaml];
        assert!(latest_status_comment_for_sha(&comments, "deadbeef", None).is_none());
    }

    #[test]
    fn test_latest_status_comment_for_sha_filters_untrusted_author() {
        let spoofed = serde_json::json!({
            "id": 103_u64,
            "user": { "login": "random-user" },
            "body": "<!-- apm2-ci-status:v1 -->\n```yaml\n# apm2-ci-status:v1\nsha: deadbeef\npr: 7\nupdated_at: 2026-02-11T00:00:03Z\ngates:\n  rustfmt:\n    status: PASS\n    duration_secs: 1\n```\n"
        });
        let trusted = serde_json::json!({
            "id": 104_u64,
            "user": { "login": "fac-bot" },
            "body": "<!-- apm2-ci-status:v1 -->\n```yaml\n# apm2-ci-status:v1\nsha: deadbeef\npr: 7\nupdated_at: 2026-02-11T00:00:04Z\ngates:\n  rustfmt:\n    status: FAIL\n    duration_secs: 2\n```\n"
        });

        let comments = vec![spoofed, trusted];
        let (id, status) = latest_status_comment_for_sha(&comments, "deadbeef", Some("fac-bot"))
            .expect("should find trusted status comment");
        assert_eq!(id, 104);
        assert_eq!(status.gates["rustfmt"].status, "FAIL");
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
