//! CI status PR comment: CRUD operations and throttled updater.
//!
//! Projects all CI gate results to a single machine-readable YAML PR comment
//! with marker `apm2-ci-status:v1`. The comment is created once per SHA and
//! updated in-place as gates complete.
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
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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

    for comment in comments {
        let body = comment
            .get("body")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !body.contains(&format!("<!-- {STATUS_MARKER} -->")) {
            continue;
        }
        // Extract YAML block between ```yaml and ```.
        if let Some(yaml_str) = extract_yaml_block(body) {
            if let Ok(status) = serde_yaml::from_str::<CiStatus>(yaml_str) {
                if status.sha == sha {
                    let comment_id = comment
                        .get("id")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    return Ok(Some((comment_id, status)));
                }
            }
        }
    }

    Ok(None)
}

/// Create or update the CI status comment on a PR.
pub fn upsert_status_comment(
    owner_repo: &str,
    pr_number: u32,
    status: &CiStatus,
) -> Result<(), String> {
    let body = status.to_comment_body();

    let (method, endpoint) =
        if let Some((comment_id, _)) = find_status_comment(owner_repo, pr_number, &status.sha)? {
            (
                "PATCH",
                format!("/repos/{owner_repo}/issues/comments/{comment_id}"),
            )
        } else {
            (
                "POST",
                format!("/repos/{owner_repo}/issues/{pr_number}/comments"),
            )
        };

    let output = Command::new("gh")
        .args([
            "api",
            "-X",
            method,
            &endpoint,
            "-f",
            &format!("body={body}"),
        ])
        .output()
        .map_err(|e| format!("failed to {method} status comment: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("status comment {method} failed: {stderr}"));
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

// ── Throttled updater ────────────────────────────────────────────────────────

/// Rate-limited wrapper around `upsert_status_comment` with debounce and
/// exponential backoff.
pub struct ThrottledUpdater {
    owner_repo: String,
    pr_number: u32,
    last_update: Option<Instant>,
    retry_count: u32,
    debounce: Duration,
}

impl ThrottledUpdater {
    /// Create a new throttled updater for the given repo and PR.
    pub fn new(owner_repo: &str, pr_number: u32) -> Self {
        Self {
            owner_repo: owner_repo.to_string(),
            pr_number,
            last_update: None,
            retry_count: 0,
            debounce: Duration::from_secs(5),
        }
    }

    /// Attempt to update the CI status comment, respecting debounce and
    /// backoff.
    ///
    /// Returns `true` if the update was sent, `false` if debounced/skipped.
    pub fn update(&mut self, status: &CiStatus) -> bool {
        // Debounce: skip if last update was too recent.
        if let Some(last) = self.last_update {
            let min_interval = if self.retry_count == 0 {
                self.debounce
            } else {
                // Exponential backoff: 2^retry * base(2s), max 60s, +jitter.
                let base_secs = 2u64.saturating_pow(self.retry_count).min(30);
                // Integer-only 30% jitter: base_secs * 3 / 10.
                let jitter_range = base_secs * 3 / 10;
                let jitter = if jitter_range > 0 {
                    // Simple deterministic jitter from retry count.
                    (u64::from(self.retry_count) * 7) % (jitter_range * 2)
                } else {
                    0
                };
                let secs = base_secs.saturating_add(jitter).min(60);
                Duration::from_secs(secs)
            };

            if last.elapsed() < min_interval {
                return false;
            }
        }

        match upsert_status_comment(&self.owner_repo, self.pr_number, status) {
            Ok(()) => {
                self.last_update = Some(Instant::now());
                self.retry_count = 0;
                true
            },
            Err(e) => {
                eprintln!(
                    "WARNING: ci_status update failed (retry={}): {e}",
                    self.retry_count
                );
                self.retry_count = self.retry_count.saturating_add(1);
                self.last_update = Some(Instant::now());
                false
            },
        }
    }

    /// Force an update, bypassing debounce (still respects backoff on errors).
    pub fn force_update(&mut self, status: &CiStatus) -> bool {
        self.last_update = None;
        self.update(status)
    }
}
