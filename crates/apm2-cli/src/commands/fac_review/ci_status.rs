//! CI gate status model projected into the PR body gate-status section.
//!
//! `CiStatus` preserves the gate-level RUNNING/PASS/FAIL semantics while the
//! projection transport is consolidated to a single PR body update path.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::projection::{self, GateResult};
use super::types::now_iso8601;

/// Per-gate status entry in the CI status projection.
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

/// Top-level CI status projected into the PR body gate-status section.
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
    #[cfg(test)]
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

    fn to_gate_results(&self) -> Vec<GateResult> {
        self.gates
            .iter()
            .map(|(name, gate)| GateResult {
                name: name.clone(),
                status: gate.status.clone(),
                duration_secs: gate.duration_secs,
                tokens_used: gate.tokens_used,
                model: gate.model.clone(),
            })
            .collect()
    }
}

/// PR-body updater wrapper around CI status projection.
pub struct PrBodyStatusUpdater {
    owner_repo: String,
    pr_number: u32,
    last_synced_snapshot: Mutex<Option<String>>,
}

impl PrBodyStatusUpdater {
    /// Create a new updater for the given repo and PR.
    pub fn new(owner_repo: &str, pr_number: u32) -> Self {
        Self {
            owner_repo: owner_repo.to_string(),
            pr_number,
            last_synced_snapshot: Mutex::new(None),
        }
    }

    fn sync_pr_body_status(&self, status: &CiStatus) -> Result<(), String> {
        projection::sync_gate_status_to_pr(
            &self.owner_repo,
            self.pr_number,
            status.to_gate_results(),
            &status.sha,
        )
        .map_err(|err| format!("pr-body status sync failed: {err}"))
    }

    /// Sync the current status projection to the PR body.
    pub fn update(&self, status: &CiStatus) -> bool {
        let snapshot = serde_json::to_string(status).ok();
        let mut guard = self
            .last_synced_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(snapshot) = snapshot.as_deref() {
            if guard.as_deref() == Some(snapshot) {
                return true;
            }
        }

        match self.sync_pr_body_status(status) {
            Ok(()) => {
                if let Some(snapshot) = snapshot {
                    *guard = Some(snapshot);
                }
                true
            },
            Err(err) => {
                eprintln!("WARNING: ci_status update failed: {err}");
                false
            },
        }
    }

    /// Force-sync the final status projection to the PR body.
    pub fn force_update(&self, status: &CiStatus) -> bool {
        let snapshot = serde_json::to_string(status).ok();
        let mut guard = self
            .last_synced_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match self.sync_pr_body_status(status) {
            Ok(()) => {
                if let Some(snapshot) = snapshot {
                    *guard = Some(snapshot);
                }
                true
            },
            Err(err) => {
                eprintln!("WARNING: ci_status force update failed: {err}");
                false
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let g = s.gates.get("fmt").expect("fmt gate");
        assert_eq!(g.status, "PASS");
        assert_eq!(g.duration_secs, Some(3));
    }

    #[test]
    fn test_set_result_fail() {
        let mut s = CiStatus::new("abc", 1);
        s.set_result("test", false, 120);
        let g = s.gates.get("test").expect("test gate");
        assert_eq!(g.status, "FAIL");
        assert_eq!(g.duration_secs, Some(120));
    }

    #[test]
    fn test_set_review_status_with_tokens_and_model() {
        let mut s = CiStatus::new("abc", 1);
        s.set_review_status("security", "PASS", Some(45), Some(8000), Some("opus-4"));
        let g = s.gates.get("security").expect("security gate");
        assert_eq!(g.status, "PASS");
        assert_eq!(g.tokens_used, Some(8000));
        assert_eq!(g.model.as_deref(), Some("opus-4"));
    }

    #[test]
    fn test_to_gate_results_includes_optional_fields() {
        let mut s = CiStatus::new("deadbeef", 7);
        s.set_review_status("security", "PASS", Some(12), Some(3456), Some("gpt-5"));

        let rendered = s.to_gate_results();
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].name, "security");
        assert_eq!(rendered[0].status, "PASS");
        assert_eq!(rendered[0].duration_secs, Some(12));
        assert_eq!(rendered[0].tokens_used, Some(3456));
        assert_eq!(rendered[0].model.as_deref(), Some("gpt-5"));
    }
}
