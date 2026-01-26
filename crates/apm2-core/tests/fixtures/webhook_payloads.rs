//! Test fixtures for GitHub webhook payloads.
//!
//! This module provides helpers for generating valid GitHub `workflow_run`
//! webhook payloads with proper HMAC-SHA256 signatures for integration testing.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Computes the HMAC-SHA256 signature for a webhook payload.
///
/// # Arguments
///
/// * `payload` - The raw JSON payload bytes
/// * `secret` - The webhook secret
///
/// # Returns
///
/// The signature in GitHub format: `sha256=<hex-encoded-signature>`
pub fn compute_signature(payload: &[u8], secret: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload);
    let result = mac.finalize();
    let bytes = result.into_bytes();

    format!(
        "sha256={}",
        bytes.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    )
}

/// Builder for creating GitHub `workflow_run.completed` webhook payloads.
#[derive(Debug, Clone)]
pub struct WorkflowRunPayloadBuilder {
    action: String,
    workflow_run_id: u64,
    head_sha: String,
    head_branch: String,
    conclusion: String,
    workflow_name: String,
    pr_numbers: Vec<u64>,
}

impl Default for WorkflowRunPayloadBuilder {
    fn default() -> Self {
        Self {
            action: "completed".to_string(),
            workflow_run_id: 12345,
            head_sha: "abc123def456".to_string(),
            head_branch: "feature/test".to_string(),
            conclusion: "success".to_string(),
            workflow_name: "CI".to_string(),
            pr_numbers: vec![42],
        }
    }
}

impl WorkflowRunPayloadBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the action type.
    #[must_use]
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }

    /// Sets the workflow run ID.
    #[must_use]
    pub const fn workflow_run_id(mut self, id: u64) -> Self {
        self.workflow_run_id = id;
        self
    }

    /// Sets the commit SHA.
    #[must_use]
    pub fn head_sha(mut self, sha: impl Into<String>) -> Self {
        self.head_sha = sha.into();
        self
    }

    /// Sets the head branch.
    #[must_use]
    pub fn head_branch(mut self, branch: impl Into<String>) -> Self {
        self.head_branch = branch.into();
        self
    }

    /// Sets the workflow conclusion.
    #[must_use]
    pub fn conclusion(mut self, conclusion: impl Into<String>) -> Self {
        self.conclusion = conclusion.into();
        self
    }

    /// Sets the workflow name.
    #[must_use]
    pub fn workflow_name(mut self, name: impl Into<String>) -> Self {
        self.workflow_name = name.into();
        self
    }

    /// Sets the PR numbers.
    #[must_use]
    pub fn pr_numbers(mut self, numbers: Vec<u64>) -> Self {
        self.pr_numbers = numbers;
        self
    }

    /// Adds a single PR number.
    #[must_use]
    pub fn add_pr_number(mut self, number: u64) -> Self {
        self.pr_numbers.push(number);
        self
    }

    /// Builds the JSON payload as bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let pr_json: String = self
            .pr_numbers
            .iter()
            .map(|n| format!(r#"{{"number": {n}}}"#))
            .collect::<Vec<_>>()
            .join(",");

        let json = format!(
            r#"{{
                "action": "{}",
                "workflow_run": {{
                    "id": {},
                    "name": "{}",
                    "head_sha": "{}",
                    "head_branch": "{}",
                    "conclusion": "{}",
                    "pull_requests": [{}]
                }}
            }}"#,
            self.action,
            self.workflow_run_id,
            self.workflow_name,
            self.head_sha,
            self.head_branch,
            self.conclusion,
            pr_json
        );

        json.into_bytes()
    }

    /// Builds the JSON payload and computes its signature.
    #[must_use]
    pub fn build_with_signature(&self, secret: &str) -> (Vec<u8>, String) {
        let payload = self.build();
        let signature = compute_signature(&payload, secret);
        (payload, signature)
    }
}

/// Creates a sample valid webhook payload with success conclusion.
pub fn sample_success_payload() -> WorkflowRunPayloadBuilder {
    WorkflowRunPayloadBuilder::new()
        .conclusion("success")
        .pr_numbers(vec![42])
}

/// Creates a sample webhook payload with failure conclusion.
pub fn sample_failure_payload() -> WorkflowRunPayloadBuilder {
    WorkflowRunPayloadBuilder::new()
        .conclusion("failure")
        .pr_numbers(vec![42])
}

/// Creates a sample webhook payload with cancelled conclusion.
pub fn sample_cancelled_payload() -> WorkflowRunPayloadBuilder {
    WorkflowRunPayloadBuilder::new()
        .conclusion("cancelled")
        .pr_numbers(vec![42])
}

/// Creates a sample webhook payload with no pull requests.
pub fn sample_no_pr_payload() -> WorkflowRunPayloadBuilder {
    WorkflowRunPayloadBuilder::new()
        .conclusion("success")
        .pr_numbers(vec![])
}

/// Creates a sample webhook payload for a non-completed action.
pub fn sample_requested_payload() -> WorkflowRunPayloadBuilder {
    WorkflowRunPayloadBuilder::new().action("requested")
}

/// Agent exit signal payload builder.
#[derive(Debug, Clone)]
pub struct ExitSignalPayloadBuilder {
    protocol: String,
    version: String,
    phase_completed: String,
    exit_reason: String,
    pr_url: Option<String>,
    evidence_bundle_ref: Option<String>,
    notes: Option<String>,
}

impl Default for ExitSignalPayloadBuilder {
    fn default() -> Self {
        Self {
            protocol: "apm2_agent_exit".to_string(),
            version: "1.0.0".to_string(),
            phase_completed: "IMPLEMENTATION".to_string(),
            exit_reason: "completed".to_string(),
            pr_url: None,
            evidence_bundle_ref: None,
            notes: None,
        }
    }
}

impl ExitSignalPayloadBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the protocol field.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }

    /// Sets the version field.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Sets the phase completed field.
    #[must_use]
    pub fn phase_completed(mut self, phase: impl Into<String>) -> Self {
        self.phase_completed = phase.into();
        self
    }

    /// Sets the exit reason field.
    #[must_use]
    pub fn exit_reason(mut self, reason: impl Into<String>) -> Self {
        self.exit_reason = reason.into();
        self
    }

    /// Sets the PR URL field.
    #[must_use]
    pub fn pr_url(mut self, url: impl Into<String>) -> Self {
        self.pr_url = Some(url.into());
        self
    }

    /// Sets the evidence bundle ref field.
    #[must_use]
    pub fn evidence_bundle_ref(mut self, ref_path: impl Into<String>) -> Self {
        self.evidence_bundle_ref = Some(ref_path.into());
        self
    }

    /// Sets the notes field.
    #[must_use]
    pub fn notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Builds the JSON string.
    #[must_use]
    pub fn build(&self) -> String {
        use std::fmt::Write;

        let mut json = format!(
            r#"{{
                "protocol": "{}",
                "version": "{}",
                "phase_completed": "{}",
                "exit_reason": "{}""#,
            self.protocol, self.version, self.phase_completed, self.exit_reason
        );

        if let Some(ref pr_url) = self.pr_url {
            let _ = write!(
                json,
                r#",
                "pr_url": "{pr_url}""#
            );
        }

        if let Some(ref evidence_ref) = self.evidence_bundle_ref {
            let _ = write!(
                json,
                r#",
                "evidence_bundle_ref": "{evidence_ref}""#
            );
        }

        if let Some(ref notes) = self.notes {
            let _ = write!(
                json,
                r#",
                "notes": "{notes}""#
            );
        }

        json.push_str("\n            }");
        json
    }
}

/// Creates a sample valid exit signal for implementation phase completion.
pub fn sample_implementation_exit() -> ExitSignalPayloadBuilder {
    ExitSignalPayloadBuilder::new()
        .phase_completed("IMPLEMENTATION")
        .exit_reason("completed")
        .pr_url("https://github.com/org/repo/pull/123")
        .notes("Implementation complete, all tests passing")
}

/// Creates a sample exit signal indicating blocked status.
pub fn sample_blocked_exit() -> ExitSignalPayloadBuilder {
    ExitSignalPayloadBuilder::new()
        .phase_completed("IMPLEMENTATION")
        .exit_reason("blocked")
        .notes("Waiting for API credentials")
}

/// Creates a sample exit signal with wrong protocol.
pub fn sample_wrong_protocol_exit() -> ExitSignalPayloadBuilder {
    ExitSignalPayloadBuilder::new().protocol("wrong_protocol")
}

/// Creates a sample exit signal with unsupported version.
pub fn sample_wrong_version_exit() -> ExitSignalPayloadBuilder {
    ExitSignalPayloadBuilder::new().version("2.0.0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_signature() {
        let payload = b"test payload";
        let secret = "test-secret";
        let signature = compute_signature(payload, secret);

        // Signature should start with sha256=
        assert!(signature.starts_with("sha256="));
        // Should be 64 hex characters after prefix
        assert_eq!(signature.len(), 7 + 64);
    }

    #[test]
    fn test_workflow_payload_builder() {
        let builder = WorkflowRunPayloadBuilder::new()
            .action("completed")
            .conclusion("success")
            .pr_numbers(vec![42, 43]);

        let payload = builder.build();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        assert_eq!(json["action"], "completed");
        assert_eq!(json["workflow_run"]["conclusion"], "success");
        assert_eq!(json["workflow_run"]["pull_requests"][0]["number"], 42);
        assert_eq!(json["workflow_run"]["pull_requests"][1]["number"], 43);
    }

    #[test]
    fn test_workflow_payload_with_signature() {
        let builder = WorkflowRunPayloadBuilder::new();
        let (payload, signature) = builder.build_with_signature("test-secret");

        // Verify signature format
        assert!(signature.starts_with("sha256="));

        // Verify signature is valid
        let expected_signature = compute_signature(&payload, "test-secret");
        assert_eq!(signature, expected_signature);
    }

    #[test]
    fn test_exit_signal_builder() {
        let builder = ExitSignalPayloadBuilder::new()
            .phase_completed("IMPLEMENTATION")
            .exit_reason("completed")
            .pr_url("https://github.com/org/repo/pull/123");

        let json_str = builder.build();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(json["protocol"], "apm2_agent_exit");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["phase_completed"], "IMPLEMENTATION");
        assert_eq!(json["exit_reason"], "completed");
        assert_eq!(json["pr_url"], "https://github.com/org/repo/pull/123");
    }

    #[test]
    fn test_exit_signal_builder_minimal() {
        let builder = ExitSignalPayloadBuilder::new();
        let json_str = builder.build();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Optional fields should not be present
        assert!(json.get("pr_url").is_none());
        assert!(json.get("evidence_bundle_ref").is_none());
        assert!(json.get("notes").is_none());
    }
}
