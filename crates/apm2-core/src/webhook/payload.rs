//! GitHub webhook payload types for `workflow_run.completed` events.
//!
//! This module defines the payload structure for GitHub `workflow_run`
//! webhooks. Only the `completed` action is processed; other actions are
//! rejected.
//!
//! # Payload Structure
//!
//! GitHub sends a JSON payload with the following relevant fields:
//!
//! ```json
//! {
//!   "action": "completed",
//!   "workflow_run": {
//!     "id": 12345,
//!     "head_sha": "abc123...",
//!     "head_branch": "feature/foo",
//!     "conclusion": "success",
//!     "pull_requests": [{"number": 42}]
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};

use super::error::WebhookError;

/// The expected payload for a GitHub `workflow_run` webhook.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkflowRunPayload {
    /// The action that triggered the webhook.
    pub action: String,

    /// The workflow run details.
    pub workflow_run: WorkflowRun,
}

/// Details about a GitHub workflow run.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkflowRun {
    /// Unique identifier for the workflow run.
    pub id: u64,

    /// The name of the workflow (e.g., "CI", "Build and Test").
    #[serde(default)]
    pub name: Option<String>,

    /// The commit SHA that triggered the workflow.
    pub head_sha: String,

    /// The branch that triggered the workflow.
    pub head_branch: String,

    /// The conclusion of the workflow run (success, failure, cancelled, etc.).
    pub conclusion: Option<String>,

    /// Pull requests associated with the workflow run.
    #[serde(default)]
    pub pull_requests: Vec<PullRequest>,
}

/// A pull request associated with a workflow run.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PullRequest {
    /// The pull request number.
    pub number: u64,
}

/// The conclusion of a completed workflow run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowConclusion {
    /// The workflow completed successfully.
    Success,
    /// The workflow failed.
    Failure,
    /// The workflow was cancelled.
    Cancelled,
    /// The workflow was skipped.
    Skipped,
    /// The workflow timed out.
    TimedOut,
    /// Action required (e.g., manual approval needed).
    ActionRequired,
    /// The workflow is stale (superseded by a newer run).
    Stale,
    /// A neutral conclusion (neither success nor failure).
    Neutral,
}

impl std::fmt::Display for WorkflowConclusion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Skipped => write!(f, "skipped"),
            Self::TimedOut => write!(f, "timed_out"),
            Self::ActionRequired => write!(f, "action_required"),
            Self::Stale => write!(f, "stale"),
            Self::Neutral => write!(f, "neutral"),
        }
    }
}

/// A processed `workflow_run.completed` event.
///
/// This struct contains the normalized, validated data from a GitHub
/// `workflow_run.completed` webhook payload.
#[derive(Debug, Clone, Serialize)]
pub struct WorkflowRunCompleted {
    /// Unique identifier for the workflow run.
    pub workflow_run_id: u64,

    /// The name of the workflow (e.g., "CI", "Build and Test").
    /// Falls back to "workflow" if not provided by GitHub.
    pub workflow_name: String,

    /// The commit SHA that triggered the workflow.
    pub commit_sha: String,

    /// The branch that triggered the workflow.
    pub branch: String,

    /// The conclusion of the workflow run.
    pub conclusion: WorkflowConclusion,

    /// Pull request numbers associated with this workflow run.
    pub pull_request_numbers: Vec<u64>,
}

impl WorkflowRunPayload {
    /// Parses a `workflow_run.completed` payload from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The JSON is malformed
    /// - The action is not "completed"
    /// - Required fields are missing
    /// - The conclusion is not a recognized value
    pub fn parse(body: &[u8]) -> Result<Self, WebhookError> {
        serde_json::from_slice(body)
            .map_err(|e| WebhookError::InvalidPayload(format!("JSON parse error: {e}")))
    }

    /// Validates that this is a `workflow_run.completed` event and extracts
    /// the relevant data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The action is not "completed"
    /// - The conclusion is missing or not recognized
    pub fn into_completed(self) -> Result<WorkflowRunCompleted, WebhookError> {
        if self.action != "completed" {
            return Err(WebhookError::UnsupportedEventType(format!(
                "workflow_run.{} (expected workflow_run.completed)",
                self.action
            )));
        }

        let conclusion_str = self.workflow_run.conclusion.ok_or_else(|| {
            WebhookError::InvalidPayload("missing conclusion for completed workflow".into())
        })?;

        let conclusion = parse_conclusion(&conclusion_str)?;

        Ok(WorkflowRunCompleted {
            workflow_run_id: self.workflow_run.id,
            workflow_name: self
                .workflow_run
                .name
                .unwrap_or_else(|| "workflow".to_string()),
            commit_sha: self.workflow_run.head_sha,
            branch: self.workflow_run.head_branch,
            conclusion,
            pull_request_numbers: self
                .workflow_run
                .pull_requests
                .into_iter()
                .map(|pr| pr.number)
                .collect(),
        })
    }
}

/// Parses a conclusion string into a `WorkflowConclusion`.
fn parse_conclusion(s: &str) -> Result<WorkflowConclusion, WebhookError> {
    match s {
        "success" => Ok(WorkflowConclusion::Success),
        "failure" => Ok(WorkflowConclusion::Failure),
        "cancelled" => Ok(WorkflowConclusion::Cancelled),
        "skipped" => Ok(WorkflowConclusion::Skipped),
        "timed_out" => Ok(WorkflowConclusion::TimedOut),
        "action_required" => Ok(WorkflowConclusion::ActionRequired),
        "stale" => Ok(WorkflowConclusion::Stale),
        "neutral" => Ok(WorkflowConclusion::Neutral),
        other => Err(WebhookError::InvalidPayload(format!(
            "unknown conclusion: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_payload(action: &str, conclusion: Option<&str>) -> Vec<u8> {
        let conclusion_json = conclusion
            .map(|c| format!(r#""conclusion": "{c}","#))
            .unwrap_or_default();

        format!(
            r#"{{
                "action": "{action}",
                "workflow_run": {{
                    "id": 12345,
                    "head_sha": "abc123def456",
                    "head_branch": "feature/test",
                    {conclusion_json}
                    "pull_requests": [
                        {{"number": 42}},
                        {{"number": 43}}
                    ]
                }}
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn test_parse_valid_completed_payload() {
        let body = make_payload("completed", Some("success"));
        let payload = WorkflowRunPayload::parse(&body).unwrap();

        assert_eq!(payload.action, "completed");
        assert_eq!(payload.workflow_run.id, 12345);
        assert_eq!(payload.workflow_run.head_sha, "abc123def456");
        assert_eq!(payload.workflow_run.head_branch, "feature/test");
        assert_eq!(payload.workflow_run.conclusion, Some("success".to_string()));
        assert_eq!(payload.workflow_run.pull_requests.len(), 2);
        assert_eq!(payload.workflow_run.pull_requests[0].number, 42);
        assert_eq!(payload.workflow_run.pull_requests[1].number, 43);
    }

    #[test]
    fn test_into_completed_success() {
        let body = make_payload("completed", Some("success"));
        let payload = WorkflowRunPayload::parse(&body).unwrap();
        let completed = payload.into_completed().unwrap();

        assert_eq!(completed.workflow_run_id, 12345);
        // Defaults to "workflow" when name not provided
        assert_eq!(completed.workflow_name, "workflow");
        assert_eq!(completed.commit_sha, "abc123def456");
        assert_eq!(completed.branch, "feature/test");
        assert_eq!(completed.conclusion, WorkflowConclusion::Success);
        assert_eq!(completed.pull_request_numbers, vec![42, 43]);
    }

    #[test]
    fn test_into_completed_with_workflow_name() {
        let body = r#"{
            "action": "completed",
            "workflow_run": {
                "id": 12345,
                "name": "Build and Test",
                "head_sha": "abc123def456",
                "head_branch": "feature/test",
                "conclusion": "success",
                "pull_requests": [{"number": 42}]
            }
        }"#
        .as_bytes();

        let payload = WorkflowRunPayload::parse(body).unwrap();
        let completed = payload.into_completed().unwrap();

        assert_eq!(completed.workflow_name, "Build and Test");
    }

    #[test]
    fn test_into_completed_failure() {
        let body = make_payload("completed", Some("failure"));
        let payload = WorkflowRunPayload::parse(&body).unwrap();
        let completed = payload.into_completed().unwrap();

        assert_eq!(completed.conclusion, WorkflowConclusion::Failure);
    }

    #[test]
    fn test_into_completed_cancelled() {
        let body = make_payload("completed", Some("cancelled"));
        let payload = WorkflowRunPayload::parse(&body).unwrap();
        let completed = payload.into_completed().unwrap();

        assert_eq!(completed.conclusion, WorkflowConclusion::Cancelled);
    }

    #[test]
    fn test_reject_non_completed_action() {
        let body = make_payload("requested", None);
        let payload = WorkflowRunPayload::parse(&body).unwrap();
        let result = payload.into_completed();

        assert!(matches!(result, Err(WebhookError::UnsupportedEventType(_))));
    }

    #[test]
    fn test_reject_missing_conclusion() {
        let body = make_payload("completed", None);
        let payload = WorkflowRunPayload::parse(&body).unwrap();
        let result = payload.into_completed();

        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_reject_unknown_conclusion() {
        let body = make_payload("completed", Some("unknown_status"));
        let payload = WorkflowRunPayload::parse(&body).unwrap();
        let result = payload.into_completed();

        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_reject_malformed_json() {
        let body = b"not valid json";
        let result = WorkflowRunPayload::parse(body);

        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[test]
    fn test_empty_pull_requests() {
        let body = r#"{
            "action": "completed",
            "workflow_run": {
                "id": 12345,
                "head_sha": "abc123",
                "head_branch": "main",
                "conclusion": "success",
                "pull_requests": []
            }
        }"#
        .as_bytes();

        let payload = WorkflowRunPayload::parse(body).unwrap();
        let completed = payload.into_completed().unwrap();

        assert!(completed.pull_request_numbers.is_empty());
    }

    #[test]
    fn test_missing_pull_requests_field() {
        let body = r#"{
            "action": "completed",
            "workflow_run": {
                "id": 12345,
                "head_sha": "abc123",
                "head_branch": "main",
                "conclusion": "success"
            }
        }"#
        .as_bytes();

        let payload = WorkflowRunPayload::parse(body).unwrap();
        let completed = payload.into_completed().unwrap();

        assert!(completed.pull_request_numbers.is_empty());
    }

    #[test]
    fn test_workflow_conclusion_display() {
        assert_eq!(format!("{}", WorkflowConclusion::Success), "success");
        assert_eq!(format!("{}", WorkflowConclusion::Failure), "failure");
        assert_eq!(format!("{}", WorkflowConclusion::Cancelled), "cancelled");
        assert_eq!(format!("{}", WorkflowConclusion::TimedOut), "timed_out");
    }

    #[test]
    fn test_all_conclusion_types() {
        let conclusions = [
            ("success", WorkflowConclusion::Success),
            ("failure", WorkflowConclusion::Failure),
            ("cancelled", WorkflowConclusion::Cancelled),
            ("skipped", WorkflowConclusion::Skipped),
            ("timed_out", WorkflowConclusion::TimedOut),
            ("action_required", WorkflowConclusion::ActionRequired),
            ("stale", WorkflowConclusion::Stale),
            ("neutral", WorkflowConclusion::Neutral),
        ];

        for (str_val, expected) in conclusions {
            let body = make_payload("completed", Some(str_val));
            let payload = WorkflowRunPayload::parse(&body).unwrap();
            let completed = payload.into_completed().unwrap();
            assert_eq!(completed.conclusion, expected, "Failed for {str_val}");
        }
    }
}
