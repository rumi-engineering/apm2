use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use apm2_core::crypto::Signer;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use uuid::Uuid;

use crate::verdict::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionVerdict {
    Pass,
    Fail,
}

impl From<ActionVerdict> for Verdict {
    fn from(value: ActionVerdict) -> Self {
        match value {
            ActionVerdict::Pass => Verdict::Pass,
            ActionVerdict::Fail => Verdict::Fail,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AgentAction {
    Claim {
        work_id: String,
    },
    Submit {
        work_id: String,
        solution: String,
    },
    Verify {
        work_id: String,
        verdict: ActionVerdict,
        reasoning: String,
    },
    ProposeFormation {
        partner_ids: Vec<String>,
        rationale: String,
    },
    AttestFormation {
        composite_id: String,
        approve: bool,
        rationale: String,
    },
    Delegate {
        work_id: String,
        delegate_to: String,
        sub_task: String,
    },
    Pass,
}

impl AgentAction {
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Claim { work_id } => format!("claim({work_id})"),
            Self::Submit { work_id, .. } => format!("submit({work_id})"),
            Self::Verify {
                work_id, verdict, ..
            } => {
                format!("verify({work_id},{verdict:?})")
            },
            Self::ProposeFormation { partner_ids, .. } => {
                format!("propose_formation({})", partner_ids.join(","))
            },
            Self::AttestFormation {
                composite_id,
                approve,
                ..
            } => format!("attest_formation({composite_id},{approve})"),
            Self::Delegate {
                work_id,
                delegate_to,
                ..
            } => format!("delegate({work_id}->{delegate_to})"),
            Self::Pass => "pass".to_string(),
        }
    }
}

#[async_trait]
pub trait AgentInvoker: Send {
    async fn invoke(
        &mut self,
        session_id: &str,
        model: &str,
        system_prompt_file: &Path,
        prompt: &str,
    ) -> Result<String>;
}

#[derive(Debug, Default)]
pub struct ClaudeCliInvoker;

#[async_trait]
impl AgentInvoker for ClaudeCliInvoker {
    async fn invoke(
        &mut self,
        session_id: &str,
        model: &str,
        system_prompt_file: &Path,
        prompt: &str,
    ) -> Result<String> {
        let output = Command::new("claude")
            .arg("-p")
            .arg("--session-id")
            .arg(session_id)
            .arg("--model")
            .arg(model)
            .arg("--system-prompt-file")
            .arg(system_prompt_file)
            .arg("--output-format")
            .arg("json")
            .arg(prompt)
            .output()
            .await
            .context("spawn claude CLI")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "claude CLI failed (status={}): stderr='{}' stdout='{}'",
                output.status,
                stderr.trim(),
                stdout.trim()
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[derive(Debug, Default)]
pub struct MockInvoker {
    scripted_responses: VecDeque<String>,
}

impl MockInvoker {
    #[must_use]
    pub fn with_scripted(responses: impl IntoIterator<Item = String>) -> Self {
        Self {
            scripted_responses: responses.into_iter().collect(),
        }
    }
}

#[async_trait]
impl AgentInvoker for MockInvoker {
    async fn invoke(
        &mut self,
        _session_id: &str,
        _model: &str,
        _system_prompt_file: &Path,
        _prompt: &str,
    ) -> Result<String> {
        self.scripted_responses
            .pop_front()
            .ok_or_else(|| anyhow!("mock invoker has no remaining responses"))
    }
}

pub struct LabAgent {
    pub id: String,
    pub domain: String,
    pub signer: Signer,
    pub session_id: String,
    pub model: String,
    pub system_prompt_file: PathBuf,
    pub budget_remaining_tokens: u64,
    pub total_tokens_used: u64,
    pub total_cli_calls: u64,
    invoker: Box<dyn AgentInvoker>,
}

impl std::fmt::Debug for LabAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabAgent")
            .field("id", &self.id)
            .field("domain", &self.domain)
            .field("session_id", &self.session_id)
            .field("model", &self.model)
            .field("budget_remaining_tokens", &self.budget_remaining_tokens)
            .field("total_tokens_used", &self.total_tokens_used)
            .field("total_cli_calls", &self.total_cli_calls)
            .finish()
    }
}

impl LabAgent {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        domain: impl Into<String>,
        signer: Signer,
        model: impl Into<String>,
        system_prompt_file: impl Into<PathBuf>,
        budget_tokens: u64,
        invoker: Box<dyn AgentInvoker>,
    ) -> Self {
        Self {
            id: id.into(),
            domain: domain.into(),
            signer,
            session_id: Uuid::new_v4().to_string(),
            model: model.into(),
            system_prompt_file: system_prompt_file.into(),
            budget_remaining_tokens: budget_tokens,
            total_tokens_used: 0,
            total_cli_calls: 0,
            invoker,
        }
    }

    pub async fn act(&mut self, prompt: &str) -> Result<AgentAction> {
        if self.budget_remaining_tokens == 0 {
            return Ok(AgentAction::Pass);
        }

        let raw = self
            .invoker
            .invoke(
                &self.session_id,
                &self.model,
                &self.system_prompt_file,
                prompt,
            )
            .await?;

        self.total_cli_calls = self.total_cli_calls.saturating_add(1);
        let token_cost = estimate_tokens(&raw);
        self.total_tokens_used = self.total_tokens_used.saturating_add(token_cost);
        self.budget_remaining_tokens = self.budget_remaining_tokens.saturating_sub(token_cost);

        parse_action(&raw).or_else(|_| {
            // Fail-closed: if parse fails, agent effectively passes this turn.
            Ok(AgentAction::Pass)
        })
    }
}

#[must_use]
pub fn estimate_tokens(text: &str) -> u64 {
    let chars = text.chars().count() as u64;
    (chars / 4).max(1)
}

pub fn parse_action(raw: &str) -> Result<AgentAction> {
    if let Ok(action) = serde_json::from_str::<AgentAction>(raw) {
        return Ok(action);
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        for candidate in extract_candidate_strings(&value) {
            if let Ok(action) = serde_json::from_str::<AgentAction>(&candidate) {
                return Ok(action);
            }
            if let Some(json_object) = extract_json_object(&candidate)
                && let Ok(action) = serde_json::from_str::<AgentAction>(&json_object)
            {
                return Ok(action);
            }
        }
    }

    if let Some(json_object) = extract_json_object(raw)
        && let Ok(action) = serde_json::from_str::<AgentAction>(&json_object)
    {
        return Ok(action);
    }

    Err(anyhow!("failed to parse agent action from output"))
}

fn extract_candidate_strings(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(s) = value.as_str() {
        out.push(s.to_string());
    }
    for key in ["result", "output", "text", "response", "completion"] {
        if let Some(s) = value.get(key).and_then(|v| v.as_str()) {
            out.push(s.to_string());
        }
    }
    if let Some(content) = value.get("content").and_then(|v| v.as_array()) {
        for item in content {
            if let Some(s) = item.get("text").and_then(|v| v.as_str()) {
                out.push(s.to_string());
            }
            if let Some(s) = item.as_str() {
                out.push(s.to_string());
            }
        }
    }
    out
}

fn extract_json_object(input: &str) -> Option<String> {
    let mut depth = 0usize;
    let mut start = None;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in input.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(idx);
                }
                depth += 1;
            },
            '}' => {
                if depth == 0 {
                    continue;
                }
                depth -= 1;
                if depth == 0
                    && let Some(start_idx) = start
                {
                    return Some(input[start_idx..=idx].to_string());
                }
            },
            _ => {},
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{AgentAction, parse_action};

    #[test]
    fn parses_plain_json_action() {
        let raw = r#"{"action":"claim","work_id":"w-001"}"#;
        let action = parse_action(raw).expect("parse action");
        assert_eq!(
            action,
            AgentAction::Claim {
                work_id: "w-001".to_string()
            }
        );
    }

    #[test]
    fn parses_nested_json_text() {
        let raw = r#"{"content":[{"type":"text","text":"{\"action\":\"pass\"}"}]}"#;
        let action = parse_action(raw).expect("parse nested");
        assert_eq!(action, AgentAction::Pass);
    }

    #[test]
    fn parses_embedded_object() {
        let raw = "model output... {\"action\":\"pass\"} ...end";
        let action = parse_action(raw).expect("parse embedded");
        assert_eq!(action, AgentAction::Pass);
    }
}
