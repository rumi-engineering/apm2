use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::process::Output;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use tokio::process::Command;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AgentTurn {
    pub role_id: String,
    pub model: String,
    pub session_id: String,
    pub system_prompt_file: PathBuf,
    pub prompt: String,
}

#[derive(Debug, Clone)]
pub struct AgentResponse {
    pub raw_output: String,
    pub token_estimate: u64,
    pub elapsed_seconds: f64,
}

impl AgentResponse {
    #[must_use]
    pub fn new(raw_output: String, elapsed_seconds: f64) -> Self {
        Self {
            token_estimate: estimate_tokens(&raw_output),
            raw_output,
            elapsed_seconds,
        }
    }
}

#[async_trait]
pub trait AgentBackend: Send {
    async fn complete(&mut self, turn: &AgentTurn) -> Result<AgentResponse>;
}

#[derive(Debug, Default)]
pub struct ClaudeBackend {
    command: String,
    session_initialized: HashMap<String, bool>,
}

impl ClaudeBackend {
    #[must_use]
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            session_initialized: HashMap::new(),
        }
    }
}

#[async_trait]
impl AgentBackend for ClaudeBackend {
    async fn complete(&mut self, turn: &AgentTurn) -> Result<AgentResponse> {
        let initialized = self
            .session_initialized
            .get(&turn.role_id)
            .copied()
            .unwrap_or(false);

        let primary_flag = if initialized {
            "--resume"
        } else {
            "--session-id"
        };

        let start = Instant::now();
        let mut output = invoke_claude(&self.command, turn, primary_flag).await?;

        if !output.status.success() && !initialized {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("already in use") {
                output = invoke_claude(&self.command, turn, "--resume").await?;
            }
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "claude CLI failed for role '{}' session_id='{}' (status={}): stderr='{}' stdout='{}'",
                turn.role_id,
                turn.session_id,
                output.status,
                stderr.trim(),
                stdout.trim()
            ));
        }

        self.session_initialized.insert(turn.role_id.clone(), true);
        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(AgentResponse::new(raw, start.elapsed().as_secs_f64()))
    }
}

async fn invoke_claude(command: &str, turn: &AgentTurn, session_flag: &str) -> Result<Output> {
    Command::new(command)
        .arg("-p")
        .arg(session_flag)
        .arg(&turn.session_id)
        .arg("--model")
        .arg(&turn.model)
        .arg("--system-prompt-file")
        .arg(&turn.system_prompt_file)
        .arg("--output-format")
        .arg("json")
        .arg(&turn.prompt)
        .output()
        .await
        .with_context(|| format!("spawn {command} for role {}", turn.role_id))
}

#[derive(Debug, Default)]
pub struct MockBackend {
    scripted: VecDeque<String>,
}

impl MockBackend {
    #[must_use]
    pub fn with_scripted(scripted: impl IntoIterator<Item = String>) -> Self {
        Self {
            scripted: scripted.into_iter().collect(),
        }
    }
}

#[async_trait]
impl AgentBackend for MockBackend {
    async fn complete(&mut self, _turn: &AgentTurn) -> Result<AgentResponse> {
        let raw = self
            .scripted
            .pop_front()
            .ok_or_else(|| anyhow!("mock backend has no scripted response left"))?;
        Ok(AgentResponse::new(raw, 0.0))
    }
}

#[must_use]
pub fn new_session_id(_role_id: &str) -> String {
    Uuid::new_v4().to_string()
}

#[must_use]
pub fn estimate_tokens(text: &str) -> u64 {
    let chars = text.chars().count() as u64;
    (chars / 4).max(1)
}

pub fn parse_structured_json<T: DeserializeOwned>(raw: &str) -> Result<T> {
    if let Ok(parsed) = serde_json::from_str::<T>(raw) {
        return Ok(parsed);
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Ok(parsed) = serde_json::from_value::<T>(value.clone()) {
            return Ok(parsed);
        }

        let mut candidates = Vec::new();
        collect_value_candidates(&value, &mut candidates);

        for candidate in candidates {
            if let Ok(parsed) = serde_json::from_value::<T>(candidate.clone()) {
                return Ok(parsed);
            }
            if let Some(s) = candidate.as_str() {
                if let Ok(parsed) = serde_json::from_str::<T>(s) {
                    return Ok(parsed);
                }
                if let Some(json_obj) = extract_json_object(s)
                    && let Ok(parsed) = serde_json::from_str::<T>(&json_obj)
                {
                    return Ok(parsed);
                }
            }
        }
    }

    if let Some(json_obj) = extract_json_object(raw)
        && let Ok(parsed) = serde_json::from_str::<T>(&json_obj)
    {
        return Ok(parsed);
    }

    Err(anyhow!("failed to parse structured JSON payload"))
}

fn collect_value_candidates(value: &serde_json::Value, out: &mut Vec<serde_json::Value>) {
    out.push(value.clone());

    for key in [
        "result",
        "output",
        "text",
        "response",
        "completion",
        "message",
        "data",
    ] {
        if let Some(v) = value.get(key) {
            out.push(v.clone());
        }
    }

    if let Some(content) = value.get("content").and_then(serde_json::Value::as_array) {
        for item in content {
            out.push(item.clone());
            if let Some(text) = item.get("text") {
                out.push(text.clone());
            }
        }
    }
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
    use serde::Deserialize;

    use super::parse_structured_json;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Payload {
        action: String,
    }

    #[test]
    fn parse_plain_payload() {
        let raw = r#"{"action":"ok"}"#;
        let payload = parse_structured_json::<Payload>(raw).expect("parse");
        assert_eq!(payload.action, "ok");
    }

    #[test]
    fn parse_nested_payload() {
        let raw = r#"{"content":[{"type":"text","text":"{\"action\":\"ok\"}"}]}"#;
        let payload = parse_structured_json::<Payload>(raw).expect("parse nested");
        assert_eq!(payload.action, "ok");
    }

    #[test]
    fn parse_embedded_payload() {
        let raw = "noise... {\"action\":\"ok\"} ...end";
        let payload = parse_structured_json::<Payload>(raw).expect("parse embedded");
        assert_eq!(payload.action, "ok");
    }
}
