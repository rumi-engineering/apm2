//! Shared JSONL helpers for FAC long-running command streaming.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;

const ERROR_HINT_MAX_CHARS: usize = 200;
const ERROR_HINT_READ_MAX_BYTES: u64 = 64 * 1024;

pub fn ts_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn emit_jsonl<T: Serialize>(event: &T) -> Result<(), String> {
    let mut out = io::stdout().lock();
    let encoded = serde_json::to_string(event)
        .map_err(|err| format!("failed to serialize JSONL event: {err}"))?;
    out.write_all(encoded.as_bytes())
        .map_err(|err| format!("failed to write JSONL event: {err}"))?;
    out.write_all(b"\n")
        .map_err(|err| format!("failed to terminate JSONL event: {err}"))?;
    out.flush()
        .map_err(|err| format!("failed to flush JSONL event: {err}"))?;
    Ok(())
}

pub fn emit_json_error(code: &str, message: &str) -> Result<(), String> {
    emit_jsonl(&serde_json::json!({
        "error": code,
        "message": message,
    }))
}

pub fn emit_jsonl_error(event: &str, message: &str) -> Result<(), String> {
    emit_jsonl(&serde_json::json!({
        "event": event,
        "error": message,
        "ts": ts_now(),
    }))
}

/// Normalize a multiline/tooling error into a bounded, single-line hint.
pub fn normalize_error_hint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut hint = trimmed
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or(trimmed)
        .trim()
        .to_string();
    if hint.chars().count() > ERROR_HINT_MAX_CHARS {
        hint = hint.chars().take(ERROR_HINT_MAX_CHARS).collect();
    }
    Some(hint)
}

/// Read a gate log and extract the most actionable one-line hint.
pub fn read_log_error_hint(log_path: &Path) -> Option<String> {
    let mut file = super::evidence::open_nofollow(log_path).ok()?;
    let file_len = file.metadata().ok()?.len();
    let start = file_len.saturating_sub(ERROR_HINT_READ_MAX_BYTES);
    if start > 0 {
        file.seek(SeekFrom::Start(start)).ok()?;
    }
    let mut content = Vec::new();
    file.read_to_end(&mut content).ok()?;
    let content = String::from_utf8_lossy(&content);
    normalize_error_hint(&content)
}

#[derive(Debug, Serialize)]
pub struct GateStartedEvent {
    pub event: &'static str,
    pub gate: String,
    pub ts: String,
}

#[derive(Debug, Serialize)]
pub struct GateProgressTickEvent {
    pub event: &'static str,
    pub gate: String,
    pub elapsed_secs: u64,
    pub bytes_streamed: u64,
    pub ts: String,
}

#[derive(Debug, Serialize)]
pub struct GateCompletedEvent {
    pub event: &'static str,
    pub gate: String,
    pub status: String,
    pub duration_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub was_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_hint: Option<String>,
    pub ts: String,
}

#[derive(Debug, Serialize)]
pub struct GateErrorEvent {
    pub event: &'static str,
    pub gate: String,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub was_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_bundle_hash: Option<String>,
    pub ts: String,
}

#[derive(Debug, Serialize)]
pub struct StageEvent {
    pub event: String,
    pub ts: String,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Serialize)]
pub struct DoctorPollEvent {
    pub event: &'static str,
    pub tick: u64,
    pub action: String,
    pub ts: String,
}

#[derive(Debug, Serialize)]
pub struct DoctorResultEvent {
    pub event: &'static str,
    pub tick: u64,
    pub action: String,
    pub timed_out: bool,
    pub elapsed_seconds: u64,
    pub ts: String,
    pub summary: Value,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn normalize_error_hint_uses_last_non_empty_line_and_caps_length() {
        let hint = normalize_error_hint("line1\n\nline2 final detail").expect("hint");
        assert_eq!(hint, "line2 final detail");

        let long = "x".repeat(400);
        let capped = normalize_error_hint(&long).expect("capped");
        assert_eq!(capped.chars().count(), ERROR_HINT_MAX_CHARS);
    }

    #[test]
    fn read_log_error_hint_handles_non_utf8_tail() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let temp_root =
            std::env::temp_dir().join(format!("apm2-jsonl-hint-{}-{}", std::process::id(), nonce));
        fs::create_dir_all(&temp_root).expect("create temp root");
        let log_path = temp_root.join("gate.log");

        let mut bytes = vec![0xFF, 0xFE, b'\n'];
        bytes.extend_from_slice(b"fatal: final actionable error\n");
        fs::write(&log_path, bytes).expect("write log file");

        let hint = read_log_error_hint(&log_path).expect("error hint");
        assert_eq!(hint, "fatal: final actionable error");

        let _ = fs::remove_file(&log_path);
        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn doctor_result_event_serialization_includes_timeout_fields() {
        let payload = serde_json::to_value(DoctorResultEvent {
            event: "doctor_result",
            tick: 3,
            action: "wait".to_string(),
            timed_out: true,
            elapsed_seconds: 1200,
            ts: "2026-02-16T00:00:00.000Z".to_string(),
            summary: serde_json::json!({"recommended_action":{"action":"wait"}}),
        })
        .expect("serialize doctor result event");
        assert_eq!(
            payload.get("timed_out").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            payload.get("elapsed_seconds").and_then(Value::as_u64),
            Some(1200)
        );
    }

    #[test]
    fn gate_progress_tick_serialization_includes_progress_fields() {
        let payload = serde_json::to_value(GateProgressTickEvent {
            event: "gate_progress",
            gate: "test".to_string(),
            elapsed_secs: 30,
            bytes_streamed: 4096,
            ts: "2026-02-16T00:00:00.000Z".to_string(),
        })
        .expect("serialize gate progress event");
        assert_eq!(
            payload.get("event").and_then(Value::as_str),
            Some("gate_progress")
        );
        assert_eq!(payload.get("gate").and_then(Value::as_str), Some("test"));
        assert_eq!(
            payload.get("elapsed_secs").and_then(Value::as_u64),
            Some(30)
        );
        assert_eq!(
            payload.get("bytes_streamed").and_then(Value::as_u64),
            Some(4096)
        );
    }
}
