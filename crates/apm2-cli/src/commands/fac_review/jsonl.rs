//! Shared JSONL helpers for FAC long-running command streaming.

use std::io::{self, Write};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;

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

#[allow(dead_code)]
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

#[derive(Debug, Serialize)]
pub struct GateStartedEvent {
    pub event: &'static str,
    pub gate: String,
    pub ts: String,
}

#[derive(Debug, Serialize)]
pub struct GateCompletedEvent {
    pub event: &'static str,
    pub gate: String,
    pub status: String,
    pub duration_secs: u64,
    pub ts: String,
}

#[derive(Debug, Serialize)]
pub struct GateErrorEvent {
    pub event: &'static str,
    pub gate: String,
    pub error: String,
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
    pub ts: String,
    pub summary: Value,
}
