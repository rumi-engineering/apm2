//! NDJSON event emission, rotation, and file locking for FAC review telemetry.

use std::path::Path;
use std::sync::atomic::Ordering;

use apm2_daemon::telemetry::reviewer::ReviewerTelemetryWriter;

use super::types::{EVENT_ROTATE_BYTES, ExecutionContext, apm2_home_dir, now_iso8601_millis};

// ── Path helpers ────────────────────────────────────────────────────────────

pub fn review_events_path() -> Result<std::path::PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_events.ndjson"))
}

// ── Event emission ──────────────────────────────────────────────────────────

pub fn emit_event(
    ctx: &ExecutionContext,
    event_name: &str,
    review_type: &str,
    head_sha: &str,
    extra: serde_json::Value,
) -> Result<(), String> {
    let seq = ctx.seq.fetch_add(1, Ordering::SeqCst).saturating_add(1);
    let mut envelope = serde_json::Map::new();
    envelope.insert("ts".to_string(), serde_json::json!(now_iso8601_millis()));
    envelope.insert("event".to_string(), serde_json::json!(event_name));
    envelope.insert("review_type".to_string(), serde_json::json!(review_type));
    envelope.insert("pr_number".to_string(), serde_json::json!(ctx.pr_number));
    envelope.insert("head_sha".to_string(), serde_json::json!(head_sha));
    envelope.insert("seq".to_string(), serde_json::json!(seq));
    if let serde_json::Value::Object(extra_fields) = extra {
        for (key, value) in extra_fields {
            envelope.insert(key, value);
        }
    }
    emit_review_event(&serde_json::Value::Object(envelope))
}

pub fn emit_review_event(event: &serde_json::Value) -> Result<(), String> {
    let events_path = review_events_path()?;
    emit_review_event_to_path(&events_path, event)
}

pub fn emit_review_event_to_path(
    events_path: &Path,
    event: &serde_json::Value,
) -> Result<(), String> {
    ReviewerTelemetryWriter::new(events_path.to_path_buf())
        .with_rotate_bytes(EVENT_ROTATE_BYTES)
        .append_value(event)
        .map_err(|err| err.to_string())
}
