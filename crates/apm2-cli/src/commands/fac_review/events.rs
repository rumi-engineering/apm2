//! NDJSON event emission, rotation, and file locking for FAC review telemetry.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};

use fs2::FileExt;

use super::types::{
    EVENT_ROTATE_BYTES, ExecutionContext, apm2_home_dir, ensure_parent_dir, now_iso8601_millis,
};

// ── Path helpers ────────────────────────────────────────────────────────────

pub fn review_events_path() -> Result<std::path::PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_events.ndjson"))
}

fn review_events_rotated_path(events_path: &Path) -> Result<std::path::PathBuf, String> {
    let parent = events_path
        .parent()
        .ok_or_else(|| format!("event path has no parent: {}", events_path.display()))?;
    Ok(parent.join("review_events.ndjson.1"))
}

fn review_events_lock_path() -> Result<std::path::PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_events.ndjson.lock"))
}

// ── Event emission ──────────────────────────────────────────────────────────

static EVENT_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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
    let lock = EVENT_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| "event file lock poisoned".to_string())?;
    ensure_parent_dir(events_path)?;
    let lock_path = review_events_lock_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open event lock {}: {err}", lock_path.display()))?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|err| format!("failed to lock event stream {}: {err}", lock_path.display()))?;

    if let Ok(meta) = fs::metadata(events_path) {
        if meta.len() > EVENT_ROTATE_BYTES {
            let rotated = review_events_rotated_path(events_path)?;
            if let Err(err) = fs::remove_file(&rotated) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(format!(
                        "failed to remove rotated event file {}: {err}",
                        rotated.display()
                    ));
                }
            }
            fs::rename(events_path, &rotated).map_err(|err| {
                format!(
                    "failed to rotate event file {} -> {}: {err}",
                    events_path.display(),
                    rotated.display()
                )
            })?;
        }
    }

    let serialized =
        serde_json::to_string(event).map_err(|err| format!("failed to serialize event: {err}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(events_path)
        .map_err(|err| format!("failed to open {}: {err}", events_path.display()))?;
    file.write_all(serialized.as_bytes())
        .map_err(|err| format!("failed to append event: {err}"))?;
    file.write_all(b"\n")
        .map_err(|err| format!("failed to write newline: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", events_path.display()))?;
    drop(lock_file);
    Ok(())
}

pub fn read_last_event_values(max_lines: usize) -> Result<Vec<serde_json::Value>, String> {
    let path = review_events_path()?;

    // Try the current events file first.
    let mut values = if path.exists() {
        let lines = super::state::read_last_lines(&path, max_lines)?;
        lines
            .into_iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    // If we still need more entries (e.g. the current file was just rotated and is
    // empty or small), fall back to the rotated file for the remainder.
    if values.len() < max_lines {
        if let Ok(rotated) = review_events_rotated_path(&path) {
            if rotated.exists() {
                let remaining = max_lines - values.len();
                let rotated_lines = super::state::read_last_lines(&rotated, remaining)?;
                let mut rotated_values: Vec<serde_json::Value> = rotated_lines
                    .into_iter()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
                    .collect();
                // Rotated events are older, so prepend them before current events.
                rotated_values.append(&mut values);
                values = rotated_values;
            }
        }
    }

    Ok(values)
}
