//! Log-based liveness and stall detection for FAC review processes.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::types::LivenessSnapshot;

pub fn scan_log_liveness(
    log_path: &Path,
    cursor: &mut u64,
    last_event_type: &mut String,
) -> Result<LivenessSnapshot, String> {
    let metadata = fs::metadata(log_path)
        .map_err(|err| format!("failed to read log metadata {}: {err}", log_path.display()))?;
    let log_bytes = metadata.len();
    if log_bytes < *cursor {
        *cursor = 0;
    }

    let mut file = File::open(log_path)
        .map_err(|err| format!("failed to open log {}: {err}", log_path.display()))?;
    file.seek(SeekFrom::Start(*cursor))
        .map_err(|err| format!("failed to seek log {}: {err}", log_path.display()))?;

    let mut appended = String::new();
    file.read_to_string(&mut appended)
        .map_err(|err| format!("failed to read log {}: {err}", log_path.display()))?;
    *cursor = log_bytes;

    let mut events_since_last = 0_u64;
    for line in appended.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            events_since_last = events_since_last.saturating_add(1);
            if let Some(kind) = value
                .get("event")
                .and_then(serde_json::Value::as_str)
                .or_else(|| value.get("type").and_then(serde_json::Value::as_str))
            {
                *last_event_type = kind.to_string();
            }
        }
    }

    Ok(LivenessSnapshot {
        events_since_last,
        last_event_type: last_event_type.clone(),
        log_bytes,
        made_progress: !appended.is_empty(),
    })
}
