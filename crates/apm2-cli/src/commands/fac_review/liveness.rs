//! Log-based liveness and stall detection for FAC review processes.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::types::LivenessSnapshot;

const TOOL_SIGNAL_KEYS: [&str; 6] = [
    "tool",
    "tool_call",
    "tool_calls",
    "tool_name",
    "toolCall",
    "toolCallId",
];

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
    let mut tool_calls_since_last = 0_u64;
    let mut max_total_tokens_seen: Option<u64> = None;
    for line in appended.lines() {
        if let Some(token_count) = extract_total_tokens_from_line(line) {
            max_total_tokens_seen =
                Some(max_total_tokens_seen.map_or(token_count, |current| current.max(token_count)));
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            events_since_last = events_since_last.saturating_add(1);
            if json_value_signals_tool_call(&value) {
                tool_calls_since_last = tool_calls_since_last.saturating_add(1);
            }
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
        tool_calls_since_last,
        max_total_tokens_seen,
    })
}

fn json_value_signals_tool_call(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            if TOOL_SIGNAL_KEYS.iter().any(|key| map.contains_key(*key)) {
                return true;
            }
            if map
                .get("event")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("tool_call"))
            {
                return true;
            }
            if map
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| {
                    value.eq_ignore_ascii_case("tool_call")
                        || value.eq_ignore_ascii_case("command_execution")
                })
            {
                return true;
            }
            map.values().any(json_value_signals_tool_call)
        },
        serde_json::Value::Array(values) => values.iter().any(json_value_signals_tool_call),
        _ => false,
    }
}

fn extract_total_tokens_from_line(line: &str) -> Option<u64> {
    [
        "\"total_tokens\"",
        "\"totalTokens\"",
        "total_tokens",
        "\"token_count\"",
    ]
    .iter()
    .find_map(|marker| extract_numeric_after_marker(line, marker))
}

fn extract_numeric_after_marker(line: &str, marker: &str) -> Option<u64> {
    let marker_idx = line.rfind(marker)?;
    let suffix = &line[marker_idx + marker.len()..];
    let delimiter_idx = suffix.find([':', '='])?;
    let value = suffix[delimiter_idx + 1..]
        .trim_start_matches(|ch: char| ch.is_ascii_whitespace() || ch == '"');
    let digits_len = value
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits_len == 0 {
        return None;
    }
    value[..digits_len].parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::scan_log_liveness;

    #[test]
    fn scan_log_liveness_tracks_tool_calls_and_tokens() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("review.log");
        std::fs::write(
            &path,
            r#"{"type":"item.completed","item":{"type":"command_execution","command":"ls -la"}}
{"event":"heartbeat","usage":{"total_tokens":321}}
"#,
        )
        .expect("write log");

        let mut cursor = 0_u64;
        let mut last_event_type = String::new();
        let snapshot = scan_log_liveness(&path, &mut cursor, &mut last_event_type)
            .expect("scan should succeed");
        assert_eq!(snapshot.events_since_last, 2);
        assert_eq!(snapshot.tool_calls_since_last, 1);
        assert_eq!(snapshot.max_total_tokens_seen, Some(321));
        assert_eq!(last_event_type, "heartbeat");
    }

    #[test]
    fn scan_log_liveness_honors_cursor_and_token_marker_variants() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("review.log");
        std::fs::write(&path, "{\"event\":\"run_start\"}\n").expect("write initial log");

        let mut cursor = 0_u64;
        let mut last_event_type = String::new();
        let first = scan_log_liveness(&path, &mut cursor, &mut last_event_type)
            .expect("first scan should succeed");
        assert_eq!(first.events_since_last, 1);
        assert_eq!(first.tool_calls_since_last, 0);
        assert_eq!(first.max_total_tokens_seen, None);

        let mut append = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open log for append");
        writeln!(append, r#"{{"totalTokens": 77}}"#).expect("append totalTokens line");
        writeln!(append, "total_tokens=88").expect("append total_tokens line");

        let second = scan_log_liveness(&path, &mut cursor, &mut last_event_type)
            .expect("second scan should succeed");
        assert_eq!(second.events_since_last, 1);
        assert_eq!(second.max_total_tokens_seen, Some(88));
    }
}
