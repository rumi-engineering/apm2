//! Error detection patterns for FAC review logs (HTTP 400, rate limit,
//! permission denied, verdict extraction).

use regex::Regex;

use super::state::read_last_lines;
use super::types::COMMENT_PERMISSION_SCAN_LINES;

// ── Log-level detectors ─────────────────────────────────────────────────────

pub fn detect_http_400_or_rate_limit(log_path: &std::path::Path) -> bool {
    let Ok(lines) = read_last_lines(log_path, COMMENT_PERMISSION_SCAN_LINES) else {
        return false;
    };
    lines
        .iter()
        .rev()
        .any(|line| line_indicates_provider_backpressure(line))
}

pub fn detect_comment_permission_denied(log_path: &std::path::Path) -> bool {
    let Ok(lines) = read_last_lines(log_path, COMMENT_PERMISSION_SCAN_LINES) else {
        return false;
    };
    lines
        .iter()
        .rev()
        .any(|line| line_indicates_comment_permission_denied(line))
}

// ── Line-level analysis ─────────────────────────────────────────────────────

fn line_indicates_comment_permission_denied(line: &str) -> bool {
    let Some(value) = parse_json_line(line) else {
        return false;
    };
    let Some((command, exit_code, status, output)) = command_execution_context(&value) else {
        return false;
    };
    let command_lower = command.to_ascii_lowercase();
    if !command_targets_comment_api(&command_lower) {
        return false;
    }
    if exit_code == 0 && !status.eq_ignore_ascii_case("failed") {
        return false;
    }

    let lower = output.to_ascii_lowercase();
    permission_marker_in_text(&lower)
}

fn line_indicates_provider_backpressure(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if !provider_backpressure_marker_in_text(&lower) {
        return false;
    }

    let Some(value) = parse_json_line(line) else {
        return true;
    };
    let Some((command, exit_code, status, output)) = command_execution_context(&value) else {
        return true;
    };
    let command_lower = command.to_ascii_lowercase();
    if command_lower.contains("gh pr diff ")
        || command_lower.contains("nl -ba ")
        || command_lower.contains("sed -n ")
        || command_lower.contains("cat ")
    {
        return false;
    }
    if exit_code == 0 && !status.eq_ignore_ascii_case("failed") {
        return false;
    }
    provider_backpressure_marker_in_text(&output.to_ascii_lowercase())
}

// ── JSON / context extraction ───────────────────────────────────────────────

fn parse_json_line(line: &str) -> Option<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(line).ok()
}

fn command_execution_context(value: &serde_json::Value) -> Option<(&str, i64, &str, &str)> {
    let item = value.get("item")?;
    if item.get("type").and_then(serde_json::Value::as_str) != Some("command_execution") {
        return None;
    }

    let command = item
        .get("command")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let exit_code = item
        .get("exit_code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let status = item
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let output = item
        .get("aggregated_output")
        .or_else(|| item.get("output"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    Some((command, exit_code, status, output))
}

// ── Marker predicates ───────────────────────────────────────────────────────

fn permission_marker_in_text(lower: &str) -> bool {
    lower.contains("resource not accessible by personal access token")
        || lower.contains("http 403 resource not accessible by personal access token")
        || lower.contains("insufficient permissions")
}

fn provider_backpressure_marker_in_text(lower: &str) -> bool {
    lower.contains("rate limit")
        || lower.contains("exhausted your capacity")
        || lower.contains("quota will reset")
        || lower.contains("modelnotfounderror")
        || lower.contains("\"status\":400")
        || lower.contains("http 400")
}

fn command_targets_comment_api(command_lower: &str) -> bool {
    command_lower.contains("gh pr comment")
        || (command_lower.contains("/issues/") && command_lower.contains("/comments"))
        || command_lower.contains("addcomment")
        || command_lower.contains("create-an-issue-comment")
}

// ── Verdict extraction ──────────────────────────────────────────────────────

pub fn extract_verdict_from_comment_body(body: &str) -> Option<String> {
    let metadata_verdict = Regex::new("(?i)\"verdict\"\\s*:\\s*\"(pass|fail)\"")
        .ok()
        .and_then(|regex| regex.captures(body))
        .and_then(|captures| {
            captures
                .get(1)
                .map(|capture| capture.as_str().to_ascii_uppercase())
        });
    if metadata_verdict.is_some() {
        return metadata_verdict;
    }

    let lower = body.to_ascii_lowercase();
    if lower.contains("## security review: pass") || lower.contains("## code quality review: pass")
    {
        return Some("PASS".to_string());
    }
    if lower.contains("## security review: fail") || lower.contains("## code quality review: fail")
    {
        return Some("FAIL".to_string());
    }
    None
}
