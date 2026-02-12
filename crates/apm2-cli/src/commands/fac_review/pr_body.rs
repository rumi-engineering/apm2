//! PR body gate-status projection for `apm2 fac push`.

use std::fmt::Write as _;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::types::{now_iso8601, validate_expected_head_sha};
use super::{github_projection, projection_store};

pub(super) const GATE_STATUS_START: &str = "<!-- apm2-gate-status:start -->";
pub(super) const GATE_STATUS_END: &str = "<!-- apm2-gate-status:end -->";
const GATE_STATUS_SCHEMA: &str = "apm2.gate_status.v1";
const MAX_PREVIOUS_STATUSES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct GateResult {
    pub name: String,
    pub passed: bool,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ShaGateStatus {
    pub sha: String,
    pub short_sha: String,
    pub timestamp: String,
    pub gates: Vec<GateResult>,
    pub all_passed: bool,
}

#[derive(Debug, Clone)]
struct ParsedPrBody {
    before_markers: String,
    existing_gate_statuses: Vec<ShaGateStatus>,
    after_markers: String,
    has_gate_markers: bool,
}

#[derive(Debug, Clone, Copy)]
struct GateMarkerSpan {
    start_line_start: usize,
    section_start: usize,
    section_end: usize,
    end_line_end: usize,
}

pub(super) fn fetch_pr_body(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    if let Some(snapshot) = projection_store::load_pr_body_snapshot(owner_repo, pr_number)? {
        return Ok(snapshot);
    }

    if !projection_store::gh_read_fallback_enabled() {
        return Ok(String::new());
    }

    let body = github_projection::fetch_pr_body(owner_repo, pr_number)?;
    let _ = projection_store::record_fallback_read(owner_repo, pr_number, "pr_body.fetch_pr_body");
    let _ = projection_store::save_pr_body_snapshot(
        owner_repo,
        pr_number,
        &body,
        "gh-fallback:pr_body.fetch_pr_body",
    );
    Ok(body)
}

fn parse_gate_statuses(section: &str) -> Vec<ShaGateStatus> {
    let Ok(re) = Regex::new(
        r"(?s)<!--\s*apm2-gate-status:sha:([a-fA-F0-9]{40})\s*-->\s*```json\s*(\{.*?\})\s*```",
    ) else {
        return Vec::new();
    };

    let mut statuses = Vec::new();
    for captures in re.captures_iter(section) {
        let marker_sha = captures
            .get(1)
            .map(|value| value.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let Some(json_payload) = captures.get(2).map(|value| value.as_str()) else {
            continue;
        };
        let Ok(mut parsed) = serde_json::from_str::<ShaGateStatus>(json_payload) else {
            continue;
        };
        if validate_expected_head_sha(&parsed.sha).is_err() {
            continue;
        }
        if !parsed.sha.eq_ignore_ascii_case(&marker_sha) {
            continue;
        }
        parsed.sha = parsed.sha.to_ascii_lowercase();
        if parsed.short_sha.is_empty() {
            parsed.short_sha = parsed.sha.chars().take(8).collect();
        }
        statuses.push(parsed);
    }
    statuses
}

fn fence_delimiter(trimmed_line: &str) -> Option<char> {
    let bytes = trimmed_line.as_bytes();
    if bytes.len() < 3 {
        return None;
    }
    let first = bytes[0];
    if !(first == b'`' || first == b'~') {
        return None;
    }
    if bytes[1] == first && bytes[2] == first {
        Some(char::from(first))
    } else {
        None
    }
}

fn find_gate_marker_span(body: &str) -> Option<GateMarkerSpan> {
    let mut offset = 0usize;
    let mut open_fence: Option<char> = None;
    let mut start_line_start: Option<usize> = None;
    let mut section_start: Option<usize> = None;

    for line in body.split_inclusive('\n') {
        let line_start = offset;
        offset += line.len();
        let line_end = offset;
        let trimmed_start = line.trim_start();
        let trimmed = line.trim();

        if let Some(delimiter) = fence_delimiter(trimmed_start) {
            match open_fence {
                Some(open) if open == delimiter => open_fence = None,
                None => open_fence = Some(delimiter),
                _ => {},
            }
            continue;
        }

        if open_fence.is_some() {
            continue;
        }

        if start_line_start.is_none() {
            if trimmed == GATE_STATUS_START {
                start_line_start = Some(line_start);
                section_start = Some(line_end);
            }
            continue;
        }

        if trimmed == GATE_STATUS_END {
            return Some(GateMarkerSpan {
                start_line_start: start_line_start.unwrap_or(0),
                section_start: section_start.unwrap_or(line_start),
                section_end: line_start,
                end_line_end: line_end,
            });
        }
    }

    None
}

fn parse_pr_body(body: &str) -> ParsedPrBody {
    let Some(span) = find_gate_marker_span(body) else {
        return ParsedPrBody {
            before_markers: body.to_string(),
            existing_gate_statuses: Vec::new(),
            after_markers: String::new(),
            has_gate_markers: false,
        };
    };
    let section = &body[span.section_start..span.section_end];
    let after_markers = body[span.end_line_end..].to_string();

    ParsedPrBody {
        before_markers: body[..span.start_line_start].to_string(),
        existing_gate_statuses: parse_gate_statuses(section),
        after_markers,
        has_gate_markers: true,
    }
}

const fn status_label(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

fn render_gate_table(status: &ShaGateStatus) -> String {
    let mut out = String::new();
    out.push_str("| Gate | Status | Duration (s) |\n");
    out.push_str("| --- | --- | --- |\n");
    for gate in &status.gates {
        let _ = writeln!(
            out,
            "| {} | {} | {} |",
            gate.name,
            status_label(gate.passed),
            gate.duration_secs
        );
    }
    out
}

fn render_status_metadata_block(status: &ShaGateStatus) -> String {
    let payload = serde_json::json!({
        "schema": GATE_STATUS_SCHEMA,
        "sha": status.sha,
        "short_sha": status.short_sha,
        "timestamp": status.timestamp,
        "all_passed": status.all_passed,
        "gates": status.gates,
    });
    let json = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
    format!(
        "<!-- apm2-gate-status:sha:{} -->\n```json\n{}\n```",
        status.sha, json
    )
}

fn render_previous_status(status: &ShaGateStatus) -> String {
    let mut out = String::new();
    out.push_str("<details>\n");
    let _ = write!(
        out,
        "<summary>Previous SHA <code>{}</code> at {}</summary>\n\n",
        status.short_sha, status.timestamp
    );
    out.push_str(&render_gate_table(status));
    out.push('\n');
    out.push_str(&render_status_metadata_block(status));
    out.push_str("\n</details>\n");
    out
}

pub(super) fn render_gate_status_section(
    latest: &ShaGateStatus,
    previous: &[ShaGateStatus],
) -> Result<String, String> {
    validate_expected_head_sha(&latest.sha)?;
    let mut out = String::new();
    out.push_str("## FAC Gate Status\n\n");
    let _ = write!(
        out,
        "Current SHA `<{}>` recorded at {}.\n\n",
        latest.short_sha, latest.timestamp
    );
    out.push_str(&render_gate_table(latest));
    out.push('\n');
    out.push_str(&render_status_metadata_block(latest));
    out.push('\n');

    for status in previous.iter().take(MAX_PREVIOUS_STATUSES) {
        if validate_expected_head_sha(&status.sha).is_err() {
            continue;
        }
        out.push('\n');
        out.push_str(&render_previous_status(status));
    }

    Ok(out.trim_end().to_string())
}

fn build_updated_pr_body(existing_body: &str, latest: &ShaGateStatus) -> Result<String, String> {
    validate_expected_head_sha(&latest.sha)?;
    let parsed = parse_pr_body(existing_body);
    let mut previous = parsed
        .existing_gate_statuses
        .into_iter()
        .filter(|status| !status.sha.eq_ignore_ascii_case(&latest.sha))
        .collect::<Vec<_>>();
    if previous.len() > MAX_PREVIOUS_STATUSES {
        previous.truncate(MAX_PREVIOUS_STATUSES);
    }

    let section = render_gate_status_section(latest, &previous)?;
    let wrapped = format!("{GATE_STATUS_START}\n{section}\n{GATE_STATUS_END}");

    if parsed.has_gate_markers {
        return Ok(format!(
            "{}{}{}",
            parsed.before_markers, wrapped, parsed.after_markers
        ));
    }

    let base = parsed.before_markers.trim_end();
    if base.is_empty() {
        Ok(format!("{wrapped}\n"))
    } else {
        Ok(format!("{base}\n\n{wrapped}\n"))
    }
}

pub(super) fn sync_gate_status_to_pr(
    owner_repo: &str,
    pr_number: u32,
    gate_results: Vec<GateResult>,
    sha: &str,
) -> Result<(), String> {
    validate_expected_head_sha(sha)?;
    let sha = sha.to_ascii_lowercase();
    let latest = ShaGateStatus {
        short_sha: sha.chars().take(8).collect(),
        timestamp: now_iso8601(),
        all_passed: gate_results.iter().all(|gate| gate.passed),
        gates: gate_results,
        sha: sha.clone(),
    };
    let existing_body = fetch_pr_body(owner_repo, pr_number)?;
    let updated_body = build_updated_pr_body(&existing_body, &latest)?;
    github_projection::edit_pr_body(owner_repo, pr_number, &updated_body)?;
    let _ =
        projection_store::save_pr_body_snapshot(owner_repo, pr_number, &updated_body, "pr_body");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{
        GATE_STATUS_END, GATE_STATUS_START, GateResult, ShaGateStatus, build_updated_pr_body,
        parse_pr_body, render_gate_status_section,
    };

    fn sample_status(sha: &str, stamp: &str, passed: bool) -> ShaGateStatus {
        ShaGateStatus {
            sha: sha.to_string(),
            short_sha: sha.chars().take(8).collect(),
            timestamp: stamp.to_string(),
            all_passed: passed,
            gates: vec![
                GateResult {
                    name: "rustfmt".to_string(),
                    passed,
                    duration_secs: 1,
                },
                GateResult {
                    name: "clippy".to_string(),
                    passed,
                    duration_secs: 2,
                },
            ],
        }
    }

    #[test]
    fn parse_pr_body_extracts_existing_gate_statuses() {
        let existing = format!(
            "intro\n\n{GATE_STATUS_START}\n<!-- apm2-gate-status:sha:0123456789abcdef0123456789abcdef01234567 -->\n```json\n{{\"sha\":\"0123456789abcdef0123456789abcdef01234567\",\"short_sha\":\"01234567\",\"timestamp\":\"2026-02-12T00:00:00Z\",\"gates\":[{{\"name\":\"rustfmt\",\"passed\":true,\"duration_secs\":1}}],\"all_passed\":true}}\n```\n{GATE_STATUS_END}\n\ntail\n"
        );
        let parsed = parse_pr_body(&existing);
        assert!(parsed.has_gate_markers);
        assert_eq!(parsed.existing_gate_statuses.len(), 1);
        assert_eq!(
            parsed.existing_gate_statuses[0].sha,
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert!(parsed.before_markers.contains("intro"));
        assert!(parsed.after_markers.contains("tail"));
    }

    #[test]
    fn render_gate_status_section_renders_latest_expanded_and_previous_collapsed() {
        let latest = sample_status(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "2026-02-12T10:00:00Z",
            true,
        );
        let previous = vec![sample_status(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "2026-02-11T10:00:00Z",
            false,
        )];
        let rendered = render_gate_status_section(&latest, &previous).expect("rendered");
        assert!(rendered.contains("## FAC Gate Status"));
        assert!(rendered.contains("| rustfmt | PASS | 1 |"));
        assert!(rendered.contains("<details>"));
        assert!(rendered.contains("Previous SHA <code>bbbbbbbb</code>"));
    }

    #[test]
    fn build_updated_pr_body_preserves_content_outside_markers() {
        let existing = format!(
            "before-line\n\n{GATE_STATUS_START}\nold gate section\n{GATE_STATUS_END}\n\nafter-line\n"
        );
        let latest = sample_status(
            "cccccccccccccccccccccccccccccccccccccccc",
            "2026-02-12T10:00:00Z",
            true,
        );
        let updated = build_updated_pr_body(&existing, &latest).expect("updated body");
        assert!(updated.contains("before-line"));
        assert!(updated.contains("after-line"));
        assert!(updated.contains("cccccccc"));
    }

    #[test]
    fn build_updated_pr_body_limits_previous_history_to_five() {
        let mut existing_statuses = String::new();
        for idx in 0..6 {
            let _ = write!(
                existing_statuses,
                "<!-- apm2-gate-status:sha:{:040x} -->\n```json\n{{\"sha\":\"{:040x}\",\"short_sha\":\"{:08x}\",\"timestamp\":\"2026-02-1{}T00:00:00Z\",\"gates\":[],\"all_passed\":true}}\n```\n",
                idx + 1,
                idx + 1,
                idx + 1,
                idx
            );
        }
        let existing = format!("{GATE_STATUS_START}\n{existing_statuses}{GATE_STATUS_END}\n");
        let latest = sample_status(
            "ffffffffffffffffffffffffffffffffffffffff",
            "2026-02-12T10:00:00Z",
            true,
        );
        let updated = build_updated_pr_body(&existing, &latest).expect("updated");
        let details_count = updated.matches("<details>").count();
        assert_eq!(details_count, 5);
    }

    #[test]
    fn parse_pr_body_ignores_markers_inside_fenced_blocks() {
        let existing = format!(
            "intro\n\n```yaml\nexample: |\n  {GATE_STATUS_START}\n  this marker is part of ticket content\n  {GATE_STATUS_END}\n```\n\ntail\n"
        );
        let parsed = parse_pr_body(&existing);
        assert!(!parsed.has_gate_markers);
        assert_eq!(parsed.before_markers, existing);
        assert!(parsed.existing_gate_statuses.is_empty());
    }

    #[test]
    fn build_updated_pr_body_appends_when_markers_only_exist_in_code_block() {
        let existing = format!(
            "```yaml\n- literal: |\n    {GATE_STATUS_START}\n    sample\n    {GATE_STATUS_END}\n```\n"
        );
        let latest = sample_status(
            "dddddddddddddddddddddddddddddddddddddddd",
            "2026-02-12T10:00:00Z",
            true,
        );
        let updated = build_updated_pr_body(&existing, &latest).expect("updated");
        assert!(updated.contains(
            "```yaml\n- literal: |\n    <!-- apm2-gate-status:start -->\n    sample\n    <!-- apm2-gate-status:end -->\n```"
        ));
        assert!(updated.contains("## FAC Gate Status"));
        assert_eq!(updated.matches(GATE_STATUS_START).count(), 2);
        assert_eq!(updated.matches(GATE_STATUS_END).count(), 2);
    }
}
