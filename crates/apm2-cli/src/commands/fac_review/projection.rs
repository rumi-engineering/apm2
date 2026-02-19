//! Projection engine: SHA resolution, state rendering, and sequence-done
//! fallback for FAC review lifecycle.

use std::fmt::Write as _;

#[cfg(test)]
use chrono::DateTime;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::state::read_pulse_file;
#[cfg(test)]
use super::types::ReviewKind;
#[cfg(test)]
use super::types::{
    MAX_RESTART_ATTEMPTS, ReviewStateFile, entry_pr_number, is_verdict_finalized_agent_stop_reason,
};
use super::types::{now_iso8601, validate_expected_head_sha};
use super::{github_projection, github_reads, projection_store};

// ── Projection state predicates ─────────────────────────────────────────────

#[cfg(test)]
pub fn projection_state_done(state: &str) -> bool {
    state.starts_with("done:")
}

#[cfg(test)]
pub fn projection_state_failed(state: &str) -> bool {
    state.starts_with("failed:")
}

#[cfg(test)]
fn projection_state_from_sequence_verdict(verdict: Option<&str>, head_short: &str) -> String {
    let normalized = verdict.unwrap_or("").trim().to_ascii_uppercase();
    match normalized.as_str() {
        "PASS" | "DEDUPED" | "SKIPPED" => format!("done:sequence/summary:r0:{head_short}"),
        "FAIL" => "failed:sequence_fail".to_string(),
        "UNKNOWN" => "failed:sequence_unknown".to_string(),
        _ => "none".to_string(),
    }
}

// ── Sequence-done fallback ──────────────────────────────────────────────────

#[cfg(test)]
pub fn apply_sequence_done_fallback(
    events: &[serde_json::Value],
    security: &mut String,
    quality: &mut String,
) {
    if *security != "none" && *quality != "none" {
        return;
    }

    let Some(sequence_done) = events
        .iter()
        .rev()
        .find(|event| event_name(event) == "sequence_done")
    else {
        return;
    };

    let head_sha = sequence_done
        .get("head_sha")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let head_short = &head_sha[..head_sha.len().min(7)];

    if *security == "none" {
        *security = projection_state_from_sequence_verdict(
            sequence_done
                .get("security_verdict")
                .and_then(serde_json::Value::as_str),
            head_short,
        );
    }
    if *quality == "none" {
        *quality = projection_state_from_sequence_verdict(
            sequence_done
                .get("quality_verdict")
                .and_then(serde_json::Value::as_str),
            head_short,
        );
    }
}

// ── SHA resolution ──────────────────────────────────────────────────────────

#[cfg(test)]
pub fn resolve_projection_sha(
    pr_number: u32,
    state: &ReviewStateFile,
    events: &[serde_json::Value],
    head_filter: Option<&str>,
) -> String {
    if let Some(head) = head_filter {
        return head.to_string();
    }
    latest_state_head_sha(state, pr_number)
        .or_else(|| latest_event_head_sha(events))
        .or_else(|| latest_pulse_head_sha(pr_number))
        .unwrap_or_else(|| "-".to_string())
}

#[cfg(test)]
pub fn resolve_current_head_sha(
    pr_number: u32,
    state: &ReviewStateFile,
    events: &[serde_json::Value],
    fallback_sha: &str,
) -> String {
    latest_pulse_head_sha(pr_number)
        .or_else(|| latest_state_head_sha(state, pr_number))
        .or_else(|| latest_event_head_sha(events))
        .unwrap_or_else(|| fallback_sha.to_string())
}

#[cfg(test)]
pub fn latest_state_head_sha(state: &ReviewStateFile, pr_number: u32) -> Option<String> {
    state
        .reviewers
        .values()
        .filter(|entry| entry_pr_number(entry).is_some_and(|value| value == pr_number))
        .max_by_key(|entry| entry.started_at)
        .map(|entry| entry.head_sha.clone())
}

#[cfg(test)]
pub fn latest_event_head_sha(events: &[serde_json::Value]) -> Option<String> {
    events.iter().rev().find_map(|event| {
        event
            .get("head_sha")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty() && *value != "-")
            .map(ToString::to_string)
    })
}

#[cfg(test)]
fn latest_pulse_head_sha(pr_number: u32) -> Option<String> {
    let security = read_pulse_file(pr_number, "security").ok().flatten();
    let quality = read_pulse_file(pr_number, "quality").ok().flatten();
    match (security, quality) {
        (Some(sec), Some(qual)) => {
            if sec.written_at >= qual.written_at {
                Some(sec.head_sha)
            } else {
                Some(qual.head_sha)
            }
        },
        (Some(sec), None) => Some(sec.head_sha),
        (None, Some(qual)) => Some(qual.head_sha),
        (None, None) => None,
    }
}

// ── Event helpers ───────────────────────────────────────────────────────────

#[cfg(test)]
pub fn event_name(event: &serde_json::Value) -> &str {
    event
        .get("event")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

#[cfg(test)]
pub fn event_seq(event: &serde_json::Value) -> u64 {
    event
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

#[cfg(test)]
fn run_state_started_epoch(state: &super::types::ReviewRunState) -> Option<u64> {
    DateTime::parse_from_rfc3339(&state.started_at)
        .ok()
        .and_then(|value| value.timestamp().try_into().ok())
}

#[cfg(test)]
fn run_state_is_stale_for_dispatch(
    state: &super::types::ReviewRunState,
    since_epoch: Option<u64>,
) -> bool {
    since_epoch.is_some_and(|min_epoch| {
        run_state_started_epoch(state).is_none_or(|started_epoch| started_epoch < min_epoch)
    })
}

#[cfg(test)]
pub fn event_is_terminal_crash(event: &serde_json::Value) -> bool {
    let restart_count = event
        .get("restart_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if restart_count >= u64::from(MAX_RESTART_ATTEMPTS) {
        return true;
    }
    event
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|reason| reason == "comment_post_permission_denied")
}

// ── Per-type projection state ───────────────────────────────────────────────

#[cfg(test)]
pub fn projection_state_for_type(
    state: &ReviewStateFile,
    events: &[serde_json::Value],
    pr_number: u32,
    review_kind: ReviewKind,
    head_filter: Option<&str>,
) -> String {
    let mut latest_entry_for_kind = state
        .reviewers
        .values()
        .filter(|entry| entry_pr_number(entry).is_some_and(|number| number == pr_number))
        .filter(|entry| entry.review_type.eq_ignore_ascii_case(review_kind.as_str()))
        .filter(|entry| head_filter.is_none_or(|head| entry.head_sha.eq_ignore_ascii_case(head)))
        .collect::<Vec<_>>();
    latest_entry_for_kind.sort_by_key(|entry| entry.started_at);

    let mut active_entries = state
        .reviewers
        .values()
        .filter(|entry| entry_pr_number(entry).is_some_and(|number| number == pr_number))
        .filter(|entry| entry.review_type.eq_ignore_ascii_case(review_kind.as_str()))
        .filter(|entry| super::state::is_process_alive(entry.pid))
        .filter(|entry| head_filter.is_none_or(|head| entry.head_sha.eq_ignore_ascii_case(head)))
        .collect::<Vec<_>>();
    active_entries.sort_by_key(|entry| entry.started_at);
    if let Some(active) = active_entries.last() {
        return format!(
            "alive:{}/{}:r{}:{}",
            active.model,
            active.backend.as_str(),
            active.restart_count,
            &active.head_sha[..active.head_sha.len().min(7)]
        );
    }

    let mut events_for_kind = events
        .iter()
        .filter(|event| {
            event
                .get("review_type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(review_kind.as_str()))
        })
        .collect::<Vec<_>>();
    events_for_kind.sort_by_key(|event| event_seq(event));

    let done = events_for_kind
        .iter()
        .rev()
        .find(|event| event_name(event) == "run_complete");
    let start = events_for_kind
        .iter()
        .rev()
        .find(|event| event_name(event) == "run_start");
    let crash = events_for_kind
        .iter()
        .rev()
        .find(|event| event_name(event) == "run_crash" && event_is_terminal_crash(event));

    if let Some(done) = done {
        let verdict = done
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .map(|value| value.trim().to_ascii_uppercase())
            .unwrap_or_default();
        match verdict.as_str() {
            "FAIL" => return "failed:verdict_fail".to_string(),
            "UNKNOWN" | "" => return "failed:verdict_unknown".to_string(),
            _ => {},
        }

        let model = start
            .and_then(|value| value.get("model"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("n/a");
        let backend = start
            .and_then(|value| value.get("backend"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("n/a");
        let restarts = done
            .get("restart_count")
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                start
                    .and_then(|value| value.get("restart_count"))
                    .and_then(serde_json::Value::as_u64)
            })
            .unwrap_or(0);
        let sha = done
            .get("head_sha")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        return format!(
            "done:{}/{backend}:r{}:{}",
            model,
            restarts,
            &sha[..sha.len().min(7)]
        );
    }

    if let Some(crash) = crash {
        let reason = crash
            .get("reason")
            .or_else(|| crash.get("signal"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("run_crash");
        return format!("failed:{reason}");
    }

    let has_current_activity = !events_for_kind.is_empty();

    if let Some(stale) = latest_entry_for_kind.last() {
        if has_current_activity && !super::state::is_process_alive(stale.pid) {
            return "failed:stale_process_state".to_string();
        }
    }

    "none".to_string()
}

#[cfg(test)]
fn render_state_code_from_run_state(
    load: &super::state::ReviewRunStateLoad,
    since_epoch: Option<u64>,
) -> String {
    match load {
        super::state::ReviewRunStateLoad::Present(state) => {
            if run_state_is_stale_for_dispatch(state, since_epoch) {
                return "stale:dispatch-window".to_string();
            }
            let head_short = &state.head_sha[..state.head_sha.len().min(7)];
            let model = state.model_id.as_deref().unwrap_or("n/a");
            let backend = state.backend_id.as_deref().unwrap_or("n/a");
            match state.status.as_str() {
                "pending" | "alive" => format!(
                    "alive:{model}/{backend}:r{}:{head_short}",
                    state.restart_count
                ),
                "done" => {
                    let reason = state.terminal_reason.as_deref().unwrap_or("");
                    let reason_upper = reason.to_ascii_uppercase();
                    if matches!(reason_upper.as_str(), "FAIL" | "UNKNOWN") {
                        format!("failed:{}", reason.to_ascii_lowercase())
                    } else {
                        format!(
                            "done:{model}/{backend}:r{}:{head_short}",
                            state.restart_count
                        )
                    }
                },
                "failed" | "crashed" => {
                    if state
                        .terminal_reason
                        .as_deref()
                        .is_some_and(is_verdict_finalized_agent_stop_reason)
                    {
                        return format!(
                            "done:{model}/{backend}:r{}:{head_short}",
                            state.restart_count
                        );
                    }
                    let reason = state
                        .terminal_reason
                        .clone()
                        .unwrap_or_else(|| state.status.as_str().to_string());
                    format!("failed:{reason}")
                },
                _ => "failed:invalid-run-state".to_string(),
            }
        },
        super::state::ReviewRunStateLoad::Missing { .. } => "no-run-state".to_string(),
        super::state::ReviewRunStateLoad::Corrupt { .. } => "corrupt-state".to_string(),
        super::state::ReviewRunStateLoad::Ambiguous { .. } => "ambiguous-state".to_string(),
    }
}

// ── Projection preflight helpers (GitHub I/O boundary) ──────────────────────

pub fn fetch_pr_head_sha_local(pr_number: u32) -> Result<String, String> {
    let owner_repo = super::target::derive_repo_from_origin()?;

    // When on a branch associated with this PR, git rev-parse HEAD is
    // authoritative.
    if let Ok(branch) = super::target::current_branch()
        && let Some(identity) = projection_store::load_branch_identity(&owner_repo, &branch)?
        && identity.pr_number == pr_number
        && let Ok(workspace_sha) = super::target::current_head_sha()
    {
        validate_expected_head_sha(&workspace_sha)?;
        return Ok(workspace_sha.to_ascii_lowercase());
    }

    // Cross-branch fallback: trust projection store cache.
    if let Some(identity) = projection_store::load_pr_identity(&owner_repo, pr_number)? {
        validate_expected_head_sha(&identity.head_sha)?;
        return Ok(identity.head_sha.to_ascii_lowercase());
    }

    if let Some(value) = super::state::resolve_local_review_head_sha(pr_number) {
        return Ok(value);
    }

    Err(format!(
        "missing local head SHA for PR #{pr_number}; run local FAC push/dispatch first or pass --sha explicitly"
    ))
}

pub fn fetch_pr_head_sha_authoritative(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    match github_reads::fetch_pr_head_sha(owner_repo, pr_number) {
        Ok(value) => {
            validate_expected_head_sha(&value)?;
            Ok(value.to_ascii_lowercase())
        },
        Err(_) => fetch_pr_head_sha_local(pr_number),
    }
}

// ── PR body projection helpers ───────────────────────────────────────────────

pub(super) const GATE_STATUS_START: &str = "<!-- apm2-gate-status:start -->";
pub(super) const GATE_STATUS_END: &str = "<!-- apm2-gate-status:end -->";
const GATE_STATUS_SCHEMA_V2: &str = "apm2-gate-status:v2";
const MAX_PREVIOUS_GATE_STATUSES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct GateResult {
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShaGateStatus {
    sha: String,
    short_sha: String,
    timestamp: String,
    gates: Vec<GateResult>,
    all_passed: bool,
}

#[derive(Debug, Deserialize)]
struct LegacyGateResult {
    name: String,
    passed: bool,
    duration_secs: u64,
}

#[derive(Debug, Deserialize)]
struct LegacyShaGateStatus {
    sha: String,
    short_sha: Option<String>,
    timestamp: String,
    #[serde(default)]
    gates: Vec<LegacyGateResult>,
    all_passed: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct V2CurrentStatusDoc {
    sha: String,
    short_sha: Option<String>,
    timestamp: String,
    #[serde(default)]
    gates: Vec<GateResult>,
    all_passed: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct PreviousShasDoc {
    #[serde(default)]
    previous_shas: Vec<PreviousShaStatusDoc>,
}

#[derive(Debug, Deserialize)]
struct PreviousShaStatusDoc {
    sha: String,
    timestamp: String,
    all_passed: Option<bool>,
    #[serde(default)]
    gates: Vec<std::collections::BTreeMap<String, String>>,
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

fn fetch_pr_body_for_projection(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    match github_projection::fetch_pr_body(owner_repo, pr_number) {
        Ok(body) if !body.trim().is_empty() => Ok(body),
        first_result => {
            let snapshot = projection_store::load_pr_body_snapshot(owner_repo, pr_number)?;
            if let Some(body) = snapshot.as_ref()
                && !body.trim().is_empty()
            {
                return Ok(body.clone());
            }
            // Return the original result rather than making a redundant API call.
            match first_result {
                Ok(body) => Ok(body),
                Err(err) => Err(err),
            }
        },
    }
}

fn normalize_gate_status(value: &str) -> String {
    match value.trim().to_ascii_uppercase().as_str() {
        "RUNNING" => "RUNNING".to_string(),
        "PASS" => "PASS".to_string(),
        _ => "FAIL".to_string(),
    }
}

fn gate_status_is_pass(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("PASS")
}

fn normalize_sha_gate_status(mut status: ShaGateStatus) -> Option<ShaGateStatus> {
    if validate_expected_head_sha(&status.sha).is_err() {
        return None;
    }
    status.sha = status.sha.to_ascii_lowercase();
    if status.short_sha.is_empty() {
        status.short_sha = status.sha.chars().take(8).collect();
    }
    status.gates = status
        .gates
        .into_iter()
        .map(|mut gate| {
            gate.status = normalize_gate_status(&gate.status);
            gate
        })
        .collect();
    if !status.gates.is_empty() {
        status.all_passed = status
            .gates
            .iter()
            .all(|gate| gate_status_is_pass(&gate.status));
    }
    Some(status)
}

fn dedupe_gate_statuses(statuses: Vec<ShaGateStatus>) -> Vec<ShaGateStatus> {
    let mut seen = std::collections::BTreeSet::new();
    let mut deduped = Vec::new();
    for status in statuses {
        if seen.insert(status.sha.clone()) {
            deduped.push(status);
        }
    }
    deduped
}

fn parse_legacy_gate_statuses(section: &str) -> Vec<ShaGateStatus> {
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
        let Ok(parsed) = serde_json::from_str::<LegacyShaGateStatus>(json_payload) else {
            continue;
        };
        if !parsed.sha.eq_ignore_ascii_case(&marker_sha) {
            continue;
        }
        let gates = parsed
            .gates
            .into_iter()
            .map(|gate| GateResult {
                name: gate.name,
                status: if gate.passed {
                    "PASS".to_string()
                } else {
                    "FAIL".to_string()
                },
                duration_secs: Some(gate.duration_secs),
                tokens_used: None,
                model: None,
            })
            .collect();
        let candidate = ShaGateStatus {
            sha: parsed.sha,
            short_sha: parsed.short_sha.unwrap_or_default(),
            timestamp: parsed.timestamp,
            gates,
            all_passed: parsed.all_passed.unwrap_or(false),
        };
        if let Some(normalized) = normalize_sha_gate_status(candidate) {
            statuses.push(normalized);
        }
    }
    statuses
}

fn strip_gate_status_yaml_header(payload: &str) -> &str {
    let trimmed = payload.trim();
    let header = format!("# {GATE_STATUS_SCHEMA_V2}");
    if trimmed.starts_with(&header)
        && let Some(first_newline) = trimmed.find('\n')
    {
        return trimmed[first_newline + 1..].trim();
    }
    trimmed
}

fn parse_v2_gate_statuses(section: &str) -> Vec<ShaGateStatus> {
    let Ok(re) = Regex::new(r"(?s)```yaml\s*(.*?)\s*```") else {
        return Vec::new();
    };
    let mut statuses = Vec::new();
    for captures in re.captures_iter(section) {
        let Some(raw_payload) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let payload = strip_gate_status_yaml_header(raw_payload);
        if payload.is_empty() {
            continue;
        }

        if let Ok(parsed) = serde_yaml::from_str::<V2CurrentStatusDoc>(payload) {
            let candidate = ShaGateStatus {
                sha: parsed.sha,
                short_sha: parsed.short_sha.unwrap_or_default(),
                timestamp: parsed.timestamp,
                gates: parsed.gates,
                all_passed: parsed.all_passed.unwrap_or(false),
            };
            if let Some(normalized) = normalize_sha_gate_status(candidate) {
                statuses.push(normalized);
            }
            continue;
        }

        if let Ok(parsed_previous) = serde_yaml::from_str::<PreviousShasDoc>(payload) {
            for previous in parsed_previous.previous_shas {
                let gates = previous
                    .gates
                    .into_iter()
                    .flat_map(std::iter::IntoIterator::into_iter)
                    .map(|(name, status)| GateResult {
                        name,
                        status,
                        duration_secs: None,
                        tokens_used: None,
                        model: None,
                    })
                    .collect::<Vec<_>>();
                let candidate = ShaGateStatus {
                    short_sha: previous.sha.chars().take(8).collect(),
                    sha: previous.sha,
                    timestamp: previous.timestamp,
                    all_passed: previous.all_passed.unwrap_or(false),
                    gates,
                };
                if let Some(normalized) = normalize_sha_gate_status(candidate) {
                    statuses.push(normalized);
                }
            }
        }
    }
    statuses
}

fn parse_gate_statuses(section: &str) -> Vec<ShaGateStatus> {
    // Prefer v2 payloads when both legacy and v2 records are present for the same
    // SHA.
    let mut combined = parse_v2_gate_statuses(section);
    combined.extend(parse_legacy_gate_statuses(section));
    dedupe_gate_statuses(combined)
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

fn yaml_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn render_current_status_yaml(status: &ShaGateStatus) -> String {
    let mut out = String::new();
    out.push_str("```yaml\n");
    let _ = writeln!(out, "# {GATE_STATUS_SCHEMA_V2}");
    let _ = writeln!(out, "sha: {}", status.sha);
    let _ = writeln!(out, "short_sha: {}", status.short_sha);
    let _ = writeln!(out, "timestamp: {}", yaml_quote(&status.timestamp));
    let _ = writeln!(out, "all_passed: {}", status.all_passed);
    if status.gates.is_empty() {
        out.push_str("gates: []\n");
    } else {
        out.push_str("gates:\n");
        for gate in &status.gates {
            let _ = writeln!(out, "  - name: {}", yaml_quote(&gate.name));
            let _ = writeln!(out, "    status: {}", normalize_gate_status(&gate.status));
            if let Some(duration_secs) = gate.duration_secs {
                let _ = writeln!(out, "    duration_secs: {duration_secs}");
            }
            if let Some(tokens_used) = gate.tokens_used {
                let _ = writeln!(out, "    tokens_used: {tokens_used}");
            }
            if let Some(model) = gate.model.as_deref() {
                let _ = writeln!(out, "    model: {}", yaml_quote(model));
            }
        }
    }
    out.push_str("```");
    out
}

fn render_previous_gates_flow(status: &ShaGateStatus) -> String {
    if status.gates.is_empty() {
        return "[]".to_string();
    }
    let items = status
        .gates
        .iter()
        .map(|gate| {
            format!(
                "{}: {}",
                yaml_quote(&gate.name),
                normalize_gate_status(&gate.status)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{items}]")
}

fn render_previous_statuses(previous: &[ShaGateStatus]) -> String {
    if previous.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("<details>\n");
    let _ = writeln!(
        out,
        "<summary>Previous SHAs ({})</summary>\n",
        previous.len()
    );
    out.push_str("```yaml\n");
    out.push_str("previous_shas:\n");
    for status in previous {
        let _ = writeln!(out, "  - sha: {}", status.sha);
        let _ = writeln!(out, "    timestamp: {}", yaml_quote(&status.timestamp));
        let _ = writeln!(out, "    all_passed: {}", status.all_passed);
        let _ = writeln!(out, "    gates: {}", render_previous_gates_flow(status));
    }
    out.push_str("```\n\n</details>");
    out
}

fn render_gate_status_section(
    latest: &ShaGateStatus,
    previous: &[ShaGateStatus],
) -> Result<String, String> {
    validate_expected_head_sha(&latest.sha)?;
    let previous_valid = previous
        .iter()
        .filter_map(|status| normalize_sha_gate_status(status.clone()))
        .filter(|status| !status.sha.eq_ignore_ascii_case(&latest.sha))
        .take(MAX_PREVIOUS_GATE_STATUSES)
        .collect::<Vec<_>>();

    let mut out = String::new();
    out.push_str("## FAC Gate Status\n\n");
    out.push_str(&render_current_status_yaml(latest));

    if !previous_valid.is_empty() {
        out.push_str("\n\n");
        out.push_str(&render_previous_statuses(&previous_valid));
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
    if previous.len() > MAX_PREVIOUS_GATE_STATUSES {
        previous.truncate(MAX_PREVIOUS_GATE_STATUSES);
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
    let normalized_gates = gate_results
        .into_iter()
        .map(|mut gate| {
            gate.status = normalize_gate_status(&gate.status);
            gate
        })
        .collect::<Vec<_>>();
    let latest = ShaGateStatus {
        short_sha: sha.chars().take(8).collect(),
        timestamp: now_iso8601(),
        all_passed: normalized_gates
            .iter()
            .all(|gate| gate_status_is_pass(&gate.status)),
        gates: normalized_gates,
        sha: sha.clone(),
    };
    let existing_body = fetch_pr_body_for_projection(owner_repo, pr_number)?;
    let updated_body = build_updated_pr_body(&existing_body, &latest)?;
    github_projection::edit_pr_body(owner_repo, pr_number, &updated_body)?;
    let _ =
        projection_store::save_pr_body_snapshot(owner_repo, pr_number, &updated_body, "pr_body");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use chrono::DateTime;

    use super::{
        GATE_STATUS_END, GATE_STATUS_START, GateResult, ShaGateStatus, build_updated_pr_body,
        parse_pr_body, render_gate_status_section, render_state_code_from_run_state,
    };
    use crate::commands::fac_review::state::ReviewRunStateLoad;
    use crate::commands::fac_review::types::{ReviewRunState, ReviewRunStatus};

    fn sample_run_state(status: ReviewRunStatus, started_at: &str) -> ReviewRunState {
        ReviewRunState {
            run_id: "pr441-security-s2-01234567".to_string(),
            owner_repo: "example/repo".to_string(),
            pr_number: 441,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            review_type: "security".to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: started_at.to_string(),
            status,
            terminal_reason: Some("pass".to_string()),
            model_id: Some("gpt-5.3-codex".to_string()),
            backend_id: Some("codex".to_string()),
            restart_count: 0,
            nudge_count: 0,
            sequence_number: 2,
            previous_run_id: None,
            previous_head_sha: None,
            pid: None,
            proc_start_time: None,
            integrity_hmac: None,
        }
    }

    #[test]
    fn stale_done_state_is_not_authoritative_after_since_epoch() {
        let load = ReviewRunStateLoad::Present(sample_run_state(
            ReviewRunStatus::Done,
            "2026-02-10T00:00:00Z",
        ));
        let since_epoch = DateTime::parse_from_rfc3339("2026-02-10T02:00:00Z")
            .expect("since_epoch parse")
            .timestamp()
            .try_into()
            .expect("since_epoch must be non-negative");
        let rendered = render_state_code_from_run_state(&load, Some(since_epoch));
        assert_eq!(rendered, "stale:dispatch-window");
    }

    #[test]
    fn fresh_done_state_remains_done_after_since_epoch() {
        let load = ReviewRunStateLoad::Present(sample_run_state(
            ReviewRunStatus::Done,
            "2026-02-10T05:00:00Z",
        ));
        let since_epoch = DateTime::parse_from_rfc3339("2026-02-10T02:00:00Z")
            .expect("since_epoch parse")
            .timestamp()
            .try_into()
            .expect("since_epoch must be non-negative");
        let rendered = render_state_code_from_run_state(&load, Some(since_epoch));
        assert!(rendered.starts_with("done:"));
    }

    fn sample_status(sha: &str, stamp: &str, passed: bool) -> ShaGateStatus {
        ShaGateStatus {
            sha: sha.to_string(),
            short_sha: sha.chars().take(8).collect(),
            timestamp: stamp.to_string(),
            all_passed: passed,
            gates: vec![
                GateResult {
                    name: "rustfmt".to_string(),
                    status: if passed {
                        "PASS".to_string()
                    } else {
                        "FAIL".to_string()
                    },
                    duration_secs: Some(1),
                    tokens_used: None,
                    model: None,
                },
                GateResult {
                    name: "clippy".to_string(),
                    status: if passed {
                        "PASS".to_string()
                    } else {
                        "FAIL".to_string()
                    },
                    duration_secs: Some(2),
                    tokens_used: None,
                    model: None,
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
        assert!(rendered.contains("```yaml"));
        assert!(rendered.contains("# apm2-gate-status:v2"));
        assert!(rendered.contains("status: PASS"));
        assert!(!rendered.contains("```json"));
        assert!(!rendered.contains("| Gate |"));
        assert!(rendered.contains("<details>"));
        assert!(rendered.contains("<summary>Previous SHAs (1)</summary>"));
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
        assert_eq!(details_count, 1);
        assert!(updated.contains("<summary>Previous SHAs (5)</summary>"));
        assert_eq!(updated.matches("  - sha: ").count(), 5);
        assert!(!updated.contains("```json"));
        assert!(!updated.contains("| Gate |"));
    }

    #[test]
    fn parse_pr_body_extracts_existing_v2_gate_statuses() {
        let existing = format!(
            "intro\n\n{GATE_STATUS_START}\n## FAC Gate Status\n\n```yaml\n# apm2-gate-status:v2\nsha: 0123456789abcdef0123456789abcdef01234567\nshort_sha: 01234567\ntimestamp: '2026-02-12T00:00:00Z'\nall_passed: false\ngates:\n  - name: 'rustfmt'\n    status: PASS\n    duration_secs: 1\n```\n\n<details>\n<summary>Previous SHAs (1)</summary>\n\n```yaml\nprevious_shas:\n  - sha: 89abcdef0123456789abcdef0123456789abcdef\n    timestamp: '2026-02-11T00:00:00Z'\n    all_passed: true\n    gates: ['rustfmt': PASS]\n```\n\n</details>\n{GATE_STATUS_END}\n\ntail\n"
        );
        let parsed = parse_pr_body(&existing);
        assert!(parsed.has_gate_markers);
        assert_eq!(parsed.existing_gate_statuses.len(), 2);
        assert_eq!(
            parsed.existing_gate_statuses[0].sha,
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(
            parsed.existing_gate_statuses[1].sha,
            "89abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn parse_pr_body_prefers_v2_when_duplicate_sha_is_present() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let existing = format!(
            "{GATE_STATUS_START}\n<!-- apm2-gate-status:sha:{sha} -->\n```json\n{{\"sha\":\"{sha}\",\"short_sha\":\"01234567\",\"timestamp\":\"2026-02-12T00:00:00Z\",\"gates\":[{{\"name\":\"lint\",\"passed\":false,\"duration_secs\":9}}],\"all_passed\":false}}\n```\n```yaml\n# apm2-gate-status:v2\nsha: {sha}\nshort_sha: 01234567\ntimestamp: '2026-02-13T00:00:00Z'\nall_passed: true\ngates:\n  - name: 'lint'\n    status: PASS\n    duration_secs: 3\n```\n{GATE_STATUS_END}\n"
        );
        let parsed = parse_pr_body(&existing);
        assert_eq!(parsed.existing_gate_statuses.len(), 1);
        assert_eq!(parsed.existing_gate_statuses[0].sha, sha);
        assert!(parsed.existing_gate_statuses[0].all_passed);
        assert_eq!(parsed.existing_gate_statuses[0].gates[0].status, "PASS");
        assert_eq!(
            parsed.existing_gate_statuses[0].gates[0].duration_secs,
            Some(3)
        );
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
