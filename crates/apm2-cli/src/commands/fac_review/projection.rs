//! Projection engine: SHA resolution, state rendering, and sequence-done
//! fallback for FAC review lifecycle.

use chrono::{DateTime, SecondsFormat, Utc};

use super::state::{read_pulse_file, with_review_state_shared};
use super::types::{
    MAX_RESTART_ATTEMPTS, ProjectionError, ProjectionStatus, ReviewKind, ReviewStateFile,
    entry_pr_number,
};

// ── Projection state predicates ─────────────────────────────────────────────

pub fn projection_state_done(state: &str) -> bool {
    state.starts_with("done:")
}

pub fn projection_state_failed(state: &str) -> bool {
    state.starts_with("failed:")
}

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

pub fn latest_state_head_sha(state: &ReviewStateFile, pr_number: u32) -> Option<String> {
    state
        .reviewers
        .values()
        .filter(|entry| entry_pr_number(entry).is_some_and(|value| value == pr_number))
        .max_by_key(|entry| entry.started_at)
        .map(|entry| entry.head_sha.clone())
}

pub fn latest_event_head_sha(events: &[serde_json::Value]) -> Option<String> {
    events.iter().rev().find_map(|event| {
        event
            .get("head_sha")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty() && *value != "-")
            .map(ToString::to_string)
    })
}

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

pub fn event_name(event: &serde_json::Value) -> &str {
    event
        .get("event")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

pub fn event_seq(event: &serde_json::Value) -> u64 {
    event
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn event_timestamp_epoch(raw: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .and_then(|value| value.timestamp().try_into().ok())
}

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

// ── run_project_inner ───────────────────────────────────────────────────────

pub fn run_project_inner(
    pr_number: u32,
    head_sha: Option<&str>,
    since_epoch: Option<u64>,
    after_seq: u64,
) -> Result<ProjectionStatus, String> {
    let normalized_head = if let Some(head) = head_sha {
        super::types::validate_expected_head_sha(head)?;
        Some(head.to_ascii_lowercase())
    } else {
        None
    };

    let state = with_review_state_shared(|state| Ok(state.clone()))?;
    let mut events = super::events::read_last_event_values(400)?
        .into_iter()
        .filter(|event| {
            event
                .get("pr_number")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|value| value == u64::from(pr_number))
        })
        .filter(|event| {
            normalized_head.as_ref().is_none_or(|head| {
                event
                    .get("head_sha")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case(head))
            })
        })
        .filter(|event| {
            since_epoch.is_none_or(|min_epoch| {
                event
                    .get("ts")
                    .and_then(serde_json::Value::as_str)
                    .and_then(event_timestamp_epoch)
                    .is_some_and(|epoch| epoch >= min_epoch)
            })
        })
        .collect::<Vec<_>>();
    events.sort_by_key(event_seq);

    let mut security = projection_state_for_type(
        &state,
        &events,
        pr_number,
        ReviewKind::Security,
        normalized_head.as_deref(),
    );
    let mut quality = projection_state_for_type(
        &state,
        &events,
        pr_number,
        ReviewKind::Quality,
        normalized_head.as_deref(),
    );
    apply_sequence_done_fallback(&events, &mut security, &mut quality);
    let sha = resolve_projection_sha(pr_number, &state, &events, normalized_head.as_deref());
    let current_head_sha = resolve_current_head_sha(pr_number, &state, &events, &sha);

    let recent_events = events
        .iter()
        .rev()
        .take(2)
        .map(|event| {
            event
                .get("event")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_string()
        })
        .collect::<Vec<_>>();
    let recent_events = if recent_events.is_empty() {
        "-".to_string()
    } else {
        recent_events
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(",")
    };

    let mut errors = Vec::new();
    let mut terminal_failure = false;
    let mut last_seq = after_seq;
    for event in &events {
        let seq = event_seq(event);
        last_seq = last_seq.max(seq);
        let ev_name = event
            .get("event")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        if ev_name == "run_crash" && event_is_terminal_crash(event) {
            terminal_failure = true;
        }
        if seq <= after_seq {
            continue;
        }
        if !matches!(
            ev_name.as_str(),
            "run_crash" | "stall_detected" | "model_fallback" | "sha_update"
        ) {
            continue;
        }

        let detail = event
            .get("reason")
            .or_else(|| event.get("signal"))
            .or_else(|| event.get("exit_code"))
            .or_else(|| event.get("new_sha"))
            .map_or_else(|| "\"-\"".to_string(), serde_json::Value::to_string)
            .trim_matches('"')
            .to_string();

        errors.push(ProjectionError {
            ts: event
                .get("ts")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_string(),
            event: ev_name,
            review_type: event
                .get("review_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_string(),
            seq,
            detail,
        });
    }

    let line = format!(
        "ts={} sha={} current_head_sha={} security={} quality={} events={}",
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        sha,
        current_head_sha,
        security,
        quality,
        recent_events
    );

    Ok(ProjectionStatus {
        line,
        sha,
        current_head_sha,
        security,
        quality,
        recent_events,
        terminal_failure,
        last_seq,
        errors,
    })
}
