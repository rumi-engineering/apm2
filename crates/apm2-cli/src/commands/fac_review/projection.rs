//! Projection engine: SHA resolution, state rendering, and sequence-done
//! fallback for FAC review lifecycle.

use std::fmt::Write as _;

use apm2_daemon::telemetry::reviewer::{
    ProjectionSummary, ReviewerProjectionFilter, ReviewerTelemetryError,
    read_reviewer_projection_events,
};
use chrono::{DateTime, SecondsFormat, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::state::{
    ReviewRunStateLoad, load_review_run_state, read_pulse_file, review_run_state_path,
    with_review_state_shared,
};
#[cfg(test)]
use super::types::ReviewKind;
use super::types::{
    MAX_RESTART_ATTEMPTS, ProjectionError, ProjectionStatus, ReviewStateFile, entry_pr_number,
    is_verdict_finalized_agent_stop_reason, now_iso8601, validate_expected_head_sha,
};
use super::{github_projection, github_reads, projection_store};

// ── Projection state predicates ─────────────────────────────────────────────

pub fn projection_state_done(state: &str) -> bool {
    state.starts_with("done:")
}

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

#[cfg(test)]
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

fn run_state_started_epoch(state: &super::types::ReviewRunState) -> Option<u64> {
    DateTime::parse_from_rfc3339(&state.started_at)
        .ok()
        .and_then(|value| value.timestamp().try_into().ok())
}

fn run_state_is_stale_for_dispatch(
    state: &super::types::ReviewRunState,
    since_epoch: Option<u64>,
) -> bool {
    since_epoch.is_some_and(|min_epoch| {
        run_state_started_epoch(state).is_none_or(|started_epoch| started_epoch < min_epoch)
    })
}

const fn run_state_is_terminal(load: &super::state::ReviewRunStateLoad) -> bool {
    match load {
        super::state::ReviewRunStateLoad::Present(state) => state.status.is_terminal(),
        super::state::ReviewRunStateLoad::Missing { .. }
        | super::state::ReviewRunStateLoad::Corrupt { .. }
        | super::state::ReviewRunStateLoad::Ambiguous { .. } => false,
    }
}

fn telemetry_projection_error(err: &ReviewerTelemetryError) -> ProjectionError {
    let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    match err {
        ReviewerTelemetryError::Missing { path } => ProjectionError {
            ts,
            event: "telemetry_missing".to_string(),
            review_type: "-".to_string(),
            seq: 0,
            detail: format!("path={}", path.display()),
        },
        ReviewerTelemetryError::Malformed { path, line, detail } => ProjectionError {
            ts,
            event: "telemetry_malformed".to_string(),
            review_type: "-".to_string(),
            seq: 0,
            detail: format!("path={} line={line} detail={detail}", path.display()),
        },
        ReviewerTelemetryError::Io { path, detail } => ProjectionError {
            ts,
            event: "telemetry_io_error".to_string(),
            review_type: "-".to_string(),
            seq: 0,
            detail: format!("path={} detail={detail}", path.display()),
        },
        ReviewerTelemetryError::Lock { path, detail } => ProjectionError {
            ts,
            event: "telemetry_lock_error".to_string(),
            review_type: "-".to_string(),
            seq: 0,
            detail: format!("path={} detail={detail}", path.display()),
        },
        ReviewerTelemetryError::Serialize { detail } => ProjectionError {
            ts,
            event: "telemetry_serialize_error".to_string(),
            review_type: "-".to_string(),
            seq: 0,
            detail: detail.clone(),
        },
        ReviewerTelemetryError::InvalidEvent { detail } => ProjectionError {
            ts,
            event: "telemetry_malformed".to_string(),
            review_type: "-".to_string(),
            seq: 0,
            detail: detail.clone(),
        },
    }
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

fn run_state_error(
    load: &super::state::ReviewRunStateLoad,
    review_type: &str,
) -> Option<ProjectionError> {
    match load {
        super::state::ReviewRunStateLoad::Corrupt { path, error } => Some(ProjectionError {
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            event: "corrupt-state".to_string(),
            review_type: review_type.to_string(),
            seq: 0,
            detail: format!("path={} detail={error}", path.display()),
        }),
        super::state::ReviewRunStateLoad::Ambiguous { dir, candidates } => Some(ProjectionError {
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            event: "ambiguous-state".to_string(),
            review_type: review_type.to_string(),
            seq: 0,
            detail: format!(
                "dir={} candidates={}",
                dir.display(),
                candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }),
        super::state::ReviewRunStateLoad::Missing { path } => Some(ProjectionError {
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            event: "no-run-state".to_string(),
            review_type: review_type.to_string(),
            seq: 0,
            detail: format!("path={}", path.display()),
        }),
        super::state::ReviewRunStateLoad::Present(_) => None,
    }
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
    let projection_filter = ReviewerProjectionFilter::new(pr_number)
        .with_head_sha(normalized_head.as_deref())
        .with_since_epoch(since_epoch)
        .with_max_events(400);
    let mut telemetry_error: Option<ReviewerTelemetryError> = None;
    let mut telemetry_event_count = 0_usize;
    let mut events = match read_reviewer_projection_events(
        &super::events::review_events_path()?,
        &projection_filter,
    ) {
        Ok(parsed) => {
            telemetry_event_count = match parsed.health {
                apm2_daemon::telemetry::reviewer::ReviewerTelemetryHealth::Present {
                    lifecycle_events,
                } => lifecycle_events,
                apm2_daemon::telemetry::reviewer::ReviewerTelemetryHealth::Missing
                | apm2_daemon::telemetry::reviewer::ReviewerTelemetryHealth::Malformed => 0,
            };
            parsed.events.into_iter().map(|entry| entry.raw).collect()
        },
        Err(
            err @ (ReviewerTelemetryError::Missing { .. }
            | ReviewerTelemetryError::Malformed { .. }),
        ) => {
            telemetry_error = Some(err);
            Vec::new()
        },
        Err(err) => return Err(err.to_string()),
    };
    events.sort_by_key(event_seq);

    let mut security_load = load_review_run_state(pr_number, "security")?;
    let mut quality_load = load_review_run_state(pr_number, "quality")?;
    if let Some(head) = normalized_head.as_deref() {
        if let ReviewRunStateLoad::Present(state) = &security_load {
            if !state.head_sha.eq_ignore_ascii_case(head) {
                security_load = ReviewRunStateLoad::Missing {
                    path: review_run_state_path(pr_number, "security")?,
                };
            }
        }
        if let ReviewRunStateLoad::Present(state) = &quality_load {
            if !state.head_sha.eq_ignore_ascii_case(head) {
                quality_load = ReviewRunStateLoad::Missing {
                    path: review_run_state_path(pr_number, "quality")?,
                };
            }
        }
    }
    let security = render_state_code_from_run_state(&security_load, since_epoch);
    let quality = render_state_code_from_run_state(&quality_load, since_epoch);

    let latest_run_state_head = [&security_load, &quality_load]
        .into_iter()
        .filter_map(|load| match load {
            super::state::ReviewRunStateLoad::Present(state)
                if !run_state_is_stale_for_dispatch(state, since_epoch) =>
            {
                Some((state.sequence_number, state.head_sha.clone()))
            },
            _ => None,
        })
        .max_by_key(|(sequence, _)| *sequence)
        .map(|(_, head_sha)| head_sha);

    let sha = normalized_head.as_ref().map_or_else(
        || {
            latest_run_state_head
                .clone()
                .or_else(|| latest_event_head_sha(&events))
                .or_else(|| latest_state_head_sha(&state, pr_number))
                .or_else(|| latest_pulse_head_sha(pr_number))
                .unwrap_or_else(|| "-".to_string())
        },
        Clone::clone,
    );
    let current_head_sha = latest_pulse_head_sha(pr_number)
        .or(latest_run_state_head)
        .or_else(|| latest_event_head_sha(&events))
        .or_else(|| latest_state_head_sha(&state, pr_number))
        .unwrap_or_else(|| sha.clone());

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
    if let Some(error) = run_state_error(&security_load, "security") {
        errors.push(error);
    }
    if let Some(error) = run_state_error(&quality_load, "quality") {
        errors.push(error);
    }
    let mut terminal_failure = matches!(
        security.as_str(),
        "no-run-state" | "corrupt-state" | "ambiguous-state"
    ) || matches!(
        quality.as_str(),
        "no-run-state" | "corrupt-state" | "ambiguous-state"
    );
    let attempting_authoritative_progression = projection_state_done(&security)
        || projection_state_done(&quality)
        || projection_state_failed(&security)
        || projection_state_failed(&quality)
        || run_state_is_terminal(&security_load)
        || run_state_is_terminal(&quality_load);
    if let Some(err) = telemetry_error.as_ref() {
        errors.push(telemetry_projection_error(err));
        if attempting_authoritative_progression {
            terminal_failure = true;
        }
    } else if telemetry_event_count == 0 && attempting_authoritative_progression {
        errors.push(ProjectionError {
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            event: "telemetry_missing".to_string(),
            review_type: "-".to_string(),
            seq: 0,
            detail: "no lifecycle telemetry events for authoritative projection".to_string(),
        });
        terminal_failure = true;
    }
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
            "run_crash" | "stall_detected" | "model_fallback" | "sha_update" | "sha_drift"
        ) {
            continue;
        }

        let detail = event
            .get("reason_code")
            .or_else(|| event.get("reason"))
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

    let line = ProjectionSummary::from_projection(
        sha.clone(),
        current_head_sha.clone(),
        security.clone(),
        quality.clone(),
        recent_events.clone(),
    )
    .render_line();

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
const GATE_STATUS_SCHEMA: &str = "apm2.gate_status.v1";
const MAX_PREVIOUS_GATE_STATUSES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct GateResult {
    pub name: String,
    pub passed: bool,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShaGateStatus {
    sha: String,
    short_sha: String,
    timestamp: String,
    gates: Vec<GateResult>,
    all_passed: bool,
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
    let _ = writeln!(
        out,
        "<summary>Previous SHA <code>{}</code> at {}</summary>\n",
        status.short_sha, status.timestamp
    );
    out.push_str(&render_gate_table(status));
    out.push('\n');
    out.push_str(&render_status_metadata_block(status));
    out.push_str("\n</details>\n");
    out
}

fn render_gate_status_section(
    latest: &ShaGateStatus,
    previous: &[ShaGateStatus],
) -> Result<String, String> {
    validate_expected_head_sha(&latest.sha)?;
    let mut out = String::new();
    out.push_str("## FAC Gate Status\n\n");
    let _ = writeln!(
        out,
        "Current SHA `<{}>` recorded at {}.\n",
        latest.short_sha, latest.timestamp
    );
    out.push_str(&render_gate_table(latest));
    out.push('\n');
    out.push_str(&render_status_metadata_block(latest));
    out.push('\n');

    for status in previous.iter().take(MAX_PREVIOUS_GATE_STATUSES) {
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
    let latest = ShaGateStatus {
        short_sha: sha.chars().take(8).collect(),
        timestamp: now_iso8601(),
        all_passed: gate_results.iter().all(|gate| gate.passed),
        gates: gate_results,
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
