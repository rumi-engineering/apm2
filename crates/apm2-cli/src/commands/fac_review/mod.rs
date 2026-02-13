//! FAC review orchestration commands.
//!
//! This module provides VPS-oriented, FAC-first review execution with:
//! - Security/quality orchestration (parallel when `--type all`)
//! - Multi-model backend dispatch (Codex + Gemini)
//! - NDJSON lifecycle telemetry under `~/.apm2/review_events.ndjson`
//! - Pulse-file based SHA freshness checks and resume flow
//! - Liveness-based stall detection and bounded model fallback
//! - Idempotent detached dispatch + projection snapshots for GitHub surfaces
//! - Intelligent pipeline restart (`apm2 fac restart`) with CI state analysis

mod backend;
mod barrier;
mod ci_status;
mod comment;
mod decision;
mod detection;
mod dispatch;
mod events;
mod evidence;
mod findings;
mod gate_attestation;
mod gate_cache;
mod gates;
mod github_projection;
mod liveness;
mod logs;
mod merge_conflicts;
mod model_pool;
mod orchestrator;
mod pipeline;
mod pr_body;
mod prepare;
mod projection;
mod projection_store;
mod publish;
mod push;
mod restart;
mod selector;
mod state;
mod target;
mod timeout_policy;
mod types;
mod worktree;

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

// Re-export public API for use by `fac.rs`
pub use comment::{ReviewCommentSeverityArg, ReviewCommentTypeArg};
pub use decision::DecisionValueArg;
use dispatch::dispatch_single_review_with_force;
use events::{read_last_event_values, review_events_path};
use projection::{projection_state_done, projection_state_failed, run_project_inner};
pub use publish::ReviewPublishTypeArg;
use state::{
    list_review_pr_numbers, load_review_run_state, read_pulse_file, review_run_state_path,
};
pub use types::ReviewRunType;
use types::{
    DispatchSummary, ProjectionStatus, ReviewKind, TERMINATE_TIMEOUT, parse_pr_url,
    validate_expected_head_sha,
};

use crate::exit_codes::codes as exit_codes;

// ── Process management helpers (used by orchestrator) ───────────────────────

fn terminate_child(child: &mut Child) -> Result<(), String> {
    let pid = child.id();
    let term_status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .map_err(|err| format!("failed to send SIGTERM to {pid}: {err}"))?;
    if !term_status.success() {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(());
    }

    let start = Instant::now();
    while start.elapsed() < TERMINATE_TIMEOUT {
        if child
            .try_wait()
            .map_err(|err| format!("failed while waiting for pid {pid}: {err}"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

fn exit_signal(status: std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn emit_run_ndjson_since(
    offset: u64,
    pr_number: u32,
    run_ids: &[String],
    to_stderr: bool,
) -> Result<(), String> {
    let path = review_events_path()?;
    if !path.exists() {
        return Ok(());
    }
    let mut file =
        File::open(&path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| format!("failed to seek {}: {err}", path.display()))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;

    for line in buf.lines() {
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let matches_pr = parsed
            .get("pr_number")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|value| value == u64::from(pr_number));
        if !matches_pr {
            continue;
        }
        let is_sequence_done = parsed
            .get("event")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|event| event == "sequence_done");
        if run_ids.is_empty() || is_sequence_done {
            if to_stderr {
                eprintln!("{line}");
            } else {
                println!("{line}");
            }
            continue;
        }
        let run_id = parsed.get("run_id").and_then(serde_json::Value::as_str);
        if run_id.is_some_and(|id| run_ids.iter().any(|candidate| candidate == id)) {
            if to_stderr {
                eprintln!("{line}");
            } else {
                println!("{line}");
            }
        }
    }
    Ok(())
}

// ── Public entry points ─────────────────────────────────────────────────────

pub fn run_review(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    force: bool,
    json_output: bool,
) -> u8 {
    let event_offset = review_events_path()
        .ok()
        .and_then(|path| fs::metadata(path).ok().map(|meta| meta.len()))
        .unwrap_or(0);

    match orchestrator::run_review_inner(pr_url, review_type, expected_head_sha, force) {
        Ok(summary) => {
            let success = summary.security.as_ref().is_none_or(|entry| entry.success)
                && summary.quality.as_ref().is_none_or(|entry| entry.success);

            if json_output {
                let mut run_ids = Vec::new();
                if let Some(entry) = &summary.security {
                    run_ids.push(entry.run_id.clone());
                }
                if let Some(entry) = &summary.quality {
                    run_ids.push(entry.run_id.clone());
                }
                let _ = emit_run_ndjson_since(event_offset, summary.pr_number, &run_ids, true);
                let payload = serde_json::json!({
                    "schema": "apm2.fac.review.run.v1",
                    "summary": summary,
                });
                println!(
                    "{}",
                    serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Review");
                println!("  PR:           {}", summary.pr_url);
                println!("  PR Number:    {}", summary.pr_number);
                println!("  Head (start): {}", summary.initial_head_sha);
                println!("  Head (final): {}", summary.final_head_sha);
                println!("  Total secs:   {}", summary.total_secs);
                if let Some(security) = &summary.security {
                    let tok = security
                        .tokens_used
                        .map_or_else(String::new, |n| format!(", tokens={n}"));
                    println!(
                        "  Security:     {} (run_id={}, state={}, verdict={}, model={}, backend={}, restarts={}, secs={}{tok})",
                        if security.success { "PASS" } else { "FAIL" },
                        security.run_id,
                        security.state,
                        security.verdict,
                        security.model,
                        security.backend,
                        security.restart_count,
                        security.duration_secs
                    );
                    if let Some(reason) = &security.terminal_reason {
                        println!("                 terminal_reason={reason}");
                    }
                }
                if let Some(quality) = &summary.quality {
                    let tok = quality
                        .tokens_used
                        .map_or_else(String::new, |n| format!(", tokens={n}"));
                    println!(
                        "  Quality:      {} (run_id={}, state={}, verdict={}, model={}, backend={}, restarts={}, secs={}{tok})",
                        if quality.success { "PASS" } else { "FAIL" },
                        quality.run_id,
                        quality.state,
                        quality.verdict,
                        quality.model,
                        quality.backend,
                        quality.restart_count,
                        quality.duration_secs
                    );
                    if let Some(reason) = &quality.terminal_reason {
                        println!("                 terminal_reason={reason}");
                    }
                }
            }

            if success {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_run_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_dispatch(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    force: bool,
    json_output: bool,
) -> u8 {
    match run_dispatch_inner(pr_url, review_type, expected_head_sha, force) {
        Ok(summary) => {
            if json_output {
                let payload = serde_json::json!({
                    "schema": "apm2.fac.review.dispatch.v1",
                    "summary": summary,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Review Dispatch");
                println!("  PR:            {}", summary.pr_url);
                println!("  PR Number:     {}", summary.pr_number);
                println!("  Head SHA:      {}", summary.head_sha);
                println!("  Dispatch Epoch:{}", summary.dispatch_epoch);
                for result in &summary.results {
                    println!(
                        "  - type={} mode={} state={} run_id={} seq={} terminal_reason={}",
                        result.review_type,
                        result.mode,
                        result.run_state,
                        result.run_id.as_deref().unwrap_or("-"),
                        result
                            .sequence_number
                            .map_or_else(|| "-".to_string(), |value| value.to_string()),
                        result.terminal_reason.as_deref().unwrap_or("-"),
                    );
                }
            }
            exit_codes::SUCCESS
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_dispatch_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_status(
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    review_type_filter: Option<&str>,
    json_output: bool,
) -> u8 {
    match run_status_inner(pr_number, pr_url, review_type_filter, json_output) {
        Ok(fail_closed) => {
            if fail_closed {
                exit_codes::GENERIC_ERROR
            } else {
                exit_codes::SUCCESS
            }
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_status_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_wait(
    pr_number: u32,
    pr_url: Option<&str>,
    review_type_filter: Option<&str>,
    wait_for_sha: Option<&str>,
    timeout_seconds: Option<u64>,
    poll_interval_seconds: u64,
    json_output: bool,
) -> u8 {
    let max_interval = poll_interval_seconds.max(1);
    let poll_interval = Duration::from_secs(max_interval);
    match run_wait_inner(
        pr_number,
        pr_url,
        review_type_filter,
        wait_for_sha,
        timeout_seconds.map(Duration::from_secs),
        poll_interval,
    ) {
        Ok((status, attempts, elapsed)) => {
            let elapsed_seconds = elapsed.as_secs();
            let has_failed = status.terminal_failure
                || review_types_terminal_failed(&status, review_type_filter);
            if json_output {
                let payload = serde_json::json!({
                    "schema": "apm2.fac.review.wait.v1",
                    "status": "completed",
                    "filter_pr": pr_number,
                    "filter_review_type": review_type_filter,
                    "wait_for_sha": wait_for_sha,
                    "attempts": attempts,
                    "elapsed_seconds": elapsed_seconds,
                    "poll_interval_seconds": max_interval,
                    "project": status,
                    "fail_closed": has_failed,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                println!("FAC Review Wait");
                println!("  Filter PR: #{pr_number}");
                if let Some(review_type) = review_type_filter {
                    println!("  Filter Type: {review_type}");
                }
                if let Some(wait_sha) = wait_for_sha {
                    println!("  Wait SHA: {wait_sha}");
                }
                println!("  Poll Interval: {max_interval}s");
                println!("  Attempts: {attempts}");
                println!("  Elapsed: {elapsed_seconds}s");
                println!("  Final: {}", status.line);
                println!("  Fail Closed: {}", if has_failed { "yes" } else { "no" });
                if !status.errors.is_empty() {
                    println!("  Errors:");
                    for error in &status.errors {
                        println!(
                            "    ts={} event={} review={} seq={} detail={}",
                            error.ts, error.event, error.review_type, error.seq, error.detail
                        );
                    }
                }
            }

            if has_failed {
                exit_codes::GENERIC_ERROR
            } else {
                exit_codes::SUCCESS
            }
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_wait_failed",
                    "message": err,
                    "filter_pr": pr_number,
                    "filter_review_type": review_type_filter,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_findings(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    refresh: bool,
    json_output: bool,
) -> u8 {
    match findings::run_findings(repo, pr_number, pr_url, sha, refresh, json_output) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_findings_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_prepare(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    json_output: bool,
) -> u8 {
    match prepare::run_prepare(repo, pr_number, pr_url, sha, json_output) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_prepare_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_publish(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    review_type: ReviewPublishTypeArg,
    body_file: &Path,
    json_output: bool,
) -> u8 {
    match publish::run_publish(
        repo,
        pr_number,
        pr_url,
        sha,
        review_type,
        body_file,
        json_output,
    ) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_publish_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_comment(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    severity: ReviewCommentSeverityArg,
    review_type: ReviewCommentTypeArg,
    body: Option<&str>,
    json_output: bool,
) -> u8 {
    match comment::run_comment(
        repo,
        pr_number,
        pr_url,
        sha,
        severity,
        review_type,
        body,
        json_output,
    ) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_comment_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_decision_set(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    dimension: &str,
    decision: DecisionValueArg,
    reason: Option<&str>,
    keep_prepared_inputs: bool,
    json_output: bool,
) -> u8 {
    match decision::run_decision_set(
        repo,
        pr_number,
        pr_url,
        sha,
        dimension,
        decision,
        reason,
        keep_prepared_inputs,
        json_output,
    ) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_decision_set_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_decision_show(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    json_output: bool,
) -> u8 {
    match decision::run_decision_show(repo, pr_number, pr_url, sha, json_output) {
        Ok(code) => code,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_decision_show_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub fn run_project(
    pr_number: u32,
    head_sha: Option<&str>,
    since_epoch: Option<u64>,
    after_seq: u64,
    emit_errors: bool,
    fail_on_terminal: bool,
    format_json: bool,
    json_output: bool,
) -> u8 {
    match run_project_inner(pr_number, head_sha, since_epoch, after_seq) {
        Ok(status) => {
            if json_output || format_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("{}", status.line);
                if emit_errors {
                    for error in &status.errors {
                        println!(
                            "ERROR ts={} event={} review={} seq={} detail={}",
                            error.ts, error.event, error.review_type, error.seq, error.detail
                        );
                    }
                }
            }

            if fail_on_terminal && status.terminal_failure {
                exit_codes::GENERIC_ERROR
            } else {
                exit_codes::SUCCESS
            }
        },
        Err(err) => {
            if json_output || format_json {
                let payload = serde_json::json!({
                    "schema": "apm2.fac.review.project.v1",
                    "status": "unavailable",
                    "error": "fac_review_project_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("WARN: fac review project unavailable: {err}");
            }
            // Projection is a debug/observability surface; do not fail callers by default.
            exit_codes::SUCCESS
        },
    }
}

fn review_type_filter_vec(review_type_filter: Option<&str>) -> Result<Vec<String>, String> {
    review_type_filter.map_or_else(
        || Ok(vec!["security".to_string(), "quality".to_string()]),
        |value| {
            let normalized = value.trim().to_ascii_lowercase();
            if matches!(normalized.as_str(), "security" | "quality") {
                Ok(vec![normalized])
            } else {
                Err(format!(
                    "invalid review type filter `{value}` (expected security|quality)"
                ))
            }
        },
    )
}

fn run_wait_inner(
    pr_number: u32,
    pr_url: Option<&str>,
    review_type_filter: Option<&str>,
    wait_for_sha: Option<&str>,
    timeout: Option<Duration>,
    poll_interval: Duration,
) -> Result<(ProjectionStatus, u64, Duration), String> {
    if let Some(url) = pr_url {
        let (_, url_pr_number) = parse_pr_url(url)?;
        if url_pr_number != pr_number {
            return Err(format!(
                "wait filters disagree: --pr={pr_number} but --pr-url resolves to #{url_pr_number}"
            ));
        }
    }

    if let Some(expected_sha) = wait_for_sha {
        validate_expected_head_sha(expected_sha)?;
    }

    let start = Instant::now();
    let mut attempts = 0_u64;
    let mut last_status = run_project_inner(pr_number, wait_for_sha, None, 0)?;
    if let Some(expected_head) = wait_for_sha {
        if !last_status
            .current_head_sha
            .eq_ignore_ascii_case(expected_head)
        {
            return Err(format!(
                "stale projection for PR #{pr_number}: expected head {expected_head}, observed {}",
                last_status.current_head_sha
            ));
        }
    }
    if review_types_all_terminal(&last_status, review_type_filter)? {
        return Ok((last_status, attempts, start.elapsed()));
    }

    loop {
        attempts = attempts.saturating_add(1);
        if let Some(timeout) = timeout {
            if start.elapsed() >= timeout {
                return Err(format!(
                    "timed out waiting for PR #{pr_number} review completion after {timeout:?}"
                ));
            }
        }

        thread::sleep(poll_interval);
        last_status = run_project_inner(pr_number, wait_for_sha, None, 0)?;
        if let Some(expected_head) = wait_for_sha {
            if !last_status
                .current_head_sha
                .eq_ignore_ascii_case(expected_head)
            {
                return Err(format!(
                    "stale projection for PR #{pr_number}: expected head {expected_head}, observed {}",
                    last_status.current_head_sha
                ));
            }
        }
        if review_types_all_terminal(&last_status, review_type_filter)? {
            return Ok((last_status, attempts, start.elapsed()));
        }
    }
}

fn review_type_state<'a>(
    status: &'a ProjectionStatus,
    review_type: &str,
) -> Result<&'a str, String> {
    match review_type {
        "security" => Ok(status.security.as_str()),
        "quality" => Ok(status.quality.as_str()),
        other => Err(format!(
            "invalid review type `{other}` (expected security|quality)"
        )),
    }
}

fn review_types_terminal_done(status: &ProjectionStatus, review_type_filter: Option<&str>) -> bool {
    let Ok(review_types) = review_type_filter_vec(review_type_filter) else {
        return false;
    };
    review_types
        .iter()
        .all(|value| review_type_state(status, value).is_ok_and(projection_state_done))
}

fn review_types_terminal_failed(
    status: &ProjectionStatus,
    review_type_filter: Option<&str>,
) -> bool {
    let Ok(review_types) = review_type_filter_vec(review_type_filter) else {
        return false;
    };
    if !review_types_terminal_done(status, review_type_filter) {
        return false;
    }
    for value in &review_types {
        if let Ok(state) = review_type_state(status, value)
            && projection_state_failed(state)
        {
            return true;
        }
    }
    false
}

fn review_types_all_terminal(
    status: &ProjectionStatus,
    review_type_filter: Option<&str>,
) -> Result<bool, String> {
    let review_types = review_type_filter_vec(review_type_filter)?;
    if review_types.is_empty() {
        return Ok(false);
    }
    for value in &review_types {
        let state = review_type_state(status, value)?;
        if !projection_state_done(state) && !projection_state_failed(state) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn run_tail(lines: usize, follow: bool) -> u8 {
    match run_tail_inner(lines, follow) {
        Ok(()) => exit_codes::SUCCESS,
        Err(err) => {
            eprintln!("ERROR: {err}");
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_terminate(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    review_type: &str,
    json_output: bool,
) -> u8 {
    match run_terminate_inner(repo, pr_number, pr_url, review_type, json_output) {
        Ok(()) => exit_codes::SUCCESS,
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "terminate_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_terminate_inner(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    review_type: &str,
    json_output: bool,
) -> Result<(), String> {
    let (owner_repo, resolved_pr) = target::resolve_pr_target(repo, pr_number, pr_url)?;
    let state_opt = state::load_review_run_state_strict(resolved_pr, review_type)?;

    let Some(mut run_state) = state_opt else {
        let msg = format!("no active reviewer for PR #{resolved_pr} type={review_type}");
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "no_active_reviewer",
                    "pr_number": resolved_pr,
                    "review_type": review_type,
                    "message": msg,
                }))
                .unwrap_or_default()
            );
        } else {
            eprintln!("{msg}");
        }
        return Ok(());
    };

    if run_state.status.is_terminal() {
        let msg = format!(
            "reviewer already terminal for PR #{resolved_pr} type={review_type} status={} reason={}",
            run_state.status.as_str(),
            run_state.terminal_reason.as_deref().unwrap_or("none"),
        );
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "already_terminal",
                    "pr_number": resolved_pr,
                    "review_type": review_type,
                    "run_status": run_state.status.as_str(),
                    "terminal_reason": run_state.terminal_reason,
                    "message": msg,
                }))
                .unwrap_or_default()
            );
        } else {
            eprintln!("{msg}");
        }
        return Ok(());
    }

    let Some(state_repo) = state::extract_repo_from_pr_url(&run_state.pr_url) else {
        let msg = format!(
            "repo mismatch guard skipped termination for PR #{resolved_pr} type={review_type}: unable to parse owner/repo from run-state pr_url {}",
            run_state.pr_url
        );
        eprintln!("WARNING: {msg}");
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "repo_mismatch",
                    "pr_number": resolved_pr,
                    "review_type": review_type,
                    "message": msg,
                }))
                .unwrap_or_default()
            );
        }
        return Err(msg);
    };
    if !state_repo.eq_ignore_ascii_case(owner_repo.as_str()) {
        let msg = format!(
            "repo mismatch guard skipped termination for PR #{resolved_pr} type={review_type}: run-state repo={state_repo} requested repo={owner_repo}"
        );
        eprintln!("WARNING: {msg}");
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "repo_mismatch",
                    "pr_number": resolved_pr,
                    "review_type": review_type,
                    "run_state_repo": state_repo,
                    "requested_repo": owner_repo,
                    "message": msg,
                }))
                .unwrap_or_default()
            );
        }
        return Err(msg);
    }

    if run_state.status == types::ReviewRunStatus::Alive && run_state.pid.is_none() {
        return Err(
            "cannot terminate: run state is Alive but PID is missing - operator must investigate."
                .to_string(),
        );
    }

    let mut killed = false;
    if let Some(pid) = run_state.pid {
        if state::is_process_alive(pid) {
            dispatch::verify_process_identity(pid, run_state.proc_start_time)?;
            dispatch::terminate_process_with_timeout(pid)?;
            killed = true;
        }
    }

    run_state.status = types::ReviewRunStatus::Failed;
    run_state.terminal_reason = Some("manual_termination".to_string());
    state::write_review_run_state(&run_state)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "terminated",
                "pr_number": resolved_pr,
                "review_type": review_type,
                "run_id": run_state.run_id,
                "pid": run_state.pid,
                "process_killed": killed,
            }))
            .unwrap_or_default()
        );
    } else {
        let pid_info = run_state
            .pid
            .map_or_else(|| "no-pid".to_string(), |p| p.to_string());
        eprintln!(
            "terminated reviewer PR #{resolved_pr} type={review_type} \
             run_id={} pid={pid_info} killed={killed}",
            run_state.run_id
        );
    }

    Ok(())
}

pub fn run_push(repo: &str, remote: &str, branch: Option<&str>, ticket: Option<&Path>) -> u8 {
    push::run_push(repo, remote, branch, ticket)
}

pub fn run_restart(
    repo: &str,
    pr: Option<u32>,
    pr_url: Option<&str>,
    force: bool,
    json_output: bool,
) -> u8 {
    restart::run_restart(repo, pr, pr_url, force, json_output)
}

pub fn run_pipeline(repo: &str, pr_url: &str, pr_number: u32, sha: &str) -> u8 {
    pipeline::run_pipeline(repo, pr_url, pr_number, sha)
}

pub fn run_logs(
    pr_number: Option<u32>,
    repo: &str,
    selector_type: Option<&str>,
    selector: Option<&str>,
    json_output: bool,
) -> u8 {
    logs::run_logs(pr_number, repo, selector_type, selector, json_output)
}

pub fn run_gates(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    json_output: bool,
) -> u8 {
    gates::run_gates(
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        json_output,
    )
}

// ── Internal dispatch helper (shared with pipeline/restart) ─────────────────

fn run_dispatch_inner(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    force: bool,
) -> Result<DispatchSummary, String> {
    let (owner_repo, pr_number) = parse_pr_url(pr_url)?;
    let current_head_sha =
        if let Some(identity) = projection_store::load_pr_identity(&owner_repo, pr_number)? {
            validate_expected_head_sha(&identity.head_sha)?;
            identity.head_sha.to_ascii_lowercase()
        } else if projection_store::gh_read_fallback_enabled() {
            let value = barrier::fetch_pr_head_sha(&owner_repo, pr_number)?;
            validate_expected_head_sha(&value)?;
            let value = value.to_ascii_lowercase();
            let _ = projection_store::record_fallback_read(
                &owner_repo,
                pr_number,
                "dispatch.resolve_head_sha",
            );
            let _ = projection_store::save_identity_with_context(
                &owner_repo,
                pr_number,
                &value,
                "gh-fallback:dispatch.resolve_head_sha",
            );
            value
        } else {
            return Err(projection_store::gh_read_fallback_disabled_error(
                "dispatch.resolve_head_sha",
            ));
        };
    if let Some(expected) = expected_head_sha {
        validate_expected_head_sha(expected)?;
        if !expected.eq_ignore_ascii_case(&current_head_sha) {
            return Err(format!(
                "PR head moved before review dispatch: expected {expected}, got {current_head_sha}"
            ));
        }
    }
    let dispatch_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    let kinds = match review_type {
        ReviewRunType::All => vec![ReviewKind::Security, ReviewKind::Quality],
        ReviewRunType::Security => vec![ReviewKind::Security],
        ReviewRunType::Quality => vec![ReviewKind::Quality],
    };

    let mut results = Vec::with_capacity(kinds.len());
    for kind in kinds {
        let result = dispatch_single_review_with_force(
            pr_url,
            &owner_repo,
            pr_number,
            kind,
            &current_head_sha,
            dispatch_epoch,
            force,
        )?;
        results.push(result);
    }

    Ok(DispatchSummary {
        pr_url: pr_url.to_string(),
        pr_number,
        head_sha: current_head_sha,
        dispatch_epoch,
        results,
    })
}

// ── Status / Tail ───────────────────────────────────────────────────────────

fn run_status_inner(
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    review_type_filter: Option<&str>,
    json_output: bool,
) -> Result<bool, String> {
    let normalized_review_type = review_type_filter.map(|value| value.trim().to_ascii_lowercase());
    if let Some(value) = normalized_review_type.as_deref() {
        if !matches!(value, "security" | "quality") {
            return Err(format!(
                "invalid review type filter `{value}` (expected security|quality)"
            ));
        }
    }

    let derived_pr = if let Some(url) = pr_url {
        let (_, number) = parse_pr_url(url)?;
        Some(number)
    } else {
        None
    };
    let filter_pr = match (pr_number, derived_pr) {
        (Some(a), Some(b)) if a != b => {
            return Err(format!(
                "status filters disagree: --pr={a} but --pr-url resolves to #{b}"
            ));
        },
        (Some(a), _) => Some(a),
        (_, Some(b)) => Some(b),
        (None, None) => None,
    };

    let target_prs = if let Some(number) = filter_pr {
        vec![number]
    } else {
        list_review_pr_numbers()?
    };
    let review_types = normalized_review_type
        .as_deref()
        .map_or_else(|| vec!["security", "quality"], |value| vec![value]);

    let mut entries = Vec::new();
    let mut fail_closed = false;
    for pr in &target_prs {
        for review_type in &review_types {
            let state_path = review_run_state_path(*pr, review_type)?;
            match load_review_run_state(*pr, review_type)? {
                state::ReviewRunStateLoad::Present(state) => {
                    entries.push(serde_json::json!({
                        "pr_number": pr,
                        "review_type": review_type,
                        "state": state.status.as_str(),
                        "run_id": state.run_id,
                        "sequence_number": state.sequence_number,
                        "pr_url": state.pr_url,
                        "head_sha": state.head_sha,
                        "started_at": state.started_at,
                        "model_id": state.model_id,
                        "backend_id": state.backend_id,
                        "restart_count": state.restart_count,
                        "terminal_reason": state.terminal_reason,
                        "state_path": state_path.display().to_string(),
                    }));
                },
                state::ReviewRunStateLoad::Missing { path } => {
                    if filter_pr.is_some() {
                        fail_closed = true;
                    }
                    entries.push(serde_json::json!({
                        "pr_number": pr,
                        "review_type": review_type,
                        "state": "no-run-state",
                        "state_path": path.display().to_string(),
                    }));
                },
                state::ReviewRunStateLoad::Corrupt { path, error } => {
                    fail_closed = true;
                    entries.push(serde_json::json!({
                        "pr_number": pr,
                        "review_type": review_type,
                        "state": "corrupt-state",
                        "state_path": path.display().to_string(),
                        "detail": error,
                    }));
                },
                state::ReviewRunStateLoad::Ambiguous { dir, candidates } => {
                    fail_closed = true;
                    entries.push(serde_json::json!({
                        "pr_number": pr,
                        "review_type": review_type,
                        "state": "ambiguous-state",
                        "state_dir": dir.display().to_string(),
                        "candidates": candidates
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect::<Vec<_>>(),
                    }));
                },
            }
        }
    }

    let filtered_events = read_last_event_values(40)?
        .into_iter()
        .filter(|event| {
            filter_pr.is_none_or(|number| {
                event
                    .get("pr_number")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|value| value == u64::from(number))
            }) && normalized_review_type.as_deref().is_none_or(|wanted| {
                event
                    .get("review_type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| {
                        value.eq_ignore_ascii_case(wanted) || value.eq_ignore_ascii_case("all")
                    })
            })
        })
        .collect::<Vec<_>>();

    let pulse_security = if let Some(number) = filter_pr {
        if normalized_review_type
            .as_deref()
            .is_some_and(|value| value != "security")
        {
            None
        } else {
            read_pulse_file(number, "security")?
        }
    } else {
        None
    };
    let pulse_quality = if let Some(number) = filter_pr {
        if normalized_review_type
            .as_deref()
            .is_some_and(|value| value != "quality")
        {
            None
        } else {
            read_pulse_file(number, "quality")?
        }
    } else {
        None
    };

    let current_head_sha = filter_pr.and_then(|number| {
        entries
            .iter()
            .filter(|entry| {
                entry
                    .get("pr_number")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|value| value == u64::from(number))
            })
            .filter_map(|entry| entry.get("head_sha").and_then(serde_json::Value::as_str))
            .find(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                pulse_security
                    .as_ref()
                    .map(|pulse| pulse.head_sha.clone())
                    .or_else(|| pulse_quality.as_ref().map(|pulse| pulse.head_sha.clone()))
            })
    });

    if json_output {
        let payload = serde_json::json!({
            "schema": "apm2.fac.review.status.v1",
            "filter_pr": filter_pr,
            "filter_review_type": normalized_review_type,
            "fail_closed": fail_closed,
            "entries": entries,
            "recent_events": filtered_events,
            "pulse_security": pulse_security,
            "pulse_quality": pulse_quality,
            "current_head_sha": current_head_sha,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
        return Ok(fail_closed);
    }

    println!("FAC Review Status");
    if let Some(number) = filter_pr {
        println!("  Filter PR: #{number}");
        if let Some(review_type) = normalized_review_type.as_deref() {
            println!("  Filter Type: {review_type}");
        }
        println!(
            "  Current Head SHA: {}",
            current_head_sha.as_deref().unwrap_or("-")
        );
    }
    if entries.is_empty() {
        println!("  Run State: no-run-state");
    } else {
        println!("  Run States:");
        for entry in &entries {
            println!(
                "    - pr=#{} type={} state={} run_id={} seq={} head_sha={} terminal_reason={}",
                entry["pr_number"].as_u64().unwrap_or(0),
                entry["review_type"].as_str().unwrap_or("-"),
                entry["state"].as_str().unwrap_or("-"),
                entry["run_id"].as_str().unwrap_or("-"),
                entry["sequence_number"].as_u64().unwrap_or(0),
                entry["head_sha"].as_str().unwrap_or("-"),
                entry["terminal_reason"].as_str().unwrap_or("-"),
            );
        }
    }

    println!("  Recent Events:");
    if filtered_events.is_empty() {
        println!("    (none)");
    } else {
        for event in filtered_events.iter().rev().take(20).rev() {
            println!(
                "    [{}] {} {} pr=#{} run_id={} event_sha={}",
                event["ts"].as_str().unwrap_or("-"),
                event["event"].as_str().unwrap_or("-"),
                event["review_type"].as_str().unwrap_or("-"),
                event["pr_number"].as_u64().unwrap_or(0),
                event["run_id"].as_str().unwrap_or("-"),
                event["head_sha"].as_str().unwrap_or("-"),
            );
        }
    }
    println!("  Pulse Files:");
    if filter_pr.is_none() {
        println!("    (set --pr or --pr-url to inspect PR-scoped pulse files)");
    } else if let Some(review_type) = normalized_review_type.as_deref() {
        let value = if review_type == "security" {
            pulse_security
                .as_ref()
                .map_or_else(|| "missing".to_string(), |pulse| pulse.head_sha.clone())
        } else {
            pulse_quality
                .as_ref()
                .map_or_else(|| "missing".to_string(), |pulse| pulse.head_sha.clone())
        };
        println!("    {review_type}: {value}");
    } else {
        println!(
            "    security: {}",
            pulse_security
                .as_ref()
                .map_or_else(|| "missing".to_string(), |pulse| pulse.head_sha.clone())
        );
        println!(
            "    quality:  {}",
            pulse_quality
                .as_ref()
                .map_or_else(|| "missing".to_string(), |pulse| pulse.head_sha.clone())
        );
    }
    println!("  Fail Closed: {}", if fail_closed { "yes" } else { "no" });

    Ok(fail_closed)
}

fn run_tail_inner(lines: usize, follow: bool) -> Result<(), String> {
    let path = review_events_path()?;
    if !path.exists() {
        return Err(format!("event stream not found at {}", path.display()));
    }

    let last_lines = state::read_last_lines(&path, lines)?;
    for line in &last_lines {
        println!("{line}");
    }

    if !follow {
        return Ok(());
    }

    let mut offset = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
    loop {
        thread::sleep(Duration::from_secs(1));
        let len = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        if len < offset {
            offset = len;
        }
        if len == offset {
            continue;
        }
        let mut file =
            File::open(&path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| format!("failed to seek {}: {err}", path.display()))?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        print!("{buf}");
        let _ = std::io::stdout().flush();
        offset = len;
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    use chrono::Utc;

    use super::backend::{build_gemini_script_command, build_script_command_for_backend};
    use super::barrier::{
        build_barrier_decision_event, is_allowed_author_association, read_event_payload_bounded,
    };
    use super::detection::{
        detect_comment_permission_denied, detect_http_400_or_rate_limit,
        extract_verdict_from_comment_body,
    };
    use super::events::emit_review_event_to_path;
    use super::model_pool::{MODEL_POOL, select_fallback_model, select_review_model_random};
    use super::projection::{
        apply_sequence_done_fallback, event_is_terminal_crash, latest_event_head_sha,
        latest_state_head_sha, projection_state_done, projection_state_failed,
        projection_state_for_type, resolve_current_head_sha, resolve_projection_sha,
    };
    use super::state::{read_last_lines, read_pulse_file_from_path, write_pulse_file_to_path};
    use super::types::{
        EVENT_ROTATE_BYTES, FacEventContext, ProjectionStatus, ReviewBackend, ReviewKind,
        ReviewRunState, ReviewRunStatus, ReviewStateEntry, ReviewStateFile, default_model,
        default_review_type, now_iso8601_millis,
    };
    use super::{
        review_types_all_terminal, review_types_terminal_done, review_types_terminal_failed,
    };
    use crate::commands::fac_review::types::apm2_home_dir;

    static TEST_PR_COUNTER: AtomicU32 = AtomicU32::new(441_000);

    fn next_test_pr() -> u32 {
        TEST_PR_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    fn sample_run_state(
        pr_number: u32,
        pid: u32,
        head_sha: &str,
        proc_start_time: Option<u64>,
    ) -> ReviewRunState {
        ReviewRunState {
            run_id: "pr441-security-s1-01234567".to_string(),
            pr_url: "https://github.com/example/repo/pull/441".to_string(),
            pr_number,
            head_sha: head_sha.to_string(),
            review_type: "security".to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: "2026-02-10T00:00:00Z".to_string(),
            status: ReviewRunStatus::Alive,
            terminal_reason: None,
            model_id: Some("gpt-5.3-codex".to_string()),
            backend_id: Some("codex".to_string()),
            restart_count: 0,
            sequence_number: 1,
            previous_run_id: None,
            previous_head_sha: None,
            pid: Some(pid),
            proc_start_time,
        }
    }

    fn spawn_persistent_process() -> std::process::Child {
        Command::new("sleep")
            .arg("1000")
            .spawn()
            .expect("spawn persistent process")
    }

    fn kill_child(mut child: std::process::Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    fn dead_pid_for_test() -> u32 {
        let mut child = std::process::Command::new("sh")
            .args(["-lc", "exit 0"])
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        let _ = child.wait();
        pid
    }

    #[test]
    fn test_select_review_model_random_returns_pool_member() {
        let models = MODEL_POOL
            .iter()
            .map(|entry| entry.model)
            .collect::<Vec<_>>();
        for _ in 0..64 {
            let selected = select_review_model_random();
            assert!(
                models.contains(&selected.model.as_str()),
                "selected model must be from pool: {}",
                selected.model
            );
        }
    }

    #[test]
    fn test_select_fallback_model_cycles() {
        let next = select_fallback_model("gemini-3-flash-preview")
            .expect("known model should produce fallback");
        assert_eq!(next.model, "gemini-3-pro-preview");

        let next = select_fallback_model("gemini-3-pro-preview")
            .expect("known model should produce fallback");
        assert_eq!(next.model, "gpt-5.3-codex");

        let next =
            select_fallback_model("gpt-5.3-codex").expect("known model should produce fallback");
        assert_eq!(next.model, "gpt-5.3-codex-spark");

        let next = select_fallback_model("gpt-5.3-codex-spark")
            .expect("known model should produce fallback");
        assert_eq!(next.model, "gemini-3-flash-preview");
    }

    #[test]
    fn test_select_fallback_model_unknown_returns_none() {
        assert!(select_fallback_model("unknown-model").is_none());
    }

    #[test]
    fn test_projection_state_helpers() {
        assert!(projection_state_done("done:gpt-5.3-codex/codex:r0:abcdef0"));
        assert!(!projection_state_done(
            "alive:gpt-5.3-codex/codex:r0:abcdef0"
        ));
        assert!(projection_state_failed(
            "failed:comment_post_permission_denied"
        ));
        assert!(!projection_state_failed("none"));
    }

    #[test]
    fn test_allowed_author_association_guard() {
        assert!(is_allowed_author_association("OWNER"));
        assert!(is_allowed_author_association("MEMBER"));
        assert!(is_allowed_author_association("COLLABORATOR"));
        assert!(!is_allowed_author_association("CONTRIBUTOR"));
        assert!(!is_allowed_author_association("NONE"));
    }

    #[test]
    fn test_review_wait_terminal_predicates_cover_filters() {
        let status_done = ProjectionStatus {
            line: String::new(),
            sha: "abcd".to_string(),
            current_head_sha: "abcd".to_string(),
            security: "done:model/backend:r0:abcd".to_string(),
            quality: "failed:sequence_unknown".to_string(),
            recent_events: String::new(),
            terminal_failure: false,
            last_seq: 0,
            errors: Vec::new(),
        };
        assert!(review_types_terminal_done(&status_done, Some("security")));
        assert!(!review_types_terminal_failed(
            &status_done,
            Some("security")
        ));
        assert!(!review_types_terminal_failed(&status_done, Some("quality")));
        assert!(!review_types_terminal_done(&status_done, Some("quality")));

        let status_running = ProjectionStatus {
            security: "alive:model/backend:r0:abcd".to_string(),
            ..status_done
        };
        assert!(!review_types_terminal_done(&status_running, None));
        assert!(!review_types_terminal_failed(&status_running, None));

        let invalid_filter = review_types_all_terminal(&status_running, Some("invalid"));
        assert!(invalid_filter.is_err());
        assert!(invalid_filter.unwrap_err().contains("invalid review type"));
    }

    #[test]
    fn test_build_gemini_script_command_syntax() {
        let prompt = std::path::Path::new("/tmp/prompt.md");
        let log = std::path::Path::new("/tmp/review.log");
        let cmd = build_gemini_script_command(prompt, log, "gemini-3-flash-preview");
        assert!(cmd.contains("script -q"));
        assert!(cmd.contains("gemini -m"));
        assert!(cmd.contains("-o stream-json"));
    }

    #[test]
    fn test_build_script_command_for_backend_dispatch() {
        let prompt = std::path::Path::new("/tmp/prompt.md");
        let log = std::path::Path::new("/tmp/review.log");
        let capture = std::path::Path::new("/tmp/capture.md");

        let codex = build_script_command_for_backend(
            ReviewBackend::Codex,
            prompt,
            log,
            "gpt-5.3-codex",
            Some(capture),
        );
        assert!(codex.contains("codex exec"));
        assert!(codex.contains("--json"));
        assert!(codex.contains("--output-last-message"));

        let gemini = build_script_command_for_backend(
            ReviewBackend::Gemini,
            prompt,
            log,
            "gemini-3-flash-preview",
            None,
        );
        assert!(gemini.contains("gemini -m"));
        assert!(gemini.contains("stream-json"));

        let claude = build_script_command_for_backend(
            ReviewBackend::ClaudeCode,
            prompt,
            log,
            "claude-3-7-sonnet",
            None,
        );
        assert!(claude.contains("claude"));
        assert!(claude.contains("--output-format json"));
        assert!(claude.contains("--permission-mode plan"));
        assert!(!claude.contains("-p \"$(cat"));
    }

    #[test]
    fn test_emit_review_event_appends_ndjson() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review_events.ndjson");

        emit_review_event_to_path(
            &path,
            &serde_json::json!({
                "ts": now_iso8601_millis(),
                "event": "test_event",
                "review_type": "security",
                "pr_number": 1,
                "head_sha": "abc",
                "seq": 1
            }),
        )
        .expect("emit event");

        let lines = read_last_lines(&path, 10).expect("read lines");
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&lines[0]).expect("parse line");
        assert_eq!(parsed["event"], "test_event");
    }

    #[test]
    fn test_emit_review_event_rotates_at_threshold() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review_events.ndjson");
        let rotated = temp_dir.path().join("review_events.ndjson.1");
        let oversized_len = usize::try_from(EVENT_ROTATE_BYTES + 1)
            .expect("event rotate threshold should fit into usize in tests");
        let oversized = vec![b'x'; oversized_len];
        std::fs::write(&path, oversized).expect("write oversized file");

        emit_review_event_to_path(
            &path,
            &serde_json::json!({
                "ts": now_iso8601_millis(),
                "event": "post_rotate",
                "review_type": "quality",
                "pr_number": 2,
                "head_sha": "def",
                "seq": 2
            }),
        )
        .expect("emit event");

        assert!(rotated.exists(), "rotated file should exist");
        let lines = read_last_lines(&path, 10).expect("read lines");
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_detect_http_400_or_rate_limit_markers() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        std::fs::write(
            &path,
            r#"{"message":"You have exhausted your capacity on this model. Your quota will reset after 2s."}"#,
        )
        .expect("write rate-limit log");
        assert!(detect_http_400_or_rate_limit(&path));

        std::fs::write(&path, r#"{"message":"normal progress"}"#).expect("write normal log");
        assert!(!detect_http_400_or_rate_limit(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_markers() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        std::fs::write(
            &path,
            "GraphQL: Resource not accessible by personal access token (addComment)",
        )
        .expect("write denied log");
        assert!(!detect_comment_permission_denied(&path));

        std::fs::write(
            &path,
            r#"{"type":"item.completed","item":{"type":"command_execution","command":"gh pr comment https://github.com/guardian-intelligence/apm2/pull/508 --body-file review.md","status":"failed","exit_code":1,"aggregated_output":"GraphQL: Resource not accessible by personal access token (addComment)"}}"#,
        )
        .expect("write structured denied log");
        assert!(detect_comment_permission_denied(&path));

        std::fs::write(&path, r#"{"message":"normal progress"}"#).expect("write normal log");
        assert!(!detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_ignores_diff_output() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        std::fs::write(
            &path,
            r#"{"type":"item.completed","item":{"command":"/bin/bash -lc 'gh pr diff https://github.com/guardian-intelligence/apm2/pull/508'","aggregated_output":"diff --git a/.github/workflows/ai-review.yml b/.github/workflows/ai-review.yml\nGraphQL: Resource not accessible by personal access token (addComment)"}}"#,
        )
        .expect("write diff-like denied marker log");
        assert!(!detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_requires_comment_context() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        std::fs::write(
            &path,
            r#"{"type":"item.completed","item":{"type":"command_execution","command":"/bin/bash -lc 'gh pr comment https://github.com/guardian-intelligence/apm2/pull/508 --body-file review.md'","status":"failed","exit_code":1,"aggregated_output":"GraphQL: Resource not accessible by personal access token (addComment)"}}"#,
        )
        .expect("write comment denied log");
        assert!(detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_ignores_source_dump() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        let line = serde_json::json!({
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "nl -ba crates/apm2-cli/src/commands/fac_review.rs",
                "status": "completed",
                "exit_code": 0,
                "aggregated_output": "2396: r#\"{\\\"type\\\":\\\"item.completed\\\",\\\"item\\\":{\\\"command\\\":\\\"/bin/bash -lc 'gh pr comment https://github.com/guardian-intelligence/apm2/pull/508 --body-file review.md'\\\",\\\"aggregated_output\\\":\\\"GraphQL: Resource not accessible by personal access token (addComment)\\\"}}\"#,"
            }
        })
        .to_string();
        std::fs::write(&path, line).expect("write source-dump denied marker log");
        assert!(!detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_run_terminate_inner_skips_when_proc_start_time_missing() {
        let pr_number = next_test_pr();
        let home = apm2_home_dir().expect("apm2 home");
        let state_path = super::state::review_run_state_path_for_home(&home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let state = sample_run_state(pr_number, pid, "abcdef1234567890", None);
        super::state::write_review_run_state_for_home(&home, &state).expect("write run state");

        let result =
            super::run_terminate_inner("example/repo", Some(pr_number), None, "security", false);
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("missing proc_start_time"));
        assert!(super::state::is_process_alive(pid));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_skips_when_proc_start_time_mismatched() {
        let pr_number = next_test_pr();
        let home = apm2_home_dir().expect("apm2 home");
        let state_path = super::state::review_run_state_path_for_home(&home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let observed_start = super::state::get_process_start_time(pid).expect("read start time");
        let state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(observed_start + 1));
        super::state::write_review_run_state_for_home(&home, &state).expect("write run state");

        let result =
            super::run_terminate_inner("example/repo", Some(pr_number), None, "security", false);
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("identity mismatch"));
        assert!(super::state::is_process_alive(pid));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_fails_when_pid_missing_for_alive_state() {
        let pr_number = next_test_pr();
        let home = apm2_home_dir().expect("apm2 home");
        let state_path = super::state::review_run_state_path_for_home(&home, pr_number, "security");

        let mut state = sample_run_state(pr_number, 0, "abcdef1234567890", Some(123_456_789));
        state.pid = None;
        super::state::write_review_run_state_for_home(&home, &state).expect("write run state");

        let result =
            super::run_terminate_inner("example/repo", Some(pr_number), None, "security", false);
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("PID is missing"));

        let loaded = super::state::load_review_run_state_for_home(&home, pr_number, "security")
            .expect("load run-state");
        let state = match loaded {
            super::state::ReviewRunStateLoad::Present(state) => state,
            other => panic!("expected present state, got {other:?}"),
        };
        assert_eq!(state.status, ReviewRunStatus::Alive);
        assert!(state.pid.is_none());

        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_skips_when_repo_mismatch() {
        let pr_number = next_test_pr();
        let home = apm2_home_dir().expect("apm2 home");
        let state_path = super::state::review_run_state_path_for_home(&home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let proc_start_time = super::state::get_process_start_time(pid).expect("read start time");
        let mut state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(proc_start_time));
        state.pr_url = "https://github.com/example/other-repo/pull/441".to_string();
        super::state::write_review_run_state_for_home(&home, &state).expect("write run state");

        let result =
            super::run_terminate_inner("owner/repo", Some(pr_number), None, "security", false);
        assert!(
            result.is_err(),
            "repo mismatch should now be treated as a failure"
        );
        let error = result.expect_err("repo mismatch should be surfaced as an error");
        assert!(error.contains("repo mismatch"));
        assert!(super::state::is_process_alive(pid));

        let loaded = super::state::load_review_run_state_for_home(&home, pr_number, "security")
            .expect("load run-state");
        let state = match loaded {
            super::state::ReviewRunStateLoad::Present(state) => state,
            other => panic!("expected present state, got {other:?}"),
        };
        assert_eq!(state.status, ReviewRunStatus::Alive);

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_fails_when_repo_parse_failed() {
        let pr_number = next_test_pr();
        let home = apm2_home_dir().expect("apm2 home");
        let state_path = super::state::review_run_state_path_for_home(&home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let proc_start_time = super::state::get_process_start_time(pid).expect("read start time");
        let mut state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(proc_start_time));
        state.pr_url = "https://github.com/not-a-repo-url".to_string();
        super::state::write_review_run_state_for_home(&home, &state).expect("write run state");

        let result =
            super::run_terminate_inner("example/repo", Some(pr_number), None, "security", false);
        assert!(
            result.is_err(),
            "repo parse failure should now be treated as an error"
        );
        let error = result.expect_err("repo parse failure should be surfaced as an error");
        assert!(error.contains("unable to parse owner/repo"));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_detect_http_400_or_rate_limit_ignores_source_dump() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        let line = serde_json::json!({
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "nl -ba crates/apm2-cli/src/commands/fac_review.rs",
                "status": "completed",
                "exit_code": 0,
                "aggregated_output": "2344: r#\"{\\\"message\\\":\\\"You have exhausted your capacity on this model. Your quota will reset after 2s.\\\"}\"#,"
            }
        })
        .to_string();
        std::fs::write(&path, line).expect("write source-dump backpressure marker log");
        assert!(!detect_http_400_or_rate_limit(&path));
    }

    #[test]
    fn test_extract_verdict_from_comment_body_prefers_metadata() {
        let body = r#"
## Security Review: PASS

<!-- apm2-review-metadata:v1:security -->
```json
{"verdict":"FAIL"}
```
"#;
        let verdict = extract_verdict_from_comment_body(body).expect("verdict from metadata");
        assert_eq!(verdict, "FAIL");
    }

    #[test]
    fn test_pulse_file_roundtrip() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review_pulse_security.json");
        write_pulse_file_to_path(&path, "0123456789abcdef").expect("write pulse");
        let pulse = read_pulse_file_from_path(&path)
            .expect("read pulse")
            .expect("pulse present");
        assert_eq!(pulse.head_sha, "0123456789abcdef");
    }

    #[test]
    fn test_review_state_entry_backward_compat_defaults() {
        let json = serde_json::json!({
            "pid": 1234,
            "started_at": Utc::now(),
            "log_file": "/tmp/review.log",
            "prompt_file": "/tmp/prompt.md",
            "last_message_file": "/tmp/last.md",
            "pr_url": "https://github.com/owner/repo/pull/1",
            "head_sha": "0123456789abcdef0123456789abcdef01234567",
            "restart_count": 0,
            "temp_files": []
        });
        let entry: ReviewStateEntry =
            serde_json::from_value(json).expect("deserialize review state entry");
        assert_eq!(entry.review_type, default_review_type());
        assert_eq!(entry.pr_number, 0);
        assert_eq!(entry.model, default_model());
        assert_eq!(entry.backend, ReviewBackend::Codex);
    }

    #[test]
    fn test_event_is_terminal_crash_conditions() {
        let by_restart = serde_json::json!({
            "event": "run_crash",
            "restart_count": 3,
            "reason": "run_crash"
        });
        assert!(event_is_terminal_crash(&by_restart));

        let by_reason = serde_json::json!({
            "event": "run_crash",
            "restart_count": 0,
            "reason": "comment_post_permission_denied"
        });
        assert!(event_is_terminal_crash(&by_reason));

        let non_terminal = serde_json::json!({
            "event": "run_crash",
            "restart_count": 1,
            "reason": "run_crash"
        });
        assert!(!event_is_terminal_crash(&non_terminal));
    }

    #[test]
    fn test_projection_state_for_type_prefers_done_event() {
        let state = ReviewStateFile::default();
        let events = vec![
            serde_json::json!({
                "event": "run_start",
                "review_type": "security",
                "pr_number": 42,
                "model": "gpt-5.3-codex",
                "backend": "codex",
                "restart_count": 1,
                "head_sha": "abcdef1234567890",
                "seq": 1
            }),
            serde_json::json!({
                "event": "run_complete",
                "review_type": "security",
                "pr_number": 42,
                "restart_count": 2,
                "head_sha": "abcdef1234567890",
                "verdict": "PASS",
                "seq": 2
            }),
        ];

        let rendered = projection_state_for_type(&state, &events, 42, ReviewKind::Security, None);
        assert_eq!(rendered, "done:gpt-5.3-codex/codex:r2:abcdef1");
    }

    #[test]
    fn test_projection_state_for_type_fail_verdict_is_failed() {
        let state = ReviewStateFile::default();
        let events = vec![serde_json::json!({
            "event": "run_complete",
            "review_type": "security",
            "pr_number": 42,
            "head_sha": "abcdef1234567890",
            "verdict": "FAIL",
            "seq": 2
        })];

        let rendered = projection_state_for_type(&state, &events, 42, ReviewKind::Security, None);
        assert_eq!(rendered, "failed:verdict_fail");
    }

    #[test]
    fn test_projection_state_for_type_unknown_verdict_is_failed() {
        let state = ReviewStateFile::default();
        let events = vec![serde_json::json!({
            "event": "run_complete",
            "review_type": "quality",
            "pr_number": 17,
            "head_sha": "abcdef1234567890",
            "verdict": "UNKNOWN",
            "seq": 2
        })];

        let rendered = projection_state_for_type(&state, &events, 17, ReviewKind::Quality, None);
        assert_eq!(rendered, "failed:verdict_unknown");
    }

    #[test]
    fn test_projection_state_for_type_terminal_crash() {
        let state = ReviewStateFile::default();
        let events = vec![serde_json::json!({
            "event": "run_crash",
            "review_type": "quality",
            "pr_number": 17,
            "restart_count": 0,
            "reason": "comment_post_permission_denied",
            "seq": 1
        })];

        let rendered = projection_state_for_type(&state, &events, 17, ReviewKind::Quality, None);
        assert_eq!(rendered, "failed:comment_post_permission_denied");
    }

    #[test]
    fn test_projection_state_for_type_stale_without_current_events_is_none() {
        let dead_pid = dead_pid_for_test();
        let mut state = ReviewStateFile::default();
        state.reviewers.insert(
            "stale-security".to_string(),
            ReviewStateEntry {
                pid: dead_pid,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/stale.log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 42,
                pr_url: "https://github.com/owner/repo/pull/42".to_string(),
                head_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
                restart_count: 0,
                model: default_model(),
                backend: ReviewBackend::Codex,
                temp_files: Vec::new(),
                run_id: "stale-security-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some(default_model()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        let events = Vec::<serde_json::Value>::new();

        let rendered = projection_state_for_type(
            &state,
            &events,
            42,
            ReviewKind::Security,
            Some("abcdef1234567890abcdef1234567890abcdef12"),
        );
        assert_eq!(rendered, "none");
    }

    #[test]
    fn test_projection_state_for_type_stale_with_current_events_is_failed() {
        let dead_pid = dead_pid_for_test();
        let mut state = ReviewStateFile::default();
        state.reviewers.insert(
            "stale-quality".to_string(),
            ReviewStateEntry {
                pid: dead_pid,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/stale.log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "quality".to_string(),
                pr_number: 17,
                pr_url: "https://github.com/owner/repo/pull/17".to_string(),
                head_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
                restart_count: 0,
                model: default_model(),
                backend: ReviewBackend::Codex,
                temp_files: Vec::new(),
                run_id: "stale-quality-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some(default_model()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        let events = vec![serde_json::json!({
            "event": "run_start",
            "review_type": "quality",
            "pr_number": 17,
            "head_sha": "abcdef1234567890abcdef1234567890abcdef12",
            "seq": 1
        })];

        let rendered = projection_state_for_type(
            &state,
            &events,
            17,
            ReviewKind::Quality,
            Some("abcdef1234567890abcdef1234567890abcdef12"),
        );
        assert_eq!(rendered, "failed:stale_process_state");
    }

    #[test]
    fn test_apply_sequence_done_fallback_sets_done_states() {
        let events = vec![serde_json::json!({
            "event": "sequence_done",
            "head_sha": "abcdef1234567890",
            "security_verdict": "DEDUPED",
            "quality_verdict": "PASS",
            "seq": 9
        })];
        let mut security = "none".to_string();
        let mut quality = "none".to_string();

        apply_sequence_done_fallback(&events, &mut security, &mut quality);

        assert_eq!(security, "done:sequence/summary:r0:abcdef1");
        assert_eq!(quality, "done:sequence/summary:r0:abcdef1");
    }

    #[test]
    fn test_apply_sequence_done_fallback_sets_failed_state() {
        let events = vec![serde_json::json!({
            "event": "sequence_done",
            "head_sha": "abcdef1234567890",
            "security_verdict": "FAIL",
            "quality_verdict": "UNKNOWN",
            "seq": 9
        })];
        let mut security = "none".to_string();
        let mut quality = "none".to_string();

        apply_sequence_done_fallback(&events, &mut security, &mut quality);

        assert_eq!(security, "failed:sequence_fail");
        assert_eq!(quality, "failed:sequence_unknown");
    }

    #[test]
    fn test_read_event_payload_bounded_rejects_oversized_payload() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("event.json");
        std::fs::write(&path, "0123456789abcdef").expect("write oversized payload");

        let err = read_event_payload_bounded(&path, 8).expect_err("payload should be rejected");
        assert!(err.contains("too large"), "unexpected error: {err}");
    }

    #[test]
    fn test_build_barrier_decision_event_contains_reason() {
        let event = build_barrier_decision_event(
            "barrier",
            "guardian-intelligence/apm2",
            "workflow_dispatch",
            None,
            false,
            Some("missing actor permission"),
        );
        assert_eq!(event["event"], "barrier_decision");
        assert_eq!(event["phase"], "barrier");
        assert_eq!(event["result"], "fail");
        assert_eq!(event["repo"], "guardian-intelligence/apm2");
        assert_eq!(event["reason"], "missing actor permission");
        assert_eq!(event["pr_number"], 0);
        assert_eq!(event["head_sha"], "-");
    }

    #[test]
    fn test_build_barrier_decision_event_with_context() {
        let ctx = FacEventContext {
            repo: "guardian-intelligence/apm2".to_string(),
            event_name: "pull_request_target".to_string(),
            pr_number: 509,
            pr_url: "https://github.com/guardian-intelligence/apm2/pull/509".to_string(),
            head_sha: "0c662aab51571e9a5d0ff7ab11bde9457cef23e1".to_string(),
            base_ref: "main".to_string(),
            default_branch: "main".to_string(),
            author_login: "Anveio".to_string(),
            author_association: "MEMBER".to_string(),
            actor_login: "Anveio".to_string(),
            actor_permission: Some("admin".to_string()),
        };
        let event = build_barrier_decision_event(
            "kickoff",
            &ctx.repo,
            &ctx.event_name,
            Some(&ctx),
            true,
            None,
        );
        assert_eq!(event["result"], "pass");
        assert_eq!(event["pr_number"], 509);
        assert_eq!(
            event["head_sha"],
            "0c662aab51571e9a5d0ff7ab11bde9457cef23e1"
        );
        assert_eq!(event["actor_permission"], "admin");
        assert!(event.get("reason").is_none());
    }

    // =========================================================================
    // SHA resolution function tests
    // =========================================================================

    #[test]
    fn test_latest_state_head_sha_empty() {
        let state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        assert_eq!(latest_state_head_sha(&state, 42), None);
    }

    #[test]
    fn test_latest_state_head_sha_match() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        state.reviewers.insert(
            "security-1".to_string(),
            ReviewStateEntry {
                pid: 1234,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 42,
                pr_url: "https://github.com/owner/repo/pull/42".to_string(),
                head_sha: "abc123def456".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "security-1-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        assert_eq!(
            latest_state_head_sha(&state, 42),
            Some("abc123def456".to_string())
        );
    }

    #[test]
    fn test_latest_state_head_sha_latest_wins() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        let early = Utc::now() - chrono::Duration::seconds(60);
        let late = Utc::now();
        state.reviewers.insert(
            "security-old".to_string(),
            ReviewStateEntry {
                pid: 1000,
                started_at: early,
                log_file: PathBuf::from("/tmp/old"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 42,
                pr_url: "https://github.com/owner/repo/pull/42".to_string(),
                head_sha: "old_sha".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "security-old-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        state.reviewers.insert(
            "security-new".to_string(),
            ReviewStateEntry {
                pid: 2000,
                started_at: late,
                log_file: PathBuf::from("/tmp/new"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 42,
                pr_url: "https://github.com/owner/repo/pull/42".to_string(),
                head_sha: "new_sha".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "security-new-run".to_string(),
                sequence_number: 2,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        assert_eq!(
            latest_state_head_sha(&state, 42),
            Some("new_sha".to_string())
        );
    }

    #[test]
    fn test_latest_state_head_sha_wrong_pr() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        state.reviewers.insert(
            "quality-1".to_string(),
            ReviewStateEntry {
                pid: 1234,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "quality".to_string(),
                pr_number: 99,
                pr_url: "https://github.com/owner/repo/pull/99".to_string(),
                head_sha: "sha_for_99".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "quality-1-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        assert_eq!(latest_state_head_sha(&state, 42), None);
    }

    #[test]
    fn test_latest_event_head_sha_empty() {
        let events: Vec<serde_json::Value> = vec![];
        assert_eq!(latest_event_head_sha(&events), None);
    }

    #[test]
    fn test_latest_event_head_sha_last_wins() {
        let events = vec![
            serde_json::json!({"head_sha": "first_sha", "event": "dispatched"}),
            serde_json::json!({"head_sha": "second_sha", "event": "started"}),
        ];
        assert_eq!(
            latest_event_head_sha(&events),
            Some("second_sha".to_string())
        );
    }

    #[test]
    fn test_latest_event_head_sha_skips_dash() {
        let events = vec![
            serde_json::json!({"head_sha": "real_sha", "event": "dispatched"}),
            serde_json::json!({"head_sha": "-", "event": "stall"}),
            serde_json::json!({"head_sha": "", "event": "crash"}),
        ];
        assert_eq!(latest_event_head_sha(&events), Some("real_sha".to_string()));
    }

    #[test]
    fn test_resolve_projection_sha_filter_priority() {
        let state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        let events: Vec<serde_json::Value> = vec![];
        assert_eq!(
            resolve_projection_sha(42, &state, &events, Some("override_sha")),
            "override_sha"
        );
    }

    #[test]
    fn test_resolve_projection_sha_state_fallback() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        state.reviewers.insert(
            "sec-1".to_string(),
            ReviewStateEntry {
                pid: 1,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 77777,
                pr_url: "https://github.com/owner/repo/pull/77777".to_string(),
                head_sha: "state_sha_wins".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "sec-state-fallback-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        let events: Vec<serde_json::Value> = vec![];
        let result = resolve_projection_sha(77777, &state, &events, None);
        assert_eq!(result, "state_sha_wins");
    }

    #[test]
    fn test_resolve_projection_sha_events_fallback() {
        let state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        let events = vec![serde_json::json!({"head_sha": "event_sha_abc", "event": "dispatched"})];
        let result = resolve_projection_sha(88888, &state, &events, None);
        assert_eq!(result, "event_sha_abc");
    }

    #[test]
    fn test_resolve_current_head_sha_state_priority() {
        let mut state = ReviewStateFile {
            reviewers: BTreeMap::new(),
        };
        state.reviewers.insert(
            "sec-1".to_string(),
            ReviewStateEntry {
                pid: 1,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/log"),
                prompt_file: None,
                last_message_file: None,
                review_type: "security".to_string(),
                pr_number: 77777,
                pr_url: "https://github.com/owner/repo/pull/77777".to_string(),
                head_sha: "state_sha_current".to_string(),
                restart_count: 0,
                model: "test-model".to_string(),
                backend: ReviewBackend::default(),
                temp_files: Vec::new(),
                run_id: "sec-current-head-run".to_string(),
                sequence_number: 1,
                terminal_reason: None,
                model_id: Some("test-model".to_string()),
                backend_id: Some("codex".to_string()),
                status: ReviewRunStatus::Alive,
            },
        );
        let events: Vec<serde_json::Value> = vec![];
        let result = resolve_current_head_sha(77777, &state, &events, "fallback_sha");
        assert_ne!(result, "fallback_sha");
    }
}
