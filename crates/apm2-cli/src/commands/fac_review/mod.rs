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
mod detection;
mod dispatch;
mod events;
mod evidence;
mod liveness;
mod logs;
mod model_pool;
mod orchestrator;
mod pipeline;
mod projection;
mod push;
mod restart;
mod state;
mod types;

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use barrier::{
    emit_barrier_decision_event, enforce_barrier, ensure_gh_cli_ready, resolve_fac_event_context,
};
use dispatch::dispatch_single_review;
use events::{read_last_event_values, review_events_path};
use projection::{
    projection_state_done, projection_state_failed, resolve_current_head_sha, run_project_inner,
};
use state::{is_process_alive, read_pulse_file, with_review_state_shared};
// Re-export public API for use by `fac.rs`
pub use types::ReviewRunType;
use types::{
    BarrierSummary, DispatchSummary, KickoffSummary, ReviewKind, TERMINATE_TIMEOUT, parse_pr_url,
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

// ── Public entry points ─────────────────────────────────────────────────────

pub fn run_review(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    json_output: bool,
) -> u8 {
    match orchestrator::run_review_inner(pr_url, review_type, expected_head_sha) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
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
                        "  Security:     {} (verdict={}, model={}, backend={}, restarts={}, secs={}{tok})",
                        if security.success { "PASS" } else { "FAIL" },
                        security.verdict,
                        security.model,
                        security.backend,
                        security.restart_count,
                        security.duration_secs
                    );
                }
                if let Some(quality) = &summary.quality {
                    let tok = quality
                        .tokens_used
                        .map_or_else(String::new, |n| format!(", tokens={n}"));
                    println!(
                        "  Quality:      {} (verdict={}, model={}, backend={}, restarts={}, secs={}{tok})",
                        if quality.success { "PASS" } else { "FAIL" },
                        quality.verdict,
                        quality.model,
                        quality.backend,
                        quality.restart_count,
                        quality.duration_secs
                    );
                }
            }

            let success = summary.security.as_ref().is_none_or(|entry| entry.success)
                && summary.quality.as_ref().is_none_or(|entry| entry.success);
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

pub fn run_status(pr_number: Option<u32>, pr_url: Option<&str>, json_output: bool) -> u8 {
    match run_status_inner(pr_number, pr_url, json_output) {
        Ok(()) => exit_codes::SUCCESS,
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

pub fn run_barrier(repo: &str, event_path: &Path, event_name: &str, json_output: bool) -> u8 {
    match resolve_fac_event_context(repo, event_path, event_name) {
        Ok(ctx) => {
            if let Err(err) = enforce_barrier(&ctx) {
                let _ = emit_barrier_decision_event(
                    "barrier",
                    repo,
                    event_name,
                    Some(&ctx),
                    false,
                    Some(&err),
                );
                if json_output {
                    let payload = serde_json::json!({
                        "error": "fac_barrier_failed",
                        "message": err,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    eprintln!("ERROR: {err}");
                }
                return exit_codes::GENERIC_ERROR;
            }
            let _ =
                emit_barrier_decision_event("barrier", repo, event_name, Some(&ctx), true, None);

            let summary = BarrierSummary {
                repo: ctx.repo,
                event_name: ctx.event_name,
                pr_number: ctx.pr_number,
                pr_url: ctx.pr_url,
                head_sha: ctx.head_sha,
                base_ref: ctx.base_ref,
                default_branch: ctx.default_branch,
                author_login: ctx.author_login,
                author_association: ctx.author_association,
                actor_login: ctx.actor_login,
                actor_permission: ctx.actor_permission,
            };
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Barrier");
                println!("  Repo:              {}", summary.repo);
                println!("  Event:             {}", summary.event_name);
                println!("  PR Number:         {}", summary.pr_number);
                println!("  Head SHA:          {}", summary.head_sha);
                println!("  Base Ref:          {}", summary.base_ref);
                println!(
                    "  Author:            {} ({})",
                    summary.author_login, summary.author_association
                );
                if let Some(permission) = &summary.actor_permission {
                    println!(
                        "  Actor:             {} ({permission})",
                        summary.actor_login
                    );
                } else {
                    println!("  Actor:             {}", summary.actor_login);
                }
                println!("  Barrier:           PASS");
            }
            exit_codes::SUCCESS
        },
        Err(err) => {
            let _ =
                emit_barrier_decision_event("barrier", repo, event_name, None, false, Some(&err));
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_barrier_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_kickoff(
    repo: &str,
    event_path: &Path,
    event_name: &str,
    max_wait_seconds: u64,
    public_projection_only: bool,
    json_output: bool,
) -> u8 {
    // SECURITY BOUNDARY: GitHub Action logs are publicly visible.
    // `public_projection_only` is intentionally fail-closed and must never emit
    // sensitive diagnostics on stdout/stderr. Rich details stay on runner-local
    // files under ~/.apm2.
    if public_projection_only && json_output {
        return exit_codes::GENERIC_ERROR;
    }
    if !json_output && !public_projection_only {
        println!(
            "details=~/.apm2/review_events.ndjson state=~/.apm2/reviewer_state.json dispatch_logs=~/.apm2/review_dispatch/"
        );
    }
    match run_kickoff_inner(
        repo,
        event_path,
        event_name,
        max_wait_seconds,
        public_projection_only,
    ) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else if !public_projection_only {
                println!("FAC Kickoff");
                println!("  Repo:              {}", summary.repo);
                println!("  Event:             {}", summary.event_name);
                println!("  PR Number:         {}", summary.pr_number);
                println!("  Head SHA:          {}", summary.head_sha);
                println!("  Dispatch Epoch:    {}", summary.dispatch_epoch);
                println!("  Total Seconds:     {}", summary.total_secs);
                println!("  Terminal State:    {}", summary.terminal_state);
            }
            if summary.terminal_state == "success" {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_kickoff_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                );
            } else if !public_projection_only {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_project(
    pr_number: u32,
    head_sha: Option<&str>,
    since_epoch: Option<u64>,
    after_seq: u64,
    emit_errors: bool,
    fail_on_terminal: bool,
    json_output: bool,
) -> u8 {
    match run_project_inner(pr_number, head_sha, since_epoch, after_seq) {
        Ok(status) => {
            if json_output {
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
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_project_failed",
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

pub fn run_tail(lines: usize, follow: bool) -> u8 {
    match run_tail_inner(lines, follow) {
        Ok(()) => exit_codes::SUCCESS,
        Err(err) => {
            eprintln!("ERROR: {err}");
            exit_codes::GENERIC_ERROR
        },
    }
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

pub fn run_logs(pr_number: Option<u32>, json_output: bool) -> u8 {
    logs::run_logs(pr_number, json_output)
}

// ── Internal dispatch helper (shared with pipeline/restart) ─────────────────

fn run_dispatch_inner(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
) -> Result<DispatchSummary, String> {
    let (owner_repo, pr_number) = parse_pr_url(pr_url)?;
    let current_head_sha = barrier::fetch_pr_head_sha(&owner_repo, pr_number)?;
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
        let result = dispatch_single_review(
            pr_url,
            &owner_repo,
            pr_number,
            kind,
            &current_head_sha,
            dispatch_epoch,
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

// ── Kickoff ─────────────────────────────────────────────────────────────────

fn run_kickoff_inner(
    repo: &str,
    event_path: &Path,
    event_name: &str,
    max_wait_seconds: u64,
    public_projection_only: bool,
) -> Result<KickoffSummary, String> {
    if max_wait_seconds == 0 {
        return Err("max_wait_seconds must be greater than zero".to_string());
    }

    let ctx = match resolve_fac_event_context(repo, event_path, event_name) {
        Ok(ctx) => ctx,
        Err(err) => {
            let _ =
                emit_barrier_decision_event("kickoff", repo, event_name, None, false, Some(&err));
            return Err(err);
        },
    };
    if let Err(err) = enforce_barrier(&ctx) {
        let _ =
            emit_barrier_decision_event("kickoff", repo, event_name, Some(&ctx), false, Some(&err));
        return Err(err);
    }
    let _ = emit_barrier_decision_event("kickoff", repo, event_name, Some(&ctx), true, None);
    ensure_gh_cli_ready()?;

    let started = Instant::now();
    let dispatch = run_dispatch_inner(&ctx.pr_url, ReviewRunType::All, Some(&ctx.head_sha))?;
    let mut after_seq = 0_u64;
    let deadline = Instant::now() + Duration::from_secs(max_wait_seconds);
    let mut terminal_state = "failure:timeout".to_string();

    loop {
        let projection = run_project_inner(
            ctx.pr_number,
            Some(&ctx.head_sha),
            Some(dispatch.dispatch_epoch),
            after_seq,
        )?;
        println!("{}", projection.line);
        for error in &projection.errors {
            if public_projection_only {
                eprintln!(
                    "ERROR ts={} event={} review={} seq={} detail={}",
                    error.ts, error.event, error.review_type, error.seq, error.detail
                );
            } else {
                println!(
                    "ERROR ts={} event={} review={} seq={} detail={}",
                    error.ts, error.event, error.review_type, error.seq, error.detail
                );
            }
        }
        after_seq = projection.last_seq;

        if projection.terminal_failure {
            terminal_state = "failure:terminal_failure".to_string();
            break;
        }
        if projection_state_failed(&projection.security) {
            terminal_state = "failure:security".to_string();
            break;
        }
        if projection_state_failed(&projection.quality) {
            terminal_state = "failure:quality".to_string();
            break;
        }
        if projection_state_done(&projection.security) && projection_state_done(&projection.quality)
        {
            terminal_state = "success".to_string();
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    Ok(KickoffSummary {
        repo: ctx.repo,
        event_name: ctx.event_name,
        pr_number: ctx.pr_number,
        pr_url: ctx.pr_url,
        head_sha: ctx.head_sha,
        dispatch_epoch: dispatch.dispatch_epoch,
        total_secs: started.elapsed().as_secs(),
        terminal_state,
    })
}

// ── Status / Tail ───────────────────────────────────────────────────────────

fn run_status_inner(
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    json_output: bool,
) -> Result<(), String> {
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

    let state = with_review_state_shared(|state| Ok(state.clone()))?;
    let events = read_last_event_values(40)?;

    let filtered_state = state
        .reviewers
        .iter()
        .filter(|(_, entry)| {
            filter_pr.is_none_or(|number| {
                if entry.pr_number > 0 {
                    entry.pr_number == number
                } else {
                    parse_pr_url(&entry.pr_url).is_ok_and(|(_, pr_num)| pr_num == number)
                }
            })
        })
        .map(|(run_key, entry)| {
            let entry_pr = if entry.pr_number > 0 {
                entry.pr_number
            } else {
                parse_pr_url(&entry.pr_url)
                    .map(|(_, pr_num)| pr_num)
                    .unwrap_or(0)
            };
            serde_json::json!({
                "run_key": run_key,
                "review_type": entry.review_type,
                "pr_number": entry_pr,
                "pid": entry.pid,
                "alive": is_process_alive(entry.pid),
                "started_at": entry.started_at,
                "pr_url": entry.pr_url,
                "head_sha": entry.head_sha,
                "model": entry.model,
                "backend": entry.backend.as_str(),
                "restart_count": entry.restart_count,
                "log_file": entry.log_file.display().to_string(),
                "last_message_file": entry
                    .last_message_file
                    .as_ref()
                    .map(|path| path.display().to_string()),
            })
        })
        .collect::<Vec<_>>();

    let pulse_security = filter_pr
        .map(|number| read_pulse_file(number, "security"))
        .transpose()?
        .flatten();
    let pulse_quality = filter_pr
        .map(|number| read_pulse_file(number, "quality"))
        .transpose()?
        .flatten();

    let filtered_events = events
        .into_iter()
        .filter(|event| {
            filter_pr.is_none_or(|number| {
                event
                    .get("pr_number")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|value| value == u64::from(number))
            })
        })
        .collect::<Vec<_>>();
    let current_head_sha =
        filter_pr.map(|number| resolve_current_head_sha(number, &state, &filtered_events, "-"));

    if json_output {
        let payload = serde_json::json!({
            "state_entries": filtered_state,
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
        return Ok(());
    }

    println!("FAC Review Status");
    if let Some(number) = filter_pr {
        println!("  Filter PR: #{number}");
        println!(
            "  Current Head SHA: {}",
            current_head_sha.as_deref().unwrap_or("-")
        );
    }
    if filtered_state.is_empty() {
        println!("  Active Runs: none");
    } else {
        println!("  Active Runs:");
        for entry in filtered_state {
            println!(
                "    - {} | pid={} alive={} model={} backend={} reviewed_sha={} restarts={}",
                entry["review_type"].as_str().unwrap_or("unknown"),
                entry["pid"].as_u64().unwrap_or(0),
                entry["alive"].as_bool().unwrap_or(false),
                entry["model"].as_str().unwrap_or("unknown"),
                entry["backend"].as_str().unwrap_or("unknown"),
                entry["head_sha"].as_str().unwrap_or("unknown"),
                entry["restart_count"].as_u64().unwrap_or(0),
            );
        }
    }

    println!("  Recent Events:");
    if filtered_events.is_empty() {
        println!("    (none)");
    } else {
        for event in filtered_events.iter().rev().take(20).rev() {
            println!(
                "    [{}] {} {} pr=#{} event_sha={}",
                event["ts"].as_str().unwrap_or("-"),
                event["event"].as_str().unwrap_or("-"),
                event["review_type"].as_str().unwrap_or("-"),
                event["pr_number"].as_u64().unwrap_or(0),
                event["head_sha"].as_str().unwrap_or("-"),
            );
        }
    }
    println!("  Pulse Files:");
    if filter_pr.is_none() {
        println!("    (set --pr or --pr-url to inspect PR-scoped pulse files)");
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

    Ok(())
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
        EVENT_ROTATE_BYTES, FacEventContext, ReviewBackend, ReviewKind, ReviewStateEntry,
        ReviewStateFile, default_model, default_review_type, now_iso8601_millis,
    };

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
            },
        );
        let events: Vec<serde_json::Value> = vec![];
        let result = resolve_current_head_sha(77777, &state, &events, "fallback_sha");
        assert_ne!(result, "fallback_sha");
    }
}
