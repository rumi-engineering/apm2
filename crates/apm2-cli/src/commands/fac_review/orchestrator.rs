//! Core state machine: `run_review_inner` and `run_single_review`.

use std::io::Read;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};
use std::{fs, thread};

use super::backend::{
    build_prompt_content, build_resume_spawn_command_for_backend, build_sha_update_message,
    build_spawn_command_for_backend,
};
use super::detection::{detect_comment_permission_denied, detect_http_400_or_rate_limit};
use super::events::emit_event;
use super::liveness::scan_log_liveness;
use super::merge_conflicts::{check_merge_conflicts_against_main, render_merge_conflict_summary};
use super::model_pool::{
    acquire_provider_slot, backoff_before_cross_family_fallback, ensure_model_backend_available,
    select_cross_family_fallback, select_fallback_model, select_review_model_random,
};
use super::prepare::prepared_review_root;
use super::projection::fetch_pr_head_sha_authoritative;
use super::state::{
    COMPLETION_RECEIPT_SCHEMA, ReviewRunCompletionReceipt, build_review_run_id, build_run_key,
    find_active_review_entry, get_process_start_time, load_review_run_completion_receipt,
    load_review_run_state_strict, next_review_sequence_number, remove_review_state_entry,
    try_acquire_review_lease, upsert_review_state_entry, write_pulse_file,
    write_review_run_completion_receipt_for_home, write_review_run_state,
};
use super::types::{
    DISPATCH_LOCK_ACQUIRE_TIMEOUT, ExecutionContext, LIVENESS_REPORT_INTERVAL, LOOP_SLEEP,
    MAX_RESTART_ATTEMPTS, PULSE_POLL_INTERVAL, ReviewKind, ReviewModelSelection, ReviewRunState,
    ReviewRunStatus, ReviewRunSummary, ReviewRunType, ReviewStateEntry, STALL_THRESHOLD,
    SingleReviewResult, SingleReviewSummary, SpawnMode, apm2_home_dir,
    is_verdict_finalized_agent_stop_reason, now_iso8601, split_owner_repo,
    validate_expected_head_sha,
};
use super::verdict_projection::resolve_completion_signal_from_projection_for_home;

const STALE_ARTIFACT_TTL_SECS_DEFAULT: u64 = 24 * 60 * 60;
const MAX_MISSING_VERDICT_NUDGES: u32 = 1;
const MISSING_VERDICT_NUDGE_PROMPT_MAX_BYTES: u64 = 64 * 1024;
const MISSING_VERDICT_NUDGE_PROMPT_MAX_CHARS: usize = 4_000;
const MISSING_VERDICT_NUDGE_DISABLE_ENV: &str = "APM2_FAC_DISABLE_NUDGE";
const REVIEW_LEASE_HANDOFF_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STALE_TEMP_FILE_PREFIXES: [&str; 3] = [
    "apm2_fac_review_",
    "apm2_fac_prompt_",
    "apm2_fac_last_message_",
];

#[derive(Debug, Clone)]
struct CompletionSignal {
    verdict: String,
    decision: String,
    decision_comment_id: u64,
}

fn bool_env_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn missing_verdict_nudge_disabled() -> bool {
    bool_env_enabled(MISSING_VERDICT_NUDGE_DISABLE_ENV)
}

const fn verdict_dimension_for_kind(review_kind: ReviewKind) -> &'static str {
    match review_kind {
        ReviewKind::Security => "security",
        ReviewKind::Quality => "code-quality",
    }
}

fn required_verdict_command(review_kind: ReviewKind) -> String {
    format!(
        "cargo run -p apm2-cli -- fac review verdict set --dimension {} --verdict <approve|deny> --reason \"<your synthesized reasoning>\" --json",
        verdict_dimension_for_kind(review_kind)
    )
}

fn seeded_pending_run_identity(
    existing_state: Option<&ReviewRunState>,
    current_head_sha: &str,
    pr_number: u32,
    review_type: &str,
) -> Option<(u32, String)> {
    let state = existing_state?;
    if !state.head_sha.eq_ignore_ascii_case(current_head_sha) {
        return None;
    }
    if state.status != ReviewRunStatus::Pending || state.pid.is_some() {
        return None;
    }
    let sequence_number = state.sequence_number.max(1);
    let run_id = if state.run_id.trim().is_empty() {
        build_review_run_id(pr_number, review_type, sequence_number, current_head_sha)
    } else {
        state.run_id.clone()
    };
    Some((sequence_number, run_id))
}

fn should_dedupe_on_lease_contention(
    current_head_sha: &str,
    existing_state: Option<&ReviewRunState>,
    existing_entry: Option<&ReviewStateEntry>,
) -> bool {
    if existing_entry.is_some() {
        return true;
    }
    existing_state.is_some_and(|state| {
        state.head_sha.eq_ignore_ascii_case(current_head_sha)
            && state_references_live_process_identity(state)
    })
}

fn state_references_live_process_identity(state: &ReviewRunState) -> bool {
    let Some(pid) = state.pid else {
        return false;
    };
    if !super::state::is_process_alive(pid) {
        return false;
    }
    let Some(expected_start) = state.proc_start_time else {
        return false;
    };
    super::state::get_process_start_time(pid)
        .is_some_and(|observed_start| observed_start == expected_start)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out = value.chars().take(max_chars).collect::<String>();
    out.push_str("\n...[truncated]");
    out
}

fn read_prompt_excerpt_for_nudge(prompt_path: &std::path::Path) -> String {
    let Ok(mut file) = fs::File::open(prompt_path) else {
        return "prompt unavailable".to_string();
    };
    let mut limited = Vec::new();
    if file
        .by_ref()
        .take(MISSING_VERDICT_NUDGE_PROMPT_MAX_BYTES)
        .read_to_end(&mut limited)
        .is_err()
    {
        return "prompt unavailable".to_string();
    }
    let text = String::from_utf8_lossy(&limited);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "prompt unavailable".to_string();
    }
    truncate_chars(trimmed, MISSING_VERDICT_NUDGE_PROMPT_MAX_CHARS)
}

fn build_missing_verdict_nudge_message(
    review_kind: ReviewKind,
    prompt_path: &std::path::Path,
) -> String {
    let command = required_verdict_command(review_kind);
    let prompt_excerpt = read_prompt_excerpt_for_nudge(prompt_path);
    format!(
        "RESUME TASK - REQUIRED TERMINAL COMMAND NOT EXECUTED.\n\
         You exited without running your required terminal command.\n\
         You MUST execute this command before exiting:\n\n\
         {command}\n\n\
         Your original assignment was:\n\
         ---\n\
         {prompt_excerpt}\n\
         ---\n\n\
         Review your findings and execute the verdict command now."
    )
}

// ── Token usage extraction ───────────────────────────────────────────────────

/// Extract total token usage from review agent output.
///
/// Scans log output for token usage patterns emitted by Codex CLI
/// (`"total_tokens": NNN`) and Gemini CLI (similar structured output).
/// Returns the last (most complete) match found.
fn extract_token_usage(log_path: &std::path::Path) -> Option<u64> {
    let content = fs::read_to_string(log_path).ok()?;
    // Codex pattern: "total_tokens": 12345 or totalTokens: 12345
    let re = regex::Regex::new(r#"(?:"total_tokens"|"totalTokens"|total_tokens)\s*[:=]\s*(\d+)"#)
        .ok()?;
    let mut last_match = None;
    for cap in re.captures_iter(&content) {
        if let Some(m) = cap.get(1) {
            if let Ok(n) = m.as_str().parse::<u64>() {
                last_match = Some(n);
            }
        }
    }
    last_match
}

// ── resolve_repo_root (kept here, used only by run_single_review) ───────────

fn resolve_repo_root() -> Result<std::path::PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to execute git rev-parse --show-toplevel: {err}"))?;
    if !output.status.success() {
        return std::env::current_dir().map_err(|err| format!("failed to resolve cwd: {err}"));
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return Err("git rev-parse returned empty repository root".to_string());
    }
    Ok(std::path::PathBuf::from(root))
}

fn stale_artifact_ttl() -> Duration {
    Duration::from_secs(
        std::env::var("APM2_FAC_STALE_ARTIFACT_TTL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(STALE_ARTIFACT_TTL_SECS_DEFAULT),
    )
}

fn path_is_stale(path: &std::path::Path, ttl: Duration) -> bool {
    path.metadata()
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|elapsed| elapsed >= ttl)
}

fn cleanup_stale_temp_files(ttl: Duration) -> Result<(), String> {
    let temp_root = std::env::temp_dir();
    let entries = match fs::read_dir(&temp_root) {
        Ok(entries) => entries,
        Err(err) => {
            return Err(format!(
                "failed to read temp dir {}: {err}",
                temp_root.display()
            ));
        },
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !STALE_TEMP_FILE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        if !path_is_stale(&path, ttl) {
            continue;
        }
        let _ = fs::remove_file(&path);
    }
    Ok(())
}

fn cleanup_stale_prepared_inputs(ttl: Duration) -> Result<(), String> {
    let root_path = prepared_review_root();
    let root = root_path.as_path();
    if !root.exists() {
        return Ok(());
    }
    let repo_dirs =
        fs::read_dir(root).map_err(|err| format!("failed to read {}: {err}", root.display()))?;
    for repo_dir in repo_dirs.filter_map(Result::ok) {
        let repo_path = repo_dir.path();
        if !repo_path.is_dir() {
            continue;
        }
        let Ok(pr_dirs) = fs::read_dir(&repo_path) else {
            continue;
        };
        for pr_dir in pr_dirs.filter_map(Result::ok) {
            let pr_path = pr_dir.path();
            if !pr_path.is_dir() {
                continue;
            }
            let Ok(sha_dirs) = fs::read_dir(&pr_path) else {
                continue;
            };
            for sha_dir in sha_dirs.filter_map(Result::ok) {
                let sha_path = sha_dir.path();
                if !sha_path.is_dir() || !path_is_stale(&sha_path, ttl) {
                    continue;
                }
                let _ = fs::remove_dir_all(&sha_path);
            }
            if fs::read_dir(&pr_path)
                .ok()
                .is_some_and(|mut entries| entries.next().is_none())
            {
                let _ = fs::remove_dir(&pr_path);
            }
        }
        if fs::read_dir(&repo_path)
            .ok()
            .is_some_and(|mut entries| entries.next().is_none())
        {
            let _ = fs::remove_dir(&repo_path);
        }
    }
    Ok(())
}

fn cleanup_stale_fac_artifacts() -> Result<(), String> {
    let ttl = stale_artifact_ttl();
    cleanup_stale_temp_files(ttl)?;
    cleanup_stale_prepared_inputs(ttl)?;
    Ok(())
}

fn decision_to_verdict(decision: &str) -> Option<String> {
    match decision.trim().to_ascii_lowercase().as_str() {
        "approve" => Some("PASS".to_string()),
        "deny" => Some("FAIL".to_string()),
        _ => None,
    }
}

fn load_completion_signal(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    run_id: &str,
    head_sha: &str,
) -> Result<Option<CompletionSignal>, String> {
    let Some(receipt) = load_review_run_completion_receipt(pr_number, review_type)? else {
        let Some(state) = load_review_run_state_strict(pr_number, review_type)? else {
            return Ok(None);
        };
        if !state.owner_repo.eq_ignore_ascii_case(owner_repo)
            || !state.run_id.eq_ignore_ascii_case(run_id)
            || !state.head_sha.eq_ignore_ascii_case(head_sha)
            || state.status != ReviewRunStatus::Done
            || !state
                .terminal_reason
                .as_deref()
                .is_some_and(is_verdict_finalized_agent_stop_reason)
        {
            return Ok(None);
        }
        let home = apm2_home_dir()?;
        let Some(signal) = resolve_completion_signal_from_projection_for_home(
            &home,
            owner_repo,
            pr_number,
            review_type,
            head_sha,
        )?
        else {
            return Ok(None);
        };
        let receipt = ReviewRunCompletionReceipt {
            schema: COMPLETION_RECEIPT_SCHEMA.to_string(),
            emitted_at: now_iso8601(),
            repo: owner_repo.to_string(),
            pr_number,
            review_type: review_type.to_string(),
            run_id: run_id.to_string(),
            head_sha: head_sha.to_string(),
            decision: signal.decision.clone(),
            decision_comment_id: signal.decision_comment_id,
            decision_author: signal.decision_author,
            decision_summary: signal.decision_summary,
            integrity_hmac: String::new(),
        };
        if let Err(err) = write_review_run_completion_receipt_for_home(&home, &receipt) {
            eprintln!(
                "WARNING: failed to repair completion receipt for PR #{pr_number} type={review_type}: {err}"
            );
        }
        return Ok(Some(CompletionSignal {
            verdict: signal.verdict,
            decision: signal.decision,
            decision_comment_id: signal.decision_comment_id,
        }));
    };
    if !receipt.repo.eq_ignore_ascii_case(owner_repo)
        || !receipt.run_id.eq_ignore_ascii_case(run_id)
        || !receipt.head_sha.eq_ignore_ascii_case(head_sha)
    {
        return Ok(None);
    }
    if receipt.decision_summary.trim().is_empty() {
        return Ok(None);
    }
    let Some(verdict) = decision_to_verdict(&receipt.decision) else {
        return Ok(None);
    };
    Ok(Some(CompletionSignal {
        verdict,
        decision: receipt.decision,
        decision_comment_id: receipt.decision_comment_id,
    }))
}

fn summary_is_terminal(summary: &SingleReviewSummary) -> bool {
    matches!(summary.state.as_str(), "done" | "failed" | "crashed")
}

fn emit_lane_terminated_event(
    event_ctx: &ExecutionContext,
    lane: &str,
    summary: &SingleReviewSummary,
    head_sha: &str,
) -> Result<(), String> {
    emit_event(
        event_ctx,
        &format!("{lane}_terminated"),
        lane,
        head_sha,
        serde_json::json!({
            "run_id": summary.run_id,
            "state": summary.state,
            "verdict": summary.verdict,
            "terminal_reason": summary.terminal_reason,
            "duration_secs": summary.duration_secs,
            "restart_count": summary.restart_count,
            "tokens_used": summary.tokens_used,
        }),
    )
}

fn lane_is_active(pr_number: u32, lane: &str) -> bool {
    let Ok(Some(state)) = load_review_run_state_strict(pr_number, lane) else {
        return false;
    };
    !state.status.is_terminal()
}

// ── run_review_inner ────────────────────────────────────────────────────────

pub fn run_review_inner(
    owner_repo: &str,
    pr_number: u32,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    force: bool,
) -> Result<ReviewRunSummary, String> {
    if let Err(err) = cleanup_stale_fac_artifacts() {
        eprintln!("WARNING: failed to clean stale FAC artifacts: {err}");
    }
    let pr_url = format!("https://github.com/{owner_repo}/pull/{pr_number}");
    let current_head_sha = fetch_pr_head_sha_authoritative(owner_repo, pr_number)?;
    if let Some(expected) = expected_head_sha {
        validate_expected_head_sha(expected)?;
        if !expected.eq_ignore_ascii_case(&current_head_sha) {
            return Err(format!(
                "PR head mismatch before review run: expected {expected}, authoritative {current_head_sha}"
            ));
        }
    }
    let initial_head_sha = current_head_sha.clone();
    let workspace_root = resolve_repo_root()?;
    let merge_report = check_merge_conflicts_against_main(&workspace_root, &initial_head_sha)?;
    if merge_report.has_conflicts() {
        return Err(format!(
            "cannot run review for conflicted head SHA {initial_head_sha}:\n{}",
            render_merge_conflict_summary(&merge_report)
        ));
    }

    let event_ctx = ExecutionContext {
        pr_number,
        seq: Arc::new(AtomicU64::new(0)),
    };
    let total_started = Instant::now();
    let mut security_summary = None;
    let mut quality_summary = None;
    let mut final_heads = vec![initial_head_sha.clone()];

    match review_type {
        ReviewRunType::Security => {
            let selected = select_review_model_random();
            let result = run_single_review(
                &pr_url,
                owner_repo,
                pr_number,
                ReviewKind::Security,
                current_head_sha,
                selected,
                &event_ctx,
                force,
            )?;
            final_heads.push(result.final_head_sha.clone());
            security_summary = Some(result.summary);
        },
        ReviewRunType::Quality => {
            let selected = select_review_model_random();
            let result = run_single_review(
                &pr_url,
                owner_repo,
                pr_number,
                ReviewKind::Quality,
                current_head_sha,
                selected,
                &event_ctx,
                force,
            )?;
            final_heads.push(result.final_head_sha.clone());
            quality_summary = Some(result.summary);
        },
        ReviewRunType::All => {
            let sec_pr_url = pr_url.clone();
            let sec_owner_repo = owner_repo.to_string();
            let sec_head = current_head_sha.clone();
            let sec_ctx = event_ctx.clone();
            let sec_model = select_review_model_random();
            let sec_handle = thread::spawn(move || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_single_review(
                        &sec_pr_url,
                        &sec_owner_repo,
                        pr_number,
                        ReviewKind::Security,
                        sec_head,
                        sec_model,
                        &sec_ctx,
                        force,
                    )
                }))
                .map_err(|_| "security review worker panicked".to_string())
                .and_then(|value| value)
            });

            let qual_pr_url = pr_url.clone();
            let qual_owner_repo = owner_repo.to_string();
            let qual_head = current_head_sha;
            let qual_ctx = event_ctx.clone();
            let qual_model = select_review_model_random();
            let qual_handle = thread::spawn(move || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_single_review(
                        &qual_pr_url,
                        &qual_owner_repo,
                        pr_number,
                        ReviewKind::Quality,
                        qual_head,
                        qual_model,
                        &qual_ctx,
                        force,
                    )
                }))
                .map_err(|_| "quality review worker panicked".to_string())
                .and_then(|value| value)
            });

            let sec_joined = sec_handle
                .join()
                .map_err(|_| "security review worker panicked".to_string())?;
            let qual_joined = qual_handle
                .join()
                .map_err(|_| "quality review worker panicked".to_string())?;
            let security_outcome = match &sec_joined {
                Ok(result) => format!(
                    "ok(run_id={},state={},verdict={})",
                    result.summary.run_id, result.summary.state, result.summary.verdict
                ),
                Err(err) => format!("error({err})"),
            };
            let quality_outcome = match &qual_joined {
                Ok(result) => format!(
                    "ok(run_id={},state={},verdict={})",
                    result.summary.run_id, result.summary.state, result.summary.verdict
                ),
                Err(err) => format!("error({err})"),
            };

            match (sec_joined, qual_joined) {
                (Ok(sec_result), Ok(qual_result)) => {
                    final_heads.push(sec_result.final_head_sha.clone());
                    final_heads.push(qual_result.final_head_sha.clone());
                    security_summary = Some(sec_result.summary);
                    quality_summary = Some(qual_result.summary);
                },
                _ => {
                    return Err(format!(
                        "parallel review aggregate failure for PR #{pr_number}: security={security_outcome}; quality={quality_outcome}"
                    ));
                },
            }
        },
    }

    let current_head_sha = final_heads
        .last()
        .cloned()
        .unwrap_or_else(|| initial_head_sha.clone());

    if let Some(summary) = security_summary.as_ref()
        && summary_is_terminal(summary)
    {
        emit_lane_terminated_event(&event_ctx, "security", summary, &current_head_sha)?;
    }
    if let Some(summary) = quality_summary.as_ref()
        && summary_is_terminal(summary)
    {
        emit_lane_terminated_event(&event_ctx, "quality", summary, &current_head_sha)?;
    }

    let can_emit_sequence_done = match review_type {
        ReviewRunType::All => {
            security_summary.as_ref().is_none_or(summary_is_terminal)
                && quality_summary.as_ref().is_none_or(summary_is_terminal)
        },
        ReviewRunType::Security => {
            security_summary.as_ref().is_some_and(summary_is_terminal)
                && !lane_is_active(pr_number, "quality")
        },
        ReviewRunType::Quality => {
            quality_summary.as_ref().is_some_and(summary_is_terminal)
                && !lane_is_active(pr_number, "security")
        },
    };
    if can_emit_sequence_done {
        emit_event(
            &event_ctx,
            "sequence_done",
            "all",
            &current_head_sha,
            serde_json::json!({
                "security_verdict": security_summary
                    .as_ref()
                    .map_or_else(|| "SKIPPED".to_string(), |entry| entry.verdict.clone()),
                "quality_verdict": quality_summary
                    .as_ref()
                    .map_or_else(|| "SKIPPED".to_string(), |entry| entry.verdict.clone()),
                "total_secs": total_started.elapsed().as_secs(),
                "security_tokens": security_summary.as_ref().and_then(|s| s.tokens_used),
                "quality_tokens": quality_summary.as_ref().and_then(|s| s.tokens_used),
                "security_run_id": security_summary.as_ref().map(|s| s.run_id.clone()),
                "quality_run_id": quality_summary.as_ref().map(|s| s.run_id.clone()),
                "security_state": security_summary.as_ref().map(|s| s.state.clone()),
                "quality_state": quality_summary.as_ref().map(|s| s.state.clone()),
                "security_terminal_reason": security_summary
                    .as_ref()
                    .and_then(|s| s.terminal_reason.clone()),
                "quality_terminal_reason": quality_summary
                    .as_ref()
                    .and_then(|s| s.terminal_reason.clone()),
            }),
        )?;
    }

    Ok(ReviewRunSummary {
        pr_url,
        pr_number,
        initial_head_sha,
        final_head_sha: current_head_sha,
        total_secs: total_started.elapsed().as_secs(),
        security: security_summary,
        quality: quality_summary,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_single_review_summary(
    run_id: &str,
    sequence_number: u32,
    state: ReviewRunStatus,
    review_type: &str,
    success: bool,
    verdict: String,
    terminal_reason: Option<String>,
    model: &str,
    backend: &str,
    duration_secs: u64,
    restart_count: u32,
    tokens_used: Option<u64>,
) -> SingleReviewSummary {
    SingleReviewSummary {
        run_id: run_id.to_string(),
        sequence_number,
        state: state.as_str().to_string(),
        review_type: review_type.to_string(),
        success,
        verdict,
        terminal_reason,
        model: model.to_string(),
        backend: backend.to_string(),
        duration_secs,
        restart_count,
        tokens_used,
    }
}

fn persist_review_run_state(
    state: &mut ReviewRunState,
    status: ReviewRunStatus,
    terminal_reason: Option<String>,
    current_head_sha: &str,
    model: &ReviewModelSelection,
    restart_count: u32,
    pid: Option<u32>,
) -> Result<(), String> {
    state.status = status;
    state.terminal_reason = terminal_reason;
    state.head_sha = current_head_sha.to_string();
    state.model_id = Some(model.model.clone());
    state.backend_id = Some(model.backend.as_str().to_string());
    state.restart_count = restart_count;
    state.pid = pid;
    state.proc_start_time = pid.and_then(get_process_start_time);
    let _ = write_review_run_state(state)?;
    Ok(())
}

// ── run_single_review ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn run_single_review(
    pr_url: &str,
    owner_repo: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    initial_head_sha: String,
    initial_model: ReviewModelSelection,
    event_ctx: &ExecutionContext,
    force: bool,
) -> Result<SingleReviewResult, String> {
    let repo_root = resolve_repo_root()?;
    let prompt_template = repo_root.join(review_kind.prompt_path());
    if !prompt_template.exists() {
        return Err(format!(
            "{} prompt missing at {}",
            review_kind.display(),
            prompt_template.display()
        ));
    }

    let log_temp = tempfile::Builder::new()
        .prefix(&format!("apm2_fac_review_{}_", review_kind.as_str()))
        .suffix(".log")
        .tempfile()
        .map_err(|err| format!("failed to create log tempfile: {err}"))?;
    let (_, log_path) = log_temp
        .keep()
        .map_err(|err| format!("failed to persist log tempfile: {err}"))?;

    let prompt_temp = tempfile::Builder::new()
        .prefix(&format!("apm2_fac_prompt_{}_", review_kind.as_str()))
        .suffix(".md")
        .tempfile()
        .map_err(|err| format!("failed to create prompt tempfile: {err}"))?;
    let (_, prompt_path) = prompt_temp
        .keep()
        .map_err(|err| format!("failed to persist prompt tempfile: {err}"))?;

    let last_msg_temp = tempfile::Builder::new()
        .prefix(&format!("apm2_fac_last_message_{}_", review_kind.as_str()))
        .suffix(".md")
        .tempfile()
        .map_err(|err| format!("failed to create last-message tempfile: {err}"))?;
    let (_, last_message_path) = last_msg_temp
        .keep()
        .map_err(|err| format!("failed to persist last-message tempfile: {err}"))?;

    let mut current_head_sha = initial_head_sha;
    let mut current_model = ensure_model_backend_available(initial_model)?;
    let mut spawn_mode = SpawnMode::Initial;
    let mut restart_count: u32 = 0;
    let review_started = Instant::now();
    let review_type = review_kind.as_str();
    let previous_state = load_review_run_state_strict(pr_number, review_type)?;
    if let Some(previous) = previous_state.as_ref() {
        if previous.head_sha.eq_ignore_ascii_case(&current_head_sha)
            && previous.status.is_terminal()
            && !force
        {
            return Err(format!(
                "same SHA already has terminal {review_type} review state={} run_id={} for {} — re-run with --force to override",
                previous.status.as_str(),
                previous.run_id,
                current_head_sha
            ));
        }
    }
    let (sequence_number, run_id) = if let Some(identity) = seeded_pending_run_identity(
        previous_state.as_ref(),
        &current_head_sha,
        pr_number,
        review_type,
    ) {
        identity
    } else {
        let sequence_number = next_review_sequence_number(pr_number, review_type)?;
        let run_id =
            build_review_run_id(pr_number, review_type, sequence_number, &current_head_sha);
        (sequence_number, run_id)
    };
    let mut run_state = ReviewRunState {
        run_id: run_id.clone(),
        owner_repo: owner_repo.to_string(),
        pr_number,
        head_sha: current_head_sha.clone(),
        review_type: review_type.to_string(),
        reviewer_role: "fac_reviewer".to_string(),
        started_at: super::types::now_iso8601(),
        status: ReviewRunStatus::Pending,
        terminal_reason: None,
        model_id: Some(current_model.model.clone()),
        backend_id: Some(current_model.backend.as_str().to_string()),
        restart_count,
        nudge_count: 0,
        sequence_number,
        previous_run_id: None,
        previous_head_sha: None,
        pid: None,
        proc_start_time: None,
        integrity_hmac: None,
    };

    let emit_run_event =
        |event_name: &str, event_head_sha: &str, extra: serde_json::Value| -> Result<(), String> {
            let mut payload = match extra {
                serde_json::Value::Object(map) => map,
                _ => serde_json::Map::new(),
            };
            payload.insert("run_id".to_string(), serde_json::json!(run_id));
            payload.insert(
                "sequence_number".to_string(),
                serde_json::json!(sequence_number),
            );
            emit_event(
                event_ctx,
                event_name,
                review_type,
                event_head_sha,
                serde_json::Value::Object(payload),
            )
        };

    let lease_wait_started = Instant::now();
    let _lease = loop {
        if let Some(lease) = try_acquire_review_lease(owner_repo, pr_number, review_type)? {
            break lease;
        }
        let existing_state = load_review_run_state_strict(pr_number, review_type)?;
        let existing = find_active_review_entry(pr_number, review_type, Some(&current_head_sha))?;
        if should_dedupe_on_lease_contention(
            &current_head_sha,
            existing_state.as_ref(),
            existing.as_ref(),
        ) {
            emit_run_event(
                "run_deduplicated",
                &current_head_sha,
                serde_json::json!({
                    "reason": "active_review_for_same_type",
                    "existing_pid": existing.as_ref().map(|entry| entry.pid),
                    "existing_sha": existing.as_ref().map(|entry| entry.head_sha.clone()),
                    "existing_run_id": existing_state.as_ref().map(|state| state.run_id.clone()),
                    "existing_state_pid": existing_state.as_ref().and_then(|state| state.pid),
                    "existing_state_proc_start_time": existing_state
                        .as_ref()
                        .and_then(|state| state.proc_start_time),
                }),
            )?;
            let model = existing
                .as_ref()
                .map_or_else(|| current_model.model.clone(), |entry| entry.model.clone());
            let backend = existing.as_ref().map_or_else(
                || current_model.backend.as_str().to_string(),
                |entry| entry.backend.as_str().to_string(),
            );
            let restart_count = existing.as_ref().map_or(0, |entry| entry.restart_count);
            return Ok(SingleReviewResult {
                summary: build_single_review_summary(
                    existing_state
                        .as_ref()
                        .map_or(&run_id, |state| state.run_id.as_str()),
                    existing_state
                        .as_ref()
                        .map_or(sequence_number, |state| state.sequence_number),
                    ReviewRunStatus::Alive,
                    review_type,
                    true,
                    "DEDUPED".to_string(),
                    Some("active_review_for_same_type".to_string()),
                    &model,
                    &backend,
                    review_started.elapsed().as_secs(),
                    restart_count,
                    None,
                ),
                final_head_sha: current_head_sha,
            });
        }
        if lease_wait_started.elapsed() >= DISPATCH_LOCK_ACQUIRE_TIMEOUT {
            let state_detail = existing_state.as_ref().map_or_else(
                || "state=none".to_string(),
                |state| {
                    format!(
                        "state.run_id={} state.status={} state.pid={:?} state.head_sha={}",
                        state.run_id,
                        state.status.as_str(),
                        state.pid,
                        state.head_sha,
                    )
                },
            );
            return Err(format!(
                "review lease contention unresolved for PR #{pr_number} type={review_type} head={current_head_sha} after {DISPATCH_LOCK_ACQUIRE_TIMEOUT:?}; {state_detail}"
            ));
        }
        thread::sleep(REVIEW_LEASE_HANDOFF_POLL_INTERVAL);
    };
    write_pulse_file(pr_number, review_type, &current_head_sha, Some(&run_id))?;
    let run_key = build_run_key(pr_number, review_type, &current_head_sha);
    persist_review_run_state(
        &mut run_state,
        ReviewRunStatus::Pending,
        None,
        &current_head_sha,
        &current_model,
        restart_count,
        None,
    )?;

    'restart_loop: loop {
        if let Some(signal) = load_completion_signal(
            owner_repo,
            pr_number,
            review_type,
            &run_id,
            &current_head_sha,
        )? {
            let latest_head = fetch_pr_head_sha_authoritative(owner_repo, pr_number)?;
            if !latest_head.eq_ignore_ascii_case(&current_head_sha) {
                let old_sha = current_head_sha.clone();
                emit_run_event(
                    "sha_update",
                    &old_sha,
                    serde_json::json!({
                        "old_sha": old_sha,
                        "new_sha": latest_head,
                    }),
                )?;
                current_head_sha.clone_from(&latest_head);
                write_pulse_file(pr_number, review_type, &current_head_sha, Some(&run_id))?;
                persist_review_run_state(
                    &mut run_state,
                    ReviewRunStatus::Pending,
                    Some("sha_update".to_string()),
                    &current_head_sha,
                    &current_model,
                    restart_count,
                    None,
                )?;
                spawn_mode = SpawnMode::Resume {
                    message: build_sha_update_message(pr_number, &old_sha, &latest_head),
                };
                continue 'restart_loop;
            }

            emit_run_event(
                "run_deduplicated",
                &current_head_sha,
                serde_json::json!({
                    "reason": "completion_receipt_already_present",
                    "decision": signal.decision,
                    "verdict": signal.verdict,
                    "decision_comment_id": signal.decision_comment_id,
                }),
            )?;
            remove_review_state_entry(&run_key)?;
            let completion_reason = signal.decision.to_ascii_lowercase();
            persist_review_run_state(
                &mut run_state,
                ReviewRunStatus::Done,
                Some(completion_reason.clone()),
                &current_head_sha,
                &current_model,
                restart_count,
                None,
            )?;
            return Ok(SingleReviewResult {
                summary: build_single_review_summary(
                    &run_id,
                    sequence_number,
                    ReviewRunStatus::Done,
                    review_type,
                    true,
                    signal.verdict,
                    Some(completion_reason),
                    &current_model.model,
                    current_model.backend.as_str(),
                    review_started.elapsed().as_secs(),
                    restart_count,
                    None,
                ),
                final_head_sha: current_head_sha.clone(),
            });
        }

        let (owner, repo) = split_owner_repo(owner_repo)?;
        if matches!(spawn_mode, SpawnMode::Initial) {
            let prompt_content =
                build_prompt_content(&prompt_template, pr_url, &current_head_sha, owner, repo)?;
            fs::write(&prompt_path, prompt_content)
                .map_err(|err| format!("failed to write prompt file: {err}"))?;
        }

        let spawn_cmd = match &spawn_mode {
            SpawnMode::Initial => build_spawn_command_for_backend(
                current_model.backend,
                &prompt_path,
                &log_path,
                &current_model.model,
                Some(&last_message_path),
            )?,
            SpawnMode::Resume { message } => {
                fs::write(&last_message_path, message).map_err(|err| {
                    format!(
                        "failed to write resume message {}: {err}",
                        last_message_path.display()
                    )
                })?;
                build_resume_spawn_command_for_backend(
                    current_model.backend,
                    &log_path,
                    &current_model.model,
                    &last_message_path,
                )
            },
        };

        let _provider_slot_lease = match acquire_provider_slot(current_model.backend) {
            Ok(lease) => lease,
            Err(err) => {
                persist_review_run_state(
                    &mut run_state,
                    ReviewRunStatus::Failed,
                    Some("provider_slot_unavailable".to_string()),
                    &current_head_sha,
                    &current_model,
                    restart_count,
                    None,
                )?;
                return Err(err);
            },
        };
        let mut child = match spawn_cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                persist_review_run_state(
                    &mut run_state,
                    ReviewRunStatus::Failed,
                    Some("spawn_failed".to_string()),
                    &current_head_sha,
                    &current_model,
                    restart_count,
                    None,
                )?;
                return Err(format!(
                    "failed to spawn {} review: {err}",
                    review_kind.display()
                ));
            },
        };

        upsert_review_state_entry(
            &run_key,
            ReviewStateEntry {
                pid: child.id(),
                started_at: chrono::Utc::now(),
                log_file: log_path.clone(),
                prompt_file: Some(prompt_path.clone()),
                last_message_file: Some(last_message_path.clone()),
                review_type: review_type.to_string(),
                pr_number,
                owner_repo: owner_repo.to_string(),
                head_sha: current_head_sha.clone(),
                restart_count,
                model: current_model.model.clone(),
                backend: current_model.backend,
                temp_files: Vec::new(),
                run_id: run_state.run_id.clone(),
                sequence_number: run_state.sequence_number,
                terminal_reason: None,
                model_id: Some(current_model.model.clone()),
                backend_id: Some(current_model.backend.as_str().to_string()),
                status: ReviewRunStatus::Alive,
            },
        )?;
        persist_review_run_state(
            &mut run_state,
            ReviewRunStatus::Alive,
            None,
            &current_head_sha,
            &current_model,
            restart_count,
            Some(child.id()),
        )?;
        if let Err(err) = super::lifecycle::bind_reviewer_runtime(
            owner_repo,
            pr_number,
            &current_head_sha,
            review_type,
            &run_id,
            child.id(),
            run_state.proc_start_time,
        ) {
            eprintln!(
                "WARNING: failed to bind reviewer runtime in agent registry for PR #{pr_number} type={review_type} run_id={run_id}: {err}",
            );
        }

        emit_run_event(
            "run_start",
            &current_head_sha,
            serde_json::json!({
                "model": current_model.model,
                "backend": current_model.backend.as_str(),
                "pid": child.id(),
                "log_file": log_path.display().to_string(),
            }),
        )?;

        let mut last_pulse_check = Instant::now();
        let mut last_liveness_report = Instant::now();
        let mut last_progress_at = Instant::now();
        let mut cursor = fs::metadata(&log_path).map(|meta| meta.len()).unwrap_or(0);
        let mut total_events_seen: u64 = 0;
        let mut last_event_type = String::new();
        let run_started = Instant::now();

        loop {
            if let Some(signal) = load_completion_signal(
                owner_repo,
                pr_number,
                review_type,
                &run_id,
                &current_head_sha,
            )? {
                emit_run_event(
                    "completion_signal_detected",
                    &current_head_sha,
                    serde_json::json!({
                        "decision": signal.decision,
                        "verdict": signal.verdict,
                        "decision_comment_id": signal.decision_comment_id,
                    }),
                )?;
                super::terminate_child(&mut child)?;
                let latest_head = fetch_pr_head_sha_authoritative(owner_repo, pr_number)?;
                emit_run_event(
                    "pulse_check",
                    &current_head_sha,
                    serde_json::json!({
                        "pulse_sha": latest_head,
                        "match": latest_head.eq_ignore_ascii_case(&current_head_sha),
                    }),
                )?;
                if !latest_head.eq_ignore_ascii_case(&current_head_sha) {
                    let old_sha = current_head_sha.clone();
                    emit_run_event(
                        "sha_update",
                        &old_sha,
                        serde_json::json!({
                            "old_sha": old_sha,
                            "new_sha": latest_head,
                        }),
                    )?;
                    current_head_sha.clone_from(&latest_head);
                    write_pulse_file(pr_number, review_type, &current_head_sha, Some(&run_id))?;
                    persist_review_run_state(
                        &mut run_state,
                        ReviewRunStatus::Pending,
                        Some("sha_update".to_string()),
                        &current_head_sha,
                        &current_model,
                        restart_count,
                        None,
                    )?;
                    spawn_mode = SpawnMode::Resume {
                        message: build_sha_update_message(pr_number, &old_sha, &latest_head),
                    };
                    continue 'restart_loop;
                }

                let tokens = extract_token_usage(&log_path);
                emit_run_event(
                    "run_complete",
                    &current_head_sha,
                    serde_json::json!({
                        "exit_code": 0,
                        "duration_secs": run_started.elapsed().as_secs(),
                        "decision": signal.decision,
                        "verdict": signal.verdict,
                        "tokens_used": tokens,
                    }),
                )?;
                if signal.decision_comment_id > 0 {
                    emit_run_event(
                        "review_posted",
                        &current_head_sha,
                        serde_json::json!({
                            "comment_id": signal.decision_comment_id,
                            "verdict": signal.verdict,
                        }),
                    )?;
                }

                remove_review_state_entry(&run_key)?;
                let completion_reason = signal.decision.to_ascii_lowercase();
                persist_review_run_state(
                    &mut run_state,
                    ReviewRunStatus::Done,
                    Some(completion_reason.clone()),
                    &current_head_sha,
                    &current_model,
                    restart_count,
                    None,
                )?;
                return Ok(SingleReviewResult {
                    summary: build_single_review_summary(
                        &run_id,
                        sequence_number,
                        ReviewRunStatus::Done,
                        review_type,
                        true,
                        signal.verdict,
                        Some(completion_reason),
                        &current_model.model,
                        current_model.backend.as_str(),
                        review_started.elapsed().as_secs(),
                        restart_count,
                        tokens,
                    ),
                    final_head_sha: current_head_sha,
                });
            }

            if let Some(status) = child
                .try_wait()
                .map_err(|err| format!("failed to poll reviewer process: {err}"))?
            {
                let exit_code = status.code();
                if status.success() {
                    if let Some(signal) = load_completion_signal(
                        owner_repo,
                        pr_number,
                        review_type,
                        &run_id,
                        &current_head_sha,
                    )? {
                        let tokens = extract_token_usage(&log_path);
                        emit_run_event(
                            "run_complete",
                            &current_head_sha,
                            serde_json::json!({
                                "exit_code": exit_code.unwrap_or(0),
                                "duration_secs": run_started.elapsed().as_secs(),
                                "decision": signal.decision,
                                "verdict": signal.verdict,
                                "tokens_used": tokens,
                            }),
                        )?;

                        if signal.decision_comment_id > 0 {
                            emit_run_event(
                                "review_posted",
                                &current_head_sha,
                                serde_json::json!({
                                    "comment_id": signal.decision_comment_id,
                                    "verdict": signal.verdict,
                                }),
                            )?;
                        }

                        let latest_head = fetch_pr_head_sha_authoritative(owner_repo, pr_number)?;
                        emit_run_event(
                            "pulse_check",
                            &current_head_sha,
                            serde_json::json!({
                                "pulse_sha": latest_head,
                                "match": latest_head.eq_ignore_ascii_case(&current_head_sha),
                            }),
                        )?;
                        if !latest_head.eq_ignore_ascii_case(&current_head_sha) {
                            let old_sha = current_head_sha.clone();
                            emit_run_event(
                                "sha_update",
                                &old_sha,
                                serde_json::json!({
                                    "old_sha": old_sha,
                                    "new_sha": latest_head,
                                }),
                            )?;
                            current_head_sha.clone_from(&latest_head);
                            write_pulse_file(
                                pr_number,
                                review_type,
                                &current_head_sha,
                                Some(&run_id),
                            )?;
                            persist_review_run_state(
                                &mut run_state,
                                ReviewRunStatus::Pending,
                                Some("sha_update".to_string()),
                                &current_head_sha,
                                &current_model,
                                restart_count,
                                None,
                            )?;
                            spawn_mode = SpawnMode::Resume {
                                message: build_sha_update_message(
                                    pr_number,
                                    &old_sha,
                                    &latest_head,
                                ),
                            };
                            continue 'restart_loop;
                        }

                        remove_review_state_entry(&run_key)?;
                        let completion_reason = signal.decision.to_ascii_lowercase();
                        persist_review_run_state(
                            &mut run_state,
                            ReviewRunStatus::Done,
                            Some(completion_reason.clone()),
                            &current_head_sha,
                            &current_model,
                            restart_count,
                            None,
                        )?;

                        return Ok(SingleReviewResult {
                            summary: build_single_review_summary(
                                &run_id,
                                sequence_number,
                                ReviewRunStatus::Done,
                                review_type,
                                true,
                                signal.verdict,
                                Some(completion_reason),
                                &current_model.model,
                                current_model.backend.as_str(),
                                review_started.elapsed().as_secs(),
                                restart_count,
                                tokens,
                            ),
                            final_head_sha: current_head_sha,
                        });
                    }

                    if run_state.nudge_count < MAX_MISSING_VERDICT_NUDGES
                        && restart_count < MAX_RESTART_ATTEMPTS
                        && !missing_verdict_nudge_disabled()
                    {
                        let nudge_message =
                            build_missing_verdict_nudge_message(review_kind, &prompt_path);
                        let required_command = required_verdict_command(review_kind);
                        run_state.nudge_count = run_state.nudge_count.saturating_add(1);
                        emit_run_event(
                            "nudge_resume",
                            &current_head_sha,
                            serde_json::json!({
                                "nudge_count": run_state.nudge_count,
                                "required_command": required_command,
                                "reason": "clean_exit_without_verdict",
                            }),
                        )?;
                        persist_review_run_state(
                            &mut run_state,
                            ReviewRunStatus::Pending,
                            Some("nudge_resume".to_string()),
                            &current_head_sha,
                            &current_model,
                            restart_count,
                            None,
                        )?;
                        spawn_mode = SpawnMode::Resume {
                            message: nudge_message,
                        };
                        continue 'restart_loop;
                    }

                    let comment_permission_denied = detect_comment_permission_denied(&log_path);
                    emit_run_event(
                        "run_crash",
                        &current_head_sha,
                        serde_json::json!({
                            "exit_code": exit_code.unwrap_or(0),
                            "signal": if comment_permission_denied { "auth_permission_denied" } else { "invalid_completion" },
                            "duration_secs": run_started.elapsed().as_secs(),
                            "restart_count": restart_count,
                            "completion_issue": "decision_receipt_missing",
                            "reason": if comment_permission_denied { "comment_post_permission_denied" } else { "invalid_completion" },
                        }),
                    )?;
                    if comment_permission_denied {
                        remove_review_state_entry(&run_key)?;
                        persist_review_run_state(
                            &mut run_state,
                            ReviewRunStatus::Crashed,
                            Some("comment_post_permission_denied".to_string()),
                            &current_head_sha,
                            &current_model,
                            restart_count,
                            None,
                        )?;
                        return Ok(SingleReviewResult {
                            summary: build_single_review_summary(
                                &run_id,
                                sequence_number,
                                ReviewRunStatus::Crashed,
                                review_type,
                                false,
                                "UNKNOWN".to_string(),
                                Some("comment_post_permission_denied".to_string()),
                                &current_model.model,
                                current_model.backend.as_str(),
                                review_started.elapsed().as_secs(),
                                restart_count,
                                extract_token_usage(&log_path),
                            ),
                            final_head_sha: current_head_sha,
                        });
                    }
                } else {
                    let reason_is_http = detect_http_400_or_rate_limit(&log_path);
                    let reason_is_auth = detect_comment_permission_denied(&log_path);
                    emit_run_event(
                        "run_crash",
                        &current_head_sha,
                        serde_json::json!({
                            "exit_code": exit_code.unwrap_or(1),
                            "signal": super::exit_signal(status),
                            "duration_secs": run_started.elapsed().as_secs(),
                            "restart_count": restart_count,
                            "reason": if reason_is_auth { "comment_post_permission_denied" } else if reason_is_http { "http_400_or_rate_limit" } else { "run_crash" },
                        }),
                    )?;
                    if reason_is_auth {
                        remove_review_state_entry(&run_key)?;
                        persist_review_run_state(
                            &mut run_state,
                            ReviewRunStatus::Crashed,
                            Some("comment_post_permission_denied".to_string()),
                            &current_head_sha,
                            &current_model,
                            restart_count,
                            None,
                        )?;
                        return Ok(SingleReviewResult {
                            summary: build_single_review_summary(
                                &run_id,
                                sequence_number,
                                ReviewRunStatus::Crashed,
                                review_type,
                                false,
                                "UNKNOWN".to_string(),
                                Some("comment_post_permission_denied".to_string()),
                                &current_model.model,
                                current_model.backend.as_str(),
                                review_started.elapsed().as_secs(),
                                restart_count,
                                extract_token_usage(&log_path),
                            ),
                            final_head_sha: current_head_sha,
                        });
                    }

                    restart_count = restart_count.saturating_add(1);
                    if restart_count > MAX_RESTART_ATTEMPTS {
                        remove_review_state_entry(&run_key)?;
                        persist_review_run_state(
                            &mut run_state,
                            ReviewRunStatus::Failed,
                            Some("max_restarts_exceeded".to_string()),
                            &current_head_sha,
                            &current_model,
                            restart_count,
                            None,
                        )?;
                        return Ok(SingleReviewResult {
                            summary: build_single_review_summary(
                                &run_id,
                                sequence_number,
                                ReviewRunStatus::Failed,
                                review_type,
                                false,
                                "UNKNOWN".to_string(),
                                Some("max_restarts_exceeded".to_string()),
                                &current_model.model,
                                current_model.backend.as_str(),
                                review_started.elapsed().as_secs(),
                                restart_count,
                                extract_token_usage(&log_path),
                            ),
                            final_head_sha: current_head_sha,
                        });
                    }

                    if reason_is_http {
                        backoff_before_cross_family_fallback(restart_count);
                    }
                    let fallback = if reason_is_http {
                        select_cross_family_fallback(&current_model.model)
                    } else {
                        select_fallback_model(&current_model.model)
                    }
                    .ok_or_else(|| "no fallback model available".to_string())?;

                    emit_run_event(
                        "model_fallback",
                        &current_head_sha,
                        serde_json::json!({
                            "from_model": current_model.model,
                            "to_model": fallback.model,
                            "reason": if reason_is_http { "http_400_or_rate_limit" } else { "run_crash" },
                        }),
                    )?;

                    current_model = ensure_model_backend_available(fallback)?;
                    persist_review_run_state(
                        &mut run_state,
                        ReviewRunStatus::Pending,
                        Some(if reason_is_http {
                            "http_400_or_rate_limit".to_string()
                        } else {
                            "run_crash".to_string()
                        }),
                        &current_head_sha,
                        &current_model,
                        restart_count,
                        None,
                    )?;
                    spawn_mode = SpawnMode::Initial;
                    continue 'restart_loop;
                }

                restart_count = restart_count.saturating_add(1);
                if restart_count > MAX_RESTART_ATTEMPTS {
                    remove_review_state_entry(&run_key)?;
                    persist_review_run_state(
                        &mut run_state,
                        ReviewRunStatus::Failed,
                        Some("max_restarts_exceeded".to_string()),
                        &current_head_sha,
                        &current_model,
                        restart_count,
                        None,
                    )?;
                    return Ok(SingleReviewResult {
                        summary: build_single_review_summary(
                            &run_id,
                            sequence_number,
                            ReviewRunStatus::Failed,
                            review_type,
                            false,
                            "UNKNOWN".to_string(),
                            Some("max_restarts_exceeded".to_string()),
                            &current_model.model,
                            current_model.backend.as_str(),
                            review_started.elapsed().as_secs(),
                            restart_count,
                            extract_token_usage(&log_path),
                        ),
                        final_head_sha: current_head_sha,
                    });
                }

                let reason_is_http = detect_http_400_or_rate_limit(&log_path);
                if reason_is_http {
                    backoff_before_cross_family_fallback(restart_count);
                }
                let fallback = select_cross_family_fallback(&current_model.model)
                    .ok_or_else(|| "no fallback model available".to_string())?;

                emit_run_event(
                    "model_fallback",
                    &current_head_sha,
                    serde_json::json!({
                        "from_model": current_model.model,
                        "to_model": fallback.model,
                        "reason": if reason_is_http { "http_400_or_rate_limit" } else { "invalid_completion" },
                    }),
                )?;

                current_model = ensure_model_backend_available(fallback)?;
                persist_review_run_state(
                    &mut run_state,
                    ReviewRunStatus::Pending,
                    Some(if reason_is_http {
                        "http_400_or_rate_limit".to_string()
                    } else {
                        "invalid_completion".to_string()
                    }),
                    &current_head_sha,
                    &current_model,
                    restart_count,
                    None,
                )?;
                spawn_mode = SpawnMode::Initial;
                continue 'restart_loop;
            }

            thread::sleep(LOOP_SLEEP);

            if last_pulse_check.elapsed() >= PULSE_POLL_INTERVAL {
                let latest_head = fetch_pr_head_sha_authoritative(owner_repo, pr_number)?;
                emit_run_event(
                    "pulse_check",
                    &current_head_sha,
                    serde_json::json!({
                        "pulse_sha": latest_head,
                        "match": latest_head.eq_ignore_ascii_case(&current_head_sha),
                    }),
                )?;
                last_pulse_check = Instant::now();

                if !latest_head.eq_ignore_ascii_case(&current_head_sha) {
                    emit_run_event(
                        "sha_update",
                        &current_head_sha,
                        serde_json::json!({
                            "old_sha": current_head_sha,
                            "new_sha": latest_head,
                        }),
                    )?;
                    super::terminate_child(&mut child)?;
                    let old_sha = current_head_sha.clone();
                    current_head_sha.clone_from(&latest_head);
                    write_pulse_file(pr_number, review_type, &current_head_sha, Some(&run_id))?;
                    persist_review_run_state(
                        &mut run_state,
                        ReviewRunStatus::Pending,
                        Some("sha_update".to_string()),
                        &current_head_sha,
                        &current_model,
                        restart_count,
                        None,
                    )?;
                    spawn_mode = SpawnMode::Resume {
                        message: build_sha_update_message(pr_number, &old_sha, &latest_head),
                    };
                    continue 'restart_loop;
                }
            }

            if last_liveness_report.elapsed() >= LIVENESS_REPORT_INTERVAL {
                let liveness = scan_log_liveness(&log_path, &mut cursor, &mut last_event_type)?;
                total_events_seen = total_events_seen.saturating_add(liveness.events_since_last);
                if liveness.made_progress {
                    last_progress_at = Instant::now();
                }
                let idle_secs = last_progress_at.elapsed().as_secs();

                emit_run_event(
                    "liveness_check",
                    &current_head_sha,
                    serde_json::json!({
                        "events_since_last": liveness.events_since_last,
                        "last_tool_call_age_secs": idle_secs,
                        "log_bytes": liveness.log_bytes,
                    }),
                )?;
                last_liveness_report = Instant::now();

                if detect_comment_permission_denied(&log_path) {
                    emit_run_event(
                        "run_crash",
                        &current_head_sha,
                        serde_json::json!({
                            "exit_code": -1,
                            "signal": "auth_permission_denied",
                            "duration_secs": run_started.elapsed().as_secs(),
                            "restart_count": restart_count,
                            "reason": "comment_post_permission_denied",
                        }),
                    )?;
                    super::terminate_child(&mut child)?;
                    remove_review_state_entry(&run_key)?;
                    persist_review_run_state(
                        &mut run_state,
                        ReviewRunStatus::Crashed,
                        Some("comment_post_permission_denied".to_string()),
                        &current_head_sha,
                        &current_model,
                        restart_count,
                        None,
                    )?;
                    return Ok(SingleReviewResult {
                        summary: build_single_review_summary(
                            &run_id,
                            sequence_number,
                            ReviewRunStatus::Crashed,
                            review_type,
                            false,
                            "UNKNOWN".to_string(),
                            Some("comment_post_permission_denied".to_string()),
                            &current_model.model,
                            current_model.backend.as_str(),
                            review_started.elapsed().as_secs(),
                            restart_count,
                            extract_token_usage(&log_path),
                        ),
                        final_head_sha: current_head_sha,
                    });
                }

                if last_progress_at.elapsed() >= STALL_THRESHOLD {
                    emit_run_event(
                        "stall_detected",
                        &current_head_sha,
                        serde_json::json!({
                            "stall_duration_secs": last_progress_at.elapsed().as_secs(),
                            "total_events_seen": total_events_seen,
                            "last_event_type": liveness.last_event_type,
                        }),
                    )?;
                    super::terminate_child(&mut child)?;

                    restart_count = restart_count.saturating_add(1);
                    if restart_count > MAX_RESTART_ATTEMPTS {
                        remove_review_state_entry(&run_key)?;
                        persist_review_run_state(
                            &mut run_state,
                            ReviewRunStatus::Failed,
                            Some("max_restarts_exceeded".to_string()),
                            &current_head_sha,
                            &current_model,
                            restart_count,
                            None,
                        )?;
                        return Ok(SingleReviewResult {
                            summary: build_single_review_summary(
                                &run_id,
                                sequence_number,
                                ReviewRunStatus::Failed,
                                review_type,
                                false,
                                "UNKNOWN".to_string(),
                                Some("max_restarts_exceeded".to_string()),
                                &current_model.model,
                                current_model.backend.as_str(),
                                review_started.elapsed().as_secs(),
                                restart_count,
                                extract_token_usage(&log_path),
                            ),
                            final_head_sha: current_head_sha,
                        });
                    }

                    let fallback = select_fallback_model(&current_model.model)
                        .ok_or_else(|| "no fallback model available after stall".to_string())?;
                    emit_run_event(
                        "model_fallback",
                        &current_head_sha,
                        serde_json::json!({
                            "from_model": current_model.model,
                            "to_model": fallback.model,
                            "reason": "stall_detected",
                        }),
                    )?;
                    current_model = ensure_model_backend_available(fallback)?;
                    persist_review_run_state(
                        &mut run_state,
                        ReviewRunStatus::Pending,
                        Some("stall_detected".to_string()),
                        &current_head_sha,
                        &current_model,
                        restart_count,
                        None,
                    )?;
                    spawn_mode = SpawnMode::Initial;
                    continue 'restart_loop;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::Utc;

    use super::{
        MISSING_VERDICT_NUDGE_PROMPT_MAX_CHARS, ReviewKind, build_missing_verdict_nudge_message,
        required_verdict_command, seeded_pending_run_identity, should_dedupe_on_lease_contention,
    };
    use crate::commands::fac_review::types::{
        ReviewBackend, ReviewRunState, ReviewRunStatus, ReviewStateEntry,
    };

    fn sample_run_state() -> ReviewRunState {
        ReviewRunState {
            run_id: "pr441-security-s2-01234567".to_string(),
            owner_repo: "example/repo".to_string(),
            pr_number: 441,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            review_type: "security".to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: "2026-02-17T00:00:00Z".to_string(),
            status: ReviewRunStatus::Pending,
            terminal_reason: None,
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

    fn sample_review_entry(pid: u32) -> ReviewStateEntry {
        ReviewStateEntry {
            pid,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/review.log"),
            prompt_file: None,
            last_message_file: None,
            review_type: "security".to_string(),
            pr_number: 441,
            owner_repo: "example/repo".to_string(),
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            restart_count: 0,
            model: "gpt-5.3-codex".to_string(),
            backend: ReviewBackend::Codex,
            temp_files: Vec::new(),
            run_id: "pr441-security-s2-01234567".to_string(),
            sequence_number: 2,
            terminal_reason: None,
            model_id: Some("gpt-5.3-codex".to_string()),
            backend_id: Some("codex".to_string()),
            status: ReviewRunStatus::Alive,
        }
    }

    fn sample_run_state_with_pid(pid: u32, proc_start_time: Option<u64>) -> ReviewRunState {
        let mut state = sample_run_state();
        state.pid = Some(pid);
        state.proc_start_time = proc_start_time;
        state
    }

    #[test]
    fn required_verdict_command_uses_code_quality_dimension_for_quality_reviews() {
        let command = required_verdict_command(ReviewKind::Quality);
        assert!(command.starts_with("cargo run -p apm2-cli -- fac review verdict set"));
        assert!(command.contains("--dimension code-quality"));
        assert!(!command.contains("--sha"));
    }

    #[test]
    fn build_missing_verdict_nudge_message_embeds_required_command_and_prompt_excerpt() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let prompt_path = temp.path().join("prompt.md");
        let oversized_prompt = "x".repeat(MISSING_VERDICT_NUDGE_PROMPT_MAX_CHARS + 128);
        std::fs::write(&prompt_path, oversized_prompt).expect("write prompt");

        let message = build_missing_verdict_nudge_message(ReviewKind::Security, &prompt_path);

        assert!(message.contains("RESUME TASK"));
        assert!(message.contains("cargo run -p apm2-cli -- fac review verdict set"));
        assert!(message.contains("--dimension security"));
        assert!(message.contains("...[truncated]"));
    }

    #[test]
    fn seeded_pending_run_identity_reuses_seeded_state() {
        let state = sample_run_state();
        let identity = seeded_pending_run_identity(
            Some(&state),
            "0123456789abcdef0123456789abcdef01234567",
            441,
            "security",
        )
        .expect("expected seeded identity");
        assert_eq!(identity.0, 2);
        assert_eq!(identity.1, "pr441-security-s2-01234567");
    }

    #[test]
    fn seeded_pending_run_identity_rejects_non_pending_or_pid_bound_state() {
        let mut terminal = sample_run_state();
        terminal.status = ReviewRunStatus::Done;
        assert!(
            seeded_pending_run_identity(
                Some(&terminal),
                "0123456789abcdef0123456789abcdef01234567",
                441,
                "security",
            )
            .is_none()
        );

        let mut pid_bound = sample_run_state();
        pid_bound.pid = Some(std::process::id());
        assert!(
            seeded_pending_run_identity(
                Some(&pid_bound),
                "0123456789abcdef0123456789abcdef01234567",
                441,
                "security",
            )
            .is_none()
        );
    }

    #[test]
    fn lease_contention_without_active_reviewer_must_not_dedupe() {
        let state = sample_run_state();
        assert!(
            !should_dedupe_on_lease_contention(
                "0123456789abcdef0123456789abcdef01234567",
                Some(&state),
                None,
            ),
            "pending/no-pid state without active entry must not dedupe"
        );
    }

    #[test]
    fn lease_contention_with_active_entry_dedupes() {
        // Spawn an ephemeral process to provide a known-live pid.
        let mut child = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .expect("spawn helper process");
        let entry = sample_review_entry(child.id());
        assert!(should_dedupe_on_lease_contention(
            "0123456789abcdef0123456789abcdef01234567",
            None,
            Some(&entry),
        ));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn lease_contention_with_identity_matched_state_dedupes() {
        let mut child = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .expect("spawn helper process");
        let proc_start_time =
            crate::commands::fac_review::state::get_process_start_time(child.id())
                .expect("read process start time");
        let state = sample_run_state_with_pid(child.id(), Some(proc_start_time));

        assert!(should_dedupe_on_lease_contention(
            "0123456789abcdef0123456789abcdef01234567",
            Some(&state),
            None,
        ));

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn lease_contention_with_pid_reuse_style_mismatch_must_not_dedupe() {
        let mut child = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .expect("spawn helper process");
        let proc_start_time =
            crate::commands::fac_review::state::get_process_start_time(child.id())
                .expect("read process start time");
        let state = sample_run_state_with_pid(child.id(), Some(proc_start_time + 1));

        assert!(
            !should_dedupe_on_lease_contention(
                "0123456789abcdef0123456789abcdef01234567",
                Some(&state),
                None,
            ),
            "mismatched proc_start_time must not dedupe"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn lease_contention_with_missing_proc_start_time_must_not_dedupe() {
        let mut child = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .expect("spawn helper process");
        let state = sample_run_state_with_pid(child.id(), None);

        assert!(
            !should_dedupe_on_lease_contention(
                "0123456789abcdef0123456789abcdef01234567",
                Some(&state),
                None,
            ),
            "missing proc_start_time must not dedupe state-only contention"
        );

        let _ = child.kill();
        let _ = child.wait();
    }
}
