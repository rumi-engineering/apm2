//! Core state machine: `run_review_inner` and `run_single_review`.

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use std::{fs, thread};

use super::backend::{
    build_prompt_content, build_resume_script_command_for_backend,
    build_script_command_for_backend, build_sha_update_message,
};
use super::barrier::{
    confirm_review_posted, confirm_review_posted_with_retry, fetch_pr_head_sha,
    resolve_authenticated_gh_login,
};
use super::detection::{
    detect_comment_permission_denied, detect_http_400_or_rate_limit, infer_verdict,
};
use super::events::emit_event;
use super::liveness::scan_log_liveness;
use super::model_pool::{
    acquire_provider_slot, backoff_before_cross_family_fallback, ensure_model_backend_available,
    select_cross_family_fallback, select_fallback_model, select_review_model_random,
};
use super::state::{
    build_run_key, find_active_review_entry, remove_review_state_entry, try_acquire_review_lease,
    upsert_review_state_entry, write_pulse_file,
};
use super::types::{
    ExecutionContext, LIVENESS_REPORT_INTERVAL, LOOP_SLEEP, MAX_RESTART_ATTEMPTS,
    PULSE_POLL_INTERVAL, ReviewKind, ReviewModelSelection, ReviewRunSummary, ReviewRunType,
    ReviewStateEntry, STALL_THRESHOLD, SingleReviewResult, SingleReviewSummary, SpawnMode,
    split_owner_repo, validate_expected_head_sha,
};

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

// ── run_review_inner ────────────────────────────────────────────────────────

pub fn run_review_inner(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
) -> Result<ReviewRunSummary, String> {
    let (owner_repo, pr_number) = super::types::parse_pr_url(pr_url)?;
    let current_head_sha = fetch_pr_head_sha(&owner_repo, pr_number)?;
    let initial_head_sha = current_head_sha.clone();
    if let Some(expected) = expected_head_sha {
        validate_expected_head_sha(expected)?;
        if !expected.eq_ignore_ascii_case(&current_head_sha) {
            return Err(format!(
                "PR head moved before review start: expected {expected}, got {current_head_sha}"
            ));
        }
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
                pr_url,
                &owner_repo,
                pr_number,
                ReviewKind::Security,
                current_head_sha,
                selected,
                &event_ctx,
            )?;
            final_heads.push(result.final_head_sha.clone());
            security_summary = Some(result.summary);
        },
        ReviewRunType::Quality => {
            let selected = select_review_model_random();
            let result = run_single_review(
                pr_url,
                &owner_repo,
                pr_number,
                ReviewKind::Quality,
                current_head_sha,
                selected,
                &event_ctx,
            )?;
            final_heads.push(result.final_head_sha.clone());
            quality_summary = Some(result.summary);
        },
        ReviewRunType::All => {
            let sec_pr_url = pr_url.to_string();
            let sec_owner_repo = owner_repo.clone();
            let sec_head = current_head_sha.clone();
            let sec_ctx = event_ctx.clone();
            let sec_model = select_review_model_random();
            let sec_handle = thread::spawn(move || {
                run_single_review(
                    &sec_pr_url,
                    &sec_owner_repo,
                    pr_number,
                    ReviewKind::Security,
                    sec_head,
                    sec_model,
                    &sec_ctx,
                )
            });

            let qual_pr_url = pr_url.to_string();
            let qual_owner_repo = owner_repo.clone();
            let qual_head = current_head_sha;
            let qual_ctx = event_ctx.clone();
            let qual_model = select_review_model_random();
            let qual_handle = thread::spawn(move || {
                run_single_review(
                    &qual_pr_url,
                    &qual_owner_repo,
                    pr_number,
                    ReviewKind::Quality,
                    qual_head,
                    qual_model,
                    &qual_ctx,
                )
            });

            let sec_result = sec_handle
                .join()
                .map_err(|_| "security review worker panicked".to_string())??;
            let qual_result = qual_handle
                .join()
                .map_err(|_| "quality review worker panicked".to_string())??;
            final_heads.push(sec_result.final_head_sha.clone());
            final_heads.push(qual_result.final_head_sha.clone());
            security_summary = Some(sec_result.summary);
            quality_summary = Some(qual_result.summary);
        },
    }

    let current_head_sha = fetch_pr_head_sha(&owner_repo, pr_number)
        .ok()
        .or_else(|| final_heads.into_iter().last())
        .unwrap_or_else(|| initial_head_sha.clone());

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
        }),
    )?;

    Ok(ReviewRunSummary {
        pr_url: pr_url.to_string(),
        pr_number,
        initial_head_sha,
        final_head_sha: current_head_sha,
        total_secs: total_started.elapsed().as_secs(),
        security: security_summary,
        quality: quality_summary,
    })
}

// ── run_single_review ───────────────────────────────────────────────────────

fn run_single_review(
    pr_url: &str,
    owner_repo: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    initial_head_sha: String,
    initial_model: ReviewModelSelection,
    event_ctx: &ExecutionContext,
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
    let expected_comment_author = resolve_authenticated_gh_login();

    let Some(_lease) = try_acquire_review_lease(owner_repo, pr_number, review_type)? else {
        let existing = find_active_review_entry(pr_number, review_type, Some(&current_head_sha))?;
        emit_event(
            event_ctx,
            "run_deduplicated",
            review_type,
            &current_head_sha,
            serde_json::json!({
                "reason": "active_review_for_same_type",
                "existing_pid": existing.as_ref().map(|entry| entry.pid),
                "existing_sha": existing.as_ref().map(|entry| entry.head_sha.clone()),
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
            summary: SingleReviewSummary {
                review_type: review_type.to_string(),
                success: true,
                verdict: "DEDUPED".to_string(),
                model,
                backend,
                duration_secs: review_started.elapsed().as_secs(),
                restart_count,
            },
            final_head_sha: current_head_sha,
        });
    };
    write_pulse_file(pr_number, review_type, &current_head_sha)?;
    let run_key = build_run_key(pr_number, review_type, &current_head_sha);

    'restart_loop: loop {
        if let Some(posted_review) = confirm_review_posted(
            owner_repo,
            pr_number,
            review_kind.marker(),
            &current_head_sha,
            expected_comment_author.as_deref(),
        )? {
            let completion_verdict = posted_review
                .verdict
                .clone()
                .unwrap_or_else(|| "UNKNOWN".to_string());
            emit_event(
                event_ctx,
                "run_deduplicated",
                review_type,
                &current_head_sha,
                serde_json::json!({
                    "reason": "review_comment_already_present",
                    "comment_id": posted_review.id,
                    "verdict": completion_verdict,
                }),
            )?;
            return Ok(SingleReviewResult {
                summary: SingleReviewSummary {
                    review_type: review_type.to_string(),
                    success: completion_verdict != "UNKNOWN",
                    verdict: completion_verdict,
                    model: current_model.model.clone(),
                    backend: current_model.backend.as_str().to_string(),
                    duration_secs: review_started.elapsed().as_secs(),
                    restart_count,
                },
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

        let command = match &spawn_mode {
            SpawnMode::Initial => build_script_command_for_backend(
                current_model.backend,
                &prompt_path,
                &log_path,
                &current_model.model,
                Some(&last_message_path),
            ),
            SpawnMode::Resume { message } => build_resume_script_command_for_backend(
                current_model.backend,
                &log_path,
                &current_model.model,
                message,
            ),
        };

        let _provider_slot_lease = acquire_provider_slot(current_model.backend)?;
        let mut child = Command::new("sh")
            .args(["-lc", &command])
            .spawn()
            .map_err(|err| format!("failed to spawn {} review: {err}", review_kind.display()))?;

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
                pr_url: pr_url.to_string(),
                head_sha: current_head_sha.clone(),
                restart_count,
                model: current_model.model.clone(),
                backend: current_model.backend,
                temp_files: Vec::new(),
            },
        )?;

        emit_event(
            event_ctx,
            "run_start",
            review_type,
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
            if let Some(status) = child
                .try_wait()
                .map_err(|err| format!("failed to poll reviewer process: {err}"))?
            {
                let exit_code = status.code();
                if status.success() {
                    let verdict = infer_verdict(review_kind, &last_message_path, &log_path)?;
                    let posted_review = confirm_review_posted_with_retry(
                        owner_repo,
                        pr_number,
                        review_kind.marker(),
                        &current_head_sha,
                        expected_comment_author.as_deref(),
                    )?;
                    let comment_id = posted_review.as_ref().map(|review| review.id);
                    let completion_verdict = posted_review
                        .as_ref()
                        .and_then(|review| review.verdict.clone())
                        .unwrap_or_else(|| verdict.clone());
                    let is_valid_completion = comment_id.is_some();

                    if is_valid_completion {
                        emit_event(
                            event_ctx,
                            "run_complete",
                            review_type,
                            &current_head_sha,
                            serde_json::json!({
                                "exit_code": exit_code.unwrap_or(0),
                                "duration_secs": run_started.elapsed().as_secs(),
                                "verdict": completion_verdict,
                            }),
                        )?;

                        if let Some(comment_id) = comment_id {
                            emit_event(
                                event_ctx,
                                "review_posted",
                                review_type,
                                &current_head_sha,
                                serde_json::json!({
                                    "comment_id": comment_id,
                                    "verdict": completion_verdict,
                                }),
                            )?;
                        }

                        let latest_head = fetch_pr_head_sha(owner_repo, pr_number)?;
                        emit_event(
                            event_ctx,
                            "pulse_check",
                            review_type,
                            &current_head_sha,
                            serde_json::json!({
                                "pulse_sha": latest_head,
                                "match": latest_head.eq_ignore_ascii_case(&current_head_sha),
                            }),
                        )?;
                        if !latest_head.eq_ignore_ascii_case(&current_head_sha) {
                            let old_sha = current_head_sha.clone();
                            emit_event(
                                event_ctx,
                                "sha_update",
                                review_type,
                                &old_sha,
                                serde_json::json!({
                                    "old_sha": old_sha,
                                    "new_sha": latest_head,
                                }),
                            )?;
                            current_head_sha.clone_from(&latest_head);
                            write_pulse_file(pr_number, review_type, &current_head_sha)?;
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

                        return Ok(SingleReviewResult {
                            summary: SingleReviewSummary {
                                review_type: review_type.to_string(),
                                success: true,
                                verdict: completion_verdict,
                                model: current_model.model,
                                backend: current_model.backend.as_str().to_string(),
                                duration_secs: review_started.elapsed().as_secs(),
                                restart_count,
                            },
                            final_head_sha: current_head_sha,
                        });
                    }

                    let comment_permission_denied = detect_comment_permission_denied(&log_path);
                    emit_event(
                        event_ctx,
                        "run_crash",
                        review_type,
                        &current_head_sha,
                        serde_json::json!({
                            "exit_code": exit_code.unwrap_or(0),
                            "signal": if comment_permission_denied { "auth_permission_denied" } else { "invalid_completion" },
                            "duration_secs": run_started.elapsed().as_secs(),
                            "restart_count": restart_count,
                            "completion_issue": "comment_not_posted",
                            "verdict": completion_verdict,
                            "reason": if comment_permission_denied { "comment_post_permission_denied" } else { "invalid_completion" },
                        }),
                    )?;
                    if comment_permission_denied {
                        remove_review_state_entry(&run_key)?;
                        return Ok(SingleReviewResult {
                            summary: SingleReviewSummary {
                                review_type: review_type.to_string(),
                                success: false,
                                verdict: "UNKNOWN".to_string(),
                                model: current_model.model,
                                backend: current_model.backend.as_str().to_string(),
                                duration_secs: review_started.elapsed().as_secs(),
                                restart_count,
                            },
                            final_head_sha: current_head_sha,
                        });
                    }
                } else {
                    let reason_is_http = detect_http_400_or_rate_limit(&log_path);
                    let reason_is_auth = detect_comment_permission_denied(&log_path);
                    emit_event(
                        event_ctx,
                        "run_crash",
                        review_type,
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
                        return Ok(SingleReviewResult {
                            summary: SingleReviewSummary {
                                review_type: review_type.to_string(),
                                success: false,
                                verdict: "UNKNOWN".to_string(),
                                model: current_model.model,
                                backend: current_model.backend.as_str().to_string(),
                                duration_secs: review_started.elapsed().as_secs(),
                                restart_count,
                            },
                            final_head_sha: current_head_sha,
                        });
                    }

                    restart_count = restart_count.saturating_add(1);
                    if restart_count > MAX_RESTART_ATTEMPTS {
                        remove_review_state_entry(&run_key)?;
                        return Ok(SingleReviewResult {
                            summary: SingleReviewSummary {
                                review_type: review_type.to_string(),
                                success: false,
                                verdict: "UNKNOWN".to_string(),
                                model: current_model.model,
                                backend: current_model.backend.as_str().to_string(),
                                duration_secs: review_started.elapsed().as_secs(),
                                restart_count,
                            },
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

                    emit_event(
                        event_ctx,
                        "model_fallback",
                        review_type,
                        &current_head_sha,
                        serde_json::json!({
                            "from_model": current_model.model,
                            "to_model": fallback.model,
                            "reason": if reason_is_http { "http_400_or_rate_limit" } else { "run_crash" },
                        }),
                    )?;

                    current_model = ensure_model_backend_available(fallback)?;
                    spawn_mode = SpawnMode::Initial;
                    continue 'restart_loop;
                }

                restart_count = restart_count.saturating_add(1);
                if restart_count > MAX_RESTART_ATTEMPTS {
                    remove_review_state_entry(&run_key)?;
                    return Ok(SingleReviewResult {
                        summary: SingleReviewSummary {
                            review_type: review_type.to_string(),
                            success: false,
                            verdict: "UNKNOWN".to_string(),
                            model: current_model.model,
                            backend: current_model.backend.as_str().to_string(),
                            duration_secs: review_started.elapsed().as_secs(),
                            restart_count,
                        },
                        final_head_sha: current_head_sha,
                    });
                }

                let reason_is_http = detect_http_400_or_rate_limit(&log_path);
                if reason_is_http {
                    backoff_before_cross_family_fallback(restart_count);
                }
                let fallback = if reason_is_http {
                    select_cross_family_fallback(&current_model.model)
                } else {
                    select_fallback_model(&current_model.model)
                }
                .ok_or_else(|| "no fallback model available".to_string())?;

                emit_event(
                    event_ctx,
                    "model_fallback",
                    review_type,
                    &current_head_sha,
                    serde_json::json!({
                        "from_model": current_model.model,
                        "to_model": fallback.model,
                        "reason": if reason_is_http { "http_400_or_rate_limit" } else { "invalid_completion" },
                    }),
                )?;

                current_model = ensure_model_backend_available(fallback)?;
                spawn_mode = SpawnMode::Initial;
                continue 'restart_loop;
            }

            thread::sleep(LOOP_SLEEP);

            if last_pulse_check.elapsed() >= PULSE_POLL_INTERVAL {
                let latest_head = fetch_pr_head_sha(owner_repo, pr_number)?;
                emit_event(
                    event_ctx,
                    "pulse_check",
                    review_type,
                    &current_head_sha,
                    serde_json::json!({
                        "pulse_sha": latest_head,
                        "match": latest_head.eq_ignore_ascii_case(&current_head_sha),
                    }),
                )?;
                last_pulse_check = Instant::now();

                if !latest_head.eq_ignore_ascii_case(&current_head_sha) {
                    emit_event(
                        event_ctx,
                        "sha_update",
                        review_type,
                        &current_head_sha,
                        serde_json::json!({
                            "old_sha": current_head_sha,
                            "new_sha": latest_head,
                        }),
                    )?;
                    super::terminate_child(&mut child)?;
                    let old_sha = current_head_sha.clone();
                    current_head_sha.clone_from(&latest_head);
                    write_pulse_file(pr_number, review_type, &current_head_sha)?;
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

                emit_event(
                    event_ctx,
                    "liveness_check",
                    review_type,
                    &current_head_sha,
                    serde_json::json!({
                        "events_since_last": liveness.events_since_last,
                        "last_tool_call_age_secs": idle_secs,
                        "log_bytes": liveness.log_bytes,
                    }),
                )?;
                last_liveness_report = Instant::now();

                if let Some(posted_review) = confirm_review_posted(
                    owner_repo,
                    pr_number,
                    review_kind.marker(),
                    &current_head_sha,
                    expected_comment_author.as_deref(),
                )? {
                    super::terminate_child(&mut child)?;
                    let completion_verdict = posted_review.verdict.unwrap_or_else(|| {
                        infer_verdict(review_kind, &last_message_path, &log_path)
                            .unwrap_or_else(|_| "UNKNOWN".to_string())
                    });
                    if completion_verdict != "UNKNOWN" {
                        emit_event(
                            event_ctx,
                            "run_complete",
                            review_type,
                            &current_head_sha,
                            serde_json::json!({
                                "exit_code": 0,
                                "duration_secs": run_started.elapsed().as_secs(),
                                "verdict": completion_verdict,
                                "completion_mode": "live_comment_detected",
                            }),
                        )?;
                        emit_event(
                            event_ctx,
                            "review_posted",
                            review_type,
                            &current_head_sha,
                            serde_json::json!({
                                "comment_id": posted_review.id,
                                "verdict": completion_verdict,
                                "completion_mode": "live_comment_detected",
                            }),
                        )?;
                        remove_review_state_entry(&run_key)?;
                        return Ok(SingleReviewResult {
                            summary: SingleReviewSummary {
                                review_type: review_type.to_string(),
                                success: true,
                                verdict: completion_verdict,
                                model: current_model.model,
                                backend: current_model.backend.as_str().to_string(),
                                duration_secs: review_started.elapsed().as_secs(),
                                restart_count,
                            },
                            final_head_sha: current_head_sha,
                        });
                    }
                }

                if detect_comment_permission_denied(&log_path) {
                    emit_event(
                        event_ctx,
                        "run_crash",
                        review_type,
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
                    return Ok(SingleReviewResult {
                        summary: SingleReviewSummary {
                            review_type: review_type.to_string(),
                            success: false,
                            verdict: "UNKNOWN".to_string(),
                            model: current_model.model,
                            backend: current_model.backend.as_str().to_string(),
                            duration_secs: review_started.elapsed().as_secs(),
                            restart_count,
                        },
                        final_head_sha: current_head_sha,
                    });
                }

                if last_progress_at.elapsed() >= STALL_THRESHOLD {
                    emit_event(
                        event_ctx,
                        "stall_detected",
                        review_type,
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
                        return Ok(SingleReviewResult {
                            summary: SingleReviewSummary {
                                review_type: review_type.to_string(),
                                success: false,
                                verdict: "UNKNOWN".to_string(),
                                model: current_model.model,
                                backend: current_model.backend.as_str().to_string(),
                                duration_secs: review_started.elapsed().as_secs(),
                                restart_count,
                            },
                            final_head_sha: current_head_sha,
                        });
                    }

                    let fallback = select_fallback_model(&current_model.model)
                        .ok_or_else(|| "no fallback model available after stall".to_string())?;
                    emit_event(
                        event_ctx,
                        "model_fallback",
                        review_type,
                        &current_head_sha,
                        serde_json::json!({
                            "from_model": current_model.model,
                            "to_model": fallback.model,
                            "reason": "stall_detected",
                        }),
                    )?;
                    current_model = ensure_model_backend_available(fallback)?;
                    spawn_mode = SpawnMode::Initial;
                    continue 'restart_loop;
                }
            }
        }
    }
}
