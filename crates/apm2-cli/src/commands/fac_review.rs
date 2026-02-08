//! FAC review orchestration commands.
//!
//! This module provides VPS-oriented, FAC-first review execution with:
//! - Security/quality orchestration (parallel when `--type all`)
//! - Multi-model backend dispatch (Codex + Gemini)
//! - NDJSON lifecycle telemetry under `~/.apm2/review_events.ndjson`
//! - Pulse-file based SHA freshness checks and resume flow
//! - Liveness-based stall detection and bounded model fallback

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use clap::ValueEnum;
use fs2::FileExt;
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::exit_codes::codes as exit_codes;

const EVENT_ROTATE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_RESTART_ATTEMPTS: u32 = 3;
const PULSE_POLL_INTERVAL: Duration = Duration::from_secs(30);
const LIVENESS_REPORT_INTERVAL: Duration = Duration::from_secs(30);
const STALL_THRESHOLD: Duration = Duration::from_secs(90);
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);
const LOOP_SLEEP: Duration = Duration::from_millis(1000);

const SECURITY_PROMPT_PATH: &str = "documents/reviews/SECURITY_REVIEW_PROMPT.md";
const QUALITY_PROMPT_PATH: &str = "documents/reviews/CODE_QUALITY_PROMPT.md";
const SECURITY_MARKER: &str = "<!-- apm2-review-metadata:v1:security -->";
const QUALITY_MARKER: &str = "<!-- apm2-review-metadata:v1:code-quality -->";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReviewBackend {
    #[default]
    Codex,
    Gemini,
}

impl ReviewBackend {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Gemini => "gemini",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewRunType {
    All,
    Security,
    Quality,
}

#[derive(Debug, Clone)]
pub struct ReviewModelSelection {
    pub model: String,
    pub backend: ReviewBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewKind {
    Security,
    Quality,
}

impl ReviewKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Quality => "quality",
        }
    }

    const fn display(self) -> &'static str {
        match self {
            Self::Security => "Security",
            Self::Quality => "Quality",
        }
    }

    const fn prompt_path(self) -> &'static str {
        match self {
            Self::Security => SECURITY_PROMPT_PATH,
            Self::Quality => QUALITY_PROMPT_PATH,
        }
    }

    const fn marker(self) -> &'static str {
        match self {
            Self::Security => SECURITY_MARKER,
            Self::Quality => QUALITY_MARKER,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewStateEntry {
    pid: u32,
    started_at: DateTime<Utc>,
    log_file: PathBuf,
    #[serde(default)]
    prompt_file: Option<PathBuf>,
    #[serde(default)]
    last_message_file: Option<PathBuf>,
    #[serde(default = "default_review_type")]
    review_type: String,
    #[serde(default)]
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    #[serde(default)]
    restart_count: u32,
    #[serde(default = "default_model")]
    model: String,
    #[serde(default)]
    backend: ReviewBackend,
    #[serde(default)]
    temp_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ReviewStateFile {
    #[serde(default)]
    reviewers: BTreeMap<String, ReviewStateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PulseFile {
    pub head_sha: String,
    pub written_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
struct SingleReviewSummary {
    review_type: String,
    success: bool,
    verdict: String,
    model: String,
    backend: String,
    duration_secs: u64,
    restart_count: u32,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewRunSummary {
    pr_url: String,
    pr_number: u32,
    initial_head_sha: String,
    final_head_sha: String,
    total_secs: u64,
    security: Option<SingleReviewSummary>,
    quality: Option<SingleReviewSummary>,
}

#[derive(Debug, Clone)]
struct ExecutionContext {
    pr_number: u32,
    seq: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
struct LivenessSnapshot {
    events_since_last: u64,
    last_event_type: String,
    log_bytes: u64,
    made_progress: bool,
}

#[derive(Debug, Clone, Copy)]
struct ModelPoolEntry {
    model: &'static str,
    backend: ReviewBackend,
}

#[derive(Debug, Clone)]
enum SpawnMode {
    Initial,
    Resume { message: String },
}

#[derive(Debug, Clone)]
struct SingleReviewResult {
    summary: SingleReviewSummary,
    final_head_sha: String,
}

const MODEL_POOL: [ModelPoolEntry; 3] = [
    ModelPoolEntry {
        model: "gemini-2.5-flash",
        backend: ReviewBackend::Gemini,
    },
    ModelPoolEntry {
        model: "gemini-2.5-pro",
        backend: ReviewBackend::Gemini,
    },
    ModelPoolEntry {
        model: "gpt-5.3-codex",
        backend: ReviewBackend::Codex,
    },
];

fn default_model() -> String {
    "gpt-5.3-codex".to_string()
}

fn default_review_type() -> String {
    "unknown".to_string()
}

fn now_iso8601_millis() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn select_review_model_random() -> ReviewModelSelection {
    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..MODEL_POOL.len());
    let selected = MODEL_POOL[idx];
    ReviewModelSelection {
        model: selected.model.to_string(),
        backend: selected.backend,
    }
}

pub fn select_fallback_model(failed: &str) -> Option<ReviewModelSelection> {
    let current_idx = MODEL_POOL
        .iter()
        .position(|entry| entry.model.eq_ignore_ascii_case(failed))?;
    let next_idx = (current_idx + 1) % MODEL_POOL.len();
    let next = MODEL_POOL[next_idx];
    Some(ReviewModelSelection {
        model: next.model.to_string(),
        backend: next.backend,
    })
}

fn select_cross_family_fallback(failed: &str) -> Option<ReviewModelSelection> {
    let current_idx = MODEL_POOL
        .iter()
        .position(|entry| entry.model.eq_ignore_ascii_case(failed))?;
    let current = MODEL_POOL[current_idx];
    for offset in 1..MODEL_POOL.len() {
        let idx = (current_idx + offset) % MODEL_POOL.len();
        let candidate = MODEL_POOL[idx];
        if candidate.backend != current.backend {
            return Some(ReviewModelSelection {
                model: candidate.model.to_string(),
                backend: candidate.backend,
            });
        }
    }
    select_fallback_model(failed)
}

pub fn run_review(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    json_output: bool,
) -> u8 {
    match run_review_inner(pr_url, review_type, expected_head_sha) {
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
                    println!(
                        "  Security:     {} (verdict={}, model={}, backend={}, restarts={}, secs={})",
                        if security.success { "PASS" } else { "FAIL" },
                        security.verdict,
                        security.model,
                        security.backend,
                        security.restart_count,
                        security.duration_secs
                    );
                }
                if let Some(quality) = &summary.quality {
                    println!(
                        "  Quality:      {} (verdict={}, model={}, backend={}, restarts={}, secs={})",
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

pub fn run_tail(lines: usize, follow: bool) -> u8 {
    match run_tail_inner(lines, follow) {
        Ok(()) => exit_codes::SUCCESS,
        Err(err) => {
            eprintln!("ERROR: {err}");
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_review_inner(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
) -> Result<ReviewRunSummary, String> {
    let (owner_repo, pr_number) = parse_pr_url(pr_url)?;
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

        let mut child = Command::new("sh")
            .args(["-lc", &command])
            .spawn()
            .map_err(|err| format!("failed to spawn {} review: {err}", review_kind.display()))?;

        upsert_review_state_entry(
            &run_key,
            ReviewStateEntry {
                pid: child.id(),
                started_at: Utc::now(),
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
                    let comment_id = confirm_review_posted_with_retry(
                        owner_repo,
                        pr_number,
                        review_kind.marker(),
                        &current_head_sha,
                    )?;
                    let is_valid_completion = verdict != "UNKNOWN" && comment_id.is_some();

                    if is_valid_completion {
                        emit_event(
                            event_ctx,
                            "run_complete",
                            review_type,
                            &current_head_sha,
                            serde_json::json!({
                                "exit_code": exit_code.unwrap_or(0),
                                "duration_secs": run_started.elapsed().as_secs(),
                                "verdict": verdict,
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
                                    "verdict": verdict,
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
                                verdict,
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
                            "completion_issue": if comment_id.is_none() { "comment_not_posted" } else { "unknown_verdict" },
                            "verdict": verdict,
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
                            "signal": exit_signal(status),
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
                    terminate_child(&mut child)?;
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
                    terminate_child(&mut child)?;
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

                if detect_http_400_or_rate_limit(&log_path) {
                    emit_event(
                        event_ctx,
                        "run_crash",
                        review_type,
                        &current_head_sha,
                        serde_json::json!({
                            "exit_code": -1,
                            "signal": "provider_backpressure",
                            "duration_secs": run_started.elapsed().as_secs(),
                            "restart_count": restart_count,
                            "reason": "http_400_or_rate_limit_live",
                        }),
                    )?;

                    terminate_child(&mut child)?;
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

                    let fallback = select_cross_family_fallback(&current_model.model)
                        .or_else(|| select_fallback_model(&current_model.model))
                        .ok_or_else(|| {
                            "no fallback model available after provider backpressure".to_string()
                        })?;
                    emit_event(
                        event_ctx,
                        "model_fallback",
                        review_type,
                        &current_head_sha,
                        serde_json::json!({
                            "from_model": current_model.model,
                            "to_model": fallback.model,
                            "reason": "http_400_or_rate_limit_live",
                        }),
                    )?;
                    current_model = ensure_model_backend_available(fallback)?;
                    spawn_mode = SpawnMode::Initial;
                    continue 'restart_loop;
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
                    terminate_child(&mut child)?;

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

    if json_output {
        let payload = serde_json::json!({
            "state_entries": filtered_state,
            "recent_events": filtered_events,
            "pulse_security": pulse_security,
            "pulse_quality": pulse_quality,
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
    }
    if filtered_state.is_empty() {
        println!("  Active Runs: none");
    } else {
        println!("  Active Runs:");
        for entry in filtered_state {
            println!(
                "    - {} | pid={} alive={} model={} backend={} sha={} restarts={}",
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
                "    [{}] {} {} pr=#{} sha={}",
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

    let last_lines = read_last_lines(&path, lines)?;
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

fn ensure_model_backend_available(
    selection: ReviewModelSelection,
) -> Result<ReviewModelSelection, String> {
    if backend_tool_available(selection.backend) {
        return Ok(selection);
    }

    let mut candidate = selection;
    for _ in 0..MODEL_POOL.len() {
        let fallback = select_fallback_model(&candidate.model)
            .ok_or_else(|| "could not select fallback model".to_string())?;
        if backend_tool_available(fallback.backend) {
            return Ok(fallback);
        }
        candidate = fallback;
    }

    Err(
        "no configured review backend tool is available (need codex and/or gemini in PATH)"
            .to_string(),
    )
}

fn backend_tool_available(backend: ReviewBackend) -> bool {
    let tool = match backend {
        ReviewBackend::Codex => "codex",
        ReviewBackend::Gemini => "gemini",
    };
    Command::new("sh")
        .args(["-lc", &format!("command -v {tool} >/dev/null 2>&1")])
        .status()
        .is_ok_and(|status| status.success())
}

fn build_prompt_content(
    prompt_template_path: &Path,
    pr_url: &str,
    head_sha: &str,
    owner: &str,
    repo: &str,
) -> Result<String, String> {
    let template = fs::read_to_string(prompt_template_path).map_err(|err| {
        format!(
            "failed to read prompt template {}: {err}",
            prompt_template_path.display()
        )
    })?;

    Ok(template
        .replace("$PR_URL", pr_url)
        .replace("$HEAD_SHA", head_sha)
        .replace(concat!("{", "owner", "}"), owner)
        .replace(concat!("{", "repo", "}"), repo))
}

fn parse_pr_url(pr_url: &str) -> Result<(String, u32), String> {
    let trimmed = pr_url.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let without_host = without_scheme
        .strip_prefix("github.com/")
        .ok_or_else(|| format!("invalid GitHub PR URL: {pr_url}"))?;
    let parts = without_host.split('/').collect::<Vec<_>>();
    if parts.len() < 4 || parts[2] != "pull" {
        return Err(format!("invalid GitHub PR URL format: {pr_url}"));
    }
    let pr_number = parts[3]
        .parse::<u32>()
        .map_err(|err| format!("invalid PR number in URL {pr_url}: {err}"))?;
    Ok((format!("{}/{}", parts[0], parts[1]), pr_number))
}

fn split_owner_repo(owner_repo: &str) -> Result<(&str, &str), String> {
    let mut parts = owner_repo.split('/');
    let owner = parts
        .next()
        .ok_or_else(|| format!("invalid owner/repo: {owner_repo}"))?;
    let repo = parts
        .next()
        .ok_or_else(|| format!("invalid owner/repo: {owner_repo}"))?;
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return Err(format!("invalid owner/repo: {owner_repo}"));
    }
    Ok((owner, repo))
}

fn validate_expected_head_sha(expected: &str) -> Result<(), String> {
    if expected.len() == 40 && expected.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(format!(
        "invalid expected head sha (need 40-hex): {expected}"
    ))
}

fn fetch_pr_head_sha(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = Command::new("gh")
        .args(["api", &endpoint, "--jq", ".head.sha"])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR head SHA: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving PR head SHA: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.is_empty() {
        return Err("gh api returned empty head sha".to_string());
    }
    Ok(sha)
}

fn resolve_repo_root() -> Result<PathBuf, String> {
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
    Ok(PathBuf::from(root))
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn build_script_wrapper_command(log_path: &Path, inner_command: &str, append: bool) -> String {
    let append_flag = if append { " -a" } else { "" };
    let log_q = sh_quote(&log_path.display().to_string());
    let inner_q = sh_quote(inner_command);
    format!("script -q{append_flag} {log_q} -c {inner_q}")
}

pub fn build_gemini_script_command(prompt_path: &Path, log_path: &Path, model: &str) -> String {
    let prompt_q = sh_quote(&prompt_path.display().to_string());
    let model_q = sh_quote(model);
    let inner = format!("gemini -m {model_q} -y -o stream-json -p \"$(cat {prompt_q})\"");
    build_script_wrapper_command(log_path, &inner, false)
}

pub fn build_script_command_for_backend(
    backend: ReviewBackend,
    prompt_path: &Path,
    log_path: &Path,
    model: &str,
    output_last_message_path: Option<&Path>,
) -> String {
    match backend {
        ReviewBackend::Codex => {
            let prompt_q = sh_quote(&prompt_path.display().to_string());
            let model_q = sh_quote(model);
            let output_flag = output_last_message_path.map_or_else(String::new, |path| {
                let capture_q = sh_quote(&path.display().to_string());
                format!("--output-last-message {capture_q} ")
            });
            let inner = format!(
                "codex exec --model {model_q} --dangerously-bypass-approvals-and-sandbox --json {output_flag}< {prompt_q}"
            );
            build_script_wrapper_command(log_path, &inner, false)
        },
        ReviewBackend::Gemini => build_gemini_script_command(prompt_path, log_path, model),
    }
}

pub fn build_resume_command_for_backend(
    backend: ReviewBackend,
    model: &str,
    sha_update_msg: &str,
) -> String {
    let msg_q = sh_quote(sha_update_msg);
    match backend {
        ReviewBackend::Codex => format!(
            "codex exec resume --last --dangerously-bypass-approvals-and-sandbox --json {msg_q}"
        ),
        ReviewBackend::Gemini => {
            let model_q = sh_quote(model);
            format!("gemini -m {model_q} -y --resume latest -p {msg_q}")
        },
    }
}

fn build_resume_script_command_for_backend(
    backend: ReviewBackend,
    log_path: &Path,
    model: &str,
    sha_update_msg: &str,
) -> String {
    let inner = build_resume_command_for_backend(backend, model, sha_update_msg);
    build_script_wrapper_command(log_path, &inner, true)
}

fn build_sha_update_message(pr_number: u32, old_sha: &str, new_sha: &str) -> String {
    format!(
        "CRITICAL: The PR HEAD has moved from {old_sha} to {new_sha}. Re-read the diff via 'gh pr diff {pr_number}'. Update your review and post a new comment targeting SHA {new_sha}. Your full prior analysis is preserved in this session."
    )
}

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
        thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

fn infer_verdict(
    review_kind: ReviewKind,
    last_message: &Path,
    log_path: &Path,
) -> Result<String, String> {
    let from_message = fs::read_to_string(last_message).unwrap_or_default();
    let source = if from_message.trim().is_empty() {
        read_tail(log_path, 120)?
    } else {
        from_message
    };

    let marker = review_kind.marker();
    let has_marker = source.contains(marker);
    let pass_re = Regex::new(r"(?i)\bPASS\b")
        .map_err(|err| format!("failed to compile PASS regex: {err}"))?;
    let fail_re = Regex::new(r"(?i)\bFAIL\b")
        .map_err(|err| format!("failed to compile FAIL regex: {err}"))?;

    let has_fail = fail_re.is_match(&source);
    let has_pass = pass_re.is_match(&source);

    if has_marker && has_fail {
        Ok("FAIL".to_string())
    } else if has_marker && has_pass {
        Ok("PASS".to_string())
    } else if has_fail && !has_pass {
        Ok("FAIL".to_string())
    } else if has_pass && !has_fail {
        Ok("PASS".to_string())
    } else {
        Ok("UNKNOWN".to_string())
    }
}

fn confirm_review_posted(
    owner_repo: &str,
    pr_number: u32,
    marker: &str,
    head_sha: &str,
) -> Result<Option<u64>, String> {
    let endpoint = format!("/repos/{owner_repo}/issues/{pr_number}/comments?per_page=100");
    let output = Command::new("gh")
        .args(["api", &endpoint])
        .output()
        .map_err(|err| format!("failed to execute gh api for comments: {err}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse comments response: {err}"))?;
    let comments = payload
        .as_array()
        .ok_or_else(|| "comments response was not an array".to_string())?;
    for comment in comments.iter().rev() {
        let body = comment
            .get("body")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if body.contains(marker)
            && body
                .to_ascii_lowercase()
                .contains(&head_sha.to_ascii_lowercase())
        {
            let id = comment
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if id != 0 {
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

fn confirm_review_posted_with_retry(
    owner_repo: &str,
    pr_number: u32,
    marker: &str,
    head_sha: &str,
) -> Result<Option<u64>, String> {
    const MAX_ATTEMPTS: usize = 5;
    for attempt in 0..MAX_ATTEMPTS {
        let maybe_id = confirm_review_posted(owner_repo, pr_number, marker, head_sha)?;
        if maybe_id.is_some() {
            return Ok(maybe_id);
        }
        if attempt + 1 < MAX_ATTEMPTS {
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(None)
}

fn detect_http_400_or_rate_limit(log_path: &Path) -> bool {
    let Ok(tail) = read_tail(log_path, 20) else {
        return false;
    };
    let lower = tail.to_ascii_lowercase();
    lower.contains("rate limit")
        || lower.contains("exhausted your capacity")
        || lower.contains("quota will reset")
        || lower.contains("modelnotfounderror")
        || lower.contains("\"status\":400")
        || lower.contains("http 400")
}

fn detect_comment_permission_denied(log_path: &Path) -> bool {
    let Ok(tail) = read_tail(log_path, 40) else {
        return false;
    };
    let lower = tail.to_ascii_lowercase();
    lower.contains("resource not accessible by personal access token (addcomment)")
        || lower.contains("resource not accessible by personal access token")
        || lower.contains("http 403 resource not accessible by personal access token")
        || lower.contains("insufficient permissions")
}

fn read_tail(path: &Path, max_lines: usize) -> Result<String, String> {
    let file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read line: {err}"))?;
        lines.push(line);
        if lines.len() > max_lines {
            let _ = lines.remove(0);
        }
    }
    Ok(lines.join("\n"))
}

fn read_last_lines(path: &Path, max_lines: usize) -> Result<Vec<String>, String> {
    let file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read line: {err}"))?;
        lines.push(line);
        if lines.len() > max_lines {
            let _ = lines.remove(0);
        }
    }
    Ok(lines)
}

fn scan_log_liveness(
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
    for line in appended.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            events_since_last = events_since_last.saturating_add(1);
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
    })
}

fn exit_signal(status: std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn emit_event(
    ctx: &ExecutionContext,
    event_name: &str,
    review_type: &str,
    head_sha: &str,
    extra: serde_json::Value,
) -> Result<(), String> {
    let seq = ctx.seq.fetch_add(1, Ordering::SeqCst).saturating_add(1);
    let mut envelope = serde_json::Map::new();
    envelope.insert("ts".to_string(), serde_json::json!(now_iso8601_millis()));
    envelope.insert("event".to_string(), serde_json::json!(event_name));
    envelope.insert("review_type".to_string(), serde_json::json!(review_type));
    envelope.insert("pr_number".to_string(), serde_json::json!(ctx.pr_number));
    envelope.insert("head_sha".to_string(), serde_json::json!(head_sha));
    envelope.insert("seq".to_string(), serde_json::json!(seq));
    if let serde_json::Value::Object(extra_fields) = extra {
        for (key, value) in extra_fields {
            envelope.insert(key, value);
        }
    }
    emit_review_event(&serde_json::Value::Object(envelope))
}

fn apm2_home_dir() -> Result<PathBuf, String> {
    let base_dirs = directories::BaseDirs::new()
        .ok_or_else(|| "could not resolve home directory".to_string())?;
    Ok(base_dirs.home_dir().join(".apm2"))
}

fn review_events_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_events.ndjson"))
}

fn review_state_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_state.json"))
}

fn review_state_lock_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_state.lock"))
}

fn review_events_rotated_path(events_path: &Path) -> Result<PathBuf, String> {
    let parent = events_path
        .parent()
        .ok_or_else(|| format!("event path has no parent: {}", events_path.display()))?;
    Ok(parent.join("review_events.ndjson.1"))
}

fn review_events_lock_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_events.ndjson.lock"))
}

fn review_locks_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_locks"))
}

fn review_lock_path(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
) -> Result<PathBuf, String> {
    let safe_repo = sanitize_for_path(owner_repo);
    let safe_type = sanitize_for_path(review_type);
    Ok(review_locks_dir_path()?.join(format!("{safe_repo}-pr{pr_number}-{safe_type}.lock")))
}

fn review_pulses_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_pulses"))
}

fn pulse_file_path(pr_number: u32, review_type: &str) -> Result<PathBuf, String> {
    let suffix = match review_type {
        "security" => "review_pulse_security.json",
        "quality" => "review_pulse_quality.json",
        other => {
            return Err(format!(
                "invalid pulse review type: {other} (expected security|quality)"
            ));
        },
    };
    Ok(review_pulses_dir_path()?.join(format!("pr{pr_number}_{suffix}")))
}

fn legacy_pulse_file_path(review_type: &str) -> Result<PathBuf, String> {
    let suffix = match review_type {
        "security" => "review_pulse_security.json",
        "quality" => "review_pulse_quality.json",
        other => {
            return Err(format!(
                "invalid pulse review type: {other} (expected security|quality)"
            ));
        },
    };
    Ok(apm2_home_dir()?.join(suffix))
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Err(format!("path has no parent: {}", path.display()));
    };
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create parent dir {}: {err}", parent.display()))
}

static EVENT_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn emit_review_event(event: &serde_json::Value) -> Result<(), String> {
    let events_path = review_events_path()?;
    emit_review_event_to_path(&events_path, event)
}

fn emit_review_event_to_path(events_path: &Path, event: &serde_json::Value) -> Result<(), String> {
    let lock = EVENT_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| "event file lock poisoned".to_string())?;
    ensure_parent_dir(events_path)?;
    let lock_path = review_events_lock_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open event lock {}: {err}", lock_path.display()))?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|err| format!("failed to lock event stream {}: {err}", lock_path.display()))?;

    if let Ok(meta) = fs::metadata(events_path) {
        if meta.len() > EVENT_ROTATE_BYTES {
            let rotated = review_events_rotated_path(events_path)?;
            let _ = fs::remove_file(&rotated);
            let _ = fs::rename(events_path, &rotated);
        }
    }

    let serialized =
        serde_json::to_string(event).map_err(|err| format!("failed to serialize event: {err}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(events_path)
        .map_err(|err| format!("failed to open {}: {err}", events_path.display()))?;
    file.write_all(serialized.as_bytes())
        .map_err(|err| format!("failed to append event: {err}"))?;
    file.write_all(b"\n")
        .map_err(|err| format!("failed to write newline: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", events_path.display()))?;
    drop(lock_file);
    Ok(())
}

pub fn write_pulse_file(pr_number: u32, review_type: &str, head_sha: &str) -> Result<(), String> {
    let path = pulse_file_path(pr_number, review_type)?;
    write_pulse_file_to_path(&path, head_sha)
}

fn write_pulse_file_to_path(path: &Path, head_sha: &str) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let pulse = PulseFile {
        head_sha: head_sha.to_string(),
        written_at: Utc::now(),
    };
    let content = serde_json::to_vec_pretty(&pulse)
        .map_err(|err| format!("failed to serialize pulse file: {err}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("pulse path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create pulse temp file: {err}"))?;
    temp.write_all(&content)
        .map_err(|err| format!("failed to write pulse temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync pulse temp file: {err}"))?;
    temp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

pub fn read_pulse_file(pr_number: u32, review_type: &str) -> Result<Option<PulseFile>, String> {
    let path = pulse_file_path(pr_number, review_type)?;
    if let Some(pulse) = read_pulse_file_from_path(&path)? {
        Ok(Some(pulse))
    } else {
        let legacy = legacy_pulse_file_path(review_type)?;
        read_pulse_file_from_path(&legacy)
    }
}

fn read_pulse_file_from_path(path: &Path) -> Result<Option<PulseFile>, String> {
    let content = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let pulse = serde_json::from_slice::<PulseFile>(&content)
        .map_err(|err| format!("failed to parse pulse file {}: {err}", path.display()))?;
    Ok(Some(pulse))
}

impl ReviewStateFile {
    fn load_from_path(path: &Path) -> Result<Self, String> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
        };
        serde_json::from_str(&content)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))
    }

    fn save_to_path(&self, path: &Path) -> Result<(), String> {
        ensure_parent_dir(path)?;
        let serialized = serde_json::to_vec_pretty(self)
            .map_err(|err| format!("failed to serialize review state: {err}"))?;

        let parent = path
            .parent()
            .ok_or_else(|| format!("state path has no parent: {}", path.display()))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|err| format!("failed to create temp state file: {err}"))?;
        temp.write_all(&serialized)
            .map_err(|err| format!("failed to write temp state file: {err}"))?;
        temp.as_file()
            .sync_all()
            .map_err(|err| format!("failed to sync temp state file: {err}"))?;
        temp.persist(path)
            .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
        Ok(())
    }
}

fn with_review_state_shared<T>(
    operation: impl FnOnce(&ReviewStateFile) -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = review_state_lock_path()?;
    let state_path = review_state_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open state lock {}: {err}", lock_path.display()))?;
    FileExt::lock_shared(&lock_file)
        .map_err(|err| format!("failed to lock state {}: {err}", lock_path.display()))?;
    let state = ReviewStateFile::load_from_path(&state_path)?;
    let result = operation(&state);
    drop(lock_file);
    result
}

fn with_review_state_exclusive<T>(
    operation: impl FnOnce(&mut ReviewStateFile) -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = review_state_lock_path()?;
    let state_path = review_state_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open state lock {}: {err}", lock_path.display()))?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|err| format!("failed to lock state {}: {err}", lock_path.display()))?;
    let mut state = ReviewStateFile::load_from_path(&state_path)?;
    let result = operation(&mut state)?;
    state.save_to_path(&state_path)?;
    drop(lock_file);
    Ok(result)
}

fn build_run_key(pr_number: u32, review_type: &str, head_sha: &str) -> String {
    let head = &head_sha[..head_sha.len().min(8)];
    let ts = now_iso8601_millis().replace([':', '.'], "");
    format!("pr{pr_number}-{review_type}-{head}-{ts}")
}

fn sanitize_for_path(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

fn try_acquire_review_lease(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<File>, String> {
    let lock_path = review_lock_path(owner_repo, pr_number, review_type)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open review lock {}: {err}", lock_path.display()))?;
    match FileExt::try_lock_exclusive(&lock_file) {
        Ok(()) => Ok(Some(lock_file)),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(err) => Err(format!(
            "failed to acquire review lock {}: {err}",
            lock_path.display()
        )),
    }
}

fn upsert_review_state_entry(run_key: &str, entry: ReviewStateEntry) -> Result<(), String> {
    with_review_state_exclusive(|state| {
        state.reviewers.insert(run_key.to_string(), entry);
        Ok(())
    })
}

fn remove_review_state_entry(run_key: &str) -> Result<(), String> {
    with_review_state_exclusive(|state| {
        state.reviewers.remove(run_key);
        Ok(())
    })
}

fn entry_pr_number(entry: &ReviewStateEntry) -> Option<u32> {
    if entry.pr_number > 0 {
        Some(entry.pr_number)
    } else {
        parse_pr_url(&entry.pr_url).ok().map(|(_, number)| number)
    }
}

fn find_active_review_entry(
    pr_number: u32,
    review_type: &str,
    head_sha: Option<&str>,
) -> Result<Option<ReviewStateEntry>, String> {
    with_review_state_shared(|state| {
        let mut candidates = state
            .reviewers
            .values()
            .filter(|entry| entry_pr_number(entry).is_some_and(|number| number == pr_number))
            .filter(|entry| entry.review_type.eq_ignore_ascii_case(review_type))
            .filter(|entry| is_process_alive(entry.pid))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(head) = head_sha {
            candidates.retain(|entry| entry.head_sha.eq_ignore_ascii_case(head));
        }
        candidates.sort_by_key(|entry| entry.started_at);
        Ok(candidates.pop())
    })
}

fn read_last_event_values(max_lines: usize) -> Result<Vec<serde_json::Value>, String> {
    let path = review_events_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let lines = read_last_lines(&path, max_lines)?;
    Ok(lines
        .into_iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
        .collect::<Vec<_>>())
}

fn is_process_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let next =
            select_fallback_model("gemini-2.5-flash").expect("known model should produce fallback");
        assert_eq!(next.model, "gemini-2.5-pro");

        let next =
            select_fallback_model("gemini-2.5-pro").expect("known model should produce fallback");
        assert_eq!(next.model, "gpt-5.3-codex");

        let next =
            select_fallback_model("gpt-5.3-codex").expect("known model should produce fallback");
        assert_eq!(next.model, "gemini-2.5-flash");
    }

    #[test]
    fn test_select_fallback_model_unknown_returns_none() {
        assert!(select_fallback_model("unknown-model").is_none());
    }

    #[test]
    fn test_build_gemini_script_command_syntax() {
        let prompt = Path::new("/tmp/prompt.md");
        let log = Path::new("/tmp/review.log");
        let cmd = build_gemini_script_command(prompt, log, "gemini-2.5-flash");
        assert!(cmd.contains("script -q"));
        assert!(cmd.contains("gemini -m"));
        assert!(cmd.contains("-o stream-json"));
    }

    #[test]
    fn test_build_script_command_for_backend_dispatch() {
        let prompt = Path::new("/tmp/prompt.md");
        let log = Path::new("/tmp/review.log");
        let capture = Path::new("/tmp/capture.md");

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
            "gemini-2.5-flash",
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
        fs::write(&path, oversized).expect("write oversized file");

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

        fs::write(
            &path,
            r#"{"message":"You have exhausted your capacity on this model. Your quota will reset after 2s."}"#,
        )
        .expect("write rate-limit log");
        assert!(detect_http_400_or_rate_limit(&path));

        fs::write(&path, r#"{"message":"normal progress"}"#).expect("write normal log");
        assert!(!detect_http_400_or_rate_limit(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_markers() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        fs::write(
            &path,
            "GraphQL: Resource not accessible by personal access token (addComment)",
        )
        .expect("write denied log");
        assert!(detect_comment_permission_denied(&path));

        fs::write(&path, r#"{"message":"normal progress"}"#).expect("write normal log");
        assert!(!detect_comment_permission_denied(&path));
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
}
