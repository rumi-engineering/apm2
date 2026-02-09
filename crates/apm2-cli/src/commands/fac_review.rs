//! FAC review orchestration commands.
//!
//! This module provides VPS-oriented, FAC-first review execution with:
//! - Security/quality orchestration (parallel when `--type all`)
//! - Multi-model backend dispatch (Codex + Gemini)
//! - NDJSON lifecycle telemetry under `~/.apm2/review_events.ndjson`
//! - Pulse-file based SHA freshness checks and resume flow
//! - Liveness-based stall detection and bounded model fallback
//! - Idempotent detached dispatch + projection snapshots for GitHub surfaces
//! - GitHub projection retrigger (`forge-admission-cycle.yml`) from local CLI

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
const COMMENT_CONFIRM_MAX_PAGES: usize = 20;
const COMMENT_CONFIRM_MAX_ATTEMPTS: usize = 20;
const COMMENT_PERMISSION_SCAN_LINES: usize = 200;
const DISPATCH_PENDING_TTL: Duration = Duration::from_secs(120);

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

#[derive(Debug, Clone, Serialize)]
struct DispatchReviewResult {
    review_type: String,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingDispatchEntry {
    started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DispatchSummary {
    pr_url: String,
    pr_number: u32,
    head_sha: String,
    dispatch_epoch: u64,
    results: Vec<DispatchReviewResult>,
}

#[derive(Debug, Clone, Serialize)]
struct RetriggerSummary {
    workflow: String,
    repo: String,
    pr_number: u32,
    dispatched_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct BarrierSummary {
    repo: String,
    event_name: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    base_ref: String,
    default_branch: String,
    author_login: String,
    author_association: String,
    actor_login: String,
    actor_permission: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct KickoffSummary {
    repo: String,
    event_name: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    dispatch_epoch: u64,
    total_secs: u64,
    terminal_state: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProjectionError {
    ts: String,
    event: String,
    review_type: String,
    seq: u64,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProjectionStatus {
    line: String,
    security: String,
    quality: String,
    recent_events: String,
    terminal_failure: bool,
    last_seq: u64,
    errors: Vec<ProjectionError>,
}

#[derive(Debug, Clone)]
struct ExecutionContext {
    pr_number: u32,
    seq: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
struct FacEventContext {
    repo: String,
    event_name: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    base_ref: String,
    default_branch: String,
    author_login: String,
    author_association: String,
    actor_login: String,
    actor_permission: Option<String>,
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

#[derive(Debug, Clone)]
struct PostedReview {
    id: u64,
    verdict: Option<String>,
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

pub fn run_dispatch(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    json_output: bool,
) -> u8 {
    match run_dispatch_inner(pr_url, review_type, expected_head_sha) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Review Dispatch");
                println!("  PR:            {}", summary.pr_url);
                println!("  PR Number:     {}", summary.pr_number);
                println!("  Head SHA:      {}", summary.head_sha);
                println!("  Dispatch Epoch {}", summary.dispatch_epoch);
                for result in &summary.results {
                    println!(
                        "  - {}: {}{}{}{}",
                        result.review_type,
                        result.mode,
                        result
                            .unit
                            .as_ref()
                            .map_or_else(String::new, |value| format!(" unit={value}")),
                        result
                            .pid
                            .map_or_else(String::new, |value| format!(" pid={value}")),
                        result
                            .log_file
                            .as_ref()
                            .map_or_else(String::new, |value| format!(" log={value}")),
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

pub fn run_retrigger(repo: &str, pr_number: u32, json_output: bool) -> u8 {
    match run_retrigger_inner(repo, pr_number) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Review Retrigger");
                println!("  Workflow:          {}", summary.workflow);
                println!("  Repo:              {}", summary.repo);
                println!("  PR Number:         {}", summary.pr_number);
                println!("  Dispatched At:     {}", summary.dispatched_at);
            }
            exit_codes::SUCCESS
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_review_retrigger_failed",
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
    json_output: bool,
) -> u8 {
    if !json_output {
        println!(
            "details=~/.apm2/review_events.ndjson state=~/.apm2/reviewer_state.json dispatch_logs=~/.apm2/review_dispatch/"
        );
    }
    match run_kickoff_inner(repo, event_path, event_name, max_wait_seconds) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
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
            } else {
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

fn run_dispatch_inner(
    pr_url: &str,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
) -> Result<DispatchSummary, String> {
    let (owner_repo, pr_number) = parse_pr_url(pr_url)?;
    let current_head_sha = fetch_pr_head_sha(&owner_repo, pr_number)?;
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

fn run_retrigger_inner(repo: &str, pr_number: u32) -> Result<RetriggerSummary, String> {
    if pr_number == 0 {
        return Err("invalid PR number: must be > 0".to_string());
    }
    let _ = split_owner_repo(repo)?;

    let args = build_retrigger_workflow_args(repo, pr_number);
    let output = Command::new("gh")
        .args(&args)
        .output()
        .map_err(|err| format!("failed to execute gh workflow run: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh workflow run failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(RetriggerSummary {
        workflow: "forge-admission-cycle.yml".to_string(),
        repo: repo.to_string(),
        pr_number,
        dispatched_at: now_iso8601_millis(),
    })
}

fn build_retrigger_workflow_args(repo: &str, pr_number: u32) -> Vec<String> {
    vec![
        "workflow".to_string(),
        "run".to_string(),
        "forge-admission-cycle.yml".to_string(),
        "--repo".to_string(),
        repo.to_string(),
        "-f".to_string(),
        format!("pr_number={pr_number}"),
    ]
}

fn run_kickoff_inner(
    repo: &str,
    event_path: &Path,
    event_name: &str,
    max_wait_seconds: u64,
) -> Result<KickoffSummary, String> {
    if max_wait_seconds == 0 {
        return Err("max_wait_seconds must be greater than zero".to_string());
    }

    let ctx = resolve_fac_event_context(repo, event_path, event_name)?;
    enforce_barrier(&ctx)?;
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
            println!(
                "ERROR ts={} event={} review={} seq={} detail={}",
                error.ts, error.event, error.review_type, error.seq, error.detail
            );
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

fn projection_state_done(state: &str) -> bool {
    state.starts_with("done:")
}

fn projection_state_failed(state: &str) -> bool {
    state.starts_with("failed:")
}

fn apply_sequence_done_fallback(
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

fn projection_state_from_sequence_verdict(verdict: Option<&str>, head_short: &str) -> String {
    let normalized = verdict.unwrap_or("").trim().to_ascii_uppercase();
    match normalized.as_str() {
        "PASS" | "DEDUPED" | "SKIPPED" => format!("done:sequence/summary:r0:{head_short}"),
        "FAIL" => "failed:sequence_fail".to_string(),
        "UNKNOWN" => "failed:sequence_unknown".to_string(),
        _ => "none".to_string(),
    }
}

fn ensure_gh_cli_ready() -> Result<(), String> {
    let output = Command::new("gh")
        .args(["auth", "status"])
        .output()
        .map_err(|err| format!("failed to execute `gh auth status`: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if detail.is_empty() {
            Err("`gh auth status` failed; authenticate the VPS runner with GitHub CLI".to_string())
        } else {
            Err(format!(
                "`gh auth status` failed; authenticate the VPS runner with GitHub CLI ({detail})"
            ))
        }
    }
}

fn resolve_fac_event_context(
    repo: &str,
    event_path: &Path,
    event_name: &str,
) -> Result<FacEventContext, String> {
    let _ = split_owner_repo(repo)?;
    let payload_text = fs::read_to_string(event_path).map_err(|err| {
        format!(
            "failed to read event payload {}: {err}",
            event_path.display()
        )
    })?;
    let payload: serde_json::Value =
        serde_json::from_str(&payload_text).map_err(|err| format!("invalid event JSON: {err}"))?;

    match event_name {
        "pull_request_target" => resolve_pull_request_target_context(repo, &payload),
        "workflow_dispatch" => resolve_workflow_dispatch_context(repo, &payload),
        other => Err(format!(
            "unsupported event_name `{other}`; expected pull_request_target or workflow_dispatch"
        )),
    }
}

fn resolve_pull_request_target_context(
    repo: &str,
    payload: &serde_json::Value,
) -> Result<FacEventContext, String> {
    let event_repo = payload
        .pointer("/repository/full_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing repository.full_name in event payload".to_string())?;
    if event_repo != repo {
        return Err(format!(
            "event repository mismatch: expected `{repo}`, got `{event_repo}`"
        ));
    }

    let pr_number = payload
        .pointer("/pull_request/number")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "missing pull_request.number in event payload".to_string())
        .and_then(|value| {
            u32::try_from(value).map_err(|_| format!("invalid pull_request.number: {value}"))
        })?;
    let pr_url = payload
        .pointer("/pull_request/html_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.html_url in event payload".to_string())?
        .to_string();
    let head_sha = payload
        .pointer("/pull_request/head/sha")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.head.sha in event payload".to_string())?
        .to_string();
    let base_ref = payload
        .pointer("/pull_request/base/ref")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.base.ref in event payload".to_string())?
        .to_string();
    let default_branch = payload
        .pointer("/repository/default_branch")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing repository.default_branch in event payload".to_string())?
        .to_string();
    let author_login = payload
        .pointer("/pull_request/user/login")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.user.login in event payload".to_string())?
        .to_string();
    let author_association = payload
        .pointer("/pull_request/author_association")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing pull_request.author_association in event payload".to_string())?
        .to_string();
    let actor_login = resolve_actor_login(payload);

    Ok(FacEventContext {
        repo: repo.to_string(),
        event_name: "pull_request_target".to_string(),
        pr_number,
        pr_url,
        head_sha,
        base_ref,
        default_branch,
        author_login,
        author_association,
        actor_login,
        actor_permission: None,
    })
}

fn resolve_workflow_dispatch_context(
    repo: &str,
    payload: &serde_json::Value,
) -> Result<FacEventContext, String> {
    let event_repo = payload
        .pointer("/repository/full_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing repository.full_name in event payload".to_string())?;
    if event_repo != repo {
        return Err(format!(
            "event repository mismatch: expected `{repo}`, got `{event_repo}`"
        ));
    }

    let pr_number_raw = payload
        .pointer("/inputs/pr_number")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "workflow_dispatch requires inputs.pr_number".to_string())?;
    let pr_number = pr_number_raw
        .parse::<u32>()
        .map_err(|err| format!("invalid inputs.pr_number `{pr_number_raw}`: {err}"))?;
    if pr_number == 0 {
        return Err("inputs.pr_number must be greater than zero".to_string());
    }

    let pr_data = fetch_pr_data(repo, pr_number)?;
    let pr_url = pr_data
        .pointer("/html_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing html_url from PR API response".to_string())?
        .to_string();
    let head_sha = pr_data
        .pointer("/head/sha")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing head.sha from PR API response".to_string())?
        .to_string();
    let base_ref = pr_data
        .pointer("/base/ref")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing base.ref from PR API response".to_string())?
        .to_string();
    let author_login = pr_data
        .pointer("/user/login")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing user.login from PR API response".to_string())?
        .to_string();
    let author_association = pr_data
        .pointer("/author_association")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing author_association from PR API response".to_string())?
        .to_string();

    let default_branch = payload
        .pointer("/repository/default_branch")
        .and_then(serde_json::Value::as_str)
        .map_or_else(
            || fetch_default_branch(repo).unwrap_or_else(|_| "main".to_string()),
            ToString::to_string,
        );
    let actor_login = resolve_actor_login(payload);
    let actor_permission = resolve_actor_permission(repo, &actor_login)?;

    Ok(FacEventContext {
        repo: repo.to_string(),
        event_name: "workflow_dispatch".to_string(),
        pr_number,
        pr_url,
        head_sha,
        base_ref,
        default_branch,
        author_login,
        author_association,
        actor_login,
        actor_permission: Some(actor_permission),
    })
}

fn resolve_actor_login(payload: &serde_json::Value) -> String {
    std::env::var("GITHUB_ACTOR")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            payload
                .pointer("/sender/login")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn enforce_barrier(ctx: &FacEventContext) -> Result<(), String> {
    validate_expected_head_sha(&ctx.head_sha)?;
    if !is_allowed_author_association(&ctx.author_association) {
        return Err(format!(
            "unauthorized PR author identity: {} ({})",
            ctx.author_login, ctx.author_association
        ));
    }

    if ctx.event_name == "workflow_dispatch" {
        let permission = ctx.actor_permission.as_deref().unwrap_or("none");
        if !matches!(permission, "admin" | "maintain" | "write") {
            return Err(format!(
                "workflow_dispatch actor `{}` lacks repository permission (need write|maintain|admin, got `{permission}`)",
                ctx.actor_login
            ));
        }

        let dispatch_ref = resolve_dispatch_ref_name();
        if dispatch_ref.is_empty() {
            return Err(
                "workflow_dispatch trusted-ref check failed: missing GITHUB_REF_NAME".to_string(),
            );
        }
        if dispatch_ref != ctx.base_ref && dispatch_ref != ctx.default_branch {
            return Err(format!(
                "workflow_dispatch ref `{dispatch_ref}` is not trusted for PR base `{}` (default `{}`)",
                ctx.base_ref, ctx.default_branch
            ));
        }
    }

    Ok(())
}

fn is_allowed_author_association(value: &str) -> bool {
    matches!(value, "OWNER" | "MEMBER" | "COLLABORATOR")
}

fn resolve_dispatch_ref_name() -> String {
    if let Ok(ref_name) = std::env::var("GITHUB_REF_NAME") {
        if !ref_name.is_empty() {
            return ref_name;
        }
    }
    if let Ok(full_ref) = std::env::var("GITHUB_REF") {
        if let Some(stripped) = full_ref.strip_prefix("refs/heads/") {
            return stripped.to_string();
        }
    }
    String::new()
}

fn fetch_default_branch(repo: &str) -> Result<String, String> {
    let output = Command::new("gh")
        .args(["api", &format!("/repos/{repo}")])
        .output()
        .map_err(|err| format!("failed to execute gh api for default branch: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving default branch: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from default branch API response: {err}"))?;
    value
        .get("default_branch")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "default_branch missing from repository API response".to_string())
}

fn fetch_pr_data(repo: &str, pr_number: u32) -> Result<serde_json::Value, String> {
    let output = Command::new("gh")
        .args(["api", &format!("/repos/{repo}/pulls/{pr_number}")])
        .output()
        .map_err(|err| format!("failed to execute gh api for PR metadata: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api failed resolving PR #{pr_number}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from PR metadata API response: {err}"))
}

fn resolve_actor_permission(repo: &str, actor: &str) -> Result<String, String> {
    if actor.is_empty() || actor == "unknown" {
        return Ok("none".to_string());
    }
    let output = Command::new("gh")
        .args([
            "api",
            &format!("/repos/{repo}/collaborators/{actor}/permission"),
        ])
        .output()
        .map_err(|err| format!("failed to execute gh api for actor permission: {err}"))?;
    if !output.status.success() {
        return Ok("none".to_string());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("invalid JSON from actor permission API response: {err}"))?;
    Ok(value
        .get("permission")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("none")
        .to_string())
}

fn run_project_inner(
    pr_number: u32,
    head_sha: Option<&str>,
    since_epoch: Option<u64>,
    after_seq: u64,
) -> Result<ProjectionStatus, String> {
    let normalized_head = if let Some(head) = head_sha {
        validate_expected_head_sha(head)?;
        Some(head.to_ascii_lowercase())
    } else {
        None
    };

    let state = with_review_state_shared(|state| Ok(state.clone()))?;
    let mut events = read_last_event_values(400)?
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
        let event_name = event
            .get("event")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        if event_name == "run_crash" && event_is_terminal_crash(event) {
            terminal_failure = true;
        }
        if seq <= after_seq {
            continue;
        }
        if !matches!(
            event_name.as_str(),
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
            event: event_name,
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
        "ts={} security={} quality={} events={}",
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        security,
        quality,
        recent_events
    );

    Ok(ProjectionStatus {
        line,
        security,
        quality,
        recent_events,
        terminal_failure,
        last_seq,
        errors,
    })
}

fn dispatch_single_review(
    pr_url: &str,
    owner_repo: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    head_sha: &str,
    dispatch_epoch: u64,
) -> Result<DispatchReviewResult, String> {
    with_dispatch_lock(
        owner_repo,
        pr_number,
        review_kind.as_str(),
        head_sha,
        || {
            if let Some(existing) =
                find_active_review_entry(pr_number, review_kind.as_str(), Some(head_sha))?
            {
                return Ok(DispatchReviewResult {
                    review_type: review_kind.as_str().to_string(),
                    mode: "joined".to_string(),
                    pid: Some(existing.pid),
                    unit: None,
                    log_file: Some(existing.log_file.display().to_string()),
                });
            }

            if let Some(pending) =
                read_fresh_pending_dispatch(owner_repo, pr_number, review_kind.as_str(), head_sha)?
            {
                return Ok(DispatchReviewResult {
                    review_type: review_kind.as_str().to_string(),
                    mode: "joined".to_string(),
                    pid: pending.pid,
                    unit: pending.unit,
                    log_file: pending.log_file,
                });
            }

            let result =
                spawn_detached_review(pr_url, pr_number, review_kind, head_sha, dispatch_epoch)?;
            write_pending_dispatch(
                owner_repo,
                pr_number,
                review_kind.as_str(),
                head_sha,
                &result,
            )?;
            Ok(result)
        },
    )
}

fn spawn_detached_review(
    pr_url: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    expected_head_sha: &str,
    dispatch_epoch: u64,
) -> Result<DispatchReviewResult, String> {
    let exe_path = std::env::current_exe()
        .map_err(|err| format!("failed to resolve current executable: {err}"))?;
    let cwd = std::env::current_dir().map_err(|err| format!("failed to resolve cwd: {err}"))?;
    let head_short = &expected_head_sha[..expected_head_sha.len().min(8)];
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ");

    let has_sensitive_token_env =
        std::env::var_os("GH_TOKEN").is_some() || std::env::var_os("GITHUB_TOKEN").is_some();
    if command_available("systemd-run") && !has_sensitive_token_env {
        let unit = format!(
            "apm2-review-pr{pr_number}-{}-{head_short}-{ts}",
            review_kind.as_str()
        );
        let mut command = Command::new("systemd-run");
        command
            .arg("--user")
            .arg("--collect")
            .arg("--unit")
            .arg(&unit)
            .arg("--property")
            .arg(format!("WorkingDirectory={}", cwd.display()));

        for key in ["PATH", "HOME", "CARGO_HOME"] {
            if let Ok(value) = std::env::var(key) {
                command.arg("--setenv").arg(format!("{key}={value}"));
            }
        }

        let output = command
            .arg(&exe_path)
            .arg("fac")
            .arg("review")
            .arg("run")
            .arg(pr_url)
            .arg("--type")
            .arg(review_kind.as_str())
            .arg("--expected-head-sha")
            .arg(expected_head_sha)
            .output()
            .map_err(|err| format!("failed to execute systemd-run: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "systemd-run failed dispatching {} review: {}",
                review_kind.as_str(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return Ok(DispatchReviewResult {
            review_type: review_kind.as_str().to_string(),
            mode: "started".to_string(),
            pid: None,
            unit: Some(unit),
            log_file: None,
        });
    }

    let dispatch_dir = apm2_home_dir()?.join("review_dispatch");
    fs::create_dir_all(&dispatch_dir).map_err(|err| {
        format!(
            "failed to create dispatch directory {}: {err}",
            dispatch_dir.display()
        )
    })?;
    let log_path = dispatch_dir.join(format!(
        "pr{pr_number}-{}-{head_short}-{dispatch_epoch}.log",
        review_kind.as_str()
    ));
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|err| format!("failed to open dispatch log {}: {err}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|err| format!("failed to clone dispatch log handle: {err}"))?;
    let child = Command::new(&exe_path)
        .arg("fac")
        .arg("review")
        .arg("run")
        .arg(pr_url)
        .arg("--type")
        .arg(review_kind.as_str())
        .arg("--expected-head-sha")
        .arg(expected_head_sha)
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|err| format!("failed to spawn detached review process: {err}"))?;
    let pid = child.id();
    drop(child);

    Ok(DispatchReviewResult {
        review_type: review_kind.as_str().to_string(),
        mode: "started".to_string(),
        pid: Some(pid),
        unit: None,
        log_file: Some(log_path.display().to_string()),
    })
}

fn command_available(command: &str) -> bool {
    Command::new("sh")
        .args(["-lc", &format!("command -v {command} >/dev/null 2>&1")])
        .status()
        .is_ok_and(|status| status.success())
}

fn projection_state_for_type(
    state: &ReviewStateFile,
    events: &[serde_json::Value],
    pr_number: u32,
    review_kind: ReviewKind,
    head_filter: Option<&str>,
) -> String {
    let mut active_entries = state
        .reviewers
        .values()
        .filter(|entry| entry_pr_number(entry).is_some_and(|number| number == pr_number))
        .filter(|entry| entry.review_type.eq_ignore_ascii_case(review_kind.as_str()))
        .filter(|entry| is_process_alive(entry.pid))
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

    "none".to_string()
}

fn event_name(event: &serde_json::Value) -> &str {
    event
        .get("event")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

fn event_seq(event: &serde_json::Value) -> u64 {
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

fn event_is_terminal_crash(event: &serde_json::Value) -> bool {
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

fn review_dispatch_locks_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_dispatch_locks"))
}

fn review_dispatch_lock_path(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
) -> Result<PathBuf, String> {
    let safe_repo = sanitize_for_path(owner_repo);
    let safe_type = sanitize_for_path(review_type);
    let safe_head = sanitize_for_path(&head_sha[..head_sha.len().min(12)]);
    Ok(review_dispatch_locks_dir_path()?.join(format!(
        "{safe_repo}-pr{pr_number}-{safe_type}-{safe_head}.lock"
    )))
}

fn review_dispatch_pending_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_dispatch_pending"))
}

fn review_dispatch_pending_path(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
) -> Result<PathBuf, String> {
    let safe_repo = sanitize_for_path(owner_repo);
    let safe_type = sanitize_for_path(review_type);
    let safe_head = sanitize_for_path(&head_sha[..head_sha.len().min(12)]);
    Ok(review_dispatch_pending_dir_path()?.join(format!(
        "{safe_repo}-pr{pr_number}-{safe_type}-{safe_head}.json"
    )))
}

fn read_pending_dispatch_entry(path: &Path) -> Result<Option<PendingDispatchEntry>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read dispatch marker {}: {err}", path.display()))?;
    let entry = serde_json::from_str::<PendingDispatchEntry>(&text)
        .map_err(|err| format!("failed to parse dispatch marker {}: {err}", path.display()))?;
    Ok(Some(entry))
}

fn read_fresh_pending_dispatch(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
) -> Result<Option<PendingDispatchEntry>, String> {
    let path = review_dispatch_pending_path(owner_repo, pr_number, review_type, head_sha)?;
    let Some(entry) = read_pending_dispatch_entry(&path)? else {
        return Ok(None);
    };
    let age = Utc::now()
        .signed_duration_since(entry.started_at)
        .to_std()
        .unwrap_or_default();
    if age <= DISPATCH_PENDING_TTL {
        if pending_dispatch_is_live(&entry) {
            return Ok(Some(entry));
        }
        let _ = fs::remove_file(&path);
        return Ok(None);
    }

    let _ = fs::remove_file(&path);
    Ok(None)
}

fn write_pending_dispatch(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
    result: &DispatchReviewResult,
) -> Result<(), String> {
    let path = review_dispatch_pending_path(owner_repo, pr_number, review_type, head_sha)?;
    ensure_parent_dir(&path)?;
    let entry = PendingDispatchEntry {
        started_at: Utc::now(),
        pid: result.pid,
        unit: result.unit.clone(),
        log_file: result.log_file.clone(),
    };
    let payload = serde_json::to_string(&entry)
        .map_err(|err| format!("failed to serialize dispatch marker: {err}"))?;
    fs::write(&path, payload)
        .map_err(|err| format!("failed to write dispatch marker {}: {err}", path.display()))
}

fn pending_dispatch_is_live(entry: &PendingDispatchEntry) -> bool {
    if let Some(pid) = entry.pid {
        return is_process_alive(pid);
    }
    if let Some(unit) = entry.unit.as_deref() {
        return is_systemd_unit_active(unit);
    }
    false
}

fn is_systemd_unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", unit])
        .status()
        .is_ok_and(|status| status.success())
}

fn with_dispatch_lock<T>(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = review_dispatch_lock_path(owner_repo, pr_number, review_type, head_sha)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open dispatch lock {}: {err}",
                lock_path.display()
            )
        })?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|err| format!("failed to lock dispatch {}: {err}", lock_path.display()))?;
    let result = operation();
    drop(lock_file);
    result
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

                if let Some(posted_review) = confirm_review_posted(
                    owner_repo,
                    pr_number,
                    review_kind.marker(),
                    &current_head_sha,
                    expected_comment_author.as_deref(),
                )? {
                    terminate_child(&mut child)?;
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

fn resolve_authenticated_gh_login() -> Option<String> {
    let output = Command::new("gh")
        .args(["api", "user", "--jq", ".login"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let login = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if login.is_empty() { None } else { Some(login) }
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
    expected_author_login: Option<&str>,
) -> Result<Option<PostedReview>, String> {
    let marker_lower = marker.to_ascii_lowercase();
    let head_sha_lower = head_sha.to_ascii_lowercase();
    let expected_author_lower = expected_author_login.map(str::to_ascii_lowercase);

    for page in 1..=COMMENT_CONFIRM_MAX_PAGES {
        let endpoint =
            format!("/repos/{owner_repo}/issues/{pr_number}/comments?per_page=100&page={page}");
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
        if comments.is_empty() {
            break;
        }

        for comment in comments.iter().rev() {
            let body = comment
                .get("body")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let body_lower = body.to_ascii_lowercase();
            if !(body_lower.contains(&marker_lower) && body_lower.contains(&head_sha_lower)) {
                continue;
            }

            if let Some(expected_author) = expected_author_lower.as_deref() {
                let author = comment
                    .get("user")
                    .and_then(|value| value.get("login"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if author != expected_author {
                    continue;
                }
            }

            let id = comment
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if id != 0 {
                return Ok(Some(PostedReview {
                    id,
                    verdict: extract_verdict_from_comment_body(body),
                }));
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
    expected_author_login: Option<&str>,
) -> Result<Option<PostedReview>, String> {
    for attempt in 0..COMMENT_CONFIRM_MAX_ATTEMPTS {
        let maybe_review = confirm_review_posted(
            owner_repo,
            pr_number,
            marker,
            head_sha,
            expected_author_login,
        )?;
        if maybe_review.is_some() {
            return Ok(maybe_review);
        }
        if attempt + 1 < COMMENT_CONFIRM_MAX_ATTEMPTS {
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(None)
}

fn detect_http_400_or_rate_limit(log_path: &Path) -> bool {
    let Ok(lines) = read_last_lines(log_path, COMMENT_PERMISSION_SCAN_LINES) else {
        return false;
    };
    lines
        .iter()
        .rev()
        .any(|line| line_indicates_provider_backpressure(line))
}

fn detect_comment_permission_denied(log_path: &Path) -> bool {
    let Ok(lines) = read_last_lines(log_path, COMMENT_PERMISSION_SCAN_LINES) else {
        return false;
    };
    lines
        .iter()
        .rev()
        .any(|line| line_indicates_comment_permission_denied(line))
}

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

fn extract_verdict_from_comment_body(body: &str) -> Option<String> {
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
    fn test_build_retrigger_workflow_args() {
        let args = build_retrigger_workflow_args("guardian-intelligence/apm2", 508);
        assert_eq!(args[0], "workflow");
        assert_eq!(args[1], "run");
        assert!(args.contains(&"forge-admission-cycle.yml".to_string()));
        assert!(args.contains(&"guardian-intelligence/apm2".to_string()));
        assert!(args.contains(&"pr_number=508".to_string()));
        assert!(!args.iter().any(|value| value.contains("mode=")));
        assert!(!args.iter().any(|value| value.contains("review_type=")));
        assert!(
            !args
                .iter()
                .any(|value| value.contains("projection_seconds="))
        );
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
        assert!(!detect_comment_permission_denied(&path));

        fs::write(
            &path,
            r#"{"type":"item.completed","item":{"type":"command_execution","command":"gh pr comment https://github.com/guardian-intelligence/apm2/pull/508 --body-file review.md","status":"failed","exit_code":1,"aggregated_output":"GraphQL: Resource not accessible by personal access token (addComment)"}}"#,
        )
        .expect("write structured denied log");
        assert!(detect_comment_permission_denied(&path));

        fs::write(&path, r#"{"message":"normal progress"}"#).expect("write normal log");
        assert!(!detect_comment_permission_denied(&path));
    }

    #[test]
    fn test_detect_comment_permission_denied_ignores_diff_output() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review.log");

        fs::write(
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

        fs::write(
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
        fs::write(&path, line).expect("write source-dump denied marker log");
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
        fs::write(&path, line).expect("write source-dump backpressure marker log");
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
                "seq": 2
            }),
        ];

        let rendered = projection_state_for_type(&state, &events, 42, ReviewKind::Security, None);
        assert_eq!(rendered, "done:gpt-5.3-codex/codex:r2:abcdef1");
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
}
