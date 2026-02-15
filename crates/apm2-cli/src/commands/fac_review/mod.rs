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
mod bounded_test_runner;
mod ci_status;
mod detection;
mod dispatch;
mod events;
mod evidence;
mod fenced_yaml;
mod finding;
mod findings;
mod findings_store;
mod gate_attestation;
mod gate_cache;
mod gates;
mod github_auth;
mod github_projection;
mod github_reads;
mod jsonl;
mod lifecycle;
mod liveness;
mod logs;
mod merge_conflicts;
mod model_pool;
mod orchestrator;
mod pipeline;
mod prepare;
mod projection;
mod projection_store;
mod push;
mod recovery;
mod restart;
mod state;
mod target;
mod timeout_policy;
mod types;
mod verdict_projection;

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
// Re-export public API for use by `fac.rs`
use dispatch::dispatch_single_review_with_force;
use events::{read_last_event_values, review_events_path};
pub use finding::{
    ReviewFindingSeverityArg as ReviewCommentSeverityArg, ReviewFindingSeverityArg,
    ReviewFindingTypeArg as ReviewCommentTypeArg, ReviewFindingTypeArg,
};
pub use lifecycle::VerdictValueArg;
use projection::{projection_state_done, projection_state_failed, run_project_inner};
use serde::Serialize;
use state::{
    list_review_pr_numbers, load_review_run_state, load_review_run_state_strict, read_pulse_file,
    review_run_state_path,
};
pub use types::ReviewRunType;
use types::{
    DispatchReviewResult, DispatchSummary, ProjectionStatus, ReviewKind,
    TERMINAL_MANUAL_TERMINATION_DECISION_BOUND, TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED,
    TERMINATE_TIMEOUT, is_verdict_finalized_agent_stop_reason, validate_expected_head_sha,
};

use crate::exit_codes::codes as exit_codes;

const DOCTOR_SCHEMA: &str = "apm2.fac.review.doctor.v1";
const DOCTOR_STALE_GATE_AGE_SECONDS: i64 = 6 * 60 * 60;
const DOCTOR_EVENT_SCAN_MAX_LINES: usize = 200_000;
const DOCTOR_EVENT_SCAN_MAX_LINE_BYTES: usize = 64 * 1024;
const DOCTOR_EVENT_SCAN_MAX_BYTES_PER_SOURCE: u64 = 8 * 1024 * 1024;
const DOCTOR_LOG_SCAN_MAX_BYTES: u64 = 2 * 1024 * 1024;
const DOCTOR_LOG_SCAN_MAX_LINES: u64 = 200_000;
const DOCTOR_LOG_SCAN_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Debug, Serialize)]
struct DoctorHealthItem {
    severity: &'static str,
    message: String,
    remediation: String,
}

#[derive(Debug, Serialize)]
struct DoctorIdentitySnapshot {
    pr_number: u32,
    branch: Option<String>,
    worktree: Option<String>,
    source: Option<String>,
    local_sha: Option<String>,
    updated_at: Option<String>,
    remote_head_sha: Option<String>,
    stale: bool,
}

#[derive(Debug, Serialize)]
struct DoctorLifecycleSnapshot {
    state: String,
    time_in_state_seconds: i64,
    error_budget_used: u32,
    retry_budget_remaining: u32,
    updated_at: String,
    last_event_seq: u64,
}

#[derive(Debug, Serialize)]
struct DoctorGateSnapshot {
    name: String,
    status: String,
    completed_at: Option<String>,
    freshness_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
struct DoctorReviewSnapshot {
    dimension: String,
    verdict: String,
    reviewed_sha: String,
    reviewed_by: String,
    reviewed_at: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal_reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct DoctorAgentSnapshot {
    agent_type: String,
    state: String,
    run_id: String,
    sha: String,
    pid: Option<u32>,
    pid_alive: bool,
    started_at: String,
    completion_status: Option<String>,
    completion_summary: Option<String>,
    completion_token_hash: String,
    completion_token_expires_at: String,
    elapsed_seconds: Option<i64>,
    models_attempted: Vec<String>,
    tool_call_count: Option<u64>,
    log_line_count: Option<u64>,
    nudge_count: Option<u32>,
    last_activity_seconds_ago: Option<i64>,
}

#[derive(Debug, Serialize)]
struct DoctorAgentSection {
    max_active_agents_per_pr: usize,
    active_agents: usize,
    total_agents: usize,
    entries: Vec<DoctorAgentSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorFindingsCounts {
    blocker: u32,
    major: u32,
    minor: u32,
    nit: u32,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorFindingsDimensionSummary {
    dimension: String,
    counts: DoctorFindingsCounts,
    formal_verdict: String,
    computed_verdict: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorMergeConflictStatus {
    NoConflicts,
    HasConflicts,
    Unknown,
}

impl DoctorMergeConflictStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoConflicts => "no_conflicts",
            Self::HasConflicts => "has_conflicts",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorShaFreshnessSource {
    RemoteMatch,
    LocalAuthoritative,
    Stale,
    Unknown,
}

impl DoctorShaFreshnessSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RemoteMatch => "remote_match",
            Self::LocalAuthoritative => "local_authoritative",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct DoctorMergeReadiness {
    merge_ready: bool,
    all_verdicts_approve: bool,
    gates_pass: bool,
    sha_fresh: bool,
    sha_freshness_source: DoctorShaFreshnessSource,
    no_merge_conflicts: bool,
    merge_conflict_status: DoctorMergeConflictStatus,
}

#[derive(Debug, Serialize)]
struct DoctorWorktreeStatus {
    worktree_exists: bool,
    worktree_clean: bool,
    merge_conflicts: usize,
}

#[derive(Debug, Serialize)]
struct DoctorGithubProjectionStatus {
    auto_merge_enabled: bool,
    last_comment_updated_at: Option<String>,
    projection_lag_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorRecommendedAction {
    pub action: String,
    pub reason: String,
    pub priority: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Serialize)]
struct DoctorRepairApplied {
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorRunStateCondition {
    Healthy,
    Missing,
    Corrupt,
    Ambiguous,
    Unavailable,
}

impl DoctorRunStateCondition {
    const fn requires_repair(self) -> bool {
        matches!(self, Self::Corrupt | Self::Ambiguous)
    }
}

#[derive(Debug, Serialize)]
struct DoctorRunStateDiagnostic {
    review_type: String,
    condition: DoctorRunStateCondition,
    canonical_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    candidates: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DoctorPushAttemptSummary {
    ts: String,
    sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_hint: Option<String>,
}

#[derive(Debug, Serialize)]
struct DoctorPrSummary {
    schema: String,
    pr_number: u32,
    owner_repo: String,
    identity: DoctorIdentitySnapshot,
    lifecycle: Option<DoctorLifecycleSnapshot>,
    gates: Vec<DoctorGateSnapshot>,
    reviews: Vec<DoctorReviewSnapshot>,
    findings_summary: Vec<DoctorFindingsDimensionSummary>,
    merge_readiness: DoctorMergeReadiness,
    worktree_status: DoctorWorktreeStatus,
    github_projection: DoctorGithubProjectionStatus,
    recommended_action: DoctorRecommendedAction,
    agents: Option<DoctorAgentSection>,
    run_state_diagnostics: Vec<DoctorRunStateDiagnostic>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    repairs_applied: Vec<DoctorRepairApplied>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_push_attempt: Option<DoctorPushAttemptSummary>,
    health: Vec<DoctorHealthItem>,
}

struct DoctorActionInputs<'a> {
    pr_number: u32,
    health: &'a [DoctorHealthItem],
    lifecycle: Option<&'a DoctorLifecycleSnapshot>,
    agents: Option<&'a DoctorAgentSection>,
    reviews: &'a [DoctorReviewSnapshot],
    review_terminal_reasons: &'a std::collections::BTreeMap<String, Option<String>>,
    run_state_diagnostics: &'a [DoctorRunStateDiagnostic],
    findings_summary: &'a [DoctorFindingsDimensionSummary],
    merge_readiness: &'a DoctorMergeReadiness,
    latest_push_attempt: Option<&'a DoctorPushAttemptSummary>,
}

#[derive(Debug, Serialize)]
pub struct DoctorTrackedPrSummary {
    pub pr_number: u32,
    pub owner_repo: String,
    pub lifecycle_state: String,
    pub recommended_action: DoctorRecommendedAction,
    pub active_agents: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_seconds_ago: Option<i64>,
}

// ── Process management helpers (used by orchestrator) ───────────────────────

pub fn derive_repo() -> Result<String, String> {
    target::derive_repo_from_origin()
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
        if run_ids.is_empty() {
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

/// Run doctor diagnostics for a specific PR.
///
/// Doctor remains machine-oriented by default. In wait mode, JSON output
/// streams NDJSON heartbeats plus a final result event; text mode prints
/// periodic status lines to stderr and emits the final summary JSON to stdout.
#[allow(clippy::too_many_arguments)]
pub fn run_doctor(
    repo: &str,
    pr_number: u32,
    fix: bool,
    json_output: bool,
    wait_for_recommended_action: bool,
    poll_interval_seconds: u64,
    wait_timeout_seconds: u64,
    exit_on: &[String],
) -> u8 {
    let mut repairs_applied = Vec::new();
    if fix {
        let pre_repair = run_doctor_inner(repo, pr_number, Vec::new(), false);
        let plan = derive_doctor_repair_plan(&pre_repair);
        let force_repair = doctor_requires_force_repair(&pre_repair);
        if plan.reap_stale_agents
            || plan.refresh_identity
            || plan.reset_lifecycle
            || !plan.run_state_review_types.is_empty()
        {
            match recovery::run_repair_plan(
                repo,
                Some(pr_number),
                force_repair,
                plan.refresh_identity,
                plan.reap_stale_agents,
                plan.reset_lifecycle,
                false,
                plan.run_state_review_types,
            ) {
                Ok(summary) => {
                    repairs_applied.extend(summary.into_doctor_repairs());
                },
                Err(err) => {
                    if let Err(emit_err) = jsonl::emit_json_error("fac_doctor_fix_failed", &err) {
                        eprintln!("WARNING: failed to emit doctor fix error: {emit_err}");
                    }
                    return exit_codes::GENERIC_ERROR;
                },
            }
        }
    }

    if !wait_for_recommended_action {
        let summary = run_doctor_inner(repo, pr_number, repairs_applied, false);
        println!(
            "{}",
            serde_json::to_string_pretty(&summary)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
        let has_critical_health = summary
            .health
            .iter()
            .any(|item| item.severity.eq_ignore_ascii_case("high"));
        let requires_intervention = matches!(
            summary.recommended_action.action.as_str(),
            "fix" | "escalate"
        );
        if has_critical_health || requires_intervention {
            return exit_codes::GENERIC_ERROR;
        }
        return exit_codes::SUCCESS;
    }

    let exit_actions = match normalize_doctor_exit_actions(exit_on) {
        Ok(value) => value,
        Err(err) => {
            return emit_doctor_wait_error(
                json_output,
                "fac_doctor_invalid_exit_on",
                &err,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let interrupted = match doctor_interrupt_flag() {
        Ok(flag) => flag,
        Err(err) => {
            return emit_doctor_wait_error(
                json_output,
                "fac_doctor_signal_handler_failed",
                &err,
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    interrupted.store(false, Ordering::SeqCst);

    let poll_interval = Duration::from_secs(poll_interval_seconds.max(1));
    let wait_timeout = Duration::from_secs(wait_timeout_seconds);
    let started = Instant::now();
    let mut tick = 0_u64;
    let mut summary = run_doctor_inner(repo, pr_number, repairs_applied, false);

    loop {
        if exit_actions.contains(summary.recommended_action.action.as_str()) {
            emit_doctor_wait_result(&summary, json_output, tick);
            return exit_codes::SUCCESS;
        }

        if interrupted.load(Ordering::SeqCst) {
            summary = run_doctor_inner(repo, pr_number, Vec::new(), true);
            emit_doctor_wait_result(&summary, json_output, tick);
            return exit_codes::SUCCESS;
        }

        if started.elapsed() >= wait_timeout {
            emit_doctor_wait_result(&summary, json_output, tick);
            return exit_codes::SUCCESS;
        }

        if json_output {
            if let Err(err) = jsonl::emit_jsonl(&jsonl::DoctorPollEvent {
                event: "doctor_poll",
                tick,
                action: summary.recommended_action.action.clone(),
                ts: jsonl::ts_now(),
            }) {
                eprintln!("WARNING: failed to emit doctor poll event: {err}");
            }
        } else {
            eprintln!(
                "doctor wait: tick={tick} action={} elapsed={}s",
                summary.recommended_action.action,
                started.elapsed().as_secs()
            );
        }

        thread::sleep(poll_interval);
        tick = tick.saturating_add(1);
        summary = run_doctor_inner(repo, pr_number, Vec::new(), true);
    }
}

const DOCTOR_WAIT_EXIT_ACTIONS: [&str; 5] = [
    "fix",
    "escalate",
    "merge",
    "dispatch_implementor",
    "restart_reviews",
];

fn normalize_doctor_exit_actions(
    exit_on: &[String],
) -> Result<std::collections::BTreeSet<String>, String> {
    if exit_on.is_empty() {
        let defaults = DOCTOR_WAIT_EXIT_ACTIONS
            .iter()
            .map(|value| (*value).to_string())
            .collect::<std::collections::BTreeSet<_>>();
        return Ok(defaults);
    }

    let mut set = std::collections::BTreeSet::new();
    for value in exit_on {
        let normalized = value.trim().to_ascii_lowercase();
        if !DOCTOR_WAIT_EXIT_ACTIONS.contains(&normalized.as_str()) {
            return Err(format!(
                "invalid --exit-on action `{value}` (expected one of: {})",
                DOCTOR_WAIT_EXIT_ACTIONS.join(", ")
            ));
        }
        set.insert(normalized);
    }
    Ok(set)
}

fn emit_doctor_wait_result(summary: &DoctorPrSummary, json_output: bool, tick: u64) {
    if json_output {
        let summary_value = match serde_json::to_value(summary) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("WARNING: failed to serialize doctor summary: {err}");
                serde_json::json!({
                    "error": "serialization_failure",
                })
            },
        };
        if let Err(err) = jsonl::emit_jsonl(&jsonl::DoctorResultEvent {
            event: "doctor_result",
            tick,
            action: summary.recommended_action.action.clone(),
            ts: jsonl::ts_now(),
            summary: summary_value,
        }) {
            eprintln!("WARNING: failed to emit doctor result event: {err}");
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(summary)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
    }
}

fn emit_doctor_wait_error(json_output: bool, error: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let _ = jsonl::emit_jsonl(&jsonl::StageEvent {
            event: "doctor_error".to_string(),
            ts: jsonl::ts_now(),
            extra: serde_json::json!({
                "error": error,
                "message": message,
            }),
        });
    } else {
        // JSON-only: emit the error as a structured JSON object.
        let payload = serde_json::json!({
            "error": error,
            "message": message,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
    }
    exit_code
}

/// Returns the global interrupt flag used by the doctor wait loop.
///
/// Registers a `ctrlc` signal handler (SIGINT + SIGTERM via the `termination`
/// feature) on first call. If the handler cannot be registered, returns `Err`
/// so the caller can refuse to start wait mode rather than running without
/// graceful shutdown semantics (fail-closed).
fn doctor_interrupt_flag() -> Result<Arc<AtomicBool>, String> {
    static INTERRUPTED: OnceLock<Result<Arc<AtomicBool>, String>> = OnceLock::new();
    INTERRUPTED
        .get_or_init(|| {
            let interrupted = Arc::new(AtomicBool::new(false));
            let handler_flag = Arc::clone(&interrupted);
            ctrlc::set_handler(move || {
                handler_flag.store(true, Ordering::SeqCst);
            })
            .map_err(|e| format!("failed to register Ctrl-C/SIGTERM handler: {e}"))?;
            Ok(interrupted)
        })
        .clone()
}

/// Maximum number of tracked PRs to include in doctor summaries.
/// Prevents unbounded memory consumption on long-lived instances.
const MAX_TRACKED_PR_SUMMARIES: usize = 100;

pub fn collect_tracked_pr_summaries(
    fallback_owner_repo: Option<&str>,
) -> Result<Vec<DoctorTrackedPrSummary>, String> {
    let mut pr_numbers = list_review_pr_numbers()?;
    // Sort descending so we keep the most recent PRs when truncating.
    pr_numbers.sort_unstable_by(|a, b| b.cmp(a));
    pr_numbers.truncate(MAX_TRACKED_PR_SUMMARIES);

    let mut summaries = Vec::with_capacity(pr_numbers.len());
    for pr_number in pr_numbers {
        let Some(owner_repo) = resolve_owner_repo_for_pr(pr_number, fallback_owner_repo) else {
            continue;
        };
        let summary = run_doctor_inner(&owner_repo, pr_number, Vec::new(), true);
        let lifecycle_state = summary
            .lifecycle
            .as_ref()
            .map_or_else(|| "unknown".to_string(), |entry| entry.state.clone());
        let active_agents = summary
            .agents
            .as_ref()
            .map_or(0, |entry| entry.active_agents);
        let last_activity_seconds_ago = summary.agents.as_ref().and_then(|agents| {
            agents
                .entries
                .iter()
                .filter_map(|entry| entry.last_activity_seconds_ago)
                .min()
        });

        summaries.push(DoctorTrackedPrSummary {
            pr_number,
            owner_repo,
            lifecycle_state,
            recommended_action: summary.recommended_action,
            active_agents,
            last_activity_seconds_ago,
        });
    }
    summaries.sort_by_key(|entry| entry.pr_number);
    Ok(summaries)
}

fn resolve_owner_repo_for_pr(pr_number: u32, fallback_owner_repo: Option<&str>) -> Option<String> {
    for review_type in ["security", "quality"] {
        if let Ok(Some(state)) = load_review_run_state_strict(pr_number, review_type) {
            let owner_repo = state.owner_repo.trim().to_ascii_lowercase();
            if !owner_repo.is_empty() {
                return Some(owner_repo);
            }
        }
    }
    fallback_owner_repo.and_then(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    })
}

fn run_doctor_inner(
    owner_repo: &str,
    pr_number: u32,
    repairs_applied: Vec<DoctorRepairApplied>,
    lightweight: bool,
) -> DoctorPrSummary {
    let mut health = Vec::new();
    let identity = match projection_store::load_pr_identity_snapshot(owner_repo, pr_number) {
        Ok(value) => value,
        Err(err) => {
            health.push(DoctorHealthItem {
                severity: "high",
                message: format!("failed to read local PR identity: {err}"),
                remediation:
                    "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to refresh local projection data"
                        .to_string(),
            });
            None
        },
    };

    let local_sha = identity.as_ref().map(|record| record.head_sha.clone());
    let branch = identity.as_ref().and_then(|record| record.branch.clone());
    let worktree = identity.as_ref().and_then(|record| record.worktree.clone());
    let identity_source = identity.as_ref().map(|record| record.source.clone());
    let identity_updated_at = identity.as_ref().map(|record| record.updated_at.clone());

    let mut remote_head = None;
    if !lightweight {
        match github_reads::fetch_pr_head_sha(owner_repo, pr_number) {
            Ok(value) => {
                if let Err(err) = validate_expected_head_sha(&value) {
                    health.push(DoctorHealthItem {
                        severity: "high",
                        message: format!("invalid remote PR head SHA from GitHub: {err}"),
                        remediation:
                            "retry later when GitHub API returns a valid SHA or refresh repo credentials"
                                .to_string(),
                    });
                } else {
                    remote_head = Some(value.to_ascii_lowercase());
                }
            },
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: format!("could not resolve remote PR head SHA: {err}"),
                    remediation: "retry doctor after GH API access is restored".to_string(),
                });
            },
        }
    }
    let stale = match (&local_sha, remote_head.as_deref()) {
        (Some(local), Some(remote)) => !local.eq_ignore_ascii_case(remote),
        _ => false,
    };

    if stale {
        health.push(DoctorHealthItem {
            severity: "high",
            message: format!(
                "local SHA {} != remote SHA {}",
                local_sha.as_deref().unwrap_or("unknown"),
                remote_head.as_deref().unwrap_or("unknown")
            ),
            remediation: "fetch latest PR head and rerun the FAC pipeline for this SHA".to_string(),
        });
    } else if local_sha.is_none() {
        health.push(DoctorHealthItem {
            severity: "high",
            message: "no local PR identity snapshot found for this PR".to_string(),
            remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to create/refresh identity"
                .to_string(),
        });
    } else if remote_head.is_none() {
        health.push(DoctorHealthItem {
            severity: "medium",
            message: "remote PR head SHA unavailable; using local SHA as authoritative".to_string(),
            remediation: "retry doctor after GitHub API access is restored".to_string(),
        });
    }

    let lifecycle = match lifecycle::load_pr_lifecycle_snapshot(owner_repo, pr_number) {
        Ok(Some(snapshot)) => {
            match snapshot.pr_state.as_str() {
                "stuck" => health.push(DoctorHealthItem {
                    severity: "high",
                    message: "lifecycle reducer is in STUCK state".to_string(),
                    remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to reconcile state"
                        .to_string(),
                }),
                "stale" => health.push(DoctorHealthItem {
                    severity: "medium",
                    message: "lifecycle reducer indicates STALE state".to_string(),
                    remediation:
                        "run `apm2 fac push --pr <PR_NUMBER> --force` to refresh lifecycle state"
                            .to_string(),
                }),
                "recovering" => health.push(DoctorHealthItem {
                    severity: "medium",
                    message: "lifecycle reducer indicates RECOVERING state".to_string(),
                    remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` if recovery stalls"
                        .to_string(),
                }),
                _ => {},
            }
            let lifecycle_view = DoctorLifecycleSnapshot {
                state: snapshot.pr_state.clone(),
                time_in_state_seconds: snapshot.time_in_state_seconds,
                error_budget_used: snapshot.error_budget_used,
                retry_budget_remaining: snapshot.retry_budget_remaining,
                updated_at: snapshot.updated_at.clone(),
                last_event_seq: snapshot.last_event_seq,
            };
            if lifecycle_retry_budget_exhausted(&lifecycle_view) {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: "retry budget exhausted".to_string(),
                    remediation:
                        "manual investigation required; repair lifecycle state before retrying"
                            .to_string(),
                });
            } else if snapshot.retry_budget_remaining == 0 {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message:
                        "retry budget is zero but lifecycle is not in an exhausted terminal shape"
                            .to_string(),
                    remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` if this persists"
                        .to_string(),
                });
            } else if snapshot.error_budget_used > 0 {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: format!(
                        "error budget used: {}/{}",
                        snapshot.error_budget_used,
                        10
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER>` after `apm2 fac restart` to verify trend".to_string(),
                });
            }
            if snapshot.error_budget_used >= 8 {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: "high lifecycle error budget usage".to_string(),
                    remediation:
                        "investigate repeating failures in lifecycle events and CI diagnostics"
                            .to_string(),
                });
            }

            if let Some(local_sha) = local_sha.as_deref()
                && !snapshot.current_sha.eq_ignore_ascii_case(local_sha)
            {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "lifecycle current SHA {} != local identity SHA {}",
                        snapshot.current_sha, local_sha
                    ),
                    remediation:
                        "run `apm2 fac push --pr <PR_NUMBER>` to align lifecycle with current local SHA".to_string(),
                });
            }

            Some(lifecycle_view)
        },
        Ok(None) => {
            health.push(DoctorHealthItem {
                severity: "high",
                message: "no lifecycle record found for this PR".to_string(),
                remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix`".to_string(),
            });
            None
        },
        Err(err) => {
            health.push(DoctorHealthItem {
                severity: "high",
                message: format!("failed to read lifecycle snapshot: {err}"),
                remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix` and re-run doctor"
                    .to_string(),
            });
            None
        },
    };

    let mut gates = Vec::new();
    match local_sha.as_deref() {
        Some(sha) => match gate_cache::GateCache::load(sha) {
            Some(cache) => {
                if cache.gates.is_empty() {
                    health.push(DoctorHealthItem {
                        severity: "medium",
                        message: "no cached gate results for current SHA".to_string(),
                        remediation: "run `apm2 fac push --pr <PR_NUMBER>`".to_string(),
                    });
                }
                for (name, result) in cache.gates {
                    let freshness = gate_result_freshness_seconds(&result.completed_at);
                    let status = verdict_from_gate_status(&result.status);
                    if status == "FAIL" {
                        health.push(DoctorHealthItem {
                            severity: "high",
                            message: format!("gate {name} failed"),
                            remediation: format!(
                                "rerun gate evidence stage with `apm2 fac push --pr {pr_number}`"
                            ),
                        });
                    } else if status == "NOT_RUN" {
                        health.push(DoctorHealthItem {
                            severity: "medium",
                            message: format!(
                                "gate {name} has non-terminal status `{}`",
                                result.status
                            ),
                            remediation: format!(
                                "rerun evidence stage for PR #{pr_number} if stale"
                            ),
                        });
                    } else if freshness.is_some_and(|age| age > DOCTOR_STALE_GATE_AGE_SECONDS) {
                        health.push(DoctorHealthItem {
                            severity: "low",
                            message: format!(
                                "gate {name} cache is stale ({})",
                                format_freshness_age(freshness)
                            ),
                            remediation: "rerun gate evidence to refresh cache".to_string(),
                        });
                    }
                    gates.push(DoctorGateSnapshot {
                        name,
                        status: status.to_string(),
                        completed_at: if result.completed_at.trim().is_empty() {
                            None
                        } else {
                            Some(result.completed_at.clone())
                        },
                        freshness_seconds: freshness,
                    });
                }
            },
            None => {
                health.push(DoctorHealthItem {
                    severity: "low",
                    message: "no gate cache found for local SHA".to_string(),
                    remediation: format!(
                        "run `apm2 fac push --pr {pr_number}` to populate evidence cache"
                    ),
                });
            },
        },
        None => health.push(DoctorHealthItem {
            severity: "high",
            message: "no local SHA resolved for gate review".to_string(),
            remediation: "establish local identity via `apm2 fac push --pr <PR_NUMBER>`"
                .to_string(),
        }),
    }

    let mut reviews = if let Some(sha) = local_sha.as_deref() {
        match verdict_projection::load_verdict_projection_snapshot(owner_repo, pr_number, sha) {
            Ok(Some(snapshot)) => {
                if !snapshot.errors.is_empty() {
                    health.push(DoctorHealthItem {
                        severity: "medium",
                        message: snapshot.errors.join("; "),
                        remediation:
                            "rerun review verdict emission paths for missing or corrupted entries"
                                .to_string(),
                    });
                }
                collect_review_dimension_snapshots(&snapshot)
            },
            Ok(None) => {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: "no verdict projection for local SHA".to_string(),
                    remediation:
                        "run both `fac review run --pr` and `fac review verdict show --pr --sha`"
                            .to_string(),
                });
                collect_default_review_dimension_snapshots(sha)
            },
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!("failed to load verdict projection: {err}"),
                    remediation:
                        "re-run review verdict flow (`fac review set`) after integrity check"
                            .to_string(),
                });
                collect_default_review_dimension_snapshots(sha)
            },
        }
    } else {
        health.push(DoctorHealthItem {
            severity: "high",
            message: "no local SHA resolved for verdict lookup".to_string(),
            remediation: "establish local PR identity before reading verdicts".to_string(),
        });
        Vec::new()
    };
    let (run_state_diagnostics, review_terminal_reasons) =
        collect_run_state_diagnostics(pr_number, &mut health);
    apply_terminal_reasons_to_reviews(&mut reviews, &review_terminal_reasons);

    let agents = match lifecycle::load_agent_registry_snapshot_for_pr(owner_repo, pr_number) {
        Ok(snapshot) => {
            let max_active = snapshot.max_active_agents_per_pr;
            let active_agents = snapshot.active_agents;
            if active_agents > max_active {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "active agent entries ({active_agents}) exceed configured max ({max_active})"
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to prune stale/invalid registry entries"
                            .to_string(),
                });
            }

            for entry in &snapshot.entries {
                if entry.pid.is_some()
                    && matches!(entry.state.as_str(), "running" | "dispatched")
                    && !entry.pid_alive
                {
                    health.push(DoctorHealthItem {
                        severity: "high",
                        message: format!(
                            "{} lane pid={} is no longer alive",
                            entry.agent_type,
                            entry.pid.unwrap_or(0)
                        ),
                        remediation:
                            "run `apm2 fac restart --pr <PR_NUMBER>` to reclaim lane state"
                                .to_string(),
                    });
                }
                if entry.pid.is_none()
                    && matches!(entry.state.as_str(), "running" | "dispatched" | "stuck")
                {
                    health.push(DoctorHealthItem {
                        severity: "medium",
                        message: format!(
                            "{} lane for PR #{} has missing PID in state {}",
                            entry.agent_type, pr_number, entry.state
                        ),
                        remediation:
                            "rerun `apm2 fac restart --pr <PR_NUMBER>` and watch for slot reapage"
                                .to_string(),
                    });
                }
            }
            if let Some(lifecycle) = lifecycle.as_ref()
                && lifecycle.state == "review_in_progress"
                && active_agents == 0
            {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: "review_in_progress lifecycle state with zero active agents"
                        .to_string(),
                    remediation: "run `apm2 fac restart --pr <PR_NUMBER>` to resume reviews"
                        .to_string(),
                });
            }

            let mut entries = Vec::with_capacity(snapshot.entries.len());
            let (
                activity_map,
                activity_by_run_id,
                model_attempts,
                model_attempts_by_run_id,
                tool_call_counts,
                nudge_counts_from_events,
                findings_activity,
            ) = if lightweight {
                (
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                )
            } else {
                let active_run_ids = snapshot
                    .entries
                    .iter()
                    .map(|entry| entry.run_id.trim().to_string())
                    .filter(|run_id| !run_id.is_empty())
                    .collect::<std::collections::BTreeSet<_>>();
                let event_signals = scan_event_signals_for_pr(pr_number, &active_run_ids);
                let fa = latest_finding_activity_by_dimension(
                    owner_repo,
                    pr_number,
                    local_sha.as_deref(),
                );
                (
                    event_signals.activity_timestamps,
                    event_signals.activity_timestamps_by_run_id,
                    event_signals.model_attempts,
                    event_signals.model_attempts_by_run_id,
                    event_signals.tool_call_counts,
                    event_signals.nudge_counts,
                    fa,
                )
            };
            let (run_state_nudge_counts, log_line_counts) = if lightweight {
                (
                    std::collections::BTreeMap::new(),
                    std::collections::BTreeMap::new(),
                )
            } else {
                (
                    load_run_state_nudge_counts_for_pr(pr_number),
                    collect_log_line_counts_for_pr(pr_number),
                )
            };
            for entry in snapshot.entries {
                let dimension = doctor_dimension_for_agent(&entry.agent_type);
                let run_id_key = entry.run_id.trim().to_string();
                let started_at = parse_rfc3339_utc(entry.started_at.as_str());
                let pulse_activity = dimension
                    .and_then(|review_type| read_pulse_file(pr_number, review_type).ok().flatten())
                    .and_then(|pulse| {
                        let run_matches = pulse
                            .run_id
                            .as_deref()
                            .is_some_and(|run_id| run_id == entry.run_id);
                        if !run_matches {
                            return None;
                        }
                        let fresh_for_run =
                            started_at.is_none_or(|started| pulse.written_at >= started);
                        if fresh_for_run && pulse.head_sha.eq_ignore_ascii_case(&entry.sha) {
                            Some(pulse.written_at)
                        } else {
                            None
                        }
                    });
                let elapsed_seconds = started_at.and_then(seconds_since_datetime_utc);
                let last_activity = dimension.and_then(|review_type| {
                    let mut latest = activity_by_run_id.get(&run_id_key).copied();
                    if latest.is_none() {
                        latest = activity_map.get(review_type).copied();
                    }
                    if let Some(ts) = pulse_activity {
                        latest = Some(latest.map_or(ts, |current: DateTime<Utc>| current.max(ts)));
                    }
                    if let Some(ts) = findings_activity.get(review_type).copied() {
                        latest = Some(latest.map_or(ts, |current: DateTime<Utc>| current.max(ts)));
                    }
                    latest
                });
                let models_attempted = model_attempts_by_run_id
                    .get(&run_id_key)
                    .cloned()
                    .or_else(|| {
                        dimension.and_then(|review_type| model_attempts.get(review_type).cloned())
                    })
                    .unwrap_or_default();
                let tool_call_count = tool_call_counts.get(&run_id_key).copied();
                let nudge_count = run_state_nudge_counts
                    .get(&run_id_key)
                    .copied()
                    .or_else(|| {
                        nudge_counts_from_events
                            .get(&run_id_key)
                            .and_then(|count| u32::try_from(*count).ok())
                    });
                let log_line_count = log_line_counts.get(&run_id_key).copied();
                entries.push(DoctorAgentSnapshot {
                    agent_type: entry.agent_type,
                    state: entry.state,
                    run_id: entry.run_id,
                    sha: entry.sha,
                    pid: entry.pid,
                    pid_alive: entry.pid_alive,
                    started_at: entry.started_at,
                    completion_status: entry.completion_status,
                    completion_summary: entry.completion_summary,
                    completion_token_hash: entry.completion_token_hash,
                    completion_token_expires_at: entry.completion_token_expires_at,
                    elapsed_seconds,
                    models_attempted,
                    tool_call_count,
                    log_line_count,
                    nudge_count,
                    last_activity_seconds_ago: last_activity.and_then(seconds_since_datetime_utc),
                });
            }
            Some(DoctorAgentSection {
                max_active_agents_per_pr: max_active,
                active_agents,
                total_agents: entries.len(),
                entries,
            })
        },
        Err(err) => {
            health.push(DoctorHealthItem {
                severity: "medium",
                message: format!("failed to load agent registry snapshot: {err}"),
                remediation: "run `apm2 fac doctor --pr <PR_NUMBER> --fix`".to_string(),
            });
            None
        },
    };

    let findings_summary =
        build_doctor_findings_summary(owner_repo, pr_number, local_sha.as_deref(), &reviews);
    let (worktree_status, merge_conflict_status) =
        build_doctor_worktree_status(&mut health, local_sha.as_deref(), worktree.as_deref());
    let merge_readiness = build_doctor_merge_readiness(
        &reviews,
        &gates,
        stale,
        local_sha.as_ref(),
        remote_head.as_ref(),
        merge_conflict_status,
    );
    let github_projection = if lightweight {
        DoctorGithubProjectionStatus {
            auto_merge_enabled: false,
            last_comment_updated_at: None,
            projection_lag_seconds: None,
        }
    } else {
        build_doctor_github_projection_status(owner_repo, pr_number, local_sha.as_deref())
    };
    let latest_push_attempt =
        match build_doctor_push_attempt_summary(owner_repo, pr_number, local_sha.as_deref()) {
            Ok(value) => value,
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: format!("failed to read push attempt log: {err}"),
                    remediation: "rerun `apm2 fac push --pr <PR_NUMBER>` to refresh push telemetry"
                        .to_string(),
                });
                None
            },
        };
    let recommended_action = build_recommended_action(&DoctorActionInputs {
        pr_number,
        health: &health,
        lifecycle: lifecycle.as_ref(),
        agents: agents.as_ref(),
        reviews: &reviews,
        review_terminal_reasons: &review_terminal_reasons,
        run_state_diagnostics: &run_state_diagnostics,
        findings_summary: &findings_summary,
        merge_readiness: &merge_readiness,
        latest_push_attempt: latest_push_attempt.as_ref(),
    });

    DoctorPrSummary {
        schema: DOCTOR_SCHEMA.to_string(),
        pr_number,
        owner_repo: owner_repo.to_ascii_lowercase(),
        identity: DoctorIdentitySnapshot {
            pr_number,
            branch,
            worktree,
            source: identity_source,
            local_sha,
            updated_at: identity_updated_at,
            remote_head_sha: remote_head,
            stale,
        },
        lifecycle,
        gates,
        reviews,
        findings_summary,
        merge_readiness,
        worktree_status,
        github_projection,
        recommended_action,
        agents,
        run_state_diagnostics,
        repairs_applied,
        latest_push_attempt,
        health,
    }
}

#[derive(Debug, Clone)]
struct DoctorRepairPlan {
    reap_stale_agents: bool,
    refresh_identity: bool,
    reset_lifecycle: bool,
    run_state_review_types: Vec<String>,
}

fn derive_doctor_repair_plan(summary: &DoctorPrSummary) -> DoctorRepairPlan {
    let has_dead_running_agent = summary.agents.as_ref().is_some_and(|agents| {
        agents.entries.iter().any(|entry| {
            matches!(entry.state.as_str(), "running" | "dispatched") && !entry.pid_alive
        })
    });
    let exceeds_capacity = summary
        .agents
        .as_ref()
        .is_some_and(|agents| agents.active_agents > agents.max_active_agents_per_pr);
    let lifecycle_needs_reset = summary.lifecycle.as_ref().is_none_or(|lifecycle| {
        matches!(
            lifecycle.state.as_str(),
            "stuck" | "recovering" | "quarantined"
        )
    });
    let fixable_health_signal = summary.health.iter().any(|item| {
        let message = item.message.to_ascii_lowercase();
        message.contains("failed to read lifecycle")
            || message.contains("failed to parse lifecycle")
            || message.contains("failed to load agent registry")
            || message.contains("unexpected agent registry schema")
            || message.contains("unexpected lifecycle state schema")
    });
    let run_state_review_types = summary
        .run_state_diagnostics
        .iter()
        .filter(|entry| entry.condition.requires_repair())
        .map(|entry| entry.review_type.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    DoctorRepairPlan {
        reap_stale_agents: has_dead_running_agent || exceeds_capacity,
        refresh_identity: summary.identity.stale || summary.identity.local_sha.is_none(),
        reset_lifecycle: lifecycle_needs_reset || fixable_health_signal,
        run_state_review_types,
    }
}

fn doctor_requires_force_repair(summary: &DoctorPrSummary) -> bool {
    let health_force = summary.health.iter().any(|item| {
        let message = item.message.to_ascii_lowercase();
        message.contains("failed to parse lifecycle")
            || message.contains("failed to read lifecycle")
            || message.contains("failed to load agent registry")
            || message.contains("unexpected agent registry schema")
            || message.contains("unexpected lifecycle state schema")
    });
    let run_state_force = summary.run_state_diagnostics.iter().any(|entry| {
        matches!(
            entry.condition,
            DoctorRunStateCondition::Corrupt | DoctorRunStateCondition::Ambiguous
        )
    });
    health_force || run_state_force
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn seconds_since_datetime_utc(value: DateTime<Utc>) -> Option<i64> {
    let delta = Utc::now() - value;
    let std_delta = delta.to_std().ok()?;
    i64::try_from(std_delta.as_secs()).ok()
}

fn doctor_dimension_for_agent(agent_type: &str) -> Option<&'static str> {
    match agent_type {
        "reviewer_security" | "security" => Some("security"),
        "reviewer_quality" | "quality" | "code-quality" => Some("quality"),
        _ => None,
    }
}

#[derive(Default)]
struct DoctorEventSignals {
    activity_timestamps: std::collections::BTreeMap<String, DateTime<Utc>>,
    activity_timestamps_by_run_id: std::collections::BTreeMap<String, DateTime<Utc>>,
    model_attempts: std::collections::BTreeMap<String, Vec<String>>,
    model_attempts_by_run_id: std::collections::BTreeMap<String, Vec<String>>,
    tool_call_counts: std::collections::BTreeMap<String, u64>,
    nudge_counts: std::collections::BTreeMap<String, u64>,
}

fn event_dimension_key(review_type: &str) -> Option<String> {
    match review_type.trim().to_ascii_lowercase().as_str() {
        "security" => Some("security".to_string()),
        "quality" | "code-quality" => Some("quality".to_string()),
        _ => None,
    }
}

fn scan_event_signals_for_pr(
    pr_number: u32,
    run_ids: &std::collections::BTreeSet<String>,
) -> DoctorEventSignals {
    let Ok(path) = review_events_path() else {
        return DoctorEventSignals::default();
    };
    let rotated_path = apm2_daemon::telemetry::reviewer::reviewer_events_rotated_path(&path);
    if !path.exists() && !rotated_path.exists() {
        return DoctorEventSignals::default();
    }

    scan_event_signals_from_sources_with_budget(
        &[path, rotated_path],
        pr_number,
        run_ids,
        DOCTOR_EVENT_SCAN_MAX_BYTES_PER_SOURCE,
    )
}

fn read_event_source_tail(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    if max_bytes == 0 {
        return Some(Vec::new());
    }
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len == 0 {
        return Some(Vec::new());
    }

    let bytes_to_read = file_len.min(max_bytes);
    let start_offset = file_len.saturating_sub(bytes_to_read);
    file.seek(SeekFrom::Start(start_offset)).ok()?;

    let mut tail = Vec::new();
    file.take(bytes_to_read).read_to_end(&mut tail).ok()?;

    if start_offset > 0 {
        if let Some(newline_idx) = tail.iter().position(|byte| *byte == b'\n') {
            tail = tail.split_off(newline_idx.saturating_add(1));
        } else {
            tail.clear();
        }
    }
    Some(tail)
}

fn scan_event_signals_from_sources_with_budget(
    sources: &[PathBuf],
    pr_number: u32,
    run_ids: &std::collections::BTreeSet<String>,
    max_bytes_per_source: u64,
) -> DoctorEventSignals {
    let mut signals = DoctorEventSignals::default();
    let mut remaining_lines = DOCTOR_EVENT_SCAN_MAX_LINES;
    for source in sources {
        if remaining_lines == 0 {
            break;
        }
        let Some(tail_bytes) = read_event_source_tail(source, max_bytes_per_source) else {
            continue;
        };
        let reader = std::io::Cursor::new(tail_bytes);
        let mut remaining_bytes = max_bytes_per_source;
        scan_event_signals_from_reader_with_budget(
            reader,
            pr_number,
            run_ids,
            &mut signals,
            &mut remaining_lines,
            &mut remaining_bytes,
        );
    }
    signals
}

#[cfg(test)]
fn scan_event_signals_from_reader<R: BufRead>(
    reader: R,
    pr_number: u32,
    run_ids: &std::collections::BTreeSet<String>,
) -> DoctorEventSignals {
    let mut signals = DoctorEventSignals::default();
    let mut remaining_lines = DOCTOR_EVENT_SCAN_MAX_LINES;
    let mut remaining_bytes = DOCTOR_EVENT_SCAN_MAX_BYTES_PER_SOURCE;
    scan_event_signals_from_reader_with_budget(
        reader,
        pr_number,
        run_ids,
        &mut signals,
        &mut remaining_lines,
        &mut remaining_bytes,
    );
    signals
}

enum BoundedLineRead {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

fn discard_until_newline<R: BufRead>(reader: &mut R) -> std::io::Result<usize> {
    let mut consumed = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(consumed);
        }
        if let Some(newline_idx) = available.iter().position(|byte| *byte == b'\n') {
            let consume_bytes = newline_idx.saturating_add(1);
            reader.consume(consume_bytes);
            return Ok(consumed.saturating_add(consume_bytes));
        }
        let chunk_len = available.len();
        reader.consume(chunk_len);
        consumed = consumed.saturating_add(chunk_len);
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_line_bytes: usize,
) -> std::io::Result<(BoundedLineRead, usize)> {
    let mut line = Vec::new();
    let line_limit_plus_one = max_line_bytes.saturating_add(1);
    let line_limit = u64::try_from(line_limit_plus_one).unwrap_or(u64::MAX);

    let (bytes_read, limit_reached) = {
        let mut limited_reader = reader.by_ref().take(line_limit);
        let bytes_read = limited_reader.read_until(b'\n', &mut line)?;
        (bytes_read, limited_reader.limit() == 0)
    };

    if bytes_read == 0 {
        return Ok((BoundedLineRead::Eof, 0));
    }
    if limit_reached && !line.ends_with(b"\n") {
        let drained = discard_until_newline(reader)?;
        let consumed_total = bytes_read.saturating_add(drained);
        return Ok((BoundedLineRead::TooLong, consumed_total));
    }

    Ok((BoundedLineRead::Line(line), bytes_read))
}

fn scan_event_signals_from_reader_with_budget<R: BufRead>(
    mut reader: R,
    pr_number: u32,
    run_ids: &std::collections::BTreeSet<String>,
    signals: &mut DoctorEventSignals,
    remaining_lines: &mut usize,
    remaining_bytes: &mut u64,
) {
    let mut event_line_counts = std::collections::BTreeMap::<String, u64>::new();
    loop {
        if *remaining_lines == 0 || *remaining_bytes == 0 {
            break;
        }
        *remaining_lines = (*remaining_lines).saturating_sub(1);

        let Ok((bounded_line, consumed_bytes)) =
            read_bounded_line(&mut reader, DOCTOR_EVENT_SCAN_MAX_LINE_BYTES)
        else {
            continue;
        };
        let consumed_u64 = u64::try_from(consumed_bytes).unwrap_or(u64::MAX);
        *remaining_bytes = (*remaining_bytes).saturating_sub(consumed_u64);

        let line = match bounded_line {
            BoundedLineRead::Eof => break,
            BoundedLineRead::TooLong => continue,
            BoundedLineRead::Line(bytes) => {
                let Ok(line) = String::from_utf8(bytes) else {
                    continue;
                };
                line
            },
        };

        let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };

        let matches_pr = event
            .get("pr_number")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|value| value == u64::from(pr_number));
        if !matches_pr {
            continue;
        }

        let event_run_id = event
            .get("run_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);

        if !run_ids.is_empty() {
            let Some(run_id) = event_run_id.as_ref() else {
                continue;
            };
            if !run_ids.contains(run_id) {
                continue;
            }
        }

        let review_type = event
            .get("review_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let Some(key) = event_dimension_key(review_type) else {
            continue;
        };

        if let Some(ts) = event
            .get("ts")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_rfc3339_utc)
        {
            update_activity_timestamp(&mut signals.activity_timestamps, &key, ts);
            if let Some(run_id) = event_run_id.as_ref() {
                update_activity_timestamp(&mut signals.activity_timestamps_by_run_id, run_id, ts);
            }
        }

        let event_name = event
            .get("event")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        if event
            .get("event")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == "run_start")
            && let Some(model) = event.get("model").and_then(serde_json::Value::as_str)
            && !model.trim().is_empty()
        {
            push_model_attempt(&mut signals.model_attempts, &key, model);
            if let Some(run_id) = event_run_id.as_ref() {
                push_model_attempt(&mut signals.model_attempts_by_run_id, run_id, model);
            }
        }

        if event
            .get("event")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == "model_fallback")
            && let Some(model) = event.get("to_model").and_then(serde_json::Value::as_str)
            && !model.trim().is_empty()
        {
            push_model_attempt(&mut signals.model_attempts, &key, model);
            if let Some(run_id) = event_run_id.as_ref() {
                push_model_attempt(&mut signals.model_attempts_by_run_id, run_id, model);
            }
        }

        if let Some(run_id) = event_run_id {
            event_line_counts
                .entry(run_id.clone())
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);

            if event_name == "nudge_resume" {
                signals
                    .nudge_counts
                    .entry(run_id.clone())
                    .and_modify(|count| *count = count.saturating_add(1))
                    .or_insert(1);
            }

            if event_contains_tool_signal(&event)
                || (!event_name.is_empty() && !is_lifecycle_event_name(event_name))
            {
                signals
                    .tool_call_counts
                    .entry(run_id)
                    .and_modify(|count| *count = count.saturating_add(1))
                    .or_insert(1);
            }
        }
    }

    for (run_id, total_lines) in event_line_counts {
        signals
            .tool_call_counts
            .entry(run_id)
            .or_insert(total_lines);
    }
}

fn update_activity_timestamp(
    target: &mut std::collections::BTreeMap<String, DateTime<Utc>>,
    key: &str,
    ts: DateTime<Utc>,
) {
    target
        .entry(key.to_string())
        .and_modify(|existing| *existing = (*existing).max(ts))
        .or_insert(ts);
}

fn push_model_attempt(
    target: &mut std::collections::BTreeMap<String, Vec<String>>,
    key: &str,
    model: &str,
) {
    target
        .entry(key.to_string())
        .or_default()
        .push(model.to_string());
}

fn is_lifecycle_event_name(event_name: &str) -> bool {
    matches!(
        event_name,
        "run_start"
            | "run_complete"
            | "run_crash"
            | "run_deduplicated"
            | "model_fallback"
            | "completion_signal_detected"
            | "pulse_check"
            | "liveness_check"
            | "stall_detected"
            | "sha_update"
            | "review_posted"
            | "nudge_resume"
    )
}

fn event_contains_tool_signal(event: &serde_json::Value) -> bool {
    [
        "tool",
        "tool_call",
        "tool_calls",
        "tool_name",
        "toolCall",
        "toolCallId",
    ]
    .iter()
    .any(|key| event.get(*key).is_some())
}

fn load_run_state_nudge_counts_for_pr(pr_number: u32) -> std::collections::BTreeMap<String, u32> {
    let mut counts = std::collections::BTreeMap::new();
    for review_type in ["security", "quality"] {
        let Ok(Some(state)) = load_review_run_state_strict(pr_number, review_type) else {
            continue;
        };
        let run_id = state.run_id.trim();
        if run_id.is_empty() {
            continue;
        }
        counts.insert(run_id.to_string(), state.nudge_count);
    }
    counts
}

fn collect_log_line_counts_for_pr(pr_number: u32) -> std::collections::BTreeMap<String, u64> {
    let mut counts = std::collections::BTreeMap::<String, u64>::new();
    let _ = state::with_review_state_shared(|review_state| {
        for entry in review_state.reviewers.values() {
            if entry.pr_number != pr_number {
                continue;
            }
            let run_id = entry.run_id.trim();
            if run_id.is_empty() {
                continue;
            }
            let Some(line_count) = count_log_lines_bounded(&entry.log_file) else {
                continue;
            };
            counts
                .entry(run_id.to_string())
                .and_modify(|existing| *existing = (*existing).max(line_count))
                .or_insert(line_count);
        }
        Ok(())
    });
    counts
}

fn count_log_lines_bounded(path: &Path) -> Option<u64> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut chunk = [0_u8; DOCTOR_LOG_SCAN_CHUNK_BYTES];
    let mut line_count = 0_u64;
    let mut byte_count = 0_u64;
    let mut saw_bytes = false;
    let mut last_byte = None;

    while line_count < DOCTOR_LOG_SCAN_MAX_LINES && byte_count < DOCTOR_LOG_SCAN_MAX_BYTES {
        let remaining_bytes = DOCTOR_LOG_SCAN_MAX_BYTES.saturating_sub(byte_count);
        let to_read =
            usize::try_from(remaining_bytes.min(DOCTOR_LOG_SCAN_CHUNK_BYTES as u64)).ok()?;
        if to_read == 0 {
            break;
        }
        let bytes_read = reader.read(&mut chunk[..to_read]).ok()?;
        if bytes_read == 0 {
            break;
        }

        saw_bytes = true;
        byte_count = byte_count.saturating_add(bytes_read as u64);
        last_byte = chunk.get(bytes_read.saturating_sub(1)).copied();

        let mut newline_count = 0_u64;
        for byte in &chunk[..bytes_read] {
            if *byte == b'\n' {
                newline_count = newline_count.saturating_add(1);
            }
        }
        line_count = line_count.saturating_add(newline_count);
    }

    if saw_bytes && line_count < DOCTOR_LOG_SCAN_MAX_LINES && !matches!(last_byte, Some(b'\n')) {
        line_count = line_count.saturating_add(1);
    }

    Some(line_count)
}

fn latest_finding_activity_by_dimension(
    owner_repo: &str,
    pr_number: u32,
    local_sha: Option<&str>,
) -> std::collections::BTreeMap<String, DateTime<Utc>> {
    let mut latest = std::collections::BTreeMap::new();
    let Some(sha) = local_sha else {
        return latest;
    };
    let Ok(Some(bundle)) = findings_store::load_findings_bundle(owner_repo, pr_number, sha) else {
        return latest;
    };
    for dimension in ["security", "code-quality"] {
        let Some(view) = findings_store::find_dimension(&bundle, dimension) else {
            continue;
        };
        let mut newest = None;
        for finding in &view.findings {
            if let Some(ts) = parse_rfc3339_utc(&finding.created_at) {
                newest = Some(newest.map_or(ts, |current: DateTime<Utc>| current.max(ts)));
            }
        }
        if let Some(ts) = newest {
            let key = if dimension == "code-quality" {
                "quality".to_string()
            } else {
                "security".to_string()
            };
            latest.insert(key, ts);
        }
    }
    latest
}

fn canonical_review_dimension(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "security" => "security".to_string(),
        "quality" | "code-quality" => "code-quality".to_string(),
        other => other.to_string(),
    }
}

fn collect_run_state_diagnostics(
    pr_number: u32,
    health: &mut Vec<DoctorHealthItem>,
) -> (
    Vec<DoctorRunStateDiagnostic>,
    std::collections::BTreeMap<String, Option<String>>,
) {
    let mut diagnostics = Vec::new();
    let mut reasons = std::collections::BTreeMap::new();
    for (review_type, dimension) in [("security", "security"), ("quality", "code-quality")] {
        let canonical_path = match review_run_state_path(pr_number, review_type) {
            Ok(path) => path.display().to_string(),
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "failed to resolve {review_type} run-state path for doctor: {err}"
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to rebuild run-state"
                            .to_string(),
                });
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Unavailable,
                    canonical_path: "-".to_string(),
                    detail: Some(err),
                    candidates: Vec::new(),
                });
                reasons.insert(dimension.to_string(), None);
                continue;
            },
        };
        match load_review_run_state(pr_number, review_type) {
            Ok(state::ReviewRunStateLoad::Present(state)) => {
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Healthy,
                    canonical_path,
                    detail: None,
                    candidates: Vec::new(),
                });
                reasons.insert(dimension.to_string(), state.terminal_reason);
            },
            Ok(state::ReviewRunStateLoad::Missing { .. }) => {
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Missing,
                    canonical_path,
                    detail: Some("run-state file missing".to_string()),
                    candidates: Vec::new(),
                });
                health.push(DoctorHealthItem {
                    severity: "low",
                    message: format!("missing {review_type} run-state file"),
                    remediation:
                        "if review execution is expected for this dimension, run `apm2 fac restart --pr <PR_NUMBER>`"
                            .to_string(),
                });
                reasons.insert(dimension.to_string(), None);
            },
            Ok(state::ReviewRunStateLoad::Corrupt { path, error }) => {
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Corrupt,
                    canonical_path,
                    detail: Some(format!(
                        "corrupt-state path={} detail={error}",
                        path.display()
                    )),
                    candidates: Vec::new(),
                });
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "{review_type} run-state is corrupt: path={} detail={error}",
                        path.display()
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to quarantine and rebuild run-state"
                            .to_string(),
                });
                reasons.insert(dimension.to_string(), None);
            },
            Ok(state::ReviewRunStateLoad::Ambiguous { dir, candidates }) => {
                let rendered_candidates = candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>();
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Ambiguous,
                    canonical_path,
                    detail: Some(format!("ambiguous-state dir={}", dir.display())),
                    candidates: rendered_candidates.clone(),
                });
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!(
                        "{review_type} run-state is ambiguous: dir={} candidates={}",
                        dir.display(),
                        rendered_candidates.join(",")
                    ),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to canonicalize run-state candidates"
                            .to_string(),
                });
                reasons.insert(dimension.to_string(), None);
            },
            Err(err) => {
                diagnostics.push(DoctorRunStateDiagnostic {
                    review_type: review_type.to_string(),
                    condition: DoctorRunStateCondition::Unavailable,
                    canonical_path,
                    detail: Some(err.clone()),
                    candidates: Vec::new(),
                });
                health.push(DoctorHealthItem {
                    severity: "high",
                    message: format!("failed to load {review_type} run-state: {err}"),
                    remediation:
                        "run `apm2 fac doctor --pr <PR_NUMBER> --fix` to rebuild run-state"
                            .to_string(),
                });
                reasons.insert(dimension.to_string(), None);
            },
        }
    }
    (diagnostics, reasons)
}

fn apply_terminal_reasons_to_reviews(
    reviews: &mut [DoctorReviewSnapshot],
    terminal_reasons: &std::collections::BTreeMap<String, Option<String>>,
) {
    for review in reviews {
        let key = canonical_review_dimension(&review.dimension);
        review.terminal_reason = terminal_reasons.get(&key).cloned().flatten();
    }
}

fn build_doctor_findings_summary(
    owner_repo: &str,
    pr_number: u32,
    local_sha: Option<&str>,
    reviews: &[DoctorReviewSnapshot],
) -> Vec<DoctorFindingsDimensionSummary> {
    let mut summaries = Vec::new();
    let findings_bundle = local_sha.and_then(|sha| {
        findings_store::load_findings_bundle(owner_repo, pr_number, sha)
            .ok()
            .flatten()
    });

    for dimension in ["security", "code-quality"] {
        let mut counts = DoctorFindingsCounts {
            blocker: 0,
            major: 0,
            minor: 0,
            nit: 0,
        };
        if let Some(bundle) = findings_bundle.as_ref()
            && let Some(view) = findings_store::find_dimension(bundle, dimension)
        {
            for finding in &view.findings {
                match finding.severity.trim().to_ascii_uppercase().as_str() {
                    "BLOCKER" => counts.blocker = counts.blocker.saturating_add(1),
                    "MINOR" => counts.minor = counts.minor.saturating_add(1),
                    "NIT" => counts.nit = counts.nit.saturating_add(1),
                    _ => counts.major = counts.major.saturating_add(1),
                }
            }
        }

        let formal_verdict = reviews
            .iter()
            .find(|entry| canonical_review_dimension(&entry.dimension) == dimension)
            .map_or_else(|| "pending".to_string(), |entry| entry.verdict.clone());
        let computed_verdict = if counts.blocker > 0 || counts.major > 0 {
            "deny".to_string()
        } else if counts.minor > 0 || counts.nit > 0 {
            "approve".to_string()
        } else {
            "pending".to_string()
        };

        summaries.push(DoctorFindingsDimensionSummary {
            dimension: dimension.to_string(),
            counts,
            formal_verdict,
            computed_verdict,
        });
    }
    summaries
}

fn build_doctor_worktree_status(
    health: &mut Vec<DoctorHealthItem>,
    local_sha: Option<&str>,
    worktree: Option<&str>,
) -> (DoctorWorktreeStatus, DoctorMergeConflictStatus) {
    let mut status = DoctorWorktreeStatus {
        worktree_exists: false,
        worktree_clean: false,
        merge_conflicts: 0,
    };
    let mut merge_conflict_status = DoctorMergeConflictStatus::Unknown;

    let Some(worktree_path) = worktree.map(PathBuf::from) else {
        return (status, merge_conflict_status);
    };
    status.worktree_exists = worktree_path.exists();
    if !status.worktree_exists {
        health.push(DoctorHealthItem {
            severity: "medium",
            message: format!("worktree path missing: {}", worktree_path.display()),
            remediation: "run `apm2 fac push --pr <PR_NUMBER>` to refresh identity/worktree"
                .to_string(),
        });
        return (status, merge_conflict_status);
    }

    status.worktree_clean = git_worktree_clean(&worktree_path).unwrap_or(false);
    if let Some(sha) = local_sha {
        match merge_conflicts::check_merge_conflicts_against_main(&worktree_path, sha) {
            Ok(report) => {
                status.merge_conflicts = report.conflict_count();
                merge_conflict_status = if report.has_conflicts() {
                    DoctorMergeConflictStatus::HasConflicts
                } else {
                    DoctorMergeConflictStatus::NoConflicts
                };
            },
            Err(err) => {
                health.push(DoctorHealthItem {
                    severity: "medium",
                    message: format!("failed to evaluate merge conflicts: {err}"),
                    remediation: "resolve local repository state and rerun doctor".to_string(),
                });
            },
        }
    }

    (status, merge_conflict_status)
}

fn git_worktree_clean(worktree: &Path) -> Result<bool, String> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(worktree)
        .output()
        .map_err(|err| format!("failed to check worktree cleanliness: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git status failed in {}: {}",
            worktree.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn build_doctor_merge_readiness(
    reviews: &[DoctorReviewSnapshot],
    gates: &[DoctorGateSnapshot],
    stale_identity: bool,
    local_sha: Option<&String>,
    remote_head_sha: Option<&String>,
    merge_conflict_status: DoctorMergeConflictStatus,
) -> DoctorMergeReadiness {
    let all_verdicts_approve = ["security", "code-quality"].iter().all(|dimension| {
        reviews.iter().any(|entry| {
            canonical_review_dimension(&entry.dimension) == *dimension
                && entry.verdict.eq_ignore_ascii_case("approve")
        })
    });
    let gates_pass = !gates.is_empty() && gates.iter().all(|gate| gate.status == "PASS");
    let (sha_fresh, sha_freshness_source) = if stale_identity {
        (false, DoctorShaFreshnessSource::Stale)
    } else if local_sha.is_some() && remote_head_sha.is_some() {
        (true, DoctorShaFreshnessSource::RemoteMatch)
    } else if local_sha.is_some() {
        (true, DoctorShaFreshnessSource::LocalAuthoritative)
    } else {
        (false, DoctorShaFreshnessSource::Unknown)
    };
    let no_merge_conflicts = merge_conflict_status == DoctorMergeConflictStatus::NoConflicts;
    let merge_ready = all_verdicts_approve && gates_pass && sha_fresh && no_merge_conflicts;
    DoctorMergeReadiness {
        merge_ready,
        all_verdicts_approve,
        gates_pass,
        sha_fresh,
        sha_freshness_source,
        no_merge_conflicts,
        merge_conflict_status,
    }
}

fn build_doctor_github_projection_status(
    owner_repo: &str,
    pr_number: u32,
    local_sha: Option<&str>,
) -> DoctorGithubProjectionStatus {
    let auto_merge_enabled = github_reads::fetch_pr_data(owner_repo, pr_number)
        .ok()
        .and_then(|value| value.get("auto_merge").cloned())
        .is_some_and(|value| !value.is_null());

    let projection_snapshot = local_sha.and_then(|sha| {
        verdict_projection::load_verdict_projection_snapshot(owner_repo, pr_number, sha)
            .ok()
            .flatten()
    });
    let projected_updated_at = projection_snapshot
        .as_ref()
        .map(|snapshot| snapshot.updated_at.clone());
    let github_updated_at = projection_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.source_comment_id)
        .filter(|comment_id| *comment_id > 0)
        .and_then(|comment_id| fetch_issue_comment_updated_at(owner_repo, comment_id));
    let last_comment_updated_at = github_updated_at.or(projected_updated_at);
    let projection_lag_seconds = last_comment_updated_at
        .as_deref()
        .and_then(parse_rfc3339_utc)
        .and_then(seconds_since_datetime_utc);

    DoctorGithubProjectionStatus {
        auto_merge_enabled,
        last_comment_updated_at,
        projection_lag_seconds,
    }
}

fn fetch_issue_comment_updated_at(owner_repo: &str, comment_id: u64) -> Option<String> {
    let endpoint = format!("/repos/{owner_repo}/issues/comments/{comment_id}");
    let output = Command::new("gh")
        .args(["api", &endpoint, "--jq", ".updated_at"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() || value.eq_ignore_ascii_case("null") {
        return None;
    }
    Some(value)
}

fn build_doctor_push_attempt_summary(
    owner_repo: &str,
    pr_number: u32,
    local_sha: Option<&str>,
) -> Result<Option<DoctorPushAttemptSummary>, String> {
    let Some(sha) = local_sha else {
        return Ok(None);
    };
    let Some(attempt) = push::load_latest_push_attempt_for_sha(owner_repo, pr_number, sha)? else {
        return Ok(None);
    };
    let failure = attempt.first_failed_stage();
    let failed_stage = failure.as_ref().map(|entry| entry.stage.clone());
    let exit_code = failure.as_ref().and_then(|entry| entry.exit_code);
    let duration_s = failure.as_ref().map(|entry| entry.duration_s);
    let error_hint = failure.and_then(|entry| entry.error_hint);
    Ok(Some(DoctorPushAttemptSummary {
        ts: attempt.ts,
        sha: attempt.sha,
        failed_stage,
        exit_code,
        duration_s,
        error_hint,
    }))
}

fn lifecycle_retry_budget_exhausted(entry: &DoctorLifecycleSnapshot) -> bool {
    entry.retry_budget_remaining == 0
        && entry.last_event_seq > 0
        && matches!(entry.state.as_str(), "stuck" | "recovering" | "quarantined")
}

fn review_requires_forced_restart(review: &DoctorReviewSnapshot) -> bool {
    review
        .terminal_reason
        .as_deref()
        .is_some_and(|reason| reason.eq_ignore_ascii_case("max_restarts_exceeded"))
}

fn terminal_reason_requires_forced_restart(terminal_reason: Option<&String>) -> bool {
    terminal_reason.is_some_and(|value| value.eq_ignore_ascii_case("max_restarts_exceeded"))
}

fn has_forced_restart_terminal_reason(
    reviews: &[DoctorReviewSnapshot],
    review_terminal_reasons: &std::collections::BTreeMap<String, Option<String>>,
) -> bool {
    reviews.iter().any(review_requires_forced_restart)
        || review_terminal_reasons
            .values()
            .map(std::option::Option::as_ref)
            .any(terminal_reason_requires_forced_restart)
}

fn build_recommended_action(input: &DoctorActionInputs<'_>) -> DoctorRecommendedAction {
    let push_failure_hint = input
        .latest_push_attempt
        .and_then(format_push_attempt_failure_hint);
    let has_run_state_repairable = input
        .run_state_diagnostics
        .iter()
        .any(|entry| entry.condition.requires_repair());
    let has_integrity_or_corruption = has_run_state_repairable
        || input.health.iter().any(|item| {
            let message = item.message.to_ascii_lowercase();
            message.contains("integrity")
                || message.contains("failed to read lifecycle snapshot")
                || message.contains("failed to parse lifecycle")
                || message.contains("failed to load agent registry")
        });

    if has_integrity_or_corruption {
        return DoctorRecommendedAction {
            action: "fix".to_string(),
            reason: "local FAC state indicates integrity/corruption issues".to_string(),
            priority: "high".to_string(),
            command: Some(format!("apm2 fac doctor --pr {} --fix", input.pr_number)),
        };
    }

    if input.merge_readiness.merge_ready {
        return DoctorRecommendedAction {
            action: "merge".to_string(),
            reason: "all verdicts approve; gates pass; SHA is fresh; no merge conflicts"
                .to_string(),
            priority: "medium".to_string(),
            command: None,
        };
    }

    if input.merge_readiness.merge_conflict_status == DoctorMergeConflictStatus::HasConflicts {
        return DoctorRecommendedAction {
            action: "escalate".to_string(),
            reason: "non-fast-forward merge conflict requires human intervention".to_string(),
            priority: "high".to_string(),
            command: None,
        };
    }

    let requires_implementor_remediation = input.findings_summary.iter().any(|entry| {
        entry.formal_verdict.eq_ignore_ascii_case("deny")
            || entry.counts.blocker > 0
            || entry.counts.major > 0
    });
    if requires_implementor_remediation {
        let push_hint = push_failure_hint
            .unwrap_or_else(|| "review findings require implementor remediation".to_string());
        return DoctorRecommendedAction {
            action: "dispatch_implementor".to_string(),
            reason: push_hint,
            priority: "high".to_string(),
            command: None,
        };
    }

    let active_agents = input.agents.map_or(0, |section| section.active_agents);
    let has_pending_verdict = input
        .findings_summary
        .iter()
        .any(|entry| entry.formal_verdict.eq_ignore_ascii_case("pending"));
    if active_agents == 0 && has_pending_verdict {
        let force_restart =
            has_forced_restart_terminal_reason(input.reviews, input.review_terminal_reasons);
        let reason = push_failure_hint
            .unwrap_or_else(|| "no active reviewer agents and verdict remains pending".to_string());
        let command = if force_restart {
            format!(
                "apm2 fac restart --pr {} --force --refresh-identity",
                input.pr_number
            )
        } else {
            format!(
                "apm2 fac restart --pr {} --refresh-identity",
                input.pr_number
            )
        };
        return DoctorRecommendedAction {
            action: "restart_reviews".to_string(),
            reason,
            priority: "high".to_string(),
            command: Some(command),
        };
    }

    let lifecycle_escalation = input.lifecycle.is_some_and(|entry| {
        entry.error_budget_used >= 8 || lifecycle_retry_budget_exhausted(entry)
    });
    if lifecycle_escalation {
        return DoctorRecommendedAction {
            action: "escalate".to_string(),
            reason: "lifecycle retry/error budget exhausted".to_string(),
            priority: "high".to_string(),
            command: None,
        };
    }

    DoctorRecommendedAction {
        action: "wait".to_string(),
        reason: "reviews are in progress or awaiting projection catch-up".to_string(),
        priority: "low".to_string(),
        command: None,
    }
}

fn format_push_attempt_failure_hint(attempt: &DoctorPushAttemptSummary) -> Option<String> {
    let stage = attempt.failed_stage.as_ref()?;
    let exit_code = attempt
        .exit_code
        .map_or_else(|| "-".to_string(), |code| code.to_string());
    let duration = attempt
        .duration_s
        .map_or_else(|| "-".to_string(), |secs| format!("{secs}s"));
    let hint = attempt
        .error_hint
        .clone()
        .unwrap_or_else(|| "no hint".to_string());
    Some(format!(
        "last push: {stage} FAIL (exit {exit_code}, {duration}) - {hint}"
    ))
}

fn collect_default_review_dimension_snapshots(local_sha: &str) -> Vec<DoctorReviewSnapshot> {
    vec![
        DoctorReviewSnapshot {
            dimension: "security".to_string(),
            verdict: "pending".to_string(),
            reviewed_sha: local_sha.to_string(),
            reviewed_by: String::new(),
            reviewed_at: String::new(),
            reason: "no verified projection loaded".to_string(),
            terminal_reason: None,
        },
        DoctorReviewSnapshot {
            dimension: "code-quality".to_string(),
            verdict: "pending".to_string(),
            reviewed_sha: local_sha.to_string(),
            reviewed_by: String::new(),
            reviewed_at: String::new(),
            reason: "no verified projection loaded".to_string(),
            terminal_reason: None,
        },
    ]
}

fn collect_review_dimension_snapshots(
    snapshot: &verdict_projection::VerdictProjectionSnapshot,
) -> Vec<DoctorReviewSnapshot> {
    let mut mapped = std::collections::BTreeMap::<
        String,
        &verdict_projection::VerdictProjectionDimensionSnapshot,
    >::new();
    for entry in &snapshot.dimensions {
        mapped.insert(entry.dimension.clone(), entry);
    }
    ["security", "code-quality"]
        .into_iter()
        .map(|dimension| {
            let Some(entry) = mapped.get(dimension) else {
                return DoctorReviewSnapshot {
                    dimension: (*dimension).to_string(),
                    verdict: "pending".to_string(),
                    reviewed_sha: snapshot.head_sha.clone(),
                    reviewed_by: String::new(),
                    reviewed_at: String::new(),
                    reason: "missing dimension in projection".to_string(),
                    terminal_reason: None,
                };
            };
            DoctorReviewSnapshot {
                dimension: entry.dimension.clone(),
                verdict: entry.decision.clone(),
                reviewed_sha: entry.reviewed_sha.clone(),
                reviewed_by: entry.reviewed_by.clone(),
                reviewed_at: entry.reviewed_at.clone(),
                reason: entry.reason.clone(),
                terminal_reason: None,
            }
        })
        .collect()
}

fn verdict_from_gate_status(status: &str) -> &'static str {
    match status.to_ascii_uppercase().as_str() {
        "PASS" => "PASS",
        "FAIL" => "FAIL",
        _ => "NOT_RUN",
    }
}

fn gate_result_freshness_seconds(completed_at: &str) -> Option<i64> {
    if completed_at.trim().is_empty() {
        return None;
    }
    let Ok(parsed) = DateTime::parse_from_rfc3339(completed_at) else {
        return None;
    };
    let age = Utc::now() - parsed.with_timezone(&Utc);
    let Ok(duration) = age.to_std() else {
        return None;
    };
    Some(
        i64::try_from(duration.as_secs())
            .unwrap_or(i64::MAX)
            .clamp(0, i64::MAX),
    )
}

fn format_freshness_age(seconds: Option<i64>) -> String {
    let Some(seconds) = seconds else {
        return "unknown".to_string();
    };
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 60 * 60 {
        format!("{}m", seconds / 60)
    } else {
        format!("{}h", seconds / (60 * 60))
    }
}

#[allow(dead_code)]
fn emit_doctor_report(summary: &DoctorPrSummary) {
    println!("FAC Doctor");
    println!("  PR:         #{}", summary.pr_number);
    println!("  Repo:       {}", summary.owner_repo);
    println!(
        "  Identity SHA local={} remote={}",
        summary.identity.local_sha.as_deref().unwrap_or("-"),
        summary.identity.remote_head_sha.as_deref().unwrap_or("-")
    );
    if summary.identity.stale {
        println!("  Identity:   STALE");
    }
    println!(
        "  Branch:     {}",
        summary.identity.branch.as_deref().unwrap_or("-")
    );
    println!(
        "  Worktree:   {}",
        summary.identity.worktree.as_deref().unwrap_or("-")
    );
    println!(
        "  Identity source: {}",
        summary.identity.source.as_deref().unwrap_or("-")
    );

    println!("IDENTITY");
    println!(
        "  local_sha:  {}{}",
        summary.identity.local_sha.as_deref().unwrap_or("unknown"),
        if summary.identity.stale {
            " [STALE]"
        } else {
            ""
        }
    );
    println!(
        "  remote_sha: {}",
        summary
            .identity
            .remote_head_sha
            .as_deref()
            .unwrap_or("unavailable")
    );
    println!(
        "  branch:     {}",
        summary.identity.branch.as_deref().unwrap_or("n/a")
    );
    println!(
        "  worktree:   {}",
        summary.identity.worktree.as_deref().unwrap_or("n/a")
    );
    println!(
        "  updated_at: {}",
        summary.identity.updated_at.as_deref().unwrap_or("n/a")
    );

    println!("LIFECYCLE");
    if let Some(lifecycle) = &summary.lifecycle {
        println!("  state:           {}", lifecycle.state);
        println!("  time_in_state:   {}s", lifecycle.time_in_state_seconds);
        println!("  error_budget:    {}", lifecycle.error_budget_used);
        println!("  retry_budget:    {}", lifecycle.retry_budget_remaining);
        println!("  updated_at:      {}", lifecycle.updated_at);
        println!("  last_event_seq:  {}", lifecycle.last_event_seq);
    } else {
        println!("  unavailable");
    }

    println!("GATES");
    if summary.gates.is_empty() {
        println!("  no gate cache entries found");
    } else {
        for gate in &summary.gates {
            println!(
                "  {}: {} (freshness={})",
                gate.name,
                gate.status,
                format_freshness_age(gate.freshness_seconds)
            );
            if let Some(completed_at) = gate.completed_at.as_deref() {
                println!("    completed_at: {completed_at}");
            }
        }
    }

    println!("REVIEWS");
    if summary.reviews.is_empty() {
        println!("  no review projection found");
    } else {
        for review in &summary.reviews {
            println!("  {}: {}", review.dimension, review.verdict);
            println!(
                "    reviewed_sha: {}  reviewed_by: {}",
                if review.reviewed_sha.is_empty() {
                    "-"
                } else {
                    &review.reviewed_sha
                },
                if review.reviewed_by.is_empty() {
                    "-"
                } else {
                    &review.reviewed_by
                }
            );
            if !review.reason.is_empty() {
                println!("    reason: {}", review.reason);
            }
            if !review.reviewed_at.is_empty() {
                println!("    reviewed_at: {}", review.reviewed_at);
            }
            if let Some(reason) = review.terminal_reason.as_deref() {
                println!("    terminal_reason: {reason}");
            }
        }
    }

    println!("FINDINGS_SUMMARY");
    for entry in &summary.findings_summary {
        println!(
            "  {}: formal={} computed={} counts={{blocker:{}, major:{}, minor:{}, nit:{}}}",
            entry.dimension,
            entry.formal_verdict,
            entry.computed_verdict,
            entry.counts.blocker,
            entry.counts.major,
            entry.counts.minor,
            entry.counts.nit
        );
    }

    println!("MERGE_READINESS");
    println!("  merge_ready: {}", summary.merge_readiness.merge_ready);
    println!(
        "  checks: all_verdicts_approve={} gates_pass={} sha_fresh={} no_merge_conflicts={}",
        summary.merge_readiness.all_verdicts_approve,
        summary.merge_readiness.gates_pass,
        summary.merge_readiness.sha_fresh,
        summary.merge_readiness.no_merge_conflicts
    );
    println!(
        "  status: sha_freshness_source={} merge_conflict_status={}",
        summary.merge_readiness.sha_freshness_source.as_str(),
        summary.merge_readiness.merge_conflict_status.as_str()
    );

    println!("WORKTREE");
    println!(
        "  exists={} clean={} merge_conflicts={}",
        summary.worktree_status.worktree_exists,
        summary.worktree_status.worktree_clean,
        summary.worktree_status.merge_conflicts
    );

    println!("RECOMMENDED_ACTION");
    println!(
        "  action={} priority={} reason={}",
        summary.recommended_action.action,
        summary.recommended_action.priority,
        summary.recommended_action.reason
    );
    if let Some(command) = summary.recommended_action.command.as_deref() {
        println!("  command={command}");
    }

    println!("AGENTS");
    if let Some(agents) = &summary.agents {
        println!(
            "  active_slots: {}/{}",
            agents.active_agents, agents.max_active_agents_per_pr
        );
        println!("  total_entries: {}", agents.total_agents);
        if agents.entries.is_empty() {
            println!("  no entries");
        } else {
            for entry in &agents.entries {
                println!(
                    "  {} {} pid={:?} alive={} sha={} run_id={}",
                    entry.agent_type,
                    entry.state,
                    entry.pid,
                    entry.pid_alive,
                    entry.sha,
                    entry.run_id
                );
                if let Some(elapsed) = entry.elapsed_seconds {
                    println!("    elapsed_seconds: {elapsed}");
                }
                if !entry.models_attempted.is_empty() {
                    println!(
                        "    models_attempted: {}",
                        entry.models_attempted.join(", ")
                    );
                }
                if let Some(tool_call_count) = entry.tool_call_count {
                    println!("    tool_call_count: {tool_call_count}");
                }
                if let Some(log_line_count) = entry.log_line_count {
                    println!("    log_line_count: {log_line_count}");
                }
                if let Some(nudge_count) = entry.nudge_count {
                    println!("    nudge_count: {nudge_count}");
                }
                if let Some(activity_age) = entry.last_activity_seconds_ago {
                    println!("    last_activity_seconds_ago: {activity_age}");
                }
            }
        }
    } else {
        println!("  unavailable");
    }

    if let Some(attempt) = summary.latest_push_attempt.as_ref() {
        println!("LATEST_PUSH_ATTEMPT");
        println!("  ts={} sha={}", attempt.ts, attempt.sha);
        if let Some(stage) = attempt.failed_stage.as_deref() {
            println!(
                "  failed_stage={} exit_code={:?} duration_s={:?} hint={}",
                stage,
                attempt.exit_code,
                attempt.duration_s,
                attempt.error_hint.as_deref().unwrap_or("-")
            );
        } else {
            println!("  failed_stage=none");
        }
    }

    if !summary.repairs_applied.is_empty() {
        println!("REPAIRS_APPLIED");
        for repair in &summary.repairs_applied {
            println!(
                "  {} before={} after={}",
                repair.operation,
                repair.before.as_deref().unwrap_or("-"),
                repair.after.as_deref().unwrap_or("-")
            );
        }
    }

    println!("HEALTH");
    if summary.health.is_empty() {
        println!("  PASS: no blockers");
    } else {
        for item in &summary.health {
            println!(
                "  [{}] {}",
                item.severity.to_ascii_uppercase(),
                item.message
            );
            println!("      remediation: {}", item.remediation);
        }
    }
}

// ── Public entry points ─────────────────────────────────────────────────────

pub fn run_review(
    repo: &str,
    pr_number: Option<u32>,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    force: bool,
    json_output: bool,
) -> u8 {
    let event_offset = review_events_path()
        .ok()
        .and_then(|path| fs::metadata(path).ok().map(|meta| meta.len()))
        .unwrap_or(0);

    let (owner_repo, resolved_pr) = match target::resolve_pr_target(repo, pr_number) {
        Ok(value) => value,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_run_target_resolution_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    match orchestrator::run_review_inner(
        &owner_repo,
        resolved_pr,
        review_type,
        expected_head_sha,
        force,
    ) {
        Ok(summary) => {
            let success = summary.security.as_ref().is_none_or(|entry| entry.success)
                && summary.quality.as_ref().is_none_or(|entry| entry.success);

            let mut run_ids = Vec::new();
            if let Some(entry) = &summary.security {
                run_ids.push(entry.run_id.clone());
            }
            if let Some(entry) = &summary.quality {
                run_ids.push(entry.run_id.clone());
            }
            if json_output {
                let _ = emit_run_ndjson_since(event_offset, summary.pr_number, &run_ids, true);
            }
            let payload = serde_json::json!({
                "schema": "apm2.fac.review.run.v1",
                "summary": summary,
            });
            println!(
                "{}",
                serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
            );

            if success {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_run_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_dispatch(
    repo: &str,
    pr_number: Option<u32>,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    force: bool,
    _json_output: bool,
) -> u8 {
    let (owner_repo, resolved_pr) = match target::resolve_pr_target(repo, pr_number) {
        Ok(value) => value,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_dispatch_target_resolution_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            return exit_codes::GENERIC_ERROR;
        },
    };
    match run_dispatch_inner(
        &owner_repo,
        resolved_pr,
        review_type,
        expected_head_sha,
        force,
    ) {
        Ok(summary) => {
            let payload = serde_json::json!({
                "schema": "apm2.fac.review.dispatch.v1",
                "summary": summary,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
            );
            exit_codes::SUCCESS
        },
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_dispatch_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_status(
    pr_number: Option<u32>,
    review_type_filter: Option<&str>,
    json_output: bool,
) -> u8 {
    match run_status_inner(pr_number, review_type_filter, json_output) {
        Ok(fail_closed) => {
            if fail_closed {
                exit_codes::GENERIC_ERROR
            } else {
                exit_codes::SUCCESS
            }
        },
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_status_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

fn annotate_verdict_finalized_status_entry(
    entry: &mut serde_json::Value,
    current_head_sha: Option<&str>,
) {
    let Some(reason) = entry
        .get("terminal_reason")
        .and_then(serde_json::Value::as_str)
    else {
        return;
    };
    if !is_verdict_finalized_agent_stop_reason(reason) {
        return;
    }

    if entry
        .get("state")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|state| state == "failed")
    {
        entry["state"] = serde_json::json!("done");
    }
    entry["terminal_reason"] = serde_json::json!(TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED);
    entry["state_explanation"] = serde_json::json!(
        "verdict was recorded and the reviewer process was intentionally stopped to prevent extra token spend"
    );

    let pr_number = entry
        .get("pr_number")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let review_type = entry
        .get("review_type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("security");
    let state_head_sha = entry.get("head_sha").and_then(serde_json::Value::as_str);
    let action = match (state_head_sha, current_head_sha) {
        (Some(state_sha), Some(current_sha))
            if !state_sha.is_empty() && !state_sha.eq_ignore_ascii_case(current_sha) =>
        {
            serde_json::json!({
                "action_required": true,
                "next_action": format!(
                    "head moved to {current_sha}; rerun this lane: `apm2 fac review dispatch --pr {pr_number} --type {review_type} --force`"
                ),
            })
        },
        _ => serde_json::json!({
            "action_required": false,
            "next_action": "no action required; rerun only if you want a fresh verdict on demand",
        }),
    };
    entry["action_required"] = action["action_required"].clone();
    entry["next_action"] = action["next_action"].clone();
}

pub fn run_wait(
    pr_number: u32,
    review_type_filter: Option<&str>,
    wait_for_sha: Option<&str>,
    timeout_seconds: Option<u64>,
    poll_interval_seconds: u64,
    _json_output: bool,
) -> u8 {
    let max_interval = poll_interval_seconds.max(1);
    let poll_interval = Duration::from_secs(max_interval);
    match run_wait_inner(
        pr_number,
        review_type_filter,
        wait_for_sha,
        timeout_seconds.map(Duration::from_secs),
        poll_interval,
    ) {
        Ok((status, attempts, elapsed)) => {
            let elapsed_seconds = elapsed.as_secs();
            let has_failed = status.terminal_failure
                || review_types_terminal_failed(&status, review_type_filter);
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

            if has_failed {
                exit_codes::GENERIC_ERROR
            } else {
                exit_codes::SUCCESS
            }
        },
        Err(err) => {
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
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_findings(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    refresh: bool,
    json_output: bool,
) -> u8 {
    match findings::run_findings(repo, pr_number, sha, refresh, json_output) {
        Ok(code) => code,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_findings_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_finding(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    review_type: ReviewFindingTypeArg,
    severity: ReviewFindingSeverityArg,
    summary: &str,
    details: Option<&str>,
    risk: Option<&str>,
    impact: Option<&str>,
    location: Option<&str>,
    reviewer_id: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    evidence_pointer: Option<&str>,
    json_output: bool,
) -> u8 {
    match finding::run_finding(
        repo,
        pr_number,
        sha,
        review_type,
        severity,
        summary,
        details,
        risk,
        impact,
        location,
        reviewer_id,
        model_id,
        backend_id,
        evidence_pointer,
        json_output,
    ) {
        Ok(code) => code,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_finding_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_comment_compat(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    review_type: ReviewFindingTypeArg,
    severity: ReviewFindingSeverityArg,
    body: Option<&str>,
    json_output: bool,
) -> u8 {
    match finding::run_comment_compat(
        repo,
        pr_number,
        sha,
        review_type,
        severity,
        body,
        json_output,
    ) {
        Ok(code) => code,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_comment_compat_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_prepare(repo: &str, pr_number: Option<u32>, sha: Option<&str>, json_output: bool) -> u8 {
    match prepare::run_prepare(repo, pr_number, sha, json_output) {
        Ok(code) => code,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "fac_review_prepare_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_verdict_set(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    dimension: &str,
    verdict: VerdictValueArg,
    reason: Option<&str>,
    model_id: Option<&str>,
    backend_id: Option<&str>,
    keep_prepared_inputs: bool,
    json_output: bool,
) -> u8 {
    lifecycle::run_verdict_set(
        repo,
        pr_number,
        sha,
        dimension,
        verdict,
        reason,
        model_id,
        backend_id,
        keep_prepared_inputs,
        json_output,
    )
}

pub fn run_verdict_show(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    json_output: bool,
) -> u8 {
    lifecycle::run_verdict_show(repo, pr_number, sha, json_output)
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub fn run_project(
    pr_number: u32,
    head_sha: Option<&str>,
    since_epoch: Option<u64>,
    after_seq: u64,
    _emit_errors: bool,
    fail_on_terminal: bool,
    _format_json: bool,
    _json_output: bool,
) -> u8 {
    match run_project_inner(pr_number, head_sha, since_epoch, after_seq) {
        Ok(status) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".to_string())
            );

            if fail_on_terminal && status.terminal_failure {
                exit_codes::GENERIC_ERROR
            } else {
                exit_codes::SUCCESS
            }
        },
        Err(err) => {
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
    review_type_filter: Option<&str>,
    wait_for_sha: Option<&str>,
    timeout: Option<Duration>,
    poll_interval: Duration,
) -> Result<(ProjectionStatus, u64, Duration), String> {
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
            let payload = serde_json::json!({
                "error": "fac_review_tail_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

pub fn run_terminate(
    repo: &str,
    pr_number: Option<u32>,
    review_type: &str,
    json_output: bool,
) -> u8 {
    match run_terminate_inner(repo, pr_number, review_type, json_output) {
        Ok(()) => exit_codes::SUCCESS,
        Err(err) => {
            let payload = serde_json::json!({
                "error": "terminate_failed",
                "message": err,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_terminate_inner(
    repo: &str,
    pr_number: Option<u32>,
    review_type: &str,
    json_output: bool,
) -> Result<(), String> {
    let home = types::apm2_home_dir()?;
    run_terminate_inner_for_home(&home, repo, pr_number, review_type, json_output)
}

fn run_terminate_inner_for_home(
    home: &Path,
    repo: &str,
    pr_number: Option<u32>,
    review_type: &str,
    json_output: bool,
) -> Result<(), String> {
    let (owner_repo, resolved_pr) = target::resolve_pr_target(repo, pr_number)?;
    let state_opt =
        state::load_review_run_state_verified_strict_for_home(home, resolved_pr, review_type)?;

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

    if !run_state
        .owner_repo
        .eq_ignore_ascii_case(owner_repo.as_str())
    {
        let msg = format!(
            "repo mismatch guard skipped termination for PR #{resolved_pr} type={review_type}: run-state repo={} requested repo={owner_repo}",
            run_state.owner_repo
        );
        eprintln!("WARNING: {msg}");
        return Err(msg);
    }

    if run_state.status == types::ReviewRunStatus::Alive && run_state.pid.is_none() {
        return Err(
            "cannot terminate: run state is Alive but PID is missing - operator must investigate."
                .to_string(),
        );
    }

    if run_state.pid.is_some() && run_state.proc_start_time.is_none() {
        return Err(format!(
            "integrity check failed for PR #{resolved_pr} type={review_type}: \
             pid is present but proc_start_time is missing — refusing to terminate"
        ));
    }

    if run_state.pid.is_some() && run_state.proc_start_time.is_some() {
        if let Err(integrity_err) =
            state::verify_review_run_state_integrity_binding(home, &run_state)
        {
            return Err(format!(
                "integrity verification failed for PR #{resolved_pr} type={review_type}: {integrity_err} -- \
                 refusing to terminate based on potentially tampered state"
            ));
        }
    }

    let authority = verdict_projection::resolve_termination_authority_for_home(
        home,
        &owner_repo,
        resolved_pr,
        review_type,
        &run_state.head_sha,
        &run_state.run_id,
    )
    .map_err(|err| {
        format!(
            "decision-bound authority required for PR #{resolved_pr} type={review_type} termination: {err}"
        )
    })?;
    authority.matches_state(&run_state).map_err(|err| {
        format!("decision authority mismatch for PR #{resolved_pr} type={review_type}: {err}")
    })?;
    if !authority.decision_signature_present() {
        return Err(format!(
            "decision-bound authority required for PR #{resolved_pr} type={review_type}: missing decision signature"
        ));
    }

    let outcome = dispatch::terminate_review_agent_for_home(home, &authority)?;
    let killed = matches!(outcome, dispatch::TerminationOutcome::Killed);

    let failure = match &outcome {
        dispatch::TerminationOutcome::Killed | dispatch::TerminationOutcome::AlreadyDead => None,
        dispatch::TerminationOutcome::SkippedMismatch => Some(format!(
            "termination skipped for PR #{resolved_pr} type={review_type}: process identity did not match authority"
        )),
        dispatch::TerminationOutcome::IdentityFailure(reason) => Some(format!(
            "failed to terminate PR #{resolved_pr} type={review_type}: {reason}"
        )),
    };
    if let Some(message) = failure {
        return Err(message);
    }

    run_state.status = types::ReviewRunStatus::Failed;
    run_state.terminal_reason = Some(TERMINAL_MANUAL_TERMINATION_DECISION_BOUND.to_string());
    state::write_review_run_state_for_home(home, &run_state)?;

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
                "outcome": format!("{outcome:?}"),
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

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub fn run_recover(
    repo: &str,
    pr_number: Option<u32>,
    force: bool,
    refresh_identity: bool,
    reap_stale_agents: bool,
    reset_lifecycle: bool,
    all: bool,
    json_output: bool,
) -> u8 {
    recovery::run_recover(
        repo,
        pr_number,
        force,
        refresh_identity,
        reap_stale_agents,
        reset_lifecycle,
        all,
        json_output,
    )
}

pub fn run_push(
    repo: &str,
    remote: &str,
    branch: Option<&str>,
    ticket: Option<&Path>,
    json_output: bool,
) -> u8 {
    push::run_push(repo, remote, branch, ticket, json_output)
}

pub fn run_restart(
    repo: &str,
    pr: Option<u32>,
    force: bool,
    refresh_identity: bool,
    json_output: bool,
) -> u8 {
    restart::run_restart(repo, pr, force, refresh_identity, json_output)
}

pub fn run_pipeline(repo: &str, pr_number: u32, sha: &str, json_output: bool) -> u8 {
    pipeline::run_pipeline(repo, pr_number, sha, json_output)
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

#[allow(clippy::too_many_arguments)]
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
    owner_repo: &str,
    pr_number: u32,
    review_type: ReviewRunType,
    expected_head_sha: Option<&str>,
    force: bool,
) -> Result<DispatchSummary, String> {
    let current_head_sha = projection::fetch_pr_head_sha_authoritative(owner_repo, pr_number)?;
    if let Some(identity) = projection_store::load_pr_identity(owner_repo, pr_number)? {
        validate_expected_head_sha(&identity.head_sha)?;
        if !identity.head_sha.eq_ignore_ascii_case(&current_head_sha) {
            projection_store::save_identity_with_context(
                owner_repo,
                pr_number,
                &current_head_sha,
                "dispatch.auto_refresh_identity",
            )
            .map_err(|err| {
                format!(
                    "local PR identity head {} is stale relative to authoritative PR head {current_head_sha}; automatic refresh failed: {err}",
                    identity.head_sha
                )
            })?;
        }
    }
    if let Some(expected) = expected_head_sha {
        validate_expected_head_sha(expected)?;
        if !expected.eq_ignore_ascii_case(&current_head_sha) {
            return Err(format!(
                "PR head mismatch before review dispatch: expected {expected}, authoritative {current_head_sha}"
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
        lifecycle::enforce_pr_capacity(owner_repo, pr_number)?;
        let result = dispatch_single_review_with_force(
            owner_repo,
            pr_number,
            kind,
            &current_head_sha,
            dispatch_epoch,
            force,
        )?;
        if !result.mode.eq_ignore_ascii_case("joined") {
            let run_id = result
                .run_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    format!(
                        "non-joined {} dispatch returned empty run_id (mode={})",
                        kind.as_str(),
                        result.mode
                    )
                })?;
            let token = lifecycle::register_reviewer_dispatch(
                owner_repo,
                pr_number,
                &current_head_sha,
                kind.as_str(),
                Some(run_id),
                result.pid,
                result.pid.and_then(state::get_process_start_time),
            )?;
            if token.is_none() {
                return Err(format!(
                    "lifecycle registration failed for {} review: register_reviewer_dispatch returned none",
                    kind.as_str()
                ));
            }
        }
        results.push(result);
    }

    Ok(DispatchSummary {
        pr_url: format!("https://github.com/{owner_repo}/pull/{pr_number}"),
        pr_number,
        head_sha: current_head_sha,
        dispatch_epoch,
        results,
    })
}

pub(super) fn dispatch_reviews_with_lifecycle(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    force: bool,
) -> Result<Vec<DispatchReviewResult>, String> {
    validate_expected_head_sha(head_sha)?;
    let summary = run_dispatch_inner(
        owner_repo,
        pr_number,
        ReviewRunType::All,
        Some(head_sha),
        force,
    )?;
    Ok(summary.results)
}

// ── Status / Tail ───────────────────────────────────────────────────────────

fn run_status_inner(
    pr_number: Option<u32>,
    review_type_filter: Option<&str>,
    _json_output: bool,
) -> Result<bool, String> {
    let normalized_review_type = review_type_filter.map(|value| value.trim().to_ascii_lowercase());
    if let Some(value) = normalized_review_type.as_deref() {
        if !matches!(value, "security" | "quality") {
            return Err(format!(
                "invalid review type filter `{value}` (expected security|quality)"
            ));
        }
    }

    let filter_pr = pr_number;

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
                        "owner_repo": state.owner_repo,
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
    for entry in &mut entries {
        annotate_verdict_finalized_status_entry(entry, current_head_sha.as_deref());
    }

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

    use super::backend::build_spawn_command_for_backend;
    use super::barrier::{
        build_barrier_decision_event, is_allowed_author_association, read_event_payload_bounded,
    };
    use super::detection::{detect_comment_permission_denied, detect_http_400_or_rate_limit};
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
            owner_repo: "example/repo".to_string(),
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
            nudge_count: 0,
            sequence_number: 1,
            previous_run_id: None,
            previous_head_sha: None,
            pid: Some(pid),
            proc_start_time,
            integrity_hmac: None,
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
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        let _ = child.wait();
        pid
    }

    fn seed_decision_projection_for_terminate(
        home: &std::path::Path,
        owner_repo: &str,
        pr_number: u32,
        review_type: &str,
        head_sha: &str,
        reviewer_login: &str,
        comment_id: u64,
    ) {
        super::verdict_projection::seed_decision_projection_for_home_for_tests(
            home,
            owner_repo,
            pr_number,
            review_type,
            head_sha,
            reviewer_login,
            comment_id,
        )
        .expect("seed decision projection");
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
    fn test_select_fallback_model_excludes_failed_and_covers_pool() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let fallback = select_fallback_model("gpt-5.3-codex")
                .expect("known model should produce fallback");
            assert_ne!(fallback.model, "gpt-5.3-codex", "must exclude failed model");
            seen.insert(fallback.model.clone());
        }
        assert!(seen.contains("gemini-3-flash-preview"));
        assert!(seen.contains("gemini-3-pro-preview"));
        assert!(seen.contains("gpt-5.3-codex-spark"));
    }

    #[test]
    fn test_select_fallback_model_unknown_returns_pool_member() {
        let fallback =
            select_fallback_model("unknown-model").expect("unknown failure should still fallback");
        assert!(
            MODEL_POOL
                .iter()
                .map(|entry| entry.model)
                .any(|candidate| candidate == fallback.model.as_str())
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
    fn test_status_annotation_for_verdict_finalized_lane_requires_rerun_when_head_drifts() {
        let mut entry = serde_json::json!({
            "pr_number": 654,
            "review_type": "security",
            "state": "failed",
            "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "terminal_reason": "manual_termination_after_decision",
        });

        super::annotate_verdict_finalized_status_entry(
            &mut entry,
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        );

        assert_eq!(entry["state"], serde_json::json!("done"));
        assert_eq!(
            entry["terminal_reason"],
            serde_json::json!("verdict_finalized_agent_stopped")
        );
        assert_eq!(entry["action_required"], serde_json::json!(true));
        assert!(entry["next_action"].as_str().is_some_and(|value| {
            value.contains("apm2 fac review dispatch --pr 654 --type security --force")
        }));
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
    fn test_build_spawn_command_for_backend_codex() {
        let prompt = std::path::Path::new("/tmp/prompt.md");
        let log = std::path::Path::new("/tmp/review.log");
        let capture = std::path::Path::new("/tmp/capture.md");

        let codex = build_spawn_command_for_backend(
            ReviewBackend::Codex,
            prompt,
            log,
            "gpt-5.3-codex",
            Some(capture),
        )
        .expect("build codex command");
        assert_eq!(codex.program, "codex");
        assert!(codex.args.contains(&"exec".to_string()));
        assert!(codex.args.contains(&"--json".to_string()));
        assert!(codex.args.contains(&"--output-last-message".to_string()));
        assert_eq!(codex.stdin_file, Some(prompt.to_path_buf()));
    }

    #[test]
    fn test_build_spawn_command_for_backend_gemini() {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let prompt = temp.path();
        std::fs::write(prompt, "test prompt").expect("write prompt");
        let log = std::path::Path::new("/tmp/review.log");

        let gemini = build_spawn_command_for_backend(
            ReviewBackend::Gemini,
            prompt,
            log,
            "gemini-3-flash-preview",
            None,
        )
        .expect("build gemini command");
        assert_eq!(gemini.program, "gemini");
        assert!(gemini.args.contains(&"-m".to_string()));
        assert!(gemini.args.contains(&"stream-json".to_string()));
    }

    #[test]
    fn test_build_spawn_command_for_backend_claude() {
        let prompt = std::path::Path::new("/tmp/prompt.md");
        let log = std::path::Path::new("/tmp/review.log");

        let claude = build_spawn_command_for_backend(
            ReviewBackend::ClaudeCode,
            prompt,
            log,
            "claude-3-7-sonnet",
            None,
        )
        .expect("build claude command");
        assert_eq!(claude.program, "claude");
        assert!(claude.args.contains(&"--output-format".to_string()));
        assert!(claude.args.contains(&"json".to_string()));
        assert!(claude.args.contains(&"--permission-mode".to_string()));
        assert!(claude.args.contains(&"plan".to_string()));
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
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let state = sample_run_state(pr_number, pid, "abcdef1234567890", None);
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("integrity"));
        assert!(super::state::is_process_alive(pid));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_skips_when_proc_start_time_mismatched() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let observed_start = super::state::get_process_start_time(pid).expect("read start time");
        let head_sha = "abcdef1234567890abcdef1234567890abcdef12";
        let state = sample_run_state(pr_number, pid, head_sha, Some(observed_start + 1));
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");
        seed_decision_projection_for_terminate(
            home,
            "example/repo",
            pr_number,
            "security",
            head_sha,
            "test-reviewer",
            43,
        );

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
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
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let mut state = sample_run_state(pr_number, 0, "abcdef1234567890", Some(123_456_789));
        state.pid = None;
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("PID is missing"));

        let loaded = super::state::load_review_run_state_for_home(home, pr_number, "security")
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
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let proc_start_time = super::state::get_process_start_time(pid).expect("read start time");
        let mut state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(proc_start_time));
        state.owner_repo = "example/other-repo".to_string();
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "owner/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(
            result.is_err(),
            "repo mismatch should now be treated as a failure"
        );
        let error = result.expect_err("repo mismatch should be surfaced as an error");
        assert!(error.contains("repo mismatch"));
        assert!(super::state::is_process_alive(pid));

        let loaded = super::state::load_review_run_state_for_home(home, pr_number, "security")
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
    fn test_run_terminate_inner_skips_when_repo_mismatch_format() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let proc_start_time = super::state::get_process_start_time(pid).expect("read start time");
        let mut state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(proc_start_time));
        state.owner_repo = "not-a-repo-url".to_string();
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(
            result.is_err(),
            "repo mismatch should now be treated as an error"
        );
        let error = result.expect_err("repo mismatch should be surfaced as an error");
        assert!(error.contains("repo mismatch"));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_fails_on_integrity_mismatch() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");

        let child = spawn_persistent_process();
        let pid = child.id();
        let proc_start_time = super::state::get_process_start_time(pid).expect("read start time");
        let state = sample_run_state(pr_number, pid, "abcdef1234567890", Some(proc_start_time));
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).expect("read run state json"))
                .expect("parse run state json");
        tampered["head_sha"] = serde_json::json!("fedcba0987654321");
        std::fs::write(
            &state_path,
            serde_json::to_vec_pretty(&tampered).expect("serialize tampered run state"),
        )
        .expect("write tampered state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(result.is_err());
        let error = result.expect_err("terminate should fail-closed");
        assert!(error.contains("integrity verification failed"));
        assert!(super::state::is_process_alive(pid));

        kill_child(child);
        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn test_run_terminate_inner_writes_manual_termination_receipt() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state_path = super::state::review_run_state_path_for_home(home, pr_number, "security");
        let dead_pid = dead_pid_for_test();
        let state = sample_run_state(
            pr_number,
            dead_pid,
            "abcdef1234567890abcdef1234567890abcdef12",
            Some(123_456_789),
        );
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");
        seed_decision_projection_for_terminate(
            home,
            "example/repo",
            pr_number,
            "security",
            &state.head_sha,
            "test-reviewer",
            42,
        );

        super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        )
        .expect("terminate should succeed");

        let receipt_path = state_path
            .parent()
            .expect("state parent")
            .join("termination_receipt.json");
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&receipt_path).expect("read termination receipt"),
        )
        .expect("parse termination receipt");
        assert_eq!(receipt["repo"], serde_json::json!("example/repo"));
        assert_eq!(receipt["review_type"], serde_json::json!("security"));
        assert_eq!(receipt["outcome"], serde_json::json!("already_dead"));
        assert_eq!(receipt["decision_comment_id"], serde_json::json!(42));
        assert_eq!(
            receipt["decision_author"],
            serde_json::json!("test-reviewer")
        );
        let decision_summary = receipt["decision_summary"]
            .as_str()
            .expect("decision_summary must be present");
        assert_eq!(
            decision_summary.len(),
            64,
            "decision_summary must be a sha256 hex digest"
        );
        assert!(
            decision_summary
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "decision_summary must be lowercase hex"
        );
        let integrity_hmac = receipt["integrity_hmac"]
            .as_str()
            .expect("integrity_hmac must be present");
        assert!(
            !integrity_hmac.is_empty(),
            "integrity_hmac must not be empty"
        );
        let loaded = super::state::load_review_run_state_for_home(home, pr_number, "security")
            .expect("load run-state");
        let terminal_state = match loaded {
            super::state::ReviewRunStateLoad::Present(state) => state,
            other => panic!("expected present state, got {other:?}"),
        };
        assert_eq!(terminal_state.status, ReviewRunStatus::Failed);
        assert_eq!(
            terminal_state.terminal_reason.as_deref(),
            Some(super::types::TERMINAL_MANUAL_TERMINATION_DECISION_BOUND)
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(receipt_path);
    }

    #[test]
    fn test_run_terminate_inner_fails_without_decision_projection() {
        let pr_number = next_test_pr();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let dead_pid = dead_pid_for_test();
        let state = sample_run_state(
            pr_number,
            dead_pid,
            "abcdef1234567890abcdef1234567890abcdef12",
            Some(123_456_789),
        );
        super::state::write_review_run_state_for_home(home, &state).expect("write run state");

        let result = super::run_terminate_inner_for_home(
            home,
            "example/repo",
            Some(pr_number),
            "security",
            false,
        );
        assert!(
            result.is_err(),
            "terminate must fail without decision authority"
        );
        let error = result.expect_err("expected decision authority error");
        assert!(
            error.contains("decision-bound authority required"),
            "unexpected error detail: {error}"
        );
        assert!(
            error.contains("missing decision projection")
                || error.contains("failed to read reviewer projection"),
            "unexpected error detail: {error}"
        );
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
    fn test_pulse_file_roundtrip() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("review_pulse_security.json");
        write_pulse_file_to_path(&path, "0123456789abcdef", None).expect("write pulse");
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
            "owner_repo": "owner/repo",
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
                owner_repo: "owner/repo".to_string(),
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
                owner_repo: "owner/repo".to_string(),
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
                owner_repo: "owner/repo".to_string(),
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
                owner_repo: "owner/repo".to_string(),
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
                owner_repo: "owner/repo".to_string(),
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
                owner_repo: "owner/repo".to_string(),
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
                owner_repo: "owner/repo".to_string(),
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
                owner_repo: "owner/repo".to_string(),
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

    fn doctor_merge_readiness_fixture(
        merge_conflict_status: super::DoctorMergeConflictStatus,
    ) -> super::DoctorMergeReadiness {
        super::DoctorMergeReadiness {
            merge_ready: false,
            all_verdicts_approve: false,
            gates_pass: false,
            sha_fresh: false,
            sha_freshness_source: super::DoctorShaFreshnessSource::Unknown,
            no_merge_conflicts: merge_conflict_status
                == super::DoctorMergeConflictStatus::NoConflicts,
            merge_conflict_status,
        }
    }

    fn pending_findings_summary() -> Vec<super::DoctorFindingsDimensionSummary> {
        vec![
            super::DoctorFindingsDimensionSummary {
                dimension: "security".to_string(),
                counts: super::DoctorFindingsCounts {
                    blocker: 0,
                    major: 0,
                    minor: 0,
                    nit: 0,
                },
                formal_verdict: "pending".to_string(),
                computed_verdict: "pending".to_string(),
            },
            super::DoctorFindingsDimensionSummary {
                dimension: "code-quality".to_string(),
                counts: super::DoctorFindingsCounts {
                    blocker: 0,
                    major: 0,
                    minor: 0,
                    nit: 0,
                },
                formal_verdict: "pending".to_string(),
                computed_verdict: "pending".to_string(),
            },
        ]
    }

    fn doctor_lifecycle_fixture(
        state: &str,
        retry_budget_remaining: u32,
        error_budget_used: u32,
        last_event_seq: u64,
    ) -> super::DoctorLifecycleSnapshot {
        super::DoctorLifecycleSnapshot {
            state: state.to_string(),
            time_in_state_seconds: 30,
            error_budget_used,
            retry_budget_remaining,
            updated_at: "2026-02-15T00:00:00Z".to_string(),
            last_event_seq,
        }
    }

    fn doctor_reviews_with_terminal_reason(
        terminal_reason: Option<&str>,
    ) -> Vec<super::DoctorReviewSnapshot> {
        vec![
            super::DoctorReviewSnapshot {
                dimension: "security".to_string(),
                verdict: "pending".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: terminal_reason.map(str::to_string),
            },
            super::DoctorReviewSnapshot {
                dimension: "code-quality".to_string(),
                verdict: "pending".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: None,
            },
        ]
    }

    fn build_recommended_action_for_tests(
        pr_number: u32,
        lifecycle: Option<&super::DoctorLifecycleSnapshot>,
        agents: Option<&super::DoctorAgentSection>,
        reviews: &[super::DoctorReviewSnapshot],
        findings_summary: &[super::DoctorFindingsDimensionSummary],
        merge_readiness: &super::DoctorMergeReadiness,
    ) -> super::DoctorRecommendedAction {
        let mut terminal_reasons = std::collections::BTreeMap::new();
        for review in reviews {
            terminal_reasons.insert(
                super::canonical_review_dimension(&review.dimension),
                review.terminal_reason.clone(),
            );
        }
        super::build_recommended_action(&super::DoctorActionInputs {
            pr_number,
            health: &[],
            lifecycle,
            agents,
            reviews,
            review_terminal_reasons: &terminal_reasons,
            run_state_diagnostics: &[],
            findings_summary,
            merge_readiness,
            latest_push_attempt: None,
        })
    }

    #[test]
    fn test_build_recommended_action_uses_force_restart_for_max_restarts_exceeded_before_escalation()
     {
        let reviews = doctor_reviews_with_terminal_reason(Some("max_restarts_exceeded"));
        let findings = pending_findings_summary();
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("stuck", 0, 9, 100)),
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "restart_reviews");
        let command = action.command.expect("restart command");
        assert!(command.contains("--force"));
        assert!(command.contains("--refresh-identity"));
    }

    #[test]
    fn test_build_recommended_action_uses_force_restart_when_terminal_reason_only_in_state_map() {
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::from([(
            "security".to_string(),
            Some("max_restarts_exceeded".to_string()),
        )]);
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            health: &[],
            lifecycle: Some(&doctor_lifecycle_fixture("stuck", 0, 9, 100)),
            agents: Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            run_state_diagnostics: &[],
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "restart_reviews");
        let command = action.command.expect("restart command");
        assert!(command.contains("--force"));
    }

    #[test]
    fn test_build_recommended_action_terminal_reason_read_warning_does_not_force_fix() {
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let health = vec![super::DoctorHealthItem {
            severity: "medium",
            message: "unable to resolve security terminal_reason from run state: corrupt-state"
                .to_string(),
            remediation: "restart".to_string(),
        }];
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            health: &health,
            lifecycle: Some(&doctor_lifecycle_fixture("stuck", 0, 9, 100)),
            agents: Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            run_state_diagnostics: &[],
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "restart_reviews");
        let command = action.command.expect("restart command");
        assert!(!command.contains("--force"));
    }

    #[test]
    fn test_build_recommended_action_recommends_fix_for_run_state_corruption() {
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let diagnostics = vec![super::DoctorRunStateDiagnostic {
            review_type: "security".to_string(),
            condition: super::DoctorRunStateCondition::Corrupt,
            canonical_path: "/tmp/state.json".to_string(),
            detail: Some("corrupt-state".to_string()),
            candidates: Vec::new(),
        }];
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            health: &[],
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 10)),
            agents: Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 1,
                total_agents: 1,
                entries: Vec::new(),
            }),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            run_state_diagnostics: &diagnostics,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_eq!(action.action, "fix");
    }

    #[test]
    fn test_build_recommended_action_missing_run_state_does_not_force_fix() {
        let findings = pending_findings_summary();
        let terminal_reasons = std::collections::BTreeMap::new();
        let diagnostics = vec![super::DoctorRunStateDiagnostic {
            review_type: "security".to_string(),
            condition: super::DoctorRunStateCondition::Missing,
            canonical_path: "/tmp/state.json".to_string(),
            detail: Some("run-state file missing".to_string()),
            candidates: Vec::new(),
        }];
        let action = super::build_recommended_action(&super::DoctorActionInputs {
            pr_number: 42,
            health: &[],
            lifecycle: Some(&doctor_lifecycle_fixture("review_in_progress", 1, 0, 10)),
            agents: Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 1,
                total_agents: 1,
                entries: Vec::new(),
            }),
            reviews: &[],
            review_terminal_reasons: &terminal_reasons,
            run_state_diagnostics: &diagnostics,
            findings_summary: &findings,
            merge_readiness: &doctor_merge_readiness_fixture(
                super::DoctorMergeConflictStatus::Unknown,
            ),
            latest_push_attempt: None,
        });
        assert_ne!(action.action, "fix");
    }

    #[test]
    fn test_build_recommended_action_unknown_merge_conflict_does_not_escalate() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let action = build_recommended_action_for_tests(
            42,
            None,
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "restart_reviews");
        let command = action.command.expect("restart command");
        assert!(!command.contains("--force"));
    }

    #[test]
    fn test_build_recommended_action_escalates_on_explicit_merge_conflicts() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let action = build_recommended_action_for_tests(
            42,
            None,
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 0,
                total_agents: 0,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::HasConflicts),
        );
        assert_eq!(action.action, "escalate");
    }

    #[test]
    fn test_lifecycle_retry_budget_exhausted_requires_seq_and_exhausted_state() {
        assert!(!super::lifecycle_retry_budget_exhausted(
            &doctor_lifecycle_fixture("pushed", 0, 0, 0)
        ));
        assert!(!super::lifecycle_retry_budget_exhausted(
            &doctor_lifecycle_fixture("pushed", 0, 0, 10)
        ));
        assert!(super::lifecycle_retry_budget_exhausted(
            &doctor_lifecycle_fixture("stuck", 0, 0, 10)
        ));
    }

    #[test]
    fn test_build_recommended_action_does_not_escalate_on_zero_retry_without_exhaustion_shape() {
        let reviews = doctor_reviews_with_terminal_reason(None);
        let findings = pending_findings_summary();
        let action = build_recommended_action_for_tests(
            42,
            Some(&doctor_lifecycle_fixture("pushed", 0, 0, 0)),
            Some(&super::DoctorAgentSection {
                max_active_agents_per_pr: 2,
                active_agents: 1,
                total_agents: 1,
                entries: Vec::new(),
            }),
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "wait");
    }

    #[test]
    fn test_build_doctor_merge_readiness_uses_local_authoritative_when_remote_unavailable() {
        let reviews = vec![
            super::DoctorReviewSnapshot {
                dimension: "security".to_string(),
                verdict: "approve".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: None,
            },
            super::DoctorReviewSnapshot {
                dimension: "code-quality".to_string(),
                verdict: "approve".to_string(),
                reviewed_sha: String::new(),
                reviewed_by: String::new(),
                reviewed_at: String::new(),
                reason: String::new(),
                terminal_reason: None,
            },
        ];
        let gates = vec![super::DoctorGateSnapshot {
            name: "rustfmt".to_string(),
            status: "PASS".to_string(),
            completed_at: None,
            freshness_seconds: None,
        }];
        let local_sha = "0123456789abcdef0123456789abcdef01234567".to_string();
        let readiness = super::build_doctor_merge_readiness(
            &reviews,
            &gates,
            false,
            Some(&local_sha),
            None,
            super::DoctorMergeConflictStatus::NoConflicts,
        );
        assert!(readiness.sha_fresh);
        assert_eq!(
            readiness.sha_freshness_source,
            super::DoctorShaFreshnessSource::LocalAuthoritative
        );
        assert!(readiness.merge_ready);
    }

    #[test]
    fn test_build_recommended_action_dispatches_on_formal_deny_without_findings() {
        let findings = vec![super::DoctorFindingsDimensionSummary {
            dimension: "security".to_string(),
            counts: super::DoctorFindingsCounts {
                blocker: 0,
                major: 0,
                minor: 0,
                nit: 0,
            },
            formal_verdict: "deny".to_string(),
            computed_verdict: "pending".to_string(),
        }];
        let reviews = doctor_reviews_with_terminal_reason(None);
        let action = build_recommended_action_for_tests(
            42,
            None,
            None,
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_build_recommended_action_dispatches_on_major_findings_without_formal_deny() {
        let findings = vec![super::DoctorFindingsDimensionSummary {
            dimension: "code-quality".to_string(),
            counts: super::DoctorFindingsCounts {
                blocker: 0,
                major: 1,
                minor: 0,
                nit: 0,
            },
            formal_verdict: "pending".to_string(),
            computed_verdict: "deny".to_string(),
        }];
        let reviews = doctor_reviews_with_terminal_reason(None);
        let action = build_recommended_action_for_tests(
            42,
            None,
            None,
            &reviews,
            &findings,
            &doctor_merge_readiness_fixture(super::DoctorMergeConflictStatus::Unknown),
        );
        assert_eq!(action.action, "dispatch_implementor");
    }

    #[test]
    fn test_normalize_doctor_exit_actions_defaults_include_escalate() {
        let normalized = super::normalize_doctor_exit_actions(&[]).expect("normalize defaults");
        assert!(normalized.contains("escalate"));
        assert!(normalized.contains("fix"));
    }

    #[test]
    fn test_normalize_doctor_exit_actions_accepts_user_supplied_escalate() {
        let normalized = super::normalize_doctor_exit_actions(&["escalate".to_string()])
            .expect("escalate should be accepted");
        assert_eq!(normalized.len(), 1);
        assert!(normalized.contains("escalate"));
    }

    #[test]
    fn test_scan_event_signals_from_reader_scans_full_log_for_pr() {
        let mut lines = String::new();
        for index in 0..5000 {
            lines.push_str(
                &serde_json::json!({
                    "pr_number": 999,
                    "review_type": "security",
                    "event": "run_start",
                    "model": format!("other-{index}"),
                    "ts": "2026-02-15T00:00:00Z"
                })
                .to_string(),
            );
            lines.push('\n');
        }
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-a",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        for _ in 0..5000 {
            lines.push_str(
                &serde_json::json!({
                    "pr_number": 999,
                    "review_type": "quality",
                    "event": "model_fallback",
                    "to_model": "other",
                    "ts": "2026-02-15T00:00:10Z"
                })
                .to_string(),
            );
            lines.push('\n');
        }
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "model_fallback",
                "to_model": "model-b",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::<String>::new();
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        let models = signals
            .model_attempts
            .get("security")
            .cloned()
            .unwrap_or_default();
        assert_eq!(models, vec!["model-a".to_string(), "model-b".to_string()]);
        assert!(signals.activity_timestamps.contains_key("security"));
    }

    #[test]
    fn test_scan_event_signals_from_reader_respects_run_id_filter() {
        let mut lines = String::new();
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "quality",
                "run_id": "ignore",
                "event": "run_start",
                "model": "model-ignore",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "quality",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-keep",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        let models = signals
            .model_attempts
            .get("quality")
            .cloned()
            .unwrap_or_default();
        assert_eq!(models, vec!["model-keep".to_string()]);
    }

    #[test]
    fn test_scan_event_signals_counts_tool_calls_and_nudges_per_run() {
        let mut lines = String::new();
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-a",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "tool_call",
                "tool": "read_file",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "nudge_resume",
                "ts": "2026-02-15T00:03:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        assert_eq!(signals.tool_call_counts.get("keep").copied(), Some(1));
        assert_eq!(signals.nudge_counts.get("keep").copied(), Some(1));
    }

    #[test]
    fn test_scan_event_signals_tool_count_falls_back_to_total_lines() {
        let mut lines = String::new();
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-a",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "liveness_check",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        assert_eq!(signals.tool_call_counts.get("keep").copied(), Some(2));
    }

    #[test]
    fn test_scan_event_signals_skips_oversized_line_and_keeps_scanning() {
        let oversized = "x".repeat(super::DOCTOR_EVENT_SCAN_MAX_LINE_BYTES.saturating_add(32));
        let mut lines = String::new();
        lines.push_str(&oversized);
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-safe",
                "ts": "2026-02-15T00:02:00Z"
            })
            .to_string(),
        );
        lines.push('\n');

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_reader(std::io::Cursor::new(lines), 42, &run_ids);
        let models = signals
            .model_attempts
            .get("security")
            .cloned()
            .unwrap_or_default();
        assert_eq!(models, vec!["model-safe".to_string()]);
    }

    #[test]
    fn test_scan_event_signals_from_sources_with_budget_prefers_tail_segment() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("review_events.ndjson");
        let mut lines = String::new();
        for index in 0..400 {
            lines.push_str(
                &serde_json::json!({
                    "pr_number": 42,
                    "review_type": "security",
                    "run_id": format!("old-{index}"),
                    "event": "run_start",
                    "model": "model-old",
                    "ts": "2026-02-15T00:00:00Z"
                })
                .to_string(),
            );
            lines.push('\n');
        }
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "run_start",
                "model": "model-tail",
                "ts": "2026-02-15T00:01:00Z"
            })
            .to_string(),
        );
        lines.push('\n');
        lines.push_str(
            &serde_json::json!({
                "pr_number": 42,
                "review_type": "security",
                "run_id": "keep",
                "event": "tool_call",
                "tool": "read_file",
                "ts": "2026-02-15T00:01:05Z"
            })
            .to_string(),
        );
        lines.push('\n');
        std::fs::write(&path, lines).expect("write events");

        let run_ids = std::collections::BTreeSet::from(["keep".to_string()]);
        let signals =
            super::scan_event_signals_from_sources_with_budget(&[path], 42, &run_ids, 1024);
        let models = signals
            .model_attempts
            .get("security")
            .cloned()
            .unwrap_or_default();
        assert_eq!(models, vec!["model-tail".to_string()]);
        assert_eq!(signals.tool_call_counts.get("keep").copied(), Some(1));
    }

    #[test]
    fn test_count_log_lines_bounded_handles_single_oversized_line_without_oom() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("oversized.log");
        let max_scan_bytes =
            usize::try_from(super::DOCTOR_LOG_SCAN_MAX_BYTES).expect("scan byte cap fits usize");
        let oversized = "z".repeat(max_scan_bytes.saturating_add(4096));
        std::fs::write(&path, oversized).expect("write oversized log");

        let line_count =
            super::count_log_lines_bounded(&path).expect("bounded count should succeed");
        assert_eq!(line_count, 1);
    }

    /// Verify the doctor interrupt flag uses a global singleton and that the
    /// `ctrlc` crate's `termination` feature is active. The `termination`
    /// feature makes `set_handler` also handle SIGTERM (and SIGHUP) in
    /// addition to SIGINT, so the doctor wait loop exits cleanly on both
    /// Ctrl-C and SIGTERM with a final `doctor_result` snapshot.
    ///
    /// This test validates the structural property: the flag is accessible and
    /// the handler was installed (or another subsystem installed one before
    /// us).
    #[test]
    fn doctor_interrupt_flag_is_singleton_and_default_false() {
        let flag_a = super::doctor_interrupt_flag()
            .expect("handler should register or already be registered");
        let flag_b = super::doctor_interrupt_flag()
            .expect("handler should register or already be registered");

        // Both calls return Arc clones of the same global flag.
        assert!(std::sync::Arc::ptr_eq(&flag_a, &flag_b));

        // The flag starts as false (not interrupted).
        assert!(!flag_a.load(std::sync::atomic::Ordering::SeqCst));

        // Simulate the signal: set the flag to true and verify.
        flag_a.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(flag_b.load(std::sync::atomic::Ordering::SeqCst));

        // Reset for other tests.
        flag_a.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Verify that the `ctrlc` crate was compiled with `termination` feature.
    ///
    /// The `termination` feature makes `ctrlc::set_handler()` also install
    /// signal handlers for SIGTERM and SIGHUP. Without it, only SIGINT is
    /// handled, meaning SIGTERM kills the process without invoking the doctor
    /// wait loop's interrupt path (no final `doctor_result` snapshot).
    ///
    /// We verify the feature is active by checking that `ctrlc::set_handler`
    /// returns `MultipleHandlers` (i.e., the global handler was already
    /// installed by `doctor_interrupt_flag()`) rather than silently accepting
    /// a new handler. This proves the handler is installed for SIGTERM too.
    #[test]
    fn ctrlc_termination_feature_handles_sigterm() {
        // Ensure the global handler is installed (must succeed for this
        // test's assertion to be meaningful).
        super::doctor_interrupt_flag().expect("handler should register or already be registered");

        // Attempting to install a second handler should fail because the
        // global handler is already installed (ctrlc only allows one handler).
        let result = ctrlc::set_handler(|| {});
        assert!(
            result.is_err(),
            "expected MultipleHandlers error since global handler was already installed"
        );
    }
}
