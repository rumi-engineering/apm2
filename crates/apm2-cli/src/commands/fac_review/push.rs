//! Lean `run_push` pipeline: blocking gates → ruleset sync → git push →
//! PR/update → dispatch.
//!
//! Bridge module: combines FAC core gate orchestration with projection-layer
//! PR management through `github_projection`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apm2_core::fac::service_user_gate::QueueWriteMode;
use apm2_core::fac::work_cas_schemas::{
    WORK_CONTEXT_ENTRY_V1_SCHEMA, WorkContextEntryV1, WorkContextKind,
};
use apm2_core::fac::{
    ChangeKind, ChangeSetBundleV1, FileChange, GitObjectRef, HashAlgo, parse_b3_256_digest,
    parse_policy_hash,
};
use apm2_daemon::protocol::{
    PublishChangeSetResponse, PublishWorkContextEntryResponse, RecordWorkPrAssociationResponse,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use super::dispatch::dispatch_single_review;
use super::evidence::{EvidenceGateResult, LANE_EVIDENCE_GATES};
use super::gate_cache::GateCache;
use super::gates::{
    GateThroughputProfile, QueuedGatesOutcome, QueuedGatesRequest, run_queued_gates_and_collect,
};
use super::github_reads::fetch_pr_base_sha;
use super::jsonl::{
    GateCompletedEvent, GateErrorEvent, StageEvent, emit_jsonl, read_log_error_hint, ts_now,
};
use super::projection::{GateResult, sync_gate_status_to_pr};
use super::types::{
    DispatchReviewResult, ReviewKind, apm2_home_dir, ensure_parent_dir, now_iso8601,
    sanitize_for_path,
};
use super::{github_projection, lifecycle, projection_store, state, verdict_projection};
use crate::client::protocol::{OperatorClient, ProtocolClientError};
use crate::commands::fac_pr::sync_required_status_ruleset;
use crate::commands::work_identity::{
    derive_adhoc_session_id, extract_tck_from_text, normalize_non_empty_arg,
    validate_lease_id as validate_push_lease_id, validate_session_id as validate_push_session_id,
    validate_work_id as validate_push_work_id,
};
use crate::exit_codes::codes as exit_codes;

const REQUIRED_TCK_FORMAT_MESSAGE: &str = "Required format: include `TCK-12345` in the branch name (recommended: `ticket/RFC-0018/TCK-12345`) or in the worktree directory name (example: `apm2-TCK-12345`).";
#[cfg(not(test))]
const RETRY_BACKOFF_BASE_MS: u64 = 250;
#[cfg(test)]
const RETRY_BACKOFF_BASE_MS: u64 = 0;
#[cfg(not(test))]
const RETRY_BACKOFF_MAX_MS: u64 = 2_000;
#[cfg(test)]
const RETRY_BACKOFF_MAX_MS: u64 = 0;
const PUSH_QUEUE_GATES_TIMEOUT_SECONDS: u64 = 600;
const PUSH_QUEUE_GATES_MEMORY_MAX: &str = "48G";
const PUSH_QUEUE_GATES_PIDS_MAX: u64 = 1536;
const PUSH_QUEUE_GATES_CPU_QUOTA: &str = "auto";
const PUSH_QUEUE_GATES_WAIT_TIMEOUT_SECS: u64 = 1200;
const PUSH_ATTEMPT_MALFORMED_WARN_LIMIT: usize = 3;
const PUSH_PROGRESS_TICK_SECS: u64 = 10;

/// Resolve TCK id from branch first, then worktree directory name.
fn resolve_tck_id(branch: &str, worktree_dir: &Path) -> Result<String, String> {
    if let Some(tck) = extract_tck_from_text(branch) {
        return Ok(tck);
    }

    let worktree_name = worktree_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if let Some(tck) = extract_tck_from_text(worktree_name) {
        return Ok(tck);
    }

    Err(format!(
        "could not derive TCK from branch `{branch}` or worktree `{}`. {REQUIRED_TCK_FORMAT_MESSAGE}",
        worktree_dir.display()
    ))
}

fn resolve_repo_root() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to resolve repository root: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to resolve repository root via git: {}",
            stderr.trim()
        ));
    }

    let repo_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if repo_root.is_empty() {
        return Err("git returned empty repository root".to_string());
    }

    Ok(PathBuf::from(repo_root))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitSummary {
    short_sha: String,
    message: String,
}

fn parse_commit_history(raw: &str) -> Vec<CommitSummary> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let (short_sha, message) = trimmed.split_once('\t')?;
            let short_sha = short_sha.trim();
            let message = message.trim();
            if short_sha.is_empty() || message.is_empty() {
                return None;
            }
            Some(CommitSummary {
                short_sha: short_sha.to_string(),
                message: message.to_string(),
            })
        })
        .collect()
}

fn resolve_commit_history_base_ref(remote: &str) -> Result<String, String> {
    let candidate = format!("{remote}/main");
    let candidate_commit = format!("{candidate}^{{commit}}");
    let remote_probe = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", &candidate_commit])
        .output()
        .map_err(|err| format!("failed to resolve commit history base ref: {err}"))?;
    if remote_probe.status.success() {
        return Ok(candidate);
    }

    let local_probe = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", "main^{commit}"])
        .output()
        .map_err(|err| format!("failed to resolve commit history base ref: {err}"))?;
    if local_probe.status.success() {
        return Ok("main".to_string());
    }

    Err(format!(
        "failed to resolve commit history base ref; neither `{remote}/main` nor `main` exists"
    ))
}

fn collect_commit_history(remote: &str, branch: &str) -> Result<Vec<CommitSummary>, String> {
    let base_ref = resolve_commit_history_base_ref(remote)?;
    let range = format!("{base_ref}..{branch}");
    let output = Command::new("git")
        .args(["log", "--format=%h%x09%s", "--reverse", &range])
        .output()
        .map_err(|err| format!("failed to collect commit history for `{range}`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to collect commit history for `{range}`: {}",
            stderr.trim()
        ));
    }

    let history = parse_commit_history(&String::from_utf8_lossy(&output.stdout));
    if !history.is_empty() {
        return Ok(history);
    }

    let head_output = Command::new("git")
        .args(["log", "-1", "--format=%h%x09%s", branch])
        .output()
        .map_err(|err| format!("failed to collect HEAD commit summary for `{branch}`: {err}"))?;
    if !head_output.status.success() {
        let stderr = String::from_utf8_lossy(&head_output.stderr);
        return Err(format!(
            "failed to collect HEAD commit summary for `{branch}`: {}",
            stderr.trim()
        ));
    }

    let fallback = parse_commit_history(&String::from_utf8_lossy(&head_output.stdout));
    if fallback.is_empty() {
        return Err(format!(
            "no commits found for branch `{branch}` while building PR description history"
        ));
    }
    Ok(fallback)
}

fn ticket_path_for_tck(repo_root: &Path, tck: &str) -> PathBuf {
    repo_root
        .join("documents")
        .join("work")
        .join("tickets")
        .join(format!("{tck}.yaml"))
}

fn load_ticket_body(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read ticket body at {}: {err}", path.display()))
}

fn load_ticket_title(path: &Path, body: &str) -> Result<String, String> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(body)
        .map_err(|err| format!("failed to parse ticket YAML at {}: {err}", path.display()))?;

    let Some(title) = parsed
        .get("ticket_meta")
        .and_then(|value| value.get("ticket"))
        .and_then(|value| value.get("title"))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(format!(
            "missing `ticket_meta.ticket.title` in {}",
            path.display()
        ));
    };

    Ok(title.to_string())
}

fn render_ticket_body_markdown(
    body: &str,
    commit_history: &[CommitSummary],
) -> Result<String, String> {
    let mut parsed: serde_yaml::Value = serde_yaml::from_str(body)
        .map_err(|err| format!("failed to parse ticket YAML for PR body rendering: {err}"))?;

    let history_entries = commit_history
        .iter()
        .map(|entry| {
            let mut item = serde_yaml::Mapping::new();
            item.insert(
                serde_yaml::Value::String("short_sha".to_string()),
                serde_yaml::Value::String(entry.short_sha.clone()),
            );
            item.insert(
                serde_yaml::Value::String("message".to_string()),
                serde_yaml::Value::String(entry.message.clone()),
            );
            serde_yaml::Value::Mapping(item)
        })
        .collect::<Vec<_>>();

    let root = parsed
        .as_mapping_mut()
        .ok_or_else(|| "ticket YAML root must be a mapping".to_string())?;
    let metadata_key = serde_yaml::Value::String("fac_push_metadata".to_string());
    let mut metadata_mapping = match root.remove(&metadata_key) {
        Some(serde_yaml::Value::Mapping(value)) => value,
        Some(_) | None => serde_yaml::Mapping::new(),
    };
    metadata_mapping.insert(
        serde_yaml::Value::String("commit_history".to_string()),
        serde_yaml::Value::Sequence(history_entries),
    );
    root.insert(metadata_key, serde_yaml::Value::Mapping(metadata_mapping));

    let mut rendered = serde_yaml::to_string(&parsed)
        .map_err(|err| format!("failed to render PR description YAML: {err}"))?;
    if let Some(stripped) = rendered.strip_prefix("---\n") {
        rendered = stripped.to_string();
    }
    let normalized = rendered.trim_end_matches('\n');
    Ok(format!("```yaml\n{normalized}\n```"))
}

fn validate_ticket_path_matches_tck(ticket_path: &Path, tck: &str) -> Result<(), String> {
    let Some(stem) = ticket_path.file_stem().and_then(|value| value.to_str()) else {
        return Err(format!(
            "invalid --ticket path `{}`; expected filename `{tck}.yaml`",
            ticket_path.display()
        ));
    };

    if stem != tck {
        return Err(format!(
            "--ticket path `{}` does not match derived TCK `{tck}`; expected filename `{tck}.yaml`",
            ticket_path.display()
        ));
    }

    Ok(())
}

#[derive(Debug)]
struct PrMetadata {
    title: String,
    body: String,
    ticket_path: PathBuf,
}

fn resolve_pr_metadata(
    branch: &str,
    worktree_dir: &Path,
    repo_root: &Path,
    commit_history: &[CommitSummary],
    ticket: Option<&Path>,
) -> Result<PrMetadata, String> {
    let tck_id = resolve_tck_id(branch, worktree_dir)?;
    if let Some(ticket_path) = ticket {
        validate_ticket_path_matches_tck(ticket_path, &tck_id)?;
    }

    let canonical_ticket_path = ticket_path_for_tck(repo_root, &tck_id);
    let raw_body = load_ticket_body(&canonical_ticket_path)?;
    let ticket_title = load_ticket_title(&canonical_ticket_path, &raw_body)?;
    let body = render_ticket_body_markdown(&raw_body, commit_history)?;
    Ok(PrMetadata {
        title: format!("{tck_id}: {ticket_title}"),
        body,
        ticket_path: canonical_ticket_path,
    })
}

// ── PR helpers ───────────────────────────────────────────────────────────────

/// Look up an existing PR number for the given branch, or return 0 if none.
fn find_existing_pr(repo: &str, branch: &str) -> u32 {
    match github_projection::find_pr_for_branch(repo, branch) {
        Ok(Some(number)) => number,
        _ => 0,
    }
}

/// Create a new PR and return the PR number on success.
fn create_pr(repo: &str, title: &str, body: &str) -> Result<u32, String> {
    github_projection::create_pr(repo, title, body)
}

/// Update an existing PR's title and body.
fn update_pr(repo: &str, pr_number: u32, title: &str, body: &str) -> Result<(), String> {
    github_projection::update_pr(repo, pr_number, title, body)
}

fn run_blocking_evidence_gates(
    sha: &str,
    work_id: Option<&str>,
    write_mode: QueueWriteMode,
) -> Result<QueuedGatesOutcome, String> {
    let request = QueuedGatesRequest {
        force: false,
        quick: false,
        timeout_seconds: PUSH_QUEUE_GATES_TIMEOUT_SECONDS,
        memory_max: PUSH_QUEUE_GATES_MEMORY_MAX.to_string(),
        pids_max: PUSH_QUEUE_GATES_PIDS_MAX,
        cpu_quota: PUSH_QUEUE_GATES_CPU_QUOTA.to_string(),
        gate_profile: GateThroughputProfile::Throughput,
        wait_timeout_secs: PUSH_QUEUE_GATES_WAIT_TIMEOUT_SECS,
        // Prefer worker execution when available, but do not hard-require it:
        // push must remain single-command operable for callers.
        require_external_worker: false,
        // TCK-00577: Use the caller-provided write mode. Default is
        // ServiceUserOnly; only bypass when --unsafe-local-write is
        // explicitly passed at the top-level FacCommand.
        write_mode,
        work_id_override: work_id.map(ToString::to_string),
    };
    let outcome = run_queued_gates_and_collect(&request)?;
    validate_queued_gates_outcome_for_push(sha, outcome)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrePushExecutionError {
    Gates(String),
    RulesetSync(String),
    GitPush(String),
}

fn run_pre_push_sequence_with<FGates, FSync, FPush>(
    mut run_gates_fn: FGates,
    mut sync_ruleset_fn: FSync,
    mut git_push_fn: FPush,
) -> Result<QueuedGatesOutcome, PrePushExecutionError>
where
    FGates: FnMut() -> Result<QueuedGatesOutcome, String>,
    FSync: FnMut() -> Result<(), String>,
    FPush: FnMut() -> Result<(), String>,
{
    let gate_outcome = run_gates_fn().map_err(PrePushExecutionError::Gates)?;
    sync_ruleset_fn().map_err(PrePushExecutionError::RulesetSync)?;
    git_push_fn().map_err(PrePushExecutionError::GitPush)?;
    Ok(gate_outcome)
}

fn apply_gate_lifecycle_events_with<F>(
    repo: &str,
    pr_number: u32,
    sha: &str,
    events: &[(&'static str, lifecycle::LifecycleEventKind)],
    mut apply_event_fn: F,
) -> Result<(), String>
where
    F: FnMut(lifecycle::LifecycleEventKind) -> Result<(), String>,
{
    // TCK-00618: gate lifecycle projection must fail closed. Any illegal
    // transition aborts the sequence and bubbles the error to caller.
    for (event_name, event) in events {
        apply_event_fn(event.clone()).map_err(|err| {
            format!(
                "failed to record {event_name} lifecycle event for PR #{pr_number} SHA {sha} repo {repo}: {err}"
            )
        })?;
    }
    Ok(())
}

fn apply_gate_failure_lifecycle_events_with<F>(
    repo: &str,
    pr_number: u32,
    sha: &str,
    apply_event_fn: F,
) -> Result<(), String>
where
    F: FnMut(lifecycle::LifecycleEventKind) -> Result<(), String>,
{
    apply_gate_lifecycle_events_with(
        repo,
        pr_number,
        sha,
        &[
            ("push_observed", lifecycle::LifecycleEventKind::PushObserved),
            ("gates_started", lifecycle::LifecycleEventKind::GatesStarted),
            ("gates_failed", lifecycle::LifecycleEventKind::GatesFailed),
        ],
        apply_event_fn,
    )
}

fn apply_gate_failure_lifecycle_events(
    repo: &str,
    pr_number: u32,
    sha: &str,
) -> Result<(), String> {
    apply_gate_failure_lifecycle_events_with(repo, pr_number, sha, |event| {
        lifecycle::apply_event(repo, pr_number, sha, &event).map(|_| ())
    })
}

fn apply_gate_success_lifecycle_events_with<F>(
    repo: &str,
    pr_number: u32,
    sha: &str,
    apply_event_fn: F,
) -> Result<(), String>
where
    F: FnMut(lifecycle::LifecycleEventKind) -> Result<(), String>,
{
    apply_gate_lifecycle_events_with(
        repo,
        pr_number,
        sha,
        &[
            ("push_observed", lifecycle::LifecycleEventKind::PushObserved),
            ("gates_started", lifecycle::LifecycleEventKind::GatesStarted),
            ("gates_passed", lifecycle::LifecycleEventKind::GatesPassed),
        ],
        apply_event_fn,
    )
}

fn apply_gate_success_lifecycle_events(
    repo: &str,
    pr_number: u32,
    sha: &str,
) -> Result<(), String> {
    apply_gate_success_lifecycle_events_with(repo, pr_number, sha, |event| {
        lifecycle::apply_event(repo, pr_number, sha, &event).map(|_| ())
    })
}

fn ensure_projection_success_for_push(successful_targets: &[&str]) -> Result<(), String> {
    let successful_count = successful_targets
        .iter()
        .filter(|target| !target.trim().is_empty())
        .count();
    if successful_count == 0 {
        return Err(
            "fac push requires at least one successful projection before lifecycle progression"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
fn run_blocking_evidence_gates_with<F>(
    sha: &str,
    mut run_queued_gates_fn: F,
) -> Result<QueuedGatesOutcome, String>
where
    F: FnMut() -> Result<QueuedGatesOutcome, String>,
{
    let outcome = run_queued_gates_fn()?;
    validate_queued_gates_outcome_for_push(sha, outcome)
}

fn validate_queued_gates_outcome_for_push(
    sha: &str,
    outcome: QueuedGatesOutcome,
) -> Result<QueuedGatesOutcome, String> {
    if outcome.job_id.trim().is_empty() {
        return Err("queued gates returned empty job_id".to_string());
    }
    if outcome.job_receipt_id.trim().is_empty() {
        return Err("queued gates returned empty job_receipt_id".to_string());
    }
    if outcome.policy_hash.trim().is_empty() {
        return Err("queued gates returned empty policy_hash".to_string());
    }
    if parse_policy_hash(outcome.policy_hash.trim()).is_none() {
        return Err(format!(
            "queued gates returned invalid policy_hash `{}`",
            outcome.policy_hash
        ));
    }
    if !outcome.head_sha.eq_ignore_ascii_case(sha) {
        return Err(format!(
            "queued gates completed for unexpected sha (requested={sha}, actual={})",
            outcome.head_sha
        ));
    }
    validate_gate_results_for_pass(sha, &outcome.gate_results)?;
    Ok(outcome)
}

fn expected_gate_names() -> BTreeSet<String> {
    LANE_EVIDENCE_GATES
        .iter()
        .map(|gate_name| (*gate_name).to_string())
        .collect()
}

fn validate_gate_results_for_pass(
    sha: &str,
    gate_results: &[EvidenceGateResult],
) -> Result<(), String> {
    if gate_results.is_empty() {
        return Err(format!(
            "queued gates completed for sha={sha} but no gate result artifacts were found; refusing to project empty gate status"
        ));
    }

    let failed_gates = gate_results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.gate_name.as_str())
        .collect::<Vec<_>>();
    if !failed_gates.is_empty() {
        return Err(format!(
            "queued gates completed for sha={sha} but reported gate rows include FAIL verdicts: {}; refusing inconsistent gate projection",
            failed_gates.join(",")
        ));
    }

    let actual = gate_results
        .iter()
        .map(|result| result.gate_name.clone())
        .collect::<BTreeSet<_>>();
    let expected = expected_gate_names();
    let missing = expected
        .difference(&actual)
        .cloned()
        .collect::<Vec<String>>();
    let extra = actual
        .difference(&expected)
        .cloned()
        .collect::<Vec<String>>();
    if !missing.is_empty() || !extra.is_empty() {
        let missing_summary = if missing.is_empty() {
            "-".to_string()
        } else {
            missing.join(",")
        };
        let extra_summary = if extra.is_empty() {
            "-".to_string()
        } else {
            extra.join(",")
        };
        return Err(format!(
            "evidence gate results for sha={sha} do not match required gate set (missing={missing_summary}, extra={extra_summary}); refusing gate projection"
        ));
    }

    let mut missing_bundle_hash = Vec::new();
    let mut invalid_bundle_hash = Vec::new();
    for gate in gate_results {
        match gate.log_bundle_hash.as_deref().map(str::trim) {
            Some(value) if !value.is_empty() => {
                if parse_b3_256_digest(value).is_none() {
                    invalid_bundle_hash.push(format!("{}={value}", gate.gate_name));
                }
            },
            _ => missing_bundle_hash.push(gate.gate_name.clone()),
        }
    }
    if !missing_bundle_hash.is_empty() || !invalid_bundle_hash.is_empty() {
        let missing_summary = if missing_bundle_hash.is_empty() {
            "-".to_string()
        } else {
            missing_bundle_hash.join(",")
        };
        let invalid_summary = if invalid_bundle_hash.is_empty() {
            "-".to_string()
        } else {
            invalid_bundle_hash.join(",")
        };
        return Err(format!(
            "queued gates completed for sha={sha} without fully attested log bundle hashes (missing={missing_summary}, invalid={invalid_summary}); refusing authoritative admission binding"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PushRetryClass {
    DispatchTransient,
    LifecycleRegistryTransient,
    LifecycleEventTransient,
    MissingRunIdTransient,
    IntegrityOrSchema,
}

impl PushRetryClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DispatchTransient => "dispatch_transient",
            Self::LifecycleRegistryTransient => "lifecycle_registry_transient",
            Self::LifecycleEventTransient => "lifecycle_event_transient",
            Self::MissingRunIdTransient => "missing_run_id_transient",
            Self::IntegrityOrSchema => "integrity_or_schema",
        }
    }

    const fn is_retryable(self) -> bool {
        !matches!(self, Self::IntegrityOrSchema)
    }
}

fn is_integrity_or_schema_error(lowercase_error: &str) -> bool {
    [
        "illegal transition",
        "unexpected lifecycle state schema",
        "unexpected agent registry schema",
        "failed to parse lifecycle state",
        "failed to parse agent registry",
        "lifecycle state identity mismatch",
        "identity mismatch",
        "invalid verdict",
        "invalid review type",
        "invalid expected head sha",
        "cannot register agent spawn with empty run_id",
        "reason=ambiguous_dispatch_ownership",
        "reason=stale_head_ambiguity",
        "corrupt-state",
        "ambiguous-state",
    ]
    .iter()
    .any(|needle| lowercase_error.contains(needle))
}

fn classify_dispatch_error(err: &str) -> PushRetryClass {
    let lower = err.to_ascii_lowercase();
    if is_integrity_or_schema_error(&lower) {
        return PushRetryClass::IntegrityOrSchema;
    }
    PushRetryClass::DispatchTransient
}

fn classify_registration_error(err: &str) -> PushRetryClass {
    let lower = err.to_ascii_lowercase();
    if is_integrity_or_schema_error(&lower) {
        return PushRetryClass::IntegrityOrSchema;
    }
    if lower.contains("at_capacity") {
        return PushRetryClass::IntegrityOrSchema;
    }
    if lower.contains("registry")
        || lower.contains("failed to open registry lock")
        || lower.contains("failed to acquire registry lock")
    {
        return PushRetryClass::LifecycleRegistryTransient;
    }
    PushRetryClass::LifecycleEventTransient
}

fn retry_backoff_delay(attempt: u32) -> Duration {
    if RETRY_BACKOFF_MAX_MS == 0 {
        return Duration::from_millis(0);
    }
    let exponent = attempt.saturating_sub(1).min(8);
    let scale = 1u64 << exponent;
    let backoff_ms = RETRY_BACKOFF_BASE_MS.saturating_mul(scale);
    let clamped_ms = if backoff_ms > RETRY_BACKOFF_MAX_MS {
        RETRY_BACKOFF_MAX_MS
    } else {
        backoff_ms
    };
    Duration::from_millis(clamped_ms)
}

fn next_retry_attempt(
    retry_counts: &mut BTreeMap<(String, PushRetryClass), u32>,
    review_type: &str,
    retry_class: PushRetryClass,
) -> u32 {
    let key = (review_type.to_string(), retry_class);
    let attempts = retry_counts.entry(key).or_insert(0);
    *attempts = attempts.saturating_add(1);
    *attempts
}

fn retry_delay_or_fail(
    retry_counts: &mut BTreeMap<(String, PushRetryClass), u32>,
    retry_budget: u32,
    review_type: &str,
    phase: &str,
    retry_class: PushRetryClass,
    err: &str,
    emit_logs: bool,
) -> Result<Duration, String> {
    if !retry_class.is_retryable() {
        return Err(format!(
            "{phase} failed for {review_type} review (class={}): {err}",
            retry_class.as_str()
        ));
    }

    let attempt = next_retry_attempt(retry_counts, review_type, retry_class);
    if attempt > retry_budget {
        return Err(format!(
            "{phase} failed for {review_type} review after exhausting retry budget (class={}, attempts={}, budget={}): {err}",
            retry_class.as_str(),
            attempt,
            retry_budget
        ));
    }

    let delay = retry_backoff_delay(attempt);
    if emit_logs {
        eprintln!(
            "WARNING: {phase} transient failure for {review_type} review (class={}, attempt {attempt}/{retry_budget}): {err}; retrying in {}ms",
            retry_class.as_str(),
            delay.as_millis()
        );
    }
    Ok(delay)
}

fn dispatch_run_state_is_terminal(run_state: &str) -> bool {
    let normalized = run_state.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "done" | "failed" | "crashed" | "completed" | "cancelled"
    )
}

fn dispatch_results_are_all_joined_terminal(results: &[DispatchReviewResult]) -> bool {
    !results.is_empty()
        && results.iter().all(|result| {
            result.mode.eq_ignore_ascii_case("joined")
                && dispatch_run_state_is_terminal(&result.run_state)
        })
}

fn projection_snapshot_is_terminal_approved(
    snapshot: &verdict_projection::VerdictProjectionSnapshot,
) -> bool {
    if snapshot.fail_closed {
        return false;
    }

    let security_approved = snapshot.dimensions.iter().any(|entry| {
        entry.dimension.eq_ignore_ascii_case("security")
            && entry.decision.eq_ignore_ascii_case("approve")
    });
    let quality_approved = snapshot.dimensions.iter().any(|entry| {
        entry.dimension.eq_ignore_ascii_case("code-quality")
            && entry.decision.eq_ignore_ascii_case("approve")
    });

    security_approved && quality_approved
}

fn should_force_projection_binding_repair(
    dispatch_results: &[DispatchReviewResult],
    projection_terminal_approved: bool,
    projection_has_remote_binding: bool,
) -> bool {
    dispatch_results_are_all_joined_terminal(dispatch_results)
        && projection_terminal_approved
        && !projection_has_remote_binding
}

fn maybe_force_projection_binding_repair(
    repo: &str,
    pr_number: u32,
    sha: &str,
    dispatch_results: &[DispatchReviewResult],
    json_output: bool,
    emit_logs: bool,
) -> Result<bool, String> {
    let Some(snapshot) =
        verdict_projection::load_verdict_projection_snapshot(repo, pr_number, sha)?
    else {
        return Ok(false);
    };

    let projection_terminal_approved = projection_snapshot_is_terminal_approved(&snapshot);
    let projection_has_remote_binding = verdict_projection::has_remote_comment_binding(
        snapshot.source_comment_id,
        snapshot.source_comment_url.as_deref(),
    );

    if !should_force_projection_binding_repair(
        dispatch_results,
        projection_terminal_approved,
        projection_has_remote_binding,
    ) {
        return Ok(false);
    }

    let repaired = super::dispatch_reviews_with_lifecycle(repo, pr_number, sha, true)?;
    if emit_logs {
        eprintln!(
            "fac push: projection remote comment binding missing for terminal-approved sha={sha}; \
             forced bounded reviewer redispatch (reviews={})",
            repaired.len()
        );
    }
    if json_output {
        let _ = emit_jsonl(&serde_json::json!({
            "event": "dispatch_projection_repair",
            "ts": ts_now(),
            "pr_number": pr_number,
            "sha": sha,
            "strategy": "force_same_sha_redispatch",
            "dispatched_reviews": repaired.len(),
        }));
    }
    Ok(true)
}

fn dispatch_reviews_with<F, R>(
    repo: &str,
    pr_number: u32,
    sha: &str,
    mut dispatch_fn: F,
    mut register_dispatch_fn: R,
    emit_logs: bool,
) -> Result<Vec<DispatchReviewResult>, String>
where
    F: FnMut(&str, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
    R: FnMut(
        &str,
        u32,
        &str,
        &str,
        Option<&str>,
        Option<u32>,
        Option<u64>,
    ) -> Result<Option<String>, String>,
{
    let dispatch_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let retry_budget = lifecycle::default_retry_budget();
    let mut retry_counts = BTreeMap::<(String, PushRetryClass), u32>::new();
    let mut dispatch_results = Vec::with_capacity(2);

    for kind in [ReviewKind::Security, ReviewKind::Quality] {
        let review_type = kind.as_str();

        let dispatch_result = loop {
            lifecycle::enforce_pr_capacity(repo, pr_number)?;
            let result = match dispatch_fn(repo, pr_number, kind, sha, dispatch_epoch) {
                Ok(result) => result,
                Err(err) => {
                    let retry_class = classify_dispatch_error(&err);
                    let delay = retry_delay_or_fail(
                        &mut retry_counts,
                        retry_budget,
                        review_type,
                        "dispatch",
                        retry_class,
                        &err,
                        emit_logs,
                    )?;
                    thread::sleep(delay);
                    continue;
                },
            };

            if emit_logs {
                eprintln!(
                    "fac push: dispatched {} review (mode={}{})",
                    result.review_type,
                    result.mode,
                    result
                        .pid
                        .map_or_else(String::new, |pid| format!(", pid={pid}")),
                );
            }

            if result.mode.eq_ignore_ascii_case("joined") {
                // BF-001 (TCK-00626): For non-terminal "joined" results,
                // verify the PID is still alive. A stale run-state with a
                // dead PID should be treated as a dispatch that needs retry.
                let is_terminal = dispatch_run_state_is_terminal(&result.run_state);
                let joined_run_id = result
                    .run_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                if !is_terminal && joined_run_id.is_none() {
                    let err = format!(
                        "{review_type} joined dispatch missing run_id in non-terminal state (run_state={})",
                        result.run_state
                    );
                    let delay = retry_delay_or_fail(
                        &mut retry_counts,
                        retry_budget,
                        review_type,
                        "dispatch_contract",
                        PushRetryClass::MissingRunIdTransient,
                        &err,
                        emit_logs,
                    )?;
                    thread::sleep(delay);
                    continue;
                }
                if !is_terminal {
                    if let Some(pid) = result.pid {
                        // BF-001 (TCK-00626 round 3): Use process-identity
                        // aware liveness check that compares the recorded
                        // proc_start_time against the current value in
                        // /proc/<pid>/stat. This prevents PID-reuse false
                        // positives. If proc_start_time was never recorded
                        // (legacy path), fail closed (treat as dead).
                        // On non-Linux, always returns false (fail-closed).
                        let alive = is_pid_alive_with_identity(pid, result.proc_start_time);
                        if !alive {
                            if emit_logs {
                                eprintln!(
                                    "fac push: {review_type} dispatch returned 'joined' with dead PID {pid}; \
                                     retrying dispatch",
                                );
                            }
                            let err = format!(
                                "{review_type} joined dispatch has dead PID {pid} (run_state={})",
                                result.run_state
                            );
                            let delay = retry_delay_or_fail(
                                &mut retry_counts,
                                retry_budget,
                                review_type,
                                "dispatch_dead_pid",
                                PushRetryClass::DispatchTransient,
                                &err,
                                emit_logs,
                            )?;
                            thread::sleep(delay);
                            continue;
                        }
                    } else {
                        // BF-001 (TCK-00626 round 4): Non-terminal joined
                        // with no PID — assume unit-based supervision is
                        // keeping the dispatch alive. In the systemd detached
                        // path, dispatches are created with unit-based
                        // supervision and no PID recorded, so pid=None is the
                        // normal steady-state for healthy unit-supervised
                        // reviews. Treating these as dead would cause
                        // spurious retry loops and duplicate dispatches.
                        // Only apply PID identity checks when a PID IS
                        // present (the branch above).
                        if emit_logs {
                            eprintln!(
                                "fac push: {review_type} dispatch returned 'joined' with no PID in non-terminal \
                                 state '{}'; assuming unit-supervised liveness",
                                result.run_state,
                            );
                        }
                    }
                }
                break result;
            }

            let missing_run_id = result
                .run_id
                .as_deref()
                .is_none_or(|run_id| run_id.trim().is_empty());
            if missing_run_id {
                let err = format!(
                    "non-joined {review_type} dispatch returned empty run_id (mode={})",
                    result.mode
                );
                let delay = retry_delay_or_fail(
                    &mut retry_counts,
                    retry_budget,
                    review_type,
                    "dispatch_contract",
                    PushRetryClass::MissingRunIdTransient,
                    &err,
                    emit_logs,
                )?;
                thread::sleep(delay);
                continue;
            }

            break result;
        };

        if dispatch_result.mode.eq_ignore_ascii_case("joined") {
            dispatch_results.push(dispatch_result);
            continue;
        }

        let run_id = dispatch_result
            .run_id
            .as_deref()
            .ok_or_else(|| format!("internal error: missing run_id for {review_type} dispatch"))?;
        loop {
            match register_dispatch_fn(
                repo,
                pr_number,
                sha,
                review_type,
                Some(run_id),
                dispatch_result.pid,
                dispatch_result.pid.and_then(state::get_process_start_time),
            ) {
                Ok(Some(_)) => {
                    if emit_logs {
                        eprintln!(
                            "fac push: registered {review_type} reviewer slot for PR #{pr_number} sha {sha}",
                        );
                    }
                    break;
                },
                Ok(None) => {
                    return Err(format!(
                        "lifecycle registration failed for {review_type} review: register_reviewer_dispatch returned none"
                    ));
                },
                Err(err) => {
                    let retry_class = classify_registration_error(&err);
                    let delay = retry_delay_or_fail(
                        &mut retry_counts,
                        retry_budget,
                        review_type,
                        "lifecycle_registration",
                        retry_class,
                        &err,
                        emit_logs,
                    )?;
                    thread::sleep(delay);
                },
            }
        }
        dispatch_results.push(dispatch_result);
    }

    Ok(dispatch_results)
}

// ── run_push entry point ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct PushSummary {
    schema: String,
    status: String,
    repo: String,
    remote: String,
    branch: String,
    pr_number: u32,
    head_sha: String,
    identity_persisted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    dispatch_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

const PUSH_ATTEMPT_SCHEMA: &str = "apm2.fac.push_attempt.v1";
const PUSH_STAGE_PASS: &str = "pass";
const PUSH_STAGE_FAIL: &str = "fail";
const PUSH_STAGE_SKIPPED: &str = "skipped";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PushAttemptStage {
    pub status: String,
    pub duration_s: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PushAttemptRecord {
    #[serde(default = "default_push_attempt_schema")]
    pub schema: String,
    pub ts: String,
    pub sha: String,
    #[serde(default)]
    pub ruleset_sync: PushAttemptStage,
    #[serde(default)]
    pub git_push: PushAttemptStage,
    #[serde(default)]
    pub gate_fmt: PushAttemptStage,
    #[serde(default)]
    pub gate_clippy: PushAttemptStage,
    #[serde(default)]
    pub gate_test: PushAttemptStage,
    #[serde(default)]
    pub gate_doc: PushAttemptStage,
    #[serde(default)]
    pub pr_update: PushAttemptStage,
    #[serde(default)]
    pub dispatch: PushAttemptStage,
}

#[derive(Debug, Clone)]
pub(super) struct PushAttemptFailedStage {
    pub stage: String,
    pub duration_s: u64,
    pub exit_code: Option<i32>,
    pub error_hint: Option<String>,
}

impl PushAttemptRecord {
    fn new(sha: &str) -> Self {
        Self {
            schema: PUSH_ATTEMPT_SCHEMA.to_string(),
            ts: now_iso8601(),
            sha: sha.to_ascii_lowercase(),
            ruleset_sync: skipped_stage(),
            git_push: skipped_stage(),
            gate_fmt: skipped_stage(),
            gate_clippy: skipped_stage(),
            gate_test: skipped_stage(),
            gate_doc: skipped_stage(),
            pr_update: skipped_stage(),
            dispatch: skipped_stage(),
        }
    }

    fn stage_mut(&mut self, stage: &str) -> Option<&mut PushAttemptStage> {
        match stage {
            "ruleset_sync" => Some(&mut self.ruleset_sync),
            "git_push" => Some(&mut self.git_push),
            "gate_fmt" => Some(&mut self.gate_fmt),
            "gate_clippy" => Some(&mut self.gate_clippy),
            "gate_test" => Some(&mut self.gate_test),
            "gate_doc" => Some(&mut self.gate_doc),
            "pr_update" => Some(&mut self.pr_update),
            "dispatch" => Some(&mut self.dispatch),
            _ => None,
        }
    }

    fn set_stage_pass(&mut self, stage: &str, duration_s: u64) {
        if let Some(slot) = self.stage_mut(stage) {
            *slot = PushAttemptStage {
                status: PUSH_STAGE_PASS.to_string(),
                duration_s,
                exit_code: None,
                error_hint: None,
            };
        }
    }

    fn set_stage_fail(
        &mut self,
        stage: &str,
        duration_s: u64,
        exit_code: Option<i32>,
        error_hint: Option<String>,
    ) {
        if let Some(slot) = self.stage_mut(stage) {
            *slot = PushAttemptStage {
                status: PUSH_STAGE_FAIL.to_string(),
                duration_s,
                exit_code,
                error_hint,
            };
        }
    }

    pub(super) fn first_failed_stage(&self) -> Option<PushAttemptFailedStage> {
        for (stage, details) in [
            ("gate_fmt", &self.gate_fmt),
            ("gate_clippy", &self.gate_clippy),
            ("gate_test", &self.gate_test),
            ("gate_doc", &self.gate_doc),
            ("ruleset_sync", &self.ruleset_sync),
            ("git_push", &self.git_push),
            ("pr_update", &self.pr_update),
            ("dispatch", &self.dispatch),
        ] {
            if details.status == PUSH_STAGE_FAIL {
                return Some(PushAttemptFailedStage {
                    stage: stage.to_string(),
                    duration_s: details.duration_s,
                    exit_code: details.exit_code,
                    error_hint: details.error_hint.clone(),
                });
            }
        }
        None
    }
}

impl Default for PushAttemptStage {
    fn default() -> Self {
        skipped_stage()
    }
}

fn default_push_attempt_schema() -> String {
    PUSH_ATTEMPT_SCHEMA.to_string()
}

fn skipped_stage() -> PushAttemptStage {
    PushAttemptStage {
        status: PUSH_STAGE_SKIPPED.to_string(),
        duration_s: 0,
        exit_code: None,
        error_hint: None,
    }
}

fn mark_ruleset_sync_stage_if_succeeded(
    attempt: &mut PushAttemptRecord,
    ruleset_sync_executed: bool,
    ruleset_sync_passed: bool,
    ruleset_sync_duration_secs: u64,
) {
    if ruleset_sync_executed && ruleset_sync_passed {
        attempt.set_stage_pass("ruleset_sync", ruleset_sync_duration_secs);
    }
}

fn push_attempts_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?
        .join("fac_projection")
        .join("repos")
        .join(sanitize_for_path(owner_repo))
        .join("push_attempts")
        .join(format!("{pr_number}.ndjson")))
}

fn push_attempts_lock_path(owner_repo: &str, pr_number: u32) -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?
        .join("fac_projection")
        .join("repos")
        .join(sanitize_for_path(owner_repo))
        .join("push_attempts")
        .join(format!("{pr_number}.lock")))
}

fn append_push_attempt_record(
    owner_repo: &str,
    pr_number: u32,
    record: &PushAttemptRecord,
) -> Result<(), String> {
    let path = push_attempts_path(owner_repo, pr_number)?;
    let lock_path = push_attempts_lock_path(owner_repo, pr_number)?;
    ensure_parent_dir(&path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open push attempt lock {}: {err}",
                lock_path.display()
            )
        })?;
    lock_file.lock_exclusive().map_err(|err| {
        format!(
            "failed to lock push attempt log {}: {err}",
            lock_path.display()
        )
    })?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| format!("failed to open push attempt log {}: {err}", path.display()))?;
    let line = serde_json::to_string(record)
        .map_err(|err| format!("failed to serialize push attempt record: {err}"))?;
    file.write_all(line.as_bytes()).map_err(|err| {
        format!(
            "failed to write push attempt record {}: {err}",
            path.display()
        )
    })?;
    file.write_all(b"\n").map_err(|err| {
        format!(
            "failed to write push attempt newline {}: {err}",
            path.display()
        )
    })?;
    file.flush().map_err(|err| {
        format!(
            "failed to flush push attempt record {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

pub(super) fn load_latest_push_attempt_for_sha(
    owner_repo: &str,
    pr_number: u32,
    sha: &str,
) -> Result<Option<PushAttemptRecord>, String> {
    let path = push_attempts_path(owner_repo, pr_number)?;
    let lock_path = push_attempts_lock_path(owner_repo, pr_number)?;
    if !path.exists() {
        return Ok(None);
    }
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open push attempt lock {}: {err}",
                lock_path.display()
            )
        })?;
    FileExt::lock_shared(&lock_file).map_err(|err| {
        format!(
            "failed to lock push attempt log {}: {err}",
            lock_path.display()
        )
    })?;
    let file = std::fs::File::open(&path)
        .map_err(|err| format!("failed to open push attempt log {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut latest = None;
    let mut malformed_lines = 0_usize;
    let mut warned_examples = 0_usize;
    for (line_number, line) in reader.lines().enumerate() {
        let line = line.map_err(|err| {
            format!(
                "failed to read line from push attempt log {}: {err}",
                path.display()
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record = match serde_json::from_str::<PushAttemptRecord>(&line) {
            Ok(record) => record,
            Err(err) => {
                malformed_lines += 1;
                if warned_examples < PUSH_ATTEMPT_MALFORMED_WARN_LIMIT {
                    warned_examples += 1;
                    eprintln!(
                        "WARN: skipping malformed push attempt line {} in {}: {}",
                        line_number + 1,
                        path.display(),
                        err
                    );
                }
                continue;
            },
        };
        if !record.sha.eq_ignore_ascii_case(sha) {
            continue;
        }
        latest = Some(record);
    }
    if malformed_lines > warned_examples {
        eprintln!(
            "WARN: skipped {} additional malformed push attempt line(s) in {}",
            malformed_lines - warned_examples,
            path.display()
        );
    }
    Ok(latest)
}

fn stage_from_gate_name(gate_name: &str) -> &'static str {
    match gate_name {
        "rustfmt" => "gate_fmt",
        "clippy" => "gate_clippy",
        "doc" => "gate_doc",
        // Collapse all non-fmt/clippy/doc gates into test stage in the fixed
        // push-attempt schema.
        _ => "gate_test",
    }
}

fn normalize_error_hint(value: &str) -> Option<String> {
    super::jsonl::normalize_error_hint(value)
}

fn parse_failed_gates_from_error(error: &str) -> Vec<String> {
    let marker = "failed_gates=";
    let Some(start) = error.find(marker) else {
        return Vec::new();
    };
    let rest = &error[start + marker.len()..];
    let raw_segment = rest.split(';').next().unwrap_or(rest).trim();
    if raw_segment.is_empty() {
        return Vec::new();
    }
    raw_segment
        .split(',')
        .map(str::trim)
        .filter(|gate| !gate.is_empty())
        .map(str::to_string)
        .collect()
}

fn lane_evidence_log_dirs(home: &Path) -> Vec<PathBuf> {
    let lanes_dir = home.join("private/fac/lanes");
    let mut logs = Vec::new();
    let Ok(lanes) = fs::read_dir(&lanes_dir) else {
        return logs;
    };

    for lane_dir_entry in lanes.filter_map(Result::ok) {
        let lane_dir_path = lane_dir_entry.path();
        if !lane_dir_path
            .metadata()
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            continue;
        }

        let jobs_dir = lane_dir_path.join("logs");
        let Ok(jobs) = fs::read_dir(&jobs_dir) else {
            continue;
        };

        let mut latest_job: Option<(PathBuf, SystemTime)> = None;
        for job_dir_entry in jobs.filter_map(Result::ok) {
            let job_dir_path = job_dir_entry.path();
            let is_dir = job_dir_entry.file_type().map_or_else(
                |_| {
                    job_dir_path
                        .metadata()
                        .map(|meta| meta.is_dir())
                        .unwrap_or(false)
                },
                |ft| ft.is_dir(),
            );
            if !is_dir {
                continue;
            }

            let modified = job_dir_path
                .metadata()
                .and_then(|meta| meta.modified())
                .unwrap_or(UNIX_EPOCH);
            match &latest_job {
                Some((_, current)) if *current >= modified => {},
                _ => latest_job = Some((job_dir_path, modified)),
            }
        }

        if let Some((latest_job_dir, _)) = latest_job {
            for gate_name in LANE_EVIDENCE_GATES {
                logs.push(latest_job_dir.join(format!("{gate_name}.log")));
            }
        }
    }

    logs.sort();
    logs
}

fn find_latest_evidence_gate_log(home: &Path, gate_name: &str) -> Option<PathBuf> {
    let expected_name = format!("{gate_name}.log");
    let mut latest: Option<(PathBuf, SystemTime)> = None;
    for path in lane_evidence_log_dirs(home) {
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            continue;
        }
        if !path.exists() {
            continue;
        }
        let modified = path
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(UNIX_EPOCH);
        if latest
            .as_ref()
            .is_none_or(|(_, current)| modified > *current)
        {
            latest = Some((path, modified));
        }
    }
    latest.map(|(path, _)| path)
}

fn gate_log_path(gate_name: &str) -> Result<PathBuf, String> {
    let home = apm2_home_dir()?;
    find_latest_evidence_gate_log(&home, gate_name).ok_or_else(|| {
        format!("no evidence gate log found for gate {gate_name} in any lane job directory")
    })
}

fn latest_gate_error_hint(gate_name: &str) -> Option<String> {
    let path = gate_log_path(gate_name).ok()?;
    read_log_error_hint(&path)
}

/// Resolve a failure hint from the per-gate evidence result's exact log path,
/// falling back to global lane/job discovery only when the result carries no
/// usable `log_path`.  This prevents concurrent runs from selecting another
/// job's log file.
fn gate_error_hint_from_result(result: &EvidenceGateResult) -> Option<String> {
    if let Some(ref log_path) = result.log_path {
        if let Some(hint) = read_log_error_hint(log_path) {
            return Some(hint);
        }
    }
    // Fallback: global discovery across all lane/job directories.
    latest_gate_error_hint(&result.gate_name)
}

struct PushPhaseProgressTicker {
    stop_tx: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl PushPhaseProgressTicker {
    fn start(phase: &'static str, json_output: bool) -> Self {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let phase_name = phase.to_string();
        let handle = thread::spawn(move || {
            let started = Instant::now();
            let mut tick = 0_u64;
            loop {
                match stop_rx.recv_timeout(Duration::from_secs(PUSH_PROGRESS_TICK_SECS)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        tick = tick.saturating_add(1);
                        let elapsed_seconds = started.elapsed().as_secs();
                        if json_output {
                            let _ = emit_jsonl(&StageEvent {
                                event: "push_progress".to_string(),
                                ts: ts_now(),
                                extra: serde_json::json!({
                                    "phase": phase_name.as_str(),
                                    "tick": tick,
                                    "elapsed_seconds": elapsed_seconds,
                                    "interval_seconds": PUSH_PROGRESS_TICK_SECS,
                                }),
                            });
                        } else {
                            eprintln!(
                                "fac push: still running phase={phase_name} elapsed={elapsed_seconds}s"
                            );
                        }
                    },
                }
            }
        });
        Self {
            stop_tx: Some(stop_tx),
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for PushPhaseProgressTicker {
    fn drop(&mut self) {
        self.stop();
    }
}

fn parse_handoff_note(handoff_note_arg: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = handoff_note_arg else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("`--handoff-note` cannot be empty when provided".to_string());
    }
    Ok(Some(trimmed.to_string()))
}

fn with_operator_client<T>(
    f: impl std::future::Future<Output = Result<T, ProtocolClientError>>,
) -> Result<T, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build tokio runtime: {err}"))?;
    rt.block_on(f).map_err(|err| err.to_string())
}

fn resolve_ticket_alias_to_work_id(
    ticket_alias: &str,
    operator_socket: &Path,
) -> Result<Option<String>, String> {
    let ticket_alias_for_rpc = ticket_alias.to_string();
    let resolved = with_operator_client(async move {
        let mut client = OperatorClient::connect(operator_socket).await?;
        client.resolve_ticket_alias(&ticket_alias_for_rpc).await
    })?;
    if !resolved.found {
        return Ok(None);
    }
    validate_push_work_id(&resolved.work_id)?;
    Ok(Some(resolved.work_id))
}

fn is_active_push_fallback_status(status: &str) -> bool {
    match status.trim().to_ascii_uppercase().as_str() {
        // Current canonical work states surfaced by daemon work projection,
        // plus legacy/in-flight aliases preserved during migration windows.
        "CLAIMED" | "IN_PROGRESS" | "INPROGRESS" | "SPAWNED" | "RUNNING" => true,
        _ => false,
    }
}

fn matches_push_fallback_candidate(
    work_item: &apm2_daemon::protocol::WorkStatusResponse,
    lease_filter: Option<&str>,
    session_filter: Option<&str>,
) -> bool {
    if !is_active_push_fallback_status(&work_item.status) {
        return false;
    }

    let Some(role_raw) = work_item.role else {
        return false;
    };
    let role = apm2_daemon::protocol::WorkRole::try_from(role_raw);
    if role != Ok(apm2_daemon::protocol::WorkRole::Implementer) {
        return false;
    }

    if let Some(expected_lease_id) = lease_filter {
        let observed_lease_id = work_item
            .lease_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if observed_lease_id != Some(expected_lease_id) {
            return false;
        }
    }

    if let Some(expected_session_id) = session_filter {
        let observed_session_id = work_item
            .session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if observed_session_id != Some(expected_session_id) {
            return false;
        }
    }

    true
}

fn select_push_fallback_work_id_from_list(
    work_items: &[apm2_daemon::protocol::WorkStatusResponse],
    lease_filter: Option<&str>,
    session_filter: Option<&str>,
) -> Result<String, String> {
    let mut candidates = BTreeSet::new();
    for work_item in work_items {
        if !matches_push_fallback_candidate(work_item, lease_filter, session_filter) {
            continue;
        }
        let work_id = work_item.work_id.trim();
        if work_id.is_empty() {
            continue;
        }
        if validate_push_work_id(work_id).is_err() {
            continue;
        }
        candidates.insert(work_id.to_string());
    }

    match candidates.len() {
        0 => Err(
            "daemon fallback could not identify an active Implementer work item; pass `--work-id` \
             explicitly or ensure ticket alias reconciliation is populated"
                .to_string(),
        ),
        1 => candidates
            .into_iter()
            .next()
            .ok_or_else(|| "internal error: fallback candidate set unexpectedly empty".to_string()),
        _ => {
            let candidate_list = candidates.into_iter().collect::<Vec<_>>().join(", ");
            Err(format!(
                "daemon fallback found multiple active Implementer work items ({candidate_list}); \
                 pass `--work-id` explicitly"
            ))
        },
    }
}

fn resolve_push_work_id_from_projection_fallback(
    operator_socket: &Path,
    lease_filter: Option<&str>,
    session_filter: Option<&str>,
) -> Result<String, String> {
    let list_response = with_operator_client(async move {
        let mut client = OperatorClient::connect(operator_socket).await?;
        client.work_list(false).await
    })?;

    select_push_fallback_work_id_from_list(&list_response.work_items, lease_filter, session_filter)
}

fn resolve_work_id_for_push(
    work_id_arg: Option<&str>,
    ticket_alias_arg: Option<&str>,
    lease_id_arg: Option<&str>,
    session_id_arg: Option<&str>,
    branch: &str,
    worktree_dir: &Path,
    operator_socket: &Path,
) -> Result<(String, Option<String>), String> {
    let trimmed_work_id = normalize_non_empty_arg(work_id_arg);
    let alias = normalize_non_empty_arg(ticket_alias_arg);
    let requested_lease_id = normalize_non_empty_arg(lease_id_arg);
    if let Some(ref lease_id) = requested_lease_id {
        validate_push_lease_id(lease_id)?;
    }
    let requested_session_id = normalize_non_empty_arg(session_id_arg);
    if let Some(ref session_id) = requested_session_id {
        validate_push_session_id(session_id)?;
    }

    match (trimmed_work_id, alias.as_deref()) {
        (Some(work_id), Some(ticket_alias)) => {
            validate_push_work_id(&work_id)?;
            let resolved_work_id = resolve_ticket_alias_to_work_id(ticket_alias, operator_socket)?;
            if let Some(ref resolved_work_id) = resolved_work_id
                && resolved_work_id != &work_id
            {
                return Err(format!(
                    "`--work-id` mismatch: provided `{work_id}` but ticket alias \
                     `{ticket_alias}` resolved to `{resolved_work_id}`",
                ));
            }
            // Only persist ticket_alias when daemon projection authority
            // verified it. Unverified aliases are never projected as
            // authoritative identity bindings.
            let verified_alias = resolved_work_id.map(|_| ticket_alias.to_string());
            Ok((work_id, verified_alias))
        },
        (Some(work_id), None) => {
            validate_push_work_id(&work_id)?;
            Ok((work_id, None))
        },
        (None, Some(ticket_alias)) => {
            if let Some(work_id) = resolve_ticket_alias_to_work_id(ticket_alias, operator_socket)? {
                return Ok((work_id, Some(ticket_alias.to_string())));
            }
            let fallback_work_id = resolve_push_work_id_from_projection_fallback(
                operator_socket,
                requested_lease_id.as_deref(),
                requested_session_id.as_deref(),
            )
            .map_err(|fallback_err| {
                format!(
                    "ticket alias `{ticket_alias}` did not resolve to a canonical work_id and \
                     projection fallback failed: {fallback_err}"
                )
            })?;
            Ok((fallback_work_id, None))
        },
        (None, None) => match resolve_tck_id(branch, worktree_dir) {
            Ok(derived_alias) => {
                if let Some(work_id) =
                    resolve_ticket_alias_to_work_id(&derived_alias, operator_socket)?
                {
                    return Ok((work_id, Some(derived_alias)));
                }
                let fallback_work_id = resolve_push_work_id_from_projection_fallback(
                    operator_socket,
                    requested_lease_id.as_deref(),
                    requested_session_id.as_deref(),
                )
                .map_err(|fallback_err| {
                    format!(
                        "derived ticket alias `{derived_alias}` did not resolve to a canonical \
                             work_id and projection fallback failed: {fallback_err}"
                    )
                })?;
                Ok((fallback_work_id, None))
            },
            Err(derive_err) => {
                let fallback_work_id = resolve_push_work_id_from_projection_fallback(
                    operator_socket,
                    requested_lease_id.as_deref(),
                    requested_session_id.as_deref(),
                )
                .map_err(|fallback_err| {
                    format!("{derive_err} Projection fallback also failed: {fallback_err}")
                })?;
                Ok((fallback_work_id, None))
            },
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PushRuntimeBinding {
    lease_id: String,
    session_id: String,
    session_id_source: PushSessionIdSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PushSessionIdSource {
    Requested,
    DaemonStatus,
    DerivedAdhoc,
}

impl PushSessionIdSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::DaemonStatus => "daemon_status",
            Self::DerivedAdhoc => "derived_adhoc",
        }
    }
}

fn resolve_runtime_binding_from_inputs(
    work_id: &str,
    requested_lease_id: Option<String>,
    requested_session_id: Option<String>,
    status_lease_id: Option<String>,
    status_session_id: Option<String>,
) -> Result<PushRuntimeBinding, String> {
    validate_push_work_id(work_id)?;

    if let Some(ref lease_id) = requested_lease_id {
        validate_push_lease_id(lease_id)?;
    }
    if let Some(ref session_id) = requested_session_id {
        validate_push_session_id(session_id)?;
    }
    if let Some(ref lease_id) = status_lease_id {
        validate_push_lease_id(lease_id)?;
    }
    if let Some(ref session_id) = status_session_id {
        validate_push_session_id(session_id)?;
    }

    if let (Some(requested), Some(observed)) = (&requested_lease_id, &status_lease_id)
        && requested != observed
    {
        return Err(format!(
            "`--lease-id` mismatch for work_id `{work_id}`: provided `{requested}` but daemon reports `{observed}`"
        ));
    }
    if let (Some(requested), Some(observed)) = (&requested_session_id, &status_session_id)
        && requested != observed
    {
        return Err(format!(
            "`--session-id` mismatch for work_id `{work_id}`: provided `{requested}` but daemon reports active `{observed}`"
        ));
    }

    let lease_id = requested_lease_id.or(status_lease_id).ok_or_else(|| {
        format!(
            "no active lease_id found for work_id `{work_id}`; pass `--lease-id` \
             or claim work before running `fac push`"
        )
    })?;
    validate_push_lease_id(&lease_id)?;

    let (session_id, session_id_source) = requested_session_id.map_or_else(
        || {
            status_session_id.map_or_else(
                || {
                    (
                        derive_adhoc_session_id(work_id, &lease_id),
                        PushSessionIdSource::DerivedAdhoc,
                    )
                },
                |from_status| (from_status, PushSessionIdSource::DaemonStatus),
            )
        },
        |requested| (requested, PushSessionIdSource::Requested),
    );
    validate_push_session_id(&session_id)?;

    Ok(PushRuntimeBinding {
        lease_id,
        session_id,
        session_id_source,
    })
}

fn resolve_runtime_binding_for_push(
    work_id: &str,
    lease_id_arg: Option<&str>,
    session_id_arg: Option<&str>,
    operator_socket: &Path,
) -> Result<PushRuntimeBinding, String> {
    let requested_lease_id = normalize_non_empty_arg(lease_id_arg);
    if let Some(ref lease_id) = requested_lease_id {
        validate_push_lease_id(lease_id)?;
    }
    let requested_session_id = normalize_non_empty_arg(session_id_arg);
    if let Some(ref session_id) = requested_session_id {
        validate_push_session_id(session_id)?;
    }

    let work_id_owned = work_id.to_string();
    let status_response = with_operator_client(async move {
        let mut client = OperatorClient::connect(operator_socket).await?;
        client.work_status(&work_id_owned).await
    })?;

    let status_lease_id = normalize_non_empty_arg(status_response.lease_id.as_deref());
    let status_session_id = normalize_non_empty_arg(status_response.session_id.as_deref());

    resolve_runtime_binding_from_inputs(
        work_id,
        requested_lease_id,
        requested_session_id,
        status_lease_id,
        status_session_id,
    )
}

fn make_push_session_dedupe_key(session_id: &str) -> Result<String, String> {
    validate_push_session_id(session_id)?;
    Ok(session_id.to_string())
}

fn parse_git_base_ref_commit(base_ref: &str) -> Result<(HashAlgo, String), String> {
    let output = Command::new("git")
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{base_ref}^{{commit}}"),
        ])
        .output()
        .map_err(|err| format!("failed to resolve base ref `{base_ref}`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to resolve base ref `{base_ref}`: {}",
            stderr.trim()
        ));
    }
    let object_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let is_hex = object_id.as_bytes().iter().all(u8::is_ascii_hexdigit);
    if !is_hex {
        return Err(format!(
            "base commit id for `{base_ref}` is not hexadecimal: `{object_id}`"
        ));
    }
    let algo = match object_id.len() {
        40 => HashAlgo::Sha1,
        64 => HashAlgo::Sha256,
        other => {
            return Err(format!(
                "unsupported base commit id length for `{base_ref}`: {other}"
            ));
        },
    };
    Ok((algo, object_id))
}

fn parse_git_diff_manifest(base_ref: &str, head_sha: &str) -> Result<Vec<FileChange>, String> {
    let range = format!("{base_ref}..{head_sha}");
    let output = Command::new("git")
        .args(["diff", "--name-status", "--find-renames", "-z", &range])
        .output()
        .map_err(|err| format!("failed to collect diff manifest for `{range}`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to collect diff manifest for `{range}`: {}",
            stderr.trim()
        ));
    }

    parse_git_name_status_manifest_z(&output.stdout, &range)
}

fn parse_git_numstat_binary_detected(raw: &str) -> bool {
    raw.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }
        let mut parts = trimmed.splitn(3, '\t');
        let inserted = parts.next().unwrap_or_default().trim();
        let deleted = parts.next().unwrap_or_default().trim();
        inserted == "-" || deleted == "-"
    })
}

fn detect_binary_changes(base_ref: &str, head_sha: &str) -> Result<bool, String> {
    let range = format!("{base_ref}..{head_sha}");
    let output = Command::new("git")
        .args(["diff", "--numstat", "--find-renames", &range])
        .output()
        .map_err(|err| format!("failed to collect numstat for `{range}`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to collect numstat for `{range}`: {}",
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_git_numstat_binary_detected(&stdout))
}

fn parse_dirty_worktree_entries(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn ensure_clean_worktree_for_push() -> Result<(), String> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map_err(|err| format!("failed to inspect git working tree status: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to inspect git working tree status: {}",
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries = parse_dirty_worktree_entries(&stdout);
    if entries.is_empty() {
        return Ok(());
    }

    let preview = entries
        .iter()
        .take(10)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let suffix = if entries.len() > 10 {
        format!(" (+{} more)", entries.len() - 10)
    } else {
        String::new()
    };
    Err(format!(
        "working tree is dirty; commit or stash changes before `fac push` \
         (detected {} entries: {preview}{suffix})",
        entries.len()
    ))
}

fn parse_git_name_status_manifest_z(raw: &[u8], range: &str) -> Result<Vec<FileChange>, String> {
    let mut manifest = Vec::new();
    let mut tokens = raw
        .split(|byte| *byte == 0)
        .filter(|token| !token.is_empty());
    while let Some(status_bytes) = tokens.next() {
        let status = std::str::from_utf8(status_bytes)
            .map_err(|_| format!("diff manifest contains non-UTF8 status token for `{range}`"))?;

        let status_prefix = status.chars().next().unwrap_or('M');
        let parse_path = |bytes: &[u8], label: &str| -> Result<String, String> {
            std::str::from_utf8(bytes)
                .map(ToString::to_string)
                .map_err(|_| {
                    format!("diff manifest contains non-UTF8 {label} path token for `{range}`")
                })
        };

        match status_prefix {
            'R' => {
                let old_path = tokens
                    .next()
                    .ok_or_else(|| {
                        format!(
                            "diff manifest for `{range}` truncated after rename status `{status}`"
                        )
                    })
                    .and_then(|value| parse_path(value, "rename old"))?;
                let new_path = tokens
                    .next()
                    .ok_or_else(|| {
                        format!(
                            "diff manifest for `{range}` truncated after rename status `{status}`"
                        )
                    })
                    .and_then(|value| parse_path(value, "rename new"))?;
                manifest.push(FileChange {
                    path: new_path,
                    change_kind: ChangeKind::Rename,
                    old_path: Some(old_path),
                });
            },
            'C' => {
                let old_path = tokens
                    .next()
                    .ok_or_else(|| {
                        format!(
                            "diff manifest for `{range}` truncated after copy status `{status}`"
                        )
                    })
                    .and_then(|value| parse_path(value, "copy old"))?;
                let new_path = tokens
                    .next()
                    .ok_or_else(|| {
                        format!(
                            "diff manifest for `{range}` truncated after copy status `{status}`"
                        )
                    })
                    .and_then(|value| parse_path(value, "copy new"))?;
                manifest.push(FileChange {
                    path: new_path,
                    change_kind: ChangeKind::Modify,
                    old_path: Some(old_path),
                });
            },
            'A' | 'D' | 'M' | 'T' | 'U' | 'X' | 'B' => {
                let path = tokens
                    .next()
                    .ok_or_else(|| {
                        format!("diff manifest for `{range}` truncated after status `{status}`")
                    })
                    .and_then(|value| parse_path(value, "file"))?;
                let change_kind = match status_prefix {
                    'A' => ChangeKind::Add,
                    'D' => ChangeKind::Delete,
                    _ => ChangeKind::Modify,
                };
                manifest.push(FileChange {
                    path,
                    change_kind,
                    old_path: None,
                });
            },
            _ => {
                return Err(format!(
                    "diff manifest for `{range}` contains unsupported status `{status}`"
                ));
            },
        }
    }
    Ok(manifest)
}

fn build_changeset_bundle_json(remote: &str, sha: &str) -> Result<Vec<u8>, String> {
    let base_ref = resolve_commit_history_base_ref(remote)?;
    let (base_algo, base_object_id) = parse_git_base_ref_commit(&base_ref)?;
    let manifest = parse_git_diff_manifest(&base_ref, sha)?;
    let binary_detected = detect_binary_changes(&base_ref, sha)?;
    let diff_range = format!("{base_ref}..{sha}");
    let diff_bytes = Command::new("git")
        .args(["diff", "--binary", &diff_range])
        .output()
        .map_err(|err| format!("failed to collect diff bytes for `{diff_range}`: {err}"))
        .and_then(|output| {
            if output.status.success() {
                Ok(output.stdout)
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!(
                    "failed to collect diff bytes for `{diff_range}`: {}",
                    stderr.trim()
                ))
            }
        })?;

    let changeset_id_suffix = &sha[..sha.len().min(12)];
    let bundle = ChangeSetBundleV1::builder()
        .changeset_id(format!("cs-{changeset_id_suffix}"))
        .base(GitObjectRef {
            algo: base_algo,
            object_kind: "commit".to_string(),
            object_id: base_object_id,
        })
        .diff_hash(*blake3::hash(&diff_bytes).as_bytes())
        .file_manifest(manifest)
        .binary_detected(binary_detected)
        .build()
        .map_err(|err| format!("failed to build changeset bundle: {err}"))?;

    serde_json::to_vec(&bundle)
        .map_err(|err| format!("failed to serialize changeset bundle: {err}"))
}

fn build_context_entry_json(
    work_id: &str,
    kind: WorkContextKind,
    dedupe_key: &str,
    body: String,
    metadata: Option<serde_json::Value>,
) -> Result<Vec<u8>, String> {
    let entry = WorkContextEntryV1 {
        schema: WORK_CONTEXT_ENTRY_V1_SCHEMA.to_string(),
        work_id: work_id.to_string(),
        entry_id: "placeholder".to_string(),
        kind,
        dedupe_key: dedupe_key.to_string(),
        source_session_id: None,
        actor_id: None,
        body: Some(body),
        metadata,
        tags: vec!["fac_push".to_string()],
        created_at_ns: None,
    };
    serde_json::to_vec(&entry)
        .map_err(|err| format!("failed to serialize work context entry: {err}"))
}

fn validate_context_entry_publication_response(
    label: &str,
    expected_work_id: &str,
    response: &PublishWorkContextEntryResponse,
) -> Result<(), String> {
    validate_push_work_id(&response.work_id)?;
    if response.work_id != expected_work_id {
        return Err(format!(
            "{label} work_id mismatch: expected `{expected_work_id}` but daemon returned `{}`",
            response.work_id
        ));
    }
    if response.entry_id.trim().is_empty() {
        return Err(format!("{label} entry_id is empty"));
    }
    if !response.entry_id.starts_with("CTX-") {
        return Err(format!(
            "{label} entry_id must start with `CTX-`, got `{}`",
            response.entry_id
        ));
    }
    if response.evidence_id != response.entry_id {
        return Err(format!(
            "{label} evidence_id mismatch: entry_id=`{}` evidence_id=`{}`",
            response.entry_id, response.evidence_id
        ));
    }
    if response.cas_hash.trim().is_empty() {
        return Err(format!("{label} cas_hash is empty"));
    }
    Ok(())
}

fn validate_work_publication_chain_responses(
    expected_work_id: &str,
    expected_pr_number: u32,
    expected_commit_sha: &str,
    changeset: &PublishChangeSetResponse,
    association: &RecordWorkPrAssociationResponse,
    handoff_entry: Option<&PublishWorkContextEntryResponse>,
    terminal_entry: &PublishWorkContextEntryResponse,
) -> Result<(), String> {
    validate_push_work_id(expected_work_id)?;
    validate_push_work_id(&changeset.work_id)?;
    if changeset.work_id != expected_work_id {
        return Err(format!(
            "changeset publication work_id mismatch: expected `{expected_work_id}` but daemon returned `{}`",
            changeset.work_id
        ));
    }
    if changeset.changeset_digest.trim().is_empty() {
        return Err("changeset publication returned empty changeset_digest".to_string());
    }
    if changeset.cas_hash.trim().is_empty() {
        return Err("changeset publication returned empty cas_hash".to_string());
    }
    if changeset.event_id.trim().is_empty() {
        return Err("changeset publication returned empty event_id".to_string());
    }

    validate_push_work_id(&association.work_id)?;
    if association.work_id != expected_work_id {
        return Err(format!(
            "PR association work_id mismatch: expected `{expected_work_id}` but daemon returned `{}`",
            association.work_id
        ));
    }
    if association.pr_number != u64::from(expected_pr_number) {
        return Err(format!(
            "PR association number mismatch: expected `{expected_pr_number}` but daemon returned `{}`",
            association.pr_number
        ));
    }
    if association.commit_sha != expected_commit_sha {
        return Err(format!(
            "PR association commit mismatch: expected `{expected_commit_sha}` but daemon returned `{}`",
            association.commit_sha
        ));
    }

    if let Some(handoff) = handoff_entry {
        validate_context_entry_publication_response("handoff", expected_work_id, handoff)?;
    }
    validate_context_entry_publication_response(
        "implementer_terminal",
        expected_work_id,
        terminal_entry,
    )?;

    Ok(())
}

pub(super) struct PushInvocation<'a> {
    pub repo: &'a str,
    pub remote: &'a str,
    pub branch: Option<&'a str>,
    pub ticket: Option<&'a Path>,
    pub work_id_arg: Option<&'a str>,
    pub ticket_alias_arg: Option<&'a str>,
    pub lease_id_arg: Option<&'a str>,
    pub session_id_arg: Option<&'a str>,
    pub handoff_note_arg: Option<&'a str>,
    pub json_output: bool,
    pub write_mode: QueueWriteMode,
    pub operator_socket: &'a Path,
}

pub(super) fn run_push(invocation: &PushInvocation<'_>) -> u8 {
    let repo = invocation.repo;
    let remote = invocation.remote;
    let branch = invocation.branch;
    let ticket = invocation.ticket;
    let work_id_arg = invocation.work_id_arg;
    let ticket_alias_arg = invocation.ticket_alias_arg;
    let lease_id_arg = invocation.lease_id_arg;
    let session_id_arg = invocation.session_id_arg;
    let handoff_note_arg = invocation.handoff_note_arg;
    let json_output = invocation.json_output;
    let write_mode = invocation.write_mode;
    let operator_socket = invocation.operator_socket;
    macro_rules! emit_machine_error {
        ($error:expr, $message:expr) => {{
            if json_output {
                let _ = emit_jsonl(&StageEvent {
                    event: "push_error".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "error": $error,
                        "message": $message,
                    }),
                });
            }
        }};
    }

    macro_rules! human_log {
        ($($arg:tt)*) => {{
            if !json_output {
                eprintln!($($arg)*);
            }
        }};
    }

    let emit_stage = |event: &str, extra: serde_json::Value| {
        if json_output {
            let _ = emit_jsonl(&StageEvent {
                event: event.to_string(),
                ts: ts_now(),
                extra,
            });
        }
    };

    // TCK-00596: Fail-fast credential gate for GitHub-facing push command.
    // This ensures actionable errors before any git push or PR creation.
    if let Err(err) = apm2_core::fac::require_github_credentials() {
        let message = err.to_string();
        human_log!("ERROR: {message}");
        emit_machine_error!("fac_push_credentials_missing", &message);
        return exit_codes::GENERIC_ERROR;
    }

    // Resolve branch name.
    let branch = if let Some(b) = branch {
        b.to_string()
    } else {
        let output = Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output();
        match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                let message = "failed to resolve current branch";
                human_log!("ERROR: {message}");
                emit_machine_error!("fac_push_branch_resolution_failed", message);
                return exit_codes::GENERIC_ERROR;
            },
        }
    };

    // Resolve HEAD SHA for logging.
    let sha = match Command::new("git").args(["rev-parse", "HEAD"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            let message = "failed to resolve HEAD SHA";
            human_log!("ERROR: {message}");
            emit_machine_error!("fac_push_head_resolution_failed", message);
            return exit_codes::GENERIC_ERROR;
        },
    };

    emit_stage(
        "push_started",
        serde_json::json!({
            "repo": repo,
            "remote": remote,
            "branch": branch.as_str(),
            "sha": sha.as_str(),
        }),
    );
    human_log!("fac push: sha={sha} branch={branch}");
    let mut attempt = PushAttemptRecord::new(&sha);
    let mut attempt_pr_number = find_existing_pr(repo, &branch);
    let emit_push_summary = |status: &str,
                             pr_number: u32,
                             identity_persisted: bool,
                             dispatch_warning: Option<&str>,
                             error: Option<&str>,
                             message: Option<&str>| {
        if !json_output {
            return;
        }
        let payload = PushSummary {
            schema: "apm2.fac.push.summary.v1".to_string(),
            status: status.to_string(),
            repo: repo.to_string(),
            remote: remote.to_string(),
            branch: branch.clone(),
            pr_number,
            head_sha: sha.clone(),
            identity_persisted,
            dispatch_warning: dispatch_warning.map(ToString::to_string),
            error: error.map(ToString::to_string),
            message: message.map(ToString::to_string),
        };
        let extra = serde_json::to_value(&payload).unwrap_or_else(|_| serde_json::json!({}));
        let _ = emit_jsonl(&StageEvent {
            event: "push_summary".to_string(),
            ts: ts_now(),
            extra,
        });
    };

    macro_rules! finish_with_attempt {
        ($code:expr) => {{
            if let Err(err) = append_push_attempt_record(repo, attempt_pr_number, &attempt) {
                human_log!("WARNING: failed to append push attempt log: {err}");
            }
            if json_output && $code != exit_codes::SUCCESS {
                let _ = emit_jsonl(&StageEvent {
                    event: "push_error".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "error": "fac_push_failed",
                        "message": "fac push failed",
                    }),
                });
            }
            if $code != exit_codes::SUCCESS {
                emit_push_summary(
                    "fail",
                    attempt_pr_number,
                    false,
                    None,
                    Some("fac_push_failed"),
                    Some("fac push failed"),
                );
            }
            return $code;
        }};
        ($code:expr, $error:expr, $message:expr) => {{
            if let Err(err) = append_push_attempt_record(repo, attempt_pr_number, &attempt) {
                human_log!("WARNING: failed to append push attempt log: {err}");
            }
            if json_output && $code != exit_codes::SUCCESS {
                let _ = emit_jsonl(&StageEvent {
                    event: "push_error".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "error": $error,
                        "message": $message,
                    }),
                });
            }
            if $code != exit_codes::SUCCESS {
                emit_push_summary(
                    "fail",
                    attempt_pr_number,
                    false,
                    None,
                    Some($error),
                    Some($message.as_ref()),
                );
            }
            return $code;
        }};
    }

    macro_rules! fail_with_attempt {
        ($error_code:expr, $message:expr) => {{
            let message = $message;
            human_log!("ERROR: {}", message);
            finish_with_attempt!(exit_codes::GENERIC_ERROR, $error_code, message);
        }};
    }

    // Explicitly stage fast, fail-closed checks before any time-consuming gate
    // execution. This ordering is a push contract: no gate job may be enqueued
    // until identity/worktree/head checks complete successfully.
    let fast_checks_started = Instant::now();
    let mut fast_checks_completed = false;
    emit_stage(
        "fast_checks_started",
        serde_json::json!({
            "checks": [
                "ticket_metadata_resolution",
                "work_binding_resolution",
                "clean_worktree",
                "head_drift_check",
            ],
        }),
    );

    // Resolve metadata deterministically from TCK identity.
    let worktree_dir = match std::env::current_dir() {
        Ok(path) => path,
        Err(err) => {
            fail_with_attempt!(
                "fac_push_worktree_resolution_failed",
                format!("failed to resolve current worktree path: {err}")
            );
        },
    };
    let repo_root = match resolve_repo_root() {
        Ok(path) => path,
        Err(err) => {
            fail_with_attempt!("fac_push_repo_root_resolution_failed", err);
        },
    };
    let commit_history = match collect_commit_history(remote, &branch) {
        Ok(value) => value,
        Err(err) => {
            fail_with_attempt!("fac_push_commit_history_failed", err);
        },
    };

    let metadata =
        match resolve_pr_metadata(&branch, &worktree_dir, &repo_root, &commit_history, ticket) {
            Ok(value) => value,
            Err(err) => {
                fail_with_attempt!(
                    "fac_push_ticket_resolution_failed",
                    format!(
                        "{err}; expected ticket file under documents/work/tickets/TCK-xxxxx.yaml"
                    )
                );
            },
        };
    human_log!(
        "fac push: metadata title={} body={}",
        metadata.title,
        metadata.ticket_path.display()
    );

    let handoff_note = match parse_handoff_note(handoff_note_arg) {
        Ok(note) => note,
        Err(err) => {
            fail_with_attempt!("fac_push_handoff_note_invalid", err);
        },
    };

    let (work_id, resolved_ticket_alias) = match resolve_work_id_for_push(
        work_id_arg,
        ticket_alias_arg,
        lease_id_arg,
        session_id_arg,
        &branch,
        &worktree_dir,
        operator_socket,
    ) {
        Ok(binding) => binding,
        Err(err) => {
            fail_with_attempt!("fac_push_work_id_resolution_failed", err);
        },
    };
    let runtime_binding = match resolve_runtime_binding_for_push(
        &work_id,
        lease_id_arg,
        session_id_arg,
        operator_socket,
    ) {
        Ok(value) => value,
        Err(err) => {
            fail_with_attempt!("fac_push_runtime_binding_resolution_failed", err);
        },
    };
    let lease_id = runtime_binding.lease_id;
    let session_id = runtime_binding.session_id;
    let session_id_source = runtime_binding.session_id_source;
    emit_stage(
        "work_binding_resolved",
        serde_json::json!({
            "work_id": work_id,
            "ticket_alias": resolved_ticket_alias,
            "lease_id": lease_id,
            "session_id": session_id,
            "session_id_source": session_id_source.as_str(),
        }),
    );
    human_log!(
        "fac push: bound work_id={} lease_id={} session_id={} (source={}){}",
        work_id,
        lease_id,
        session_id,
        session_id_source.as_str(),
        resolved_ticket_alias
            .as_deref()
            .map_or_else(String::new, |alias| format!(" ticket_alias={alias}"),)
    );

    if let Err(err) = ensure_clean_worktree_for_push() {
        fail_with_attempt!("fac_push_dirty_worktree", err);
    }

    // Step 1: fail closed on HEAD drift before running queued gates.
    let current_head = match Command::new("git").args(["rev-parse", "HEAD"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            fail_with_attempt!(
                "fac_push_head_reresolution_failed",
                "failed to re-resolve HEAD SHA before gates"
            );
        },
    };
    if !current_head.eq_ignore_ascii_case(&sha) {
        fail_with_attempt!(
            "fac_push_head_drift_detected",
            format!(
                "HEAD drift detected before gate execution (captured={sha}, current={current_head}); refusing mixed-SHA gate run"
            )
        );
    }
    if fast_checks_completed {
        fail_with_attempt!(
            "fac_push_fast_checks_state_invalid",
            "internal invariant violation: fast checks already marked complete"
        );
    }
    fast_checks_completed = true;
    emit_stage(
        "fast_checks_completed",
        serde_json::json!({
            "duration_secs": fast_checks_started.elapsed().as_secs(),
            "work_id": work_id,
            "lease_id": lease_id,
            "session_id": session_id,
            "head_sha": sha,
        }),
    );

    let existing_pr_number = find_existing_pr(repo, &branch);
    attempt_pr_number = existing_pr_number;
    let mut git_push_duration_secs = 0_u64;
    let mut git_push_exit_code: Option<i32> = None;
    let mut git_push_error_hint: Option<String> = None;
    let mut git_push_executed = false;
    let mut ruleset_sync_duration_secs = 0_u64;
    let mut ruleset_sync_error_hint: Option<String> = None;
    let mut ruleset_sync_executed = false;
    let mut ruleset_sync_passed = false;
    if !fast_checks_completed {
        fail_with_attempt!(
            "fac_push_fast_checks_not_completed",
            "internal invariant violation: fast checks must complete before gate execution"
        );
    }
    let gate_outcome = match run_pre_push_sequence_with(
        || {
            let _phase_progress = PushPhaseProgressTicker::start("gates", json_output);
            human_log!(
                "fac push: enqueuing evidence gates job (blocking; external worker if present, inline fallback otherwise)"
            );
            emit_stage("gates_started", serde_json::json!({}));
            let gates_started = Instant::now();
            let gate_outcome = match run_blocking_evidence_gates(&sha, Some(&work_id), write_mode) {
                Ok(outcome) => {
                    for gate in &outcome.gate_results {
                        let stage = stage_from_gate_name(&gate.gate_name);
                        let log_path = gate
                            .log_path
                            .as_ref()
                            .and_then(|path| path.to_str())
                            .map(str::to_string);
                        let error_hint = if gate.passed {
                            None
                        } else {
                            gate_error_hint_from_result(gate).or_else(|| {
                                normalize_error_hint(&format!("gate {} failed", gate.gate_name))
                            })
                        };
                        if gate.passed {
                            attempt.set_stage_pass(stage, gate.duration_secs);
                        } else {
                            attempt.set_stage_fail(
                                stage,
                                gate.duration_secs,
                                None,
                                error_hint.clone(),
                            );
                        }
                        if json_output {
                            let status = if gate.passed { "pass" } else { "fail" }.to_string();
                            let _ = emit_jsonl(&GateCompletedEvent {
                                event: "gate_completed",
                                gate: gate.gate_name.clone(),
                                status,
                                duration_secs: gate.duration_secs,
                                log_path: log_path.clone(),
                                bytes_written: gate.bytes_written,
                                bytes_total: gate.bytes_total,
                                was_truncated: gate.was_truncated,
                                log_bundle_hash: gate.log_bundle_hash.clone(),
                                error_hint: error_hint.clone(),
                                ts: ts_now(),
                            });
                            if !gate.passed {
                                let _ = emit_jsonl(&GateErrorEvent {
                                    event: "gate_error",
                                    gate: gate.gate_name.clone(),
                                    error: error_hint
                                        .clone()
                                        .unwrap_or_else(|| "gate failed".to_string()),
                                    log_path,
                                    duration_secs: Some(gate.duration_secs),
                                    bytes_written: gate.bytes_written,
                                    bytes_total: gate.bytes_total,
                                    was_truncated: gate.was_truncated,
                                    log_bundle_hash: gate.log_bundle_hash.clone(),
                                    ts: ts_now(),
                                });
                            }
                        }
                    }
                    outcome
                },
                Err(err) => {
                    emit_stage(
                        "gates_completed",
                        serde_json::json!({
                            "passed": false,
                            "duration_secs": gates_started.elapsed().as_secs(),
                            "error": err.as_str(),
                        }),
                    );
                    let mut mapped_any = false;
                    if let Some(cache) = GateCache::load(&sha) {
                        for (gate_name, gate_result) in cache.gates {
                            let stage = stage_from_gate_name(&gate_name);
                            mapped_any = true;
                            if gate_result.status.eq_ignore_ascii_case("PASS") {
                                attempt.set_stage_pass(stage, gate_result.duration_secs);
                            } else {
                                let hint = latest_gate_error_hint(&gate_name).or_else(|| {
                                    normalize_error_hint(&format!("gate {gate_name} failed"))
                                });
                                attempt.set_stage_fail(
                                    stage,
                                    gate_result.duration_secs,
                                    None,
                                    hint,
                                );
                            }
                            if json_output {
                                let normalized_status = gate_result.status.to_ascii_lowercase();
                                let log_path = gate_result.log_path.clone();
                                let error_hint = if gate_result.status.eq_ignore_ascii_case("PASS")
                                {
                                    None
                                } else {
                                    gate_result.log_path.as_deref().and_then(|path| {
                                        read_log_error_hint(std::path::Path::new(path))
                                            .or_else(|| latest_gate_error_hint(&gate_name))
                                    })
                                };
                                let _ = emit_jsonl(&GateCompletedEvent {
                                    event: "gate_completed",
                                    gate: gate_name.clone(),
                                    status: normalized_status,
                                    duration_secs: gate_result.duration_secs,
                                    log_path: log_path.clone(),
                                    bytes_written: gate_result.bytes_written,
                                    bytes_total: gate_result.bytes_total,
                                    was_truncated: gate_result.was_truncated,
                                    log_bundle_hash: gate_result.log_bundle_hash.clone(),
                                    error_hint: error_hint.clone(),
                                    ts: ts_now(),
                                });
                                if gate_result.status.eq_ignore_ascii_case("FAIL") {
                                    let _ = emit_jsonl(&GateErrorEvent {
                                        event: "gate_error",
                                        gate: gate_name.clone(),
                                        error: error_hint
                                            .unwrap_or_else(|| "gate failed".to_string()),
                                        log_path,
                                        duration_secs: Some(gate_result.duration_secs),
                                        bytes_written: gate_result.bytes_written,
                                        bytes_total: gate_result.bytes_total,
                                        was_truncated: gate_result.was_truncated,
                                        log_bundle_hash: gate_result.log_bundle_hash.clone(),
                                        ts: ts_now(),
                                    });
                                }
                            }
                        }
                    }
                    if !mapped_any {
                        let duration = gates_started.elapsed().as_secs();
                        let failed_gates = parse_failed_gates_from_error(&err);
                        if failed_gates.is_empty() {
                            for stage in ["gate_fmt", "gate_clippy", "gate_test", "gate_doc"] {
                                attempt.set_stage_fail(
                                    stage,
                                    duration,
                                    None,
                                    normalize_error_hint(&err),
                                );
                            }
                        } else {
                            for gate_name in &failed_gates {
                                attempt.set_stage_fail(
                                    stage_from_gate_name(gate_name),
                                    duration,
                                    None,
                                    normalize_error_hint(&err),
                                );
                            }
                        }
                        if json_output {
                            if failed_gates.is_empty() {
                                let _ = emit_jsonl(&GateErrorEvent {
                                    event: "gate_error",
                                    gate: "unknown".to_string(),
                                    error: normalize_error_hint(&err)
                                        .unwrap_or_else(|| err.clone()),
                                    log_path: None,
                                    duration_secs: Some(duration),
                                    bytes_written: None,
                                    bytes_total: None,
                                    was_truncated: None,
                                    log_bundle_hash: None,
                                    ts: ts_now(),
                                });
                            } else {
                                for gate_name in failed_gates {
                                    let _ = emit_jsonl(&GateErrorEvent {
                                        event: "gate_error",
                                        gate: gate_name,
                                        error: normalize_error_hint(&err)
                                            .unwrap_or_else(|| err.clone()),
                                        log_path: None,
                                        duration_secs: Some(duration),
                                        bytes_written: None,
                                        bytes_total: None,
                                        was_truncated: None,
                                        log_bundle_hash: None,
                                        ts: ts_now(),
                                    });
                                }
                            }
                        }
                    }
                    if existing_pr_number > 0 {
                        if let Err(state_err) =
                            apply_gate_failure_lifecycle_events(repo, existing_pr_number, &sha)
                        {
                            return Err(format!(
                                "{err}; additionally failed to persist gate-failure lifecycle sequence: {state_err}"
                            ));
                        }
                    }
                    return Err(err);
                },
            };
            emit_stage(
                "gates_completed",
                serde_json::json!({
                    "passed": true,
                    "duration_secs": gates_started.elapsed().as_secs(),
                    "worker_bootstrapped": gate_outcome.worker_bootstrapped,
                }),
            );
            if gate_outcome.worker_bootstrapped {
                human_log!(
                    "fac push: no live worker heartbeat detected; auto-started detached FAC worker"
                );
            }
            human_log!("fac push: evidence gates PASSED");
            Ok(gate_outcome)
        },
        || {
            let _phase_progress = PushPhaseProgressTicker::start("ruleset_sync", json_output);
            emit_stage("ruleset_sync_started", serde_json::json!({}));
            let sync_started = Instant::now();
            match sync_required_status_ruleset(repo, None, None, false) {
                Ok(sync_outcome) => {
                    let duration_secs = sync_started.elapsed().as_secs();
                    ruleset_sync_duration_secs = duration_secs;
                    ruleset_sync_error_hint = None;
                    ruleset_sync_executed = true;
                    ruleset_sync_passed = true;
                    let required_status_contexts = sync_outcome.contexts.clone();
                    emit_stage(
                        "ruleset_sync_completed",
                        serde_json::json!({
                            "status": "pass",
                            "duration_secs": duration_secs,
                            "ruleset_id": sync_outcome.ruleset_id,
                            "drift_detected": sync_outcome.drift_detected,
                            "changed": sync_outcome.changed,
                            "required_status_contexts": required_status_contexts,
                        }),
                    );
                    if sync_outcome.changed {
                        human_log!(
                            "fac push: synchronized GitHub ruleset #{} required-status contexts from local source of truth",
                            sync_outcome.ruleset_id
                        );
                    } else {
                        human_log!(
                            "fac push: GitHub ruleset #{} already aligned with local required-status policy",
                            sync_outcome.ruleset_id
                        );
                    }
                    Ok(())
                },
                Err(err) => {
                    let duration_secs = sync_started.elapsed().as_secs();
                    ruleset_sync_duration_secs = duration_secs;
                    ruleset_sync_error_hint = normalize_error_hint(&err);
                    ruleset_sync_executed = true;
                    ruleset_sync_passed = false;
                    emit_stage(
                        "ruleset_sync_completed",
                        serde_json::json!({
                            "status": "fail",
                            "duration_secs": duration_secs,
                            "error": err.as_str(),
                        }),
                    );
                    Err(err)
                },
            }
        },
        || {
            let _phase_progress = PushPhaseProgressTicker::start("git_push", json_output);
            let git_push_started = Instant::now();
            let push_output = Command::new("git")
                .args(["push", "--force", remote, &branch])
                .output();
            match push_output {
                Ok(o) if o.status.success() => {
                    let duration_secs = git_push_started.elapsed().as_secs();
                    git_push_executed = true;
                    git_push_duration_secs = duration_secs;
                    git_push_exit_code = None;
                    git_push_error_hint = None;
                    emit_stage(
                        "git_push_completed",
                        serde_json::json!({
                            "status": "pass",
                            "duration_secs": duration_secs,
                        }),
                    );
                    human_log!("fac push: git push --force succeeded");
                    Ok(())
                },
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    let duration_secs = git_push_started.elapsed().as_secs();
                    git_push_executed = true;
                    git_push_duration_secs = duration_secs;
                    git_push_exit_code = o.status.code();
                    git_push_error_hint = normalize_error_hint(&stderr);
                    emit_stage(
                        "git_push_completed",
                        serde_json::json!({
                            "status": "fail",
                            "duration_secs": duration_secs,
                            "error": stderr.trim(),
                        }),
                    );
                    Err(format!("git push --force failed: {stderr}"))
                },
                Err(err) => {
                    let duration_secs = git_push_started.elapsed().as_secs();
                    git_push_executed = true;
                    git_push_duration_secs = duration_secs;
                    git_push_exit_code = None;
                    git_push_error_hint = normalize_error_hint(&err.to_string());
                    emit_stage(
                        "git_push_completed",
                        serde_json::json!({
                            "status": "error",
                            "duration_secs": duration_secs,
                            "error": err.to_string(),
                        }),
                    );
                    Err(format!("failed to execute git push --force: {err}"))
                },
            }
        },
    ) {
        Ok(results) => {
            mark_ruleset_sync_stage_if_succeeded(
                &mut attempt,
                ruleset_sync_executed,
                ruleset_sync_passed,
                ruleset_sync_duration_secs,
            );
            if git_push_executed {
                attempt.set_stage_pass("git_push", git_push_duration_secs);
            }
            results
        },
        Err(PrePushExecutionError::Gates(err)) => {
            fail_with_attempt!("fac_push_gates_failed", err);
        },
        Err(PrePushExecutionError::RulesetSync(err)) => {
            if ruleset_sync_executed {
                attempt.set_stage_fail(
                    "ruleset_sync",
                    ruleset_sync_duration_secs,
                    None,
                    ruleset_sync_error_hint.or_else(|| normalize_error_hint(&err)),
                );
            } else {
                attempt.set_stage_fail("ruleset_sync", 0, None, normalize_error_hint(&err));
            }
            fail_with_attempt!("fac_push_ruleset_sync_failed", err);
        },
        Err(PrePushExecutionError::GitPush(err)) => {
            mark_ruleset_sync_stage_if_succeeded(
                &mut attempt,
                ruleset_sync_executed,
                ruleset_sync_passed,
                ruleset_sync_duration_secs,
            );
            if git_push_executed {
                attempt.set_stage_fail(
                    "git_push",
                    git_push_duration_secs,
                    git_push_exit_code,
                    git_push_error_hint,
                );
            } else {
                attempt.set_stage_fail("git_push", 0, None, normalize_error_hint(&err));
            }
            fail_with_attempt!("fac_push_git_push_failed", err);
        },
    };

    // Step 2: create or update PR.
    let pr_update_started = Instant::now();
    let pr_update_progress = PushPhaseProgressTicker::start("pr_update", json_output);
    let pr_number = find_existing_pr(repo, &branch);
    let pr_number = if pr_number == 0 {
        match create_pr(repo, &metadata.title, &metadata.body) {
            Ok(num) => {
                attempt.set_stage_pass("pr_update", pr_update_started.elapsed().as_secs());
                human_log!("fac push: created PR #{num}");
                num
            },
            Err(e) => {
                attempt.set_stage_fail(
                    "pr_update",
                    pr_update_started.elapsed().as_secs(),
                    None,
                    normalize_error_hint(&e),
                );
                fail_with_attempt!(
                    "fac_push_pr_create_failed",
                    format!(
                        "{e}; unable to resolve authoritative PR mapping for branch `{branch}` after create failure; refusing local fallback to prevent wrong-PR association"
                    )
                );
            },
        }
    } else {
        if let Err(err) = update_pr(repo, pr_number, &metadata.title, &metadata.body) {
            attempt.set_stage_fail(
                "pr_update",
                pr_update_started.elapsed().as_secs(),
                None,
                normalize_error_hint(&err),
            );
            fail_with_attempt!(
                "fac_push_pr_update_failed",
                format!("failed to update PR projection for #{pr_number}: {err}")
            );
        }
        attempt.set_stage_pass("pr_update", pr_update_started.elapsed().as_secs());
        human_log!("fac push: using PR #{pr_number}");
        pr_number
    };
    attempt_pr_number = pr_number;
    drop(pr_update_progress);
    emit_stage(
        "pr_updated",
        serde_json::json!({
            "pr_number": pr_number,
            "url": format!("https://github.com/{repo}/pull/{pr_number}"),
        }),
    );

    let pr_url = format!("https://github.com/{repo}/pull/{pr_number}");
    let dedupe_key = match make_push_session_dedupe_key(&session_id) {
        Ok(value) => value,
        Err(err) => {
            fail_with_attempt!("fac_push_session_dedupe_key_failed", err);
        },
    };
    emit_stage(
        "work_publication_started",
        serde_json::json!({
            "work_id": work_id,
            "lease_id": lease_id,
            "session_id": session_id,
            "pr_number": pr_number,
            "dedupe_key": dedupe_key,
            "handoff_note_present": handoff_note.is_some(),
        }),
    );

    let bundle_bytes = match build_changeset_bundle_json(remote, &sha) {
        Ok(bytes) => bytes,
        Err(err) => {
            fail_with_attempt!("fac_push_changeset_bundle_failed", err);
        },
    };
    let handoff_entry_json = if let Some(handoff_note) = handoff_note {
        Some(
            match build_context_entry_json(
                &work_id,
                WorkContextKind::HandoffNote,
                &dedupe_key,
                handoff_note,
                Some(serde_json::json!({
                    "repo": repo,
                    "branch": branch,
                    "pr_number": pr_number,
                    "head_sha": sha,
                    "ticket_alias": resolved_ticket_alias,
                    "source": "fac.push",
                    "session_id": session_id,
                    "lease_id": lease_id,
                })),
            ) {
                Ok(bytes) => bytes,
                Err(err) => {
                    fail_with_attempt!("fac_push_handoff_entry_build_failed", err);
                },
            },
        )
    } else {
        None
    };
    let terminal_entry_json = match build_context_entry_json(
        &work_id,
        WorkContextKind::ImplementerTerminal,
        &dedupe_key,
        format!(
            "fac push session complete\nrepo: {repo}\npr: #{pr_number}\nbranch: {branch}\nhead_sha: {sha}\n"
        ),
        Some(serde_json::json!({
            "repo": repo,
            "branch": branch,
            "pr_number": pr_number,
            "head_sha": sha,
            "ticket_alias": resolved_ticket_alias,
            "source": "fac.push",
            "mode": "implementer_terminal",
            "session_id": session_id,
            "lease_id": lease_id,
        })),
    ) {
        Ok(bytes) => bytes,
        Err(err) => {
            fail_with_attempt!("fac_push_terminal_entry_build_failed", err);
        },
    };

    let rpc_work_id = work_id.clone();
    let rpc_lease_id = lease_id.clone();
    let rpc_sha = sha.clone();
    let rpc_pr_url = pr_url;
    let rpc_dedupe_key = dedupe_key.clone();
    let rpc_bundle_bytes = bundle_bytes;
    let rpc_handoff_entry_json = handoff_entry_json;
    let rpc_terminal_entry_json = terminal_entry_json;
    let work_publication_progress =
        PushPhaseProgressTicker::start("work_publication_rpc", json_output);
    let rpc_result = match with_operator_client(async move {
        let mut client = OperatorClient::connect(operator_socket).await?;
        let changeset = client
            .publish_changeset(&rpc_work_id, rpc_bundle_bytes)
            .await?;
        let association = client
            .record_work_pr_association(
                &rpc_work_id,
                u64::from(pr_number),
                &rpc_sha,
                &rpc_lease_id,
                Some(&rpc_pr_url),
            )
            .await?;
        let handoff_entry = if let Some(handoff_entry_json) = rpc_handoff_entry_json {
            Some(
                client
                    .publish_work_context_entry(
                        &rpc_work_id,
                        "HANDOFF_NOTE",
                        &rpc_dedupe_key,
                        handoff_entry_json,
                        &rpc_lease_id,
                    )
                    .await?,
            )
        } else {
            None
        };
        let terminal_entry = client
            .publish_work_context_entry(
                &rpc_work_id,
                "IMPLEMENTER_TERMINAL",
                &rpc_dedupe_key,
                rpc_terminal_entry_json,
                &rpc_lease_id,
            )
            .await?;
        Ok::<_, ProtocolClientError>((changeset, association, handoff_entry, terminal_entry))
    }) {
        Ok(value) => value,
        Err(err) => {
            fail_with_attempt!("fac_push_work_publication_failed", err);
        },
    };
    drop(work_publication_progress);
    let (changeset_response, pr_association_response, handoff_response, terminal_response) =
        rpc_result;
    if let Err(err) = validate_work_publication_chain_responses(
        &work_id,
        pr_number,
        &sha,
        &changeset_response,
        &pr_association_response,
        handoff_response.as_ref(),
        &terminal_response,
    ) {
        fail_with_attempt!(
            "fac_push_work_publication_response_invalid",
            format!("daemon returned invalid publication chain response: {err}")
        );
    }
    emit_stage(
        "work_publication_completed",
        serde_json::json!({
            "work_id": work_id,
            "changeset_digest": changeset_response.changeset_digest,
            "changeset_event_id": changeset_response.event_id,
            "changeset_cas_hash": changeset_response.cas_hash,
            "pr_number": pr_association_response.pr_number,
            "pr_association_already_existed": pr_association_response.already_existed,
            "handoff_entry_id": handoff_response.as_ref().map(|response| response.entry_id.clone()),
            "implementer_terminal_entry_id": terminal_response.entry_id,
            "lease_id": lease_id,
            "session_id": session_id,
            "dedupe_key": dedupe_key,
        }),
    );
    let handoff_entry_display = handoff_response
        .as_ref()
        .map_or("none", |response| response.entry_id.as_str());
    human_log!(
        "fac push: published work projection chain (work_id={}, changeset={}, handoff_entry={}, implementer_terminal_entry={})",
        work_id,
        changeset_response.changeset_digest,
        handoff_entry_display,
        terminal_response.entry_id
    );

    let mut successful_projection_targets = Vec::new();
    successful_projection_targets.push("pr_metadata");
    successful_projection_targets.push("work_projection");
    match fetch_pr_base_sha(repo, pr_number) {
        Ok(base_sha) => {
            if let Err(err) = projection_store::save_prepare_base_snapshot(
                repo,
                pr_number,
                &sha,
                &base_sha,
                "push_pr_base_api",
            ) {
                human_log!(
                    "WARNING: failed to persist prepare base snapshot for PR #{pr_number}: {err}"
                );
            }
        },
        Err(err) => {
            human_log!(
                "WARNING: failed to fetch PR base SHA for PR #{pr_number}; offline prepare may fall back to local main: {err}"
            );
        },
    }

    let gate_evidence_hashes = gate_outcome
        .gate_results
        .iter()
        .filter_map(|gate| gate.log_bundle_hash.clone())
        .collect::<Vec<_>>();
    if let Err(err) = projection_store::save_gates_admission(
        repo,
        pr_number,
        &sha,
        &projection_store::GatesAdmissionSaveRequest {
            gate_job_id: &gate_outcome.job_id,
            gate_receipt_id: &gate_outcome.job_receipt_id,
            policy_hash: &gate_outcome.policy_hash,
            gate_evidence_hashes: &gate_evidence_hashes,
            source: "push",
        },
    ) {
        fail_with_attempt!(
            "fac_push_gates_admission_persist_failed",
            format!("failed to persist authoritative gates admission binding: {err}")
        );
    }

    // Step 3: sync gate status section to PR body (best-effort).
    let gate_status_rows = gate_outcome
        .gate_results
        .iter()
        .map(|result| GateResult {
            name: result.gate_name.clone(),
            status: if result.passed {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            duration_secs: Some(result.duration_secs),
            tokens_used: None,
            model: None,
        })
        .collect::<Vec<_>>();
    if let Err(err) = sync_gate_status_to_pr(repo, pr_number, gate_status_rows, &sha) {
        human_log!("WARNING: failed to sync gate status section in PR body: {err}");
    } else {
        human_log!("fac push: synced gate status section in PR body for PR #{pr_number}");
        successful_projection_targets.push("gate_status");
    }

    if let Err(err) = ensure_projection_success_for_push(&successful_projection_targets) {
        fail_with_attempt!(
            "fac_push_projection_required_failed",
            format!("failed projection gate before lifecycle progression: {err}")
        );
    }

    if let Err(err) = apply_gate_success_lifecycle_events(repo, pr_number, &sha) {
        fail_with_attempt!(
            "fac_push_lifecycle_gates_passed_failed",
            format!("failed to persist gate-success lifecycle sequence: {err}")
        );
    }

    // Step 4: dispatch reviews.
    //
    // Intentional: dispatch failures are non-fatal for `fac push`. Push owns
    // publication and gate validation; reviewer liveness and retry are handled
    // by doctor-first remediation surfaces.
    let dispatch_started = Instant::now();
    emit_stage("dispatch_started", serde_json::json!({}));
    let dispatch_progress = PushPhaseProgressTicker::start("dispatch_reviews", json_output);
    let mut emitted_reviews_dispatched = false;
    let dispatch_warning = match dispatch_reviews_with(
        repo,
        pr_number,
        &sha,
        dispatch_single_review,
        |owner_repo, pr_number, sha, review_type, run_id, pid, proc_start_time| {
            let emit_reviews_dispatched = !emitted_reviews_dispatched;
            let result = lifecycle::register_reviewer_dispatch(
                owner_repo,
                pr_number,
                sha,
                review_type,
                run_id,
                pid,
                proc_start_time,
                emit_reviews_dispatched,
                true,
            );
            if emit_reviews_dispatched && result.is_ok() {
                emitted_reviews_dispatched = true;
            }
            result
        },
        !json_output,
    ) {
        Err(e) => {
            attempt.set_stage_fail(
                "dispatch",
                dispatch_started.elapsed().as_secs(),
                None,
                normalize_error_hint(&e),
            );
            human_log!("WARNING: review dispatch failed: {e}");
            human_log!("  Reviewers are NOT running. Use:");
            human_log!("    apm2 fac doctor --pr {pr_number} --fix");
            // BF-001 (TCK-00626): Emit structured dispatch_failed event so
            // the event stream captures the failure for automated recovery.
            if json_output {
                let _ = emit_jsonl(&serde_json::json!({
                    "event": "dispatch_failed",
                    "ts": ts_now(),
                    "pr_number": pr_number,
                    "sha": sha,
                    "error": e,
                    "recovery_commands": [
                        format!("apm2 fac doctor --pr {pr_number} --fix"),
                    ],
                }));
            }
            Some(e)
        },
        Ok(results) => {
            attempt.set_stage_pass("dispatch", dispatch_started.elapsed().as_secs());
            match maybe_force_projection_binding_repair(
                repo,
                pr_number,
                &sha,
                &results,
                json_output,
                !json_output,
            ) {
                Ok(_repaired) => None,
                Err(err) => {
                    let warning = format!(
                        "projection-gap dispatch repair failed after initial dispatch success: {err}"
                    );
                    if json_output {
                        let _ = emit_jsonl(&serde_json::json!({
                            "event": "dispatch_projection_repair_failed",
                            "ts": ts_now(),
                            "pr_number": pr_number,
                            "sha": sha,
                            "error": warning,
                            "recovery_commands": [
                                format!("apm2 fac doctor --pr {pr_number} --fix"),
                            ],
                        }));
                    } else {
                        human_log!("WARNING: {warning}");
                    }
                    Some(warning)
                },
            }
        },
    };
    drop(dispatch_progress);
    let has_dispatch_warning = dispatch_warning.is_some();
    emit_stage(
        "dispatch_completed",
        serde_json::json!({
            "status": if has_dispatch_warning { "warn" } else { "pass" },
            "duration_secs": dispatch_started.elapsed().as_secs(),
            "warning": dispatch_warning.as_deref(),
        }),
    );

    // Step 5: persist projection identity only after gates + dispatch attempt.
    let mut identity_persisted = false;
    if let Err(err) = projection_store::save_identity_with_context(repo, pr_number, &sha, "push") {
        human_log!("WARNING: failed to persist local projection identity: {err}");
    } else if let Err(err) =
        projection_store::save_pr_body_snapshot(repo, pr_number, &metadata.body, "push")
    {
        human_log!("WARNING: failed to persist local PR body snapshot: {err}");
    } else {
        identity_persisted = true;
    }

    emit_push_summary(
        "pass",
        pr_number,
        identity_persisted,
        dispatch_warning.as_deref(),
        None,
        None,
    );

    if let Err(err) = append_push_attempt_record(repo, pr_number, &attempt) {
        human_log!("WARNING: failed to append push attempt log: {err}");
    }

    human_log!("fac push: done (PR #{pr_number})");
    if has_dispatch_warning {
        human_log!(
            "  review dispatch warning surfaced; rerun: apm2 fac doctor --pr {pr_number} --fix"
        );
    } else {
        human_log!("  if review dispatch stalls: apm2 fac doctor --pr {pr_number} --fix");
    }
    exit_codes::SUCCESS
}

/// Read `/proc/<pid>/stat` field 22 (`starttime`) for PID-reuse validation.
///
/// Returns the kernel-monotonic start time in clock ticks for the given PID,
/// or `None` if the `/proc` entry is unreadable (process dead, non-Linux, or
/// restricted procfs). This is the same technique used by `apm2-daemon`'s
/// process identity validation (`adapter::read_proc_start_time`), duplicated
/// here because the daemon helper is `pub(crate)` and not accessible from
/// `apm2-cli`.
///
/// # Known limitation
///
/// This check is Linux-specific. On non-Linux platforms it always returns
/// `None`, which the caller treats as "cannot verify" (fail-closed: the PID
/// is treated as dead, triggering a retry). PID reuse is mitigated but not
/// fully eliminated: the start-time check ensures the PID was started at
/// the expected time, which makes reuse collision astronomically unlikely
/// within the polling window.
#[cfg(unix)]
fn read_proc_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let contents = std::fs::read_to_string(stat_path).ok()?;
    // Field 22 is `starttime` (0-indexed after the comm field in parens).
    // Comm can contain spaces/parens, so split after the last ')'.
    let after_comm = contents.rsplit_once(')')?.1;
    let tokens: Vec<&str> = after_comm.split_whitespace().collect();
    // Field 22 is at index 19 after the comm field (fields are 1-indexed in
    // proc(5) and the first two fields before ')' are pid and comm).
    tokens.get(19)?.parse::<u64>().ok()
}

#[cfg(not(unix))]
const fn read_proc_start_time(_pid: u32) -> Option<u64> {
    None
}

/// Check whether a PID is alive with process-identity validation.
///
/// Returns `true` only if ALL of the following hold:
/// 1. `/proc/<pid>` exists (process slot is occupied),
/// 2. The current `proc_start_time` can be read from `/proc/<pid>/stat`,
/// 3. `recorded_start_time` was provided (not `None`), and
/// 4. The current start time matches the recorded start time.
///
/// If `recorded_start_time` is `None` (legacy path where start time was never
/// captured), the function returns `false` (fail-closed: treat the process as
/// dead, triggering a retry).  This prevents PID-reuse false positives where
/// a different process has been assigned the same PID after the original
/// terminated.
///
/// On non-Linux platforms, always returns `false` (fail-closed: treat as dead,
/// triggering a retry).
fn is_pid_alive_with_identity(pid: u32, recorded_start_time: Option<u64>) -> bool {
    let proc_path = format!("/proc/{pid}");
    if !std::path::Path::new(&proc_path).exists() {
        return false;
    }
    // Fail-closed: if no recorded start time was captured at dispatch time,
    // we cannot distinguish the original process from a PID-reuse impostor.
    let Some(recorded) = recorded_start_time else {
        return false;
    };
    // The start time (field 22 in /proc/<pid>/stat) is monotonic within a
    // boot epoch. Matching it against the recorded value confirms that the
    // running process is the same one we originally dispatched.
    #[cfg(unix)]
    {
        read_proc_start_time(pid).is_some_and(|current| current == recorded)
    }
    #[cfg(not(unix))]
    {
        let _ = recorded;
        false
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    use super::*;

    #[test]
    fn ensure_projection_success_for_push_rejects_empty_set() {
        let err = ensure_projection_success_for_push(&[]).expect_err("empty set must fail");
        assert!(err.contains("at least one successful projection"));
    }

    #[test]
    fn validate_push_work_id_accepts_canonical_value() {
        validate_push_work_id("W-12345-abcdef").expect("canonical work_id must pass");
    }

    #[test]
    fn validate_push_work_id_rejects_non_canonical_value() {
        let err = validate_push_work_id("owner/repo").expect_err("non-canonical work_id must fail");
        assert!(err.contains("must start with `W-`"));
    }

    #[test]
    fn parse_handoff_note_allows_omission() {
        let parsed = parse_handoff_note(None).expect("omitted handoff note should be accepted");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_handoff_note_rejects_empty_when_provided() {
        let err = parse_handoff_note(Some("   ")).expect_err("blank handoff note must be rejected");
        assert!(err.contains("cannot be empty"));
    }

    #[test]
    fn parse_handoff_note_trims_when_provided() {
        let parsed = parse_handoff_note(Some("  ready for review  "))
            .expect("non-empty handoff note should be accepted");
        assert_eq!(parsed.as_deref(), Some("ready for review"));
    }

    fn sample_daemon_work_item(
        work_id: &str,
        status: &str,
        role: Option<apm2_daemon::protocol::WorkRole>,
        lease_id: Option<&str>,
        session_id: Option<&str>,
    ) -> apm2_daemon::protocol::WorkStatusResponse {
        apm2_daemon::protocol::WorkStatusResponse {
            work_id: work_id.to_string(),
            status: status.to_string(),
            actor_id: Some("actor:test".to_string()),
            role: role.map(|value| value as i32),
            session_id: session_id.map(str::to_string),
            lease_id: lease_id.map(str::to_string),
            created_at_ns: 0,
            claimed_at_ns: None,
            implementer_claim_blocked: false,
            dependency_diagnostics: Vec::new(),
        }
    }

    #[test]
    fn select_push_fallback_work_id_from_list_prefers_unique_implementer() {
        let rows = vec![
            sample_daemon_work_item(
                "W-gate-executor",
                "CLAIMED",
                Some(apm2_daemon::protocol::WorkRole::GateExecutor),
                Some("L-gate"),
                None,
            ),
            sample_daemon_work_item(
                "W-implementer",
                "CLAIMED",
                Some(apm2_daemon::protocol::WorkRole::Implementer),
                Some("L-implementer"),
                None,
            ),
        ];

        let selected = select_push_fallback_work_id_from_list(&rows, None, None)
            .expect("unique implementer candidate should resolve");
        assert_eq!(selected, "W-implementer");
    }

    #[test]
    fn select_push_fallback_work_id_from_list_fails_closed_on_ambiguity() {
        let rows = vec![
            sample_daemon_work_item(
                "W-implementer-1",
                "CLAIMED",
                Some(apm2_daemon::protocol::WorkRole::Implementer),
                Some("L-1"),
                None,
            ),
            sample_daemon_work_item(
                "W-implementer-2",
                "SPAWNED",
                Some(apm2_daemon::protocol::WorkRole::Implementer),
                Some("L-2"),
                Some("S-2"),
            ),
        ];

        let err = select_push_fallback_work_id_from_list(&rows, None, None)
            .expect_err("ambiguous implementer candidates must fail closed");
        assert!(err.contains("multiple active Implementer work items"));
    }

    #[test]
    fn select_push_fallback_work_id_from_list_honors_lease_filter() {
        let rows = vec![
            sample_daemon_work_item(
                "W-implementer-1",
                "CLAIMED",
                Some(apm2_daemon::protocol::WorkRole::Implementer),
                Some("L-target"),
                None,
            ),
            sample_daemon_work_item(
                "W-implementer-2",
                "CLAIMED",
                Some(apm2_daemon::protocol::WorkRole::Implementer),
                Some("L-other"),
                None,
            ),
        ];

        let selected = select_push_fallback_work_id_from_list(&rows, Some("L-target"), None)
            .expect("lease filter should disambiguate candidate selection");
        assert_eq!(selected, "W-implementer-1");
    }

    #[test]
    fn select_push_fallback_work_id_from_list_requires_session_match_when_filter_provided() {
        let rows = vec![sample_daemon_work_item(
            "W-implementer-1",
            "CLAIMED",
            Some(apm2_daemon::protocol::WorkRole::Implementer),
            Some("L-target"),
            None,
        )];

        let err = select_push_fallback_work_id_from_list(
            &rows,
            Some("L-target"),
            Some("S-backfill"),
        )
        .expect_err(
            "missing daemon session metadata must fail closed when session filter is explicit",
        );
        assert!(err.contains("could not identify an active Implementer work item"));
    }

    #[test]
    fn select_push_fallback_work_id_from_list_accepts_in_progress_status() {
        let rows = vec![sample_daemon_work_item(
            "W-implementer-1",
            "IN_PROGRESS",
            Some(apm2_daemon::protocol::WorkRole::Implementer),
            Some("L-target"),
            Some("S-target"),
        )];

        let selected =
            select_push_fallback_work_id_from_list(&rows, Some("L-target"), Some("S-target"))
                .expect("IN_PROGRESS should be treated as an active status");
        assert_eq!(selected, "W-implementer-1");
    }

    #[test]
    fn select_push_fallback_work_id_from_list_rejects_missing_role() {
        let rows = vec![sample_daemon_work_item(
            "W-implementer-1",
            "CLAIMED",
            None,
            Some("L-target"),
            Some("S-target"),
        )];

        let err = select_push_fallback_work_id_from_list(&rows, Some("L-target"), Some("S-target"))
            .expect_err("missing role must fail closed");
        assert!(err.contains("could not identify an active Implementer work item"));
    }

    #[test]
    fn select_push_fallback_work_id_from_list_rejects_non_active_status() {
        let rows = vec![sample_daemon_work_item(
            "W-implementer",
            "COMPLETED",
            Some(apm2_daemon::protocol::WorkRole::Implementer),
            Some("L-implementer"),
            None,
        )];

        let err = select_push_fallback_work_id_from_list(&rows, None, None)
            .expect_err("non-active statuses must not be selected for fallback");
        assert!(err.contains("could not identify an active Implementer work item"));
    }

    #[test]
    fn make_push_session_dedupe_key_uses_session_id() {
        let dedupe = make_push_session_dedupe_key("S-1234-5678")
            .expect("session id dedupe key should be accepted");
        assert_eq!(dedupe, "S-1234-5678");
    }

    #[test]
    fn make_push_session_dedupe_key_rejects_invalid_session_id() {
        let err = make_push_session_dedupe_key("session/1")
            .expect_err("invalid session id should be rejected");
        assert!(err.contains("must start with `S-`") || err.contains("invalid characters"));
    }

    #[test]
    fn resolve_runtime_binding_from_inputs_prefers_requested_session_when_daemon_session_missing() {
        let binding = resolve_runtime_binding_from_inputs(
            "W-TCK-00640",
            Some("L-lease-123".to_string()),
            Some("S-requested-123".to_string()),
            Some("L-lease-123".to_string()),
            None,
        )
        .expect("requested session should be used when daemon status has no active session");
        assert_eq!(binding.lease_id, "L-lease-123");
        assert_eq!(binding.session_id, "S-requested-123");
        assert_eq!(binding.session_id_source, PushSessionIdSource::Requested);
    }

    #[test]
    fn resolve_runtime_binding_from_inputs_uses_daemon_session_when_not_requested() {
        let binding = resolve_runtime_binding_from_inputs(
            "W-TCK-00640",
            None,
            None,
            Some("L-lease-123".to_string()),
            Some("S-daemon-999".to_string()),
        )
        .expect("daemon session should be used when no request override is provided");
        assert_eq!(binding.lease_id, "L-lease-123");
        assert_eq!(binding.session_id, "S-daemon-999");
        assert_eq!(binding.session_id_source, PushSessionIdSource::DaemonStatus);
    }

    #[test]
    fn resolve_runtime_binding_from_inputs_derives_adhoc_session_when_missing() {
        let binding = resolve_runtime_binding_from_inputs(
            "W-TCK-00640",
            Some("L-lease-123".to_string()),
            None,
            Some("L-lease-123".to_string()),
            None,
        )
        .expect("missing daemon session should derive deterministic ad-hoc session");
        assert_eq!(binding.lease_id, "L-lease-123");
        assert!(binding.session_id.starts_with("S-adhoc-"));
        assert_eq!(binding.session_id_source, PushSessionIdSource::DerivedAdhoc);
    }

    #[test]
    fn resolve_runtime_binding_from_inputs_rejects_lease_mismatch() {
        let err = resolve_runtime_binding_from_inputs(
            "W-TCK-00640",
            Some("L-requested".to_string()),
            None,
            Some("L-daemon".to_string()),
            None,
        )
        .expect_err("lease mismatch must fail closed");
        assert!(err.contains("`--lease-id` mismatch"));
    }

    #[test]
    fn resolve_runtime_binding_from_inputs_rejects_session_mismatch() {
        let err = resolve_runtime_binding_from_inputs(
            "W-TCK-00640",
            Some("L-lease-123".to_string()),
            Some("S-requested".to_string()),
            Some("L-lease-123".to_string()),
            Some("S-daemon".to_string()),
        )
        .expect_err("session mismatch must fail closed");
        assert!(err.contains("`--session-id` mismatch"));
    }

    fn sample_changeset_response(work_id: &str) -> PublishChangeSetResponse {
        PublishChangeSetResponse {
            changeset_digest: "b3-256:abc123".to_string(),
            cas_hash: "b3-256:def456".to_string(),
            work_id: work_id.to_string(),
            event_id: "evt-123".to_string(),
        }
    }

    fn sample_pr_association_response(
        work_id: &str,
        pr_number: u32,
        commit_sha: &str,
    ) -> RecordWorkPrAssociationResponse {
        RecordWorkPrAssociationResponse {
            work_id: work_id.to_string(),
            pr_number: u64::from(pr_number),
            commit_sha: commit_sha.to_string(),
            already_existed: false,
        }
    }

    fn sample_context_response(work_id: &str, entry_id: &str) -> PublishWorkContextEntryResponse {
        PublishWorkContextEntryResponse {
            entry_id: entry_id.to_string(),
            evidence_id: entry_id.to_string(),
            cas_hash: "b3-256:ctx".to_string(),
            work_id: work_id.to_string(),
        }
    }

    #[test]
    fn validate_work_publication_chain_responses_accepts_valid_payload() {
        let changeset = sample_changeset_response("W-TCK-00640");
        let association = sample_pr_association_response(
            "W-TCK-00640",
            640,
            "0123456789abcdef0123456789abcdef01234567",
        );
        let handoff = sample_context_response("W-TCK-00640", "CTX-123");
        let terminal = sample_context_response("W-TCK-00640", "CTX-456");

        validate_work_publication_chain_responses(
            "W-TCK-00640",
            640,
            "0123456789abcdef0123456789abcdef01234567",
            &changeset,
            &association,
            Some(&handoff),
            &terminal,
        )
        .expect("valid publication chain should be accepted");
    }

    #[test]
    fn validate_work_publication_chain_responses_rejects_pr_number_mismatch() {
        let changeset = sample_changeset_response("W-TCK-00640");
        let association = sample_pr_association_response(
            "W-TCK-00640",
            999,
            "0123456789abcdef0123456789abcdef01234567",
        );
        let terminal = sample_context_response("W-TCK-00640", "CTX-456");

        let err = validate_work_publication_chain_responses(
            "W-TCK-00640",
            640,
            "0123456789abcdef0123456789abcdef01234567",
            &changeset,
            &association,
            None,
            &terminal,
        )
        .expect_err("pr number mismatch must fail closed");
        assert!(err.contains("PR association number mismatch"));
    }

    #[test]
    fn validate_work_publication_chain_responses_rejects_non_context_entry_id() {
        let changeset = sample_changeset_response("W-TCK-00640");
        let association = sample_pr_association_response(
            "W-TCK-00640",
            640,
            "0123456789abcdef0123456789abcdef01234567",
        );
        let terminal = sample_context_response("W-TCK-00640", "bad-entry");

        let err = validate_work_publication_chain_responses(
            "W-TCK-00640",
            640,
            "0123456789abcdef0123456789abcdef01234567",
            &changeset,
            &association,
            None,
            &terminal,
        )
        .expect_err("non-CTX entry id must fail closed");
        assert!(err.contains("entry_id must start with `CTX-`"));
    }

    #[test]
    fn derive_adhoc_session_id_is_deterministic_and_prefixed() {
        let first = derive_adhoc_session_id("W-TCK-00640", "L-lease-123");
        let second = derive_adhoc_session_id("W-TCK-00640", "L-lease-123");
        let different = derive_adhoc_session_id("W-TCK-00640", "L-lease-456");

        assert_eq!(
            first, second,
            "adhoc session derivation must be deterministic"
        );
        assert_ne!(
            first, different,
            "different lease_id must produce different ad-hoc session ids"
        );
        assert!(
            first.starts_with("S-adhoc-"),
            "derived ad-hoc session id must be canonical: {first}"
        );
    }

    #[test]
    fn parse_git_name_status_manifest_z_parses_add_modify_delete() {
        let raw = b"A\0added.rs\0M\0mod.rs\0D\0deleted.rs\0";
        let manifest =
            parse_git_name_status_manifest_z(raw, "base..head").expect("manifest should parse");
        assert_eq!(manifest.len(), 3);
        assert_eq!(manifest[0].path, "added.rs");
        assert_eq!(manifest[0].change_kind, ChangeKind::Add);
        assert_eq!(manifest[1].path, "mod.rs");
        assert_eq!(manifest[1].change_kind, ChangeKind::Modify);
        assert_eq!(manifest[2].path, "deleted.rs");
        assert_eq!(manifest[2].change_kind, ChangeKind::Delete);
    }

    #[test]
    fn parse_git_name_status_manifest_z_parses_rename_and_copy() {
        let raw = b"R100\0old.rs\0new.rs\0C100\0src.rs\0dst.rs\0";
        let manifest =
            parse_git_name_status_manifest_z(raw, "base..head").expect("manifest should parse");
        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest[0].change_kind, ChangeKind::Rename);
        assert_eq!(manifest[0].old_path.as_deref(), Some("old.rs"));
        assert_eq!(manifest[0].path, "new.rs");
        assert_eq!(manifest[1].change_kind, ChangeKind::Modify);
        assert_eq!(manifest[1].old_path.as_deref(), Some("src.rs"));
        assert_eq!(manifest[1].path, "dst.rs");
    }

    #[test]
    fn parse_git_name_status_manifest_z_rejects_truncated_rename_tokens() {
        let raw = b"R100\0only-old.rs\0";
        let err = parse_git_name_status_manifest_z(raw, "base..head")
            .expect_err("truncated rename should fail");
        assert!(err.contains("truncated"));
    }

    #[test]
    fn parse_git_name_status_manifest_z_rejects_unsupported_status() {
        let raw = b"Z\0mystery.rs\0";
        let err = parse_git_name_status_manifest_z(raw, "base..head")
            .expect_err("unsupported status should fail");
        assert!(err.contains("unsupported status"));
    }

    #[test]
    fn parse_git_numstat_binary_detected_flags_binary_rows() {
        let raw = "12\t4\tsrc/lib.rs\n-\t-\tassets/logo.png\n";
        assert!(
            parse_git_numstat_binary_detected(raw),
            "numstat parser must detect binary rows marked with '-'"
        );
    }

    #[test]
    fn parse_git_numstat_binary_detected_ignores_text_only_rows() {
        let raw = "12\t4\tsrc/lib.rs\n1\t0\tREADME.md\n";
        assert!(
            !parse_git_numstat_binary_detected(raw),
            "numstat parser must not report binary when all rows are text"
        );
    }

    #[test]
    fn parse_dirty_worktree_entries_filters_blank_lines() {
        let entries = parse_dirty_worktree_entries(" M src/main.rs\n\n?? new-file.txt\n");
        assert_eq!(
            entries,
            vec!["M src/main.rs".to_string(), "?? new-file.txt".to_string()]
        );
    }

    #[test]
    fn ensure_projection_success_for_push_accepts_non_empty_set() {
        ensure_projection_success_for_push(&["pr_metadata"]).expect("non-empty set should pass");
    }

    #[test]
    fn ensure_projection_success_for_push_rejects_blank_entries() {
        let err = ensure_projection_success_for_push(&["", "   "])
            .expect_err("blank entries must not satisfy projection gate");
        assert!(err.contains("at least one successful projection"));
    }

    #[test]
    fn is_pid_alive_with_identity_rejects_none_recorded_start_time() {
        // Fail-closed: if no recorded start time was captured (legacy path),
        // the function must return false even for a live PID. This prevents
        // PID-reuse false positives on legacy dispatch payloads.
        let current_pid = std::process::id();
        assert!(
            !is_pid_alive_with_identity(current_pid, None),
            "expected false when recorded_start_time is None (fail-closed)"
        );
    }

    #[test]
    fn is_pid_alive_with_identity_rejects_mismatched_start_time() {
        // A different process with the same PID will have a different start
        // time.  Simulate this by passing a deliberately wrong start time for
        // the current process.
        let current_pid = std::process::id();
        let wrong_start_time: u64 = 1; // any value that won't match the real start time
        assert!(
            !is_pid_alive_with_identity(current_pid, Some(wrong_start_time)),
            "expected false when recorded start time does not match current process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn is_pid_alive_with_identity_accepts_matching_start_time() {
        // When the recorded start time matches the current process, the
        // function should return true.
        let current_pid = std::process::id();
        let real_start_time = read_proc_start_time(current_pid)
            .expect("should be able to read start time for own process");
        assert!(
            is_pid_alive_with_identity(current_pid, Some(real_start_time)),
            "expected true when recorded start time matches current process"
        );
    }

    #[test]
    fn is_pid_alive_with_identity_rejects_dead_pid() {
        // A PID that does not exist should return false regardless of the
        // recorded start time.
        let dead_pid = 4_000_000_000_u32; // unlikely to be a real PID
        assert!(
            !is_pid_alive_with_identity(dead_pid, Some(12345)),
            "expected false for non-existent PID"
        );
        assert!(
            !is_pid_alive_with_identity(dead_pid, None),
            "expected false for non-existent PID with None start time"
        );
    }

    #[allow(unsafe_code)]
    fn with_test_apm2_home<T>(f: impl FnOnce(&Path) -> T) -> T {
        struct EnvGuard {
            original_apm2_home: Option<OsString>,
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                if let Some(value) = self.original_apm2_home.take() {
                    // SAFETY: serialized through env_var_test_lock in test scope.
                    unsafe { std::env::set_var("APM2_HOME", value) };
                } else {
                    // SAFETY: serialized through env_var_test_lock in test scope.
                    unsafe { std::env::remove_var("APM2_HOME") };
                }
            }
        }

        let _env_lock = crate::commands::env_var_test_lock()
            .lock()
            .expect("serialize APM2_HOME tests");
        let temp = tempfile::tempdir().expect("tempdir");
        let apm2_home = temp.path().join("apm2-home");
        fs::create_dir_all(&apm2_home).expect("create apm2 home");
        let original_apm2_home = std::env::var_os("APM2_HOME");
        // SAFETY: serialized through env_var_test_lock in test scope.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };
        let _guard = EnvGuard { original_apm2_home };
        f(&apm2_home)
    }

    fn sample_commit_history() -> Vec<CommitSummary> {
        vec![
            CommitSummary {
                short_sha: "abc12345".to_string(),
                message: "first change".to_string(),
            },
            CommitSummary {
                short_sha: "def67890".to_string(),
                message: "second change".to_string(),
            },
        ]
    }

    #[test]
    fn push_attempt_record_returns_first_failed_stage_in_order() {
        let mut record = PushAttemptRecord::new("0123456789abcdef0123456789abcdef01234567");
        record.set_stage_pass("git_push", 2);
        record.set_stage_fail("gate_test", 15, Some(1), Some("timeout".to_string()));
        record.set_stage_fail("dispatch", 4, None, Some("at_capacity".to_string()));

        let failed = record.first_failed_stage().expect("failed stage");
        assert_eq!(failed.stage, "gate_test");
        assert_eq!(failed.duration_s, 15);
        assert_eq!(failed.exit_code, Some(1));
        assert_eq!(failed.error_hint.as_deref(), Some("timeout"));
    }

    #[test]
    fn push_attempt_record_reports_ruleset_sync_failure_stage() {
        let mut record = PushAttemptRecord::new("0123456789abcdef0123456789abcdef01234567");
        record.set_stage_pass("gate_fmt", 1);
        record.set_stage_pass("gate_clippy", 2);
        record.set_stage_pass("gate_test", 3);
        record.set_stage_pass("gate_doc", 4);
        record.set_stage_fail(
            "ruleset_sync",
            5,
            None,
            Some("ruleset drift not synchronized".to_string()),
        );

        let failed = record.first_failed_stage().expect("failed stage");
        assert_eq!(failed.stage, "ruleset_sync");
        assert_eq!(failed.duration_s, 5);
        assert_eq!(
            failed.error_hint.as_deref(),
            Some("ruleset drift not synchronized")
        );
    }

    #[test]
    fn mark_ruleset_sync_stage_if_succeeded_sets_pass_only_on_success() {
        let mut success = PushAttemptRecord::new("0123456789abcdef0123456789abcdef01234567");
        mark_ruleset_sync_stage_if_succeeded(&mut success, true, true, 7);
        assert_eq!(success.ruleset_sync.status, PUSH_STAGE_PASS);
        assert_eq!(success.ruleset_sync.duration_s, 7);

        let mut skipped = PushAttemptRecord::new("0123456789abcdef0123456789abcdef01234567");
        mark_ruleset_sync_stage_if_succeeded(&mut skipped, true, false, 7);
        assert_eq!(skipped.ruleset_sync.status, PUSH_STAGE_SKIPPED);
    }

    #[test]
    fn push_attempt_record_preserves_ruleset_sync_pass_when_git_push_fails() {
        let mut record = PushAttemptRecord::new("0123456789abcdef0123456789abcdef01234567");
        mark_ruleset_sync_stage_if_succeeded(&mut record, true, true, 2);
        record.set_stage_fail("git_push", 1, Some(1), Some("remote rejected".to_string()));

        assert_eq!(record.ruleset_sync.status, PUSH_STAGE_PASS);
        let failed = record.first_failed_stage().expect("failed stage");
        assert_eq!(failed.stage, "git_push");
    }

    #[test]
    fn gate_failure_lifecycle_events_apply_canonical_sequence() {
        let mut seen = Vec::new();
        apply_gate_failure_lifecycle_events_with(
            "guardian-intelligence/apm2",
            42,
            "0123456789abcdef0123456789abcdef01234567",
            |event| {
                let label = match event {
                    lifecycle::LifecycleEventKind::PushObserved => "push_observed",
                    lifecycle::LifecycleEventKind::GatesStarted => "gates_started",
                    lifecycle::LifecycleEventKind::GatesFailed => "gates_failed",
                    _ => "unexpected",
                };
                seen.push(label.to_string());
                Ok(())
            },
        )
        .expect("sequence should apply cleanly");

        assert_eq!(seen, vec!["push_observed", "gates_started", "gates_failed"]);
    }

    #[test]
    fn gate_failure_lifecycle_events_fail_closed_on_transition_error() {
        let err = apply_gate_failure_lifecycle_events_with(
            "guardian-intelligence/apm2",
            99,
            "fedcba9876543210fedcba9876543210fedcba98",
            |event| match event {
                lifecycle::LifecycleEventKind::GatesStarted => {
                    Err("illegal transition: gates_failed + gates_started".to_string())
                },
                _ => Ok(()),
            },
        )
        .expect_err("transition failure must surface as hard error");
        assert!(err.contains("gates_started"));
        assert!(err.contains("illegal transition"));
    }

    #[test]
    fn gate_success_lifecycle_events_apply_canonical_sequence() {
        let mut seen = Vec::new();
        apply_gate_success_lifecycle_events_with(
            "guardian-intelligence/apm2",
            77,
            "00112233445566778899aabbccddeeff00112233",
            |event| {
                let label = match event {
                    lifecycle::LifecycleEventKind::PushObserved => "push_observed",
                    lifecycle::LifecycleEventKind::GatesStarted => "gates_started",
                    lifecycle::LifecycleEventKind::GatesPassed => "gates_passed",
                    _ => "unexpected",
                };
                seen.push(label.to_string());
                Ok(())
            },
        )
        .expect("sequence should apply cleanly");

        assert_eq!(seen, vec!["push_observed", "gates_started", "gates_passed"]);
    }

    #[test]
    fn gate_success_lifecycle_events_fail_closed_on_transition_error() {
        let err = apply_gate_success_lifecycle_events_with(
            "guardian-intelligence/apm2",
            88,
            "ffeeddccbbaa99887766554433221100ffeeddcc",
            |event| match event {
                lifecycle::LifecycleEventKind::GatesPassed => {
                    Err("illegal transition: gates_failed + gates_passed".to_string())
                },
                _ => Ok(()),
            },
        )
        .expect_err("transition failure must surface as hard error");
        assert!(err.contains("gates_passed"));
        assert!(err.contains("illegal transition"));
    }

    #[test]
    fn push_attempt_record_deserializes_legacy_rows_without_ruleset_sync_field() {
        let stage = serde_json::json!({
            "status": PUSH_STAGE_PASS,
            "duration_s": 1_u64
        });
        let legacy = serde_json::json!({
            "ts": "2026-02-18T01:00:00Z",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "git_push": stage,
            "gate_fmt": stage,
            "gate_clippy": stage,
            "gate_test": stage,
            "gate_doc": stage,
            "pr_update": stage,
            "dispatch": stage
        });

        let record: PushAttemptRecord =
            serde_json::from_value(legacy).expect("legacy row should deserialize");
        assert_eq!(record.schema, PUSH_ATTEMPT_SCHEMA);
        assert_eq!(record.ruleset_sync.status, PUSH_STAGE_SKIPPED);
        assert_eq!(record.ruleset_sync.duration_s, 0);
    }

    #[test]
    fn load_latest_push_attempt_for_sha_skips_malformed_lines_and_keeps_valid_rows() {
        with_test_apm2_home(|_| {
            let owner_repo = "guardian-intelligence/apm2";
            let pr_number = 42_u32;
            let sha = "0123456789abcdef0123456789abcdef01234567";

            let mut record = PushAttemptRecord::new(sha);
            record.set_stage_pass("gate_fmt", 1);
            append_push_attempt_record(owner_repo, pr_number, &record)
                .expect("append valid record");

            let path = push_attempts_path(owner_repo, pr_number).expect("push attempts path");
            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open push attempts file");
            writeln!(file, "{{malformed-json").expect("write malformed line");

            let loaded = load_latest_push_attempt_for_sha(owner_repo, pr_number, sha)
                .expect("load attempt")
                .expect("matching attempt");
            assert_eq!(loaded.sha, sha);
            assert_eq!(loaded.gate_fmt.status, PUSH_STAGE_PASS);
        });
    }

    #[test]
    fn normalize_error_hint_uses_last_non_empty_line_and_caps_length() {
        let hint = normalize_error_hint("line1\n\nline2 final detail").expect("hint");
        assert_eq!(hint, "line2 final detail");

        let long = "x".repeat(400);
        let capped = normalize_error_hint(&long).expect("capped");
        assert_eq!(capped.chars().count(), 200);
    }

    fn parse_yaml_from_markdown_fence(markdown: &str) -> serde_yaml::Value {
        let content = markdown
            .strip_prefix("```yaml\n")
            .and_then(|value| value.strip_suffix("\n```"))
            .expect("yaml fence");
        serde_yaml::from_str(content).expect("valid yaml")
    }

    fn seed_required_pass_results() -> Vec<EvidenceGateResult> {
        expected_gate_names()
            .into_iter()
            .map(|gate_name| EvidenceGateResult {
                gate_name,
                passed: true,
                duration_secs: 1,
                log_bundle_hash: Some(format!("b3-256:{}", "ab".repeat(32))),
                ..Default::default()
            })
            .collect()
    }

    fn queued_outcome_with(
        job_id: &str,
        sha: &str,
        gate_results: Vec<EvidenceGateResult>,
    ) -> QueuedGatesOutcome {
        QueuedGatesOutcome {
            job_id: job_id.to_string(),
            job_receipt_id: format!("{job_id}-receipt"),
            policy_hash: format!("b3-256:{}", "ab".repeat(32)),
            head_sha: sha.to_string(),
            worker_bootstrapped: false,
            gate_results,
        }
    }

    #[test]
    fn run_pre_push_sequence_with_enforces_gates_then_ruleset_sync_then_git_push() {
        let calls = std::cell::RefCell::new(Vec::new());
        let expected_results = seed_required_pass_results();
        let sha = "f".repeat(40);
        let outcome = run_pre_push_sequence_with(
            || {
                calls.borrow_mut().push("gates");
                Ok(queued_outcome_with(
                    "gates-pre-push-order",
                    &sha,
                    expected_results.clone(),
                ))
            },
            || {
                calls.borrow_mut().push("ruleset_sync");
                Ok(())
            },
            || {
                calls.borrow_mut().push("git_push");
                Ok(())
            },
        )
        .expect("pre-push sequence should succeed");

        assert_eq!(*calls.borrow(), vec!["gates", "ruleset_sync", "git_push"]);
        assert_eq!(outcome.gate_results.len(), expected_results.len());
    }

    #[test]
    fn run_pre_push_sequence_with_stops_before_remote_side_effects_on_gate_failure() {
        let calls = std::cell::RefCell::new(Vec::new());
        let error = run_pre_push_sequence_with(
            || {
                calls.borrow_mut().push("gates");
                Err("gate failed".to_string())
            },
            || {
                calls.borrow_mut().push("ruleset_sync");
                Ok(())
            },
            || {
                calls.borrow_mut().push("git_push");
                Ok(())
            },
        )
        .expect_err("gate failure should fail closed");

        assert_eq!(*calls.borrow(), vec!["gates"]);
        assert_eq!(
            error,
            PrePushExecutionError::Gates("gate failed".to_string())
        );
    }

    #[test]
    fn run_pre_push_sequence_with_stops_before_git_push_when_ruleset_sync_fails() {
        let calls = std::cell::RefCell::new(Vec::new());
        let error = run_pre_push_sequence_with(
            || {
                calls.borrow_mut().push("gates");
                Ok(queued_outcome_with(
                    "gates-pre-push-ruleset-fail",
                    &"a".repeat(40),
                    seed_required_pass_results(),
                ))
            },
            || {
                calls.borrow_mut().push("ruleset_sync");
                Err("ruleset drift not synchronized".to_string())
            },
            || {
                calls.borrow_mut().push("git_push");
                Ok(())
            },
        )
        .expect_err("ruleset sync failure should block git push");

        assert_eq!(*calls.borrow(), vec!["gates", "ruleset_sync"]);
        assert_eq!(
            error,
            PrePushExecutionError::RulesetSync("ruleset drift not synchronized".to_string())
        );
    }

    #[test]
    fn extract_tck_from_text_accepts_valid_pattern() {
        assert_eq!(
            extract_tck_from_text("ticket/RFC-0018/TCK-00412"),
            Some("TCK-00412".to_string())
        );
    }

    #[test]
    fn extract_tck_from_text_rejects_invalid_variants() {
        assert_eq!(extract_tck_from_text("ticket/rfc/TCK-412"), None);
        assert_eq!(extract_tck_from_text("ticket/rfc/tck-00412"), None);
        assert_eq!(extract_tck_from_text("ticket/rfc/TCK-004123"), None);
    }

    #[test]
    fn resolve_tck_id_prefers_branch() {
        let worktree = Path::new("/tmp/apm2-TCK-99999");
        let tck = resolve_tck_id("ticket/RFC-0018/TCK-00412", worktree)
            .expect("branch should provide tck");
        assert_eq!(tck, "TCK-00412");
    }

    #[test]
    fn resolve_tck_id_falls_back_to_worktree_name() {
        let worktree = Path::new("/tmp/apm2-TCK-00444");
        let tck = resolve_tck_id("feat/no-ticket", worktree).expect("worktree should provide tck");
        assert_eq!(tck, "TCK-00444");
    }

    #[test]
    fn resolve_tck_id_returns_actionable_error() {
        let worktree = Path::new("/tmp/apm2-no-ticket");
        let err = resolve_tck_id("feat/no-ticket", worktree).expect_err("should fail");
        assert!(err.contains("Required format"));
        assert!(err.contains("TCK-12345"));
    }

    #[test]
    fn ticket_path_for_tck_uses_canonical_location() {
        let path = ticket_path_for_tck(Path::new("/repo"), "TCK-00412");
        assert_eq!(
            path,
            PathBuf::from("/repo/documents/work/tickets/TCK-00412.yaml")
        );
    }

    #[test]
    fn validate_ticket_path_matches_tck_accepts_matching_filename() {
        let result = validate_ticket_path_matches_tck(
            Path::new("documents/work/tickets/TCK-00412.yaml"),
            "TCK-00412",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_ticket_path_matches_tck_rejects_mismatch() {
        let err = validate_ticket_path_matches_tck(
            Path::new("documents/work/tickets/TCK-00411.yaml"),
            "TCK-00412",
        )
        .expect_err("mismatch should fail");
        assert!(err.contains("does not match derived TCK"));
    }

    #[test]
    fn load_ticket_body_reads_raw_contents() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let ticket_path = temp_dir.path().join("TCK-00412.yaml");
        std::fs::write(
            &ticket_path,
            "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n",
        )
        .expect("write ticket");

        let content = load_ticket_body(&ticket_path).expect("load ticket body");
        assert_eq!(content, "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n");
    }

    #[test]
    fn load_ticket_title_reads_plain_title() {
        let ticket_path = Path::new("/repo/documents/work/tickets/TCK-00412.yaml");
        let body = "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n    title: \"Title Value\"\n";
        let title = load_ticket_title(ticket_path, body).expect("title should parse");
        assert_eq!(title, "Title Value");
    }

    #[test]
    fn load_ticket_title_fails_when_missing() {
        let ticket_path = Path::new("/repo/documents/work/tickets/TCK-00412.yaml");
        let body = "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n";
        let err = load_ticket_title(ticket_path, body).expect_err("missing title should fail");
        assert!(err.contains("ticket_meta.ticket.title"));
    }

    #[test]
    fn parse_commit_history_parses_short_sha_and_message() {
        let parsed = parse_commit_history("abc12345\tfirst change\ndef67890\tsecond change\n");
        assert_eq!(parsed, sample_commit_history());
    }

    #[test]
    fn render_ticket_body_markdown_includes_commit_history_metadata() {
        let rendered = render_ticket_body_markdown(
            "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n",
            &sample_commit_history(),
        )
        .expect("render ticket body");
        let yaml = parse_yaml_from_markdown_fence(&rendered);

        let ticket_id = yaml
            .get("ticket_meta")
            .and_then(|value| value.get("ticket"))
            .and_then(|value| value.get("id"))
            .and_then(serde_yaml::Value::as_str)
            .expect("ticket id");
        assert_eq!(ticket_id, "TCK-00412");

        let history = yaml
            .get("fac_push_metadata")
            .and_then(|value| value.get("commit_history"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("commit history");
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0]
                .get("short_sha")
                .and_then(serde_yaml::Value::as_str),
            Some("abc12345")
        );
        assert_eq!(
            history[0]
                .get("message")
                .and_then(serde_yaml::Value::as_str),
            Some("first change")
        );
    }

    #[test]
    fn resolve_pr_metadata_branch_tck_yields_title_and_markdown_body() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo_root = temp_dir.path();
        let tickets_dir = repo_root.join("documents/work/tickets");
        fs::create_dir_all(&tickets_dir).expect("create tickets dir");
        let ticket_path = tickets_dir.join("TCK-00412.yaml");
        let ticket_content = "ticket_meta:\n  ticket:\n    id: \"TCK-00412\"\n    title: \"Any\"\n";
        fs::write(&ticket_path, ticket_content).expect("write ticket");

        let metadata = resolve_pr_metadata(
            "ticket/RFC-0018/TCK-00412",
            Path::new("/tmp/apm2-no-ticket"),
            repo_root,
            &sample_commit_history(),
            None,
        )
        .expect("resolve metadata");
        assert_eq!(metadata.title, "TCK-00412: Any");
        let yaml = parse_yaml_from_markdown_fence(&metadata.body);
        let history = yaml
            .get("fac_push_metadata")
            .and_then(|value| value.get("commit_history"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("commit history");
        assert_eq!(history.len(), 2);
        assert_eq!(metadata.ticket_path, ticket_path);
    }

    #[test]
    fn resolve_pr_metadata_uses_worktree_fallback() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo_root = temp_dir.path();
        let tickets_dir = repo_root.join("documents/work/tickets");
        fs::create_dir_all(&tickets_dir).expect("create tickets dir");
        let ticket_path = tickets_dir.join("TCK-00444.yaml");
        let ticket_content =
            "ticket_meta:\n  ticket:\n    id: \"TCK-00444\"\n    title: \"Fallback Title\"\n";
        fs::write(&ticket_path, ticket_content).expect("write ticket");

        let metadata = resolve_pr_metadata(
            "feat/no-ticket",
            Path::new("/tmp/apm2-TCK-00444"),
            repo_root,
            &sample_commit_history(),
            None,
        )
        .expect("resolve metadata");
        assert_eq!(metadata.title, "TCK-00444: Fallback Title");
        let yaml = parse_yaml_from_markdown_fence(&metadata.body);
        let history = yaml
            .get("fac_push_metadata")
            .and_then(|value| value.get("commit_history"))
            .and_then(serde_yaml::Value::as_sequence)
            .expect("commit history");
        assert_eq!(history.len(), 2);
        assert_eq!(metadata.ticket_path, ticket_path);
    }

    #[test]
    fn resolve_pr_metadata_rejects_ticket_mismatch() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo_root = temp_dir.path();
        let tickets_dir = repo_root.join("documents/work/tickets");
        fs::create_dir_all(&tickets_dir).expect("create tickets dir");
        fs::write(tickets_dir.join("TCK-00412.yaml"), "ticket_meta:\n").expect("write ticket");

        let err = resolve_pr_metadata(
            "ticket/RFC-0018/TCK-00412",
            Path::new("/tmp/apm2-no-ticket"),
            repo_root,
            &sample_commit_history(),
            Some(Path::new("documents/work/tickets/TCK-00411.yaml")),
        )
        .expect_err("mismatch should fail");
        assert!(err.contains("does not match derived TCK"));
    }

    #[test]
    fn resolve_pr_metadata_fails_when_canonical_ticket_missing() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo_root = temp_dir.path();
        let err = resolve_pr_metadata(
            "ticket/RFC-0018/TCK-00412",
            Path::new("/tmp/apm2-no-ticket"),
            repo_root,
            &sample_commit_history(),
            None,
        )
        .expect_err("missing ticket should fail");
        assert!(err.contains("failed to read ticket body"));
        assert!(err.contains("TCK-00412.yaml"));
    }

    #[test]
    fn run_blocking_evidence_gates_with_returns_reported_results_for_pass() {
        let sha = "c".repeat(40);
        let results = seed_required_pass_results();

        let result = run_blocking_evidence_gates_with(&sha, || {
            Ok(queued_outcome_with(
                "gates-test-pass",
                &sha,
                results.clone(),
            ))
        })
        .expect("pass should return reported rows");

        assert_eq!(result.gate_results.len(), expected_gate_names().len());
        assert!(result.gate_results.iter().all(|gate| gate.passed));
    }

    #[test]
    fn run_blocking_evidence_gates_with_fails_closed_when_pass_without_gate_artifacts() {
        let sha = "d".repeat(40);
        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(queued_outcome_with("gates-test-empty", &sha, Vec::new()))
        })
        .expect_err("missing gate artifacts on PASS must fail closed");
        assert!(err.contains("no gate result artifacts"));
        assert!(err.contains(&sha));
    }

    #[test]
    fn run_blocking_evidence_gates_with_reports_failed_gate_names() {
        let sha = "e".repeat(40);
        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(queued_outcome_with(
                "gates-test-failed",
                &sha,
                vec![
                    EvidenceGateResult {
                        gate_name: "rustfmt".to_string(),
                        passed: false,
                        duration_secs: 1,
                        ..Default::default()
                    },
                    EvidenceGateResult {
                        gate_name: "clippy".to_string(),
                        passed: true,
                        duration_secs: 2,
                        ..Default::default()
                    },
                ],
            ))
        })
        .expect_err("failed gate should surface reported failing names");
        assert!(err.contains("rustfmt"));
        assert!(!err.contains("clippy"));
    }

    #[test]
    fn parse_failed_gates_from_error_extracts_comma_separated_names() {
        let parsed = parse_failed_gates_from_error(
            "gates failed with exit code 1; failed_gates=rustfmt,clippy,test; first_failure=test: timed out",
        );
        assert_eq!(parsed, vec!["rustfmt", "clippy", "test"]);
    }

    #[test]
    fn parse_failed_gates_from_error_returns_empty_without_marker() {
        let parsed = parse_failed_gates_from_error("gates failed with exit code 1");
        assert!(parsed.is_empty());
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_pass_when_reported_row_is_fail() {
        let sha = "f".repeat(40);
        let mut results = seed_required_pass_results();
        let rustfmt = results
            .iter_mut()
            .find(|result| result.gate_name == "rustfmt")
            .expect("rustfmt row");
        rustfmt.passed = false;

        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(queued_outcome_with(
                "gates-test-pass-with-fail-row",
                &sha,
                results.clone(),
            ))
        })
        .expect_err("pass path must fail when reported gate row is FAIL");
        assert!(err.contains("reported gate rows include FAIL"));
        assert!(err.contains("rustfmt"));
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_incomplete_results_on_pass() {
        let sha = "1".repeat(40);
        let incomplete_results = vec![
            EvidenceGateResult {
                gate_name: "rustfmt".to_string(),
                passed: true,
                duration_secs: 1,
                ..Default::default()
            },
            EvidenceGateResult {
                gate_name: "clippy".to_string(),
                passed: true,
                duration_secs: 1,
                ..Default::default()
            },
        ];

        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(queued_outcome_with(
                "gates-test-incomplete",
                &sha,
                incomplete_results.clone(),
            ))
        })
        .expect_err("pass path must fail on incomplete reported gate set");
        assert!(err.contains("required gate set"));
        assert!(err.contains("missing="));
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_mismatched_head_sha() {
        let sha = "2".repeat(40);
        let mismatch_sha = "3".repeat(40);
        let results = seed_required_pass_results();

        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(queued_outcome_with(
                "gates-test-sha-mismatch",
                &mismatch_sha,
                results.clone(),
            ))
        })
        .expect_err("sha mismatch must fail closed");
        assert!(err.contains("unexpected sha"));
        assert!(err.contains(&mismatch_sha));
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_empty_job_id() {
        let sha = "4".repeat(40);
        let results = seed_required_pass_results();

        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(QueuedGatesOutcome {
                job_id: String::new(),
                job_receipt_id: "gates-test-empty-job-id-receipt".to_string(),
                policy_hash: format!("b3-256:{}", "ab".repeat(32)),
                head_sha: sha.clone(),
                worker_bootstrapped: false,
                gate_results: results.clone(),
            })
        })
        .expect_err("empty job_id must fail closed");
        assert!(err.contains("empty job_id"));
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_invalid_policy_hash() {
        let sha = "5".repeat(40);
        let results = seed_required_pass_results();
        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(QueuedGatesOutcome {
                job_id: "gates-test-invalid-policy-hash".to_string(),
                job_receipt_id: "gates-test-invalid-policy-hash-receipt".to_string(),
                policy_hash: "not-a-hash".to_string(),
                head_sha: sha.clone(),
                worker_bootstrapped: false,
                gate_results: results.clone(),
            })
        })
        .expect_err("invalid policy hash must fail closed");
        assert!(err.contains("invalid policy_hash"));
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_missing_log_bundle_hash() {
        let sha = "6".repeat(40);
        let mut results = seed_required_pass_results();
        let rustfmt = results
            .iter_mut()
            .find(|result| result.gate_name == "rustfmt")
            .expect("rustfmt row");
        rustfmt.log_bundle_hash = None;

        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(queued_outcome_with(
                "gates-test-missing-log-bundle-hash",
                &sha,
                results.clone(),
            ))
        })
        .expect_err("missing log bundle hash must fail closed");
        assert!(err.contains("log bundle hashes"));
        assert!(err.contains("rustfmt"));
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_invalid_log_bundle_hash() {
        let sha = "7".repeat(40);
        let mut results = seed_required_pass_results();
        let rustfmt = results
            .iter_mut()
            .find(|result| result.gate_name == "rustfmt")
            .expect("rustfmt row");
        rustfmt.log_bundle_hash = Some("b3-256:nothex".to_string());

        let err = run_blocking_evidence_gates_with(&sha, || {
            Ok(queued_outcome_with(
                "gates-test-invalid-log-bundle-hash",
                &sha,
                results.clone(),
            ))
        })
        .expect_err("invalid log bundle hash must fail closed");
        assert!(err.contains("log bundle hashes"));
        assert!(err.contains("rustfmt"));
    }

    #[test]
    fn dispatch_reviews_with_dispatches_security_then_quality() {
        let mut dispatched = Vec::new();
        let mut registered = Vec::new();
        let result = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "a".repeat(40).as_str(),
            |_, _, kind, _, _| {
                dispatched.push(kind.as_str().to_string());
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode: "dispatched".to_string(),
                    run_state: "pending".to_string(),
                    run_id: Some(format!("{}-run-1", kind.as_str())),
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    proc_start_time: None,
                    unit: None,
                    log_file: None,
                })
            },
            |_, _, _, review_type, run_id, _, _| {
                registered.push((review_type.to_string(), run_id.map(str::to_string)));
                Ok(Some(format!("{review_type}-token")))
            },
            false,
        );

        let dispatched_results = result.expect("dispatch should succeed");
        assert_eq!(dispatched_results.len(), 2);
        assert_eq!(dispatched, vec!["security", "quality"]);
        assert_eq!(registered.len(), 2);
        assert_eq!(registered[0].0, "security");
        assert_eq!(registered[1].0, "quality");
        assert_eq!(registered[0].1.as_deref(), Some("security-run-1"));
        assert_eq!(registered[1].1.as_deref(), Some("quality-run-1"));
    }

    #[test]
    fn dispatch_reviews_with_fails_closed_after_retry_budget_exhaustion() {
        let mut calls = 0usize;
        let err = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "b".repeat(40).as_str(),
            |_, _, kind, _, _| {
                calls += 1;
                if kind == ReviewKind::Security {
                    return Err("temporary dispatch failure".to_string());
                }
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode: "dispatched".to_string(),
                    run_state: "pending".to_string(),
                    run_id: Some(format!("{}-run-1", kind.as_str())),
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    proc_start_time: None,
                    unit: None,
                    log_file: None,
                })
            },
            |_, _, _, review_type, _, _, _| Ok(Some(format!("{review_type}-token"))),
            false,
        )
        .expect_err("expected dispatch failure");

        assert!(err.contains("exhausting retry budget"));
        assert_eq!(calls, (lifecycle::default_retry_budget() as usize) + 1);
    }

    #[test]
    fn dispatch_reviews_with_fails_fast_on_integrity_error() {
        let mut calls = 0usize;
        let err = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "c".repeat(40).as_str(),
            |_, _, kind, _, _| {
                calls += 1;
                if kind == ReviewKind::Security {
                    return Err("illegal transition: untracked + reviewer_spawned".to_string());
                }
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode: "dispatched".to_string(),
                    run_state: "pending".to_string(),
                    run_id: Some(format!("{}-run-1", kind.as_str())),
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    proc_start_time: None,
                    unit: None,
                    log_file: None,
                })
            },
            |_, _, _, review_type, _, _, _| Ok(Some(format!("{review_type}-token"))),
            false,
        )
        .expect_err("expected fail-fast integrity failure");

        assert!(err.contains("class=integrity_or_schema"));
        assert_eq!(calls, 1);
    }

    #[test]
    fn dispatch_reviews_with_fails_fast_on_at_capacity_registration_error() {
        let mut register_calls = 0usize;
        let err = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "2".repeat(40).as_str(),
            |_, _, kind, _, _| {
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode: "dispatched".to_string(),
                    run_state: "pending".to_string(),
                    run_id: Some(format!("{}-run-1", kind.as_str())),
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    proc_start_time: None,
                    unit: None,
                    log_file: None,
                })
            },
            |_, _, _, _, _, _, _| {
                register_calls += 1;
                Err("at_capacity: PR #42 already has 2 active agents (max=2)".to_string())
            },
            false,
        )
        .expect_err("at_capacity must fail fast and not retry");

        assert!(err.contains("class=integrity_or_schema"));
        assert_eq!(register_calls, 1);
    }

    #[test]
    fn dispatch_reviews_with_retries_missing_run_id_then_succeeds() {
        let mut security_dispatch_calls = 0usize;
        let mut quality_dispatch_calls = 0usize;
        let mut register_calls = 0usize;
        let result = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "d".repeat(40).as_str(),
            |_, _, kind, _, _| {
                let (mode, run_id) = match kind {
                    ReviewKind::Security => {
                        security_dispatch_calls += 1;
                        if security_dispatch_calls <= 2 {
                            ("dispatched".to_string(), None)
                        } else {
                            ("dispatched".to_string(), Some("security-run-3".to_string()))
                        }
                    },
                    ReviewKind::Quality => {
                        quality_dispatch_calls += 1;
                        ("dispatched".to_string(), Some("quality-run-1".to_string()))
                    },
                };
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode,
                    run_state: "pending".to_string(),
                    run_id,
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    proc_start_time: None,
                    unit: None,
                    log_file: None,
                })
            },
            |_, _, _, _, _, _, _| {
                register_calls += 1;
                Ok(Some("token".to_string()))
            },
            false,
        );

        let dispatched_results = result.expect("dispatch should succeed");
        assert_eq!(dispatched_results.len(), 2);
        assert_eq!(security_dispatch_calls, 3);
        assert_eq!(quality_dispatch_calls, 1);
        assert_eq!(register_calls, 2);
    }

    #[test]
    fn dispatch_reviews_with_retries_joined_non_terminal_missing_run_id_then_succeeds() {
        let mut security_dispatch_calls = 0usize;
        let mut quality_dispatch_calls = 0usize;
        let mut register_calls = 0usize;
        let result = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "11".repeat(20).as_str(),
            |_, _, kind, _, _| match kind {
                ReviewKind::Security => {
                    security_dispatch_calls += 1;
                    if security_dispatch_calls == 1 {
                        Ok(DispatchReviewResult {
                            review_type: "security".to_string(),
                            mode: "joined".to_string(),
                            run_state: "running".to_string(),
                            run_id: None,
                            sequence_number: Some(2),
                            terminal_reason: None,
                            pid: None,
                            proc_start_time: None,
                            unit: Some("apm2-review-security@42.service".to_string()),
                            log_file: None,
                        })
                    } else {
                        Ok(DispatchReviewResult {
                            review_type: "security".to_string(),
                            mode: "joined".to_string(),
                            run_state: "running".to_string(),
                            run_id: Some("security-run-2".to_string()),
                            sequence_number: Some(2),
                            terminal_reason: None,
                            pid: None,
                            proc_start_time: None,
                            unit: Some("apm2-review-security@42.service".to_string()),
                            log_file: None,
                        })
                    }
                },
                ReviewKind::Quality => {
                    quality_dispatch_calls += 1;
                    Ok(DispatchReviewResult {
                        review_type: "quality".to_string(),
                        mode: "dispatched".to_string(),
                        run_state: "pending".to_string(),
                        run_id: Some("quality-run-1".to_string()),
                        sequence_number: None,
                        terminal_reason: None,
                        pid: None,
                        proc_start_time: None,
                        unit: None,
                        log_file: None,
                    })
                },
            },
            |_, _, _, _, _, _, _| {
                register_calls += 1;
                Ok(Some("token".to_string()))
            },
            false,
        );

        let dispatched_results = result.expect("dispatch should succeed");
        assert_eq!(dispatched_results.len(), 2);
        assert_eq!(security_dispatch_calls, 2);
        assert_eq!(quality_dispatch_calls, 1);
        assert_eq!(
            register_calls, 1,
            "joined reviewer should not attempt lifecycle registration"
        );
    }

    #[test]
    fn dispatch_reviews_with_joined_terminal_done_missing_run_id_does_not_retry() {
        let mut security_dispatch_calls = 0usize;
        let mut quality_dispatch_calls = 0usize;
        let mut register_calls = 0usize;
        let result = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "22".repeat(20).as_str(),
            |_, _, kind, _, _| match kind {
                ReviewKind::Security => {
                    security_dispatch_calls += 1;
                    Ok(DispatchReviewResult {
                        review_type: "security".to_string(),
                        mode: "joined".to_string(),
                        run_state: "done".to_string(),
                        run_id: None,
                        sequence_number: Some(4),
                        terminal_reason: Some("completed".to_string()),
                        pid: None,
                        proc_start_time: None,
                        unit: None,
                        log_file: None,
                    })
                },
                ReviewKind::Quality => {
                    quality_dispatch_calls += 1;
                    Ok(DispatchReviewResult {
                        review_type: "quality".to_string(),
                        mode: "dispatched".to_string(),
                        run_state: "pending".to_string(),
                        run_id: Some("quality-run-1".to_string()),
                        sequence_number: None,
                        terminal_reason: None,
                        pid: None,
                        proc_start_time: None,
                        unit: None,
                        log_file: None,
                    })
                },
            },
            |_, _, _, _, _, _, _| {
                register_calls += 1;
                Ok(Some("token".to_string()))
            },
            false,
        );

        let dispatched_results = result.expect("dispatch should succeed");
        assert_eq!(dispatched_results.len(), 2);
        assert_eq!(
            security_dispatch_calls, 1,
            "terminal joined state should not retry when run_id is missing"
        );
        assert_eq!(quality_dispatch_calls, 1);
        assert_eq!(
            register_calls, 1,
            "only non-joined dispatch should register lifecycle"
        );
    }

    #[test]
    fn dispatch_reviews_with_retries_registration_failures_then_succeeds() {
        let mut dispatch_calls = 0usize;
        let mut security_register_calls = 0usize;
        let result = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "e".repeat(40).as_str(),
            |_, _, kind, _, _| {
                dispatch_calls += 1;
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode: "dispatched".to_string(),
                    run_state: "pending".to_string(),
                    run_id: Some(format!("{}-run-1", kind.as_str())),
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    proc_start_time: None,
                    unit: None,
                    log_file: None,
                })
            },
            |_, _, _, review_type, _, _, _| {
                if review_type == "security" {
                    security_register_calls += 1;
                    if security_register_calls <= 2 {
                        return Err("failed to acquire registry lock".to_string());
                    }
                }
                Ok(Some("token".to_string()))
            },
            false,
        );

        let dispatched_results = result.expect("dispatch should succeed");
        assert_eq!(dispatched_results.len(), 2);
        assert_eq!(dispatch_calls, 2);
        assert_eq!(security_register_calls, 3);
    }

    #[test]
    fn dispatch_reviews_with_uses_independent_error_class_budgets() {
        let mut security_dispatch_calls = 0usize;
        let mut security_register_calls = 0usize;
        let result = dispatch_reviews_with(
            "guardian-intelligence/apm2",
            42,
            "f".repeat(40).as_str(),
            |_, _, kind, _, _| {
                if kind == ReviewKind::Security {
                    security_dispatch_calls += 1;
                    if security_dispatch_calls == 1 {
                        return Err("temporary dispatch queue saturation".to_string());
                    }
                    if security_dispatch_calls == 2 {
                        return Ok(DispatchReviewResult {
                            review_type: kind.as_str().to_string(),
                            mode: "dispatched".to_string(),
                            run_state: "pending".to_string(),
                            run_id: None,
                            sequence_number: None,
                            terminal_reason: None,
                            pid: None,
                            proc_start_time: None,
                            unit: None,
                            log_file: None,
                        });
                    }
                }
                Ok(DispatchReviewResult {
                    review_type: kind.as_str().to_string(),
                    mode: "dispatched".to_string(),
                    run_state: "pending".to_string(),
                    run_id: Some(format!("{}-run-{}", kind.as_str(), security_dispatch_calls)),
                    sequence_number: None,
                    terminal_reason: None,
                    pid: None,
                    proc_start_time: None,
                    unit: None,
                    log_file: None,
                })
            },
            |_, _, _, review_type, _, _, _| {
                if review_type == "security" {
                    security_register_calls += 1;
                    if security_register_calls == 1 {
                        return Err("failed to acquire registry lock".to_string());
                    }
                }
                Ok(Some("token".to_string()))
            },
            false,
        );

        let dispatched_results = result.expect("dispatch should succeed");
        assert_eq!(dispatched_results.len(), 2);
        assert_eq!(security_dispatch_calls, 3);
        assert_eq!(security_register_calls, 2);
    }

    #[test]
    fn dispatch_results_are_all_joined_terminal_requires_all_terminal_joined() {
        let joined_terminal = vec![
            DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "joined".to_string(),
                run_state: "done".to_string(),
                run_id: Some("security-run-4".to_string()),
                sequence_number: Some(4),
                terminal_reason: Some("completed".to_string()),
                pid: None,
                proc_start_time: None,
                unit: None,
                log_file: None,
            },
            DispatchReviewResult {
                review_type: "quality".to_string(),
                mode: "joined".to_string(),
                run_state: "failed".to_string(),
                run_id: Some("quality-run-5".to_string()),
                sequence_number: Some(5),
                terminal_reason: Some("gate_failed".to_string()),
                pid: None,
                proc_start_time: None,
                unit: None,
                log_file: None,
            },
        ];
        assert!(dispatch_results_are_all_joined_terminal(&joined_terminal));

        let mut non_terminal = joined_terminal.clone();
        non_terminal[1].run_state = "running".to_string();
        assert!(!dispatch_results_are_all_joined_terminal(&non_terminal));

        let mut non_joined = joined_terminal;
        non_joined[1].mode = "started".to_string();
        assert!(!dispatch_results_are_all_joined_terminal(&non_joined));
    }

    #[test]
    fn should_force_projection_binding_repair_only_for_missing_binding_on_terminal_join() {
        let dispatch_results = vec![
            DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "joined".to_string(),
                run_state: "done".to_string(),
                run_id: Some("security-run-4".to_string()),
                sequence_number: Some(4),
                terminal_reason: Some("completed".to_string()),
                pid: None,
                proc_start_time: None,
                unit: None,
                log_file: None,
            },
            DispatchReviewResult {
                review_type: "quality".to_string(),
                mode: "joined".to_string(),
                run_state: "done".to_string(),
                run_id: Some("quality-run-4".to_string()),
                sequence_number: Some(4),
                terminal_reason: Some("completed".to_string()),
                pid: None,
                proc_start_time: None,
                unit: None,
                log_file: None,
            },
        ];

        assert!(should_force_projection_binding_repair(
            &dispatch_results,
            true,
            false
        ));
        assert!(!should_force_projection_binding_repair(
            &dispatch_results,
            true,
            true
        ));
        assert!(!should_force_projection_binding_repair(
            &dispatch_results,
            false,
            false
        ));
    }
}
