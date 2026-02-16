//! Lean `run_push` pipeline: git push → blocking gates → PR/update → dispatch.
//!
//! Bridge module: combines FAC core gate orchestration with projection-layer
//! PR management through `github_projection`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use super::dispatch::dispatch_single_review;
use super::evidence::{
    EvidenceGateOptions, EvidenceGateResult, LANE_EVIDENCE_GATES, run_evidence_gates,
    run_evidence_gates_with_status,
};
use super::gate_cache::GateCache;
use super::jsonl::{
    GateCompletedEvent, GateErrorEvent, StageEvent, emit_jsonl, read_log_error_hint, ts_now,
};
use super::projection::{GateResult, sync_gate_status_to_pr};
use super::types::{
    DispatchReviewResult, ReviewKind, apm2_home_dir, ensure_parent_dir, now_iso8601,
    sanitize_for_path,
};
use super::{github_projection, lifecycle, projection_store, state};
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

/// Extract `TCK-xxxxx` from arbitrary text.
fn extract_tck_from_text(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    if bytes.len() < 9 {
        return None;
    }

    for idx in 0..=bytes.len() - 9 {
        if &bytes[idx..idx + 4] != b"TCK-" {
            continue;
        }

        let digits = &bytes[idx + 4..idx + 9];
        if !digits.iter().all(u8::is_ascii_digit) {
            continue;
        }

        if idx + 9 < bytes.len() && bytes[idx + 9].is_ascii_digit() {
            continue;
        }

        let matched = std::str::from_utf8(&bytes[idx..idx + 9]).ok()?;
        return Some(matched.to_string());
    }

    None
}

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

/// Enable auto-merge (merge commit) on a PR.
fn enable_auto_merge(repo: &str, pr_number: u32) -> Result<(), String> {
    github_projection::enable_auto_merge(repo, pr_number)
}

#[cfg(test)]
fn ensure_evidence_gates_pass_with<F>(
    workspace_root: &Path,
    sha: &str,
    mut run_gates_fn: F,
) -> Result<Vec<EvidenceGateResult>, String>
where
    F: FnMut(&Path, &str) -> Result<(bool, Vec<EvidenceGateResult>), String>,
{
    let (passed, results) = run_gates_fn(workspace_root, sha)?;
    if passed {
        return Ok(results);
    }

    let failed_gates = results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.gate_name.as_str())
        .collect::<Vec<_>>();
    let failed_summary = if failed_gates.is_empty() {
        "unknown".to_string()
    } else {
        failed_gates.join(",")
    };
    Err(format!(
        "evidence gates failed for sha={sha}; failing gates: {failed_summary}"
    ))
}

fn run_blocking_evidence_gates(
    workspace_root: &Path,
    sha: &str,
    owner_repo: &str,
    pr_number: Option<u32>,
    emit_human_logs: bool,
) -> Result<Vec<EvidenceGateResult>, String> {
    run_blocking_evidence_gates_with(
        workspace_root,
        sha,
        owner_repo,
        pr_number,
        |workspace_root, sha, owner_repo, pr_number| {
            pr_number.map_or_else(
                || {
                    let opts = EvidenceGateOptions {
                        test_command: None,
                        test_command_environment: Vec::new(),
                        env_remove_keys: Vec::new(),
                        skip_test_gate: false,
                        skip_merge_conflict_gate: false,
                        emit_human_logs,
                        on_gate_progress: None,
                    };
                    run_evidence_gates(workspace_root, sha, None, Some(&opts))
                },
                |pr_number| {
                    run_evidence_gates_with_status(
                        workspace_root,
                        sha,
                        owner_repo,
                        pr_number,
                        None,
                        emit_human_logs,
                        None,
                    )
                },
            )
        },
    )
}

fn run_blocking_evidence_gates_with<F>(
    workspace_root: &Path,
    sha: &str,
    owner_repo: &str,
    pr_number: Option<u32>,
    mut run_with_status_fn: F,
) -> Result<Vec<EvidenceGateResult>, String>
where
    F: FnMut(&Path, &str, &str, Option<u32>) -> Result<(bool, Vec<EvidenceGateResult>), String>,
{
    let (passed, mut gate_results) =
        run_with_status_fn(workspace_root, sha, owner_repo, pr_number)?;

    if passed {
        validate_gate_results_for_pass(workspace_root, sha, &gate_results)?;
        return Ok(gate_results);
    }

    let failed_gates = gate_results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.gate_name.as_str())
        .collect::<Vec<_>>();
    let failed_summary = if failed_gates.is_empty() {
        "unknown".to_string()
    } else {
        failed_gates.join(",")
    };
    if gate_results.is_empty() {
        gate_results.push(EvidenceGateResult {
            gate_name: "unknown".to_string(),
            passed: false,
            duration_secs: 0,
            ..Default::default()
        });
    }
    Err(format!(
        "evidence gates failed for sha={sha}; failing gates: {failed_summary}"
    ))
}

fn expected_gate_names_for_workspace(workspace_root: &Path) -> BTreeSet<String> {
    let mut expected = BTreeSet::from([
        "merge_conflict_main".to_string(),
        "rustfmt".to_string(),
        "clippy".to_string(),
        "doc".to_string(),
        "test".to_string(),
        "workspace_integrity".to_string(),
    ]);
    if workspace_root
        .join("scripts/ci/test_safety_guard.sh")
        .exists()
    {
        expected.insert("test_safety_guard".to_string());
    }
    if workspace_root
        .join("scripts/ci/review_artifact_lint.sh")
        .exists()
    {
        expected.insert("review_artifact_lint".to_string());
    }
    expected
}

fn validate_gate_results_for_pass(
    workspace_root: &Path,
    sha: &str,
    gate_results: &[EvidenceGateResult],
) -> Result<(), String> {
    if gate_results.is_empty() {
        return Err(format!(
            "evidence gates reported PASS for sha={sha} but no gate result artifacts were found; refusing to project empty gate status"
        ));
    }

    let failed_gates = gate_results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| result.gate_name.as_str())
        .collect::<Vec<_>>();
    if !failed_gates.is_empty() {
        return Err(format!(
            "evidence gates reported PASS for sha={sha} but reported gate rows include FAIL verdicts: {}; refusing inconsistent gate projection",
            failed_gates.join(",")
        ));
    }

    let actual = gate_results
        .iter()
        .map(|result| result.gate_name.clone())
        .collect::<BTreeSet<_>>();
    let expected = expected_gate_names_for_workspace(workspace_root);
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

fn dispatch_reviews_with<F, R>(
    repo: &str,
    pr_number: u32,
    sha: &str,
    mut dispatch_fn: F,
    mut register_dispatch_fn: R,
    emit_logs: bool,
) -> Result<(), String>
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
    }

    Ok(())
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
    pub schema: String,
    pub ts: String,
    pub sha: String,
    pub git_push: PushAttemptStage,
    pub gate_fmt: PushAttemptStage,
    pub gate_clippy: PushAttemptStage,
    pub gate_test: PushAttemptStage,
    pub gate_doc: PushAttemptStage,
    pub pr_update: PushAttemptStage,
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
            ("git_push", &self.git_push),
            ("gate_fmt", &self.gate_fmt),
            ("gate_clippy", &self.gate_clippy),
            ("gate_test", &self.gate_test),
            ("gate_doc", &self.gate_doc),
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

fn skipped_stage() -> PushAttemptStage {
    PushAttemptStage {
        status: PUSH_STAGE_SKIPPED.to_string(),
        duration_s: 0,
        exit_code: None,
        error_hint: None,
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
        let record = serde_json::from_str::<PushAttemptRecord>(&line).map_err(|err| {
            format!(
                "failed to parse line {} in push attempt log {}: {err}",
                line_number + 1,
                path.display()
            )
        })?;
        if !record.sha.eq_ignore_ascii_case(sha) {
            continue;
        }
        latest = Some(record);
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

pub fn run_push(
    repo: &str,
    remote: &str,
    branch: Option<&str>,
    ticket: Option<&Path>,
    json_output: bool,
) -> u8 {
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

    // Step 1: git push (always force; local branch truth is authoritative).
    let git_push_started = Instant::now();
    let push_output = Command::new("git")
        .args(["push", "--force", remote, &branch])
        .output();
    match push_output {
        Ok(o) if o.status.success() => {
            let duration_secs = git_push_started.elapsed().as_secs();
            attempt.set_stage_pass("git_push", duration_secs);
            emit_stage(
                "git_push_completed",
                serde_json::json!({
                    "status": "pass",
                    "duration_secs": duration_secs,
                }),
            );
            human_log!("fac push: git push --force succeeded");
        },
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let duration_secs = git_push_started.elapsed().as_secs();
            attempt.set_stage_fail(
                "git_push",
                duration_secs,
                o.status.code(),
                normalize_error_hint(&stderr),
            );
            emit_stage(
                "git_push_completed",
                serde_json::json!({
                    "status": "fail",
                    "duration_secs": duration_secs,
                    "error": stderr.trim(),
                }),
            );
            fail_with_attempt!(
                "fac_push_git_push_failed",
                format!("git push --force failed: {stderr}")
            );
        },
        Err(e) => {
            let duration_secs = git_push_started.elapsed().as_secs();
            attempt.set_stage_fail(
                "git_push",
                duration_secs,
                None,
                normalize_error_hint(&e.to_string()),
            );
            emit_stage(
                "git_push_completed",
                serde_json::json!({
                    "status": "error",
                    "duration_secs": duration_secs,
                    "error": e.to_string(),
                }),
            );
            fail_with_attempt!(
                "fac_push_git_push_exec_failed",
                format!("failed to execute git push --force: {e}")
            );
        },
    }

    // Step 2: run evidence gates synchronously with cache-aware status path.
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

    let existing_pr_number = find_existing_pr(repo, &branch);
    attempt_pr_number = existing_pr_number;
    human_log!("fac push: running evidence gates (blocking, cache-aware)");
    emit_stage("gates_started", serde_json::json!({}));
    let gates_started = Instant::now();
    let gate_results = match run_blocking_evidence_gates(
        &worktree_dir,
        &sha,
        repo,
        (existing_pr_number > 0).then_some(existing_pr_number),
        !json_output,
    ) {
        Ok(results) => {
            for gate in &results {
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
                    attempt.set_stage_fail(stage, gate.duration_secs, None, error_hint.clone());
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
            results
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
                        let hint = latest_gate_error_hint(&gate_name)
                            .or_else(|| normalize_error_hint(&format!("gate {gate_name} failed")));
                        attempt.set_stage_fail(stage, gate_result.duration_secs, None, hint);
                    }
                    if json_output {
                        let normalized_status = gate_result.status.to_ascii_lowercase();
                        let log_path = gate_result.log_path.clone();
                        let error_hint = if gate_result.status.eq_ignore_ascii_case("PASS") {
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
                                error: error_hint.unwrap_or_else(|| "gate failed".to_string()),
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
                for stage in ["gate_fmt", "gate_clippy", "gate_test", "gate_doc"] {
                    attempt.set_stage_fail(stage, duration, None, normalize_error_hint(&err));
                }
                if json_output {
                    let _ = emit_jsonl(&GateErrorEvent {
                        event: "gate_error",
                        gate: "unknown".to_string(),
                        error: normalize_error_hint(&err).unwrap_or_else(|| err.clone()),
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
            if existing_pr_number > 0 {
                if let Err(state_err) = lifecycle::apply_event(
                    repo,
                    existing_pr_number,
                    &sha,
                    &lifecycle::LifecycleEventKind::PushObserved,
                ) {
                    human_log!(
                        "WARNING: failed to record push_observed lifecycle event for PR #{existing_pr_number}: {state_err}",
                    );
                }
                if let Err(state_err) = lifecycle::apply_event(
                    repo,
                    existing_pr_number,
                    &sha,
                    &lifecycle::LifecycleEventKind::GatesStarted,
                ) {
                    human_log!(
                        "WARNING: failed to record gates_started lifecycle event for PR #{existing_pr_number}: {state_err}",
                    );
                }
                if let Err(state_err) = lifecycle::apply_event(
                    repo,
                    existing_pr_number,
                    &sha,
                    &lifecycle::LifecycleEventKind::GatesFailed,
                ) {
                    human_log!(
                        "WARNING: failed to record gates_failed lifecycle event for PR #{existing_pr_number}: {state_err}",
                    );
                }
            }
            fail_with_attempt!("fac_push_gates_failed", err);
        },
    };
    emit_stage(
        "gates_completed",
        serde_json::json!({
            "passed": true,
            "duration_secs": gates_started.elapsed().as_secs(),
        }),
    );
    human_log!("fac push: evidence gates PASSED");

    // Step 3: create or update PR.
    let pr_update_started = Instant::now();
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
    emit_stage(
        "pr_updated",
        serde_json::json!({
            "pr_number": pr_number,
            "url": format!("https://github.com/{repo}/pull/{pr_number}"),
        }),
    );

    if let Err(err) = lifecycle::apply_event(
        repo,
        pr_number,
        &sha,
        &lifecycle::LifecycleEventKind::PushObserved,
    ) {
        fail_with_attempt!(
            "fac_push_lifecycle_push_observed_failed",
            format!("failed to record push lifecycle event: {err}")
        );
    }
    if let Err(err) = lifecycle::apply_event(
        repo,
        pr_number,
        &sha,
        &lifecycle::LifecycleEventKind::GatesStarted,
    ) {
        fail_with_attempt!(
            "fac_push_lifecycle_gates_started_failed",
            format!("failed to record gates_started lifecycle event: {err}")
        );
    }
    if let Err(err) = lifecycle::apply_event(
        repo,
        pr_number,
        &sha,
        &lifecycle::LifecycleEventKind::GatesPassed,
    ) {
        fail_with_attempt!(
            "fac_push_lifecycle_gates_passed_failed",
            format!("failed to record gates_passed lifecycle event: {err}")
        );
    }

    // Step 4: sync gate status section to PR body (best-effort).
    let gate_status_rows = gate_results
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
    }

    // Step 5: enable auto-merge.
    if let Err(e) = enable_auto_merge(repo, pr_number) {
        human_log!("WARNING: auto-merge enable failed: {e}");
    } else {
        human_log!("fac push: auto-merge enabled on PR #{pr_number}");
    }

    // Step 6: dispatch reviews.
    //
    // Intentional: dispatch failures are non-fatal for `fac push`. Push owns
    // publication and gate validation; reviewer liveness and retry are handled
    // by restart/recover lifecycle surfaces.
    let dispatch_started = Instant::now();
    emit_stage("dispatch_started", serde_json::json!({}));
    let mut emitted_reviews_dispatched = false;
    let dispatch_warning = if let Err(e) = dispatch_reviews_with(
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
        attempt.set_stage_fail(
            "dispatch",
            dispatch_started.elapsed().as_secs(),
            None,
            normalize_error_hint(&e),
        );
        human_log!("WARNING: review dispatch failed: {e}");
        human_log!("  Use `apm2 fac restart --pr {pr_number}` to retry.");
        Some(e)
    } else {
        attempt.set_stage_pass("dispatch", dispatch_started.elapsed().as_secs());
        None
    };
    let has_dispatch_warning = dispatch_warning.is_some();
    emit_stage(
        "dispatch_completed",
        serde_json::json!({
            "status": if has_dispatch_warning { "warn" } else { "pass" },
            "duration_secs": dispatch_started.elapsed().as_secs(),
            "warning": dispatch_warning.as_deref(),
        }),
    );

    // Step 7: persist projection identity only after gates + dispatch attempt.
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
        human_log!("  review dispatch warning surfaced; rerun: apm2 fac restart --pr {pr_number}");
    } else {
        human_log!("  if review dispatch stalls: apm2 fac restart --pr {pr_number}");
    }
    exit_codes::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

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

    fn seed_required_pass_results(workspace_root: &Path) -> Vec<EvidenceGateResult> {
        expected_gate_names_for_workspace(workspace_root)
            .into_iter()
            .map(|gate_name| EvidenceGateResult {
                gate_name,
                passed: true,
                duration_secs: 1,
                ..Default::default()
            })
            .collect()
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
    fn ensure_evidence_gates_pass_with_accepts_pass_result() {
        let result =
            ensure_evidence_gates_pass_with(Path::new("/tmp"), "a".repeat(40).as_str(), |_, _| {
                Ok((true, Vec::new()))
            });
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_evidence_gates_pass_with_reports_failed_gate_names() {
        let result =
            ensure_evidence_gates_pass_with(Path::new("/tmp"), "b".repeat(40).as_str(), |_, _| {
                Ok((
                    false,
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
                        EvidenceGateResult {
                            gate_name: "doc".to_string(),
                            passed: false,
                            duration_secs: 3,
                            ..Default::default()
                        },
                    ],
                ))
            })
            .expect_err("expected failure");

        assert!(result.contains("rustfmt"));
        assert!(result.contains("doc"));
        assert!(!result.contains("clippy"));
    }

    #[test]
    fn run_blocking_evidence_gates_with_returns_reported_results_for_pass() {
        let sha = "c".repeat(40);
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace_root = temp.path();
        let results = seed_required_pass_results(workspace_root);

        let result = run_blocking_evidence_gates_with(
            workspace_root,
            &sha,
            "guardian-intelligence/apm2",
            Some(615),
            |_, _, _, _| Ok((true, results.clone())),
        )
        .expect("pass should return reported rows");

        assert_eq!(
            result.len(),
            expected_gate_names_for_workspace(workspace_root).len()
        );
        assert!(result.iter().all(|gate| gate.passed));
    }

    #[test]
    fn run_blocking_evidence_gates_with_fails_closed_when_pass_without_gate_artifacts() {
        let sha = "d".repeat(40);
        let err = run_blocking_evidence_gates_with(
            Path::new("/tmp"),
            &sha,
            "guardian-intelligence/apm2",
            Some(616),
            |_, _, _, _| Ok((true, Vec::new())),
        )
        .expect_err("missing gate artifacts on PASS must fail closed");
        assert!(err.contains("no gate result artifacts"));
        assert!(err.contains(&sha));
    }

    #[test]
    fn run_blocking_evidence_gates_with_reports_failed_gate_names() {
        let sha = "e".repeat(40);
        let err = run_blocking_evidence_gates_with(
            Path::new("/tmp"),
            &sha,
            "guardian-intelligence/apm2",
            Some(617),
            |_, _, _, _| {
                Ok((
                    false,
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
            },
        )
        .expect_err("failed gate should surface reported failing names");
        assert!(err.contains("rustfmt"));
        assert!(!err.contains("clippy"));
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_pass_when_reported_row_is_fail() {
        let sha = "f".repeat(40);
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace_root = temp.path();
        let mut results = seed_required_pass_results(workspace_root);
        let rustfmt = results
            .iter_mut()
            .find(|result| result.gate_name == "rustfmt")
            .expect("rustfmt row");
        rustfmt.passed = false;

        let err = run_blocking_evidence_gates_with(
            workspace_root,
            &sha,
            "guardian-intelligence/apm2",
            Some(618),
            |_, _, _, _| Ok((true, results.clone())),
        )
        .expect_err("pass path must fail when reported gate row is FAIL");
        assert!(err.contains("reported gate rows include FAIL"));
        assert!(err.contains("rustfmt"));
    }

    #[test]
    fn run_blocking_evidence_gates_with_rejects_incomplete_results_on_pass() {
        let sha = "1".repeat(40);
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace_root = temp.path();
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

        let err = run_blocking_evidence_gates_with(
            workspace_root,
            &sha,
            "guardian-intelligence/apm2",
            Some(619),
            |_, _, _, _| Ok((true, incomplete_results.clone())),
        )
        .expect_err("pass path must fail on incomplete reported gate set");
        assert!(err.contains("required gate set"));
        assert!(err.contains("missing="));
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

        assert!(result.is_ok());
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

        assert!(result.is_ok());
        assert_eq!(security_dispatch_calls, 3);
        assert_eq!(quality_dispatch_calls, 1);
        assert_eq!(register_calls, 2);
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

        assert!(result.is_ok());
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

        assert!(result.is_ok());
        assert_eq!(security_dispatch_calls, 3);
        assert_eq!(security_register_calls, 2);
    }
}
