//! Privileged FAC recovery flows.
//!
//! Recovery intentionally bypasses reducer transition validation and pre-write
//! HMAC verification so operators can repair corrupt/stuck local state.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::projection::fetch_pr_head_sha_authoritative;
use super::state::{self, ReviewRunStateLoad};
use super::target::resolve_pr_target;
use super::types::{
    ReviewRunState, ReviewRunStatus, TERMINAL_REPAIR_STATE_REBUILT, apm2_home_dir, now_iso8601,
    now_iso8601_millis, validate_expected_head_sha,
};
use super::{lifecycle, projection_store};

const REPAIR_SUMMARY_SCHEMA: &str = "apm2.fac.repair_summary.v1";
const OPERATION_REPAIR_RUN_STATE: &str = "repair_run_state";
const OPERATION_REPAIR_REGISTRY: &str = "repair_registry_integrity";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum RunStateRepairCondition {
    Missing,
    Corrupt,
    Ambiguous,
    InconsistentRuntimeHandle,
}

impl RunStateRepairCondition {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
            Self::Ambiguous => "ambiguous",
            Self::InconsistentRuntimeHandle => "inconsistent_runtime_handle",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum RunStateRepairAction {
    BaselineCreated,
    Canonicalized,
    RebuiltFromCandidate,
    RebuiltFromPresent,
}

impl RunStateRepairAction {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::BaselineCreated => "baseline_created",
            Self::Canonicalized => "canonicalized",
            Self::RebuiltFromCandidate => "rebuilt_from_candidate",
            Self::RebuiltFromPresent => "rebuilt_from_present",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct RunStateRepairSnapshot {
    run_id: String,
    sequence_number: u32,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RunStateRepairOutcome {
    review_type: String,
    condition: RunStateRepairCondition,
    action: RunStateRepairAction,
    canonical_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_candidate: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    quarantined_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<RunStateRepairSnapshot>,
    after: RunStateRepairSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RepairSummary {
    schema: String,
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    requested_operations: Vec<String>,
    applied_operations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reaped_agents: Option<lifecycle::BypassReapOutcome>,
    refreshed_identity: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle_reset: Option<lifecycle::BypassLifecycleResetOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_repair: Option<lifecycle::BypassRegistryRepairOutcome>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    run_state_repairs: Vec<RunStateRepairOutcome>,
}

impl RepairSummary {
    pub(super) fn into_doctor_repairs(self) -> Vec<super::DoctorRepairApplied> {
        let mut repairs = Vec::new();
        if let Some(reaped) = self.reaped_agents {
            repairs.push(super::DoctorRepairApplied {
                operation: "reap_stale_agents".to_string(),
                before: Some(format!("active_agents={}", reaped.before_active_agents)),
                after: Some(format!("active_agents={}", reaped.after_active_agents)),
            });
        }
        if self.refreshed_identity {
            repairs.push(super::DoctorRepairApplied {
                operation: "refresh_identity".to_string(),
                before: None,
                after: Some("identity_refreshed".to_string()),
            });
        }
        if let Some(reset) = self.lifecycle_reset {
            repairs.push(super::DoctorRepairApplied {
                operation: "reset_lifecycle".to_string(),
                before: Some(reset.before_state),
                after: Some(reset.after_state),
            });
        }
        if let Some(registry) = self.registry_repair {
            let before = format!(
                "active_agents={} total_entries={}",
                registry.before_active_agents, registry.before_total_entries
            );
            let mut after = format!(
                "active_agents={} total_entries={} reaped_agents={}",
                registry.after_active_agents, registry.after_total_entries, registry.reaped_agents
            );
            if let Some(path) = registry.quarantined_registry_path.as_deref() {
                let _ = write!(after, " quarantined={path}");
            }
            if let Some(reason) = registry.quarantine_reason.as_deref() {
                let _ = write!(after, " quarantine_reason={reason}");
            }
            repairs.push(super::DoctorRepairApplied {
                operation: OPERATION_REPAIR_REGISTRY.to_string(),
                before: Some(before),
                after: Some(after),
            });
        }
        for repair in self.run_state_repairs {
            let before = repair.before.as_ref().map(|snapshot| {
                format!(
                    "seq={} status={} run_id={}",
                    snapshot.sequence_number, snapshot.status, snapshot.run_id
                )
            });
            let after = Some(format!(
                "condition={} action={} seq={} status={} run_id={}",
                repair.condition.as_str(),
                repair.action.as_str(),
                repair.after.sequence_number,
                repair.after.status,
                repair.after.run_id
            ));
            repairs.push(super::DoctorRepairApplied {
                operation: format!("repair_run_state:{}", repair.review_type),
                before,
                after,
            });
        }
        repairs
    }
}

#[allow(clippy::fn_params_excessive_bools)]
const fn resolve_operation_set(
    refresh_identity: bool,
    reap_stale_agents: bool,
    reset_lifecycle: bool,
    repair_registry_integrity: bool,
    all: bool,
    run_state_repair_requested: bool,
) -> (bool, bool, bool, bool) {
    let mut do_reap = reap_stale_agents;
    let mut do_refresh = refresh_identity;
    let mut do_reset = reset_lifecycle;
    let mut do_repair_registry = repair_registry_integrity;

    if all {
        do_reap = true;
        do_refresh = true;
        do_reset = true;
        do_repair_registry = true;
    } else if !do_reap
        && !do_refresh
        && !do_reset
        && !do_repair_registry
        && !run_state_repair_requested
    {
        // Safe default: recover staleness and identity drift without mutating
        // lifecycle state unless explicitly requested.
        do_reap = true;
        do_refresh = true;
    }

    (do_reap, do_refresh, do_reset, do_repair_registry)
}

fn canonical_review_type(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "security" => Some("security"),
        "quality" | "code-quality" => Some("quality"),
        _ => None,
    }
}

fn normalize_run_state_review_types(review_types: Vec<String>) -> Result<Vec<String>, String> {
    let mut include_security = false;
    let mut include_quality = false;

    for review_type in review_types {
        match canonical_review_type(&review_type) {
            Some("security") => include_security = true,
            Some("quality") => include_quality = true,
            Some(_) => {
                return Err(format!("unsupported run-state review type `{review_type}`"));
            },
            None => {
                return Err(format!(
                    "invalid run-state review type `{review_type}` (expected security|quality)"
                ));
            },
        }
    }

    let mut normalized = Vec::new();
    if include_security {
        normalized.push("security".to_string());
    }
    if include_quality {
        normalized.push("quality".to_string());
    }
    Ok(normalized)
}

fn run_state_snapshot(state: &ReviewRunState) -> RunStateRepairSnapshot {
    RunStateRepairSnapshot {
        run_id: state.run_id.clone(),
        sequence_number: state.sequence_number,
        status: state.status.as_str().to_string(),
        terminal_reason: state.terminal_reason.clone(),
    }
}

fn require_present_run_state(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunState, String> {
    match state::load_review_run_state_for_home(home, pr_number, review_type)? {
        ReviewRunStateLoad::Present(state) => Ok(state),
        ReviewRunStateLoad::Missing { path } => Err(format!(
            "expected repaired run-state to exist for {review_type}, but it is missing at {}",
            path.display()
        )),
        ReviewRunStateLoad::Corrupt { path, error } => Err(format!(
            "expected repaired run-state to be valid for {review_type}, but found corrupt-state path={} detail={error}",
            path.display()
        )),
        ReviewRunStateLoad::Ambiguous { dir, candidates } => Err(format!(
            "expected repaired run-state to be canonical for {review_type}, but found ambiguous-state dir={} candidates={}",
            dir.display(),
            candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(",")
        )),
    }
}

fn quarantine_path(path: &Path) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(format!(
            "failed to derive file name for quarantine path {}",
            path.display()
        ));
    };

    let stamp = now_iso8601_millis().replace([':', '.', '-'], "");
    let mut suffix_index = 0usize;
    loop {
        let candidate_name = if suffix_index == 0 {
            format!("{file_name}.quarantine.{stamp}")
        } else {
            format!("{file_name}.quarantine.{stamp}.{suffix_index}")
        };
        let candidate = path.with_file_name(candidate_name);
        if !candidate.exists() {
            fs::rename(path, &candidate).map_err(|err| {
                format!(
                    "failed to quarantine run-state file {} -> {}: {err}",
                    path.display(),
                    candidate.display()
                )
            })?;
            return Ok(Some(candidate));
        }
        suffix_index = suffix_index.saturating_add(1);
        if suffix_index > 1024 {
            return Err(format!(
                "failed to allocate unique quarantine path for {}",
                path.display()
            ));
        }
    }
}

fn write_baseline_run_state_for_repair(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: Option<&str>,
    previous: Option<&ReviewRunState>,
) -> Result<ReviewRunState, String> {
    let resolved_head_sha = match head_sha {
        Some(sha) if !sha.trim().is_empty() => {
            validate_expected_head_sha(sha)?;
            sha.to_ascii_lowercase()
        },
        _ => previous
            .map(|state| state.head_sha.trim().to_string())
            .filter(|sha| validate_expected_head_sha(sha).is_ok())
            .or_else(|| {
                resolve_recovery_head_sha(owner_repo, pr_number, true, false)
                    .ok()
                    .filter(|sha| validate_expected_head_sha(sha).is_ok())
            })
            .ok_or_else(|| {
                format!(
                    "cannot rebuild baseline run-state for {review_type}: no valid head SHA available"
                )
            })?,
    };
    let sequence_number =
        previous.map_or(1, |state| state.sequence_number.saturating_add(1).max(1));
    let run_id =
        state::build_review_run_id(pr_number, review_type, sequence_number, &resolved_head_sha);
    let baseline = ReviewRunState {
        run_id,
        owner_repo: owner_repo.to_ascii_lowercase(),
        pr_number,
        head_sha: resolved_head_sha,
        review_type: review_type.to_string(),
        reviewer_role: "fac_reviewer".to_string(),
        started_at: now_iso8601(),
        status: ReviewRunStatus::Failed,
        terminal_reason: Some(TERMINAL_REPAIR_STATE_REBUILT.to_string()),
        model_id: None,
        backend_id: None,
        restart_count: 0,
        nudge_count: 0,
        sequence_number,
        previous_run_id: previous.map(|state| state.run_id.clone()),
        previous_head_sha: previous.map(|state| state.head_sha.clone()),
        pid: None,
        proc_start_time: None,
        integrity_hmac: None,
    };
    state::write_review_run_state_for_home(home, &baseline)?;
    require_present_run_state(home, pr_number, review_type)
}

fn load_candidate_run_state_for_repair(
    home: &Path,
    path: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunState, String> {
    let bytes = fs::read(path).map_err(|err| {
        format!(
            "failed to read run-state candidate {}: {err}",
            path.display()
        )
    })?;
    let state: ReviewRunState = serde_json::from_slice(&bytes).map_err(|err| {
        format!(
            "failed to parse run-state candidate {}: {err}",
            path.display()
        )
    })?;
    if state.pr_number != pr_number || !state.review_type.eq_ignore_ascii_case(review_type) {
        return Err(format!(
            "run-state candidate identity mismatch at {}: expected pr={pr_number} type={review_type}, got pr={} type={}",
            path.display(),
            state.pr_number,
            state.review_type
        ));
    }
    state::verify_review_run_state_integrity_binding(home, &state).map_err(|err| {
        format!(
            "run-state candidate integrity verification failed at {}: {err}",
            path.display()
        )
    })?;
    Ok(state)
}

fn repair_ambiguous_run_state_for_review_type(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: Option<&str>,
    candidates: &[PathBuf],
) -> Result<RunStateRepairOutcome, String> {
    let canonical = state::review_run_state_path_for_home(home, pr_number, review_type);
    let mut valid_candidates = Vec::new();
    for candidate in candidates {
        if let Ok(state) =
            load_candidate_run_state_for_repair(home, candidate, pr_number, review_type)
        {
            valid_candidates.push((candidate.clone(), state));
        }
    }

    if let Some((_, canonical_state)) = valid_candidates
        .iter()
        .find(|(path, _)| *path == canonical)
        .cloned()
    {
        let mut quarantined = Vec::new();
        for candidate in candidates {
            if *candidate == canonical {
                continue;
            }
            if let Some(path) = quarantine_path(candidate)? {
                quarantined.push(path.display().to_string());
            }
        }
        return Ok(RunStateRepairOutcome {
            review_type: review_type.to_string(),
            condition: RunStateRepairCondition::Ambiguous,
            action: RunStateRepairAction::Canonicalized,
            canonical_path: canonical.display().to_string(),
            source_candidate: None,
            quarantined_paths: quarantined,
            before: Some(run_state_snapshot(&canonical_state)),
            after: run_state_snapshot(&canonical_state),
        });
    }

    if let Some((source_path, source_state)) = valid_candidates.first().cloned() {
        let mut quarantined = Vec::new();
        if canonical.exists() && canonical != source_path {
            if let Some(path) = quarantine_path(&canonical)? {
                quarantined.push(path.display().to_string());
            }
        }
        state::write_review_run_state_for_home(home, &source_state)?;
        for candidate in candidates {
            if *candidate == canonical {
                continue;
            }
            if let Some(path) = quarantine_path(candidate)? {
                quarantined.push(path.display().to_string());
            }
        }
        let repaired = require_present_run_state(home, pr_number, review_type)?;
        return Ok(RunStateRepairOutcome {
            review_type: review_type.to_string(),
            condition: RunStateRepairCondition::Ambiguous,
            action: RunStateRepairAction::RebuiltFromCandidate,
            canonical_path: canonical.display().to_string(),
            source_candidate: Some(source_path.display().to_string()),
            quarantined_paths: quarantined,
            before: Some(run_state_snapshot(&source_state)),
            after: run_state_snapshot(&repaired),
        });
    }

    let mut quarantined = Vec::new();
    for candidate in candidates {
        if let Some(path) = quarantine_path(candidate)? {
            quarantined.push(path.display().to_string());
        }
    }
    let repaired = write_baseline_run_state_for_repair(
        home,
        owner_repo,
        pr_number,
        review_type,
        head_sha,
        None,
    )?;
    Ok(RunStateRepairOutcome {
        review_type: review_type.to_string(),
        condition: RunStateRepairCondition::Ambiguous,
        action: RunStateRepairAction::BaselineCreated,
        canonical_path: canonical.display().to_string(),
        source_candidate: None,
        quarantined_paths: quarantined,
        before: None,
        after: run_state_snapshot(&repaired),
    })
}

fn repair_run_state_for_review_type(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: Option<&str>,
) -> Result<Option<RunStateRepairOutcome>, String> {
    let canonical = state::review_run_state_path_for_home(home, pr_number, review_type);
    match state::load_review_run_state_for_home(home, pr_number, review_type)? {
        ReviewRunStateLoad::Present(state) => {
            let Some(_detail) = present_run_state_repair_detail(review_type, &state) else {
                return Ok(None);
            };
            let repaired = write_baseline_run_state_for_repair(
                home,
                owner_repo,
                pr_number,
                review_type,
                head_sha,
                Some(&state),
            )?;
            Ok(Some(RunStateRepairOutcome {
                review_type: review_type.to_string(),
                condition: RunStateRepairCondition::InconsistentRuntimeHandle,
                action: RunStateRepairAction::RebuiltFromPresent,
                canonical_path: canonical.display().to_string(),
                source_candidate: None,
                quarantined_paths: Vec::new(),
                before: Some(run_state_snapshot(&state)),
                after: run_state_snapshot(&repaired),
            }))
        },
        ReviewRunStateLoad::Missing { .. } => {
            let repaired = write_baseline_run_state_for_repair(
                home,
                owner_repo,
                pr_number,
                review_type,
                head_sha,
                None,
            )?;
            Ok(Some(RunStateRepairOutcome {
                review_type: review_type.to_string(),
                condition: RunStateRepairCondition::Missing,
                action: RunStateRepairAction::BaselineCreated,
                canonical_path: canonical.display().to_string(),
                source_candidate: None,
                quarantined_paths: Vec::new(),
                before: None,
                after: run_state_snapshot(&repaired),
            }))
        },
        ReviewRunStateLoad::Corrupt { path, .. } => {
            let mut quarantined = Vec::new();
            if let Some(quarantine_path) = quarantine_path(&path)? {
                quarantined.push(quarantine_path.display().to_string());
            }
            let repaired = write_baseline_run_state_for_repair(
                home,
                owner_repo,
                pr_number,
                review_type,
                head_sha,
                None,
            )?;
            Ok(Some(RunStateRepairOutcome {
                review_type: review_type.to_string(),
                condition: RunStateRepairCondition::Corrupt,
                action: RunStateRepairAction::BaselineCreated,
                canonical_path: canonical.display().to_string(),
                source_candidate: None,
                quarantined_paths: quarantined,
                before: None,
                after: run_state_snapshot(&repaired),
            }))
        },
        ReviewRunStateLoad::Ambiguous { candidates, .. } => {
            Ok(Some(repair_ambiguous_run_state_for_review_type(
                home,
                owner_repo,
                pr_number,
                review_type,
                head_sha,
                &candidates,
            )?))
        },
    }
}

fn present_run_state_repair_detail(review_type: &str, state: &ReviewRunState) -> Option<String> {
    if state.status.is_terminal() {
        return None;
    }
    if state.status == ReviewRunStatus::Alive && state.pid.is_none() {
        return Some(format!(
            "{review_type} run-state is Alive but missing pid (run_id={})",
            state.run_id
        ));
    }
    if let Some(pid) = state.pid {
        let Some(expected_start_time) = state.proc_start_time else {
            return Some(format!(
                "{review_type} run-state has pid={pid} but missing proc_start_time (run_id={})",
                state.run_id
            ));
        };
        if !state::is_process_alive(pid) {
            return Some(format!(
                "{review_type} run-state references dead pid={pid} (run_id={})",
                state.run_id
            ));
        }
        if state::get_process_start_time(pid) != Some(expected_start_time) {
            return Some(format!(
                "{review_type} run-state process identity mismatch pid={pid} expected_start={expected_start_time}",
            ));
        }
    }
    None
}

fn repair_run_states_for_pr(
    home: &Path,
    owner_repo: &str,
    pr_number: u32,
    head_sha: Option<&str>,
    review_types: &[String],
) -> Result<Vec<RunStateRepairOutcome>, String> {
    let mut outcomes = Vec::new();
    for review_type in review_types {
        let Some(canonical_type) = canonical_review_type(review_type) else {
            return Err(format!(
                "invalid run-state review type `{review_type}` (expected security|quality)"
            ));
        };
        if let Some(outcome) =
            repair_run_state_for_review_type(home, owner_repo, pr_number, canonical_type, head_sha)?
        {
            outcomes.push(outcome);
        }
    }
    Ok(outcomes)
}

fn resolve_recovery_head_sha(
    owner_repo: &str,
    pr_number: u32,
    fetch_authoritative: bool,
    require_authoritative: bool,
) -> Result<String, String> {
    let mut head_sha = projection_store::load_pr_identity(owner_repo, pr_number)?
        .map(|identity| identity.head_sha)
        .filter(|sha| validate_expected_head_sha(sha).is_ok())
        .unwrap_or_default();
    if head_sha.is_empty() {
        head_sha = lifecycle::load_pr_lifecycle_snapshot(owner_repo, pr_number)
            .ok()
            .flatten()
            .map(|snapshot| snapshot.current_sha)
            .filter(|sha| validate_expected_head_sha(sha).is_ok())
            .unwrap_or_default();
    }

    if fetch_authoritative {
        match fetch_pr_head_sha_authoritative(owner_repo, pr_number) {
            Ok(authoritative_head_sha) => {
                head_sha = authoritative_head_sha;
            },
            Err(err) => {
                if require_authoritative || head_sha.is_empty() {
                    return Err(format!(
                        "failed to resolve authoritative PR head SHA for recovery target: {err}"
                    ));
                }
            },
        }
    }

    validate_expected_head_sha(&head_sha)?;
    Ok(head_sha.to_ascii_lowercase())
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn run_repair_inner(
    repo: &str,
    pr_number: Option<u32>,
    force: bool,
    refresh_identity: bool,
    reap_stale_agents: bool,
    reset_lifecycle: bool,
    repair_registry_integrity: bool,
    all: bool,
    run_state_review_types: Vec<String>,
) -> Result<RepairSummary, String> {
    lifecycle::ensure_machine_artifact()?;
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let home = apm2_home_dir()?;

    let run_state_review_types = normalize_run_state_review_types(run_state_review_types)?;
    let do_run_state_repair = !run_state_review_types.is_empty();
    let (do_reap, do_refresh, do_reset, do_repair_registry) = resolve_operation_set(
        refresh_identity,
        reap_stale_agents,
        reset_lifecycle,
        repair_registry_integrity,
        all,
        do_run_state_repair,
    );

    let mut head_sha = if do_refresh || do_reset || do_run_state_repair {
        match resolve_recovery_head_sha(
            &owner_repo,
            resolved_pr,
            do_refresh || do_reset || do_run_state_repair,
            do_refresh || do_reset,
        ) {
            Ok(sha) => Some(sha),
            Err(err) => {
                if do_refresh || do_reset {
                    return Err(err);
                }
                None
            },
        }
    } else {
        None
    };

    let mut requested_operations = Vec::new();
    let mut applied_operations = Vec::new();
    let mut reaped_agents = None;
    let mut lifecycle_reset = None;
    let mut registry_repair = None;
    let mut refreshed_identity = false;
    let mut run_state_repairs = Vec::new();

    if do_repair_registry {
        requested_operations.push(OPERATION_REPAIR_REGISTRY.to_string());
        let outcome = lifecycle::repair_registry_integrity_for_pr_bypass_hmac(
            &owner_repo,
            resolved_pr,
            force,
        )?;
        registry_repair = Some(outcome);
        applied_operations.push(OPERATION_REPAIR_REGISTRY.to_string());
    }

    if do_run_state_repair {
        requested_operations.push(OPERATION_REPAIR_RUN_STATE.to_string());
        run_state_repairs = repair_run_states_for_pr(
            &home,
            &owner_repo,
            resolved_pr,
            head_sha.as_deref(),
            &run_state_review_types,
        )?;
        if !run_state_repairs.is_empty() {
            applied_operations.push(OPERATION_REPAIR_RUN_STATE.to_string());
        }
    }

    if do_reap {
        requested_operations.push("reap_stale_agents".to_string());
        let outcome =
            lifecycle::reap_stale_agents_for_pr_bypass_hmac(&owner_repo, resolved_pr, force)?;
        reaped_agents = Some(outcome);
        applied_operations.push("reap_stale_agents".to_string());
    }

    if do_refresh {
        let Some(current_head_sha) = head_sha.as_deref() else {
            return Err(
                "refresh_identity requested but no valid head SHA was resolved".to_string(),
            );
        };
        requested_operations.push("refresh_identity".to_string());
        projection_store::save_identity_with_context(
            &owner_repo,
            resolved_pr,
            current_head_sha,
            "repair",
        )
        .map_err(|err| format!("failed to refresh local projection identity: {err}"))?;
        refreshed_identity = true;
        applied_operations.push("refresh_identity".to_string());
    }

    if do_reset {
        let Some(current_head_sha) = head_sha.as_deref() else {
            return Err("reset_lifecycle requested but no valid head SHA was resolved".to_string());
        };
        requested_operations.push("reset_lifecycle".to_string());
        let outcome = lifecycle::reset_lifecycle_for_pr_bypass_hmac(
            &owner_repo,
            resolved_pr,
            current_head_sha,
            force,
        )?;
        lifecycle_reset = Some(outcome);
        applied_operations.push("reset_lifecycle".to_string());
    }

    let summary_head_sha = head_sha.take().unwrap_or_default();

    Ok(RepairSummary {
        schema: REPAIR_SUMMARY_SCHEMA.to_string(),
        owner_repo,
        pr_number: resolved_pr,
        head_sha: summary_head_sha,
        requested_operations,
        applied_operations,
        reaped_agents,
        refreshed_identity,
        lifecycle_reset,
        registry_repair,
        run_state_repairs,
    })
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub(super) fn run_repair_plan(
    repo: &str,
    pr_number: Option<u32>,
    force: bool,
    refresh_identity: bool,
    reap_stale_agents: bool,
    reset_lifecycle: bool,
    repair_registry_integrity: bool,
    all: bool,
    run_state_review_types: Vec<String>,
) -> Result<RepairSummary, String> {
    run_repair_inner(
        repo,
        pr_number,
        force,
        refresh_identity,
        reap_stale_agents,
        reset_lifecycle,
        repair_registry_integrity,
        all,
        run_state_review_types,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        OPERATION_REPAIR_REGISTRY, RepairSummary, normalize_run_state_review_types,
        repair_run_state_for_review_type, resolve_operation_set,
    };
    use crate::commands::fac_review::lifecycle::BypassRegistryRepairOutcome;
    use crate::commands::fac_review::state::{
        self, load_review_run_state_for_home, review_run_state_path_for_home,
        write_review_run_state_for_home,
    };
    use crate::commands::fac_review::types::{
        ReviewRunState, ReviewRunStatus, TERMINAL_REPAIR_STATE_REBUILT,
    };

    fn sample_state(pr_number: u32, review_type: &str, head_sha: &str) -> ReviewRunState {
        ReviewRunState {
            run_id: state::build_review_run_id(pr_number, review_type, 2, head_sha),
            owner_repo: "example/repo".to_string(),
            pr_number,
            head_sha: head_sha.to_string(),
            review_type: review_type.to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: "2026-02-10T00:00:00Z".to_string(),
            status: ReviewRunStatus::Alive,
            terminal_reason: None,
            model_id: Some("gpt-5.3-codex".to_string()),
            backend_id: Some("codex".to_string()),
            restart_count: 0,
            nudge_count: 0,
            sequence_number: 2,
            previous_run_id: None,
            previous_head_sha: None,
            pid: Some(4242),
            proc_start_time: Some(1_000_000),
            integrity_hmac: None,
        }
    }

    #[test]
    fn default_operation_set_enables_reap_and_refresh() {
        let (reap, refresh, reset, repair_registry) =
            resolve_operation_set(false, false, false, false, false, false);
        assert!(reap);
        assert!(refresh);
        assert!(!reset);
        assert!(!repair_registry);
    }

    #[test]
    fn explicit_operation_set_respects_flags() {
        let (reap, refresh, reset, repair_registry) =
            resolve_operation_set(true, true, false, false, false, false);
        assert!(reap);
        assert!(refresh);
        assert!(!reset);
        assert!(!repair_registry);
    }

    #[test]
    fn defaults_do_not_enable_lifecycle_reset_without_explicit_request() {
        let (reap, refresh, reset, repair_registry) =
            resolve_operation_set(false, false, false, false, false, false);
        assert!(reap);
        assert!(refresh);
        assert!(!reset);
        assert!(!repair_registry);
    }

    #[test]
    fn all_flag_enables_everything() {
        let (reap, refresh, reset, repair_registry) =
            resolve_operation_set(false, false, false, false, true, false);
        assert!(reap);
        assert!(refresh);
        assert!(reset);
        assert!(repair_registry);
    }

    #[test]
    fn explicit_registry_repair_respects_flag() {
        let (reap, refresh, reset, repair_registry) =
            resolve_operation_set(false, false, false, true, false, false);
        assert!(!reap);
        assert!(!refresh);
        assert!(!reset);
        assert!(repair_registry);
    }

    #[test]
    fn run_state_repair_only_does_not_enable_reap_or_refresh_defaults() {
        let (reap, refresh, reset, repair_registry) =
            resolve_operation_set(false, false, false, false, false, true);
        assert!(!reap);
        assert!(!refresh);
        assert!(!reset);
        assert!(!repair_registry);
    }

    #[test]
    fn repair_summary_reports_registry_repair_operation() {
        let summary = RepairSummary {
            schema: "apm2.fac.repair_summary.v1".to_string(),
            owner_repo: "example/repo".to_string(),
            pr_number: 444,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            requested_operations: vec![OPERATION_REPAIR_REGISTRY.to_string()],
            applied_operations: vec![OPERATION_REPAIR_REGISTRY.to_string()],
            reaped_agents: None,
            refreshed_identity: false,
            lifecycle_reset: None,
            registry_repair: Some(BypassRegistryRepairOutcome {
                before_active_agents: 1,
                after_active_agents: 0,
                before_total_entries: 2,
                after_total_entries: 0,
                reaped_agents: 1,
                quarantined_registry_path: Some("/tmp/registry.quarantine".to_string()),
                quarantine_reason: Some("agent registry integrity check failed".to_string()),
            }),
            run_state_repairs: Vec::new(),
        };

        let repairs = summary.into_doctor_repairs();
        assert!(
            repairs
                .iter()
                .any(|entry| entry.operation == OPERATION_REPAIR_REGISTRY),
            "registry repair operation should be surfaced in doctor repair summaries"
        );
    }

    #[test]
    fn normalize_run_state_review_types_deduplicates_and_normalizes() {
        let result = normalize_run_state_review_types(vec![
            "security".to_string(),
            "code-quality".to_string(),
            "quality".to_string(),
        ])
        .expect("normalize review types");
        assert_eq!(result, vec!["security".to_string(), "quality".to_string()]);
    }

    #[test]
    fn normalize_run_state_review_types_rejects_invalid_type() {
        let error = normalize_run_state_review_types(vec!["bogus".to_string()])
            .expect_err("invalid type must fail");
        assert!(
            error.contains("invalid run-state review type"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn repair_run_state_missing_creates_baseline_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let outcome =
            repair_run_state_for_review_type(home, "example/repo", 441, "security", Some(head_sha))
                .expect("repair missing run-state")
                .expect("missing run-state should be repaired");
        assert_eq!(outcome.review_type, "security");
        assert_eq!(outcome.after.status, "failed");
        assert_eq!(
            outcome.after.terminal_reason.as_deref(),
            Some(TERMINAL_REPAIR_STATE_REBUILT)
        );

        let loaded = load_review_run_state_for_home(home, 441, "security").expect("load run-state");
        let state = match loaded {
            state::ReviewRunStateLoad::Present(state) => state,
            other => panic!("expected repaired present run-state, got {other:?}"),
        };
        assert_eq!(state.status, ReviewRunStatus::Failed);
        assert_eq!(
            state.terminal_reason.as_deref(),
            Some(TERMINAL_REPAIR_STATE_REBUILT)
        );
    }

    #[test]
    fn repair_run_state_present_with_inconsistent_runtime_handle_rebuilds_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let pr_number = 441;
        let review_type = "security";
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let mut state = sample_state(pr_number, review_type, head_sha);
        state.proc_start_time = None;
        write_review_run_state_for_home(home, &state).expect("write inconsistent run-state");

        let outcome =
            repair_run_state_for_review_type(home, "example/repo", pr_number, review_type, None)
                .expect("repair run-state")
                .expect("inconsistent run-state should be repaired");

        assert_eq!(outcome.review_type, review_type);
        assert_eq!(
            outcome.condition.as_str(),
            "inconsistent_runtime_handle",
            "repair outcome must classify inconsistent runtime handle"
        );
        assert!(outcome.before.is_some());
        assert_eq!(outcome.after.status, "failed");
        assert_eq!(
            outcome.after.terminal_reason.as_deref(),
            Some(TERMINAL_REPAIR_STATE_REBUILT)
        );
    }

    #[test]
    fn repair_run_state_ambiguous_keeps_valid_canonical_and_quarantines_alternate() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let pr_number = 442;
        let review_type = "security";
        let head_sha = "0123456789abcdef0123456789abcdef01234567";

        let canonical_path = review_run_state_path_for_home(home, pr_number, review_type);
        let state = sample_state(pr_number, review_type, head_sha);
        write_review_run_state_for_home(home, &state).expect("write canonical state");

        let alt_path = canonical_path.with_file_name("state.alt.json");
        std::fs::copy(&canonical_path, &alt_path).expect("copy alternate state");

        let outcome = repair_run_state_for_review_type(
            home,
            "example/repo",
            pr_number,
            review_type,
            Some(head_sha),
        )
        .expect("repair ambiguous state")
        .expect("ambiguous state should be repaired");

        assert_eq!(outcome.review_type, review_type);
        assert_eq!(outcome.after.run_id, state.run_id);
        assert!(
            !alt_path.exists(),
            "alternate ambiguous state should be quarantined"
        );
        assert!(
            !outcome.quarantined_paths.is_empty(),
            "repair outcome should include quarantined paths"
        );
    }

    #[test]
    fn repair_run_state_ambiguous_succeeds_without_provided_head_when_candidate_is_valid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let pr_number = 443;
        let review_type = "security";
        let head_sha = "0123456789abcdef0123456789abcdef01234567";

        let canonical_path = review_run_state_path_for_home(home, pr_number, review_type);
        let state = sample_state(pr_number, review_type, head_sha);
        write_review_run_state_for_home(home, &state).expect("write canonical state");
        let alt_path = canonical_path.with_file_name("state.alt.json");
        std::fs::copy(&canonical_path, &alt_path).expect("copy alternate state");

        let outcome =
            repair_run_state_for_review_type(home, "example/repo", pr_number, review_type, None)
                .expect("repair ambiguous state")
                .expect("ambiguous state should be repaired");

        assert_eq!(outcome.review_type, review_type);
        assert_eq!(outcome.after.run_id, state.run_id);
        assert!(
            !alt_path.exists(),
            "alternate candidate should be quarantined"
        );
    }
}
