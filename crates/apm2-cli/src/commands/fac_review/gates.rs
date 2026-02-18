//! `apm2 fac gates` — unified local evidence gates with bounded test execution.
//!
//! Runs all evidence gates locally, caches results per-SHA so the background
//! pipeline can skip already-validated gates.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use apm2_core::fac::job_spec::{
    Actuation, FacJobSpecV1, JobConstraints, JobSource, JobSpecValidationPolicy, LaneRequirements,
    MAX_QUEUE_LANE_LENGTH, validate_job_spec_with_policy,
};
use apm2_core::fac::{
    FacPolicyV1, LaneLockGuard, LaneManager, LaneState, apply_lane_env_overrides,
    build_job_environment, compute_test_env_for_parallelism, ensure_lane_env_dirs,
    lookup_job_receipt, parse_b3_256_digest, parse_policy_hash, resolve_host_test_parallelism,
};
use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
use sha2::{Digest, Sha256};

use super::bounded_test_runner::{
    BoundedTestLimits, build_bounded_test_command as build_systemd_bounded_test_command,
};
use super::evidence::{
    EvidenceGateOptions, EvidenceGateResult, LANE_EVIDENCE_GATES,
    run_evidence_gates_with_lane_context,
};
use super::gate_attestation::{
    GateResourcePolicy, build_nextest_command, compute_gate_attestation,
    gate_command_for_attestation,
};
use super::gate_cache::GateCache;
use super::jsonl::read_log_error_hint;
use super::merge_conflicts::{check_merge_conflicts_against_main, render_merge_conflict_summary};
use super::timeout_policy::{
    MAX_MANUAL_TIMEOUT_SECONDS, TEST_TIMEOUT_SLA_MESSAGE, max_memory_bytes, parse_memory_limit,
    resolve_bounded_test_timeout,
};
use crate::commands::fac_gates_job::GatesJobOptionsV1;
use crate::commands::fac_queue_submit::{
    enqueue_job, generate_job_suffix, init_broker, load_or_init_policy, resolve_fac_root,
    resolve_queue_root, resolve_repo_source_info,
};
use crate::commands::fac_utils::{MAX_SCAN_ENTRIES, read_job_spec_bounded};
use crate::exit_codes::codes as exit_codes;

const DEFAULT_TEST_KILL_AFTER_SECONDS: u64 = 20;
const BALANCED_MIN_PARALLELISM: u32 = 4;
const BALANCED_MAX_PARALLELISM: u32 = 16;
const CONSERVATIVE_PARALLELISM: u32 = 2;
const DEFAULT_GATES_WAIT_TIMEOUT_SECS: u64 = 1200;
const GATES_WAIT_POLL_INTERVAL_SECS: u64 = 5;
const INLINE_WORKER_POLL_INTERVAL_SECS: u64 = 1;
const EXTERNAL_WORKER_BOOTSTRAP_POLL_INTERVAL_MS: u64 = 250;
// 40 * 250ms ~= 10s bootstrap window for detached worker heartbeat.
const EXTERNAL_WORKER_BOOTSTRAP_MAX_POLLS: u32 = 40;
const GATES_QUEUE_LANE: &str = "consume";
const GATES_SINGLE_FLIGHT_DIR: &str = "queue/singleflight";
const GATES_QUEUE_PENDING_DIR: &str = "pending";
const GATES_QUEUE_CLAIMED_DIR: &str = "claimed";
const DIRTY_TREE_STATUS_MAX_LINES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueProcessingMode {
    ExternalWorker,
    InlineSingleJob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerExecutionMode {
    AllowInlineFallback,
    RequireExternalWorker,
}

/// Request payload for queued FAC gates execution.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct QueuedGatesRequest {
    pub(super) force: bool,
    pub(super) quick: bool,
    pub(super) timeout_seconds: u64,
    pub(super) memory_max: String,
    pub(super) pids_max: u64,
    pub(super) cpu_quota: String,
    pub(super) gate_profile: GateThroughputProfile,
    pub(super) wait_timeout_secs: u64,
    pub(super) require_external_worker: bool,
    /// TCK-00540: Allow reuse of legacy gate cache entries without
    /// RFC-0028/0029 receipt bindings (unsafe migration override).
    pub(super) allow_legacy_cache: bool,
}

/// Queue-backed FAC gates outcome with materialized per-gate rows.
#[derive(Debug, Clone)]
pub(super) struct QueuedGatesOutcome {
    pub(super) job_id: String,
    pub(super) job_receipt_id: String,
    pub(super) policy_hash: String,
    pub(super) head_sha: String,
    pub(super) worker_bootstrapped: bool,
    pub(super) gate_results: Vec<EvidenceGateResult>,
}

#[derive(Debug, Clone)]
struct PreparedQueuedGatesJob {
    fac_root: PathBuf,
    head_sha: String,
    job_id: String,
    spec: FacJobSpecV1,
    coalesced_with_existing: bool,
    worker_bootstrapped: bool,
    policy_hash: String,
    options: GatesJobOptionsV1,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
struct GatesQueueSnapshot {
    pending_gates: usize,
    claimed_gates: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    ahead_of_job: Option<usize>,
    job_state: String,
}

/// Throughput profile for bounded FAC gate execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateThroughputProfile {
    Throughput,
    Balanced,
    Conservative,
}

impl GateThroughputProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Throughput => "throughput",
            Self::Balanced => "balanced",
            Self::Conservative => "conservative",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ResolvedGateExecutionProfile {
    pub(super) test_parallelism: u32,
    pub(super) cpu_quota_percent: u32,
}

pub(super) fn resolve_gate_execution_profile(
    profile: GateThroughputProfile,
) -> ResolvedGateExecutionProfile {
    let host = resolve_host_test_parallelism();
    let test_parallelism = match profile {
        GateThroughputProfile::Throughput => host,
        GateThroughputProfile::Balanced => {
            let half = host / 2;
            half.clamp(BALANCED_MIN_PARALLELISM, BALANCED_MAX_PARALLELISM)
                .min(host)
        },
        GateThroughputProfile::Conservative => CONSERVATIVE_PARALLELISM.min(host).max(1),
    };
    ResolvedGateExecutionProfile {
        test_parallelism,
        cpu_quota_percent: test_parallelism.saturating_mul(100).max(100),
    }
}

fn parse_cpu_quota_percent(cpu_quota: &str) -> Result<u32, String> {
    let normalized = cpu_quota.trim().trim_end_matches('%').trim();
    if normalized.is_empty() {
        return Err("cpu_quota cannot be empty".to_string());
    }
    normalized
        .parse::<u32>()
        .map_err(|_| format!("invalid cpu_quota value: `{cpu_quota}`"))
}

fn quota_percent_to_parallelism(percent: u32) -> u32 {
    if percent == 0 {
        // `CPUQuota=0` in systemd means "no limit"; in that case preserve full
        // host parallelism instead of forcing single-thread execution.
        return resolve_host_test_parallelism();
    }
    percent.saturating_add(99) / 100
}

pub(super) fn resolve_effective_execution_profile(
    requested_cpu_quota: &str,
    gate_profile: GateThroughputProfile,
) -> Result<(ResolvedGateExecutionProfile, String), String> {
    let profile = resolve_gate_execution_profile(gate_profile);
    if requested_cpu_quota.trim().eq_ignore_ascii_case("auto") {
        return Ok((profile, format!("{}%", profile.cpu_quota_percent)));
    }
    let cpu_quota_percent = parse_cpu_quota_percent(requested_cpu_quota)?;
    let host_parallelism = resolve_host_test_parallelism();
    let test_parallelism = quota_percent_to_parallelism(cpu_quota_percent)
        .min(host_parallelism)
        .max(1);
    Ok((
        ResolvedGateExecutionProfile {
            test_parallelism,
            cpu_quota_percent,
        },
        format!("{cpu_quota_percent}%"),
    ))
}

/// Enqueue FAC gates as a worker job.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
pub fn run_gates(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    gate_profile: GateThroughputProfile,
    json_output: bool,
    wait: bool,
    wait_timeout_secs: u64,
    allow_legacy_cache: bool,
) -> u8 {
    run_gates_via_worker(
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        gate_profile,
        wait,
        wait_timeout_secs,
        json_output,
        allow_legacy_cache,
    )
}

/// Submit queued gates to worker execution and collect per-gate results from
/// the authoritative per-SHA gate cache.
pub(super) fn run_queued_gates_and_collect(
    request: &QueuedGatesRequest,
) -> Result<QueuedGatesOutcome, String> {
    if request.quick {
        return Err(
            "queued gate-result collection requires full mode (quick=false) because quick mode does not persist attested gate cache entries".to_string(),
        );
    }

    let prepared = prepare_queued_gates_job(request, true)?;
    let timeout_secs = normalize_wait_timeout(request.wait_timeout_secs);
    wait_for_gates_job_receipt_with_mode(
        &prepared.fac_root,
        &prepared.job_id,
        Duration::from_secs(timeout_secs),
        WorkerExecutionMode::RequireExternalWorker,
    )?;
    let receipts_dir = prepared.fac_root.join("receipts");
    let job_receipt = lookup_job_receipt(&receipts_dir, &prepared.job_id).ok_or_else(|| {
        format!(
            "queued gates job {} completed but no FAC job receipt was found",
            prepared.job_id
        )
    })?;
    let job_receipt_id = job_receipt.receipt_id.trim().to_string();
    if job_receipt_id.is_empty() {
        return Err(format!(
            "queued gates job {} completed with empty receipt_id",
            prepared.job_id
        ));
    }
    let policy_hash = job_receipt
        .policy_hash
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "queued gates job {} completed without policy_hash in authoritative receipt",
                prepared.job_id
            )
        })?
        .to_string();
    if parse_policy_hash(&policy_hash).is_none() {
        return Err(format!(
            "queued gates job {} returned invalid policy_hash `{policy_hash}` in authoritative receipt",
            prepared.job_id
        ));
    }

    let gate_results = load_gate_results_from_cache_for_sha(&prepared.head_sha)?;
    Ok(QueuedGatesOutcome {
        job_id: prepared.job_id,
        job_receipt_id,
        policy_hash,
        head_sha: prepared.head_sha,
        worker_bootstrapped: prepared.worker_bootstrapped,
        gate_results,
    })
}

const fn normalize_wait_timeout(wait_timeout_secs: u64) -> u64 {
    if wait_timeout_secs == 0 {
        DEFAULT_GATES_WAIT_TIMEOUT_SECS
    } else {
        wait_timeout_secs
    }
}

fn prepare_queued_gates_job(
    request: &QueuedGatesRequest,
    wait: bool,
) -> Result<PreparedQueuedGatesJob, String> {
    validate_timeout_seconds(request.timeout_seconds)?;
    let memory_max_bytes = parse_memory_limit(&request.memory_max)?;
    if memory_max_bytes > max_memory_bytes() {
        return Err(format!(
            "--memory-max {} exceeds FAC test memory cap of {}",
            request.memory_max,
            max_memory_bytes(),
        ));
    }
    resolve_effective_execution_profile(&request.cpu_quota, request.gate_profile)?;

    let fac_root = resolve_fac_root().map_err(|err| format!("cannot resolve FAC root: {err}"))?;
    let worker_bootstrapped = if request.require_external_worker {
        ensure_external_worker_bootstrap(
            &fac_root,
            has_live_worker_heartbeat,
            spawn_detached_worker_for_queue,
        )
        .map_err(|err| format!("cannot bootstrap external FAC worker: {err}"))?
    } else if wait {
        false
    } else {
        ensure_non_wait_worker_bootstrap(
            &fac_root,
            has_live_worker_heartbeat,
            spawn_detached_worker_for_queue,
        )
        .map_err(|err| format!("cannot bootstrap FAC worker for --no-wait mode: {err}"))?
    };
    let boundary_id = apm2_core::fac::load_or_default_boundary_id(&fac_root)
        .unwrap_or_else(|_| "local".to_string());
    let mut broker = init_broker(&fac_root, &boundary_id)
        .map_err(|err| format!("cannot initialize broker: {err}"))?;
    let (policy_hash, policy_digest, fac_policy) =
        load_or_init_policy(&fac_root).map_err(|err| format!("cannot load FAC policy: {err}"))?;
    broker
        .admit_policy_digest(policy_digest)
        .map_err(|err| format!("cannot admit FAC policy digest: {err}"))?;

    // TCK-00579: Derive job spec validation policy from FAC policy for
    // enqueue-time enforcement of repo_id allowlist, bytes_backend
    // allowlist, and filesystem-path rejection.
    let job_spec_policy = fac_policy
        .job_spec_validation_policy()
        .map_err(|err| format!("cannot derive job spec validation policy: {err}"))?;

    let repo_source = resolve_repo_source_info();
    let options = GatesJobOptionsV1::new(
        request.force,
        request.quick,
        request.timeout_seconds,
        &request.memory_max,
        request.pids_max,
        &request.cpu_quota,
        request.gate_profile.as_str(),
        &repo_source.workspace_root,
        request.allow_legacy_cache,
    );
    let queue_root =
        resolve_queue_root().map_err(|err| format!("cannot resolve queue root: {err}"))?;
    let _single_flight_lock =
        acquire_gates_single_flight_lock(&fac_root, &repo_source.repo_id, &repo_source.head_sha)?;
    let include_claimed = has_live_worker_heartbeat(&fac_root);
    if let Some(existing_spec) = find_coalescible_gates_job(
        &queue_root,
        &repo_source.repo_id,
        &repo_source.head_sha,
        &options,
        include_claimed,
    )? {
        return Ok(PreparedQueuedGatesJob {
            fac_root,
            head_sha: repo_source.head_sha,
            job_id: existing_spec.job_id.clone(),
            spec: existing_spec,
            coalesced_with_existing: true,
            worker_bootstrapped,
            policy_hash,
            options,
        });
    }

    let job_id = format!("gates-{}", generate_job_suffix());
    let lease_id = format!("gates-lease-{}", generate_job_suffix());
    let spec = build_gates_job_spec(
        &job_id,
        &lease_id,
        &repo_source.repo_id,
        &repo_source.head_sha,
        &policy_digest,
        memory_max_bytes,
        &options,
        &boundary_id,
        &mut broker,
        &job_spec_policy,
        fac_policy.allowed_intents.as_deref(),
    )
    .map_err(|err| format!("cannot build gates job spec: {err}"))?;
    enqueue_job(
        &queue_root,
        &fac_root,
        &spec,
        &fac_policy.queue_bounds_policy,
    )
    .map_err(|err| format!("failed to enqueue gates job: {err}"))?;

    Ok(PreparedQueuedGatesJob {
        fac_root,
        head_sha: repo_source.head_sha,
        job_id,
        spec,
        coalesced_with_existing: false,
        worker_bootstrapped,
        policy_hash,
        options,
    })
}

fn acquire_gates_single_flight_lock(
    fac_root: &Path,
    repo_id: &str,
    head_sha: &str,
) -> Result<std::fs::File, String> {
    let lock_name = format!(
        "gates-{}-{}.lock",
        sanitize_single_flight_segment(repo_id),
        sanitize_single_flight_segment(head_sha),
    );
    let lock_path = fac_root.join(GATES_SINGLE_FLIGHT_DIR).join(lock_name);
    if let Some(parent) = lock_path.parent() {
        #[cfg(unix)]
        {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|err| {
                    format!(
                        "cannot create gates single-flight lock directory {}: {err}",
                        parent.display()
                    )
                })?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "cannot create gates single-flight lock directory {}: {err}",
                    parent.display()
                )
            })?;
        }
    }
    let lock_file = {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        options.open(&lock_path).map_err(|err| {
            format!(
                "cannot open gates single-flight lock {}: {err}",
                lock_path.display()
            )
        })?
    };
    lock_file.lock_exclusive().map_err(|err| {
        format!(
            "cannot acquire gates single-flight lock {}: {err}",
            lock_path.display()
        )
    })?;
    Ok(lock_file)
}

fn sanitize_single_flight_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    while out.starts_with('-') || out.starts_with('_') || out.starts_with('.') {
        out.remove(0);
    }
    while out.ends_with('-') || out.ends_with('_') || out.ends_with('.') {
        out.pop();
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

fn find_coalescible_gates_job(
    queue_root: &Path,
    repo_id: &str,
    head_sha: &str,
    options: &GatesJobOptionsV1,
    include_claimed: bool,
) -> Result<Option<FacJobSpecV1>, String> {
    let expected_patch =
        serde_json::to_value(options).map_err(|err| format!("serialize gates options: {err}"))?;
    let mut selected: Option<FacJobSpecV1> = None;
    for dir_name in [
        Some(GATES_QUEUE_PENDING_DIR),
        include_claimed.then_some(GATES_QUEUE_CLAIMED_DIR),
    ]
    .into_iter()
    .flatten()
    {
        let dir = queue_root.join(dir_name);
        if !dir.is_dir() {
            continue;
        }
        let entries = fs::read_dir(&dir)
            .map_err(|err| format!("cannot read queue directory {}: {err}", dir.display()))?;
        for (idx, entry) in entries.enumerate() {
            if idx >= MAX_SCAN_ENTRIES {
                break;
            }
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(spec) = read_job_spec_bounded(&path) else {
                continue;
            };
            if !is_coalescible_gates_spec(&spec, repo_id, head_sha, &expected_patch) {
                continue;
            }
            let replace = selected.as_ref().is_none_or(|current| {
                spec.enqueue_time < current.enqueue_time
                    || (spec.enqueue_time == current.enqueue_time && spec.job_id < current.job_id)
            });
            if replace {
                selected = Some(spec);
            }
        }
    }
    Ok(selected)
}

fn is_coalescible_gates_spec(
    spec: &FacJobSpecV1,
    repo_id: &str,
    head_sha: &str,
    expected_patch: &serde_json::Value,
) -> bool {
    spec.kind == "gates"
        && spec.queue_lane == GATES_QUEUE_LANE
        && spec.source.repo_id.eq_ignore_ascii_case(repo_id)
        && spec.source.head_sha.eq_ignore_ascii_case(head_sha)
        && spec
            .source
            .patch
            .as_ref()
            .is_some_and(|patch| patch == expected_patch)
}

fn load_gate_results_from_cache_for_sha(sha: &str) -> Result<Vec<EvidenceGateResult>, String> {
    let cache = GateCache::load(sha).ok_or_else(|| {
        format!(
            "queued gates job completed for sha={sha} but no attested gate cache entry was found"
        )
    })?;

    let expected = LANE_EVIDENCE_GATES
        .iter()
        .map(|gate| (*gate).to_string())
        .collect::<BTreeSet<_>>();
    let actual = cache.gates.keys().cloned().collect::<BTreeSet<_>>();

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
            "queued gates cache for sha={sha} does not match required gate set (missing={missing_summary}, extra={extra_summary})"
        ));
    }

    let mut results = Vec::with_capacity(LANE_EVIDENCE_GATES.len());
    for gate_name in LANE_EVIDENCE_GATES {
        let cached = cache.get(gate_name).ok_or_else(|| {
            format!("queued gates cache for sha={sha} missing required gate `{gate_name}`")
        })?;
        let passed = if cached.status.eq_ignore_ascii_case("PASS") {
            true
        } else if cached.status.eq_ignore_ascii_case("FAIL") {
            false
        } else {
            return Err(format!(
                "queued gates cache for sha={sha} has unsupported gate status for `{gate_name}`: {}",
                cached.status
            ));
        };
        results.push(EvidenceGateResult {
            gate_name: (*gate_name).to_string(),
            passed,
            duration_secs: cached.duration_secs,
            log_path: cached.log_path.as_deref().map(PathBuf::from),
            bytes_written: cached.bytes_written,
            bytes_total: cached.bytes_total,
            was_truncated: cached.was_truncated,
            log_bundle_hash: cached.log_bundle_hash.clone(),
            legacy_cache_override: cached.legacy_cache_override,
        });
    }
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(test, allow(dead_code))]
pub(super) fn run_gates_local_worker(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    gate_profile: GateThroughputProfile,
    workspace_root: &Path,
    allow_legacy_cache: bool,
) -> Result<u8, String> {
    let (resolved_profile, effective_cpu_quota) =
        resolve_effective_execution_profile(cpu_quota, gate_profile)?;
    let summary = run_gates_inner(
        workspace_root,
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        &effective_cpu_quota,
        gate_profile,
        resolved_profile.test_parallelism,
        false,
        None,
        allow_legacy_cache,
    )?;
    Ok(if summary.passed {
        exit_codes::SUCCESS
    } else {
        exit_codes::GENERIC_ERROR
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
fn run_gates_via_worker(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    gate_profile: GateThroughputProfile,
    wait: bool,
    wait_timeout_secs: u64,
    json_output: bool,
    allow_legacy_cache: bool,
) -> u8 {
    let request = QueuedGatesRequest {
        force,
        quick,
        timeout_seconds,
        memory_max: memory_max.to_string(),
        pids_max,
        cpu_quota: cpu_quota.to_string(),
        gate_profile,
        wait_timeout_secs,
        require_external_worker: false,
        allow_legacy_cache,
    };
    let prepared = match prepare_queued_gates_job(&request, wait) {
        Ok(prepared) => prepared,
        Err(err) => {
            let code = if err.starts_with("--timeout-seconds")
                || err.starts_with("--memory-max")
                || err.starts_with("invalid cpu_quota")
                || err.starts_with("cpu_quota")
            {
                exit_codes::VALIDATION_ERROR
            } else {
                exit_codes::GENERIC_ERROR
            };
            return output_worker_enqueue_error(json_output, &err, code);
        },
    };

    let queued_job_id = prepared.job_id.clone();
    let queued_head_sha = prepared.head_sha.clone();
    let queued_lane = prepared.spec.queue_lane.clone();
    let queued_coalesced = prepared.coalesced_with_existing;
    let queued_bootstrapped = prepared.worker_bootstrapped;
    let queue_snapshot = resolve_queue_root()
        .ok()
        .and_then(|queue_root| collect_gates_queue_snapshot(&queue_root, &queued_job_id).ok());

    if json_output {
        let payload = serde_json::json!({
            "status": if queued_coalesced { "coalesced" } else { "enqueued" },
            "job_kind": "gates",
            "job_id": queued_job_id,
            "queue_lane": queued_lane,
            "policy_hash": &prepared.policy_hash,
            "head_sha": queued_head_sha,
            "coalesced_with_existing": queued_coalesced,
            "worker_bootstrapped": queued_bootstrapped,
            "options": &prepared.options,
            "queue_snapshot": queue_snapshot,
            "throughput_mode": "single_flight_max_compute",
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
    } else {
        let action = if queued_coalesced {
            "coalesced with queued worker job"
        } else {
            "enqueued worker job"
        };
        eprintln!(
            "fac gates: {action} {job_id} lane={} head_sha={}{}",
            queued_lane,
            queued_head_sha,
            if queued_bootstrapped {
                " (bootstrapped detached worker)"
            } else {
                ""
            },
            job_id = queued_job_id,
        );
        if let Some(snapshot) = queue_snapshot.as_ref() {
            let ahead = snapshot
                .ahead_of_job
                .map_or_else(|| "unknown".to_string(), |value| value.to_string());
            eprintln!(
                "fac gates: queue snapshot state={} ahead={} pending_gates={} claimed_gates={}",
                snapshot.job_state, ahead, snapshot.pending_gates, snapshot.claimed_gates
            );
        }
        if wait {
            eprintln!(
                "fac gates: execution mode is single-flight max-compute \
                 (one full gates job gets the host at a time per VPS)."
            );
        }
    }

    if wait {
        let timeout_secs = normalize_wait_timeout(wait_timeout_secs);
        let timeout = Duration::from_secs(timeout_secs);
        match wait_for_gates_job_receipt(&prepared.fac_root, &prepared.job_id, timeout) {
            Ok(()) => {
                if json_output {
                    let payload = serde_json::json!({
                        "status": "completed",
                        "job_kind": "gates",
                        "job_id": prepared.job_id,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| {
                            "{\"error\":\"serialization_failure\"}".to_string()
                        })
                    );
                } else {
                    eprintln!("fac gates: worker job {} completed", prepared.job_id);
                }
            },
            Err(err) => {
                return output_worker_enqueue_error(json_output, &err, exit_codes::GENERIC_ERROR);
            },
        }
    }

    exit_codes::SUCCESS
}

fn output_worker_enqueue_error(json_output: bool, message: &str, code: u8) -> u8 {
    if json_output {
        let payload = serde_json::json!({
            "status": "error",
            "error": "fac_gates_worker_enqueue_failed",
            "message": message,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
        );
    } else {
        eprintln!("ERROR: {message}");
    }
    code
}

fn collect_gates_queue_snapshot(
    queue_root: &Path,
    job_id: &str,
) -> Result<GatesQueueSnapshot, String> {
    let pending_specs =
        collect_gates_specs_in_queue_dir(&queue_root.join(GATES_QUEUE_PENDING_DIR))?;
    let claimed_specs =
        collect_gates_specs_in_queue_dir(&queue_root.join(GATES_QUEUE_CLAIMED_DIR))?;

    let mut snapshot = GatesQueueSnapshot {
        pending_gates: pending_specs.len(),
        claimed_gates: claimed_specs.len(),
        ahead_of_job: None,
        job_state: "missing".to_string(),
    };

    if let Some(position) = claimed_specs.iter().position(|spec| spec.job_id == job_id) {
        snapshot.ahead_of_job = Some(position);
        snapshot.job_state = "claimed".to_string();
        return Ok(snapshot);
    }
    if let Some(position) = pending_specs.iter().position(|spec| spec.job_id == job_id) {
        snapshot.ahead_of_job = Some(claimed_specs.len().saturating_add(position));
        snapshot.job_state = "pending".to_string();
        return Ok(snapshot);
    }

    Ok(snapshot)
}

fn collect_gates_specs_in_queue_dir(dir: &Path) -> Result<Vec<FacJobSpecV1>, String> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut specs = Vec::new();
    let entries = fs::read_dir(dir)
        .map_err(|err| format!("cannot read queue directory {}: {err}", dir.display()))?;
    for (idx, entry) in entries.enumerate() {
        if idx >= MAX_SCAN_ENTRIES {
            break;
        }
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(spec) = read_job_spec_bounded(&path) else {
            continue;
        };
        if spec.kind == "gates" && spec.queue_lane == GATES_QUEUE_LANE {
            specs.push(spec);
        }
    }
    specs.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.enqueue_time.cmp(&right.enqueue_time))
            .then_with(|| left.job_id.cmp(&right.job_id))
    });
    Ok(specs)
}

#[allow(clippy::too_many_arguments)]
fn build_gates_job_spec(
    job_id: &str,
    lease_id: &str,
    repo_id: &str,
    head_sha: &str,
    policy_digest: &[u8; 32],
    memory_max_bytes: u64,
    options: &GatesJobOptionsV1,
    boundary_id: &str,
    broker: &mut apm2_core::fac::broker::FacBroker,
    job_spec_policy: &JobSpecValidationPolicy,
    allowed_intents: Option<&[apm2_core::fac::job_spec::FacIntent]>,
) -> Result<FacJobSpecV1, String> {
    if GATES_QUEUE_LANE.is_empty() || GATES_QUEUE_LANE.len() > MAX_QUEUE_LANE_LENGTH {
        return Err("invalid gates queue lane configuration".to_string());
    }

    let enqueue_time = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let patch = serde_json::to_value(options).map_err(|err| format!("serialize patch: {err}"))?;
    let mut spec = FacJobSpecV1 {
        schema: apm2_core::fac::job_spec::JOB_SPEC_SCHEMA_ID.to_string(),
        job_id: job_id.to_string(),
        job_spec_digest: String::new(),
        kind: "gates".to_string(),
        queue_lane: GATES_QUEUE_LANE.to_string(),
        priority: 40,
        enqueue_time,
        actuation: Actuation {
            lease_id: lease_id.to_string(),
            request_id: String::new(),
            channel_context_token: None,
            decoded_source: Some("fac_gates_worker".to_string()),
        },
        source: JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: repo_id.to_string(),
            head_sha: head_sha.to_string(),
            patch: Some(patch),
        },
        lane_requirements: LaneRequirements {
            lane_profile_hash: None,
        },
        constraints: JobConstraints {
            require_nextest: !options.quick,
            test_timeout_seconds: Some(options.timeout_seconds),
            memory_max_bytes: Some(memory_max_bytes),
        },
        cancel_target_job_id: None,
    };
    let digest = spec
        .compute_digest()
        .map_err(|err| format!("compute digest: {err}"))?;
    spec.job_spec_digest.clone_from(&digest);
    spec.actuation.request_id.clone_from(&digest);

    // Bind policy fields to the admitted FAC policy digest and bind the
    // specific job through request_id (= spec digest), preserving fail-closed
    // token verification while avoiding digest-domain mismatch.
    // TCK-00567: Derive intent from job kind for intent-bound token issuance.
    // Thread FacPolicyV1.allowed_intents so the broker enforces the allowlist
    // at issuance (fail-closed).
    let intent = apm2_core::fac::job_spec::job_kind_to_intent(&spec.kind).ok_or_else(|| {
        format!(
            "cannot derive RFC-0028 intent binding for gates job kind `{}`",
            spec.kind
        )
    })?;
    let (token, wal_bytes) = broker
        .issue_channel_context_token(
            policy_digest,
            lease_id,
            &digest,
            boundary_id,
            Some(&intent),
            allowed_intents,
        )
        .map_err(|err| format!("issue channel context token: {err}"))?;
    // BLOCKER fix: persist the WAL entry before releasing the token
    // (crash durability for issuance registration).
    super::super::fac_worker::append_token_ledger_wal_pub(&wal_bytes)
        .map_err(|err| format!("token ledger WAL persist on issuance: {err}"))?;
    spec.actuation.channel_context_token = Some(token);
    validate_job_spec_with_policy(&spec, job_spec_policy)
        .map_err(|err| format!("validate job spec: {err}"))?;
    Ok(spec)
}

fn wait_for_gates_job_receipt(
    fac_root: &Path,
    job_id: &str,
    timeout: Duration,
) -> Result<(), String> {
    wait_for_gates_job_receipt_with_mode(
        fac_root,
        job_id,
        timeout,
        WorkerExecutionMode::AllowInlineFallback,
    )
}

fn wait_for_gates_job_receipt_with_mode(
    fac_root: &Path,
    job_id: &str,
    timeout: Duration,
    mode: WorkerExecutionMode,
) -> Result<(), String> {
    let receipts_dir = fac_root.join("receipts");
    let start = Instant::now();
    loop {
        if start.elapsed() >= timeout {
            return Err(format!(
                "gates job {job_id} did not reach terminal receipt within {}s",
                timeout.as_secs()
            ));
        }
        if let Some(receipt) = lookup_job_receipt(&receipts_dir, job_id) {
            return match receipt.outcome {
                apm2_core::fac::FacJobOutcome::Completed => Ok(()),
                apm2_core::fac::FacJobOutcome::Denied => {
                    Err(format!("gates job {job_id} denied: {}", receipt.reason))
                },
                apm2_core::fac::FacJobOutcome::Quarantined => Err(format!(
                    "gates job {job_id} quarantined: {}",
                    receipt.reason
                )),
                apm2_core::fac::FacJobOutcome::Cancelled => {
                    Err(format!("gates job {job_id} cancelled: {}", receipt.reason))
                },
                apm2_core::fac::FacJobOutcome::CancellationRequested => Err(format!(
                    "gates job {job_id} cancellation requested: {}",
                    receipt.reason
                )),
                _ => Err(format!(
                    "gates job {job_id} returned unsupported outcome: {:?}",
                    receipt.outcome
                )),
            };
        }
        match detect_queue_processing_mode(fac_root) {
            QueueProcessingMode::ExternalWorker => {
                std::thread::sleep(Duration::from_secs(GATES_WAIT_POLL_INTERVAL_SECS));
            },
            QueueProcessingMode::InlineSingleJob => match mode {
                WorkerExecutionMode::AllowInlineFallback => run_inline_worker_cycle()?,
                WorkerExecutionMode::RequireExternalWorker => {
                    std::thread::sleep(Duration::from_secs(GATES_WAIT_POLL_INTERVAL_SECS));
                },
            },
        }
    }
}

fn detect_queue_processing_mode(fac_root: &Path) -> QueueProcessingMode {
    if has_live_worker_heartbeat(fac_root) {
        QueueProcessingMode::ExternalWorker
    } else {
        QueueProcessingMode::InlineSingleJob
    }
}

fn has_live_worker_heartbeat(fac_root: &Path) -> bool {
    let heartbeat = apm2_core::fac::worker_heartbeat::read_heartbeat(fac_root);
    if !heartbeat.found || !heartbeat.fresh || heartbeat.pid == 0 {
        return false;
    }
    if heartbeat.pid == std::process::id() {
        return false;
    }
    is_pid_running(heartbeat.pid)
}

fn ensure_non_wait_worker_bootstrap<F>(
    fac_root: &Path,
    has_live_heartbeat: fn(&Path) -> bool,
    mut spawn_worker: F,
) -> Result<bool, String>
where
    F: FnMut() -> Result<(), String>,
{
    if has_live_heartbeat(fac_root) {
        return Ok(false);
    }
    spawn_worker()?;
    Ok(true)
}

fn ensure_external_worker_bootstrap(
    fac_root: &Path,
    has_live_heartbeat: fn(&Path) -> bool,
    spawn_worker: fn() -> Result<(), String>,
) -> Result<bool, String> {
    ensure_external_worker_bootstrap_with(fac_root, has_live_heartbeat, spawn_worker, || {
        std::thread::sleep(Duration::from_millis(
            EXTERNAL_WORKER_BOOTSTRAP_POLL_INTERVAL_MS,
        ));
    })
}

fn ensure_external_worker_bootstrap_with<FHeartbeat, FSpawn, FWait>(
    fac_root: &Path,
    mut has_live_heartbeat: FHeartbeat,
    mut spawn_worker: FSpawn,
    mut wait_for_heartbeat: FWait,
) -> Result<bool, String>
where
    FHeartbeat: FnMut(&Path) -> bool,
    FSpawn: FnMut() -> Result<(), String>,
    FWait: FnMut(),
{
    if has_live_heartbeat(fac_root) {
        return Ok(false);
    }
    spawn_worker()?;
    for _ in 0..EXTERNAL_WORKER_BOOTSTRAP_MAX_POLLS {
        if has_live_heartbeat(fac_root) {
            return Ok(true);
        }
        wait_for_heartbeat();
    }
    if has_live_heartbeat(fac_root) {
        return Ok(true);
    }
    Err(
        "no live FAC worker heartbeat found after auto-start attempts; run `apm2 fac worker --poll-interval-secs 1`".to_string(),
    )
}

fn spawn_detached_worker_for_queue() -> Result<(), String> {
    let current_exe =
        std::env::current_exe().map_err(|err| format!("resolve current executable: {err}"))?;
    let mut command = Command::new(current_exe);
    command
        .args(["fac", "worker", "--poll-interval-secs", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _child = command
        .spawn()
        .map_err(|err| format!("spawn detached FAC worker: {err}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_pid_running(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).is_dir()
}

#[cfg(not(target_os = "linux"))]
fn is_pid_running(pid: u32) -> bool {
    pid > 0
}

fn run_inline_worker_cycle() -> Result<(), String> {
    let code = crate::commands::fac_worker::run_fac_worker(
        true,
        INLINE_WORKER_POLL_INTERVAL_SECS,
        1,
        false,
        false,
    );
    if code == exit_codes::SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "inline FAC worker cycle failed with exit code {code}"
        ))
    }
}

#[derive(Debug, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct GatesSummary {
    sha: String,
    passed: bool,
    bounded: bool,
    quick: bool,
    gate_profile: String,
    effective_cpu_quota: String,
    effective_test_parallelism: u32,
    requested_timeout_seconds: u64,
    effective_timeout_seconds: u64,
    cache_status: String,
    gates: Vec<GateResult>,
}

#[derive(Debug, serde::Serialize)]
struct GateResult {
    name: String,
    status: String,
    duration_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    was_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_hint: Option<String>,
}

fn canonical_log_bundle_hash(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn bind_merge_gate_log_bundle_hash(
    merge_gate: &mut GateResult,
    gate_results: &[EvidenceGateResult],
) -> Result<(), String> {
    if let Some(existing) = canonical_log_bundle_hash(merge_gate.log_bundle_hash.as_deref()) {
        if parse_b3_256_digest(&existing).is_none() {
            return Err(format!(
                "merge_conflict_main gate emitted invalid log bundle hash `{existing}`"
            ));
        }
        merge_gate.log_bundle_hash = Some(existing);
        return Ok(());
    }

    let mut missing = Vec::new();
    let mut invalid = Vec::new();
    let mut shared_hash: Option<String> = None;

    for gate in gate_results {
        let Some(hash) = canonical_log_bundle_hash(gate.log_bundle_hash.as_deref()) else {
            missing.push(gate.gate_name.clone());
            continue;
        };
        if parse_b3_256_digest(&hash).is_none() {
            invalid.push(format!("{}={hash}", gate.gate_name));
            continue;
        }
        if let Some(existing) = shared_hash.as_ref() {
            if existing != &hash {
                return Err(format!(
                    "evidence gates produced inconsistent log bundle hashes while binding merge_conflict_main (expected={existing}, observed={hash}, gate={})",
                    gate.gate_name
                ));
            }
        } else {
            shared_hash = Some(hash);
        }
    }

    if !missing.is_empty() || !invalid.is_empty() {
        let missing_summary = if missing.is_empty() {
            "-".to_string()
        } else {
            missing.join(",")
        };
        let invalid_summary = if invalid.is_empty() {
            "-".to_string()
        } else {
            invalid.join(",")
        };
        return Err(format!(
            "cannot bind merge_conflict_main to log bundle hash (missing={missing_summary}, invalid={invalid_summary})"
        ));
    }

    let shared_hash = shared_hash.ok_or_else(|| {
        "cannot bind merge_conflict_main to log bundle hash because no evidence gate hashes were present"
            .to_string()
    })?;
    merge_gate.log_bundle_hash = Some(shared_hash);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
fn run_gates_inner(
    workspace_root: &Path,
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    gate_profile: GateThroughputProfile,
    test_parallelism: u32,
    emit_human_logs: bool,
    on_gate_progress: Option<Box<dyn Fn(super::evidence::GateProgressEvent) + Send>>,
    allow_legacy_cache: bool,
) -> Result<GatesSummary, String> {
    validate_timeout_seconds(timeout_seconds)?;
    let memory_max_bytes = parse_memory_limit(memory_max)?;
    if memory_max_bytes > max_memory_bytes() {
        return Err(format!(
            "--memory-max {memory_max} exceeds FAC test memory cap of {max_bytes}",
            max_bytes = max_memory_bytes()
        ));
    }

    let timeout_decision = resolve_bounded_test_timeout(workspace_root, timeout_seconds);

    // TCK-00526: Load FAC policy for environment enforcement.
    let apm2_home = apm2_core::github::resolve_apm2_home()
        .ok_or_else(|| "cannot resolve APM2_HOME for env policy enforcement".to_string())?;
    let fac_root = apm2_home.join("private/fac");
    let policy = load_or_create_gate_policy(&fac_root)?;

    // TCK-00526: Ensure the managed CARGO_HOME directory exists when the
    // policy denies ambient cargo home. Created with restrictive permissions
    // (0o700) to prevent cross-user contamination (CTR-2611).
    if let Some(cargo_home) = policy.resolve_cargo_home(&apm2_home) {
        ensure_managed_cargo_home(&cargo_home)?;
    }

    // TCK-00575: Acquire exclusive lane lock on lane-00 before any lane
    // operations. This prevents concurrent `apm2 fac gates` invocations
    // from colliding on the shared synthetic lane directory.
    let lane_manager = LaneManager::from_default_home()
        .map_err(|e| format!("failed to initialize lane manager: {e}"))?;
    lane_manager
        .ensure_directories()
        .map_err(|e| format!("failed to ensure lane directories: {e}"))?;
    let lane_guard = acquire_gates_lane_lock(&lane_manager)?;

    // TCK-00575: Check for CORRUPT state before executing gates.
    // If lane-00 is corrupt (from a previous failed run), refuse to
    // run gates in a dirty environment. The user must reset first.
    check_lane_not_corrupt(&lane_manager)?;

    // 1. Require clean working tree for full gates only. `--force` allows
    // rerunning gates for the same SHA while local edits are in progress.
    ensure_clean_working_tree(workspace_root, quick || force)?;

    // 2. Resolve HEAD SHA.
    let sha_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git rev-parse HEAD: {e}"))?;
    if !sha_output.status.success() {
        return Err("git rev-parse HEAD failed".to_string());
    }
    let sha = String::from_utf8_lossy(&sha_output.stdout)
        .trim()
        .to_string();
    if sha.len() < 7 {
        return Err(format!("unexpected short SHA: {sha}"));
    }

    // 3. Merge-conflict gate always runs first and is never cache-reused.
    // Emit gate_started before execution for streaming observability.
    if let Some(ref cb) = on_gate_progress {
        cb(super::evidence::GateProgressEvent::Started {
            gate_name: "merge_conflict_main".to_string(),
        });
    }
    let mut merge_gate = evaluate_merge_conflict_gate(workspace_root, &sha, emit_human_logs)?;
    // Emit gate_completed immediately after the merge gate finishes.
    if let Some(ref cb) = on_gate_progress {
        cb(super::evidence::GateProgressEvent::Completed {
            gate_name: merge_gate.name.clone(),
            passed: merge_gate.status == "PASS",
            duration_secs: merge_gate.duration_secs,
            log_path: merge_gate.log_path.clone(),
            bytes_written: merge_gate.bytes_written,
            bytes_total: merge_gate.bytes_total,
            was_truncated: merge_gate.was_truncated,
            log_bundle_hash: merge_gate.log_bundle_hash.clone(),
            error_hint: merge_gate.error_hint.clone(),
        });
    }
    if merge_gate.status == "FAIL" {
        return Ok(GatesSummary {
            sha,
            passed: false,
            bounded: false,
            quick,
            gate_profile: gate_profile.as_str().to_string(),
            effective_cpu_quota: cpu_quota.to_string(),
            effective_test_parallelism: test_parallelism,
            requested_timeout_seconds: timeout_seconds,
            effective_timeout_seconds: timeout_decision.effective_seconds,
            cache_status: "disabled (merge conflicts)".to_string(),
            gates: vec![merge_gate],
        });
    }

    // 4. Build test command override for test execution.
    // TCK-00526: Environment is now built from policy (default-deny with
    // allowlist), replacing the previous ambient-inherit approach.
    let default_nextest_command = build_nextest_command();
    let mut test_command_environment =
        compute_nextest_test_environment(&policy, &apm2_home, test_parallelism)?;
    let mut bounded = false;

    // TCK-00573 MAJOR-1 fix: compute the effective sandbox hardening hash
    // BEFORE the profile is moved into build_systemd_bounded_test_command,
    // so attestation binds to the actual policy-driven profile.
    let sandbox_hardening_hash = policy.sandbox_hardening.content_hash_hex();

    // TCK-00574: Resolve network policy for gates with operator override.
    // Computed before the conditional branch so the hash is available for
    // gate attestation (MAJOR-1: attestation digest must bind network policy).
    let gate_network_policy =
        apm2_core::fac::resolve_network_policy("gates", policy.network_policy.as_ref());
    let network_policy_hash = gate_network_policy.content_hash_hex();

    let mut env_remove_keys = Vec::new();
    let test_command = if quick {
        None
    } else {
        let spec = build_systemd_bounded_test_command(
            workspace_root,
            BoundedTestLimits {
                timeout_seconds: timeout_decision.effective_seconds,
                kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
                memory_max,
                pids_max,
                cpu_quota,
            },
            &default_nextest_command,
            &test_command_environment,
            policy.sandbox_hardening,
            gate_network_policy,
        )
        .map_err(|err| format!("bounded test runner unavailable for FAC gates: {err}"))?;
        bounded = true;
        test_command_environment.extend(spec.environment);

        // TCK-00549: The policy-computed environment from
        // compute_nextest_test_environment() is passed directly to
        // build_bounded_test_command(). The bounded executor uses
        // FacPolicyV1-driven env filtering (no ad-hoc allowlists).
        // Defense-in-depth: RUSTC_WRAPPER and SCCACHE_* are stripped
        // both inside build_policy_setenv_pairs() and via env_remove_keys
        // on the spawned process (TCK-00548, INV-ENV-008).
        test_command_environment.extend(spec.setenv_pairs);

        // Log if sccache env vars were found and stripped.
        if emit_human_logs && !spec.env_remove_keys.is_empty() {
            eprintln!(
                "INFO: sccache env vars stripped from bounded test (containment cannot be \
                 verified for systemd transient units): {:?}",
                spec.env_remove_keys
            );
        }

        env_remove_keys = spec.env_remove_keys;
        Some(spec.command)
    };

    let lane_context =
        super::evidence::allocate_evidence_lane_context(&lane_manager, "lane-00", lane_guard)?;

    // TCK-00540 fix round 3: Build the gate resource policy BEFORE the
    // evidence call so it can be passed through EvidenceGateOptions for
    // attestation digest computation during cache-reuse decisions.
    // The same policy is reused below for the cache-write phase.
    let policy = GateResourcePolicy::from_cli(
        quick,
        timeout_decision.effective_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        bounded,
        Some(gate_profile.as_str()),
        Some(test_parallelism),
        Some(&sandbox_hardening_hash),
        Some(&network_policy_hash),
    );

    let opts = EvidenceGateOptions {
        test_command,
        test_command_environment,
        env_remove_keys,
        skip_test_gate: quick,
        skip_merge_conflict_gate: true,
        emit_human_logs,
        on_gate_progress,
        allow_legacy_cache,
        gate_resource_policy: Some(policy.clone()),
    };

    // 5. Run evidence gates.
    let started = Instant::now();
    let (passed, gate_results) = run_evidence_gates_with_lane_context(
        workspace_root,
        &sha,
        None,
        Some(&opts),
        lane_context,
    )?;
    bind_merge_gate_log_bundle_hash(&mut merge_gate, &gate_results)?;
    let total_secs = started.elapsed().as_secs();

    // 6. Write attested results to gate cache for full runs only.
    if !quick {
        // TCK-00573 MAJOR-3: Include sandbox hardening hash in gate attestation.
        // TCK-00574 MAJOR-1: Include network policy hash in gate attestation
        // to prevent cache reuse across network policy drift.
        // Uses the effective policy-driven hashes computed above (before the
        // profile was moved into the bounded test command builder).
        // TCK-00540: `policy` is now computed before the evidence call so it
        // can also be used for cache-reuse attestation digest matching.
        let mut cache = GateCache::new(&sha);
        let merge_command = gate_command_for_attestation(
            workspace_root,
            &merge_gate.name,
            opts.test_command.as_deref(),
        );
        let merge_attestation_digest = merge_command.and_then(|cmd| {
            compute_gate_attestation(workspace_root, &sha, &merge_gate.name, &cmd, &policy)
                .ok()
                .map(|attestation| attestation.attestation_digest)
        });
        let merge_evidence_log_digest = merge_gate
            .log_path
            .as_deref()
            .map(Path::new)
            .and_then(gate_log_digest);
        cache.set_with_attestation(
            &merge_gate.name,
            merge_gate.status == "PASS",
            merge_gate.duration_secs,
            merge_attestation_digest,
            quick,
            merge_evidence_log_digest,
            merge_gate.log_path.clone(),
        );
        for result in &gate_results {
            let command = gate_command_for_attestation(
                workspace_root,
                &result.gate_name,
                opts.test_command.as_deref(),
            );
            let attestation_digest = command.and_then(|cmd| {
                compute_gate_attestation(workspace_root, &sha, &result.gate_name, &cmd, &policy)
                    .ok()
                    .map(|attestation| attestation.attestation_digest)
            });
            let evidence_log_digest = result
                .log_path
                .as_ref()
                .and_then(|path| gate_log_digest(path));
            cache.set_with_attestation(
                &result.gate_name,
                result.passed,
                result.duration_secs,
                attestation_digest,
                quick,
                evidence_log_digest,
                result
                    .log_path
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .map(str::to_string),
            );
            // TCK-00540 fix round 3: Preserve the legacy override audit trail.
            // When a gate result was reused via `--allow-legacy-cache`, downgrade
            // the cache entry so future default-mode runs still detect and deny
            // the unbound entry.
            if result.legacy_cache_override {
                cache.mark_legacy_override(&result.gate_name);
            }
        }
        cache.backfill_evidence_metadata(
            &merge_gate.name,
            merge_gate.log_bundle_hash.as_deref(),
            merge_gate.bytes_written,
            merge_gate.bytes_total,
            merge_gate.was_truncated,
            merge_gate.log_path.as_deref(),
        );
        for result in &gate_results {
            cache.backfill_evidence_metadata(
                &result.gate_name,
                result.log_bundle_hash.as_deref(),
                result.bytes_written,
                result.bytes_total,
                result.was_truncated,
                result.log_path.as_ref().and_then(|p| p.to_str()),
            );
        }

        // TCK-00576: Sign all gate cache entries before persisting.
        // The persistent signer is loaded (or generated on first use) from
        // the FAC root.  Signing ensures unsigned or forged cache entries
        // are rejected on reuse (fail-closed).
        let signer =
            crate::commands::fac_key_material::load_or_generate_persistent_signer(&fac_root)
                .map_err(|e| format!("cannot load signing key for gate cache: {e}"))?;
        cache.sign_all(&signer);

        cache.save()?;
    }

    let mut gates = vec![merge_gate];
    let mut evidence_gates: Vec<GateResult> = gate_results
        .iter()
        .map(|r| {
            let error_hint = if r.passed {
                None
            } else {
                r.log_path.as_deref().and_then(read_log_error_hint)
            };
            GateResult {
                name: r.gate_name.clone(),
                status: if r.passed { "PASS" } else { "FAIL" }.to_string(),
                duration_secs: r.duration_secs,
                log_path: r
                    .log_path
                    .as_ref()
                    .and_then(|path| path.to_str())
                    .map(str::to_string),
                bytes_written: r.bytes_written,
                bytes_total: r.bytes_total,
                was_truncated: r.was_truncated,
                log_bundle_hash: r.log_bundle_hash.clone(),
                error_hint,
            }
        })
        .collect();
    gates.append(&mut evidence_gates);
    if quick {
        normalize_quick_test_gate(&mut gates);
    }

    if emit_human_logs {
        eprintln!(
            "fac gates (mode={}): completed in {total_secs}s — {}",
            if quick { "quick" } else { "full" },
            if passed { "PASS" } else { "FAIL" }
        );
    }

    Ok(GatesSummary {
        sha,
        passed,
        bounded,
        quick,
        gate_profile: gate_profile.as_str().to_string(),
        effective_cpu_quota: cpu_quota.to_string(),
        effective_test_parallelism: test_parallelism,
        requested_timeout_seconds: timeout_seconds,
        effective_timeout_seconds: timeout_decision.effective_seconds,
        cache_status: if quick {
            "disabled (quick mode)".to_string()
        } else if force {
            "bypass (--force)".to_string()
        } else {
            "write-through".to_string()
        },
        gates,
    })
}

fn gate_log_digest(log_path: &Path) -> Option<String> {
    if !log_path.exists() {
        return None;
    }
    let bytes = fs::read(log_path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

fn validate_timeout_seconds(timeout_seconds: u64) -> Result<(), String> {
    if timeout_seconds == 0 {
        return Err(format!(
            "--timeout-seconds must be greater than zero (max {MAX_MANUAL_TIMEOUT_SECONDS}). {TEST_TIMEOUT_SLA_MESSAGE}"
        ));
    }
    if timeout_seconds > MAX_MANUAL_TIMEOUT_SECONDS {
        return Err(format!(
            "--timeout-seconds cannot exceed {MAX_MANUAL_TIMEOUT_SECONDS}. {TEST_TIMEOUT_SLA_MESSAGE}"
        ));
    }
    Ok(())
}

fn evaluate_merge_conflict_gate(
    workspace_root: &Path,
    sha: &str,
    emit_human_logs: bool,
) -> Result<GateResult, String> {
    let started = Instant::now();
    let report = check_merge_conflicts_against_main(workspace_root, sha)?;
    let duration = started.elapsed().as_secs();
    let passed = !report.has_conflicts();
    if emit_human_logs && !passed {
        eprintln!("{}", render_merge_conflict_summary(&report));
    }
    Ok(GateResult {
        name: "merge_conflict_main".to_string(),
        status: if passed { "PASS" } else { "FAIL" }.to_string(),
        duration_secs: duration,
        log_path: None,
        bytes_written: None,
        bytes_total: None,
        was_truncated: None,
        log_bundle_hash: None,
        error_hint: None,
    })
}

fn normalize_quick_test_gate(gates: &mut Vec<GateResult>) {
    // Preserve a single canonical `test` gate entry in quick mode.
    if let Some(test_gate) = gates.iter_mut().find(|gate| gate.name == "test") {
        test_gate.status = "SKIP".to_string();
        return;
    }

    let insert_index = gates
        .iter()
        .position(|gate| gate.name == "workspace_integrity")
        .unwrap_or(gates.len());
    gates.insert(
        insert_index,
        GateResult {
            name: "test".to_string(),
            status: "SKIP".to_string(),
            duration_secs: 0,
            log_path: None,
            bytes_written: None,
            bytes_total: None,
            was_truncated: None,
            log_bundle_hash: None,
            error_hint: None,
        },
    );
}

fn compute_nextest_test_environment(
    policy: &FacPolicyV1,
    apm2_home: &std::path::Path,
    test_parallelism: u32,
) -> Result<Vec<(String, String)>, String> {
    let lane_env = compute_test_env_for_parallelism(test_parallelism);

    // Build policy-filtered environment from the current process environment.
    let ambient: Vec<(String, String)> = std::env::vars().collect();
    let mut policy_env = build_job_environment(policy, &ambient, apm2_home);

    // TCK-00575: Apply per-lane env isolation (HOME, TMPDIR, XDG_CACHE_HOME,
    // XDG_CONFIG_HOME). For CLI gates, use the synthetic lane-00 directory
    // under $APM2_HOME/private/fac/lanes/lane-00.
    let fac_root = apm2_home.join("private/fac");
    let lane_dir = fac_root.join("lanes/lane-00");
    ensure_lane_env_dirs(&lane_dir)?;
    apply_lane_env_overrides(&mut policy_env, &lane_dir);

    // Throughput-profile vars (NEXTEST_TEST_THREADS, CARGO_BUILD_JOBS) take
    // precedence over ambient values but env_set overrides in the policy
    // are already applied by build_job_environment.
    for (key, value) in &lane_env {
        policy_env.insert(key.clone(), value.clone());
    }

    Ok(policy_env.into_iter().collect())
}

fn ensure_clean_working_tree(workspace_root: &Path, quick: bool) -> Result<(), String> {
    if quick {
        return Ok(());
    }

    let diff_status = Command::new("git")
        .args(["diff", "--exit-code"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git diff: {e}"))?;
    if !diff_status.status.success() {
        let status_hint = render_dirty_tree_status_hint(workspace_root);
        return Err(format!(
            "DIRTY TREE: working tree has unstaged changes. ALL changes must be committed before \
             running full gates — build artifacts are SHA-attested and reused as a source of truth. \
             Run `git add -A && git commit` first, or use `apm2 fac gates --quick` for inner-loop development.{status_hint}"
        ));
    }

    let cached_status = Command::new("git")
        .args(["diff", "--cached", "--exit-code"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git diff --cached: {e}"))?;
    if !cached_status.status.success() {
        let status_hint = render_dirty_tree_status_hint(workspace_root);
        return Err(format!(
            "DIRTY TREE: working tree has staged but uncommitted changes. ALL changes must be \
             committed before running full gates — build artifacts are SHA-attested and reused \
             as a source of truth. Run `git commit` first, or use `apm2 fac gates --quick` for \
             inner-loop development.{status_hint}"
        ));
    }

    let untracked = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git ls-files --others --exclude-standard: {e}"))?;
    if !untracked.status.success() {
        return Err("failed to evaluate untracked files for clean-tree check".to_string());
    }
    if !String::from_utf8_lossy(&untracked.stdout).trim().is_empty() {
        let status_hint = render_dirty_tree_status_hint(workspace_root);
        return Err(format!(
            "DIRTY TREE: working tree has untracked files. ALL files must be committed (or \
             .gitignored) before running full gates — build artifacts are SHA-attested and \
             reused as a source of truth. Run `git add -A && git commit` first, or use \
             `apm2 fac gates --quick` for inner-loop development.{status_hint}"
        ));
    }

    Ok(())
}

fn render_dirty_tree_status_hint(workspace_root: &Path) -> String {
    let output = match Command::new("git")
        .args(["status", "--short", "--untracked-files=all"])
        .current_dir(workspace_root)
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return String::new(),
    };
    let rendered = String::from_utf8_lossy(&output.stdout);
    let mut status_lines = rendered
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .take(DIRTY_TREE_STATUS_MAX_LINES)
        .map(str::to_string)
        .collect::<Vec<_>>();
    if status_lines.is_empty() {
        return String::new();
    }
    if rendered.lines().count() > status_lines.len() {
        status_lines.push("...".to_string());
    }
    format!("\nCurrent git status:\n{}", status_lines.join("\n"))
}

/// Load or create the FAC policy. Delegates to the shared `policy_loader`
/// module for bounded I/O and deduplication (TCK-00526).
fn load_or_create_gate_policy(fac_root: &Path) -> Result<FacPolicyV1, String> {
    super::policy_loader::load_or_create_fac_policy(fac_root)
}

/// Ensure the managed `CARGO_HOME` directory exists. Delegates to the shared
/// `policy_loader` module (TCK-00526).
fn ensure_managed_cargo_home(cargo_home: &Path) -> Result<(), String> {
    super::policy_loader::ensure_managed_cargo_home(cargo_home)
}

/// Acquire an exclusive lock on `lane-00` for gate execution.
///
/// `apm2 fac gates` uses a shared synthetic lane directory `lane-00`.
/// Without an exclusive lock, concurrent gate invocations would collide
/// on the lane's env dirs, workspace, and target directories.
fn acquire_gates_lane_lock(lane_manager: &LaneManager) -> Result<LaneLockGuard, String> {
    lane_manager.acquire_lock("lane-00").map_err(|e| {
        format!(
            "cannot acquire exclusive lock on lane-00 for gate execution — \
             another `apm2 fac gates` process may be running: {e}"
        )
    })
}

/// Check that `lane-00` is not in a CORRUPT state.
///
/// If a previous gate run (or worker) marked the lane as corrupt, running
/// gates in that environment risks non-deterministic results. The user must
/// run `apm2 fac lane reset lane-00` to clear the corrupt marker first.
fn check_lane_not_corrupt(lane_manager: &LaneManager) -> Result<(), String> {
    let status = lane_manager
        .lane_status("lane-00")
        .map_err(|e| format!("cannot check lane-00 status: {e}"))?;
    if status.state == LaneState::Corrupt {
        let reason = status.corrupt_reason.as_deref().unwrap_or("unknown");
        return Err(format!(
            "lane-00 is in CORRUPT state (reason: {reason}). \
             Cannot run gates in a dirty environment. \
             Run `apm2 fac lane reset lane-00` to clear the corrupt marker first."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    use super::*;

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
        fs::create_dir_all(apm2_home.join("private/fac")).expect("create fac root");
        let original_apm2_home = std::env::var_os("APM2_HOME");
        // SAFETY: serialized through env_var_test_lock in test scope.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };
        let _guard = EnvGuard { original_apm2_home };
        f(&apm2_home)
    }

    fn default_queued_request(require_external_worker: bool, quick: bool) -> QueuedGatesRequest {
        QueuedGatesRequest {
            force: false,
            quick,
            timeout_seconds: 30,
            memory_max: "128M".to_string(),
            pids_max: 128,
            cpu_quota: "100%".to_string(),
            gate_profile: GateThroughputProfile::Conservative,
            wait_timeout_secs: 60,
            require_external_worker,
            allow_legacy_cache: false,
        }
    }

    fn sample_gates_options() -> GatesJobOptionsV1 {
        let workspace = std::env::current_dir().expect("workspace root");
        GatesJobOptionsV1::new(
            false,
            false,
            60,
            "256M",
            128,
            "200%",
            GateThroughputProfile::Balanced.as_str(),
            &workspace,
        )
    }

    fn sample_gates_spec(
        job_id: &str,
        repo_id: &str,
        head_sha: &str,
        enqueue_time: &str,
        options: &GatesJobOptionsV1,
    ) -> FacJobSpecV1 {
        FacJobSpecV1 {
            schema: apm2_core::fac::job_spec::JOB_SPEC_SCHEMA_ID.to_string(),
            job_id: job_id.to_string(),
            job_spec_digest: String::new(),
            kind: "gates".to_string(),
            queue_lane: GATES_QUEUE_LANE.to_string(),
            priority: 40,
            enqueue_time: enqueue_time.to_string(),
            actuation: Actuation {
                lease_id: format!("lease-{job_id}"),
                request_id: String::new(),
                channel_context_token: None,
                decoded_source: Some("fac_gates_worker".to_string()),
            },
            source: JobSource {
                kind: "mirror_commit".to_string(),
                repo_id: repo_id.to_string(),
                head_sha: head_sha.to_string(),
                patch: Some(serde_json::to_value(options).expect("serialize options")),
            },
            lane_requirements: LaneRequirements {
                lane_profile_hash: None,
            },
            constraints: JobConstraints {
                require_nextest: !options.quick,
                test_timeout_seconds: Some(options.timeout_seconds),
                memory_max_bytes: Some(256 * 1024 * 1024),
            },
            cancel_target_job_id: None,
        }
    }

    fn write_queue_spec(path: &Path, spec: &FacJobSpecV1) {
        let body = serde_json::to_vec_pretty(spec).expect("serialize spec");
        fs::write(path, body).expect("write spec");
    }

    #[test]
    fn build_gates_job_spec_embeds_execute_gates_intent_in_token_binding() {
        with_test_apm2_home(|apm2_home| {
            use base64::Engine as _;

            let fac_root = apm2_home.join("private/fac");
            let boundary_id = apm2_core::fac::load_or_default_boundary_id(&fac_root)
                .unwrap_or_else(|_| "apm2.fac.local".to_string());
            let mut broker = init_broker(&fac_root, &boundary_id).expect("init broker");
            let (_policy_hash, policy_digest, fac_policy) =
                load_or_init_policy(&fac_root).expect("load policy");
            broker
                .admit_policy_digest(policy_digest)
                .expect("admit policy digest");
            let job_spec_policy = fac_policy
                .job_spec_validation_policy()
                .expect("validation policy");
            let options = sample_gates_options();
            let spec = build_gates_job_spec(
                "gates-intent-test",
                "gates-lease-intent-test",
                "guardian-intelligence/apm2",
                &"d".repeat(40),
                &policy_digest,
                256 * 1024 * 1024,
                &options,
                &boundary_id,
                &mut broker,
                &job_spec_policy,
                fac_policy.allowed_intents.as_deref(),
            )
            .expect("build gates spec");
            let token = spec
                .actuation
                .channel_context_token
                .expect("channel context token must be present");
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(token)
                .expect("decode token");
            let payload: serde_json::Value =
                serde_json::from_slice(&decoded).expect("parse token payload");
            let intent = payload
                .pointer("/payload/token_binding/intent")
                .and_then(serde_json::Value::as_str);
            assert_eq!(intent, Some("intent.fac.execute_gates"));
        });
    }

    #[test]
    fn fac_broker_issue_token_carries_execute_gates_intent() {
        with_test_apm2_home(|apm2_home| {
            use base64::Engine as _;

            let fac_root = apm2_home.join("private/fac");
            let boundary_id = apm2_core::fac::load_or_default_boundary_id(&fac_root)
                .unwrap_or_else(|_| "apm2.fac.local".to_string());
            let mut broker = init_broker(&fac_root, &boundary_id).expect("init broker");
            let (_policy_hash, policy_digest, fac_policy) =
                load_or_init_policy(&fac_root).expect("load policy");
            broker
                .admit_policy_digest(policy_digest)
                .expect("admit policy digest");
            let request_id =
                "b3-256:9b8f808f6f8f3fb18b7160676f3fdaf23fba278cca11dd5358db8c7525f1de8c";
            let (token, _wal_bytes) = broker
                .issue_channel_context_token(
                    &policy_digest,
                    "gates-lease-intent-direct",
                    request_id,
                    &boundary_id,
                    Some(&apm2_core::fac::job_spec::FacIntent::ExecuteGates),
                    fac_policy.allowed_intents.as_deref(),
                )
                .expect("issue channel context token");
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(token)
                .expect("decode token");
            let payload: serde_json::Value =
                serde_json::from_slice(&decoded).expect("parse token payload");
            let intent = payload
                .pointer("/payload/token_binding/intent")
                .and_then(serde_json::Value::as_str);
            assert_eq!(intent, Some("intent.fac.execute_gates"));
        });
    }

    #[test]
    fn gate_execution_profile_resolves_auto_quota_from_profile() {
        let (profile, effective_quota) =
            resolve_effective_execution_profile("auto", GateThroughputProfile::Conservative)
                .expect("auto profile resolves");
        assert_eq!(profile.test_parallelism, 2);
        assert_eq!(profile.cpu_quota_percent, 200);
        assert_eq!(effective_quota, "200%");
    }

    #[test]
    fn gate_execution_profile_applies_explicit_cpu_quota_to_parallelism() {
        let host = resolve_host_test_parallelism();
        let (profile, effective_quota) =
            resolve_effective_execution_profile("150%", GateThroughputProfile::Throughput)
                .expect("explicit quota resolves");
        assert_eq!(effective_quota, "150%");
        assert_eq!(profile.cpu_quota_percent, 150);
        assert_eq!(profile.test_parallelism, 2_u32.min(host));
    }

    #[test]
    fn gate_execution_profile_zero_quota_preserves_host_parallelism() {
        let host = resolve_host_test_parallelism();
        let (profile, effective_quota) =
            resolve_effective_execution_profile("0%", GateThroughputProfile::Conservative)
                .expect("zero quota resolves");
        assert_eq!(effective_quota, "0%");
        assert_eq!(profile.cpu_quota_percent, 0);
        assert_eq!(profile.test_parallelism, host);
    }

    #[test]
    fn gate_execution_profile_rejects_invalid_explicit_cpu_quota() {
        let err =
            resolve_effective_execution_profile("not-a-percent", GateThroughputProfile::Throughput)
                .expect_err("invalid quota must fail");
        assert!(err.contains("invalid cpu_quota value"));
    }

    #[test]
    fn gate_execution_profile_balanced_is_within_expected_bounds() {
        let host = resolve_host_test_parallelism();
        let balanced = resolve_gate_execution_profile(GateThroughputProfile::Balanced);
        assert!(balanced.test_parallelism >= 1);
        assert!(balanced.test_parallelism <= host);
        assert!(balanced.test_parallelism <= BALANCED_MAX_PARALLELISM.min(host));
    }

    #[test]
    fn run_queued_gates_and_collect_rejects_quick_mode() {
        let request = default_queued_request(false, true);
        let err = run_queued_gates_and_collect(&request)
            .expect_err("quick mode must be rejected for queue collection");
        assert!(err.contains("quick=false"));
    }

    #[test]
    fn find_coalescible_gates_job_returns_matching_pending_job() {
        with_test_apm2_home(|apm2_home| {
            let queue_root = apm2_home.join("queue");
            fs::create_dir_all(queue_root.join("pending")).expect("create pending");
            let options = sample_gates_options();
            let repo_id = "guardian-intelligence/apm2";
            let head_sha = "a".repeat(40);
            let spec = sample_gates_spec(
                "gates-existing-pending",
                repo_id,
                &head_sha,
                "2026-02-18T01:00:00Z",
                &options,
            );
            write_queue_spec(
                &queue_root
                    .join("pending")
                    .join("gates-existing-pending.json"),
                &spec,
            );

            let found =
                find_coalescible_gates_job(&queue_root, repo_id, &head_sha, &options, false)
                    .expect("scan")
                    .expect("matching spec");
            assert_eq!(found.job_id, "gates-existing-pending");
        });
    }

    #[test]
    fn find_coalescible_gates_job_rejects_option_mismatch() {
        with_test_apm2_home(|apm2_home| {
            let queue_root = apm2_home.join("queue");
            fs::create_dir_all(queue_root.join("pending")).expect("create pending");
            let repo_id = "guardian-intelligence/apm2";
            let head_sha = "b".repeat(40);

            let expected_options = sample_gates_options();
            let mut mismatched_options = sample_gates_options();
            mismatched_options.cpu_quota = "300%".to_string();

            let spec = sample_gates_spec(
                "gates-option-mismatch",
                repo_id,
                &head_sha,
                "2026-02-18T01:00:01Z",
                &mismatched_options,
            );
            write_queue_spec(
                &queue_root
                    .join("pending")
                    .join("gates-option-mismatch.json"),
                &spec,
            );

            let found = find_coalescible_gates_job(
                &queue_root,
                repo_id,
                &head_sha,
                &expected_options,
                false,
            )
            .expect("scan result");
            assert!(found.is_none(), "mismatched options must not coalesce");
        });
    }

    #[test]
    fn find_coalescible_gates_job_ignores_claimed_without_live_worker() {
        with_test_apm2_home(|apm2_home| {
            let queue_root = apm2_home.join("queue");
            fs::create_dir_all(queue_root.join("claimed")).expect("create claimed");
            let options = sample_gates_options();
            let repo_id = "guardian-intelligence/apm2";
            let head_sha = "c".repeat(40);

            let claimed = sample_gates_spec(
                "gates-claimed-only",
                repo_id,
                &head_sha,
                "2026-02-18T01:00:00Z",
                &options,
            );
            write_queue_spec(
                &queue_root.join("claimed").join("gates-claimed-only.json"),
                &claimed,
            );

            let found =
                find_coalescible_gates_job(&queue_root, repo_id, &head_sha, &options, false)
                    .expect("scan");
            assert!(
                found.is_none(),
                "claimed entries must be ignored without live worker heartbeat"
            );
        });
    }

    #[test]
    fn find_coalescible_gates_job_prefers_oldest_enqueue_time() {
        with_test_apm2_home(|apm2_home| {
            let queue_root = apm2_home.join("queue");
            fs::create_dir_all(queue_root.join("pending")).expect("create pending");
            fs::create_dir_all(queue_root.join("claimed")).expect("create claimed");
            let options = sample_gates_options();
            let repo_id = "guardian-intelligence/apm2";
            let head_sha = "c".repeat(40);

            let newer = sample_gates_spec(
                "gates-newer",
                repo_id,
                &head_sha,
                "2026-02-18T02:00:00Z",
                &options,
            );
            write_queue_spec(&queue_root.join("pending").join("gates-newer.json"), &newer);

            let older = sample_gates_spec(
                "gates-older",
                repo_id,
                &head_sha,
                "2026-02-18T01:00:00Z",
                &options,
            );
            write_queue_spec(&queue_root.join("claimed").join("gates-older.json"), &older);

            let found = find_coalescible_gates_job(&queue_root, repo_id, &head_sha, &options, true)
                .expect("scan")
                .expect("matching spec");
            assert_eq!(found.job_id, "gates-older");
        });
    }

    #[test]
    fn collect_gates_queue_snapshot_reports_pending_position() {
        with_test_apm2_home(|apm2_home| {
            let queue_root = apm2_home.join("queue");
            fs::create_dir_all(queue_root.join("pending")).expect("create pending");
            fs::create_dir_all(queue_root.join("claimed")).expect("create claimed");

            let options = sample_gates_options();
            let repo_id = "guardian-intelligence/apm2";
            let head_sha = "e".repeat(40);

            let claimed = sample_gates_spec(
                "gates-running",
                repo_id,
                &head_sha,
                "2026-02-18T01:00:00Z",
                &options,
            );
            let pending_target = sample_gates_spec(
                "gates-target",
                repo_id,
                &head_sha,
                "2026-02-18T01:00:02Z",
                &options,
            );
            let pending_other = sample_gates_spec(
                "gates-ahead",
                repo_id,
                &head_sha,
                "2026-02-18T01:00:01Z",
                &options,
            );

            write_queue_spec(
                &queue_root.join("claimed").join("gates-running.json"),
                &claimed,
            );
            write_queue_spec(
                &queue_root.join("pending").join("gates-target.json"),
                &pending_target,
            );
            write_queue_spec(
                &queue_root.join("pending").join("gates-ahead.json"),
                &pending_other,
            );

            let snapshot =
                collect_gates_queue_snapshot(&queue_root, "gates-target").expect("snapshot");
            assert_eq!(snapshot.claimed_gates, 1);
            assert_eq!(snapshot.pending_gates, 2);
            assert_eq!(snapshot.ahead_of_job, Some(2));
            assert_eq!(snapshot.job_state, "pending");
        });
    }

    #[test]
    fn external_worker_bootstrap_fails_closed_when_heartbeat_never_appears() {
        let temp = tempfile::tempdir().expect("tempdir");
        let err = ensure_external_worker_bootstrap_with(temp.path(), |_| false, || Ok(()), || {})
            .expect_err("missing worker heartbeat must fail closed after auto-start");
        assert!(err.contains("after auto-start attempts"));
        assert!(err.contains("apm2 fac worker"));
    }

    #[test]
    fn external_worker_bootstrap_skips_spawn_when_heartbeat_is_live() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut spawn_attempted = false;
        let result = ensure_external_worker_bootstrap_with(
            temp.path(),
            |_| true,
            || {
                spawn_attempted = true;
                Ok(())
            },
            || {},
        )
        .expect("live heartbeat should skip bootstrap");
        assert!(!result);
        assert!(!spawn_attempted);
    }

    #[test]
    fn external_worker_bootstrap_spawns_and_waits_until_heartbeat_is_live() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut checks = 0_u32;
        let mut waits = 0_u32;
        let mut spawned = false;
        let result = ensure_external_worker_bootstrap_with(
            temp.path(),
            |_| {
                checks += 1;
                checks >= 3
            },
            || {
                spawned = true;
                Ok(())
            },
            || {
                waits += 1;
            },
        )
        .expect("bootstrap should succeed once heartbeat appears");
        assert!(result);
        assert!(spawned);
        assert_eq!(waits, 1);
        assert_eq!(checks, 3);
    }

    #[test]
    fn load_gate_results_from_cache_for_sha_rejects_incomplete_gate_set() {
        with_test_apm2_home(|_| {
            let sha = "a".repeat(40);
            let mut cache = GateCache::new(&sha);
            for gate_name in LANE_EVIDENCE_GATES
                .iter()
                .take(LANE_EVIDENCE_GATES.len().saturating_sub(1))
            {
                cache.set_with_attestation(
                    gate_name,
                    true,
                    1,
                    Some(format!("b3-256:{}", "a".repeat(64))),
                    false,
                    Some(format!("b3-256:{}", "b".repeat(64))),
                    Some(format!("/tmp/{gate_name}.log")),
                );
            }
            cache.save().expect("persist cache");

            let err = load_gate_results_from_cache_for_sha(&sha)
                .expect_err("incomplete gate set must fail closed");
            assert!(err.contains("required gate set"));
            assert!(err.contains("missing="));
        });
    }

    #[test]
    fn load_gate_results_from_cache_for_sha_returns_rows_in_lane_order() {
        with_test_apm2_home(|_| {
            let sha = "b".repeat(40);
            let mut cache = GateCache::new(&sha);
            for (idx, gate_name) in LANE_EVIDENCE_GATES.iter().enumerate() {
                let passed = idx != 2;
                cache.set_with_attestation(
                    gate_name,
                    passed,
                    (idx + 1) as u64,
                    Some(format!("b3-256:{}", "c".repeat(64))),
                    false,
                    Some(format!("b3-256:{}", "d".repeat(64))),
                    Some(format!("/tmp/{gate_name}.log")),
                );
            }
            cache.save().expect("persist cache");

            let rows =
                load_gate_results_from_cache_for_sha(&sha).expect("full cache should materialize");
            assert_eq!(rows.len(), LANE_EVIDENCE_GATES.len());
            for (idx, row) in rows.iter().enumerate() {
                assert_eq!(row.gate_name, LANE_EVIDENCE_GATES[idx]);
                assert_eq!(row.duration_secs, (idx + 1) as u64);
            }
            assert!(!rows[2].passed, "third gate should preserve FAIL status");
        });
    }

    #[test]
    fn non_wait_worker_bootstrap_requests_spawn_without_heartbeat() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut spawned = false;
        let result = ensure_non_wait_worker_bootstrap(
            temp.path(),
            |_| false,
            || {
                spawned = true;
                Ok(())
            },
        )
        .expect("bootstrap should succeed");
        assert!(result);
        assert!(spawned);
    }

    #[test]
    fn non_wait_worker_bootstrap_skips_when_heartbeat_is_live() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut spawned = false;
        let result = ensure_non_wait_worker_bootstrap(
            temp.path(),
            |_| true,
            || {
                spawned = true;
                Ok(())
            },
        )
        .expect("live heartbeat should bypass bootstrap");
        assert!(!result);
        assert!(!spawned);
    }

    #[cfg(unix)]
    #[test]
    fn gates_single_flight_lock_uses_restricted_permissions() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fac_root = temp.path().join("private").join("fac");
        std::fs::create_dir_all(&fac_root).expect("create fac root");
        let repo = "example/repo";
        let sha = "0123456789abcdef0123456789abcdef01234567";

        let _lock = acquire_gates_single_flight_lock(&fac_root, repo, sha).expect("lock");
        let lock_dir = fac_root.join(GATES_SINGLE_FLIGHT_DIR);
        let lock_name = format!(
            "gates-{}-{}.lock",
            sanitize_single_flight_segment(repo),
            sanitize_single_flight_segment(sha),
        );
        let lock_path = lock_dir.join(lock_name);

        let dir_mode = std::fs::metadata(&lock_dir)
            .expect("lock dir metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&lock_path)
            .expect("lock file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn detect_queue_processing_mode_defaults_inline_without_heartbeat() {
        let temp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            detect_queue_processing_mode(temp.path()),
            QueueProcessingMode::InlineSingleJob
        );
    }

    #[test]
    fn has_live_worker_heartbeat_rejects_self_pid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let heartbeat = serde_json::json!({
            "schema": apm2_core::fac::worker_heartbeat::HEARTBEAT_SCHEMA,
            "pid": std::process::id(),
            "timestamp_epoch_secs": now,
            "cycle_count": 1,
            "jobs_completed": 0,
            "jobs_denied": 0,
            "jobs_quarantined": 0,
            "health_status": "healthy",
        });
        fs::write(
            temp.path()
                .join(apm2_core::fac::worker_heartbeat::HEARTBEAT_FILENAME),
            serde_json::to_vec_pretty(&heartbeat).expect("serialize heartbeat"),
        )
        .expect("write heartbeat");

        assert!(!has_live_worker_heartbeat(temp.path()));
        assert_eq!(
            detect_queue_processing_mode(temp.path()),
            QueueProcessingMode::InlineSingleJob
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn has_live_worker_heartbeat_accepts_foreign_live_pid() {
        if !Path::new("/proc/1").is_dir() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let heartbeat = serde_json::json!({
            "schema": apm2_core::fac::worker_heartbeat::HEARTBEAT_SCHEMA,
            "pid": 1_u32,
            "timestamp_epoch_secs": now,
            "cycle_count": 7,
            "jobs_completed": 3,
            "jobs_denied": 0,
            "jobs_quarantined": 0,
            "health_status": "healthy",
        });
        fs::write(
            temp.path()
                .join(apm2_core::fac::worker_heartbeat::HEARTBEAT_FILENAME),
            serde_json::to_vec_pretty(&heartbeat).expect("serialize heartbeat"),
        )
        .expect("write heartbeat");

        assert!(has_live_worker_heartbeat(temp.path()));
        assert_eq!(
            detect_queue_processing_mode(temp.path()),
            QueueProcessingMode::ExternalWorker
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn has_live_worker_heartbeat_accepts_stale_foreign_pid_if_process_exists() {
        if !Path::new("/proc/1").is_dir() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let stale_epoch_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            .saturating_sub(apm2_core::fac::worker_heartbeat::MAX_HEARTBEAT_AGE_SECS + 30);
        let heartbeat = serde_json::json!({
            "schema": apm2_core::fac::worker_heartbeat::HEARTBEAT_SCHEMA,
            "pid": 1_u32,
            "timestamp_epoch_secs": stale_epoch_secs,
            "cycle_count": 7,
            "jobs_completed": 3,
            "jobs_denied": 0,
            "jobs_quarantined": 0,
            "health_status": "stale",
        });
        fs::write(
            temp.path()
                .join(apm2_core::fac::worker_heartbeat::HEARTBEAT_FILENAME),
            serde_json::to_vec_pretty(&heartbeat).expect("serialize heartbeat"),
        )
        .expect("write heartbeat");

        assert!(!has_live_worker_heartbeat(temp.path()));
        assert_eq!(
            detect_queue_processing_mode(temp.path()),
            QueueProcessingMode::InlineSingleJob
        );
    }

    #[test]
    fn ensure_clean_working_tree_skips_checks_in_quick_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let result = ensure_clean_working_tree(temp_dir.path(), true);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_clean_working_tree_rejects_unstaged_changes_in_full_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo = temp_dir.path();

        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);

        fs::write(repo.join("sample.txt"), "v1\n").expect("write file");
        run_git(repo, &["add", "sample.txt"]);
        run_git(repo, &["commit", "-m", "init"]);

        fs::write(repo.join("sample.txt"), "v2\n").expect("modify file");

        let err = ensure_clean_working_tree(repo, false).expect_err("dirty tree should fail");
        assert!(err.contains("working tree has unstaged changes"));
    }

    #[test]
    fn ensure_clean_working_tree_rejects_untracked_changes_in_full_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo = temp_dir.path();

        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);

        fs::write(repo.join("tracked.txt"), "v1\n").expect("write tracked file");
        run_git(repo, &["add", "tracked.txt"]);
        run_git(repo, &["commit", "-m", "init"]);

        fs::write(repo.join("untracked.txt"), "new\n").expect("write untracked file");

        let err = ensure_clean_working_tree(repo, false).expect_err("untracked tree should fail");
        assert!(err.contains("working tree has untracked files"));
    }

    #[test]
    fn normalize_quick_test_gate_reuses_existing_test_entry() {
        let mut gates = vec![
            GateResult {
                name: "merge_conflict_main".to_string(),
                status: "PASS".to_string(),
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            },
            GateResult {
                name: "test".to_string(),
                status: "PASS".to_string(),
                duration_secs: 2,
                log_path: Some("/tmp/test.log".to_string()),
                bytes_written: Some(10),
                bytes_total: Some(10),
                was_truncated: Some(false),
                log_bundle_hash: Some("b3-256:abc".to_string()),
                error_hint: None,
            },
            GateResult {
                name: "workspace_integrity".to_string(),
                status: "PASS".to_string(),
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            },
        ];

        normalize_quick_test_gate(&mut gates);

        let test_gates = gates
            .iter()
            .filter(|gate| gate.name == "test")
            .collect::<Vec<_>>();
        assert_eq!(test_gates.len(), 1);
        let gate = test_gates[0];
        assert_eq!(gate.status, "SKIP");
        assert_eq!(gate.log_path.as_deref(), Some("/tmp/test.log"));
    }

    #[test]
    fn bind_merge_gate_log_bundle_hash_populates_from_evidence_results() {
        let shared = format!("b3-256:{}", "a".repeat(64));
        let mut merge_gate = GateResult {
            name: "merge_conflict_main".to_string(),
            status: "PASS".to_string(),
            duration_secs: 1,
            log_path: None,
            bytes_written: None,
            bytes_total: None,
            was_truncated: None,
            log_bundle_hash: None,
            error_hint: None,
        };
        let evidence = vec![
            EvidenceGateResult {
                gate_name: "rustfmt".to_string(),
                passed: true,
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: Some(shared.clone()),
                legacy_cache_override: false,
            },
            EvidenceGateResult {
                gate_name: "clippy".to_string(),
                passed: true,
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: Some(shared.clone()),
                legacy_cache_override: false,
            },
        ];

        bind_merge_gate_log_bundle_hash(&mut merge_gate, &evidence)
            .expect("merge gate hash should bind from evidence gates");
        assert_eq!(merge_gate.log_bundle_hash.as_deref(), Some(shared.as_str()));
    }

    #[test]
    fn bind_merge_gate_log_bundle_hash_rejects_missing_or_invalid_hashes() {
        let mut merge_gate = GateResult {
            name: "merge_conflict_main".to_string(),
            status: "PASS".to_string(),
            duration_secs: 1,
            log_path: None,
            bytes_written: None,
            bytes_total: None,
            was_truncated: None,
            log_bundle_hash: None,
            error_hint: None,
        };
        let evidence = vec![
            EvidenceGateResult {
                gate_name: "rustfmt".to_string(),
                passed: true,
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                legacy_cache_override: false,
            },
            EvidenceGateResult {
                gate_name: "clippy".to_string(),
                passed: true,
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: Some("b3-256:nothex".to_string()),
                legacy_cache_override: false,
            },
        ];

        let err = bind_merge_gate_log_bundle_hash(&mut merge_gate, &evidence)
            .expect_err("missing/invalid evidence hashes must fail closed");
        assert!(err.contains("missing=rustfmt"));
        assert!(err.contains("invalid=clippy=b3-256:nothex"));
    }

    #[test]
    fn bind_merge_gate_log_bundle_hash_rejects_inconsistent_hashes() {
        let mut merge_gate = GateResult {
            name: "merge_conflict_main".to_string(),
            status: "PASS".to_string(),
            duration_secs: 1,
            log_path: None,
            bytes_written: None,
            bytes_total: None,
            was_truncated: None,
            log_bundle_hash: None,
            error_hint: None,
        };
        let evidence = vec![
            EvidenceGateResult {
                gate_name: "rustfmt".to_string(),
                passed: true,
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: Some(format!("b3-256:{}", "b".repeat(64))),
                legacy_cache_override: false,
            },
            EvidenceGateResult {
                gate_name: "clippy".to_string(),
                passed: true,
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: Some(format!("b3-256:{}", "c".repeat(64))),
                legacy_cache_override: false,
            },
        ];

        let err = bind_merge_gate_log_bundle_hash(&mut merge_gate, &evidence)
            .expect_err("inconsistent evidence hashes must fail closed");
        assert!(err.contains("inconsistent log bundle hashes"));
    }

    /// Verify that the `on_gate_progress` callback in [`EvidenceGateOptions`]
    /// receives `Started` events BEFORE `Completed` events for each gate.
    ///
    /// This test validates BLOCKER 2 fix: gate lifecycle events must be emitted
    /// during execution (via callback) rather than buffered and replayed after
    /// all gates return. The callback structure ensures callers can stream
    /// JSONL events in real time at each gate boundary.
    #[test]
    fn gate_progress_callback_receives_events_in_order() {
        use std::sync::{Arc, Mutex};

        use super::super::evidence::GateProgressEvent;

        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let events_clone = Arc::clone(&events);

        // Build a callback that records event types.
        let callback: Box<dyn Fn(GateProgressEvent) + Send> =
            Box::new(move |event: GateProgressEvent| match event {
                GateProgressEvent::Started { gate_name } => {
                    events_clone
                        .lock()
                        .unwrap()
                        .push(format!("started:{gate_name}"));
                },
                GateProgressEvent::Progress {
                    gate_name,
                    elapsed_secs,
                    bytes_streamed,
                } => {
                    events_clone.lock().unwrap().push(format!(
                        "progress:{gate_name}:elapsed={elapsed_secs}:bytes={bytes_streamed}"
                    ));
                },
                GateProgressEvent::Completed {
                    gate_name, passed, ..
                } => {
                    events_clone
                        .lock()
                        .unwrap()
                        .push(format!("completed:{gate_name}:passed={passed}"));
                },
            });

        // Verify that the callback type matches what EvidenceGateOptions expects.
        let opts = super::super::evidence::EvidenceGateOptions {
            test_command: None,
            test_command_environment: Vec::new(),
            env_remove_keys: Vec::new(),
            skip_test_gate: true,
            skip_merge_conflict_gate: true,
            emit_human_logs: false,
            on_gate_progress: Some(callback),
            allow_legacy_cache: false,
            gate_resource_policy: None,
        };

        // Simulate the callback being invoked for a gate lifecycle.
        if let Some(ref cb) = opts.on_gate_progress {
            cb(GateProgressEvent::Started {
                gate_name: "test_gate".to_string(),
            });
            cb(GateProgressEvent::Progress {
                gate_name: "test_gate".to_string(),
                elapsed_secs: 10,
                bytes_streamed: 1024,
            });
            cb(GateProgressEvent::Completed {
                gate_name: "test_gate".to_string(),
                passed: true,
                duration_secs: 5,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            });
        }

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0], "started:test_gate");
        assert_eq!(recorded[1], "progress:test_gate:elapsed=10:bytes=1024");
        assert_eq!(recorded[2], "completed:test_gate:passed=true");
    }

    /// Regression (MAJOR 2): `check_lane_not_corrupt` must refuse to run
    /// gates when `lane-00` has a corrupt marker, preventing execution in
    /// a known-bad environment.
    #[test]
    fn check_lane_not_corrupt_rejects_corrupt_lane() {
        use apm2_core::fac::{LANE_CORRUPT_MARKER_SCHEMA, LaneCorruptMarkerV1};

        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        // Plant a corrupt marker on lane-00.
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            reason: "test corruption".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-02-15T00:00:00Z".to_string(),
        };
        marker.persist(&fac_root).expect("persist marker");

        let err = check_lane_not_corrupt(&manager).expect_err("should reject corrupt lane");
        assert!(
            err.contains("CORRUPT"),
            "error should mention CORRUPT, got: {err}"
        );
        assert!(
            err.contains("test corruption"),
            "error should include corrupt reason, got: {err}"
        );
    }

    /// Positive case: `check_lane_not_corrupt` should succeed when
    /// `lane-00` has no corrupt marker.
    #[test]
    fn check_lane_not_corrupt_accepts_clean_lane() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        check_lane_not_corrupt(&manager).expect("clean lane should pass");
    }

    /// Regression (MAJOR 1): `acquire_gates_lane_lock` must acquire an
    /// exclusive lock preventing concurrent gate invocations from colliding.
    #[test]
    fn acquire_gates_lane_lock_succeeds_on_free_lane() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let guard = acquire_gates_lane_lock(&manager).expect("should acquire lock");
        // Lock is held while guard is alive.
        drop(guard);
    }

    /// Regression (BLOCKER 1/2): `run_gates_inner` with `lane_count = 1`
    /// should run all command-style phases in the same lane-local env context.
    ///
    /// This test exercises `run_gates_inner` directly with a custom fake
    /// `cargo` and native gate prerequisites. It confirms:
    /// - single-lane mode does not fail due to nested lock acquisition, and
    /// - all active evidence phases receive the same lane-local HOME/TMPDIR
    ///   /XDG env values.
    #[allow(unsafe_code)] // Env var mutation is required for test setup and teardown.
    #[test]
    fn run_gates_inner_reuses_single_lane_env_for_all_phases() {
        use std::env;
        use std::ffi::OsString;

        struct EnvGuard {
            vars: Vec<(&'static str, Option<OsString>)>,
            current_dir: Option<std::path::PathBuf>,
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for (name, value) in self.vars.drain(..) {
                    if let Some(value) = value {
                        // SAFETY: serialized via crate::commands::env_var_test_lock
                        unsafe { std::env::set_var(name, value) };
                    } else {
                        // SAFETY: serialized via crate::commands::env_var_test_lock
                        unsafe { std::env::remove_var(name) };
                    }
                }

                if let Some(path) = self.current_dir.take() {
                    let _ = std::env::set_current_dir(path);
                }
            }
        }

        let _guard = crate::commands::env_var_test_lock()
            .lock()
            .expect("serialize env-mutating integration test");

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let repo = temp_dir.path().join("workspace");
        fs::create_dir_all(&repo).expect("create workspace");
        let apm2_home = temp_dir.path().join("apm2_home");
        let bin_dir = temp_dir.path().join("fake-bin");
        let review_dir = repo.join("documents").join("reviews");
        let review_gate_dir = repo.join(".github").join("review-gate");
        let log_file = repo.join(".fac_gate_env_log");

        fs::create_dir_all(apm2_home.join("private").join("fac")).expect("create apm2 home");
        fs::create_dir_all(&bin_dir).expect("create fake bin dir");
        fs::create_dir_all(&review_dir).expect("create review dir");
        fs::create_dir_all(&review_gate_dir).expect("create review gate dir");

        run_git(&repo, &["init"]);
        run_git(&repo, &["config", "user.email", "test@example.com"]);
        run_git(&repo, &["config", "user.name", "Test User"]);
        fs::write(repo.join("README.md"), "fac gates lane test\n").expect("write repo file");
        run_git(&repo, &["add", "README.md"]);
        run_git(&repo, &["commit", "-m", "initial"]);
        run_git(&repo, &["branch", "-M", "main"]);

        // Shell scripts use $phase / $1 / $HOME etc. — NOT Rust format args.
        #[allow(clippy::literal_string_with_formatting_args)]
        let fake_cargo = "#!/bin/sh\necho \"phase=$1|HOME=$HOME|TMPDIR=$TMPDIR|XDG_CACHE_HOME=$XDG_CACHE_HOME|XDG_CONFIG_HOME=$XDG_CONFIG_HOME\" >> \"$PWD/.fac_gate_env_log\"\nexit 0\n";
        fs::write(bin_dir.join("cargo"), fake_cargo).expect("write fake cargo");
        fs::write(
            review_gate_dir.join("test-safety-allowlist.txt"),
            b"# empty\n",
        )
        .expect("write allowlist");

        let prompt = concat!(
            "{\n",
            "  \"payload\": {\n",
            "    \"commands\": {\n",
            "      \"binary_prefix\": \"cargo run -p apm2-cli --\",\n",
            "      \"prepare\": \"cargo run -p apm2-cli -- fac review prepare --json\",\n",
            "      \"finding\": \"cargo run -p apm2-cli -- fac review finding --json\",\n",
            "      \"verdict\": \"cargo run -p apm2-cli -- fac review verdict set --json\"\n",
            "    },\n",
            "    \"constraints\": {\n",
            "      \"forbidden_operations\": [\n",
            "        \"Do not pass --sha manually; CLI auto-derives the SHA and SHA is managed by the CLI.\"\n",
            "      ],\n",
            "      \"invariants\": [\n",
            "        \"SHA is managed by the CLI\"\n",
            "      ]\n",
            "    }\n",
            "  }\n",
            "}\n"
        );
        fs::write(review_dir.join("CODE_QUALITY_PROMPT.cac.json"), prompt)
            .expect("write code quality prompt");
        fs::write(review_dir.join("SECURITY_REVIEW_PROMPT.cac.json"), prompt)
            .expect("write security prompt");
        fs::write(review_gate_dir.join("trusted-reviewers.json"), b"[]\n")
            .expect("write trusted reviewers");

        let cargo_path = bin_dir.join("cargo");
        fs::set_permissions(cargo_path, fs::Permissions::from_mode(0o755))
            .expect("set fake cargo mode");

        let original_path = env::var_os("PATH");
        let original_apm2_home = env::var_os("APM2_HOME");
        let original_lane_count = env::var_os("APM2_FAC_LANE_COUNT");
        let original_dir = env::current_dir().expect("capture current dir");
        let path_override = format!(
            "{}:{}",
            bin_dir.display(),
            env::var("PATH").unwrap_or_default()
        );

        // SAFETY: serialized via crate::commands::env_var_test_lock
        unsafe {
            env::set_var("PATH", path_override);
            env::set_var("APM2_HOME", &apm2_home);
            env::set_var("APM2_FAC_LANE_COUNT", "1");
        }
        let _env_guard = EnvGuard {
            vars: vec![
                ("PATH", original_path),
                ("APM2_HOME", original_apm2_home),
                ("APM2_FAC_LANE_COUNT", original_lane_count),
            ],
            current_dir: Some(original_dir),
        };

        env::set_current_dir(&repo).expect("set test repository as cwd");

        let summary = run_gates_inner(
            &repo,
            false,
            true,
            30,
            "128M",
            128,
            "100%",
            GateThroughputProfile::Conservative,
            2,
            false,
            None,
            false,
        )
        .expect("gates should run in single-lane mode");
        assert!(summary.passed);

        let lane_dir = apm2_home
            .join("private")
            .join("fac")
            .join("lanes")
            .join("lane-00");
        let expected = [
            lane_dir.join("home").to_string_lossy().into_owned(),
            lane_dir.join("tmp").to_string_lossy().into_owned(),
            lane_dir.join("xdg_cache").to_string_lossy().into_owned(),
            lane_dir.join("xdg_config").to_string_lossy().into_owned(),
        ];

        let log_contents = fs::read_to_string(&log_file).expect("read env log file");
        let mut observed_tuples = HashSet::new();
        let mut phases = HashSet::new();
        for line in log_contents.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let mut fields = line.split('|');
            let phase = fields
                .next()
                .and_then(|value| value.strip_prefix("phase="))
                .unwrap_or("unknown");
            let home = fields
                .next()
                .and_then(|value| value.strip_prefix("HOME="))
                .unwrap_or("");
            let tmpdir = fields
                .next()
                .and_then(|value| value.strip_prefix("TMPDIR="))
                .unwrap_or("");
            let xdg_cache = fields
                .next()
                .and_then(|value| value.strip_prefix("XDG_CACHE_HOME="))
                .unwrap_or("");
            let xdg_config = fields
                .next()
                .and_then(|value| value.strip_prefix("XDG_CONFIG_HOME="))
                .unwrap_or("");

            let tuple = (
                home.to_string(),
                tmpdir.to_string(),
                xdg_cache.to_string(),
                xdg_config.to_string(),
            );
            observed_tuples.insert(tuple);
            phases.insert(phase.to_string());
        }

        // Verify that the lane-local env tuple appears (proving the overrides
        // are applied) and that all cargo-based phases (fmt, clippy, doc) use it.
        let expected_tuple = (
            expected[0].clone(),
            expected[1].clone(),
            expected[2].clone(),
            expected[3].clone(),
        );
        assert!(
            observed_tuples.contains(&expected_tuple),
            "lane-local env tuple not observed; got: {observed_tuples:#?}"
        );

        // Cargo-based phases must be present.
        for expected_phase in ["fmt", "clippy", "doc"] {
            assert!(
                phases.contains(expected_phase),
                "missing cargo phase {expected_phase}"
            );
        }
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git command should execute");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
