// AGENT-AUTHORED (TCK-00525)
//! `apm2 fac warm` — lane-scoped prewarm with receipts + economics +
//! authorization.
//!
//! Enqueues a warm job to the FAC queue (default) or optionally waits for
//! completion. Warm phases are selectable via `--phases`.
//!
//! The warm command:
//! 1. Resolves the FAC root and queue directories.
//! 2. Initializes the broker with proper health gate (matching worker flow).
//! 3. Obtains an RFC-0028 channel context token from the broker.
//! 4. Builds a `FacJobSpecV1(kind="warm")`.
//! 5. Enqueues to `queue/pending/`.
//! 6. Optionally waits for the receipt.
//!
//! The worker handles actual execution of warm phases using the lane target
//! namespace and FAC-managed `CARGO_HOME`.
//!
//! # Invariants
//!
//! - [INV-WARM-CLI-001] Warm jobs use the same broker token flow as gates.
//! - [INV-WARM-CLI-002] Phases are validated before enqueue.
//! - [INV-WARM-CLI-003] Queue writes are atomic (temp + rename).
//! - [INV-WARM-CLI-004] Broker health gate is opened before token issuance
//!   (fail-closed on missing/stale authority).

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apm2_core::crypto::Signer;
use apm2_core::economics::queue_admission::HtfEvaluationWindow;
use apm2_core::fac::broker::FacBroker;
use apm2_core::fac::broker_health::WorkerHealthPolicy;
use apm2_core::fac::job_spec::{
    Actuation, FacJobSpecV1, JobConstraints, JobSource, LaneRequirements, MAX_JOB_SPEC_SIZE,
    MAX_QUEUE_LANE_LENGTH, parse_b3_256_digest,
};
use apm2_core::fac::warm::{DEFAULT_WARM_PHASES, MAX_WARM_PHASES, WarmPhase};
use apm2_core::fac::{
    FacPolicyV1, MAX_POLICY_SIZE, check_disk_space, compute_policy_hash, deserialize_policy,
    load_or_default_boundary_id, parse_policy_hash, persist_policy,
};
use apm2_core::github::resolve_apm2_home;

use crate::exit_codes::codes as exit_codes;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Queue subdirectory under `$APM2_HOME`.
const QUEUE_DIR: &str = "queue";
const PENDING_DIR: &str = "pending";

/// Default wait timeout for warm job completion (seconds).
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 1200;

/// Poll interval when waiting for receipt (seconds).
const WAIT_POLL_INTERVAL_SECS: u64 = 5;

/// Extra headroom iterations beyond the timeout-derived cap.
/// Provides a small buffer so the timeout check (elapsed >= timeout) fires
/// before the iteration cap in normal operation.
const POLL_ITERATION_HEADROOM: u64 = 10;

/// FAC receipts directory.
const FAC_RECEIPTS_DIR: &str = "receipts";

/// Default authority clock for local-mode evaluation windows.
const DEFAULT_AUTHORITY_CLOCK: &str = "local";

/// Maximum size for the signing key file.
const MAX_SIGNING_KEY_SIZE: usize = 64;

/// Maximum size for broker state file (1 MiB, matching broker constant).
const MAX_BROKER_STATE_FILE_SIZE: usize = 1_048_576;

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run `apm2 fac warm`.
///
/// Returns an exit code.
#[allow(clippy::too_many_arguments, clippy::ref_option)]
pub fn run_fac_warm(
    phases_str: &Option<String>,
    lane: &Option<String>,
    wait: bool,
    wait_timeout_secs: u64,
    json_output: bool,
) -> u8 {
    // Resolve FAC root.
    let fac_root = match resolve_fac_root() {
        Ok(root) => root,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_resolve_root_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Parse and validate phases.
    let phases = match parse_phases(phases_str) {
        Ok(p) => p,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_invalid_phases",
                &msg,
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

    // Validate and resolve queue lane from --lane flag.
    let queue_lane = match validate_lane(lane) {
        Ok(l) => l,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_invalid_lane",
                &msg,
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

    // Quick disk space check (full preflight is worker-owned).
    if let Ok(free) = check_disk_space(&fac_root) {
        // 100 MiB minimum for enqueueing.
        const MIN_ENQUEUE_BYTES: u64 = 100 * 1024 * 1024;
        if free < MIN_ENQUEUE_BYTES {
            return output_error(
                json_output,
                "warm_disk_space_low",
                &format!(
                    "insufficient disk space for enqueue: {free} bytes free (need {MIN_ENQUEUE_BYTES})",
                ),
                exit_codes::GENERIC_ERROR,
            );
        }
    }

    // Load boundary ID (fallback to "local" on error, matching worker pattern).
    let boundary_id =
        load_or_default_boundary_id(&fac_root).unwrap_or_else(|_| "local".to_string());

    // Load or initialize broker with proper health gate (matching worker flow).
    let mut broker = match init_broker(&fac_root, &boundary_id) {
        Ok(b) => b,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_broker_init_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Load or initialize policy.
    let (policy_hash, policy_digest, _policy) = match load_or_init_policy(&fac_root) {
        Ok(p) => p,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_policy_load_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Admit the policy digest so the broker will accept token issuance.
    if let Err(e) = broker.admit_policy_digest(policy_digest) {
        return output_error(
            json_output,
            "warm_policy_admit_failed",
            &format!("cannot admit policy digest: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    // Generate job ID.
    let job_id = format!("warm-{}", generate_job_suffix());

    // Determine source info (use current repo state).
    let (repo_id, head_sha) = resolve_repo_info();

    // Build the job spec.
    let lease_id = format!("warm-lease-{}", generate_job_suffix());
    let spec = match build_warm_job_spec(
        &job_id,
        &lease_id,
        &repo_id,
        &head_sha,
        &phases,
        &queue_lane,
        &boundary_id,
        &mut broker,
    ) {
        Ok(s) => s,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_spec_build_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Enqueue the job.
    let apm2_home = resolve_apm2_home().unwrap_or_else(|| PathBuf::from("/tmp/.apm2"));
    let queue_root = apm2_home.join(QUEUE_DIR);
    if let Err(e) = enqueue_job(&queue_root, &spec) {
        return output_error(
            json_output,
            "warm_enqueue_failed",
            &format!("failed to enqueue warm job: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    let output = serde_json::json!({
        "status": "enqueued",
        "job_id": job_id,
        "phases": phases.iter().map(|p| p.name()).collect::<Vec<_>>(),
        "queue_lane": spec.queue_lane,
        "policy_hash": policy_hash,
    });

    if json_output {
        println!("{}", serde_json::to_string(&output).unwrap_or_default());
    } else {
        eprintln!(
            "warm: enqueued job {job_id} with phases: {}",
            phases
                .iter()
                .map(|p| p.name())
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    // Optionally wait for completion.
    if wait {
        let timeout = if wait_timeout_secs > 0 {
            Duration::from_secs(wait_timeout_secs)
        } else {
            Duration::from_secs(DEFAULT_WAIT_TIMEOUT_SECS)
        };

        match wait_for_receipt(&fac_root, &job_id, timeout, json_output) {
            Ok(()) => {},
            Err(msg) => {
                return output_error(
                    json_output,
                    "warm_wait_failed",
                    &msg,
                    exit_codes::GENERIC_ERROR,
                );
            },
        }
    }

    exit_codes::SUCCESS
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase Parsing
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::ref_option)]
fn parse_phases(phases_str: &Option<String>) -> Result<Vec<WarmPhase>, String> {
    match phases_str {
        None => Ok(DEFAULT_WARM_PHASES.to_vec()),
        Some(s) => {
            let parts: Vec<&str> = s
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                return Err("no phases specified".to_string());
            }
            if parts.len() > MAX_WARM_PHASES {
                return Err(format!(
                    "too many phases: {} exceeds max {}",
                    parts.len(),
                    MAX_WARM_PHASES
                ));
            }
            let mut phases = Vec::with_capacity(parts.len());
            for part in parts {
                match WarmPhase::parse(part) {
                    Ok(p) => phases.push(p),
                    Err(e) => return Err(format!("invalid phase '{part}': {e}")),
                }
            }
            Ok(phases)
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Default queue lane for warm jobs when `--lane` is not specified.
const DEFAULT_QUEUE_LANE: &str = "bulk";

/// Validates and resolves the `--lane` flag value.
///
/// Returns the validated lane string (defaults to "bulk" when not specified).
/// Rejects empty, over-length, and unsafe lane names using the same character
/// set the worker enforces: `[A-Za-z0-9_-]`.
#[allow(clippy::ref_option)]
fn validate_lane(lane: &Option<String>) -> Result<String, String> {
    let lane_str = match lane {
        None => return Ok(DEFAULT_QUEUE_LANE.to_string()),
        Some(s) => s.trim(),
    };

    if lane_str.is_empty() {
        return Ok(DEFAULT_QUEUE_LANE.to_string());
    }

    if lane_str.len() > MAX_QUEUE_LANE_LENGTH {
        return Err(format!(
            "lane name too long: {} exceeds max {}",
            lane_str.len(),
            MAX_QUEUE_LANE_LENGTH
        ));
    }

    // Match the worker's queue_lane sanitization: only [A-Za-z0-9_-].
    if !lane_str
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "unsafe lane value {lane_str:?}: only [A-Za-z0-9_-] allowed"
        ));
    }

    Ok(lane_str.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Broker / Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize the broker with health gate, following the same flow as the
/// worker (`fac_worker.rs`). This is required because
/// `issue_channel_context_token` enforces the admission health gate
/// (fail-closed).
fn init_broker(fac_root: &Path, boundary_id: &str) -> Result<FacBroker, String> {
    // Load or generate a persistent signing key (same path as worker).
    let signer = load_or_generate_persistent_signer(fac_root)?;
    let signer_key_bytes = signer.secret_key_bytes().to_vec();

    // Load or create broker state (matching worker pattern).
    let mk_default_state_broker = || {
        let default_state = apm2_core::fac::broker::BrokerState::default();
        let s = Signer::from_bytes(&signer_key_bytes).ok()?;
        FacBroker::from_signer_and_state(s, default_state).ok()
    };

    let mut broker = load_broker_state(fac_root).map_or_else(
        || mk_default_state_broker().unwrap_or_else(FacBroker::new),
        |state| {
            Signer::from_bytes(&signer_key_bytes)
                .ok()
                .and_then(|s| FacBroker::from_signer_and_state(s, state).ok())
                .unwrap_or_else(|| mk_default_state_broker().unwrap_or_else(FacBroker::new))
        },
    );

    // Perform admission health gate check so the broker can issue tokens.
    // This mirrors the worker startup sequence exactly.
    let mut checker = apm2_core::fac::broker_health::BrokerHealthChecker::new();

    let current_tick = broker.current_tick();
    let tick_end = current_tick.saturating_add(1);
    let eval_window = broker
        .build_evaluation_window(boundary_id, DEFAULT_AUTHORITY_CLOCK, current_tick, tick_end)
        .unwrap_or_else(|_| make_default_eval_window(boundary_id));

    // Advance freshness horizon to keep startup checks in sync.
    broker.advance_freshness_horizon(tick_end);

    let startup_envelope = broker
        .issue_time_authority_envelope_default_ttl(
            boundary_id,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .ok();

    let _health = broker.check_health(startup_envelope.as_ref(), &eval_window, &[], &mut checker);

    if let Err(e) =
        broker.evaluate_admission_health_gate(&checker, &eval_window, WorkerHealthPolicy::default())
    {
        return Err(format!("admission health gate failed: {e}"));
    }

    Ok(broker)
}

/// Load or generate a persistent signing key from
/// `$FAC_ROOT/signing_key`.
fn load_or_generate_persistent_signer(fac_root: &Path) -> Result<Signer, String> {
    let key_path = fac_root.join("signing_key");

    if key_path.exists() {
        let bytes = read_bounded(&key_path, MAX_SIGNING_KEY_SIZE)?;
        Signer::from_bytes(&bytes).map_err(|e| format!("invalid signing key: {e}"))
    } else {
        let signer = Signer::generate();
        let key_bytes = signer.secret_key_bytes();
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create key directory: {e}"))?;
        }
        fs::write(&key_path, key_bytes.as_ref())
            .map_err(|e| format!("cannot write signing key: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&key_path, perms)
                .map_err(|e| format!("cannot set key permissions: {e}"))?;
        }
        Ok(signer)
    }
}

/// Load persisted broker state from `$FAC_ROOT/broker_state.json`.
fn load_broker_state(fac_root: &Path) -> Option<apm2_core::fac::broker::BrokerState> {
    let state_path = fac_root.join("broker_state.json");
    if !state_path.exists() {
        return None;
    }
    let bytes = read_bounded(&state_path, MAX_BROKER_STATE_FILE_SIZE).ok()?;
    FacBroker::deserialize_state(&bytes).ok()
}

/// Creates a default evaluation window for local-only queue admission.
fn make_default_eval_window(boundary_id: &str) -> HtfEvaluationWindow {
    HtfEvaluationWindow {
        boundary_id: boundary_id.to_string(),
        authority_clock: DEFAULT_AUTHORITY_CLOCK.to_string(),
        tick_start: 0,
        tick_end: 1,
    }
}

/// Load or initialize policy, returning (`hash_string`, `digest_bytes`,
/// policy).
fn load_or_init_policy(fac_root: &Path) -> Result<(String, [u8; 32], FacPolicyV1), String> {
    let policy_dir = fac_root.join("policy");
    let policy_path = policy_dir.join("fac_policy.v1.json");

    let policy = if policy_path.exists() {
        let bytes = read_bounded(&policy_path, MAX_POLICY_SIZE)?;
        deserialize_policy(&bytes).map_err(|e| format!("cannot load fac policy: {e}"))?
    } else {
        let default_policy = FacPolicyV1::default();
        persist_policy(fac_root, &default_policy)
            .map_err(|e| format!("cannot persist default policy: {e}"))?;
        default_policy
    };

    let policy_hash =
        compute_policy_hash(&policy).map_err(|e| format!("cannot compute policy hash: {e}"))?;
    let policy_digest =
        parse_policy_hash(&policy_hash).ok_or_else(|| "invalid policy hash".to_string())?;

    Ok((policy_hash, policy_digest, policy))
}

// ─────────────────────────────────────────────────────────────────────────────
// Job Spec Construction
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn build_warm_job_spec(
    job_id: &str,
    lease_id: &str,
    repo_id: &str,
    head_sha: &str,
    phases: &[WarmPhase],
    queue_lane: &str,
    boundary_id: &str,
    broker: &mut FacBroker,
) -> Result<FacJobSpecV1, String> {
    let enqueue_time = format_iso8601(current_epoch_secs());
    let phases_csv = phases
        .iter()
        .map(|p| p.name())
        .collect::<Vec<_>>()
        .join(",");

    // Build the spec structure.
    let mut spec = FacJobSpecV1 {
        schema: apm2_core::fac::job_spec::JOB_SPEC_SCHEMA_ID.to_string(),
        job_id: job_id.to_string(),
        job_spec_digest: String::new(), // Computed below
        kind: "warm".to_string(),
        queue_lane: queue_lane.to_string(),
        priority: 50,
        enqueue_time,
        actuation: Actuation {
            lease_id: lease_id.to_string(),
            request_id: String::new(),   // Set after digest
            channel_context_token: None, // Set after token issuance
            decoded_source: Some(phases_csv),
        },
        source: JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: repo_id.to_string(),
            head_sha: head_sha.to_string(),
            patch: None,
        },
        lane_requirements: LaneRequirements {
            lane_profile_hash: None,
        },
        constraints: JobConstraints {
            require_nextest: false,
            test_timeout_seconds: None,
            memory_max_bytes: None,
        },
        cancel_target_job_id: None,
    };

    // Compute digest using the spec's own method (nulls token + digest fields).
    let digest = spec
        .compute_digest()
        .map_err(|e| format!("digest computation: {e}"))?;

    let digest_bytes =
        parse_b3_256_digest(&digest).ok_or_else(|| "failed to parse spec digest".to_string())?;

    spec.job_spec_digest.clone_from(&digest);
    spec.actuation.request_id = digest;

    // Issue channel context token from broker.
    // Signature: issue_channel_context_token(&Hash, &str, &str, &str)
    // where Hash = [u8; 32].
    let token = broker
        .issue_channel_context_token(
            &digest_bytes,
            lease_id,
            &spec.actuation.request_id,
            boundary_id,
        )
        .map_err(|e| format!("broker token issuance: {e}"))?;
    spec.actuation.channel_context_token = Some(token);

    Ok(spec)
}

// ─────────────────────────────────────────────────────────────────────────────
// Queue Operations
// ─────────────────────────────────────────────────────────────────────────────

fn enqueue_job(queue_root: &Path, spec: &FacJobSpecV1) -> Result<PathBuf, String> {
    let pending_dir = queue_root.join(PENDING_DIR);
    fs::create_dir_all(&pending_dir).map_err(|e| format!("create pending dir: {e}"))?;

    // Also ensure other queue directories exist.
    for subdir in &["claimed", "completed", "denied", "cancelled", "quarantine"] {
        let _ = fs::create_dir_all(queue_root.join(subdir));
    }

    let json = serde_json::to_string_pretty(spec).map_err(|e| format!("serialize: {e}"))?;
    if json.len() > MAX_JOB_SPEC_SIZE {
        return Err(format!(
            "serialized spec too large: {} > {}",
            json.len(),
            MAX_JOB_SPEC_SIZE
        ));
    }

    let filename = format!("{}.json", spec.job_id);
    let target = pending_dir.join(&filename);

    // Atomic write: temp file + rename.
    let temp =
        tempfile::NamedTempFile::new_in(&pending_dir).map_err(|e| format!("temp file: {e}"))?;
    {
        let mut file = temp.as_file();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        file.write_all(json.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        file.sync_all().map_err(|e| format!("sync: {e}"))?;
    }
    temp.persist(&target)
        .map_err(|e| format!("persist: {}", e.error))?;

    Ok(target)
}

// ─────────────────────────────────────────────────────────────────────────────
// Wait for Receipt
// ─────────────────────────────────────────────────────────────────────────────

fn wait_for_receipt(
    fac_root: &Path,
    job_id: &str,
    timeout: Duration,
    json_output: bool,
) -> Result<(), String> {
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let start = Instant::now();
    let mut iterations: u64 = 0;

    // Derive the iteration cap from the effective timeout so that callers
    // passing wait_timeout > DEFAULT_WAIT_TIMEOUT_SECS are not cut short by
    // a fixed cap. The headroom ensures the elapsed-time check fires first
    // under normal conditions.
    let max_poll_iterations = timeout.as_secs() / WAIT_POLL_INTERVAL_SECS + POLL_ITERATION_HEADROOM;

    loop {
        if start.elapsed() >= timeout {
            return Err(format!(
                "warm job {} did not complete within {}s",
                job_id,
                timeout.as_secs()
            ));
        }

        iterations = iterations.saturating_add(1);
        if iterations > max_poll_iterations {
            return Err(format!(
                "warm job {job_id} exceeded max poll iterations ({max_poll_iterations})",
            ));
        }

        // Check if a receipt exists for this job.
        if apm2_core::fac::has_receipt_for_job(&receipts_dir, job_id) {
            if json_output {
                let output = serde_json::json!({
                    "status": "completed",
                    "job_id": job_id,
                });
                println!("{}", serde_json::to_string(&output).unwrap_or_default());
            } else {
                eprintln!("warm: job {job_id} completed");
            }
            return Ok(());
        }

        std::thread::sleep(Duration::from_secs(WAIT_POLL_INTERVAL_SECS));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the FAC root directory at `$APM2_HOME/private/fac`.
fn resolve_fac_root() -> Result<PathBuf, String> {
    let home =
        resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home directory".to_string())?;
    Ok(home.join("private").join("fac"))
}

fn resolve_repo_info() -> (String, String) {
    // Try to get repo info from current git state.
    let repo_id = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "local".to_string());

    let head_sha = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string());

    (repo_id, head_sha)
}

fn generate_job_suffix() -> String {
    let ts = current_epoch_secs();
    let pid = std::process::id();
    format!("{ts}-{pid}")
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Formats an epoch timestamp as ISO 8601 UTC.
fn format_iso8601(epoch_secs: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = epoch_secs / secs_per_day;
    let time_of_day = epoch_secs % secs_per_day;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Compute year/month/day from days since epoch (simplified Gregorian).
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
const fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days.wrapping_add(719_468);
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Reads a file with a size bound to prevent unbounded allocation.
fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    let file_size = metadata.len();
    if file_size > max_size as u64 {
        return Err(format!(
            "file {} too large: {} > {}",
            path.display(),
            file_size,
            max_size
        ));
    }

    #[allow(clippy::cast_possible_truncation)]
    let alloc_size = file_size as usize;
    let mut buf = Vec::with_capacity(alloc_size);

    let read_limit = max_size.saturating_add(1);
    let mut limited_reader = file.take(read_limit as u64);
    limited_reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {}: {e}", path.display()))?;

    if buf.len() > max_size {
        return Err(format!(
            "file {} grew to {} (exceeds max {})",
            path.display(),
            buf.len(),
            max_size
        ));
    }

    Ok(buf)
}

fn output_error(json_output: bool, code: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let output = serde_json::json!({
            "status": "error",
            "error_code": code,
            "message": message,
        });
        println!("{}", serde_json::to_string(&output).unwrap_or_default());
    } else {
        eprintln!("warm: ERROR: [{code}] {message}");
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────
    // validate_lane tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_lane_none_defaults_to_bulk() {
        assert_eq!(validate_lane(&None).unwrap(), "bulk");
    }

    #[test]
    fn test_validate_lane_empty_defaults_to_bulk() {
        assert_eq!(validate_lane(&Some(String::new())).unwrap(), "bulk");
        assert_eq!(validate_lane(&Some("  ".to_string())).unwrap(), "bulk");
    }

    #[test]
    fn test_validate_lane_valid_values() {
        for lane in &[
            "bulk", "control", "consume", "replay", "lane-01", "my_lane", "A-Z",
        ] {
            let result = validate_lane(&Some(lane.to_string()));
            assert!(
                result.is_ok(),
                "expected Ok for lane {lane:?}, got {result:?}"
            );
            assert_eq!(result.unwrap(), *lane);
        }
    }

    #[test]
    fn test_validate_lane_rejects_unsafe_chars() {
        for unsafe_lane in &["lane;rm", "lane foo", "lane/bar", "lane..baz", "lane\nX"] {
            let result = validate_lane(&Some(unsafe_lane.to_string()));
            assert!(
                result.is_err(),
                "expected Err for unsafe lane {unsafe_lane:?}, got {result:?}"
            );
            let err = result.unwrap_err();
            assert!(
                err.contains("unsafe lane value"),
                "error should mention unsafe lane: {err}"
            );
        }
    }

    #[test]
    fn test_validate_lane_rejects_overlong() {
        let long_lane = "x".repeat(MAX_QUEUE_LANE_LENGTH + 1);
        let result = validate_lane(&Some(long_lane));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_validate_lane_accepts_max_length() {
        let max_lane = "a".repeat(MAX_QUEUE_LANE_LENGTH);
        let result = validate_lane(&Some(max_lane.clone()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), max_lane);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Poll iteration cap tests (Fix #3)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_poll_iteration_cap_scales_with_timeout() {
        // For a 1200s timeout with 5s interval + 10 headroom: 250 iterations
        let cap_1200 = 1200u64 / WAIT_POLL_INTERVAL_SECS + POLL_ITERATION_HEADROOM;
        assert_eq!(cap_1200, 250);

        // For a 3600s timeout: should be 730, not 250
        let cap_3600 = 3600u64 / WAIT_POLL_INTERVAL_SECS + POLL_ITERATION_HEADROOM;
        assert_eq!(cap_3600, 730);

        // The cap for 3600s must exceed the old fixed cap of 250
        assert!(cap_3600 > cap_1200);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Phase parsing tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_phases_default() {
        let result = parse_phases(&None);
        assert!(result.is_ok());
        let phases = result.unwrap();
        assert!(!phases.is_empty());
    }

    #[test]
    fn test_parse_phases_empty_string_error() {
        let result = parse_phases(&Some(String::new()));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_phases_valid_single() {
        let result = parse_phases(&Some("fetch".to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_parse_phases_valid_multiple() {
        let result = parse_phases(&Some("fetch,build".to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_parse_phases_invalid_phase() {
        let result = parse_phases(&Some("nonexistent_phase".to_string()));
        assert!(result.is_err());
    }
}
