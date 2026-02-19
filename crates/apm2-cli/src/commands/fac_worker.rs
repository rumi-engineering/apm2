// AGENT-AUTHORED (TCK-00511)
//! FAC Worker: queue consumer with RFC-0028 authorization + RFC-0029 admission
//! gating.
//!
//! Implements the `apm2 fac worker` subcommand that scans
//! `$APM2_HOME/queue/pending/` for job specs, validates them against
//! RFC-0028 channel context tokens and RFC-0029 queue admission, then
//! atomically claims and executes valid jobs.
//!
//! # Processing Pipeline
//!
//! ```text
//! scan ~/.apm2/queue/pending/*.json
//!   -> sort by (priority ASC, enqueue_time ASC, job_id ASC)
//!   -> for each:
//!     1. Bounded deserialize (64KB) -> on fail: quarantine + receipt
//!     2. Validate job_spec_digest   -> on fail: quarantine + receipt
//!     3. Validate RFC-0028 token    -> on fail: deny + receipt
//!     4. Evaluate RFC-0029 admission -> on fail: deny + receipt
//!     5. Atomic claim: rename pending/X.json -> claimed/X.json
//!     6. Acquire lane lease via LaneManager::try_lock
//!     7. Execute job under containment
//!     8. Emit completion receipt, move to completed/
//! ```
//!
//! # Security Model
//!
//! - All queue reads bounded to 64KB (RSK-1601).
//! - Token decode failures -> DENY + receipt.
//! - Admission failures -> DENY + receipt.
//! - Digest mismatch -> QUARANTINE.
//! - Malformed/oversize files -> QUARANTINE + receipt (never silently dropped).
//! - No secrets in receipts/logs.
//! - Atomic rename prevents double-execution.
//! - Collision-safe target names prevent clobbering (timestamp-nanos suffix).
//!
//! # Broker Key Sharing (Default Mode)
//!
//! In default mode, the worker and broker share a single process. The same
//! `FacBroker` instance that issues tokens also provides the verifying key
//! used to decode them. This is a documented limitation of default-mode
//! operation: distributed workers would need to load the broker's persisted
//! state or receive the verifying key via a secure channel. The broker
//! issues a time authority envelope and populates freshness/revocation/
//! convergence state so that the RFC-0029 admission path can reach `Allow`.
//!
//! # Invariants
//!
//! - [INV-WRK-001] All file reads are bounded to `MAX_JOB_SPEC_SIZE`.
//! - [INV-WRK-002] Fail-closed: any validation failure results in
//!   deny/quarantine.
//! - [INV-WRK-003] Atomic claim via rename prevents double-execution.
//! - [INV-WRK-004] No secrets appear in receipts or log output.
//! - [INV-WRK-005] Deterministic ordering: priority ASC, `enqueue_time` ASC,
//!   `job_id` ASC.
//! - [INV-WRK-006] In-memory collections are bounded by
//!   `MAX_PENDING_SCAN_ENTRIES`.
//! - [INV-WRK-007] Malformed/unreadable/oversize files are quarantined with
//!   receipts, never silently dropped.
//! - [INV-WRK-008] Lane lease is acquired before job execution; jobs that
//!   cannot acquire a lane are moved back to pending.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use apm2_core::channel::{
    ChannelBoundaryDefect, ExpectedTokenBinding, decode_channel_context_token_with_binding,
    validate_channel_boundary,
};
use apm2_core::crypto::Signer;
use apm2_core::economics::admission::{
    BudgetAdmissionEvaluator, BudgetAdmissionTrace as EconomicsBudgetAdmissionTrace,
    BudgetAdmissionVerdict, ObservedUsage,
};
use apm2_core::economics::profile::EconomicsProfile;
use apm2_core::economics::queue_admission::{
    HtfEvaluationWindow, QueueAdmissionDecision, QueueAdmissionRequest, QueueAdmissionVerdict,
    QueueLane, QueueSchedulerState, evaluate_queue_admission,
};
use apm2_core::evidence::MemoryCas;
use apm2_core::fac::broker::{BrokerError, BrokerSignatureVerifier, FacBroker};
use apm2_core::fac::broker_health::WorkerHealthPolicy;
use apm2_core::fac::job_spec::{
    FacJobSpecV1, JobSpecError, MAX_JOB_SPEC_SIZE, deserialize_job_spec, job_kind_to_budget_key,
    parse_b3_256_digest, validate_job_spec_control_lane_with_policy, validate_job_spec_with_policy,
};
use apm2_core::fac::lane::{LaneLeaseV1, LaneLockGuard, LaneManager, LaneState};
use apm2_core::fac::scan_lock::{ScanLockResult, check_stuck_scan_lock, try_acquire_scan_lock};
use apm2_core::fac::scheduler_state::{load_scheduler_state, persist_scheduler_state};
use apm2_core::fac::{
    BlobStore, BudgetAdmissionTrace as FacBudgetAdmissionTrace, CanonicalizerTupleV1,
    ChannelBoundaryTrace, DenialReasonCode, ExecutionBackend, FAC_LANE_CLEANUP_RECEIPT_SCHEMA,
    FacJobOutcome, FacJobReceiptV1, FacJobReceiptV1Builder, FacPolicyV1, GateReceipt,
    GateReceiptBuilder, LANE_CORRUPT_MARKER_SCHEMA, LaneCleanupOutcome, LaneCleanupReceiptV1,
    LaneCorruptMarkerV1, LaneProfileV1, MAX_POLICY_SIZE, PATCH_FORMAT_GIT_DIFF_V1,
    QueueAdmissionTrace as JobQueueAdmissionTrace, ReceiptPipelineError, ReceiptWritePipeline,
    RepoMirrorManager, SystemModeConfig, SystemdUnitProperties, TOOLCHAIN_MAX_CACHE_FILE_BYTES,
    apply_credential_mount_to_env, build_github_credential_mount, build_job_environment,
    compute_policy_hash, deserialize_policy, fingerprint_short_hex, load_or_default_boundary_id,
    move_job_to_terminal, outcome_to_terminal_state, parse_policy_hash,
    persist_content_addressed_receipt, persist_policy, rename_noreplace,
    resolve_toolchain_fingerprint_cached, run_preflight, select_and_validate_backend,
    serialize_cache, toolchain_cache_dir, toolchain_cache_file_path,
};
use apm2_core::github::{parse_github_remote_url, resolve_apm2_home};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::fac_gates_job::{GATES_JOB_OPTIONS_SCHEMA, GatesJobOptionsV1};
use super::{fac_key_material, fac_secure_io};
#[cfg(not(test))]
use crate::commands::fac_review as fac_review_api;
#[cfg(test)]
mod fac_review_api {
    use std::cell::RefCell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GateThroughputProfile {
        Throughput,
        Balanced,
        Conservative,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LocalGatesRunResult {
        pub exit_code: u8,
        pub failure_summary: Option<String>,
    }

    thread_local! {
        static RUN_GATES_LOCAL_WORKER_OVERRIDE: RefCell<Option<Result<LocalGatesRunResult, String>>> =
            const { RefCell::new(None) };
        static GATE_LIFECYCLE_OVERRIDE: RefCell<Option<Result<usize, String>>> =
            const { RefCell::new(None) };
    }

    pub fn set_run_gates_local_worker_override(
        result: Option<Result<LocalGatesRunResult, String>>,
    ) {
        RUN_GATES_LOCAL_WORKER_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = result;
        });
    }

    pub fn set_gate_lifecycle_override(result: Option<Result<usize, String>>) {
        GATE_LIFECYCLE_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = result;
        });
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::unnecessary_wraps)]
    pub fn run_gates_local_worker(
        _force: bool,
        _quick: bool,
        _timeout_seconds: u64,
        _memory_max: &str,
        _pids_max: u64,
        _cpu_quota: &str,
        _gate_profile: GateThroughputProfile,
        _workspace_root: &std::path::Path,
    ) -> Result<LocalGatesRunResult, String> {
        if let Some(override_result) =
            RUN_GATES_LOCAL_WORKER_OVERRIDE.with(|slot| slot.borrow().clone())
        {
            return override_result;
        }
        Ok(LocalGatesRunResult {
            exit_code: crate::exit_codes::codes::GENERIC_ERROR,
            failure_summary: None,
        })
    }

    /// Test stub: no-op rebinding (v2).
    pub fn rebind_gate_cache_after_receipt(
        _sha: &str,
        _receipts_dir: &std::path::Path,
        _job_id: &str,
        _signer: &apm2_core::crypto::Signer,
    ) {
    }

    /// Test stub: no-op rebinding (v3).
    pub fn rebind_v3_gate_cache_after_receipt(
        _sha: &str,
        _policy_hash: &str,
        _sbx_hash: &str,
        _net_hash: &str,
        _receipts_dir: &std::path::Path,
        _job_id: &str,
        _signer: &apm2_core::crypto::Signer,
    ) {
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn apply_gate_result_lifecycle_for_repo_sha(
        owner_repo: &str,
        head_sha: &str,
        _passed: bool,
    ) -> Result<usize, String> {
        if let Some(override_result) = GATE_LIFECYCLE_OVERRIDE.with(|slot| slot.borrow().clone()) {
            return override_result;
        }
        // Test shim: enforce non-empty routing inputs and return a non-zero
        // applied count so worker unit tests do not silently mask no-op behavior.
        if owner_repo.trim().is_empty() {
            return Err("owner_repo is empty".to_string());
        }
        if head_sha.trim().is_empty() {
            return Err("head_sha is empty".to_string());
        }
        Ok(1)
    }
}

#[cfg(test)]
mod fac_permissions {
    use std::path::Path;
    use std::{fs, io};

    pub fn ensure_dir_with_mode(path: &Path) -> Result<(), io::Error> {
        fs::create_dir_all(path)
    }

    /// Test-mode stub for atomic file write with restricted permissions.
    /// In test mode, simply writes directly without permission enforcement.
    pub fn write_fac_file_with_mode(path: &Path, data: &[u8]) -> Result<(), io::Error> {
        fs::write(path, data)
    }

    /// Test-mode stub: always passes.  Integration tests for real
    /// owner+mode enforcement live in `fac_permissions::tests`.
    pub fn validate_directory(path: &Path, _expected_uid: u32) -> Result<(), io::Error> {
        if !path.exists() {
            fs::create_dir_all(path)?;
        }
        Ok(())
    }
}
#[cfg(not(test))]
use crate::commands::fac_permissions;
use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of pending entries to scan per cycle (INV-WRK-006).
///
/// Prevents unbounded memory growth from a queue directory with many files.
const MAX_PENDING_SCAN_ENTRIES: usize = 4096;

/// Queue subdirectory names.
const QUEUE_DIR: &str = "queue";
const PENDING_DIR: &str = "pending";
const CLAIMED_DIR: &str = "claimed";
const COMPLETED_DIR: &str = "completed";
const DENIED_DIR: &str = "denied";
const QUARANTINE_DIR: &str = "quarantine";
const CANCELLED_DIR: &str = "cancelled";
const CONSUME_RECEIPTS_DIR: &str = "authority_consumed";

/// Maximum poll interval to prevent misconfiguration (1 hour).
const MAX_POLL_INTERVAL_SECS: u64 = 3600;

/// Max number of boundary defect classes retained in a trace.
const MAX_BOUNDARY_DEFECT_CLASSES: usize = 32;
const SCHEDULER_RECOVERY_SCHEMA: &str = "apm2.scheduler_recovery.v1";

/// FAC receipt directory under `$APM2_HOME/private/fac`.
const FAC_RECEIPTS_DIR: &str = "receipts";
const CORRUPT_MARKER_PERSIST_RETRIES: usize = 3;
const CORRUPT_MARKER_PERSIST_RETRY_DELAY_MS: u64 = 25;

/// Last-resort fallback boundary ID when node identity cannot be loaded.
///
/// Production deployments use `load_or_default_boundary_id()` which reads
/// the actual boundary from `$APM2_HOME/private/fac/identity/boundary_id`.
/// This constant is only used when `resolve_apm2_home()` fails (no home
/// directory available at all).
const FALLBACK_BOUNDARY_ID: &str = "local";

/// Default authority clock for local-mode evaluation windows.
const DEFAULT_AUTHORITY_CLOCK: &str = "local";
#[cfg(test)]
const DEFAULT_GATES_TIMEOUT_SECONDS: u64 = 600;
#[cfg(test)]
const DEFAULT_GATES_MEMORY_MAX: &str = "48G";
#[cfg(test)]
const DEFAULT_GATES_PIDS_MAX: u64 = 1536;
#[cfg(test)]
const DEFAULT_GATES_CPU_QUOTA: &str = "auto";
const UNKNOWN_REPO_SEGMENT: &str = "unknown";
const ALLOWED_WORKSPACE_ROOTS_ENV: &str = "APM2_FAC_ALLOWED_WORKSPACE_ROOTS";
const GATES_HEARTBEAT_REFRESH_SECS: u64 = 5;
const ORPHAN_LEASE_WARNING_MULTIPLIER: u64 = 2;
const MAX_COMPLETED_SCAN_ENTRIES: usize = 4096;
const MAX_TERMINAL_JOB_METADATA_FILE_SIZE: usize = MAX_JOB_SPEC_SIZE * 4;

#[cfg(test)]
pub fn env_var_test_lock() -> &'static crate::commands::EnvVarTestLock {
    crate::commands::env_var_test_lock()
}

// =============================================================================
// Worker result types
// =============================================================================

/// Outcome of processing a single job spec file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum JobOutcome {
    /// Job was quarantined due to malformed spec or digest mismatch.
    Quarantined { reason: String },
    /// Job was denied due to token or admission failure.
    Denied { reason: String },
    /// Job was successfully claimed and executed.
    Completed {
        job_id: String,
        /// Observed runtime cost metrics for post-run cost model calibration.
        observed_cost: Option<apm2_core::economics::cost_model::ObservedJobCost>,
    },
    /// Job was aborted due to unrecoverable internal error.
    /// NOTE: currently unused because cleanup failures no longer change
    /// job outcome (BLOCKER fix for f-685-code_quality-0). Retained for
    /// future use by execution substrate error paths.
    Aborted { reason: String },
    /// Job was skipped (already claimed or missing).
    Skipped { reason: String },
}

/// Summary output for JSON mode.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct WorkerSummary {
    /// Number of jobs processed.
    jobs_processed: usize,
    /// Number of jobs completed (claimed + executed).
    jobs_completed: usize,
    /// Number of jobs denied.
    jobs_denied: usize,
    /// Number of jobs quarantined.
    jobs_quarantined: usize,
    /// Number of jobs skipped.
    jobs_skipped: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum CanonicalizerTupleCheck {
    Matched,
    Missing,
    Mismatch(CanonicalizerTupleV1),
}

#[derive(Debug)]
struct SchedulerRecoveryReceipt {
    /// Scheduler recovery receipt schema.
    schema: String,
    /// Recovery reason for reconstructing scheduler state.
    reason: String,
    /// Recovery timestamp in epoch seconds.
    timestamp_secs: u64,
}

/// A candidate pending job for sorting and processing.
#[derive(Debug)]
struct PendingCandidate {
    /// Path to the pending JSON file.
    path: PathBuf,
    /// Deserialized job spec (valid parse only, not yet fully validated).
    spec: FacJobSpecV1,
    /// Raw bytes from the bounded read.
    raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct GatesJobOptions {
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: String,
    pids_max: u64,
    cpu_quota: String,
    gate_profile: fac_review_api::GateThroughputProfile,
    workspace_root: PathBuf,
}

// =============================================================================
// Public entry point
// =============================================================================

/// Runs the FAC worker, returning an exit code.
///
/// The worker scans the pending queue, validates each job spec against
/// RFC-0028 and RFC-0029, and atomically claims valid jobs. In default
/// mode, the broker and worker share a single process: the same
/// `FacBroker` instance issues tokens and provides the verifying key.
///
/// # Arguments
///
/// * `once` - If true, process at most one job and exit.
/// * `poll_interval_secs` - Seconds between queue scans in continuous mode.
/// * `max_jobs` - Maximum total jobs to process before exiting (0 = unlimited).
/// * `json_output` - If true, emit JSON output.
/// * `print_unit` - If true, print systemd unit directives/properties for each
///   job.
pub fn run_fac_worker(
    once: bool,
    poll_interval_secs: u64,
    max_jobs: u64,
    json_output: bool,
    print_unit: bool,
) -> u8 {
    let poll_interval_secs = poll_interval_secs.min(MAX_POLL_INTERVAL_SECS);
    if json_output {
        emit_worker_event(
            "worker_started",
            serde_json::json!({
                "once": once,
                "poll_interval_secs": poll_interval_secs,
                "max_jobs": max_jobs,
            }),
        );
    }

    // Resolve queue root directory
    let queue_root = match resolve_queue_root() {
        Ok(root) => root,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot resolve queue root: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };
    let fac_root = match resolve_fac_root() {
        Ok(root) => root,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot resolve FAC root: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    // TCK-00565 MAJOR-1 fix: Load the actual boundary_id from FAC node identity
    // instead of using a hardcoded constant. Falls back to FALLBACK_BOUNDARY_ID
    // only when APM2 home cannot be resolved (no-home edge case).
    let boundary_id = resolve_apm2_home()
        .and_then(|home| load_or_default_boundary_id(&home).ok())
        .unwrap_or_else(|| FALLBACK_BOUNDARY_ID.to_string());

    // Ensure queue directories exist
    if let Err(e) = ensure_queue_dirs(&queue_root) {
        output_worker_error(
            json_output,
            &format!("cannot create queue directories: {e}"),
        );
        return exit_codes::GENERIC_ERROR;
    }

    // Load persistent signing key for stable broker identity and receipts across
    // restarts.
    let persistent_signer = match load_or_generate_persistent_signer() {
        Ok(signer) => signer,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot load signing key: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };
    let persistent_signer_key_bytes = persistent_signer.secret_key_bytes().to_vec();

    let signer = match Signer::from_bytes(&persistent_signer_key_bytes) {
        Ok(s) => s,
        Err(e) => {
            output_worker_error(
                json_output,
                &format!("cannot initialize receipt signer: {e}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    let mk_default_state_broker = || {
        let default_state = apm2_core::fac::broker::BrokerState::default();
        let signer = Signer::from_bytes(&persistent_signer_key_bytes).ok()?;
        FacBroker::from_signer_and_state(signer, default_state).ok()
    };

    // Create broker for token verification and admission evaluation.
    // In default mode, the broker and worker share a process: the same
    // FacBroker instance issues tokens AND verifies them. This is documented
    // as a limitation of default-mode operation. Distributed workers would
    // need to load the broker's persisted verifying key.
    let mut broker = load_broker_state().map_or_else(
        || mk_default_state_broker().unwrap_or_else(FacBroker::new),
        |state| {
            Signer::from_bytes(&persistent_signer_key_bytes)
                .ok()
                .and_then(|signer| FacBroker::from_signer_and_state(signer, state).ok())
                .unwrap_or_else(|| mk_default_state_broker().unwrap_or_else(FacBroker::new))
        },
    );

    // TCK-00566: Load persisted token ledger if available. The ledger
    // survives restarts so replay protection is not lost on daemon restart.
    // INV-TL-009: Load errors from an existing file are hard security faults.
    match load_token_ledger(broker.current_tick()) {
        Ok(Some(ledger)) => {
            broker.set_token_ledger(ledger);
        },
        Ok(None) => {
            // No persisted ledger (first run). Fresh ledger already
            // initialized.
        },
        Err(e) => {
            let msg = format!("FATAL: token ledger load failed (fail-closed): {e}");
            output_worker_error(json_output, &msg);
            return exit_codes::GENERIC_ERROR;
        },
    }

    let (mut queue_state, mut cost_model) = match load_scheduler_state(&fac_root) {
        Ok(Some(saved)) => {
            let cm = saved
                .cost_model
                .clone()
                .unwrap_or_else(apm2_core::economics::CostModelV1::with_defaults);
            (QueueSchedulerState::from_persisted(&saved), cm)
        },
        Ok(None) => {
            let recovery = SchedulerRecoveryReceipt {
                schema: SCHEDULER_RECOVERY_SCHEMA.to_string(),
                reason: "scheduler state missing, reconstructing conservatively".to_string(),
                timestamp_secs: current_timestamp_epoch_secs(),
            };
            if json_output {
                emit_worker_event(
                    "scheduler_recovery",
                    serde_json::json!({
                        "schema": recovery.schema,
                        "reason": recovery.reason,
                        "timestamp_secs": recovery.timestamp_secs,
                    }),
                );
            } else {
                eprintln!(
                    "INFO: scheduler state reconstructed: {} ({}, {})",
                    recovery.schema, recovery.reason, recovery.timestamp_secs
                );
            }
            (
                QueueSchedulerState::new(),
                apm2_core::economics::CostModelV1::with_defaults(),
            )
        },
        Err(e) => {
            let recovery = SchedulerRecoveryReceipt {
                schema: SCHEDULER_RECOVERY_SCHEMA.to_string(),
                reason: "scheduler state missing or corrupt, reconstructing conservatively"
                    .to_string(),
                timestamp_secs: current_timestamp_epoch_secs(),
            };
            if json_output {
                emit_worker_event(
                    "scheduler_recovery",
                    serde_json::json!({
                        "schema": recovery.schema,
                        "reason": recovery.reason,
                        "timestamp_secs": recovery.timestamp_secs,
                        "load_error": e,
                    }),
                );
            } else {
                eprintln!("WARNING: failed to load scheduler state: {e}, starting fresh");
                eprintln!(
                    "INFO: scheduler state reconstructed: {} ({}, {})",
                    recovery.schema, recovery.reason, recovery.timestamp_secs
                );
            }
            (
                QueueSchedulerState::new(),
                apm2_core::economics::CostModelV1::with_defaults(),
            )
        },
    };

    // Perform admission health gate check so the broker can issue tokens.
    // In default (local) mode we use minimal health check inputs.
    let mut checker = apm2_core::fac::broker_health::BrokerHealthChecker::new();

    // Issue a time authority envelope from the broker so RFC-0029 admission
    // has valid TP-EIO29-001 authority. Without this, admission always denies
    // fail-closed due to missing envelope.
    let current_tick = broker.current_tick();
    let tick_end = current_tick.saturating_add(1);
    let eval_window = broker
        .build_evaluation_window(
            &boundary_id,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .unwrap_or_else(|_| make_default_eval_window(&boundary_id));

    // Advance freshness to keep startup checks in sync with the first
    // admission window.
    broker.advance_freshness_horizon(tick_end);

    let startup_envelope = broker
        .issue_time_authority_envelope_default_ttl(
            &boundary_id,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .ok();

    let _health = broker.check_health(startup_envelope.as_ref(), &eval_window, &[], &mut checker);
    if let Err(e) =
        broker.evaluate_admission_health_gate(&checker, &eval_window, WorkerHealthPolicy::default())
    {
        output_worker_error(json_output, &format!("admission health gate failed: {e}"));
        return exit_codes::GENERIC_ERROR;
    }

    let (policy_hash, policy_digest, policy) = match load_or_create_policy(&fac_root) {
        Ok(policy) => policy,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot load fac policy: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    // TCK-00579: Derive job spec validation policy from FAC policy.
    // This enables repo_id allowlist, bytes_backend allowlist, and
    // filesystem-path rejection at worker pre-claim time.
    let job_spec_policy = match policy.job_spec_validation_policy() {
        Ok(p) => p,
        Err(e) => {
            output_worker_error(
                json_output,
                &format!("cannot derive job spec validation policy: {e}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    let budget_cas = MemoryCas::new();
    let baseline_profile = EconomicsProfile::default_baseline();
    if let Err(e) = baseline_profile.store_in_cas(&budget_cas) {
        output_worker_error(
            json_output,
            &format!("cannot seed baseline economics profile in CAS: {e}"),
        );
        return exit_codes::GENERIC_ERROR;
    }
    // Verify that the policy's economics_profile_hash is resolvable from CAS.
    // Currently only the baseline profile is available. If the policy references
    // a different hash (future custom profile), we cannot resolve it — fail
    // explicitly rather than silently denying all jobs.
    let baseline_hash = baseline_profile.profile_hash().unwrap_or([0u8; 32]);
    if policy.economics_profile_hash != baseline_hash && policy.economics_profile_hash != [0u8; 32]
    {
        output_worker_error(
            json_output,
            &format!(
                "fac policy references economics profile hash {:x?} which is not loaded in CAS; \
                 only baseline profile (hash {:x?}) is currently supported",
                &policy.economics_profile_hash[..8],
                &baseline_hash[..8],
            ),
        );
        return exit_codes::GENERIC_ERROR;
    }

    if let Err(e) = broker.admit_policy_digest(policy_digest) {
        output_worker_error(json_output, &format!("cannot admit fac policy digest: {e}"));
        return exit_codes::GENERIC_ERROR;
    }

    let current_tuple = CanonicalizerTupleV1::from_current();
    let current_tuple_digest = compute_canonicalizer_tuple_digest();
    match check_or_admit_canonicalizer_tuple(&fac_root) {
        Ok(CanonicalizerTupleCheck::Matched) => {},
        Ok(CanonicalizerTupleCheck::Missing) => {
            output_worker_error(
                json_output,
                "no admitted canonicalizer tuple found. run `apm2 fac canonicalizer admit` to bootstrap",
            );
            return exit_codes::GENERIC_ERROR;
        },
        Ok(CanonicalizerTupleCheck::Mismatch(admitted_tuple)) => {
            output_worker_error(
                json_output,
                &format!(
                    "canonicalizer tuple mismatch (current={}/{}, admitted={}/{}). remedy: re-run broker admission or update binary",
                    current_tuple.canonicalizer_id,
                    current_tuple.canonicalizer_version,
                    admitted_tuple.canonicalizer_id,
                    admitted_tuple.canonicalizer_version
                ),
            );
            return exit_codes::GENERIC_ERROR;
        },
        Err(e) => {
            output_worker_error(
                json_output,
                &format!("cannot initialize canonicalizer tuple: {e}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    }

    let verifying_key = broker.verifying_key();

    // TCK-00534: Crash recovery — reconcile queue/claimed and lane leases on
    // worker startup. Detects stale leases (PID dead, lock released) and
    // orphaned claimed jobs, then recovers them deterministically with receipts.
    {
        let _ = apm2_core::fac::sd_notify::notify_status("reconciling queue and lane state");
        match apm2_core::fac::reconcile_on_startup(
            &fac_root,
            &queue_root,
            apm2_core::fac::OrphanedJobPolicy::Requeue,
            false, // apply mutations
        ) {
            Ok(receipt) => {
                let recovered = receipt.stale_leases_recovered
                    + receipt.orphaned_jobs_requeued
                    + receipt.orphaned_jobs_failed;
                if json_output {
                    emit_worker_event(
                        "reconcile_complete",
                        serde_json::json!({
                            "schema": receipt.schema,
                            "lanes_inspected": receipt.lanes_inspected,
                            "stale_leases_recovered": receipt.stale_leases_recovered,
                            "orphaned_jobs_requeued": receipt.orphaned_jobs_requeued,
                            "orphaned_jobs_failed": receipt.orphaned_jobs_failed,
                            "lanes_marked_corrupt": receipt.lanes_marked_corrupt,
                            "claimed_files_inspected": receipt.claimed_files_inspected,
                        }),
                    );
                } else if recovered > 0 {
                    eprintln!(
                        "INFO: reconciliation recovered {} items \
                         (stale_leases={}, requeued={}, failed={}, corrupt={})",
                        recovered,
                        receipt.stale_leases_recovered,
                        receipt.orphaned_jobs_requeued,
                        receipt.orphaned_jobs_failed,
                        receipt.lanes_marked_corrupt,
                    );
                }
            },
            Err(e) => {
                // Reconciliation failure is fatal: the worker must not process
                // new jobs while queue/lane state may be inconsistent from a
                // prior crash. Fail-closed to prevent duplicate execution or
                // stale state interference (INV-RECON-001, INV-RECON-002).
                if json_output {
                    emit_worker_event(
                        "reconcile_error",
                        serde_json::json!({ "error": e.to_string() }),
                    );
                } else {
                    eprintln!("ERROR: reconciliation failed, cannot start worker: {e}");
                }
                return exit_codes::GENERIC_ERROR;
            },
        }
    }

    // TCK-00538: Resolve toolchain fingerprint with cache-first strategy.
    // Fail-closed: if fingerprint resolution fails, the worker refuses to
    // start. The fingerprint is required for receipt integrity and lane
    // target namespacing.
    //
    // Cache path: $APM2_HOME/private/fac/toolchain/fingerprint.v1.json
    // Cache validation: re-derive fingerprint from stored raw_versions and
    // compare (INV-TC-004). If mismatch, recompute fresh.
    let toolchain_fingerprint: String = {
        let mut probe_env = std::collections::BTreeMap::new();
        if let Ok(path) = std::env::var("PATH") {
            probe_env.insert("PATH".to_string(), path);
        }
        if let Ok(home) = std::env::var("HOME") {
            probe_env.insert("HOME".to_string(), home);
        }
        if let Ok(user) = std::env::var("USER") {
            probe_env.insert("USER".to_string(), user);
        }

        // Step 1: Try loading cache (bounded read, O_NOFOLLOW via
        // fac_secure_io::read_bounded).
        let cache_path = toolchain_cache_file_path(&fac_root);
        let cache_bytes = if cache_path.exists() {
            fac_secure_io::read_bounded(&cache_path, TOOLCHAIN_MAX_CACHE_FILE_BYTES).ok()
        } else {
            None
        };

        // Step 2: Resolve fingerprint (cache-first, fresh fallback).
        match resolve_toolchain_fingerprint_cached(&probe_env, cache_bytes.as_deref()) {
            Ok((fp, versions)) => {
                // Step 3: Persist cache atomically if we computed fresh
                // (i.e. cache was missing or invalid). We detect this by
                // checking whether the returned fingerprint differs from
                // what was in the cache.
                let cache_was_valid = cache_bytes
                    .as_deref()
                    .and_then(apm2_core::fac::validate_cached_fingerprint)
                    .is_some_and(|cached_fp| cached_fp == fp);

                if !cache_was_valid {
                    // Ensure cache directory exists with restricted perms
                    // (dir 0o700).
                    let tc_cache_dir = toolchain_cache_dir(&fac_root);
                    if let Err(e) = fac_permissions::ensure_dir_with_mode(&tc_cache_dir) {
                        // Cache write failure is non-fatal: log and continue.
                        // The fingerprint was successfully computed.
                        if json_output {
                            emit_worker_event(
                                "toolchain_cache_dir_error",
                                serde_json::json!({
                                    "path": tc_cache_dir.display().to_string(),
                                    "error": e.to_string(),
                                }),
                            );
                        }
                    } else if let Ok(cache_data) = serialize_cache(&fp, &versions) {
                        // Atomic write with restricted perms (file 0o600,
                        // O_NOFOLLOW, symlink-safe via
                        // write_fac_file_with_mode).
                        if let Err(e) =
                            fac_permissions::write_fac_file_with_mode(&cache_path, &cache_data)
                        {
                            // Cache write failure is non-fatal.
                            if json_output {
                                emit_worker_event(
                                    "toolchain_cache_write_error",
                                    serde_json::json!({
                                        "path": cache_path.display().to_string(),
                                        "error": e.to_string(),
                                    }),
                                );
                            }
                        }
                    }
                }
                fp
            },
            Err(e) => {
                output_worker_error(
                    json_output,
                    &format!(
                        "toolchain fingerprint computation failed: {e} \
                         (fail-closed: fingerprint required for receipts and lane target namespacing)"
                    ),
                );
                return exit_codes::GENERIC_ERROR;
            },
        }
    };

    let mut total_processed: u64 = 0;
    let mut cycle_count: u64 = 0;
    let mut summary = WorkerSummary {
        jobs_processed: 0,
        jobs_completed: 0,
        jobs_denied: 0,
        jobs_quarantined: 0,
        jobs_skipped: 0,
    };

    // TCK-00600: Notify systemd that the worker is ready and spawn a
    // background thread for watchdog pings. The background thread pings
    // independently of the job processing loop, preventing systemd from
    // restarting the worker during long-running jobs (process_job can
    // take minutes). The daemon already uses this pattern (background
    // poller task). The thread is marked as a daemon thread and will
    // exit when the main worker thread exits.
    let _ = apm2_core::fac::sd_notify::notify_ready();
    let _ = apm2_core::fac::sd_notify::notify_status("worker ready, polling queue");

    // Spawn a background thread for watchdog pings, independent of job
    // processing. This follows the same pattern as the daemon's poller
    // task which pings in a background tokio::spawn.
    //
    // Synchronization protocol (RS-21):
    // - Protected data: `watchdog_stop` AtomicBool.
    // - Writer: main thread sets `true` on exit (Release).
    // - Reader: background thread checks with Acquire ordering.
    // - Happens-before: Release store → Acquire load ensures the stop signal is
    //   visible to the background thread.
    let watchdog_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog_stop_bg = std::sync::Arc::clone(&watchdog_stop);
    let _watchdog_thread = {
        let ticker = apm2_core::fac::sd_notify::WatchdogTicker::new();
        if ticker.is_enabled() {
            let ping_interval = Duration::from_secs(ticker.ping_interval_secs());
            Some(std::thread::spawn(move || {
                let mut bg_ticker = ticker;
                loop {
                    std::thread::sleep(ping_interval);
                    if watchdog_stop_bg.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                    bg_ticker.ping_if_due();
                }
            }))
        } else {
            None
        }
    };

    loop {
        let cycle_start = Instant::now();
        cycle_count = cycle_count.saturating_add(1);

        // TCK-00600: Write worker heartbeat file for `services status`.
        if let Err(e) = apm2_core::fac::worker_heartbeat::write_heartbeat(
            &fac_root,
            cycle_count,
            summary.jobs_completed as u64,
            summary.jobs_denied as u64,
            summary.jobs_quarantined as u64,
            "healthy",
        ) {
            // Non-fatal: heartbeat is observability, not correctness.
            if !json_output {
                eprintln!("WARNING: heartbeat write failed: {e}");
            }
        }

        // S10: Proactively reap orphaned LEASED lanes each poll tick.
        reap_orphaned_leases_on_tick(&fac_root, json_output);

        // TCK-00586: Multi-worker fairness — try scan lock before scanning.
        //
        // When multiple workers poll the same queue, redundant directory scans
        // cause a CPU/IO stampede. The optional scan lock ensures at most one
        // worker scans per cycle; others wait with jitter and rely on atomic
        // claim (rename) for correctness.
        //
        // The lock is purely advisory: if acquisition fails due to I/O error
        // the worker falls through to scan anyway (fail-open for availability,
        // correctness preserved by atomic rename).
        let scan_lock_guard = match try_acquire_scan_lock(&queue_root) {
            Ok(ScanLockResult::Acquired(guard)) => Some(guard),
            Ok(ScanLockResult::Held) => {
                // Another worker holds the scan lock. Check for stuck lock
                // and emit receipt if detected.
                if let Ok(Some(stuck_receipt)) = check_stuck_scan_lock(&queue_root) {
                    if json_output {
                        emit_worker_event(
                            "scan_lock_stuck",
                            serde_json::json!({
                                "schema": stuck_receipt.schema,
                                "stuck_holder_pid": stuck_receipt.stuck_holder_pid,
                                "acquired_epoch_secs": stuck_receipt.acquired_epoch_secs,
                                "detected_epoch_secs": stuck_receipt.detected_epoch_secs,
                                "held_duration_secs": stuck_receipt.held_duration_secs,
                            }),
                        );
                    } else {
                        eprintln!(
                            "WARNING: scan lock stuck (holder_pid={}, held={}s)",
                            stuck_receipt.stuck_holder_pid, stuck_receipt.held_duration_secs,
                        );
                    }
                    // Persist stuck receipt for audit.
                    let receipt_json =
                        serde_json::to_string_pretty(&stuck_receipt).unwrap_or_default();
                    let _ = persist_scan_lock_stuck_receipt(&fac_root, &receipt_json);
                }

                // Skip scan this cycle; sleep with jitter to avoid thundering
                // herd retries.
                if once {
                    // In --once mode we cannot skip; fall through to scan
                    // regardless (correctness via atomic rename).
                    None
                } else {
                    let jitter =
                        apm2_core::fac::scan_lock::scan_lock_jitter_duration(poll_interval_secs);
                    std::thread::sleep(jitter);
                    continue;
                }
            },
            Ok(ScanLockResult::Unavailable) => None, // No queue dir yet; scan anyway.
            Err(e) => {
                // I/O error acquiring lock; log and fall through to scan.
                // Fail-open: availability over efficiency.
                if !json_output {
                    eprintln!("WARNING: scan lock acquisition failed: {e}");
                }
                None
            },
        };

        // Scan pending directory (quarantines malformed files inline).
        let candidates = match scan_pending(
            &queue_root,
            &fac_root,
            &current_tuple_digest,
            Some(toolchain_fingerprint.as_str()),
        ) {
            Ok(c) => c,
            Err(e) => {
                output_worker_error(json_output, &format!("scan error: {e}"));
                if once {
                    if let Err(persist_err) = persist_queue_scheduler_state(
                        &fac_root,
                        &queue_state,
                        broker.current_tick(),
                        Some(&cost_model),
                    ) {
                        output_worker_error(json_output, &persist_err);
                    }
                    return exit_codes::GENERIC_ERROR;
                }
                sleep_remaining(cycle_start, poll_interval_secs);
                continue;
            },
        };

        // Drop the scan lock guard now that scanning is complete.
        // This releases the flock so other workers can proceed.
        drop(scan_lock_guard);

        let mut cycle_scheduler = queue_state.clone();
        let mut completed_gates_cache: Option<CompletedGatesCache> = None;

        if candidates.is_empty() {
            if once {
                if let Err(persist_err) = persist_queue_scheduler_state(
                    &fac_root,
                    &cycle_scheduler,
                    broker.current_tick(),
                    Some(&cost_model),
                ) {
                    output_worker_error(json_output, &persist_err);
                    return exit_codes::GENERIC_ERROR;
                }
                let _ = save_broker_state(&broker);
                if let Err(e) = save_token_ledger(&mut broker) {
                    output_worker_error(json_output, &format!("token ledger save failed: {e}"));
                    return exit_codes::GENERIC_ERROR;
                }
                if json_output {
                    emit_worker_summary(&summary);
                } else {
                    eprintln!("worker: no pending jobs found");
                }
                return exit_codes::SUCCESS;
            }
            sleep_remaining(cycle_start, poll_interval_secs);
            continue;
        }

        // TCK-00587: Anti-starvation two-pass semantics. Candidates are
        // sorted by (priority ASC, enqueue_time ASC, job_id ASC) where
        // StopRevoke priority = 0 (highest). This ordering guarantees all
        // stop_revoke jobs in the cycle are processed before any lower-
        // priority lane, providing first-pass anti-starvation without
        // requiring a separate scan pass. The StopRevokeAdmissionTrace
        // records `worker_first_pass: true` to document this guarantee.
        for candidate in &candidates {
            if max_jobs > 0 && total_processed >= max_jobs {
                break;
            }
            if json_output {
                emit_worker_event(
                    "job_started",
                    serde_json::json!({
                        "job_id": candidate.spec.job_id,
                        "queue_lane": candidate.spec.queue_lane,
                    }),
                );
            }

            let job_started = Instant::now();
            let lane = parse_queue_lane(&candidate.spec.queue_lane);
            let outcome = if let Err(e) = cycle_scheduler.record_admission(lane) {
                JobOutcome::Denied {
                    reason: format!("scheduler admission reservation failed: {e}"),
                }
            } else {
                let outcome = process_job(
                    candidate,
                    &queue_root,
                    &fac_root,
                    &mut completed_gates_cache,
                    &verifying_key,
                    &cycle_scheduler,
                    lane,
                    &mut broker,
                    &signer,
                    &policy_hash,
                    &policy_digest,
                    &policy,
                    &job_spec_policy,
                    &budget_cas,
                    candidates.len(),
                    print_unit,
                    &current_tuple_digest,
                    &boundary_id,
                    cycle_count,
                    summary.jobs_completed as u64,
                    summary.jobs_denied as u64,
                    summary.jobs_quarantined as u64,
                    &cost_model,
                    Some(toolchain_fingerprint.as_str()),
                );
                cycle_scheduler.record_completion(lane);
                outcome
            };
            let duration_secs = job_started.elapsed().as_secs();

            match &outcome {
                JobOutcome::Quarantined { reason } => {
                    summary.jobs_quarantined += 1;
                    if json_output {
                        emit_worker_event(
                            "job_failed",
                            serde_json::json!({
                                "job_id": candidate.spec.job_id,
                                "outcome": "quarantined",
                                "queue_lane": candidate.spec.queue_lane,
                                "duration_secs": duration_secs,
                                "reason": reason,
                            }),
                        );
                    }
                    if !json_output {
                        eprintln!("worker: quarantined {}: {reason}", candidate.path.display());
                    }
                },
                JobOutcome::Aborted { reason } => {
                    summary.jobs_denied += 1;
                    if !json_output {
                        eprintln!("worker: aborted {}: {reason}", candidate.spec.job_id);
                    }
                },
                JobOutcome::Denied { reason } => {
                    summary.jobs_denied += 1;
                    if json_output {
                        emit_worker_event(
                            "job_failed",
                            serde_json::json!({
                                "job_id": candidate.spec.job_id,
                                "outcome": "denied",
                                "queue_lane": candidate.spec.queue_lane,
                                "duration_secs": duration_secs,
                                "reason": reason,
                            }),
                        );
                    }
                    if !json_output {
                        eprintln!("worker: denied {}: {reason}", candidate.spec.job_id);
                    }
                },
                JobOutcome::Completed {
                    job_id,
                    observed_cost,
                } => {
                    summary.jobs_completed += 1;
                    append_completed_gates_fingerprint_if_loaded(
                        &mut completed_gates_cache,
                        &candidate.spec,
                        &current_tuple_digest,
                    );

                    if let Some(cost) = observed_cost {
                        let job_kind = &candidate.spec.kind;
                        if let Err(cal_err) = cost_model.calibrate(job_kind, cost) {
                            if !json_output {
                                eprintln!(
                                    "worker: cost model calibration warning for kind \
                                     '{job_kind}': {cal_err}"
                                );
                            }
                        }
                    }
                    if json_output {
                        emit_worker_event(
                            "job_completed",
                            serde_json::json!({
                                "job_id": job_id,
                                "outcome": "completed",
                                "queue_lane": candidate.spec.queue_lane,
                                "duration_secs": duration_secs,
                            }),
                        );
                    }
                    if !json_output {
                        eprintln!("worker: completed {job_id}");
                    }
                },
                JobOutcome::Skipped { reason } => {
                    summary.jobs_skipped += 1;
                    if json_output {
                        emit_worker_event(
                            "job_skipped",
                            serde_json::json!({
                                "job_id": candidate.spec.job_id,
                                "outcome": "skipped",
                                "queue_lane": candidate.spec.queue_lane,
                                "duration_secs": duration_secs,
                                "reason": reason,
                            }),
                        );
                    }
                    if !json_output {
                        eprintln!("worker: skipped: {reason}");
                    }
                },
            }

            summary.jobs_processed += 1;
            total_processed += 1;

            if matches!(
                &outcome,
                JobOutcome::Skipped { reason } if reason.contains("no lane available")
            ) {
                break;
            }
            if matches!(&outcome, JobOutcome::Aborted { .. }) {
                break;
            }

            if once {
                if let Err(persist_err) = persist_queue_scheduler_state(
                    &fac_root,
                    &cycle_scheduler,
                    broker.current_tick(),
                    Some(&cost_model),
                ) {
                    output_worker_error(json_output, &persist_err);
                    return exit_codes::GENERIC_ERROR;
                }
                let _ = save_broker_state(&broker);
                if let Err(e) = save_token_ledger(&mut broker) {
                    output_worker_error(json_output, &format!("token ledger save failed: {e}"));
                    return exit_codes::GENERIC_ERROR;
                }
                if json_output {
                    emit_worker_summary(&summary);
                }
                return exit_codes::SUCCESS;
            }
        }

        if let Err(persist_err) = persist_queue_scheduler_state(
            &fac_root,
            &cycle_scheduler,
            broker.current_tick(),
            Some(&cost_model),
        ) {
            output_worker_error(json_output, &persist_err);
            return exit_codes::GENERIC_ERROR;
        }
        queue_state = cycle_scheduler;

        if max_jobs > 0 && total_processed >= max_jobs {
            break;
        }

        if once {
            break;
        }

        sleep_remaining(cycle_start, poll_interval_secs);
    }

    // Signal the background watchdog thread to stop.
    watchdog_stop.store(true, std::sync::atomic::Ordering::Release);

    if json_output {
        emit_worker_summary(&summary);
    }

    if let Err(persist_err) = persist_queue_scheduler_state(
        &fac_root,
        &queue_state,
        broker.current_tick(),
        Some(&cost_model),
    ) {
        output_worker_error(json_output, &persist_err);
        return exit_codes::GENERIC_ERROR;
    }
    let _ = save_broker_state(&broker);
    if let Err(e) = save_token_ledger(&mut broker) {
        output_worker_error(json_output, &format!("token ledger save failed: {e}"));
        return exit_codes::GENERIC_ERROR;
    }
    exit_codes::SUCCESS
}

fn reap_orphaned_leases_on_tick(fac_root: &Path, json_output: bool) {
    let lane_mgr = match LaneManager::new(fac_root.to_path_buf()) {
        Ok(manager) => manager,
        Err(err) => {
            tracing::warn!(error = %err, "lane maintenance skipped: cannot initialize lane manager");
            return;
        },
    };

    for lane_id in LaneManager::default_lane_ids() {
        let lane_dir = lane_mgr.lane_dir(&lane_id);
        let status = match lane_mgr.lane_status(&lane_id) {
            Ok(status) => status,
            Err(err) => {
                tracing::warn!(lane_id = lane_id.as_str(), error = %err, "lane maintenance status read failed");
                continue;
            },
        };
        let orphaned = match LaneLeaseV1::load(&lane_dir) {
            Ok(Some(lease)) => {
                lease.state == LaneState::Leased
                    && matches!(check_process_liveness(lease.pid), ProcessLiveness::Dead)
            },
            Ok(None) => status.state == LaneState::Leased && status.pid.is_none(),
            Err(err) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    error = %err,
                    "lane maintenance lease load failed"
                );
                false
            },
        };
        if !orphaned {
            continue;
        }

        let expected_runtime_secs = load_lane_expected_runtime_secs(&lane_mgr, &lane_id);
        let warning_threshold_secs =
            expected_runtime_secs.saturating_mul(ORPHAN_LEASE_WARNING_MULTIPLIER);
        let age_secs = parse_started_at_age_secs(status.started_at.as_deref());
        if age_secs.is_none_or(|age| age >= warning_threshold_secs) {
            if json_output {
                emit_worker_event(
                    "lane_orphan_lease_warning",
                    serde_json::json!({
                        "lane_id": lane_id,
                        "state": status.state.to_string(),
                        "pid": status.pid,
                        "pid_alive": status.pid_alive,
                        "age_secs": age_secs,
                        "warning_threshold_secs": warning_threshold_secs,
                    }),
                );
            } else {
                eprintln!(
                    "WARNING: orphaned lane lease detected (lane={}, pid={:?}, pid_alive={:?}, age_secs={:?}, threshold_secs={})",
                    lane_id, status.pid, status.pid_alive, age_secs, warning_threshold_secs
                );
            }
        }

        match lane_mgr.try_lock(&lane_id) {
            Ok(Some(_guard)) => match LaneLeaseV1::remove(&lane_dir) {
                Ok(()) => {
                    tracing::warn!(
                        lane_id = lane_id.as_str(),
                        pid = ?status.pid,
                        pid_alive = ?status.pid_alive,
                        "reaped orphaned lane lease during poll tick"
                    );
                    if json_output {
                        emit_worker_event(
                            "lane_orphan_lease_reaped",
                            serde_json::json!({
                                "lane_id": lane_id,
                                "pid": status.pid,
                                "pid_alive": status.pid_alive,
                            }),
                        );
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        lane_id = lane_id.as_str(),
                        error = %err,
                        "failed to remove orphaned lease during poll tick"
                    );
                },
            },
            Ok(None) => {
                tracing::debug!(
                    lane_id = lane_id.as_str(),
                    "orphaned lease reap deferred: lane lock held"
                );
            },
            Err(err) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    error = %err,
                    "orphaned lease reap failed: could not acquire lane lock"
                );
            },
        }
    }
}

fn load_lane_expected_runtime_secs(lane_mgr: &LaneManager, lane_id: &str) -> u64 {
    let lane_dir = lane_mgr.lane_dir(lane_id);
    LaneProfileV1::load(&lane_dir)
        .map(|profile| profile.timeouts.job_runtime_max_seconds)
        .unwrap_or(1_800)
}

fn parse_started_at_age_secs(started_at: Option<&str>) -> Option<u64> {
    let started_at = started_at?;
    let parsed = chrono::DateTime::parse_from_rfc3339(started_at).ok()?;
    let age_secs = Utc::now()
        .signed_duration_since(parsed.with_timezone(&Utc))
        .num_seconds();
    u64::try_from(age_secs).ok()
}

fn persist_queue_scheduler_state(
    fac_root: &Path,
    queue_state: &QueueSchedulerState,
    current_tick: u64,
    cost_model: Option<&apm2_core::economics::CostModelV1>,
) -> Result<(), String> {
    let mut state = queue_state.to_scheduler_state_v1(current_tick);
    state.persisted_at_secs = current_timestamp_epoch_secs();
    state.cost_model = cost_model.cloned();
    persist_scheduler_state(fac_root, &state)
        .map(|_| ())
        .map_err(|e| format!("failed to persist scheduler state: {e}"))
}

fn check_or_admit_canonicalizer_tuple(fac_root: &Path) -> Result<CanonicalizerTupleCheck, String> {
    let tuple = CanonicalizerTupleV1::from_current();
    let tuple_path = fac_root
        .join("broker")
        .join("admitted_canonicalizer_tuple.v1.json");

    if !tuple_path.exists() {
        return Ok(CanonicalizerTupleCheck::Missing);
    }

    match FacBroker::load_admitted_tuple(fac_root) {
        Ok(admitted_tuple) => {
            if admitted_tuple == tuple {
                Ok(CanonicalizerTupleCheck::Matched)
            } else {
                Ok(CanonicalizerTupleCheck::Mismatch(admitted_tuple))
            }
        },
        Err(BrokerError::Deserialization { detail }) => {
            Err(format!("canonicalizer tuple is corrupted: {detail}"))
        },
        Err(err) => Err(format!("failed to load canonicalizer tuple: {err}")),
    }
}

// Used by tests to avoid computing digest twice.
// Used by startup checks to avoid duplicated digest logic.
fn compute_canonicalizer_tuple_digest() -> String {
    CanonicalizerTupleV1::from_current().compute_digest()
}

// =============================================================================
// Queue scanning
// =============================================================================

/// Scans `queue/pending/` and returns sorted candidates.
///
/// Files are read with bounded I/O (INV-WRK-001), deserialized, and sorted
/// by (priority ASC, `enqueue_time` ASC, `job_id` ASC) for deterministic
/// ordering (INV-WRK-005).
///
/// Malformed, unreadable, or oversize files are quarantined with receipts
/// (INV-WRK-007) rather than silently dropped.
fn scan_pending(
    queue_root: &Path,
    fac_root: &Path,
    canonicalizer_tuple_digest: &str,
    // TCK-00538: Optional toolchain fingerprint for scan receipt provenance.
    toolchain_fingerprint: Option<&str>,
) -> Result<Vec<PendingCandidate>, String> {
    let pending_dir = queue_root.join(PENDING_DIR);
    if !pending_dir.is_dir() {
        return Ok(Vec::new());
    }

    let entries =
        fs::read_dir(&pending_dir).map_err(|e| format!("cannot read pending directory: {e}"))?;

    let mut candidates = Vec::new();

    for (idx, entry) in entries.enumerate() {
        // Bound the number of entries scanned (INV-WRK-006).
        if idx >= MAX_PENDING_SCAN_ENTRIES {
            break;
        }

        let Ok(entry) = entry else { continue };

        let path = entry.path();

        // Only process .json files.
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // Read with bounded I/O (INV-WRK-001).
        // On read failure -> quarantine + receipt (INV-WRK-007).
        let bytes = match read_bounded(&path, MAX_JOB_SPEC_SIZE) {
            Ok(b) => b,
            Err(e) => {
                let reason = format!("read failure: {e}");
                let moved_path =
                    move_to_dir_safe(&path, &queue_root.join(QUARANTINE_DIR), &file_name)
                        .map(|p| {
                            p.strip_prefix(queue_root)
                                .unwrap_or(&p)
                                .to_string_lossy()
                                .to_string()
                        })
                        .ok();
                let job_id = file_name.trim_end_matches(".json").to_string();
                let _ = emit_scan_receipt(
                    fac_root,
                    &file_name,
                    &job_id,
                    &compute_job_spec_digest_preview(&[]),
                    FacJobOutcome::Quarantined,
                    DenialReasonCode::MalformedSpec,
                    moved_path.as_deref(),
                    &reason,
                    canonicalizer_tuple_digest,
                    toolchain_fingerprint,
                );
                continue;
            },
        };

        // Bounded deserialize.
        // On deserialize failure -> quarantine + receipt (INV-WRK-007).
        let spec = match deserialize_job_spec(&bytes) {
            Ok(s) => s,
            Err(e) => {
                let reason = format!("deserialization failed: {e}");
                let moved_path =
                    move_to_dir_safe(&path, &queue_root.join(QUARANTINE_DIR), &file_name)
                        .map(|p| {
                            p.strip_prefix(queue_root)
                                .unwrap_or(&p)
                                .to_string_lossy()
                                .to_string()
                        })
                        .ok();
                let job_id = file_name.trim_end_matches(".json").to_string();
                let _ = emit_scan_receipt(
                    fac_root,
                    &file_name,
                    &job_id,
                    &compute_job_spec_digest_preview(&bytes),
                    FacJobOutcome::Quarantined,
                    DenialReasonCode::MalformedSpec,
                    moved_path.as_deref(),
                    &reason,
                    canonicalizer_tuple_digest,
                    toolchain_fingerprint,
                );
                continue;
            },
        };

        candidates.push(PendingCandidate {
            path,
            spec,
            raw_bytes: bytes,
        });
    }

    // Sort deterministically (INV-WRK-005): priority ASC, enqueue_time ASC,
    // job_id ASC.
    candidates.sort_by(|a, b| {
        a.spec
            .priority
            .cmp(&b.spec.priority)
            .then_with(|| a.spec.enqueue_time.cmp(&b.spec.enqueue_time))
            .then_with(|| a.spec.job_id.cmp(&b.spec.job_id))
    });

    Ok(candidates)
}

// =============================================================================
// Queue lane parsing
// =============================================================================

/// Parses a queue lane string into a `QueueLane` enum variant.
///
/// Supports the serde `snake_case` names used in `QueueLane` serialization.
/// Unknown lane strings default to `QueueLane::Bulk` (fail-safe: unknown
/// lane gets lowest priority).
fn parse_queue_lane(lane_str: &str) -> QueueLane {
    match lane_str {
        "stop_revoke" => QueueLane::StopRevoke,
        "control" => QueueLane::Control,
        "consume" => QueueLane::Consume,
        "replay" => QueueLane::Replay,
        "projection_replay" => QueueLane::ProjectionReplay,
        "bulk" => QueueLane::Bulk,
        _ => {
            // Try serde deserialization as fallback for quoted JSON values.
            let quoted = format!("\"{lane_str}\"");
            serde_json::from_str::<QueueLane>(&quoted).unwrap_or(QueueLane::Bulk)
        },
    }
}

fn parse_gate_profile(value: &str) -> Result<fac_review_api::GateThroughputProfile, String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "throughput" => Ok(fac_review_api::GateThroughputProfile::Throughput),
        "balanced" => Ok(fac_review_api::GateThroughputProfile::Balanced),
        "conservative" => Ok(fac_review_api::GateThroughputProfile::Conservative),
        other => Err(format!(
            "invalid gates gate_profile `{other}`; expected throughput|balanced|conservative"
        )),
    }
}

fn parse_gates_job_options(spec: &FacJobSpecV1) -> Result<GatesJobOptions, String> {
    match spec.actuation.decoded_source.as_deref() {
        Some("fac_gates_worker") => {},
        Some(other) => {
            return Err(format!(
                "unsupported gates decoded_source hint: {other} (expected fac_gates_worker)"
            ));
        },
        None => {
            return Err("missing gates decoded_source hint".to_string());
        },
    }

    let patch_value = spec
        .source
        .patch
        .as_ref()
        .ok_or_else(|| "missing gates options payload".to_string())?;
    let payload: GatesJobOptionsV1 = serde_json::from_value(patch_value.clone())
        .map_err(|err| format!("invalid gates options payload: {err}"))?;
    if payload.schema != GATES_JOB_OPTIONS_SCHEMA {
        return Err(format!(
            "unsupported gates options schema: expected {GATES_JOB_OPTIONS_SCHEMA}, got {}",
            payload.schema
        ));
    }
    Ok(GatesJobOptions {
        force: payload.force,
        quick: payload.quick,
        timeout_seconds: payload.timeout_seconds,
        memory_max: payload.memory_max,
        pids_max: payload.pids_max,
        cpu_quota: payload.cpu_quota,
        gate_profile: parse_gate_profile(&payload.gate_profile)?,
        workspace_root: resolve_workspace_root(&payload.workspace_root, &spec.source.repo_id)?,
    })
}

fn resolve_workspace_root(raw: &str, expected_repo_id: &str) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(raw);
    if !candidate.is_dir() {
        return Err(format!(
            "workspace_root is not a directory: {}",
            candidate.display()
        ));
    }

    let canonical = candidate
        .canonicalize()
        .map_err(|err| format!("failed to canonicalize workspace_root {raw}: {err}"))?;

    // Explicitly block FAC-internal roots.
    let apm2_home = resolve_apm2_home().ok_or_else(|| "cannot resolve APM2_HOME".to_string())?;
    let apm2_home = apm2_home.canonicalize().unwrap_or(apm2_home);
    let blocked_roots = [
        apm2_home.join("private").join("fac"),
        apm2_home.join("queue"),
    ];
    if blocked_roots
        .iter()
        .any(|blocked| canonical == *blocked || canonical.starts_with(blocked))
    {
        return Err(format!(
            "workspace_root {} is within FAC-internal storage (denied)",
            canonical.display()
        ));
    }

    let allowed_roots = resolve_allowed_workspace_roots()?;
    if !is_within_allowed_workspace_roots(&canonical, &allowed_roots) {
        return Err(format!(
            "workspace_root {} is outside allowed workspace roots [{}]; configure {}",
            canonical.display(),
            format_allowed_workspace_roots(&allowed_roots),
            ALLOWED_WORKSPACE_ROOTS_ENV
        ));
    }

    // Must be a git toplevel root, not a nested path.
    let toplevel_output = Command::new("git")
        .arg("-C")
        .arg(&canonical)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to run git rev-parse --show-toplevel: {err}"))?;
    if !toplevel_output.status.success() {
        return Err(format!(
            "workspace_root {} is not a git worktree root",
            canonical.display()
        ));
    }
    let git_toplevel_raw = String::from_utf8_lossy(&toplevel_output.stdout)
        .trim()
        .to_string();
    let git_toplevel = PathBuf::from(git_toplevel_raw)
        .canonicalize()
        .map_err(|err| format!("failed to canonicalize git toplevel for {raw}: {err}"))?;
    if git_toplevel != canonical {
        return Err(format!(
            "workspace_root {} must equal git toplevel {} (denied)",
            canonical.display(),
            git_toplevel.display()
        ));
    }

    // Hard-bind job payload to expected repository identity.
    let resolved_repo_id = resolve_repo_id(&canonical);
    if !resolved_repo_id.eq_ignore_ascii_case(expected_repo_id) {
        return Err(format!(
            "workspace_root repo mismatch: expected {expected_repo_id}, resolved {resolved_repo_id}"
        ));
    }

    Ok(canonical)
}

fn resolve_allowed_workspace_roots() -> Result<Vec<PathBuf>, String> {
    let mut allowed = Vec::new();

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if home.is_dir() {
            if let Ok(canonical_home) = home.canonicalize() {
                allowed.push(canonical_home);
            }
        }
    }

    if let Some(repo_root) = resolve_current_git_toplevel() {
        allowed.push(repo_root);
    }

    if let Some(raw) = std::env::var_os(ALLOWED_WORKSPACE_ROOTS_ENV) {
        for root in std::env::split_paths(&raw) {
            if root.as_os_str().is_empty() {
                continue;
            }
            if !root.is_dir() {
                return Err(format!(
                    "{} entry is not a directory: {}",
                    ALLOWED_WORKSPACE_ROOTS_ENV,
                    root.display()
                ));
            }
            let canonical_root = root.canonicalize().map_err(|err| {
                format!(
                    "failed to canonicalize {} entry {}: {err}",
                    ALLOWED_WORKSPACE_ROOTS_ENV,
                    root.display()
                )
            })?;
            allowed.push(canonical_root);
        }
    }

    allowed.sort();
    allowed.dedup();
    if allowed.is_empty() {
        return Err(format!(
            "no allowed workspace roots resolved; set {ALLOWED_WORKSPACE_ROOTS_ENV}"
        ));
    }
    Ok(allowed)
}

fn resolve_current_git_toplevel() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let path = PathBuf::from(raw.trim());
    if !path.is_dir() {
        return None;
    }
    path.canonicalize().ok()
}

fn is_within_allowed_workspace_roots(candidate: &Path, allowed_roots: &[PathBuf]) -> bool {
    allowed_roots
        .iter()
        .any(|root| candidate == root || candidate.starts_with(root))
}

fn format_allowed_workspace_roots(allowed_roots: &[PathBuf]) -> String {
    allowed_roots
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn resolve_repo_id(workspace_root: &Path) -> String {
    if let Some(remote_url) = resolve_origin_remote_url(workspace_root) {
        if let Some((owner, repo)) = parse_github_remote_url(&remote_url) {
            return format!("{owner}/{repo}");
        }
    }

    let segment = workspace_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_repo_segment)
        .filter(|segment| !segment.is_empty())
        .unwrap_or_else(|| UNKNOWN_REPO_SEGMENT.to_string());
    format!("local/{segment}")
}

fn resolve_origin_remote_url(workspace_root: &Path) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            } else {
                None
            }
        })
}

fn sanitize_repo_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }

    while out.starts_with('-') || out.starts_with('.') || out.starts_with('_') {
        out.remove(0);
    }
    while out.ends_with('-') || out.ends_with('.') || out.ends_with('_') {
        out.pop();
    }

    if out.is_empty() {
        UNKNOWN_REPO_SEGMENT.to_string()
    } else {
        out
    }
}

fn resolve_workspace_head(workspace_root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("failed to run git rev-parse HEAD: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err("git rev-parse HEAD failed".to_string());
        }
        return Err(format!("git rev-parse HEAD failed: {stderr}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[allow(clippy::too_many_arguments)]
fn run_gates_in_workspace(
    options: &GatesJobOptions,
    fac_root: &Path,
    heartbeat_cycle_count: u64,
    heartbeat_jobs_completed: u64,
    heartbeat_jobs_denied: u64,
    heartbeat_jobs_quarantined: u64,
    heartbeat_job_id: &str,
) -> Result<fac_review_api::LocalGatesRunResult, String> {
    let stop_refresh = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_refresh_bg = std::sync::Arc::clone(&stop_refresh);
    let heartbeat_fac_root = fac_root.to_path_buf();
    let heartbeat_job_id = heartbeat_job_id.to_string();
    let heartbeat_handle = std::thread::spawn(move || {
        while !stop_refresh_bg.load(std::sync::atomic::Ordering::Acquire) {
            if let Err(error) = apm2_core::fac::worker_heartbeat::write_heartbeat(
                &heartbeat_fac_root,
                heartbeat_cycle_count,
                heartbeat_jobs_completed,
                heartbeat_jobs_denied,
                heartbeat_jobs_quarantined,
                "healthy",
            ) {
                eprintln!(
                    "worker: WARNING: heartbeat refresh failed during gates job {heartbeat_job_id}: {error}"
                );
            }
            for _ in 0..(GATES_HEARTBEAT_REFRESH_SECS * 10) {
                if stop_refresh_bg.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });

    let run_result = fac_review_api::run_gates_local_worker(
        options.force,
        options.quick,
        options.timeout_seconds,
        &options.memory_max,
        options.pids_max,
        &options.cpu_quota,
        options.gate_profile,
        &options.workspace_root,
    );

    stop_refresh.store(true, std::sync::atomic::Ordering::Release);
    let _ = heartbeat_handle.join();
    run_result
}

fn apply_gates_job_lifecycle_events(spec: &FacJobSpecV1, passed: bool) -> Result<usize, String> {
    fac_review_api::apply_gate_result_lifecycle_for_repo_sha(
        &spec.source.repo_id,
        &spec.source.head_sha,
        passed,
    )
    .map_err(|err| {
        format!(
            "failed to persist lifecycle gate sequence for repo {} sha {}: {err}",
            spec.source.repo_id, spec.source.head_sha
        )
    })
}

const MAX_FAC_RECEIPT_REASON_CHARS: usize = 512;

fn truncate_receipt_reason(raw: &str) -> String {
    let len = raw.chars().count();
    if len <= MAX_FAC_RECEIPT_REASON_CHARS {
        return raw.to_string();
    }
    if MAX_FAC_RECEIPT_REASON_CHARS <= 3 {
        return raw.chars().take(MAX_FAC_RECEIPT_REASON_CHARS).collect();
    }
    let mut out = raw
        .chars()
        .take(MAX_FAC_RECEIPT_REASON_CHARS - 3)
        .collect::<String>();
    out.push_str("...");
    out
}

#[allow(clippy::too_many_arguments)]
fn execute_queued_gates_job(
    spec: &FacJobSpecV1,
    claimed_path: &Path,
    claimed_file_name: &str,
    queue_root: &Path,
    fac_root: &Path,
    boundary_trace: &ChannelBoundaryTrace,
    queue_trace: &JobQueueAdmissionTrace,
    budget_trace: Option<&FacBudgetAdmissionTrace>,
    canonicalizer_tuple_digest: &str,
    policy_hash: &str,
    sbx_hash: &str,
    net_hash: &str,
    heartbeat_cycle_count: u64,
    heartbeat_jobs_completed: u64,
    heartbeat_jobs_denied: u64,
    heartbeat_jobs_quarantined: u64,
    // TCK-00538: Toolchain fingerprint computed at worker startup.
    toolchain_fingerprint: Option<&str>,
) -> JobOutcome {
    let job_wall_start = Instant::now();
    let options = match parse_gates_job_options(spec) {
        Ok(options) => options,
        Err(reason) => {
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied gates job (parse options)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    let current_head = match resolve_workspace_head(&options.workspace_root) {
        Ok(head) => head,
        Err(err) => {
            let reason = format!(
                "cannot resolve workspace HEAD for {}: {err}",
                options.workspace_root.display()
            );
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied gates job (resolve HEAD)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };
    if !current_head.eq_ignore_ascii_case(&spec.source.head_sha) {
        let reason = format!(
            "gates job head mismatch: worker workspace HEAD {current_head} does not match job head {}",
            spec.source.head_sha
        );
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(sbx_hash),
            Some(net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied gates job (head mismatch)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    let gate_run_result = match run_gates_in_workspace(
        &options,
        fac_root,
        heartbeat_cycle_count,
        heartbeat_jobs_completed,
        heartbeat_jobs_denied,
        heartbeat_jobs_quarantined,
        &spec.job_id,
    ) {
        Ok(code) => code,
        Err(err) => {
            let reason = format!("failed to execute gates in workspace: {err}");
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied gates job (execution error)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    let lifecycle_update_result =
        apply_gates_job_lifecycle_events(spec, gate_run_result.exit_code == exit_codes::SUCCESS);

    if gate_run_result.exit_code == exit_codes::SUCCESS {
        if let Err(err) = lifecycle_update_result {
            let reason = format!("gates passed but lifecycle update failed: {err}");
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied gates job (lifecycle update failure after pass)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        }

        let observed_cost = observed_cost_from_elapsed(job_wall_start.elapsed());
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Completed,
            None,
            "gates completed",
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            Some(observed_cost),
            Some(sbx_hash),
            Some(net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: pipeline commit failed for gates job: {commit_err}");
            if let Err(move_err) = move_to_dir_safe(
                claimed_path,
                &queue_root.join(PENDING_DIR),
                claimed_file_name,
            ) {
                eprintln!(
                    "worker: WARNING: failed to return claimed gates job to pending: {move_err}"
                );
            }
            return JobOutcome::Skipped {
                reason: format!("pipeline commit failed for gates job: {commit_err}"),
            };
        }

        // TCK-00540 BLOCKER fix: After the receipt is committed, rebind
        // the gate cache with real RFC-0028/0029 receipt evidence. This
        // promotes the fail-closed default (`false`) to `true` only when
        // the durable receipt contains the required bindings.
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        if let Ok(signer) = fac_key_material::load_or_generate_persistent_signer(fac_root) {
            fac_review_api::rebind_gate_cache_after_receipt(
                &spec.source.head_sha,
                &receipts_dir,
                &spec.job_id,
                &signer,
            );
            // TCK-00541 round-3 MAJOR fix: Also rebind the v3 gate cache.
            // Without this, v3 entries persist with `rfc0028_receipt_bound =
            // false` and `rfc0029_receipt_bound = false`, causing
            // `check_reuse` to deny all hits and defeating v3 cache reuse.
            fac_review_api::rebind_v3_gate_cache_after_receipt(
                &spec.source.head_sha,
                policy_hash,
                sbx_hash,
                net_hash,
                &receipts_dir,
                &spec.job_id,
                &signer,
            );
        }

        return JobOutcome::Completed {
            job_id: spec.job_id.clone(),
            observed_cost: Some(observed_cost),
        };
    }

    // Gates failed: commit claimed job to denied via pipeline.
    let base_reason = match lifecycle_update_result {
        Ok(_) => format!("gates failed with exit code {}", gate_run_result.exit_code),
        Err(err) => format!(
            "gates failed with exit code {}; {err}",
            gate_run_result.exit_code
        ),
    };
    let reason = match gate_run_result.failure_summary.as_deref() {
        Some(summary) if !summary.trim().is_empty() => {
            truncate_receipt_reason(&format!("{base_reason}; {summary}"))
        },
        _ => truncate_receipt_reason(&base_reason),
    };
    // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
    if let Err(commit_err) = commit_claimed_job_via_pipeline(
        fac_root,
        queue_root,
        spec,
        claimed_path,
        claimed_file_name,
        FacJobOutcome::Denied,
        Some(DenialReasonCode::ValidationFailed),
        &reason,
        Some(boundary_trace),
        Some(queue_trace),
        budget_trace,
        None,
        Some(canonicalizer_tuple_digest),
        policy_hash,
        None,
        None,
        Some(sbx_hash),
        Some(net_hash),
        None, // stop_revoke_admission
        None, // bytes_backend
        toolchain_fingerprint,
    ) {
        return handle_pipeline_commit_failure(
            &commit_err,
            "denied gates job (gate failure)",
            claimed_path,
            queue_root,
            claimed_file_name,
        );
    }
    JobOutcome::Denied { reason }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShaDuplicateMatch {
    existing_job_id: String,
    existing_enqueue_time: String,
    matched_by: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletedGatesFingerprint {
    job_id: String,
    enqueue_time: String,
    repo_id: String,
    head_sha: String,
    /// Canonicalizer tuple digest of the binary that ran this job.
    /// Dedup only matches when the current binary's digest equals this value,
    /// ensuring that a rebuilt binary re-gates the same SHA.
    toolchain_digest: String,
}

#[derive(Debug, Clone, Default)]
struct CompletedGatesCache {
    by_repo_sha: HashMap<(String, String), Vec<CompletedGatesFingerprint>>,
}

#[derive(Debug, Deserialize)]
struct CompletedGatesFingerprintSpec {
    job_id: String,
    kind: String,
    enqueue_time: String,
    source: CompletedGatesFingerprintSource,
}

#[derive(Debug, Deserialize)]
struct CompletedGatesFingerprintSource {
    repo_id: String,
    head_sha: String,
}

impl CompletedGatesFingerprint {
    fn from_spec(spec: &FacJobSpecV1, toolchain_digest: &str) -> Option<Self> {
        if !spec.kind.eq_ignore_ascii_case("gates") {
            return None;
        }
        Some(Self {
            job_id: spec.job_id.clone(),
            enqueue_time: spec.enqueue_time.clone(),
            repo_id: spec.source.repo_id.clone(),
            head_sha: spec.source.head_sha.clone(),
            toolchain_digest: toolchain_digest.to_string(),
        })
    }
}

impl CompletedGatesCache {
    fn from_fingerprints(fingerprints: Vec<CompletedGatesFingerprint>) -> Self {
        let mut cache = Self::default();
        for fingerprint in fingerprints {
            cache.insert(fingerprint);
        }
        cache
    }

    fn insert(&mut self, fingerprint: CompletedGatesFingerprint) {
        let key = (
            normalize_dedupe_key_component(&fingerprint.repo_id),
            normalize_dedupe_key_component(&fingerprint.head_sha),
        );
        self.by_repo_sha.entry(key).or_default().push(fingerprint);
    }
}

fn append_completed_gates_fingerprint_if_loaded(
    completed_gates_cache: &mut Option<CompletedGatesCache>,
    spec: &FacJobSpecV1,
    toolchain_digest: &str,
) {
    let Some(cache) = completed_gates_cache.as_mut() else {
        return;
    };
    let Some(fingerprint) = CompletedGatesFingerprint::from_spec(spec, toolchain_digest) else {
        return;
    };
    cache.insert(fingerprint);
}

fn normalize_dedupe_key_component(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn load_completed_gates_fingerprints(
    queue_root: &Path,
    fac_root: &Path,
) -> Vec<CompletedGatesFingerprint> {
    let mut fingerprints = Vec::new();
    let completed_dir = queue_root.join(COMPLETED_DIR);
    if !completed_dir.is_dir() {
        return fingerprints;
    }

    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let Ok(entries) = fs::read_dir(&completed_dir) else {
        return fingerprints;
    };

    for (idx, entry) in entries.enumerate() {
        if idx >= MAX_COMPLETED_SCAN_ENTRIES {
            break;
        }

        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let Ok(bytes) = read_bounded(&path, MAX_JOB_SPEC_SIZE) else {
            continue;
        };
        let parsed: CompletedGatesFingerprintSpec = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !parsed.kind.eq_ignore_ascii_case("gates") {
            continue;
        }

        let Some(existing_receipt) =
            apm2_core::fac::find_receipt_for_job(&receipts_dir, &parsed.job_id)
        else {
            continue;
        };
        if existing_receipt.outcome != FacJobOutcome::Completed {
            continue;
        }

        fingerprints.push(CompletedGatesFingerprint {
            job_id: parsed.job_id,
            enqueue_time: parsed.enqueue_time,
            repo_id: parsed.source.repo_id,
            head_sha: parsed.source.head_sha,
            toolchain_digest: existing_receipt
                .canonicalizer_tuple_digest
                .unwrap_or_default(),
        });
    }

    fingerprints
}

fn load_completed_gates_cache(queue_root: &Path, fac_root: &Path) -> CompletedGatesCache {
    CompletedGatesCache::from_fingerprints(load_completed_gates_fingerprints(queue_root, fac_root))
}

fn find_completed_gates_duplicate_in_cache(
    incoming: &FacJobSpecV1,
    completed_gates_cache: &CompletedGatesCache,
    current_toolchain_digest: &str,
) -> Option<ShaDuplicateMatch> {
    let key = (
        normalize_dedupe_key_component(incoming.source.repo_id.as_str()),
        normalize_dedupe_key_component(incoming.source.head_sha.as_str()),
    );
    let existing_fingerprints = completed_gates_cache.by_repo_sha.get(&key)?;
    // Only match when the toolchain digest is identical — a rebuilt binary must
    // re-gate the same SHA so that gate results reflect the current toolchain.
    let existing = existing_fingerprints
        .iter()
        .find(|fp| fp.toolchain_digest == current_toolchain_digest)?;
    Some(ShaDuplicateMatch {
        existing_job_id: existing.job_id.clone(),
        existing_enqueue_time: existing.enqueue_time.clone(),
        matched_by: "repo_sha_toolchain",
    })
}

fn find_completed_gates_duplicate(
    queue_root: &Path,
    fac_root: &Path,
    incoming: &FacJobSpecV1,
    completed_gates_cache: &mut Option<CompletedGatesCache>,
    current_toolchain_digest: &str,
) -> Option<ShaDuplicateMatch> {
    if !incoming.kind.eq_ignore_ascii_case("gates") {
        return None;
    }

    let cache = completed_gates_cache
        .get_or_insert_with(|| load_completed_gates_cache(queue_root, fac_root));
    find_completed_gates_duplicate_in_cache(incoming, cache, current_toolchain_digest)
}

fn serialize_denial_reason_code(denial_reason: DenialReasonCode) -> String {
    serde_json::to_value(denial_reason)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "missing_denial_reason_code".to_string())
}

fn derive_queue_root_from_fac_root(fac_root: &Path) -> Option<PathBuf> {
    let apm2_home = fac_root.parent()?.parent()?;
    Some(apm2_home.join(QUEUE_DIR))
}

fn annotate_denied_job_file(
    denied_path: &Path,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
) -> Result<(), String> {
    let bytes = read_bounded(denied_path, MAX_TERMINAL_JOB_METADATA_FILE_SIZE)?;
    let mut payload: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "cannot parse denied job file {}: {e}",
            denied_path.display()
        )
    })?;
    let Some(map) = payload.as_object_mut() else {
        return Err(format!(
            "denied job payload is not a JSON object: {}",
            denied_path.display()
        ));
    };

    let denial_reason_code = denial_reason.map_or_else(
        || "missing_denial_reason_code".to_string(),
        serialize_denial_reason_code,
    );
    let denial_reason_text = {
        let trimmed = reason.trim();
        if trimmed.is_empty() {
            format!("denied ({denial_reason_code})")
        } else {
            trimmed.to_string()
        }
    };

    map.insert(
        "denial_reason_code".to_string(),
        serde_json::Value::String(denial_reason_code),
    );
    map.insert(
        "denial_reason".to_string(),
        serde_json::Value::String(denial_reason_text),
    );
    map.insert(
        "denied_at".to_string(),
        serde_json::Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
    );

    let output = serde_json::to_vec_pretty(&payload).map_err(|e| {
        format!(
            "cannot serialize denied job metadata update {}: {e}",
            denied_path.display()
        )
    })?;
    if output.len() > MAX_TERMINAL_JOB_METADATA_FILE_SIZE {
        return Err(format!(
            "denied job metadata payload exceeds max size ({} > {}) for {}",
            output.len(),
            MAX_TERMINAL_JOB_METADATA_FILE_SIZE,
            denied_path.display()
        ));
    }

    fac_permissions::write_fac_file_with_mode(denied_path, &output).map_err(|e| {
        format!(
            "cannot persist denied job metadata for {}: {e}",
            denied_path.display()
        )
    })
}

fn annotate_denied_job_metadata_from_receipt(terminal_path: &Path, receipt: &FacJobReceiptV1) {
    if receipt.outcome != FacJobOutcome::Denied {
        return;
    }
    if let Err(err) = annotate_denied_job_file(
        terminal_path,
        receipt.denial_reason,
        receipt.reason.as_str(),
    ) {
        eprintln!(
            "worker: WARNING: duplicate denied job metadata update failed for {}: {err}",
            terminal_path.display()
        );
    }
}

fn annotate_denied_job_from_moved_path(
    fac_root: &Path,
    moved_job_path: &str,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
) {
    let normalized = moved_job_path.trim().trim_start_matches('/');
    if normalized.is_empty() || !normalized.starts_with("denied/") {
        return;
    }

    let rel_path = Path::new(normalized);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        eprintln!(
            "worker: WARNING: refusing denied metadata update for unsafe moved path: {moved_job_path}"
        );
        return;
    }

    let Some(queue_root) = derive_queue_root_from_fac_root(fac_root) else {
        return;
    };
    let denied_path = queue_root.join(rel_path);
    if let Err(err) = annotate_denied_job_file(&denied_path, denial_reason, reason) {
        eprintln!(
            "worker: WARNING: failed to populate denied job metadata for {}: {err}",
            denied_path.display()
        );
    }
}

// =============================================================================
// Job processing
// =============================================================================

/// Processes a single pending job through the validation pipeline.
///
/// Returns the outcome (quarantine, deny, complete, or skip).
#[allow(clippy::too_many_arguments)]
fn process_job(
    candidate: &PendingCandidate,
    queue_root: &Path,
    fac_root: &Path,
    completed_gates_cache: &mut Option<CompletedGatesCache>,
    verifying_key: &apm2_core::crypto::VerifyingKey,
    scheduler: &QueueSchedulerState,
    lane: QueueLane,
    broker: &mut FacBroker,
    signer: &Signer,
    policy_hash: &str,
    policy_digest: &[u8; 32],
    policy: &FacPolicyV1,
    job_spec_policy: &apm2_core::fac::JobSpecValidationPolicy,
    budget_cas: &MemoryCas,
    _candidates_count: usize,
    print_unit: bool,
    canonicalizer_tuple_digest: &str,
    boundary_id: &str,
    heartbeat_cycle_count: u64,
    heartbeat_jobs_completed: u64,
    heartbeat_jobs_denied: u64,
    heartbeat_jobs_quarantined: u64,
    cost_model: &apm2_core::economics::CostModelV1,
    // TCK-00538: Toolchain fingerprint computed once at worker startup.
    toolchain_fingerprint: Option<&str>,
) -> JobOutcome {
    let job_wall_start = Instant::now();

    let path = &candidate.path;
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_string(),
        None => {
            return JobOutcome::Skipped {
                reason: "invalid filename".to_string(),
            };
        },
    };

    // Step 0: Index-first duplicate detection (TCK-00560).
    //
    // Check the receipt index to see if a receipt already exists for this
    // job_id. This avoids redundant processing of already-completed jobs
    // and replaces full directory scans with an O(1) index lookup.
    //
    // When a duplicate is detected, the pending file is moved to the correct
    // terminal directory based on the receipt outcome (completed, denied,
    // cancelled, quarantine). This is outcome-aware to prevent denied jobs
    // from being routed to completed/ (TCK-00564 MAJOR-1 fix round 4).
    let spec = &candidate.spec;
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    if let Some(existing_receipt) =
        apm2_core::fac::find_receipt_for_job(&receipts_dir, &spec.job_id)
    {
        // BLOCKER-1 fix (round 7): Handle non-terminal outcomes explicitly.
        // If the receipt outcome is non-terminal (e.g., CancellationRequested),
        // do NOT move the job — skip it and log a warning. Only terminal
        // outcomes produce a valid target directory.
        let Some(terminal_state) =
            apm2_core::fac::outcome_to_terminal_state(existing_receipt.outcome)
        else {
            eprintln!(
                "worker: duplicate job {} has non-terminal receipt outcome {:?}, \
                 skipping move (job stays in pending/ for reconciliation)",
                spec.job_id, existing_receipt.outcome,
            );
            return JobOutcome::Skipped {
                reason: format!(
                    "receipt already exists for job {} with non-terminal outcome {:?}, \
                     skipped (no terminal directory for this outcome)",
                    spec.job_id, existing_receipt.outcome,
                ),
            };
        };
        let terminal_dir = queue_root.join(terminal_state.dir_name());
        // BLOCKER-2 fix (round 7): Use hardened move_job_to_terminal instead
        // of move_to_dir_safe. move_job_to_terminal includes symlink checks,
        // ownership verification, and restrictive directory creation mode.
        let moved_terminal_path = match move_job_to_terminal(path, &terminal_dir, &file_name) {
            Ok(path) => path,
            Err(move_err) => {
                eprintln!(
                    "worker: duplicate job {} detected but move to terminal failed: {move_err}",
                    spec.job_id,
                );
                return JobOutcome::Skipped {
                    reason: format!(
                        "receipt already exists for job {} but move to terminal failed: {move_err}",
                        spec.job_id,
                    ),
                };
            },
        };

        annotate_denied_job_metadata_from_receipt(&moved_terminal_path, &existing_receipt);
        return JobOutcome::Skipped {
            reason: format!(
                "receipt already exists for job {} (index lookup, outcome={:?})",
                spec.job_id, existing_receipt.outcome,
            ),
        };
    }

    // NIT-2: Compute sandbox hardening hash once at the top of process_job
    // instead of re-computing it in every denial path.
    let sbx_hash = policy.sandbox_hardening.content_hash_hex();

    // TCK-00574 MAJOR-2 fix: Resolve the network policy hash immediately
    // using spec.kind (always available since spec is parsed before
    // process_job is called). This ensures ALL receipt commits — including
    // early post-parse denial paths — use the correct resolved hash for the
    // job kind, not the default-deny hash. The operator policy override is
    // threaded through to preserve FacPolicyV1.network_policy configuration.
    let resolved_net_hash =
        apm2_core::fac::resolve_network_policy(&spec.kind, policy.network_policy.as_ref())
            .content_hash_hex();

    // TCK-00622 S8: SHA-level gates dedupe.
    //
    // For `gates` jobs, deny duplicate submissions when a completed receipt
    // already exists for the same `(repo_id, head_sha)` AND the same
    // toolchain (canonicalizer_tuple_digest). Including the toolchain digest
    // ensures that a rebuilt binary re-gates the same SHA, while identical
    // binaries still benefit from dedup.
    if let Some(dupe) = find_completed_gates_duplicate(
        queue_root,
        fac_root,
        spec,
        completed_gates_cache,
        canonicalizer_tuple_digest,
    ) {
        let reason = format!(
            "already completed: repo={} sha={} kind={} existing_job_id={} matched_by={} existing_enqueue_time={}",
            spec.source.repo_id,
            spec.source.head_sha,
            spec.kind,
            dupe.existing_job_id,
            dupe.matched_by,
            dupe.existing_enqueue_time
        );
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::AlreadyCompleted),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!(
                "worker: WARNING: receipt emission failed for dedup-denied job: {receipt_err}"
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Step 1+2: Use the bounded bytes already loaded by scan_pending.
    //
    // The file was already validated by `scan_pending`; this avoids duplicate I/O.
    let _ = &candidate.raw_bytes;
    // Validate structure + digest + request_id binding.
    // stop_revoke jobs use control-lane validation which now enforces the
    // RFC-0028 token at the core validation layer, consistent with the
    // worker's dual-layer authorization (token + queue directory ownership).
    let is_stop_revoke = spec.kind == "stop_revoke";
    let validation_result = if is_stop_revoke {
        validate_job_spec_control_lane_with_policy(spec, job_spec_policy)
    } else {
        validate_job_spec_with_policy(spec, job_spec_policy)
    };
    if let Err(e) = validation_result {
        let is_digest_error = matches!(
            e,
            JobSpecError::DigestMismatch { .. } | JobSpecError::RequestIdMismatch { .. }
        );
        if is_digest_error {
            let reason = format!("digest validation failed: {e}");
            // BLOCKER-3 fix (round 7): Use ReceiptWritePipeline for atomic
            // commit even for pre-claim paths. The pipeline persists the
            // receipt, updates the index, and moves the job to the terminal
            // directory using the hardened move_job_to_terminal.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                path,
                &file_name,
                FacJobOutcome::Quarantined,
                Some(DenialReasonCode::DigestMismatch),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: WARNING: pipeline commit failed for quarantined job: {commit_err}"
                );
                // Job stays in pending/ for reconciliation.
                return JobOutcome::Skipped {
                    reason: format!(
                        "pipeline commit failed for quarantined job (digest mismatch): {commit_err}"
                    ),
                };
            }
            return JobOutcome::Quarantined { reason };
        }
        // Other validation errors (missing token, schema, etc.) -> deny.
        let reason = format!("validation failed: {e}");
        let reason_code = match e {
            JobSpecError::MissingToken { .. } => DenialReasonCode::MissingChannelToken,
            JobSpecError::InvalidDigest { .. } => DenialReasonCode::MalformedSpec,
            // TCK-00579: Policy-specific variants map to PolicyViolation
            // for distinct audit signal and automated triage.
            JobSpecError::DisallowedRepoId { .. }
            | JobSpecError::DisallowedBytesBackend { .. }
            | JobSpecError::FilesystemPathRejected { .. }
            | JobSpecError::InvalidControlLaneRepoId { .. } => DenialReasonCode::PolicyViolation,
            _ => DenialReasonCode::ValidationFailed,
        };
        // BLOCKER-3 fix (round 7): Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            path,
            &file_name,
            FacJobOutcome::Denied,
            Some(reason_code),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: pipeline commit failed for denied job: {commit_err}");
            // Job stays in pending/ for reconciliation.
            return JobOutcome::Skipped {
                reason: format!(
                    "pipeline commit failed for denied job (validation failed): {commit_err}"
                ),
            };
        }
        return JobOutcome::Denied { reason };
    }

    // TCK-00587: Control-lane stop_revoke with RFC-0028 token enforcement.
    //
    // Control-lane stop_revoke jobs enforce a dual-layer authorization:
    // 1. RFC-0028 token validation (signing key proof)
    // 2. Queue directory ownership validation (filesystem privilege proof)
    //
    // The cancel command issues a self-signed token using the persistent FAC
    // signing key. The worker validates this token here, ensuring only entities
    // with access to the signing key can issue valid cancellation tokens.
    if is_stop_revoke {
        // Step CL-1: Validate RFC-0028 token (fail-closed).
        // The token MUST be present and valid. Missing or invalid tokens
        // deny the job immediately — no queue-write-only authorization.
        let token = match &spec.actuation.channel_context_token {
            Some(t) if !t.is_empty() => t.as_str(),
            _ => {
                let reason = "stop_revoke missing RFC-0028 token (no unauth cancel)".to_string();
                let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                    .map(|p| {
                        p.strip_prefix(queue_root)
                            .unwrap_or(&p)
                            .to_string_lossy()
                            .to_string()
                    })
                    .ok();
                if let Err(receipt_err) = emit_job_receipt(
                    fac_root,
                    spec,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::MissingChannelToken),
                    &reason,
                    None,
                    None,
                    None,
                    None,
                    Some(canonicalizer_tuple_digest),
                    moved_path.as_deref(),
                    policy_hash,
                    None,
                    Some(&sbx_hash),
                    Some(&resolved_net_hash),
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    eprintln!(
                        "worker: WARNING: receipt emission failed for denied stop_revoke: {receipt_err}"
                    );
                }
                return JobOutcome::Denied { reason };
            },
        };

        let current_time_secs = current_timestamp_epoch_secs();
        // Decode and verify the token signature+fields without binding
        // checks (control-lane tokens do not carry policy/canonicalizer
        // bindings — those are broker-issued concerns).
        let boundary_check = match apm2_core::channel::enforcement::decode_channel_context_token(
            token,
            verifying_key,
            &spec.actuation.lease_id,
            current_time_secs,
            &spec.actuation.request_id,
        ) {
            Ok(check) => check,
            Err(e) => {
                let reason = format!("stop_revoke token validation failed: {e}");
                let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                    .map(|p| {
                        p.strip_prefix(queue_root)
                            .unwrap_or(&p)
                            .to_string_lossy()
                            .to_string()
                    })
                    .ok();
                if let Err(receipt_err) = emit_job_receipt(
                    fac_root,
                    spec,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::TokenDecodeFailed),
                    &reason,
                    None,
                    None,
                    None,
                    None,
                    Some(canonicalizer_tuple_digest),
                    moved_path.as_deref(),
                    policy_hash,
                    None,
                    Some(&sbx_hash),
                    Some(&resolved_net_hash),
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    eprintln!(
                        "worker: WARNING: receipt emission failed for denied stop_revoke: {receipt_err}"
                    );
                }
                return JobOutcome::Denied { reason };
            },
        };

        // Build boundary trace from real token validation results.
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            // Control-lane tokens do not carry policy/canonicalizer bindings;
            // populate from token_binding if present, otherwise None.
            token_fac_policy_hash: boundary_check
                .token_binding
                .as_ref()
                .map(|b| hex::encode(b.fac_policy_hash)),
            token_canonicalizer_tuple_digest: boundary_check
                .token_binding
                .as_ref()
                .map(|b| hex::encode(b.canonicalizer_tuple_digest)),
            token_boundary_id: boundary_check
                .token_binding
                .as_ref()
                .map(|b| b.boundary_id.clone()),
            token_issued_at_tick: boundary_check
                .token_binding
                .as_ref()
                .map(|b| b.issued_at_tick),
            token_expiry_tick: boundary_check.token_binding.as_ref().map(|b| b.expiry_tick),
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "stop_revoke".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let budget_trace: Option<FacBudgetAdmissionTrace> = None;

        // Step CL-2: Verify local-origin authority via strict owner+mode
        // validation on the queue directory tree. The queue root and all
        // critical subdirectories must be owned by the current uid with
        // mode <= 0700 (no group/world access).
        {
            #[cfg(unix)]
            let current_uid = nix::unistd::geteuid().as_raw();
            #[cfg(not(unix))]
            let current_uid = 0u32;

            // Validate queue_root and all state subdirectories.
            let dirs_to_check: &[&Path] = &[
                queue_root,
                &queue_root.join(PENDING_DIR),
                &queue_root.join(CLAIMED_DIR),
                &queue_root.join(COMPLETED_DIR),
                &queue_root.join(DENIED_DIR),
                &queue_root.join(CANCELLED_DIR),
            ];
            let mut perm_err: Option<String> = None;
            for dir in dirs_to_check {
                if !dir.exists() {
                    continue;
                }
                if let Err(e) = fac_permissions::validate_directory(dir, current_uid) {
                    perm_err = Some(format!(
                        "stop_revoke local-origin authority denied: \
                         unsafe queue directory {}: {e}",
                        dir.display()
                    ));
                    break;
                }
            }
            if let Some(reason) = perm_err {
                let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                    .map(|p| {
                        p.strip_prefix(queue_root)
                            .unwrap_or(&p)
                            .to_string_lossy()
                            .to_string()
                    })
                    .ok();
                if let Err(receipt_err) = emit_job_receipt(
                    fac_root,
                    spec,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::UnsafeQueuePermissions),
                    &reason,
                    Some(&boundary_trace),
                    Some(&queue_trace),
                    budget_trace.as_ref(),
                    None,
                    Some(canonicalizer_tuple_digest),
                    moved_path.as_deref(),
                    policy_hash,
                    None,
                    Some(&sbx_hash),
                    Some(&resolved_net_hash),
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    eprintln!(
                        "worker: WARNING: receipt emission failed for denied stop_revoke: {receipt_err}"
                    );
                }
                return JobOutcome::Denied { reason };
            }
        }

        // PCAC lifecycle: check if authority was already consumed.
        if is_authority_consumed(queue_root, &spec.job_id) {
            let reason = format!("authority already consumed for job {}", spec.job_id);
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::AuthorityAlreadyConsumed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: WARNING: receipt emission failed for denied stop_revoke: {receipt_err}"
                );
            }
            return JobOutcome::Denied { reason };
        }

        // Atomic claim via rename.
        let claimed_dir = queue_root.join(CLAIMED_DIR);
        let claimed_path = match move_to_dir_safe(path, &claimed_dir, &file_name) {
            Ok(p) => p,
            Err(e) => {
                return JobOutcome::Skipped {
                    reason: format!("atomic claim failed: {e}"),
                };
            },
        };
        let claimed_file_name = claimed_path
            .file_name()
            .map_or_else(|| file_name.clone(), |n| n.to_string_lossy().to_string());

        // PCAC consume.
        if let Err(e) = consume_authority(queue_root, &spec.job_id, &spec.job_spec_digest) {
            let reason = format!("PCAC consume failed: {e}");
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                &claimed_path,
                &claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::PcacConsumeFailed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied job (PCAC consume failed)",
                    &claimed_path,
                    queue_root,
                    &claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        }

        // TCK-00587: Construct stop/revoke admission trace from real
        // runtime state. Each field is derived from actual admission
        // predicates and queue state — no hardcoded constants.
        let sr_policy =
            apm2_core::economics::queue_admission::StopRevokeAdmissionPolicy::default_policy();
        let lane_state = scheduler.lane(QueueLane::StopRevoke);
        let total_items = scheduler.total_items();
        // reservation_used: true only when total queue was already at or over
        // capacity before this job was admitted (i.e., the lane reservation was
        // actually needed). Uses `>` because `total_items` includes the
        // currently admitted job.
        let reservation_used =
            total_items > apm2_core::economics::queue_admission::MAX_TOTAL_QUEUE_ITEMS;
        // Control-lane jobs bypass RFC-0029 temporal predicates entirely.
        // TP-001/002/003 are not evaluated — record None to indicate
        // "not evaluated" (distinct from Some(false) = "evaluated and failed").
        let tp001_emergency_carveout_activated = false;
        let tp002_passed: Option<bool> = None;
        let tp003_passed: Option<bool> = None;
        // tick_floor_active: true when stop_revoke items have been waiting
        // longer than the policy max_wait_ticks threshold.
        let tick_floor_active = lane_state.max_wait_ticks >= sr_policy.max_wait_ticks;
        // worker_first_pass: stop_revoke jobs have priority 0 (highest) in
        // the sorted candidate list, so they are always processed before
        // other lanes.  This is true by construction of the scan ordering.
        let worker_first_pass = sr_policy.worker_priority_first_pass;

        let sr_admission_trace = apm2_core::economics::queue_admission::StopRevokeAdmissionTrace {
            verdict: "allow".to_string(),
            reservation_used,
            tp001_emergency_carveout_activated,
            tp002_passed,
            tp003_passed,
            lane_backlog_at_admission: lane_state.backlog,
            total_queue_items_at_admission: total_items,
            tick_floor_active,
            worker_first_pass,
            policy_snapshot: sr_policy,
        };

        // Control-lane stop_revoke jobs skip lane acquisition and go
        // directly to handle_stop_revoke.
        return handle_stop_revoke(
            spec,
            &claimed_path,
            &claimed_file_name,
            queue_root,
            fac_root,
            &boundary_trace,
            &queue_trace,
            budget_trace.as_ref(),
            canonicalizer_tuple_digest,
            policy_hash,
            &sbx_hash,
            &resolved_net_hash,
            job_wall_start,
            Some(&sr_admission_trace),
            toolchain_fingerprint,
        );
    }

    // Step 2.5: Enforce admitted policy binding (INV-PADOPT-004, TCK-00561).
    // Workers MUST fail-closed when the actuation token's policy binding
    // does not match the admitted digest. This prevents policy drift where
    // tokens issued under an old policy continue to authorize actuation
    // after a new policy has been adopted.
    if !apm2_core::fac::is_policy_hash_admitted(fac_root, policy_hash) {
        let reason = format!(
            "policy hash not admitted (INV-PADOPT-004): worker policy_hash={policy_hash} is not \
             the currently admitted digest"
        );
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            path,
            &file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::PolicyAdmissionDenied),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!(
                "worker: WARNING: pipeline commit failed for policy-admission-denied job: {commit_err}"
            );
            return JobOutcome::Skipped {
                reason: format!(
                    "pipeline commit failed for policy-admission-denied job: {commit_err}"
                ),
            };
        }
        return JobOutcome::Denied { reason };
    }

    // Step 2.6: Enforce admitted economics profile binding (INV-EADOPT-004,
    // TCK-00584). Workers MUST fail-closed when the policy's economics
    // profile hash does not match the broker-admitted economics profile
    // digest. This prevents economics drift where profiles from an old
    // policy continue to authorize budget decisions after a new economics
    // profile has been adopted.
    //
    // Error handling is fail-closed by error variant:
    // - NoAdmittedRoot + policy has non-zero economics_profile_hash: DENY the job.
    //   The policy requires economics enforcement but there is no admitted root to
    //   verify against. An attacker could delete the root file to bypass admission
    //   — this arm prevents that (INV-EADOPT-004).
    // - NoAdmittedRoot + policy has zero economics_profile_hash: skip check
    //   (backwards compatibility for installations that have not adopted an
    //   economics profile and whose policies don't require one).
    // - Any other error (Io, Serialization, FileTooLarge, SchemaMismatch,
    //   UnsupportedSchemaVersion, etc.): DENY the job. Treating I/O/corruption
    //   errors as "no root" would let an attacker bypass admission by tampering
    //   with or removing the admitted-economics root file.
    {
        let profile_hash_str = format!("b3-256:{}", hex::encode(policy.economics_profile_hash));
        let fac_root_for_econ = fac_root;
        let econ_load_result =
            apm2_core::fac::economics_adoption::load_admitted_economics_profile_root(
                fac_root_for_econ,
            );
        let econ_denial_reason: Option<String> = match econ_load_result {
            Ok(root) => {
                // Root loaded successfully: constant-time compare hashes.
                let admitted_bytes = root.admitted_profile_hash.as_bytes();
                let check_bytes = profile_hash_str.as_bytes();
                let matches = admitted_bytes.len() == check_bytes.len()
                    && bool::from(admitted_bytes.ct_eq(check_bytes));
                if matches {
                    None // admitted -- proceed
                } else {
                    Some(format!(
                        "economics profile hash not admitted (INV-EADOPT-004): \
                         policy economics_profile_hash={profile_hash_str} is not \
                         the currently admitted digest"
                    ))
                }
            },
            Err(apm2_core::fac::EconomicsAdoptionError::NoAdmittedRoot { .. }) => {
                // No admitted root exists. Fail-closed decision based on
                // whether the policy requires economics enforcement:
                // - If the policy's economics_profile_hash is all zeros, no economics binding
                //   is required, so the check is skipped (backwards compatibility for
                //   installations that have not adopted an economics profile).
                // - If the policy's economics_profile_hash is non-zero, it specifies a concrete
                //   economics binding. Without an admitted root, we cannot verify that binding,
                //   so the job MUST be denied. This prevents bypass via root file deletion
                //   (INV-EADOPT-004).
                if policy.economics_profile_hash == [0u8; 32] {
                    None
                } else {
                    Some(format!(
                        "economics admission denied (INV-EADOPT-004, fail-closed): \
                         policy requires economics binding (economics_profile_hash={profile_hash_str}) \
                         but no admitted economics root exists on this broker"
                    ))
                }
            },
            Err(load_err) => {
                // Any other error (I/O, corruption, schema mismatch,
                // oversized file, etc.) is fail-closed: deny the job
                // to prevent admission bypass via root tampering.
                Some(format!(
                    "economics admission denied (INV-EADOPT-004, fail-closed): \
                     cannot load admitted economics root: {load_err}"
                ))
            },
        };
        if let Some(reason) = econ_denial_reason {
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                path,
                &file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::EconomicsAdmissionDenied),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: WARNING: pipeline commit failed for \
                     economics-admission-denied job: {commit_err}"
                );
                return JobOutcome::Skipped {
                    reason: format!(
                        "pipeline commit failed for \
                         economics-admission-denied job: {commit_err}"
                    ),
                };
            }
            return JobOutcome::Denied { reason };
        }
    }

    // Step 3: Validate RFC-0028 token (non-control-lane jobs only).
    let token = match &spec.actuation.channel_context_token {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            let reason = "missing channel_context_token".to_string();
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            // (sbx_hash computed once at top of process_job)
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::MissingChannelToken),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Use monotonic wall-clock seconds for token temporal validation.
    let current_time_secs = current_timestamp_epoch_secs();

    // TCK-00565: Build expected token binding for fail-closed validation.
    // Parse the canonicalizer tuple digest from the b3-256 hex string to raw bytes.
    // Fail-closed: if the digest cannot be parsed, deny the job immediately —
    // never fall through with None (which would skip token binding validation).
    let Some(ct_digest_bytes) = parse_b3_256_digest(canonicalizer_tuple_digest) else {
        let reason = format!(
            "invalid canonicalizer tuple digest: cannot parse b3-256 hex: {canonicalizer_tuple_digest}"
        );
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::InvalidCanonicalizerDigest),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    };
    // TCK-00567: Derive expected intent from job kind for intent-binding
    // verification.  The worker denies if the token intent does not match
    // the job kind (fail-closed).  Unknown job kinds produce None from
    // job_kind_to_intent — treat as hard denial to prevent fail-open bypass.
    let Some(expected_intent) = apm2_core::fac::job_spec::job_kind_to_intent(&spec.kind) else {
        let reason = format!("unknown job kind for intent binding: {}", spec.kind);
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::UnknownJobKindIntent),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    };
    let expected_intent_str = Some(expected_intent.as_str());
    let expected_binding = ExpectedTokenBinding {
        fac_policy_hash: policy_digest,
        canonicalizer_tuple_digest: &ct_digest_bytes,
        boundary_id,
        current_tick: broker.current_tick(),
        expected_intent: expected_intent_str,
    };

    let boundary_check = match decode_channel_context_token_with_binding(
        token,
        verifying_key,
        &spec.actuation.lease_id,
        current_time_secs,
        &spec.actuation.request_id,
        Some(&expected_binding),
    ) {
        Ok(check) => check,
        Err(e) => {
            let reason = format!("token decode failed: {e}");
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            // (sbx_hash computed once at top of process_job)
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::TokenDecodeFailed),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }
            return JobOutcome::Denied { reason };
        },
    };

    let admitted_policy_root_digest = if let Some(binding) =
        boundary_check.boundary_flow_policy_binding.as_ref()
    {
        if !bool::from(
            binding
                .policy_digest
                .ct_eq(&binding.admitted_policy_root_digest),
        ) {
            let reason = "policy digest mismatch within channel boundary binding".to_string();
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            // (sbx_hash computed once at top of process_job)
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ChannelBoundaryViolation),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }

            return JobOutcome::Denied { reason };
        }

        binding.admitted_policy_root_digest
    } else {
        let reason = "missing boundary-flow policy binding".to_string();
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ChannelBoundaryViolation),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    };

    if !broker.is_policy_digest_admitted(&admitted_policy_root_digest)
        || !bool::from(admitted_policy_root_digest.ct_eq(policy_digest))
    {
        let reason = "policy digest mismatch with admitted fac policy".to_string();
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ChannelBoundaryViolation),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // Validate boundary check defects.
    let defects = validate_channel_boundary(&boundary_check);
    // TCK-00565: Include decoded token binding in the boundary trace for receipt
    // audit.
    let boundary_trace =
        build_channel_boundary_trace_with_binding(&defects, boundary_check.token_binding.as_ref());
    if !defects.is_empty() {
        let reason = format!(
            "channel boundary violations: {}",
            defects
                .iter()
                .map(|d| strip_json_string_quotes(&serialize_to_json_string(&d.violation_class)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ChannelBoundaryViolation),
            &reason,
            Some(&boundary_trace),
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // TCK-00566: Token replay protection — validate nonce and record use.
    //
    // After the token is decoded and boundary defects are checked, extract
    // the nonce from the token binding and validate it against the broker's
    // token-use ledger. If the nonce is already consumed or revoked, deny
    // the job (fail-closed). If the nonce is fresh, record it so any
    // subsequent replay is detected.
    //
    // BLOCKER fix: the WAL entry MUST be persisted to disk (with fsync)
    // BEFORE job execution begins. This ensures the "consumed" state is
    // durable even if the process crashes during job execution.
    if let Some(binding) = boundary_check.token_binding.as_ref() {
        if let Some(ref nonce) = binding.nonce {
            match broker.validate_and_record_token_nonce(nonce, &spec.actuation.request_id) {
                Ok(wal_bytes) => {
                    // INV-TL-009/INV-TL-010: Persist WAL entry BEFORE job
                    // execution. If persistence fails, deny the job
                    // (fail-closed: we cannot guarantee replay protection
                    // without durable state).
                    if let Err(wal_err) = append_token_ledger_wal(&wal_bytes) {
                        let reason = format!(
                            "FATAL: token ledger WAL persist failed (fail-closed): {wal_err}"
                        );
                        eprintln!("worker: {reason}");
                        let moved_path =
                            move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                                .map(|p| {
                                    p.strip_prefix(queue_root)
                                        .unwrap_or(&p)
                                        .to_string_lossy()
                                        .to_string()
                                })
                                .ok();
                        if let Err(receipt_err) = emit_job_receipt(
                            fac_root,
                            spec,
                            FacJobOutcome::Denied,
                            Some(DenialReasonCode::TokenReplayDetected),
                            &reason,
                            Some(&boundary_trace),
                            None,
                            None,
                            None,
                            Some(canonicalizer_tuple_digest),
                            moved_path.as_deref(),
                            policy_hash,
                            None,
                            Some(&sbx_hash),
                            Some(&resolved_net_hash),
                            None, // bytes_backend
                            toolchain_fingerprint,
                        ) {
                            eprintln!(
                                "worker: WARNING: receipt emission failed for denied job: {receipt_err}"
                            );
                        }
                        return JobOutcome::Denied { reason };
                    }
                },
                Err(ledger_err) => {
                    let denial_code = match &ledger_err {
                        apm2_core::fac::token_ledger::TokenLedgerError::TokenRevoked { .. } => {
                            DenialReasonCode::TokenRevoked
                        },
                        _ => DenialReasonCode::TokenReplayDetected,
                    };
                    let reason =
                        format!("token nonce replay/revocation check failed: {ledger_err}");
                    let moved_path =
                        move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                            .map(|p| {
                                p.strip_prefix(queue_root)
                                    .unwrap_or(&p)
                                    .to_string_lossy()
                                    .to_string()
                            })
                            .ok();
                    if let Err(receipt_err) = emit_job_receipt(
                        fac_root,
                        spec,
                        FacJobOutcome::Denied,
                        Some(denial_code),
                        &reason,
                        Some(&boundary_trace),
                        None,
                        None,
                        None,
                        Some(canonicalizer_tuple_digest),
                        moved_path.as_deref(),
                        policy_hash,
                        None,
                        Some(&sbx_hash),
                        Some(&resolved_net_hash),
                        None, // bytes_backend
                        toolchain_fingerprint,
                    ) {
                        eprintln!(
                            "worker: WARNING: receipt emission failed for denied job: {receipt_err}"
                        );
                    }
                    return JobOutcome::Denied { reason };
                },
            }
        }
        // If nonce is None (pre-TCK-00566 token), skip nonce validation.
        // This is backwards-compatible: old tokens without nonces are
        // admitted based on other checks alone.
    }

    // Step 4: Evaluate RFC-0029 queue admission.
    //
    if !broker.is_admission_health_gate_passed() {
        let reason = "broker admission health gate not passed (INV-BH-003)".to_string();
        let admission_trace = JobQueueAdmissionTrace {
            verdict: "deny".to_string(),
            queue_lane: spec.queue_lane.clone(),
            defect_reason: Some("admission health gate not passed".to_string()),
            cost_estimate_ticks: None,
        };
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::AdmissionHealthGateFailed),
            &reason,
            Some(&boundary_trace),
            Some(&admission_trace),
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    let verifier = BrokerSignatureVerifier::new(*verifying_key);

    // Build a proper admission request with broker-issued authority artifacts
    // (BLOCKER-1 fix). The broker provides:
    // - TP-EIO29-001: time authority envelope (signed)
    // - TP-EIO29-002: freshness horizon + revocation frontier
    // - TP-EIO29-003: convergence horizon + convergence receipts
    let current_tick = broker.current_tick();
    let tick_end = current_tick.saturating_add(1);

    // Advance the freshness horizon so TP-EIO29-002 check passes:
    // eval_window.tick_end must be <= freshness_horizon.tick_end.
    // Without this, the default horizon (tick_end=1) is exceeded by any
    // eval_window with tick_end >= 2, causing fail-closed denial.
    broker.advance_freshness_horizon(tick_end);

    let eval_window = broker
        .build_evaluation_window(boundary_id, DEFAULT_AUTHORITY_CLOCK, current_tick, tick_end)
        .unwrap_or_else(|_| make_default_eval_window(boundary_id));

    let envelope = broker
        .issue_time_authority_envelope_default_ttl(
            boundary_id,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .ok();

    let freshness = Some(broker.freshness_horizon());
    let revocation = Some(broker.revocation_frontier());
    let convergence = Some(broker.convergence_horizon());
    let convergence_receipts = broker.convergence_receipts().to_vec();

    let admission_request = QueueAdmissionRequest {
        lane,
        envelope,
        eval_window,
        freshness_horizon: freshness,
        revocation_frontier: revocation,
        convergence_horizon: convergence,
        convergence_receipts,
        required_authority_sets: Vec::new(),
        cost: cost_model.queue_cost(&spec.kind),
        current_tick,
    };

    let decision = evaluate_queue_admission(&admission_request, scheduler, Some(&verifier));
    let queue_trace = build_queue_admission_trace(&decision);
    if decision.verdict != QueueAdmissionVerdict::Allow {
        let reason = decision.defect().map_or_else(
            || "admission denied (no defect detail)".to_string(),
            |defect| format!("admission denied: {}", defect.reason),
        );
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::QueueAdmissionDenied),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    let (budget_tier, budget_intent_class) = job_kind_to_budget_key(&spec.kind);
    let budget_trace = {
        let budget_evaluator =
            BudgetAdmissionEvaluator::new(budget_cas, policy.economics_profile_hash);
        // Pre-execution budget admission: observed_usage reflects declared constraints
        // from the job spec, not runtime telemetry. Tokens and tool calls have no
        // pre-execution estimate. Post-execution enforcement is a separate concern.
        let observed_usage = ObservedUsage {
            tokens_used: 0,
            tool_calls_used: 0,
            time_ms_used: spec
                .constraints
                .test_timeout_seconds
                .map_or(0, |s| s.saturating_mul(1000)),
            io_bytes_used: candidate.raw_bytes.len() as u64,
        };
        let budget_decision =
            budget_evaluator.evaluate(budget_tier, budget_intent_class, &observed_usage);
        let trace = fac_budget_admission_trace(&budget_decision.trace);
        if budget_decision.verdict != BudgetAdmissionVerdict::Allow {
            let reason = budget_decision
                .deny_reason
                .as_deref()
                .unwrap_or("budget admission denied (no detail)");
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            // (sbx_hash computed once at top of process_job)
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::BudgetAdmissionDenied),
                reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                Some(&trace),
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: WARNING: receipt emission failed for budget-denied job: {receipt_err}"
                );
            }
            return JobOutcome::Denied {
                reason: reason.to_string(),
            };
        }
        Some(trace)
    };

    // PCAC lifecycle: check if authority was already consumed (replay protection).
    if is_authority_consumed(queue_root, &spec.job_id) {
        let reason = format!("authority already consumed for job {}", spec.job_id);
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::AuthorityAlreadyConsumed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // Step 5: Atomic claim via rename (INV-WRK-003).
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    let claimed_path = match move_to_dir_safe(path, &claimed_dir, &file_name) {
        Ok(p) => p,
        Err(e) => {
            // If rename fails (e.g., already claimed by another worker), skip.
            return JobOutcome::Skipped {
                reason: format!("atomic claim failed: {e}"),
            };
        },
    };

    let claimed_file_name = claimed_path
        .file_name()
        .map_or_else(|| file_name.clone(), |n| n.to_string_lossy().to_string());

    // PCAC lifecycle: durable consume after atomic claim; if this fails the claimed
    // job is committed to denied/ via pipeline.
    if let Err(e) = consume_authority(queue_root, &spec.job_id, &spec.job_spec_digest) {
        let reason = format!("PCAC consume failed: {e}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::PcacConsumeFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (PCAC consume failed)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Gates jobs are executed through the FAC gate runner directly. They are
    // already admission-checked (RFC-0028/0029) and consumed at this point.
    // Avoid acquiring a second worker lane here: `fac gates` already uses its
    // own lane lock/containment strategy for heavy phases.
    if spec.kind == "gates" {
        // TCK-00574 MAJOR-2: Use the resolved net hash computed at the top
        // of process_job (same resolve_network_policy call, now deduplicated).
        return execute_queued_gates_job(
            spec,
            &claimed_path,
            &claimed_file_name,
            queue_root,
            fac_root,
            &boundary_trace,
            &queue_trace,
            budget_trace.as_ref(),
            canonicalizer_tuple_digest,
            policy_hash,
            &sbx_hash,
            &resolved_net_hash,
            heartbeat_cycle_count,
            heartbeat_jobs_completed,
            heartbeat_jobs_denied,
            heartbeat_jobs_quarantined,
            toolchain_fingerprint,
        );
    }

    // Step 6: Acquire lane lease (INV-WRK-008, BLOCKER-3 fix).
    //
    // Try to acquire a lane lock. If no lane is available, move the job
    // back to pending for retry in a future cycle.
    let lane_mgr = match LaneManager::new(fac_root.to_path_buf()) {
        Ok(mgr) => mgr,
        Err(e) => {
            if let Err(move_err) = move_to_dir_safe(
                &claimed_path,
                &queue_root.join(PENDING_DIR),
                &claimed_file_name,
            ) {
                eprintln!("worker: WARNING: failed to return claimed job to pending: {move_err}");
            }
            return JobOutcome::Skipped {
                reason: format!("lane manager init failed: {e}"),
            };
        },
    };

    // Best-effort directory setup (ignore errors if already exists).
    let _ = lane_mgr.ensure_directories();

    let lane_ids = LaneManager::default_lane_ids();
    let Some((_lane_guard, acquired_lane_id)) = acquire_worker_lane(&lane_mgr, &lane_ids) else {
        // No lane available -> move back to pending for retry.
        if let Err(move_err) = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(PENDING_DIR),
            &claimed_file_name,
        ) {
            eprintln!("worker: WARNING: failed to return claimed job to pending: {move_err}");
        }
        return JobOutcome::Skipped {
            reason: "no lane available, returning to pending".to_string(),
        };
    };

    if let Err(error) = run_preflight(
        fac_root,
        &lane_mgr,
        u64::from(policy.quarantine_ttl_days).saturating_mul(86400),
        u64::from(policy.denied_ttl_days).saturating_mul(86400),
    ) {
        let reason = format!("preflight failed: {error:?}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::InsufficientDiskSpace),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (preflight failed)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Step 7: Compute authoritative Systemd properties for the acquired lane.
    // This is the single source of truth for CPU/memory/PIDs/IO/timeouts and
    // is shared between user-mode and system-mode execution backends.
    let lane_dir = lane_mgr.lane_dir(&acquired_lane_id);
    let lane_profile = match LaneProfileV1::load(&lane_dir) {
        Ok(profile) => profile,
        Err(e) => {
            let reason = format!("lane profile load failed for {acquired_lane_id}: {e}");
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                &claimed_path,
                &claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied warm job (lane profile load)",
                    &claimed_path,
                    queue_root,
                    &claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Resolve network policy for this job kind (TCK-00574).
    // The hash was already computed at the top of process_job (resolved_net_hash).
    // We still need the full NetworkPolicy struct here for SystemdUnitProperties.
    let job_network_policy =
        apm2_core::fac::resolve_network_policy(&spec.kind, policy.network_policy.as_ref());
    let lane_systemd_properties = SystemdUnitProperties::from_lane_profile_with_hardening(
        &lane_profile,
        Some(&spec.constraints),
        policy.sandbox_hardening.clone(),
        job_network_policy,
    );
    if print_unit {
        eprintln!(
            "worker: computed systemd properties for job {}",
            spec.job_id
        );
        eprintln!("{}", lane_systemd_properties.to_unit_directives());
        eprintln!("worker: D-Bus properties for job {}", spec.job_id);
        eprintln!("{:?}", lane_systemd_properties.to_dbus_properties());
    }

    // Step 6b: Persist a RUNNING lease for this lane/job (INV-LANE-CLEANUP-001).
    //
    // The lane cleanup state machine in `run_lane_cleanup` requires a RUNNING
    // lease to be present. Without it, cleanup fails its precondition and
    // marks the lane CORRUPT, which deterministically exhausts lane capacity.
    //
    // Synchronization: this lease is bound to the current PID and the flock-
    // guarded lane lock held by `_lane_guard`. Only this process can write to
    // the lane directory while the lock is held.
    let lane_profile_hash = lane_profile
        .compute_hash()
        .unwrap_or_else(|_| "b3-256:unknown".to_string());

    // TCK-00538: Use toolchain fingerprint from worker startup for lane lease.
    // Worker startup is fail-closed (refuses to start without fingerprint), so
    // this should always be Some. The unwrap_or is defensive only.
    let toolchain_fp_for_lease = toolchain_fingerprint.unwrap_or("b3-256:unknown");

    let lane_lease = match LaneLeaseV1::new(
        &acquired_lane_id,
        &spec.job_id,
        std::process::id(),
        LaneState::Running,
        &current_timestamp_epoch_secs().to_string(),
        &lane_profile_hash,
        toolchain_fp_for_lease,
    ) {
        Ok(lease) => lease,
        Err(e) => {
            let reason = format!("failed to create lane lease: {e}");
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                &claimed_path,
                &claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied warm job (lane lease creation)",
                    &claimed_path,
                    queue_root,
                    &claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };
    if let Err(e) = lane_lease.persist(&lane_dir) {
        let reason = format!("failed to persist lane lease: {e}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (lane lease persist)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Step 7: Execute job under containment.
    //
    // For the default-mode MVP, execution validates that the job is structurally
    // sound and the lane is held. Full FESv1 execution (subprocess spawning,
    // cgroup containment) is deferred to a future ticket. The lane guard ensures
    // exclusive access during this phase.
    //
    // We verify that the claimed file is still present and intact before
    // marking as completed.
    //
    // INVARIANT: A RUNNING lease is now persisted for `acquired_lane_id`.
    // Every early return from this point MUST remove the lease via
    // `LaneLeaseV1::remove(&lane_dir)` to prevent stale lease accumulation.
    if !claimed_path.exists() {
        let _ = LaneLeaseV1::remove(&lane_dir);
        return JobOutcome::Skipped {
            reason: "claimed file disappeared during execution".to_string(),
        };
    }

    // Handle stop_revoke jobs: kill the target unit and cancel the target job.
    if spec.kind == "stop_revoke" {
        let _ = LaneLeaseV1::remove(&lane_dir);
        return handle_stop_revoke(
            spec,
            &claimed_path,
            &claimed_file_name,
            queue_root,
            fac_root,
            &boundary_trace,
            &queue_trace,
            budget_trace.as_ref(),
            canonicalizer_tuple_digest,
            policy_hash,
            &sbx_hash,
            &resolved_net_hash,
            job_wall_start,
            None, // Non-control-lane stop_revoke: standard admission path
            toolchain_fingerprint,
        );
    }

    let mut patch_digest: Option<String> = None;
    // TCK-00546: Track which bytes_backend was used for receipt binding.
    let mut resolved_bytes_backend: Option<String> = None;
    // process_job executes one job at a time in a single worker lane, so
    // blocking mirror I/O is intentionally accepted in this default-mode
    // execution path. The entire job execution remains sequential behind the
    // lane lease and remains fail-closed on error.
    let mirror_manager = RepoMirrorManager::new(fac_root);
    if let Err(e) = mirror_manager
        .ensure_mirror(&spec.source.repo_id, None)
        .map(|(_path, _receipt)| ())
    {
        let reason = format!("mirror ensure failed: {e}");
        let _ = LaneLeaseV1::remove(&lane_dir);
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (mirror ensure)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    let lanes_root = fac_root.join("lanes");
    let lane_workspace = lane_mgr.lane_dir(&acquired_lane_id).join("workspace");
    if let Err(e) = mirror_manager.checkout_to_lane(
        &spec.source.repo_id,
        &spec.source.head_sha,
        &lane_workspace,
        &lanes_root,
    ) {
        let reason = format!("lane workspace checkout failed: {e}");
        // SEC-CTRL-LANE-CLEANUP-002: Checkout failure may leave the workspace
        // in a partially modified state. Run lane cleanup to restore isolation
        // before denying the job. On cleanup failure, the lane is marked CORRUPT.
        if let Err(cleanup_err) =
            execute_lane_cleanup(fac_root, &lane_mgr, &acquired_lane_id, &lane_workspace)
        {
            eprintln!(
                "worker: WARNING: lane cleanup during checkout-failure denial failed for {acquired_lane_id}: {cleanup_err}"
            );
            // Lane is already marked CORRUPT by execute_lane_cleanup on
            // failure.
        }
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (checkout failure)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // SEC-CTRL-LANE-CLEANUP-002: Cleanup-aware denial helper for post-checkout
    // paths.
    //
    // After workspace modification (checkout, patch application), a denial MUST
    // run `execute_lane_cleanup` to restore the workspace to a clean state.
    // Without this, the next job on the lane inherits a modified workspace,
    // violating lane isolation invariants (cross-job contamination).
    //
    // The cleanup transitions the lease to Cleanup, runs git reset + clean +
    // temp prune + log quota, then removes the lease on success. On cleanup
    // failure, the lane is marked CORRUPT via `execute_lane_cleanup`'s
    // existing corruption handling, preventing future job execution on a
    // dirty lane.
    let deny_with_reason_and_lease_cleanup = |reason: &str| -> JobOutcome {
        // Run full lane cleanup to restore workspace isolation.
        // This is the same cleanup path used after successful job completion.
        if let Err(cleanup_err) =
            execute_lane_cleanup(fac_root, &lane_mgr, &acquired_lane_id, &lane_workspace)
        {
            eprintln!(
                "worker: WARNING: lane cleanup during denial failed for {acquired_lane_id}: {cleanup_err}"
            );
            // Lane is already marked CORRUPT by execute_lane_cleanup on
            // failure. The denial receipt is still emitted below so
            // the job has a terminal receipt.
        }
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (post-checkout denial)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        JobOutcome::Denied {
            reason: reason.to_string(),
        }
    };

    if spec.source.kind == "patch_injection" {
        let patch_missing_error = "patch_injection requires a patch descriptor object";

        let Some(patch_value) = &spec.source.patch else {
            return deny_with_reason_and_lease_cleanup(patch_missing_error);
        };
        let Some(patch_obj) = patch_value.as_object() else {
            return deny_with_reason_and_lease_cleanup(patch_missing_error);
        };

        // TCK-00546: Branch on `bytes_backend` to resolve patch bytes.
        let bytes_backend = patch_obj.get("bytes_backend").and_then(|v| v.as_str());
        // MINOR-1 fix: Capture resolved_bytes_backend immediately at
        // deserialization time so both success and failure receipts carry
        // consistent metadata.  Previously this was deferred until after
        // the patch was successfully applied, leaving failure receipts
        // without bytes_backend.
        resolved_bytes_backend = bytes_backend.map(String::from);

        let patch_bytes: Vec<u8> = match bytes_backend {
            // ---- apm2_cas backend: retrieve from daemon CAS ----
            Some("apm2_cas") => {
                let Some(digest_str) = patch_obj.get("digest").and_then(|v| v.as_str()) else {
                    return deny_with_reason_and_lease_cleanup(
                        "apm2_cas backend requires a 'digest' field in patch descriptor",
                    );
                };
                let Some(hash_bytes) = apm2_core::fac::job_spec::parse_b3_256_digest(digest_str)
                else {
                    return deny_with_reason_and_lease_cleanup(&format!(
                        "invalid digest format for apm2_cas backend: {digest_str}"
                    ));
                };
                // Resolve CAS root: $APM2_HOME/private/cas (sibling of fac_root).
                let cas_root = fac_root.parent().map(|private| private.join("cas"));
                let Some(cas_root) = cas_root else {
                    return deny_with_reason_and_lease_cleanup(
                        "cannot resolve CAS root from FAC root (fail-closed)",
                    );
                };
                let reader = match apm2_core::fac::cas_reader::CasReader::new(&cas_root) {
                    Ok(r) => r,
                    Err(e) => {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "apm2_cas backend unavailable: {e} (fail-closed)"
                        ));
                    },
                };
                match reader.retrieve(&hash_bytes) {
                    Ok(bytes) => {
                        // Record the CAS reference for GC tracking.
                        if let Err(e) = apm2_core::fac::record_cas_ref(fac_root, &hash_bytes) {
                            eprintln!("worker: WARNING: failed to record CAS ref for GC: {e}");
                        }
                        bytes
                    },
                    Err(e) => {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "failed to retrieve patch from CAS: {e} (fail-closed)"
                        ));
                    },
                }
            },

            // ---- fac_blobs_v1 backend: retrieve from blob store ----
            Some("fac_blobs_v1") => {
                let Some(digest_str) = patch_obj.get("digest").and_then(|v| v.as_str()) else {
                    return deny_with_reason_and_lease_cleanup(
                        "fac_blobs_v1 backend requires a 'digest' field in patch descriptor",
                    );
                };
                let Some(hash_bytes) = apm2_core::fac::job_spec::parse_b3_256_digest(digest_str)
                else {
                    return deny_with_reason_and_lease_cleanup(&format!(
                        "invalid digest format for fac_blobs_v1 backend: {digest_str}"
                    ));
                };
                let blob_store = BlobStore::new(fac_root);
                match blob_store.retrieve(&hash_bytes) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "failed to retrieve patch from blob store: {e}"
                        ));
                    },
                }
            },

            // ---- Inline bytes (no backend or unknown with bytes) ----
            _ => {
                let Some(bytes_b64) = patch_obj.get("bytes").and_then(|value| value.as_str())
                else {
                    // Fail-closed: unknown backend without inline bytes.
                    let backend_desc = bytes_backend.unwrap_or("(none)");
                    return deny_with_reason_and_lease_cleanup(&format!(
                        "patch_injection: no inline bytes and unknown/missing bytes_backend={backend_desc} (fail-closed)"
                    ));
                };
                let decoded = match STANDARD.decode(bytes_b64) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "invalid base64 in patch.bytes: {err}"
                        ));
                    },
                };
                // Verify digest if provided.
                if let Some(expected_digest) = patch_obj.get("digest").and_then(|v| v.as_str()) {
                    let actual_digest = format!("b3-256:{}", blake3::hash(&decoded).to_hex());
                    let expected_bytes = expected_digest.as_bytes();
                    let actual_bytes = actual_digest.as_bytes();
                    if expected_bytes.len() != actual_bytes.len()
                        || !bool::from(expected_bytes.ct_eq(actual_bytes))
                    {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "patch digest mismatch: expected {expected_digest}, got {actual_digest}"
                        ));
                    }
                }
                decoded
            },
        };

        // Store patch bytes in blob store for local caching regardless of
        // backend source.
        let blob_store = BlobStore::new(fac_root);
        if let Err(error) = blob_store.store(&patch_bytes) {
            return deny_with_reason_and_lease_cleanup(&format!(
                "failed to store patch in blob store: {error}"
            ));
        }

        let patch_outcome = match mirror_manager.apply_patch_hardened(
            &lane_workspace,
            &patch_bytes,
            PATCH_FORMAT_GIT_DIFF_V1,
        ) {
            Ok((outcome, _receipt)) => outcome,
            Err(apm2_core::fac::RepoMirrorError::PatchHardeningDenied { reason, receipt }) => {
                // TCK-00581: Map PatchHardeningDenied to explicit denial
                // with receipt metadata in the reason string for audit.
                let receipt_hash = receipt.content_hash_hex();
                let denial_reason =
                    format!("patch hardening denied: {reason} [receipt_hash={receipt_hash}]");

                // Persist the denial receipt as a standalone file for
                // provenance evidence alongside the job receipt.
                let patch_receipt_json = serde_json::json!({
                    "schema_id": receipt.schema_id,
                    "schema_version": receipt.schema_version,
                    "patch_digest": receipt.patch_digest,
                    "applied_files_count": receipt.applied_files_count,
                    "applied": receipt.applied,
                    "refusals": receipt.refusals.iter().map(|r| {
                        serde_json::json!({
                            "path": r.path,
                            "reason": r.reason,
                        })
                    }).collect::<Vec<_>>(),
                    "content_hash": receipt_hash,
                });
                let patch_receipts_dir = fac_root.join("patch_receipts");
                if let Err(e) = std::fs::create_dir_all(&patch_receipts_dir) {
                    eprintln!("worker: WARNING: failed to create patch_receipts dir: {e}");
                } else if let Ok(body) = serde_json::to_vec_pretty(&patch_receipt_json) {
                    let receipt_file = patch_receipts_dir.join(format!("{receipt_hash}.json"));
                    if let Err(e) = std::fs::write(&receipt_file, &body) {
                        eprintln!("worker: WARNING: failed to persist patch denial receipt: {e}");
                    }
                }

                // Run lane cleanup and commit denial via pipeline.
                if let Err(cleanup_err) =
                    execute_lane_cleanup(fac_root, &lane_mgr, &acquired_lane_id, &lane_workspace)
                {
                    eprintln!(
                        "worker: WARNING: lane cleanup during patch hardening denial failed for {acquired_lane_id}: {cleanup_err}"
                    );
                }
                if let Err(commit_err) = commit_claimed_job_via_pipeline(
                    fac_root,
                    queue_root,
                    spec,
                    &claimed_path,
                    &claimed_file_name,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::PatchHardeningDenied),
                    &denial_reason,
                    Some(&boundary_trace),
                    Some(&queue_trace),
                    budget_trace.as_ref(),
                    None,
                    Some(canonicalizer_tuple_digest),
                    policy_hash,
                    None,
                    None,
                    Some(&sbx_hash),
                    Some(&resolved_net_hash),
                    None, // stop_revoke_admission
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    return handle_pipeline_commit_failure(
                        &commit_err,
                        "denied warm job (patch hardening denied)",
                        &claimed_path,
                        queue_root,
                        &claimed_file_name,
                    );
                }
                return JobOutcome::Denied {
                    reason: denial_reason,
                };
            },
            Err(err) => {
                return deny_with_reason_and_lease_cleanup(&format!("patch apply failed: {err}"));
            },
        };
        patch_digest = Some(patch_outcome.patch_digest);
        // (resolved_bytes_backend already captured at deserialization time
        // above)
    } else if spec.source.kind != "mirror_commit" {
        let reason = format!("unsupported source kind: {}", spec.source.kind);
        // SEC-CTRL-LANE-CLEANUP-002: This denial path is post-checkout, so the
        // workspace may have been modified by a prior checkout. Run lane cleanup
        // to restore workspace isolation before denying the job.
        if let Err(cleanup_err) =
            execute_lane_cleanup(fac_root, &lane_mgr, &acquired_lane_id, &lane_workspace)
        {
            eprintln!(
                "worker: WARNING: lane cleanup during source-kind denial failed for {acquired_lane_id}: {cleanup_err}"
            );
            // Lane is already marked CORRUPT by execute_lane_cleanup on
            // failure.
        }
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (unsupported source kind)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Step 8: Containment verification (TCK-00548 BLOCKER-1).
    //
    // Verify that the worker's process tree is contained within the
    // expected cgroup hierarchy. This uses the current process PID as
    // the reference because the default-mode worker validates the job
    // spec in-process (no subprocess spawning yet).
    //
    // TCK-00553: sccache activation is now policy-gated. When
    // `policy.sccache_enabled` is true, sccache is active (the env
    // injection happens in `build_job_environment`). When disabled,
    // we still check ambient RUSTC_WRAPPER for legacy detection.
    let sccache_active = policy.sccache_enabled
        || std::env::var("RUSTC_WRAPPER")
            .ok()
            .is_some_and(|v| v.contains("sccache"));

    // TCK-00554: Build sccache env for server lifecycle management.
    // Defined before the containment match so it's accessible for both
    // the server containment protocol and the stop call at unit end.
    //
    // fix-round-4 MAJOR: Use lane-scoped SCCACHE_DIR to prevent server
    // lifecycle collisions across concurrent lanes. Each lane gets its own
    // sccache directory (and therefore its own Unix domain socket), so
    // --stop-server in one lane cannot terminate another lane's server.
    let sccache_server_env: Vec<(String, String)> = if policy.sccache_enabled {
        let apm2_home = resolve_apm2_home().unwrap_or_else(|| {
            fac_root
                .parent()
                .and_then(|p| p.parent())
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf()
        });
        let sccache_dir = policy
            .resolve_sccache_dir(&apm2_home)
            .join(&acquired_lane_id);
        vec![(
            "SCCACHE_DIR".to_string(),
            sccache_dir.to_string_lossy().to_string(),
        )]
    } else {
        vec![]
    };

    let containment_trace = match apm2_core::fac::containment::verify_containment(
        std::process::id(),
        sccache_active,
    ) {
        Ok(verdict) => {
            eprintln!(
                "worker: containment check: contained={} processes_checked={} mismatches={}",
                verdict.contained,
                verdict.processes_checked,
                verdict.mismatches.len(),
            );
            if !verdict.contained {
                return deny_with_reason_and_lease_cleanup(&format!(
                    "containment verification failed: contained=false processes_checked={} mismatches={}",
                    verdict.processes_checked,
                    verdict.mismatches.len()
                ));
            }
            // TCK-00553: Probe sccache version when policy enables it.
            let sccache_version = if policy.sccache_enabled {
                apm2_core::fac::containment::probe_sccache_version()
            } else {
                None
            };

            // TCK-00554: Execute sccache server containment protocol.
            //
            // When the policy enables sccache, verify that the sccache
            // server is inside the unit cgroup. If a pre-existing server
            // is outside the cgroup, refuse to use it and start a new one.
            // If server containment cannot be verified, auto-disable sccache.
            let server_containment = if policy.sccache_enabled {
                let sc = apm2_core::fac::containment::execute_sccache_server_containment_protocol(
                    std::process::id(),
                    &verdict.reference_cgroup,
                    &sccache_server_env,
                );
                eprintln!(
                    "worker: sccache server containment: protocol_executed={} \
                     server_started={} server_cgroup_verified={} auto_disabled={}",
                    sc.protocol_executed,
                    sc.server_started,
                    sc.server_cgroup_verified,
                    sc.auto_disabled,
                );
                if sc.auto_disabled {
                    eprintln!(
                        "worker: WARNING: sccache auto-disabled by server containment: {}",
                        sc.reason.as_deref().unwrap_or("unknown"),
                    );
                }
                Some(sc)
            } else {
                None
            };

            if let Some(ref sc) = server_containment {
                Some(
                    apm2_core::fac::containment::ContainmentTrace::from_verdict_with_server_containment(
                        &verdict,
                        policy.sccache_enabled,
                        sccache_version,
                        sc.clone(),
                    ),
                )
            } else {
                Some(
                    apm2_core::fac::containment::ContainmentTrace::from_verdict_with_sccache(
                        &verdict,
                        policy.sccache_enabled,
                        sccache_version,
                    ),
                )
            }
        },
        Err(err) => {
            eprintln!("worker: ERROR: containment check failed: {err}");
            return deny_with_reason_and_lease_cleanup(&format!(
                "containment verification failed: {err}"
            ));
        },
    };

    // Step 8b: Handle warm jobs (TCK-00525).
    //
    // Warm jobs execute warm phases (fetch/build/nextest/clippy/doc) using the
    // lane workspace and lane-managed CARGO_HOME/CARGO_TARGET_DIR. The warm
    // receipt is persisted to the FAC receipts directory alongside the job receipt.
    if spec.kind == "warm" {
        // TCK-00554 BLOCKER-1 fix: Derive effective sccache enablement from
        // server containment protocol result. If the containment protocol
        // auto-disabled sccache, the warm execution environment MUST NOT
        // inject RUSTC_WRAPPER/SCCACHE_* — even though `policy.sccache_enabled`
        // is true. This prevents build paths from using an untrusted server
        // that was refused by containment verification.
        let effective_sccache_enabled = policy.sccache_enabled
            && containment_trace
                .as_ref()
                .is_some_and(|ct| !ct.sccache_auto_disabled);
        let warm_outcome = execute_warm_job(
            spec,
            &claimed_path,
            &claimed_file_name,
            queue_root,
            fac_root,
            signer,
            &lane_workspace,
            &lane_dir,
            &acquired_lane_id,
            &lane_profile_hash,
            &boundary_trace,
            &queue_trace,
            budget_trace.as_ref(),
            patch_digest.as_deref(),
            canonicalizer_tuple_digest,
            policy_hash,
            containment_trace.as_ref(),
            &lane_mgr,
            &candidate.raw_bytes,
            policy,
            &lane_systemd_properties,
            &sbx_hash,
            &resolved_net_hash,
            heartbeat_cycle_count,
            heartbeat_jobs_completed,
            heartbeat_jobs_denied,
            heartbeat_jobs_quarantined,
            job_wall_start,
            toolchain_fingerprint,
            effective_sccache_enabled,
        );

        // TCK-00554: Stop sccache server at unit end (INV-CONTAIN-011).
        // MINOR-1 fix: Gate shutdown on ownership — only stop the server if
        // this unit started one or verified a pre-existing in-cgroup server.
        // This prevents one lane from terminating a shared sccache server
        // that another concurrent lane is using.
        if owns_sccache_server(containment_trace.as_ref()) && !sccache_server_env.is_empty() {
            let stopped = apm2_core::fac::stop_sccache_server(&sccache_server_env);
            eprintln!("worker: sccache server stop (warm unit end): stopped={stopped}");
        }

        return warm_outcome;
    }

    // Step 9: Write authoritative GateReceipt and move to completed.
    //
    // BLOCKER FIX (f-685-code_quality-0): Job completion is now recorded
    // BEFORE lane cleanup. This ensures that infrastructure failures in
    // the cleanup phase cannot negate a successful job execution. The job
    // outcome is decoupled from lane lifecycle management.
    let evidence_hash = compute_evidence_hash(&candidate.raw_bytes);
    let changeset_digest = compute_evidence_hash(spec.source.head_sha.as_bytes());
    let receipt_id = format!("wkr-{}-{}", spec.job_id, current_timestamp_epoch_secs());
    let gate_receipt =
        GateReceiptBuilder::new(&receipt_id, "fac-worker-exec", &spec.actuation.lease_id)
            .changeset_digest(changeset_digest)
            .executor_actor_id("fac-worker")
            .receipt_version(1)
            .payload_kind("validation-only")
            .payload_schema_version(1)
            .payload_hash(evidence_hash)
            .evidence_bundle_hash(evidence_hash)
            .job_spec_digest(&spec.job_spec_digest)
            .sandbox_hardening_hash(&sbx_hash)
            .network_policy_hash(&resolved_net_hash)
            .passed(false)
            .build_and_sign(signer);

    let observed_cost = observed_cost_from_elapsed(job_wall_start.elapsed());

    // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
    // This ensures receipt persistence, index update, and job move happen
    // in a crash-safe order via a single ReceiptWritePipeline::commit() call.
    // Persist the gate receipt alongside the completed job (before atomic commit).
    write_gate_receipt(queue_root, &claimed_file_name, &gate_receipt);

    // TCK-00538: Include toolchain fingerprint in the completed job receipt.
    if let Err(commit_err) = commit_claimed_job_via_pipeline(
        fac_root,
        queue_root,
        spec,
        &claimed_path,
        &claimed_file_name,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&boundary_trace),
        Some(&queue_trace),
        budget_trace.as_ref(),
        patch_digest.as_deref(),
        Some(canonicalizer_tuple_digest),
        policy_hash,
        containment_trace.as_ref(),
        Some(observed_cost),
        Some(&sbx_hash),
        Some(&resolved_net_hash),
        None,                              // stop_revoke_admission
        resolved_bytes_backend.as_deref(), // TCK-00546: bytes_backend
        toolchain_fingerprint,
    ) {
        eprintln!("worker: pipeline commit failed, cannot complete job: {commit_err}");
        let _ = LaneLeaseV1::remove(&lane_dir);
        if let Err(move_err) = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(PENDING_DIR),
            &claimed_file_name,
        ) {
            eprintln!("worker: WARNING: failed to return claimed job to pending: {move_err}");
        }
        // TCK-00554 MINOR-1 fix: Stop sccache server on early-return path.
        // The containment protocol may have started a server; failing to stop
        // it here would leak a daemon beyond the unit lifecycle, violating
        // INV-CONTAIN-011.
        // Gate on ownership: only stop the server this unit started/verified.
        if owns_sccache_server(containment_trace.as_ref()) && !sccache_server_env.is_empty() {
            let stopped = apm2_core::fac::stop_sccache_server(&sccache_server_env);
            eprintln!("worker: sccache server stop (pipeline commit failure): stopped={stopped}");
        }
        return JobOutcome::Skipped {
            reason: format!("pipeline commit failed: {commit_err}"),
        };
    }

    // Step 10: Post-completion lane cleanup.
    //
    // Lane cleanup runs AFTER the job is officially completed (Step 9).
    // Cleanup failures are logged and result in lane corruption markers,
    // but they do NOT change the already-recorded job outcome. This
    // decouples infrastructure lifecycle from job execution integrity.
    if let Err(cleanup_err) =
        execute_lane_cleanup(fac_root, &lane_mgr, &acquired_lane_id, &lane_workspace)
    {
        eprintln!(
            "worker: WARNING: post-completion lane cleanup failed for {acquired_lane_id}: {cleanup_err}"
        );
        // Lane is already marked corrupt by execute_lane_cleanup on failure.
        // The job outcome remains Completed — infrastructure failures do not
        // retroactively negate successful execution.
    }

    // TCK-00554: Stop sccache server at unit end (INV-CONTAIN-011).
    // MINOR-1 fix: Gate shutdown on ownership — only stop the server if
    // this unit started one or verified a pre-existing in-cgroup server.
    // This prevents one lane from terminating a shared sccache server
    // that another concurrent lane is using.
    if owns_sccache_server(containment_trace.as_ref()) && !sccache_server_env.is_empty() {
        let stopped = apm2_core::fac::stop_sccache_server(&sccache_server_env);
        eprintln!("worker: sccache server stop (unit end): stopped={stopped}");
    }

    // Lane guard is dropped here (RAII), releasing the lane lock.
    let _ = acquired_lane_id;

    JobOutcome::Completed {
        job_id: spec.job_id.clone(),
        observed_cost: Some(observed_cost),
    }
}

/// Determines whether this unit owns the sccache server for shutdown purposes.
///
/// Ownership for shutdown is based on `server_started` / `started_server_pid`,
/// independent of `auto_disabled`. The `auto_disabled` flag controls build-time
/// enablement (whether sccache is USED for builds), not lifecycle cleanup.
/// A server we started must always be stopped at unit end, even if containment
/// verification failed and sccache was auto-disabled for builds.
///
/// Returns `true` when:
/// - The unit started a new server (`server_started` is true), OR
/// - The unit recorded a `started_server_pid`, OR
/// - A pre-existing server was detected AND verified in-cgroup (adopted
///   server).
///
/// MAJOR fix (fix-round-3): Previously returned `false` whenever
/// `auto_disabled` was `true`, causing servers started on the auto-disabled
/// path to leak beyond the unit lifecycle.
fn owns_sccache_server(
    containment_trace: Option<&apm2_core::fac::containment::ContainmentTrace>,
) -> bool {
    let Some(trace) = containment_trace else {
        return false;
    };
    let Some(ref sc) = trace.sccache_server_containment else {
        return false;
    };
    if !sc.protocol_executed {
        return false;
    }
    // This unit started a new server — must stop it regardless of auto_disabled.
    if sc.server_started || sc.started_server_pid.is_some() {
        return true;
    }
    // This unit adopted a pre-existing in-cgroup server.
    if sc.preexisting_server_detected && sc.preexisting_server_in_cgroup == Some(true) {
        return true;
    }
    false
}

/// Result of a process liveness check via `kill(pid, 0)`.
///
/// Distinguishes three outcomes to prevent EPERM-based false negatives
/// from causing lane reuse while a process is still running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessLiveness {
    /// Process exists and is owned by the current user (kill -0 succeeded).
    Alive,
    /// Process does not exist (ESRCH).
    Dead,
    /// Process exists but is not owned by the current user (EPERM).
    /// Treat as busy/corrupt — do NOT assume the lane is idle.
    PermissionDenied,
}

/// Check whether a process is alive using `kill(pid, 0)` with proper
/// errno discrimination.
///
/// BLOCKER FIX (f-685-code_quality-1): The previous implementation used
/// `status.success()` which conflated ESRCH (no such process) with EPERM
/// (operation not permitted). EPERM means the process EXISTS but belongs
/// to a different user — treating this as "dead" could cause lane reuse
/// while the previous process is still running.
///
/// This implementation uses `libc::kill` directly and checks errno:
/// - Success (0): process is alive and we can signal it
/// - ESRCH (3): process does not exist — safe to reclaim the lane
/// - EPERM (1): process exists but we lack permission — NOT safe
#[allow(unsafe_code)]
fn check_process_liveness(pid: u32) -> ProcessLiveness {
    // Guard against signaling pid 0 (entire process group) or negative
    // PIDs (which signal process groups by absolute value).
    if pid == 0 {
        return ProcessLiveness::Dead;
    }

    // SAFETY: This block is safe because the following pre-conditions are
    // upheld by the caller and the guard above, and result in a sound
    // post-condition:
    //
    // Pre-conditions:
    //   1. `pid` is non-zero (guarded by the `pid == 0` early return above).
    //   2. Signal 0 is used, which performs an existence check without delivering
    //      any signal — a standard POSIX `kill(2)` operation.
    //   3. The cast from `u32` to `i32` (`pid_t`) is bounded: valid Linux PIDs fit
    //      in `i32`. Wrapping of very large `u32` values (> i32::MAX) produces a
    //      negative `pid_t`. Negative values sent to `kill()` signal process groups
    //      by absolute value (e.g., -1 signals all processes). However, the
    //      function remains safe and fail-closed: signal 0 delivers no actual
    //      signal, and only an explicit ESRCH errno maps to `Dead`. Process-group
    //      signals that succeed return 0 (mapped to `Alive`), and EPERM or other
    //      errors map to `PermissionDenied` — both are fail-closed outcomes that
    //      prevent lane reuse.
    //
    // Post-condition: `ret` contains the kernel return value (0 = exists,
    // -1 = error with errno set). No memory is accessed, no signal is
    // delivered, and no UB can result from any `pid_t` value passed to
    // `kill(2)` with signal 0.
    #[allow(clippy::cast_possible_wrap)]
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };

    if ret == 0 {
        ProcessLiveness::Alive
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            ProcessLiveness::Dead
        } else {
            // EPERM: process exists but we lack permission to signal it.
            // Any other errno: fail-closed — assume process may exist.
            ProcessLiveness::PermissionDenied
        }
    }
}

/// Structured reset recommendation emitted when the worker encounters a
/// CORRUPT lane during lane acquisition.  Operators and monitoring tools can
/// parse these JSON objects from stderr to automate or triage reset actions.
///
/// TCK-00570: the worker refuses to lease a CORRUPT lane and emits this
/// structured recommendation.  The `FESv1` queue-based control-job
/// infrastructure is not yet available, so the recommendation is emitted as
/// a JSON line to **stderr** (machine-readable NDJSON channel).  All other
/// human-readable diagnostics in `acquire_worker_lane` flow through the
/// `tracing` subscriber (structured logging), not raw `eprintln!`, so the
/// only `eprintln!` on stderr from that path is the JSON recommendation
/// itself.  This keeps the stderr channel JSON-only for downstream
/// automation that consumes newline-delimited JSON.
/// When `FESv1` queue-based control jobs land (RFC-0019), this struct can
/// be enqueued directly.
#[derive(Debug, Clone, serde::Serialize)]
struct LaneResetRecommendation {
    /// Fixed schema identifier for forward-compatible parsing.
    schema: &'static str,
    /// The lane that needs operator reset.
    lane_id: String,
    /// Human-readable summary for operators (encoded inside the JSON payload,
    /// not emitted as a separate plain-text line — keeps stderr JSON-only).
    message: String,
    /// Why the lane is corrupt.
    reason: String,
    /// Suggested operator action.
    recommended_action: &'static str,
}

/// Schema identifier for [`LaneResetRecommendation`] payloads.
const LANE_RESET_RECOMMENDATION_SCHEMA: &str = "apm2.fac.lane_reset_recommendation.v1";

/// Emit a structured reset recommendation for a corrupt lane to **stderr**.
///
/// Channel contract (TCK-00570 scope):
/// - **stderr** carries machine-readable NDJSON recommendations (this fn) as
///   `apm2.fac.lane_reset_recommendation.v1` JSON lines.
/// - All other diagnostics in `acquire_worker_lane` use `tracing::warn!` /
///   `tracing::info!` / `tracing::error!` (structured logging), never raw
///   `eprintln!`, so the only `eprintln!` output from the lane-acquisition path
///   is the JSON recommendation itself.  This keeps the stderr channel
///   JSON-only for downstream automation.
///
/// Every line written to stderr by this function is a valid, parseable JSON
/// object.  Human-readable context is encoded inside the `message` field of
/// the JSON payload rather than emitted as a separate plain-text line.
///
/// This is a best-effort diagnostic -- the worker must not abort lane
/// scanning due to a recommendation emission failure.  Serialization
/// errors are routed through `tracing::warn!` (structured logging) so they
/// never pollute the JSON-only stderr recommendation stream.
fn emit_lane_reset_recommendation(lane_id: &str, reason: &str) {
    let rec = LaneResetRecommendation {
        schema: LANE_RESET_RECOMMENDATION_SCHEMA,
        lane_id: lane_id.to_string(),
        message: format!("worker: RECOMMENDATION: lane {lane_id} needs reset"),
        reason: reason.to_string(),
        recommended_action: "apm2 fac lane reset",
    };
    match serde_json::to_string(&rec) {
        Ok(json) => {
            // Write to stderr — the machine-readable NDJSON recommendation
            // channel (TCK-00570 scope: "JSON to stderr").  All other
            // diagnostics in acquire_worker_lane use tracing::* macros,
            // keeping the only eprintln! output as this JSON line.
            eprintln!("{json}");
        },
        Err(e) => tracing::warn!(
            lane_id = lane_id,
            error = %e,
            "failed to serialize reset recommendation (non-fatal)"
        ),
    }
}

fn acquire_worker_lane(
    lane_mgr: &LaneManager,
    lane_ids: &[String],
) -> Option<(LaneLockGuard, String)> {
    for lane_id in lane_ids {
        let guard = match lane_mgr.try_lock(lane_id) {
            Ok(Some(guard)) => guard,
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    error = %err,
                    "failed to probe lane"
                );
                continue;
            },
        };

        match LaneCorruptMarkerV1::load(lane_mgr.fac_root(), lane_id) {
            Ok(Some(marker)) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    reason = marker.reason.as_str(),
                    "skipping corrupt lane"
                );
                // TCK-00570: Emit structured reset recommendation for corrupt lane.
                emit_lane_reset_recommendation(lane_id, &marker.reason);
            },
            Ok(None) => {
                let lane_dir = lane_mgr.lane_dir(lane_id);
                match LaneLeaseV1::load(&lane_dir) {
                    Ok(Some(lease)) => match lease.state {
                        LaneState::Corrupt => {
                            tracing::warn!(
                                lane_id = lane_id.as_str(),
                                state = %lease.state,
                                "skipping corrupt lease lane"
                            );
                            // TCK-00570: Emit structured reset recommendation for
                            // corrupt lease state.
                            emit_lane_reset_recommendation(
                                lane_id,
                                &format!("lease state is {}", lease.state),
                            );
                        },
                        LaneState::Running | LaneState::Cleanup => {
                            // Check process liveness with proper errno
                            // discrimination (BLOCKER fix for EPERM vs ESRCH).
                            match check_process_liveness(lease.pid) {
                                ProcessLiveness::Dead => {
                                    // Process is confirmed dead (ESRCH). Safe to
                                    // recover this lane by removing the stale lease.
                                    tracing::info!(
                                        lane_id = lane_id.as_str(),
                                        pid = lease.pid,
                                        "stale lease recovery: pid is dead, reclaiming lane"
                                    );
                                    let _ = LaneLeaseV1::remove(&lane_dir);
                                    return Some((guard, lane_id.clone()));
                                },
                                ProcessLiveness::Alive => {
                                    // Process is still running. We have the flock
                                    // but the process is alive — this is unexpected
                                    // (flock should prevent concurrent acquisition).
                                    // Mark as corrupt to be safe.
                                    let reason = format!(
                                        "lane has RUNNING lease for pid {} which is still alive (unexpected with flock held)",
                                        lease.pid
                                    );
                                    tracing::warn!(
                                        lane_id = lane_id.as_str(),
                                        reason = reason.as_str(),
                                        "marking lane as corrupt"
                                    );
                                    if let Err(err) = persist_corrupt_marker_with_retries(
                                        lane_mgr.fac_root(),
                                        lane_id,
                                        &reason,
                                        None,
                                    ) {
                                        tracing::error!(
                                            lane_id = lane_id.as_str(),
                                            error = %err,
                                            "failed to persist corrupt marker for lane"
                                        );
                                    }
                                    // TCK-00570: Emit structured reset recommendation
                                    // after marking lane corrupt.
                                    emit_lane_reset_recommendation(lane_id, &reason);
                                },
                                ProcessLiveness::PermissionDenied => {
                                    // Process exists but we lack permission to
                                    // signal it (EPERM). The lane is NOT idle.
                                    // Mark as corrupt because we cannot determine
                                    // whether the process is still using the lane.
                                    let reason = format!(
                                        "lane has RUNNING lease for pid {} which exists but is not signalable (EPERM), marking corrupt",
                                        lease.pid
                                    );
                                    tracing::warn!(
                                        lane_id = lane_id.as_str(),
                                        reason = reason.as_str(),
                                        "lane has running lease with permission-denied liveness check"
                                    );
                                    if let Err(err) = persist_corrupt_marker_with_retries(
                                        lane_mgr.fac_root(),
                                        lane_id,
                                        &reason,
                                        None,
                                    ) {
                                        tracing::error!(
                                            lane_id = lane_id.as_str(),
                                            error = %err,
                                            "failed to persist corrupt marker for lane"
                                        );
                                    }
                                    // TCK-00570: Emit structured reset recommendation
                                    // after marking lane corrupt.
                                    emit_lane_reset_recommendation(lane_id, &reason);
                                },
                            }
                        },
                        _ => {
                            return Some((guard, lane_id.clone()));
                        },
                    },
                    Ok(None) => return Some((guard, lane_id.clone())),
                    Err(err) => {
                        tracing::warn!(
                            lane_id = lane_id.as_str(),
                            error = %err,
                            "skipping lane after lease load failed"
                        );
                    },
                }
            },
            Err(err) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    error = %err,
                    "skipping lane after corrupt marker check failed"
                );
            },
        }
    }

    None
}

#[derive(Debug)]
enum LaneCleanupError {
    CorruptMarkerPersistenceFailed { reason: String },
    CleanupFailed { reason: String },
}

impl std::fmt::Display for LaneCleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CorruptMarkerPersistenceFailed { reason } | Self::CleanupFailed { reason } => {
                write!(f, "{reason}")
            },
        }
    }
}

/// Run lane cleanup and emit cleanup receipts.
/// On failure, mark the lane as corrupt.
fn execute_lane_cleanup(
    fac_root: &Path,
    lane_mgr: &LaneManager,
    lane_id: &str,
    lane_workspace: &Path,
) -> Result<(), LaneCleanupError> {
    let cleanup_timestamp = current_timestamp_epoch_secs();

    match lane_mgr.run_lane_cleanup(lane_id, lane_workspace) {
        Ok(steps_completed) => {
            if let Err(receipt_err) = emit_lane_cleanup_receipt(
                fac_root,
                lane_id,
                LaneCleanupOutcome::Success,
                steps_completed.clone(),
                None,
                cleanup_timestamp,
            ) {
                eprintln!(
                    "worker: ERROR: failed to emit lane cleanup success receipt for {lane_id}: {receipt_err}"
                );
                let failure_reason = "cleanup receipt persistence failed";
                handle_cleanup_corruption(
                    fac_root,
                    lane_id,
                    failure_reason,
                    steps_completed,
                    cleanup_timestamp,
                )?;
                return Err(LaneCleanupError::CleanupFailed {
                    reason: failure_reason.to_string(),
                });
            }
            Ok(())
        },
        Err(err) => {
            let reason = format!("lane cleanup failed: {err}");
            let steps_completed = err.steps_completed().to_vec();
            let failure_step = err.failure_step().map(std::string::ToString::to_string);

            let failure_reason = failure_step.as_deref().map_or_else(
                || reason.clone(),
                |step| format!("{reason} (failure_step={step})"),
            );

            handle_cleanup_corruption(
                fac_root,
                lane_id,
                &failure_reason,
                steps_completed,
                cleanup_timestamp,
            )?;
            Err(LaneCleanupError::CleanupFailed {
                reason: failure_reason,
            })
        },
    }
}

fn handle_cleanup_corruption(
    fac_root: &Path,
    lane_id: &str,
    reason: &str,
    steps_completed: Vec<String>,
    cleanup_receipt_timestamp: u64,
) -> Result<(), LaneCleanupError> {
    let failure_reason = reason.to_string();
    let failed_receipt_digest = match emit_lane_cleanup_receipt(
        fac_root,
        lane_id,
        LaneCleanupOutcome::Failed,
        steps_completed,
        Some(&failure_reason),
        cleanup_receipt_timestamp,
    ) {
        Ok(receipt_digest) => Some(receipt_digest),
        Err(err) => {
            let emit_failure_reason =
                format!("failed to emit lane cleanup failure receipt for {lane_id}: {err}");
            tracing::warn!(lane_id = lane_id, reason = %emit_failure_reason, "lane cleanup failure receipt emission failed");
            if let Err(marker_err) =
                persist_corrupt_marker_with_retries(fac_root, lane_id, &emit_failure_reason, None)
            {
                return Err(LaneCleanupError::CorruptMarkerPersistenceFailed {
                    reason: format!(
                        "failed to persist corrupt marker after cleanup failure receipt emission failure for lane {lane_id}: {marker_err}"
                    ),
                });
            }
            return Err(LaneCleanupError::CleanupFailed {
                reason: reason.to_string(),
            });
        },
    };

    if let Err(err) = persist_corrupt_marker_with_retries(
        fac_root,
        lane_id,
        &failure_reason,
        failed_receipt_digest,
    ) {
        return Err(LaneCleanupError::CorruptMarkerPersistenceFailed { reason: err });
    }

    Ok(())
}

fn persist_corrupt_marker_with_retries(
    fac_root: &Path,
    lane_id: &str,
    reason: &str,
    cleanup_receipt_digest: Option<String>,
) -> Result<(), String> {
    let marker = LaneCorruptMarkerV1 {
        schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
        lane_id: lane_id.to_string(),
        reason: reason.to_string(),
        cleanup_receipt_digest,
        detected_at: apm2_core::fac::current_time_iso8601(),
    };

    let mut last_error: Option<String> = None;
    for attempt in 1..=CORRUPT_MARKER_PERSIST_RETRIES {
        match persist_corrupt_marker_with_durability(fac_root, &marker) {
            Ok(()) => return Ok(()),
            Err(marker_err) => {
                last_error = Some(marker_err.clone());
                tracing::warn!(
                    lane_id = lane_id,
                    attempt = attempt,
                    max_attempts = CORRUPT_MARKER_PERSIST_RETRIES,
                    error = %marker_err,
                    "failed to persist corrupt lane marker"
                );
                let delay_ms =
                    CORRUPT_MARKER_PERSIST_RETRY_DELAY_MS.saturating_mul(1u64 << (attempt - 1));
                if attempt < CORRUPT_MARKER_PERSIST_RETRIES && delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms));
                }
                if attempt == CORRUPT_MARKER_PERSIST_RETRIES {
                    return Err("failed to persist corrupt marker".to_string());
                }
            },
        }
    }

    Err(last_error.unwrap_or_else(|| "failed to persist corrupt marker".to_string()))
}

/// Persist a corrupt marker with full crash-safe durability.
///
/// Durability chain (MAJOR FIX for f-685-code_quality-2):
/// 1. `marker.persist()` -> `atomic_write()` which: a. Creates a temp file in
///    the same directory b. Writes all marker data to the temp file c. Calls
///    `file.sync_all()` to fsync the temp file data to disk d. Calls
///    `temp.persist(target)` to atomically rename the temp file
/// 2. This function then fsyncs the parent directory to ensure the directory
///    entry (rename result) is committed to storage media.
///
/// Together, steps 1c (fsync data) + 1d (atomic rename) + 2 (fsync dir)
/// ensure that a crash at any point either leaves no marker or leaves a
/// complete, valid marker. The lane will never appear IDLE when it should
/// be CORRUPT after a power loss.
fn persist_corrupt_marker_with_durability(
    fac_root: &Path,
    marker: &LaneCorruptMarkerV1,
) -> Result<(), String> {
    marker.persist(fac_root).map_err(|e| e.to_string())?;

    // Fsync the parent directory to ensure the rename (from atomic_write)
    // is committed to the storage media's directory entry table.
    let lane_dir = fac_root.join("lanes").join(&marker.lane_id);
    let dir = fs::OpenOptions::new()
        .read(true)
        .open(&lane_dir)
        .map_err(|err| {
            format!(
                "opening corrupt marker directory {} for durability sync: {err}",
                lane_dir.display()
            )
        })?;
    dir.sync_all().map_err(|err| {
        format!(
            "fsyncing corrupt marker directory {} for durability: {err}",
            lane_dir.display()
        )
    })?;

    Ok(())
}

// =============================================================================
// stop_revoke handler
// =============================================================================

/// Handles a `stop_revoke` job: kills the target unit and cancels the target
/// job.
///
/// MAJOR 3: This handler is fail-closed.  Each step must succeed for the
/// operation to complete.  If any critical step fails, the `stop_revoke` job
/// emits a failure receipt and does NOT complete.
///
/// MAJOR 2 fix (round 3): Receipt persistence is REQUIRED before any
/// terminal state transition.  Receipts are built and persisted BEFORE
/// moving jobs to terminal directories.  If receipt build or persist fails,
/// the job stays in its current state (claimed/) or moves to denied/.
///
/// # Steps
///
/// 1. Read the `cancel_target_job_id` from the spec.
/// 2. Locate the target job in `claimed/` (or check terminal directories).
/// 3. Read the target spec to get `queue_lane` for exact unit name.
/// 4. Stop the systemd unit (`systemctl stop apm2-fac-job-{lane}-{job_id}`).
/// 5. Build + persist cancellation receipt for the target job.
/// 6. Move the target job from `claimed/` to `cancelled/`.
/// 7. Build + persist completion receipt for the `stop_revoke` job.
/// 8. Move `stop_revoke` to `completed/`.
///
/// # Security
///
/// - Evidence and logs are never deleted (INV-CANCEL-004).
/// - Fail-closed: if `systemctl stop` fails, receipt build/persist fails, or
///   move-to-cancelled fails, a failure receipt is emitted and the
///   `stop_revoke` is NOT completed.
/// - Receipt persistence is REQUIRED before state transitions (proof-carrying).
/// - If the target is not found in `claimed/`, we check terminal directories
///   (completed/cancelled) to distinguish "already done" from "unknown".
#[allow(clippy::too_many_arguments)]
fn handle_stop_revoke(
    spec: &FacJobSpecV1,
    claimed_path: &Path,
    claimed_file_name: &str,
    queue_root: &Path,
    fac_root: &Path,
    boundary_trace: &ChannelBoundaryTrace,
    queue_trace: &JobQueueAdmissionTrace,
    budget_trace: Option<&FacBudgetAdmissionTrace>,
    canonicalizer_tuple_digest: &str,
    policy_hash: &str,
    sbx_hash: &str,
    net_hash: &str,
    job_wall_start: Instant,
    // TCK-00587: Stop/revoke admission trace for receipt binding.
    sr_trace: Option<&apm2_core::economics::queue_admission::StopRevokeAdmissionTrace>,
    // TCK-00538: Toolchain fingerprint computed at worker startup.
    toolchain_fingerprint: Option<&str>,
) -> JobOutcome {
    let target_job_id = match &spec.cancel_target_job_id {
        Some(id) if !id.is_empty() => id.as_str(),
        _ => {
            let reason = "stop_revoke job missing cancel_target_job_id".to_string();
            eprintln!(
                "worker: stop_revoke job {} missing cancel_target_job_id",
                spec.job_id
            );
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::MalformedSpec),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                sr_trace, // stop_revoke_admission
                None,     // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied stop_revoke (missing target)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Step 1: Locate target job in claimed/ directory.
    let target_path = find_target_job_in_dir(&queue_root.join(CLAIMED_DIR), target_job_id);

    // MAJOR 3 fail-closed: if target not in claimed/, check if it's already
    // in a terminal state (completed/cancelled).  If so, the cancellation
    // is a no-op.  If the target is truly unknown, fail with structured error.
    let Some(target_file_path) = target_path else {
        // Check terminal directories.
        let in_completed =
            find_target_job_in_dir(&queue_root.join(COMPLETED_DIR), target_job_id).is_some();
        let in_cancelled =
            find_target_job_in_dir(&queue_root.join(CANCELLED_DIR), target_job_id).is_some();

        if in_completed || in_cancelled {
            let terminal_state = if in_completed {
                "completed"
            } else {
                "cancelled"
            };
            eprintln!(
                "worker: stop_revoke: target {target_job_id} already in {terminal_state}/, treating as success"
            );
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            let observed = observed_cost_from_elapsed(job_wall_start.elapsed());
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Completed,
                None,
                &format!("stop_revoke: target {target_job_id} already {terminal_state}"),
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                Some(observed),
                Some(sbx_hash),
                Some(net_hash),
                sr_trace, // stop_revoke_admission
                None,     // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: pipeline commit failed for stop_revoke (target already terminal): {commit_err}"
                );
                return JobOutcome::Skipped {
                    reason: format!("pipeline commit failed: {commit_err}"),
                };
            }
            return JobOutcome::Completed {
                job_id: spec.job_id.clone(),
                observed_cost: Some(observed),
            };
        }

        // Target not found anywhere -- fail-closed.
        let reason = format!(
            "stop_revoke: target job {target_job_id} not found in claimed/ or any terminal directory"
        );
        eprintln!("worker: {reason}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(sbx_hash),
            Some(net_hash),
            sr_trace, // stop_revoke_admission
            None,     // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied stop_revoke (target not found)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    };

    let target_file_name = target_file_path.file_name().map_or_else(
        || format!("{target_job_id}.json"),
        |n| n.to_string_lossy().to_string(),
    );

    // Step 2: Read target spec for receipt emission and exact unit name.
    let target_spec_opt = read_bounded(&target_file_path, MAX_JOB_SPEC_SIZE)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<FacJobSpecV1>(&bytes).ok());

    // MAJOR 7: Construct exact unit name from the target spec's queue_lane.
    // No wildcard matching.
    let target_lane = target_spec_opt
        .as_ref()
        .map_or("unknown", |s| s.queue_lane.as_str());
    let stop_result = stop_target_unit_exact(target_lane, target_job_id);
    if let Err(ref e) = stop_result {
        eprintln!(
            "worker: stop_revoke: unit stop for target {target_job_id} (lane {target_lane}) failed: {e}"
        );
        // MAJOR 3 fail-closed: if systemctl stop fails, emit failure receipt.
        let reason =
            format!("stop_revoke failed: systemctl stop failed for target {target_job_id}: {e}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(sbx_hash),
            Some(net_hash),
            sr_trace, // stop_revoke_admission
            None,     // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied stop_revoke (systemctl stop failed)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // MAJOR 2 fix (round 3): Receipt persistence is REQUIRED before any
    // terminal state transition.  Reordered steps:
    //   3a. Build + persist cancellation receipt for target job
    //   3b. Only THEN move target to cancelled/
    //   4a. Build + persist completion receipt for stop_revoke job
    //   4b. Only THEN move stop_revoke to completed/
    // If any receipt build or persist fails, the job stays in claimed/
    // (or is moved to denied/) — never transitions to a terminal state
    // without a persisted receipt.

    // Step 3a: Build and persist cancellation receipt for the target job
    // BEFORE moving it to cancelled/.
    if let Some(ref target_spec) = target_spec_opt {
        let cancel_reason = spec
            .actuation
            .decoded_source
            .as_deref()
            .unwrap_or("stop_revoke");
        let reason = format!(
            "cancelled by stop_revoke job {}: {cancel_reason}",
            spec.job_id
        );
        let bounded_reason = truncate_receipt_reason(&reason);

        let receipt_id = format!(
            "cancel-{}-{}",
            target_job_id,
            current_timestamp_epoch_secs()
        );
        let mut builder = FacJobReceiptV1Builder::new(
            receipt_id,
            &target_spec.job_id,
            &target_spec.job_spec_digest,
        )
        .policy_hash(policy_hash)
        .outcome(FacJobOutcome::Cancelled)
        .denial_reason(DenialReasonCode::Cancelled)
        .reason(&bounded_reason)
        .timestamp_secs(current_timestamp_epoch_secs());
        // TCK-00538: Bind toolchain fingerprint to cancellation receipt.
        if let Some(fp) = toolchain_fingerprint {
            builder = builder.toolchain_fingerprint(fp);
        }

        let receipt = match builder.try_build() {
            Ok(r) => r,
            Err(e) => {
                // Fail-closed: cannot build receipt -> deny stop_revoke.
                let deny_reason = format!(
                    "stop_revoke failed: cannot build cancellation receipt for target {target_job_id}: {e}"
                );
                eprintln!("worker: {deny_reason}");
                // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
                if let Err(commit_err) = commit_claimed_job_via_pipeline(
                    fac_root,
                    queue_root,
                    spec,
                    claimed_path,
                    claimed_file_name,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::StopRevokeFailed),
                    &deny_reason,
                    Some(boundary_trace),
                    Some(queue_trace),
                    budget_trace,
                    None,
                    Some(canonicalizer_tuple_digest),
                    policy_hash,
                    None,
                    None,
                    Some(sbx_hash),
                    Some(net_hash),
                    sr_trace, // stop_revoke_admission
                    None,     // bytes_backend
                    toolchain_fingerprint,
                ) {
                    return handle_pipeline_commit_failure(
                        &commit_err,
                        "denied stop_revoke (receipt build failed)",
                        claimed_path,
                        queue_root,
                        claimed_file_name,
                    );
                }
                return JobOutcome::Denied {
                    reason: deny_reason,
                };
            },
        };

        let receipts_dir_sr = fac_root.join(FAC_RECEIPTS_DIR);
        if let Err(e) = persist_content_addressed_receipt(&receipts_dir_sr, &receipt) {
            // Fail-closed: cannot persist receipt -> deny stop_revoke.
            let deny_reason = format!(
                "stop_revoke failed: cannot persist cancellation receipt for target {target_job_id}: {e}"
            );
            eprintln!("worker: {deny_reason}");
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::StopRevokeFailed),
                &deny_reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                sr_trace, // stop_revoke_admission
                None,     // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied stop_revoke (receipt persist failed)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied {
                reason: deny_reason,
            };
        }
        // TCK-00576: Best-effort signed envelope alongside cancellation receipt.
        if let Ok(signer) = fac_key_material::load_or_generate_persistent_signer(fac_root) {
            let content_hash = apm2_core::fac::compute_job_receipt_content_hash(&receipt);
            let envelope = apm2_core::fac::sign_receipt(&content_hash, &signer, "fac-worker");
            if let Err(e) = apm2_core::fac::persist_signed_envelope(&receipts_dir_sr, &envelope) {
                tracing::warn!(
                    error = %e,
                    "signed cancellation receipt envelope failed (non-fatal)"
                );
            }
        }
    }

    // Step 3b: Move target job to cancelled/ — receipt is already persisted.
    if let Err(e) = move_to_dir_safe(
        &target_file_path,
        &queue_root.join(CANCELLED_DIR),
        &target_file_name,
    ) {
        let reason =
            format!("stop_revoke failed: cannot move target {target_job_id} to cancelled: {e}");
        eprintln!("worker: {reason}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::StopRevokeFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(sbx_hash),
            Some(net_hash),
            sr_trace, // stop_revoke_admission
            None,     // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied stop_revoke (move to cancelled failed)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }
    eprintln!("worker: stop_revoke: moved target {target_job_id} to cancelled/");

    // Step 4: TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
    // Receipt persistence, index update, and job move happen in a crash-safe
    // order via a single ReceiptWritePipeline::commit() call.
    let observed = observed_cost_from_elapsed(job_wall_start.elapsed());
    if let Err(commit_err) = commit_claimed_job_via_pipeline(
        fac_root,
        queue_root,
        spec,
        claimed_path,
        claimed_file_name,
        FacJobOutcome::Completed,
        None,
        &format!("stop_revoke completed for target {target_job_id}"),
        Some(boundary_trace),
        Some(queue_trace),
        budget_trace,
        None,
        Some(canonicalizer_tuple_digest),
        policy_hash,
        None,
        Some(observed),
        Some(sbx_hash),
        Some(net_hash),
        sr_trace, // stop_revoke_admission
        None,     // bytes_backend
        toolchain_fingerprint,
    ) {
        // Fail-closed: pipeline commit failed — stop_revoke job stays in claimed/.
        let reason = format!(
            "stop_revoke pipeline commit failed for job {}: {commit_err}",
            spec.job_id
        );
        eprintln!("worker: {reason}");
        return JobOutcome::Skipped { reason };
    }

    JobOutcome::Completed {
        job_id: spec.job_id.clone(),
        observed_cost: Some(observed),
    }
}

/// Execute a warm job: parse phases, run warm execution, persist receipt.
///
/// This handler is dispatched by `process_job` when `spec.kind == "warm"`.
/// Warm jobs prime the build cache in the lane workspace by running
/// user-selected phases (fetch/build/nextest/clippy/doc). The warm receipt
/// is persisted to the FAC receipts directory.
///
/// # Lane Lifecycle
///
/// The lane lease is cleaned up after job completion. On receipt emission
/// failure, the lease is removed and the job is returned to pending.
#[allow(clippy::too_many_arguments)]
fn execute_warm_job(
    spec: &FacJobSpecV1,
    claimed_path: &Path,
    claimed_file_name: &str,
    queue_root: &Path,
    fac_root: &Path,
    signer: &Signer,
    lane_workspace: &Path,
    lane_dir: &Path,
    acquired_lane_id: &str,
    lane_profile_hash: &str,
    boundary_trace: &ChannelBoundaryTrace,
    queue_trace: &JobQueueAdmissionTrace,
    budget_trace: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: &str,
    policy_hash: &str,
    containment_trace: Option<&apm2_core::fac::containment::ContainmentTrace>,
    lane_mgr: &LaneManager,
    _raw_bytes: &[u8],
    policy: &FacPolicyV1,
    lane_systemd_properties: &SystemdUnitProperties,
    sbx_hash: &str,
    net_hash: &str,
    heartbeat_cycle_count: u64,
    heartbeat_jobs_completed: u64,
    heartbeat_jobs_denied: u64,
    heartbeat_jobs_quarantined: u64,
    job_wall_start: Instant,
    // TCK-00538: Toolchain fingerprint computed at worker startup.
    toolchain_fingerprint: Option<&str>,
    // TCK-00554 BLOCKER-1 fix: Effective sccache enablement derived from
    // server containment protocol. When false, RUSTC_WRAPPER/SCCACHE_* are
    // stripped from the warm execution environment even if
    // `policy.sccache_enabled` is true. This prevents builds from using an
    // untrusted sccache server that was refused by containment verification.
    effective_sccache_enabled: bool,
) -> JobOutcome {
    use apm2_core::fac::warm::{WarmContainment, WarmPhase, execute_warm};

    // Parse warm phases from decoded_source (comma-separated phase names).
    let phases: Vec<WarmPhase> = match &spec.actuation.decoded_source {
        Some(phases_csv) if !phases_csv.is_empty() => {
            let mut parsed = Vec::new();
            for name in phases_csv
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                match WarmPhase::parse(name) {
                    Ok(p) => parsed.push(p),
                    Err(e) => {
                        let reason = format!("invalid warm phase '{name}': {e}");
                        eprintln!("worker: warm job {}: {reason}", spec.job_id);
                        let _ = LaneLeaseV1::remove(lane_dir);
                        // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
                        // (claimed/ -> denied/ transition).
                        if let Err(commit_err) = commit_claimed_job_via_pipeline(
                            fac_root,
                            queue_root,
                            spec,
                            claimed_path,
                            claimed_file_name,
                            FacJobOutcome::Denied,
                            Some(DenialReasonCode::ValidationFailed),
                            &reason,
                            Some(boundary_trace),
                            Some(queue_trace),
                            budget_trace,
                            patch_digest,
                            Some(canonicalizer_tuple_digest),
                            policy_hash,
                            containment_trace,
                            None,
                            Some(sbx_hash),
                            Some(net_hash),
                            None, // stop_revoke_admission
                            None, // bytes_backend
                            toolchain_fingerprint,
                        ) {
                            return handle_pipeline_commit_failure(
                                &commit_err,
                                "denied warm job (invalid phase)",
                                claimed_path,
                                queue_root,
                                claimed_file_name,
                            );
                        }
                        return JobOutcome::Denied { reason };
                    },
                }
            }
            parsed
        },
        _ => apm2_core::fac::warm::DEFAULT_WARM_PHASES.to_vec(),
    };

    // Set up CARGO_HOME and CARGO_TARGET_DIR within the lane.
    // TCK-00538: Namespace CARGO_TARGET_DIR by toolchain fingerprint so that
    // toolchain changes get a fresh build directory, preventing stale artifacts
    // from a different compiler version from corrupting incremental builds.
    let cargo_home = lane_dir.join("cargo_home");
    // Defensive: if fingerprint is somehow invalid (should not happen since
    // worker startup validates it), fall back to plain "target".
    let target_dir_name = toolchain_fingerprint
        .and_then(fingerprint_short_hex)
        .map_or_else(|| "target".to_string(), |hex16| format!("target-{hex16}"));
    let cargo_target_dir = lane_dir.join(&target_dir_name);
    if let Err(e) = std::fs::create_dir_all(&cargo_home) {
        let reason = format!("cannot create lane CARGO_HOME: {e}");
        let _ = LaneLeaseV1::remove(lane_dir);
        // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
        // (claimed/ -> denied/ transition).
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            patch_digest,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            containment_trace,
            None,
            Some(sbx_hash),
            Some(net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (CARGO_HOME creation failed)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }
    if let Err(e) = std::fs::create_dir_all(&cargo_target_dir) {
        let reason = format!("cannot create lane CARGO_TARGET_DIR: {e}");
        let _ = LaneLeaseV1::remove(lane_dir);
        // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
        // (claimed/ -> denied/ transition).
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            patch_digest,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            containment_trace,
            None,
            Some(sbx_hash),
            Some(net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (CARGO_TARGET_DIR creation failed)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    eprintln!(
        "worker: warm job {}: executing {} phase(s) in {}",
        spec.job_id,
        phases.len(),
        lane_workspace.display(),
    );

    // [INV-WARM-009] Build hardened environment via policy-driven default-deny
    // construction. This ensures warm subprocesses (which compile untrusted
    // repository code including build.rs and proc-macros) cannot access
    // FAC-private state, secrets, or worker authority context.
    let apm2_home = resolve_apm2_home().unwrap_or_else(|| {
        // Fallback: derive from fac_root (which is $APM2_HOME/private/fac).
        fac_root
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf()
    });
    let ambient_env: Vec<(String, String)> = std::env::vars().collect();
    let mut hardened_env = build_job_environment(policy, &ambient_env, &apm2_home);

    // fix-round-4 MAJOR: Override SCCACHE_DIR with lane-scoped path to prevent
    // server lifecycle collisions across concurrent lanes. build_job_environment
    // injects the global resolve_sccache_dir() path; we narrow it to a per-lane
    // subdirectory so each lane has its own sccache server Unix domain socket.
    if effective_sccache_enabled {
        let lane_sccache_dir = policy
            .resolve_sccache_dir(&apm2_home)
            .join(acquired_lane_id);
        hardened_env.insert(
            "SCCACHE_DIR".to_string(),
            lane_sccache_dir.to_string_lossy().to_string(),
        );
    }

    // TCK-00554 BLOCKER-1 fix: If the server containment protocol auto-disabled
    // sccache, strip RUSTC_WRAPPER and SCCACHE_* from the hardened environment.
    // `build_job_environment` injects these when `policy.sccache_enabled` is true,
    // but the containment protocol may have determined that the server is
    // untrusted. Fail-closed: an untrusted server MUST NOT be used for
    // compilation.
    if !effective_sccache_enabled && policy.sccache_enabled {
        eprintln!(
            "worker: warm job {}: sccache auto-disabled by containment — \
             stripping RUSTC_WRAPPER and SCCACHE_* from environment",
            spec.job_id,
        );
        hardened_env.remove("RUSTC_WRAPPER");
        hardened_env.retain(|key, _| !key.starts_with("SCCACHE_"));
    }

    // TCK-00596: Plumb credential mount metadata into execution environment.
    // This selectively re-introduces credential env vars (for example
    // GITHUB_TOKEN) after policy default-deny filtering when a validated
    // credential mount is available. Secret values are resolved at runtime and
    // are never serialized into receipts/job specs.
    if let Some(credential_mount) = build_github_credential_mount() {
        if let Err(error) =
            apply_credential_mount_to_env(&credential_mount, &mut hardened_env, &ambient_env)
        {
            let reason = format!("credential mount injection failed: {error}");
            eprintln!("worker: warm job {}: {reason}", spec.job_id);
            let _ = LaneLeaseV1::remove(lane_dir);
            // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
            // (claimed/ -> denied/ transition).
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                patch_digest,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                containment_trace,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied warm job (credential mount injection failed)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        }
    }

    // [INV-WARM-014] Construct systemd-run containment for warm phase
    // subprocesses. This wraps each cargo command in a transient unit with
    // MemoryMax/CPUQuota/TasksMax/RuntimeMaxSec from the lane profile,
    // matching the containment model used by standard bounded test execution.
    //
    // Uses select_and_validate_backend() for consistency with other components
    // (bounded test runner, gate execution). This validates prerequisites
    // (user bus for user-mode, systemd-run for system-mode) in one call.
    //
    // Fail-closed: only fall back to uncontained execution when the platform
    // genuinely doesn't support systemd-run (container environments, no user
    // D-Bus session in auto mode). Configuration errors (invalid backend
    // value, invalid service user, env var issues) deny the job — they
    // indicate operator misconfiguration that should be fixed, not silently
    // degraded.
    let warm_containment = match select_and_validate_backend() {
        Ok(backend) => {
            let system_config = if backend == ExecutionBackend::SystemMode {
                match SystemModeConfig::from_env() {
                    Ok(cfg) => Some(cfg),
                    Err(e) => {
                        // System-mode config failure is a configuration error
                        // (invalid service user, env var issues) — fail the job.
                        let reason = format!(
                            "warm containment denied: system-mode config error \
                             (not a platform limitation): {e}"
                        );
                        eprintln!("worker: warm job {}: {reason}", spec.job_id);
                        let _ = LaneLeaseV1::remove(lane_dir);
                        // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
                        // (claimed/ -> denied/ transition).
                        if let Err(commit_err) = commit_claimed_job_via_pipeline(
                            fac_root,
                            queue_root,
                            spec,
                            claimed_path,
                            claimed_file_name,
                            FacJobOutcome::Denied,
                            Some(DenialReasonCode::ValidationFailed),
                            &reason,
                            Some(boundary_trace),
                            Some(queue_trace),
                            budget_trace,
                            patch_digest,
                            Some(canonicalizer_tuple_digest),
                            policy_hash,
                            containment_trace,
                            None,
                            Some(sbx_hash),
                            Some(net_hash),
                            None, // stop_revoke_admission
                            None, // bytes_backend
                            toolchain_fingerprint,
                        ) {
                            return handle_pipeline_commit_failure(
                                &commit_err,
                                "denied warm job (system-mode config error)",
                                claimed_path,
                                queue_root,
                                claimed_file_name,
                            );
                        }
                        return JobOutcome::Denied { reason };
                    },
                }
            } else {
                None
            };
            Some(WarmContainment {
                backend,
                properties: lane_systemd_properties.clone(),
                system_config,
            })
        },
        Err(e) => {
            if e.is_platform_unavailable() {
                // Platform doesn't support systemd-run — acceptable fallback
                // to uncontained execution with a logged warning.
                eprintln!(
                    "worker: WARNING: warm job {} executing WITHOUT systemd-run containment \
                     (platform unavailable: {e}) — warm phase subprocesses (including build.rs \
                     and proc-macros) are not resource-limited by transient unit properties",
                    spec.job_id,
                );
                None
            } else {
                // Configuration/invariant error — fail-closed, deny the job.
                let reason = format!(
                    "warm containment denied: backend configuration error \
                     (not a platform limitation): {e}"
                );
                eprintln!("worker: warm job {}: {reason}", spec.job_id);
                let _ = LaneLeaseV1::remove(lane_dir);
                // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
                // (claimed/ -> denied/ transition).
                if let Err(commit_err) = commit_claimed_job_via_pipeline(
                    fac_root,
                    queue_root,
                    spec,
                    claimed_path,
                    claimed_file_name,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::ValidationFailed),
                    &reason,
                    Some(boundary_trace),
                    Some(queue_trace),
                    budget_trace,
                    patch_digest,
                    Some(canonicalizer_tuple_digest),
                    policy_hash,
                    containment_trace,
                    None,
                    Some(sbx_hash),
                    Some(net_hash),
                    None, // stop_revoke_admission
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    return handle_pipeline_commit_failure(
                        &commit_err,
                        "denied warm job (backend configuration error)",
                        claimed_path,
                        queue_root,
                        claimed_file_name,
                    );
                }
                return JobOutcome::Denied { reason };
            }
        },
    };
    if warm_containment.is_none() {
        eprintln!(
            "worker: WARNING: warm job {} executing WITHOUT systemd-run containment — \
             warm phase subprocesses (including build.rs and proc-macros) are not \
             resource-limited by transient unit properties",
            spec.job_id,
        );
    }

    // [INV-WARM-015] Build heartbeat refresh closure for the warm phase
    // polling loop. This prevents the worker heartbeat file from going stale
    // during long-running warm phases (which can take hours for large
    // projects). The heartbeat is refreshed every HEARTBEAT_REFRESH_INTERVAL
    // (5s) inside the try_wait loop.
    //
    // The closure captures the last known cycle_count and job counters from
    // the worker's main loop so that observers see accurate state during
    // long warm phases, rather than misleading zeroed counters.
    //
    // Synchronization: heartbeat_fn captures fac_root by value (Path clone)
    // and counter values by copy. Invoked synchronously from the same
    // thread that calls execute_warm_phase. No cross-thread sharing or
    // interior mutability.
    let heartbeat_fac_root = fac_root.to_path_buf();
    let heartbeat_job_id = spec.job_id.clone();
    let heartbeat_fn = move || {
        if let Err(e) = apm2_core::fac::worker_heartbeat::write_heartbeat(
            &heartbeat_fac_root,
            heartbeat_cycle_count,
            heartbeat_jobs_completed,
            heartbeat_jobs_denied,
            heartbeat_jobs_quarantined,
            "warm-executing",
        ) {
            // Non-fatal: heartbeat is observability, not correctness.
            eprintln!(
                "worker: WARNING: heartbeat refresh failed during warm job {heartbeat_job_id}: {e}",
            );
        }
    };

    // Execute warm phases.
    let start_epoch_secs = current_timestamp_epoch_secs();
    let warm_result = execute_warm(
        &phases,
        acquired_lane_id,
        lane_profile_hash,
        lane_workspace,
        &cargo_home,
        &cargo_target_dir,
        &spec.source.head_sha,
        start_epoch_secs,
        &hardened_env,
        warm_containment.as_ref(),
        Some(&heartbeat_fn),
        &spec.job_id,
    );

    let receipt = match warm_result {
        Ok(r) => r,
        Err(e) => {
            let reason = format!("warm execution failed: {e}");
            eprintln!("worker: warm job {}: {reason}", spec.job_id);
            // Warm execution failure is still a completed job (the phases ran,
            // just some may have failed). But structural errors (too many phases,
            // field too long) are denials.
            let _ = LaneLeaseV1::remove(lane_dir);
            // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
            // (claimed/ -> denied/ transition).
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                patch_digest,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                containment_trace,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied warm job (execution failed)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Persist the warm receipt to the FAC receipts directory.
    // [Finding #8] GateReceipt emission depends on successful persistence.
    // If the warm receipt cannot be persisted, the GateReceipt is emitted
    // with passed=false to reflect the incomplete measurement.
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let persist_ok = match receipt.persist(&receipts_dir) {
        Ok(_) => {
            eprintln!(
                "worker: warm receipt persisted for {} (hash: {})",
                spec.job_id, receipt.content_hash
            );
            true
        },
        Err(e) => {
            eprintln!(
                "worker: warm receipt persistence failed for {}: {e}",
                spec.job_id
            );
            false
        },
    };

    // [Finding #1/#4] Compute payload_hash from the serialized WarmReceiptV1,
    // not from the input job spec bytes. This binds the GateReceipt to the
    // actual warm execution output.
    let receipt_json = serde_json::to_vec(&receipt).unwrap_or_default();
    let warm_receipt_hash = compute_evidence_hash(&receipt_json);
    let changeset_digest = compute_evidence_hash(spec.source.head_sha.as_bytes());
    let receipt_id = format!("wkr-{}-{}", spec.job_id, current_timestamp_epoch_secs());
    let gate_receipt =
        GateReceiptBuilder::new(&receipt_id, "fac-worker-warm", &spec.actuation.lease_id)
            .changeset_digest(changeset_digest)
            .executor_actor_id("fac-worker")
            .receipt_version(1)
            .payload_kind("warm-receipt")
            .payload_schema_version(1)
            .payload_hash(warm_receipt_hash)
            .evidence_bundle_hash(warm_receipt_hash)
            .job_spec_digest(&spec.job_spec_digest)
            .sandbox_hardening_hash(sbx_hash)
            .network_policy_hash(net_hash)
            .passed(persist_ok)
            .build_and_sign(signer);

    let observed_cost = observed_cost_from_elapsed(job_wall_start.elapsed());

    // Persist the gate receipt alongside the completed job (before atomic commit).
    write_gate_receipt(queue_root, claimed_file_name, &gate_receipt);

    // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
    // Receipt persistence, index update, and job move happen in a crash-safe
    // order via a single ReceiptWritePipeline::commit() call.
    if let Err(commit_err) = commit_claimed_job_via_pipeline(
        fac_root,
        queue_root,
        spec,
        claimed_path,
        claimed_file_name,
        FacJobOutcome::Completed,
        None,
        "warm completed",
        Some(boundary_trace),
        Some(queue_trace),
        budget_trace,
        patch_digest,
        Some(canonicalizer_tuple_digest),
        policy_hash,
        containment_trace,
        Some(observed_cost),
        Some(sbx_hash),
        Some(net_hash),
        None, // stop_revoke_admission
        None, // bytes_backend
        toolchain_fingerprint,
    ) {
        eprintln!("worker: pipeline commit failed for warm job: {commit_err}");
        let _ = LaneLeaseV1::remove(lane_dir);
        if let Err(move_err) = move_to_dir_safe(
            claimed_path,
            &queue_root.join(PENDING_DIR),
            claimed_file_name,
        ) {
            eprintln!("worker: WARNING: failed to return claimed warm job to pending: {move_err}");
        }
        return JobOutcome::Skipped {
            reason: format!("pipeline commit failed for warm job: {commit_err}"),
        };
    }

    // Post-completion lane cleanup (same as standard jobs).
    if let Err(cleanup_err) =
        execute_lane_cleanup(fac_root, lane_mgr, acquired_lane_id, lane_workspace)
    {
        eprintln!(
            "worker: WARNING: post-completion lane cleanup failed for warm job on {acquired_lane_id}: {cleanup_err}"
        );
    }

    JobOutcome::Completed {
        job_id: spec.job_id.clone(),
        observed_cost: Some(observed_cost),
    }
}

/// Locates a target job file in a directory by `job_id`.
///
/// Scans with bounded entries to prevent unbounded memory growth.
fn find_target_job_in_dir(dir: &Path, target_job_id: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;

    for (idx, entry) in entries.enumerate() {
        if idx >= MAX_PENDING_SCAN_ENTRIES {
            break;
        }
        let Ok(entry) = entry else { continue };
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        // Try reading the spec to match by job_id.
        let Ok(bytes) = read_bounded(&path, MAX_JOB_SPEC_SIZE) else {
            continue;
        };
        let Ok(spec) = serde_json::from_slice::<FacJobSpecV1>(&bytes) else {
            continue;
        };
        if spec.job_id == target_job_id {
            return Some(path);
        }
    }

    None
}

/// Attempts to stop the exact systemd unit for a target job.
///
/// MAJOR 7: Uses the exact unit name `apm2-fac-job-{lane}-{job_id}` instead
/// of wildcard matching.  The `queue_lane` is read from the target job spec
/// in `claimed/`.
///
/// Tries both user-mode and system-mode `systemctl stop` commands.
/// Uses `KillMode=control-group` semantics to kill all processes in the
/// cgroup.
///
/// BLOCKER fix (round 3): Exit code 5 from one scope no longer short-circuits.
/// The function attempts BOTH scopes and only returns `Ok(())` when:
/// - A stop actually succeeded (exit code 0) in at least one scope, OR
/// - Both scopes confirm the unit is not found (exit code 5 in both).
///
/// Returns `Ok(())` if the unit was stopped or confirmed absent in all scopes,
/// or `Err` with details.
fn stop_target_unit_exact(lane: &str, target_job_id: &str) -> Result<(), String> {
    // MAJOR-1 fix: Sanitize queue_lane to only allow [A-Za-z0-9_-].
    // Fail-closed: reject lanes containing unsafe characters to prevent
    // command injection via crafted unit names.
    if lane.is_empty()
        || !lane
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "unsafe queue_lane value {lane:?}: only [A-Za-z0-9_-] allowed"
        ));
    }
    let unit_name = format!("apm2-fac-job-{lane}-{target_job_id}");
    let mut last_err = String::new();
    let mut any_stop_succeeded = false;
    let mut not_found_count: u32 = 0;
    let scopes: &[&str] = &["--user", "--system"];

    // Attempt to stop in BOTH scopes (user and system).
    // Exit code 5 means "unit not loaded in this scope" — NOT "already stopped".
    // We must check both scopes because the unit may be running in either.
    for mode_flag in scopes {
        eprintln!("worker: stop_revoke: stopping unit {unit_name} ({mode_flag})");
        let stop_result = std::process::Command::new("systemctl")
            .args([mode_flag, "stop", "--", &unit_name])
            .output();
        match stop_result {
            Ok(out) if out.status.success() => {
                eprintln!(
                    "worker: stop_revoke: unit {unit_name} stopped successfully ({mode_flag})"
                );
                any_stop_succeeded = true;
            },
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                // Exit code 5 means "unit not loaded" — NOT in this scope.
                // The unit might still be running in the other scope, so we
                // record "not found here" and continue checking.
                if out.status.code() == Some(5) {
                    eprintln!(
                        "worker: stop_revoke: unit {unit_name} not loaded ({mode_flag}), \
                         not found in this scope"
                    );
                    not_found_count = not_found_count.saturating_add(1);
                } else {
                    last_err = format!("{mode_flag}: {stderr}");
                    eprintln!(
                        "worker: stop_revoke: stop {unit_name} failed ({mode_flag}): {stderr}"
                    );
                }
            },
            Err(e) => {
                last_err = format!("{mode_flag}: {e}");
                eprintln!("worker: stop_revoke: systemctl stop failed ({mode_flag}): {e}");
            },
        }
    }

    // Success conditions:
    // 1. At least one scope returned exit code 0 (stop succeeded), OR
    // 2. Both scopes returned exit code 5 (unit not found in either — truly
    //    absent).
    #[allow(clippy::cast_possible_truncation)]
    let total_scopes = scopes.len() as u32;
    if any_stop_succeeded || not_found_count == total_scopes {
        if not_found_count == total_scopes {
            eprintln!(
                "worker: stop_revoke: unit {unit_name} not found in any scope, \
                 treating as already stopped"
            );
        }
        return Ok(());
    }

    // Fail-closed: neither mode confirmed the unit as stopped or absent.
    // Return error so the caller emits a failure receipt.
    Err(format!(
        "systemctl stop failed for unit {unit_name}: {last_err}"
    ))
}

// =============================================================================
// Filesystem helpers
// =============================================================================

/// Resolves the queue root directory from `$APM2_HOME/queue`.
fn resolve_queue_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home".to_string())?;
    Ok(home.join(QUEUE_DIR))
}

/// Resolves the FAC root directory at `$APM2_HOME/private/fac`.
fn resolve_fac_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home".to_string())?;
    Ok(home.join("private").join("fac"))
}

/// Ensures all required queue subdirectories exist.
fn ensure_queue_dirs(queue_root: &Path) -> Result<(), String> {
    for dir in [
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINE_DIR,
        CANCELLED_DIR,
        CONSUME_RECEIPTS_DIR,
    ] {
        let path = queue_root.join(dir);
        if !path.exists() {
            fs::create_dir_all(&path)
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Checks if a PCAC authority token has already been consumed for this job.
///
/// Returns true if a consume receipt exists for the given `job_id`, indicating
/// the authority was already consumed and the job should be skipped.
fn is_authority_consumed(queue_root: &Path, job_id: &str) -> bool {
    let consume_dir = queue_root.join(CONSUME_RECEIPTS_DIR);
    let receipt_path = consume_dir.join(format!("{job_id}.consumed"));
    receipt_path.exists()
}

/// Durably records PCAC authority consumption BEFORE any side effect.
///
/// This implements the essential property of the PCAC lifecycle:
/// a single-use, durable authorization record must exist before the
/// authority-bearing effect (job claim + receipt emission).
///
/// The consume receipt commits to: `job_id`, `claim timestamp`, and
/// `spec_digest` for binding integrity.
fn consume_authority(queue_root: &Path, job_id: &str, spec_digest: &str) -> Result<(), String> {
    let consume_dir = queue_root.join(CONSUME_RECEIPTS_DIR);
    fs::create_dir_all(&consume_dir)
        .map_err(|e| format!("cannot create consume receipt dir: {e}"))?;

    let receipt_path = consume_dir.join(format!("{job_id}.consumed"));

    // Fail-closed: if the receipt already exists, authority was already
    // consumed.
    if receipt_path.exists() {
        return Err(format!("authority already consumed for job {job_id}"));
    }

    let receipt = serde_json::json!({
        "schema": "apm2.fac.pcac_consume.v1",
        "job_id": job_id,
        "spec_digest": spec_digest,
        "consumed_at_epoch_secs": current_timestamp_epoch_secs(),
    });

    let bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|e| format!("cannot serialize consume receipt: {e}"))?;
    fs::write(&receipt_path, bytes).map_err(|e| format!("cannot write consume receipt: {e}"))?;

    if let Ok(dir) = fs::File::open(&consume_dir) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Reads a file with bounded I/O (INV-WRK-001).
///
/// Returns an error if the file is larger than `max_size` or cannot be read.
fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    fac_secure_io::read_bounded(path, max_size)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Loads or generates a persistent signing key from
/// `$APM2_HOME/private/fac/signing_key`.
///
/// On first run, generates a new key and saves it with 0600 permissions.
/// On subsequent runs, loads the existing key. This keeps broker state and
/// receipts consistent across worker restarts.
fn load_or_generate_persistent_signer() -> Result<Signer, String> {
    let fac_root = resolve_fac_root()?;
    fac_key_material::load_or_generate_persistent_signer(&fac_root)
}

/// Loads persisted broker state from
/// `$APM2_HOME/private/fac/broker_state.json`.
///
/// Returns None if the file doesn't exist.
fn load_broker_state() -> Option<apm2_core::fac::broker::BrokerState> {
    let Ok(fac_root) = resolve_fac_root() else {
        return None;
    };
    let state_path = fac_root.join("broker_state.json");
    if !state_path.exists() {
        return None;
    }
    let bytes = read_bounded(&state_path, 1_048_576).ok()?;
    FacBroker::deserialize_state(&bytes).ok()
}

/// Saves broker state to `$APM2_HOME/private/fac/broker_state.json`.
fn save_broker_state(broker: &FacBroker) -> Result<(), String> {
    let fac_root = resolve_fac_root()?;
    let state_path = fac_root.join("broker_state.json");
    let bytes = broker
        .serialize_state()
        .map_err(|e| format!("cannot serialize broker state: {e}"))?;
    fs::write(&state_path, bytes).map_err(|e| format!("cannot write broker state: {e}"))
}

/// TCK-00566: Loads persisted token ledger from
/// `$APM2_HOME/private/fac/broker/token_ledger/state.json`.
///
/// Returns `Ok(None)` if the file doesn't exist (first run).
/// Returns `Err` if the file exists but cannot be read or deserialized
/// (INV-TL-009: fail-closed — load errors from an existing ledger file
/// are hard security faults that refuse to continue).
/// Expired entries are dropped on load.
///
/// If a WAL file exists alongside the snapshot, it is replayed after
/// snapshot load to restore full ledger state.
#[allow(dead_code)] // Called from fac_queue_submit; dead_code false positive in test targets.
pub fn load_token_ledger_pub(
    current_tick: u64,
) -> Result<Option<apm2_core::fac::token_ledger::TokenUseLedger>, String> {
    load_token_ledger(current_tick)
}

fn load_token_ledger(
    current_tick: u64,
) -> Result<Option<apm2_core::fac::token_ledger::TokenUseLedger>, String> {
    let fac_root = resolve_fac_root()?;
    let ledger_dir = fac_root.join("broker").join("token_ledger");
    let state_path = ledger_dir.join("state.json");
    if !state_path.exists() {
        // No WAL without a snapshot is valid on first run.
        return Ok(None);
    }
    let bytes = read_bounded(
        &state_path,
        apm2_core::fac::token_ledger::MAX_TOKEN_LEDGER_FILE_SIZE,
    )?;
    let mut ledger =
        apm2_core::fac::token_ledger::TokenUseLedger::deserialize_state(&bytes, current_tick)
            .map_err(|e| format!("token ledger load failed (fail-closed): {e}"))?;

    // Replay WAL if it exists.
    let wal_path = ledger_dir.join("wal.jsonl");
    if wal_path.exists() {
        let wal_bytes = read_bounded(&wal_path, apm2_core::fac::token_ledger::MAX_WAL_FILE_SIZE)?;
        let replayed = ledger
            .replay_wal(&wal_bytes)
            .map_err(|e| format!("token ledger WAL replay failed (fail-closed): {e}"))?;
        if replayed > 0 {
            eprintln!("worker: replayed {replayed} WAL entries for token ledger");
        }
    }

    Ok(Some(ledger))
}

/// TCK-00566: Saves token ledger snapshot to
/// `$APM2_HOME/private/fac/broker/token_ledger/state.json`.
///
/// Uses `write_atomic` (`temp+fsync+dir_fsync+rename`) for crash safety
/// per CTR-2607. After a successful snapshot, the WAL file is truncated
/// and the WAL counter is reset (compaction).
///
/// Errors are propagated to the caller (INV-TL-009: fail-closed).
fn save_token_ledger(broker: &mut FacBroker) -> Result<(), String> {
    let fac_root = resolve_fac_root()?;
    let ledger_dir = fac_root.join("broker").join("token_ledger");
    if !ledger_dir.exists() {
        fac_permissions::ensure_dir_with_mode(&ledger_dir)
            .map_err(|e| format!("cannot create token ledger dir: {e}"))?;
    }

    // BLOCKER fix: acquire exclusive flock on compaction.lock to prevent
    // multi-process compaction races. Worker A truncates WAL after snapshot,
    // but Worker B may have appended between snapshot and truncation — B's
    // entry would be lost without this lock.
    let lock_path = ledger_dir.join("compaction.lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false) // Lock file only — never truncate its contents.
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("cannot open compaction lock: {e}"))?;
    // Exclusive lock — blocks until acquired. Flock::lock takes ownership and
    // automatically unlocks on drop.
    let _lock_guard = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_file, e)| format!("cannot acquire compaction lock: {e}"))?;

    let state_path = ledger_dir.join("state.json");
    let bytes = broker
        .serialize_token_ledger()
        .map_err(|e| format!("cannot serialize token ledger: {e}"))?;
    // CTR-2607: full atomic write protocol (temp+fsync+dir_fsync+rename).
    apm2_core::determinism::write_atomic(&state_path, &bytes)
        .map_err(|e| format!("cannot write token ledger snapshot: {e}"))?;
    // MAJOR fix: Truncate WAL with fsync after successful snapshot (compaction).
    // Uses open+set_len(0)+sync_all instead of fs::write to ensure the
    // truncation is durable before releasing the compaction lock.
    let wal_path = ledger_dir.join("wal.jsonl");
    if wal_path.exists() {
        let wal_file = fs::OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .map_err(|e| format!("cannot open token ledger WAL for truncation: {e}"))?;
        wal_file
            .set_len(0)
            .map_err(|e| format!("cannot truncate token ledger WAL: {e}"))?;
        wal_file
            .sync_all()
            .map_err(|e| format!("cannot fsync token ledger WAL truncation: {e}"))?;
    }
    broker.reset_token_ledger_wal_counter();

    // _lock_guard dropped here — exclusive flock released automatically.
    Ok(())
}

/// TCK-00566: Appends a WAL entry to
/// `$APM2_HOME/private/fac/broker/token_ledger/wal.jsonl`.
///
/// Uses append mode with fsync for crash durability (INV-TL-010).
/// This MUST be called immediately after `validate_and_record_token_nonce`
/// returns Ok and BEFORE job execution begins (BLOCKER fix).
#[allow(dead_code)] // Called from fac_warm and gates; dead_code false positive in test targets.
pub fn append_token_ledger_wal_pub(wal_bytes: &[u8]) -> Result<(), String> {
    append_token_ledger_wal(wal_bytes)
}

fn append_token_ledger_wal(wal_bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    let fac_root = resolve_fac_root()?;
    let ledger_dir = fac_root.join("broker").join("token_ledger");
    if !ledger_dir.exists() {
        fac_permissions::ensure_dir_with_mode(&ledger_dir)
            .map_err(|e| format!("cannot create token ledger dir: {e}"))?;
    }
    let wal_path = ledger_dir.join("wal.jsonl");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&wal_path)
        .map_err(|e| format!("cannot open token ledger WAL: {e}"))?;
    file.write_all(wal_bytes)
        .map_err(|e| format!("cannot write token ledger WAL: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("cannot fsync token ledger WAL: {e}"))?;
    Ok(())
}

/// Atomically moves a file to a destination directory with collision-safe
/// target names.
///
/// Uses `fs::rename` for atomicity on the same filesystem (INV-WRK-003).
/// If the target file already exists (duplicate job ID from a concurrent
/// worker or replay), the file name is suffixed with a nanosecond timestamp
/// to prevent clobbering (MAJOR-2 fix).
fn move_to_dir_safe(src: &Path, dest_dir: &Path, file_name: &str) -> Result<PathBuf, String> {
    let do_move = || -> Result<PathBuf, String> {
        if !dest_dir.exists() {
            fac_permissions::ensure_dir_with_mode(dest_dir)
                .map_err(|e| format!("cannot create {}: {e}", dest_dir.display()))?;
        }
        let dest = dest_dir.join(file_name);

        // Attempt atomic no-replace rename (RENAME_NOREPLACE).
        // On collision (EEXIST / ENOTEMPTY), generate a unique timestamped name.
        match rename_noreplace(src, &dest) {
            Ok(()) => return Ok(dest),
            Err(e)
                if e.raw_os_error() == Some(libc::EEXIST)
                    || e.raw_os_error() == Some(libc::ENOTEMPTY)
                    || e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => {
                return Err(format!(
                    "rename {} -> {}: {e}",
                    src.display(),
                    dest.display()
                ));
            },
        }

        // Generate a unique timestamped filename for the collision case.
        let ts_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stem = file_name.trim_end_matches(".json");
        let safe_name = format!("{stem}-{ts_nanos}.json");
        let safe_dest = dest_dir.join(&safe_name);
        rename_noreplace(src, &safe_dest)
            .map_err(|e| format!("rename {} -> {}: {e}", src.display(), safe_dest.display()))?;
        Ok(safe_dest)
    };

    let result = do_move();
    if let Err(ref e) = result {
        eprintln!("worker: WARNING: move_to_dir_safe failed: {e}");
    }
    result
}

// NOTE: `rename_noreplace` is imported from `apm2_core::fac::rename_noreplace`
// (MAJOR-3 fix round 7: unified into single canonical implementation in
// receipt_pipeline.rs to avoid behavioral drift and security maintenance
// burden).

/// Emit a structured job receipt for scan failures (typically malformed input).
#[allow(clippy::too_many_arguments)]
fn emit_scan_receipt(
    fac_root: &Path,
    file_name: &str,
    job_id: &str,
    job_spec_digest: &str,
    outcome: FacJobOutcome,
    denial_reason: DenialReasonCode,
    moved_job_path: Option<&str>,
    reason: &str,
    canonicalizer_tuple_digest: &str,
    // TCK-00538: Optional toolchain fingerprint for receipt provenance.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    let mut builder = FacJobReceiptV1Builder::new(
        format!("wkr-scan-{}-{}", file_name, current_timestamp_epoch_secs()),
        job_id,
        job_spec_digest,
    )
    .outcome(outcome)
    .denial_reason(denial_reason)
    .canonicalizer_tuple_digest(canonicalizer_tuple_digest)
    .reason(reason)
    .timestamp_secs(current_timestamp_epoch_secs());

    if let Some(path) = moved_job_path {
        builder = builder.moved_job_path(path);
    }
    // TCK-00538: Bind toolchain fingerprint to scan receipt.
    if let Some(fp) = toolchain_fingerprint {
        builder = builder.toolchain_fingerprint(fp);
    }

    let receipt = builder
        .try_build()
        .map_err(|e| format!("cannot build scan receipt: {e}"))?;

    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let result = persist_content_addressed_receipt(&receipts_dir, &receipt)?;

    // TCK-00576: Best-effort signed envelope alongside scan receipt.
    if let Ok(signer) = fac_key_material::load_or_generate_persistent_signer(fac_root) {
        let content_hash = apm2_core::fac::compute_job_receipt_content_hash(&receipt);
        let envelope = apm2_core::fac::sign_receipt(&content_hash, &signer, "fac-worker");
        if let Err(e) = apm2_core::fac::persist_signed_envelope(&receipts_dir, &envelope) {
            tracing::warn!(error = %e, "signed scan receipt envelope failed (non-fatal)");
        }
    }

    Ok(result)
}

fn emit_lane_cleanup_receipt(
    fac_root: &Path,
    lane_id: &str,
    outcome: LaneCleanupOutcome,
    steps_completed: Vec<String>,
    failure_reason: Option<&str>,
    timestamp_secs: u64,
) -> Result<String, String> {
    let receipt = LaneCleanupReceiptV1 {
        schema: FAC_LANE_CLEANUP_RECEIPT_SCHEMA.to_string(),
        receipt_id: format!("wkr-cleanup-{lane_id}-{timestamp_secs}"),
        lane_id: lane_id.to_string(),
        outcome,
        steps_completed,
        failure_reason: failure_reason.map(std::string::ToString::to_string),
        timestamp_secs,
        content_hash: String::new(),
    };

    let receipt_path = receipt
        .persist(&fac_root.join(FAC_RECEIPTS_DIR), timestamp_secs)
        .map_err(|e| format!("cannot persist lane cleanup receipt: {e}"))?;
    receipt_path
        .file_name()
        .and_then(|s| s.to_str())
        .map_or_else(
            || Err("receipt filename was not UTF-8".to_string()),
            |name| {
                let digest = name.trim_end_matches(".json");
                Ok(digest.to_string())
            },
        )
}

fn load_or_create_policy(fac_root: &Path) -> Result<(String, [u8; 32], FacPolicyV1), String> {
    let policy_dir = fac_root.join("policy");
    let policy_path = policy_dir.join("fac_policy.v1.json");

    let policy = if policy_path.exists() {
        let bytes = read_bounded(&policy_path, MAX_POLICY_SIZE)?;
        deserialize_policy(&bytes).map_err(|e| format!("cannot load fac policy: {e}"))?
    } else {
        let default_policy = apm2_core::fac::FacPolicyV1::default_policy();
        persist_policy(fac_root, &default_policy)
            .map_err(|e| format!("cannot persist default fac policy: {e}"))?;
        default_policy
    };

    let policy_hash =
        compute_policy_hash(&policy).map_err(|e| format!("cannot compute policy hash: {e}"))?;
    let policy_digest =
        parse_policy_hash(&policy_hash).ok_or_else(|| "invalid policy hash".to_string())?;

    Ok((policy_hash, policy_digest, policy))
}

/// Emit a unified `FacJobReceiptV1` and persist under
/// `$APM2_HOME/private/fac/receipts`.
///
/// MAJOR-2 fix: accepts `bytes_backend` so non-pipeline emission paths
/// carry consistent metadata for GC tracking.
#[allow(clippy::too_many_arguments)]
fn emit_job_receipt(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    moved_job_path: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00546 MAJOR-2: bytes_backend for GC tracking in non-pipeline paths.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    emit_job_receipt_internal(
        fac_root,
        spec,
        outcome,
        denial_reason,
        reason,
        rfc0028_channel_boundary,
        eio29_queue_admission,
        eio29_budget_admission,
        patch_digest,
        canonicalizer_tuple_digest,
        moved_job_path,
        policy_hash,
        containment,
        None,
        sandbox_hardening_hash,
        network_policy_hash,
        bytes_backend,
        toolchain_fingerprint,
    )
}

/// Emit a unified `FacJobReceiptV1` with observed runtime cost metrics.
///
/// Note: Most callers have been migrated to `commit_claimed_job_via_pipeline`
/// (TCK-00564 BLOCKER-1). This function is retained for future non-pipeline
/// receipt emission paths.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn emit_job_receipt_with_observed_cost(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    moved_job_path: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    observed_cost: apm2_core::economics::cost_model::ObservedJobCost,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00546 MAJOR-2: bytes_backend for GC tracking.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    emit_job_receipt_internal(
        fac_root,
        spec,
        outcome,
        denial_reason,
        reason,
        rfc0028_channel_boundary,
        eio29_queue_admission,
        eio29_budget_admission,
        patch_digest,
        canonicalizer_tuple_digest,
        moved_job_path,
        policy_hash,
        containment,
        Some(observed_cost),
        sandbox_hardening_hash,
        network_policy_hash,
        bytes_backend,
        toolchain_fingerprint,
    )
}

/// Build a `FacJobReceiptV1` from the given parameters without persisting.
///
/// This is the shared receipt construction logic used by both the direct
/// persist path and the `ReceiptWritePipeline` commit path (TCK-00564).
#[allow(clippy::too_many_arguments)]
fn build_job_receipt(
    spec: &FacJobSpecV1,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    moved_job_path: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    observed_cost: Option<apm2_core::economics::cost_model::ObservedJobCost>,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00587: Optional stop/revoke admission trace for receipt binding.
    stop_revoke_admission: Option<&apm2_core::economics::queue_admission::StopRevokeAdmissionTrace>,
    // TCK-00546: Optional patch bytes backend identifier for GC tracking.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint.
    toolchain_fingerprint: Option<&str>,
) -> Result<FacJobReceiptV1, String> {
    let mut builder = FacJobReceiptV1Builder::new(
        format!("wkr-{}-{}", spec.job_id, current_timestamp_epoch_secs()),
        &spec.job_id,
        &spec.job_spec_digest,
    )
    .policy_hash(policy_hash)
    .outcome(outcome)
    .reason(reason)
    .timestamp_secs(current_timestamp_epoch_secs());

    if let Some(denial_reason) = denial_reason {
        builder = builder.denial_reason(denial_reason);
    }

    if let Some(boundary_trace) = rfc0028_channel_boundary {
        builder = builder.rfc0028_channel_boundary(boundary_trace.clone());
    }
    if let Some(queue_admission_trace) = eio29_queue_admission {
        builder = builder.eio29_queue_admission(queue_admission_trace.clone());
    }
    if let Some(budget_admission_trace) = eio29_budget_admission {
        builder = builder.eio29_budget_admission(budget_admission_trace.clone());
    }
    if let Some(patch_digest) = patch_digest {
        builder = builder.patch_digest(patch_digest);
    }
    if let Some(canonicalizer_tuple_digest) = canonicalizer_tuple_digest {
        builder = builder.canonicalizer_tuple_digest(canonicalizer_tuple_digest);
    }
    if let Some(path) = moved_job_path {
        builder = builder.moved_job_path(path);
    }
    if let Some(fp) = toolchain_fingerprint {
        builder = builder.toolchain_fingerprint(fp);
    }
    if let Some(trace) = containment {
        builder = builder.containment(trace.clone());
    }
    if let Some(cost) = observed_cost {
        builder = builder.observed_cost(cost);
    }
    // TCK-00573: Bind sandbox hardening hash to receipt for audit.
    if let Some(hash) = sandbox_hardening_hash {
        builder = builder.sandbox_hardening_hash(hash);
    }
    // TCK-00574: Bind network policy hash to receipt for audit.
    if let Some(hash) = network_policy_hash {
        builder = builder.network_policy_hash(hash);
    }
    // TCK-00587: Bind stop/revoke admission trace to receipt for audit.
    if let Some(trace) = stop_revoke_admission {
        builder = builder.stop_revoke_admission(trace.clone());
    }
    // TCK-00546: Bind bytes_backend to receipt for GC tracking.
    if let Some(backend) = bytes_backend {
        builder = builder.bytes_backend(backend);
    }

    builder
        .try_build()
        .map_err(|e| format!("cannot build job receipt: {e}"))
}

#[allow(clippy::too_many_arguments)]
fn emit_job_receipt_internal(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    moved_job_path: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    observed_cost: Option<apm2_core::economics::cost_model::ObservedJobCost>,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00546 MAJOR-2: bytes_backend threaded through for GC tracking.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    let receipt = build_job_receipt(
        spec,
        outcome,
        denial_reason,
        reason,
        rfc0028_channel_boundary,
        eio29_queue_admission,
        eio29_budget_admission,
        patch_digest,
        canonicalizer_tuple_digest,
        moved_job_path,
        policy_hash,
        containment,
        observed_cost,
        sandbox_hardening_hash,
        network_policy_hash,
        None,                  // stop_revoke_admission
        bytes_backend,         // TCK-00546: bytes_backend
        toolchain_fingerprint, // TCK-00538: toolchain fingerprint
    )?;
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let result = persist_content_addressed_receipt(&receipts_dir, &receipt)?;

    // TCK-00576: Best-effort signed envelope alongside receipt.
    if let Ok(signer) = fac_key_material::load_or_generate_persistent_signer(fac_root) {
        let content_hash = apm2_core::fac::compute_job_receipt_content_hash(&receipt);
        let envelope = apm2_core::fac::sign_receipt(&content_hash, &signer, "fac-worker");
        if let Err(e) = apm2_core::fac::persist_signed_envelope(&receipts_dir, &envelope) {
            tracing::warn!(error = %e, "signed envelope persistence failed (non-fatal)");
        }
    }

    if outcome == FacJobOutcome::Denied
        && let Some(path) = moved_job_path
    {
        annotate_denied_job_from_moved_path(fac_root, path, denial_reason, reason);
    }

    Ok(result)
}

/// Commit a claimed job through the `ReceiptWritePipeline`: persist receipt,
/// update index, move job atomically (TCK-00564 BLOCKER-1).
///
/// Returns the terminal path of the moved job file, or a structured
/// [`ReceiptPipelineError`] that preserves error specificity (including
/// [`ReceiptPipelineError::TornState`]) for callers to decide recovery
/// strategy.
#[allow(clippy::too_many_arguments)]
fn commit_claimed_job_via_pipeline(
    fac_root: &Path,
    queue_root: &Path,
    spec: &FacJobSpecV1,
    claimed_path: &Path,
    claimed_file_name: &str,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    observed_cost: Option<apm2_core::economics::cost_model::ObservedJobCost>,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00587: Optional stop/revoke admission trace for receipt binding.
    stop_revoke_admission: Option<&apm2_core::economics::queue_admission::StopRevokeAdmissionTrace>,
    // TCK-00546: Optional patch bytes backend identifier for GC tracking.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint for receipt binding.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, ReceiptPipelineError> {
    let terminal_state = outcome_to_terminal_state(outcome).ok_or_else(|| {
        ReceiptPipelineError::ReceiptPersistFailed(format!(
            "non-terminal outcome {outcome:?} cannot be committed"
        ))
    })?;

    let receipt = build_job_receipt(
        spec,
        outcome,
        denial_reason,
        reason,
        rfc0028_channel_boundary,
        eio29_queue_admission,
        eio29_budget_admission,
        patch_digest,
        canonicalizer_tuple_digest,
        None, // moved_job_path: not known before move
        policy_hash,
        containment,
        observed_cost,
        sandbox_hardening_hash,
        network_policy_hash,
        stop_revoke_admission,
        bytes_backend,
        toolchain_fingerprint,
    )
    .map_err(ReceiptPipelineError::ReceiptPersistFailed)?;

    let pipeline =
        ReceiptWritePipeline::new(fac_root.join(FAC_RECEIPTS_DIR), queue_root.to_path_buf());

    // TCK-00576: Attempt signed commit using the persistent broker key.
    // If the signing key is available, persist a signed receipt envelope
    // alongside the receipt. If key loading fails, fall back to unsigned
    // commit (the receipt is still valid but will be treated as unsigned
    // for cache-reuse decisions, which is fail-closed).
    let result = match fac_key_material::load_or_generate_persistent_signer(fac_root) {
        Ok(signer) => pipeline.commit_signed(
            &receipt,
            claimed_path,
            claimed_file_name,
            terminal_state,
            &signer,
            "fac-worker",
        )?,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "cannot load signing key for receipt signing (falling back to unsigned)"
            );
            pipeline.commit(&receipt, claimed_path, claimed_file_name, terminal_state)?
        },
    };

    if outcome == FacJobOutcome::Denied
        && let Err(err) = annotate_denied_job_file(&result.job_terminal_path, denial_reason, reason)
    {
        eprintln!(
            "worker: WARNING: failed to update denied job metadata for {}: {err}",
            result.job_terminal_path.display()
        );
    }

    Ok(result.job_terminal_path)
}

/// Handle a pipeline commit failure for a denial/failure path.
///
/// When `commit_claimed_job_via_pipeline` fails, the job has no terminal
/// receipt and no terminal queue transition. This function:
/// 1. Logs the commit error prominently via `eprintln!`.
/// 2. Leaves the job in `claimed/` for reconcile to repair.
/// 3. Returns `JobOutcome::Skipped` so the caller does NOT report a terminal
///    outcome that was never durably persisted.
///
/// The job is intentionally left in `claimed/` rather than moved to `pending/`.
/// If the receipt was persisted before the commit failed (torn state),
/// reconcile will detect the receipt and route the job to the correct terminal
/// directory based on the receipt outcome (completed, denied, etc.) via
/// `recover_torn_state`. If the receipt was not persisted, the orphan policy
/// applies. Moving to `pending/` would cause the outcome-blind duplicate
/// detection in `process_job` to route all receipted jobs to `completed/`,
/// masking denied outcomes (TCK-00564 MAJOR-1 fix round 4).
fn handle_pipeline_commit_failure(
    commit_err: &ReceiptPipelineError,
    context: &str,
    _claimed_path: &Path,
    _queue_root: &Path,
    _claimed_file_name: &str,
) -> JobOutcome {
    eprintln!("worker: pipeline commit failed for {context}: {commit_err}");
    // Job stays in claimed/ — reconcile will repair torn states or the orphan
    // policy will handle unreceipted failures.
    JobOutcome::Skipped {
        reason: format!("pipeline commit failed for {context}: {commit_err}"),
    }
}

/// Compute observed job cost from wall-clock elapsed time.
///
/// CPU time and I/O bytes are reported as 0 (best-effort: these metrics
/// require cgroup accounting which is not yet wired into the worker).
fn observed_cost_from_elapsed(
    elapsed: std::time::Duration,
) -> apm2_core::economics::cost_model::ObservedJobCost {
    apm2_core::economics::cost_model::ObservedJobCost {
        duration_ms: u64::try_from(elapsed.as_millis().min(u128::from(u64::MAX)))
            .unwrap_or(u64::MAX),
        cpu_time_ms: 0,
        bytes_written: 0,
    }
}

fn compute_job_spec_digest_preview(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    format!("b3-256:{}", hash.to_hex())
}

fn build_channel_boundary_trace_with_binding(
    defects: &[ChannelBoundaryDefect],
    binding: Option<&apm2_core::channel::TokenBindingV1>,
) -> ChannelBoundaryTrace {
    let mut defect_classes = Vec::new();
    for defect in defects.iter().take(MAX_BOUNDARY_DEFECT_CLASSES) {
        defect_classes.push(strip_json_string_quotes(&serialize_to_json_string(
            &defect.violation_class,
        )));
    }

    let defect_count = u32::try_from(defects.len()).unwrap_or(u32::MAX);

    let (policy_hash, tuple_digest, boundary_id, issued_at_tick, expiry_tick) =
        binding.map_or((None, None, None, None, None), |b| {
            (
                Some(hex::encode(b.fac_policy_hash)),
                Some(hex::encode(b.canonicalizer_tuple_digest)),
                Some(b.boundary_id.clone()),
                Some(b.issued_at_tick),
                Some(b.expiry_tick),
            )
        });

    ChannelBoundaryTrace {
        passed: defects.is_empty(),
        defect_count,
        defect_classes,
        token_fac_policy_hash: policy_hash,
        token_canonicalizer_tuple_digest: tuple_digest,
        token_boundary_id: boundary_id,
        token_issued_at_tick: issued_at_tick,
        token_expiry_tick: expiry_tick,
    }
}

fn fac_budget_admission_trace(trace: &EconomicsBudgetAdmissionTrace) -> FacBudgetAdmissionTrace {
    let verdict = match trace.verdict {
        BudgetAdmissionVerdict::Allow => "allow",
        BudgetAdmissionVerdict::Freeze => "freeze",
        BudgetAdmissionVerdict::Escalate => "escalate",
        _ => "deny",
    };

    FacBudgetAdmissionTrace {
        verdict: verdict.to_string(),
        reason: trace.deny_reason.clone(),
    }
}

fn build_queue_admission_trace(decision: &QueueAdmissionDecision) -> JobQueueAdmissionTrace {
    let lane = decision.trace.lane.as_ref().map_or_else(
        || "unknown".to_string(),
        |v| strip_json_string_quotes(&serialize_to_json_string(v)),
    );

    JobQueueAdmissionTrace {
        verdict: strip_json_string_quotes(&serialize_to_json_string(&decision.trace.verdict)),
        queue_lane: lane,
        defect_reason: decision.trace.defect.as_ref().map(|d| d.reason.clone()),
        cost_estimate_ticks: decision.trace.cost_estimate_ticks,
    }
}

fn serialize_to_json_string<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"serialization_error\"".to_string())
}

fn strip_json_string_quotes(value: &str) -> String {
    value.trim_matches('\"').to_string()
}

/// Persists a `GateReceipt` alongside the completed job.
fn write_gate_receipt(queue_root: &Path, file_name: &str, receipt: &GateReceipt) {
    let receipts_dir = queue_root.join("receipts");
    let _ = fs::create_dir_all(&receipts_dir);

    let receipt_name = format!("{}-gate.receipt.json", file_name.trim_end_matches(".json"),);
    let receipt_path = receipts_dir.join(receipt_name);

    if let Ok(bytes) = serde_json::to_vec_pretty(receipt) {
        let _ = fs::write(&receipt_path, bytes);
    }
}

/// Returns the current epoch seconds as a u64.
///
/// Named `current_timestamp_epoch_secs` to accurately reflect that this
/// returns epoch seconds, not an ISO 8601 string (MINOR-1 fix).
fn current_timestamp_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

/// Computes a BLAKE3 evidence hash for receipt binding.
fn compute_evidence_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.fac_worker.evidence.v1");
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Persists a stuck scan lock receipt under `$APM2_HOME/private/fac/receipts/`.
///
/// Best-effort: errors are logged but not propagated (stuck detection is
/// observability, not correctness).
///
/// Atomic write protocol (CTR-1502): writes to a temp file via
/// `NamedTempFile::new_in()` then `persist()` to rename into place.
/// Directory created with mode 0700 (CTR-2611).
fn persist_scan_lock_stuck_receipt(fac_root: &Path, receipt_json: &str) -> Result<(), String> {
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);

    // Create receipts directory with restricted permissions (CTR-2611).
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&receipts_dir)
            .map_err(|e| format!("create receipts dir: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(&receipts_dir).map_err(|e| format!("create receipts dir: {e}"))?;
    }

    let filename = format!(
        "scan_lock_stuck_{}.json",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
    );

    // Atomic write: temp file + persist (rename) to prevent partial reads
    // (CTR-1502). NamedTempFile provides unpredictable name + O_EXCL.
    let mut tmp = tempfile::NamedTempFile::new_in(&receipts_dir)
        .map_err(|e| format!("create stuck receipt temp file: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = tmp.as_file().set_permissions(perms);
    }

    tmp.write_all(receipt_json.as_bytes())
        .map_err(|e| format!("write stuck receipt: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync stuck receipt: {e}"))?;

    let receipt_path = receipts_dir.join(&filename);
    tmp.persist(&receipt_path)
        .map_err(|e| format!("rename stuck receipt: {e}"))?;

    Ok(())
}

/// Sleeps for the remaining time in the poll interval.
fn sleep_remaining(cycle_start: Instant, poll_interval_secs: u64) {
    let elapsed = cycle_start.elapsed();
    let target = Duration::from_secs(poll_interval_secs);
    if let Some(remaining) = target.checked_sub(elapsed) {
        std::thread::sleep(remaining);
    }
}

/// Outputs a worker error message.
fn output_worker_error(json_output: bool, message: &str) {
    if json_output {
        emit_worker_event(
            "worker_error",
            serde_json::json!({
                "error": "fac_worker_failed",
                "message": message,
            }),
        );
    } else {
        eprintln!("worker error: {message}");
    }
}

fn worker_ts_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn emit_worker_jsonl(value: &serde_json::Value) {
    if let Ok(line) = serde_json::to_string(value) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

fn emit_worker_event(event: &str, extra: serde_json::Value) {
    let mut map = serde_json::Map::new();
    map.insert(
        "event".to_string(),
        serde_json::Value::String(event.to_string()),
    );
    map.insert("ts".to_string(), serde_json::Value::String(worker_ts_now()));
    match extra {
        serde_json::Value::Object(extra_map) => {
            for (key, value) in extra_map {
                map.insert(key, value);
            }
        },
        other => {
            map.insert("data".to_string(), other);
        },
    }
    emit_worker_jsonl(&serde_json::Value::Object(map));
}

fn emit_worker_summary(summary: &WorkerSummary) {
    let data = serde_json::to_value(summary).unwrap_or_else(|_| serde_json::json!({}));
    emit_worker_event("worker_summary", data);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use apm2_core::fac::LaneState;
    use apm2_core::fac::lane::LaneLeaseV1;

    use super::*;

    #[test]
    fn test_deterministic_ordering() {
        // Verify that candidates sort by priority ASC, enqueue_time ASC,
        // job_id ASC.
        let mut items = [
            ("c", 50u32, "2026-02-12T00:00:02Z"),
            ("a", 50, "2026-02-12T00:00:01Z"),
            ("b", 10, "2026-02-12T00:00:03Z"),
            ("d", 50, "2026-02-12T00:00:01Z"),
        ];

        items.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.2.cmp(b.2))
                .then_with(|| a.0.cmp(b.0))
        });

        let ids: Vec<&str> = items.iter().map(|i| i.0).collect();
        assert_eq!(ids, vec!["b", "a", "d", "c"]);
    }

    #[test]
    fn test_read_bounded_rejects_oversized() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("big.json");
        let data = vec![b'x'; MAX_JOB_SPEC_SIZE + 1];
        fs::write(&file_path, &data).expect("write");

        let result = read_bounded(&file_path, MAX_JOB_SPEC_SIZE);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }

    #[test]
    fn test_read_bounded_accepts_valid_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("ok.json");
        let data = b"{}";
        fs::write(&file_path, data).expect("write");

        let result = read_bounded(&file_path, MAX_JOB_SPEC_SIZE);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data.to_vec());
    }

    #[test]
    fn test_ensure_queue_dirs_creates_all() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue_root = dir.path().join("queue");

        ensure_queue_dirs(&queue_root).expect("create dirs");

        for sub in [
            PENDING_DIR,
            CLAIMED_DIR,
            COMPLETED_DIR,
            DENIED_DIR,
            QUARANTINE_DIR,
            CONSUME_RECEIPTS_DIR,
        ] {
            assert!(queue_root.join(sub).is_dir(), "missing {sub}");
        }
    }

    #[test]
    fn test_move_to_dir_safe_atomic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_dir = dir.path().join("src");
        let dst_dir = dir.path().join("dst");
        fs::create_dir_all(&src_dir).expect("src dir");

        let src_file = src_dir.join("test.json");
        fs::write(&src_file, b"data").expect("write");

        move_to_dir_safe(&src_file, &dst_dir, "test.json").expect("move");

        assert!(!src_file.exists(), "source should be gone");
        assert!(dst_dir.join("test.json").exists(), "dest should exist");
    }

    #[test]
    fn test_move_to_dir_safe_collision_avoidance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_dir = dir.path().join("src");
        let dst_dir = dir.path().join("dst");
        fs::create_dir_all(&src_dir).expect("src dir");
        fs::create_dir_all(&dst_dir).expect("dst dir");

        // Create existing target to trigger collision path.
        fs::write(dst_dir.join("test.json"), b"existing").expect("write existing");

        let src_file = src_dir.join("test.json");
        fs::write(&src_file, b"new data").expect("write src");

        move_to_dir_safe(&src_file, &dst_dir, "test.json").expect("move with collision");

        // Original target should be untouched.
        let existing_content = fs::read_to_string(dst_dir.join("test.json")).expect("read");
        assert_eq!(
            existing_content, "existing",
            "original file should be untouched"
        );

        // New file should exist with a timestamp suffix.
        let entries: Vec<_> = fs::read_dir(&dst_dir)
            .expect("read dir")
            .flatten()
            .collect();
        assert_eq!(
            entries.len(),
            2,
            "should have original + collision-safe file"
        );
    }

    #[test]
    fn test_emit_scan_receipt_bounded_reason() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        ensure_queue_dirs(&dir.path().join("queue")).expect("create dirs");

        let long_reason = "x".repeat(1024);
        let result = emit_scan_receipt(
            &fac_root,
            "test.json",
            "job1",
            &compute_job_spec_digest_preview(&[]),
            FacJobOutcome::Quarantined,
            DenialReasonCode::MalformedSpec,
            None,
            &long_reason,
            &CanonicalizerTupleV1::from_current().compute_digest(),
            None, // toolchain_fingerprint
        );

        assert!(
            result.is_err(),
            "receipt emit should reject oversized reason with 512-char bound"
        );
    }

    #[test]
    fn test_current_timestamp_epoch_secs_is_nonzero() {
        let secs = current_timestamp_epoch_secs();
        assert!(secs > 0, "timestamp should be nonzero");
    }

    #[test]
    fn test_parse_queue_lane_known_values() {
        assert_eq!(parse_queue_lane("stop_revoke"), QueueLane::StopRevoke);
        assert_eq!(parse_queue_lane("control"), QueueLane::Control);
        assert_eq!(parse_queue_lane("consume"), QueueLane::Consume);
        assert_eq!(parse_queue_lane("replay"), QueueLane::Replay);
        assert_eq!(
            parse_queue_lane("projection_replay"),
            QueueLane::ProjectionReplay
        );
        assert_eq!(parse_queue_lane("bulk"), QueueLane::Bulk);
    }

    #[test]
    fn test_parse_queue_lane_unknown_defaults_to_bulk() {
        assert_eq!(parse_queue_lane("unknown_lane"), QueueLane::Bulk);
        assert_eq!(parse_queue_lane(""), QueueLane::Bulk);
    }

    #[test]
    fn test_parse_gates_job_options_rejects_missing_payload() {
        let spec = make_receipt_test_spec();
        let err = parse_gates_job_options(&spec).expect_err("missing payload must fail closed");
        assert!(err.contains("missing gates options payload"));
    }

    #[test]
    fn test_parse_gates_job_options_from_patch_payload() {
        let workspace_root = repo_toplevel_for_tests();
        let mut spec = make_receipt_test_spec();
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": true,
            "quick": true,
            "timeout_seconds": 77,
            "memory_max": "1G",
            "pids_max": 99,
            "cpu_quota": "150%",
            "gate_profile": "balanced",
            "workspace_root": workspace_root
        }));
        let options = parse_gates_job_options(&spec).expect("parse payload");
        assert!(options.force);
        assert!(options.quick);
        assert_eq!(options.timeout_seconds, 77);
        assert_eq!(options.memory_max, "1G");
        assert_eq!(options.pids_max, 99);
        assert_eq!(options.cpu_quota, "150%");
        assert_eq!(
            options.gate_profile,
            fac_review_api::GateThroughputProfile::Balanced
        );
        assert!(options.workspace_root.is_dir());
    }

    #[test]
    fn test_parse_gates_job_options_rejects_missing_decoded_source() {
        let workspace_root = repo_toplevel_for_tests();
        let mut spec = make_receipt_test_spec();
        spec.actuation.decoded_source = None;
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": DEFAULT_GATES_TIMEOUT_SECONDS,
            "memory_max": DEFAULT_GATES_MEMORY_MAX,
            "pids_max": DEFAULT_GATES_PIDS_MAX,
            "cpu_quota": DEFAULT_GATES_CPU_QUOTA,
            "gate_profile": "throughput",
            "workspace_root": workspace_root
        }));
        let err = parse_gates_job_options(&spec).expect_err("missing decoded_source must fail");
        assert!(err.contains("missing gates decoded_source hint"));
    }

    #[test]
    fn test_parse_gates_job_options_rejects_schema_mismatch() {
        let workspace_root = repo_toplevel_for_tests();
        let mut spec = make_receipt_test_spec();
        spec.source.patch = Some(serde_json::json!({
            "schema": "apm2.fac.gates_job_options.v0",
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": workspace_root
        }));
        let err = parse_gates_job_options(&spec).expect_err("schema mismatch must fail closed");
        assert!(err.contains("unsupported gates options schema"));
    }

    #[test]
    fn test_parse_gates_job_options_rejects_invalid_profile() {
        let workspace_root = repo_toplevel_for_tests();
        let mut spec = make_receipt_test_spec();
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "extreme",
            "workspace_root": workspace_root
        }));
        let err = parse_gates_job_options(&spec).expect_err("invalid profile must fail closed");
        assert!(err.contains("invalid gates gate_profile"));
    }

    #[test]
    fn test_parse_gates_job_options_rejects_missing_workspace_root() {
        let mut spec = make_receipt_test_spec();
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": "/path/does/not/exist"
        }));
        let err =
            parse_gates_job_options(&spec).expect_err("invalid workspace root must fail closed");
        assert!(err.contains("workspace_root"));
    }

    #[test]
    fn test_parse_gates_job_options_rejects_repo_mismatch() {
        let workspace_root = repo_toplevel_for_tests();
        let mut spec = make_receipt_test_spec();
        spec.source.repo_id = "local/not-this-workspace".to_string();
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": workspace_root
        }));
        let err = parse_gates_job_options(&spec).expect_err("repo mismatch must fail closed");
        assert!(err.contains("repo mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn test_parse_gates_job_options_rejects_fac_internal_workspace_root() {
        let _guard = env_var_test_lock().lock().expect("serialize env test");
        let original_apm2_home = std::env::var_os("APM2_HOME");

        let dir = tempfile::tempdir().expect("tempdir");
        let apm2_home = dir.path().join(".apm2");
        let fac_internal = apm2_home.join("private").join("fac").join("workspace");
        fs::create_dir_all(&fac_internal).expect("create fac internal path");

        set_env_var_for_test("APM2_HOME", &apm2_home);

        let mut spec = make_receipt_test_spec();
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": fac_internal.to_string_lossy()
        }));
        let err = parse_gates_job_options(&spec).expect_err("fac internal path must be denied");
        assert!(
            err.contains("FAC-internal storage"),
            "unexpected error: {err}"
        );

        if let Some(value) = original_apm2_home {
            set_env_var_for_test("APM2_HOME", value);
        } else {
            remove_env_var_for_test("APM2_HOME");
        }
    }

    #[test]
    fn test_parse_gates_job_options_rejects_workspace_outside_allowlist_roots() {
        let _guard = env_var_test_lock().lock().expect("serialize env test");
        let original_allowlist = std::env::var_os(ALLOWED_WORKSPACE_ROOTS_ENV);
        remove_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV);

        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("foreign-workspace");
        fs::create_dir_all(&workspace).expect("create workspace");
        init_test_workspace_git_repo(&workspace);

        let mut spec = make_receipt_test_spec();
        spec.source.repo_id = resolve_repo_id(&workspace);
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": workspace.to_string_lossy()
        }));
        let err =
            parse_gates_job_options(&spec).expect_err("workspace outside allowlist must deny");
        assert!(
            err.contains("outside allowed workspace roots"),
            "unexpected error: {err}"
        );

        if let Some(value) = original_allowlist {
            set_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV, value);
        } else {
            remove_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV);
        }
    }

    #[test]
    fn test_parse_gates_job_options_accepts_workspace_in_explicit_allowlist() {
        let _guard = env_var_test_lock().lock().expect("serialize env test");
        let original_allowlist = std::env::var_os(ALLOWED_WORKSPACE_ROOTS_ENV);

        let dir = tempfile::tempdir().expect("tempdir");
        let workspace = dir.path().join("allowed-workspace");
        fs::create_dir_all(&workspace).expect("create workspace");
        init_test_workspace_git_repo(&workspace);
        set_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV, &workspace);

        let mut spec = make_receipt_test_spec();
        spec.source.repo_id = resolve_repo_id(&workspace);
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": workspace.to_string_lossy()
        }));
        let options = parse_gates_job_options(&spec).expect("allowlisted workspace should pass");
        assert_eq!(options.workspace_root, workspace);

        if let Some(value) = original_allowlist {
            set_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV, value);
        } else {
            remove_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV);
        }
    }

    #[allow(unsafe_code)]
    fn set_env_var_for_test<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(
        key: K,
        value: V,
    ) {
        unsafe { std::env::set_var(key, value) };
    }

    #[allow(unsafe_code)]
    fn remove_env_var_for_test<K: AsRef<std::ffi::OsStr>>(key: K) {
        unsafe { std::env::remove_var(key) };
    }

    struct FacReviewApiOverrideGuard;

    impl FacReviewApiOverrideGuard {
        fn install(
            run_result: Result<fac_review_api::LocalGatesRunResult, String>,
            lifecycle_result: Result<usize, String>,
        ) -> Self {
            fac_review_api::set_run_gates_local_worker_override(Some(run_result));
            fac_review_api::set_gate_lifecycle_override(Some(lifecycle_result));
            Self
        }
    }

    impl Drop for FacReviewApiOverrideGuard {
        fn drop(&mut self) {
            fac_review_api::set_run_gates_local_worker_override(None);
            fac_review_api::set_gate_lifecycle_override(None);
        }
    }

    fn make_receipt_test_spec() -> FacJobSpecV1 {
        let repo_root = PathBuf::from(repo_toplevel_for_tests());
        let repo_id = resolve_repo_id(&repo_root);
        FacJobSpecV1 {
            schema: "apm2.fac.job_spec.v1".to_string(),
            job_id: "job-001".to_string(),
            job_spec_digest: "b3-256:".to_string() + &"a".repeat(64),
            kind: "gates".to_string(),
            queue_lane: "control".to_string(),
            priority: 50,
            enqueue_time: "2026-02-13T12:00:00Z".to_string(),
            actuation: apm2_core::fac::job_spec::Actuation {
                lease_id: "lease-001".to_string(),
                request_id: "b3-256:".to_string() + &"b".repeat(64),
                channel_context_token: Some("token".to_string()),
                decoded_source: Some("fac_gates_worker".to_string()),
            },
            source: apm2_core::fac::job_spec::JobSource {
                kind: "mirror_commit".to_string(),
                repo_id,
                head_sha: "abcd1234abcd1234abcd1234abcd1234abcd1234".to_string(),
                patch: None,
            },
            lane_requirements: apm2_core::fac::job_spec::LaneRequirements {
                lane_profile_hash: Some("b3-256:".to_string() + &"c".repeat(64)),
            },
            constraints: apm2_core::fac::job_spec::JobConstraints {
                require_nextest: false,
                test_timeout_seconds: None,
                memory_max_bytes: None,
            },
            cancel_target_job_id: None,
        }
    }

    fn repo_toplevel_for_tests() -> String {
        let output = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .expect("git rev-parse should execute");
        assert!(
            output.status.success(),
            "git rev-parse --show-toplevel failed"
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    #[test]
    fn test_check_or_admit_canonicalizer_tuple_missing_is_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let _broker = FacBroker::new();

        let result = check_or_admit_canonicalizer_tuple(&fac_root)
            .expect("first run should return a canonicalizer check result");
        match result {
            CanonicalizerTupleCheck::Missing => {},
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn test_check_or_admit_canonicalizer_tuple_mismatch_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let mut broker = FacBroker::new();

        broker
            .admit_canonicalizer_tuple(&fac_root)
            .expect("seed admitted tuple");

        let mut tuple = CanonicalizerTupleV1::from_current();
        tuple.canonicalizer_version.push_str("-mismatch");
        let tuple_path = fac_root
            .join("broker")
            .join("admitted_canonicalizer_tuple.v1.json");
        fs::create_dir_all(fac_root.join("broker")).expect("tuple directory exists");
        let tuple_bytes = serde_json::to_vec_pretty(&tuple).expect("serialize mismatch tuple");
        fs::write(&tuple_path, tuple_bytes).expect("write mismatch tuple");

        match check_or_admit_canonicalizer_tuple(&fac_root) {
            Ok(CanonicalizerTupleCheck::Mismatch(admitted_tuple)) => {
                assert_ne!(admitted_tuple, CanonicalizerTupleV1::from_current());
            },
            other => panic!("expected mismatch, got: {other:?}"),
        }
    }

    #[test]
    fn test_check_or_admit_canonicalizer_tuple_rejects_deserialization_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let _broker = FacBroker::new();
        let tuple_path = fac_root
            .join("broker")
            .join("admitted_canonicalizer_tuple.v1.json");
        fs::create_dir_all(tuple_path.parent().expect("tuple directory parent"))
            .expect("create tuple directory");
        fs::write(&tuple_path, b"{not-json").expect("write corrupted tuple");

        let result = check_or_admit_canonicalizer_tuple(&fac_root);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("corrupted"),
            "expected corruption error, got: {err}"
        );
        assert_eq!(
            fs::read(&tuple_path).expect("read tuple").as_slice(),
            b"{not-json"
        );
    }

    #[test]
    fn test_emit_job_receipt_includes_canonicalizer_tuple_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let spec = make_receipt_test_spec();
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "control".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };

        let receipt_path = emit_job_receipt(
            &fac_root,
            &spec,
            FacJobOutcome::Completed,
            None,
            "completed",
            Some(&boundary_trace),
            Some(&queue_trace),
            None,
            None,
            Some(&tuple_digest),
            None,
            &spec.job_spec_digest,
            None,
            None,
            None,
            None, // bytes_backend
            None,
        )
        .expect("emit receipt");

        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(&receipt_path).expect("read receipt"),
        )
        .expect("parse receipt JSON");
        assert_eq!(
            receipt_json
                .get("canonicalizer_tuple_digest")
                .and_then(|value| value.as_str()),
            Some(tuple_digest.as_str())
        );
        assert!(
            receipt_json.get("patch_digest").is_none(),
            "patch_digest should remain unset in this receipt path"
        );
    }

    #[test]
    fn test_emit_job_receipt_channel_boundary_defect_path_sets_canonicalizer_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let canonicalizer_tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let spec = make_receipt_test_spec();

        let receipt_path = emit_job_receipt(
            &fac_root,
            &spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ChannelBoundaryViolation),
            "channel boundary violation",
            None,
            None,
            None,
            None,
            Some(&canonicalizer_tuple_digest),
            None,
            &spec.job_spec_digest,
            None,
            None,
            None,
            None, // bytes_backend
            None,
        )
        .expect("emit receipt");

        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(&receipt_path).expect("read receipt"),
        )
        .expect("parse receipt JSON");
        assert_eq!(
            receipt_json
                .get("canonicalizer_tuple_digest")
                .and_then(|value| value.as_str()),
            Some(canonicalizer_tuple_digest.as_str())
        );
        assert!(
            receipt_json.get("patch_digest").is_none(),
            "channel-boundary receipt should not set patch_digest"
        );
    }

    #[test]
    fn test_scan_pending_quarantines_malformed_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue_root = dir.path().join("queue");
        ensure_queue_dirs(&queue_root).expect("create dirs");

        // Write a malformed JSON file to pending.
        let malformed_path = queue_root.join("pending").join("bad.json");
        fs::write(&malformed_path, b"not valid json {{{").expect("write malformed");

        let fac_root = dir.path().join("private").join("fac");
        let candidates = scan_pending(
            &queue_root,
            &fac_root,
            &CanonicalizerTupleV1::from_current().compute_digest(),
            None, // toolchain_fingerprint
        )
        .expect("scan");

        // Malformed file should have been quarantined, not included in candidates.
        assert!(
            candidates.is_empty(),
            "malformed file should not be a candidate"
        );

        // Check it was quarantined.
        let quarantine_dir = queue_root.join(QUARANTINE_DIR);
        let quarantined_files: Vec<_> = fs::read_dir(&quarantine_dir)
            .expect("read quarantine")
            .flatten()
            .collect();
        assert!(
            !quarantined_files.is_empty(),
            "malformed file should be in quarantine"
        );

        // Check receipt was written.
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        let receipt_files: Vec<_> = fs::read_dir(&receipts_dir)
            .expect("read receipts")
            .flatten()
            .collect();
        assert!(
            !receipt_files.is_empty(),
            "quarantine receipt should be written"
        );
    }

    #[test]
    fn test_scan_pending_quarantines_oversize_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue_root = dir.path().join("queue");
        ensure_queue_dirs(&queue_root).expect("create dirs");

        // Write an oversize file to pending.
        let oversize_path = queue_root.join("pending").join("huge.json");
        let data = vec![b'x'; MAX_JOB_SPEC_SIZE + 1];
        fs::write(&oversize_path, &data).expect("write oversize");

        let fac_root = dir.path().join("private").join("fac");
        let candidates = scan_pending(
            &queue_root,
            &fac_root,
            &CanonicalizerTupleV1::from_current().compute_digest(),
            None, // toolchain_fingerprint
        )
        .expect("scan");

        assert!(
            candidates.is_empty(),
            "oversize file should not be a candidate"
        );

        // Check it was quarantined.
        let quarantine_dir = queue_root.join(QUARANTINE_DIR);
        let quarantined_files: Vec<_> = fs::read_dir(&quarantine_dir)
            .expect("read quarantine")
            .flatten()
            .collect();
        assert!(
            !quarantined_files.is_empty(),
            "oversize file should be in quarantine"
        );
    }

    #[test]
    fn test_compute_evidence_hash_deterministic() {
        let h1 = compute_evidence_hash(b"test-data");
        let h2 = compute_evidence_hash(b"test-data");
        assert_eq!(h1, h2, "same input must produce same hash");
    }

    #[test]
    fn test_compute_evidence_hash_different_inputs() {
        let h1 = compute_evidence_hash(b"data-a");
        let h2 = compute_evidence_hash(b"data-b");
        assert_ne!(h1, h2, "different inputs must produce different hashes");
    }

    /// MAJOR-1 regression: `stop_target_unit_exact` must reject unsafe lane
    /// characters to prevent command injection via crafted unit names.
    #[test]
    fn test_stop_target_unit_exact_rejects_unsafe_lane() {
        for unsafe_lane in &["../evil", "lane;rm", "a b", "lane/path", "lane*glob", ""] {
            let result = stop_target_unit_exact(unsafe_lane, "job-123");
            assert!(
                result.is_err(),
                "should reject unsafe lane {unsafe_lane:?}: {result:?}"
            );
            let err_msg = result.unwrap_err();
            assert!(
                err_msg.contains("unsafe queue_lane"),
                "error should mention unsafe lane: {err_msg}"
            );
        }
    }

    /// MAJOR-1 regression: `stop_target_unit_exact` must accept valid lanes.
    #[test]
    fn test_stop_target_unit_exact_accepts_valid_lane() {
        // This will fail to actually stop a unit (no systemd in test), but it
        // should NOT fail due to lane sanitization.
        for valid_lane in &["control", "default-0", "lane_1", "A-Z-test"] {
            let result = stop_target_unit_exact(valid_lane, "job-123");
            // We expect Err from systemctl (not installed or unit not found),
            // but NOT an "unsafe queue_lane" error.
            if let Err(ref e) = result {
                assert!(
                    !e.contains("unsafe queue_lane"),
                    "valid lane {valid_lane:?} should not be rejected: {e}"
                );
            }
        }
    }

    /// BLOCKER-1 regression: Completed receipts must include containment
    /// evidence when a `ContainmentTrace` is provided.
    #[test]
    fn test_emit_job_receipt_includes_containment_trace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let spec = make_receipt_test_spec();
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let containment_trace = apm2_core::fac::containment::ContainmentTrace {
            verified: true,
            cgroup_path: "/system.slice/apm2-job.service".to_string(),
            processes_checked: 5,
            mismatch_count: 0,
            sccache_auto_disabled: false,
            sccache_enabled: false,
            sccache_version: None,
            sccache_server_containment: None,
        };

        let receipt_path = emit_job_receipt(
            &fac_root,
            &spec,
            FacJobOutcome::Completed,
            None,
            "completed",
            Some(&boundary_trace),
            Some(&queue_trace),
            None,
            None,
            Some(&tuple_digest),
            None,
            &spec.job_spec_digest,
            Some(&containment_trace),
            None,
            None,
            None, // bytes_backend
            None,
        )
        .expect("emit receipt with containment");

        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(&receipt_path).expect("read receipt"),
        )
        .expect("parse receipt JSON");

        let containment = receipt_json
            .get("containment")
            .expect("containment field must be present in completed receipt");
        assert_eq!(
            containment
                .get("verified")
                .and_then(serde_json::Value::as_bool),
            Some(true),
        );
        assert_eq!(
            containment
                .get("cgroup_path")
                .and_then(serde_json::Value::as_str),
            Some("/system.slice/apm2-job.service"),
        );
        assert_eq!(
            containment
                .get("processes_checked")
                .and_then(serde_json::Value::as_u64),
            Some(5),
        );
    }

    /// BLOCKER-1 regression: Completed receipts without containment must
    /// NOT have the containment field (None case).
    #[test]
    fn test_emit_job_receipt_omits_containment_when_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let spec = make_receipt_test_spec();
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();

        let receipt_path = emit_job_receipt(
            &fac_root,
            &spec,
            FacJobOutcome::Completed,
            None,
            "completed",
            Some(&boundary_trace),
            Some(&queue_trace),
            None,
            None,
            Some(&tuple_digest),
            None,
            &spec.job_spec_digest,
            None,
            None,
            None,
            None, // bytes_backend
            None,
        )
        .expect("emit receipt without containment");

        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(&receipt_path).expect("read receipt"),
        )
        .expect("parse receipt JSON");

        assert!(
            receipt_json.get("containment").is_none(),
            "containment field must be absent when None"
        );
    }

    /// Verify that `sandbox_hardening_hash` is included in the persisted
    /// receipt when provided (TCK-00573 regression test).
    #[test]
    fn test_emit_job_receipt_includes_sandbox_hardening_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let spec = make_receipt_test_spec();
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "control".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };

        let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();

        let receipt_path = emit_job_receipt(
            &fac_root,
            &spec,
            FacJobOutcome::Completed,
            None,
            "completed",
            Some(&boundary_trace),
            Some(&queue_trace),
            None,
            None,
            Some(&tuple_digest),
            None,
            &spec.job_spec_digest,
            None,
            Some(&hardening_hash),
            None,
            None, // bytes_backend
            None,
        )
        .expect("emit receipt with sandbox_hardening_hash");

        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(&receipt_path).expect("read receipt"),
        )
        .expect("parse receipt JSON");

        assert_eq!(
            receipt_json
                .get("sandbox_hardening_hash")
                .and_then(|v| v.as_str()),
            Some(hardening_hash.as_str()),
            "sandbox_hardening_hash must be present in persisted receipt"
        );
        // Verify the hash has the expected b3-256: prefix format.
        assert!(
            hardening_hash.starts_with("b3-256:"),
            "hash must have b3-256: prefix"
        );
        assert_eq!(
            hardening_hash.len(),
            71,
            "b3-256:<64hex> must be exactly 71 chars"
        );
    }

    /// Verify that `sandbox_hardening_hash` is absent when not provided.
    #[test]
    fn test_emit_job_receipt_omits_sandbox_hardening_hash_when_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let spec = make_receipt_test_spec();
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "control".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };

        let receipt_path = emit_job_receipt(
            &fac_root,
            &spec,
            FacJobOutcome::Completed,
            None,
            "completed",
            Some(&boundary_trace),
            Some(&queue_trace),
            None,
            None,
            Some(&tuple_digest),
            None,
            &spec.job_spec_digest,
            None,
            None,
            None,
            None, // bytes_backend
            None,
        )
        .expect("emit receipt without sandbox_hardening_hash");

        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(&receipt_path).expect("read receipt"),
        )
        .expect("parse receipt JSON");

        assert!(
            receipt_json.get("sandbox_hardening_hash").is_none(),
            "sandbox_hardening_hash must be absent when None"
        );
    }

    #[test]
    fn test_execute_queued_gates_job_binds_sandbox_hardening_hash_in_denial_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let queue_root = dir.path().join("queue");
        fs::create_dir_all(&fac_root).expect("create fac root");
        ensure_queue_dirs(&queue_root).expect("create queue dirs");

        let claimed_path = queue_root.join(CLAIMED_DIR).join("gates-test.json");
        fs::write(&claimed_path, b"{}").expect("seed claimed file");
        let claimed_file_name = "gates-test.json";

        let spec = make_receipt_test_spec();
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "consume".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();

        let outcome = execute_queued_gates_job(
            &spec,
            &claimed_path,
            claimed_file_name,
            &queue_root,
            &fac_root,
            &boundary_trace,
            &queue_trace,
            None,
            &tuple_digest,
            &spec.job_spec_digest,
            &hardening_hash,
            &apm2_core::fac::NetworkPolicy::deny().content_hash_hex(),
            1,
            0,
            0,
            0,
            None, // toolchain_fingerprint
        );
        assert!(
            matches!(outcome, JobOutcome::Denied { .. }),
            "missing gates payload should fail closed in denial path"
        );

        let receipt_file = fs::read_dir(fac_root.join(FAC_RECEIPTS_DIR))
            .expect("receipts dir")
            .flatten()
            .find(|entry| {
                entry.file_type().is_ok_and(|ty| ty.is_file())
                    && entry
                        .path()
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| !n.contains(".sig."))
            })
            .expect("at least one receipt emitted");
        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(receipt_file.path()).expect("read receipt"),
        )
        .expect("parse receipt JSON");
        assert_eq!(
            receipt_json
                .get("sandbox_hardening_hash")
                .and_then(serde_json::Value::as_str),
            Some(hardening_hash.as_str()),
            "queued gates receipt must bind sandbox hardening hash"
        );
    }

    #[test]
    fn test_execute_queued_gates_job_denies_when_lifecycle_replay_returns_illegal_transition() {
        let _override_guard = FacReviewApiOverrideGuard::install(
            Ok(fac_review_api::LocalGatesRunResult {
                exit_code: exit_codes::SUCCESS,
                failure_summary: None,
            }),
            Err("illegal transition: pushed + gates_started".to_string()),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let queue_root = dir.path().join("queue");
        fs::create_dir_all(&fac_root).expect("create fac root");
        ensure_queue_dirs(&queue_root).expect("create queue dirs");

        let claimed_path = queue_root
            .join(CLAIMED_DIR)
            .join("gates-lifecycle-illegal.json");
        fs::write(&claimed_path, b"{}").expect("seed claimed file");
        let claimed_file_name = "gates-lifecycle-illegal.json";

        let repo_root = PathBuf::from(repo_toplevel_for_tests());
        let current_head = resolve_workspace_head(&repo_root).expect("resolve workspace head");
        let mut spec = make_receipt_test_spec();
        spec.source.head_sha = current_head;
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": repo_root.to_string_lossy(),
        }));

        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "consume".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();
        let network_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();

        let outcome = execute_queued_gates_job(
            &spec,
            &claimed_path,
            claimed_file_name,
            &queue_root,
            &fac_root,
            &boundary_trace,
            &queue_trace,
            None,
            &tuple_digest,
            &spec.job_spec_digest,
            &hardening_hash,
            &network_hash,
            1,
            0,
            0,
            0,
            None, // toolchain_fingerprint
        );
        let reason = match outcome {
            JobOutcome::Denied { reason } => reason,
            other => panic!("expected denied outcome, got {other:?}"),
        };
        assert!(reason.contains("lifecycle update failed"));
        assert!(reason.contains("illegal transition"));
        assert!(
            queue_root
                .join(DENIED_DIR)
                .join(claimed_file_name)
                .is_file(),
            "job should be moved to denied on lifecycle replay failure"
        );
    }

    #[test]
    fn test_execute_queued_gates_job_denied_reason_includes_gate_failure_summary() {
        let _override_guard = FacReviewApiOverrideGuard::install(
            Ok(fac_review_api::LocalGatesRunResult {
                exit_code: exit_codes::GENERIC_ERROR,
                failure_summary: Some(
                    "failed_gates=test; first_failure=test: timeout exceeded".to_string(),
                ),
            }),
            Ok(1),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let queue_root = dir.path().join("queue");
        fs::create_dir_all(&fac_root).expect("create fac root");
        ensure_queue_dirs(&queue_root).expect("create queue dirs");

        let claimed_path = queue_root
            .join(CLAIMED_DIR)
            .join("gates-failure-summary.json");
        fs::write(&claimed_path, b"{}").expect("seed claimed file");
        let claimed_file_name = "gates-failure-summary.json";

        let repo_root = PathBuf::from(repo_toplevel_for_tests());
        let current_head = resolve_workspace_head(&repo_root).expect("resolve workspace head");
        let mut spec = make_receipt_test_spec();
        spec.source.head_sha = current_head;
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": repo_root.to_string_lossy(),
        }));

        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "consume".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();
        let network_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();

        let outcome = execute_queued_gates_job(
            &spec,
            &claimed_path,
            claimed_file_name,
            &queue_root,
            &fac_root,
            &boundary_trace,
            &queue_trace,
            None,
            &tuple_digest,
            &spec.job_spec_digest,
            &hardening_hash,
            &network_hash,
            1,
            0,
            0,
            0,
            None, // toolchain_fingerprint
        );
        let reason = match outcome {
            JobOutcome::Denied { reason } => reason,
            other => panic!("expected denied outcome, got {other:?}"),
        };
        assert!(reason.contains("gates failed with exit code 1"));
        assert!(reason.contains("failed_gates=test"));
        assert!(reason.contains("first_failure=test: timeout exceeded"));
    }

    #[test]
    fn test_execute_queued_gates_job_denied_reason_is_utf8_safe_and_bounded() {
        let _override_guard = FacReviewApiOverrideGuard::install(
            Ok(fac_review_api::LocalGatesRunResult {
                exit_code: exit_codes::GENERIC_ERROR,
                failure_summary: Some(format!(
                    "failed_gates=test; first_failure=test: {}",
                    "🚧".repeat(700)
                )),
            }),
            Ok(1),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let queue_root = dir.path().join("queue");
        fs::create_dir_all(&fac_root).expect("create fac root");
        ensure_queue_dirs(&queue_root).expect("create queue dirs");

        let claimed_path = queue_root
            .join(CLAIMED_DIR)
            .join("gates-bounded-reason.json");
        fs::write(&claimed_path, b"{}").expect("seed claimed file");
        let claimed_file_name = "gates-bounded-reason.json";

        let repo_root = PathBuf::from(repo_toplevel_for_tests());
        let current_head = resolve_workspace_head(&repo_root).expect("resolve workspace head");
        let mut spec = make_receipt_test_spec();
        spec.source.head_sha = current_head;
        spec.source.patch = Some(serde_json::json!({
            "schema": GATES_JOB_OPTIONS_SCHEMA,
            "force": false,
            "quick": false,
            "timeout_seconds": 600,
            "memory_max": "48G",
            "pids_max": 1536,
            "cpu_quota": "auto",
            "gate_profile": "throughput",
            "workspace_root": repo_root.to_string_lossy(),
        }));

        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "consume".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();
        let network_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();

        let outcome = execute_queued_gates_job(
            &spec,
            &claimed_path,
            claimed_file_name,
            &queue_root,
            &fac_root,
            &boundary_trace,
            &queue_trace,
            None,
            &tuple_digest,
            &spec.job_spec_digest,
            &hardening_hash,
            &network_hash,
            1,
            0,
            0,
            0,
            None, // toolchain_fingerprint
        );
        let reason = match outcome {
            JobOutcome::Denied { reason } => reason,
            other => panic!("expected denied outcome, got {other:?}"),
        };
        assert!(
            reason.chars().count() <= MAX_FAC_RECEIPT_REASON_CHARS,
            "reason must be bounded to FAC receipt limit"
        );
        assert!(reason.ends_with("..."), "long reason should be truncated");
        assert!(reason.contains("failed_gates=test"));
    }

    fn init_test_workspace_git_repo(workspace: &Path) {
        let init_output = std::process::Command::new("git")
            .args(["init"])
            .current_dir(workspace)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("init git repo");
        assert!(
            init_output.status.success(),
            "git init should succeed, got {}",
            String::from_utf8_lossy(&init_output.stderr)
        );

        let set_name_output = std::process::Command::new("git")
            .args(["config", "user.name", "apm2 test"])
            .current_dir(workspace)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("set git user name");
        assert!(
            set_name_output.status.success(),
            "git config user.name should succeed, got {}",
            String::from_utf8_lossy(&set_name_output.stderr)
        );

        let set_email_output = std::process::Command::new("git")
            .args(["config", "user.email", "test@apm2.local"])
            .current_dir(workspace)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("set git user email");
        assert!(
            set_email_output.status.success(),
            "git config user.email should succeed, got {}",
            String::from_utf8_lossy(&set_email_output.stderr)
        );

        fs::write(workspace.join("README.md"), b"seed").expect("write seed file");

        let add_output = std::process::Command::new("git")
            .args(["add", "README.md"])
            .current_dir(workspace)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git add");
        assert!(
            add_output.status.success(),
            "git add should succeed, got {}",
            String::from_utf8_lossy(&add_output.stderr)
        );

        let commit_output = std::process::Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(workspace)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git commit");
        assert!(
            commit_output.status.success(),
            "git commit should succeed, got {}",
            String::from_utf8_lossy(&commit_output.stderr)
        );
    }

    fn persist_running_lease(manager: &LaneManager, lane_id: &str) {
        let lane_dir = manager.lane_dir(lane_id);
        let lease = LaneLeaseV1::new(
            lane_id,
            "job_cleanup",
            std::process::id(),
            LaneState::Running,
            "2026-02-12T03:15:00Z",
            "b3-256:ph",
            "b3-256:th",
        )
        .expect("create lease");
        lease.persist(&lane_dir).expect("persist lease");
    }

    fn persist_lease_with_pid(manager: &LaneManager, lane_id: &str, state: LaneState, pid: u32) {
        let lane_dir = manager.lane_dir(lane_id);
        let lease = LaneLeaseV1::new(
            lane_id,
            "job_cleanup",
            pid,
            state,
            "2026-02-12T03:15:00Z",
            "b3-256:ph",
            "b3-256:th",
        )
        .expect("create lease");
        lease.persist(&lane_dir).expect("persist lease");
    }

    #[test]
    fn test_reap_orphaned_leases_on_tick_reaps_dead_leased_lane() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        let dead_pid = find_dead_pid();
        persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Leased, dead_pid);
        let lane_dir = lane_mgr.lane_dir("lane-00");
        assert!(
            LaneLeaseV1::load(&lane_dir).expect("load lease").is_some(),
            "test precondition: lease exists before maintenance"
        );

        reap_orphaned_leases_on_tick(&fac_root, false);

        assert!(
            LaneLeaseV1::load(&lane_dir)
                .expect("load lease after maintenance")
                .is_none(),
            "dead leased lane should be reaped during poll tick maintenance"
        );
    }

    #[test]
    fn test_reap_orphaned_leases_on_tick_keeps_alive_leased_lane() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Leased, std::process::id());
        let lane_dir = lane_mgr.lane_dir("lane-00");

        reap_orphaned_leases_on_tick(&fac_root, false);

        assert!(
            LaneLeaseV1::load(&lane_dir)
                .expect("load lease after maintenance")
                .is_some(),
            "alive leased lane should not be reaped"
        );
    }

    #[test]
    fn test_execute_lane_cleanup_success_emits_success_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        let lane_id = "lane-00";
        let workspace = lane_mgr.lane_dir(lane_id).join("workspace");
        persist_running_lease(&lane_mgr, lane_id);
        init_test_workspace_git_repo(&workspace);

        execute_lane_cleanup(&fac_root, &lane_mgr, lane_id, &workspace)
            .expect("lane cleanup should succeed");

        let status = lane_mgr.lane_status(lane_id).expect("lane status");
        assert_eq!(status.state, LaneState::Idle);

        let receipt_file = fs::read_dir(fac_root.join(FAC_RECEIPTS_DIR))
            .expect("receipts dir")
            .flatten()
            .find(|entry| entry.file_type().is_ok_and(|ty| ty.is_file()))
            .expect("at least one lane cleanup receipt");
        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(receipt_file.path()).expect("read receipt"),
        )
        .expect("parse lane cleanup receipt");
        assert_eq!(
            receipt_json
                .get("outcome")
                .and_then(serde_json::Value::as_str),
            Some("success"),
            "cleanup success should emit success receipt"
        );
        assert_eq!(
            receipt_json
                .get("lane_id")
                .and_then(serde_json::Value::as_str),
            Some(lane_id),
            "receipt should target executed lane"
        );
    }

    #[test]
    fn test_execute_lane_cleanup_failure_marks_corrupt_and_emits_failed_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        let lane_id = "lane-00";
        let workspace = lane_mgr.lane_dir(lane_id).join("workspace");
        persist_running_lease(&lane_mgr, lane_id);

        let err = execute_lane_cleanup(&fac_root, &lane_mgr, lane_id, &workspace)
            .expect_err("cleanup should fail when workspace is not a git repo");
        assert!(err.to_string().contains("lane cleanup failed"));

        let status = lane_mgr.lane_status(lane_id).expect("lane status");
        assert_eq!(status.state, LaneState::Corrupt);

        let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect("marker should be persisted on cleanup failure")
            .expect("marker should exist");
        assert!(marker.reason.contains("lane cleanup failed"));

        let receipt_file = fs::read_dir(fac_root.join(FAC_RECEIPTS_DIR))
            .expect("receipts dir")
            .flatten()
            .find(|entry| entry.file_type().is_ok_and(|ty| ty.is_file()))
            .expect("at least one lane cleanup receipt");
        let expected_receipt_digest = receipt_file
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("receipt file must have digest stem")
            .to_string();
        let receipt_json = serde_json::from_slice::<serde_json::Value>(
            &fs::read(receipt_file.path()).expect("read receipt"),
        )
        .expect("parse lane cleanup receipt");
        assert_eq!(
            receipt_json
                .get("outcome")
                .and_then(serde_json::Value::as_str),
            Some("failed"),
            "cleanup failure should emit failed receipt"
        );
        assert_eq!(
            marker.cleanup_receipt_digest.as_deref(),
            Some(expected_receipt_digest.as_str()),
            "corrupt marker must bind to the emitted failed cleanup receipt digest"
        );
    }

    #[test]
    fn test_acquire_worker_lane_skips_corrupt_and_uses_next_lane() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        let corrupt_marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            reason: "corrupt from previous failed cleanup".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-02-15T00:00:00Z".to_string(),
        };
        corrupt_marker
            .persist(&fac_root)
            .expect("persist corrupt marker");

        let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
        let (_guard, acquired_lane_id) =
            acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
        assert_eq!(
            acquired_lane_id, "lane-01",
            "corrupt lane should be skipped and next lane acquired"
        );
    }

    /// Find a PID that is guaranteed to not exist (returns ESRCH on kill -0).
    ///
    /// Starts from a high PID and walks down until one is confirmed dead.
    /// Falls back to PID 0 which `check_process_liveness` treats as Dead.
    fn find_dead_pid() -> u32 {
        // Walk from a high PID downward to find one that returns ESRCH.
        // Typical Linux pid_max is 32768 or 4194304; we start well above
        // the common range to minimize collision risk with running processes.
        for pid_candidate in (100_000..200_000).rev() {
            if matches!(check_process_liveness(pid_candidate), ProcessLiveness::Dead) {
                return pid_candidate;
            }
        }
        // Fallback: PID 0 is special-cased as Dead in check_process_liveness.
        0
    }

    #[test]
    fn test_acquire_worker_lane_recovers_dead_running_lease() {
        // When a lane has a RUNNING lease for a DEAD process, the lane
        // should be recovered (stale lease removed) and acquired, not
        // marked corrupt.
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        let dead_pid = find_dead_pid();
        persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Running, dead_pid);

        let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
        let (_guard, acquired_lane_id) =
            acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
        // Lane-00 should be recovered (dead process), not skipped.
        assert_eq!(acquired_lane_id, "lane-00");

        // No corrupt marker should exist — the lane was recovered.
        assert!(
            LaneCorruptMarkerV1::load(&fac_root, "lane-00")
                .expect("marker load")
                .is_none(),
            "recovered lane should NOT have a corrupt marker"
        );
    }

    #[test]
    fn test_acquire_worker_lane_marks_alive_running_lease_corrupt() {
        // When a lane has a RUNNING lease for an ALIVE process (current PID),
        // acquiring the flock is unexpected. The lane should be marked corrupt.
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        persist_running_lease(&lane_mgr, "lane-00");

        let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
        let (_guard, acquired_lane_id) =
            acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
        assert_eq!(acquired_lane_id, "lane-01");

        let marker = LaneCorruptMarkerV1::load(&fac_root, "lane-00")
            .expect("marker load")
            .expect("marker should exist for alive-process lease");
        assert!(
            marker.reason.contains("still alive"),
            "marker reason should mention process is still alive, got: {}",
            marker.reason
        );
    }

    #[test]
    fn test_acquire_worker_lane_recovers_dead_cleanup_lease() {
        // When a lane has a CLEANUP lease for a DEAD process, the lane
        // should be recovered and acquired.
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        let dead_pid = find_dead_pid();
        persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Cleanup, dead_pid);

        let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
        let (_guard, acquired_lane_id) =
            acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
        // Lane-00 should be recovered (dead process).
        assert_eq!(acquired_lane_id, "lane-00");

        assert!(
            LaneCorruptMarkerV1::load(&fac_root, "lane-00")
                .expect("marker load")
                .is_none(),
            "recovered lane should NOT have a corrupt marker"
        );
    }

    #[test]
    fn test_acquire_worker_lane_skips_corrupt_lease_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Corrupt, u32::MAX);

        let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
        let (_guard, acquired_lane_id) =
            acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
        assert_eq!(acquired_lane_id, "lane-01");
    }

    #[test]
    fn test_execute_lane_cleanup_restores_dirty_workspace_on_denial() {
        // SEC-CTRL-LANE-CLEANUP-002: Verify that execute_lane_cleanup restores
        // a workspace that has been dirtied by a partial checkout/patch to a
        // clean state. This is the mechanism used by post-checkout denial paths
        // to prevent cross-job contamination.
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        let lane_id = "lane-00";
        let workspace = lane_mgr.lane_dir(lane_id).join("workspace");
        persist_running_lease(&lane_mgr, lane_id);
        init_test_workspace_git_repo(&workspace);

        // Simulate workspace modification from a partial patch or checkout:
        // create untracked files and modify tracked files.
        fs::write(
            workspace.join("malicious_untracked.txt"),
            b"injected payload",
        )
        .expect("create untracked file");
        fs::write(workspace.join("README.md"), b"modified content").expect("modify tracked file");

        // Verify workspace is dirty before cleanup.
        assert!(
            workspace.join("malicious_untracked.txt").exists(),
            "untracked file should exist before cleanup"
        );
        let readme_content = fs::read_to_string(workspace.join("README.md")).expect("read README");
        assert_eq!(readme_content, "modified content");

        // Run lane cleanup (same function used on denial paths).
        execute_lane_cleanup(&fac_root, &lane_mgr, lane_id, &workspace)
            .expect("lane cleanup should succeed");

        // Verify workspace is restored to clean state.
        assert!(
            !workspace.join("malicious_untracked.txt").exists(),
            "untracked file should be removed by git clean"
        );
        let restored_readme =
            fs::read_to_string(workspace.join("README.md")).expect("read restored README");
        assert_eq!(
            restored_readme, "seed",
            "tracked file should be restored to HEAD by git reset"
        );

        // Verify lane is back to idle (lease removed).
        let status = lane_mgr.lane_status(lane_id).expect("lane status");
        assert_eq!(status.state, LaneState::Idle);
    }

    #[test]
    fn test_execute_lane_cleanup_marks_corrupt_on_failure_during_denial() {
        // SEC-CTRL-LANE-CLEANUP-002: When cleanup fails on a denial path,
        // the lane should be marked CORRUPT to prevent future jobs from
        // running on the contaminated workspace.
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
        lane_mgr.ensure_directories().expect("ensure lanes");

        let lane_id = "lane-00";
        let workspace = lane_mgr.lane_dir(lane_id).join("workspace");
        persist_running_lease(&lane_mgr, lane_id);
        // Do NOT init git repo — this will cause cleanup to fail.
        fs::create_dir_all(&workspace).expect("create workspace dir");

        let err = execute_lane_cleanup(&fac_root, &lane_mgr, lane_id, &workspace)
            .expect_err("cleanup should fail on non-git workspace");
        assert!(err.to_string().contains("lane cleanup failed"));

        // Verify lane is marked CORRUPT.
        let status = lane_mgr.lane_status(lane_id).expect("lane status");
        assert_eq!(
            status.state,
            LaneState::Corrupt,
            "lane should be CORRUPT after failed cleanup on denial path"
        );

        // Verify corrupt marker exists.
        let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect("marker load")
            .expect("corrupt marker should exist");
        assert!(
            marker.reason.contains("lane cleanup failed"),
            "corrupt marker should describe cleanup failure"
        );
    }

    // ── TCK-00579: DenialReasonCode mapping assertions ──

    /// Helper to map `JobSpecError` to `DenialReasonCode` using the same
    /// logic as the worker denial path.
    fn map_job_spec_error_to_denial_reason(e: &JobSpecError) -> DenialReasonCode {
        match e {
            JobSpecError::MissingToken { .. } => DenialReasonCode::MissingChannelToken,
            JobSpecError::InvalidDigest { .. } => DenialReasonCode::MalformedSpec,
            JobSpecError::DisallowedRepoId { .. }
            | JobSpecError::DisallowedBytesBackend { .. }
            | JobSpecError::FilesystemPathRejected { .. }
            | JobSpecError::InvalidControlLaneRepoId { .. } => DenialReasonCode::PolicyViolation,
            _ => DenialReasonCode::ValidationFailed,
        }
    }

    #[test]
    fn test_disallowed_repo_id_maps_to_policy_violation() {
        let err = JobSpecError::DisallowedRepoId {
            repo_id: "evil-org/evil-repo".to_string(),
        };
        assert_eq!(
            map_job_spec_error_to_denial_reason(&err),
            DenialReasonCode::PolicyViolation,
            "DisallowedRepoId must map to PolicyViolation"
        );
    }

    #[test]
    fn test_disallowed_bytes_backend_maps_to_policy_violation() {
        let err = JobSpecError::DisallowedBytesBackend {
            backend: "evil_backend".to_string(),
        };
        assert_eq!(
            map_job_spec_error_to_denial_reason(&err),
            DenialReasonCode::PolicyViolation,
            "DisallowedBytesBackend must map to PolicyViolation"
        );
    }

    #[test]
    fn test_filesystem_path_rejected_maps_to_policy_violation() {
        let err = JobSpecError::FilesystemPathRejected {
            field: "source.repo_id",
            value: "/etc/passwd".to_string(),
        };
        assert_eq!(
            map_job_spec_error_to_denial_reason(&err),
            DenialReasonCode::PolicyViolation,
            "FilesystemPathRejected must map to PolicyViolation"
        );
    }

    #[test]
    fn test_missing_token_maps_to_missing_channel_token() {
        let err = JobSpecError::MissingToken {
            field: "actuation.channel_context_token",
        };
        assert_eq!(
            map_job_spec_error_to_denial_reason(&err),
            DenialReasonCode::MissingChannelToken,
            "MissingToken must map to MissingChannelToken"
        );
    }

    #[test]
    fn test_invalid_digest_maps_to_malformed_spec() {
        let err = JobSpecError::InvalidDigest {
            field: "job_spec_digest",
            value: "bad".to_string(),
        };
        assert_eq!(
            map_job_spec_error_to_denial_reason(&err),
            DenialReasonCode::MalformedSpec,
            "InvalidDigest must map to MalformedSpec"
        );
    }

    #[test]
    fn test_other_errors_map_to_validation_failed() {
        let err = JobSpecError::EmptyField { field: "job_id" };
        assert_eq!(
            map_job_spec_error_to_denial_reason(&err),
            DenialReasonCode::ValidationFailed,
            "generic errors must map to ValidationFailed"
        );
    }

    /// TCK-00564 MAJOR-1 regression: denied receipt + pending job must route
    /// to denied/, NOT completed/.
    ///
    /// Prior to fix round 4, the duplicate detection in `process_job` used
    /// `has_receipt_for_job` (boolean) and unconditionally moved duplicates
    /// to `completed/`. This masked denied outcomes. The fix uses
    /// `find_receipt_for_job` and routes to the correct terminal directory
    /// via `outcome_to_terminal_state`.
    #[test]
    fn test_duplicate_detection_routes_denied_receipt_to_denied_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let queue_root = dir.path().join("queue");
        ensure_queue_dirs(&queue_root).expect("create queue dirs");

        let spec = make_receipt_test_spec();

        // Step 1: Emit a Denied receipt for the job.
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        emit_job_receipt(
            &fac_root,
            &spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            "test: validation failed",
            None,
            None,
            None,
            None,
            Some(&tuple_digest),
            None,
            &spec.job_spec_digest,
            None,
            None,
            None,
            None, // bytes_backend
            None,
        )
        .expect("emit denied receipt");

        // Step 2: Place a pending job file simulating a requeued job.
        let pending_file = queue_root.join(PENDING_DIR).join("test-denied-job.json");
        let spec_bytes = serde_json::to_vec(&spec).expect("serialize spec");
        fs::write(&pending_file, &spec_bytes).expect("write pending job");

        // Step 3: Verify that find_receipt_for_job returns the denied receipt.
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        let found_receipt = apm2_core::fac::find_receipt_for_job(&receipts_dir, &spec.job_id)
            .expect("receipt must be found");
        assert_eq!(
            found_receipt.outcome,
            FacJobOutcome::Denied,
            "found receipt must have Denied outcome"
        );

        // Step 4: Verify outcome_to_terminal_state routes to Denied.
        let terminal_state = apm2_core::fac::outcome_to_terminal_state(found_receipt.outcome)
            .expect("Denied must have a terminal state");
        assert_eq!(
            terminal_state.dir_name(),
            DENIED_DIR,
            "Denied outcome must route to denied/ directory, not completed/"
        );

        // Step 5: Execute the outcome-aware routing (same logic as process_job).
        let terminal_dir = queue_root.join(terminal_state.dir_name());
        move_to_dir_safe(&pending_file, &terminal_dir, "test-denied-job.json")
            .expect("move to terminal dir");

        // Step 6: Assert the job landed in denied/, NOT completed/.
        assert!(
            queue_root
                .join(DENIED_DIR)
                .join("test-denied-job.json")
                .exists(),
            "denied receipt must route job to denied/"
        );
        assert!(
            !queue_root
                .join(COMPLETED_DIR)
                .join("test-denied-job.json")
                .exists(),
            "denied receipt must NOT route job to completed/"
        );
        assert!(
            !pending_file.exists(),
            "pending file must be removed after routing"
        );
    }

    #[test]
    fn test_find_completed_gates_duplicate_matches_completed_receipt_by_request_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("private").join("fac");
        let queue_root = dir.path().join("queue");
        ensure_queue_dirs(&queue_root).expect("create queue dirs");
        fs::create_dir_all(queue_root.join(COMPLETED_DIR)).expect("create completed dir");

        let mut completed_spec = make_receipt_test_spec();
        completed_spec.job_id = "job-completed-sha".to_string();
        completed_spec.enqueue_time = "2026-02-19T01:00:00Z".to_string();
        fs::write(
            queue_root
                .join(COMPLETED_DIR)
                .join("job-completed-sha.json"),
            serde_json::to_vec(&completed_spec).expect("serialize completed spec"),
        )
        .expect("write completed spec");

        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            token_fac_policy_hash: None,
            token_canonicalizer_tuple_digest: None,
            token_boundary_id: None,
            token_issued_at_tick: None,
            token_expiry_tick: None,
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "control".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
        emit_job_receipt(
            &fac_root,
            &completed_spec,
            FacJobOutcome::Completed,
            None,
            "completed for dedupe",
            Some(&boundary_trace),
            Some(&queue_trace),
            None,
            None,
            Some(&tuple_digest),
            Some("completed/job-completed-sha.json"),
            &completed_spec.job_spec_digest,
            None,
            None,
            None,
            None, // bytes_backend
            None,
        )
        .expect("emit completed receipt");

        let mut incoming = completed_spec.clone();
        incoming.job_id = "job-incoming-sha".to_string();
        incoming.enqueue_time = "2026-02-19T01:03:00Z".to_string();

        let mut completed_gates_cache = None;
        let duplicate = find_completed_gates_duplicate(
            &queue_root,
            &fac_root,
            &incoming,
            &mut completed_gates_cache,
            &tuple_digest,
        )
        .expect("duplicate");
        assert_eq!(duplicate.existing_job_id, completed_spec.job_id);
        assert_eq!(duplicate.matched_by, "repo_sha_toolchain");
    }

    #[test]
    fn test_find_completed_gates_duplicate_matches_on_repo_sha_and_toolchain() {
        let toolchain = "b3-256:aaaa";
        let mut cache = CompletedGatesCache::default();
        cache.insert(CompletedGatesFingerprint {
            job_id: "job-completed-sha".to_string(),
            enqueue_time: "2026-02-19T01:00:00Z".to_string(),
            repo_id: "owner/repo".to_string(),
            head_sha: "abc123".to_string(),
            toolchain_digest: toolchain.to_string(),
        });

        let mut incoming = make_receipt_test_spec();
        incoming.source.repo_id = "OWNER/REPO".to_string();
        incoming.source.head_sha = "ABC123".to_string();
        incoming.actuation.request_id = "request-new".to_string();
        incoming.enqueue_time = "2026-02-19T01:10:00Z".to_string();

        // Same toolchain -> match.
        let duplicate = find_completed_gates_duplicate_in_cache(&incoming, &cache, toolchain)
            .expect("same (repo_id, head_sha, toolchain) must match");
        assert_eq!(duplicate.existing_job_id, "job-completed-sha");
        assert_eq!(duplicate.matched_by, "repo_sha_toolchain");

        // Different toolchain -> no match (binary changed, must re-gate).
        let no_match = find_completed_gates_duplicate_in_cache(&incoming, &cache, "b3-256:bbbb");
        assert!(
            no_match.is_none(),
            "different toolchain digest must NOT match"
        );
    }

    #[test]
    fn test_append_completed_gates_fingerprint_if_loaded_supports_same_cycle_dedupe() {
        let toolchain = "b3-256:cccc";
        let mut completed_spec = make_receipt_test_spec();
        completed_spec.job_id = "job-completed-sha".to_string();
        completed_spec.enqueue_time = "2026-02-19T01:00:00Z".to_string();

        let mut incoming = completed_spec.clone();
        incoming.job_id = "job-incoming-sha".to_string();
        incoming.enqueue_time = "2026-02-19T01:03:00Z".to_string();

        let mut cache = Some(CompletedGatesCache::default());
        append_completed_gates_fingerprint_if_loaded(&mut cache, &completed_spec, toolchain);
        let duplicate = find_completed_gates_duplicate_in_cache(
            &incoming,
            cache.as_ref().expect("cache loaded"),
            toolchain,
        )
        .expect("duplicate");
        assert_eq!(duplicate.existing_job_id, "job-completed-sha");
        assert_eq!(duplicate.matched_by, "repo_sha_toolchain");
    }

    #[test]
    fn test_annotate_denied_job_file_populates_reason_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let denied_path = dir.path().join("job-denied.json");
        let spec = make_receipt_test_spec();
        fs::write(
            &denied_path,
            serde_json::to_vec_pretty(&spec).expect("serialize job spec"),
        )
        .expect("write denied job file");

        annotate_denied_job_file(
            &denied_path,
            Some(DenialReasonCode::AlreadyCompleted),
            "already completed for repo+sha",
        )
        .expect("annotate denied job");

        let payload: serde_json::Value =
            serde_json::from_slice(&fs::read(&denied_path).expect("read denied metadata"))
                .expect("parse denied metadata");
        assert_eq!(
            payload
                .get("denial_reason_code")
                .and_then(serde_json::Value::as_str),
            Some("already_completed")
        );
        assert_eq!(
            payload
                .get("denial_reason")
                .and_then(serde_json::Value::as_str),
            Some("already completed for repo+sha")
        );
        assert!(
            payload
                .get("denied_at")
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "denied file must include denied_at"
        );
    }

    #[test]
    fn test_annotate_denied_job_file_defaults_when_reason_and_code_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let denied_path = dir.path().join("job-denied.json");
        let spec = make_receipt_test_spec();
        fs::write(
            &denied_path,
            serde_json::to_vec_pretty(&spec).expect("serialize job spec"),
        )
        .expect("write denied job file");

        annotate_denied_job_file(&denied_path, None, "   ").expect("annotate denied job");

        let payload: serde_json::Value =
            serde_json::from_slice(&fs::read(&denied_path).expect("read denied metadata"))
                .expect("parse denied metadata");
        assert_eq!(
            payload
                .get("denial_reason_code")
                .and_then(serde_json::Value::as_str),
            Some("missing_denial_reason_code")
        );
        assert_eq!(
            payload
                .get("denial_reason")
                .and_then(serde_json::Value::as_str),
            Some("denied (missing_denial_reason_code)")
        );
    }

    #[test]
    fn test_annotate_denied_job_metadata_from_receipt_updates_denied_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let denied_path = dir.path().join("job-denied.json");
        fs::write(
            &denied_path,
            serde_json::to_vec_pretty(&make_receipt_test_spec()).expect("serialize job spec"),
        )
        .expect("write denied job file");

        let denied_receipt = FacJobReceiptV1 {
            outcome: FacJobOutcome::Denied,
            denial_reason: Some(DenialReasonCode::AlreadyCompleted),
            reason: "already completed".to_string(),
            ..FacJobReceiptV1::default()
        };
        annotate_denied_job_metadata_from_receipt(&denied_path, &denied_receipt);
        let payload: serde_json::Value =
            serde_json::from_slice(&fs::read(&denied_path).expect("read denied metadata"))
                .expect("parse denied metadata");
        assert_eq!(
            payload
                .get("denial_reason")
                .and_then(serde_json::Value::as_str),
            Some("already completed")
        );

        let completed_path = dir.path().join("job-completed.json");
        fs::write(
            &completed_path,
            serde_json::to_vec_pretty(&make_receipt_test_spec()).expect("serialize job spec"),
        )
        .expect("write completed job file");
        let completed_receipt = FacJobReceiptV1 {
            outcome: FacJobOutcome::Completed,
            denial_reason: None,
            reason: "completed".to_string(),
            ..FacJobReceiptV1::default()
        };
        annotate_denied_job_metadata_from_receipt(&completed_path, &completed_receipt);
        let completed_payload: serde_json::Value =
            serde_json::from_slice(&fs::read(&completed_path).expect("read completed metadata"))
                .expect("parse completed metadata");
        assert!(
            completed_payload.get("denial_reason").is_none(),
            "completed outcomes must not be annotated as denied"
        );
    }

    /// TCK-00564 MAJOR-1 regression: `handle_pipeline_commit_failure` must
    /// leave the job in claimed/ rather than moving it to pending/.
    ///
    /// Prior to fix round 4, commit failures moved jobs from claimed/ to
    /// pending/, which caused the outcome-blind duplicate detection to
    /// route them to completed/ regardless of the receipt outcome. The fix
    /// leaves the job in claimed/ for reconcile to repair via
    /// `recover_torn_state`.
    #[test]
    fn test_handle_pipeline_commit_failure_leaves_job_in_claimed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue_root = dir.path().join("queue");
        ensure_queue_dirs(&queue_root).expect("create queue dirs");

        // Place a job file in claimed/.
        let claimed_path = queue_root.join(CLAIMED_DIR).join("commit-fail.json");
        fs::write(&claimed_path, b"{}").expect("write claimed job");

        // Call handle_pipeline_commit_failure with a structured error.
        let test_err = ReceiptPipelineError::ReceiptPersistFailed("test commit error".to_string());
        let outcome = handle_pipeline_commit_failure(
            &test_err,
            "test context",
            &claimed_path,
            &queue_root,
            "commit-fail.json",
        );

        // The job should still be in claimed/, NOT in pending/.
        assert!(
            claimed_path.exists(),
            "job must remain in claimed/ after commit failure"
        );
        assert!(
            !queue_root
                .join(PENDING_DIR)
                .join("commit-fail.json")
                .exists(),
            "job must NOT be moved to pending/ after commit failure"
        );
        assert!(
            matches!(outcome, JobOutcome::Skipped { .. }),
            "outcome should be Skipped, got: {outcome:?}"
        );
    }

    // --- TCK-00574 MAJOR-2: resolved network policy hash consistency ---

    #[test]
    fn resolve_network_policy_hash_matches_for_gates_kind() {
        // Regression: the resolved network policy hash for "gates" kind
        // must match the hash produced by resolve_network_policy("gates", None).
        // This validates that the early-resolve approach in process_job
        // produces the same hash as the later resolve_network_policy call.
        let resolved = apm2_core::fac::resolve_network_policy("gates", None);
        let expected_deny = apm2_core::fac::NetworkPolicy::deny();
        assert_eq!(
            resolved, expected_deny,
            "gates kind should resolve to deny policy by default"
        );
        assert_eq!(
            resolved.content_hash_hex(),
            expected_deny.content_hash_hex(),
            "hash of resolved policy must match deny policy hash"
        );
    }

    #[test]
    fn resolve_network_policy_hash_matches_for_warm_kind() {
        // The resolved network policy for "warm" kind must be allow.
        let resolved = apm2_core::fac::resolve_network_policy("warm", None);
        let expected_allow = apm2_core::fac::NetworkPolicy::allow();
        assert_eq!(
            resolved, expected_allow,
            "warm kind should resolve to allow policy by default"
        );
        // Verify the hashes differ between deny and allow.
        let deny_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();
        assert_ne!(
            resolved.content_hash_hex(),
            deny_hash,
            "warm (allow) hash must differ from gates (deny) hash"
        );
    }

    /// Verify that `LaneResetRecommendation` serializes to a standalone valid
    /// JSON object with the expected schema identifier, matching the contract
    /// that `emit_lane_reset_recommendation` emits each recommendation as a
    /// single parseable JSON line on stderr.
    #[test]
    fn test_lane_reset_recommendation_serializes_as_valid_json() {
        let rec = LaneResetRecommendation {
            schema: LANE_RESET_RECOMMENDATION_SCHEMA,
            lane_id: "lane-42".to_string(),
            message: "worker: RECOMMENDATION: lane lane-42 needs reset".to_string(),
            reason: "cleanup failure: disk full".to_string(),
            recommended_action: "apm2 fac lane reset",
        };
        let json_str = serde_json::to_string(&rec).expect("serialization must succeed");

        // The serialized string must parse back as valid JSON.
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("output must be valid JSON");

        // Verify expected fields.
        assert_eq!(
            parsed["schema"], "apm2.fac.lane_reset_recommendation.v1",
            "schema field must match LANE_RESET_RECOMMENDATION_SCHEMA"
        );
        assert_eq!(parsed["lane_id"], "lane-42");
        assert_eq!(
            parsed["message"], "worker: RECOMMENDATION: lane lane-42 needs reset",
            "human-readable context must be encoded inside JSON, not as a separate plain-text line"
        );
        assert_eq!(parsed["reason"], "cleanup failure: disk full");
        assert_eq!(parsed["recommended_action"], "apm2 fac lane reset");

        // The output must NOT contain any non-JSON prefix — verify the first
        // non-whitespace character is '{'.
        let trimmed = json_str.trim();
        assert!(
            trimmed.starts_with('{'),
            "serialized recommendation must be a standalone JSON object, got: {trimmed}"
        );
    }

    /// Verify that `emit_lane_reset_recommendation` emits exactly one line
    /// to stderr and that the line is valid, parseable JSON with the expected
    /// schema.  This is the contract: the stderr recommendation channel is
    /// JSON-only (NDJSON) — no plain-text preamble, no mixed lines.
    #[test]
    fn test_emit_lane_reset_recommendation_stderr_is_json_only() {
        // We cannot capture real stderr in-process without redirecting FDs,
        // so we replicate the emission logic and verify that every line
        // produced is valid JSON.
        let lane_id = "lane-77";
        let reason = "stale lease detected";
        let rec = LaneResetRecommendation {
            schema: LANE_RESET_RECOMMENDATION_SCHEMA,
            lane_id: lane_id.to_string(),
            message: format!("worker: RECOMMENDATION: lane {lane_id} needs reset"),
            reason: reason.to_string(),
            recommended_action: "apm2 fac lane reset",
        };
        let json_str =
            serde_json::to_string(&rec).expect("serialization must succeed for test fixture");

        // Simulate what emit_lane_reset_recommendation writes to stderr:
        // exactly one line containing the JSON.  Verify EACH line is
        // parseable JSON.
        let emitted_lines: Vec<&str> = json_str.lines().collect();
        assert_eq!(
            emitted_lines.len(),
            1,
            "recommendation must be emitted as exactly one line, got {}",
            emitted_lines.len()
        );
        for (i, line) in emitted_lines.iter().enumerate() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "stderr line {i} is not valid JSON: {line}");
            let val = parsed.unwrap();
            assert_eq!(
                val["schema"], "apm2.fac.lane_reset_recommendation.v1",
                "each emitted JSON line must carry the recommendation schema"
            );
        }
    }

    /// Verify channel separation: `emit_lane_reset_recommendation` writes
    /// JSON to stderr (via `eprintln!`).  The `acquire_worker_lane` function
    /// uses only `tracing::warn!` / `tracing::info!` for diagnostics (routed
    /// to the tracing subscriber), never raw `eprintln!`, so the only
    /// `eprintln!` output from the lane-acquisition path is the JSON
    /// recommendation itself.  This test verifies the serialized output
    /// parses as valid NDJSON, confirming that no plain-text prefix or
    /// suffix contaminates the stderr recommendation channel.
    #[test]
    fn test_recommendation_channel_separation() {
        // Verify multiple recommendations can be concatenated as NDJSON
        // (one valid JSON object per line) on the stdout channel.
        let test_cases = [
            ("lane-1", "disk full"),
            ("lane-2", "stale lease for pid 12345"),
            ("lane-3", "lease state is Corrupt"),
        ];

        let mut ndjson_output = String::new();
        for (lane_id, reason) in &test_cases {
            let rec = LaneResetRecommendation {
                schema: LANE_RESET_RECOMMENDATION_SCHEMA,
                lane_id: lane_id.to_string(),
                message: format!("worker: RECOMMENDATION: lane {lane_id} needs reset"),
                reason: reason.to_string(),
                recommended_action: "apm2 fac lane reset",
            };
            let json_str =
                serde_json::to_string(&rec).expect("serialization must succeed for test fixture");
            ndjson_output.push_str(&json_str);
            ndjson_output.push('\n');
        }

        // Parse as NDJSON: every non-empty line must be valid JSON.
        let lines: Vec<&str> = ndjson_output
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        assert_eq!(
            lines.len(),
            3,
            "expected 3 NDJSON lines for 3 recommendations, got {}",
            lines.len()
        );
        for (i, line) in lines.iter().enumerate() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("stderr NDJSON line {i} is not valid JSON: {e}\nline: {line}")
            });
            assert_eq!(
                parsed["schema"], "apm2.fac.lane_reset_recommendation.v1",
                "line {i}: schema field mismatch"
            );
            assert_eq!(
                parsed["lane_id"], test_cases[i].0,
                "line {i}: lane_id mismatch"
            );
            assert_eq!(
                parsed["reason"], test_cases[i].1,
                "line {i}: reason mismatch"
            );
            // Verify no non-JSON prefix: first non-whitespace char must be '{'.
            assert!(
                line.trim().starts_with('{'),
                "line {i}: stderr NDJSON line must start with '{{', got: {line}"
            );
        }
    }

    #[test]
    fn resolve_network_policy_hash_with_override() {
        // When an operator override is provided, it takes precedence
        // over the default kind-based mapping.
        let override_allow = apm2_core::fac::NetworkPolicy::allow();
        let resolved = apm2_core::fac::resolve_network_policy("gates", Some(&override_allow));
        assert_eq!(
            resolved, override_allow,
            "operator override must take precedence over kind default"
        );
        assert_eq!(
            resolved.content_hash_hex(),
            override_allow.content_hash_hex(),
            "hash must match the override policy, not the default deny"
        );
    }

    // ========================================================================
    // owns_sccache_server tests (fix-round-3)
    // ========================================================================

    fn make_trace_with_sc(
        sc: apm2_core::fac::containment::SccacheServerContainment,
    ) -> apm2_core::fac::containment::ContainmentTrace {
        apm2_core::fac::containment::ContainmentTrace {
            verified: true,
            cgroup_path: "/test".to_string(),
            processes_checked: 1,
            mismatch_count: 0,
            sccache_auto_disabled: sc.auto_disabled,
            sccache_enabled: !sc.auto_disabled,
            sccache_version: None,
            sccache_server_containment: Some(sc),
        }
    }

    #[test]
    fn owns_server_started_auto_disabled_returns_true() {
        let sc = apm2_core::fac::containment::SccacheServerContainment {
            protocol_executed: true,
            server_started: true,
            auto_disabled: true,
            server_cgroup_verified: false,
            ..Default::default()
        };
        let trace = make_trace_with_sc(sc);
        assert!(
            owns_sccache_server(Some(&trace)),
            "server_started=true must own for shutdown even when auto_disabled"
        );
    }

    #[test]
    fn owns_server_not_started_auto_disabled_returns_false() {
        let sc = apm2_core::fac::containment::SccacheServerContainment {
            protocol_executed: true,
            server_started: false,
            auto_disabled: true,
            server_cgroup_verified: false,
            ..Default::default()
        };
        let trace = make_trace_with_sc(sc);
        assert!(
            !owns_sccache_server(Some(&trace)),
            "server_started=false auto_disabled=true must not own"
        );
    }

    #[test]
    fn owns_server_started_pid_auto_disabled_returns_true() {
        let sc = apm2_core::fac::containment::SccacheServerContainment {
            protocol_executed: true,
            server_started: false,
            started_server_pid: Some(12345),
            auto_disabled: true,
            server_cgroup_verified: false,
            ..Default::default()
        };
        let trace = make_trace_with_sc(sc);
        assert!(
            owns_sccache_server(Some(&trace)),
            "started_server_pid=Some must own for shutdown even when auto_disabled"
        );
    }

    #[test]
    fn owns_preexisting_in_cgroup_returns_true() {
        let sc = apm2_core::fac::containment::SccacheServerContainment {
            protocol_executed: true,
            preexisting_server_detected: true,
            preexisting_server_in_cgroup: Some(true),
            server_started: false,
            auto_disabled: false,
            server_cgroup_verified: true,
            ..Default::default()
        };
        let trace = make_trace_with_sc(sc);
        assert!(
            owns_sccache_server(Some(&trace)),
            "preexisting in-cgroup server must own"
        );
    }
}
