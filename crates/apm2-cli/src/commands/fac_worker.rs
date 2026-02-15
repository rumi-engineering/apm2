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

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use apm2_core::channel::{
    ChannelBoundaryDefect, decode_channel_context_token, validate_channel_boundary,
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
    validate_job_spec,
};
use apm2_core::fac::lane::LaneManager;
use apm2_core::fac::scheduler_state::{load_scheduler_state, persist_scheduler_state};
use apm2_core::fac::{
    BlobStore, BudgetAdmissionTrace as FacBudgetAdmissionTrace, CanonicalizerTupleV1,
    ChannelBoundaryTrace, DenialReasonCode, FacJobOutcome, FacJobReceiptV1Builder, FacPolicyV1,
    GateReceipt, GateReceiptBuilder, LaneProfileV1, MAX_POLICY_SIZE,
    QueueAdmissionTrace as JobQueueAdmissionTrace, RepoMirrorManager, SystemdUnitProperties,
    compute_policy_hash, deserialize_policy, parse_policy_hash, persist_content_addressed_receipt,
    persist_policy, run_preflight,
};
use apm2_core::github::resolve_apm2_home;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use subtle::ConstantTimeEq;

#[cfg(test)]
mod fac_permissions {
    use std::path::Path;
    use std::{fs, io};

    pub fn ensure_dir_with_mode(path: &Path) -> Result<(), io::Error> {
        fs::create_dir_all(path)
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
const CONSUME_RECEIPTS_DIR: &str = "authority_consumed";

/// Maximum poll interval to prevent misconfiguration (1 hour).
const MAX_POLL_INTERVAL_SECS: u64 = 3600;

/// Max number of boundary defect classes retained in a trace.
const MAX_BOUNDARY_DEFECT_CLASSES: usize = 32;
const SCHEDULER_RECOVERY_SCHEMA: &str = "apm2.scheduler_recovery.v1";

/// FAC receipt directory under `$APM2_HOME/private/fac`.
const FAC_RECEIPTS_DIR: &str = "receipts";

/// Default boundary ID for local-mode evaluation windows.
const DEFAULT_BOUNDARY_ID: &str = "local";

/// Default authority clock for local-mode evaluation windows.
const DEFAULT_AUTHORITY_CLOCK: &str = "local";

// =============================================================================
// Worker result types
// =============================================================================

/// Outcome of processing a single job spec file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum JobOutcome {
    /// Job was quarantined due to malformed spec or digest mismatch.
    Quarantined { reason: String },
    /// Job was denied due to token or admission failure.
    Denied { reason: String },
    /// Job was successfully claimed and executed.
    Completed { job_id: String },
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

    let mut queue_state = match load_scheduler_state(&fac_root) {
        Ok(Some(saved)) => QueueSchedulerState::from_persisted(&saved),
        Ok(None) => {
            let recovery = SchedulerRecoveryReceipt {
                schema: SCHEDULER_RECOVERY_SCHEMA.to_string(),
                reason: "scheduler state missing, reconstructing conservatively".to_string(),
                timestamp_secs: current_timestamp_epoch_secs(),
            };
            eprintln!(
                "INFO: scheduler state reconstructed: {} ({}, {})",
                recovery.schema, recovery.reason, recovery.timestamp_secs
            );
            QueueSchedulerState::new()
        },
        Err(e) => {
            let recovery = SchedulerRecoveryReceipt {
                schema: SCHEDULER_RECOVERY_SCHEMA.to_string(),
                reason: "scheduler state missing or corrupt, reconstructing conservatively"
                    .to_string(),
                timestamp_secs: current_timestamp_epoch_secs(),
            };
            eprintln!("WARNING: failed to load scheduler state: {e}, starting fresh");
            eprintln!(
                "INFO: scheduler state reconstructed: {} ({}, {})",
                recovery.schema, recovery.reason, recovery.timestamp_secs
            );
            QueueSchedulerState::new()
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
            DEFAULT_BOUNDARY_ID,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .unwrap_or_else(|_| make_default_eval_window());

    // Advance freshness to keep startup checks in sync with the first
    // admission window.
    broker.advance_freshness_horizon(tick_end);

    let startup_envelope = broker
        .issue_time_authority_envelope_default_ttl(
            DEFAULT_BOUNDARY_ID,
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
            eprintln!(
                "FATAL: no admitted canonicalizer tuple found. Run 'apm2 fac canonicalizer admit' to bootstrap."
            );
            return exit_codes::GENERIC_ERROR;
        },
        Ok(CanonicalizerTupleCheck::Mismatch(admitted_tuple)) => {
            eprintln!("FATAL: canonicalizer tuple mismatch");
            eprintln!(
                "  current: {}/{}",
                current_tuple.canonicalizer_id, current_tuple.canonicalizer_version
            );
            eprintln!(
                "  admitted: {}/{}",
                admitted_tuple.canonicalizer_id, admitted_tuple.canonicalizer_version
            );
            eprintln!("  remedy: re-run broker admission or update binary");
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

    let mut total_processed: u64 = 0;
    let mut summary = WorkerSummary {
        jobs_processed: 0,
        jobs_completed: 0,
        jobs_denied: 0,
        jobs_quarantined: 0,
        jobs_skipped: 0,
    };

    loop {
        let cycle_start = Instant::now();

        // Scan pending directory (quarantines malformed files inline).
        let candidates = match scan_pending(&queue_root, &fac_root, &current_tuple_digest) {
            Ok(c) => c,
            Err(e) => {
                output_worker_error(json_output, &format!("scan error: {e}"));
                if once {
                    persist_queue_scheduler_state(&fac_root, &queue_state, broker.current_tick());
                    return exit_codes::GENERIC_ERROR;
                }
                sleep_remaining(cycle_start, poll_interval_secs);
                continue;
            },
        };

        let mut cycle_scheduler = queue_state.clone();

        if candidates.is_empty() {
            if once {
                persist_queue_scheduler_state(&fac_root, &cycle_scheduler, broker.current_tick());
                let _ = save_broker_state(&broker);
                if json_output {
                    print_json(&summary);
                } else {
                    eprintln!("worker: no pending jobs found");
                }
                return exit_codes::SUCCESS;
            }
            sleep_remaining(cycle_start, poll_interval_secs);
            continue;
        }

        for candidate in &candidates {
            if max_jobs > 0 && total_processed >= max_jobs {
                break;
            }

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
                    &verifying_key,
                    &cycle_scheduler,
                    lane,
                    &mut broker,
                    &signer,
                    &policy_hash,
                    &policy_digest,
                    &policy,
                    &budget_cas,
                    candidates.len(),
                    print_unit,
                    &current_tuple_digest,
                );
                cycle_scheduler.record_completion(lane);
                outcome
            };

            match &outcome {
                JobOutcome::Quarantined { reason } => {
                    summary.jobs_quarantined += 1;
                    if !json_output {
                        eprintln!("worker: quarantined {}: {reason}", candidate.path.display());
                    }
                },
                JobOutcome::Denied { reason } => {
                    summary.jobs_denied += 1;
                    if !json_output {
                        eprintln!("worker: denied {}: {reason}", candidate.spec.job_id);
                    }
                },
                JobOutcome::Completed { job_id } => {
                    summary.jobs_completed += 1;
                    if !json_output {
                        eprintln!("worker: completed {job_id}");
                    }
                },
                JobOutcome::Skipped { reason } => {
                    summary.jobs_skipped += 1;
                    if !json_output {
                        eprintln!("worker: skipped: {reason}");
                    }
                },
            }

            summary.jobs_processed += 1;
            total_processed += 1;

            if matches!(&outcome, JobOutcome::Skipped { reason } if reason.contains("no lane available"))
            {
                break;
            }

            if once {
                persist_queue_scheduler_state(&fac_root, &cycle_scheduler, broker.current_tick());
                let _ = save_broker_state(&broker);
                if json_output {
                    print_json(&summary);
                }
                return exit_codes::SUCCESS;
            }
        }

        persist_queue_scheduler_state(&fac_root, &cycle_scheduler, broker.current_tick());
        queue_state = cycle_scheduler;

        if max_jobs > 0 && total_processed >= max_jobs {
            break;
        }

        if once {
            break;
        }

        sleep_remaining(cycle_start, poll_interval_secs);
    }

    if json_output {
        print_json(&summary);
    }

    persist_queue_scheduler_state(&fac_root, &queue_state, broker.current_tick());
    let _ = save_broker_state(&broker);
    exit_codes::SUCCESS
}

fn persist_queue_scheduler_state(
    fac_root: &Path,
    queue_state: &QueueSchedulerState,
    current_tick: u64,
) {
    let mut state = queue_state.to_scheduler_state_v1(current_tick);
    state.persisted_at_secs = current_timestamp_epoch_secs();
    if let Err(e) = persist_scheduler_state(fac_root, &state) {
        eprintln!("WARNING: failed to persist scheduler state: {e}");
    }
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
    verifying_key: &apm2_core::crypto::VerifyingKey,
    scheduler: &QueueSchedulerState,
    lane: QueueLane,
    broker: &mut FacBroker,
    signer: &Signer,
    policy_hash: &str,
    policy_digest: &[u8; 32],
    policy: &FacPolicyV1,
    budget_cas: &MemoryCas,
    _candidates_count: usize,
    print_unit: bool,
    canonicalizer_tuple_digest: &str,
) -> JobOutcome {
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
    // When a duplicate is detected, the pending file is moved to completed/
    // so it is not re-scanned every cycle (queue-pinning DoS prevention).
    let spec = &candidate.spec;
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    if apm2_core::fac::has_receipt_for_job(&receipts_dir, &spec.job_id) {
        let _ = move_to_dir_safe(path, &queue_root.join(COMPLETED_DIR), &file_name);
        return JobOutcome::Skipped {
            reason: format!(
                "receipt already exists for job {} (index lookup)",
                spec.job_id
            ),
        };
    }

    // Step 1+2: Use the bounded bytes already loaded by scan_pending.
    //
    // The file was already validated by `scan_pending`; this avoids duplicate I/O.
    let _ = &candidate.raw_bytes;
    // Validate structure + digest + request_id binding.
    if let Err(e) = validate_job_spec(spec) {
        let is_digest_error = matches!(
            e,
            JobSpecError::DigestMismatch { .. } | JobSpecError::RequestIdMismatch { .. }
        );
        if is_digest_error {
            let reason = format!("digest validation failed: {e}");
            let moved_path = move_to_dir_safe(path, &queue_root.join(QUARANTINE_DIR), &file_name)
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
                FacJobOutcome::Quarantined,
                Some(DenialReasonCode::DigestMismatch),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
            ) {
                eprintln!(
                    "worker: WARNING: receipt emission failed for quarantined job: {receipt_err}"
                );
            }
            return JobOutcome::Quarantined { reason };
        }
        // Other validation errors (missing token, schema, etc.) -> deny.
        let reason = format!("validation failed: {e}");
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        let reason_code = match e {
            JobSpecError::MissingToken { .. } => DenialReasonCode::MissingChannelToken,
            JobSpecError::InvalidDigest { .. } => DenialReasonCode::MalformedSpec,
            _ => DenialReasonCode::ValidationFailed,
        };
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(reason_code),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // Step 3: Validate RFC-0028 token.
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
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Use monotonic wall-clock seconds for token temporal validation.
    let current_time_secs = current_timestamp_epoch_secs();

    let boundary_check = match decode_channel_context_token(
        token,
        verifying_key,
        &spec.actuation.lease_id,
        current_time_secs,
        &spec.actuation.request_id,
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
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // Validate boundary check defects.
    let defects = validate_channel_boundary(&boundary_check);
    let boundary_trace = build_channel_boundary_trace(&defects);
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
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // Step 4: Evaluate RFC-0029 queue admission.
    //
    if !broker.is_admission_health_gate_passed() {
        let reason = "broker admission health gate not passed (INV-BH-003)".to_string();
        let admission_trace = JobQueueAdmissionTrace {
            verdict: "deny".to_string(),
            queue_lane: spec.queue_lane.clone(),
            defect_reason: Some("admission health gate not passed".to_string()),
        };
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
            Some(DenialReasonCode::AdmissionHealthGateFailed),
            &reason,
            Some(&boundary_trace),
            Some(&admission_trace),
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
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
        .build_evaluation_window(
            DEFAULT_BOUNDARY_ID,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .unwrap_or_else(|_| make_default_eval_window());

    let envelope = broker
        .issue_time_authority_envelope_default_ttl(
            DEFAULT_BOUNDARY_ID,
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
        cost: 1,
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
    // job is moved to denied/.
    if let Err(e) = consume_authority(queue_root, &spec.job_id, &spec.job_spec_digest) {
        let reason = format!("PCAC consume failed: {e}");
        let moved_path = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(DENIED_DIR),
            &claimed_file_name,
        )
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
            Some(DenialReasonCode::PcacConsumeFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
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
    let mut acquired_guard = None;
    let mut acquired_lane_id = String::new();

    for lane_id in &lane_ids {
        if let Ok(Some(guard)) = lane_mgr.try_lock(lane_id) {
            acquired_guard = Some(guard);
            acquired_lane_id.clone_from(lane_id);
            break;
        }
    }

    let Some(_lane_guard) = acquired_guard else {
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
        let moved_path = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(DENIED_DIR),
            &claimed_file_name,
        )
        .map(|p| {
            p.strip_prefix(queue_root)
                .unwrap_or(&p)
                .to_string_lossy()
                .to_string()
        })
        .ok();
        if moved_path.is_none() {
            eprintln!("worker: WARNING: failed to move job to denied");
        }
        let reason = format!("preflight failed: {error:?}");
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::InsufficientDiskSpace),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied {
            reason: format!("preflight failed: {error:?}"),
        };
    }

    // Step 7: Compute authoritative Systemd properties for the acquired lane.
    // This is the single source of truth for CPU/memory/PIDs/IO/timeouts and
    // is shared between user-mode and system-mode execution backends.
    let lane_dir = lane_mgr.lane_dir(&acquired_lane_id);
    let lane_profile = match LaneProfileV1::load(&lane_dir) {
        Ok(profile) => profile,
        Err(e) => {
            let reason = format!("lane profile load failed for {acquired_lane_id}: {e}");
            let moved_path = move_to_dir_safe(
                &claimed_path,
                &queue_root.join(DENIED_DIR),
                &claimed_file_name,
            )
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
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }
            return JobOutcome::Denied { reason };
        },
    };

    let lane_systemd_properties =
        SystemdUnitProperties::from_lane_profile(&lane_profile, Some(&spec.constraints));
    if print_unit {
        eprintln!(
            "worker: computed systemd properties for job {}",
            spec.job_id
        );
        eprintln!("{}", lane_systemd_properties.to_unit_directives());
        eprintln!("worker: D-Bus properties for job {}", spec.job_id);
        eprintln!("{:?}", lane_systemd_properties.to_dbus_properties());
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
    if !claimed_path.exists() {
        return JobOutcome::Skipped {
            reason: "claimed file disappeared during execution".to_string(),
        };
    }

    let mut patch_digest: Option<String> = None;
    // process_job executes one job at a time in a single worker lane, so
    // blocking mirror I/O is intentionally accepted in this default-mode
    // execution path. The entire job execution remains sequential behind the
    // lane lease and remains fail-closed on error.
    let mirror_manager = RepoMirrorManager::new(fac_root);
    if let Err(e) = mirror_manager.ensure_mirror(&spec.source.repo_id, None) {
        let reason = format!("mirror ensure failed: {e}");
        let moved_path = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(DENIED_DIR),
            &claimed_file_name,
        )
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
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
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
        let moved_path = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(DENIED_DIR),
            &claimed_file_name,
        )
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
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    if spec.source.kind == "patch_injection" {
        let inline_patch_error =
            "patch_injection requires inline patch bytes (CAS backend not yet implemented)";

        let deny_with_reason = |reason: &str| -> JobOutcome {
            let moved_path = move_to_dir_safe(
                &claimed_path,
                &queue_root.join(DENIED_DIR),
                &claimed_file_name,
            )
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
                Some(DenialReasonCode::ValidationFailed),
                reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }
            JobOutcome::Denied {
                reason: reason.to_string(),
            }
        };

        let Some(patch_value) = &spec.source.patch else {
            return deny_with_reason(inline_patch_error);
        };
        let Some(patch_obj) = patch_value.as_object() else {
            return deny_with_reason(inline_patch_error);
        };
        let Some(bytes_b64) = patch_obj.get("bytes").and_then(|value| value.as_str()) else {
            return deny_with_reason(inline_patch_error);
        };
        let patch_bytes = match STANDARD.decode(bytes_b64) {
            Ok(bytes) => bytes,
            Err(err) => {
                return deny_with_reason(&format!("invalid base64 in patch.bytes: {err}"));
            },
        };
        if let Some(expected_digest) = patch_obj.get("digest").and_then(|v| v.as_str()) {
            let actual_digest = format!("b3-256:{}", blake3::hash(&patch_bytes).to_hex());
            let expected_bytes = expected_digest.as_bytes();
            let actual_bytes = actual_digest.as_bytes();
            if expected_bytes.len() != actual_bytes.len()
                || !bool::from(expected_bytes.ct_eq(actual_bytes))
            {
                return deny_with_reason(&format!(
                    "patch digest mismatch: expected {expected_digest}, got {actual_digest}"
                ));
            }
        }

        let blob_store = BlobStore::new(fac_root);
        if let Err(error) = blob_store.store(&patch_bytes) {
            return deny_with_reason(&format!("failed to store patch in blob store: {error}"));
        }

        let patch_outcome = match mirror_manager.apply_patch(&lane_workspace, &patch_bytes) {
            Ok(patch_outcome) => patch_outcome,
            Err(err) => {
                return deny_with_reason(&format!("patch apply failed: {err}"));
            },
        };
        patch_digest = Some(patch_outcome.patch_digest);
    } else if spec.source.kind != "mirror_commit" {
        let reason = format!("unsupported source kind: {}", spec.source.kind);
        let moved_path = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(DENIED_DIR),
            &claimed_file_name,
        )
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
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // Step 8: Write authoritative GateReceipt and move to completed.
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
            .passed(false)
            .build_and_sign(signer);

    if let Err(receipt_err) = emit_job_receipt(
        fac_root,
        spec,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&boundary_trace),
        Some(&queue_trace),
        budget_trace.as_ref(),
        patch_digest.as_deref(),
        Some(canonicalizer_tuple_digest),
        None,
        policy_hash,
    ) {
        eprintln!("worker: receipt emission failed, cannot complete job: {receipt_err}");
        if let Err(move_err) = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(PENDING_DIR),
            &claimed_file_name,
        ) {
            eprintln!("worker: WARNING: failed to return claimed job to pending: {move_err}");
        }
        return JobOutcome::Skipped {
            reason: "receipt emission failed".to_string(),
        };
    }

    // Persist the gate receipt alongside the completed job.
    write_gate_receipt(queue_root, &claimed_file_name, &gate_receipt);

    // Move to completed.
    if let Err(e) = move_to_dir_safe(
        &claimed_path,
        &queue_root.join(COMPLETED_DIR),
        &claimed_file_name,
    ) {
        return JobOutcome::Skipped {
            reason: format!("move to completed failed: {e}"),
        };
    }

    // Lane guard is dropped here (RAII), releasing the lane lock.
    let _ = acquired_lane_id;

    JobOutcome::Completed {
        job_id: spec.job_id.clone(),
    }
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
    let file = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let file_size = metadata.len();
    if file_size > max_size as u64 {
        return Err(format!("file size {file_size} exceeds max {max_size}"));
    }

    // Read with explicit size bound. We allocate based on verified metadata.
    #[allow(clippy::cast_possible_truncation)]
    let alloc_size = file_size as usize;
    let mut buf = Vec::with_capacity(alloc_size);

    // Read up to max_size + 1 to detect if the file grew between stat and read.
    let read_limit = max_size.saturating_add(1);
    let mut limited_reader = file.take(read_limit as u64);
    limited_reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("read error on {}: {e}", path.display()))?;

    if buf.len() > max_size {
        return Err(format!(
            "file grew to {} (exceeds max {})",
            buf.len(),
            max_size
        ));
    }

    Ok(buf)
}

/// Loads or generates a persistent signing key from
/// `$APM2_HOME/private/fac/signing_key`.
///
/// On first run, generates a new key and saves it with 0600 permissions.
/// On subsequent runs, loads the existing key. This keeps broker state and
/// receipts consistent across worker restarts.
fn load_or_generate_persistent_signer() -> Result<Signer, String> {
    let fac_root = resolve_fac_root()?;
    let key_path = fac_root.join("signing_key");

    if key_path.exists() {
        let bytes = read_bounded(&key_path, 64)?;
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
            let perms = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(&key_path, perms)
                .map_err(|e| format!("cannot set key permissions: {e}"))?;
        }
        Ok(signer)
    }
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

/// Atomic rename that fails (instead of overwriting) when the destination
/// already exists.  Uses Linux `renameat2(RENAME_NOREPLACE)`.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn rename_noreplace(src: &Path, dest: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_c = CString::new(src.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let dest_c = CString::new(dest.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // SAFETY: paths are valid C strings, AT_FDCWD means use current directory
    // for relative paths.
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dest_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Best-effort fallback for non-Linux: check + rename with inherent TOCTOU
/// window.  Acceptable because the nanosecond-timestamped collision path in
/// `move_to_dir_safe` provides a secondary safety net.
#[cfg(not(target_os = "linux"))]
fn rename_noreplace(src: &Path, dest: &Path) -> std::io::Result<()> {
    if dest.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    fs::rename(src, dest)
}

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

    let receipt = builder
        .try_build()
        .map_err(|e| format!("cannot build scan receipt: {e}"))?;

    persist_content_addressed_receipt(&fac_root.join(FAC_RECEIPTS_DIR), &receipt)
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
) -> Result<PathBuf, String> {
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

    let receipt = builder
        .try_build()
        .map_err(|e| format!("cannot build job receipt: {e}"))?;
    persist_content_addressed_receipt(&fac_root.join(FAC_RECEIPTS_DIR), &receipt)
}

fn compute_job_spec_digest_preview(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    format!("b3-256:{}", hash.to_hex())
}

fn build_channel_boundary_trace(defects: &[ChannelBoundaryDefect]) -> ChannelBoundaryTrace {
    let mut defect_classes = Vec::new();
    for defect in defects.iter().take(MAX_BOUNDARY_DEFECT_CLASSES) {
        defect_classes.push(strip_json_string_quotes(&serialize_to_json_string(
            &defect.violation_class,
        )));
    }

    let defect_count = u32::try_from(defects.len()).unwrap_or(u32::MAX);
    ChannelBoundaryTrace {
        passed: defects.is_empty(),
        defect_count,
        defect_classes,
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
    }
}

fn serialize_to_json_string<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"unknown\"".to_string())
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
fn make_default_eval_window() -> HtfEvaluationWindow {
    HtfEvaluationWindow {
        boundary_id: DEFAULT_BOUNDARY_ID.to_string(),
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
        let err = serde_json::json!({
            "error": message,
        });
        eprintln!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
    } else {
        eprintln!("worker error: {message}");
    }
}

/// Prints a JSON-serializable value to stdout.
fn print_json<T: Serialize>(value: &T) {
    if let Ok(json) = serde_json::to_string_pretty(value) {
        println!("{json}");
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
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
        assert!(result.unwrap_err().contains("exceeds max"),);
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

    fn make_receipt_test_spec() -> FacJobSpecV1 {
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
                decoded_source: None,
            },
            source: apm2_core::fac::job_spec::JobSource {
                kind: "mirror_commit".to_string(),
                repo_id: "repo-001".to_string(),
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
        }
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
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "control".to_string(),
            defect_reason: None,
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
}
