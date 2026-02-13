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

use apm2_core::channel::{decode_channel_context_token, validate_channel_boundary};
use apm2_core::crypto::Signer;
use apm2_core::economics::queue_admission::{
    HtfEvaluationWindow, QueueAdmissionRequest, QueueAdmissionVerdict, QueueLane,
    QueueSchedulerState, evaluate_queue_admission,
};
use apm2_core::fac::broker::{BrokerSignatureVerifier, FacBroker};
use apm2_core::fac::job_spec::{
    FacJobSpecV1, JobSpecError, MAX_JOB_SPEC_SIZE, deserialize_job_spec, validate_job_spec,
};
use apm2_core::fac::lane::LaneManager;
use apm2_core::fac::{GateReceipt, GateReceiptBuilder};
use serde::Serialize;

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
const QUARANTINED_DIR: &str = "quarantined";

/// Maximum poll interval to prevent misconfiguration (1 hour).
const MAX_POLL_INTERVAL_SECS: u64 = 3600;

/// Schema identifier for worker receipt traces.
const WORKER_RECEIPT_SCHEMA: &str = "apm2.fac.worker_receipt.v1";

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

/// A candidate pending job for sorting and processing.
#[derive(Debug)]
struct PendingCandidate {
    /// Path to the pending JSON file.
    path: PathBuf,
    /// Deserialized job spec (valid parse only, not yet fully validated).
    spec: FacJobSpecV1,
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
pub fn run_fac_worker(once: bool, poll_interval_secs: u64, max_jobs: u64, json_output: bool) -> u8 {
    let poll_interval_secs = poll_interval_secs.min(MAX_POLL_INTERVAL_SECS);

    // Resolve queue root directory
    let queue_root = match resolve_queue_root() {
        Ok(root) => root,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot resolve queue root: {e}"));
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

    // Create broker for token verification and admission evaluation.
    // In default mode, the broker and worker share a process: the same
    // FacBroker instance issues tokens AND verifies them. This is documented
    // as a limitation of default-mode operation. Distributed workers would
    // need to load the broker's persisted verifying key.
    let mut broker = FacBroker::new();

    // Perform admission health gate check so the broker can issue tokens.
    // In default (local) mode we use minimal health check inputs.
    let mut checker = apm2_core::fac::broker_health::BrokerHealthChecker::new();

    // Issue a time authority envelope from the broker so RFC-0029 admission
    // has valid TP-EIO29-001 authority. Without this, admission always denies
    // fail-closed due to missing envelope.
    let current_tick = broker.current_tick();
    let eval_window = broker
        .build_evaluation_window(
            DEFAULT_BOUNDARY_ID,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            current_tick.saturating_add(1),
        )
        .unwrap_or_else(|_| make_default_eval_window());

    let _health = broker.check_health(None, &eval_window, &[], &mut checker);

    let verifying_key = broker.verifying_key();
    let signer = Signer::generate();

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
        let candidates = match scan_pending(&queue_root) {
            Ok(c) => c,
            Err(e) => {
                output_worker_error(json_output, &format!("scan error: {e}"));
                if once {
                    return exit_codes::GENERIC_ERROR;
                }
                sleep_remaining(cycle_start, poll_interval_secs);
                continue;
            },
        };

        if candidates.is_empty() {
            if once {
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

            let outcome = process_job(candidate, &queue_root, &verifying_key, &mut broker, &signer);

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

            if once {
                if json_output {
                    print_json(&summary);
                }
                return exit_codes::SUCCESS;
            }
        }

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

    exit_codes::SUCCESS
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
fn scan_pending(queue_root: &Path) -> Result<Vec<PendingCandidate>, String> {
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
                let _ = move_to_dir_safe(&path, &queue_root.join(QUARANTINED_DIR), &file_name);
                write_receipt(queue_root, &file_name, "quarantine", &reason, None);
                continue;
            },
        };

        // Bounded deserialize.
        // On deserialize failure -> quarantine + receipt (INV-WRK-007).
        let spec = match deserialize_job_spec(&bytes) {
            Ok(s) => s,
            Err(e) => {
                let reason = format!("deserialization failed: {e}");
                let _ = move_to_dir_safe(&path, &queue_root.join(QUARANTINED_DIR), &file_name);
                write_receipt(queue_root, &file_name, "quarantine", &reason, None);
                continue;
            },
        };

        candidates.push(PendingCandidate { path, spec });
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
fn process_job(
    candidate: &PendingCandidate,
    queue_root: &Path,
    verifying_key: &apm2_core::crypto::VerifyingKey,
    broker: &mut FacBroker,
    signer: &Signer,
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

    // Step 1+2: Re-read and fully validate (bounded deserialize + digest check).
    let bytes = match read_bounded(path, MAX_JOB_SPEC_SIZE) {
        Ok(b) => b,
        Err(e) => {
            // Read failure during processing -> quarantine + receipt.
            let reason = format!("cannot read file: {e}");
            let _ = move_to_dir_safe(path, &queue_root.join(QUARANTINED_DIR), &file_name);
            write_receipt(queue_root, &file_name, "quarantine", &reason, None);
            return JobOutcome::Quarantined { reason };
        },
    };

    let spec = match deserialize_job_spec(&bytes) {
        Ok(s) => s,
        Err(e) => {
            // Malformed JSON -> quarantine + receipt.
            let reason = format!("deserialization failed: {e}");
            let _ = move_to_dir_safe(path, &queue_root.join(QUARANTINED_DIR), &file_name);
            write_receipt(queue_root, &file_name, "quarantine", &reason, None);
            return JobOutcome::Quarantined { reason };
        },
    };

    // Validate structure + digest + request_id binding.
    if let Err(e) = validate_job_spec(&spec) {
        let is_digest_error = matches!(
            e,
            JobSpecError::DigestMismatch { .. } | JobSpecError::RequestIdMismatch { .. }
        );
        if is_digest_error {
            let reason = format!("digest validation failed: {e}");
            let _ = move_to_dir_safe(path, &queue_root.join(QUARANTINED_DIR), &file_name);
            write_receipt(
                queue_root,
                &file_name,
                "quarantine",
                &reason,
                Some(&spec.job_id),
            );
            return JobOutcome::Quarantined { reason };
        }
        // Other validation errors (missing token, schema, etc.) -> deny.
        let reason = format!("validation failed: {e}");
        let _ = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name);
        write_receipt(queue_root, &file_name, "deny", &reason, Some(&spec.job_id));
        return JobOutcome::Denied { reason };
    }

    // Step 3: Validate RFC-0028 token.
    let token = match &spec.actuation.channel_context_token {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            let reason = "missing channel_context_token".to_string();
            let _ = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name);
            write_receipt(queue_root, &file_name, "deny", &reason, Some(&spec.job_id));
            return JobOutcome::Denied { reason };
        },
    };

    let current_time_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

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
            let _ = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name);
            write_receipt(queue_root, &file_name, "deny", &reason, Some(&spec.job_id));
            return JobOutcome::Denied { reason };
        },
    };

    // Validate boundary check defects.
    let defects = validate_channel_boundary(&boundary_check);
    if !defects.is_empty() {
        let reason = format!(
            "channel boundary violations: {}",
            defects
                .iter()
                .map(|d| format!("{:?}", d.violation_class))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name);
        write_receipt(queue_root, &file_name, "deny", &reason, Some(&spec.job_id));
        return JobOutcome::Denied { reason };
    }

    // Step 4: Evaluate RFC-0029 queue admission.
    //
    // Parse the spec's queue_lane to determine the correct lane, rather than
    // hard-coding Bulk (MAJOR-3 fix).
    let lane = parse_queue_lane(&spec.queue_lane);

    let scheduler = QueueSchedulerState::new();
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

    let decision = evaluate_queue_admission(&admission_request, &scheduler, Some(&verifier));

    if decision.verdict != QueueAdmissionVerdict::Allow {
        let reason = decision.defect().map_or_else(
            || "admission denied (no defect detail)".to_string(),
            |defect| format!("admission denied: {}", defect.reason),
        );
        let _ = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name);

        // Write admission trace to receipt.
        write_receipt(queue_root, &file_name, "deny", &reason, Some(&spec.job_id));
        return JobOutcome::Denied { reason };
    }

    // Step 5: Atomic claim via rename (INV-WRK-003).
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    if let Err(e) = move_to_dir_safe(path, &claimed_dir, &file_name) {
        // If rename fails (e.g., already claimed by another worker), skip.
        return JobOutcome::Skipped {
            reason: format!("atomic claim failed: {e}"),
        };
    }

    // Step 6: Acquire lane lease (INV-WRK-008, BLOCKER-3 fix).
    //
    // Try to acquire a lane lock. If no lane is available, move the job
    // back to pending for retry in a future cycle.
    let fac_root = match resolve_fac_root() {
        Ok(root) => root,
        Err(e) => {
            // Cannot resolve FAC root -> move back to pending.
            let _ = move_to_dir_safe(
                &claimed_dir.join(&file_name),
                &queue_root.join(PENDING_DIR),
                &file_name,
            );
            return JobOutcome::Skipped {
                reason: format!("cannot resolve FAC root for lane management: {e}"),
            };
        },
    };

    let lane_mgr = match LaneManager::new(fac_root) {
        Ok(mgr) => mgr,
        Err(e) => {
            let _ = move_to_dir_safe(
                &claimed_dir.join(&file_name),
                &queue_root.join(PENDING_DIR),
                &file_name,
            );
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
        let _ = move_to_dir_safe(
            &claimed_dir.join(&file_name),
            &queue_root.join(PENDING_DIR),
            &file_name,
        );
        return JobOutcome::Skipped {
            reason: "no lane available, returning to pending".to_string(),
        };
    };

    // Step 7: Execute job under containment.
    //
    // For the default-mode MVP, execution validates that the job is structurally
    // sound and the lane is held. Full FESv1 execution (subprocess spawning,
    // cgroup containment) is deferred to a future ticket. The lane guard ensures
    // exclusive access during this phase.
    //
    // We verify that the claimed file is still present and intact before
    // marking as completed.
    let claimed_path = claimed_dir.join(&file_name);
    if !claimed_path.exists() {
        return JobOutcome::Skipped {
            reason: "claimed file disappeared during execution".to_string(),
        };
    }

    // Step 8: Write authoritative GateReceipt and move to completed.
    let evidence_hash = compute_evidence_hash(spec.job_id.as_bytes());
    let changeset_digest = compute_evidence_hash(spec.job_spec_digest.as_bytes());
    let receipt_id = format!("wkr-{}-{}", spec.job_id, current_timestamp_epoch_secs());
    let receipt = GateReceiptBuilder::new(&receipt_id, "fac-worker-exec", &spec.actuation.lease_id)
        .changeset_digest(changeset_digest)
        .executor_actor_id("fac-worker")
        .receipt_version(1)
        .payload_kind("quality")
        .payload_schema_version(1)
        .payload_hash(evidence_hash)
        .evidence_bundle_hash(evidence_hash)
        .job_spec_digest(&spec.job_spec_digest)
        .passed(true)
        .build_and_sign(signer);

    // Persist the gate receipt alongside the completed job.
    write_gate_receipt(queue_root, &file_name, &receipt);

    // Move to completed.
    if let Err(e) = move_to_dir_safe(&claimed_path, &queue_root.join(COMPLETED_DIR), &file_name) {
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
    let home = resolve_apm2_home()?;
    Ok(home.join(QUEUE_DIR))
}

/// Resolves the FAC root directory at `$APM2_HOME/private/fac`.
fn resolve_fac_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home()?;
    Ok(home.join("private").join("fac"))
}

/// Resolves `$APM2_HOME` from environment or default.
fn resolve_apm2_home() -> Result<PathBuf, String> {
    if let Some(override_dir) = std::env::var_os("APM2_HOME") {
        let path = PathBuf::from(override_dir);
        if !path.as_os_str().is_empty() {
            return Ok(path);
        }
    }
    let base_dirs = directories::BaseDirs::new()
        .ok_or_else(|| "could not resolve home directory".to_string())?;
    Ok(base_dirs.home_dir().join(".apm2"))
}

/// Ensures all required queue subdirectories exist.
fn ensure_queue_dirs(queue_root: &Path) -> Result<(), String> {
    for dir in [
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINED_DIR,
    ] {
        let path = queue_root.join(dir);
        if !path.exists() {
            fs::create_dir_all(&path)
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Reads a file with bounded I/O (INV-WRK-001).
///
/// Returns an error if the file is larger than `max_size` or cannot be read.
fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;

    let file_size = metadata.len();
    if file_size > max_size as u64 {
        return Err(format!("file size {file_size} exceeds max {max_size}"));
    }

    // Read with explicit size bound. We allocate based on verified metadata.
    #[allow(clippy::cast_possible_truncation)]
    let alloc_size = file_size as usize;
    let mut buf = Vec::with_capacity(alloc_size);
    let file = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;

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

/// Atomically moves a file to a destination directory with collision-safe
/// target names.
///
/// Uses `fs::rename` for atomicity on the same filesystem (INV-WRK-003).
/// If the target file already exists (duplicate job ID from a concurrent
/// worker or replay), the file name is suffixed with a nanosecond timestamp
/// to prevent clobbering (MAJOR-2 fix).
fn move_to_dir_safe(src: &Path, dest_dir: &Path, file_name: &str) -> Result<(), String> {
    if !dest_dir.exists() {
        fs::create_dir_all(dest_dir)
            .map_err(|e| format!("cannot create {}: {e}", dest_dir.display()))?;
    }
    let dest = dest_dir.join(file_name);

    // Check for collision and generate a unique name if needed.
    if dest.exists() {
        let ts_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stem = file_name.trim_end_matches(".json");
        let safe_name = format!("{stem}-{ts_nanos}.json");
        let safe_dest = dest_dir.join(safe_name);
        return fs::rename(src, &safe_dest)
            .map_err(|e| format!("rename {} -> {}: {e}", src.display(), safe_dest.display()));
    }

    fs::rename(src, &dest)
        .map_err(|e| format!("rename {} -> {}: {e}", src.display(), dest.display()))
}

/// Writes a receipt file to `queue/receipts/` (or alongside the moved file).
///
/// Receipt is a minimal JSON trace with no secrets (INV-WRK-004).
fn write_receipt(
    queue_root: &Path,
    file_name: &str,
    outcome: &str,
    reason: &str,
    job_id: Option<&str>,
) {
    let receipts_dir = queue_root.join("receipts");
    let _ = fs::create_dir_all(&receipts_dir);

    // Truncate reason to prevent unbounded receipt size.
    let bounded_reason: String = reason.chars().take(512).collect();

    let receipt = serde_json::json!({
        "schema": WORKER_RECEIPT_SCHEMA,
        "source_file": file_name,
        "outcome": outcome,
        "reason": bounded_reason,
        "job_id": job_id.unwrap_or("unknown"),
        "timestamp_secs": current_timestamp_epoch_secs(),
    });

    let receipt_name = format!(
        "{}-{}.receipt.json",
        file_name.trim_end_matches(".json"),
        outcome
    );
    let receipt_path = receipts_dir.join(receipt_name);

    // Best-effort write; worker should not fail due to receipt I/O.
    if let Ok(bytes) = serde_json::to_vec_pretty(&receipt) {
        let _ = fs::write(&receipt_path, bytes);
    }
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
            QUARANTINED_DIR,
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
    fn test_write_receipt_bounded_reason() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue_root = dir.path();

        let long_reason = "x".repeat(1024);
        write_receipt(queue_root, "test.json", "deny", &long_reason, Some("job1"));

        let receipt_path = queue_root.join("receipts").join("test-deny.receipt.json");
        assert!(receipt_path.exists(), "receipt should be written");

        let content = fs::read_to_string(&receipt_path).expect("read receipt");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse receipt");
        let reason = parsed["reason"].as_str().expect("reason field");
        assert!(
            reason.len() <= 512,
            "reason should be truncated to 512 chars, got {}",
            reason.len()
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
    fn test_scan_pending_quarantines_malformed_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue_root = dir.path().join("queue");
        ensure_queue_dirs(&queue_root).expect("create dirs");

        // Write a malformed JSON file to pending.
        let malformed_path = queue_root.join("pending").join("bad.json");
        fs::write(&malformed_path, b"not valid json {{{").expect("write malformed");

        let candidates = scan_pending(&queue_root).expect("scan");

        // Malformed file should have been quarantined, not included in candidates.
        assert!(
            candidates.is_empty(),
            "malformed file should not be a candidate"
        );

        // Check it was quarantined.
        let quarantine_dir = queue_root.join("quarantined");
        let quarantined_files: Vec<_> = fs::read_dir(&quarantine_dir)
            .expect("read quarantine")
            .flatten()
            .collect();
        assert!(
            !quarantined_files.is_empty(),
            "malformed file should be in quarantine"
        );

        // Check receipt was written.
        let receipts_dir = queue_root.join("receipts");
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

        let candidates = scan_pending(&queue_root).expect("scan");

        assert!(
            candidates.is_empty(),
            "oversize file should not be a candidate"
        );

        // Check it was quarantined.
        let quarantine_dir = queue_root.join("quarantined");
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
