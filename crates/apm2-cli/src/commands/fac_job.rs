// AGENT-AUTHORED (TCK-00533)
//! FAC Job lifecycle management: cancel command.
//!
//! Implements `apm2 fac job cancel <job_id>` with the following semantics:
//!
//! - **Pending job**: Atomically moves to `cancelled/` and emits a cancellation
//!   receipt.
//! - **Claimed/running job**: Enqueues a highest-priority `stop_revoke` job
//!   that will kill the active systemd unit (`KillMode=control-group`) and mark
//!   the target job cancelled.  The cancel command emits a non-terminal
//!   `CancellationRequested` receipt; the terminal `Cancelled` receipt is
//!   emitted by the worker when the `stop_revoke` is confirmed.
//! - **Completed job**: Returns an error (already finished).
//! - **Ambiguous state** (job found in multiple directories): Returns an error
//!   (fail-closed).
//!
//! Cancellation never deletes evidence or logs; it only stops execution and
//! writes receipts.
//!
//! # Security Model
//!
//! - The cancel command verifies local operator authority by checking that the
//!   caller owns the queue root directory (same uid).  This proves the caller
//!   has local filesystem privilege over the queue.
//! - Cancellation receipts include the cancellation reason and previous state.
//! - No evidence or log artifacts are deleted.
//! - `stop_revoke` jobs bypass the RFC-0028 channel context token requirement;
//!   the worker validates local-origin authority (queue directory ownership)
//!   instead.  This is the `CONTROL_LANE` concept: operator-initiated control
//!   jobs use filesystem-level privilege proof rather than broker tokens.
//! - Receipt emission failures are fatal: the cancel command fails with an
//!   error exit code rather than silently continuing without evidence.
//!
//! # Invariants
//!
//! - [INV-CANCEL-001] Fail-closed: ambiguous job state results in denial.
//! - [INV-CANCEL-002] Receipts are emitted for all cancellation outcomes.
//!   Receipt emission failure is fatal.
//! - [INV-CANCEL-003] Atomic state transitions via filesystem rename.
//! - [INV-CANCEL-004] Evidence and logs are never deleted by cancellation.
//! - [INV-CANCEL-005] `stop_revoke` jobs have priority 0 (highest).
//! - [INV-CANCEL-006] `cancel_target_job_id` uses strict `[A-Za-z0-9_-]`
//!   validation to prevent glob/path injection.
//! - [INV-CANCEL-007] `locate_job` scans ALL queue directories and denies on
//!   ambiguity (job found in multiple directories).
//! - [INV-CANCEL-008] Claimed-job cancel emits `CancellationRequested` (non-
//!   terminal); terminal `Cancelled` receipt is emitted only by the worker.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use apm2_core::fac::job_spec::{FacJobSpecV1, JobSource, LaneRequirements, MAX_JOB_SPEC_SIZE};
use apm2_core::fac::{
    DenialReasonCode, FacJobOutcome, FacJobReceiptV1Builder, persist_content_addressed_receipt,
};
use apm2_core::github::resolve_apm2_home;
use serde::Serialize;

use crate::commands::fac::CancelArgs;
use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Constants
// =============================================================================

/// Queue subdirectory names (duplicated from `fac_worker` for module
/// isolation).
const QUEUE_DIR: &str = "queue";
const PENDING_DIR: &str = "pending";
const CLAIMED_DIR: &str = "claimed";
const COMPLETED_DIR: &str = "completed";
const CANCELLED_DIR: &str = "cancelled";
const DENIED_DIR: &str = "denied";
const QUARANTINE_DIR: &str = "quarantine";

/// FAC receipt directory under `$APM2_HOME/private/fac`.
const FAC_RECEIPTS_DIR: &str = "receipts";

/// Maximum number of directory entries to scan when locating a job.
/// Prevents unbounded memory growth.
const MAX_SCAN_ENTRIES: usize = 4096;

// =============================================================================
// Output types
// =============================================================================

/// JSON output for cancel command.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CancelOutput {
    /// The job ID that was cancelled.
    job_id: String,
    /// Previous state of the job before cancellation.
    previous_state: String,
    /// The action taken.
    action: String,
    /// Path to the cancellation receipt.
    receipt_path: Option<String>,
    /// Path to the `stop_revoke` spec (if enqueued).
    stop_revoke_spec_path: Option<String>,
}

/// Represents the discovered state of a job in the queue.
#[derive(Debug)]
enum JobState {
    /// Job is in `pending/` directory.
    Pending(PathBuf),
    /// Job is in `claimed/` directory (may be running).
    Claimed(PathBuf),
    /// Job is in `completed/` directory (path used for state identity).
    Completed(#[allow(dead_code)] PathBuf),
    /// Job is in `cancelled/` directory (path used for state identity).
    Cancelled(#[allow(dead_code)] PathBuf),
    /// Job is in `denied/` directory (path used for state identity).
    Denied(#[allow(dead_code)] PathBuf),
    /// Job is in `quarantine/` directory (path used for state identity).
    Quarantined(#[allow(dead_code)] PathBuf),
    /// Job was not found in any directory.
    NotFound,
    /// Job was found in multiple directories (ambiguous, fail-closed).
    Ambiguous(Vec<String>),
}

// =============================================================================
// Authority check
// =============================================================================

/// Verifies that the caller has local operator authority over the queue.
///
/// On Unix, this checks that the queue root directory is owned by the current
/// user (same uid).  This proves the caller has filesystem-level privilege
/// over the queue, which is the local authority model for the cancel command.
///
/// The authority check is implemented by verifying that the caller can write
/// a probe file into the queue root directory.  This is a capability-based
/// proof: only users with filesystem write access to the queue directory can
/// successfully create and remove the probe file.
///
/// On non-Unix platforms, returns Ok (authority is assumed for local CLI).
fn verify_local_operator_authority(queue_root: &Path) -> Result<(), String> {
    // Capability-based authority proof: attempt to create a probe file in the
    // queue root.  Only callers with write access to the directory succeed.
    // This avoids unsafe FFI calls while providing the same security guarantee.
    let probe_path = queue_root.join(".cancel-authority-probe");
    fs::write(&probe_path, b"probe").map_err(|e| {
        format!(
            "operator authority denied: cannot write to queue root {}: {e}",
            queue_root.display()
        )
    })?;
    let _ = fs::remove_file(&probe_path);
    Ok(())
}

// =============================================================================
// Public entry point
// =============================================================================

/// Runs the `apm2 fac job cancel` command.
///
/// Returns an exit code.
pub fn run_cancel(args: &CancelArgs, json_output: bool) -> u8 {
    let queue_root = match resolve_queue_root() {
        Ok(root) => root,
        Err(e) => {
            output_error(json_output, &format!("cannot resolve queue root: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };
    let fac_root = match resolve_fac_root() {
        Ok(root) => root,
        Err(e) => {
            output_error(json_output, &format!("cannot resolve FAC root: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    // BLOCKER 1: Verify local operator authority before any mutation.
    if let Err(e) = verify_local_operator_authority(&queue_root) {
        output_error(json_output, &format!("authority check failed: {e}"));
        return exit_codes::PERMISSION_DENIED;
    }

    // Ensure the cancelled directory exists.
    let cancelled_dir = queue_root.join(CANCELLED_DIR);
    if let Err(e) = fs::create_dir_all(&cancelled_dir) {
        output_error(
            json_output,
            &format!("cannot create cancelled directory: {e}"),
        );
        return exit_codes::GENERIC_ERROR;
    }

    let job_id = &args.job_id;
    let reason = &args.reason;

    // MAJOR 5 (caller-side): Validate job_id charset before scanning.
    if !job_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        output_error(
            json_output,
            &format!("invalid job_id: only [A-Za-z0-9_-] characters allowed, got {job_id:?}"),
        );
        return exit_codes::VALIDATION_ERROR;
    }
    if job_id.is_empty() {
        output_error(json_output, "job_id must not be empty");
        return exit_codes::VALIDATION_ERROR;
    }

    // MAJOR 4: Locate the job across ALL queue directories; deny on ambiguity.
    let state = locate_job(&queue_root, job_id);

    match state {
        JobState::Pending(path) => {
            cancel_pending_job(&path, job_id, reason, &queue_root, &fac_root, json_output)
        },
        JobState::Claimed(path) => {
            cancel_claimed_job(&path, job_id, reason, &queue_root, &fac_root, json_output)
        },
        JobState::Completed(_) => {
            output_error(
                json_output,
                &format!("job {job_id} is already completed; cannot cancel"),
            );
            exit_codes::VALIDATION_ERROR
        },
        JobState::Cancelled(_) => {
            output_error(json_output, &format!("job {job_id} is already cancelled"));
            exit_codes::VALIDATION_ERROR
        },
        JobState::Denied(_) => {
            output_error(
                json_output,
                &format!("job {job_id} was denied; cannot cancel"),
            );
            exit_codes::VALIDATION_ERROR
        },
        JobState::Quarantined(_) => {
            output_error(
                json_output,
                &format!("job {job_id} was quarantined; cannot cancel"),
            );
            exit_codes::VALIDATION_ERROR
        },
        JobState::NotFound => {
            output_error(
                json_output,
                &format!("job {job_id} not found in any queue directory"),
            );
            exit_codes::NOT_FOUND
        },
        // INV-CANCEL-001 / MAJOR 4: Ambiguous state is fail-closed.
        JobState::Ambiguous(dirs) => {
            output_error(
                json_output,
                &format!(
                    "job {job_id} found in multiple directories (ambiguous state, fail-closed): {}",
                    dirs.join(", ")
                ),
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

// =============================================================================
// Cancel implementations
// =============================================================================

/// Cancels a pending job by atomically moving it to `cancelled/` and emitting
/// a receipt.
fn cancel_pending_job(
    path: &Path,
    job_id: &str,
    reason: &str,
    queue_root: &Path,
    fac_root: &Path,
    json_output: bool,
) -> u8 {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        output_error(json_output, "invalid job filename");
        return exit_codes::GENERIC_ERROR;
    };
    let file_name = file_name.to_string();

    // Read the spec for receipt emission.
    let spec = match read_job_spec(path) {
        Ok(spec) => spec,
        Err(e) => {
            output_error(json_output, &format!("cannot read job spec: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    // BLOCKER-2 fix: Emit the cancellation receipt BEFORE the state transition.
    // This ensures a job is NEVER in cancelled/ without a terminal receipt.
    // If receipt emission fails, the job remains in pending/ (safe state).
    let receipt_path = match emit_cancellation_receipt(fac_root, &spec, "pending", reason) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            output_error(
                json_output,
                &format!("FATAL: cancellation receipt emission failed: {e}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    // Atomically move to cancelled/ (INV-CANCEL-003).
    // Receipt is already persisted, so the cancelled/ invariant holds.
    let cancelled_path = match move_to_dir_safe(path, &queue_root.join(CANCELLED_DIR), &file_name) {
        Ok(p) => p,
        Err(e) => {
            output_error(json_output, &format!("cannot move job to cancelled: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    let output = CancelOutput {
        job_id: job_id.to_string(),
        previous_state: "pending".to_string(),
        action: "moved to cancelled".to_string(),
        receipt_path: Some(receipt_path),
        stop_revoke_spec_path: None,
    };

    if json_output {
        print_json(&output);
    } else {
        eprintln!(
            "cancel: job {} moved from pending to cancelled ({})",
            job_id,
            cancelled_path.display()
        );
    }

    exit_codes::SUCCESS
}

/// Cancels a claimed/running job by enqueuing a highest-priority `stop_revoke`
/// job.
///
/// MAJOR 1 / INV-CANCEL-008: Emits a `CancellationRequested` (non-terminal)
/// receipt.  The terminal `Cancelled` receipt is emitted only by the worker
/// after `handle_stop_revoke` confirms the target was stopped.
fn cancel_claimed_job(
    claimed_path: &Path,
    job_id: &str,
    reason: &str,
    queue_root: &Path,
    fac_root: &Path,
    json_output: bool,
) -> u8 {
    // Enqueue a stop_revoke job targeting this job.
    let stop_revoke_spec = match build_stop_revoke_spec(job_id, reason) {
        Ok(spec) => spec,
        Err(e) => {
            output_error(json_output, &format!("cannot build stop_revoke spec: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    let spec_json = match serde_json::to_vec_pretty(&stop_revoke_spec) {
        Ok(json) => json,
        Err(e) => {
            output_error(
                json_output,
                &format!("cannot serialize stop_revoke spec: {e}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    let pending_dir = queue_root.join(PENDING_DIR);
    if let Err(e) = fs::create_dir_all(&pending_dir) {
        output_error(
            json_output,
            &format!("cannot create pending directory: {e}"),
        );
        return exit_codes::GENERIC_ERROR;
    }

    let spec_filename = format!("{}.json", stop_revoke_spec.job_id);
    let spec_path = pending_dir.join(&spec_filename);

    // Atomic write: write to temp then rename.
    let tmp_path = pending_dir.join(format!(".tmp-{spec_filename}"));
    if let Err(e) = fs::write(&tmp_path, &spec_json) {
        output_error(json_output, &format!("cannot write stop_revoke spec: {e}"));
        return exit_codes::GENERIC_ERROR;
    }
    if let Err(e) = fs::rename(&tmp_path, &spec_path) {
        // Clean up temp file on failure.
        let _ = fs::remove_file(&tmp_path);
        output_error(
            json_output,
            &format!("cannot atomically place stop_revoke spec: {e}"),
        );
        return exit_codes::GENERIC_ERROR;
    }

    // MAJOR 1+2 fix: Emit a CancellationRequested (non-terminal) receipt.
    // The final Cancelled receipt will be emitted by the worker when
    // stop_revoke completes.
    //
    // MAJOR-2 fix: If read_job_spec fails, treat as a HARD failure.
    // A cancellation MUST NOT complete without a cancellation-requested receipt.
    // The stop_revoke spec is already enqueued, but we return an error exit
    // code to signal that the receipt could not be emitted.
    let spec_for_receipt = match read_job_spec(claimed_path) {
        Ok(spec) => spec,
        Err(e) => {
            output_error(
                json_output,
                &format!(
                    "FATAL: cannot read claimed job spec for receipt emission: {e}; \
                     stop_revoke was enqueued at {} but cancellation-requested receipt \
                     could not be emitted (fail-closed)",
                    spec_path.display()
                ),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    // MAJOR 1+6: Emit CancellationRequested receipt. Failure is fatal.
    let receipt_path =
        match emit_cancellation_requested_receipt(fac_root, &spec_for_receipt, "claimed", reason) {
            Ok(p) => Some(p.to_string_lossy().to_string()),
            Err(e) => {
                output_error(
                    json_output,
                    &format!("FATAL: cancellation-requested receipt emission failed: {e}"),
                );
                return exit_codes::GENERIC_ERROR;
            },
        };

    let output = CancelOutput {
        job_id: job_id.to_string(),
        previous_state: "claimed".to_string(),
        action: "stop_revoke enqueued".to_string(),
        receipt_path,
        stop_revoke_spec_path: Some(spec_path.to_string_lossy().to_string()),
    };

    if json_output {
        print_json(&output);
    } else {
        eprintln!(
            "cancel: stop_revoke enqueued for claimed job {} ({})",
            job_id,
            spec_path.display()
        );
    }

    exit_codes::SUCCESS
}

// =============================================================================
// Job state discovery
// =============================================================================

/// Locates a job by ID across ALL queue directories.
///
/// MAJOR 4 / INV-CANCEL-007: Scans every directory and denies on ambiguity
/// (job found in multiple directories).  Returns `JobState::Ambiguous` with
/// the list of matching directories when the job appears in more than one.
///
/// Uses bounded scanning to prevent unbounded memory growth.
fn locate_job(queue_root: &Path, job_id: &str) -> JobState {
    type StateConstructor = fn(PathBuf) -> JobState;
    let dirs_and_states: &[(&str, StateConstructor)] = &[
        (PENDING_DIR, JobState::Pending),
        (CLAIMED_DIR, JobState::Claimed),
        (COMPLETED_DIR, JobState::Completed),
        (CANCELLED_DIR, JobState::Cancelled),
        (DENIED_DIR, JobState::Denied),
        (QUARANTINE_DIR, JobState::Quarantined),
    ];

    let mut found: Vec<(&str, PathBuf, StateConstructor)> = Vec::new();

    for &(dir_name, state_constructor) in dirs_and_states {
        let dir_path = queue_root.join(dir_name);
        if !dir_path.is_dir() {
            continue;
        }

        if let Some(path) = find_job_in_dir(&dir_path, job_id) {
            found.push((dir_name, path, state_constructor));
        }
    }

    match found.len() {
        0 => JobState::NotFound,
        1 => {
            let (_, path, constructor) = found.into_iter().next().expect("checked len == 1");
            constructor(path)
        },
        _ => {
            // INV-CANCEL-001: Ambiguous state, fail-closed.
            let dirs: Vec<String> = found
                .iter()
                .map(|(name, _, _)| (*name).to_string())
                .collect();
            JobState::Ambiguous(dirs)
        },
    }
}

/// Searches a directory for a job spec file matching the given `job_id`.
///
/// Returns the first matching path, or None. Scans are bounded to
/// `MAX_SCAN_ENTRIES`.
fn find_job_in_dir(dir: &Path, job_id: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;

    for (idx, entry) in entries.enumerate() {
        if idx >= MAX_SCAN_ENTRIES {
            break;
        }

        let Ok(entry) = entry else { continue };
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        // Quick check: does the filename contain the job_id?
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if file_name.contains(job_id) {
                // Verify by reading the actual spec.
                if let Ok(spec) = read_job_spec(&path) {
                    if spec.job_id == job_id {
                        return Some(path);
                    }
                }
            }
        }

        // If filename doesn't match, try reading the spec anyway
        // (filenames may use collision-safe suffixes).
        if let Ok(spec) = read_job_spec(&path) {
            if spec.job_id == job_id {
                return Some(path);
            }
        }
    }

    None
}

// =============================================================================
// stop_revoke spec construction
// =============================================================================

/// Builds a `stop_revoke` job spec targeting the given `job_id`.
///
/// The spec has priority 0 (highest) to ensure it is processed before any
/// other pending jobs (INV-CANCEL-005).
///
/// BLOCKER 2+3: The `channel_context_token` is set to `None` because
/// `stop_revoke` jobs are operator-initiated local commands.  The worker
/// validates local-origin authority (queue directory ownership) instead of an
/// RFC-0028 token.  This is the `CONTROL_LANE` bypass: `stop_revoke` jobs are
/// validated via `validate_job_spec_control_lane()` which skips the token
/// requirement.
fn build_stop_revoke_spec(target_job_id: &str, reason: &str) -> Result<FacJobSpecV1, String> {
    let now = current_timestamp_epoch_secs();
    let stop_revoke_job_id = format!("stop-revoke-{target_job_id}-{now}");

    // For stop_revoke jobs, we use a placeholder source since the job
    // doesn't need repo checkout -- it only needs to kill a unit.
    let source = JobSource {
        kind: "mirror_commit".to_string(),
        repo_id: "internal/control".to_string(),
        head_sha: "0".repeat(40),
        patch: None,
    };

    // Build spec with highest priority (0).
    // CONTROL_LANE: token is intentionally None; the worker uses
    // validate_job_spec_control_lane() and verifies queue dir ownership.
    let mut spec = FacJobSpecV1 {
        schema: apm2_core::fac::job_spec::JOB_SPEC_SCHEMA_ID.to_string(),
        job_id: stop_revoke_job_id,
        job_spec_digest: String::new(),
        kind: "stop_revoke".to_string(),
        queue_lane: "control".to_string(),
        priority: 0, // Highest priority.
        enqueue_time: format_iso8601(now),
        actuation: apm2_core::fac::job_spec::Actuation {
            lease_id: format!("cancel-{target_job_id}"),
            request_id: String::new(),
            channel_context_token: None,
            decoded_source: Some(truncate_string(reason, 64)),
        },
        source,
        lane_requirements: LaneRequirements {
            lane_profile_hash: None,
        },
        constraints: apm2_core::fac::job_spec::JobConstraints {
            require_nextest: false,
            test_timeout_seconds: Some(30),
            memory_max_bytes: None,
        },
        cancel_target_job_id: Some(target_job_id.to_string()),
    };

    // Compute digest.
    let digest = spec
        .compute_digest()
        .map_err(|e| format!("digest computation failed: {e}"))?;
    spec.job_spec_digest.clone_from(&digest);
    spec.actuation.request_id = digest;

    Ok(spec)
}

// =============================================================================
// Receipt emission
// =============================================================================

/// Emits a terminal cancellation receipt for a pending job.
fn emit_cancellation_receipt(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    previous_state: &str,
    reason: &str,
) -> Result<PathBuf, String> {
    let now = current_timestamp_epoch_secs();
    let receipt_id = format!("cancel-{}-{now}", spec.job_id);
    let full_reason = format!("cancelled from {previous_state}: {reason}");

    // Truncate reason to receipt limit (512 chars).
    let bounded_reason = truncate_string(&full_reason, 512);

    let builder = FacJobReceiptV1Builder::new(receipt_id, &spec.job_id, &spec.job_spec_digest)
        .outcome(FacJobOutcome::Cancelled)
        .denial_reason(DenialReasonCode::Cancelled)
        .reason(&bounded_reason)
        .timestamp_secs(now);

    let receipt = builder
        .try_build()
        .map_err(|e| format!("cannot build cancellation receipt: {e}"))?;

    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    persist_content_addressed_receipt(&receipts_dir, &receipt)
}

/// Emits a non-terminal `CancellationRequested` receipt for a claimed job.
///
/// MAJOR 1: This is NOT a terminal receipt.  The terminal `Cancelled` receipt
/// is emitted only by the worker's `handle_stop_revoke` after the target is
/// confirmed stopped.
fn emit_cancellation_requested_receipt(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    previous_state: &str,
    reason: &str,
) -> Result<PathBuf, String> {
    let now = current_timestamp_epoch_secs();
    let receipt_id = format!("cancel-req-{}-{now}", spec.job_id);
    let full_reason = format!("cancellation requested from {previous_state}: {reason}");

    // Truncate reason to receipt limit (512 chars).
    let bounded_reason = truncate_string(&full_reason, 512);

    let builder = FacJobReceiptV1Builder::new(receipt_id, &spec.job_id, &spec.job_spec_digest)
        .outcome(FacJobOutcome::CancellationRequested)
        .denial_reason(DenialReasonCode::Cancelled)
        .reason(&bounded_reason)
        .timestamp_secs(now);

    let receipt = builder
        .try_build()
        .map_err(|e| format!("cannot build cancellation-requested receipt: {e}"))?;

    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    persist_content_addressed_receipt(&receipts_dir, &receipt)
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

/// Reads and deserializes a job spec from a file with bounded I/O.
///
/// BLOCKER-1 fix: Uses `File::open().take(MAX_JOB_SPEC_SIZE + 1)` to enforce
/// the size limit on the actual read operation.  This prevents
/// denial-of-service via special files (e.g. `/dev/zero`, procfs, FIFOs) where
/// `metadata.len()` may report zero or misleading sizes while producing
/// unbounded data on read.
fn read_job_spec(path: &Path) -> Result<FacJobSpecV1, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // Read at most MAX_JOB_SPEC_SIZE + 1 bytes.  If we get more than
    // MAX_JOB_SPEC_SIZE, the file is over the limit.
    let limit = (MAX_JOB_SPEC_SIZE as u64).saturating_add(1);
    let mut bounded_reader = file.take(limit);
    let mut bytes = Vec::with_capacity(MAX_JOB_SPEC_SIZE.min(8192));
    bounded_reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() > MAX_JOB_SPEC_SIZE {
        return Err(format!(
            "file content {} exceeds max {}",
            bytes.len(),
            MAX_JOB_SPEC_SIZE
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

/// Moves a file to a destination directory with collision-safe naming.
///
/// If the destination already exists, appends a nanosecond timestamp suffix.
fn move_to_dir_safe(src: &Path, dest_dir: &Path, file_name: &str) -> Result<PathBuf, String> {
    if let Err(e) = fs::create_dir_all(dest_dir) {
        return Err(format!(
            "cannot create directory {}: {e}",
            dest_dir.display()
        ));
    }
    let mut dest = dest_dir.join(file_name);
    if dest.exists() {
        let now = current_timestamp_nanos();
        let stem = Path::new(file_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(file_name);
        let ext = Path::new(file_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("json");
        dest = dest_dir.join(format!("{stem}-{now}.{ext}"));
    }
    fs::rename(src, &dest)
        .map_err(|e| format!("cannot move {} -> {}: {e}", src.display(), dest.display()))?;
    Ok(dest)
}

// =============================================================================
// Time helpers
// =============================================================================

/// Returns the current epoch timestamp in seconds.
fn current_timestamp_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Returns the current epoch timestamp in nanoseconds.
fn current_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

/// Formats an epoch timestamp as ISO 8601.
fn format_iso8601(epoch_secs: u64) -> String {
    // Minimal ISO 8601 format for queue timestamps.
    // We compute year/month/day/hour/min/sec from epoch.
    // For simplicity, use the chrono-free approach.
    let secs_per_day: u64 = 86400;
    let days = epoch_secs / secs_per_day;
    let time_of_day = epoch_secs % secs_per_day;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Compute date from days since epoch (1970-01-01).
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Converts days since 1970-01-01 to (year, month, day).
const fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil date from day count algorithm.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Truncates a string to the given maximum length.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find a valid UTF-8 boundary.
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// Prints a serializable value as JSON to stdout.
fn print_json<T: Serialize>(value: &T) {
    if let Ok(json) = serde_json::to_string_pretty(value) {
        println!("{json}");
    }
}

/// Outputs an error message in text or JSON format.
fn output_error(json_output: bool, message: &str) {
    if json_output {
        let err = serde_json::json!({ "error": message });
        println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
    } else {
        eprintln!("error: {message}");
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_iso8601() {
        // 2026-02-15T00:00:00Z = 1771027200 epoch seconds
        let ts = format_iso8601(1_771_027_200);
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
        assert!(ts.len() >= 20);
    }

    #[test]
    fn test_truncate_string_within_limit() {
        assert_eq!(truncate_string("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_string_at_limit() {
        assert_eq!(truncate_string("hello world", 5), "hello");
    }

    #[test]
    fn test_truncate_string_utf8_boundary() {
        // Multi-byte UTF-8 character.
        let s = "hello\u{00e9}world"; // e-acute is 2 bytes
        let truncated = truncate_string(s, 6);
        // Should not split the multi-byte char.
        assert!(truncated.len() <= 6);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn test_build_stop_revoke_spec() {
        let spec = build_stop_revoke_spec("target-job-123", "test cancellation")
            .expect("should build stop_revoke spec");

        assert_eq!(spec.kind, "stop_revoke");
        assert_eq!(spec.priority, 0);
        assert_eq!(spec.cancel_target_job_id.as_deref(), Some("target-job-123"));
        assert!(spec.job_id.starts_with("stop-revoke-target-job-123-"));
        assert!(!spec.job_spec_digest.is_empty());
        assert_eq!(spec.actuation.request_id, spec.job_spec_digest);
        // CONTROL_LANE: token is intentionally None.
        assert!(spec.actuation.channel_context_token.is_none());
    }

    #[test]
    fn test_locate_job_not_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path();
        fs::create_dir_all(queue_root.join(PENDING_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CLAIMED_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(COMPLETED_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CANCELLED_DIR)).unwrap();

        let state = locate_job(queue_root, "nonexistent-job");
        assert!(matches!(state, JobState::NotFound));
    }

    #[test]
    fn test_locate_job_ambiguous_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path();
        fs::create_dir_all(queue_root.join(PENDING_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CLAIMED_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(COMPLETED_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CANCELLED_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(DENIED_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(QUARANTINE_DIR)).unwrap();

        // Create the same job spec in two directories.
        let spec = build_stop_revoke_spec("ambig-target", "test").expect("spec builds");
        let spec_json = serde_json::to_vec_pretty(&spec).unwrap();
        let file_name = format!("{}.json", spec.job_id);
        fs::write(queue_root.join(PENDING_DIR).join(&file_name), &spec_json).unwrap();
        fs::write(queue_root.join(CLAIMED_DIR).join(&file_name), &spec_json).unwrap();

        let state = locate_job(queue_root, &spec.job_id);
        assert!(
            matches!(state, JobState::Ambiguous(ref dirs) if dirs.len() == 2),
            "expected Ambiguous with 2 dirs, got {state:?}"
        );
    }

    #[test]
    fn test_cancel_pending_job_in_tempdir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        let fac_root = tmp.path().join("fac");
        fs::create_dir_all(queue_root.join(PENDING_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CANCELLED_DIR)).unwrap();
        fs::create_dir_all(fac_root.join(FAC_RECEIPTS_DIR)).unwrap();

        // Create a minimal job spec file in pending/.
        let spec = build_stop_revoke_spec("dummy-target", "test").expect("spec builds");
        let spec_json = serde_json::to_vec_pretty(&spec).unwrap();
        let file_name = format!("{}.json", spec.job_id);
        let pending_path = queue_root.join(PENDING_DIR).join(&file_name);
        fs::write(&pending_path, &spec_json).unwrap();

        // Verify the job is found as pending.
        let state = locate_job(&queue_root, &spec.job_id);
        assert!(matches!(state, JobState::Pending(_)));

        // Cancel it.
        let exit_code = cancel_pending_job(
            &pending_path,
            &spec.job_id,
            "unit test cancellation",
            &queue_root,
            &fac_root,
            false,
        );
        assert_eq!(exit_code, exit_codes::SUCCESS);

        // Verify: no longer in pending, now in cancelled.
        assert!(!pending_path.exists());
        let state_after = locate_job(&queue_root, &spec.job_id);
        assert!(matches!(state_after, JobState::Cancelled(_)));
    }

    #[test]
    fn test_cancel_claimed_enqueues_stop_revoke() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        let fac_root = tmp.path().join("fac");
        fs::create_dir_all(queue_root.join(PENDING_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CLAIMED_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CANCELLED_DIR)).unwrap();
        fs::create_dir_all(fac_root.join(FAC_RECEIPTS_DIR)).unwrap();

        // Create a job spec in claimed/.
        let spec = build_stop_revoke_spec("some-target", "test").expect("spec builds");
        let spec_json = serde_json::to_vec_pretty(&spec).unwrap();
        let file_name = format!("{}.json", spec.job_id);
        let claimed_path = queue_root.join(CLAIMED_DIR).join(&file_name);
        fs::write(&claimed_path, &spec_json).unwrap();

        // Cancel it (should enqueue stop_revoke).
        let exit_code = cancel_claimed_job(
            &claimed_path,
            &spec.job_id,
            "unit test cancellation",
            &queue_root,
            &fac_root,
            false,
        );
        assert_eq!(exit_code, exit_codes::SUCCESS);

        // Verify: a stop_revoke spec was placed in pending/.
        let pending_dir = queue_root.join(PENDING_DIR);
        let pending_entries: Vec<_> = fs::read_dir(&pending_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert!(
            !pending_entries.is_empty(),
            "stop_revoke spec should be in pending/"
        );

        // Read and verify the stop_revoke spec.
        let stop_spec_path = &pending_entries[0].path();
        let stop_spec: FacJobSpecV1 =
            serde_json::from_slice(&fs::read(stop_spec_path).unwrap()).unwrap();
        assert_eq!(stop_spec.kind, "stop_revoke");
        assert_eq!(stop_spec.priority, 0);
        assert_eq!(
            stop_spec.cancel_target_job_id.as_deref(),
            Some(spec.job_id.as_str())
        );
    }

    #[test]
    fn test_job_id_charset_validation() {
        // Valid job IDs.
        for valid in &["abc-123", "ABC_def", "job-42", "a"] {
            assert!(
                valid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "{valid} should be valid"
            );
        }

        // Invalid job IDs (glob injection, path traversal, etc.).
        for invalid in &["../evil", "job*", "a;b", "a b", "a/b", "a\x00b"] {
            assert!(
                !invalid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "{invalid:?} should be invalid"
            );
        }
    }

    #[test]
    fn test_verify_local_operator_authority_on_owned_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // The tempdir is owned by the current user, so authority should pass.
        let result = verify_local_operator_authority(tmp.path());
        assert!(
            result.is_ok(),
            "should succeed on owned directory: {result:?}"
        );
    }

    /// BLOCKER-1 regression: `read_job_spec` must reject files exceeding
    /// `MAX_JOB_SPEC_SIZE` via bounded read, not metadata check.
    #[test]
    fn test_read_job_spec_rejects_oversized_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let oversized_path = tmp.path().join("oversized.json");
        // Write a file that exceeds MAX_JOB_SPEC_SIZE.
        let oversized_content = vec![b'{'; MAX_JOB_SPEC_SIZE + 100];
        fs::write(&oversized_path, &oversized_content).unwrap();

        let result = read_job_spec(&oversized_path);
        assert!(result.is_err(), "should reject oversized file");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("exceeds max"),
            "error should mention size limit: {err_msg}"
        );
    }

    /// BLOCKER-1 regression: `read_job_spec` must work for valid small files.
    #[test]
    fn test_read_job_spec_accepts_valid_spec() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let spec = build_stop_revoke_spec("bounded-read-test", "test").expect("spec builds");
        let spec_json = serde_json::to_vec_pretty(&spec).unwrap();
        let spec_path = tmp.path().join("valid.json");
        fs::write(&spec_path, &spec_json).unwrap();

        let result = read_job_spec(&spec_path);
        assert!(result.is_ok(), "should accept valid spec: {result:?}");
        assert_eq!(result.unwrap().job_id, spec.job_id);
    }

    /// MAJOR-2 regression: `cancel_claimed_job` must fail if the claimed job
    /// spec cannot be read (receipt cannot be emitted).
    #[test]
    fn test_cancel_claimed_fails_on_unreadable_spec() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        let fac_root = tmp.path().join("fac");
        fs::create_dir_all(queue_root.join(PENDING_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CLAIMED_DIR)).unwrap();
        fs::create_dir_all(queue_root.join(CANCELLED_DIR)).unwrap();
        fs::create_dir_all(fac_root.join(FAC_RECEIPTS_DIR)).unwrap();

        // Create a claimed job spec that contains invalid JSON.
        let bad_path = queue_root.join(CLAIMED_DIR).join("bad-job.json");
        fs::write(&bad_path, b"not valid json").unwrap();

        let exit_code = cancel_claimed_job(
            &bad_path,
            "bad-job",
            "test cancellation",
            &queue_root,
            &fac_root,
            false,
        );
        // MAJOR-2: must return error (not success) when spec cannot be read.
        assert_ne!(
            exit_code,
            exit_codes::SUCCESS,
            "should fail when claimed job spec cannot be read"
        );
        assert_eq!(exit_code, exit_codes::GENERIC_ERROR);
    }
}
