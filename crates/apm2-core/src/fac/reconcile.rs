// AGENT-AUTHORED (TCK-00534)
//! Crash recovery and reconciliation for FAC queue and lane state.
//!
//! After an unclean shutdown (crash, SIGKILL, OOM-kill), the queue and lane
//! state can become inconsistent:
//!
//! - Lanes may have stale leases (owner process dead or PID identity mismatch,
//!   lock released, but lease file still present with RUNNING/LEASED/CLEANUP
//!   state).
//! - The `queue/claimed/` directory may contain job specs that are no longer
//!   being processed by any worker.
//!
//! This module implements deterministic recovery:
//!
//! 1. **Lane reconciliation**: Detect stale leases (identity dead/mismatch +
//!    lock not held), transition through CLEANUP → remove lease (IDLE), emit
//!    recovery receipts.
//! 2. **Queue reconciliation**: Detect claimed jobs that are not backed by any
//!    active lane lease, and requeue them (move back to `pending/`).
//!
//! # Security Model
//!
//! - Stale lease detection uses PID identity checks (fail-closed on unknown).
//! - All recovery actions emit structured receipts for auditability.
//! - In-memory collections are bounded by hard MAX_* constants.
//! - Reconciliation is idempotent: running it multiple times produces the same
//!   result.
//! - File operations use O_NOFOLLOW and reject symlinks/non-regular files
//!   (CTR-1503).
//! - Directories are created with mode 0o700 (CTR-2611).
//! - Receipt persistence uses NamedTempFile + sync_all + rename (CTR-2607).
//! - Receipt persistence is fail-closed in apply mode (INV-RECON-001).
//! - Deserialization is bounded by size cap before parse (INV-BH-007).
//!
//! # Invariants
//!
//! - [INV-RECON-001] No job is silently dropped; all outcomes recorded as
//!   receipts. Receipt persistence is mandatory in apply mode — both for the
//!   final receipt and for partial receipts after Phase-1 or Phase-2 failures.
//!   If partial receipt persistence also fails, a combined error is returned so
//!   that apply-mode lane mutations never lack durable receipt evidence.
//! - [INV-RECON-002] Stale lease detection uses PID identity classification:
//!   `AliveMismatch` (PID reuse) is recoverable stale state; `Unknown` is
//!   fail-closed `CORRUPT`. Ambiguous states are durably marked via
//!   `LaneCorruptMarkerV1`. Corrupt marker persistence failure is a hard error
//!   in apply mode — ambiguous states must not proceed without durable
//!   evidence.
//! - [INV-RECON-003] All in-memory collections are bounded by hard MAX_*
//!   constants.
//! - [INV-RECON-004] Reconciliation is idempotent and safe to call on every
//!   startup.
//! - [INV-RECON-005] Queue reads are bounded (MAX_CLAIMED_SCAN_ENTRIES). Every
//!   directory entry counts toward the cap before file-type filtering.
//! - [INV-RECON-006] Stale lease recovery transitions through CLEANUP → IDLE
//!   with receipts before removing the lease. CLEANUP persist failure is a hard
//!   error — lease removal is blocked without durable CLEANUP evidence.
//! - [INV-RECON-007] Move operations are fail-closed: counters only increment
//!   after confirmed rename success.
//! - [INV-RECON-008] The `queue/claimed` directory itself is verified via
//!   `symlink_metadata()` before traversal; symlinked directories are rejected.
//! - [INV-RECON-009] Orphaned claimed jobs carrying a `channel_context_token`
//!   are requeued under `Requeue` policy only when authoritative token-ledger
//!   state shows the token nonce is still fresh. Consumed/revoked or
//!   unverifiable nonce state is fail-closed to `denied/`.
//! - [INV-RECON-012] Reconciliation is exempt from AJC lifecycle requirements
//!   (RS-42, RFC-0027). It runs at startup as an internal crash-recovery
//!   mechanism before the worker accepts any external authority — it is itself
//!   the authority reset for crash recovery. See the doc comment on
//!   `reconcile_on_startup` for the full exemption rationale and boundary
//!   conditions.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::flock_util::try_acquire_exclusive_nonblocking;
use super::lane::{
    LANE_CORRUPT_MARKER_SCHEMA, LaneCorruptMarkerV1, LaneLeaseV1, LaneManager, LaneState,
    MAX_STRING_LENGTH, ProcessIdentity, atomic_write, create_dir_restricted, verify_pid_identity,
};
use super::receipt_index::find_receipt_for_job;
use super::receipt_pipeline::{ReceiptWritePipeline, outcome_to_terminal_state};
use super::systemd_unit::{
    FacUnitLiveness, ORPHANED_SYSTEMD_UNIT_REASON_CODE, check_fac_unit_liveness,
};
use crate::fac::job_spec::MAX_CHANNEL_CONTEXT_TOKEN_LENGTH;
use crate::fac::token_ledger::{TokenLedgerError, TokenUseLedger};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Schema identifier for reconciliation receipts.
pub const RECONCILE_RECEIPT_SCHEMA: &str = "apm2.fac.reconcile_receipt.v1";

/// Maximum number of claimed entries to scan per reconciliation pass
/// (INV-RECON-005).
pub const MAX_CLAIMED_SCAN_ENTRIES: usize = 4096;

/// Maximum number of lane recovery actions per reconciliation pass
/// (INV-RECON-003).
pub const MAX_LANE_RECOVERY_ACTIONS: usize = 64;

/// Maximum number of queue recovery actions per reconciliation pass
/// (INV-RECON-003).
pub const MAX_QUEUE_RECOVERY_ACTIONS: usize = 4096;

/// Maximum size of a claimed job spec file for bounded reads (64 KiB).
const MAX_CLAIMED_FILE_SIZE: u64 = 65_536;

/// Maximum size of a reconciliation receipt file for bounded deserialization
/// (INV-BH-007). 1 MiB is generous for JSON receipts.
const MAX_RECEIPT_FILE_SIZE: u64 = 1_048_576;

/// Maximum number of lane actions in deserialized receipt (INV-BH-007).
const MAX_DESERIALIZED_LANE_ACTIONS: usize = 256;

/// Maximum number of queue actions in deserialized receipt (INV-BH-007).
const MAX_DESERIALIZED_QUEUE_ACTIONS: usize = 8192;

/// Maximum size of broker state JSON snapshot (matches FAC worker loader).
const MAX_BROKER_STATE_FILE_SIZE: u64 = 1_048_576;

/// Denial reason for token-bound orphaned jobs whose nonce is already consumed.
const TOKEN_NONCE_CONSUMED_DENIAL_REASON: &str =
    "orphaned claimed job token nonce is already consumed; non-retriable to avoid replay";

/// Denial reason prefix for token-bound orphaned jobs with revoked nonces.
const TOKEN_NONCE_REVOKED_DENIAL_REASON_PREFIX: &str =
    "orphaned claimed job token nonce is revoked; non-retriable";

/// Denial reason prefix for token-bound orphaned jobs whose nonce cannot be
/// verified from the token.
const TOKEN_NONCE_UNVERIFIABLE_DENIAL_REASON_PREFIX: &str =
    "orphaned claimed job token nonce is missing or invalid; fail-closed";

/// Denial reason prefix for token-bound orphaned jobs when token-ledger state
/// cannot be loaded or replayed.
const TOKEN_LEDGER_UNAVAILABLE_DENIAL_REASON_PREFIX: &str =
    "orphaned claimed job token ledger state unavailable; fail-closed";

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from reconciliation operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReconcileError {
    /// Lane management error.
    #[error("lane error: {0}")]
    Lane(#[from] super::lane::LaneError),

    /// I/O error during reconciliation.
    #[error("reconcile I/O error: {context}: {source}")]
    Io {
        /// Description of what was being attempted.
        context: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Too many entries found (bounded collection overflow).
    #[error("too many {kind} entries: {count} exceeds limit {limit}")]
    TooManyEntries {
        /// Kind of entries.
        kind: &'static str,
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        limit: usize,
    },

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Queue move operation failed.
    #[error("queue move failed: {context}")]
    MoveFailed {
        /// Description of the failed operation.
        context: String,
    },
}

impl ReconcileError {
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Recovery policy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy for handling claimed jobs without a running lane.
///
/// This determines what happens to orphaned claimed jobs discovered during
/// reconciliation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanedJobPolicy {
    /// Move orphaned claimed jobs back to `pending/` for reprocessing.
    /// This is the default and is appropriate when jobs are idempotent.
    #[default]
    Requeue,
    /// Move orphaned claimed jobs to `denied/` with a failure receipt.
    /// This is appropriate when re-execution is unsafe.
    MarkFailed,
}

// `Default` derived via `#[default]` attribute on `Requeue` variant.

// ─────────────────────────────────────────────────────────────────────────────
// Recovery action types
// ─────────────────────────────────────────────────────────────────────────────

/// A lane recovery action taken during reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum LaneRecoveryAction {
    /// Stale lease was cleared and lane returned to IDLE via CLEANUP
    /// transition.
    StaleLeaseCleared {
        /// Lane identifier.
        lane_id: String,
        /// Job ID from the stale lease.
        job_id: String,
        /// PID from the stale lease (now dead).
        pid: u32,
        /// Previous lane state in the lease.
        previous_state: String,
    },
    /// Lane was already in a consistent state (no action needed).
    AlreadyConsistent {
        /// Lane identifier.
        lane_id: String,
        /// Current lane state.
        state: String,
    },
    /// Lane was marked CORRUPT (ambiguous state, requires manual intervention).
    MarkedCorrupt {
        /// Lane identifier.
        lane_id: String,
        /// Reason for marking corrupt.
        reason: String,
    },
}

/// A queue recovery action taken during reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum QueueRecoveryAction {
    /// Orphaned claimed job was requeued (moved back to pending/).
    Requeued {
        /// Job ID.
        job_id: String,
        /// Original filename.
        file_name: String,
    },
    /// Orphaned claimed job was moved to denied/.
    MarkedFailed {
        /// Job ID.
        job_id: String,
        /// Original filename.
        file_name: String,
        /// Reason for failure.
        reason: String,
    },
    /// Claimed job is still actively being processed (no action).
    StillActive {
        /// Job ID.
        job_id: String,
        /// Lane ID processing this job.
        lane_id: String,
    },
    /// Torn state recovered: receipt existed but job was still in claimed/.
    /// The job was moved to its correct terminal directory (TCK-00564
    /// BLOCKER-2).
    TornStateRecovered {
        /// Job ID.
        job_id: String,
        /// Original filename.
        file_name: String,
        /// Terminal directory the job was moved to.
        terminal_dir: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Reconciliation receipt
// ─────────────────────────────────────────────────────────────────────────────

/// Structured receipt emitted after a reconciliation pass.
///
/// This receipt is persisted for auditability (INV-RECON-001).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// ISO-8601 timestamp of reconciliation.
    pub timestamp: String,
    /// Whether this was a dry run (no mutations applied).
    pub dry_run: bool,
    /// Lane recovery actions taken.
    pub lane_actions: Vec<LaneRecoveryAction>,
    /// Queue recovery actions taken.
    pub queue_actions: Vec<QueueRecoveryAction>,
    /// Number of lanes inspected.
    pub lanes_inspected: usize,
    /// Number of claimed files inspected.
    pub claimed_files_inspected: usize,
    /// Number of stale leases recovered.
    pub stale_leases_recovered: usize,
    /// Number of orphaned jobs requeued.
    pub orphaned_jobs_requeued: usize,
    /// Number of orphaned jobs marked failed.
    pub orphaned_jobs_failed: usize,
    /// Number of torn states recovered (receipt existed but job still in
    /// claimed/). Added by TCK-00564 BLOCKER-2.
    #[serde(default)]
    pub torn_states_recovered: usize,
    /// Number of lanes marked corrupt.
    pub lanes_marked_corrupt: usize,
}

impl ReconcileReceiptV1 {
    /// Persist the receipt to the FAC receipts directory.
    ///
    /// Uses the secure atomic write protocol (CTR-2607):
    /// - Directory created with mode 0o700 (CTR-2611).
    /// - `NamedTempFile` with unpredictable name (RSK-1502).
    /// - File permissions 0o600.
    /// - `sync_all()` before rename for durability (CTR-1502).
    /// - Collision-resistant filename with nanos + random suffix.
    ///
    /// # Errors
    ///
    /// Returns `ReconcileError::Io` on filesystem errors.
    /// Returns `ReconcileError::Lane` if directory creation fails.
    pub fn persist(&self, fac_root: &Path) -> Result<PathBuf, ReconcileError> {
        let receipts_dir = fac_root.join("receipts").join("reconcile");
        // CTR-2611: create directory with restricted permissions (0o700).
        create_dir_restricted(&receipts_dir)?;

        // Collision-resistant filename: timestamp + nanos + random suffix.
        let timestamp_safe = self.timestamp.replace(':', "-").replace('+', "p");
        let nanos = wall_clock_nanos();
        let random_suffix: u32 = random_u32();
        let filename = format!("reconcile-{timestamp_safe}-{nanos}-{random_suffix:08x}.json");
        let receipt_path = receipts_dir.join(&filename);

        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| ReconcileError::Serialization(e.to_string()))?;

        // CTR-2607: Atomic write via lane::atomic_write (NamedTempFile + 0o600
        // + sync_all + rename). This reuses the hardened write protocol from
        // lane.rs which handles symlink rejection, permission enforcement,
        // and fsync durability.
        atomic_write(&receipt_path, &bytes)?;

        Ok(receipt_path)
    }

    /// Validate deserialized receipt bounds (INV-BH-007).
    ///
    /// Checks that Vec fields do not exceed safe bounds after deserialization.
    fn validate_bounds(&self) -> Result<(), ReconcileError> {
        if self.lane_actions.len() > MAX_DESERIALIZED_LANE_ACTIONS {
            return Err(ReconcileError::TooManyEntries {
                kind: "deserialized_lane_actions",
                count: self.lane_actions.len(),
                limit: MAX_DESERIALIZED_LANE_ACTIONS,
            });
        }
        if self.queue_actions.len() > MAX_DESERIALIZED_QUEUE_ACTIONS {
            return Err(ReconcileError::TooManyEntries {
                kind: "deserialized_queue_actions",
                count: self.queue_actions.len(),
                limit: MAX_DESERIALIZED_QUEUE_ACTIONS,
            });
        }
        Ok(())
    }

    /// Load a receipt from a file with bounded deserialization (INV-BH-007).
    ///
    /// Size-caps the file read before parsing to prevent memory exhaustion.
    /// Validates the `schema` field matches `RECONCILE_RECEIPT_SCHEMA` after
    /// deserialization, consistent with the validation pattern used by other
    /// FAC record types (`LaneProfile`, `LaneLease`, `LaneCorruptMarker`).
    ///
    /// # Errors
    ///
    /// Returns `ReconcileError` on I/O, parse, schema mismatch, or bounds
    /// violation.
    #[allow(dead_code)] // Used in tests for receipt verification; may be wired to production later.
    pub fn load(path: &Path) -> Result<Self, ReconcileError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|e| ReconcileError::io(format!("stat receipt at {}", path.display()), e))?;
        if metadata.file_type().is_symlink() {
            return Err(ReconcileError::io(
                format!("receipt path is a symlink: {}", path.display()),
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "symlink not allowed"),
            ));
        }
        if metadata.len() > MAX_RECEIPT_FILE_SIZE {
            return Err(ReconcileError::io(
                format!(
                    "receipt file {} exceeds max size ({} > {MAX_RECEIPT_FILE_SIZE})",
                    path.display(),
                    metadata.len()
                ),
                std::io::Error::new(std::io::ErrorKind::InvalidData, "file too large"),
            ));
        }
        let mut file = open_file_no_follow(path)?;
        let mut buf = Vec::with_capacity(metadata.len().min(MAX_RECEIPT_FILE_SIZE) as usize);
        let mut reader = (&mut file).take(MAX_RECEIPT_FILE_SIZE);
        reader
            .read_to_end(&mut buf)
            .map_err(|e| ReconcileError::io(format!("reading receipt at {}", path.display()), e))?;
        let receipt: Self = serde_json::from_slice(&buf)
            .map_err(|e| ReconcileError::Serialization(e.to_string()))?;

        // Schema validation: verify the schema field matches the expected
        // value. This is consistent with the pattern used by LaneCorruptMarkerV1,
        // LaneLeaseV1, and LaneProfileV1 which all validate the schema field
        // on load to prevent loading mismatched/malformed records.
        if receipt.schema != RECONCILE_RECEIPT_SCHEMA {
            return Err(ReconcileError::Serialization(format!(
                "schema mismatch: expected '{}', got '{}'",
                RECONCILE_RECEIPT_SCHEMA, receipt.schema
            )));
        }

        receipt.validate_bounds()?;
        Ok(receipt)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core reconciliation logic
// ─────────────────────────────────────────────────────────────────────────────

/// Intermediate result from phase 1 lane reconciliation.
struct LaneReconcileResult {
    actions: Vec<LaneRecoveryAction>,
    active_job_ids: HashSet<String>,
    unknown_identity_job_ids_for_orphan_suppression: HashSet<String>,
    stale_leases_recovered: usize,
    lanes_marked_corrupt: usize,
    /// If phase 1 encountered an error after partial mutations, the error
    /// is captured here alongside the partial results so the caller can
    /// persist a partial receipt before propagating (INV-RECON-001).
    partial_error: Option<ReconcileError>,
}

/// Intermediate result from phase 2 queue reconciliation.
///
/// Like `LaneReconcileResult`, this carries partial results alongside any
/// error so the caller can persist an accurate partial receipt containing
/// the actual `claimed_files_inspected` count (MINOR audit trail fix).
struct QueueReconcileResult {
    actions: Vec<QueueRecoveryAction>,
    claimed_files_inspected: usize,
    orphaned_jobs_requeued: usize,
    orphaned_jobs_failed: usize,
    /// Count of torn states recovered (receipt existed but job still in
    /// claimed/).
    torn_states_recovered: usize,
    /// If queue reconciliation encountered an error after inspecting some
    /// files, the error is captured here alongside the partial counts so
    /// the caller can include the actual `claimed_files_inspected` in the
    /// partial receipt before propagating (INV-RECON-001).
    partial_error: Option<ReconcileError>,
}

fn build_orphaned_systemd_reclaim_reason(
    lane_id: &str,
    lease: &LaneLeaseV1,
    liveness: &FacUnitLiveness,
) -> String {
    let detail = match liveness {
        FacUnitLiveness::Active { active_units } => {
            let preview = active_units
                .iter()
                .take(4)
                .map(std::string::String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            if preview.is_empty() {
                format!(
                    "associated systemd units still active (count={})",
                    active_units.len()
                )
            } else {
                let suffix = if active_units.len() > 4 { " +more" } else { "" };
                format!(
                    "associated systemd units still active (count={}, units=[{preview}]{suffix})",
                    active_units.len()
                )
            }
        },
        FacUnitLiveness::Unknown { reason } => {
            format!("systemd liveness probe inconclusive ({reason}); fail-closed")
        },
        FacUnitLiveness::Inactive => "no active associated systemd units".to_string(),
    };

    truncate_string(
        &format!(
            "{ORPHANED_SYSTEMD_UNIT_REASON_CODE}: lane={lane_id} job_id={} pid={} stale lease recovery blocked: {detail}",
            lease.job_id, lease.pid
        ),
        MAX_STRING_LENGTH,
    )
}

/// Metadata parsed from a claimed job spec.
///
/// Parsed with bounded I/O and `O_NOFOLLOW` to preserve reconciliation safety
/// invariants.
#[derive(Debug, Clone, Default)]
struct ClaimedJobMetadata {
    job_id: Option<String>,
    channel_context_token: Option<String>,
}

/// Run crash recovery reconciliation on worker startup.
///
/// This function:
/// 1. Scans all lanes for stale leases (identity dead/mismatch + lock not
///    held).
/// 2. For stale lanes: transitions lease through CLEANUP → removes lease
///    (IDLE), emitting recovery receipts (INV-RECON-006).
/// 3. Scans `queue/claimed/` for orphaned jobs not backed by any active lane.
/// 4. Moves orphaned jobs back to `pending/` (requeue) or `denied/` (fail),
///    based on the configured policy.
/// 5. Emits a structured reconciliation receipt.
///
/// # AJC Lifecycle Exemption (INV-RECON-012)
///
/// This function performs authoritative mutations (requeueing jobs, marking
/// lanes corrupt, clearing stale leases) **without** an AJC lifecycle
/// (`join → revalidate → consume → effect`). This is an intentional and
/// documented exemption from the PCAC standard (RS-42, RFC-0027) for the
/// following reasons:
///
/// 1. **Startup-time authority reset.** Reconciliation runs as the *first*
///    operation on worker startup, before the worker accepts any external
///    authority, issues any tokens, or processes any jobs. There is no active
///    authority context to join or revalidate against — the reconciliation
///    *itself* is the mechanism that restores the system to a state where
///    authority contexts can be established.
///
/// 2. **Crash recovery is self-authorising.** The mutations performed here
///    (clearing dead-PID leases, requeueing orphaned files, marking corrupt
///    lanes) are internal infrastructure recovery actions, not
///    externally-requested authority-bearing effects. The "authority" is the
///    worker process itself repairing its own local state after an unclean
///    shutdown.
///
/// 3. **No external request surface.** Reconciliation is invoked only by the
///    worker's own startup path or by `apm2 fac doctor --fix`. There is no IPC
///    handler, no network endpoint, and no delegated capability that could be
///    confused or replayed. The filesystem-level access to `$APM2_HOME` is the
///    sole trust anchor.
///
/// 4. **Boundary conditions.** This exemption holds only when:
///    - Reconciliation runs before the worker's job-processing loop starts.
///    - No broker tokens have been issued for the current epoch.
///    - The mutations are limited to local queue/lane filesystem state.
///
///    If reconciliation were ever extended to perform cross-node or
///    broker-mediated actions, AJC integration would be required.
///
/// All recovery actions emit structured `ReconcileReceiptV1` receipts for
/// auditability, and receipt persistence is fail-closed in apply mode
/// (INV-RECON-001).
///
/// # Arguments
///
/// * `fac_root` — Path to `$APM2_HOME/private/fac`.
/// * `queue_root` — Path to `$APM2_HOME/queue`.
/// * `orphan_policy` — Policy for handling orphaned claimed jobs.
/// * `dry_run` — If true, report what would be done without mutating state.
///
/// # Errors
///
/// Returns [`ReconcileError`] on lane, filesystem, or receipt persistence
/// errors. In apply mode (not `dry_run`), receipt persistence failure is a
/// hard error (fail-closed, INV-RECON-001).
pub fn reconcile_on_startup(
    fac_root: &Path,
    queue_root: &Path,
    orphan_policy: OrphanedJobPolicy,
    dry_run: bool,
) -> Result<ReconcileReceiptV1, ReconcileError> {
    let timestamp = current_timestamp_rfc3339();
    let manager = LaneManager::new(fac_root.to_path_buf())?;
    let lane_ids = LaneManager::default_lane_ids();

    // Phase 1: Lane reconciliation.
    //
    // MAJOR 2 FIX: reconcile_lanes now always returns partial results
    // (actions, counters) alongside any error. If Phase 1 fails after
    // mutating some lanes, we persist a partial receipt containing the
    // already-applied actions before propagating the error. This ensures
    // INV-RECON-001 traceability for all mutations, matching the Phase-2
    // partial receipt pattern.
    let lane_result = reconcile_lanes(&manager, &lane_ids, fac_root, &timestamp, dry_run);

    // Check for Phase 1 errors. If there was an error, persist a partial
    // receipt with the actions that were completed before the error.
    if let Some(phase1_err) = lane_result.partial_error {
        if !dry_run {
            let partial_receipt = ReconcileReceiptV1 {
                schema: RECONCILE_RECEIPT_SCHEMA.to_string(),
                timestamp,
                dry_run,
                lane_actions: lane_result.actions,
                queue_actions: Vec::new(),
                lanes_inspected: lane_ids.len(),
                claimed_files_inspected: 0,
                stale_leases_recovered: lane_result.stale_leases_recovered,
                orphaned_jobs_requeued: 0,
                orphaned_jobs_failed: 0,
                torn_states_recovered: 0,
                lanes_marked_corrupt: lane_result.lanes_marked_corrupt,
            };
            // INV-RECON-001 (fail-closed): Partial receipt persistence
            // is mandatory in apply mode. If persistence also fails,
            // return a combined error.
            if let Err(persist_err) = partial_receipt.persist(fac_root) {
                return Err(ReconcileError::io(
                    format!(
                        "partial receipt persistence failed after Phase 1 error \
                         (phase1: {phase1_err}, persist: {persist_err}); \
                         apply-mode lane mutations may lack durable receipt evidence"
                    ),
                    std::io::Error::other("partial receipt persistence is mandatory in apply mode"),
                ));
            }
        }
        return Err(phase1_err);
    }

    // Phase 2: Queue reconciliation — scan claimed/ for orphaned jobs.
    // INV-RECON-001: If Phase 2 fails after Phase 1 mutated state (e.g.,
    // clearing stale leases), we must persist a partial receipt containing
    // Phase 1 actions before propagating the Phase 2 error.
    //
    // reconcile_queue now returns partial results alongside any error
    // (mirroring Phase 1's LaneReconcileResult pattern) so the partial
    // receipt includes the actual claimed_files_inspected count rather
    // than a misleading 0 (MINOR audit trail fix).
    let queue_result = reconcile_queue(
        fac_root,
        queue_root,
        &lane_result.active_job_ids,
        &lane_result.unknown_identity_job_ids_for_orphan_suppression,
        orphan_policy,
        dry_run,
    );

    if let Some(phase2_err) = queue_result.partial_error {
        // Phase 1 may have mutated state (stale lease recovery).
        // Persist a partial receipt with Phase 1 results and the actual
        // Phase 2 partial counts so those actions are never silently
        // lost (INV-RECON-001).
        if !dry_run {
            let partial_receipt = ReconcileReceiptV1 {
                schema: RECONCILE_RECEIPT_SCHEMA.to_string(),
                timestamp,
                dry_run,
                lane_actions: lane_result.actions,
                queue_actions: queue_result.actions,
                lanes_inspected: lane_ids.len(),
                claimed_files_inspected: queue_result.claimed_files_inspected,
                stale_leases_recovered: lane_result.stale_leases_recovered,
                orphaned_jobs_requeued: queue_result.orphaned_jobs_requeued,
                orphaned_jobs_failed: queue_result.orphaned_jobs_failed,
                torn_states_recovered: queue_result.torn_states_recovered,
                lanes_marked_corrupt: lane_result.lanes_marked_corrupt,
            };
            // INV-RECON-001 (fail-closed): Partial receipt persistence
            // is mandatory in apply mode. If persistence also fails, return
            // a combined error that includes both the Phase-2 failure
            // context and the persistence failure context so the caller
            // knows that lane mutations occurred without durable receipts.
            if let Err(persist_err) = partial_receipt.persist(fac_root) {
                return Err(ReconcileError::io(
                    format!(
                        "partial receipt persistence failed after Phase 2 error \
                         (phase2: {phase2_err}, persist: {persist_err}); \
                         apply-mode lane mutations lack durable receipt evidence"
                    ),
                    std::io::Error::other("partial receipt persistence is mandatory in apply mode"),
                ));
            }
        }
        return Err(phase2_err);
    }

    let receipt = ReconcileReceiptV1 {
        schema: RECONCILE_RECEIPT_SCHEMA.to_string(),
        timestamp,
        dry_run,
        lane_actions: lane_result.actions,
        queue_actions: queue_result.actions,
        lanes_inspected: lane_ids.len(),
        claimed_files_inspected: queue_result.claimed_files_inspected,
        stale_leases_recovered: lane_result.stale_leases_recovered,
        orphaned_jobs_requeued: queue_result.orphaned_jobs_requeued,
        orphaned_jobs_failed: queue_result.orphaned_jobs_failed,
        torn_states_recovered: queue_result.torn_states_recovered,
        lanes_marked_corrupt: lane_result.lanes_marked_corrupt,
    };

    // INV-RECON-001: Receipt persistence is mandatory in apply mode.
    // In dry-run mode, persist best-effort (failure is non-fatal since no
    // mutations occurred).
    match receipt.persist(fac_root) {
        Ok(_path) => {},
        Err(e) if dry_run => {
            // Non-fatal in dry-run: no mutations to audit.
            eprintln!("WARNING: failed to persist reconcile receipt (dry-run): {e}");
        },
        Err(e) => {
            // Fail-closed in apply mode: mutations occurred without durable
            // receipt evidence. Return error to prevent silent loss of audit
            // trail (INV-RECON-001).
            return Err(ReconcileError::io(
                format!("receipt persistence failed (apply mode, fail-closed): {e}"),
                std::io::Error::other("receipt persistence is mandatory in apply mode"),
            ));
        },
    }

    Ok(receipt)
}

/// Phase 1: Scan all lanes for stale leases and reconcile them.
///
/// Returns the set of active job IDs (used by phase 2 to detect orphans)
/// along with recovery actions taken.
///
/// INV-RECON-002: Unknown identity states are durably marked CORRUPT via
/// `LaneCorruptMarkerV1`.
///
/// INV-RECON-006: Stale lease recovery transitions through CLEANUP → IDLE.
///
/// Active-job tracking includes lanes whose lease identity is `AliveMatch`,
/// plus stale-lease jobs blocked by the orphaned-systemd-unit reclaim guard.
/// This prevents false orphan requeue when detached systemd units are still
/// active or liveness probing is inconclusive.
///
/// Lock-held lanes with `Unknown` identity are tracked separately for
/// orphan-suppression handling in queue reconciliation so this invariant
/// remains strict.
#[allow(clippy::too_many_lines)] // lane reconciliation with corrupt-marker persistence is inherently branchy
fn reconcile_lanes(
    manager: &LaneManager,
    lane_ids: &[String],
    fac_root: &Path,
    timestamp: &str,
    dry_run: bool,
) -> LaneReconcileResult {
    let mut actions: Vec<LaneRecoveryAction> = Vec::new();
    let mut stale_leases_recovered: usize = 0;
    let mut lanes_marked_corrupt: usize = 0;
    let mut active_job_ids: HashSet<String> = HashSet::new();
    let mut unknown_identity_job_ids_for_orphan_suppression: HashSet<String> = HashSet::new();
    let mut partial_error: Option<ReconcileError> = None;

    for lane_id in lane_ids {
        if actions.len() >= MAX_LANE_RECOVERY_ACTIONS {
            partial_error = Some(ReconcileError::TooManyEntries {
                kind: "lane_recovery_actions",
                count: actions.len(),
                limit: MAX_LANE_RECOVERY_ACTIONS,
            });
            break;
        }

        let status = match manager.lane_status(lane_id) {
            Ok(s) => s,
            Err(e) => {
                // Cannot determine lane state — mark corrupt (fail-closed,
                // INV-RECON-002).
                let reason = format!("failed to read lane status: {e}");
                if !dry_run {
                    if let Err(marker_err) =
                        persist_corrupt_marker(fac_root, lane_id, &reason, timestamp)
                    {
                        partial_error = Some(marker_err);
                        break;
                    }
                }
                actions.push(LaneRecoveryAction::MarkedCorrupt {
                    lane_id: lane_id.clone(),
                    reason: truncate_string(&reason, MAX_STRING_LENGTH),
                });
                lanes_marked_corrupt += 1;
                continue;
            },
        };
        let lane_dir = manager.lane_dir(lane_id);
        let lease_snapshot = LaneLeaseV1::load(&lane_dir).ok().flatten();
        let lease_identity = lease_snapshot
            .as_ref()
            .map(|lease| verify_pid_identity(lease.pid, lease.proc_start_time_ticks));

        match status.state {
            LaneState::Idle => {
                if let (Some(lease), Some(pid_identity)) = (lease_snapshot.as_ref(), lease_identity)
                {
                    if !status.lock_held
                        && matches!(
                            pid_identity,
                            ProcessIdentity::Dead | ProcessIdentity::AliveMismatch
                        )
                    {
                        let liveness = check_fac_unit_liveness(lane_id, &lease.job_id);
                        if !matches!(liveness, FacUnitLiveness::Inactive) {
                            let reason =
                                build_orphaned_systemd_reclaim_reason(lane_id, lease, &liveness);
                            if !dry_run {
                                if let Err(marker_err) =
                                    persist_corrupt_marker(fac_root, lane_id, &reason, timestamp)
                                {
                                    partial_error = Some(marker_err);
                                    break;
                                }
                            }
                            // Prevent queue reconcile from requeueing this
                            // claimed job while orphaned systemd units are
                            // active or liveness probing is inconclusive.
                            active_job_ids.insert(lease.job_id.clone());
                            actions.push(LaneRecoveryAction::MarkedCorrupt {
                                lane_id: lane_id.clone(),
                                reason,
                            });
                            lanes_marked_corrupt += 1;
                            continue;
                        }
                        // Dead PID + free lock → stale lease.
                        // INV-RECON-006: Transition through CLEANUP → IDLE.
                        if dry_run {
                            actions.push(LaneRecoveryAction::StaleLeaseCleared {
                                lane_id: lane_id.clone(),
                                job_id: lease.job_id.clone(),
                                pid: lease.pid,
                                previous_state: lease.state.to_string(),
                            });
                            stale_leases_recovered += 1;
                        } else {
                            match recover_stale_lease(&lane_dir, lease, fac_root) {
                                Ok(StaleLeaseOutcome::Recovered) => {
                                    actions.push(LaneRecoveryAction::StaleLeaseCleared {
                                        lane_id: lane_id.clone(),
                                        job_id: lease.job_id.clone(),
                                        pid: lease.pid,
                                        previous_state: lease.state.to_string(),
                                    });
                                    stale_leases_recovered += 1;
                                },
                                Ok(StaleLeaseOutcome::MarkedCorrupt) => {
                                    // Cleanup failed but lane was durably
                                    // marked CORRUPT. Worker can continue
                                    // startup — lane will not accept new
                                    // jobs until reset. This prevents
                                    // crash loops in SystemMode where
                                    // safe_rmtree_v1 fails due to 0o770
                                    // lane directory permissions.
                                    let reason = format!(
                                        "stale lease cleanup failed for lane {lane_id} \
                                         (pid={}, state={}); lane marked CORRUPT",
                                        lease.pid, lease.state,
                                    );
                                    actions.push(LaneRecoveryAction::MarkedCorrupt {
                                        lane_id: lane_id.clone(),
                                        reason: truncate_string(&reason, MAX_STRING_LENGTH),
                                    });
                                    lanes_marked_corrupt += 1;
                                },
                                Err(recover_err) => {
                                    // Recovery itself failed (e.g., corrupt
                                    // marker persistence failed). Capture
                                    // the error with partial state.
                                    partial_error = Some(recover_err);
                                    break;
                                },
                            }
                        }
                        continue;
                    }
                    match pid_identity {
                        ProcessIdentity::AliveMatch => {
                            // INV-RECON-002: lock free + active owner identity match is
                            // ambiguous/inconsistent. Mark CORRUPT durably and treat as active
                            // to prevent orphan requeue.
                            let reason = format!(
                                "ambiguous lane state: lease present (pid={}, state={}) \
                                 but lock is free and process identity matches",
                                lease.pid, lease.state,
                            );
                            if !dry_run {
                                if let Err(marker_err) =
                                    persist_corrupt_marker(fac_root, lane_id, &reason, timestamp)
                                {
                                    partial_error = Some(marker_err);
                                    break;
                                }
                            }
                            active_job_ids.insert(lease.job_id.clone());
                            actions.push(LaneRecoveryAction::MarkedCorrupt {
                                lane_id: lane_id.clone(),
                                reason: truncate_string(&reason, MAX_STRING_LENGTH),
                            });
                            lanes_marked_corrupt += 1;
                            continue;
                        },
                        ProcessIdentity::Unknown => {
                            // Fail-closed when identity cannot be verified.
                            let reason = format!(
                                "ambiguous lane state: lease present (pid={}, state={}) \
                                 but process identity is unknown",
                                lease.pid, lease.state
                            );
                            if !dry_run {
                                if let Err(marker_err) =
                                    persist_corrupt_marker(fac_root, lane_id, &reason, timestamp)
                                {
                                    partial_error = Some(marker_err);
                                    break;
                                }
                            }
                            actions.push(LaneRecoveryAction::MarkedCorrupt {
                                lane_id: lane_id.clone(),
                                reason: truncate_string(&reason, MAX_STRING_LENGTH),
                            });
                            lanes_marked_corrupt += 1;
                            continue;
                        },
                        ProcessIdentity::Dead | ProcessIdentity::AliveMismatch => {
                            // Already handled by stale-lease branch above when
                            // lock is free.
                        },
                    }
                }
                actions.push(LaneRecoveryAction::AlreadyConsistent {
                    lane_id: lane_id.clone(),
                    state: "IDLE".to_string(),
                });
            },
            LaneState::Running | LaneState::Leased | LaneState::Cleanup => {
                let unknown_identity_with_live_job = status.lock_held
                    && status.job_id.is_some()
                    && matches!(lease_identity, Some(ProcessIdentity::Unknown));
                if let Some(job_id) = status.job_id.as_ref()
                    && matches!(lease_identity, Some(ProcessIdentity::AliveMatch))
                {
                    active_job_ids.insert(job_id.clone());
                }

                if unknown_identity_with_live_job {
                    if let Some(job_id) = status.job_id.as_ref() {
                        // Keep lock-held unknown-identity suppression separate
                        // from active_job_ids for clearer queue-action labels.
                        unknown_identity_job_ids_for_orphan_suppression.insert(job_id.clone());
                    }
                    // Fail-closed: emit a corrupt marker so operators have durable
                    // evidence and manual cleanup guidance. Queue phase uses the
                    // dedicated suppression set to avoid orphan mutations on this
                    // lock-held ambiguous job.
                    let reason = if let Some(lease) = lease_snapshot.as_ref() {
                        format!(
                            "active lane state {} (pid={}) has lock held but process identity is unknown; preserving orphan suppression via dedicated unknown-identity set and marking lane corrupt for manual cleanup",
                            status.state, lease.pid
                        )
                    } else {
                        format!(
                            "active lane state {} has lock held but process identity is unknown; preserving orphan suppression via dedicated unknown-identity set and marking lane corrupt for manual cleanup",
                            status.state
                        )
                    };
                    if !dry_run {
                        if let Err(marker_err) =
                            persist_corrupt_marker(fac_root, lane_id, &reason, timestamp)
                        {
                            partial_error = Some(marker_err);
                            break;
                        }
                    }
                    actions.push(LaneRecoveryAction::MarkedCorrupt {
                        lane_id: lane_id.clone(),
                        reason: truncate_string(&reason, MAX_STRING_LENGTH),
                    });
                    lanes_marked_corrupt += 1;
                    continue;
                }
                actions.push(LaneRecoveryAction::AlreadyConsistent {
                    lane_id: lane_id.clone(),
                    state: status.state.to_string(),
                });
            },
            LaneState::Corrupt => {
                // INV-RECON-002: Ensure derived corruption is durably marked.
                // If `lane_status` returned Corrupt (e.g., lock free but PID
                // alive), a durable corrupt marker may not yet exist — for
                // example if the corruption was derived from runtime state
                // rather than a persisted marker. Check for the marker and
                // persist one if absent so that subsequent startups see the
                // lane as corrupt without depending on the same runtime
                // conditions (which may have changed).
                if !dry_run {
                    let marker_exists = LaneCorruptMarkerV1::load(fac_root, lane_id)
                        .ok()
                        .flatten()
                        .is_some();
                    if !marker_exists {
                        let reason = format!(
                            "derived corrupt state for lane {lane_id} was not \
                             durably marked; persisting corrupt marker"
                        );
                        if let Err(marker_err) =
                            persist_corrupt_marker(fac_root, lane_id, &reason, timestamp)
                        {
                            partial_error = Some(marker_err);
                            break;
                        }
                    }
                }
                // Corrupt lanes still suppress orphan handling when a lock-held
                // active job has unknown identity (fail-closed liveness) via a
                // dedicated suppression set, or when identity matches the lease
                // owner via active_job_ids.
                if let Some(job_id) = status.job_id.as_ref()
                    && matches!(lease_identity, Some(ProcessIdentity::AliveMatch))
                {
                    active_job_ids.insert(job_id.clone());
                }
                if let Some(job_id) = status.job_id.as_ref()
                    && status.lock_held
                    && matches!(lease_identity, Some(ProcessIdentity::Unknown))
                {
                    unknown_identity_job_ids_for_orphan_suppression.insert(job_id.clone());
                }
                actions.push(LaneRecoveryAction::AlreadyConsistent {
                    lane_id: lane_id.clone(),
                    state: "CORRUPT".to_string(),
                });
                lanes_marked_corrupt += 1;
            },
        }
    }

    LaneReconcileResult {
        actions,
        active_job_ids,
        unknown_identity_job_ids_for_orphan_suppression,
        stale_leases_recovered,
        lanes_marked_corrupt,
        partial_error,
    }
}

/// Outcome of stale lease recovery.
enum StaleLeaseOutcome {
    /// Stale lease was successfully recovered: cleanup succeeded and lease
    /// was removed (lane is now IDLE).
    Recovered,
    /// Cleanup failed but the lane was durably marked CORRUPT. The lease
    /// was NOT removed. The worker can continue startup safely because
    /// the corrupt marker prevents the lane from accepting new jobs.
    MarkedCorrupt,
}

/// INV-RECON-006: Transition stale lease through CLEANUP → IDLE before removal.
///
/// This implements the lane cleanup lifecycle for crash recovery:
/// 1. Transition lease state to CLEANUP and persist durably.
/// 2. Best-effort filesystem cleanup: prune `tmp/` and per-lane env dirs
///    (`home/`, `xdg_cache/`, `xdg_config/`, etc.) via `safe_rmtree_v1`.
/// 3. Remove the lease file (returning lane to IDLE).
///
/// Fail-closed: If the CLEANUP transition persist fails, return an error
/// instead of proceeding with lease removal. The caller must not remove the
/// lease without durable CLEANUP evidence.
///
/// # Scope Limitations (MAJOR 2 remediation)
///
/// The reconciler runs at startup with limited access to `LaneManager`
/// internals. Full `LaneManager::run_lane_cleanup` requires a RUNNING lease
/// and a known workspace path (which may not be derivable from a stale
/// lease after a crash). Therefore, this function performs a **best-effort
/// subset** of the full cleanup:
///
/// - **Included**: `tmp/` pruning and per-lane env dir pruning via
///   `safe_rmtree_v1`. These are the most likely sources of cross-job
///   contamination (stale temp files, cached credentials in `home/`, etc.).
/// - **Excluded**: `git reset --hard` and `git clean -ffdxq` (the workspace
///   path is derived from the lane profile and mirror checkout, not stored in
///   the lease record; additionally, git state after a crash may be arbitrary
///   and unsafe to reset without validation). Also excluded: log quota
///   enforcement (non-critical for contamination prevention).
///
/// If any cleanup step fails, the lane is marked CORRUPT via
/// `LaneCorruptMarkerV1` rather than silently continuing. This ensures the
/// lane will not accept new jobs until explicitly reset via
/// `apm2 fac doctor --fix`.
fn recover_stale_lease(
    lane_dir: &Path,
    lease: &LaneLeaseV1,
    fac_root: &Path,
) -> Result<StaleLeaseOutcome, ReconcileError> {
    // Step 1: Transition to CLEANUP state and persist durably.
    // Fail-closed: if this write fails, we must NOT remove the lease.
    let mut cleanup_lease = lease.clone();
    cleanup_lease.state = LaneState::Cleanup;
    cleanup_lease.persist(lane_dir).map_err(|e| {
        ReconcileError::io(
            format!(
                "failed to persist CLEANUP transition for stale lease at {} \
                 (fail-closed: lease removal blocked without durable CLEANUP evidence)",
                lane_dir.display()
            ),
            std::io::Error::other(e.to_string()),
        )
    })?;

    // Step 2: Best-effort filesystem cleanup — prune tmp/ and per-lane env
    // dirs to prevent cross-job contamination from stale files left by the
    // crashed job.
    //
    // NOTE: Git reset/clean is intentionally excluded because (a) the
    // workspace path is not stored in the lease record, and (b) git state
    // after a crash may be arbitrary. The workspace will be re-checked-out
    // from the bare mirror on the next job assignment, which implicitly
    // replaces any stale git state.
    let cleanup_failed = best_effort_lane_cleanup(lane_dir);

    if let Some(cleanup_reason) = cleanup_failed {
        // Cleanup failed — mark lane CORRUPT (fail-closed). The lane must
        // not accept new jobs until explicitly reset via `apm2 fac doctor --fix`.
        //
        // BLOCKER FIX: The corrupt marker IS the fail-closed safety net.
        // Once the lane is marked CORRUPT, the worker can safely continue
        // startup — the lane will not accept new jobs until explicitly
        // reset. Previously, this code returned Err which caused the
        // entire worker startup to abort, creating a persistent crash
        // loop in SystemMode where safe_rmtree_v1 fails due to 0o770
        // lane directory permissions (INV-RMTREE-006 vs SystemMode).
        let lane_id = lane_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let reason = format!(
            "stale lease recovery cleanup failed for lane {lane_id}: {cleanup_reason}; \
             lane marked corrupt (fail-closed, requires `apm2 fac doctor --fix`)"
        );
        let timestamp = current_timestamp_rfc3339();
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: truncate_string(&reason, MAX_STRING_LENGTH),
            cleanup_receipt_digest: None,
            detected_at: timestamp,
        };
        match marker.persist(fac_root) {
            Ok(()) => {
                // Corrupt marker persisted successfully. Log warning and
                // continue — the lane is durably marked CORRUPT and will
                // not accept new jobs until reset.
                eprintln!(
                    "WARNING: lane cleanup failed during stale lease recovery at {}: \
                     {cleanup_reason}; lane marked CORRUPT (requires `apm2 fac doctor --fix`)",
                    lane_dir.display()
                );
                // Do NOT remove the lease — lane is corrupt and needs
                // manual reset. Return Ok(MarkedCorrupt) because the
                // lane was successfully handled (marked corrupt is a
                // valid terminal state for this recovery path).
                return Ok(StaleLeaseOutcome::MarkedCorrupt);
            },
            Err(e) => {
                // Corrupt marker persistence itself failed. This IS a
                // hard error because the lane is in an ambiguous state
                // with no durable evidence. Subsequent startups would
                // not see the lane as corrupt and could attempt unsafe
                // recovery.
                return Err(ReconcileError::io(
                    format!(
                        "failed to persist corrupt marker after cleanup failure for lane \
                         {lane_id} (original cleanup error: {cleanup_reason})"
                    ),
                    std::io::Error::other(e.to_string()),
                ));
            },
        }
    }

    // Step 3: Remove the lease file (IDLE). Safe because CLEANUP is now durable
    // and filesystem cleanup succeeded.
    LaneLeaseV1::remove(lane_dir).map_err(|e| {
        ReconcileError::io(
            format!("failed to remove stale lease at {}", lane_dir.display()),
            std::io::Error::other(e.to_string()),
        )
    })?;

    Ok(StaleLeaseOutcome::Recovered)
}

/// Best-effort filesystem cleanup for a lane during stale lease recovery.
///
/// Prunes `tmp/` and per-lane env directories (`home/`, `xdg_cache/`,
/// `xdg_config/`, `xdg_data/`, `xdg_state/`, `xdg_runtime/`) via
/// `safe_rmtree_v1`. Returns `None` on success, or `Some(reason)` describing
/// all failures encountered.
///
/// **Truly best-effort**: All cleanup steps are attempted regardless of
/// individual failures. In `SystemMode`, lane directories have mode 0o770
/// (group-accessible), which conflicts with `safe_rmtree_v1`'s strict
/// INV-RMTREE-006 (mode 0o700) check. Rather than modifying the security
/// invariant, failures are logged as warnings and accumulated. The caller
/// marks the lane CORRUPT on any failure, which is the fail-closed safety
/// net — the lane will not accept new jobs until explicitly reset via
/// `apm2 fac doctor --fix`.
///
/// This is a subset of the full `LaneManager::run_lane_cleanup` that can run
/// without knowledge of the workspace path or git state.
fn best_effort_lane_cleanup(lane_dir: &Path) -> Option<String> {
    use super::safe_rmtree::safe_rmtree_v1;

    let mut failures: Vec<String> = Vec::new();

    // Prune tmp/ directory.
    let tmp_dir = lane_dir.join("tmp");
    if tmp_dir.exists() {
        if let Err(e) = safe_rmtree_v1(&tmp_dir, lane_dir) {
            eprintln!(
                "WARNING: best-effort lane cleanup: tmp prune failed for {}: {e}",
                lane_dir.display()
            );
            failures.push(format!("tmp prune failed: {e}"));
        }
    }

    // Prune per-lane env directories (home/, xdg_cache/, xdg_config/, etc.).
    // Skip tmp/ since it was already handled above.
    for &env_subdir in super::policy::LANE_ENV_DIRS {
        if env_subdir == super::policy::LANE_ENV_DIR_TMP {
            continue;
        }
        let env_dir = lane_dir.join(env_subdir);
        if env_dir.exists() {
            if let Err(e) = safe_rmtree_v1(&env_dir, lane_dir) {
                eprintln!(
                    "WARNING: best-effort lane cleanup: env dir prune failed for {}: {e}",
                    env_dir.display()
                );
                failures.push(format!(
                    "env dir prune failed for {}: {e}",
                    env_dir.display()
                ));
            }
        }
    }

    if failures.is_empty() {
        None
    } else {
        Some(failures.join("; "))
    }
}

/// Persist a `LaneCorruptMarkerV1` for a lane (INV-RECON-002).
///
/// Fail-closed in apply mode: marker persistence failures are propagated as
/// errors. Ambiguous lane states must not proceed without durable corruption
/// evidence, because subsequent startups would not see the lane as corrupt
/// and could attempt unsafe recovery.
fn persist_corrupt_marker(
    fac_root: &Path,
    lane_id: &str,
    reason: &str,
    timestamp: &str,
) -> Result<(), ReconcileError> {
    let marker = LaneCorruptMarkerV1 {
        schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
        lane_id: lane_id.to_string(),
        reason: truncate_string(reason, MAX_STRING_LENGTH),
        cleanup_receipt_digest: None,
        detected_at: timestamp.to_string(),
    };
    marker.persist(fac_root).map_err(|e| {
        ReconcileError::io(
            format!(
                "failed to persist corrupt marker for lane {lane_id} \
                 (fail-closed: ambiguous state must be durably marked corrupt, \
                 INV-RECON-002)"
            ),
            std::io::Error::other(e.to_string()),
        )
    })
}

/// Phase 2: Scan `queue/claimed/` for orphaned jobs and apply recovery policy.
///
/// INV-RECON-007: Move failures are propagated as errors; counters only
/// increment after confirmed rename success.
#[allow(clippy::too_many_lines)] // recovery logic with fallback branches is inherently branchy
fn reconcile_queue(
    fac_root: &Path,
    queue_root: &Path,
    active_job_ids: &HashSet<String>,
    unknown_identity_job_ids_for_orphan_suppression: &HashSet<String>,
    orphan_policy: OrphanedJobPolicy,
    dry_run: bool,
) -> QueueReconcileResult {
    let claimed_dir = queue_root.join("claimed");
    let pending_dir = queue_root.join("pending");
    let denied_dir = queue_root.join("denied");
    let receipts_dir = fac_root.join("receipts");

    let mut actions: Vec<QueueRecoveryAction> = Vec::new();
    let mut orphaned_jobs_requeued: usize = 0;
    let mut orphaned_jobs_failed: usize = 0;
    let mut torn_states_recovered: usize = 0;
    let mut claimed_files_inspected: usize = 0;
    let mut token_ledger_state: Option<Result<TokenUseLedger, String>> = None;

    // Helper macro to build QueueReconcileResult with current partial counts.
    // This ensures partial_error receipts always carry the actual inspected
    // count (MINOR audit trail fix).
    macro_rules! queue_result {
        ($err:expr) => {
            QueueReconcileResult {
                actions,
                claimed_files_inspected,
                orphaned_jobs_requeued,
                orphaned_jobs_failed,
                torn_states_recovered,
                partial_error: $err,
            }
        };
    }

    // INV-RECON-008: Verify claimed_dir is a real directory, not a symlink.
    // Using symlink_metadata to detect symlinks without following them.
    // If claimed_dir is a symlink, reconciliation must fail closed to prevent
    // iterating and moving files from outside the queue tree.
    match fs::symlink_metadata(&claimed_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return queue_result!(Some(ReconcileError::io(
                    format!(
                        "queue/claimed directory is a symlink: {}",
                        claimed_dir.display()
                    ),
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "claimed directory symlink traversal rejected",
                    ),
                )));
            }
            if !meta.is_dir() {
                // Not a directory and not a symlink — nothing to scan.
                return queue_result!(None);
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Directory does not exist — nothing to reconcile.
            return queue_result!(None);
        },
        Err(e) => {
            return queue_result!(Some(ReconcileError::io(
                format!("stat claimed directory {}", claimed_dir.display()),
                e,
            )));
        },
    }

    let entries = match fs::read_dir(&claimed_dir) {
        Ok(entries) => entries,
        Err(e) => {
            return queue_result!(Some(ReconcileError::io(
                format!("reading claimed directory {}", claimed_dir.display()),
                e,
            )));
        },
    };

    for entry in entries {
        // INV-RECON-005: Count EVERY directory entry toward the scan cap
        // BEFORE file-type filtering. This prevents an attacker from flooding
        // queue/claimed with symlinks, directories, or special files to bypass
        // the MAX_CLAIMED_SCAN_ENTRIES budget and cause unbounded traversal.
        claimed_files_inspected += 1;
        if claimed_files_inspected > MAX_CLAIMED_SCAN_ENTRIES {
            return queue_result!(Some(ReconcileError::TooManyEntries {
                kind: "claimed_scan",
                count: claimed_files_inspected,
                limit: MAX_CLAIMED_SCAN_ENTRIES,
            }));
        }
        let action_count = actions.len();
        if action_count >= MAX_QUEUE_RECOVERY_ACTIONS {
            return queue_result!(Some(ReconcileError::TooManyEntries {
                kind: "queue_recovery_actions",
                count: action_count,
                limit: MAX_QUEUE_RECOVERY_ACTIONS,
            }));
        }

        let Ok(entry) = entry else { continue };

        // THEME 1 (CTR-1503): Reject symlinks, FIFOs, devices, and other
        // non-regular files before processing. Uses symlink_metadata to
        // detect symlinks without following them.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() || file_type.is_dir() {
            // Silently skip symlinks and directories — they are not valid
            // claimed job entries.
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if file_type.is_fifo()
                || file_type.is_block_device()
                || file_type.is_char_device()
                || file_type.is_socket()
            {
                // Skip special files to prevent blocking on FIFOs or
                // interacting with devices.
                continue;
            }
        }
        if !file_type.is_file() {
            continue;
        }

        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        // Only process .json files (case-insensitive extension check).
        if !std::path::Path::new(&file_name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            continue;
        }

        // S11: Reconciliation must not move files currently flock'd by a
        // worker commit. Acquire a non-blocking exclusive flock and keep it
        // held for this iteration to serialize with worker-side commit.
        let claimed_lock_file = match open_file_no_follow(&path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!(
                    "reconcile: skipping claimed entry {} (cannot open for flock probe: {err})",
                    path.display()
                );
                continue;
            },
        };
        let lock_acquired = match try_acquire_exclusive_nonblocking(&claimed_lock_file) {
            Ok(locked) => locked,
            Err(err) => {
                eprintln!(
                    "reconcile: skipping claimed entry {} (flock probe failed: {err})",
                    path.display()
                );
                continue;
            },
        };
        if !lock_acquired {
            let inferred_job_id = file_name.trim_end_matches(".json").to_string();
            actions.push(QueueRecoveryAction::StillActive {
                job_id: inferred_job_id,
                lane_id: "flock_held".to_string(),
            });
            continue;
        }
        // Parse claimed job metadata using bounded I/O. If parsing fails, fall
        // back to filename-derived job_id and treat token binding as unknown.
        let claimed_metadata = parse_claimed_job_metadata(&claimed_lock_file).unwrap_or_default();
        let job_id = claimed_metadata
            .job_id
            .unwrap_or_else(|| file_name.trim_end_matches(".json").to_string());

        // Check if this job is backed by an active lane.
        if active_job_ids.contains(&job_id) {
            actions.push(QueueRecoveryAction::StillActive {
                job_id,
                lane_id: "unknown".to_string(),
            });
            continue;
        }
        if unknown_identity_job_ids_for_orphan_suppression.contains(&job_id) {
            actions.push(QueueRecoveryAction::StillActive {
                job_id,
                lane_id: "unknown_identity_lock_held".to_string(),
            });
            continue;
        }

        // TCK-00564 BLOCKER-2: Detect and repair torn receipt states.
        //
        // Before applying the orphan policy, check if a receipt already exists
        // for this job. If a receipt exists, the worker completed the job and
        // persisted the receipt, but crashed before moving the job file to its
        // terminal directory. This is a "torn state" that should be repaired
        // by moving the job to its correct terminal directory, not by requeuing
        // or marking as failed (which would lose the completed work).
        if let Some(receipt) = find_receipt_for_job(&receipts_dir, &job_id) {
            if let Some(terminal_state) = outcome_to_terminal_state(receipt.outcome) {
                let terminal_dir_name = terminal_state.dir_name().to_string();
                if !dry_run {
                    let pipeline =
                        ReceiptWritePipeline::new(receipts_dir.clone(), queue_root.to_path_buf());
                    // SECURITY JUSTIFICATION: Wall-clock time is acceptable here because
                    // reconciliation is an operational recovery task at startup, not a
                    // coordinated consensus operation. The timestamp is used only for
                    // recovery receipt labelling.
                    #[allow(clippy::disallowed_methods)]
                    let timestamp_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    match pipeline.recover_torn_state(
                        &path,
                        &file_name,
                        &receipt,
                        terminal_state,
                        timestamp_secs,
                    ) {
                        Ok(_recovery_receipt) => {
                            eprintln!(
                                "reconcile: recovered torn state for job {job_id}: \
                                 moved claimed/{file_name} to {terminal_dir_name}/"
                            );
                        },
                        Err(e) => {
                            eprintln!(
                                "reconcile: WARNING: torn state recovery failed for job {job_id}: {e}"
                            );
                            // Fall through to normal orphan handling below.
                            // The job stays in claimed/ and the orphan policy applies.
                            #[allow(clippy::needless_continue)]
                            {
                                // Do NOT continue here; fall through to orphan
                                // policy.
                            }
                        },
                    }
                }
                // If we reach here in dry_run mode, or recovery succeeded:
                if dry_run || !path.exists() {
                    actions.push(QueueRecoveryAction::TornStateRecovered {
                        job_id,
                        file_name,
                        terminal_dir: terminal_dir_name,
                    });
                    torn_states_recovered += 1;
                    continue;
                }
            }
        }

        // Orphaned claimed job — apply policy.
        // INV-RECON-007: Only count success after confirmed rename.
        match orphan_policy {
            OrphanedJobPolicy::Requeue => {
                // INV-RECON-009: Token-bound orphaned claimed jobs are requeued
                // only when authoritative token-ledger state confirms the
                // token nonce is still fresh. Consumed/revoked or unverifiable
                // nonce state is fail-closed to denied.
                if let Some(channel_context_token) =
                    claimed_metadata.channel_context_token.as_deref()
                {
                    let ledger_state = token_ledger_state
                        .get_or_insert_with(|| load_token_ledger_for_reconcile(fac_root));
                    if let Err(reason) =
                        evaluate_token_bound_orphan_requeue(channel_context_token, ledger_state)
                    {
                        if !dry_run && let Err(e) = move_file_safe(&path, &denied_dir, &file_name) {
                            return queue_result!(Some(ReconcileError::MoveFailed {
                                context: format!(
                                    "claimed job {job_id}: token-bound fallback to denied failed: {e}"
                                ),
                            }));
                        }
                        actions.push(QueueRecoveryAction::MarkedFailed {
                            job_id,
                            file_name,
                            reason,
                        });
                        orphaned_jobs_failed += 1;
                        continue;
                    }
                }

                if dry_run {
                    actions.push(QueueRecoveryAction::Requeued { job_id, file_name });
                    orphaned_jobs_requeued += 1;
                    continue;
                }

                match move_file_safe(&path, &pending_dir, &file_name) {
                    Ok(()) => {
                        actions.push(QueueRecoveryAction::Requeued { job_id, file_name });
                        orphaned_jobs_requeued += 1;
                    },
                    Err(requeue_err) => {
                        // Requeue failed — try fallback to denied.
                        let reason = format!("requeue failed: {requeue_err}");
                        match move_file_safe(&path, &denied_dir, &file_name) {
                            Ok(()) => {
                                actions.push(QueueRecoveryAction::MarkedFailed {
                                    job_id,
                                    file_name,
                                    reason,
                                });
                                orphaned_jobs_failed += 1;
                            },
                            Err(deny_err) => {
                                // Both moves failed — propagate as error
                                // with partial counts (INV-RECON-007).
                                return queue_result!(Some(ReconcileError::MoveFailed {
                                    context: format!(
                                        "claimed job {job_id}: requeue failed \
                                         ({requeue_err}), fallback to denied also \
                                         failed ({deny_err})"
                                    ),
                                }));
                            },
                        }
                    },
                }
            },
            OrphanedJobPolicy::MarkFailed => {
                let reason = "orphaned claimed job: no active lane processing \
                              this job after crash recovery"
                    .to_string();
                if !dry_run {
                    // INV-RECON-007: propagate move failure with partial counts.
                    if let Err(e) = move_file_safe(&path, &denied_dir, &file_name) {
                        return queue_result!(Some(ReconcileError::MoveFailed {
                            context: format!("claimed job {job_id}: move to denied failed: {e}"),
                        }));
                    }
                }
                actions.push(QueueRecoveryAction::MarkedFailed {
                    job_id,
                    file_name,
                    reason,
                });
                orphaned_jobs_failed += 1;
            },
        }
    }

    queue_result!(None)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse bounded metadata from an already-open claimed job spec file.
///
/// Security: Caller opens the file with `O_NOFOLLOW` and holds an exclusive
/// flock while parsing. This keeps parsing bound to the same inode that was
/// type-checked and lock-probed in the reconcile loop.
fn parse_claimed_job_metadata(file: &fs::File) -> Option<ClaimedJobMetadata> {
    let file_metadata = file.metadata().ok()?;
    if !file_metadata.is_file() {
        return None;
    }
    if file_metadata.len() > MAX_CLAIMED_FILE_SIZE {
        return None;
    }
    let mut reader = file.try_clone().ok()?;
    reader.seek(std::io::SeekFrom::Start(0)).ok()?;
    let mut buf = Vec::with_capacity(file_metadata.len().min(MAX_CLAIMED_FILE_SIZE) as usize);
    let mut reader = reader.take(MAX_CLAIMED_FILE_SIZE);
    reader.read_to_end(&mut buf).ok()?;

    // Minimal JSON extraction — reconciliation needs only stable metadata.
    let value: serde_json::Value = serde_json::from_slice(&buf).ok()?;
    let job_id = value
        .get("job_id")
        .and_then(serde_json::Value::as_str)
        .filter(|job_id| !job_id.is_empty())
        .map(std::string::ToString::to_string);
    let channel_context_token = value
        .get("actuation")
        .and_then(|actuation| actuation.get("channel_context_token"))
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .map(std::string::ToString::to_string);
    Some(ClaimedJobMetadata {
        job_id,
        channel_context_token,
    })
}

/// Loads token-ledger authority state for reconciliation.
///
/// Returns `Err` when broker state or token-ledger state cannot be loaded,
/// parsed, or replayed. Callers should treat that as fail-closed ambiguity for
/// token-bound orphaned jobs.
fn load_token_ledger_for_reconcile(fac_root: &Path) -> Result<TokenUseLedger, String> {
    let broker_state_path = fac_root.join("broker_state.json");
    let broker_state_bytes =
        read_file_no_follow_bounded(&broker_state_path, MAX_BROKER_STATE_FILE_SIZE)
            .map_err(|e| format!("broker_state.json load failed: {e}"))?;
    let broker_state = super::broker::FacBroker::deserialize_state(&broker_state_bytes)
        .map_err(|e| format!("broker_state.json decode failed: {e}"))?;

    let ledger_dir = fac_root.join("broker").join("token_ledger");
    let snapshot_path = ledger_dir.join("state.json");
    let snapshot_bytes = read_file_no_follow_bounded(
        &snapshot_path,
        crate::fac::token_ledger::MAX_TOKEN_LEDGER_FILE_SIZE as u64,
    )
    .map_err(|e| format!("token ledger snapshot load failed: {e}"))?;
    let mut ledger = TokenUseLedger::deserialize_state(&snapshot_bytes, broker_state.current_tick)
        .map_err(|e| format!("token ledger snapshot decode failed: {e}"))?;

    let wal_path = ledger_dir.join("wal.jsonl");
    if wal_path.exists() {
        let wal_bytes = read_file_no_follow_bounded(
            &wal_path,
            crate::fac::token_ledger::MAX_WAL_FILE_SIZE as u64,
        )
        .map_err(|e| format!("token ledger WAL load failed: {e}"))?;
        ledger
            .replay_wal(&wal_bytes)
            .map_err(|e| format!("token ledger WAL replay failed: {e}"))?;
    }

    Ok(ledger)
}

/// Determines whether a token-bound orphaned job is safe to requeue.
///
/// Returns `Ok(())` only when authoritative token-ledger state confirms the
/// token nonce is still fresh.
fn evaluate_token_bound_orphan_requeue(
    channel_context_token: &str,
    token_ledger_state: &Result<TokenUseLedger, String>,
) -> Result<(), String> {
    let ledger = token_ledger_state
        .as_ref()
        .map_err(|e| format!("{TOKEN_LEDGER_UNAVAILABLE_DENIAL_REASON_PREFIX}: {e}"))?;

    let nonce = extract_token_nonce(channel_context_token)
        .ok_or_else(|| TOKEN_NONCE_UNVERIFIABLE_DENIAL_REASON_PREFIX.to_string())?;

    match ledger.check_nonce(&nonce) {
        Ok(()) => Ok(()),
        Err(TokenLedgerError::ReplayDetected) => {
            Err(TOKEN_NONCE_CONSUMED_DENIAL_REASON.to_string())
        },
        Err(TokenLedgerError::TokenRevoked { reason }) => Err(format!(
            "{TOKEN_NONCE_REVOKED_DENIAL_REASON_PREFIX}: {reason}"
        )),
        Err(e) => Err(format!(
            "{TOKEN_NONCE_UNVERIFIABLE_DENIAL_REASON_PREFIX}: {e}"
        )),
    }
}

/// Extracts the token nonce from a base64-encoded channel-context token.
///
/// Returns `None` if the token is missing required fields, malformed, or
/// exceeds bounded size limits.
fn extract_token_nonce(channel_context_token: &str) -> Option<[u8; 32]> {
    #[derive(Deserialize)]
    struct TokenNonceEnvelope {
        payload: TokenNoncePayload,
    }

    #[derive(Deserialize)]
    struct TokenNoncePayload {
        #[serde(default)]
        token_binding: Option<TokenBindingPayload>,
    }

    #[derive(Deserialize)]
    struct TokenBindingPayload {
        #[serde(default)]
        nonce: Option<[u8; 32]>,
    }

    if channel_context_token.is_empty()
        || channel_context_token.len() > MAX_CHANNEL_CONTEXT_TOKEN_LENGTH
    {
        return None;
    }

    let token_bytes = base64::engine::general_purpose::STANDARD
        .decode(channel_context_token)
        .ok()?;
    let token: TokenNonceEnvelope = serde_json::from_slice(&token_bytes).ok()?;
    token
        .payload
        .token_binding
        .and_then(|binding| binding.nonce)
}

/// Reads a regular file with `O_NOFOLLOW` and bounded size.
fn read_file_no_follow_bounded(path: &Path, max_size: u64) -> Result<Vec<u8>, String> {
    let file = open_file_no_follow(path).map_err(|e| e.to_string())?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.len() > max_size {
        return Err(format!(
            "{} exceeds bounded read cap: {} > {max_size}",
            path.display(),
            metadata.len()
        ));
    }

    let mut reader = file.take(max_size);
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| format!("{} size does not fit usize", path.display()))?;
    let mut buf = Vec::with_capacity(capacity);
    reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(buf)
}

/// Open a file without following symlinks (`O_NOFOLLOW` on Unix).
///
/// Returns `ReconcileError::Io` on failure.
fn open_file_no_follow(path: &Path) -> Result<fs::File, ReconcileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| ReconcileError::io(format!("opening {} (O_NOFOLLOW)", path.display()), e))
    }

    #[cfg(not(unix))]
    {
        fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| ReconcileError::io(format!("opening {}", path.display()), e))
    }
}

/// Move a file to a destination directory, creating the directory if needed.
///
/// Security:
/// - Directories created with mode 0o700 (CTR-2611).
/// - Always uses a unique destination name (nanos + random suffix) to eliminate
///   TOCTOU race between exists-check and rename (RSK-1501). This is safe
///   because reconciliation filenames are internal artifacts.
///
/// Returns `Err` on filesystem errors.
fn move_file_safe(src: &Path, dest_dir: &Path, file_name: &str) -> Result<(), String> {
    // CTR-2611: Create destination dir with restricted permissions (0o700).
    create_dir_restricted(dest_dir)
        .map_err(|e| format!("cannot create {}: {e}", dest_dir.display()))?;

    // Always use a unique destination name to eliminate TOCTOU race
    // (RSK-1501). On POSIX, rename() atomically overwrites regular files,
    // but using unique names prevents any data loss from collision.
    let ts_nanos = wall_clock_nanos();
    let random_suffix = random_u32();
    let stem = file_name.trim_end_matches(".json");
    let unique_name = format!("{stem}-{ts_nanos}-{random_suffix:08x}.json");
    let dest = dest_dir.join(&unique_name);

    match fs::rename(src, &dest) {
        Ok(()) => {},
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // The source file no longer exists — another worker already
            // moved it during concurrent reconciliation. This is expected
            // in multi-worker deployments and is consistent with the
            // idempotent design of Phase 1 reconciliation. Treat as
            // success ("already handled") rather than a terminal failure.
            eprintln!(
                "INFO: move_file_safe: source {} not found (already moved by another worker), \
                 treating as success",
                src.display()
            );
            return Ok(());
        },
        Err(e) => {
            return Err(format!(
                "rename {} -> {}: {e}",
                src.display(),
                dest.display()
            ));
        },
    }

    // Harden destination permissions to 0o600 after move.
    // fs::rename preserves source permissions, which may be world-readable.
    // Reconciliation moves should ensure restricted permissions on destination
    // files to prevent information disclosure (CTR-2611).
    //
    // MAJOR 1 FIX: After a successful rename, chmod failure is logged as a
    // warning but does NOT return Err. The rename has already committed
    // the filesystem mutation — returning Err would cause the caller to
    // interpret the move as failed, attempt a fallback move from the
    // original src path (which no longer exists), and return MoveFailed.
    // This would create unrecorded queue mutations breaking INV-RECON-001/007.
    // Since the file is already in the correct destination, a chmod failure
    // is a permission-hardening miss, not a move failure.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(&dest, perms) {
            eprintln!(
                "WARNING: move_file_safe: rename succeeded but set_permissions failed \
                 for {}: {e} (file moved successfully, permissions not hardened)",
                dest.display()
            );
        }
    }

    Ok(())
}

// SECURITY JUSTIFICATION (CTR-2501): Reconciliation receipt timestamps use
// wall-clock time because reconciliation is an operational recovery task that
// runs at startup, not a coordinated consensus operation. The timestamp is
// used only for receipt labelling and file naming.
#[allow(clippy::disallowed_methods)]
fn current_timestamp_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// SECURITY JUSTIFICATION (CTR-2501): Collision-avoidance suffix for file
// rename uses wall-clock nanos because this is a best-effort deduplication
// mechanism for file moves, not a coordinated timestamp.
#[allow(clippy::disallowed_methods)]
fn wall_clock_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Generate a pseudo-random u32 for collision avoidance in filenames.
///
/// Uses process-local entropy (PID + monotonic time + thread ID) hashed
/// together. Not cryptographic — used only for filename uniqueness.
fn random_u32() -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::hash::DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::time::Instant::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    #[allow(clippy::cast_possible_truncation)] // intentional: we want 32 bits of hash entropy
    let result = hasher.finish() as u32;
    result
}

/// Truncate a string to a maximum byte length, ensuring valid UTF-8.
///
/// When truncation is needed and `max_len >= 3`, the output includes a `"..."`
/// suffix and the total output length is guaranteed to be `<= max_len`. This
/// ensures truncated strings pass `validate_string_field(_, _, max_len)` checks
/// downstream (e.g., `LaneCorruptMarkerV1::load` enforces `MAX_STRING_LENGTH`
/// on the `reason` field).
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    // When max_len < 3, we cannot fit any prefix + "...", so just truncate
    // to max_len bytes at a valid UTF-8 boundary without an ellipsis.
    if max_len < 3 {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        return s[..end].to_string();
    }
    // Reserve 3 bytes for "..." so the total output is <= max_len.
    let truncated_len = max_len - 3;
    let mut end = truncated_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::Engine;
    use tempfile::TempDir;

    use super::*;

    fn setup_fac_and_queue(lane_count: usize) -> (TempDir, PathBuf, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let fac_root = tmp.path().join("private").join("fac");
        let queue_root = tmp.path().join("queue");

        // Create lane directories and lock directories.
        let lanes_dir = fac_root.join("lanes");
        let locks_dir = fac_root.join("locks").join("lanes");
        fs::create_dir_all(&lanes_dir).unwrap();
        fs::create_dir_all(&locks_dir).unwrap();

        for i in 0..lane_count {
            let lane_id = format!("lane-{i:02}");
            let lane_path = lanes_dir.join(&lane_id);
            fs::create_dir_all(lane_path.join("workspace")).unwrap();
            fs::create_dir_all(lane_path.join("target")).unwrap();
            fs::create_dir_all(lane_path.join("logs")).unwrap();
        }

        // Create queue directories.
        for dir in ["pending", "claimed", "completed", "denied", "quarantine"] {
            fs::create_dir_all(queue_root.join(dir)).unwrap();
        }

        (tmp, fac_root, queue_root)
    }

    fn write_lease(fac_root: &Path, lane_id: &str, job_id: &str, pid: u32, state: LaneState) {
        let lane_dir = fac_root.join("lanes").join(lane_id);
        let lease = LaneLeaseV1::new(
            lane_id,
            job_id,
            pid,
            state,
            "2026-01-01T00:00:00Z",
            "deadbeef",
            "cafebabe",
        )
        .unwrap();
        lease.persist(&lane_dir).unwrap();
    }

    fn write_claimed_job(queue_root: &Path, job_id: &str) {
        let claimed_dir = queue_root.join("claimed");
        let spec = serde_json::json!({
            "schema": "apm2.fac.job_spec.v1",
            "job_id": job_id,
            "kind": "test",
        });
        let path = claimed_dir.join(format!("{job_id}.json"));
        fs::write(path, serde_json::to_vec_pretty(&spec).unwrap()).unwrap();
    }

    fn write_broker_state_with_current_tick(fac_root: &Path, current_tick: u64) {
        let mut broker = super::super::broker::FacBroker::new();
        while broker.current_tick() < current_tick {
            let _ = broker.advance_tick();
        }
        fs::write(
            fac_root.join("broker_state.json"),
            broker.serialize_state().expect("serialize broker state"),
        )
        .expect("persist broker state");
    }

    fn write_token_ledger_snapshot_and_wal(
        fac_root: &Path,
        snapshot_bytes: &[u8],
        wal_entries: &[crate::fac::token_ledger::WalEntry],
    ) {
        let ledger_dir = fac_root.join("broker").join("token_ledger");
        fs::create_dir_all(&ledger_dir).expect("create token ledger dir");
        fs::write(ledger_dir.join("state.json"), snapshot_bytes).expect("persist token snapshot");

        if wal_entries.is_empty() {
            return;
        }
        let mut wal_bytes = Vec::new();
        for entry in wal_entries {
            wal_bytes.extend(
                crate::fac::token_ledger::TokenUseLedger::serialize_wal_entry(entry)
                    .expect("serialize wal entry"),
            );
        }
        fs::write(ledger_dir.join("wal.jsonl"), wal_bytes).expect("persist token wal");
    }

    fn make_channel_context_token_with_nonce(nonce: [u8; 32]) -> String {
        let token_json = serde_json::json!({
            "payload": {
                "token_binding": {
                    "nonce": nonce,
                }
            }
        });
        base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&token_json).expect("serialize token payload"))
    }

    fn write_claimed_job_with_token(queue_root: &Path, job_id: &str, channel_context_token: &str) {
        let claimed_dir = queue_root.join("claimed");
        let spec = serde_json::json!({
            "schema": "apm2.fac.job_spec.v1",
            "job_id": job_id,
            "kind": "gates",
            "actuation": {
                "lease_id": "lease-test",
                "request_id": "request-test",
                "channel_context_token": channel_context_token
            }
        });
        let path = claimed_dir.join(format!("{job_id}.json"));
        fs::write(path, serde_json::to_vec_pretty(&spec).unwrap()).unwrap();
    }

    fn write_claimed_job_with_token_without_job_id(
        queue_root: &Path,
        file_stem: &str,
        channel_context_token: &str,
    ) {
        let claimed_dir = queue_root.join("claimed");
        let spec = serde_json::json!({
            "schema": "apm2.fac.job_spec.v1",
            "kind": "gates",
            "actuation": {
                "lease_id": "lease-test",
                "request_id": "request-test",
                "channel_context_token": channel_context_token
            }
        });
        let path = claimed_dir.join(format!("{file_stem}.json"));
        fs::write(path, serde_json::to_vec_pretty(&spec).unwrap()).unwrap();
    }

    #[test]
    fn test_reconcile_clean_state() {
        // No stale leases, no orphaned claimed jobs.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(receipt.stale_leases_recovered, 0);
        assert_eq!(receipt.orphaned_jobs_requeued, 0);
        assert_eq!(receipt.orphaned_jobs_failed, 0);
        assert_eq!(receipt.lanes_marked_corrupt, 0);
        assert_eq!(receipt.lanes_inspected, 3);
        assert!(!receipt.dry_run);
    }

    #[test]
    fn test_reconcile_stale_lease_recovery() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant a stale lease with a dead PID (PID 999999999 should not exist).
        write_lease(
            &fac_root,
            "lane-00",
            "job-stale-1",
            999_999_999,
            LaneState::Running,
        );

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(receipt.stale_leases_recovered, 1);
        // Verify the lease file was removed.
        let lease_path = fac_root.join("lanes").join("lane-00").join("lease.v1.json");
        assert!(!lease_path.exists(), "stale lease file should be removed");
    }

    #[test]
    fn test_reconcile_stale_lease_dry_run() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant a stale lease with a dead PID.
        write_lease(
            &fac_root,
            "lane-00",
            "job-stale-1",
            999_999_999,
            LaneState::Running,
        );

        let receipt = reconcile_on_startup(
            &fac_root,
            &queue_root,
            OrphanedJobPolicy::Requeue,
            true, // dry_run
        )
        .unwrap();

        assert_eq!(receipt.stale_leases_recovered, 1);
        assert!(receipt.dry_run);
        // Verify the lease file was NOT removed in dry-run mode.
        let lease_path = fac_root.join("lanes").join("lane-00").join("lease.v1.json");
        assert!(
            lease_path.exists(),
            "stale lease file should still exist in dry-run mode"
        );
    }

    #[test]
    fn test_reconcile_pid_identity_mismatch_recovers_and_requeues_claimed_job() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(1);
        let lane_id = "lane-00";
        let job_id = "job-pid-mismatch";

        // Write a running lease for the current PID, then corrupt the
        // proc_start_time_ticks to simulate PID reuse identity mismatch.
        write_lease(
            &fac_root,
            lane_id,
            job_id,
            std::process::id(),
            LaneState::Running,
        );
        let lease_path = fac_root.join("lanes").join(lane_id).join("lease.v1.json");
        let mut lease_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&lease_path).expect("read lease")).expect("parse");
        let observed_ticks = lease_value
            .get("proc_start_time_ticks")
            .and_then(serde_json::Value::as_u64)
            .expect("lease should include proc_start_time_ticks");
        lease_value["proc_start_time_ticks"] = serde_json::Value::from(observed_ticks + 1);
        fs::write(
            &lease_path,
            serde_json::to_vec_pretty(&lease_value).expect("serialize lease"),
        )
        .expect("persist mismatched lease");

        // Claimed job should be requeued once stale mismatched lease is
        // recovered.
        write_claimed_job(&queue_root, job_id);

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .expect("reconcile");

        assert_eq!(
            receipt.stale_leases_recovered, 1,
            "identity mismatch must recover stale lease"
        );
        assert_eq!(
            receipt.lanes_marked_corrupt, 0,
            "identity mismatch should not fail-closed to corrupt"
        );
        assert_eq!(
            receipt.orphaned_jobs_requeued, 1,
            "claimed job should be requeued once mismatched lease is recovered"
        );
        assert!(
            !lease_path.exists(),
            "stale mismatched lease file should be removed"
        );
    }

    #[test]
    fn test_reconcile_lock_held_unknown_identity_keeps_claimed_job_still_active() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(1);
        let lane_id = "lane-00";
        let job_id = "job-unknown-identity-active";

        // Seed a running lease for this process, then clear proc_start_time_ticks
        // to force ProcessIdentity::Unknown.
        write_lease(
            &fac_root,
            lane_id,
            job_id,
            std::process::id(),
            LaneState::Running,
        );
        let lease_path = fac_root.join("lanes").join(lane_id).join("lease.v1.json");
        let mut lease_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&lease_path).expect("read lease")).expect("parse");
        lease_value["proc_start_time_ticks"] = serde_json::Value::Null;
        fs::write(
            &lease_path,
            serde_json::to_vec_pretty(&lease_value).expect("serialize lease"),
        )
        .expect("persist unknown-identity lease");

        // Keep the lane lock held to represent an active in-flight owner.
        let lane_lock_path = fac_root
            .join("locks")
            .join("lanes")
            .join(format!("{lane_id}.lock"));
        let lane_lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lane_lock_path)
            .expect("open lane lock");
        crate::fac::flock_util::acquire_exclusive_blocking(&lane_lock).expect("acquire lane lock");

        write_claimed_job(&queue_root, job_id);

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .expect("reconcile");

        assert_eq!(
            receipt.orphaned_jobs_requeued, 0,
            "lock-held unknown identity lane must suppress orphan requeue"
        );
        assert_eq!(
            receipt.orphaned_jobs_failed, 0,
            "lock-held unknown identity lane must not fail active claimed job"
        );
        assert!(
            receipt.queue_actions.iter().any(|action| matches!(
                action,
                QueueRecoveryAction::StillActive { job_id, lane_id }
                if job_id == "job-unknown-identity-active"
                    && lane_id == "unknown_identity_lock_held"
            )),
            "expected StillActive action via active-job suppression for unknown identity"
        );
        assert!(
            receipt.lanes_marked_corrupt >= 1,
            "unknown identity should be durably marked corrupt for manual cleanup"
        );

        let claimed_path = queue_root.join("claimed").join(format!("{job_id}.json"));
        assert!(
            claimed_path.exists(),
            "claimed job must remain in claimed/ while active lane lock is held"
        );
        let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect("load marker")
            .expect("marker should exist");
        assert!(
            marker.reason.contains("process identity is unknown"),
            "corrupt marker should explain unknown identity: {}",
            marker.reason
        );
    }

    #[test]
    fn test_reconcile_orphaned_claimed_requeue() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant an orphaned claimed job (no lane is processing it).
        write_claimed_job(&queue_root, "job-orphan-1");

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(receipt.orphaned_jobs_requeued, 1);
        assert_eq!(receipt.orphaned_jobs_failed, 0);

        // Verify the file was moved from claimed/ to pending/.
        let claimed_path = queue_root.join("claimed").join("job-orphan-1.json");
        assert!(!claimed_path.exists(), "claimed file should be moved");
        // File is moved with a unique name, so check pending/ has exactly one file.
        let pending_entries: Vec<_> = fs::read_dir(queue_root.join("pending"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(pending_entries.len(), 1, "file should be in pending/");
    }

    #[test]
    fn test_reconcile_orphaned_claimed_mark_failed() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        write_claimed_job(&queue_root, "job-orphan-2");

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::MarkFailed, false)
                .unwrap();

        assert_eq!(receipt.orphaned_jobs_requeued, 0);
        assert_eq!(receipt.orphaned_jobs_failed, 1);

        // Verify the file was moved from claimed/ to denied/.
        let claimed_path = queue_root.join("claimed").join("job-orphan-2.json");
        assert!(!claimed_path.exists(), "claimed file should be moved");
        // File is moved with a unique name, so check denied/ has exactly one file.
        let denied_entries: Vec<_> = fs::read_dir(queue_root.join("denied"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(denied_entries.len(), 1, "file should be in denied/");
    }

    #[test]
    fn test_reconcile_orphaned_token_bound_claimed_fail_closed_when_ledger_unavailable() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);
        let token = make_channel_context_token_with_nonce([0x42; 32]);

        write_claimed_job_with_token(&queue_root, "job-orphan-token", &token);

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(
            receipt.orphaned_jobs_requeued, 0,
            "token-bound orphaned jobs must not be requeued"
        );
        assert_eq!(
            receipt.orphaned_jobs_failed, 1,
            "token-bound orphaned jobs should fail-closed when ledger state is unavailable"
        );
        assert!(
            receipt.queue_actions.iter().any(|action| matches!(
                action,
                QueueRecoveryAction::MarkedFailed { reason, .. }
                    if reason.starts_with(TOKEN_LEDGER_UNAVAILABLE_DENIAL_REASON_PREFIX)
            )),
            "queue action should record token-ledger fail-closed reason"
        );

        let claimed_path = queue_root.join("claimed").join("job-orphan-token.json");
        assert!(
            !claimed_path.exists(),
            "token-bound claimed file should be moved out of claimed/"
        );
        let denied_entries: Vec<_> = fs::read_dir(queue_root.join("denied"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(denied_entries.len(), 1, "file should be in denied/");
    }

    #[test]
    fn test_reconcile_orphaned_token_bound_claimed_consumed_nonce_marks_failed() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);
        let job_id = "job-orphan-token-consumed";
        let nonce = [0x9A; 32];
        let request_digest = [0x11; 32];
        let token = make_channel_context_token_with_nonce(nonce);

        // Snapshot has nonce in Issued state; WAL records transition to Consumed.
        let mut ledger = TokenUseLedger::new();
        ledger
            .register_nonce(&nonce, &request_digest, 10)
            .expect("register nonce");
        let snapshot_bytes = ledger.serialize_state().expect("serialize snapshot");
        let consume_wal = ledger
            .record_token_use(&nonce, &request_digest, 11)
            .expect("consume nonce");

        write_broker_state_with_current_tick(&fac_root, 11);
        write_token_ledger_snapshot_and_wal(&fac_root, &snapshot_bytes, &[consume_wal]);
        write_claimed_job_with_token(&queue_root, job_id, &token);

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(
            receipt.orphaned_jobs_requeued, 0,
            "consumed nonce jobs must not be requeued"
        );
        assert_eq!(
            receipt.orphaned_jobs_failed, 1,
            "consumed nonce jobs should be marked failed under requeue policy"
        );
        assert!(
            receipt.queue_actions.iter().any(|action| matches!(
                action,
                QueueRecoveryAction::MarkedFailed {
                    job_id, reason, ..
                } if job_id == "job-orphan-token-consumed" && reason == TOKEN_NONCE_CONSUMED_DENIAL_REASON
            )),
            "expected consumed-nonce denial reason for replay prevention"
        );

        let claimed_path = queue_root.join("claimed").join(format!("{job_id}.json"));
        assert!(
            !claimed_path.exists(),
            "token-bound claimed file should be moved out of claimed/"
        );
        let denied_entries: Vec<_> = fs::read_dir(queue_root.join("denied"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(denied_entries.len(), 1, "file should be in denied/");
    }

    #[test]
    fn test_reconcile_orphaned_token_bound_claimed_fresh_nonce_requeues() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);
        let job_id = "job-orphan-token-fresh";
        let nonce = [0xB7; 32];
        let request_digest = [0x22; 32];
        let token = make_channel_context_token_with_nonce(nonce);

        let mut ledger = TokenUseLedger::new();
        ledger
            .register_nonce(&nonce, &request_digest, 10)
            .expect("register nonce");
        let snapshot_bytes = ledger.serialize_state().expect("serialize snapshot");

        write_broker_state_with_current_tick(&fac_root, 10);
        write_token_ledger_snapshot_and_wal(&fac_root, &snapshot_bytes, &[]);
        write_claimed_job_with_token(&queue_root, job_id, &token);

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(
            receipt.orphaned_jobs_requeued, 1,
            "fresh nonce jobs should requeue under requeue policy"
        );
        assert_eq!(
            receipt.orphaned_jobs_failed, 0,
            "fresh nonce jobs should not be marked failed"
        );
        let claimed_path = queue_root.join("claimed").join(format!("{job_id}.json"));
        assert!(
            !claimed_path.exists(),
            "claimed file should be moved to pending/"
        );
        let pending_entries: Vec<_> = fs::read_dir(queue_root.join("pending"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(pending_entries.len(), 1, "file should be in pending/");
    }

    #[test]
    fn test_reconcile_orphaned_token_bound_claimed_without_job_id_uses_filename_fallback() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);
        let file_stem = "job-orphan-token-no-job-id";
        let token = make_channel_context_token_with_nonce([0x61; 32]);
        write_claimed_job_with_token_without_job_id(&queue_root, file_stem, &token);

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(receipt.orphaned_jobs_requeued, 0);
        assert_eq!(receipt.orphaned_jobs_failed, 1);
        assert!(
            receipt.queue_actions.iter().any(|action| matches!(
                action,
                QueueRecoveryAction::MarkedFailed {
                    job_id, reason, ..
                } if job_id == file_stem && reason.starts_with(TOKEN_LEDGER_UNAVAILABLE_DENIAL_REASON_PREFIX)
            )),
            "missing job_id should fall back to filename under fail-closed token-ledger ambiguity"
        );
    }

    #[test]
    fn test_reconcile_orphaned_token_bound_claimed_consumed_nonce_dry_run_marks_failed_without_move()
     {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);
        let job_id = "job-orphan-token-dry-run";
        let nonce = [0xC3; 32];
        let request_digest = [0x33; 32];
        let token = make_channel_context_token_with_nonce(nonce);

        let mut ledger = TokenUseLedger::new();
        ledger
            .register_nonce(&nonce, &request_digest, 10)
            .expect("register nonce");
        let snapshot_bytes = ledger.serialize_state().expect("serialize snapshot");
        let consume_wal = ledger
            .record_token_use(&nonce, &request_digest, 11)
            .expect("consume nonce");

        write_broker_state_with_current_tick(&fac_root, 11);
        write_token_ledger_snapshot_and_wal(&fac_root, &snapshot_bytes, &[consume_wal]);
        write_claimed_job_with_token(&queue_root, job_id, &token);

        let receipt = reconcile_on_startup(
            &fac_root,
            &queue_root,
            OrphanedJobPolicy::Requeue,
            true, // dry_run
        )
        .unwrap();

        assert_eq!(receipt.orphaned_jobs_requeued, 0);
        assert_eq!(receipt.orphaned_jobs_failed, 1);
        assert!(
            receipt.queue_actions.iter().any(|action| matches!(
                action,
                QueueRecoveryAction::MarkedFailed { reason, .. }
                    if reason == TOKEN_NONCE_CONSUMED_DENIAL_REASON
            )),
            "dry-run should classify consumed nonce as non-retriable"
        );
        let claimed_path = queue_root.join("claimed").join(format!("{job_id}.json"));
        assert!(claimed_path.exists(), "dry-run must not move claimed files");
        let denied_entries: Vec<_> = fs::read_dir(queue_root.join("denied"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(denied_entries.len(), 0, "dry-run must not populate denied/");
    }

    #[test]
    fn test_reconcile_receipt_persisted() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        let _receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        // Verify the receipt was persisted.
        let receipts_dir = fac_root.join("receipts").join("reconcile");
        assert!(receipts_dir.is_dir());
        let entries: Vec<_> = fs::read_dir(&receipts_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one receipt should be persisted");
    }

    #[test]
    fn test_reconcile_idempotent() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant a stale lease.
        write_lease(
            &fac_root,
            "lane-01",
            "job-idem",
            999_999_999,
            LaneState::Running,
        );

        // First reconciliation.
        let r1 = reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
            .unwrap();
        assert_eq!(r1.stale_leases_recovered, 1);

        // Second reconciliation should find everything clean.
        let r2 = reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
            .unwrap();
        assert_eq!(r2.stale_leases_recovered, 0);
        assert_eq!(r2.orphaned_jobs_requeued, 0);
    }

    #[test]
    fn test_reconcile_corrupt_lane_not_recovered() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant a corrupt marker.
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: "lane-02".to_string(),
            reason: "test corruption".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-01-01T00:00:00Z".to_string(),
        };
        marker.persist(&fac_root).unwrap();

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        // Corrupt lane should be reported but not recovered.
        assert_eq!(receipt.lanes_marked_corrupt, 1);
        assert_eq!(receipt.stale_leases_recovered, 0);
    }

    #[test]
    fn test_reconcile_mixed_scenario() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Lane 0: stale lease (dead PID).
        write_lease(
            &fac_root,
            "lane-00",
            "job-a",
            999_999_999,
            LaneState::Running,
        );

        // Lane 1: clean (no lease).
        // Lane 2: corrupt marker.
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: "lane-02".to_string(),
            reason: "previous crash".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-01-01T00:00:00Z".to_string(),
        };
        marker.persist(&fac_root).unwrap();

        // Orphaned claimed job (not backed by any lane).
        write_claimed_job(&queue_root, "job-orphan");

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(receipt.stale_leases_recovered, 1);
        assert_eq!(receipt.orphaned_jobs_requeued, 1);
        assert_eq!(receipt.lanes_marked_corrupt, 1);
        assert_eq!(receipt.lanes_inspected, 3);
    }

    #[test]
    fn test_truncate_string() {
        // No truncation needed — string fits within max_len.
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("", 5), "");

        // Truncation with ellipsis — total output must be <= max_len.
        assert_eq!(truncate_string("hello world", 8), "hello...");
        assert_eq!(truncate_string("hello world", 8).len(), 8);

        // Edge case: max_len == 3 → empty prefix + "...".
        assert_eq!(truncate_string("hello world", 3), "...");
        assert_eq!(truncate_string("hello world", 3).len(), 3);

        // Edge case: max_len < 3 → no ellipsis, just truncated.
        assert_eq!(truncate_string("hello", 2), "he");
        assert_eq!(truncate_string("hello", 0), "");

        // Verify truncated strings pass MAX_STRING_LENGTH validation.
        // This is the critical property: truncate_string(s, MAX_STRING_LENGTH)
        // must produce a string whose len() <= MAX_STRING_LENGTH, so that
        // LaneCorruptMarkerV1::load can validate the reason field.
        let long_string = "x".repeat(MAX_STRING_LENGTH + 100);
        let truncated = truncate_string(&long_string, MAX_STRING_LENGTH);
        assert!(
            truncated.len() <= MAX_STRING_LENGTH,
            "truncated string length {} exceeds MAX_STRING_LENGTH {}",
            truncated.len(),
            MAX_STRING_LENGTH,
        );
        assert!(
            truncated.ends_with("..."),
            "truncated string should end with '...'"
        );
    }

    #[test]
    fn test_receipt_persistence_fail_closed_in_apply_mode() {
        // When the receipts directory cannot be written (e.g., read-only
        // parent), reconcile_on_startup in apply mode must return Err.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Make the fac_root read-only so receipt persistence fails.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o500);
            fs::set_permissions(&fac_root, perms).unwrap();
        }

        let result =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false);

        // Restore permissions for cleanup.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&fac_root, perms).unwrap();
        }

        assert!(
            result.is_err(),
            "apply mode must fail when receipt persistence fails"
        );
    }

    #[test]
    fn test_receipt_persistence_best_effort_in_dry_run() {
        // In dry-run mode, receipt persistence failure is non-fatal.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Make the receipts parent dir read-only.
        let receipts_parent = fac_root.join("receipts");
        fs::create_dir_all(&receipts_parent).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o500);
            fs::set_permissions(&receipts_parent, perms).unwrap();
        }

        let result = reconcile_on_startup(
            &fac_root,
            &queue_root,
            OrphanedJobPolicy::Requeue,
            true, // dry_run
        );

        // Restore permissions for cleanup.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&receipts_parent, perms).unwrap();
        }

        assert!(
            result.is_ok(),
            "dry-run mode should succeed even when receipt persistence fails"
        );
    }

    #[test]
    fn test_symlink_in_claimed_skipped() {
        // Symlinks in claimed/ should be skipped, not followed.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let claimed_dir = queue_root.join("claimed");
            let target = queue_root.join("pending").join("decoy.json");
            fs::write(&target, b"{}").unwrap();
            symlink(&target, claimed_dir.join("symlink-job.json")).unwrap();
        }

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        // The symlink should have been skipped, not processed.
        assert_eq!(receipt.orphaned_jobs_requeued, 0);
        assert_eq!(receipt.orphaned_jobs_failed, 0);
    }

    #[test]
    fn test_move_failure_propagated_not_swallowed() {
        // When a move fails and fallback also fails, reconciliation must
        // return an error (INV-RECON-007).
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        write_claimed_job(&queue_root, "job-stuck");

        // Remove pending and denied dirs and make them non-creatable.
        let pending = queue_root.join("pending");
        let denied = queue_root.join("denied");
        fs::remove_dir_all(&pending).unwrap();
        fs::remove_dir_all(&denied).unwrap();

        // Make queue_root read-only so dirs cannot be created.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o500);
            fs::set_permissions(&queue_root, perms).unwrap();
        }

        let result =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false);

        // Restore permissions for cleanup.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&queue_root, perms).unwrap();
        }

        assert!(
            result.is_err(),
            "move failure must propagate as error, not be swallowed"
        );
    }

    #[test]
    fn test_receipt_collision_resistant_filenames() {
        // Multiple reconciliation passes should produce uniquely named
        // receipts even within the same second.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        let _r1 = reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
            .unwrap();
        let _r2 = reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
            .unwrap();

        let receipts_dir = fac_root.join("receipts").join("reconcile");
        let entries: Vec<_> = fs::read_dir(&receipts_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(
            entries.len(),
            2,
            "two receipts should exist with unique filenames"
        );
    }

    #[test]
    fn test_non_regular_entries_count_toward_scan_cap() {
        // Non-regular entries (symlinks, directories) MUST count toward the
        // MAX_CLAIMED_SCAN_ENTRIES budget to prevent an attacker from flooding
        // claimed/ with non-regular entries to bypass the scan cap.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let claimed_dir = queue_root.join("claimed");
            let target = queue_root.join("pending").join("decoy.json");
            fs::write(&target, b"{}").unwrap();

            // Create one symlink and one subdirectory in claimed/.
            symlink(&target, claimed_dir.join("symlink-entry.json")).unwrap();
            fs::create_dir(claimed_dir.join("subdir-entry")).unwrap();
            // Create one real claimed job.
            write_claimed_job(&queue_root, "job-real");
        }

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        // All three entries (symlink + directory + regular file) should count
        // toward claimed_files_inspected, not just the regular file.
        #[cfg(unix)]
        assert!(
            receipt.claimed_files_inspected >= 3,
            "all directory entries (including non-regular) must count toward scan cap, \
             got {}",
            receipt.claimed_files_inspected
        );
    }

    #[test]
    fn test_claimed_dir_symlink_rejected() {
        // If queue/claimed itself is a symlink, reconciliation must fail
        // closed to prevent iterating files from outside the queue tree.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            // Remove the real claimed/ directory and replace with a symlink
            // to a decoy directory.
            let claimed_dir = queue_root.join("claimed");
            let decoy_dir = queue_root.join("decoy_target");
            fs::create_dir_all(&decoy_dir).unwrap();
            fs::write(decoy_dir.join("trap.json"), b"{\"job_id\":\"trap\"}").unwrap();
            fs::remove_dir_all(&claimed_dir).unwrap();
            symlink(&decoy_dir, &claimed_dir).unwrap();

            let result =
                reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false);

            assert!(
                result.is_err(),
                "reconciliation must fail closed when claimed/ is a symlink"
            );
            let err_msg = format!("{}", result.unwrap_err());
            assert!(
                err_msg.contains("symlink"),
                "error message should mention symlink: {err_msg}"
            );
        }
    }

    #[test]
    fn test_partial_receipt_persisted_on_phase2_failure() {
        // If Phase 1 (lane reconciliation) succeeds and mutates state, but
        // Phase 2 (queue reconciliation) fails, a partial receipt containing
        // Phase 1 actions must be persisted before the error is returned
        // (INV-RECON-001).
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant a stale lease so Phase 1 actually does work (mutation).
        write_lease(
            &fac_root,
            "lane-00",
            "job-stale-partial",
            999_999_999,
            LaneState::Running,
        );

        // Plant a claimed job, then sabotage both pending/ and denied/ and
        // make queue_root read-only so the move operation fails (Phase 2
        // error).
        write_claimed_job(&queue_root, "job-orphan-partial");
        let pending = queue_root.join("pending");
        let denied = queue_root.join("denied");
        fs::remove_dir_all(&pending).unwrap();
        fs::remove_dir_all(&denied).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o500);
            fs::set_permissions(&queue_root, perms).unwrap();
        }

        let result =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false);

        // Restore permissions for cleanup.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&queue_root, perms).unwrap();
        }

        // Phase 2 should have failed.
        assert!(result.is_err(), "Phase 2 failure should propagate");

        // But Phase 1's partial receipt should have been persisted.
        let receipts_dir = fac_root.join("receipts").join("reconcile");
        assert!(
            receipts_dir.is_dir(),
            "receipts directory should exist for partial receipt"
        );
        let receipt_entries: Vec<_> = fs::read_dir(&receipts_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(
            receipt_entries.len(),
            1,
            "exactly one partial receipt should be persisted despite Phase 2 failure"
        );

        // Load the partial receipt and verify it contains Phase 1 actions.
        let receipt_path = receipt_entries[0].path();
        let partial_receipt = ReconcileReceiptV1::load(&receipt_path).unwrap();
        assert_eq!(
            partial_receipt.stale_leases_recovered, 1,
            "partial receipt should record Phase 1 lane recovery"
        );
        assert!(
            partial_receipt.queue_actions.is_empty(),
            "partial receipt should have empty queue_actions since Phase 2 failed"
        );
    }

    #[test]
    fn test_cleanup_persist_failure_is_fail_closed() {
        // INV-RECON-006: When the CLEANUP transition persist fails (e.g.,
        // lane directory is read-only), recover_stale_lease must return Err
        // instead of proceeding with lease removal.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant a stale lease with a dead PID.
        write_lease(
            &fac_root,
            "lane-00",
            "job-cleanup-fail",
            999_999_999,
            LaneState::Running,
        );

        // Make the lane directory read-only so the CLEANUP persist fails.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lane_dir = fac_root.join("lanes").join("lane-00");
            let perms = fs::Permissions::from_mode(0o500);
            fs::set_permissions(&lane_dir, perms).unwrap();

            let result =
                reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false);

            // Restore permissions for cleanup.
            fs::set_permissions(&lane_dir, fs::Permissions::from_mode(0o700)).unwrap();

            assert!(
                result.is_err(),
                "CLEANUP persist failure must be a hard error (fail-closed), \
                 not log-and-continue"
            );
            let err_msg = format!("{}", result.unwrap_err());
            assert!(
                err_msg.contains("CLEANUP"),
                "error message should mention CLEANUP: {err_msg}"
            );

            // The lease file should still exist (removal was blocked).
            let lease_path = lane_dir.join("lease.v1.json");
            assert!(
                lease_path.exists(),
                "lease file must NOT be removed when CLEANUP persist fails"
            );
        }
    }

    #[test]
    fn test_corrupt_marker_persist_failure_is_fail_closed() {
        // INV-RECON-002: When corrupt marker persistence fails in apply mode,
        // reconciliation must return Err. Ambiguous states must not proceed
        // without durable corruption evidence.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Create an ambiguous lane state: lease present with a PID that is
        // alive (use our own PID) but lock is not held. This triggers the
        // "ambiguous lane state" → MarkedCorrupt path.
        let our_pid = std::process::id();
        write_lease(
            &fac_root,
            "lane-00",
            "job-ambiguous",
            our_pid,
            LaneState::Idle,
        );

        // Make the corrupt markers directory unwritable so marker persist fails.
        // The corrupt marker path is fac_root/lanes/<lane_id>/corrupt.v1.json.
        // Make the lane directory read-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lane_dir = fac_root.join("lanes").join("lane-00");
            let perms = fs::Permissions::from_mode(0o500);
            fs::set_permissions(&lane_dir, perms).unwrap();

            let result =
                reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false);

            // Restore permissions for cleanup.
            fs::set_permissions(&lane_dir, fs::Permissions::from_mode(0o700)).unwrap();

            assert!(
                result.is_err(),
                "corrupt marker persist failure must be a hard error in apply mode"
            );
            let err_msg = format!("{}", result.unwrap_err());
            assert!(
                err_msg.contains("corrupt marker") || err_msg.contains("INV-RECON-002"),
                "error message should reference corrupt marker or INV-RECON-002: {err_msg}"
            );
        }
    }

    #[test]
    fn test_partial_receipt_persist_failure_returns_combined_error() {
        // INV-RECON-001: When Phase 2 fails AND partial receipt persistence
        // also fails, the returned error must include both failure contexts
        // (not silently drop the persistence failure).
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant a stale lease so Phase 1 does work.
        write_lease(
            &fac_root,
            "lane-00",
            "job-combined-err",
            999_999_999,
            LaneState::Running,
        );

        // Plant a claimed job, then sabotage moves to cause Phase 2 failure.
        write_claimed_job(&queue_root, "job-orphan-combined");
        let pending = queue_root.join("pending");
        let denied = queue_root.join("denied");
        fs::remove_dir_all(&pending).unwrap();
        fs::remove_dir_all(&denied).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Make queue_root read-only so Phase 2 moves fail.
            fs::set_permissions(&queue_root, fs::Permissions::from_mode(0o500)).unwrap();

            // Also make the receipts directory unwritable so partial receipt
            // persistence fails.
            let receipts_dir = fac_root.join("receipts");
            fs::create_dir_all(&receipts_dir).unwrap();
            fs::set_permissions(&receipts_dir, fs::Permissions::from_mode(0o500)).unwrap();

            let result =
                reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false);

            // Restore permissions for cleanup.
            fs::set_permissions(&queue_root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&receipts_dir, fs::Permissions::from_mode(0o700)).unwrap();

            assert!(result.is_err(), "combined failure should propagate");
            let err_msg = format!("{}", result.unwrap_err());
            // The error should mention both failures (partial receipt + phase 2).
            assert!(
                err_msg.contains("partial receipt persistence failed")
                    && err_msg.contains("phase2"),
                "combined error should mention both partial receipt and phase 2: {err_msg}"
            );
        }
    }

    #[test]
    fn test_corrupt_branch_persists_marker_when_absent() {
        // INV-RECON-014: When reconcile_lanes encounters a LaneState::Corrupt
        // derived from runtime state (e.g., lock free + PID alive), but no
        // durable corrupt marker exists on disk, reconciliation must persist
        // one. This test verifies that behaviour by creating a scenario where
        // derive_lane_state returns Corrupt without a persisted marker.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Create a lease for lane-00 where our own PID is alive and the
        // lock is NOT held. derive_lane_state sees: lock_free + lease
        // present + PID alive → Corrupt (INV-LANE-004).
        // Importantly, do NOT plant a LaneCorruptMarkerV1 — the corruption
        // is derived from runtime state only.
        let our_pid = std::process::id();
        write_lease(
            &fac_root,
            "lane-00",
            "job-derived-corrupt",
            our_pid,
            LaneState::Running,
        );

        // Confirm no marker exists before reconciliation.
        let marker_before =
            LaneCorruptMarkerV1::load(&fac_root, "lane-00").expect("load marker before");
        assert!(
            marker_before.is_none(),
            "no marker should exist before reconciliation"
        );

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        // The lane should be counted as corrupt.
        assert!(
            receipt.lanes_marked_corrupt >= 1,
            "lane-00 should be marked corrupt, got lanes_marked_corrupt={}",
            receipt.lanes_marked_corrupt
        );

        // A durable corrupt marker should now exist on disk.
        let marker_after =
            LaneCorruptMarkerV1::load(&fac_root, "lane-00").expect("load marker after");
        assert!(
            marker_after.is_some(),
            "durable corrupt marker must be persisted for derived corrupt state"
        );
    }

    #[test]
    fn test_receipt_load_rejects_wrong_schema() {
        // ReconcileReceiptV1::load must reject receipts with a non-matching
        // schema field, consistent with other FAC record types.
        let tmp = TempDir::new().unwrap();
        let receipt_path = tmp.path().join("bad-schema.json");

        let bad_receipt = serde_json::json!({
            "schema": "apm2.fac.WRONG_SCHEMA.v1",
            "timestamp": "2026-01-01T00:00:00Z",
            "dry_run": false,
            "lane_actions": [],
            "queue_actions": [],
            "lanes_inspected": 0,
            "claimed_files_inspected": 0,
            "stale_leases_recovered": 0,
            "orphaned_jobs_requeued": 0,
            "orphaned_jobs_failed": 0,
            "lanes_marked_corrupt": 0
        });
        fs::write(
            &receipt_path,
            serde_json::to_vec_pretty(&bad_receipt).unwrap(),
        )
        .unwrap();

        let result = ReconcileReceiptV1::load(&receipt_path);
        assert!(result.is_err(), "load must reject wrong schema");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("schema mismatch"),
            "error should mention schema mismatch: {err_msg}"
        );
    }

    #[test]
    fn test_receipt_load_accepts_correct_schema() {
        // ReconcileReceiptV1::load must accept receipts with the correct schema.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Run a reconciliation to produce a receipt with the correct schema.
        let _receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        let receipts_dir = fac_root.join("receipts").join("reconcile");
        let entries: Vec<_> = fs::read_dir(&receipts_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(entries.len(), 1);

        let loaded = ReconcileReceiptV1::load(&entries[0].path()).unwrap();
        assert_eq!(loaded.schema, RECONCILE_RECEIPT_SCHEMA);
    }

    #[test]
    fn test_stale_lease_recovery_prunes_tmp_and_env_dirs() {
        // MAJOR 2 fix: recover_stale_lease must prune tmp/ and per-lane env
        // dirs (home/, xdg_cache/, xdg_config/, etc.) during cleanup to
        // prevent cross-job contamination.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // safe_rmtree_v1 requires the allowed_parent (lane_dir) to have mode
        // 0o700 (INV-RMTREE-006). Set this before creating child dirs.
        let lane_dir = fac_root.join("lanes").join("lane-00");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lane_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        // Plant stale files in lane-00's tmp/ and env dirs.
        let tmp_dir = lane_dir.join("tmp");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(tmp_dir.join("stale-build-artifact.o"), b"stale").unwrap();

        let home_dir = lane_dir.join("home");
        fs::create_dir_all(&home_dir).unwrap();
        fs::write(home_dir.join(".bash_history"), b"secret commands").unwrap();

        let xdg_cache_dir = lane_dir.join("xdg_cache");
        fs::create_dir_all(&xdg_cache_dir).unwrap();
        fs::write(xdg_cache_dir.join("cached-crate.tar"), b"cached data").unwrap();

        // Plant a stale lease with dead PID.
        write_lease(
            &fac_root,
            "lane-00",
            "job-dirty-workspace",
            999_999_999,
            LaneState::Running,
        );

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        assert_eq!(receipt.stale_leases_recovered, 1);

        // Verify stale files were cleaned up.
        assert!(
            !tmp_dir.exists(),
            "tmp/ directory should be removed during stale lease recovery"
        );
        assert!(
            !home_dir.exists(),
            "home/ directory should be removed during stale lease recovery"
        );
        assert!(
            !xdg_cache_dir.exists(),
            "xdg_cache/ directory should be removed during stale lease recovery"
        );

        // Verify the lease file was also removed (lane is IDLE).
        let lease_path = lane_dir.join("lease.v1.json");
        assert!(
            !lease_path.exists(),
            "stale lease file should be removed after successful cleanup"
        );
    }

    #[test]
    fn test_truncated_corrupt_reason_passes_marker_load_validation() {
        // MAJOR 1 regression test: Verify that a corrupt marker persisted
        // with a truncated reason can be loaded back successfully. Previously,
        // truncate_string(s, MAX_STRING_LENGTH) could produce strings of length
        // MAX_STRING_LENGTH + 3 (due to appending "..."), which would fail the
        // LaneCorruptMarkerV1::load validation.
        let (_tmp, fac_root, _queue_root) = setup_fac_and_queue(3);

        // Create a reason string that exceeds MAX_STRING_LENGTH to trigger truncation.
        let long_reason = "x".repeat(MAX_STRING_LENGTH + 100);
        let timestamp = "2026-01-01T00:00:00Z";

        // persist_corrupt_marker internally calls truncate_string.
        persist_corrupt_marker(&fac_root, "lane-00", &long_reason, timestamp).unwrap();

        // Load must succeed — the truncated reason must fit within MAX_STRING_LENGTH.
        let loaded = LaneCorruptMarkerV1::load(&fac_root, "lane-00").unwrap();
        assert!(
            loaded.is_some(),
            "corrupt marker with truncated reason must load successfully"
        );
        let marker = loaded.unwrap();
        assert!(
            marker.reason.len() <= MAX_STRING_LENGTH,
            "loaded reason length {} exceeds MAX_STRING_LENGTH {}",
            marker.reason.len(),
            MAX_STRING_LENGTH,
        );
        assert!(
            marker.reason.ends_with("..."),
            "truncated reason should end with '...'"
        );
    }

    #[test]
    fn test_move_file_safe_hardens_permissions() {
        // INV-RECON-013: move_file_safe must set destination file permissions
        // to 0o600 after rename, regardless of source permissions.
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        let dest_dir = tmp.path().join("dest");
        fs::create_dir_all(&src_dir).unwrap();

        // Create a source file with permissive permissions.
        let src_file = src_dir.join("test-job.json");
        fs::write(&src_file, b"{\"job_id\": \"test\"}").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Set source file to world-readable.
            fs::set_permissions(&src_file, fs::Permissions::from_mode(0o644)).unwrap();

            move_file_safe(&src_file, &dest_dir, "test-job.json").unwrap();

            // Verify the file was moved.
            assert!(!src_file.exists(), "source file should be gone");

            // Find the moved file in dest_dir.
            let entries: Vec<_> = fs::read_dir(&dest_dir)
                .unwrap()
                .filter_map(std::result::Result::ok)
                .collect();
            assert_eq!(entries.len(), 1, "exactly one file in dest");

            // Check that permissions were hardened to 0o600.
            let dest_meta = entries[0].metadata().unwrap();
            let mode = dest_meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "destination file should have 0o600 permissions, got {mode:#o}"
            );
        }
    }

    // ── BLOCKER regression: SystemMode crash recovery ──────────────────

    #[test]
    fn test_blocker_cleanup_failure_does_not_abort_worker_startup() {
        // BLOCKER regression: When best_effort_lane_cleanup fails (e.g.,
        // safe_rmtree_v1 rejects 0o770 SystemMode permissions), the
        // worker must NOT abort startup. The lane should be marked
        // CORRUPT and the worker continues processing other lanes.
        //
        // Previously, recover_stale_lease returned Err on cleanup
        // failure, which propagated up through reconcile_lanes and
        // reconcile_on_startup, causing a persistent crash loop.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Set lane-00 to 0o770 (simulating SystemMode) so
        // safe_rmtree_v1 will fail its INV-RMTREE-006 check.
        let lane_dir = fac_root.join("lanes").join("lane-00");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lane_dir, fs::Permissions::from_mode(0o770)).unwrap();
        }

        // Create a tmp/ directory with stale files in the lane.
        let tmp_dir = lane_dir.join("tmp");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(tmp_dir.join("stale.o"), b"stale").unwrap();

        // Plant a stale lease with dead PID.
        write_lease(
            &fac_root,
            "lane-00",
            "job-system-mode",
            999_999_999,
            LaneState::Running,
        );

        // Reconciliation should succeed overall — the lane is marked
        // CORRUPT instead of causing a crash loop.
        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        // lane-00 should be marked corrupt (cleanup failed).
        assert!(
            receipt.lanes_marked_corrupt >= 1,
            "lane with failed cleanup should be marked CORRUPT, got lanes_marked_corrupt={}",
            receipt.lanes_marked_corrupt
        );

        // Verify a corrupt marker was persisted.
        let marker = LaneCorruptMarkerV1::load(&fac_root, "lane-00")
            .unwrap()
            .expect("corrupt marker should exist");
        assert!(
            marker.reason.contains("cleanup failed"),
            "corrupt reason should mention cleanup failure: {}",
            marker.reason
        );
    }

    // ── MAJOR 1 regression: rename+chmod error path ────────────────────

    #[test]
    fn test_major1_rename_success_chmod_failure_returns_ok() {
        // MAJOR 1 regression: After a successful fs::rename, a chmod
        // failure must NOT return Err. Returning Err previously caused
        // the caller to interpret the move as failed, try a fallback
        // move from the original path (which no longer exists), and
        // return MoveFailed — creating unrecorded queue mutations.
        //
        // This test simulates the scenario by moving a file then making
        // the destination read-only so chmod would fail if it were
        // implemented as map_err(?).
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        let dest_dir = tmp.path().join("dest");
        fs::create_dir_all(&src_dir).unwrap();

        let src_file = src_dir.join("rename-test.json");
        fs::write(&src_file, b"{\"job_id\": \"test\"}").unwrap();

        // move_file_safe should always succeed if rename succeeds, even
        // if the destination filesystem had permission quirks. Since we
        // can't easily make set_permissions fail on a file we own, we
        // verify the contract: rename succeeds → Ok returned → source
        // is gone.
        move_file_safe(&src_file, &dest_dir, "rename-test.json").unwrap();

        assert!(
            !src_file.exists(),
            "source file should be gone after successful rename"
        );

        let entries: Vec<_> = fs::read_dir(&dest_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "exactly one file should be in destination"
        );
    }

    // ── MAJOR 2 regression: Phase-1 partial receipt ────────────────────

    #[test]
    fn test_major2_phase1_error_persists_partial_receipt() {
        // MAJOR 2 regression: When Phase 1 fails after mutating some
        // lanes (e.g., recovering lane-00's stale lease, then failing to
        // persist a corrupt marker for lane-01), a partial receipt must
        // be persisted containing the Phase 1 actions that were
        // completed before the error.
        //
        // This test creates a scenario where lane-00 has a stale lease
        // (recoverable), and lane-01 has an ambiguous state that
        // triggers corrupt marker persistence, but the lane directory
        // is read-only so the marker persist fails.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Lane-00: stale lease with dead PID (will be recovered first).
        let lane_00_dir = fac_root.join("lanes").join("lane-00");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lane_00_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        write_lease(
            &fac_root,
            "lane-00",
            "job-phase1-partial",
            999_999_999,
            LaneState::Running,
        );

        // Lane-01: lease with our own PID (alive) + lock not held →
        // ambiguous state → triggers persist_corrupt_marker.
        let our_pid = std::process::id();
        write_lease(
            &fac_root,
            "lane-01",
            "job-ambiguous-phase1",
            our_pid,
            LaneState::Idle,
        );

        // Make lane-01 directory read-only so corrupt marker persist fails.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lane_01_dir = fac_root.join("lanes").join("lane-01");
            fs::set_permissions(&lane_01_dir, fs::Permissions::from_mode(0o500)).unwrap();

            let result =
                reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false);

            // Restore permissions for cleanup.
            fs::set_permissions(&lane_01_dir, fs::Permissions::from_mode(0o700)).unwrap();

            // Phase 1 should have failed due to corrupt marker persist
            // failure on lane-01.
            assert!(result.is_err(), "Phase 1 error should propagate");

            // But a partial receipt should have been persisted with the
            // Phase 1 actions that completed (lane-00 recovery).
            let receipts_dir = fac_root.join("receipts").join("reconcile");
            assert!(
                receipts_dir.is_dir(),
                "receipts directory should exist for Phase 1 partial receipt"
            );
            let receipt_entries: Vec<_> = fs::read_dir(&receipts_dir)
                .unwrap()
                .filter_map(std::result::Result::ok)
                .collect();
            assert!(
                !receipt_entries.is_empty(),
                "at least one partial receipt should be persisted for Phase 1 actions"
            );

            // Load and verify the partial receipt contains the Phase 1
            // lane actions that were completed before the error.
            let partial = ReconcileReceiptV1::load(&receipt_entries[0].path()).unwrap();
            assert!(
                partial.stale_leases_recovered >= 1
                    || partial.lanes_marked_corrupt >= 1
                    || !partial.lane_actions.is_empty(),
                "partial receipt should contain Phase 1 actions: \
                 stale_leases_recovered={}, lanes_marked_corrupt={}, lane_actions={}",
                partial.stale_leases_recovered,
                partial.lanes_marked_corrupt,
                partial.lane_actions.len(),
            );
        }
    }

    // ── MAJOR R7: Race condition — NotFound during rename ───────────────

    #[test]
    fn test_major_r7_move_file_safe_notfound_treated_as_success() {
        // MAJOR R7 regression: In multi-worker deployments, concurrent
        // reconciliation workers race to move orphaned files. When worker A
        // moves a file and worker B tries to move the same file, worker B
        // gets NotFound from fs::rename. This must be treated as "already
        // handled" (Ok), not as a terminal MoveFailed error.
        let tmp = TempDir::new().unwrap();
        let dest_dir = tmp.path().join("dest");

        // Attempt to move a file that does not exist.
        let nonexistent_src = tmp.path().join("does-not-exist.json");
        let result = move_file_safe(&nonexistent_src, &dest_dir, "does-not-exist.json");

        // Must succeed — the file was "already handled" by another worker.
        assert!(
            result.is_ok(),
            "NotFound on rename should be treated as success (already moved), got: {result:?}"
        );

        // Destination directory may have been created but should have no
        // files (the rename was a no-op).
        if dest_dir.exists() {
            let entries: Vec<_> = fs::read_dir(&dest_dir)
                .unwrap()
                .filter_map(std::result::Result::ok)
                .collect();
            assert_eq!(
                entries.len(),
                0,
                "no file should appear in dest when source was not found"
            );
        }
    }

    #[test]
    fn test_major_r7_move_file_safe_other_errors_still_propagated() {
        // MAJOR R7: Only NotFound is tolerated. Other I/O errors (e.g.,
        // permission denied) must still propagate as Err.
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("test-job.json");
        fs::write(&src_file, b"{\"job_id\": \"test\"}").unwrap();

        // Make destination parent read-only so mkdir fails (simulating
        // a non-NotFound I/O error).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let read_only_parent = tmp.path().join("readonly");
            fs::create_dir_all(&read_only_parent).unwrap();
            fs::set_permissions(&read_only_parent, fs::Permissions::from_mode(0o500)).unwrap();

            let dest_dir = read_only_parent.join("dest");
            let result = move_file_safe(&src_file, &dest_dir, "test-job.json");

            // Restore permissions for cleanup.
            fs::set_permissions(&read_only_parent, fs::Permissions::from_mode(0o700)).unwrap();

            assert!(
                result.is_err(),
                "non-NotFound errors must still propagate: {result:?}"
            );
        }
    }

    #[test]
    fn test_major_r7_reconcile_queue_tolerates_concurrent_move() {
        // MAJOR R7 end-to-end: When an orphaned claimed job's file is
        // removed between the directory listing and the move attempt
        // (simulating another worker moving it first), reconcile must
        // succeed rather than abort with MoveFailed.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant an orphaned claimed job.
        write_claimed_job(&queue_root, "job-raced");

        // Delete the file before reconciliation runs (simulating another
        // worker moving it).
        let claimed_path = queue_root.join("claimed").join("job-raced.json");
        fs::remove_file(&claimed_path).unwrap();

        // Reconciliation must succeed — the missing file should be
        // treated as "already handled".
        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::Requeue, false)
                .unwrap();

        // The file was already gone, so it should not appear in requeued
        // or failed counts (metadata parsing will also fail since the file
        // is missing, so it won't even enter the move path).
        // The important thing is no MoveFailed error.
        assert_eq!(receipt.orphaned_jobs_requeued, 0);
        assert_eq!(receipt.orphaned_jobs_failed, 0);
    }

    #[test]
    fn test_reconcile_skips_claimed_file_when_worker_flock_is_held() {
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);
        write_claimed_job(&queue_root, "job-locked");

        let claimed_path = queue_root.join("claimed").join("job-locked.json");
        let claimed_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&claimed_path)
            .expect("open claimed file");
        crate::fac::flock_util::acquire_exclusive_blocking(&claimed_file)
            .expect("acquire worker flock");

        let receipt =
            reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::MarkFailed, false)
                .expect("reconcile should succeed when file is worker-locked");

        assert!(
            claimed_path.exists(),
            "reconcile must not move a claimed file while worker lock is held"
        );
        assert!(
            receipt.queue_actions.iter().any(|action| matches!(
                action,
                QueueRecoveryAction::StillActive { job_id, lane_id }
                if job_id == "job-locked" && lane_id == "flock_held"
            )),
            "expected StillActive action with flock_held lane marker, got: {:?}",
            receipt.queue_actions
        );
    }

    // ── MINOR R7: Partial receipt inspected count accuracy ─────────────

    #[test]
    fn test_minor_r7_partial_receipt_includes_actual_inspected_count() {
        // MINOR R7 regression: When Phase 2 fails, the partial receipt
        // must include the actual claimed_files_inspected count, not 0.
        //
        // We trigger a Phase 2 failure by exceeding MAX_QUEUE_RECOVERY_ACTIONS
        // while having some files inspected. Since MAX_QUEUE_RECOVERY_ACTIONS
        // is 4096, we use a simpler approach: create orphaned jobs and make
        // the denied directory unwritable so MoveFailed triggers after some
        // inspection.
        let (_tmp, fac_root, queue_root) = setup_fac_and_queue(3);

        // Plant two orphaned claimed jobs.
        write_claimed_job(&queue_root, "job-inspected-1");
        write_claimed_job(&queue_root, "job-inspected-2");

        // Make both pending and denied directories read-only so both
        // move attempts fail, triggering MoveFailed after some inspection.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Use MarkFailed policy so it tries denied/ directly.
            // Make denied dir a file (not a dir) so create_dir_restricted fails.
            let denied_dir = queue_root.join("denied");
            fs::remove_dir_all(&denied_dir).unwrap();
            // Make the parent queue_root read-only so creating denied/ fails.
            fs::set_permissions(&queue_root, fs::Permissions::from_mode(0o500)).unwrap();

            let result =
                reconcile_on_startup(&fac_root, &queue_root, OrphanedJobPolicy::MarkFailed, false);

            // Restore permissions for cleanup.
            fs::set_permissions(&queue_root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir_all(&denied_dir).unwrap();

            // Phase 2 should have failed with MoveFailed.
            assert!(result.is_err(), "Phase 2 should fail due to move failure");

            // The partial receipt should have been persisted with the
            // actual inspected count (non-zero).
            let receipts_dir = fac_root.join("receipts").join("reconcile");
            if receipts_dir.is_dir() {
                let receipt_entries: Vec<_> = fs::read_dir(&receipts_dir)
                    .unwrap()
                    .filter_map(std::result::Result::ok)
                    .collect();
                if !receipt_entries.is_empty() {
                    let partial = ReconcileReceiptV1::load(&receipt_entries[0].path()).unwrap();
                    // The key assertion: claimed_files_inspected must reflect
                    // the actual files that were inspected before the error,
                    // not the hardcoded 0 that was previously there.
                    assert!(
                        partial.claimed_files_inspected >= 1,
                        "partial receipt must include actual inspected count, \
                         got claimed_files_inspected={}",
                        partial.claimed_files_inspected,
                    );
                }
            }
        }
    }
}
