// AGENT-AUTHORED (TCK-00534)
//! Crash recovery and reconciliation for FAC queue and lane state.
//!
//! After an unclean shutdown (crash, SIGKILL, OOM-kill), the queue and lane
//! state can become inconsistent:
//!
//! - Lanes may have stale leases (PID dead, lock released, but lease file still
//!   present with RUNNING/LEASED/CLEANUP state).
//! - The `queue/claimed/` directory may contain job specs that are no longer
//!   being processed by any worker.
//!
//! This module implements deterministic recovery:
//!
//! 1. **Lane reconciliation**: Detect stale leases (PID dead + lock not held),
//!    transition through CLEANUP → remove lease (IDLE), emit recovery receipts.
//! 2. **Queue reconciliation**: Detect claimed jobs that are not backed by any
//!    active lane lease, and requeue them (move back to `pending/`).
//!
//! # Security Model
//!
//! - Stale lease detection uses PID liveness checks (fail-closed: ambiguous →
//!   CORRUPT).
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
//!   final receipt and for partial receipts after Phase-2 failures. If partial
//!   receipt persistence also fails, a combined error is returned so that
//!   apply-mode lane mutations never lack durable receipt evidence.
//! - [INV-RECON-002] Stale lease detection is fail-closed: ambiguous PID state
//!   → CORRUPT (not recovered). Ambiguous states are durably marked via
//!   `LaneCorruptMarkerV1`. Corrupt marker persistence failure is a hard error
//!   in apply mode — ambiguous states must not proceed without durable evidence.
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

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::lane::{
    LANE_CORRUPT_MARKER_SCHEMA, LaneCorruptMarkerV1, LaneLeaseV1, LaneManager, LaneState,
    MAX_STRING_LENGTH, atomic_write, create_dir_restricted, is_pid_alive,
};

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
    ///
    /// # Errors
    ///
    /// Returns `ReconcileError` on I/O, parse, or bounds violation.
    #[allow(dead_code)]
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
    stale_leases_recovered: usize,
    lanes_marked_corrupt: usize,
}

/// Intermediate result from phase 2 queue reconciliation.
struct QueueReconcileResult {
    actions: Vec<QueueRecoveryAction>,
    claimed_files_inspected: usize,
    orphaned_jobs_requeued: usize,
    orphaned_jobs_failed: usize,
}

/// Run crash recovery reconciliation on worker startup.
///
/// This function:
/// 1. Scans all lanes for stale leases (PID dead + lock not held).
/// 2. For stale lanes: transitions lease through CLEANUP → removes lease
///    (IDLE), emitting recovery receipts (INV-RECON-006).
/// 3. Scans `queue/claimed/` for orphaned jobs not backed by any active lane.
/// 4. Moves orphaned jobs back to `pending/` (requeue) or `denied/` (fail),
///    based on the configured policy.
/// 5. Emits a structured reconciliation receipt.
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
    let lane_result = reconcile_lanes(&manager, &lane_ids, fac_root, &timestamp, dry_run)?;

    // Phase 2: Queue reconciliation — scan claimed/ for orphaned jobs.
    // INV-RECON-001: If Phase 2 fails after Phase 1 mutated state (e.g.,
    // clearing stale leases), we must persist a partial receipt containing
    // Phase 1 actions before propagating the Phase 2 error.
    let queue_result = match reconcile_queue(
        queue_root,
        &lane_result.active_job_ids,
        orphan_policy,
        dry_run,
    ) {
        Ok(result) => result,
        Err(phase2_err) => {
            // Phase 1 may have mutated state (stale lease recovery).
            // Persist a partial receipt with Phase 1 results so those
            // actions are never silently lost (INV-RECON-001).
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
                        std::io::Error::other(
                            "partial receipt persistence is mandatory in apply mode",
                        ),
                    ));
                }
            }
            return Err(phase2_err);
        },
    };

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
/// INV-RECON-002: Ambiguous PID states (EPERM, alive-but-unlocked) are
/// durably marked CORRUPT via `LaneCorruptMarkerV1`.
///
/// INV-RECON-006: Stale lease recovery transitions through CLEANUP → IDLE.
///
/// THEME 7: Corrupt lanes with live PIDs add their `job_id` to `active_job_ids`
/// to prevent orphan requeue of still-executing jobs.
fn reconcile_lanes(
    manager: &LaneManager,
    lane_ids: &[String],
    fac_root: &Path,
    timestamp: &str,
    dry_run: bool,
) -> Result<LaneReconcileResult, ReconcileError> {
    let mut actions: Vec<LaneRecoveryAction> = Vec::new();
    let mut stale_leases_recovered: usize = 0;
    let mut lanes_marked_corrupt: usize = 0;
    let mut active_job_ids: HashSet<String> = HashSet::new();

    for lane_id in lane_ids {
        if actions.len() >= MAX_LANE_RECOVERY_ACTIONS {
            return Err(ReconcileError::TooManyEntries {
                kind: "lane_recovery_actions",
                count: actions.len(),
                limit: MAX_LANE_RECOVERY_ACTIONS,
            });
        }

        let status = match manager.lane_status(lane_id) {
            Ok(s) => s,
            Err(e) => {
                // Cannot determine lane state — mark corrupt (fail-closed,
                // INV-RECON-002).
                let reason = format!("failed to read lane status: {e}");
                if !dry_run {
                    persist_corrupt_marker(fac_root, lane_id, &reason, timestamp)?;
                }
                actions.push(LaneRecoveryAction::MarkedCorrupt {
                    lane_id: lane_id.clone(),
                    reason: truncate_string(&reason, MAX_STRING_LENGTH),
                });
                lanes_marked_corrupt += 1;
                continue;
            },
        };

        match status.state {
            LaneState::Idle => {
                let lane_dir = manager.lane_dir(lane_id);
                let lease = LaneLeaseV1::load(&lane_dir).ok().flatten();
                if let Some(lease) = lease {
                    let pid_alive = is_pid_alive(lease.pid);
                    if !pid_alive && !status.lock_held {
                        // Dead PID + free lock → stale lease.
                        // INV-RECON-006: Transition through CLEANUP → IDLE.
                        if !dry_run {
                            recover_stale_lease(&lane_dir, &lease)?;
                        }
                        actions.push(LaneRecoveryAction::StaleLeaseCleared {
                            lane_id: lane_id.clone(),
                            job_id: lease.job_id.clone(),
                            pid: lease.pid,
                            previous_state: lease.state.to_string(),
                        });
                        stale_leases_recovered += 1;
                        continue;
                    }
                    // INV-RECON-002: PID alive (or EPERM) but lock free with
                    // lease present is an ambiguous/inconsistent state. Mark
                    // CORRUPT durably and treat as active to prevent orphan
                    // requeue (THEME 5, THEME 7).
                    let reason = format!(
                        "ambiguous lane state: lease present (pid={}, state={}) \
                         but lock is free and pid is alive/EPERM",
                        lease.pid, lease.state,
                    );
                    if !dry_run {
                        persist_corrupt_marker(fac_root, lane_id, &reason, timestamp)?;
                    }
                    // THEME 7: treat this as active to prevent orphan requeue.
                    active_job_ids.insert(lease.job_id.clone());
                    actions.push(LaneRecoveryAction::MarkedCorrupt {
                        lane_id: lane_id.clone(),
                        reason: truncate_string(&reason, MAX_STRING_LENGTH),
                    });
                    lanes_marked_corrupt += 1;
                    continue;
                }
                actions.push(LaneRecoveryAction::AlreadyConsistent {
                    lane_id: lane_id.clone(),
                    state: "IDLE".to_string(),
                });
            },
            LaneState::Running | LaneState::Leased | LaneState::Cleanup => {
                if let Some(ref job_id) = status.job_id {
                    active_job_ids.insert(job_id.clone());
                }
                actions.push(LaneRecoveryAction::AlreadyConsistent {
                    lane_id: lane_id.clone(),
                    state: status.state.to_string(),
                });
            },
            LaneState::Corrupt => {
                // THEME 7: Corrupt lanes with a live PID may still be
                // executing. Add their job_id to active_job_ids to prevent
                // orphan requeue of still-running jobs.
                if let Some(ref job_id) = status.job_id {
                    if status.pid_alive == Some(true) {
                        active_job_ids.insert(job_id.clone());
                    }
                }
                actions.push(LaneRecoveryAction::AlreadyConsistent {
                    lane_id: lane_id.clone(),
                    state: "CORRUPT".to_string(),
                });
                lanes_marked_corrupt += 1;
            },
        }
    }

    Ok(LaneReconcileResult {
        actions,
        active_job_ids,
        stale_leases_recovered,
        lanes_marked_corrupt,
    })
}

/// INV-RECON-006: Transition stale lease through CLEANUP → IDLE before removal.
///
/// This implements the lane cleanup lifecycle for crash recovery:
/// 1. Transition lease state to CLEANUP and persist durably.
/// 2. Remove the lease file (returning lane to IDLE).
///
/// Fail-closed: If the CLEANUP transition persist fails, return an error
/// instead of proceeding with lease removal. The caller must not remove the
/// lease without durable CLEANUP evidence.
fn recover_stale_lease(lane_dir: &Path, lease: &LaneLeaseV1) -> Result<(), ReconcileError> {
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

    // Step 2: Remove the lease file (IDLE). Safe because CLEANUP is now durable.
    LaneLeaseV1::remove(lane_dir).map_err(|e| {
        ReconcileError::io(
            format!("failed to remove stale lease at {}", lane_dir.display()),
            std::io::Error::other(e.to_string()),
        )
    })
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
    queue_root: &Path,
    active_job_ids: &HashSet<String>,
    orphan_policy: OrphanedJobPolicy,
    dry_run: bool,
) -> Result<QueueReconcileResult, ReconcileError> {
    let claimed_dir = queue_root.join("claimed");
    let pending_dir = queue_root.join("pending");
    let denied_dir = queue_root.join("denied");

    let mut actions: Vec<QueueRecoveryAction> = Vec::new();
    let mut orphaned_jobs_requeued: usize = 0;
    let mut orphaned_jobs_failed: usize = 0;
    let mut claimed_files_inspected: usize = 0;

    // INV-RECON-008: Verify claimed_dir is a real directory, not a symlink.
    // Using symlink_metadata to detect symlinks without following them.
    // If claimed_dir is a symlink, reconciliation must fail closed to prevent
    // iterating and moving files from outside the queue tree.
    match fs::symlink_metadata(&claimed_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(ReconcileError::io(
                    format!(
                        "queue/claimed directory is a symlink: {}",
                        claimed_dir.display()
                    ),
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "claimed directory symlink traversal rejected",
                    ),
                ));
            }
            if !meta.is_dir() {
                // Not a directory and not a symlink — nothing to scan.
                return Ok(QueueReconcileResult {
                    actions,
                    claimed_files_inspected,
                    orphaned_jobs_requeued,
                    orphaned_jobs_failed,
                });
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Directory does not exist — nothing to reconcile.
            return Ok(QueueReconcileResult {
                actions,
                claimed_files_inspected,
                orphaned_jobs_requeued,
                orphaned_jobs_failed,
            });
        },
        Err(e) => {
            return Err(ReconcileError::io(
                format!("stat claimed directory {}", claimed_dir.display()),
                e,
            ));
        },
    }

    let entries = fs::read_dir(&claimed_dir).map_err(|e| {
        ReconcileError::io(
            format!("reading claimed directory {}", claimed_dir.display()),
            e,
        )
    })?;

    for entry in entries {
        // INV-RECON-005: Count EVERY directory entry toward the scan cap
        // BEFORE file-type filtering. This prevents an attacker from flooding
        // queue/claimed with symlinks, directories, or special files to bypass
        // the MAX_CLAIMED_SCAN_ENTRIES budget and cause unbounded traversal.
        claimed_files_inspected += 1;
        if claimed_files_inspected > MAX_CLAIMED_SCAN_ENTRIES {
            return Err(ReconcileError::TooManyEntries {
                kind: "claimed_scan",
                count: claimed_files_inspected,
                limit: MAX_CLAIMED_SCAN_ENTRIES,
            });
        }
        if actions.len() >= MAX_QUEUE_RECOVERY_ACTIONS {
            return Err(ReconcileError::TooManyEntries {
                kind: "queue_recovery_actions",
                count: actions.len(),
                limit: MAX_QUEUE_RECOVERY_ACTIONS,
            });
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

        // Try to extract `job_id` from the file contents.
        // If unparseable, fall back to filename stem as ID.
        let job_id = extract_job_id_from_claimed(&path)
            .unwrap_or_else(|| file_name.trim_end_matches(".json").to_string());

        // Check if this job is backed by an active lane.
        if active_job_ids.contains(&job_id) {
            actions.push(QueueRecoveryAction::StillActive {
                job_id,
                lane_id: "unknown".to_string(),
            });
            continue;
        }

        // Orphaned claimed job — apply policy.
        // INV-RECON-007: Only count success after confirmed rename.
        match orphan_policy {
            OrphanedJobPolicy::Requeue => {
                if dry_run {
                    actions.push(QueueRecoveryAction::Requeued { job_id, file_name });
                    orphaned_jobs_requeued += 1;
                } else {
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
                                    // (INV-RECON-007).
                                    return Err(ReconcileError::MoveFailed {
                                        context: format!(
                                            "claimed job {job_id}: requeue failed ({requeue_err}), \
                                             fallback to denied also failed ({deny_err})"
                                        ),
                                    });
                                },
                            }
                        },
                    }
                }
            },
            OrphanedJobPolicy::MarkFailed => {
                let reason = "orphaned claimed job: no active lane processing \
                              this job after crash recovery"
                    .to_string();
                if !dry_run {
                    // INV-RECON-007: propagate move failure.
                    move_file_safe(&path, &denied_dir, &file_name).map_err(|e| {
                        ReconcileError::MoveFailed {
                            context: format!("claimed job {job_id}: move to denied failed: {e}"),
                        }
                    })?;
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

    Ok(QueueReconcileResult {
        actions,
        claimed_files_inspected,
        orphaned_jobs_requeued,
        orphaned_jobs_failed,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract a `job_id` from a claimed job spec file.
///
/// Uses bounded I/O to read at most `MAX_CLAIMED_FILE_SIZE` bytes, then
/// extracts the `job_id` field from the JSON.
///
/// Security: Opens file with `O_NOFOLLOW` to reject symlinks (CTR-1503).
/// Validates regular file type before reading. Uses bounded read (CTR-1603).
fn extract_job_id_from_claimed(path: &Path) -> Option<String> {
    // CTR-1503: Reject symlinks via symlink_metadata check.
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }

    // Open with O_NOFOLLOW to prevent symlink traversal.
    let file = open_file_no_follow(path).ok()?;
    let file_metadata = file.metadata().ok()?;
    if file_metadata.len() > MAX_CLAIMED_FILE_SIZE {
        return None;
    }
    let mut buf = Vec::with_capacity(file_metadata.len().min(MAX_CLAIMED_FILE_SIZE) as usize);
    let mut reader = file.take(MAX_CLAIMED_FILE_SIZE);
    reader.read_to_end(&mut buf).ok()?;

    // Minimal JSON extraction — we only need the job_id field.
    let value: serde_json::Value = serde_json::from_slice(&buf).ok()?;
    value
        .get("job_id")?
        .as_str()
        .map(std::string::ToString::to_string)
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

    fs::rename(src, &dest)
        .map_err(|e| format!("rename {} -> {}: {e}", src.display(), dest.display()))
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
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find the last valid UTF-8 boundary at or before max_len.
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::fs;

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
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 5), "hello...");
        assert_eq!(truncate_string("", 5), "");
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
}
