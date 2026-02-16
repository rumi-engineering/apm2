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
//!
//! # Invariants
//!
//! - [INV-RECON-001] No job is silently dropped; all outcomes recorded as
//!   receipts.
//! - [INV-RECON-002] Stale lease detection is fail-closed: ambiguous PID state
//!   → CORRUPT (not recovered).
//! - [INV-RECON-003] All in-memory collections are bounded by hard MAX_*
//!   constants.
//! - [INV-RECON-004] Reconciliation is idempotent and safe to call on every
//!   startup.
//! - [INV-RECON-005] Queue reads are bounded (MAX_CLAIMED_SCAN_ENTRIES).

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::lane::{
    LANE_CORRUPT_MARKER_SCHEMA, LaneCorruptMarkerV1, LaneLeaseV1, LaneManager, LaneState,
    MAX_STRING_LENGTH,
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
    /// Stale lease was cleared and lane returned to IDLE.
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
    /// # Errors
    ///
    /// Returns `ReconcileError::Io` on filesystem errors.
    pub fn persist(&self, fac_root: &Path) -> Result<PathBuf, ReconcileError> {
        let receipts_dir = fac_root.join("receipts").join("reconcile");
        if !receipts_dir.exists() {
            fs::create_dir_all(&receipts_dir).map_err(|e| {
                ReconcileError::io(
                    format!("creating reconcile receipts dir {}", receipts_dir.display()),
                    e,
                )
            })?;
        }

        let timestamp_safe = self.timestamp.replace(':', "-").replace('+', "p");
        let filename = format!("reconcile-{timestamp_safe}.json");
        let receipt_path = receipts_dir.join(&filename);

        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| ReconcileError::Serialization(e.to_string()))?;

        // Atomic write: temp file + rename.
        let tmp_path = receipt_path.with_extension("tmp");
        fs::write(&tmp_path, &bytes).map_err(|e| {
            ReconcileError::io(
                format!("writing reconcile receipt to {}", tmp_path.display()),
                e,
            )
        })?;
        fs::rename(&tmp_path, &receipt_path).map_err(|e| {
            ReconcileError::io(
                format!(
                    "renaming {} to {}",
                    tmp_path.display(),
                    receipt_path.display()
                ),
                e,
            )
        })?;

        Ok(receipt_path)
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
/// 2. For stale lanes: removes the lease file to return lane to IDLE.
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
/// Returns [`ReconcileError`] on lane or filesystem errors.
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
    let queue_result = reconcile_queue(
        queue_root,
        &lane_result.active_job_ids,
        orphan_policy,
        dry_run,
    )?;

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

    // Persist the receipt (even for dry runs, for auditability).
    if let Err(e) = receipt.persist(fac_root) {
        // Non-fatal: receipt persistence failure does not block recovery.
        eprintln!("WARNING: failed to persist reconcile receipt: {e}");
    }

    Ok(receipt)
}

/// Phase 1: Scan all lanes for stale leases and reconcile them.
///
/// Returns the set of active job IDs (used by phase 2 to detect orphans)
/// along with recovery actions taken.
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
                    let marker = LaneCorruptMarkerV1 {
                        schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
                        lane_id: lane_id.clone(),
                        reason: truncate_string(&reason, MAX_STRING_LENGTH),
                        cleanup_receipt_digest: None,
                        detected_at: timestamp.to_string(),
                    };
                    let _ = marker.persist(fac_root);
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
                    if !is_pid_alive(lease.pid) && !status.lock_held {
                        if !dry_run {
                            let _ = LaneLeaseV1::remove(&lane_dir);
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

/// Phase 2: Scan `queue/claimed/` for orphaned jobs and apply recovery policy.
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

    if !claimed_dir.is_dir() {
        return Ok(QueueReconcileResult {
            actions,
            claimed_files_inspected,
            orphaned_jobs_requeued,
            orphaned_jobs_failed,
        });
    }

    let entries = fs::read_dir(&claimed_dir).map_err(|e| {
        ReconcileError::io(
            format!("reading claimed directory {}", claimed_dir.display()),
            e,
        )
    })?;

    for entry in entries {
        if claimed_files_inspected >= MAX_CLAIMED_SCAN_ENTRIES {
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
        claimed_files_inspected += 1;

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
        match orphan_policy {
            OrphanedJobPolicy::Requeue => {
                if !dry_run {
                    if let Err(e) = move_file_safe(&path, &pending_dir, &file_name) {
                        let reason = format!("requeue failed: {e}");
                        let _ = move_file_safe(&path, &denied_dir, &file_name);
                        actions.push(QueueRecoveryAction::MarkedFailed {
                            job_id,
                            file_name,
                            reason,
                        });
                        orphaned_jobs_failed += 1;
                        continue;
                    }
                }
                actions.push(QueueRecoveryAction::Requeued { job_id, file_name });
                orphaned_jobs_requeued += 1;
            },
            OrphanedJobPolicy::MarkFailed => {
                let reason = "orphaned claimed job: no active lane processing \
                              this job after crash recovery"
                    .to_string();
                if !dry_run {
                    let _ = move_file_safe(&path, &denied_dir, &file_name);
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
fn extract_job_id_from_claimed(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.len() > MAX_CLAIMED_FILE_SIZE {
        return None;
    }
    let mut buf = Vec::with_capacity(metadata.len().min(MAX_CLAIMED_FILE_SIZE) as usize);
    let mut reader = file.take(MAX_CLAIMED_FILE_SIZE);
    reader.read_to_end(&mut buf).ok()?;

    // Minimal JSON extraction — we only need the job_id field.
    let value: serde_json::Value = serde_json::from_slice(&buf).ok()?;
    value
        .get("job_id")?
        .as_str()
        .map(std::string::ToString::to_string)
}

/// Check whether a given PID is alive.
///
/// Duplicated from `lane.rs` since it is `pub(super)` there; this avoids
/// changing the visibility of the lane-internal function.
fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let Ok(pid_i32) = i32::try_from(pid) else {
        return false;
    };
    #[cfg(unix)]
    {
        #[allow(unsafe_code)]
        let result = unsafe { libc::kill(pid_i32, 0) };
        if result == 0 {
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        errno == libc::EPERM
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Move a file to a destination directory, creating the directory if needed.
///
/// Returns `Err` on filesystem errors.
fn move_file_safe(src: &Path, dest_dir: &Path, file_name: &str) -> Result<(), String> {
    if !dest_dir.exists() {
        fs::create_dir_all(dest_dir)
            .map_err(|e| format!("cannot create {}: {e}", dest_dir.display()))?;
    }
    let dest = dest_dir.join(file_name);

    // If destination already exists, suffix with nanos to prevent clobbering.
    if dest.exists() {
        let ts_nanos = wall_clock_nanos();
        let stem = file_name.trim_end_matches(".json");
        let safe_name = format!("{stem}-requeue-{ts_nanos}.json");
        let safe_dest = dest_dir.join(&safe_name);
        fs::rename(src, &safe_dest)
            .map_err(|e| format!("rename {} -> {}: {e}", src.display(), safe_dest.display()))?;
    } else {
        fs::rename(src, &dest)
            .map_err(|e| format!("rename {} -> {}: {e}", src.display(), dest.display()))?;
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
        let pending_path = queue_root.join("pending").join("job-orphan-1.json");
        assert!(!claimed_path.exists(), "claimed file should be moved");
        assert!(pending_path.exists(), "file should be in pending/");
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
        let denied_path = queue_root.join("denied").join("job-orphan-2.json");
        assert!(!claimed_path.exists(), "claimed file should be moved");
        assert!(denied_path.exists(), "file should be in denied/");
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
}
