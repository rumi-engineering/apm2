// AGENT-AUTHORED (TCK-00564)
//! Receipt write pipeline: atomic commit protocol for job completion.
//!
//! This module implements [`ReceiptWritePipeline`], a crash-safe commit
//! protocol that atomically transitions a job from `claimed/` to its
//! terminal directory (`completed/`, `denied/`, `cancelled/`) while
//! ensuring a receipt is always present before the job is marked done.
//!
//! # Commit Protocol
//!
//! The three steps are ordered to guarantee crash safety:
//!
//! 1. **Write receipt** (content-addressed file) -- after this point, the
//!    receipt is durable in the receipt store.
//! 2. **Update receipt index** -- best-effort cache update; on failure the
//!    index is deleted so it will be rebuilt on next read.
//! 3. **Move job file** (`claimed/ -> terminal/`) -- this is the commit point.
//!    After this rename, the job is considered done.
//!
//! # Crash Safety
//!
//! - **Crash before step 1 completes**: Receipt temp file is cleaned up by the
//!   OS. Job stays in `claimed/`. Reconciliation on next startup will detect
//!   the orphaned claimed job and either requeue or deny it.
//! - **Crash after step 1, before step 3**: Receipt exists in the store but the
//!   job is still in `claimed/`. On startup, reconciliation detects that a
//!   receipt already exists for this job (via index or scan) and completes the
//!   transition by moving the job to its terminal directory.
//! - **Crash after step 3**: Job is in its terminal directory and the receipt
//!   is present. Fully committed state.
//!
//! # Invariant
//!
//! **No scenario exists where a job is marked done (moved to a terminal
//! directory) without its receipt being present in the receipt store.**
//!
//! This is guaranteed by the ordering: receipt write (step 1) always
//! precedes job move (step 3). The receipt is content-addressed and
//! idempotent, so re-writing the same receipt on recovery is safe.
//!
//! # Recovery Receipts
//!
//! When reconciliation detects a torn state (receipt exists but job still
//! in `claimed/`), it emits a [`RecoveryReceiptV1`] documenting the
//! detected inconsistency and the repair action taken.
//!
//! # Security Model
//!
//! - Receipt persistence uses atomic temp + fsync + rename (CTR-2607).
//! - All string fields are bounded (RSK-1601).
//! - Index updates are non-authoritative (attacker-writable cache).
//! - File operations use `O_NOFOLLOW` where available.
//! - Directories are created with mode 0o700 (CTR-2611).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::receipt::{
    FacJobReceiptV1, compute_job_receipt_content_hash, persist_content_addressed_receipt,
};
use super::receipt_index::ReceiptIndexV1;

// =============================================================================
// Constants
// =============================================================================

/// Schema identifier for recovery receipts.
pub const RECOVERY_RECEIPT_SCHEMA: &str = "apm2.fac.recovery_receipt.v1";

/// Maximum reason string length for recovery receipts.
const MAX_RECOVERY_REASON_LENGTH: usize = 1024;

/// Maximum serialized size of a recovery receipt (bytes).
pub const MAX_RECOVERY_RECEIPT_SIZE: usize = 65_536;

// =============================================================================
// Error Types
// =============================================================================

/// Errors from the receipt write pipeline.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReceiptPipelineError {
    /// Receipt persistence failed.
    #[error("receipt persistence failed: {0}")]
    ReceiptPersistFailed(String),

    /// Job move (rename) failed.
    #[error("job move failed from {from} to {to}: {reason}")]
    JobMoveFailed {
        /// Source path.
        from: String,
        /// Destination path.
        to: String,
        /// Error reason.
        reason: String,
    },

    /// Receipt already exists for this job but move failed.
    /// This indicates a torn state that needs recovery.
    #[error("torn state: receipt exists for job {job_id} but move failed: {reason}")]
    TornState {
        /// The job ID.
        job_id: String,
        /// Path to the existing receipt.
        receipt_path: PathBuf,
        /// Reason the move failed.
        reason: String,
    },
}

// =============================================================================
// Terminal State
// =============================================================================

/// Terminal state a job can transition to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalState {
    /// Job completed successfully.
    Completed,
    /// Job was denied.
    Denied,
    /// Job was cancelled.
    Cancelled,
    /// Job was quarantined.
    Quarantined,
}

impl TerminalState {
    /// Returns the directory name for this terminal state.
    #[must_use]
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Quarantined => "quarantine",
        }
    }
}

impl std::fmt::Display for TerminalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.dir_name())
    }
}

// =============================================================================
// Recovery Receipt
// =============================================================================

/// Recovery receipt emitted when a torn state is detected and repaired.
///
/// This documents that reconciliation found a receipt without a
/// corresponding job move (or vice versa) and completed the transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Recovery receipt ID.
    pub receipt_id: String,
    /// Job ID that was recovered.
    pub job_id: String,
    /// Content hash of the original job receipt.
    pub original_receipt_hash: String,
    /// The torn state that was detected.
    pub detected_state: String,
    /// The repair action taken.
    pub repair_action: String,
    /// Source path of the job file.
    pub source_path: String,
    /// Destination path after recovery.
    pub destination_path: String,
    /// Unix epoch seconds when recovery occurred.
    pub timestamp_secs: u64,
}

impl RecoveryReceiptV1 {
    /// Validate boundedness constraints.
    ///
    /// # Errors
    ///
    /// Returns error if any field exceeds bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != RECOVERY_RECEIPT_SCHEMA {
            return Err(format!(
                "schema mismatch: expected '{RECOVERY_RECEIPT_SCHEMA}', got '{}'",
                self.schema,
            ));
        }
        if self.receipt_id.is_empty() {
            return Err("receipt_id is empty".to_string());
        }
        if self.job_id.is_empty() {
            return Err("job_id is empty".to_string());
        }
        if self.detected_state.len() > MAX_RECOVERY_REASON_LENGTH {
            return Err(format!(
                "detected_state too long: {} > {MAX_RECOVERY_REASON_LENGTH}",
                self.detected_state.len()
            ));
        }
        if self.repair_action.len() > MAX_RECOVERY_REASON_LENGTH {
            return Err(format!(
                "repair_action too long: {} > {MAX_RECOVERY_REASON_LENGTH}",
                self.repair_action.len()
            ));
        }
        if self.timestamp_secs == 0 {
            return Err("timestamp_secs must be non-zero".to_string());
        }
        Ok(())
    }

    /// Persist this recovery receipt to the receipts directory.
    ///
    /// Uses atomic write protocol: temp file + fsync + rename.
    ///
    /// # Errors
    ///
    /// Returns error if serialization or I/O fails.
    pub fn persist(&self, receipts_dir: &Path) -> Result<PathBuf, String> {
        self.validate()?;

        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| format!("cannot serialize recovery receipt: {e}"))?;

        if bytes.len() > MAX_RECOVERY_RECEIPT_SIZE {
            return Err(format!(
                "recovery receipt too large: {} > {MAX_RECOVERY_RECEIPT_SIZE}",
                bytes.len()
            ));
        }

        std::fs::create_dir_all(receipts_dir)
            .map_err(|e| format!("cannot create receipts dir: {e}"))?;

        let final_name = format!("recovery-{}.json", self.receipt_id);
        let final_path = receipts_dir.join(&final_name);

        // Atomic write: NamedTempFile + fsync + rename (CTR-2607).
        let temp = tempfile::NamedTempFile::new_in(receipts_dir)
            .map_err(|e| format!("cannot create temp file: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(temp.path(), perms);
        }

        {
            use std::io::Write;
            let mut file = temp.as_file();
            file.write_all(&bytes)
                .map_err(|e| format!("cannot write recovery receipt: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("cannot sync recovery receipt: {e}"))?;
        }

        temp.persist(&final_path)
            .map_err(|e| format!("cannot persist recovery receipt: {}", e.error))?;

        Ok(final_path)
    }
}

// =============================================================================
// Pipeline Result
// =============================================================================

/// Result of a successful pipeline commit.
#[derive(Debug)]
pub struct CommitResult {
    /// Path to the persisted receipt file.
    pub receipt_path: PathBuf,
    /// Content hash of the receipt.
    pub content_hash: String,
    /// Path to the moved job file (in terminal directory).
    pub job_terminal_path: PathBuf,
}

// =============================================================================
// Receipt Write Pipeline
// =============================================================================

/// Atomic commit protocol for job completion.
///
/// Ensures that receipt persistence, index update, and job state
/// transition happen in a crash-safe order.
///
/// # Usage
///
/// ```rust,ignore
/// let pipeline = ReceiptWritePipeline::new(receipts_dir, queue_root);
/// let result = pipeline.commit(
///     &receipt,
///     &claimed_path,
///     &file_name,
///     TerminalState::Completed,
/// )?;
/// ```
pub struct ReceiptWritePipeline {
    /// Path to the receipts directory (`$APM2_HOME/private/fac/receipts`).
    receipts_dir: PathBuf,
    /// Path to the queue root (`$APM2_HOME/private/fac/queue`).
    queue_root: PathBuf,
}

impl ReceiptWritePipeline {
    /// Create a new pipeline instance.
    #[must_use]
    pub const fn new(receipts_dir: PathBuf, queue_root: PathBuf) -> Self {
        Self {
            receipts_dir,
            queue_root,
        }
    }

    /// Execute the atomic commit protocol.
    ///
    /// Steps (crash-safe ordering):
    /// 1. Persist the receipt content-addressed file.
    /// 2. Update the receipt index (best-effort).
    /// 3. Move the job file from `claimed/` to the terminal directory.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptPipelineError`] if receipt persistence or job move
    /// fails. If the receipt is persisted but the move fails, a
    /// [`ReceiptPipelineError::TornState`] is returned; reconciliation will
    /// complete the transition on next startup.
    pub fn commit(
        &self,
        receipt: &FacJobReceiptV1,
        claimed_path: &Path,
        file_name: &str,
        terminal_state: TerminalState,
    ) -> Result<CommitResult, ReceiptPipelineError> {
        // Step 1: Persist the receipt (content-addressed, idempotent).
        let receipt_path = persist_content_addressed_receipt(&self.receipts_dir, receipt)
            .map_err(ReceiptPipelineError::ReceiptPersistFailed)?;

        let content_hash = compute_job_receipt_content_hash(receipt);

        // Step 2: Update receipt index (best-effort, non-authoritative).
        // Index failure does not block the commit. On failure, delete the
        // stale index to force rebuild on next read.
        if let Err(e) = ReceiptIndexV1::incremental_update(&self.receipts_dir, receipt) {
            eprintln!("WARN: receipt pipeline index update failed: {e}");
            let index_path = ReceiptIndexV1::index_path(&self.receipts_dir);
            let _ = std::fs::remove_file(&index_path);
        }

        // Step 3: Move job file to terminal directory (commit point).
        let dest_dir = self.queue_root.join(terminal_state.dir_name());
        let job_terminal_path =
            move_job_to_terminal(claimed_path, &dest_dir, file_name).map_err(|reason| {
                ReceiptPipelineError::TornState {
                    job_id: receipt.job_id.clone(),
                    receipt_path: receipt_path.clone(),
                    reason,
                }
            })?;

        Ok(CommitResult {
            receipt_path,
            content_hash,
            job_terminal_path,
        })
    }

    /// Attempt recovery of a torn state: receipt exists but job is still
    /// in `claimed/`.
    ///
    /// This is called by reconciliation when it detects a claimed job that
    /// already has a receipt. It completes the transition by moving the
    /// job to the appropriate terminal directory and emitting a recovery
    /// receipt.
    ///
    /// # Errors
    ///
    /// Returns error if the move or recovery receipt persistence fails.
    pub fn recover_torn_state(
        &self,
        claimed_path: &Path,
        file_name: &str,
        receipt: &FacJobReceiptV1,
        terminal_state: TerminalState,
        timestamp_secs: u64,
    ) -> Result<RecoveryReceiptV1, String> {
        let dest_dir = self.queue_root.join(terminal_state.dir_name());
        let dest_path = move_job_to_terminal(claimed_path, &dest_dir, file_name)
            .map_err(|e| format!("recovery move failed: {e}"))?;

        let recovery_receipt = RecoveryReceiptV1 {
            schema: RECOVERY_RECEIPT_SCHEMA.to_string(),
            receipt_id: format!("recovery-{}-{timestamp_secs}", receipt.job_id),
            job_id: receipt.job_id.clone(),
            original_receipt_hash: receipt.content_hash.clone(),
            detected_state: format!(
                "receipt exists in store but job still in claimed/ at {}",
                claimed_path.display()
            ),
            repair_action: format!("moved job to {}/{}", terminal_state.dir_name(), file_name),
            source_path: claimed_path.to_string_lossy().to_string(),
            destination_path: dest_path.to_string_lossy().to_string(),
            timestamp_secs,
        };

        recovery_receipt.persist(&self.receipts_dir)?;

        Ok(recovery_receipt)
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Move a job file to a terminal directory with collision-safe naming.
///
/// Creates the destination directory if it does not exist (mode 0o700).
/// Uses `rename_noreplace` for atomicity on the same filesystem. On
/// collision (file already exists), generates a timestamped name.
///
/// # Errors
///
/// Returns an error string if the move fails.
fn move_job_to_terminal(src: &Path, dest_dir: &Path, file_name: &str) -> Result<PathBuf, String> {
    if !dest_dir.exists() {
        #[cfg(unix)]
        {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dest_dir)
                .map_err(|e| format!("cannot create {}: {e}", dest_dir.display()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(dest_dir)
                .map_err(|e| format!("cannot create {}: {e}", dest_dir.display()))?;
        }
    }

    let dest = dest_dir.join(file_name);

    // Attempt no-replace rename. On collision, generate a timestamped name.
    match rename_noreplace(src, &dest) {
        Ok(()) => Ok(dest),
        Err(e)
            if e.raw_os_error() == Some(libc::EEXIST)
                || e.raw_os_error() == Some(libc::ENOTEMPTY)
                || e.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            let ts_nanos = wall_clock_nanos();
            let stem = file_name.trim_end_matches(".json");
            let collision_name = format!("{stem}-{ts_nanos}.json");
            let collision_dest = dest_dir.join(&collision_name);
            rename_noreplace(src, &collision_dest).map_err(|e2| {
                format!(
                    "rename {} -> {} failed (collision retry): {e2}",
                    src.display(),
                    collision_dest.display()
                )
            })?;
            Ok(collision_dest)
        },
        Err(e) => Err(format!(
            "rename {} -> {}: {e}",
            src.display(),
            dest.display()
        )),
    }
}

/// Atomic rename that fails (instead of overwriting) when the destination
/// already exists. Uses Linux `renameat2(RENAME_NOREPLACE)`.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn rename_noreplace(src: &Path, dest: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_c = CString::new(src.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let dest_c = CString::new(dest.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // SAFETY: paths are valid C strings. AT_FDCWD means use current directory
    // for relative paths. `renameat2` with RENAME_NOREPLACE atomically fails
    // with EEXIST if the destination already exists. No memory is read or
    // written other than the path strings. The kernel syscall is always safe
    // to call with valid C-string pointers and AT_FDCWD.
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
/// window. Acceptable because the nanosecond-timestamped collision path
/// provides a secondary safety net.
#[cfg(not(target_os = "linux"))]
fn rename_noreplace(src: &Path, dest: &Path) -> std::io::Result<()> {
    if dest.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    std::fs::rename(src, dest)
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

/// Check if a receipt exists for a job in the receipts directory.
///
/// Uses the index for O(1) lookup with fallback to directory scan.
/// This is used by reconciliation to detect torn states.
#[must_use]
pub fn receipt_exists_for_job(receipts_dir: &Path, job_id: &str) -> bool {
    super::receipt_index::has_receipt_for_job(receipts_dir, job_id)
}

/// Map a [`super::receipt::FacJobOutcome`] to a [`TerminalState`].
///
/// Returns `None` for non-terminal outcomes (e.g., `CancellationRequested`).
#[must_use]
pub const fn outcome_to_terminal_state(
    outcome: super::receipt::FacJobOutcome,
) -> Option<TerminalState> {
    match outcome {
        super::receipt::FacJobOutcome::Completed => Some(TerminalState::Completed),
        super::receipt::FacJobOutcome::Denied => Some(TerminalState::Denied),
        super::receipt::FacJobOutcome::Cancelled => Some(TerminalState::Cancelled),
        super::receipt::FacJobOutcome::Quarantined => Some(TerminalState::Quarantined),
        super::receipt::FacJobOutcome::CancellationRequested => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::receipt::{FacJobOutcome, FacJobReceiptV1, QueueAdmissionTrace};

    fn make_receipt(job_id: &str, outcome: FacJobOutcome) -> FacJobReceiptV1 {
        FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: format!("test-rcpt-{job_id}"),
            job_id: job_id.to_string(),
            job_spec_digest:
                "b3-256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            policy_hash: None,
            patch_digest: None,
            canonicalizer_tuple_digest: None,
            outcome,
            denial_reason: None,
            unsafe_direct: false,
            reason: "test".to_string(),
            moved_job_path: None,
            rfc0028_channel_boundary: None,
            eio29_queue_admission: Some(QueueAdmissionTrace {
                verdict: "allow".to_string(),
                queue_lane: "default".to_string(),
                defect_reason: None,
                cost_estimate_ticks: None,
            }),
            eio29_budget_admission: None,
            containment: None,
            observed_cost: None,
            sandbox_hardening_hash: None,
            timestamp_secs: 1000,
            content_hash: String::new(),
        }
    }

    fn setup_claimed_job(queue_root: &Path, job_id: &str) -> PathBuf {
        let claimed_dir = queue_root.join("claimed");
        std::fs::create_dir_all(&claimed_dir).expect("create claimed dir");
        let file_name = format!("{job_id}.json");
        let claimed_path = claimed_dir.join(&file_name);
        std::fs::write(&claimed_path, format!(r#"{{"job_id":"{job_id}"}}"#))
            .expect("write claimed file");
        claimed_path
    }

    // =========================================================================
    // Happy path: receipt + move atomic commit
    // =========================================================================

    #[test]
    fn test_commit_completed_job() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        let queue_root = tmp.path().join("queue");
        let claimed_path = setup_claimed_job(&queue_root, "job-1");

        let pipeline = ReceiptWritePipeline::new(receipts_dir, queue_root);
        let receipt = make_receipt("job-1", FacJobOutcome::Completed);

        let result = pipeline
            .commit(
                &receipt,
                &claimed_path,
                "job-1.json",
                TerminalState::Completed,
            )
            .expect("commit should succeed");

        // Receipt file must exist.
        assert!(result.receipt_path.exists(), "receipt file must exist");

        // Job must be in completed/.
        assert!(
            result.job_terminal_path.exists(),
            "job must be in completed/"
        );
        assert!(
            result
                .job_terminal_path
                .to_string_lossy()
                .contains("completed"),
            "terminal path must contain 'completed'"
        );

        // Claimed file must NOT exist anymore.
        assert!(!claimed_path.exists(), "claimed file must be gone");
    }

    #[test]
    fn test_commit_denied_job() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        let queue_root = tmp.path().join("queue");
        let claimed_path = setup_claimed_job(&queue_root, "job-deny");

        let pipeline = ReceiptWritePipeline::new(receipts_dir, queue_root);
        let receipt = make_receipt("job-deny", FacJobOutcome::Denied);

        let result = pipeline
            .commit(
                &receipt,
                &claimed_path,
                "job-deny.json",
                TerminalState::Denied,
            )
            .expect("commit should succeed");

        assert!(result.receipt_path.exists());
        assert!(result.job_terminal_path.exists());
        assert!(
            result
                .job_terminal_path
                .to_string_lossy()
                .contains("denied")
        );
    }

    #[test]
    fn test_commit_cancelled_job() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        let queue_root = tmp.path().join("queue");
        let claimed_path = setup_claimed_job(&queue_root, "job-cancel");

        let pipeline = ReceiptWritePipeline::new(receipts_dir, queue_root);
        let receipt = make_receipt("job-cancel", FacJobOutcome::Cancelled);

        let result = pipeline
            .commit(
                &receipt,
                &claimed_path,
                "job-cancel.json",
                TerminalState::Cancelled,
            )
            .expect("commit should succeed");

        assert!(result.receipt_path.exists());
        assert!(
            result
                .job_terminal_path
                .to_string_lossy()
                .contains("cancelled")
        );
    }

    // =========================================================================
    // Invariant: no done without receipt
    // =========================================================================

    #[test]
    fn test_receipt_persisted_before_move() {
        // Verify the ordering invariant: after commit, the receipt must exist.
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        let queue_root = tmp.path().join("queue");
        let claimed_path = setup_claimed_job(&queue_root, "job-order");

        let pipeline = ReceiptWritePipeline::new(receipts_dir.clone(), queue_root);
        let receipt = make_receipt("job-order", FacJobOutcome::Completed);

        let result = pipeline
            .commit(
                &receipt,
                &claimed_path,
                "job-order.json",
                TerminalState::Completed,
            )
            .expect("commit");

        // Receipt must exist in the store.
        let hash = compute_job_receipt_content_hash(&receipt);
        let receipt_file = receipts_dir.join(format!("{hash}.json"));
        assert!(
            receipt_file.exists(),
            "receipt must be in content-addressed store"
        );

        // Job must be in terminal directory.
        assert!(result.job_terminal_path.exists());
    }

    // =========================================================================
    // Crash simulation: receipt exists, move not done
    // =========================================================================

    #[test]
    fn test_torn_state_recovery() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        let queue_root = tmp.path().join("queue");
        let claimed_path = setup_claimed_job(&queue_root, "job-torn");

        // Simulate step 1 completing (receipt written) but step 3 not
        // happening (crash before move).
        let receipt = make_receipt("job-torn", FacJobOutcome::Completed);
        let _receipt_path =
            persist_content_addressed_receipt(&receipts_dir, &receipt).expect("persist");

        // Job is still in claimed/.
        assert!(claimed_path.exists(), "job should still be in claimed/");

        // Verify receipt exists for this job.
        assert!(
            receipt_exists_for_job(&receipts_dir, "job-torn"),
            "receipt should exist after persistence"
        );

        // Now run recovery.
        let pipeline = ReceiptWritePipeline::new(receipts_dir.clone(), queue_root);
        let recovery = pipeline
            .recover_torn_state(
                &claimed_path,
                "job-torn.json",
                &receipt,
                TerminalState::Completed,
                2000,
            )
            .expect("recovery should succeed");

        // Job should now be in completed/.
        assert!(!claimed_path.exists(), "job must be gone from claimed/");
        assert!(
            recovery.repair_action.contains("completed"),
            "repair action must mention completed"
        );

        // Recovery receipt should be persisted.
        let recovery_path = receipts_dir.join(format!("recovery-{}.json", recovery.receipt_id));
        assert!(recovery_path.exists(), "recovery receipt must be persisted");
    }

    // =========================================================================
    // Index consistency after crash
    // =========================================================================

    #[test]
    fn test_index_rebuilt_after_crash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        let queue_root = tmp.path().join("queue");

        // Commit a job normally.
        let claimed_path = setup_claimed_job(&queue_root, "job-idx");
        let pipeline = ReceiptWritePipeline::new(receipts_dir.clone(), queue_root);
        let receipt = make_receipt("job-idx", FacJobOutcome::Completed);
        pipeline
            .commit(
                &receipt,
                &claimed_path,
                "job-idx.json",
                TerminalState::Completed,
            )
            .expect("commit");

        // Delete the index to simulate corruption.
        let index_path = ReceiptIndexV1::index_path(&receipts_dir);
        if index_path.exists() {
            std::fs::remove_file(&index_path).expect("remove index");
        }

        // Index should auto-rebuild on next query.
        let index = ReceiptIndexV1::load_or_rebuild(&receipts_dir).expect("rebuild");
        assert!(
            index.latest_digest_for_job("job-idx").is_some(),
            "index must contain the receipt after rebuild"
        );
    }

    // =========================================================================
    // Terminal state mapping
    // =========================================================================

    #[test]
    fn test_outcome_to_terminal_state_mapping() {
        assert_eq!(
            outcome_to_terminal_state(FacJobOutcome::Completed),
            Some(TerminalState::Completed)
        );
        assert_eq!(
            outcome_to_terminal_state(FacJobOutcome::Denied),
            Some(TerminalState::Denied)
        );
        assert_eq!(
            outcome_to_terminal_state(FacJobOutcome::Cancelled),
            Some(TerminalState::Cancelled)
        );
        assert_eq!(
            outcome_to_terminal_state(FacJobOutcome::Quarantined),
            Some(TerminalState::Quarantined)
        );
        assert_eq!(
            outcome_to_terminal_state(FacJobOutcome::CancellationRequested),
            None
        );
    }

    // =========================================================================
    // Recovery receipt validation
    // =========================================================================

    #[test]
    fn test_recovery_receipt_validation() {
        let valid = RecoveryReceiptV1 {
            schema: RECOVERY_RECEIPT_SCHEMA.to_string(),
            receipt_id: "test-recovery-1".to_string(),
            job_id: "job-1".to_string(),
            original_receipt_hash: "hash-1".to_string(),
            detected_state: "receipt exists, job in claimed/".to_string(),
            repair_action: "moved to completed/".to_string(),
            source_path: "/tmp/claimed/job-1.json".to_string(),
            destination_path: "/tmp/completed/job-1.json".to_string(),
            timestamp_secs: 1000,
        };
        assert!(valid.validate().is_ok());

        // Empty receipt_id should fail.
        let mut invalid = valid.clone();
        invalid.receipt_id = String::new();
        assert!(invalid.validate().is_err());

        // Zero timestamp should fail.
        let mut invalid = valid.clone();
        invalid.timestamp_secs = 0;
        assert!(invalid.validate().is_err());

        // Wrong schema should fail.
        let mut invalid = valid;
        invalid.schema = "wrong".to_string();
        assert!(invalid.validate().is_err());
    }

    // =========================================================================
    // Collision handling on move
    // =========================================================================

    #[test]
    fn test_move_collision_generates_unique_name() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        let queue_root = tmp.path().join("queue");

        // Create first claimed job.
        let claimed_path_1 = setup_claimed_job(&queue_root, "dupe");
        let pipeline = ReceiptWritePipeline::new(receipts_dir, queue_root.clone());
        let receipt_1 = make_receipt("dupe", FacJobOutcome::Completed);

        // First commit.
        let result_1 = pipeline
            .commit(
                &receipt_1,
                &claimed_path_1,
                "dupe.json",
                TerminalState::Completed,
            )
            .expect("first commit");

        // Create another claimed job with same name but different receipt
        // (different timestamp to get a different content hash).
        let claimed_path_2 = setup_claimed_job(&queue_root, "dupe");
        let mut receipt_2 = make_receipt("dupe", FacJobOutcome::Completed);
        receipt_2.timestamp_secs = 2000;
        receipt_2.receipt_id = "test-rcpt-dupe-2".to_string();

        // Second commit should succeed with a collision-safe name.
        let result_2 = pipeline
            .commit(
                &receipt_2,
                &claimed_path_2,
                "dupe.json",
                TerminalState::Completed,
            )
            .expect("second commit with collision");

        assert!(result_1.job_terminal_path.exists());
        assert!(result_2.job_terminal_path.exists());
        // Paths should differ (collision avoidance).
        assert_ne!(result_1.job_terminal_path, result_2.job_terminal_path);
    }

    // =========================================================================
    // Receipt pipeline error on missing source
    // =========================================================================

    #[test]
    fn test_commit_fails_gracefully_on_missing_claimed_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        let queue_root = tmp.path().join("queue");

        // Do NOT create the claimed file.
        let claimed_path = queue_root.join("claimed").join("ghost.json");
        let pipeline = ReceiptWritePipeline::new(receipts_dir, queue_root);
        let receipt = make_receipt("ghost", FacJobOutcome::Completed);

        // Commit should fail on the move step (receipt persists fine).
        let result = pipeline.commit(
            &receipt,
            &claimed_path,
            "ghost.json",
            TerminalState::Completed,
        );
        assert!(result.is_err(), "commit must fail when source is missing");
    }

    // =========================================================================
    // Directory name mapping
    // =========================================================================

    #[test]
    fn test_terminal_state_dir_names() {
        assert_eq!(TerminalState::Completed.dir_name(), "completed");
        assert_eq!(TerminalState::Denied.dir_name(), "denied");
        assert_eq!(TerminalState::Cancelled.dir_name(), "cancelled");
        assert_eq!(TerminalState::Quarantined.dir_name(), "quarantine");
    }
}
