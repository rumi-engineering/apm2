// AGENT-AUTHORED (TCK-00578)
//! Queue bounds enforcement: `max_pending_jobs`, `max_pending_bytes`,
//! and optional `per_lane_max_pending_jobs`.
//!
//! Implements TCK-00578: enqueue-time bounds checks that prevent the
//! pending queue from growing unbounded and exhausting disk. Excess
//! enqueue attempts are denied with structured denial receipts.
//!
//! # Design
//!
//! The `QueueBoundsPolicy` configures hard caps for the queue:
//! - `max_pending_jobs`: maximum number of files in `queue/pending/`
//! - `max_pending_bytes`: maximum total bytes of files in `queue/pending/`
//! - `per_lane_max_pending_jobs`: optional per-lane job cap (not yet enforced
//!   at the filesystem layer; reserved for future lane-aware queue
//!   partitioning)
//!
//! `check_queue_bounds` scans `queue/pending/` to compute the current
//! job count and total bytes, then evaluates the proposed enqueue against
//! the policy. If the enqueue would exceed any configured limit, a
//! `QueueBoundsDenialReceipt` is returned via error.
//!
//! # Fail-Closed Semantics
//!
//! - If the pending directory cannot be read, the check **denies**
//!   (fail-closed).
//! - If metadata for a file cannot be read, that file is counted as 1 job and 0
//!   bytes (conservative: may under-count bytes but never under-count jobs).
//! - A `max_pending_jobs` or `max_pending_bytes` of `0` means the dimension is
//!   disabled (all enqueue attempts denied).
//! - If the scan is truncated at `MAX_SCAN_ENTRIES`, the check **denies**
//!   (fail-closed) because a partial count cannot safely approve enqueue.
//!
//! # Thread Safety
//!
//! ACKNOWLEDGED TOCTOU (RSK-1501): The check is a point-in-time filesystem
//! scan. The check and subsequent write are not atomic. In the current
//! single-process broker architecture, only one `enqueue_job` call is active
//! at a time, so the race window is limited to external filesystem mutations.
//! Concurrent enqueue from separate processes could briefly exceed the cap
//! by a small margin. A file lock is out of scope per TCK-00578; the
//! single-process mitigation is sufficient for the local broker context.
//!
//! # Security Invariants
//!
//! - [INV-QB-001] Fail-closed: unreadable pending directory denies all enqueue
//!   attempts.
//! - [INV-QB-002] Directory scan is bounded by `MAX_SCAN_ENTRIES` to prevent
//!   DoS from a directory with millions of entries. Truncated scans are
//!   treated as fail-closed denials.
//! - [INV-QB-003] Denial receipts include the exceeded dimension, current
//!   usage, limit, and stable reason code for audit.
//! - [INV-QB-004] Arithmetic uses `checked_add`; overflow returns Err.
//! - [INV-QB-005] Symlinks in pending directory are skipped (not counted) to
//!   prevent inflation attacks.
//! - [INV-QB-006] `pending_dir` is verified not to be a symlink before
//!   scanning, preventing DoS via symlink-swapped queue directories.

use std::path::Path;

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of directory entries to scan in `queue/pending/`.
///
/// Prevents `DoS` from a directory with millions of entries (INV-QB-002).
pub const MAX_SCAN_ENTRIES: usize = 100_000;

/// Default maximum number of pending jobs.
pub const DEFAULT_MAX_PENDING_JOBS: u64 = 10_000;

/// Default maximum pending bytes (1 GiB).
pub const DEFAULT_MAX_PENDING_BYTES: u64 = 1_073_741_824;

/// Hard cap for `max_pending_jobs` (prevents misconfiguration).
pub const HARD_CAP_MAX_PENDING_JOBS: u64 = 1_000_000;

/// Hard cap for `max_pending_bytes` (64 GiB, prevents misconfiguration).
pub const HARD_CAP_MAX_PENDING_BYTES: u64 = 68_719_476_736;

/// Stable denial reason code for queue quota exceeded.
pub const DENY_REASON_QUEUE_QUOTA_EXCEEDED: &str = "queue/quota_exceeded";

/// Maximum length for denial reason strings.
const MAX_DENIAL_REASON_LENGTH: usize = 256;

/// Maximum filename byte length before conversion to String.
///
/// Bounds memory allocation per entry during scan, preventing `DoS`
/// via maliciously crafted long filenames (security NIT).
const MAX_FILENAME_BYTES: usize = 4096;

// ============================================================================
// Errors
// ============================================================================

/// Errors from queue bounds evaluation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueueBoundsError {
    /// The enqueue would exceed the configured queue bounds.
    #[error("queue bounds exceeded: {reason}")]
    QueueBoundsExceeded {
        /// Stable denial reason code.
        reason: String,
        /// Structured denial receipt.
        receipt: QueueBoundsDenialReceipt,
    },

    /// Queue bounds policy is invalid.
    #[error("invalid queue bounds policy: {detail}")]
    InvalidPolicy {
        /// Detail about the validation failure.
        detail: String,
    },

    /// Pending directory scan failed (fail-closed: INV-QB-001).
    #[error("pending directory scan failed: {detail}")]
    ScanFailed {
        /// Detail about the scan failure.
        detail: String,
    },
}

// ============================================================================
// Policy configuration
// ============================================================================

/// Queue bounds policy controlling maximum pending queue size.
///
/// Configures hard caps for the number of pending jobs and total
/// pending bytes. A limit of `0` means the dimension is disabled
/// (all enqueue attempts denied -- fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueBoundsPolicy {
    /// Maximum number of jobs allowed in `queue/pending/`.
    pub max_pending_jobs: u64,
    /// Maximum total bytes of job spec files in `queue/pending/`.
    pub max_pending_bytes: u64,
    /// Optional per-lane maximum pending jobs. When `Some`, each lane
    /// is individually capped. Currently reserved for future lane-aware
    /// queue partitioning; not enforced at the filesystem layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_lane_max_pending_jobs: Option<u64>,
}

impl Default for QueueBoundsPolicy {
    fn default() -> Self {
        Self {
            max_pending_jobs: DEFAULT_MAX_PENDING_JOBS,
            max_pending_bytes: DEFAULT_MAX_PENDING_BYTES,
            per_lane_max_pending_jobs: None,
        }
    }
}

impl QueueBoundsPolicy {
    /// Validates that the policy does not exceed hard caps.
    ///
    /// # Errors
    ///
    /// Returns [`QueueBoundsError::InvalidPolicy`] if any limit exceeds
    /// its hard cap.
    pub fn validate(&self) -> Result<(), QueueBoundsError> {
        if self.max_pending_jobs > HARD_CAP_MAX_PENDING_JOBS {
            return Err(QueueBoundsError::InvalidPolicy {
                detail: format!(
                    "max_pending_jobs {} exceeds hard cap {HARD_CAP_MAX_PENDING_JOBS}",
                    self.max_pending_jobs
                ),
            });
        }
        if self.max_pending_bytes > HARD_CAP_MAX_PENDING_BYTES {
            return Err(QueueBoundsError::InvalidPolicy {
                detail: format!(
                    "max_pending_bytes {} exceeds hard cap {HARD_CAP_MAX_PENDING_BYTES}",
                    self.max_pending_bytes
                ),
            });
        }
        if let Some(per_lane) = self.per_lane_max_pending_jobs {
            if per_lane > HARD_CAP_MAX_PENDING_JOBS {
                return Err(QueueBoundsError::InvalidPolicy {
                    detail: format!(
                        "per_lane_max_pending_jobs {per_lane} exceeds hard cap {HARD_CAP_MAX_PENDING_JOBS}",
                    ),
                });
            }
        }
        Ok(())
    }
}

// ============================================================================
// Queue snapshot
// ============================================================================

/// Point-in-time snapshot of the pending queue state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingQueueSnapshot {
    /// Number of regular files in `queue/pending/`.
    pub job_count: u64,
    /// Total bytes of regular files in `queue/pending/`.
    pub total_bytes: u64,
    /// Whether the scan was truncated at `MAX_SCAN_ENTRIES`.
    pub truncated: bool,
}

// ============================================================================
// Denial receipts
// ============================================================================

/// Which queue dimension was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueBoundsDimension {
    /// Pending job count exceeded.
    PendingJobs,
    /// Pending bytes exceeded.
    PendingBytes,
    /// Directory scan was truncated at `MAX_SCAN_ENTRIES`; fail-closed
    /// because partial counts cannot safely approve enqueue.
    ScanTruncated,
}

/// Structured denial receipt for queue bounds violations.
///
/// Contains evidence of the exceeded dimension, current usage, the
/// configured limit, and a stable reason code for audit (INV-QB-003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueBoundsDenialReceipt {
    /// Which queue dimension was exceeded.
    pub dimension: QueueBoundsDimension,
    /// Current usage at the time of denial.
    pub current_usage: u64,
    /// Configured limit for this dimension.
    pub limit: u64,
    /// The increment that was requested (and denied).
    pub requested_increment: u64,
    /// Stable denial reason code.
    pub reason: String,
}

// ============================================================================
// Queue bounds check
// ============================================================================

/// Scans `pending_dir` and evaluates whether an enqueue of
/// `proposed_bytes` would exceed the configured `policy`.
///
/// # Arguments
///
/// * `pending_dir` - Path to `queue/pending/`.
/// * `proposed_bytes` - Size in bytes of the job spec to be enqueued.
/// * `policy` - Queue bounds policy to enforce.
///
/// # Errors
///
/// Returns [`QueueBoundsError::QueueBoundsExceeded`] if the enqueue
/// would violate the policy, or [`QueueBoundsError::ScanFailed`] if
/// the pending directory cannot be scanned (fail-closed: INV-QB-001).
pub fn check_queue_bounds(
    pending_dir: &Path,
    proposed_bytes: u64,
    policy: &QueueBoundsPolicy,
) -> Result<PendingQueueSnapshot, QueueBoundsError> {
    // ACKNOWLEDGED TOCTOU (RSK-1501): The filesystem scan and the subsequent
    // file write (by the caller) are not atomic. In the current single-process
    // broker architecture, only one `enqueue_job` call is active at a time,
    // so the race window is limited to external filesystem mutations.
    // Concurrent enqueue from separate processes could briefly exceed the cap
    // by a small margin. A file lock is out of scope per TCK-00578; the
    // single-process mitigation is sufficient for the local broker context.

    // Fail-closed: zero limits deny everything (INV-QB-001).
    check_zero_limits(policy, proposed_bytes)?;

    // If the directory does not exist, the queue is empty.
    if !pending_dir.exists() {
        return Ok(PendingQueueSnapshot {
            job_count: 0,
            total_bytes: 0,
            truncated: false,
        });
    }

    // [INV-QB-006] Reject symlinked pending_dir to prevent `DoS` via a
    // symlink-swapped queue directory pointing at a large filesystem tree.
    // Uses `symlink_metadata()` to detect symlinks without following them.
    reject_symlink_pending_dir(pending_dir)?;

    let snapshot = scan_pending_dir(pending_dir)?;

    // Fail-closed on truncated scan: a partial count that looks under-limit
    // is not safe to approve. Treat truncation as a quota denial.
    if snapshot.truncated {
        return Err(quota_exceeded(
            QueueBoundsDimension::ScanTruncated,
            snapshot.job_count,
            policy.max_pending_jobs,
            1,
            "queue/quota_exceeded: scan truncated at MAX_SCAN_ENTRIES; fail-closed",
        ));
    }

    // Check job count and bytes against policy limits.
    enforce_job_limit(&snapshot, policy)?;
    enforce_byte_limit(&snapshot, proposed_bytes, policy)?;

    Ok(snapshot)
}

/// Returns an error if either zero-limit dimension is configured.
fn check_zero_limits(
    policy: &QueueBoundsPolicy,
    proposed_bytes: u64,
) -> Result<(), QueueBoundsError> {
    if policy.max_pending_jobs == 0 {
        return Err(quota_exceeded(
            QueueBoundsDimension::PendingJobs,
            0,
            0,
            1,
            DENY_REASON_QUEUE_QUOTA_EXCEEDED,
        ));
    }
    if policy.max_pending_bytes == 0 {
        return Err(quota_exceeded(
            QueueBoundsDimension::PendingBytes,
            0,
            0,
            proposed_bytes,
            DENY_REASON_QUEUE_QUOTA_EXCEEDED,
        ));
    }
    Ok(())
}

/// Rejects a pending directory that is a symlink (INV-QB-006).
fn reject_symlink_pending_dir(pending_dir: &Path) -> Result<(), QueueBoundsError> {
    let dir_meta = pending_dir
        .symlink_metadata()
        .map_err(|e| QueueBoundsError::ScanFailed {
            detail: format!(
                "cannot stat pending directory {}: {e}",
                pending_dir.display()
            ),
        })?;
    if dir_meta.file_type().is_symlink() {
        return Err(QueueBoundsError::ScanFailed {
            detail: format!(
                "pending directory {} is a symlink; refusing to scan (INV-QB-006)",
                pending_dir.display()
            ),
        });
    }
    Ok(())
}

/// Enforces the job count limit against the snapshot.
fn enforce_job_limit(
    snapshot: &PendingQueueSnapshot,
    policy: &QueueBoundsPolicy,
) -> Result<(), QueueBoundsError> {
    let next_job_count = snapshot.job_count.checked_add(1).ok_or_else(|| {
        quota_exceeded(
            QueueBoundsDimension::PendingJobs,
            snapshot.job_count,
            policy.max_pending_jobs,
            1,
            "queue/quota_exceeded: job count overflow",
        )
    })?;
    if next_job_count > policy.max_pending_jobs {
        return Err(quota_exceeded(
            QueueBoundsDimension::PendingJobs,
            snapshot.job_count,
            policy.max_pending_jobs,
            1,
            DENY_REASON_QUEUE_QUOTA_EXCEEDED,
        ));
    }
    Ok(())
}

/// Enforces the byte limit against the snapshot.
fn enforce_byte_limit(
    snapshot: &PendingQueueSnapshot,
    proposed_bytes: u64,
    policy: &QueueBoundsPolicy,
) -> Result<(), QueueBoundsError> {
    let next_bytes = snapshot
        .total_bytes
        .checked_add(proposed_bytes)
        .ok_or_else(|| {
            quota_exceeded(
                QueueBoundsDimension::PendingBytes,
                snapshot.total_bytes,
                policy.max_pending_bytes,
                proposed_bytes,
                "queue/quota_exceeded: byte count overflow",
            )
        })?;
    if next_bytes > policy.max_pending_bytes {
        return Err(quota_exceeded(
            QueueBoundsDimension::PendingBytes,
            snapshot.total_bytes,
            policy.max_pending_bytes,
            proposed_bytes,
            DENY_REASON_QUEUE_QUOTA_EXCEEDED,
        ));
    }
    Ok(())
}

/// Constructs a `QueueBoundsExceeded` error with a denial receipt.
fn quota_exceeded(
    dimension: QueueBoundsDimension,
    current_usage: u64,
    limit: u64,
    requested_increment: u64,
    reason_str: &str,
) -> QueueBoundsError {
    QueueBoundsError::QueueBoundsExceeded {
        reason: DENY_REASON_QUEUE_QUOTA_EXCEEDED.to_string(),
        receipt: QueueBoundsDenialReceipt {
            dimension,
            current_usage,
            limit,
            requested_increment,
            reason: truncate_reason(reason_str),
        },
    }
}

/// Scans the pending directory and returns a snapshot of current state.
///
/// Only counts regular files (not symlinks, directories, or special
/// files) per INV-QB-005. The scan is bounded by [`MAX_SCAN_ENTRIES`]
/// per INV-QB-002. When the scan cap is hit, `truncated` is set to `true`
/// so the caller can apply fail-closed logic.
fn scan_pending_dir(pending_dir: &Path) -> Result<PendingQueueSnapshot, QueueBoundsError> {
    let read_dir = std::fs::read_dir(pending_dir).map_err(|e| QueueBoundsError::ScanFailed {
        detail: format!(
            "cannot read pending directory {}: {e}",
            pending_dir.display()
        ),
    })?;

    let mut job_count: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut truncated = false;

    for (entries_scanned, entry_result) in read_dir.enumerate() {
        if entries_scanned >= MAX_SCAN_ENTRIES {
            // Hit the scan cap -- mark as truncated so the caller
            // can apply fail-closed logic. A partial count that looks
            // under-limit is not safe to approve.
            truncated = true;
            break;
        }

        let Ok(entry) = entry_result else {
            // Cannot read entry -- count as a job with 0 bytes
            // (conservative for job count, not for bytes).
            job_count = job_count.saturating_add(1);
            continue;
        };

        // Check filename byte length before converting to String to
        // bound memory allocation per entry (security NIT: prevents
        // DoS via maliciously crafted long filenames).
        let file_name = entry.file_name();
        if file_name.len() > MAX_FILENAME_BYTES {
            // Skip entries with excessively long filenames. Count as
            // a job with 0 bytes (conservative for job count).
            job_count = job_count.saturating_add(1);
            continue;
        }

        // Use symlink_metadata to detect symlinks without following them.
        let Ok(metadata) = entry.path().symlink_metadata() else {
            // Cannot stat entry -- count as a job with 0 bytes.
            job_count = job_count.saturating_add(1);
            continue;
        };

        // Only count regular files (INV-QB-005: skip symlinks).
        if !metadata.is_file() {
            continue;
        }

        // Skip hidden/temporary files (start with '.')
        let name_str = file_name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }

        job_count = job_count.saturating_add(1);
        total_bytes = total_bytes.saturating_add(metadata.len());
    }

    Ok(PendingQueueSnapshot {
        job_count,
        total_bytes,
        truncated,
    })
}

// ============================================================================
// Helpers
// ============================================================================

/// Truncates a reason string to the maximum allowed length (UTF-8 safe).
fn truncate_reason(reason: &str) -> String {
    if reason.len() <= MAX_DENIAL_REASON_LENGTH {
        reason.to_string()
    } else {
        let boundary = reason
            .char_indices()
            .take_while(|&(i, _)| i <= MAX_DENIAL_REASON_LENGTH)
            .last()
            .map_or(0, |(i, _)| i);
        reason[..boundary].to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Policy validation
    // -----------------------------------------------------------------------

    #[test]
    fn default_policy_passes_validation() {
        let policy = QueueBoundsPolicy::default();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn policy_exceeding_job_hard_cap_rejected() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: HARD_CAP_MAX_PENDING_JOBS + 1,
            ..QueueBoundsPolicy::default()
        };
        let err = policy.validate().unwrap_err();
        assert!(
            matches!(err, QueueBoundsError::InvalidPolicy { .. }),
            "expected InvalidPolicy, got {err:?}"
        );
    }

    #[test]
    fn policy_exceeding_bytes_hard_cap_rejected() {
        let policy = QueueBoundsPolicy {
            max_pending_bytes: HARD_CAP_MAX_PENDING_BYTES + 1,
            ..QueueBoundsPolicy::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(QueueBoundsError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn policy_exceeding_per_lane_hard_cap_rejected() {
        let policy = QueueBoundsPolicy {
            per_lane_max_pending_jobs: Some(HARD_CAP_MAX_PENDING_JOBS + 1),
            ..QueueBoundsPolicy::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(QueueBoundsError::InvalidPolicy { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Zero-limit fail-closed
    // -----------------------------------------------------------------------

    #[test]
    fn zero_max_pending_jobs_denies_immediately() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 0,
            ..QueueBoundsPolicy::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        let err = check_queue_bounds(&pending, 100, &policy).unwrap_err();
        match err {
            QueueBoundsError::QueueBoundsExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_QUEUE_QUOTA_EXCEEDED);
                assert_eq!(receipt.dimension, QueueBoundsDimension::PendingJobs);
                assert_eq!(receipt.limit, 0);
            },
            other => panic!("expected QueueBoundsExceeded, got {other:?}"),
        }
    }

    #[test]
    fn zero_max_pending_bytes_denies_immediately() {
        let policy = QueueBoundsPolicy {
            max_pending_bytes: 0,
            ..QueueBoundsPolicy::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        let err = check_queue_bounds(&pending, 100, &policy).unwrap_err();
        match err {
            QueueBoundsError::QueueBoundsExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_QUEUE_QUOTA_EXCEEDED);
                assert_eq!(receipt.dimension, QueueBoundsDimension::PendingBytes);
                assert_eq!(receipt.limit, 0);
            },
            other => panic!("expected QueueBoundsExceeded, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Empty directory allows enqueue
    // -----------------------------------------------------------------------

    #[test]
    fn empty_pending_dir_allows_enqueue() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 5,
            max_pending_bytes: 1000,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        let snapshot = check_queue_bounds(&pending, 100, &policy).unwrap();
        assert_eq!(snapshot.job_count, 0);
        assert_eq!(snapshot.total_bytes, 0);
    }

    #[test]
    fn nonexistent_pending_dir_allows_enqueue() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 5,
            max_pending_bytes: 1000,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("nonexistent");

        let snapshot = check_queue_bounds(&pending, 100, &policy).unwrap();
        assert_eq!(snapshot.job_count, 0);
        assert_eq!(snapshot.total_bytes, 0);
    }

    // -----------------------------------------------------------------------
    // Job count enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn job_count_at_limit_denies_next_enqueue() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 3,
            max_pending_bytes: 100_000,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        // Create 3 job files.
        for i in 0..3 {
            let path = pending.join(format!("job-{i}.json"));
            std::fs::write(&path, format!("{{\"job\":{i}}}")).unwrap();
        }

        let err = check_queue_bounds(&pending, 20, &policy).unwrap_err();
        match err {
            QueueBoundsError::QueueBoundsExceeded { receipt, .. } => {
                assert_eq!(receipt.dimension, QueueBoundsDimension::PendingJobs);
                assert_eq!(receipt.current_usage, 3);
                assert_eq!(receipt.limit, 3);
                assert_eq!(receipt.requested_increment, 1);
            },
            other => panic!("expected QueueBoundsExceeded, got {other:?}"),
        }
    }

    #[test]
    fn job_count_below_limit_allows_enqueue() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 5,
            max_pending_bytes: 100_000,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        // Create 2 job files.
        for i in 0..2 {
            let path = pending.join(format!("job-{i}.json"));
            std::fs::write(&path, format!("{{\"job\":{i}}}")).unwrap();
        }

        let snapshot = check_queue_bounds(&pending, 20, &policy).unwrap();
        assert_eq!(snapshot.job_count, 2);
    }

    // -----------------------------------------------------------------------
    // Bytes enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn bytes_exceeding_limit_denies_enqueue() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 100,
            max_pending_bytes: 50,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        // Create a file of 40 bytes.
        let content = "a]".repeat(20); // 40 bytes
        std::fs::write(pending.join("job-0.json"), &content).unwrap();

        // Propose 20 more bytes: 40 + 20 = 60 > 50.
        let err = check_queue_bounds(&pending, 20, &policy).unwrap_err();
        match err {
            QueueBoundsError::QueueBoundsExceeded { receipt, .. } => {
                assert_eq!(receipt.dimension, QueueBoundsDimension::PendingBytes);
                assert_eq!(receipt.current_usage, 40);
                assert_eq!(receipt.limit, 50);
                assert_eq!(receipt.requested_increment, 20);
            },
            other => panic!("expected QueueBoundsExceeded, got {other:?}"),
        }
    }

    #[test]
    fn bytes_within_limit_allows_enqueue() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 100,
            max_pending_bytes: 100,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        let content = "a".repeat(30);
        std::fs::write(pending.join("job-0.json"), &content).unwrap();

        // Propose 20 more bytes: 30 + 20 = 50 <= 100.
        let snapshot = check_queue_bounds(&pending, 20, &policy).unwrap();
        assert_eq!(snapshot.job_count, 1);
        assert_eq!(snapshot.total_bytes, 30);
    }

    // -----------------------------------------------------------------------
    // Symlinks are skipped
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_counted() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 2,
            max_pending_bytes: 100_000,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        // Create one real file.
        std::fs::write(pending.join("job-0.json"), "real").unwrap();

        // Create a symlink.
        std::os::unix::fs::symlink("/dev/null", pending.join("symlink.json")).unwrap();

        // Only the real file should be counted.
        let snapshot = check_queue_bounds(&pending, 10, &policy).unwrap();
        assert_eq!(snapshot.job_count, 1);
    }

    // -----------------------------------------------------------------------
    // Hidden files (temp files) are skipped
    // -----------------------------------------------------------------------

    #[test]
    fn hidden_files_not_counted() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 2,
            max_pending_bytes: 100_000,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        // Create one real file and one hidden file.
        std::fs::write(pending.join("job-0.json"), "real").unwrap();
        std::fs::write(pending.join(".tmp-job-1.json"), "temp").unwrap();

        let snapshot = check_queue_bounds(&pending, 10, &policy).unwrap();
        assert_eq!(snapshot.job_count, 1);
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn policy_serialization_round_trip() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 500,
            max_pending_bytes: 50_000,
            per_lane_max_pending_jobs: Some(100),
        };
        let json = serde_json::to_string(&policy).expect("serialize");
        let loaded: QueueBoundsPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, loaded);
    }

    #[test]
    fn denial_receipt_serialization_round_trip() {
        let receipt = QueueBoundsDenialReceipt {
            dimension: QueueBoundsDimension::PendingJobs,
            current_usage: 42,
            limit: 100,
            requested_increment: 1,
            reason: DENY_REASON_QUEUE_QUOTA_EXCEEDED.to_string(),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let loaded: QueueBoundsDenialReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, loaded);
    }

    // -----------------------------------------------------------------------
    // Flooding test (Definition of Done)
    // -----------------------------------------------------------------------

    #[test]
    fn flooding_enqueue_attempts_denied_with_receipts() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 5,
            max_pending_bytes: 100_000,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        // Fill to capacity.
        for i in 0..5 {
            std::fs::write(pending.join(format!("job-{i}.json")), "data").unwrap();
        }

        // Every subsequent attempt should be denied.
        let mut denied_count = 0;
        for _ in 0..100 {
            if check_queue_bounds(&pending, 10, &policy).is_err() {
                denied_count += 1;
            }
        }
        assert_eq!(
            denied_count, 100,
            "all 100 excess enqueue attempts must be denied"
        );
    }

    // -----------------------------------------------------------------------
    // Symlink pending_dir rejection (INV-QB-006)
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn symlinked_pending_dir_is_rejected() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 100,
            max_pending_bytes: 100_000,
            per_lane_max_pending_jobs: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real_pending");
        std::fs::create_dir_all(&real_dir).unwrap();

        // Create a symlink to the real directory.
        let symlink_dir = tmp.path().join("symlink_pending");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        // Scanning the symlink must fail with ScanFailed.
        let err = check_queue_bounds(&symlink_dir, 10, &policy).unwrap_err();
        match err {
            QueueBoundsError::ScanFailed { detail } => {
                assert!(
                    detail.contains("symlink"),
                    "error must mention symlink, got: {detail}"
                );
            },
            other => panic!("expected ScanFailed for symlinked dir, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Truncated scan fail-closed
    // -----------------------------------------------------------------------

    #[test]
    fn scan_truncated_dimension_serializes_correctly() {
        let receipt = QueueBoundsDenialReceipt {
            dimension: QueueBoundsDimension::ScanTruncated,
            current_usage: 100_000,
            limit: 10_000,
            requested_increment: 1,
            reason: "queue/quota_exceeded: scan truncated at MAX_SCAN_ENTRIES; fail-closed"
                .to_string(),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        assert!(
            json.contains("scan_truncated"),
            "ScanTruncated must serialize as 'scan_truncated', got: {json}"
        );
        let loaded: QueueBoundsDenialReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, loaded);
    }

    // -----------------------------------------------------------------------
    // Truncation safety
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_reason_short_string_unchanged() {
        assert_eq!(truncate_reason("hello"), "hello");
    }

    #[test]
    fn truncate_reason_utf8_safe() {
        let multi_byte = "\u{1F600}";
        let long_reason = multi_byte.repeat(100);
        let truncated = truncate_reason(&long_reason);
        assert!(truncated.len() <= MAX_DENIAL_REASON_LENGTH);
        // Verify valid UTF-8.
        let _ = truncated.as_str();
    }
}
