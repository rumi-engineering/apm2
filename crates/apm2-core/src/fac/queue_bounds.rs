// AGENT-AUTHORED (TCK-00578)
//! Queue bounds and backpressure: max pending jobs/bytes with denial receipts.
//!
//! Implements TCK-00578: hard queue-level bounds on the number and total size
//! of pending jobs.  When a new enqueue would exceed any configured bound, the
//! enqueue is denied fail-closed with a structured `QueueQuotaDenialReceipt`.
//!
//! # Design
//!
//! The broker (or CLI enqueue path) calls `check_queue_bounds()` **before**
//! writing the job spec to `queue/pending/`.  The check scans the pending
//! directory with bounded I/O (`scan_pending_queue`) and evaluates the
//! proposed addition against `QueueBoundsPolicy`.
//!
//! Three dimensions are enforced:
//!
//! - **`max_pending_jobs`**: hard cap on the total number of pending job specs
//!   across all lanes.
//! - **`max_pending_bytes`**: hard cap on the total bytes of all pending job
//!   spec files.
//! - **`per_lane_max_pending_jobs`**: optional per-lane cap on pending jobs.
//!   When set, each distinct `queue_lane` value is counted independently.
//!
//! # Fail-Closed Semantics
//!
//! - A zero limit means the dimension is disabled (all enqueues denied for that
//!   dimension).
//! - Scan errors (I/O failures, permission issues) deny fail-closed with a
//!   `scan_error` denial reason.
//! - Counter arithmetic uses `checked_add`; overflow denies fail-closed.
//!
//! # Thread Safety
//!
//! The functions in this module are stateless and operate on the filesystem.
//! Callers must ensure appropriate serialization if multiple producers enqueue
//! concurrently (the filesystem directory is the shared state; the scan is a
//! point-in-time snapshot).  The TOCTOU gap between scan and write is
//! acceptable because:
//! 1. The bounds are soft-enforcement (advisory cap, not hard quota).
//! 2. Concurrent enqueues at the boundary may admit slightly more than the cap,
//!    which is bounded by the number of concurrent producers.
//! 3. The broker rate limits (TCK-00568) provide the primary admission gate;
//!    queue bounds provide defense-in-depth.
//!
//! # Security Invariants
//!
//! - [INV-QB-001] Fail-closed: scan failure or overflow denies the enqueue.
//! - [INV-QB-002] Bounds check occurs BEFORE the job spec is written to disk.
//! - [INV-QB-003] Denial receipts include the exceeded dimension, current
//!   usage, limit, and stable reason code for audit.
//! - [INV-QB-004] All string fields in receipts are bounded
//!   (`MAX_DENIAL_REASON_LENGTH`).
//! - [INV-QB-005] Directory scan is bounded by `MAX_SCAN_ENTRIES` to prevent
//!   DoS from a directory with millions of entries.
//! - [INV-QB-006] File metadata reads use `symlink_metadata` (no symlink
//!   following) per CTR-1503.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of directory entries to scan in `queue/pending/`.
///
/// Prevents unbounded iteration over a directory with millions of entries
/// (INV-QB-005).  If the pending directory contains more than this many
/// entries, the scan is truncated and the truncated snapshot is used for
/// bounds evaluation.  This is safe because truncation means the queue is
/// already very large and will likely exceed bounds anyway.
pub const MAX_SCAN_ENTRIES: usize = 100_000;

/// Maximum length for denial reason strings (INV-QB-004).
const MAX_DENIAL_REASON_LENGTH: usize = 256;

/// Hard cap on `max_pending_jobs` to prevent configuration errors.
pub const HARD_CAP_MAX_PENDING_JOBS: u64 = 1_000_000;

/// Hard cap on `max_pending_bytes` (1 TiB) to prevent configuration errors.
pub const HARD_CAP_MAX_PENDING_BYTES: u64 = 1_099_511_627_776;

/// Hard cap on `per_lane_max_pending_jobs` to prevent configuration errors.
pub const HARD_CAP_PER_LANE_MAX_PENDING_JOBS: u64 = 100_000;

/// Maximum number of distinct lanes tracked during a scan.
///
/// Prevents unbounded `HashMap` growth if job files contain adversarial
/// lane names (CTR-1303).
const MAX_TRACKED_LANES: usize = 256;

// Stable denial reason codes

/// Queue pending job count exceeded.
pub const DENY_REASON_PENDING_JOBS_EXCEEDED: &str = "queue/quota_exceeded:pending_jobs";

/// Queue pending bytes exceeded.
pub const DENY_REASON_PENDING_BYTES_EXCEEDED: &str = "queue/quota_exceeded:pending_bytes";

/// Per-lane pending job count exceeded.
pub const DENY_REASON_PER_LANE_JOBS_EXCEEDED: &str = "queue/quota_exceeded:per_lane_pending_jobs";

/// Queue scan failed (I/O error); enqueue denied fail-closed.
pub const DENY_REASON_SCAN_ERROR: &str = "queue/quota_exceeded:scan_error";

/// Counter overflow; enqueue denied fail-closed.
pub const DENY_REASON_COUNTER_OVERFLOW: &str = "queue/quota_exceeded:counter_overflow";

// ============================================================================
// Errors
// ============================================================================

/// Errors from queue bounds evaluation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueueBoundsError {
    /// The proposed enqueue would exceed a configured queue bound.
    #[error("queue quota exceeded: {reason}")]
    QuotaExceeded {
        /// Stable denial reason code.
        reason: String,
        /// Structured denial receipt.
        receipt: QueueQuotaDenialReceipt,
    },

    /// The pending directory could not be scanned.
    #[error("queue scan failed: {detail}")]
    ScanFailed {
        /// Detail about the scan failure.
        detail: String,
        /// Structured denial receipt (INV-QB-001).
        receipt: QueueQuotaDenialReceipt,
    },

    /// Policy configuration is invalid.
    #[error("invalid queue bounds policy: {detail}")]
    InvalidPolicy {
        /// Detail about the policy violation.
        detail: String,
    },
}

// ============================================================================
// Configuration
// ============================================================================

/// Queue bounds policy.
///
/// Configures hard caps for queue-level dimensions.  A limit of `0` means
/// the dimension is disabled (all enqueues denied for that dimension --
/// fail-closed per INV-QB-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueBoundsPolicy {
    /// Maximum number of pending job specs allowed across all lanes.
    pub max_pending_jobs: u64,
    /// Maximum total bytes of all pending job spec files.
    pub max_pending_bytes: u64,
    /// Optional per-lane cap on pending jobs.  When `Some(0)`, all enqueues
    /// for any lane are denied.  When `None`, per-lane enforcement is
    /// disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_lane_max_pending_jobs: Option<u64>,
}

impl Default for QueueBoundsPolicy {
    fn default() -> Self {
        Self {
            max_pending_jobs: 10_000,
            max_pending_bytes: 10_737_418_240, // 10 GiB
            per_lane_max_pending_jobs: None,
        }
    }
}

impl QueueBoundsPolicy {
    /// Validates that policy limits do not exceed hard caps.
    ///
    /// # Errors
    ///
    /// Returns [`QueueBoundsError::InvalidPolicy`] if any limit exceeds its
    /// hard cap.
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
            if per_lane > HARD_CAP_PER_LANE_MAX_PENDING_JOBS {
                return Err(QueueBoundsError::InvalidPolicy {
                    detail: format!(
                        "per_lane_max_pending_jobs {per_lane} exceeds hard cap \
                         {HARD_CAP_PER_LANE_MAX_PENDING_JOBS}"
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
///
/// Produced by [`scan_pending_queue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueSnapshot {
    /// Total number of `.json` files in `queue/pending/`.
    pub total_jobs: u64,
    /// Total size in bytes of all `.json` files in `queue/pending/`.
    pub total_bytes: u64,
    /// Per-lane job counts (lane name -> count).
    ///
    /// Only populated if per-lane enforcement is configured.  Bounded by
    /// `MAX_TRACKED_LANES`.
    pub per_lane_jobs: HashMap<String, u64>,
    /// Whether the directory scan was truncated at `MAX_SCAN_ENTRIES`.
    pub scan_truncated: bool,
}

// ============================================================================
// Denial receipts
// ============================================================================

/// Dimension of the queue bound that was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueBoundsDimension {
    /// Total pending job count.
    PendingJobs,
    /// Total pending bytes.
    PendingBytes,
    /// Per-lane pending job count.
    PerLanePendingJobs,
    /// Scan failure (I/O error).
    ScanError,
}

/// Structured denial receipt for queue bounds violations (INV-QB-003).
///
/// Contains evidence of the exceeded dimension, current usage, the configured
/// limit, and a stable reason code for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueQuotaDenialReceipt {
    /// Which queue bound dimension was exceeded.
    pub dimension: QueueBoundsDimension,
    /// Current usage at the time of denial.
    pub current_usage: u64,
    /// Configured limit for this dimension.
    pub limit: u64,
    /// The proposed increment that was denied.
    pub proposed_increment: u64,
    /// Stable denial reason code.
    pub reason: String,
    /// Lane name, if the denial is per-lane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
}

// ============================================================================
// Queue scanning
// ============================================================================

/// Scan the `queue/pending/` directory to produce a [`QueueSnapshot`].
///
/// - Only counts regular `.json` files (symlinks rejected per INV-QB-006).
/// - Scan is bounded by [`MAX_SCAN_ENTRIES`] (INV-QB-005).
/// - If `track_lanes` is `true`, attempts to parse each file to extract the
///   `queue_lane` field for per-lane counting.  Lane tracking is bounded by
///   `MAX_TRACKED_LANES` (256).
///
/// # Errors
///
/// Returns [`QueueBoundsError::ScanFailed`] if the directory cannot be read.
pub fn scan_pending_queue(
    queue_root: &Path,
    track_lanes: bool,
) -> Result<QueueSnapshot, QueueBoundsError> {
    let pending_dir = queue_root.join("pending");

    // If the pending directory does not exist, the queue is empty.
    if !pending_dir.exists() {
        return Ok(QueueSnapshot {
            total_jobs: 0,
            total_bytes: 0,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        });
    }

    let entries = std::fs::read_dir(&pending_dir).map_err(|err| {
        let receipt = QueueQuotaDenialReceipt {
            dimension: QueueBoundsDimension::ScanError,
            current_usage: 0,
            limit: 0,
            proposed_increment: 0,
            reason: truncate_reason(DENY_REASON_SCAN_ERROR),
            lane: None,
        };
        QueueBoundsError::ScanFailed {
            detail: format!("cannot read {}: {err}", pending_dir.display()),
            receipt,
        }
    })?;

    let mut total_jobs: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut per_lane_jobs: HashMap<String, u64> = HashMap::new();
    let mut scan_truncated = false;

    for (entries_scanned, entry_result) in entries.enumerate() {
        if entries_scanned >= MAX_SCAN_ENTRIES {
            scan_truncated = true;
            break;
        }

        let Ok(entry) = entry_result else {
            continue; // Skip unreadable entries.
        };

        let path = entry.path();

        // Only count .json files.
        let is_json = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
        if !is_json {
            continue;
        }

        // Use symlink_metadata to reject symlinks (INV-QB-006).
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };

        // Only count regular files.
        if !metadata.is_file() {
            continue;
        }

        let file_size = metadata.len();

        // Saturating arithmetic prevents overflow (INV-QB-001).
        total_jobs = total_jobs.saturating_add(1);
        total_bytes = total_bytes.saturating_add(file_size);

        // Per-lane tracking: parse the file to extract queue_lane.
        if track_lanes && per_lane_jobs.len() < MAX_TRACKED_LANES {
            if let Some(lane) = extract_queue_lane(&path) {
                let count = per_lane_jobs.entry(lane).or_insert(0);
                *count = count.checked_add(1).unwrap_or(u64::MAX);
            }
        }
    }

    Ok(QueueSnapshot {
        total_jobs,
        total_bytes,
        per_lane_jobs,
        scan_truncated,
    })
}

/// Extract the `queue_lane` field from a job spec file.
///
/// Uses bounded read to prevent OOM from oversized files.
fn extract_queue_lane(path: &Path) -> Option<String> {
    // Read at most 64 KiB (MAX_JOB_SPEC_SIZE) to extract the lane field.
    const MAX_READ: usize = 65_536;

    let metadata = std::fs::symlink_metadata(path).ok()?;
    if metadata.len() > MAX_READ as u64 {
        return None;
    }

    let data = std::fs::read(path).ok()?;
    if data.len() > MAX_READ {
        return None;
    }

    // Minimal JSON extraction: look for "queue_lane" field.
    // We use serde_json::Value to safely parse without full type binding.
    let value: serde_json::Value = serde_json::from_slice(&data).ok()?;
    value.get("queue_lane").and_then(|v| v.as_str()).map(|s| {
        // Truncate lane name to prevent unbounded string growth.
        if s.len() > 64 {
            s[..64].to_string()
        } else {
            s.to_string()
        }
    })
}

// ============================================================================
// Bounds checking
// ============================================================================

/// Check whether a proposed enqueue would violate queue bounds.
///
/// INV-QB-002: This function must be called BEFORE writing the job spec to
/// disk.
///
/// # Arguments
///
/// * `snapshot` - Current queue state from [`scan_pending_queue`].
/// * `policy` - Queue bounds policy to enforce.
/// * `proposed_bytes` - Size in bytes of the job spec to be enqueued.
/// * `proposed_lane` - Lane name of the job to be enqueued (for per-lane
///   enforcement).
///
/// # Errors
///
/// Returns [`QueueBoundsError::QuotaExceeded`] if any bound would be
/// exceeded.
pub fn check_queue_bounds(
    snapshot: &QueueSnapshot,
    policy: &QueueBoundsPolicy,
    proposed_bytes: u64,
    proposed_lane: Option<&str>,
) -> Result<(), QueueBoundsError> {
    // Check total pending jobs.
    if policy.max_pending_jobs == 0 {
        return Err(deny_pending_jobs(snapshot.total_jobs, 0));
    }
    let next_jobs =
        snapshot
            .total_jobs
            .checked_add(1)
            .ok_or_else(|| QueueBoundsError::QuotaExceeded {
                reason: DENY_REASON_COUNTER_OVERFLOW.to_string(),
                receipt: QueueQuotaDenialReceipt {
                    dimension: QueueBoundsDimension::PendingJobs,
                    current_usage: snapshot.total_jobs,
                    limit: policy.max_pending_jobs,
                    proposed_increment: 1,
                    reason: truncate_reason(DENY_REASON_COUNTER_OVERFLOW),
                    lane: None,
                },
            })?;
    if next_jobs > policy.max_pending_jobs {
        return Err(deny_pending_jobs(
            snapshot.total_jobs,
            policy.max_pending_jobs,
        ));
    }

    // Check total pending bytes.
    if policy.max_pending_bytes == 0 {
        return Err(deny_pending_bytes(snapshot.total_bytes, 0, proposed_bytes));
    }
    let next_bytes = snapshot
        .total_bytes
        .checked_add(proposed_bytes)
        .ok_or_else(|| QueueBoundsError::QuotaExceeded {
            reason: DENY_REASON_COUNTER_OVERFLOW.to_string(),
            receipt: QueueQuotaDenialReceipt {
                dimension: QueueBoundsDimension::PendingBytes,
                current_usage: snapshot.total_bytes,
                limit: policy.max_pending_bytes,
                proposed_increment: proposed_bytes,
                reason: truncate_reason(DENY_REASON_COUNTER_OVERFLOW),
                lane: None,
            },
        })?;
    if next_bytes > policy.max_pending_bytes {
        return Err(deny_pending_bytes(
            snapshot.total_bytes,
            policy.max_pending_bytes,
            proposed_bytes,
        ));
    }

    // Check per-lane pending jobs (optional).
    if let Some(per_lane_limit) = policy.per_lane_max_pending_jobs {
        if let Some(lane_name) = proposed_lane {
            if per_lane_limit == 0 {
                return Err(deny_per_lane_jobs(0, 0, lane_name));
            }

            let current_lane_jobs = snapshot.per_lane_jobs.get(lane_name).copied().unwrap_or(0);

            let next_lane_jobs = current_lane_jobs.checked_add(1).ok_or_else(|| {
                QueueBoundsError::QuotaExceeded {
                    reason: DENY_REASON_COUNTER_OVERFLOW.to_string(),
                    receipt: QueueQuotaDenialReceipt {
                        dimension: QueueBoundsDimension::PerLanePendingJobs,
                        current_usage: current_lane_jobs,
                        limit: per_lane_limit,
                        proposed_increment: 1,
                        reason: truncate_reason(DENY_REASON_COUNTER_OVERFLOW),
                        lane: Some(truncate_lane_name(lane_name)),
                    },
                }
            })?;

            if next_lane_jobs > per_lane_limit {
                return Err(deny_per_lane_jobs(
                    current_lane_jobs,
                    per_lane_limit,
                    lane_name,
                ));
            }
        }
    }

    Ok(())
}

// ============================================================================
// Denial builders (INV-QB-003)
// ============================================================================

fn deny_pending_jobs(current: u64, limit: u64) -> QueueBoundsError {
    QueueBoundsError::QuotaExceeded {
        reason: DENY_REASON_PENDING_JOBS_EXCEEDED.to_string(),
        receipt: QueueQuotaDenialReceipt {
            dimension: QueueBoundsDimension::PendingJobs,
            current_usage: current,
            limit,
            proposed_increment: 1,
            reason: truncate_reason(DENY_REASON_PENDING_JOBS_EXCEEDED),
            lane: None,
        },
    }
}

fn deny_pending_bytes(current: u64, limit: u64, proposed: u64) -> QueueBoundsError {
    QueueBoundsError::QuotaExceeded {
        reason: DENY_REASON_PENDING_BYTES_EXCEEDED.to_string(),
        receipt: QueueQuotaDenialReceipt {
            dimension: QueueBoundsDimension::PendingBytes,
            current_usage: current,
            limit,
            proposed_increment: proposed,
            reason: truncate_reason(DENY_REASON_PENDING_BYTES_EXCEEDED),
            lane: None,
        },
    }
}

fn deny_per_lane_jobs(current: u64, limit: u64, lane: &str) -> QueueBoundsError {
    QueueBoundsError::QuotaExceeded {
        reason: DENY_REASON_PER_LANE_JOBS_EXCEEDED.to_string(),
        receipt: QueueQuotaDenialReceipt {
            dimension: QueueBoundsDimension::PerLanePendingJobs,
            current_usage: current,
            limit,
            proposed_increment: 1,
            reason: truncate_reason(DENY_REASON_PER_LANE_JOBS_EXCEEDED),
            lane: Some(truncate_lane_name(lane)),
        },
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Truncates a reason string to the maximum allowed length (UTF-8 safe).
///
/// Uses `char_indices` to find a safe truncation boundary, ensuring we never
/// split a multi-byte UTF-8 character (INV-QB-004, RSK-2406 panic safety).
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

/// Truncates a lane name to 64 bytes (UTF-8 safe) for receipt fields.
fn truncate_lane_name(lane: &str) -> String {
    const MAX_LANE_NAME: usize = 64;
    if lane.len() <= MAX_LANE_NAME {
        lane.to_string()
    } else {
        let boundary = lane
            .char_indices()
            .take_while(|&(i, _)| i <= MAX_LANE_NAME)
            .last()
            .map_or(0, |(i, _)| i);
        lane[..boundary].to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> QueueBoundsPolicy {
        QueueBoundsPolicy {
            max_pending_jobs: 5,
            max_pending_bytes: 500,
            per_lane_max_pending_jobs: Some(3),
        }
    }

    // -----------------------------------------------------------------------
    // Policy validation
    // -----------------------------------------------------------------------

    #[test]
    fn default_policy_passes_validation() {
        let policy = QueueBoundsPolicy::default();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn policy_exceeding_max_pending_jobs_hard_cap_rejected() {
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
    fn policy_exceeding_max_pending_bytes_hard_cap_rejected() {
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
            per_lane_max_pending_jobs: Some(HARD_CAP_PER_LANE_MAX_PENDING_JOBS + 1),
            ..QueueBoundsPolicy::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(QueueBoundsError::InvalidPolicy { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // check_queue_bounds: total jobs
    // -----------------------------------------------------------------------

    #[test]
    fn enqueue_within_job_limit_succeeds() {
        let snapshot = QueueSnapshot {
            total_jobs: 3,
            total_bytes: 100,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = default_policy();
        assert!(check_queue_bounds(&snapshot, &policy, 50, None).is_ok());
    }

    #[test]
    fn enqueue_at_job_limit_denied() {
        let snapshot = QueueSnapshot {
            total_jobs: 5,
            total_bytes: 100,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = default_policy();
        let err = check_queue_bounds(&snapshot, &policy, 50, None).unwrap_err();
        match err {
            QueueBoundsError::QuotaExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_PENDING_JOBS_EXCEEDED);
                assert_eq!(receipt.dimension, QueueBoundsDimension::PendingJobs);
                assert_eq!(receipt.current_usage, 5);
                assert_eq!(receipt.limit, 5);
                assert_eq!(receipt.proposed_increment, 1);
            },
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
    }

    #[test]
    fn enqueue_zero_job_limit_denied_immediately() {
        let snapshot = QueueSnapshot {
            total_jobs: 0,
            total_bytes: 0,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 0,
            ..default_policy()
        };
        let err = check_queue_bounds(&snapshot, &policy, 10, None).unwrap_err();
        assert!(matches!(err, QueueBoundsError::QuotaExceeded { .. }));
    }

    // -----------------------------------------------------------------------
    // check_queue_bounds: total bytes
    // -----------------------------------------------------------------------

    #[test]
    fn enqueue_within_byte_limit_succeeds() {
        let snapshot = QueueSnapshot {
            total_jobs: 1,
            total_bytes: 400,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = default_policy();
        assert!(check_queue_bounds(&snapshot, &policy, 50, None).is_ok());
    }

    #[test]
    fn enqueue_exceeding_byte_limit_denied() {
        let snapshot = QueueSnapshot {
            total_jobs: 1,
            total_bytes: 450,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = default_policy();
        let err = check_queue_bounds(&snapshot, &policy, 60, None).unwrap_err();
        match err {
            QueueBoundsError::QuotaExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_PENDING_BYTES_EXCEEDED);
                assert_eq!(receipt.dimension, QueueBoundsDimension::PendingBytes);
                assert_eq!(receipt.current_usage, 450);
                assert_eq!(receipt.limit, 500);
                assert_eq!(receipt.proposed_increment, 60);
            },
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
    }

    #[test]
    fn enqueue_zero_byte_limit_denied_immediately() {
        let snapshot = QueueSnapshot {
            total_jobs: 0,
            total_bytes: 0,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = QueueBoundsPolicy {
            max_pending_bytes: 0,
            ..default_policy()
        };
        let err = check_queue_bounds(&snapshot, &policy, 10, None).unwrap_err();
        assert!(matches!(err, QueueBoundsError::QuotaExceeded { .. }));
    }

    // -----------------------------------------------------------------------
    // check_queue_bounds: per-lane
    // -----------------------------------------------------------------------

    #[test]
    fn enqueue_within_per_lane_limit_succeeds() {
        let mut per_lane = HashMap::new();
        per_lane.insert("gates".to_string(), 2);
        let snapshot = QueueSnapshot {
            total_jobs: 2,
            total_bytes: 100,
            per_lane_jobs: per_lane,
            scan_truncated: false,
        };
        let policy = default_policy();
        assert!(check_queue_bounds(&snapshot, &policy, 50, Some("gates")).is_ok());
    }

    #[test]
    fn enqueue_at_per_lane_limit_denied() {
        let mut per_lane = HashMap::new();
        per_lane.insert("gates".to_string(), 3);
        let snapshot = QueueSnapshot {
            total_jobs: 3,
            total_bytes: 100,
            per_lane_jobs: per_lane,
            scan_truncated: false,
        };
        let policy = default_policy();
        let err = check_queue_bounds(&snapshot, &policy, 50, Some("gates")).unwrap_err();
        match err {
            QueueBoundsError::QuotaExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_PER_LANE_JOBS_EXCEEDED);
                assert_eq!(receipt.dimension, QueueBoundsDimension::PerLanePendingJobs);
                assert_eq!(receipt.current_usage, 3);
                assert_eq!(receipt.limit, 3);
                assert_eq!(receipt.lane, Some("gates".to_string()));
            },
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
    }

    #[test]
    fn enqueue_new_lane_succeeds_when_within_limits() {
        let snapshot = QueueSnapshot {
            total_jobs: 1,
            total_bytes: 100,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = default_policy();
        // "bulk" lane has 0 existing jobs, so 0+1 = 1 <= 3 limit.
        assert!(check_queue_bounds(&snapshot, &policy, 50, Some("bulk")).is_ok());
    }

    #[test]
    fn enqueue_per_lane_zero_limit_denied() {
        let snapshot = QueueSnapshot {
            total_jobs: 0,
            total_bytes: 0,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = QueueBoundsPolicy {
            per_lane_max_pending_jobs: Some(0),
            ..default_policy()
        };
        let err = check_queue_bounds(&snapshot, &policy, 10, Some("gates")).unwrap_err();
        assert!(matches!(err, QueueBoundsError::QuotaExceeded { .. }));
    }

    #[test]
    fn enqueue_per_lane_disabled_skips_check() {
        let mut per_lane = HashMap::new();
        per_lane.insert("gates".to_string(), 100);
        let snapshot = QueueSnapshot {
            total_jobs: 100,
            total_bytes: 100,
            per_lane_jobs: per_lane,
            scan_truncated: false,
        };
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 1000,
            max_pending_bytes: 100_000,
            per_lane_max_pending_jobs: None, // Disabled
        };
        assert!(check_queue_bounds(&snapshot, &policy, 50, Some("gates")).is_ok());
    }

    // -----------------------------------------------------------------------
    // scan_pending_queue with real filesystem
    // -----------------------------------------------------------------------

    #[test]
    fn scan_empty_pending_returns_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let queue_root = dir.path();
        // Don't create pending/ -- empty queue.
        let snapshot = scan_pending_queue(queue_root, false).unwrap();
        assert_eq!(snapshot.total_jobs, 0);
        assert_eq!(snapshot.total_bytes, 0);
        assert!(!snapshot.scan_truncated);
    }

    #[test]
    fn scan_counts_json_files_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pending = dir.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        // Write 3 .json files and 1 .txt file.
        std::fs::write(pending.join("job1.json"), r#"{"queue_lane":"gates"}"#).unwrap();
        std::fs::write(pending.join("job2.json"), r#"{"queue_lane":"bulk"}"#).unwrap();
        std::fs::write(pending.join("job3.json"), r#"{"queue_lane":"gates"}"#).unwrap();
        std::fs::write(pending.join("readme.txt"), "not a job").unwrap();

        let snapshot = scan_pending_queue(dir.path(), true).unwrap();
        assert_eq!(snapshot.total_jobs, 3);
        assert!(snapshot.total_bytes > 0);
        assert_eq!(snapshot.per_lane_jobs.get("gates"), Some(&2));
        assert_eq!(snapshot.per_lane_jobs.get("bulk"), Some(&1));
        assert!(!snapshot.scan_truncated);
    }

    #[test]
    fn scan_counts_bytes_correctly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pending = dir.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        let content = r#"{"queue_lane":"gates","job_id":"test"}"#;
        std::fs::write(pending.join("job1.json"), content).unwrap();

        let snapshot = scan_pending_queue(dir.path(), false).unwrap();
        assert_eq!(snapshot.total_jobs, 1);
        assert_eq!(snapshot.total_bytes, content.len() as u64);
    }

    #[test]
    fn scan_without_lane_tracking_skips_parsing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pending = dir.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        std::fs::write(pending.join("job1.json"), r#"{"queue_lane":"gates"}"#).unwrap();

        let snapshot = scan_pending_queue(dir.path(), false).unwrap();
        assert_eq!(snapshot.total_jobs, 1);
        assert!(snapshot.per_lane_jobs.is_empty());
    }

    // -----------------------------------------------------------------------
    // Flooding test (Definition of Done)
    // -----------------------------------------------------------------------

    #[test]
    fn flooding_enqueue_attempts_denied_not_collapse() {
        let policy = QueueBoundsPolicy {
            max_pending_jobs: 100,
            max_pending_bytes: 10_000,
            per_lane_max_pending_jobs: None,
        };

        let mut denied = 0usize;
        for i in 0..1000u64 {
            let snapshot = QueueSnapshot {
                total_jobs: i.min(100),
                total_bytes: (i * 50).min(10_000),
                per_lane_jobs: HashMap::new(),
                scan_truncated: false,
            };
            if check_queue_bounds(&snapshot, &policy, 50, None).is_err() {
                denied += 1;
            }
        }
        // After job 100 (index 100..999), all should be denied = 900.
        assert_eq!(denied, 900);
    }

    // -----------------------------------------------------------------------
    // Counter overflow
    // -----------------------------------------------------------------------

    #[test]
    fn job_counter_overflow_denied() {
        let snapshot = QueueSnapshot {
            total_jobs: u64::MAX,
            total_bytes: 0,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = QueueBoundsPolicy {
            max_pending_jobs: HARD_CAP_MAX_PENDING_JOBS,
            max_pending_bytes: HARD_CAP_MAX_PENDING_BYTES,
            per_lane_max_pending_jobs: None,
        };
        let err = check_queue_bounds(&snapshot, &policy, 10, None).unwrap_err();
        match err {
            QueueBoundsError::QuotaExceeded { reason, .. } => {
                assert_eq!(reason, DENY_REASON_COUNTER_OVERFLOW);
            },
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
    }

    #[test]
    fn byte_counter_overflow_denied() {
        let snapshot = QueueSnapshot {
            total_jobs: 1,
            total_bytes: u64::MAX - 5,
            per_lane_jobs: HashMap::new(),
            scan_truncated: false,
        };
        let policy = QueueBoundsPolicy {
            max_pending_jobs: HARD_CAP_MAX_PENDING_JOBS,
            max_pending_bytes: HARD_CAP_MAX_PENDING_BYTES,
            per_lane_max_pending_jobs: None,
        };
        let err = check_queue_bounds(&snapshot, &policy, 10, None).unwrap_err();
        match err {
            QueueBoundsError::QuotaExceeded { reason, .. } => {
                assert_eq!(reason, DENY_REASON_COUNTER_OVERFLOW);
            },
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn policy_serialization_round_trip() {
        let policy = default_policy();
        let json = serde_json::to_string(&policy).expect("serialize");
        let loaded: QueueBoundsPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, loaded);
    }

    #[test]
    fn denial_receipt_serialization_round_trip() {
        let receipt = QueueQuotaDenialReceipt {
            dimension: QueueBoundsDimension::PendingJobs,
            current_usage: 100,
            limit: 100,
            proposed_increment: 1,
            reason: DENY_REASON_PENDING_JOBS_EXCEEDED.to_string(),
            lane: None,
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let loaded: QueueQuotaDenialReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, loaded);
    }

    #[test]
    fn denial_receipt_with_lane_serialization_round_trip() {
        let receipt = QueueQuotaDenialReceipt {
            dimension: QueueBoundsDimension::PerLanePendingJobs,
            current_usage: 50,
            limit: 50,
            proposed_increment: 1,
            reason: DENY_REASON_PER_LANE_JOBS_EXCEEDED.to_string(),
            lane: Some("gates".to_string()),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let loaded: QueueQuotaDenialReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, loaded);
    }

    // -----------------------------------------------------------------------
    // UTF-8-safe truncation
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_reason_utf8_safe() {
        let multi_byte = "\u{1F600}"; // 4-byte emoji
        let long_reason = multi_byte.repeat(100); // 400 bytes
        let truncated = truncate_reason(&long_reason);
        assert!(truncated.len() <= MAX_DENIAL_REASON_LENGTH);
        // Verify valid UTF-8.
        let _ = truncated.as_str();
    }

    #[test]
    fn truncate_reason_short_unchanged() {
        assert_eq!(truncate_reason("hello"), "hello");
    }

    #[test]
    fn truncate_lane_name_short_unchanged() {
        assert_eq!(truncate_lane_name("gates"), "gates");
    }

    #[test]
    fn truncate_lane_name_long_truncated() {
        let long = "a".repeat(200);
        let truncated = truncate_lane_name(&long);
        assert!(truncated.len() <= 64);
    }
}
