//! Receipt-derived metrics for FAC observability (TCK-00551).
//!
//! This module extracts operator-facing metrics from [`FacJobReceiptV1`] and
//! [`GcReceiptV1`] data. All computation is pure (no I/O, no side effects):
//! callers provide loaded receipt data and receive a [`MetricsSummary`].
//!
//! # Metrics
//!
//! - **Throughput**: completed jobs per hour over the observation window.
//! - **Queue wait**: median and p95 wall-clock duration (from `observed_cost`).
//! - **Denial counts**: per-[`DenialReasonCode`] breakdown.
//! - **Quarantine volume**: count of quarantined jobs.
//! - **GC freed bytes**: total bytes reclaimed by GC within the window.
//! - **Disk preflight failures**: denials due to
//!   [`DenialReasonCode::InsufficientDiskSpace`].
//!
//! # Bounded Collections
//!
//! The denial-reason map is capped at [`MAX_DENIAL_REASON_ENTRIES`]. Overflow
//! is aggregated into an `"other"` bucket to keep totals accurate.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::io::Read as _;

use serde::{Deserialize, Serialize};

use super::gc_receipt::GcReceiptV1;
use super::receipt::{DenialReasonCode, FacJobOutcome, FacJobReceiptV1};
use super::receipt_index::{is_regular_file, open_no_follow};

// =============================================================================
// Constants
// =============================================================================

/// Maximum distinct denial reason entries in the summary map.
/// Overflow is aggregated into an `"other"` bucket.
pub const MAX_DENIAL_REASON_ENTRIES: usize = 64;

/// Schema identifier for the metrics summary.
pub const METRICS_SUMMARY_SCHEMA: &str = "apm2.fac.metrics_summary.v1";

// =============================================================================
// Types
// =============================================================================

/// Aggregate metrics summary derived from receipts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSummary {
    /// Schema identifier.
    pub schema: String,
    /// Observation window start (Unix epoch seconds, inclusive).
    pub since_epoch_secs: u64,
    /// Observation window end (Unix epoch seconds, inclusive).
    pub until_epoch_secs: u64,

    // -- Throughput --
    /// Total completed jobs in the window.
    pub completed_jobs: u64,
    /// Total denied jobs in the window.
    pub denied_jobs: u64,
    /// Total quarantined jobs in the window.
    pub quarantined_jobs: u64,
    /// Total cancelled jobs in the window.
    pub cancelled_jobs: u64,
    /// Total receipts scanned.
    pub total_receipts: u64,
    /// Completed jobs per hour (f64 serialised as finite number).
    /// Zero when the window duration is zero.
    pub throughput_jobs_per_hour: f64,

    // -- Queue wait / duration --
    /// Median wall-clock duration of completed jobs (milliseconds).
    /// `None` when no completed jobs have `observed_cost`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub median_duration_ms: Option<u64>,
    /// P95 wall-clock duration of completed jobs (milliseconds).
    /// `None` when no completed jobs have `observed_cost`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_duration_ms: Option<u64>,

    // -- Denial breakdown --
    /// Per-reason denial counts (`BTreeMap` for deterministic ordering).
    /// Capped at [`MAX_DENIAL_REASON_ENTRIES`]; overflow goes to `"other"`.
    pub denial_counts_by_reason: BTreeMap<String, u64>,

    // -- Disk preflight --
    /// Count of denials due to insufficient disk space.
    pub disk_preflight_failures: u64,

    // -- GC --
    /// Total bytes freed by GC in the window.
    pub gc_freed_bytes: u64,
    /// Number of GC receipts processed.
    pub gc_receipts: u64,
    /// Whether the GC receipt list was truncated due to the
    /// [`MAX_GC_RECEIPTS_LOADED`] cap.  When `true`, the GC metrics
    /// reflect only a deterministic subset (newest-first by timestamp,
    /// then content-hash tiebreaker) and operators should investigate
    /// why the receipt count exceeds the cap.
    #[serde(default)]
    pub gc_receipts_truncated: bool,

    /// Whether the job receipt list was truncated due to the caller's
    /// `MAX_METRICS_RECEIPTS` cap.  When `true`, latency percentiles
    /// and denial-reason breakdowns are computed from a partial subset
    /// of receipts, but aggregate counts (completed, denied, quarantined,
    /// cancelled, total) and throughput are still accurate because they
    /// are derived from receipt headers (not full receipt loading).
    #[serde(default)]
    pub job_receipts_truncated: bool,
}

/// Pre-counted aggregate totals derived from receipt headers.
///
/// These counts are computed from ALL headers in the observation window
/// (not subject to the receipt-loading cap), ensuring accurate aggregate
/// metrics even when full receipt loading is truncated.
#[derive(Debug, Clone, Default)]
pub struct HeaderCounts {
    /// Total completed jobs in the window (from headers).
    pub completed: u64,
    /// Total denied jobs in the window (from headers).
    pub denied: u64,
    /// Total quarantined jobs in the window (from headers).
    pub quarantined: u64,
    /// Total cancelled jobs in the window (from headers).
    pub cancelled: u64,
    /// Total receipts scanned in the window (from headers).
    pub total: u64,
}

/// Input parameters for metrics computation.
#[derive(Debug, Clone)]
pub struct MetricsInput<'a> {
    /// Job receipts within the observation window (may be truncated).
    /// Used for latency percentiles and denial-reason breakdowns.
    pub job_receipts: &'a [FacJobReceiptV1],
    /// GC receipts within the observation window.
    pub gc_receipts: &'a [GcReceiptV1],
    /// Observation window start (Unix epoch seconds, inclusive).
    pub since_epoch_secs: u64,
    /// Observation window end (Unix epoch seconds, inclusive).
    pub until_epoch_secs: u64,
    /// Pre-counted aggregate totals from ALL receipt headers in the window.
    /// When `Some`, these override the counts derived from `job_receipts`
    /// (which may be a truncated subset).  When `None`, counts are derived
    /// from `job_receipts` (backwards-compatible behavior for tests).
    pub header_counts: Option<HeaderCounts>,
}

// =============================================================================
// Computation
// =============================================================================

/// Compute a [`MetricsSummary`] from the provided receipt data.
///
/// When `input.header_counts` is `Some`, the aggregate outcome counts
/// (completed, denied, quarantined, cancelled, total) and throughput are
/// derived from the header counts (which cover ALL receipts in the window,
/// not just the truncated subset loaded for detail analysis).  Latency
/// percentiles and denial-reason breakdowns are always computed from the
/// (possibly truncated) `job_receipts` slice.
///
/// This is a pure function with no I/O. All collections are bounded.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn compute_metrics(input: &MetricsInput<'_>) -> MetricsSummary {
    let mut summary = MetricsSummary {
        schema: METRICS_SUMMARY_SCHEMA.to_string(),
        since_epoch_secs: input.since_epoch_secs,
        until_epoch_secs: input.until_epoch_secs,
        ..MetricsSummary::default()
    };

    // -- Job receipt detail aggregation (from loaded receipts, may be truncated) --
    let mut durations: Vec<u64> = Vec::new();

    // Track receipt-derived counts (used as fallback when header_counts is None).
    let mut receipt_completed: u64 = 0;
    let mut receipt_denied: u64 = 0;
    let mut receipt_quarantined: u64 = 0;
    let mut receipt_cancelled: u64 = 0;
    let mut receipt_total: u64 = 0;

    for receipt in input.job_receipts {
        receipt_total += 1;

        match receipt.outcome {
            FacJobOutcome::Completed => {
                receipt_completed += 1;
                // Collect duration for percentile computation.
                if let Some(ref cost) = receipt.observed_cost {
                    durations.push(cost.duration_ms);
                }
            },
            FacJobOutcome::Denied => {
                receipt_denied += 1;
                // Aggregate denial reason.
                if let Some(reason) = receipt.denial_reason {
                    let key = serialize_denial_reason(reason);
                    increment_bounded_map(&mut summary.denial_counts_by_reason, &key);
                    // Track disk preflight failures specifically.
                    if reason == DenialReasonCode::InsufficientDiskSpace {
                        summary.disk_preflight_failures += 1;
                    }
                } else {
                    increment_bounded_map(&mut summary.denial_counts_by_reason, "unknown");
                }
            },
            FacJobOutcome::Quarantined => {
                receipt_quarantined += 1;
            },
            FacJobOutcome::Cancelled | FacJobOutcome::CancellationRequested => {
                receipt_cancelled += 1;
            },
        }
    }

    // -- Aggregate counts: prefer header_counts (covers ALL receipts) --
    if let Some(ref hc) = input.header_counts {
        summary.completed_jobs = hc.completed;
        summary.denied_jobs = hc.denied;
        summary.quarantined_jobs = hc.quarantined;
        summary.cancelled_jobs = hc.cancelled;
        summary.total_receipts = hc.total;
    } else {
        // Fallback: derive from loaded receipts (backwards-compatible).
        summary.completed_jobs = receipt_completed;
        summary.denied_jobs = receipt_denied;
        summary.quarantined_jobs = receipt_quarantined;
        summary.cancelled_jobs = receipt_cancelled;
        summary.total_receipts = receipt_total;
    }

    // -- Duration percentiles --
    if !durations.is_empty() {
        durations.sort_unstable();
        summary.median_duration_ms = Some(percentile(&durations, 50));
        summary.p95_duration_ms = Some(percentile(&durations, 95));
    }

    // -- Throughput --
    let window_secs = input
        .until_epoch_secs
        .saturating_sub(input.since_epoch_secs);
    if window_secs > 0 {
        // Avoid division by zero; use checked float conversion.
        let hours = window_secs as f64 / 3600.0;
        if hours > 0.0 {
            summary.throughput_jobs_per_hour = summary.completed_jobs as f64 / hours;
        }
    }

    // -- GC receipt aggregation --
    for gc in input.gc_receipts {
        summary.gc_receipts += 1;
        for action in &gc.actions {
            summary.gc_freed_bytes = summary.gc_freed_bytes.saturating_add(action.bytes_freed);
        }
    }

    summary
}

// =============================================================================
// Helpers
// =============================================================================

/// Serialize a `DenialReasonCode` to its stable `snake_case` string.
fn serialize_denial_reason(reason: DenialReasonCode) -> String {
    // Use serde's snake_case serialization for stable keys.
    serde_json::to_string(&reason)
        .unwrap_or_else(|_| "\"unknown\"".to_string())
        .trim_matches('"')
        .to_string()
}

/// Increment a count in a bounded `BTreeMap`. Overflow goes to `"other"`.
fn increment_bounded_map(map: &mut BTreeMap<String, u64>, key: &str) {
    if map.contains_key(key) {
        if let Some(count) = map.get_mut(key) {
            *count = count.saturating_add(1);
        }
    } else if map.len() < MAX_DENIAL_REASON_ENTRIES {
        map.insert(key.to_string(), 1);
    } else {
        // Overflow: aggregate into "other" bucket.
        let count = map.entry("other".to_string()).or_insert(0);
        *count = count.saturating_add(1);
    }
}

/// Compute the `p`-th percentile from a sorted slice.
///
/// Uses nearest-rank method. `p` must be in `[0, 100]`.
fn percentile(sorted: &[u64], p: u32) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let p = p.min(100);
    // nearest-rank: index = ceil(p/100 * n) - 1, clamped to valid range.
    let n = sorted.len();
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    let rank = (u64::from(p) * n as u64).div_ceil(100) as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted[idx]
}

// =============================================================================
// I/O helpers (loading receipts from disk)
// =============================================================================

/// Maximum number of directory entries to visit when loading GC receipts.
///
/// GC receipts share the receipt directory with job receipts. In large
/// directories, GC receipt files may appear after many job receipt entries in
/// the directory enumeration. A limit of 65,536 total directory entries
/// (matching [`super::receipt_index::MAX_REBUILD_SCAN_FILES`]) ensures GC
/// receipts are found in all but the most extreme cases. This is a
/// defense-in-depth bound, not a correctness guarantee — operators with
/// extremely large receipt directories should periodically reindex or
/// increase this constant.
pub const MAX_GC_RECEIPT_SCAN_FILES: usize = 65_536;

/// Maximum GC receipt file size to read (256 KiB).
const MAX_GC_RECEIPT_READ_SIZE: u64 = 256 * 1024;

/// Maximum number of GC receipts to retain in memory at any time.
///
/// Enforced *during* collection via a bounded min-heap (not just
/// post-collection truncation), so in-memory receipt count never exceeds
/// this constant regardless of how many files match on disk.  At ~256 KiB
/// per receipt and 4,096 entries, the worst-case memory for the receipt
/// set is ~1 GiB.
pub const MAX_GC_RECEIPTS_LOADED: usize = 4_096;

/// Maximum number of shard subdirectories to visit when loading GC receipts.
///
/// GC receipts are stored in a sharded layout: `receipts/<2-char-hex-prefix>/
/// <remaining-hash>.json`.  There are at most 256 possible hex-prefix shards,
/// so a limit of 512 provides generous headroom while preventing unbounded
/// directory traversal of attacker-created directories.
const MAX_GC_SHARD_DIRS: usize = 512;

/// Wrapper for `GcReceiptV1` that orders by "newness" for use in a bounded
/// min-heap.  The [`Ord`] implementation defines *ascending* newness:
/// `(timestamp_secs ASC, content_hash DESC)`.  When wrapped in
/// [`std::cmp::Reverse`] inside a [`BinaryHeap`] (which is a max-heap),
/// the *oldest* (least new) receipt sits at the heap root and is evicted
/// first, ensuring the heap retains the newest `MAX_GC_RECEIPTS_LOADED`
/// receipts at all times during scanning.
///
/// Only the comparison key fields (`timestamp_secs`, `content_hash`) are
/// used for ordering; the full receipt is carried along for extraction.
struct GcReceiptHeapEntry(GcReceiptV1);

impl PartialEq for GcReceiptHeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.timestamp_secs == other.0.timestamp_secs
            && self.0.content_hash == other.0.content_hash
    }
}

impl Eq for GcReceiptHeapEntry {}

impl PartialOrd for GcReceiptHeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GcReceiptHeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Ascending newness: higher timestamp = newer = greater.
        // For equal timestamps, *lower* content_hash = newer (comes first
        // in the final descending sort), so we reverse the hash comparison.
        self.0
            .timestamp_secs
            .cmp(&other.0.timestamp_secs)
            .then_with(|| other.0.content_hash.cmp(&self.0.content_hash))
    }
}

/// Result of loading GC receipts from disk.
#[derive(Debug, Clone)]
pub struct LoadGcReceiptsResult {
    /// The loaded GC receipts, sorted deterministically by
    /// `(timestamp_secs DESC, content_hash ASC)` (newest first).
    pub receipts: Vec<GcReceiptV1>,
    /// Whether the result was truncated due to the
    /// [`MAX_GC_RECEIPTS_LOADED`] cap.  When `true`, only the newest
    /// `MAX_GC_RECEIPTS_LOADED` receipts (by timestamp descending, then
    /// content-hash tiebreaker) are included — older receipts beyond the
    /// cap are discarded.
    pub truncated: bool,
}

/// Insert a receipt into the bounded min-heap used by [`load_gc_receipts`].
///
/// If the heap has fewer than [`MAX_GC_RECEIPTS_LOADED`] entries, the receipt
/// is pushed unconditionally.  If the heap is full, the new receipt replaces
/// the oldest entry when it is strictly newer; otherwise it is discarded.
/// `truncated` is set to `true` whenever any receipt is discarded (whether the
/// new one or an evicted old one).
fn gc_heap_insert(
    heap: &mut BinaryHeap<Reverse<GcReceiptHeapEntry>>,
    receipt: GcReceiptV1,
    truncated: &mut bool,
) {
    let entry = Reverse(GcReceiptHeapEntry(receipt));
    if heap.len() < MAX_GC_RECEIPTS_LOADED {
        heap.push(entry);
    } else if let Some(min) = heap.peek() {
        // `entry.0` is the new receipt's heap entry.
        // `min.0` is the current oldest receipt's heap entry.
        // If the new receipt is newer (greater in our Ord), evict the oldest.
        if entry.0 > min.0 {
            heap.pop();
            heap.push(entry);
        }
        // Either the old min was evicted or the new entry was discarded —
        // in both cases a receipt was dropped, so mark truncated.
        *truncated = true;
    }
}

/// Load GC receipts from the receipts directory, filtering by
/// `since_epoch_secs`.
///
/// Scans the sharded hash-prefix subdirectory layout that
/// [`super::gc_receipt::persist_gc_receipt`] produces:
/// `receipts_dir/<2-char-hex-prefix>/<remaining-hash>.json`.  Also scans
/// top-level `.json` files for backward compatibility with any legacy
/// flat-layout receipts.
///
/// Bounded by [`MAX_GC_RECEIPT_SCAN_FILES`] total directory entries
/// (across all shards), [`MAX_GC_RECEIPTS_LOADED`] loaded receipts, and
/// `MAX_GC_RECEIPT_READ_SIZE` per file.  Parse failures are silently
/// skipped (GC receipts share the directory with job receipts; we only
/// care about files matching the GC schema).
///
/// # Bounded collection via min-heap
///
/// To enforce the [`MAX_GC_RECEIPTS_LOADED`] cap *during* collection
/// (not just after), a bounded min-heap is used.  The heap is keyed by
/// "newness" (ascending `timestamp_secs`, descending `content_hash`) so
/// the *oldest* receipt sits at the root.  When a new receipt is found:
///
/// 1. If the heap has fewer than `MAX_GC_RECEIPTS_LOADED` entries, push.
/// 2. If the heap is full and the new receipt is *newer* than the root
///    (oldest), pop the root and push the new receipt.
/// 3. Otherwise the new receipt is discarded and `truncated` is set.
///
/// After scanning, the heap is drained into a `Vec` and sorted
/// descending (newest first by `timestamp_secs`, then ascending
/// `content_hash` as tiebreaker) — producing the same deterministic
/// result as the previous collect-sort-truncate approach, but with
/// worst-case memory bounded to `MAX_GC_RECEIPTS_LOADED` receipts
/// (~1 GiB at 256 KiB per receipt and 4,096 entries).
///
/// # Security
///
/// - File reads use `open_no_follow` (`O_NOFOLLOW | O_NONBLOCK` on Unix) to
///   prevent symlink-following and FIFO blocking attacks.
/// - After `open_no_follow`, the fd is checked via `is_regular_file` (`fstat`)
///   to reject FIFOs, device nodes, sockets, and directories (MINOR-2 fix).
/// - Shard directory validation requires exactly 2-character lowercase hex
///   names to prevent path traversal through crafted directory names.
/// - Shard directory entries are checked via `DirEntry::file_type()` (which
///   does NOT follow symlinks on Linux) to reject symlinked shard directories
///   (MAJOR-1 fix).
/// - Both shard directories visited and total file entries scanned are bounded
///   to prevent unbounded traversal.
#[must_use]
pub fn load_gc_receipts(
    receipts_dir: &std::path::Path,
    since_epoch_secs: u64,
) -> LoadGcReceiptsResult {
    // Bounded min-heap: `Reverse` turns the max-heap into a min-heap
    // by "newness", so the oldest (least desirable) receipt is at the root.
    let mut heap: BinaryHeap<Reverse<GcReceiptHeapEntry>> =
        BinaryHeap::with_capacity(MAX_GC_RECEIPTS_LOADED.saturating_add(1));
    let mut truncated = false;
    let mut total_scanned: usize = 0;

    // Phase 1: Scan sharded subdirectories (canonical layout from
    // persist_gc_receipt). Layout: `receipts_dir/<2-hex>/<rest>.json`.
    let mut shard_dirs_visited: usize = 0;
    if let Ok(top_entries) = std::fs::read_dir(receipts_dir) {
        for top_entry in top_entries {
            // Global scan cap.
            total_scanned = total_scanned.saturating_add(1);
            if total_scanned > MAX_GC_RECEIPT_SCAN_FILES {
                break;
            }

            let Ok(top_entry) = top_entry else {
                continue;
            };

            let top_path = top_entry.path();

            // Check if this is a 2-character hex shard directory.
            let Some(dir_name) = top_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            // MAJOR-1 fix: Use `DirEntry::file_type()` which on Linux uses
            // `d_type` from the dirent and does NOT follow symlinks.  This
            // rejects symlinked shard directories that could redirect
            // traversal outside the receipts root.  `entry.path().is_dir()`
            // follows symlinks and is therefore unsafe here.
            let Ok(entry_type) = top_entry.file_type() else {
                continue;
            };
            if dir_name.len() == 2
                && dir_name.bytes().all(|b| b.is_ascii_hexdigit())
                && entry_type.is_dir()
            {
                // This is a shard directory — scan its contents.
                shard_dirs_visited = shard_dirs_visited.saturating_add(1);
                if shard_dirs_visited > MAX_GC_SHARD_DIRS {
                    break;
                }

                let Ok(shard_entries) = std::fs::read_dir(&top_path) else {
                    continue;
                };

                for shard_entry in shard_entries {
                    total_scanned = total_scanned.saturating_add(1);
                    if total_scanned > MAX_GC_RECEIPT_SCAN_FILES {
                        break;
                    }

                    let Ok(shard_entry) = shard_entry else {
                        continue;
                    };

                    let shard_path = shard_entry.path();
                    if let Some(receipt) = try_load_gc_receipt_file(&shard_path, since_epoch_secs) {
                        gc_heap_insert(&mut heap, receipt, &mut truncated);
                    }
                }
            } else {
                // Top-level .json file (legacy flat layout or job receipts).
                if let Some(receipt) = try_load_gc_receipt_file(&top_path, since_epoch_secs) {
                    gc_heap_insert(&mut heap, receipt, &mut truncated);
                }
            }
        }
    }

    // Drain the bounded heap and sort deterministically: newest first
    // (timestamp_secs DESC, content_hash ASC).
    let mut results: Vec<GcReceiptV1> = heap
        .into_sorted_vec()
        .into_iter()
        .map(|Reverse(entry)| entry.0)
        .collect();
    results.sort_by(|a, b| {
        b.timestamp_secs
            .cmp(&a.timestamp_secs)
            .then_with(|| a.content_hash.cmp(&b.content_hash))
    });

    LoadGcReceiptsResult {
        receipts: results,
        truncated,
    }
}

/// Attempt to load a single GC receipt from a file path.
///
/// Returns `Some(receipt)` if the file is a valid GC receipt with
/// `timestamp_secs >= since_epoch_secs`. Returns `None` for non-JSON files,
/// non-regular files, oversized files, parse failures, schema mismatches,
/// or receipts outside the time window.
///
/// # Security
///
/// Opens with `O_NOFOLLOW | O_NONBLOCK` and validates via `fstat` that the
/// fd refers to a regular file before reading (MINOR-2 FIFO blocking fix).
fn try_load_gc_receipt_file(path: &std::path::Path, since_epoch_secs: u64) -> Option<GcReceiptV1> {
    // Only process .json files.
    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
        return None;
    }

    // Open with O_NOFOLLOW | O_NONBLOCK to prevent symlink-following
    // and FIFO blocking attacks.
    let file = open_no_follow(path).ok()?;

    // Verify via fstat that the fd is a regular file.  Rejects FIFOs,
    // device nodes, sockets, and directories (MINOR-2 fix).
    if !is_regular_file(&file) {
        return None;
    }

    let file_meta = file.metadata().ok()?;
    if file_meta.len() > MAX_GC_RECEIPT_READ_SIZE {
        return None;
    }

    let mut buf = Vec::new();
    let cap = MAX_GC_RECEIPT_READ_SIZE;
    if file.take(cap + 1).read_to_end(&mut buf).is_err() {
        return None;
    }
    if buf.len() as u64 > cap {
        return None;
    }

    // Try parsing as GC receipt.  Skip files that don't match.
    let receipt: GcReceiptV1 = serde_json::from_slice(&buf).ok()?;

    if receipt.schema != super::gc_receipt::GC_RECEIPT_SCHEMA {
        return None;
    }

    if receipt.timestamp_secs >= since_epoch_secs {
        Some(receipt)
    } else {
        None
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::cost_model::ObservedJobCost;
    use crate::fac::receipt::{DenialReasonCode, FacJobOutcome, FacJobReceiptV1};

    fn make_job_receipt(
        outcome: FacJobOutcome,
        denial_reason: Option<DenialReasonCode>,
        duration_ms: Option<u64>,
        timestamp_secs: u64,
    ) -> FacJobReceiptV1 {
        FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: format!("test-{timestamp_secs}"),
            job_id: format!("job-{timestamp_secs}"),
            job_spec_digest: "deadbeef".to_string(),
            policy_hash: None,
            patch_digest: None,
            canonicalizer_tuple_digest: None,
            outcome,
            denial_reason,
            unsafe_direct: false,
            reason: "test".to_string(),
            moved_job_path: None,
            rfc0028_channel_boundary: None,
            eio29_queue_admission: None,
            eio29_budget_admission: None,
            stop_revoke_admission: None,
            containment: None,
            observed_cost: duration_ms.map(|ms| ObservedJobCost {
                duration_ms: ms,
                cpu_time_ms: 0,
                bytes_written: 0,
            }),
            sandbox_hardening_hash: None,
            network_policy_hash: None,
            bytes_backend: None,
            htf_time_envelope_ns: None,
            node_fingerprint: None,
            toolchain_fingerprint: None,
            timestamp_secs,
            content_hash: "abc123".to_string(),
        }
    }

    fn make_gc_receipt(timestamp_secs: u64, bytes_freed: u64) -> GcReceiptV1 {
        GcReceiptV1 {
            schema: super::super::gc_receipt::GC_RECEIPT_SCHEMA.to_string(),
            receipt_id: format!("gc-{timestamp_secs}"),
            timestamp_secs,
            before_free_bytes: 10_000_000_000,
            after_free_bytes: 10_000_000_000 + bytes_freed,
            min_free_threshold: 1_000_000_000,
            actions: vec![super::super::gc_receipt::GcAction {
                target_path: "/tmp/lane-0/target".to_string(),
                action_kind: super::super::gc_receipt::GcActionKind::LaneTarget,
                bytes_freed,
                files_deleted: 10,
                dirs_deleted: 2,
            }],
            errors: vec![],
            content_hash: "gc-hash-123".to_string(),
        }
    }

    #[test]
    fn empty_input_returns_zeroed_summary() {
        let input = MetricsInput {
            job_receipts: &[],
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 2000,
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        assert_eq!(summary.completed_jobs, 0);
        assert_eq!(summary.denied_jobs, 0);
        assert_eq!(summary.quarantined_jobs, 0);
        assert_eq!(summary.cancelled_jobs, 0);
        assert_eq!(summary.total_receipts, 0);
        assert!(summary.throughput_jobs_per_hour.abs() < f64::EPSILON);
        assert!(summary.median_duration_ms.is_none());
        assert!(summary.p95_duration_ms.is_none());
        assert!(summary.denial_counts_by_reason.is_empty());
        assert_eq!(summary.disk_preflight_failures, 0);
        assert_eq!(summary.gc_freed_bytes, 0);
        assert_eq!(summary.gc_receipts, 0);
        assert_eq!(summary.schema, METRICS_SUMMARY_SCHEMA);
    }

    #[test]
    fn throughput_computed_correctly() {
        // 10 completed jobs over 2 hours = 5 jobs/hour
        let receipts: Vec<_> = (0..10)
            .map(|i| make_job_receipt(FacJobOutcome::Completed, None, Some(100), 1000 + i))
            .collect();
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 1000 + 7200, // 2 hours
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        assert_eq!(summary.completed_jobs, 10);
        assert!((summary.throughput_jobs_per_hour - 5.0).abs() < 0.001);
    }

    #[test]
    fn zero_duration_window_yields_zero_throughput() {
        let receipts = vec![make_job_receipt(
            FacJobOutcome::Completed,
            None,
            Some(100),
            1000,
        )];
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 1000, // zero window
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        assert_eq!(summary.completed_jobs, 1);
        assert!(summary.throughput_jobs_per_hour.abs() < f64::EPSILON);
    }

    #[test]
    fn denial_counts_by_reason_aggregated() {
        let receipts = vec![
            make_job_receipt(
                FacJobOutcome::Denied,
                Some(DenialReasonCode::DigestMismatch),
                None,
                1000,
            ),
            make_job_receipt(
                FacJobOutcome::Denied,
                Some(DenialReasonCode::DigestMismatch),
                None,
                1001,
            ),
            make_job_receipt(
                FacJobOutcome::Denied,
                Some(DenialReasonCode::InsufficientDiskSpace),
                None,
                1002,
            ),
            make_job_receipt(
                FacJobOutcome::Denied,
                Some(DenialReasonCode::MalformedSpec),
                None,
                1003,
            ),
        ];
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 2000,
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        assert_eq!(summary.denied_jobs, 4);
        assert_eq!(
            summary.denial_counts_by_reason.get("digest_mismatch"),
            Some(&2)
        );
        assert_eq!(
            summary
                .denial_counts_by_reason
                .get("insufficient_disk_space"),
            Some(&1)
        );
        assert_eq!(
            summary.denial_counts_by_reason.get("malformed_spec"),
            Some(&1)
        );
        assert_eq!(summary.disk_preflight_failures, 1);
    }

    #[test]
    fn quarantine_and_cancel_counted() {
        let receipts = vec![
            make_job_receipt(FacJobOutcome::Quarantined, None, None, 1000),
            make_job_receipt(FacJobOutcome::Quarantined, None, None, 1001),
            make_job_receipt(FacJobOutcome::Cancelled, None, None, 1002),
        ];
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 2000,
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        assert_eq!(summary.quarantined_jobs, 2);
        assert_eq!(summary.cancelled_jobs, 1);
    }

    #[test]
    fn duration_percentiles_computed() {
        // Create 20 jobs with durations 100, 200, ..., 2000ms
        let receipts: Vec<_> = (1..=20)
            .map(|i| make_job_receipt(FacJobOutcome::Completed, None, Some(i * 100), 1000 + i))
            .collect();
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 2000,
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        // Median of 20 items: 50th percentile => ceil(0.5 * 20) = 10 => index 9 =>
        // value 1000
        assert_eq!(summary.median_duration_ms, Some(1000));
        // P95 of 20 items: ceil(0.95 * 20) = 19 => index 18 => value 1900
        assert_eq!(summary.p95_duration_ms, Some(1900));
    }

    #[test]
    fn gc_bytes_freed_aggregated() {
        let gc_receipts = vec![
            make_gc_receipt(1500, 500_000_000),
            make_gc_receipt(1600, 300_000_000),
        ];
        let input = MetricsInput {
            job_receipts: &[],
            gc_receipts: &gc_receipts,
            since_epoch_secs: 1000,
            until_epoch_secs: 2000,
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        assert_eq!(summary.gc_freed_bytes, 800_000_000);
        assert_eq!(summary.gc_receipts, 2);
    }

    #[test]
    fn denial_reason_map_bounded() {
        // Create more than MAX_DENIAL_REASON_ENTRIES distinct reasons.
        // We can only test with the available enum variants, so we test the
        // overflow logic directly via increment_bounded_map.
        let mut map = BTreeMap::new();
        for i in 0..MAX_DENIAL_REASON_ENTRIES {
            increment_bounded_map(&mut map, &format!("reason_{i}"));
        }
        assert_eq!(map.len(), MAX_DENIAL_REASON_ENTRIES);

        // Next insert should go to "other".
        increment_bounded_map(&mut map, "new_reason");
        assert_eq!(map.get("other"), Some(&1));
        assert!(!map.contains_key("new_reason"));
        // Total entries: MAX + 1 (for "other")
        assert_eq!(map.len(), MAX_DENIAL_REASON_ENTRIES + 1);
    }

    #[test]
    fn percentile_edge_cases() {
        assert_eq!(percentile(&[], 50), 0);
        assert_eq!(percentile(&[42], 0), 42);
        assert_eq!(percentile(&[42], 50), 42);
        assert_eq!(percentile(&[42], 100), 42);
        assert_eq!(percentile(&[10, 20, 30], 0), 10);
        assert_eq!(percentile(&[10, 20, 30], 100), 30);
    }

    #[test]
    fn summary_serializes_to_json() {
        let receipts = vec![make_job_receipt(
            FacJobOutcome::Completed,
            None,
            Some(500),
            1000,
        )];
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 4600, // 1 hour
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        let json = serde_json::to_string_pretty(&summary);
        assert!(json.is_ok(), "summary must serialize to JSON");
        let json_str = json.unwrap();
        assert!(json_str.contains("throughput_jobs_per_hour"));
        assert!(json_str.contains("completed_jobs"));
    }

    #[test]
    fn denial_without_reason_classified_as_unknown() {
        let receipts = vec![make_job_receipt(
            FacJobOutcome::Denied,
            None, // no denial reason
            None,
            1000,
        )];
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 2000,
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        assert_eq!(summary.denied_jobs, 1);
        assert_eq!(summary.denial_counts_by_reason.get("unknown"), Some(&1));
    }

    // =========================================================================
    // MAJOR-1 regression: load_gc_receipts symlink hardening
    // =========================================================================

    #[test]
    #[cfg(unix)]
    fn load_gc_receipts_rejects_symlinks() {
        // Regression test for MAJOR-1: load_gc_receipts must not follow
        // symlinks. A symlink in the receipts directory must not cause
        // arbitrary file reads.
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create a target file that looks like a GC receipt.
        let target_dir = tmp.path().join("targets");
        std::fs::create_dir_all(&target_dir).expect("mkdir");
        let gc = make_gc_receipt(2000, 100);
        let gc_bytes = serde_json::to_vec_pretty(&gc).expect("ser");
        let target_path = target_dir.join("real_gc.json");
        std::fs::write(&target_path, &gc_bytes).expect("write");

        // Create a symlink in receipts_dir pointing to the target.
        let symlink_path = receipts_dir.join("symlinked_gc.json");
        std::os::unix::fs::symlink(&target_path, &symlink_path).expect("symlink");

        // load_gc_receipts must NOT follow the symlink and thus return
        // an empty result (since the only .json file is a symlink).
        let result = load_gc_receipts(receipts_dir, 0);
        assert!(
            result.receipts.is_empty(),
            "load_gc_receipts must not follow symlinks (got {} results)",
            result.receipts.len()
        );
    }

    #[test]
    fn load_gc_receipts_loads_regular_files() {
        // Positive test: load_gc_receipts correctly loads regular GC receipt
        // files from the directory.
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let gc = make_gc_receipt(2000, 500_000);
        let gc_bytes = serde_json::to_vec_pretty(&gc).expect("ser");
        std::fs::write(receipts_dir.join("gc-receipt-1.json"), &gc_bytes).expect("write");

        let result = load_gc_receipts(receipts_dir, 1000);
        assert_eq!(result.receipts.len(), 1, "should load one GC receipt");
        assert_eq!(result.receipts[0].timestamp_secs, 2000);
    }

    // =========================================================================
    // BLOCKER-1/BLOCKER-2 regression: load_gc_receipts sharded layout
    // =========================================================================

    #[test]
    fn load_gc_receipts_finds_sharded_receipts() {
        // Regression test for BLOCKER-1/BLOCKER-2: load_gc_receipts must
        // traverse the sharded directory layout produced by persist_gc_receipt.
        // persist_gc_receipt writes: receipts/<first_2_hex>/<remaining>.json
        use crate::fac::gc_receipt::persist_gc_receipt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Use persist_gc_receipt to write a GC receipt in the canonical
        // sharded layout.
        let gc = make_gc_receipt(3000, 1_000_000);
        let receipt_path =
            persist_gc_receipt(receipts_dir, gc).expect("persist_gc_receipt should succeed");

        // Verify the receipt was written to a sharded path (not top-level).
        assert!(
            receipt_path.parent().unwrap() != receipts_dir,
            "persist_gc_receipt should write to a shard subdirectory, \
             not top-level. Path: {receipt_path:?}"
        );

        // load_gc_receipts MUST find the sharded receipt.
        let result = load_gc_receipts(receipts_dir, 0);
        assert_eq!(
            result.receipts.len(),
            1,
            "load_gc_receipts must find receipts in sharded layout \
             (found {} instead of 1)",
            result.receipts.len()
        );
        assert_eq!(result.receipts[0].timestamp_secs, 3000);
    }

    #[test]
    fn load_gc_receipts_finds_multiple_sharded_receipts() {
        // Write multiple GC receipts across different shard buckets and
        // verify all are discovered.
        use crate::fac::gc_receipt::persist_gc_receipt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create receipts with different content hashes to get different shards.
        for i in 0..5 {
            let gc = make_gc_receipt(4000 + i, (i + 1) * 100_000);
            persist_gc_receipt(receipts_dir, gc).expect("persist");
        }

        let result = load_gc_receipts(receipts_dir, 4000);
        assert_eq!(
            result.receipts.len(),
            5,
            "should find all 5 sharded GC receipts (found {})",
            result.receipts.len()
        );
    }

    #[test]
    fn load_gc_receipts_handles_mixed_sharded_and_flat() {
        // Verify load_gc_receipts finds both sharded (canonical) and flat
        // (legacy) GC receipt files.
        use crate::fac::gc_receipt::persist_gc_receipt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write one receipt via persist_gc_receipt (sharded).
        let gc_sharded = make_gc_receipt(5000, 200_000);
        persist_gc_receipt(receipts_dir, gc_sharded).expect("persist sharded");

        // Write one receipt directly to top-level (legacy flat layout).
        let gc_flat = make_gc_receipt(5001, 300_000);
        let flat_bytes = serde_json::to_vec_pretty(&gc_flat).expect("ser");
        std::fs::write(receipts_dir.join("legacy-gc-flat.json"), &flat_bytes).expect("write flat");

        let result = load_gc_receipts(receipts_dir, 5000);
        assert_eq!(
            result.receipts.len(),
            2,
            "should find both sharded and flat GC receipts (found {})",
            result.receipts.len()
        );
    }

    #[test]
    fn load_gc_receipts_filters_by_timestamp_in_shards() {
        // Verify timestamp filtering works for sharded receipts.
        use crate::fac::gc_receipt::persist_gc_receipt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write receipts with different timestamps.
        let gc_old = make_gc_receipt(1000, 50_000);
        let gc_new = make_gc_receipt(3000, 100_000);
        persist_gc_receipt(receipts_dir, gc_old).expect("persist old");
        persist_gc_receipt(receipts_dir, gc_new).expect("persist new");

        // Only the receipt at timestamp 3000 should pass the filter.
        let result = load_gc_receipts(receipts_dir, 2000);
        assert_eq!(
            result.receipts.len(),
            1,
            "should filter old receipts from sharded layout"
        );
        assert_eq!(result.receipts[0].timestamp_secs, 3000);
    }

    #[test]
    fn load_gc_receipts_ignores_non_hex_shard_dirs() {
        // Verify that directories with non-hex names are not treated as
        // shard directories (defense-in-depth against crafted dir names).
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create a directory with a non-hex name containing a GC receipt.
        let bad_dir = receipts_dir.join("zz");
        std::fs::create_dir_all(&bad_dir).expect("mkdir");
        let gc = make_gc_receipt(6000, 100);
        let gc_bytes = serde_json::to_vec_pretty(&gc).expect("ser");
        std::fs::write(bad_dir.join("receipt.json"), &gc_bytes).expect("write");

        // "zz" contains non-hex chars, so it should NOT be treated as a shard.
        let result = load_gc_receipts(receipts_dir, 0);
        assert!(
            result.receipts.is_empty(),
            "non-hex shard dirs must not be traversed"
        );
    }

    // =========================================================================
    // MINOR-2 regression: FIFO/non-regular file rejection
    // =========================================================================

    #[test]
    #[cfg(unix)]
    fn load_gc_receipts_skips_fifo_entries() {
        // Regression test for MINOR-2: load_gc_receipts must not block on
        // named pipes (FIFOs). A FIFO with a .json extension in the receipt
        // directory must be detected and skipped.
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create a named pipe (FIFO) with a .json extension.
        let fifo_path = receipts_dir.join("trap.json");
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
        assert!(fifo_path.exists(), "FIFO must exist");

        // Also create a shard dir with a FIFO inside.
        let shard_dir = receipts_dir.join("ab");
        std::fs::create_dir_all(&shard_dir).expect("mkdir");
        let fifo_in_shard = shard_dir.join("fifo-in-shard.json");
        nix::unistd::mkfifo(&fifo_in_shard, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");

        // load_gc_receipts must NOT block on the FIFO and must return
        // empty results (the only entries are FIFOs).
        let start = std::time::Instant::now();
        let result = load_gc_receipts(receipts_dir, 0);
        let elapsed = start.elapsed();

        assert!(
            result.receipts.is_empty(),
            "load_gc_receipts must skip FIFOs (got {} results)",
            result.receipts.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "load_gc_receipts must not block on FIFO: took {elapsed:?}"
        );
    }

    // =========================================================================
    // MAJOR-1 regression: symlinked shard directory must be rejected
    // =========================================================================

    #[test]
    #[cfg(unix)]
    fn load_gc_receipts_rejects_symlinked_shard_directory() {
        // Regression test for MAJOR-1 (round 5): a two-character symlinked
        // directory name (e.g., "ab") that redirects to an external directory
        // containing a valid GC receipt must be ignored by load_gc_receipts.
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create an external directory with a valid GC receipt.
        let external_dir = tmp.path().join("external_data");
        std::fs::create_dir_all(&external_dir).expect("mkdir external");
        let gc = make_gc_receipt(7000, 999_999);
        let gc_bytes = serde_json::to_vec_pretty(&gc).expect("ser");
        std::fs::write(external_dir.join("evil.json"), &gc_bytes).expect("write");

        // Create a symlink "ab" -> external_data in the receipts dir.
        // "ab" is a valid 2-char hex prefix, so the old code (using
        // path.is_dir()) would follow this symlink and traverse
        // external_data.
        let symlink_shard = receipts_dir.join("ab");
        std::os::unix::fs::symlink(&external_dir, &symlink_shard).expect("symlink");

        // Verify the symlink exists and IS seen as a directory when following.
        assert!(
            symlink_shard.is_dir(),
            "symlink target should appear as dir when following"
        );

        // load_gc_receipts must NOT follow the symlinked shard and must
        // return empty results.
        let result = load_gc_receipts(receipts_dir, 0);
        assert!(
            result.receipts.is_empty(),
            "load_gc_receipts must not follow symlinked shard directories \
             (got {} results from external dir)",
            result.receipts.len()
        );
    }

    // =========================================================================
    // MAJOR-2 regression: deterministic cap + truncation flag
    // =========================================================================

    #[test]
    fn load_gc_receipts_result_sorted_deterministically() {
        // Verify that load_gc_receipts returns receipts sorted by
        // (timestamp_secs, content_hash) regardless of filesystem order.
        use crate::fac::gc_receipt::persist_gc_receipt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write receipts with varying timestamps.
        let gc_c = make_gc_receipt(9000, 300);
        let gc_a = make_gc_receipt(7000, 100);
        let gc_b = make_gc_receipt(8000, 200);
        persist_gc_receipt(receipts_dir, gc_c).expect("persist");
        persist_gc_receipt(receipts_dir, gc_a).expect("persist");
        persist_gc_receipt(receipts_dir, gc_b).expect("persist");

        let result = load_gc_receipts(receipts_dir, 0);
        assert_eq!(result.receipts.len(), 3);
        assert!(!result.truncated, "should not be truncated");
        // Must be sorted by timestamp descending (newest first).
        assert_eq!(result.receipts[0].timestamp_secs, 9000);
        assert_eq!(result.receipts[1].timestamp_secs, 8000);
        assert_eq!(result.receipts[2].timestamp_secs, 7000);
    }

    #[test]
    fn gc_receipts_truncated_field_serializes() {
        // Verify the gc_receipts_truncated field appears in JSON output
        // when true, and defaults to false when absent.
        let mut summary = MetricsSummary {
            schema: METRICS_SUMMARY_SCHEMA.to_string(),
            gc_receipts_truncated: true,
            ..MetricsSummary::default()
        };
        let json_str = serde_json::to_string_pretty(&summary).expect("serialize");
        assert!(
            json_str.contains("\"gc_receipts_truncated\": true"),
            "gc_receipts_truncated=true must appear in JSON"
        );

        summary.gc_receipts_truncated = false;
        let json_str2 = serde_json::to_string_pretty(&summary).expect("serialize");
        assert!(
            json_str2.contains("\"gc_receipts_truncated\": false"),
            "gc_receipts_truncated=false must appear in JSON"
        );

        // Verify serde(default) allows deserialization of old JSON without
        // the field.
        let old_json = r#"{
            "schema": "apm2.fac.metrics_summary.v1",
            "since_epoch_secs": 0,
            "until_epoch_secs": 0,
            "completed_jobs": 0,
            "denied_jobs": 0,
            "quarantined_jobs": 0,
            "cancelled_jobs": 0,
            "total_receipts": 0,
            "throughput_jobs_per_hour": 0.0,
            "denial_counts_by_reason": {},
            "disk_preflight_failures": 0,
            "gc_freed_bytes": 0,
            "gc_receipts": 0
        }"#;
        let deserialized: MetricsSummary =
            serde_json::from_str(old_json).expect("deserialize old JSON");
        assert!(
            !deserialized.gc_receipts_truncated,
            "gc_receipts_truncated must default to false for old JSON"
        );
        assert!(
            !deserialized.job_receipts_truncated,
            "job_receipts_truncated must default to false for old JSON"
        );
    }

    // =========================================================================
    // MAJOR fix (round 6): header_counts override for accurate aggregates
    // =========================================================================

    #[test]
    fn header_counts_override_receipt_derived_counts() {
        // When header_counts is provided, aggregate counts must come from
        // the header pass (covering ALL receipts), not from the truncated
        // job_receipts slice.
        let receipts = vec![
            make_job_receipt(FacJobOutcome::Completed, None, Some(100), 1000),
            make_job_receipt(
                FacJobOutcome::Denied,
                Some(DenialReasonCode::DigestMismatch),
                None,
                1001,
            ),
        ];
        let header_counts = HeaderCounts {
            completed: 500,
            denied: 200,
            quarantined: 50,
            cancelled: 30,
            total: 780,
        };
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 1000 + 7200, // 2 hours
            header_counts: Some(header_counts),
        };
        let summary = compute_metrics(&input);

        // Aggregate counts must come from header_counts, not receipts.
        assert_eq!(summary.completed_jobs, 500);
        assert_eq!(summary.denied_jobs, 200);
        assert_eq!(summary.quarantined_jobs, 50);
        assert_eq!(summary.cancelled_jobs, 30);
        assert_eq!(summary.total_receipts, 780);
        // Throughput uses header_counts.completed.
        assert!((summary.throughput_jobs_per_hour - 250.0).abs() < 0.001);

        // Detail metrics still come from loaded receipts.
        assert_eq!(summary.median_duration_ms, Some(100));
        assert_eq!(
            summary.denial_counts_by_reason.get("digest_mismatch"),
            Some(&1)
        );
    }

    #[test]
    fn header_counts_none_falls_back_to_receipt_counts() {
        // When header_counts is None, counts are derived from job_receipts
        // (backwards-compatible behavior).
        let receipts = vec![
            make_job_receipt(FacJobOutcome::Completed, None, Some(200), 1000),
            make_job_receipt(FacJobOutcome::Completed, None, Some(300), 1001),
            make_job_receipt(
                FacJobOutcome::Denied,
                Some(DenialReasonCode::MalformedSpec),
                None,
                1002,
            ),
        ];
        let input = MetricsInput {
            job_receipts: &receipts,
            gc_receipts: &[],
            since_epoch_secs: 1000,
            until_epoch_secs: 2000,
            header_counts: None,
        };
        let summary = compute_metrics(&input);
        assert_eq!(summary.completed_jobs, 2);
        assert_eq!(summary.denied_jobs, 1);
        assert_eq!(summary.total_receipts, 3);
    }

    #[test]
    fn job_receipts_truncated_field_serializes() {
        let mut summary = MetricsSummary {
            schema: METRICS_SUMMARY_SCHEMA.to_string(),
            job_receipts_truncated: true,
            ..MetricsSummary::default()
        };
        let json_str = serde_json::to_string_pretty(&summary).expect("serialize");
        assert!(
            json_str.contains("\"job_receipts_truncated\": true"),
            "job_receipts_truncated=true must appear in JSON"
        );

        summary.job_receipts_truncated = false;
        let json_str2 = serde_json::to_string_pretty(&summary).expect("serialize");
        assert!(
            json_str2.contains("\"job_receipts_truncated\": false"),
            "job_receipts_truncated=false must appear in JSON"
        );
    }

    // =========================================================================
    // Bounded heap regression: gc_heap_insert memory cap during collection
    // =========================================================================

    #[test]
    fn gc_heap_insert_enforces_cap_during_collection() {
        // Regression test for MAJOR finding: the bounded min-heap must never
        // hold more than MAX_GC_RECEIPTS_LOADED entries at any point during
        // collection.  We simulate inserting more receipts than the cap and
        // verify the heap stays bounded and retains the newest entries.
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let cap = 5_usize; // Use a small cap for testing.
        // We can't change the constant, so test gc_heap_insert at the real cap
        // by testing the logic directly with a controlled heap.
        let mut heap: BinaryHeap<Reverse<GcReceiptHeapEntry>> = BinaryHeap::with_capacity(cap + 1);
        let mut truncated = false;

        // Insert exactly MAX_GC_RECEIPTS_LOADED receipts.
        for i in 0..MAX_GC_RECEIPTS_LOADED {
            let receipt = make_gc_receipt(1000 + i as u64, 100);
            gc_heap_insert(&mut heap, receipt, &mut truncated);
            assert!(
                heap.len() <= MAX_GC_RECEIPTS_LOADED,
                "heap must never exceed MAX_GC_RECEIPTS_LOADED (len={}, cap={})",
                heap.len(),
                MAX_GC_RECEIPTS_LOADED
            );
        }
        assert_eq!(heap.len(), MAX_GC_RECEIPTS_LOADED);
        assert!(!truncated, "no truncation when exactly at cap");

        // Insert one more receipt that is NEWER than the oldest in the heap.
        // The oldest has timestamp_secs = 1000.
        let newer = make_gc_receipt(999_999, 100);
        gc_heap_insert(&mut heap, newer, &mut truncated);
        assert_eq!(
            heap.len(),
            MAX_GC_RECEIPTS_LOADED,
            "heap must not grow beyond cap after insert"
        );
        assert!(truncated, "truncated must be set when a receipt is evicted");

        // Insert one more receipt that is OLDER than everything in the heap.
        // This receipt should be discarded immediately.
        let older = make_gc_receipt(1, 100);
        gc_heap_insert(&mut heap, older, &mut truncated);
        assert_eq!(
            heap.len(),
            MAX_GC_RECEIPTS_LOADED,
            "heap must stay at cap when older receipt is discarded"
        );

        // Drain and verify the newest receipt (999_999) is present and the
        // discarded receipt (timestamp=1) is not.
        let drained: Vec<GcReceiptV1> = heap
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse(entry)| entry.0)
            .collect();
        assert!(
            drained.iter().any(|r| r.timestamp_secs == 999_999),
            "newest receipt must be retained"
        );
        assert!(
            drained.iter().all(|r| r.timestamp_secs != 1),
            "oldest discarded receipt must not be in heap"
        );
    }

    #[test]
    fn gc_heap_produces_same_result_as_sort_truncate() {
        // Verify that the bounded heap approach produces the exact same
        // deterministic result as the old collect-sort-truncate approach
        // for a set of receipts exceeding the cap.
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        // Create receipts: timestamps from 1 to MAX_GC_RECEIPTS_LOADED + 100.
        let total = MAX_GC_RECEIPTS_LOADED + 100;
        let receipts: Vec<GcReceiptV1> = (1..=total)
            .map(|i| make_gc_receipt(i as u64, (i * 7) as u64))
            .collect();

        // --- Old approach: collect all, sort, truncate ---
        let mut old_results = receipts.clone();
        old_results.sort_by(|a, b| {
            b.timestamp_secs
                .cmp(&a.timestamp_secs)
                .then_with(|| a.content_hash.cmp(&b.content_hash))
        });
        old_results.truncate(MAX_GC_RECEIPTS_LOADED);

        // --- New approach: bounded heap ---
        let mut heap: BinaryHeap<Reverse<GcReceiptHeapEntry>> =
            BinaryHeap::with_capacity(MAX_GC_RECEIPTS_LOADED + 1);
        let mut truncated = false;
        for receipt in receipts {
            gc_heap_insert(&mut heap, receipt, &mut truncated);
        }
        let mut new_results: Vec<GcReceiptV1> = heap
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse(entry)| entry.0)
            .collect();
        new_results.sort_by(|a, b| {
            b.timestamp_secs
                .cmp(&a.timestamp_secs)
                .then_with(|| a.content_hash.cmp(&b.content_hash))
        });

        assert!(truncated, "should be truncated with excess receipts");
        assert_eq!(new_results.len(), old_results.len());
        for (i, (new, old)) in new_results.iter().zip(old_results.iter()).enumerate() {
            assert_eq!(
                new.timestamp_secs, old.timestamp_secs,
                "mismatch at index {i}: new ts={}, old ts={}",
                new.timestamp_secs, old.timestamp_secs
            );
            assert_eq!(
                new.content_hash, old.content_hash,
                "mismatch at index {i}: new hash={}, old hash={}",
                new.content_hash, old.content_hash
            );
        }
    }

    // Compile-time assertion: load cap must not exceed scan cap.
    const _: () = {
        assert!(MAX_GC_RECEIPTS_LOADED > 0);
        assert!(MAX_GC_RECEIPTS_LOADED <= MAX_GC_RECEIPT_SCAN_FILES);
    };
}
