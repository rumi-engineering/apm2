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

use std::collections::BTreeMap;
use std::io::Read as _;

use serde::{Deserialize, Serialize};

use super::gc_receipt::GcReceiptV1;
use super::receipt::{DenialReasonCode, FacJobOutcome, FacJobReceiptV1};
use super::receipt_index::open_no_follow;

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
}

/// Input parameters for metrics computation.
#[derive(Debug, Clone)]
pub struct MetricsInput<'a> {
    /// Job receipts within the observation window.
    pub job_receipts: &'a [FacJobReceiptV1],
    /// GC receipts within the observation window.
    pub gc_receipts: &'a [GcReceiptV1],
    /// Observation window start (Unix epoch seconds, inclusive).
    pub since_epoch_secs: u64,
    /// Observation window end (Unix epoch seconds, inclusive).
    pub until_epoch_secs: u64,
}

// =============================================================================
// Computation
// =============================================================================

/// Compute a [`MetricsSummary`] from the provided receipt data.
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

    // -- Job receipt aggregation --
    let mut durations: Vec<u64> = Vec::new();

    for receipt in input.job_receipts {
        summary.total_receipts += 1;

        match receipt.outcome {
            FacJobOutcome::Completed => {
                summary.completed_jobs += 1;
                // Collect duration for percentile computation.
                if let Some(ref cost) = receipt.observed_cost {
                    durations.push(cost.duration_ms);
                }
            },
            FacJobOutcome::Denied => {
                summary.denied_jobs += 1;
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
                summary.quarantined_jobs += 1;
            },
            FacJobOutcome::Cancelled | FacJobOutcome::CancellationRequested => {
                summary.cancelled_jobs += 1;
            },
        }
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

/// Maximum number of GC receipts to load into memory.
///
/// Prevents unbounded memory growth from a large number of GC receipts.
/// At ~256 KiB per receipt and 4,096 receipts, the worst-case memory is
/// ~1 GiB.
pub const MAX_GC_RECEIPTS_LOADED: usize = 4_096;

/// Load GC receipts from the receipts directory, filtering by
/// `since_epoch_secs`.
///
/// Scans `.json` files in `receipts_dir`, attempts to parse each as a
/// `GcReceiptV1`, and returns those with `timestamp_secs >= since_epoch_secs`.
///
/// Bounded by [`MAX_GC_RECEIPT_SCAN_FILES`] directory entries,
/// [`MAX_GC_RECEIPTS_LOADED`] loaded receipts, and
/// `MAX_GC_RECEIPT_READ_SIZE` per file. Parse failures are silently skipped
/// (GC receipts share the directory with job receipts; we only care about
/// files matching the GC schema).
///
/// # Security
///
/// File reads use `open_no_follow` (`O_NOFOLLOW` on Unix) to prevent
/// symlink-following attacks (MAJOR-1). An attacker placing a symlink in
/// the receipt directory cannot trigger arbitrary file reads.
#[must_use]
pub fn load_gc_receipts(receipts_dir: &std::path::Path, since_epoch_secs: u64) -> Vec<GcReceiptV1> {
    let mut results = Vec::new();
    let Ok(entries) = std::fs::read_dir(receipts_dir) else {
        return results;
    };

    let mut scanned: usize = 0;
    for entry in entries {
        scanned = scanned.saturating_add(1);
        if scanned > MAX_GC_RECEIPT_SCAN_FILES {
            break;
        }

        // Cap loaded results to prevent unbounded memory growth.
        if results.len() >= MAX_GC_RECEIPTS_LOADED {
            break;
        }

        let Ok(entry) = entry else {
            continue;
        };

        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        // Skip index subdirectory entries.
        if path.is_dir() {
            continue;
        }

        // Open with O_NOFOLLOW to prevent symlink-following attacks
        // (MAJOR-1 fix). This matches the pattern used in
        // `load_receipt_bounded` from receipt_index.rs.
        let Ok(file) = open_no_follow(&path) else {
            continue;
        };
        let Ok(file_meta) = file.metadata() else {
            continue;
        };
        if file_meta.len() > MAX_GC_RECEIPT_READ_SIZE {
            continue;
        }

        let mut buf = Vec::new();
        let cap = MAX_GC_RECEIPT_READ_SIZE;
        if file.take(cap + 1).read_to_end(&mut buf).is_err() {
            continue;
        }
        if buf.len() as u64 > cap {
            continue;
        }

        // Try parsing as GC receipt. Skip files that don't match.
        let Ok(receipt) = serde_json::from_slice::<GcReceiptV1>(&buf) else {
            continue;
        };

        if receipt.schema != super::gc_receipt::GC_RECEIPT_SCHEMA {
            continue;
        }

        if receipt.timestamp_secs >= since_epoch_secs {
            results.push(receipt);
        }
    }

    results
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
            htf_time_envelope_ns: None,
            node_fingerprint: None,
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
        let results = load_gc_receipts(receipts_dir, 0);
        assert!(
            results.is_empty(),
            "load_gc_receipts must not follow symlinks (got {} results)",
            results.len()
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

        let results = load_gc_receipts(receipts_dir, 1000);
        assert_eq!(results.len(), 1, "should load one GC receipt");
        assert_eq!(results[0].timestamp_secs, 2000);
    }

    // Compile-time assertion: load cap must not exceed scan cap.
    const _: () = {
        assert!(MAX_GC_RECEIPTS_LOADED > 0);
        assert!(MAX_GC_RECEIPTS_LOADED <= MAX_GC_RECEIPT_SCAN_FILES);
    };
}
