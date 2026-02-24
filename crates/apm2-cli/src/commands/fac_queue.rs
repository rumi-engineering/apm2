// AGENT-AUTHORED (TCK-00535)
//! FAC queue introspection: `apm2 fac queue status`.
//!
//! Provides forensics-first queue status reporting for operators by scanning
//! queue directories with bounded reads. Shows:
//!
//! - Job counts by directory (pending, claimed, completed, denied, quarantine,
//!   cancelled).
//! - Oldest job per directory (by `enqueue_time`).
//! - Denial/quarantine stats with reason code distribution.
//!
//! # Security Model
//!
//! - Directory scans are bounded by `MAX_SCAN_ENTRIES` per directory.
//! - Job spec reads are bounded by `MAX_JOB_SPEC_SIZE`.
//! - No mutations are performed; this is a read-only command.
//!
//! # Invariants
//!
//! - [INV-QSTAT-001] All directory scans are bounded; never iterate unbounded
//!   entries.
//! - [INV-QSTAT-002] File reads use bounded I/O (take-based reader).
//! - [INV-QSTAT-003] Output is deterministic: directories reported in fixed
//!   order, stats aggregated from bounded scans.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::commands::fac::QueueStatusArgs;
use crate::commands::fac_utils::{
    MAX_SCAN_ENTRIES, read_job_spec_bounded, resolve_fac_root, resolve_queue_root,
};
use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Constants
// =============================================================================

const PENDING_DIR: &str = "pending";
const CLAIMED_DIR: &str = "claimed";
const COMPLETED_DIR: &str = "completed";
const CANCELLED_DIR: &str = "cancelled";
const DENIED_DIR: &str = "denied";
const QUARANTINE_DIR: &str = "quarantine";

/// Maximum number of denial reason codes to track in the distribution.
/// Prevents unbounded `HashMap` growth from adversarial reason codes.
const MAX_REASON_CODES: usize = 64;

/// All queue directory names in display order.
const QUEUE_DIRS: &[&str] = &[
    PENDING_DIR,
    CLAIMED_DIR,
    COMPLETED_DIR,
    DENIED_DIR,
    QUARANTINE_DIR,
    CANCELLED_DIR,
];

// =============================================================================
// Output types
// =============================================================================

/// JSON output for `apm2 fac queue status`.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct QueueStatusOutput {
    /// Per-directory counts and oldest job.
    directories: Vec<DirectoryStatus>,
    /// Denial reason code distribution (from `denied/` directory).
    denial_stats: Vec<ReasonStat>,
    /// Quarantine reason code distribution (from `quarantine/` directory).
    quarantine_stats: Vec<ReasonStat>,
    /// Total jobs across all directories.
    total_jobs: usize,
    /// Queue root path.
    queue_root: String,
}

/// Status for a single queue directory.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryStatus {
    /// Directory name (e.g., "pending").
    name: String,
    /// Number of valid `.json` job spec files successfully parsed.
    /// Only incremented after `read_job_spec_bounded` succeeds, so
    /// malformed/unreadable entries are excluded (Finding 4).
    count: usize,
    /// Number of `.json` files that failed to parse (malformed, oversized,
    /// non-regular file types, etc.). Recorded separately so operators can
    /// detect queue corruption without inflating job counts.
    malformed: usize,
    /// Whether the scan was truncated at the limit.
    scan_truncated: bool,
    /// Oldest job ID (by `enqueue_time`), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_job_id: Option<String>,
    /// Oldest job enqueue time (ISO 8601), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_enqueue_time: Option<String>,
}

/// Reason code distribution stat.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ReasonStat {
    /// The reason code string (e.g., `malformed_spec`).
    reason: String,
    /// Count of receipts with this reason code.
    count: usize,
}

// =============================================================================
// Public entry point
// =============================================================================

/// Runs the `apm2 fac queue status` command.
///
/// Returns an exit code.
pub fn run_queue_status(args: &QueueStatusArgs, json_output: bool) -> u8 {
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
    let receipts_dir = fac_root.join("receipts");

    if !queue_root.is_dir() {
        output_error(
            json_output,
            &format!("queue root does not exist: {}", queue_root.display()),
        );
        return exit_codes::NOT_FOUND;
    }

    let mut directories = Vec::with_capacity(QUEUE_DIRS.len());
    let mut total_jobs: usize = 0;
    let mut denial_reasons: HashMap<String, usize> = HashMap::new();
    let mut quarantine_reasons: HashMap<String, usize> = HashMap::new();

    for &dir_name in QUEUE_DIRS {
        let dir_path = queue_root.join(dir_name);
        let status = scan_directory(&dir_path, dir_name);

        total_jobs = total_jobs.saturating_add(status.count);

        // Collect denial/quarantine reason codes from spec files.
        if dir_name == DENIED_DIR || dir_name == QUARANTINE_DIR {
            let reasons = if dir_name == DENIED_DIR {
                &mut denial_reasons
            } else {
                &mut quarantine_reasons
            };
            collect_reason_stats(&dir_path, &receipts_dir, reasons);
        }

        directories.push(status);
    }

    let denial_stats = to_sorted_reason_stats(&denial_reasons);
    let quarantine_stats = to_sorted_reason_stats(&quarantine_reasons);

    let output = QueueStatusOutput {
        directories,
        denial_stats,
        quarantine_stats,
        total_jobs,
        queue_root: queue_root.display().to_string(),
    };

    if json_output {
        print_json(&output);
    } else {
        print_text_status(&output, args);
    }

    exit_codes::SUCCESS
}

// =============================================================================
// Directory scanning
// =============================================================================

/// Scans a single queue directory and returns its status.
///
/// Reads are bounded: at most `MAX_SCAN_ENTRIES` entries are scanned
/// (INV-QSTAT-001). Job specs are read with bounded I/O (INV-QSTAT-002).
fn scan_directory(dir_path: &Path, dir_name: &str) -> DirectoryStatus {
    if !dir_path.is_dir() {
        return DirectoryStatus {
            name: dir_name.to_string(),
            count: 0,
            malformed: 0,
            scan_truncated: false,
            oldest_job_id: None,
            oldest_enqueue_time: None,
        };
    }

    let Ok(entries) = fs::read_dir(dir_path) else {
        return DirectoryStatus {
            name: dir_name.to_string(),
            count: 0,
            malformed: 0,
            scan_truncated: false,
            oldest_job_id: None,
            oldest_enqueue_time: None,
        };
    };

    let mut count: usize = 0;
    let mut malformed: usize = 0;
    let mut scan_truncated = false;
    let mut oldest_job_id: Option<String> = None;
    let mut oldest_enqueue_time: Option<String> = None;

    for (idx, entry) in entries.enumerate() {
        if idx >= MAX_SCAN_ENTRIES {
            scan_truncated = true;
            break;
        }

        let Ok(entry) = entry else { continue };
        let path = entry.path();

        // Only consider .json files (job specs).
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        // Count only after successful parse — malformed .json entries
        // must not inflate job counts (Finding 4).
        match read_job_spec_bounded(&path) {
            Ok(spec) => {
                count = count.saturating_add(1);
                let should_update = oldest_enqueue_time
                    .as_ref()
                    .is_none_or(|current_oldest| spec.enqueue_time < *current_oldest);
                if should_update {
                    oldest_job_id = Some(spec.job_id.clone());
                    oldest_enqueue_time = Some(spec.enqueue_time.clone());
                }
            },
            Err(_) => {
                malformed = malformed.saturating_add(1);
            },
        }
    }

    DirectoryStatus {
        name: dir_name.to_string(),
        count,
        malformed,
        scan_truncated,
        oldest_job_id,
        oldest_enqueue_time,
    }
}

/// Collects denial/quarantine reason stats from job specs in a directory.
///
/// Uses canonical `denial_reason` from receipts (via `lookup_job_receipt`)
/// as the aggregation key. Falls back to an explicit
/// `"missing_denial_reason"` bucket only when receipt data is unavailable.
/// This satisfies the forensics-first
/// requirement: operators see denial/quarantine *cause taxonomy*, not job
/// types (BLOCKER finding: spec.kind is a job type, not a reason code).
///
/// Bounded by `MAX_SCAN_ENTRIES` reads and `MAX_REASON_CODES` distinct
/// reason codes to prevent unbounded `HashMap` growth.
fn collect_reason_stats(
    dir_path: &Path,
    receipts_dir: &Path,
    reasons: &mut HashMap<String, usize>,
) {
    if !dir_path.is_dir() {
        return;
    }

    let Ok(entries) = fs::read_dir(dir_path) else {
        return;
    };

    for (idx, entry) in entries.enumerate() {
        if idx >= MAX_SCAN_ENTRIES {
            break;
        }

        let Ok(entry) = entry else { continue };
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        // Best-effort: try to read the spec to get the job_id.
        if let Ok(spec) = read_job_spec_bounded(&path) {
            // Primary: resolve canonical denial_reason from receipt.
            // Finding 4 fix: use serde-serialized snake_case codes
            // (e.g., "malformed_spec") instead of Debug strings
            // (e.g., "MalformedSpec") for stable machine-readable output.
            let reason_key = apm2_core::fac::lookup_job_receipt(receipts_dir, &spec.job_id)
                .and_then(|receipt| receipt.denial_reason)
                .map_or_else(
                    || "missing_denial_reason".to_string(),
                    |dr| {
                        serde_json::to_value(dr)
                            .ok()
                            .and_then(|v| v.as_str().map(String::from))
                            .unwrap_or_else(|| "missing_denial_reason".to_string())
                    },
                );

            if reasons.len() < MAX_REASON_CODES || reasons.contains_key(&reason_key) {
                *reasons.entry(reason_key).or_insert(0) += 1;
            } else {
                // Finding 3 fix: aggregate overflow codes into "other"
                // so total counts remain accurate.
                *reasons.entry("other".to_string()).or_insert(0) += 1;
            }
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Converts a reason `HashMap` to a sorted `Vec` of `ReasonStat` entries.
///
/// Sorted by count descending, then by reason key ascending for
/// deterministic output (INV-QSTAT-003).
fn to_sorted_reason_stats(reasons: &HashMap<String, usize>) -> Vec<ReasonStat> {
    let mut stats: Vec<ReasonStat> = reasons
        .iter()
        .map(|(reason, count)| ReasonStat {
            reason: reason.clone(),
            count: *count,
        })
        .collect();

    stats.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    stats
}

/// Prints text-formatted queue status.
fn print_text_status(output: &QueueStatusOutput, _args: &QueueStatusArgs) {
    println!("Queue Status ({})", output.queue_root);
    println!();

    println!(
        "  {:<14} {:>7}  {:<40} Enqueue Time",
        "Directory", "Count", "Oldest Job"
    );
    println!("  {}", "-".repeat(80));

    for dir in &output.directories {
        let oldest_display = dir
            .oldest_job_id
            .as_deref()
            .unwrap_or("-")
            .chars()
            .take(40)
            .collect::<String>();
        let time_display = dir.oldest_enqueue_time.as_deref().unwrap_or("-");
        let truncated_marker = if dir.scan_truncated { "+" } else { "" };
        let malformed_marker = if dir.malformed > 0 {
            format!(" ({} malformed)", dir.malformed)
        } else {
            String::new()
        };
        println!(
            "  {:<14} {:>6}{:<1}  {:<40} {time_display}{malformed_marker}",
            dir.name, dir.count, truncated_marker, oldest_display
        );
    }

    println!();
    println!("  Total: {} jobs", output.total_jobs);

    if !output.denial_stats.is_empty() {
        println!();
        println!("  Denial Reason Distribution:");
        for stat in &output.denial_stats {
            println!("    {:<30} {}", stat.reason, stat.count);
        }
    }

    if !output.quarantine_stats.is_empty() {
        println!();
        println!("  Quarantine Reason Distribution:");
        for stat in &output.quarantine_stats {
            println!("    {:<30} {}", stat.reason, stat.count);
        }
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
    use apm2_core::fac::job_spec::FacJobSpecV1;

    use super::*;

    #[test]
    fn test_scan_empty_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_path = tmp.path().join("pending");
        fs::create_dir_all(&dir_path).unwrap();

        let status = scan_directory(&dir_path, "pending");
        assert_eq!(status.name, "pending");
        assert_eq!(status.count, 0);
        assert_eq!(status.malformed, 0);
        assert!(!status.scan_truncated);
        assert!(status.oldest_job_id.is_none());
        assert!(status.oldest_enqueue_time.is_none());
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_path = tmp.path().join("nonexistent");

        let status = scan_directory(&dir_path, "nonexistent");
        assert_eq!(status.count, 0);
        assert!(!status.scan_truncated);
    }

    #[test]
    fn test_scan_directory_with_json_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_path = tmp.path().join("pending");
        fs::create_dir_all(&dir_path).unwrap();

        // Create a minimal valid job spec.
        let spec = make_test_spec("test-job-1", "2026-02-15T10:00:00Z");
        let json = serde_json::to_string_pretty(&spec).unwrap();
        fs::write(dir_path.join("test-job-1.json"), &json).unwrap();

        let spec2 = make_test_spec("test-job-2", "2026-02-15T09:00:00Z");
        let json2 = serde_json::to_string_pretty(&spec2).unwrap();
        fs::write(dir_path.join("test-job-2.json"), &json2).unwrap();

        let status = scan_directory(&dir_path, "pending");
        assert_eq!(status.count, 2);
        assert!(!status.scan_truncated);
        // Oldest by `enqueue_time` should be test-job-2.
        assert_eq!(status.oldest_job_id.as_deref(), Some("test-job-2"));
        assert_eq!(
            status.oldest_enqueue_time.as_deref(),
            Some("2026-02-15T09:00:00Z")
        );
    }

    #[test]
    fn test_scan_ignores_non_json_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_path = tmp.path().join("pending");
        fs::create_dir_all(&dir_path).unwrap();

        fs::write(dir_path.join("readme.txt"), b"not a job spec").unwrap();
        fs::write(dir_path.join(".lock"), b"lock file").unwrap();

        let status = scan_directory(&dir_path, "pending");
        assert_eq!(status.count, 0);
    }

    #[test]
    fn test_to_sorted_reason_stats_deterministic() {
        let mut reasons = HashMap::new();
        reasons.insert("malformed_spec".to_string(), 5);
        reasons.insert("digest_mismatch".to_string(), 3);
        reasons.insert("channel_boundary".to_string(), 5);

        let stats = to_sorted_reason_stats(&reasons);
        assert_eq!(stats.len(), 3);
        // Both with count 5, sorted alphabetically.
        assert_eq!(stats[0].reason, "channel_boundary");
        assert_eq!(stats[0].count, 5);
        assert_eq!(stats[1].reason, "malformed_spec");
        assert_eq!(stats[1].count, 5);
        assert_eq!(stats[2].reason, "digest_mismatch");
        assert_eq!(stats[2].count, 3);
    }

    #[test]
    fn test_read_job_spec_bounded_rejects_oversized() {
        use apm2_core::fac::job_spec::MAX_JOB_SPEC_SIZE;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("oversized.json");
        let oversized = vec![b'{'; MAX_JOB_SPEC_SIZE + 100];
        fs::write(&path, &oversized).unwrap();

        let result = read_job_spec_bounded(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds max"));
    }

    /// Regression test: `collect_reason_stats` uses receipt-based
    /// `denial_reason` as the aggregation key, NOT `spec.kind` (BLOCKER
    /// finding from review). When no receipt exists for a job, it falls
    /// back to `"missing_denial_reason"`.
    #[test]
    fn test_collect_reason_stats_uses_receipt_denial_reason() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let denied_dir = tmp.path().join("denied");
        let receipts_dir = tmp.path().join("receipts");
        fs::create_dir_all(&denied_dir).unwrap();
        fs::create_dir_all(&receipts_dir).unwrap();

        // Create a job spec in denied/ with kind="gates".
        // Without a receipt, it should aggregate under "missing_denial_reason"
        // -- NOT "gates".
        let spec = make_test_spec("no-receipt-job", "2026-02-15T10:00:00Z");
        let json = serde_json::to_string_pretty(&spec).unwrap();
        fs::write(denied_dir.join("no-receipt-job.json"), &json).unwrap();

        // Create another job spec with a receipt that has a denial_reason.
        let spec2 = make_test_spec("has-receipt-job", "2026-02-15T11:00:00Z");
        let json2 = serde_json::to_string_pretty(&spec2).unwrap();
        fs::write(denied_dir.join("has-receipt-job.json"), &json2).unwrap();

        // Persist a receipt with a denial reason for the second job.
        let fake_digest = format!("b3-256:{}", "a".repeat(64));
        let builder = apm2_core::fac::FacJobReceiptV1Builder::new(
            "receipt-1",
            "has-receipt-job",
            &fake_digest,
        )
        .outcome(apm2_core::fac::FacJobOutcome::Denied)
        .denial_reason(apm2_core::fac::DenialReasonCode::DigestMismatch)
        .reason("test denial")
        .timestamp_secs(1_700_000_000);
        let receipt = builder.try_build().expect("receipt builds");
        apm2_core::fac::persist_content_addressed_receipt(&receipts_dir, &receipt)
            .expect("persist receipt");

        let mut reasons = HashMap::new();
        collect_reason_stats(&denied_dir, &receipts_dir, &mut reasons);

        // Finding 4 fix: the job with a receipt should be keyed by
        // "digest_mismatch" (serde snake_case), NOT "DigestMismatch" (Debug).
        assert!(
            reasons.contains_key("digest_mismatch"),
            "expected digest_mismatch reason key (serde snake_case), got: {reasons:?}"
        );
        assert_eq!(reasons["digest_mismatch"], 1);

        // The job without a receipt should be keyed by
        // "missing_denial_reason", NOT "gates".
        assert!(
            !reasons.contains_key("gates"),
            "spec.kind must NOT be used as reason key: {reasons:?}"
        );
        assert!(
            reasons.contains_key("missing_denial_reason"),
            "expected 'missing_denial_reason' fallback for missing receipt: {reasons:?}"
        );
        assert_eq!(reasons["missing_denial_reason"], 1);
    }

    /// Finding 4 regression: malformed `.json` files must NOT inflate the
    /// job count. They must be tracked separately in the `malformed` field.
    #[test]
    fn test_scan_directory_counts_malformed_separately() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_path = tmp.path().join("pending");
        fs::create_dir_all(&dir_path).unwrap();

        // One valid job spec.
        let spec = make_test_spec("valid-job", "2026-02-15T10:00:00Z");
        let json = serde_json::to_string_pretty(&spec).unwrap();
        fs::write(dir_path.join("valid-job.json"), &json).unwrap();

        // One malformed .json file (invalid JSON).
        fs::write(dir_path.join("corrupt.json"), b"not valid json").unwrap();

        // One .json file with valid JSON but wrong schema.
        fs::write(dir_path.join("wrong-schema.json"), b"{\"foo\": \"bar\"}").unwrap();

        let status = scan_directory(&dir_path, "pending");
        // Only the valid job spec should be counted.
        assert_eq!(
            status.count, 1,
            "only valid specs should be counted as jobs"
        );
        // The two malformed entries should be tracked separately.
        assert_eq!(
            status.malformed, 2,
            "malformed .json files must be tracked separately"
        );
        assert_eq!(status.oldest_job_id.as_deref(), Some("valid-job"));
    }

    /// Create a minimal test job spec for unit tests.
    fn make_test_spec(job_id: &str, enqueue_time: &str) -> FacJobSpecV1 {
        FacJobSpecV1 {
            schema: apm2_core::fac::job_spec::JOB_SPEC_SCHEMA_ID.to_string(),
            job_id: job_id.to_string(),
            job_spec_digest: String::new(),
            kind: "gates".to_string(),
            queue_lane: "bulk".to_string(),
            priority: 50,
            enqueue_time: enqueue_time.to_string(),
            actuation: apm2_core::fac::job_spec::Actuation {
                lease_id: format!("lease-{job_id}"),
                request_id: String::new(),
                channel_context_token: None,
                decoded_source: None,
            },
            source: apm2_core::fac::job_spec::JobSource {
                kind: "mirror_commit".to_string(),
                repo_id: "test/repo".to_string(),
                work_id: "W-TEST".to_string(),
                head_sha: "a".repeat(40),
                patch: None,
            },
            lane_requirements: apm2_core::fac::job_spec::LaneRequirements {
                lane_profile_hash: None,
            },
            constraints: apm2_core::fac::job_spec::JobConstraints {
                require_nextest: false,
                test_timeout_seconds: Some(60),
                memory_max_bytes: None,
            },
            cancel_target_job_id: None,
        }
    }

    /// Finding 3 regression: when `MAX_REASON_CODES` distinct reason keys
    /// are reached, subsequent new keys must aggregate into an `"other"`
    /// bucket so total counts remain accurate.
    #[test]
    fn test_collect_reason_stats_overflow_aggregates_to_other() {
        // Pre-fill the map with MAX_REASON_CODES distinct keys.
        let mut reasons = HashMap::new();
        for i in 0..MAX_REASON_CODES {
            reasons.insert(format!("reason_{i}"), 1usize);
        }
        assert_eq!(reasons.len(), MAX_REASON_CODES);

        // Simulate an overflow scenario: create a dir with a job spec
        // that has no receipt (will produce a "missing_denial_reason" key).
        // Since that key is not yet in the map, it should go to "other".
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("denied");
        let receipts_dir = tmp.path().join("receipts");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&receipts_dir).unwrap();

        let spec = make_test_spec("overflow-job", "2026-02-15T10:00:00Z");
        let json = serde_json::to_string_pretty(&spec).unwrap();
        fs::write(dir.join("overflow-job.json"), &json).unwrap();

        collect_reason_stats(&dir, &receipts_dir, &mut reasons);

        // The new reason ("missing_denial_reason") was not in the map and
        // the map was
        // at capacity, so it should have been aggregated into "other".
        assert!(
            reasons.contains_key("other"),
            "overflow codes must aggregate into 'other': {reasons:?}"
        );
        assert_eq!(reasons["other"], 1);
        // "missing_denial_reason" should NOT have been inserted since map was
        // at capacity.
        assert!(
            !reasons.contains_key("missing_denial_reason"),
            "'missing_denial_reason' should not be inserted when map is at capacity: {reasons:?}"
        );
    }
}
