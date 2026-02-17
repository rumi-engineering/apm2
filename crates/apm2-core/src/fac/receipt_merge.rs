// AGENT-AUTHORED
//! Receipt stream merge: set-union merge with deterministic ordering and
//! conflict audit report.
//!
//! This module implements receipt directory merging for the Forge Admission
//! Cycle. Receipts are content-addressed JSON files named `{digest}.json`
//! where `digest` is a BLAKE3 hash (`b3-256:...` prefix stripped for the
//! filename, or stored as the full `b3-256:...` form depending on version).
//!
//! # Merge Semantics
//!
//! The merge is a **set union on receipt digests**: a receipt from the source
//! directory is copied into the target directory only if no file with the
//! same digest-derived filename already exists there. This is idempotent
//! and preserves provenance — the original receipt bytes are never modified.
//!
//! # Deterministic Ordering
//!
//! Merged receipts are presented in deterministic order:
//! - Primary sort: `timestamp_secs` descending (most recent first).
//! - Tiebreaker: `content_hash` ascending (lexicographic).
//!
//! # Audit Report
//!
//! The merge emits an audit report containing:
//! - `duplicates_skipped`: count of receipts already present in target.
//! - `receipts_copied`: count of new receipts written to target.
//! - `job_id_mismatches`: receipts in both dirs with same digest but different
//!   job ID (should never happen -- indicates corruption).
//! - `parse_failures`: files that could not be parsed as valid receipts.
//!
//! # Security Model
//!
//! - All receipt reads use bounded I/O (`MAX_JOB_RECEIPT_SIZE`).
//! - Digest filenames are validated before use as path components.
//! - Receipt integrity is verified by recomputing the content hash.
//! - Directory scans are bounded by `MAX_MERGE_SCAN_FILES`.
//! - Writes use atomic temp+rename protocol.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::receipt::{
    FacJobReceiptV1, MAX_JOB_RECEIPT_SIZE, compute_job_receipt_content_hash,
    compute_job_receipt_content_hash_v2,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of receipt files to scan per directory during merge.
/// Prevents unbounded directory traversal.
pub const MAX_MERGE_SCAN_FILES: usize = 65_536;

/// Maximum number of parse failures to collect before stopping.
/// Prevents unbounded memory growth from a directory full of corrupt files.
pub const MAX_PARSE_FAILURES: usize = 1_024;

/// Maximum number of `job_id` mismatch entries to collect.
pub const MAX_JOB_ID_MISMATCHES: usize = 256;

// =============================================================================
// Error Types
// =============================================================================

/// Errors from receipt merge operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptMergeError {
    /// Source directory does not exist or is not a directory.
    #[error("source directory does not exist or is not a directory: {0}")]
    SourceNotDirectory(PathBuf),

    /// Target directory does not exist or is not a directory.
    #[error("target directory does not exist or is not a directory: {0}")]
    TargetNotDirectory(PathBuf),

    /// Source and target are the same directory.
    #[error("source and target directories are the same: {0}")]
    SameDirectory(PathBuf),

    /// I/O error during merge.
    #[error("I/O error during {context}: {source}")]
    Io {
        /// Human-readable context.
        context: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Source directory scan exceeded limit.
    #[error("source directory scan exceeded limit of {limit} files")]
    ScanLimitExceeded {
        /// The scan limit.
        limit: usize,
    },
}

impl ReceiptMergeError {
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// =============================================================================
// Audit Report Types
// =============================================================================

/// A single `job_id` mismatch entry: same digest, different `job_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobIdMismatch {
    /// The content hash (digest) that appears in both directories.
    pub content_hash: String,
    /// The `job_id` from the source receipt.
    pub source_job_id: String,
    /// The `job_id` from the target receipt.
    pub target_job_id: String,
}

/// A parse failure entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParseFailure {
    /// Path of the file that failed to parse.
    pub path: String,
    /// Human-readable reason for the failure.
    pub reason: String,
}

/// Merged receipt header for deterministic output ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergedReceiptHeader {
    /// Content hash (digest).
    pub content_hash: String,
    /// Job ID.
    pub job_id: String,
    /// Epoch timestamp (seconds).
    pub timestamp_secs: u64,
    /// Origin: "source", "target", or "both".
    pub origin: String,
}

/// Audit report from a receipt merge operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeAuditReport {
    /// Number of receipts copied from source to target.
    pub receipts_copied: usize,
    /// Number of receipts skipped because they already exist in target.
    pub duplicates_skipped: usize,
    /// Total receipts in target after merge (includes pre-existing).
    pub total_target_receipts: usize,
    /// Job ID mismatches: same digest, different `job_id`.
    pub job_id_mismatches: Vec<JobIdMismatch>,
    /// Files that could not be parsed as valid receipts.
    pub parse_failures: Vec<ParseFailure>,
    /// Merged receipt headers in deterministic order.
    pub merged_headers: Vec<MergedReceiptHeader>,
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Validate that a string is a well-formed BLAKE3-256 hex digest.
///
/// Accepts both bare 64-char hex and `b3-256:` prefixed forms.
fn is_valid_digest(s: &str) -> bool {
    let hex_part = s.strip_prefix("b3-256:").unwrap_or(s);
    hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Open a file with `O_NOFOLLOW` on Unix for symlink safety.
fn open_no_follow(path: &Path) -> Result<fs::File, std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }

    #[cfg(not(unix))]
    {
        fs::File::open(path)
    }
}

/// Load a single receipt file with bounded read and `O_NOFOLLOW`.
fn load_receipt_bounded(path: &Path) -> Result<FacJobReceiptV1, String> {
    let file = open_no_follow(path).map_err(|e| format!("open failed: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("metadata failed: {e}"))?;
    if meta.len() > MAX_JOB_RECEIPT_SIZE as u64 {
        return Err(format!(
            "file too large: {} bytes > {} max",
            meta.len(),
            MAX_JOB_RECEIPT_SIZE
        ));
    }
    let cap = MAX_JOB_RECEIPT_SIZE as u64;
    let mut buf = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;
    if buf.len() as u64 > cap {
        return Err(format!(
            "read exceeded cap: {} bytes > {cap} max",
            buf.len()
        ));
    }
    serde_json::from_slice::<FacJobReceiptV1>(&buf).map_err(|e| format!("JSON parse failed: {e}"))
}

/// Verify content-addressed integrity of a loaded receipt against the
/// expected digest derived from its filename.
fn verify_receipt_integrity(receipt: &FacJobReceiptV1, expected_digest: &str) -> bool {
    // Try v1 hash first.
    let v1_hash = compute_job_receipt_content_hash(receipt);
    if v1_hash.as_bytes().ct_eq(expected_digest.as_bytes()).into() {
        return true;
    }
    // Try v2 hash (includes unsafe_direct).
    let v2_hash = compute_job_receipt_content_hash_v2(receipt);
    if v2_hash.as_bytes().ct_eq(expected_digest.as_bytes()).into() {
        return true;
    }
    false
}

/// Scan a receipt directory, returning a map of digest -> parsed receipt.
///
/// Only files matching `{valid_digest}.json` are included. Files that fail
/// to parse or verify integrity are recorded in `parse_failures`.
fn scan_receipt_dir(
    dir: &Path,
    parse_failures: &mut Vec<ParseFailure>,
) -> Result<BTreeMap<String, FacJobReceiptV1>, ReceiptMergeError> {
    let mut receipts = BTreeMap::new();
    let entries = fs::read_dir(dir)
        .map_err(|e| ReceiptMergeError::io(format!("reading directory {}", dir.display()), e))?;

    let mut visited: usize = 0;
    for entry_result in entries {
        visited = visited.saturating_add(1);
        if visited > MAX_MERGE_SCAN_FILES {
            return Err(ReceiptMergeError::ScanLimitExceeded {
                limit: MAX_MERGE_SCAN_FILES,
            });
        }
        let Ok(entry) = entry_result else { continue };
        let path = entry.path();

        // Skip non-JSON files.
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        // Skip directories.
        if path.is_dir() {
            continue;
        }
        // Skip index subdirectory files.
        if path
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|name| name == "index")
        {
            continue;
        }

        // Derive expected digest from filename.
        let Some(digest_os) = path.file_stem() else {
            continue;
        };
        let Some(expected_digest) = digest_os.to_str() else {
            if parse_failures.len() < MAX_PARSE_FAILURES {
                parse_failures.push(ParseFailure {
                    path: path.display().to_string(),
                    reason: "non-UTF-8 filename".to_string(),
                });
            }
            continue;
        };

        // Validate digest format.
        if !is_valid_digest(expected_digest) {
            if parse_failures.len() < MAX_PARSE_FAILURES {
                parse_failures.push(ParseFailure {
                    path: path.display().to_string(),
                    reason: "invalid digest filename format".to_string(),
                });
            }
            continue;
        }

        // Load and parse.
        let receipt = match load_receipt_bounded(&path) {
            Ok(r) => r,
            Err(reason) => {
                if parse_failures.len() < MAX_PARSE_FAILURES {
                    parse_failures.push(ParseFailure {
                        path: path.display().to_string(),
                        reason,
                    });
                }
                continue;
            },
        };

        // Verify integrity.
        if !verify_receipt_integrity(&receipt, expected_digest) {
            if parse_failures.len() < MAX_PARSE_FAILURES {
                parse_failures.push(ParseFailure {
                    path: path.display().to_string(),
                    reason: format!(
                        "content hash mismatch: filename digest {expected_digest} \
                         does not match recomputed hash"
                    ),
                });
            }
            continue;
        }

        receipts.insert(expected_digest.to_string(), receipt);
    }

    Ok(receipts)
}

/// Atomically write receipt bytes to the target directory.
fn atomic_write_receipt(
    target_dir: &Path,
    digest: &str,
    receipt: &FacJobReceiptV1,
) -> Result<PathBuf, ReceiptMergeError> {
    let body = serde_json::to_vec_pretty(receipt).map_err(|e| {
        ReceiptMergeError::io(
            format!("serializing receipt {digest}"),
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;

    let final_path = target_dir.join(format!("{digest}.json"));
    let temp_path = target_dir.join(format!("{digest}.merge.tmp"));

    fs::write(&temp_path, body).map_err(|e| {
        ReceiptMergeError::io(format!("writing temp file {}", temp_path.display()), e)
    })?;
    fs::rename(&temp_path, &final_path).map_err(|e| {
        // Clean up temp file on rename failure.
        let _ = fs::remove_file(&temp_path);
        ReceiptMergeError::io(
            format!(
                "renaming {} to {}",
                temp_path.display(),
                final_path.display()
            ),
            e,
        )
    })?;

    Ok(final_path)
}

// =============================================================================
// Public API
// =============================================================================

/// Merge receipts from `source_dir` into `target_dir` using set-union
/// on receipt digests.
///
/// Returns an audit report with merge statistics and any anomalies found.
///
/// # Errors
///
/// Returns `ReceiptMergeError` if directory I/O fails or scan limits are
/// exceeded.
pub fn merge_receipt_dirs(
    source_dir: &Path,
    target_dir: &Path,
) -> Result<MergeAuditReport, ReceiptMergeError> {
    // Validate directories.
    if !source_dir.is_dir() {
        return Err(ReceiptMergeError::SourceNotDirectory(
            source_dir.to_path_buf(),
        ));
    }
    if !target_dir.is_dir() {
        return Err(ReceiptMergeError::TargetNotDirectory(
            target_dir.to_path_buf(),
        ));
    }

    // Prevent merging a directory into itself.
    // Use canonical paths to handle symlinks and relative paths.
    let source_canonical = source_dir
        .canonicalize()
        .map_err(|e| ReceiptMergeError::io("canonicalizing source", e))?;
    let target_canonical = target_dir
        .canonicalize()
        .map_err(|e| ReceiptMergeError::io("canonicalizing target", e))?;
    if source_canonical == target_canonical {
        return Err(ReceiptMergeError::SameDirectory(source_dir.to_path_buf()));
    }

    let mut parse_failures = Vec::new();

    // Scan both directories.
    let source_receipts = scan_receipt_dir(source_dir, &mut parse_failures)?;
    let target_receipts = scan_receipt_dir(target_dir, &mut parse_failures)?;

    let mut receipts_copied: usize = 0;
    let mut duplicates_skipped: usize = 0;
    let mut job_id_mismatches = Vec::new();

    // All merged headers: track origin for each digest.
    let mut all_headers: BTreeMap<String, MergedReceiptHeader> = BTreeMap::new();

    // Register target receipts.
    for (digest, receipt) in &target_receipts {
        all_headers.insert(
            digest.clone(),
            MergedReceiptHeader {
                content_hash: digest.clone(),
                job_id: receipt.job_id.clone(),
                timestamp_secs: receipt.timestamp_secs,
                origin: "target".to_string(),
            },
        );
    }

    // Process source receipts.
    for (digest, source_receipt) in &source_receipts {
        if let Some(target_receipt) = target_receipts.get(digest) {
            // Duplicate: same digest exists in target.
            duplicates_skipped = duplicates_skipped.saturating_add(1);

            // Check for job_id mismatch (should never happen).
            if source_receipt.job_id != target_receipt.job_id
                && job_id_mismatches.len() < MAX_JOB_ID_MISMATCHES
            {
                job_id_mismatches.push(JobIdMismatch {
                    content_hash: digest.clone(),
                    source_job_id: source_receipt.job_id.clone(),
                    target_job_id: target_receipt.job_id.clone(),
                });
            }

            // Update origin to "both".
            if let Some(header) = all_headers.get_mut(digest) {
                header.origin = "both".to_string();
            }
        } else {
            // New receipt: copy to target.
            atomic_write_receipt(target_dir, digest, source_receipt)?;
            receipts_copied = receipts_copied.saturating_add(1);

            all_headers.insert(
                digest.clone(),
                MergedReceiptHeader {
                    content_hash: digest.clone(),
                    job_id: source_receipt.job_id.clone(),
                    timestamp_secs: source_receipt.timestamp_secs,
                    origin: "source".to_string(),
                },
            );
        }
    }

    // Build deterministic ordering: timestamp_secs desc, content_hash asc.
    let mut merged_headers: Vec<MergedReceiptHeader> = all_headers.into_values().collect();
    merged_headers.sort_by(|a, b| {
        b.timestamp_secs
            .cmp(&a.timestamp_secs)
            .then_with(|| a.content_hash.cmp(&b.content_hash))
    });

    let total_target_receipts = target_receipts.len().saturating_add(receipts_copied);

    Ok(MergeAuditReport {
        receipts_copied,
        duplicates_skipped,
        total_target_receipts,
        job_id_mismatches,
        parse_failures,
        merged_headers,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::receipt::{
        DenialReasonCode, FacJobOutcome, FacJobReceiptV1Builder,
        compute_job_receipt_content_hash_v2,
    };

    /// Create a test receipt with the given `job_id` and timestamp.
    fn make_test_receipt(job_id: &str, timestamp_secs: u64) -> FacJobReceiptV1 {
        let receipt_id = format!("test-receipt-{job_id}-{timestamp_secs}");
        let digest = "b3-256:".to_string() + &"ab".repeat(32);
        let mut receipt = FacJobReceiptV1Builder::new(&receipt_id, job_id, &digest)
            .outcome(FacJobOutcome::Denied)
            .denial_reason(DenialReasonCode::MalformedSpec)
            .reason("test merge receipt")
            .timestamp_secs(timestamp_secs)
            .try_build()
            .expect("test receipt build should succeed");
        let hash = compute_job_receipt_content_hash_v2(&receipt);
        receipt.content_hash = hash;
        receipt
    }

    /// Persist a receipt to a directory using the same filename convention
    /// as the production `persist_content_addressed_receipt_v2`.
    fn persist_receipt(dir: &Path, receipt: &FacJobReceiptV1) -> String {
        let filename_stem = &receipt.content_hash;
        let path = dir.join(format!("{filename_stem}.json"));
        let body = serde_json::to_vec_pretty(receipt).expect("serialize");
        fs::write(&path, body).expect("write");
        filename_stem.clone()
    }

    #[test]
    fn test_merge_empty_source_into_empty_target() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 0);
        assert_eq!(report.duplicates_skipped, 0);
        assert_eq!(report.total_target_receipts, 0);
        assert!(report.job_id_mismatches.is_empty());
        assert!(report.parse_failures.is_empty());
        assert!(report.merged_headers.is_empty());
    }

    #[test]
    fn test_merge_new_receipts_into_empty_target() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let r1 = make_test_receipt("job-001", 1000);
        let r2 = make_test_receipt("job-002", 2000);

        persist_receipt(source.path(), &r1);
        persist_receipt(source.path(), &r2);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 2);
        assert_eq!(report.duplicates_skipped, 0);
        assert_eq!(report.total_target_receipts, 2);
        assert!(report.job_id_mismatches.is_empty());
        assert!(report.parse_failures.is_empty());
        assert_eq!(report.merged_headers.len(), 2);
        // Verify deterministic ordering: most recent first.
        assert_eq!(report.merged_headers[0].job_id, "job-002");
        assert_eq!(report.merged_headers[1].job_id, "job-001");
    }

    #[test]
    fn test_merge_duplicate_skipped() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let receipt = make_test_receipt("job-001", 1000);

        persist_receipt(source.path(), &receipt);
        persist_receipt(target.path(), &receipt);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 0);
        assert_eq!(report.duplicates_skipped, 1);
        assert_eq!(report.total_target_receipts, 1);
        assert!(report.job_id_mismatches.is_empty());
        // Origin should be "both".
        assert_eq!(report.merged_headers.len(), 1);
        assert_eq!(report.merged_headers[0].origin, "both");
    }

    #[test]
    fn test_merge_partial_overlap() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let shared = make_test_receipt("job-shared", 1000);
        let source_only = make_test_receipt("job-source", 2000);
        let target_only = make_test_receipt("job-target", 3000);

        persist_receipt(source.path(), &shared);
        persist_receipt(source.path(), &source_only);
        persist_receipt(target.path(), &shared);
        persist_receipt(target.path(), &target_only);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 1);
        assert_eq!(report.duplicates_skipped, 1);
        assert_eq!(report.total_target_receipts, 3);
        assert!(report.job_id_mismatches.is_empty());
        assert_eq!(report.merged_headers.len(), 3);
        // Ordered: target_only (3000), source_only (2000), shared (1000).
        assert_eq!(report.merged_headers[0].job_id, "job-target");
        assert_eq!(report.merged_headers[1].job_id, "job-source");
        assert_eq!(report.merged_headers[2].job_id, "job-shared");
    }

    #[test]
    fn test_merge_parse_failure_recorded() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        // Write a corrupt file with a valid digest filename.
        let fake_digest = "a".repeat(64);
        let corrupt_path = source.path().join(format!("{fake_digest}.json"));
        fs::write(&corrupt_path, b"not valid json").expect("write corrupt");

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 0);
        assert_eq!(report.duplicates_skipped, 0);
        assert_eq!(report.parse_failures.len(), 1);
        assert!(
            report.parse_failures[0]
                .reason
                .contains("JSON parse failed")
                || report.parse_failures[0]
                    .reason
                    .contains("content hash mismatch")
        );
    }

    #[test]
    fn test_merge_invalid_digest_filename_recorded() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let bad_path = source.path().join("not-a-digest.json");
        fs::write(&bad_path, b"{}").expect("write");

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 0);
        assert_eq!(report.parse_failures.len(), 1);
        assert!(
            report.parse_failures[0]
                .reason
                .contains("invalid digest filename")
        );
    }

    #[test]
    fn test_merge_source_not_dir() {
        let target = tempfile::tempdir().expect("tempdir");
        let result = merge_receipt_dirs(Path::new("/nonexistent/path"), target.path());
        assert!(matches!(
            result,
            Err(ReceiptMergeError::SourceNotDirectory(_))
        ));
    }

    #[test]
    fn test_merge_target_not_dir() {
        let source = tempfile::tempdir().expect("tempdir");
        let result = merge_receipt_dirs(source.path(), Path::new("/nonexistent/path"));
        assert!(matches!(
            result,
            Err(ReceiptMergeError::TargetNotDirectory(_))
        ));
    }

    #[test]
    fn test_merge_same_directory_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = merge_receipt_dirs(dir.path(), dir.path());
        assert!(matches!(result, Err(ReceiptMergeError::SameDirectory(_))));
    }

    #[test]
    fn test_deterministic_ordering_equal_timestamps() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        // Create two receipts with the same timestamp but different job IDs.
        let r1 = make_test_receipt("job-zzz", 1000);
        let r2 = make_test_receipt("job-aaa", 1000);

        persist_receipt(source.path(), &r1);
        persist_receipt(source.path(), &r2);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.merged_headers.len(), 2);
        // Same timestamp: ordered by content_hash ascending.
        assert!(report.merged_headers[0].content_hash <= report.merged_headers[1].content_hash);
    }

    #[test]
    fn test_merge_idempotent() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let receipt = make_test_receipt("job-001", 1000);
        persist_receipt(source.path(), &receipt);

        // First merge.
        let report1 =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");
        assert_eq!(report1.receipts_copied, 1);
        assert_eq!(report1.duplicates_skipped, 0);

        // Second merge: should be a no-op.
        let report2 =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");
        assert_eq!(report2.receipts_copied, 0);
        assert_eq!(report2.duplicates_skipped, 1);
        assert_eq!(report2.total_target_receipts, 1);
    }

    #[test]
    fn test_merge_non_json_files_ignored() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        // Write a non-JSON file.
        fs::write(source.path().join("readme.txt"), b"hello").expect("write");
        // Write a valid receipt.
        let receipt = make_test_receipt("job-001", 1000);
        persist_receipt(source.path(), &receipt);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 1);
        assert!(report.parse_failures.is_empty());
    }

    #[test]
    fn test_merge_empty_source_into_populated_target() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let receipt = make_test_receipt("job-001", 1000);
        persist_receipt(target.path(), &receipt);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 0);
        assert_eq!(report.duplicates_skipped, 0);
        assert_eq!(report.total_target_receipts, 1);
        assert_eq!(report.merged_headers.len(), 1);
        assert_eq!(report.merged_headers[0].origin, "target");
    }
}
