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
//! # Deterministic Ordering (RFC-0019 section 8.4)
//!
//! Merged receipts are presented in deterministic order per the RFC-0019
//! ordering contract:
//! - Primary: HTF time envelope stamp descending (when present; RFC-0016).
//! - Fallback (when HTF is absent): `timestamp_secs` descending, then
//!   `node_fingerprint` ascending, then `content_hash` ascending.
//! - Receipts with HTF stamps sort before receipts without.
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
///
/// Fields support the full RFC-0019 section 8.4 ordering contract:
/// 1. Primary: `htf_time_envelope_ns` (when present)
/// 2. Fallback: `timestamp_secs` > `node_fingerprint` > `content_hash`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergedReceiptHeader {
    /// Content hash (digest).
    pub content_hash: String,
    /// Job ID.
    pub job_id: String,
    /// Epoch timestamp (seconds).
    pub timestamp_secs: u64,
    /// HTF time envelope stamp in nanoseconds (RFC-0016, TCK-00543).
    ///
    /// When present, this is the primary sort key for deterministic
    /// receipt ordering per RFC-0019 section 8.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub htf_time_envelope_ns: Option<u64>,
    /// Node fingerprint for deterministic ordering fallback (TCK-00543).
    ///
    /// Second component of the fallback ordering tuple per RFC-0019
    /// section 8.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_fingerprint: Option<String>,
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

/// Compare two optional string values in ascending order, treating
/// `None` as greater than `Some` (receipts with a node fingerprint sort
/// before those without).
fn cmp_option_str_asc(a: Option<&str>, b: Option<&str>) -> std::cmp::Ordering {
    match (a, b) {
        (Some(a_s), Some(b_s)) => a_s.cmp(b_s),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

/// Normalize a digest filename stem to canonical `b3-256:<hex>` form.
///
/// Accepts both bare 64-char hex and `b3-256:`-prefixed forms.
/// Returns the canonical prefixed form in both cases.
fn normalize_digest(stem: &str) -> String {
    if stem.starts_with("b3-256:") {
        stem.to_string()
    } else {
        format!("b3-256:{stem}")
    }
}

/// Verify content-addressed integrity of a loaded receipt against the
/// expected digest derived from its filename.
///
/// Normalizes the filename stem to canonical `b3-256:<hex>` form before
/// comparison, so both bare `<hex>.json` and `b3-256:<hex>.json` filenames
/// verify correctly.
fn verify_receipt_integrity(receipt: &FacJobReceiptV1, expected_digest: &str) -> bool {
    let canonical = normalize_digest(expected_digest);
    // Try v1 hash first.
    let v1_hash = compute_job_receipt_content_hash(receipt);
    if v1_hash.as_bytes().ct_eq(canonical.as_bytes()).into() {
        return true;
    }
    // Try v2 hash (includes unsafe_direct).
    let v2_hash = compute_job_receipt_content_hash_v2(receipt);
    if v2_hash.as_bytes().ct_eq(canonical.as_bytes()).into() {
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
        // Skip directories. Use entry.file_type() (lstat) instead of
        // path.is_dir() (stat) to avoid following symlinks and the
        // extra syscall / TOCTOU window.
        if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
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

        // Normalize digest to canonical `b3-256:<hex>` form so that
        // bare-hex and prefixed filenames for the same hash map to the
        // same key. This prevents duplicate-detection bypass when source
        // and target use different filename forms for the same receipt.
        let canonical_key = normalize_digest(expected_digest);
        receipts.insert(canonical_key, receipt);
    }

    Ok(receipts)
}

/// Atomically write receipt bytes to the target directory.
///
/// Uses `tempfile::NamedTempFile::new_in` for secure temp file creation
/// with `O_EXCL` protection, preventing symlink attacks on deterministic
/// temp file names (CVE-class: CWE-367 / CWE-59).
fn atomic_write_receipt(
    target_dir: &Path,
    digest: &str,
    receipt: &FacJobReceiptV1,
) -> Result<PathBuf, ReceiptMergeError> {
    use std::io::Write as _;

    let body = serde_json::to_vec_pretty(receipt).map_err(|e| {
        ReceiptMergeError::io(
            format!("serializing receipt {digest}"),
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;

    let final_path = target_dir.join(format!("{digest}.json"));

    // Create a securely randomized temp file with O_EXCL (no symlink follow).
    let mut temp_file = tempfile::NamedTempFile::new_in(target_dir).map_err(|e| {
        ReceiptMergeError::io(
            format!("creating secure temp file in {}", target_dir.display()),
            e,
        )
    })?;
    temp_file.write_all(&body).map_err(|e| {
        ReceiptMergeError::io(
            format!("writing temp file {}", temp_file.path().display()),
            e,
        )
    })?;
    // persist() performs an atomic rename from the randomized temp path to
    // the final destination — preserving atomicity and preventing symlink
    // attacks since the temp name is unpredictable.
    temp_file.persist(&final_path).map_err(|e| {
        ReceiptMergeError::io(
            format!("persisting temp file to {}", final_path.display()),
            e.error,
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
#[allow(clippy::too_many_lines)] // Sequential merge pipeline with inline comparator; splitting obscures the unified ordering contract.
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
                htf_time_envelope_ns: receipt.htf_time_envelope_ns,
                node_fingerprint: receipt.node_fingerprint.clone(),
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
                    htf_time_envelope_ns: source_receipt.htf_time_envelope_ns,
                    node_fingerprint: source_receipt.node_fingerprint.clone(),
                    origin: "source".to_string(),
                },
            );
        }
    }

    // Build deterministic ordering per RFC-0019 section 8.4:
    //   1. Primary: HTF time envelope stamp desc (when present).
    //   2. Fallback: timestamp_secs desc > node_fingerprint asc > content_hash asc.
    //
    // Receipts with HTF stamps sort before receipts without (HTF-bearing
    // receipts carry stronger provenance). Within the HTF group, sort by
    // HTF ns descending. Within the no-HTF group, fall back to the
    // monotonic timestamp + node fingerprint + digest tuple.
    let mut merged_headers: Vec<MergedReceiptHeader> = all_headers.into_values().collect();
    merged_headers.sort_by(|a, b| {
        // HTF-bearing receipts sort before non-HTF receipts.
        // Within HTF group: descending by htf_time_envelope_ns.
        // Within non-HTF group: fallback tuple.
        match (a.htf_time_envelope_ns, b.htf_time_envelope_ns) {
            (Some(a_htf), Some(b_htf)) => {
                // Both have HTF: sort desc by HTF, then fallback.
                b_htf
                    .cmp(&a_htf)
                    .then_with(|| b.timestamp_secs.cmp(&a.timestamp_secs))
                    .then_with(|| {
                        cmp_option_str_asc(
                            a.node_fingerprint.as_deref(),
                            b.node_fingerprint.as_deref(),
                        )
                    })
                    .then_with(|| a.content_hash.cmp(&b.content_hash))
            },
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => {
                // Neither has HTF: fallback tuple.
                b.timestamp_secs
                    .cmp(&a.timestamp_secs)
                    .then_with(|| {
                        cmp_option_str_asc(
                            a.node_fingerprint.as_deref(),
                            b.node_fingerprint.as_deref(),
                        )
                    })
                    .then_with(|| a.content_hash.cmp(&b.content_hash))
            },
        }
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

    /// Regression test: bare-hex filename receipts (without `b3-256:` prefix)
    /// must merge successfully. Previously, integrity verification compared
    /// the recomputed `b3-256:<hex>` hash directly against the bare `<hex>`
    /// filename stem, causing a constant mismatch and treating all bare-hex
    /// files as parse failures.
    #[test]
    fn test_bare_hex_filename_receipts_merge_successfully() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let receipt = make_test_receipt("job-bare-hex", 5000);
        // The receipt's content_hash is `b3-256:<hex>`. Extract the bare hex
        // portion and persist using that as the filename stem instead.
        let bare_hex = receipt
            .content_hash
            .strip_prefix("b3-256:")
            .expect("hash should have b3-256: prefix");
        let bare_path = source.path().join(format!("{bare_hex}.json"));
        let body = serde_json::to_vec_pretty(&receipt).expect("serialize");
        fs::write(&bare_path, body).expect("write bare-hex receipt");

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        // The bare-hex receipt must be copied, not treated as a parse failure.
        assert_eq!(
            report.receipts_copied, 1,
            "bare-hex receipt should be copied, not rejected"
        );
        assert!(
            report.parse_failures.is_empty(),
            "bare-hex receipt must not produce a parse failure: {:?}",
            report.parse_failures
        );
        assert_eq!(report.merged_headers.len(), 1);
        assert_eq!(report.merged_headers[0].job_id, "job-bare-hex");
    }

    /// Regression test: symlink in target directory must not cause the merge
    /// to overwrite an arbitrary file. The atomic write uses
    /// `tempfile::NamedTempFile::new_in()` with `O_EXCL`, which creates a
    /// randomized temp name that cannot be predicted for a symlink attack.
    /// Additionally, `persist()` atomically renames to the final path.
    #[cfg(unix)]
    #[test]
    fn test_symlink_in_target_not_overwritten() {
        use std::os::unix::fs as unix_fs;

        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");
        let victim_dir = tempfile::tempdir().expect("tempdir for victim");

        // Create a receipt in source.
        let receipt = make_test_receipt("job-symlink-test", 7000);
        let digest = persist_receipt(source.path(), &receipt);

        // Create a "victim" file that the attacker wants us to overwrite.
        let victim_path = victim_dir.path().join("precious_data.txt");
        let victim_content = b"ORIGINAL VICTIM CONTENT - MUST NOT BE OVERWRITTEN";
        fs::write(&victim_path, victim_content).expect("write victim");

        // Pre-create a symlink at the final destination path in target,
        // pointing to the victim file. With the old deterministic temp name,
        // this could not happen on the final path (since rename replaces),
        // but we verify the final file does not follow a pre-existing symlink
        // to overwrite the victim.
        let final_name = format!("{digest}.json");
        let symlink_path = target.path().join(&final_name);
        unix_fs::symlink(&victim_path, &symlink_path).expect("create symlink");

        // The merge should succeed — the receipt is written atomically and
        // the persist() call replaces the symlink with a regular file via
        // rename(). The victim file must remain untouched.
        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.receipts_copied, 1);

        // Verify the victim file was NOT overwritten.
        let victim_after = fs::read(&victim_path).expect("read victim after merge");
        assert_eq!(
            victim_after, victim_content,
            "victim file must not be overwritten by merge"
        );

        // Verify the target file is now a regular file (not a symlink).
        let target_meta = fs::symlink_metadata(&symlink_path).expect("metadata for target path");
        assert!(
            !target_meta.file_type().is_symlink(),
            "target path should be a regular file, not a symlink"
        );
    }

    /// Regression test for f-732-security-1771363955822169-0:
    /// Mixed digest filename forms (bare hex vs `b3-256:`-prefixed) for the
    /// same logical receipt must be detected as duplicates.
    ///
    /// Previously, scan maps used the raw filename stem as the key, so a
    /// bare-hex file in source and a `b3-256:`-prefixed file in target (or
    /// vice versa) would not match. This test asserts that
    /// `duplicates_skipped` increments and no extra copy occurs when the
    /// same receipt hash appears in mixed filename forms across source and
    /// target.
    #[test]
    fn test_mixed_digest_filename_forms_detected_as_duplicate() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let receipt = make_test_receipt("job-mixed-form", 9000);
        let prefixed_hash = &receipt.content_hash; // `b3-256:<hex>`
        let bare_hex = prefixed_hash
            .strip_prefix("b3-256:")
            .expect("hash should have b3-256: prefix");

        // Persist to source using bare-hex filename form.
        let bare_path = source.path().join(format!("{bare_hex}.json"));
        let body = serde_json::to_vec_pretty(&receipt).expect("serialize");
        fs::write(&bare_path, &body).expect("write bare-hex receipt to source");

        // Persist to target using `b3-256:`-prefixed filename form.
        let prefixed_path = target.path().join(format!("{prefixed_hash}.json"));
        fs::write(&prefixed_path, &body).expect("write prefixed receipt to target");

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        // The same logical receipt in mixed forms must be detected as a
        // duplicate, not treated as a new receipt.
        assert_eq!(
            report.duplicates_skipped, 1,
            "mixed-form duplicate must be detected: got {report:?}"
        );
        assert_eq!(
            report.receipts_copied, 0,
            "no extra copy should occur for mixed-form duplicate: got {report:?}"
        );
        assert!(
            report.parse_failures.is_empty(),
            "no parse failures expected: {:?}",
            report.parse_failures
        );
        // Only one merged header since it is the same logical receipt.
        assert_eq!(
            report.merged_headers.len(),
            1,
            "only one merged header for a single logical receipt: got {report:?}"
        );
        assert_eq!(report.merged_headers[0].origin, "both");

        // Verify no extra file was written to target: only the original
        // prefixed file should exist (no bare-hex copy).
        let target_files: Vec<_> = fs::read_dir(target.path())
            .expect("read target dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
            .collect();
        assert_eq!(
            target_files.len(),
            1,
            "target should contain exactly one receipt file, not a duplicate: {:?}",
            target_files
                .iter()
                .map(std::fs::DirEntry::path)
                .collect::<Vec<_>>()
        );
    }

    /// Create a test receipt with HTF and/or `node_fingerprint` for
    /// deterministic ordering tests (TCK-00543).
    fn make_test_receipt_with_provenance(
        job_id: &str,
        timestamp_secs: u64,
        htf_time_envelope_ns: Option<u64>,
        node_fingerprint: Option<&str>,
    ) -> FacJobReceiptV1 {
        let receipt_id = format!("test-receipt-{job_id}-{timestamp_secs}");
        let digest = "b3-256:".to_string() + &"ab".repeat(32);
        let mut builder = FacJobReceiptV1Builder::new(&receipt_id, job_id, &digest)
            .outcome(FacJobOutcome::Denied)
            .denial_reason(DenialReasonCode::MalformedSpec)
            .reason("test merge receipt with provenance")
            .timestamp_secs(timestamp_secs);
        if let Some(ns) = htf_time_envelope_ns {
            builder = builder.htf_time_envelope_ns(ns);
        }
        if let Some(fp) = node_fingerprint {
            builder = builder.node_fingerprint(fp);
        }
        let mut receipt = builder
            .try_build()
            .expect("test receipt build should succeed");
        let hash = compute_job_receipt_content_hash_v2(&receipt);
        receipt.content_hash = hash;
        receipt
    }

    /// TCK-00543: Two receipts with the same timestamp but different HTF
    /// envelopes must sort by HTF (descending).
    #[test]
    fn test_htf_ordering_same_timestamp_different_htf() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        // Same timestamp, different HTF stamps.
        let r1 = make_test_receipt_with_provenance("job-htf-low", 1000, Some(100_000), None);
        let r2 = make_test_receipt_with_provenance("job-htf-high", 1000, Some(200_000), None);

        persist_receipt(source.path(), &r1);
        persist_receipt(source.path(), &r2);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.merged_headers.len(), 2);
        // Higher HTF value sorts first (descending).
        assert_eq!(
            report.merged_headers[0].htf_time_envelope_ns,
            Some(200_000),
            "receipt with higher HTF should sort first"
        );
        assert_eq!(
            report.merged_headers[1].htf_time_envelope_ns,
            Some(100_000),
            "receipt with lower HTF should sort second"
        );
    }

    /// TCK-00543: Receipts with HTF stamps sort before receipts without,
    /// regardless of timestamp.
    #[test]
    fn test_htf_receipts_sort_before_non_htf() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        // Non-HTF receipt with a higher timestamp.
        let r_no_htf =
            make_test_receipt_with_provenance("job-no-htf", 9999, None, Some("node-aaa"));
        // HTF receipt with a lower timestamp.
        let r_htf = make_test_receipt_with_provenance("job-htf", 1, Some(1_000), Some("node-bbb"));

        persist_receipt(source.path(), &r_no_htf);
        persist_receipt(source.path(), &r_htf);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.merged_headers.len(), 2);
        // HTF receipt sorts first despite lower timestamp.
        assert!(
            report.merged_headers[0].htf_time_envelope_ns.is_some(),
            "HTF-bearing receipt must sort before non-HTF"
        );
        assert!(
            report.merged_headers[1].htf_time_envelope_ns.is_none(),
            "non-HTF receipt must sort after HTF-bearing"
        );
    }

    /// TCK-00543: Two receipts with same timestamp and no HTF sort by
    /// `node_fingerprint` ascending.
    #[test]
    fn test_no_htf_same_timestamp_sort_by_node_fingerprint() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let r1 = make_test_receipt_with_provenance("job-node-z", 1000, None, Some("node-zzz"));
        let r2 = make_test_receipt_with_provenance("job-node-a", 1000, None, Some("node-aaa"));

        persist_receipt(source.path(), &r1);
        persist_receipt(source.path(), &r2);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.merged_headers.len(), 2);
        // Same timestamp, no HTF: sorted by node_fingerprint ascending.
        assert_eq!(
            report.merged_headers[0].node_fingerprint.as_deref(),
            Some("node-aaa"),
            "lower node_fingerprint should sort first"
        );
        assert_eq!(
            report.merged_headers[1].node_fingerprint.as_deref(),
            Some("node-zzz"),
            "higher node_fingerprint should sort second"
        );
    }

    /// TCK-00543: Receipts with `node_fingerprint` sort before those without
    /// when timestamps are equal and no HTF is present.
    #[test]
    fn test_no_htf_same_timestamp_fingerprint_before_no_fingerprint() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let r_with_fp = make_test_receipt_with_provenance("job-fp", 1000, None, Some("node-xxx"));
        let r_no_fp = make_test_receipt_with_provenance("job-no-fp", 1000, None, None);

        persist_receipt(source.path(), &r_with_fp);
        persist_receipt(source.path(), &r_no_fp);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.merged_headers.len(), 2);
        // Receipt with fingerprint sorts before receipt without.
        assert!(
            report.merged_headers[0].node_fingerprint.is_some(),
            "receipt with node_fingerprint sorts first"
        );
        assert!(
            report.merged_headers[1].node_fingerprint.is_none(),
            "receipt without node_fingerprint sorts second"
        );
    }

    /// TCK-00543: Full fallback chain is deterministic — same inputs always
    /// produce the same ordering regardless of insertion order.
    #[test]
    fn test_full_ordering_determinism() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        // Mix of HTF, non-HTF, with/without node_fingerprint.
        let r_htf_high =
            make_test_receipt_with_provenance("job-htf-hi", 5000, Some(500_000), Some("node-aaa"));
        let r_htf_low =
            make_test_receipt_with_provenance("job-htf-lo", 5000, Some(100_000), Some("node-bbb"));
        let r_no_htf_a =
            make_test_receipt_with_provenance("job-no-htf-a", 3000, None, Some("node-aaa"));
        let r_no_htf_z =
            make_test_receipt_with_provenance("job-no-htf-z", 3000, None, Some("node-zzz"));
        let r_no_htf_none = make_test_receipt_with_provenance("job-no-htf-none", 3000, None, None);

        persist_receipt(source.path(), &r_htf_high);
        persist_receipt(source.path(), &r_htf_low);
        persist_receipt(source.path(), &r_no_htf_a);
        persist_receipt(source.path(), &r_no_htf_z);
        persist_receipt(target.path(), &r_no_htf_none);

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(report.merged_headers.len(), 5);

        // Expected order:
        // 1. HTF high (500k ns) — HTF receipts first, descending
        // 2. HTF low (100k ns) — HTF receipts first, descending
        // 3. no-HTF, ts=3000, node-aaa — fallback: ts desc, fingerprint asc
        // 4. no-HTF, ts=3000, node-zzz — fallback: ts desc, fingerprint asc
        // 5. no-HTF, ts=3000, no fingerprint — None sorts after Some
        assert_eq!(report.merged_headers[0].htf_time_envelope_ns, Some(500_000));
        assert_eq!(report.merged_headers[1].htf_time_envelope_ns, Some(100_000));
        assert!(report.merged_headers[2].htf_time_envelope_ns.is_none());
        assert_eq!(
            report.merged_headers[2].node_fingerprint.as_deref(),
            Some("node-aaa")
        );
        assert!(report.merged_headers[3].htf_time_envelope_ns.is_none());
        assert_eq!(
            report.merged_headers[3].node_fingerprint.as_deref(),
            Some("node-zzz")
        );
        assert!(report.merged_headers[4].htf_time_envelope_ns.is_none());
        assert!(report.merged_headers[4].node_fingerprint.is_none());

        // Run again and verify identical ordering (determinism).
        let source2 = tempfile::tempdir().expect("tempdir");
        let target2 = tempfile::tempdir().expect("tempdir");
        // Persist in reverse order to test ordering independence.
        persist_receipt(target2.path(), &r_no_htf_none);
        persist_receipt(target2.path(), &r_no_htf_z);
        persist_receipt(source2.path(), &r_no_htf_a);
        persist_receipt(source2.path(), &r_htf_low);
        persist_receipt(source2.path(), &r_htf_high);

        let report2 =
            merge_receipt_dirs(source2.path(), target2.path()).expect("merge should succeed");

        assert_eq!(report2.merged_headers.len(), 5);
        for (i, (h1, h2)) in report
            .merged_headers
            .iter()
            .zip(report2.merged_headers.iter())
            .enumerate()
        {
            assert_eq!(
                h1.content_hash, h2.content_hash,
                "determinism: position {i} content_hash mismatch"
            );
        }
    }

    /// Regression test: mixed forms in the reverse direction (prefixed in
    /// source, bare-hex in target) must also be detected as duplicates.
    #[test]
    fn test_mixed_digest_filename_forms_reverse_direction() {
        let source = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");

        let receipt = make_test_receipt("job-mixed-reverse", 8000);
        let prefixed_hash = &receipt.content_hash;
        let bare_hex = prefixed_hash
            .strip_prefix("b3-256:")
            .expect("hash should have b3-256: prefix");

        // Persist to source using `b3-256:`-prefixed filename form.
        let prefixed_path = source.path().join(format!("{prefixed_hash}.json"));
        let body = serde_json::to_vec_pretty(&receipt).expect("serialize");
        fs::write(&prefixed_path, &body).expect("write prefixed receipt to source");

        // Persist to target using bare-hex filename form.
        let bare_path = target.path().join(format!("{bare_hex}.json"));
        fs::write(&bare_path, &body).expect("write bare-hex receipt to target");

        let report =
            merge_receipt_dirs(source.path(), target.path()).expect("merge should succeed");

        assert_eq!(
            report.duplicates_skipped, 1,
            "reverse mixed-form duplicate must be detected: got {report:?}"
        );
        assert_eq!(
            report.receipts_copied, 0,
            "no extra copy for reverse mixed-form duplicate: got {report:?}"
        );
        assert!(report.parse_failures.is_empty());
        assert_eq!(report.merged_headers.len(), 1);
        assert_eq!(report.merged_headers[0].origin, "both");
    }
}
