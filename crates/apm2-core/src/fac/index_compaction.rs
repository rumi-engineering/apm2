//! Receipt index compaction: prune old time buckets, rebuild deterministically,
//! and emit `IndexCompactionReceiptV1`.
//!
//! This module implements bounded index retention policies for the receipt
//! index (TCK-00583). The receipt index is a non-authoritative cache;
//! compaction removes stale entries to keep disk and memory usage bounded while
//! preserving the ability to rebuild from the authoritative receipt store.
//!
//! # Design
//!
//! - **Retention policy**: entries older than `retention_secs` are pruned from
//!   the in-memory index.
//! - **Deterministic rebuild**: after pruning, the index is persisted
//!   atomically so the on-disk representation is always self-consistent.
//! - **Receipt emission**: every compaction emits an `IndexCompactionReceiptV1`
//!   documenting what was pruned, enabling audit trails.
//! - **GC integration**: compaction is a low-impact step in the `apm2 fac gc`
//!   escalation path.
//!
//! # Security Model
//!
//! The receipt index is non-authoritative (attacker-writable under A2
//! assumptions). Compaction does not affect the authoritative receipt store.
//! On any inconsistency, the system rebuilds from the receipt store.
//!
//! # Out of Scope
//!
//! Deleting receipts from the content-addressed store is forbidden by default
//! (TCK-00583 out_of_scope).

use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::receipt_index::{ReceiptIndexError, ReceiptIndexV1};

// =============================================================================
// Constants
// =============================================================================

/// Schema identifier for the index compaction receipt.
pub const INDEX_COMPACTION_RECEIPT_SCHEMA: &str = "apm2.fac.index_compaction_receipt.v1";

/// Default index entry retention: 30 days (in seconds).
///
/// Entries older than this are pruned during compaction. The index can always
/// be rebuilt from the receipt store, so pruning is safe.
pub const DEFAULT_INDEX_RETENTION_SECS: u64 = 30 * 24 * 3600;

/// Maximum number of compaction receipts that can be loaded during metrics.
/// Prevents unbounded collection growth when scanning receipt directories.
pub const MAX_COMPACTION_RECEIPTS: usize = 1024;

/// Maximum serialized size of a compaction receipt (256 KiB).
pub const MAX_COMPACTION_RECEIPT_SIZE: usize = 262_144;

/// Expected length of a BLAKE3 hex-encoded digest string (32 bytes = 64 hex
/// chars).
const BLAKE3_HEX_LEN: usize = 64;

/// Validate that a content hash is a strict BLAKE3 hex digest.
///
/// Returns `Ok(())` if the string is exactly 64 lowercase hex characters.
/// Returns `Err` with a description otherwise.
fn validate_strict_hex_digest(hash: &str) -> Result<(), String> {
    if hash.len() != BLAKE3_HEX_LEN {
        return Err(format!(
            "content hash length {}, expected {BLAKE3_HEX_LEN}",
            hash.len()
        ));
    }
    if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("content hash contains non-hex characters".to_string());
    }
    Ok(())
}

// =============================================================================
// Compaction Receipt
// =============================================================================

/// Receipt documenting an index compaction operation.
///
/// Emitted by [`compact_index`] and persisted alongside GC receipts for
/// audit and observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexCompactionReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Wall-clock timestamp of compaction (seconds since UNIX epoch).
    pub timestamp_secs: u64,
    /// Retention window applied (seconds).
    pub retention_secs: u64,
    /// Cutoff timestamp: entries with `timestamp_secs < cutoff` were pruned.
    pub cutoff_timestamp_secs: u64,
    /// Number of header entries before compaction.
    pub entries_before: usize,
    /// Number of header entries after compaction.
    pub entries_after: usize,
    /// Number of header entries pruned.
    pub entries_pruned: usize,
    /// Number of job index entries before compaction.
    pub jobs_before: usize,
    /// Number of job index entries after compaction.
    pub jobs_after: usize,
    /// Number of job index entries pruned.
    pub jobs_pruned: usize,
    /// Rebuild epoch of the index after compaction.
    pub rebuild_epoch_after: u64,
    /// BLAKE3 content hash over canonical JSON (computed with this field
    /// set to empty string).
    pub content_hash: String,
}

impl IndexCompactionReceiptV1 {
    /// Validate this receipt for structural correctness.
    ///
    /// # Errors
    ///
    /// Returns an error string if required fields are missing or invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != INDEX_COMPACTION_RECEIPT_SCHEMA {
            return Err(format!(
                "schema mismatch: expected {INDEX_COMPACTION_RECEIPT_SCHEMA}, found {}",
                self.schema
            ));
        }
        if self.receipt_id.trim().is_empty() {
            return Err("receipt_id must not be empty".to_string());
        }
        if self.timestamp_secs == 0 {
            return Err("timestamp_secs must be positive".to_string());
        }
        if self.retention_secs == 0 {
            return Err("retention_secs must be positive".to_string());
        }
        if self.entries_pruned != self.entries_before.saturating_sub(self.entries_after) {
            return Err("entries_pruned does not match before/after delta".to_string());
        }
        if self.jobs_pruned != self.jobs_before.saturating_sub(self.jobs_after) {
            return Err("jobs_pruned does not match before/after delta".to_string());
        }
        Ok(())
    }

    /// Compute the BLAKE3 content hash over canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn compute_content_hash(&self) -> Result<String, String> {
        let mut copy = self.clone();
        copy.content_hash = String::new();
        let json = serde_json::to_string(&copy)
            .map_err(|e| format!("failed to serialize compaction receipt: {e}"))?;
        let canonical = crate::determinism::canonicalize_json(&json)
            .map_err(|e| format!("failed to canonicalize compaction receipt: {e}"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(INDEX_COMPACTION_RECEIPT_SCHEMA.as_bytes());
        hasher.update(b"\0");
        hasher.update(canonical.as_bytes());
        Ok(hasher.finalize().to_hex().to_string())
    }
}

// =============================================================================
// Compaction Logic
// =============================================================================

/// Compact the receipt index by pruning entries older than the retention
/// window.
///
/// 1. Loads (or rebuilds) the index from `receipts_dir`.
/// 2. Removes all header entries with `timestamp_secs < cutoff`.
/// 3. Removes orphaned job index entries (jobs whose latest receipt was
///    pruned).
/// 4. Persists the compacted index atomically.
/// 5. Returns an `IndexCompactionReceiptV1` documenting the operation.
///
/// # Arguments
///
/// - `receipts_dir`: path to the receipt store directory.
/// - `retention_secs`: retention window in seconds. Entries older than
///   `now_secs - retention_secs` are pruned.
/// - `now_secs`: current wall-clock time in seconds since UNIX epoch.
///
/// # Errors
///
/// Returns [`ReceiptIndexError`] if the index cannot be loaded or persisted.
/// Returns `CompactionError::ReceiptEmission` if the receipt cannot be
/// constructed.
pub fn compact_index(
    receipts_dir: &Path,
    retention_secs: u64,
    now_secs: u64,
) -> Result<IndexCompactionReceiptV1, CompactionError> {
    // Fail-closed: zero retention means no compaction (preserve everything).
    if retention_secs == 0 {
        return Err(CompactionError::InvalidRetention(
            "retention_secs must be positive".to_string(),
        ));
    }

    let mut index =
        ReceiptIndexV1::load_or_rebuild(receipts_dir).map_err(CompactionError::Index)?;

    let entries_before = index.header_index.len();
    let jobs_before = index.job_index.len();

    let cutoff = now_secs.saturating_sub(retention_secs);

    // Collect content hashes to prune (entries older than cutoff).
    let hashes_to_prune: Vec<String> = index
        .header_index
        .iter()
        .filter(|(_, header)| header.timestamp_secs < cutoff)
        .map(|(hash, _)| hash.clone())
        .collect();

    // Remove pruned headers.
    for hash in &hashes_to_prune {
        index.header_index.remove(hash);
    }

    // Rebuild job_index: for each job, find the latest remaining header.
    // Remove jobs that have no remaining headers, and update pointers for
    // jobs whose latest receipt was pruned but older receipts remain.
    //
    // Deterministic tie-breaking for equal timestamps:
    //   1. If the current job_index digest is still present at the max timestamp,
    //      keep it (stability: compaction does not flip pointers when no stale
    //      entry for the job was relevant).
    //   2. Otherwise, break ties by lexicographically greatest content_hash
    //      (deterministic across HashMap iteration orders and process seeds).
    let jobs_to_check: Vec<String> = index.job_index.keys().cloned().collect();
    for job_id in &jobs_to_check {
        // Collect all remaining headers for this job.
        let candidates: Vec<&super::receipt_index::ReceiptHeaderV1> = index
            .header_index
            .values()
            .filter(|h| h.job_id == *job_id)
            .collect();

        // Select the winner using a deterministic comparator:
        //   Primary key: timestamp_secs (descending — greatest wins).
        //   Tie-break:   content_hash   (descending — lex-greatest wins).
        // This is fully deterministic regardless of HashMap iteration order.
        let deterministic_winner = candidates.iter().max_by(|a, b| {
            a.timestamp_secs
                .cmp(&b.timestamp_secs)
                .then_with(|| a.content_hash.cmp(&b.content_hash))
        });

        let Some(det_winner) = deterministic_winner else {
            // No remaining headers for this job — remove from job_index.
            index.job_index.remove(job_id);
            continue;
        };

        // Stability preference: if the current job_index digest is still
        // present at the max timestamp, keep it instead of the deterministic
        // winner. This prevents compaction from flipping pointers when the
        // current receipt is still valid at the max timestamp.
        let max_ts = det_winner.timestamp_secs;
        let current_digest = index.job_index.get(job_id).cloned();

        let winner_digest = current_digest
            .as_ref()
            .filter(|current| {
                // Keep current digest only if it is among candidates at
                // the max timestamp.
                candidates
                    .iter()
                    .any(|h| h.content_hash == **current && h.timestamp_secs == max_ts)
            })
            .cloned()
            .unwrap_or_else(|| det_winner.content_hash.clone());

        index.job_index.insert(job_id.clone(), winner_digest);
    }

    let entries_after = index.header_index.len();
    let jobs_after = index.job_index.len();
    let entries_pruned = entries_before.saturating_sub(entries_after);
    let jobs_pruned = jobs_before.saturating_sub(jobs_after);

    // Persist the compacted index.
    index
        .persist(receipts_dir)
        .map_err(CompactionError::Index)?;

    // Build the compaction receipt.
    let mut receipt = IndexCompactionReceiptV1 {
        schema: INDEX_COMPACTION_RECEIPT_SCHEMA.to_string(),
        receipt_id: now_secs.to_string(),
        timestamp_secs: now_secs,
        retention_secs,
        cutoff_timestamp_secs: cutoff,
        entries_before,
        entries_after,
        entries_pruned,
        jobs_before,
        jobs_after,
        jobs_pruned,
        rebuild_epoch_after: index.rebuild_epoch,
        content_hash: String::new(),
    };

    let content_hash = receipt
        .compute_content_hash()
        .map_err(CompactionError::ReceiptEmission)?;
    receipt.content_hash = content_hash;

    Ok(receipt)
}

/// Persist an index compaction receipt to the receipts directory.
///
/// Uses content-addressed naming: `{prefix}/{suffix}.json` where the full
/// string is the recomputed content hash. The receipt's `content_hash` field
/// is validated by recomputing the BLAKE3 digest from canonical bytes and
/// comparing via constant-time equality. The hash must be strict hex-only,
/// fixed-length (64 chars for BLAKE3-256), and the final path is verified
/// to remain within `receipts_dir`.
///
/// Persistence uses `NamedTempFile::new_in` for unpredictable temp names,
/// restrictive permissions, fsync, and atomic rename.
///
/// # Errors
///
/// Returns an error string if validation, persistence, or path construction
/// fails.
pub fn persist_compaction_receipt(
    receipts_dir: &Path,
    receipt: &IndexCompactionReceiptV1,
) -> Result<std::path::PathBuf, String> {
    receipt.validate()?;

    // --- Step 1: Recompute content hash and compare via constant-time eq ---
    let expected_hash = receipt.compute_content_hash()?;
    let claimed_hash = &receipt.content_hash;

    // Constant-time comparison to prevent timing side-channels on hash values.
    if expected_hash
        .as_bytes()
        .ct_eq(claimed_hash.as_bytes())
        .into()
    {
        // match — proceed
    } else {
        return Err(format!(
            "content hash mismatch: expected {expected_hash}, found {claimed_hash}"
        ));
    }

    // --- Step 2: Validate strict hex digest format ---
    validate_strict_hex_digest(claimed_hash)?;

    // --- Step 3: Serialize and check size ---
    let bytes = serde_json::to_vec_pretty(receipt)
        .map_err(|e| format!("failed to serialize compaction receipt: {e}"))?;

    if bytes.len() > MAX_COMPACTION_RECEIPT_SIZE {
        return Err(format!(
            "compaction receipt exceeds max size: {} > {MAX_COMPACTION_RECEIPT_SIZE}",
            bytes.len()
        ));
    }

    // --- Step 4: Construct path from validated hex digest ---
    // After validate_strict_hex_digest, claimed_hash is exactly 64 hex chars.
    let prefix = &claimed_hash[..2];
    let suffix = &claimed_hash[2..];
    let dir = receipts_dir.join(prefix);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder
            .create(&dir)
            .map_err(|e| format!("failed to create receipt dir: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create receipt dir: {e}"))?;
    }

    let final_path = dir.join(format!("{suffix}.json"));

    // Defense-in-depth: verify final path is within receipts_dir.
    // Canonicalize both to resolve any symbolic links or `.` components.
    let canonical_receipts = receipts_dir
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize receipts_dir: {e}"))?;
    let canonical_parent = dir
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize target dir: {e}"))?;
    if !canonical_parent.starts_with(&canonical_receipts) {
        return Err(format!(
            "path traversal detected: {} escapes {}",
            canonical_parent.display(),
            canonical_receipts.display()
        ));
    }

    // --- Step 5: Atomic write via NamedTempFile ---
    let mut tmp_file = tempfile::NamedTempFile::new_in(&dir)
        .map_err(|e| format!("failed to create temp file for compaction receipt: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let perms = std::fs::Permissions::from_mode(0o600);
        tmp_file
            .as_file()
            .set_permissions(perms)
            .map_err(|e| format!("failed to set temp file permissions: {e}"))?;
    }

    tmp_file
        .write_all(&bytes)
        .map_err(|e| format!("failed to write compaction receipt: {e}"))?;
    tmp_file
        .as_file()
        .sync_all()
        .map_err(|e| format!("failed to fsync compaction receipt: {e}"))?;
    tmp_file
        .persist(&final_path)
        .map_err(|e| format!("failed to persist compaction receipt: {e}"))?;

    Ok(final_path)
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors from index compaction operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum CompactionError {
    /// Index load/rebuild/persist failure.
    Index(ReceiptIndexError),
    /// Invalid retention parameter.
    InvalidRetention(String),
    /// Receipt construction failure.
    ReceiptEmission(String),
}

impl std::fmt::Display for CompactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Index(e) => write!(f, "index error: {e}"),
            Self::InvalidRetention(msg) => write!(f, "invalid retention: {msg}"),
            Self::ReceiptEmission(msg) => write!(f, "receipt emission error: {msg}"),
        }
    }
}

impl std::error::Error for CompactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Index(e) => Some(e),
            _ => None,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::receipt::FacJobOutcome;
    use crate::fac::receipt_index::{ReceiptHeaderV1, ReceiptIndexV1};

    fn make_header(job_id: &str, content_hash: &str, timestamp: u64) -> ReceiptHeaderV1 {
        ReceiptHeaderV1 {
            content_hash: content_hash.to_string(),
            job_id: job_id.to_string(),
            outcome: FacJobOutcome::Completed,
            timestamp_secs: timestamp,
            queue_lane: Some("default".to_string()),
            unsafe_direct: false,
        }
    }

    fn setup_index_with_entries(
        receipts_dir: &Path,
        entries: &[(&str, &str, u64)],
    ) -> ReceiptIndexV1 {
        let mut index = ReceiptIndexV1::new();
        for &(job_id, hash, ts) in entries {
            index.upsert(make_header(job_id, hash, ts)).expect("upsert");
        }
        index.persist(receipts_dir).expect("persist");
        index
    }

    #[test]
    fn compact_prunes_old_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create index with entries at various timestamps.
        // now=1000, retention=500 => cutoff=500
        // Entries at ts=100,200 should be pruned; ts=600,800 should remain.
        setup_index_with_entries(
            receipts_dir,
            &[
                ("job-old-1", "hash-old-1", 100),
                ("job-old-2", "hash-old-2", 200),
                ("job-new-1", "hash-new-1", 600),
                ("job-new-2", "hash-new-2", 800),
            ],
        );

        let receipt = compact_index(receipts_dir, 500, 1000).expect("compact");

        assert_eq!(receipt.entries_before, 4);
        assert_eq!(receipt.entries_after, 2);
        assert_eq!(receipt.entries_pruned, 2);
        assert_eq!(receipt.jobs_before, 4);
        assert_eq!(receipt.jobs_after, 2);
        assert_eq!(receipt.jobs_pruned, 2);
        assert_eq!(receipt.cutoff_timestamp_secs, 500);
        assert_eq!(receipt.retention_secs, 500);
        assert_eq!(receipt.schema, INDEX_COMPACTION_RECEIPT_SCHEMA);
        assert!(!receipt.content_hash.is_empty());

        // Verify the persisted index only contains new entries.
        let reloaded = ReceiptIndexV1::load(receipts_dir)
            .expect("load")
            .expect("some");
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.header_for_digest("hash-new-1").is_some());
        assert!(reloaded.header_for_digest("hash-new-2").is_some());
        assert!(reloaded.header_for_digest("hash-old-1").is_none());
        assert!(reloaded.header_for_digest("hash-old-2").is_none());
    }

    #[test]
    fn compact_no_op_when_all_entries_within_retention() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        setup_index_with_entries(
            receipts_dir,
            &[("job-1", "hash-1", 900), ("job-2", "hash-2", 950)],
        );

        let receipt = compact_index(receipts_dir, 500, 1000).expect("compact");

        assert_eq!(receipt.entries_before, 2);
        assert_eq!(receipt.entries_after, 2);
        assert_eq!(receipt.entries_pruned, 0);
        assert_eq!(receipt.jobs_pruned, 0);
    }

    #[test]
    fn compact_prunes_all_entries_when_all_stale() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        setup_index_with_entries(
            receipts_dir,
            &[("job-1", "hash-1", 100), ("job-2", "hash-2", 200)],
        );

        let receipt = compact_index(receipts_dir, 500, 1000).expect("compact");

        assert_eq!(receipt.entries_before, 2);
        assert_eq!(receipt.entries_after, 0);
        assert_eq!(receipt.entries_pruned, 2);
        assert_eq!(receipt.jobs_pruned, 2);

        let reloaded = ReceiptIndexV1::load(receipts_dir)
            .expect("load")
            .expect("some");
        assert!(reloaded.is_empty());
    }

    #[test]
    fn compact_rejects_zero_retention() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        setup_index_with_entries(receipts_dir, &[("job-1", "hash-1", 100)]);

        let result = compact_index(receipts_dir, 0, 1000);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), CompactionError::InvalidRetention(_)),
            "zero retention must be rejected (fail-closed)"
        );
    }

    #[test]
    fn compact_handles_missing_index_by_rebuilding() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // No index file exists — compact should rebuild (empty) and succeed.
        let receipt = compact_index(receipts_dir, 500, 1000).expect("compact");

        assert_eq!(receipt.entries_before, 0);
        assert_eq!(receipt.entries_after, 0);
        assert_eq!(receipt.entries_pruned, 0);
    }

    #[test]
    fn compact_preserves_job_with_mixed_age_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Same job with two receipts: one old (pruned), one new (kept).
        // now=1000, retention=500 => cutoff=500
        let mut index = ReceiptIndexV1::new();
        index
            .upsert(make_header("job-1", "hash-old", 100))
            .expect("upsert old");
        index
            .upsert(make_header("job-1", "hash-new", 700))
            .expect("upsert new");
        index.persist(receipts_dir).expect("persist");

        let receipt = compact_index(receipts_dir, 500, 1000).expect("compact");

        // Old header pruned, new header kept.
        assert_eq!(receipt.entries_before, 2);
        assert_eq!(receipt.entries_after, 1);
        assert_eq!(receipt.entries_pruned, 1);
        // Job still has a remaining header, so job_index should still contain it.
        assert_eq!(receipt.jobs_before, 1);
        assert_eq!(receipt.jobs_after, 1);
        assert_eq!(receipt.jobs_pruned, 0);

        let reloaded = ReceiptIndexV1::load(receipts_dir)
            .expect("load")
            .expect("some");
        assert_eq!(reloaded.latest_digest_for_job("job-1"), Some("hash-new"));
    }

    #[test]
    fn compact_receipt_is_deterministic() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        setup_index_with_entries(
            receipts_dir,
            &[("job-1", "hash-1", 100), ("job-2", "hash-2", 800)],
        );

        let receipt_a = compact_index(receipts_dir, 500, 1000).expect("compact a");

        // Re-setup the same state.
        setup_index_with_entries(
            receipts_dir,
            &[("job-1", "hash-1", 100), ("job-2", "hash-2", 800)],
        );

        let receipt_b = compact_index(receipts_dir, 500, 1000).expect("compact b");

        assert_eq!(receipt_a.content_hash, receipt_b.content_hash);
    }

    #[test]
    fn compact_receipt_validate_succeeds_for_valid() {
        let receipt = IndexCompactionReceiptV1 {
            schema: INDEX_COMPACTION_RECEIPT_SCHEMA.to_string(),
            receipt_id: "test-1".to_string(),
            timestamp_secs: 1000,
            retention_secs: 500,
            cutoff_timestamp_secs: 500,
            entries_before: 4,
            entries_after: 2,
            entries_pruned: 2,
            jobs_before: 4,
            jobs_after: 2,
            jobs_pruned: 2,
            rebuild_epoch_after: 1,
            content_hash: "abc".to_string(),
        };
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn compact_receipt_validate_rejects_bad_schema() {
        let receipt = IndexCompactionReceiptV1 {
            schema: "wrong".to_string(),
            receipt_id: "test-1".to_string(),
            timestamp_secs: 1000,
            retention_secs: 500,
            cutoff_timestamp_secs: 500,
            entries_before: 0,
            entries_after: 0,
            entries_pruned: 0,
            jobs_before: 0,
            jobs_after: 0,
            jobs_pruned: 0,
            rebuild_epoch_after: 0,
            content_hash: String::new(),
        };
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn compact_receipt_validate_rejects_zero_timestamp() {
        let receipt = IndexCompactionReceiptV1 {
            schema: INDEX_COMPACTION_RECEIPT_SCHEMA.to_string(),
            receipt_id: "test-1".to_string(),
            timestamp_secs: 0,
            retention_secs: 500,
            cutoff_timestamp_secs: 500,
            entries_before: 0,
            entries_after: 0,
            entries_pruned: 0,
            jobs_before: 0,
            jobs_after: 0,
            jobs_pruned: 0,
            rebuild_epoch_after: 0,
            content_hash: String::new(),
        };
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn compact_receipt_validate_rejects_inconsistent_counts() {
        let receipt = IndexCompactionReceiptV1 {
            schema: INDEX_COMPACTION_RECEIPT_SCHEMA.to_string(),
            receipt_id: "test-1".to_string(),
            timestamp_secs: 1000,
            retention_secs: 500,
            cutoff_timestamp_secs: 500,
            entries_before: 4,
            entries_after: 2,
            entries_pruned: 5, // Wrong: should be 2.
            jobs_before: 0,
            jobs_after: 0,
            jobs_pruned: 0,
            rebuild_epoch_after: 0,
            content_hash: String::new(),
        };
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn persist_compaction_receipt_creates_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = IndexCompactionReceiptV1 {
            schema: INDEX_COMPACTION_RECEIPT_SCHEMA.to_string(),
            receipt_id: "persist-test".to_string(),
            timestamp_secs: 1000,
            retention_secs: 500,
            cutoff_timestamp_secs: 500,
            entries_before: 0,
            entries_after: 0,
            entries_pruned: 0,
            jobs_before: 0,
            jobs_after: 0,
            jobs_pruned: 0,
            rebuild_epoch_after: 0,
            content_hash: String::new(),
        };
        let hash = receipt.compute_content_hash().expect("hash");
        receipt.content_hash = hash;

        let path = persist_compaction_receipt(receipts_dir, &receipt).expect("persist");
        assert!(path.exists());

        // Verify roundtrip.
        let bytes = std::fs::read(&path).expect("read");
        let loaded: IndexCompactionReceiptV1 = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(loaded.schema, INDEX_COMPACTION_RECEIPT_SCHEMA);
        assert_eq!(loaded.content_hash, receipt.content_hash);
    }

    #[test]
    fn compact_receipt_content_hash_deterministic() {
        let receipt = IndexCompactionReceiptV1 {
            schema: INDEX_COMPACTION_RECEIPT_SCHEMA.to_string(),
            receipt_id: "det-test".to_string(),
            timestamp_secs: 42,
            retention_secs: 100,
            cutoff_timestamp_secs: 0,
            entries_before: 10,
            entries_after: 5,
            entries_pruned: 5,
            jobs_before: 10,
            jobs_after: 5,
            jobs_pruned: 5,
            rebuild_epoch_after: 3,
            content_hash: String::new(),
        };

        let hash_a = receipt.compute_content_hash().expect("hash a");
        let hash_b = receipt.compute_content_hash().expect("hash b");
        assert_eq!(hash_a, hash_b, "content hash must be deterministic");
    }

    #[test]
    fn compact_cutoff_boundary_is_exclusive() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // now=1000, retention=500 => cutoff=500
        // Entry at exactly ts=500 should NOT be pruned (cutoff is exclusive:
        // only entries with timestamp_secs < cutoff are pruned).
        setup_index_with_entries(
            receipts_dir,
            &[
                ("job-boundary", "hash-boundary", 500),
                ("job-old", "hash-old", 499),
            ],
        );

        let receipt = compact_index(receipts_dir, 500, 1000).expect("compact");

        assert_eq!(receipt.entries_pruned, 1);
        assert_eq!(receipt.entries_after, 1);

        let reloaded = ReceiptIndexV1::load(receipts_dir)
            .expect("load")
            .expect("some");
        assert!(
            reloaded.header_for_digest("hash-boundary").is_some(),
            "entry at exact cutoff must be retained"
        );
        assert!(
            reloaded.header_for_digest("hash-old").is_none(),
            "entry below cutoff must be pruned"
        );
    }

    // =========================================================================
    // Regression: compaction must not flip job_index on equal-timestamp ties
    // (MAJOR finding — nondeterministic HashMap iteration order).
    // =========================================================================

    #[test]
    fn compact_does_not_flip_latest_digest_on_equal_timestamp_ties() {
        // Two receipts for the same job with identical timestamps but
        // different content hashes. Compaction must produce a stable,
        // deterministic result regardless of HashMap iteration order.
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Insert two same-timestamp receipts for the same job.
        let mut index = ReceiptIndexV1::new();
        index
            .upsert(make_header("job-tie", "aaaa_digest_first", 800))
            .expect("upsert a");
        index
            .upsert(make_header("job-tie", "zzzz_digest_second", 800))
            .expect("upsert b");
        index.persist(receipts_dir).expect("persist");

        // Record what job_index points to before compaction.
        let pre_compaction_digest = index
            .latest_digest_for_job("job-tie")
            .expect("pre-compaction digest")
            .to_string();

        // Run compaction multiple times; the result must be stable.
        // now=2000, retention=5000 => cutoff=-3000 (clamped to 0) => nothing pruned.
        let mut observed_digests = std::collections::HashSet::new();
        for _ in 0..20 {
            // Re-setup the index each time to exercise different HashMap seeds.
            let mut fresh_index = ReceiptIndexV1::new();
            fresh_index
                .upsert(make_header("job-tie", "aaaa_digest_first", 800))
                .expect("upsert a");
            fresh_index
                .upsert(make_header("job-tie", "zzzz_digest_second", 800))
                .expect("upsert b");
            fresh_index.persist(receipts_dir).expect("persist");

            let receipt = compact_index(receipts_dir, 5000, 2000).expect("compact");
            assert_eq!(receipt.entries_pruned, 0, "no entries should be pruned");

            let reloaded = ReceiptIndexV1::load(receipts_dir)
                .expect("load")
                .expect("some");
            let digest = reloaded
                .latest_digest_for_job("job-tie")
                .expect("digest after compaction")
                .to_string();
            observed_digests.insert(digest);
        }

        // The compaction must always pick the same digest (stability).
        assert_eq!(
            observed_digests.len(),
            1,
            "compaction must produce a stable job_index pointer across runs, \
             but observed {} distinct digests: {:?}",
            observed_digests.len(),
            observed_digests
        );

        // Additionally: the stable digest should be the pre-compaction one
        // (since both receipts are retained, the current pointer is stable).
        let stable_digest = observed_digests.into_iter().next().unwrap();
        assert_eq!(
            stable_digest, pre_compaction_digest,
            "compaction must preserve the pre-compaction job_index pointer \
             when both tied receipts are retained"
        );
    }

    #[test]
    fn compact_deterministic_tiebreak_when_current_digest_pruned() {
        // When the current job_index digest is pruned and two remaining
        // receipts tie on timestamp, compaction must pick the
        // lexicographically greatest content_hash (deterministic).
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut index = ReceiptIndexV1::new();
        // Old receipt (will be pruned): this is currently the "latest" via upsert.
        index
            .upsert(make_header("job-tie2", "cccc_old_pruned", 100))
            .expect("upsert old");
        // Two newer receipts with same timestamp (both retained).
        index
            .upsert(make_header("job-tie2", "aaaa_newer_low", 800))
            .expect("upsert a");
        index
            .upsert(make_header("job-tie2", "zzzz_newer_high", 800))
            .expect("upsert b");
        index.persist(receipts_dir).expect("persist");

        // now=1000, retention=500 => cutoff=500
        // cccc_old_pruned (ts=100) is pruned; both aaaa and zzzz (ts=800)
        // remain. The current digest after upsert is "zzzz_newer_high"
        // (last-writer-wins in upsert). After pruning, both aaaa and zzzz
        // are at max ts=800. The current digest ("zzzz_newer_high") is
        // still present, so it should be kept.
        let receipt = compact_index(receipts_dir, 500, 1000).expect("compact");
        assert_eq!(receipt.entries_pruned, 1);

        let reloaded = ReceiptIndexV1::load(receipts_dir)
            .expect("load")
            .expect("some");
        let digest = reloaded
            .latest_digest_for_job("job-tie2")
            .expect("digest after compaction");

        // Current digest "zzzz_newer_high" is at max timestamp, so it is kept.
        assert_eq!(
            digest, "zzzz_newer_high",
            "must keep current digest when it is at max timestamp"
        );
    }

    #[test]
    fn compact_lex_greatest_tiebreak_when_current_not_at_max() {
        // Verify the lexicographic tiebreak when the current pointer is
        // NOT at the max timestamp.
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut index = ReceiptIndexV1::new();
        // Current "latest" points to this one (ts=600, within retention).
        index
            .upsert(make_header("job-lex", "mmmm_current", 600))
            .expect("upsert current");
        // Two newer receipts with same timestamp > current.
        index
            .upsert(make_header("job-lex", "aaaa_newer_low", 900))
            .expect("upsert a");
        index
            .upsert(make_header("job-lex", "zzzz_newer_high", 900))
            .expect("upsert b");
        index.persist(receipts_dir).expect("persist");

        // After upsert, current digest is "zzzz_newer_high" (last-writer
        // wins on equal-or-greater timestamp). Both aaaa and zzzz are at
        // max ts=900. Since current digest "zzzz_newer_high" IS at max
        // timestamp, it should be kept (stability preference).
        //
        // But let's force the current pointer to "mmmm_current" (ts=600)
        // to test the lex tiebreak path.
        index
            .job_index
            .insert("job-lex".to_string(), "mmmm_current".to_string());
        index.persist(receipts_dir).expect("persist forced");

        // now=2000, retention=5000 => cutoff=0 => nothing pruned.
        let _receipt = compact_index(receipts_dir, 5000, 2000).expect("compact");

        let reloaded = ReceiptIndexV1::load(receipts_dir)
            .expect("load")
            .expect("some");
        let digest = reloaded
            .latest_digest_for_job("job-lex")
            .expect("digest after compaction");

        // mmmm_current is at ts=600, not at max (900). So the tiebreak
        // between aaaa_newer_low and zzzz_newer_high uses lexicographic
        // greatest => "zzzz_newer_high".
        assert_eq!(
            digest, "zzzz_newer_high",
            "when current digest is not at max timestamp, \
             lex-greatest content_hash must win the tie"
        );
    }

    // =========================================================================
    // Regression tests for path-traversal, hash validation, and hardened
    // persistence (BLOCKER + MAJOR fix).
    // =========================================================================

    /// Helper: build a valid receipt with a computed content hash.
    fn make_valid_receipt() -> IndexCompactionReceiptV1 {
        let mut receipt = IndexCompactionReceiptV1 {
            schema: INDEX_COMPACTION_RECEIPT_SCHEMA.to_string(),
            receipt_id: "security-test".to_string(),
            timestamp_secs: 1000,
            retention_secs: 500,
            cutoff_timestamp_secs: 500,
            entries_before: 0,
            entries_after: 0,
            entries_pruned: 0,
            jobs_before: 0,
            jobs_after: 0,
            jobs_pruned: 0,
            rebuild_epoch_after: 0,
            content_hash: String::new(),
        };
        let hash = receipt.compute_content_hash().expect("compute hash");
        receipt.content_hash = hash;
        receipt
    }

    #[test]
    fn persist_rejects_path_traversal_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = make_valid_receipt();
        // Inject a path-traversal hash string.
        receipt.content_hash =
            "../etc/passwd/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let result = persist_compaction_receipt(receipts_dir, &receipt);
        assert!(
            result.is_err(),
            "path-traversal hash must be rejected, got: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("mismatch") || err.contains("non-hex") || err.contains("length"),
            "error must indicate hash validation failure: {err}"
        );
    }

    #[test]
    fn persist_rejects_absolute_path_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = make_valid_receipt();
        // Inject an absolute path as hash.
        receipt.content_hash =
            "/tmp/evil/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let result = persist_compaction_receipt(receipts_dir, &receipt);
        assert!(
            result.is_err(),
            "absolute-path hash must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn persist_rejects_mismatched_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = make_valid_receipt();
        // Forge a valid-format but incorrect hash (all zeros).
        receipt.content_hash = "0".repeat(64);

        let result = persist_compaction_receipt(receipts_dir, &receipt);
        assert!(
            result.is_err(),
            "mismatched hash must be rejected, got: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("mismatch"),
            "error must indicate hash mismatch: {err}"
        );
    }

    #[test]
    fn persist_rejects_non_hex_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = make_valid_receipt();
        // Valid length but contains non-hex characters.
        receipt.content_hash =
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();

        let result = persist_compaction_receipt(receipts_dir, &receipt);
        assert!(
            result.is_err(),
            "non-hex hash must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn persist_rejects_short_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = make_valid_receipt();
        receipt.content_hash = "abcd".to_string();

        let result = persist_compaction_receipt(receipts_dir, &receipt);
        assert!(
            result.is_err(),
            "short hash must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn persist_rejects_dot_dot_components_in_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = make_valid_receipt();
        // Exactly 64 chars but containing ".." in positions that could escape.
        receipt.content_hash =
            "..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let result = persist_compaction_receipt(receipts_dir, &receipt);
        assert!(
            result.is_err(),
            "hash with dot-dot must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn persist_valid_receipt_stays_within_receipts_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let receipt = make_valid_receipt();
        let path = persist_compaction_receipt(receipts_dir, &receipt).expect("persist");

        // Verify the file was created within receipts_dir.
        let canonical_receipts = receipts_dir.canonicalize().expect("canonicalize receipts");
        let canonical_path = path.canonicalize().expect("canonicalize path");
        assert!(
            canonical_path.starts_with(&canonical_receipts),
            "persisted path {} must be within receipts_dir {}",
            canonical_path.display(),
            canonical_receipts.display()
        );

        // Verify the file content is valid.
        let bytes = std::fs::read(&path).expect("read");
        let loaded: IndexCompactionReceiptV1 = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(loaded.content_hash, receipt.content_hash);
    }

    #[cfg(unix)]
    #[test]
    fn persist_does_not_follow_symlinked_temp_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path().join("receipts");
        std::fs::create_dir_all(&receipts_dir).expect("create receipts_dir");

        // Create a trap directory that a symlink attack might try to redirect to.
        let trap_dir = tmp.path().join("trap");
        std::fs::create_dir_all(&trap_dir).expect("create trap_dir");

        // Create a symlink inside the receipts prefix dir pointing to trap.
        // First, compute what prefix directory the valid receipt would use.
        let receipt = make_valid_receipt();
        let prefix = &receipt.content_hash[..2];
        let prefix_dir = receipts_dir.join(prefix);
        // DO NOT create prefix_dir yet — let persist create it.

        // Instead, create a symlink at the prefix path pointing to the trap.
        // The persist function should create the dir itself (not follow a
        // symlink), and the canonicalize defense-in-depth check should catch
        // any escape.
        symlink(&trap_dir, &prefix_dir).expect("create symlink");

        // Persist should succeed because canonicalize resolves the symlink
        // and the resolved path (trap_dir) is NOT within receipts_dir.
        let result = persist_compaction_receipt(&receipts_dir, &receipt);
        // The symlink resolves to trap_dir which is outside receipts_dir,
        // so the defense-in-depth check should reject it.
        assert!(
            result.is_err(),
            "symlinked prefix dir must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn validate_strict_hex_digest_accepts_valid() {
        let valid = "a".repeat(64);
        assert!(super::validate_strict_hex_digest(&valid).is_ok());
        let mixed = "0123456789abcdefABCDEF01234567890123456789abcdef0123456789abcdef".to_string();
        assert!(super::validate_strict_hex_digest(&mixed).is_ok());
    }

    #[test]
    fn validate_strict_hex_digest_rejects_wrong_length() {
        assert!(super::validate_strict_hex_digest("abcd").is_err());
        assert!(super::validate_strict_hex_digest(&"a".repeat(63)).is_err());
        assert!(super::validate_strict_hex_digest(&"a".repeat(65)).is_err());
        assert!(super::validate_strict_hex_digest("").is_err());
    }

    #[test]
    fn validate_strict_hex_digest_rejects_non_hex() {
        let with_dots =
            "..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        assert!(super::validate_strict_hex_digest(&with_dots).is_err());
        let with_slash =
            "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        assert!(super::validate_strict_hex_digest(&with_slash).is_err());
        let with_space =
            " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        assert!(super::validate_strict_hex_digest(&with_space).is_err());
    }
}
