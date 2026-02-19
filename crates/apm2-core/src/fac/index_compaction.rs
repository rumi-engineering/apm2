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

use std::path::Path;

use serde::{Deserialize, Serialize};

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
    let jobs_to_check: Vec<String> = index.job_index.keys().cloned().collect();
    for job_id in &jobs_to_check {
        // Find the latest remaining header for this job.
        let latest = index
            .header_index
            .values()
            .filter(|h| h.job_id == *job_id)
            .max_by_key(|h| h.timestamp_secs);

        match latest {
            Some(header) => {
                // Update job_index to point to the latest remaining header.
                index
                    .job_index
                    .insert(job_id.clone(), header.content_hash.clone());
            },
            None => {
                // No remaining headers for this job — remove from job_index.
                index.job_index.remove(job_id);
            },
        }
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
/// string is the content hash.
///
/// # Errors
///
/// Returns an error string if persistence fails.
pub fn persist_compaction_receipt(
    receipts_dir: &Path,
    receipt: &IndexCompactionReceiptV1,
) -> Result<std::path::PathBuf, String> {
    receipt.validate()?;

    let bytes = serde_json::to_vec_pretty(receipt)
        .map_err(|e| format!("failed to serialize compaction receipt: {e}"))?;

    if bytes.len() > MAX_COMPACTION_RECEIPT_SIZE {
        return Err(format!(
            "compaction receipt exceeds max size: {} > {MAX_COMPACTION_RECEIPT_SIZE}",
            bytes.len()
        ));
    }

    let content_hash = &receipt.content_hash;
    if content_hash.len() < 4 {
        return Err("content hash is too short".to_string());
    }

    let prefix = &content_hash[..2];
    let suffix = &content_hash[2..];
    let dir = receipts_dir.join(prefix);
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create receipt dir: {e}"))?;

    let path = dir.join(format!("{suffix}.json"));

    // Atomic write: temp + rename.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes).map_err(|e| format!("failed to write compaction receipt: {e}"))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| format!("failed to persist compaction receipt: {e}"))?;

    Ok(path)
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
}
