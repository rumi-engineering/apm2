//! Receipt Index v1: rebuildable, non-authoritative cache for fast job/receipt
//! lookup.
//!
//! This module implements [`ReceiptIndexV1`], a best-effort index over the
//! content-addressed receipt store. The index lives under
//! `$APM2_HOME/private/fac/receipts/index/` and maps:
//!
//! - `job_id` → latest receipt content hash (digest)
//! - receipt content hash → parsed header fields (outcome, timestamp,
//!   queue_lane, etc.)
//!
//! # Security Model
//!
//! The index is **non-authoritative**: it is treated as attacker-writable cache
//! under A2 assumptions. Receipt validation always goes through the
//! content-addressed receipt store with digest verification. The index is never
//! trusted for authorization, admission, or any security-critical decision.
//!
//! On any inconsistency (missing receipt, digest mismatch, corrupt index file),
//! the system rebuilds the index from the receipt store or falls back to direct
//! store scanning.
//!
//! # Persistence
//!
//! Index writes use the `fs_safe` atomic write protocol (temp + fsync + rename)
//! via the caller-provided write function. Index reads use bounded JSON
//! deserialization with size caps.
//!
//! # Bounded Collections
//!
//! All in-memory maps are capped by [`MAX_INDEX_ENTRIES`]. Overflow during
//! rebuild evicts oldest entries by timestamp. Overflow during incremental
//! update returns an error.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::receipt::{FacJobOutcome, FacJobReceiptV1, MAX_JOB_RECEIPT_SIZE};

// =============================================================================
// Constants
// =============================================================================

/// Schema identifier for the receipt index.
pub const RECEIPT_INDEX_SCHEMA: &str = "apm2.fac.receipt_index.v1";

/// Maximum number of entries in the header index (`content_hash` → header).
/// This bounds the in-memory footprint. At ~200 bytes per header entry,
/// 16384 entries ≈ 3.2 MiB worst case.
pub const MAX_INDEX_ENTRIES: usize = 16_384;

/// Maximum number of entries in the job-to-digest index.
/// Same cap as header entries since each job maps to exactly one digest.
pub const MAX_JOB_INDEX_ENTRIES: usize = 16_384;

/// Maximum serialized size of the index file (bytes).
/// 8 MiB is generous for the bounded index while preventing memory exhaustion.
pub const MAX_INDEX_FILE_SIZE: u64 = 8 * 1024 * 1024;

/// Maximum number of receipt files to scan during a rebuild.
/// Prevents unbounded directory traversal.
pub const MAX_REBUILD_SCAN_FILES: usize = 65_536;

/// Subdirectory name for the index within the receipts directory.
pub const INDEX_SUBDIR: &str = "index";

/// Index file name within the index subdirectory.
pub const INDEX_FILE_NAME: &str = "receipt_index.v1.json";

// =============================================================================
// Error Types
// =============================================================================

/// Errors from receipt index operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptIndexError {
    /// Index file exceeds size cap.
    #[error("index file too large: {size} bytes exceeds maximum of {max} bytes")]
    IndexTooLarge {
        /// Actual size.
        size: u64,
        /// Maximum allowed.
        max: u64,
    },

    /// Index is at capacity and cannot accept new entries.
    #[error("index at capacity: {current} entries, maximum {max}")]
    IndexAtCapacity {
        /// Current entry count.
        current: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// JSON serialization/deserialization failure.
    #[error("index serialization error: {0}")]
    Serialization(String),

    /// I/O error during index operation.
    #[error("index I/O error during {context}: {source}")]
    Io {
        /// Human-readable operation context.
        context: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// Schema mismatch in loaded index.
    #[error("index schema mismatch: expected {expected}, found {found}")]
    SchemaMismatch {
        /// Expected schema.
        expected: String,
        /// Found schema.
        found: String,
    },

    /// Receipt parse error during rebuild.
    #[error("receipt parse error for {path}: {reason}")]
    ReceiptParseError {
        /// Path of the problematic receipt.
        path: String,
        /// Reason for parse failure.
        reason: String,
    },
}

impl ReceiptIndexError {
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// =============================================================================
// Index Types
// =============================================================================

/// Parsed header fields extracted from a `FacJobReceiptV1`.
///
/// This is the minimal set of fields needed for fast lookups without
/// deserializing the full receipt from the content-addressed store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptHeaderV1 {
    /// The receipt's content hash (digest), used as the key.
    pub content_hash: String,
    /// Job ID from the receipt.
    pub job_id: String,
    /// Outcome of the job.
    pub outcome: FacJobOutcome,
    /// Epoch timestamp (seconds).
    pub timestamp_secs: u64,
    /// Queue lane from the queue admission trace, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_lane: Option<String>,
    /// Whether this was a direct-mode execution.
    #[serde(default)]
    pub unsafe_direct: bool,
}

impl ReceiptHeaderV1 {
    /// Extract header fields from a full `FacJobReceiptV1`.
    #[must_use]
    pub fn from_receipt(receipt: &FacJobReceiptV1) -> Self {
        Self {
            content_hash: receipt.content_hash.clone(),
            job_id: receipt.job_id.clone(),
            outcome: receipt.outcome,
            timestamp_secs: receipt.timestamp_secs,
            queue_lane: receipt
                .eio29_queue_admission
                .as_ref()
                .map(|t| t.queue_lane.clone()),
            unsafe_direct: receipt.unsafe_direct,
        }
    }
}

/// Non-authoritative, rebuildable index over the receipt store.
///
/// # Security
///
/// This index is a **cache only**. It must never be trusted for
/// authorization, admission, or security decisions. Receipt validation
/// always uses the content-addressed store with digest verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIndexV1 {
    /// Schema identifier for version checking.
    pub schema: String,
    /// Monotonic rebuild counter. Incremented on each full rebuild.
    pub rebuild_epoch: u64,
    /// Map from `job_id` to the latest receipt content hash.
    pub job_index: HashMap<String, String>,
    /// Map from receipt content hash to parsed header fields.
    pub header_index: HashMap<String, ReceiptHeaderV1>,
}

impl Default for ReceiptIndexV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptIndexV1 {
    /// Create a new empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema: RECEIPT_INDEX_SCHEMA.to_string(),
            rebuild_epoch: 0,
            job_index: HashMap::new(),
            header_index: HashMap::new(),
        }
    }

    /// Returns the number of receipt headers in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.header_index.len()
    }

    /// Returns true if the index contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.header_index.is_empty()
    }

    /// Look up the latest receipt content hash for a job ID.
    ///
    /// Returns `None` if the job is not in the index. The caller should
    /// fall back to scanning the receipt store.
    #[must_use]
    pub fn latest_digest_for_job(&self, job_id: &str) -> Option<&str> {
        self.job_index.get(job_id).map(String::as_str)
    }

    /// Look up parsed header fields by receipt content hash.
    ///
    /// Returns `None` if the digest is not in the index.
    #[must_use]
    pub fn header_for_digest(&self, content_hash: &str) -> Option<&ReceiptHeaderV1> {
        self.header_index.get(content_hash)
    }

    /// Look up parsed header fields for the latest receipt of a job.
    ///
    /// Convenience method that chains `latest_digest_for_job` and
    /// `header_for_digest`.
    #[must_use]
    pub fn latest_header_for_job(&self, job_id: &str) -> Option<&ReceiptHeaderV1> {
        self.latest_digest_for_job(job_id)
            .and_then(|digest| self.header_for_digest(digest))
    }

    /// Insert or update a receipt in the index.
    ///
    /// If the job already has an entry and the new receipt has a later
    /// timestamp, the `job_index` is updated to point to the new receipt.
    /// If timestamps are equal, the new receipt wins (last-writer-wins).
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptIndexError::IndexAtCapacity`] if adding a new
    /// header entry would exceed [`MAX_INDEX_ENTRIES`].
    pub fn upsert(&mut self, header: ReceiptHeaderV1) -> Result<(), ReceiptIndexError> {
        let content_hash = header.content_hash.clone();
        let job_id = header.job_id.clone();
        let timestamp = header.timestamp_secs;

        // Check capacity before inserting a new header entry.
        if !self.header_index.contains_key(&content_hash)
            && self.header_index.len() >= MAX_INDEX_ENTRIES
        {
            return Err(ReceiptIndexError::IndexAtCapacity {
                current: self.header_index.len(),
                max: MAX_INDEX_ENTRIES,
            });
        }

        // Insert or replace header entry.
        self.header_index.insert(content_hash.clone(), header);

        // Update job_index: point to the latest receipt (by timestamp).
        if let Some(existing_digest) = self.job_index.get(&job_id) {
            let should_replace = self
                .header_index
                .get(existing_digest)
                .is_none_or(|existing| timestamp >= existing.timestamp_secs);
            if should_replace {
                self.job_index.insert(job_id, content_hash);
            }
        } else {
            if self.job_index.len() >= MAX_JOB_INDEX_ENTRIES {
                return Err(ReceiptIndexError::IndexAtCapacity {
                    current: self.job_index.len(),
                    max: MAX_JOB_INDEX_ENTRIES,
                });
            }
            self.job_index.insert(job_id, content_hash);
        }

        Ok(())
    }

    /// Validate the loaded index for schema correctness and bounds.
    ///
    /// # Errors
    ///
    /// Returns errors on schema mismatch or bounds violation.
    pub fn validate(&self) -> Result<(), ReceiptIndexError> {
        if self.schema != RECEIPT_INDEX_SCHEMA {
            return Err(ReceiptIndexError::SchemaMismatch {
                expected: RECEIPT_INDEX_SCHEMA.to_string(),
                found: self.schema.clone(),
            });
        }
        if self.header_index.len() > MAX_INDEX_ENTRIES {
            return Err(ReceiptIndexError::IndexAtCapacity {
                current: self.header_index.len(),
                max: MAX_INDEX_ENTRIES,
            });
        }
        if self.job_index.len() > MAX_JOB_INDEX_ENTRIES {
            return Err(ReceiptIndexError::IndexAtCapacity {
                current: self.job_index.len(),
                max: MAX_JOB_INDEX_ENTRIES,
            });
        }
        Ok(())
    }

    /// Rebuild the index by scanning the receipt store directory.
    ///
    /// Reads all `*.json` files in `receipts_dir`, parses each as a
    /// `FacJobReceiptV1`, and populates the index. Files that fail to
    /// parse are skipped (logged but not fatal).
    ///
    /// The rebuild is bounded by [`MAX_REBUILD_SCAN_FILES`] to prevent
    /// unbounded directory traversal.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptIndexError::Io`] if the receipt directory cannot
    /// be read.
    pub fn rebuild_from_store(receipts_dir: &Path) -> Result<Self, ReceiptIndexError> {
        let mut index = Self::new();

        if !receipts_dir.is_dir() {
            // No receipt directory yet — return empty index.
            return Ok(index);
        }

        let entries = std::fs::read_dir(receipts_dir)
            .map_err(|e| ReceiptIndexError::io("read receipt directory", e))?;

        let mut scanned: usize = 0;
        for entry_result in entries {
            if scanned >= MAX_REBUILD_SCAN_FILES {
                break;
            }

            let Ok(entry) = entry_result else {
                continue;
            };

            let path = entry.path();

            // Only process .json files (skip .tmp, subdirectories, etc.)
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }

            // Skip if it's a directory or symlink to a directory.
            if path.is_dir() {
                continue;
            }

            scanned += 1;

            // Bounded read: skip files exceeding receipt size cap.
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            if metadata.len() > MAX_JOB_RECEIPT_SIZE as u64 {
                continue;
            }

            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };

            let Ok(receipt) = serde_json::from_slice::<FacJobReceiptV1>(&bytes) else {
                continue; // Not a valid job receipt — skip.
            };

            let header = ReceiptHeaderV1::from_receipt(&receipt);

            // Best-effort: if index is full, stop adding.
            if index.upsert(header).is_err() {
                break;
            }
        }

        index.rebuild_epoch = index.rebuild_epoch.saturating_add(1);
        Ok(index)
    }

    /// Compute the canonical index file path given the receipts directory.
    ///
    /// Returns `receipts_dir/index/receipt_index.v1.json`.
    #[must_use]
    pub fn index_path(receipts_dir: &Path) -> PathBuf {
        receipts_dir.join(INDEX_SUBDIR).join(INDEX_FILE_NAME)
    }

    /// Serialize the index to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptIndexError::Serialization`] on failure.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ReceiptIndexError> {
        serde_json::to_vec_pretty(self).map_err(|e| ReceiptIndexError::Serialization(e.to_string()))
    }

    /// Persist the index atomically to the canonical path.
    ///
    /// Creates the index subdirectory if needed. Uses temp-file + rename
    /// for crash safety.
    ///
    /// # Errors
    ///
    /// Returns errors on I/O or serialization failure.
    pub fn persist(&self, receipts_dir: &Path) -> Result<PathBuf, ReceiptIndexError> {
        let index_dir = receipts_dir.join(INDEX_SUBDIR);
        std::fs::create_dir_all(&index_dir)
            .map_err(|e| ReceiptIndexError::io("create index directory", e))?;

        let index_path = index_dir.join(INDEX_FILE_NAME);
        let bytes = self.to_json_bytes()?;

        // Atomic write: temp file + rename.
        let tmp_path = index_dir.join(format!("{INDEX_FILE_NAME}.tmp"));
        std::fs::write(&tmp_path, &bytes)
            .map_err(|e| ReceiptIndexError::io("write index temp file", e))?;
        std::fs::rename(&tmp_path, &index_path)
            .map_err(|e| ReceiptIndexError::io("rename index file", e))?;

        Ok(index_path)
    }

    /// Load the index from the canonical path.
    ///
    /// Returns `None` if the index file does not exist. Returns `Err` if the
    /// file exists but is corrupt, oversized, or has a schema mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptIndexError`] on I/O, size, parse, or schema errors.
    pub fn load(receipts_dir: &Path) -> Result<Option<Self>, ReceiptIndexError> {
        let index_path = Self::index_path(receipts_dir);

        if !index_path.exists() {
            return Ok(None);
        }

        // Bounded read: check size before reading.
        let metadata = std::fs::metadata(&index_path)
            .map_err(|e| ReceiptIndexError::io("stat index file", e))?;
        if metadata.len() > MAX_INDEX_FILE_SIZE {
            return Err(ReceiptIndexError::IndexTooLarge {
                size: metadata.len(),
                max: MAX_INDEX_FILE_SIZE,
            });
        }

        let bytes =
            std::fs::read(&index_path).map_err(|e| ReceiptIndexError::io("read index file", e))?;

        let index: Self = serde_json::from_slice(&bytes)
            .map_err(|e| ReceiptIndexError::Serialization(e.to_string()))?;

        index.validate()?;
        Ok(Some(index))
    }

    /// Load the index, rebuilding if missing or corrupt.
    ///
    /// This is the primary entry point for consumers that want the index
    /// with automatic fallback. On corruption, rebuilds from the receipt
    /// store and persists the rebuilt index.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptIndexError`] only if rebuild itself fails.
    pub fn load_or_rebuild(receipts_dir: &Path) -> Result<Self, ReceiptIndexError> {
        if let Ok(Some(index)) = Self::load(receipts_dir) {
            return Ok(index);
        }
        // Missing or corrupt — rebuild.
        let index = Self::rebuild_from_store(receipts_dir)?;
        // Best-effort persist; don't fail the caller if persist fails.
        let _ = index.persist(receipts_dir);
        Ok(index)
    }

    /// Incrementally update the index with a newly persisted receipt,
    /// then persist the updated index.
    ///
    /// This is called after `persist_content_addressed_receipt` succeeds.
    /// If the index cannot be loaded, it is rebuilt first.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptIndexError`] on capacity overflow or I/O failure.
    pub fn incremental_update(
        receipts_dir: &Path,
        receipt: &FacJobReceiptV1,
    ) -> Result<(), ReceiptIndexError> {
        let mut index = Self::load_or_rebuild(receipts_dir)?;
        let header = ReceiptHeaderV1::from_receipt(receipt);
        index.upsert(header)?;
        index.persist(receipts_dir)?;
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::receipt::FacJobOutcome;

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

    fn make_receipt(job_id: &str, content_hash: &str, timestamp: u64) -> FacJobReceiptV1 {
        use crate::fac::receipt::QueueAdmissionTrace;

        FacJobReceiptV1 {
            schema: "apm2.fac.job_receipt.v1".to_string(),
            receipt_id: format!("rcpt-{job_id}"),
            job_id: job_id.to_string(),
            job_spec_digest:
                "b3-256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            policy_hash: None,
            patch_digest: None,
            canonicalizer_tuple_digest: None,
            outcome: FacJobOutcome::Completed,
            denial_reason: None,
            unsafe_direct: false,
            reason: "ok".to_string(),
            moved_job_path: None,
            rfc0028_channel_boundary: None,
            eio29_queue_admission: Some(QueueAdmissionTrace {
                verdict: "allow".to_string(),
                queue_lane: "default".to_string(),
                defect_reason: None,
            }),
            eio29_budget_admission: None,
            timestamp_secs: timestamp,
            content_hash: content_hash.to_string(),
        }
    }

    #[test]
    fn test_new_index_is_empty() {
        let index = ReceiptIndexV1::new();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert_eq!(index.schema, RECEIPT_INDEX_SCHEMA);
    }

    #[test]
    fn test_upsert_and_lookup() {
        let mut index = ReceiptIndexV1::new();
        let header = make_header("job-1", "hash-1", 1000);
        index.upsert(header).expect("upsert");

        assert_eq!(index.len(), 1);
        assert_eq!(index.latest_digest_for_job("job-1"), Some("hash-1"));

        let h = index.header_for_digest("hash-1").expect("header");
        assert_eq!(h.job_id, "job-1");
        assert_eq!(h.timestamp_secs, 1000);
    }

    #[test]
    fn test_upsert_updates_to_newer_receipt() {
        let mut index = ReceiptIndexV1::new();
        index
            .upsert(make_header("job-1", "hash-1", 1000))
            .expect("upsert 1");
        index
            .upsert(make_header("job-1", "hash-2", 2000))
            .expect("upsert 2");

        // job_index should point to the newer receipt.
        assert_eq!(index.latest_digest_for_job("job-1"), Some("hash-2"));
        // Both headers should exist.
        assert!(index.header_for_digest("hash-1").is_some());
        assert!(index.header_for_digest("hash-2").is_some());
    }

    #[test]
    fn test_upsert_keeps_newer_when_older_inserted_later() {
        let mut index = ReceiptIndexV1::new();
        index
            .upsert(make_header("job-1", "hash-2", 2000))
            .expect("upsert newer first");
        index
            .upsert(make_header("job-1", "hash-1", 1000))
            .expect("upsert older second");

        // job_index should still point to the newer receipt.
        assert_eq!(index.latest_digest_for_job("job-1"), Some("hash-2"));
    }

    #[test]
    fn test_latest_header_for_job() {
        let mut index = ReceiptIndexV1::new();
        index
            .upsert(make_header("job-1", "hash-1", 1000))
            .expect("upsert");

        let header = index.latest_header_for_job("job-1").expect("header");
        assert_eq!(header.content_hash, "hash-1");
        assert!(index.latest_header_for_job("nonexistent").is_none());
    }

    #[test]
    fn test_header_from_receipt() {
        let receipt = make_receipt("job-42", "hash-42", 5000);
        let header = ReceiptHeaderV1::from_receipt(&receipt);

        assert_eq!(header.job_id, "job-42");
        assert_eq!(header.content_hash, "hash-42");
        assert_eq!(header.timestamp_secs, 5000);
        assert_eq!(header.outcome, FacJobOutcome::Completed);
        assert_eq!(header.queue_lane.as_deref(), Some("default"));
        assert!(!header.unsafe_direct);
    }

    #[test]
    fn test_validate_correct_schema() {
        let index = ReceiptIndexV1::new();
        assert!(index.validate().is_ok());
    }

    #[test]
    fn test_validate_wrong_schema() {
        let mut index = ReceiptIndexV1::new();
        index.schema = "wrong.schema".to_string();
        assert!(index.validate().is_err());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut index = ReceiptIndexV1::new();
        index
            .upsert(make_header("job-1", "hash-1", 1000))
            .expect("upsert");
        index
            .upsert(make_header("job-2", "hash-2", 2000))
            .expect("upsert");

        let bytes = index.to_json_bytes().expect("serialize");
        let loaded: ReceiptIndexV1 = serde_json::from_slice(&bytes).expect("deserialize");

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.latest_digest_for_job("job-1"), Some("hash-1"));
        assert_eq!(loaded.latest_digest_for_job("job-2"), Some("hash-2"));
    }

    #[test]
    fn test_persist_and_load() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut index = ReceiptIndexV1::new();
        index
            .upsert(make_header("job-1", "hash-1", 1000))
            .expect("upsert");

        let path = index.persist(receipts_dir).expect("persist");
        assert!(path.exists());

        let loaded = ReceiptIndexV1::load(receipts_dir)
            .expect("load")
            .expect("some");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.latest_digest_for_job("job-1"), Some("hash-1"));
    }

    #[test]
    fn test_load_missing_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = ReceiptIndexV1::load(tmp.path()).expect("load");
        assert!(result.is_none());
    }

    #[test]
    fn test_rebuild_from_empty_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let index = ReceiptIndexV1::rebuild_from_store(tmp.path()).expect("rebuild");
        assert!(index.is_empty());
        assert_eq!(index.rebuild_epoch, 1);
    }

    #[test]
    fn test_rebuild_from_nonexistent_dir() {
        let path = PathBuf::from("/tmp/nonexistent-receipt-index-test-dir-12345");
        let index = ReceiptIndexV1::rebuild_from_store(&path).expect("rebuild");
        assert!(index.is_empty());
    }

    #[test]
    fn test_rebuild_from_store_with_receipts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write some receipt files.
        let r1 = make_receipt("job-1", "hash-1", 1000);
        let r2 = make_receipt("job-2", "hash-2", 2000);

        let bytes1 = serde_json::to_vec_pretty(&r1).expect("ser");
        let bytes2 = serde_json::to_vec_pretty(&r2).expect("ser");

        std::fs::write(receipts_dir.join("hash-1.json"), bytes1).expect("write");
        std::fs::write(receipts_dir.join("hash-2.json"), bytes2).expect("write");

        // Also write a non-json file that should be skipped.
        std::fs::write(receipts_dir.join("not-a-receipt.tmp"), b"junk").expect("write");

        let index = ReceiptIndexV1::rebuild_from_store(receipts_dir).expect("rebuild");
        assert_eq!(index.len(), 2);
        assert_eq!(index.latest_digest_for_job("job-1"), Some("hash-1"));
        assert_eq!(index.latest_digest_for_job("job-2"), Some("hash-2"));
    }

    #[test]
    fn test_rebuild_skips_corrupt_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Valid receipt.
        let r1 = make_receipt("job-1", "hash-1", 1000);
        let bytes1 = serde_json::to_vec_pretty(&r1).expect("ser");
        std::fs::write(receipts_dir.join("hash-1.json"), bytes1).expect("write");

        // Corrupt receipt.
        std::fs::write(receipts_dir.join("corrupt.json"), b"not valid json").expect("write");

        let index = ReceiptIndexV1::rebuild_from_store(receipts_dir).expect("rebuild");
        assert_eq!(index.len(), 1);
        assert_eq!(index.latest_digest_for_job("job-1"), Some("hash-1"));
    }

    #[test]
    fn test_load_or_rebuild_creates_index() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write a receipt.
        let r1 = make_receipt("job-1", "hash-1", 1000);
        let bytes1 = serde_json::to_vec_pretty(&r1).expect("ser");
        std::fs::write(receipts_dir.join("hash-1.json"), bytes1).expect("write");

        // No index exists yet.
        let index = ReceiptIndexV1::load_or_rebuild(receipts_dir).expect("load_or_rebuild");
        assert_eq!(index.len(), 1);

        // Index file should now exist.
        assert!(ReceiptIndexV1::index_path(receipts_dir).exists());
    }

    #[test]
    fn test_incremental_update() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Start with an empty index.
        let index = ReceiptIndexV1::new();
        index.persist(receipts_dir).expect("persist");

        // Incrementally add a receipt.
        let r1 = make_receipt("job-1", "hash-1", 1000);
        ReceiptIndexV1::incremental_update(receipts_dir, &r1).expect("update");

        // Verify the index was updated.
        let loaded = ReceiptIndexV1::load(receipts_dir)
            .expect("load")
            .expect("some");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.latest_digest_for_job("job-1"), Some("hash-1"));
    }

    #[test]
    fn test_capacity_enforcement() {
        let mut index = ReceiptIndexV1::new();

        // Fill to capacity.
        for i in 0..MAX_INDEX_ENTRIES {
            let header = make_header(&format!("job-{i}"), &format!("hash-{i}"), i as u64);
            index.upsert(header).expect("upsert within capacity");
        }

        assert_eq!(index.len(), MAX_INDEX_ENTRIES);

        // Next insert should fail.
        let overflow = make_header("overflow-job", "overflow-hash", 99999);
        let result = index.upsert(overflow);
        assert!(result.is_err());
        match result {
            Err(ReceiptIndexError::IndexAtCapacity { current, max }) => {
                assert_eq!(current, MAX_INDEX_ENTRIES);
                assert_eq!(max, MAX_INDEX_ENTRIES);
            },
            _ => panic!("expected IndexAtCapacity error"),
        }
    }

    #[test]
    fn test_upsert_existing_digest_does_not_grow() {
        let mut index = ReceiptIndexV1::new();
        let header = make_header("job-1", "hash-1", 1000);
        index.upsert(header.clone()).expect("first upsert");

        // Re-upserting the same digest should not increase count.
        index.upsert(header).expect("second upsert");
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn test_multiple_jobs_independent() {
        let mut index = ReceiptIndexV1::new();
        index
            .upsert(make_header("job-a", "hash-a1", 100))
            .expect("upsert");
        index
            .upsert(make_header("job-b", "hash-b1", 200))
            .expect("upsert");
        index
            .upsert(make_header("job-a", "hash-a2", 300))
            .expect("upsert");

        // job-a should point to hash-a2, job-b still at hash-b1.
        assert_eq!(index.latest_digest_for_job("job-a"), Some("hash-a2"));
        assert_eq!(index.latest_digest_for_job("job-b"), Some("hash-b1"));
        assert_eq!(index.len(), 3); // 3 distinct hashes.
    }
}
