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
//!
//! # Consumer Wiring (TCK-00560)
//!
//! The ticket requires: "Common operations do not require full receipt
//! directory scans (job show, wait, metrics, list)." All production
//! consumers of the job receipt store are wired through this index:
//!
//! | Ticket waiter   | Consumer path                                        |
//! |-----------------|------------------------------------------------------|
//! | **job show**    | `lookup_job_receipt` → index O(1) + bounded fallback  |
//! | **wait/worker** | `has_receipt_for_job` → index O(1) + verified receipt |
//! | **list**        | `list_receipt_headers` → index only, no dir scan      |
//! | **reindex**     | `rebuild_from_store` (intentional full scan)          |
//!
//! **Gates** use their own gate-result cache (`gate_cache.rs`), not the job
//! receipt store, so no wiring is needed. **Metrics** modules (daemon and
//! consensus) do not reference the job receipt store and thus require no
//! index wiring. The `fac_gc` and `fac_quarantine` commands persist GC
//! receipts (a different type) and do not scan job receipts.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::receipt::{
    FacJobOutcome, FacJobReceiptV1, MAX_JOB_RECEIPT_SIZE, compute_job_receipt_content_hash,
    compute_job_receipt_content_hash_v2,
};

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

        // Check ALL capacities before ANY mutation to prevent inconsistent
        // state on overflow (review finding: NIT capacity check ordering).
        let is_new_header = !self.header_index.contains_key(&content_hash);
        let is_new_job = !self.job_index.contains_key(&job_id);

        if is_new_header && self.header_index.len() >= MAX_INDEX_ENTRIES {
            return Err(ReceiptIndexError::IndexAtCapacity {
                current: self.header_index.len(),
                max: MAX_INDEX_ENTRIES,
            });
        }
        if is_new_job && self.job_index.len() >= MAX_JOB_INDEX_ENTRIES {
            return Err(ReceiptIndexError::IndexAtCapacity {
                current: self.job_index.len(),
                max: MAX_JOB_INDEX_ENTRIES,
            });
        }

        // All capacity checks passed — safe to mutate.
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

        // Count EVERY visited directory entry toward the scan cap, not just
        // .json files. This prevents adversarial non-JSON entries from
        // bypassing MAX_REBUILD_SCAN_FILES (security review finding: MAJOR-2).
        let mut visited: usize = 0;
        for entry_result in entries {
            visited = visited.saturating_add(1);
            if visited > MAX_REBUILD_SCAN_FILES {
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

            // Bounded read via open-once with O_NOFOLLOW (TOCTOU-safe).
            // Opens the file handle first, then checks size from the same
            // handle to avoid stat-then-read race (security finding: MAJOR-1).
            let Ok(file) = open_no_follow(&path) else {
                continue;
            };
            let Ok(file_meta) = file.metadata() else {
                continue;
            };
            if file_meta.len() > MAX_JOB_RECEIPT_SIZE as u64 {
                continue;
            }
            let mut buf = Vec::new();
            let cap = MAX_JOB_RECEIPT_SIZE as u64;
            if file.take(cap + 1).read_to_end(&mut buf).is_err() {
                continue;
            }
            if buf.len() as u64 > cap {
                continue;
            }

            let Ok(receipt) = serde_json::from_slice::<FacJobReceiptV1>(&buf) else {
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

        // Atomic write using NamedTempFile: random temp name in the same
        // directory, write + fsync, then rename-into-place. This prevents
        // symlink attacks on predictable temp paths (security finding: MAJOR-3).
        let temp = tempfile::NamedTempFile::new_in(&index_dir)
            .map_err(|e| ReceiptIndexError::io("create temp file for index", e))?;

        // Set restrictive permissions on the temp file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(temp.path(), perms);
        }

        {
            use std::io::Write;
            let mut file = temp.as_file();
            file.write_all(&bytes)
                .map_err(|e| ReceiptIndexError::io("write index temp file", e))?;
            file.sync_all()
                .map_err(|e| ReceiptIndexError::io("fsync index temp file", e))?;
        }

        temp.persist(&index_path)
            .map_err(|e| ReceiptIndexError::io("rename index temp file to final path", e.error))?;

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

        // Open once with O_NOFOLLOW, then check size on the same handle.
        // This avoids stat-then-read TOCTOU (security finding: MAJOR-1).
        let file = match open_no_follow(&index_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ReceiptIndexError::io("open index file", e)),
        };

        let metadata = file
            .metadata()
            .map_err(|e| ReceiptIndexError::io("fstat index file", e))?;
        if metadata.len() > MAX_INDEX_FILE_SIZE {
            return Err(ReceiptIndexError::IndexTooLarge {
                size: metadata.len(),
                max: MAX_INDEX_FILE_SIZE,
            });
        }

        // Bounded streaming read from the already-opened handle.
        let mut buf = Vec::new();
        let cap = MAX_INDEX_FILE_SIZE;
        file.take(cap + 1)
            .read_to_end(&mut buf)
            .map_err(|e| ReceiptIndexError::io("read index file", e))?;
        if buf.len() as u64 > cap {
            return Err(ReceiptIndexError::IndexTooLarge {
                size: buf.len() as u64,
                max: cap,
            });
        }

        let index: Self = serde_json::from_slice(&buf)
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
// Symlink-safe File Open
// =============================================================================

/// Open a file for reading without following symlinks (`O_NOFOLLOW` on Unix).
///
/// On non-Unix platforms, falls back to a plain open (no symlink protection).
fn open_no_follow(path: &Path) -> Result<std::fs::File, std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }

    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

// =============================================================================
// Consumer Helpers
// =============================================================================

/// Look up the latest receipt for a job using the index, with fallback to
/// directory scan if the index does not contain the job.
///
/// Returns the parsed [`FacJobReceiptV1`] if found, or `None` if no receipt
/// exists for the given job ID. The index is loaded (or rebuilt) automatically.
///
/// # Security
///
/// The index is non-authoritative; this function reads the receipt from the
/// content-addressed store and **verifies content-hash integrity** before
/// returning. The index only provides the content hash hint. On hash mismatch,
/// the receipt is treated as corrupted and the fallback directory scan is used.
#[must_use]
pub fn lookup_job_receipt(receipts_dir: &Path, job_id: &str) -> Option<FacJobReceiptV1> {
    // Try the index first — O(1) lookup.
    if let Ok(index) = ReceiptIndexV1::load_or_rebuild(receipts_dir) {
        if let Some(digest) = index.latest_digest_for_job(job_id) {
            // Validate digest is a well-formed BLAKE3-256 hex string before
            // using it as a filesystem path component (path traversal prevention).
            if is_valid_digest(digest) {
                let receipt_path = receipts_dir.join(format!("{digest}.json"));
                if let Some(receipt) = load_receipt_bounded(&receipt_path) {
                    if receipt.job_id == job_id && verify_receipt_integrity(&receipt, digest) {
                        return Some(receipt);
                    }
                    // Index was stale or integrity check failed — fall through
                    // to scan.
                }
            }
            // Malformed digest or failed verification — fall through to scan.
        }
    }

    // Fallback: bounded directory scan (last resort).
    scan_receipt_for_job(receipts_dir, job_id)
}

/// List receipt headers from the index without directory scanning.
///
/// Returns an iterator-like vec of headers from the index, sorted by
/// timestamp descending (most recent first). If the index cannot be loaded,
/// returns an empty vec.
#[must_use]
pub fn list_receipt_headers(receipts_dir: &Path) -> Vec<ReceiptHeaderV1> {
    let Ok(index) = ReceiptIndexV1::load_or_rebuild(receipts_dir) else {
        return Vec::new();
    };
    let mut headers: Vec<ReceiptHeaderV1> = index.header_index.into_values().collect();
    headers.sort_by(|a, b| b.timestamp_secs.cmp(&a.timestamp_secs));
    headers
}

/// Check whether a receipt exists for the given job ID using the index.
///
/// Loads the receipt from the content-addressed store and verifies both
/// `job_id` binding and content-hash integrity before returning `true`.
/// The index is non-authoritative (attacker-writable under A2 assumptions),
/// so we never trust an index pointer without full verification.
///
/// Falls back to a bounded directory scan if the index is unavailable or
/// the index entry fails verification.
///
/// This is used by the worker to skip jobs that already have receipts,
/// avoiding redundant processing and unnecessary directory scans.
#[must_use]
pub fn has_receipt_for_job(receipts_dir: &Path, job_id: &str) -> bool {
    // Try the index first — O(1) lookup with full verification.
    if let Ok(index) = ReceiptIndexV1::load_or_rebuild(receipts_dir) {
        if let Some(digest) = index.latest_digest_for_job(job_id) {
            // Validate digest is a well-formed BLAKE3-256 hex string before
            // using it as a filesystem path component (path traversal prevention).
            if is_valid_digest(digest) {
                let receipt_path = receipts_dir.join(format!("{digest}.json"));
                // Load the receipt with bounded read + O_NOFOLLOW, then verify:
                // 1. receipt.job_id matches the requested job_id (prevents index corruption
                //    from causing false duplicate detection)
                // 2. content-hash integrity (prevents tampered receipts)
                if let Some(receipt) = load_receipt_bounded(&receipt_path) {
                    if receipt.job_id == job_id && verify_receipt_integrity(&receipt, digest) {
                        return true;
                    }
                }
            }
            // Index entry failed verification — stale/corrupt/malformed, fall
            // through.
        }
    }

    // Fallback: bounded directory scan.
    scan_receipt_for_job(receipts_dir, job_id).is_some()
}

/// Find and return a verified receipt for a given `job_id`, if one exists.
///
/// Performs the same lookup and integrity verification as
/// [`has_receipt_for_job`], but returns the full receipt rather than just a
/// boolean. This is used by reconciliation to recover torn states where a
/// receipt was persisted but the job was not moved to its terminal directory
/// (TCK-00564 BLOCKER-2).
///
/// The receipt's `content_hash` is verified against the recomputed hash to
/// prevent tampered receipts from driving recovery actions.
#[must_use]
pub fn find_receipt_for_job(receipts_dir: &Path, job_id: &str) -> Option<FacJobReceiptV1> {
    // Try the index first -- O(1) lookup with full verification.
    if let Ok(index) = ReceiptIndexV1::load_or_rebuild(receipts_dir) {
        if let Some(digest) = index.latest_digest_for_job(job_id) {
            if is_valid_digest(digest) {
                let receipt_path = receipts_dir.join(format!("{digest}.json"));
                if let Some(receipt) = load_receipt_bounded(&receipt_path) {
                    if receipt.job_id == job_id && verify_receipt_integrity(&receipt, digest) {
                        return Some(receipt);
                    }
                }
            }
        }
    }

    // Fallback: bounded directory scan.
    scan_receipt_for_job(receipts_dir, job_id)
}

/// Validate that a digest string is a well-formed BLAKE3-256 hex digest.
///
/// Accepts both bare 64-char lowercase hex strings and `b3-256:`-prefixed
/// 71-char strings (the canonical format used by
/// `compute_job_receipt_content_hash` and persisted in receipt `content_hash`
/// fields). Rejects path separators, `..`, and any non-hex characters to
/// prevent path traversal when the digest is used as a filename component.
fn is_valid_digest(s: &str) -> bool {
    let hex_part = s.strip_prefix("b3-256:").unwrap_or(s);
    hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Verify content-addressed integrity of a loaded receipt against its
/// expected digest from the index.
///
/// Recomputes the hash from the receipt's canonical content using both v1
/// and v2 hash schemes. Returns `true` if either recomputed hash matches.
///
/// The receipt's self-reported `content_hash` field is **never** trusted —
/// an attacker could set it to any value to bypass verification.
fn verify_receipt_integrity(receipt: &FacJobReceiptV1, expected_digest: &str) -> bool {
    // Try v1 hash first (most common for existing receipts).
    // Use constant-time comparison (INV-PC-001) to avoid timing
    // side-channels on digest comparisons.
    let v1_hash = compute_job_receipt_content_hash(receipt);
    if v1_hash.as_bytes().ct_eq(expected_digest.as_bytes()).into() {
        return true;
    }
    // Try v2 hash (includes unsafe_direct).
    let v2_hash = compute_job_receipt_content_hash_v2(receipt);
    if v2_hash.as_bytes().ct_eq(expected_digest.as_bytes()).into() {
        return true;
    }
    // Never trust receipt.content_hash — must always recompute.
    false
}

/// Load a single receipt file with bounded read and `O_NOFOLLOW`.
fn load_receipt_bounded(path: &Path) -> Option<FacJobReceiptV1> {
    let file = open_no_follow(path).ok()?;
    let meta = file.metadata().ok()?;
    if meta.len() > MAX_JOB_RECEIPT_SIZE as u64 {
        return None;
    }
    let mut buf = Vec::new();
    let cap = MAX_JOB_RECEIPT_SIZE as u64;
    file.take(cap + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > cap {
        return None;
    }
    serde_json::from_slice::<FacJobReceiptV1>(&buf).ok()
}

/// Bounded fallback scan: iterate the receipt directory looking for a specific
/// job ID. Bounded by `MAX_REBUILD_SCAN_FILES`.
///
/// Each candidate receipt is verified against its expected digest (derived
/// from the filename, which is the content hash). Receipts that fail
/// integrity verification are skipped — this prevents unverified data from
/// driving terminal routing in worker duplicate handling and reconcile
/// torn-state repair (MAJOR-1 fix, TCK-00564 round 8).
fn scan_receipt_for_job(receipts_dir: &Path, job_id: &str) -> Option<FacJobReceiptV1> {
    let entries = std::fs::read_dir(receipts_dir).ok()?;
    let mut visited: usize = 0;
    let mut best: Option<FacJobReceiptV1> = None;

    for entry_result in entries {
        visited = visited.saturating_add(1);
        if visited > MAX_REBUILD_SCAN_FILES {
            break;
        }
        let Ok(entry) = entry_result else { continue };
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        if path.is_dir() {
            continue;
        }
        // Derive the expected digest from the filename stem. The receipt
        // store uses content-addressed naming: `{digest}.json`.
        let Some(digest_os) = path.file_stem() else {
            continue;
        };
        let Some(expected_digest) = digest_os.to_str() else {
            continue;
        };
        // Reject malformed digests before loading (path traversal + validity).
        if !is_valid_digest(expected_digest) {
            continue;
        }
        let Some(receipt) = load_receipt_bounded(&path) else {
            continue;
        };
        if receipt.job_id != job_id {
            continue;
        }
        // Verify content-addressed integrity: recompute BLAKE3 hash and
        // compare against the filename-derived digest. Never trust the
        // receipt's self-reported content_hash field (INV-PC-001).
        if !verify_receipt_integrity(&receipt, expected_digest) {
            continue;
        }
        // Keep the receipt with the latest timestamp.
        if best
            .as_ref()
            .is_none_or(|b| receipt.timestamp_secs >= b.timestamp_secs)
        {
            best = Some(receipt);
        }
    }
    best
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
                cost_estimate_ticks: None,
            }),
            eio29_budget_admission: None,
            containment: None,
            observed_cost: None,
            sandbox_hardening_hash: None,
            network_policy_hash: None,
            htf_time_envelope_ns: None,
            node_fingerprint: None,
            timestamp_secs: timestamp,
            content_hash: content_hash.to_string(),
        }
    }

    /// Create a receipt with a properly computed content hash and persist it
    /// to the receipt store with the correct content-addressed filename.
    /// Returns the receipt (with `content_hash` set) and the filename stem
    /// (the integrity digest).
    fn make_and_persist_receipt(
        receipts_dir: &std::path::Path,
        job_id: &str,
        timestamp: u64,
    ) -> (FacJobReceiptV1, String) {
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let mut receipt = make_receipt(job_id, "", timestamp);
        let integrity_hash = compute_job_receipt_content_hash(&receipt);
        receipt.content_hash = integrity_hash.clone();
        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{integrity_hash}.json")), &bytes).expect("write");
        (receipt, integrity_hash)
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

    // =========================================================================
    // NIT-2 regression: upsert capacity check ordering
    // =========================================================================

    #[test]
    fn test_upsert_capacity_check_does_not_leave_dangling_header() {
        // Fill header_index to capacity with unique jobs.
        let mut index = ReceiptIndexV1::new();
        for i in 0..MAX_INDEX_ENTRIES {
            let header = make_header(&format!("job-{i}"), &format!("hash-{i}"), i as u64);
            index.upsert(header).expect("upsert within capacity");
        }
        assert_eq!(index.header_index.len(), MAX_INDEX_ENTRIES);
        assert_eq!(index.job_index.len(), MAX_INDEX_ENTRIES);

        // Attempting to add a new header+job should fail on header capacity
        // and leave BOTH maps unchanged.
        let header_before = index.header_index.len();
        let job_before = index.job_index.len();
        let overflow = make_header("new-job", "new-hash", 99999);
        assert!(index.upsert(overflow).is_err());
        assert_eq!(index.header_index.len(), header_before);
        assert_eq!(index.job_index.len(), job_before);
    }

    // =========================================================================
    // MAJOR-2 regression: rebuild counts all directory entries
    // =========================================================================

    #[test]
    fn test_rebuild_counts_non_json_entries_toward_scan_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write a valid receipt.
        let r1 = make_receipt("job-1", "hash-1", 1000);
        let bytes1 = serde_json::to_vec_pretty(&r1).expect("ser");
        std::fs::write(receipts_dir.join("hash-1.json"), bytes1).expect("write");

        // Write many non-JSON junk files — these should still count toward
        // the scan cap to prevent bypass.
        for i in 0..10 {
            std::fs::write(receipts_dir.join(format!("junk-{i}.tmp")), b"not a receipt")
                .expect("write");
        }

        // Rebuild should still find the receipt since 11 entries < cap.
        let index = ReceiptIndexV1::rebuild_from_store(receipts_dir).expect("rebuild");
        assert!(!index.is_empty(), "should find the valid receipt");
    }

    // =========================================================================
    // Consumer helper tests
    // =========================================================================

    #[test]
    fn test_lookup_job_receipt_via_index() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write a receipt file with correct content-addressed filename.
        let (r1, _digest) = make_and_persist_receipt(receipts_dir, "job-1", 1000);

        // Build the index.
        let index = ReceiptIndexV1::rebuild_from_store(receipts_dir).expect("rebuild");
        index.persist(receipts_dir).expect("persist");

        // Lookup via the public helper.
        let found = lookup_job_receipt(receipts_dir, "job-1");
        assert!(found.is_some(), "should find receipt for job-1");
        let receipt = found.unwrap();
        assert_eq!(receipt.job_id, "job-1");
        assert_eq!(receipt.content_hash, r1.content_hash);
    }

    #[test]
    fn test_lookup_job_receipt_fallback_scan() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write a receipt file with correct content-addressed filename
        // but do NOT build the index.
        let (_r1, _digest) = make_and_persist_receipt(receipts_dir, "job-fallback", 2000);

        // Lookup should still work via fallback scan (and auto-rebuild).
        let found = lookup_job_receipt(receipts_dir, "job-fallback");
        assert!(found.is_some(), "should find receipt via fallback");
        assert_eq!(found.unwrap().job_id, "job-fallback");
    }

    #[test]
    fn test_lookup_job_receipt_not_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let found = lookup_job_receipt(receipts_dir, "nonexistent-job");
        assert!(found.is_none(), "should return None for nonexistent job");
    }

    #[test]
    fn test_list_receipt_headers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write receipt files.
        for (i, ts) in [(1, 3000_u64), (2, 1000), (3, 2000)] {
            let r = make_receipt(&format!("job-{i}"), &format!("hash-{i}"), ts);
            let bytes = serde_json::to_vec_pretty(&r).expect("ser");
            std::fs::write(receipts_dir.join(format!("hash-{i}.json")), &bytes).expect("write");
        }

        // Build index.
        let index = ReceiptIndexV1::rebuild_from_store(receipts_dir).expect("rebuild");
        index.persist(receipts_dir).expect("persist");

        // List headers — should be sorted by timestamp descending.
        let headers = list_receipt_headers(receipts_dir);
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].timestamp_secs, 3000);
        assert_eq!(headers[1].timestamp_secs, 2000);
        assert_eq!(headers[2].timestamp_secs, 1000);
    }

    #[test]
    fn test_list_receipt_headers_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let headers = list_receipt_headers(tmp.path());
        assert!(headers.is_empty());
    }

    // =========================================================================
    // has_receipt_for_job tests (BLOCKER: consumer wiring)
    // =========================================================================

    #[test]
    fn test_has_receipt_for_job_found_via_index() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let (_r1, _digest) = make_and_persist_receipt(receipts_dir, "job-exists", 1000);

        // Build the index.
        let index = ReceiptIndexV1::rebuild_from_store(receipts_dir).expect("rebuild");
        index.persist(receipts_dir).expect("persist");

        assert!(
            has_receipt_for_job(receipts_dir, "job-exists"),
            "should find receipt via index"
        );
    }

    #[test]
    fn test_has_receipt_for_job_not_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(
            !has_receipt_for_job(tmp.path(), "no-such-job"),
            "should not find receipt for nonexistent job"
        );
    }

    #[test]
    fn test_has_receipt_for_job_fallback_scan() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write receipt file with correct content-addressed filename
        // but do NOT build the index.
        let (_r1, _digest) = make_and_persist_receipt(receipts_dir, "job-scan", 2000);

        assert!(
            has_receipt_for_job(receipts_dir, "job-scan"),
            "should find receipt via fallback scan"
        );
    }

    // =========================================================================
    // has_receipt_for_job verification tests (MAJOR: index trust)
    // =========================================================================

    #[test]
    fn test_has_receipt_for_job_rejects_wrong_job_id_in_index() {
        // Regression test: if the index maps job "target-job" to a receipt
        // that actually belongs to "other-job", has_receipt_for_job must
        // return false (not trust the stale/corrupt index pointer).
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Write a receipt for "other-job".
        let receipt = make_receipt("other-job", "hash-other", 1000);
        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join("hash-other.json"), &bytes).expect("write");

        // Build a corrupt index that maps "target-job" -> "hash-other"
        // (the receipt file exists but belongs to a different job).
        let mut index = ReceiptIndexV1::new();
        let corrupt_header = ReceiptHeaderV1 {
            content_hash: "hash-other".to_string(),
            job_id: "target-job".to_string(), // lies about job_id
            outcome: FacJobOutcome::Completed,
            timestamp_secs: 1000,
            queue_lane: None,
            unsafe_direct: false,
        };
        index.upsert(corrupt_header).expect("upsert");
        index.persist(receipts_dir).expect("persist");

        // has_receipt_for_job should NOT trust the index — the receipt's
        // actual job_id ("other-job") does not match "target-job".
        assert!(
            !has_receipt_for_job(receipts_dir, "target-job"),
            "must reject index entry pointing to receipt with wrong job_id"
        );
    }

    #[test]
    fn test_has_receipt_for_job_verifies_integrity() {
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create a receipt with correct content hash and write it.
        let mut receipt = make_receipt("job-verify-has", "placeholder", 3000);
        let hash = compute_job_receipt_content_hash(&receipt);
        receipt.content_hash = hash.clone();
        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{hash}.json")), &bytes).expect("write");

        // Build index pointing to the correct receipt.
        let mut index = ReceiptIndexV1::new();
        index
            .upsert(ReceiptHeaderV1::from_receipt(&receipt))
            .expect("upsert");
        index.persist(receipts_dir).expect("persist");

        // Should return true — receipt exists, job_id matches, integrity OK.
        assert!(
            has_receipt_for_job(receipts_dir, "job-verify-has"),
            "should find receipt with valid integrity"
        );
    }

    // =========================================================================
    // verify_receipt_integrity tests (MAJOR: content-addressed integrity)
    // =========================================================================

    #[test]
    fn test_verify_receipt_integrity_matching_content_hash() {
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let receipt = make_receipt("job-verify", "placeholder", 3000);
        // Compute the v1 content hash and use it as the digest.
        let hash = compute_job_receipt_content_hash(&receipt);
        let receipt_with_hash = FacJobReceiptV1 {
            content_hash: hash.clone(),
            ..receipt
        };

        assert!(
            verify_receipt_integrity(&receipt_with_hash, &hash),
            "should verify against v1 content hash"
        );
    }

    #[test]
    fn test_verify_receipt_integrity_fails_on_mismatch() {
        let receipt = make_receipt("job-tampered", "original-hash", 3000);
        assert!(
            !verify_receipt_integrity(
                &receipt,
                "b3-256:0000000000000000000000000000000000000000000000000000000000000001"
            ),
            "should reject mismatched digest"
        );
    }

    #[test]
    fn test_lookup_verifies_integrity() {
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create a receipt with a correct content hash.
        let mut receipt = make_receipt("job-integrity", "placeholder", 4000);
        let hash = compute_job_receipt_content_hash(&receipt);
        receipt.content_hash = hash.clone();

        // Write the receipt file named by its hash.
        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{hash}.json")), &bytes).expect("write");

        // Build the index with the correct hash.
        let mut index = ReceiptIndexV1::new();
        let header = ReceiptHeaderV1 {
            content_hash: hash.clone(),
            job_id: "job-integrity".to_string(),
            outcome: FacJobOutcome::Completed,
            timestamp_secs: 4000,
            queue_lane: None,
            unsafe_direct: false,
        };
        index.upsert(header).expect("upsert");
        index.persist(receipts_dir).expect("persist");

        // Lookup should succeed with integrity verification.
        let found = lookup_job_receipt(receipts_dir, "job-integrity");
        assert!(found.is_some(), "should find receipt with valid integrity");
        assert_eq!(found.unwrap().content_hash, hash);
    }

    // =========================================================================
    // MAJOR-2: digest validation (path traversal prevention)
    // =========================================================================

    #[test]
    fn test_is_valid_digest_accepts_valid_blake3() {
        assert!(is_valid_digest(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"
        ));
        assert!(is_valid_digest(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_valid_digest(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
    }

    #[test]
    fn test_is_valid_digest_rejects_path_traversal() {
        // Too short.
        assert!(!is_valid_digest("abcd"));
        // Contains path separator.
        assert!(!is_valid_digest(
            "../../../etc/passwd\x00000000000000000000000000000000000000000000000"
        ));
        // Contains non-hex chars.
        assert!(!is_valid_digest(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
        // Too long (65 chars).
        assert!(!is_valid_digest(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a"
        ));
        // Empty.
        assert!(!is_valid_digest(""));
        // Contains slash.
        assert!(!is_valid_digest(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6/7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"
        ));
        // Contains backslash.
        assert!(!is_valid_digest(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\\7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f"
        ));
    }

    #[test]
    fn test_lookup_rejects_malformed_index_digest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Build a corrupt index with a path-traversal digest.
        let mut index = ReceiptIndexV1::new();
        let corrupt_header = ReceiptHeaderV1 {
            content_hash: "../../../etc/passwd".to_string(),
            job_id: "job-traversal".to_string(),
            outcome: FacJobOutcome::Completed,
            timestamp_secs: 1000,
            queue_lane: None,
            unsafe_direct: false,
        };
        index.upsert(corrupt_header).expect("upsert");
        index.persist(receipts_dir).expect("persist");

        // lookup_job_receipt must not attempt to open the traversal path.
        let found = lookup_job_receipt(receipts_dir, "job-traversal");
        assert!(
            found.is_none(),
            "must reject malformed digest in index (path traversal)"
        );
    }

    #[test]
    fn test_has_receipt_rejects_malformed_index_digest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Build a corrupt index with a non-hex digest.
        let mut index = ReceiptIndexV1::new();
        let corrupt_header = ReceiptHeaderV1 {
            content_hash: "not-a-valid-hex-digest-at-all!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                .to_string(),
            job_id: "job-bad-digest".to_string(),
            outcome: FacJobOutcome::Completed,
            timestamp_secs: 1000,
            queue_lane: None,
            unsafe_direct: false,
        };
        index.upsert(corrupt_header).expect("upsert");
        index.persist(receipts_dir).expect("persist");

        // has_receipt_for_job must fall through to scan, not use bad digest as path.
        assert!(
            !has_receipt_for_job(receipts_dir, "job-bad-digest"),
            "must reject malformed digest in index"
        );
    }

    // =========================================================================
    // MAJOR-3: verify_receipt_integrity must not trust content_hash field
    // =========================================================================

    #[test]
    fn test_verify_integrity_rejects_self_reported_content_hash() {
        // Create a receipt whose content_hash == expected_digest but whose
        // recomputed hash does NOT match. This tests that the content_hash
        // field is never trusted as a fallback.
        let fake_digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let receipt = FacJobReceiptV1 {
            content_hash: fake_digest.to_string(),
            ..make_receipt("job-fake", "placeholder", 1000)
        };
        // The receipt's content_hash matches expected_digest, but the
        // recomputed hashes (v1 and v2) will NOT match.
        assert!(
            !verify_receipt_integrity(&receipt, fake_digest),
            "must not trust receipt's self-reported content_hash"
        );
    }

    // =========================================================================
    // TCK-00564 MAJOR-1 regression: is_valid_digest must accept b3-256: prefix
    // =========================================================================

    #[test]
    fn test_is_valid_digest_accepts_b3_256_prefixed() {
        // Canonical format used by compute_job_receipt_content_hash.
        assert!(is_valid_digest(
            "b3-256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"
        ));
        assert!(is_valid_digest(
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_valid_digest(
            "b3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
    }

    #[test]
    fn test_is_valid_digest_rejects_malformed_b3_256() {
        // Wrong prefix.
        assert!(!is_valid_digest(
            "b3-512:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2"
        ));
        // Prefix with too-short hex.
        assert!(!is_valid_digest("b3-256:abcdef"));
        // Prefix with non-hex chars.
        assert!(!is_valid_digest(
            "b3-256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
        // Prefix with path traversal.
        assert!(!is_valid_digest("b3-256:../../../etc/passwd"));
    }

    #[test]
    fn test_lookup_job_receipt_succeeds_with_b3_256_prefixed_content_hash() {
        // Regression test for MAJOR-1 (TCK-00564): index lookup must succeed
        // when receipt content_hash uses the canonical b3-256: prefix format.
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create a receipt with a correct b3-256:-prefixed content hash.
        let mut receipt = make_receipt("job-b3-prefix", "placeholder", 5000);
        let hash = compute_job_receipt_content_hash(&receipt);
        assert!(
            hash.starts_with("b3-256:"),
            "content hash must be b3-256:-prefixed"
        );
        receipt.content_hash = hash.clone();

        // Persist receipt file using the prefixed hash as filename (production format).
        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{hash}.json")), &bytes).expect("write");

        // Build index with b3-256:-prefixed content_hash (via from_receipt).
        let mut index = ReceiptIndexV1::new();
        let header = ReceiptHeaderV1::from_receipt(&receipt);
        assert!(
            header.content_hash.starts_with("b3-256:"),
            "header content_hash must preserve b3-256: prefix"
        );
        index.upsert(header).expect("upsert");
        index.persist(receipts_dir).expect("persist");

        // lookup_job_receipt must succeed via the index path, NOT the fallback scan.
        let found = lookup_job_receipt(receipts_dir, "job-b3-prefix");
        assert!(
            found.is_some(),
            "lookup must succeed for b3-256:-prefixed digest in index"
        );
        let found_receipt = found.unwrap();
        assert_eq!(found_receipt.job_id, "job-b3-prefix");
        assert_eq!(found_receipt.content_hash, hash);
    }

    #[test]
    fn test_has_receipt_for_job_succeeds_with_b3_256_prefixed_content_hash() {
        // Regression test for MAJOR-1 (TCK-00564): has_receipt_for_job must
        // succeed when receipt content_hash uses the canonical b3-256: prefix.
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = make_receipt("job-has-b3", "placeholder", 6000);
        let hash = compute_job_receipt_content_hash(&receipt);
        receipt.content_hash = hash.clone();

        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{hash}.json")), &bytes).expect("write");

        let mut index = ReceiptIndexV1::new();
        index
            .upsert(ReceiptHeaderV1::from_receipt(&receipt))
            .expect("upsert");
        index.persist(receipts_dir).expect("persist");

        assert!(
            has_receipt_for_job(receipts_dir, "job-has-b3"),
            "has_receipt_for_job must succeed for b3-256:-prefixed digest in index"
        );
    }

    #[test]
    fn test_find_receipt_for_job_succeeds_with_b3_256_prefixed_content_hash() {
        // Regression test for MAJOR-1 (TCK-00564): find_receipt_for_job must
        // succeed when receipt content_hash uses the canonical b3-256: prefix.
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        let mut receipt = make_receipt("job-find-b3", "placeholder", 7000);
        let hash = compute_job_receipt_content_hash(&receipt);
        receipt.content_hash = hash.clone();

        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{hash}.json")), &bytes).expect("write");

        let mut index = ReceiptIndexV1::new();
        index
            .upsert(ReceiptHeaderV1::from_receipt(&receipt))
            .expect("upsert");
        index.persist(receipts_dir).expect("persist");

        let found = find_receipt_for_job(receipts_dir, "job-find-b3");
        assert!(
            found.is_some(),
            "find_receipt_for_job must succeed for b3-256:-prefixed digest in index"
        );
        assert_eq!(found.unwrap().job_id, "job-find-b3");
    }

    // =========================================================================
    // MAJOR-1 round 8: fallback scan verifies receipt integrity
    // =========================================================================

    #[test]
    fn test_fallback_scan_rejects_tampered_receipt() {
        // Regression test for MAJOR-1 (TCK-00564 round 8): the fallback scan
        // path in find_receipt_for_job and has_receipt_for_job must verify
        // receipt integrity against the filename-derived digest. A tampered
        // receipt whose content does not match its filename hash must be
        // rejected.
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create a valid receipt and compute its real content hash.
        let mut receipt = make_receipt("job-tampered-scan", "placeholder", 8000);
        let real_hash = compute_job_receipt_content_hash(&receipt);
        receipt.content_hash = real_hash.clone();

        // Write the receipt with the CORRECT filename.
        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{real_hash}.json")), &bytes).expect("write");

        // Tamper with the receipt payload: change the reason field so the
        // content no longer matches the filename hash.
        receipt.reason = "tampered-payload-should-not-verify".to_string();
        let tampered_bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        // Overwrite the file with tampered content (filename stays the same).
        std::fs::write(
            receipts_dir.join(format!("{real_hash}.json")),
            &tampered_bytes,
        )
        .expect("write");

        // Do NOT build an index — force the fallback scan path.
        // find_receipt_for_job must reject the tampered receipt.
        let found = find_receipt_for_job(receipts_dir, "job-tampered-scan");
        assert!(
            found.is_none(),
            "fallback scan must reject receipt with tampered payload"
        );

        // has_receipt_for_job must also reject it.
        assert!(
            !has_receipt_for_job(receipts_dir, "job-tampered-scan"),
            "has_receipt_for_job must reject tampered receipt in fallback scan"
        );
    }

    #[test]
    fn test_fallback_scan_accepts_valid_receipt() {
        // Positive test: fallback scan accepts a receipt whose content matches
        // its filename-derived digest.
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create a receipt with correct content hash as filename.
        let mut receipt = make_receipt("job-valid-scan", "placeholder", 9000);
        let hash = compute_job_receipt_content_hash(&receipt);
        receipt.content_hash = hash.clone();
        let bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{hash}.json")), &bytes).expect("write");

        // Do NOT build an index — force fallback scan.
        let found = find_receipt_for_job(receipts_dir, "job-valid-scan");
        assert!(
            found.is_some(),
            "fallback scan must accept receipt with valid integrity"
        );
        assert_eq!(found.unwrap().job_id, "job-valid-scan");

        assert!(
            has_receipt_for_job(receipts_dir, "job-valid-scan"),
            "has_receipt_for_job must accept valid receipt in fallback scan"
        );
    }

    #[test]
    fn test_fallback_scan_with_index_miss_and_tampered_receipt() {
        // Regression test: index exists but doesn't have the job (index miss),
        // fallback scan finds a tampered receipt — must reject it.
        use crate::fac::receipt::compute_job_receipt_content_hash;

        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts_dir = tmp.path();

        // Create and write a valid receipt.
        let mut receipt = make_receipt("job-index-miss", "placeholder", 10000);
        let hash = compute_job_receipt_content_hash(&receipt);
        receipt.content_hash = hash.clone();

        // Write tampered content under the correct hash filename.
        receipt.reason = "tampered-after-write".to_string();
        let tampered_bytes = serde_json::to_vec_pretty(&receipt).expect("ser");
        std::fs::write(receipts_dir.join(format!("{hash}.json")), &tampered_bytes).expect("write");

        // Build an index that does NOT contain this job (simulating index miss).
        let index = ReceiptIndexV1::new();
        index.persist(receipts_dir).expect("persist");

        // find_receipt_for_job must reject the tampered receipt even when
        // the index exists but doesn't have this job.
        let found = find_receipt_for_job(receipts_dir, "job-index-miss");
        assert!(
            found.is_none(),
            "must reject tampered receipt after index miss"
        );
    }
}
