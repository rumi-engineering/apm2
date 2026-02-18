// AGENT-AUTHORED (TCK-00586)
//! Queue scan lock: optional short-lived lease for scan ownership.
//!
//! Implements TCK-00586: multi-worker fairness and scan efficiency.
//! When multiple workers poll the same `queue/pending/` directory,
//! redundant directory scans cause a CPU/IO stampede. This module
//! provides an optional advisory `flock`-based scan lock so that at
//! most one worker performs a full directory scan per cycle while
//! others wait with jitter and rely on the atomic claim (rename)
//! for correctness.
//!
//! # Design
//!
//! - The scan lock is a file lock at `queue/scan.lock`.
//! - Acquisition is non-blocking (`LOCK_EX | LOCK_NB`).
//! - The lock is held for the duration of the directory scan, then released via
//!   RAII `Drop` on `ScanLockGuard`.
//! - Workers that fail to acquire the lock sleep with jitter and skip the scan,
//!   proceeding directly to the next poll cycle. The atomic claim (rename
//!   `pending/X.json` -> `claimed/X.json`) remains the correctness mechanism;
//!   the scan lock is purely an efficiency optimization.
//!
//! # Stuck Lock Detection
//!
//! Each scan lock acquisition writes the holder PID and a monotonic
//! timestamp into the lock file. If a subsequent acquisition attempt
//! reads a lock file whose holder PID is no longer alive and the
//! timestamp exceeds `MAX_SCAN_LOCK_HOLD_DURATION`, a structured
//! `ScanLockStuckReceipt` is emitted for observability.
//!
//! # Determinism Preservation
//!
//! The scan lock does NOT change the claim selection order.
//! Candidates are still sorted by `(priority ASC, enqueue_time ASC,
//! job_id ASC)` after scanning. The lock only determines WHICH
//! worker performs the scan in a given cycle.
//!
//! # Security Invariants
//!
//! - [INV-SL-001] Lock file creation uses O_NOFOLLOW to prevent symlink attacks
//!   (CTR-2609).
//! - [INV-SL-002] Lock file metadata reads are bounded to
//!   `MAX_SCAN_LOCK_FILE_SIZE` (CTR-1603).
//! - [INV-SL-003] Stuck detection uses wall-clock epoch seconds for
//!   cross-process timestamp comparison. `SystemTime` deviation documented
//!   inline (CTR-2501).
//! - [INV-SL-004] Lock file writes use atomic write (temp + rename) to prevent
//!   partial reads (CTR-2607).
//! - [INV-SL-005] All string fields in `ScanLockMetadata` are bounded during
//!   deserialization.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Constants
// ============================================================================

/// Lock file name within the queue directory.
const SCAN_LOCK_FILENAME: &str = "scan.lock";

/// Maximum scan lock hold duration before declaring stuck (30 seconds).
///
/// Scan operations on a directory with `MAX_PENDING_SCAN_ENTRIES` (4096)
/// entries should complete well within this window. If the lock is held
/// longer, the holder is likely stuck or crashed without releasing.
pub const MAX_SCAN_LOCK_HOLD_DURATION: Duration = Duration::from_secs(30);

/// Maximum size of the scan lock metadata file (1 KiB).
///
/// The metadata JSON is small (PID + timestamp + schema); 1 KiB is
/// generous. Prevents OOM from a crafted lock file (INV-SL-002).
const MAX_SCAN_LOCK_FILE_SIZE: usize = 1024;

/// Default jitter range for workers that fail to acquire the scan lock.
///
/// Workers sleep for `base_interval + random(0..SCAN_LOCK_JITTER_MS)` when
/// the scan lock is held by another worker.
pub const SCAN_LOCK_JITTER_MS: u64 = 500;

/// Schema identifier for scan lock metadata.
const SCAN_LOCK_METADATA_SCHEMA: &str = "apm2.fac.scan_lock_metadata.v1";

/// Schema identifier for stuck scan lock receipts.
pub const SCAN_LOCK_STUCK_RECEIPT_SCHEMA: &str = "apm2.fac.scan_lock_stuck_receipt.v1";

/// Maximum string length for schema fields in lock metadata.
const MAX_SCHEMA_STRING_LENGTH: usize = 128;

// ============================================================================
// Error types
// ============================================================================

/// Errors from scan lock operations.
#[derive(Debug, Error)]
pub enum ScanLockError {
    /// Filesystem I/O error during lock operations.
    #[error("scan lock I/O error: {context}: {source}")]
    Io {
        /// Human-readable context for the error.
        context: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// Lock file path is a symlink (INV-SL-001).
    #[error("scan lock path is a symlink: {path}")]
    SymlinkDetected {
        /// The symlink path.
        path: String,
    },

    /// Lock metadata file exceeds maximum size (INV-SL-002).
    #[error("scan lock metadata too large: {size} > {max}")]
    MetadataTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Lock metadata deserialization failed.
    #[error("scan lock metadata parse error: {detail}")]
    MetadataParseFailed {
        /// Parse error detail.
        detail: String,
    },
}

impl ScanLockError {
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// ============================================================================
// Scan lock metadata
// ============================================================================

/// Metadata written to the scan lock file by the lock holder.
///
/// Enables stuck detection: if the holder PID is dead and the timestamp
/// is older than `MAX_SCAN_LOCK_HOLD_DURATION`, the lock is stuck.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanLockMetadata {
    /// Schema identifier (bounded, INV-SL-005).
    pub schema: String,
    /// PID of the lock holder.
    pub holder_pid: u32,
    /// Epoch timestamp (seconds) when the lock was acquired.
    ///
    /// Uses `SystemTime` for the persisted value (cross-process readable).
    /// CTR-2501 deviation documented at `current_epoch_secs()`.
    pub acquired_epoch_secs: u64,
}

// ============================================================================
// Stuck receipt
// ============================================================================

/// Receipt emitted when a stuck scan lock is detected.
///
/// A lock is considered stuck when:
/// 1. The lock file exists and is held (flock returns EWOULDBLOCK), AND
/// 2. The holder PID recorded in the metadata is no longer alive, AND
/// 3. The elapsed time since acquisition exceeds `MAX_SCAN_LOCK_HOLD_DURATION`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanLockStuckReceipt {
    /// Schema identifier.
    pub schema: String,
    /// PID of the stuck holder.
    pub stuck_holder_pid: u32,
    /// Epoch timestamp when the stuck lock was acquired.
    pub acquired_epoch_secs: u64,
    /// Epoch timestamp when the stuck condition was detected.
    pub detected_epoch_secs: u64,
    /// PID of the detecting worker.
    pub detector_pid: u32,
    /// Duration the lock was held (seconds).
    pub held_duration_secs: u64,
}

// ============================================================================
// Scan lock result
// ============================================================================

/// Result of attempting to acquire the scan lock.
#[derive(Debug)]
pub enum ScanLockResult {
    /// Lock acquired; guard releases on drop.
    Acquired(ScanLockGuard),
    /// Lock is held by another worker; skip scan this cycle.
    Held,
    /// Lock file does not exist or the queue directory is absent; scan anyway
    /// (single-worker mode or first run).
    Unavailable,
}

// ============================================================================
// Scan lock guard (RAII)
// ============================================================================

/// RAII guard that holds the scan lock.
///
/// The lock file (`queue/scan.lock`) is held via `flock(LOCK_EX)` for the
/// lifetime of this guard. Dropping the guard closes the file descriptor,
/// which releases the lock.
///
/// # Synchronization Protocol (RS-21)
///
/// - Protected data: the queue `pending/` directory listing.
/// - Publication: holder writes lock metadata, then scans `pending/`.
/// - Consumption: other workers attempt `flock(LOCK_EX | LOCK_NB)`; on
///   `EWOULDBLOCK` they skip the scan.
/// - Happens-before: `flock` release on the holder → next successful `flock`
///   acquisition by any worker.
/// - Async suspension: N/A (synchronous `std::thread` worker loop).
pub struct ScanLockGuard {
    /// The lock file (held open for the guard lifetime).
    lock_file: File,
    /// Path to the lock file (for diagnostics).
    lock_path: PathBuf,
}

impl std::fmt::Debug for ScanLockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanLockGuard")
            .field("lock_file", &self.lock_file)
            .field("lock_path", &self.lock_path)
            .finish()
    }
}

// Drop is implicit: closing the File releases the flock.

// ============================================================================
// Public API
// ============================================================================

/// Try to acquire the scan lock (non-blocking).
///
/// The lock file is created at `queue_root/scan.lock`. If the lock is held
/// by another process, returns `ScanLockResult::Held`. If the queue root
/// does not exist, returns `ScanLockResult::Unavailable`.
///
/// On successful acquisition, writes `ScanLockMetadata` to the lock file
/// for stuck detection by other workers.
///
/// # Errors
///
/// Returns `ScanLockError` on unexpected I/O failures (not on contention).
pub fn try_acquire_scan_lock(queue_root: &Path) -> Result<ScanLockResult, ScanLockError> {
    if !queue_root.is_dir() {
        return Ok(ScanLockResult::Unavailable);
    }

    let lock_path = queue_root.join(SCAN_LOCK_FILENAME);

    // Symlink check (INV-SL-001).
    if let Ok(meta) = fs::symlink_metadata(&lock_path) {
        if meta.file_type().is_symlink() {
            return Err(ScanLockError::SymlinkDetected {
                path: lock_path.display().to_string(),
            });
        }
    }

    let lock_file = open_scan_lock_file(&lock_path)?;

    if try_flock_exclusive(&lock_file)? {
        // Lock acquired. Write metadata for stuck detection.
        let metadata = ScanLockMetadata {
            schema: SCAN_LOCK_METADATA_SCHEMA.to_string(),
            holder_pid: std::process::id(),
            acquired_epoch_secs: current_epoch_secs(),
        };
        // Best-effort metadata write; lock is still held via flock even
        // if the metadata write fails. The metadata is only used for
        // stuck detection, not for correctness.
        let _ = write_lock_metadata(&lock_path, &metadata);

        Ok(ScanLockResult::Acquired(ScanLockGuard {
            lock_file,
            lock_path,
        }))
    } else {
        Ok(ScanLockResult::Held)
    }
}

/// Check whether the scan lock is stuck (held by a dead process for too long).
///
/// Reads the lock metadata from `queue_root/scan.lock` and checks:
/// 1. Is the lock currently held (flock probe)?
/// 2. Is the holder PID still alive?
/// 3. Has the lock been held longer than `MAX_SCAN_LOCK_HOLD_DURATION`?
///
/// Returns `Some(receipt)` if stuck, `None` otherwise.
///
/// # Errors
///
/// Returns `ScanLockError` on I/O failures.
pub fn check_stuck_scan_lock(
    queue_root: &Path,
) -> Result<Option<ScanLockStuckReceipt>, ScanLockError> {
    let lock_path = queue_root.join(SCAN_LOCK_FILENAME);

    if !lock_path.exists() {
        return Ok(None);
    }

    // Read metadata first (before lock probe) to avoid TOCTOU with the
    // lock holder writing metadata.
    let Ok(metadata) = read_lock_metadata(&lock_path) else {
        return Ok(None); // Can't read metadata; not stuck.
    };

    // Probe whether the lock is actually held.
    let Ok(probe_file) = open_scan_lock_file(&lock_path) else {
        return Ok(None);
    };
    let lock_held = match try_flock_exclusive(&probe_file) {
        Ok(true) => {
            // We acquired the lock, meaning no one else holds it.
            // Drop immediately to release.
            drop(probe_file);
            false
        },
        Ok(false) => true,
        Err(_) => return Ok(None),
    };

    if !lock_held {
        return Ok(None);
    }

    // Lock is held. Check if the holder is alive.
    if is_pid_alive(metadata.holder_pid) {
        return Ok(None); // Holder is alive; lock is legitimately held.
    }

    // Holder is dead. Check duration.
    let now_epoch = current_epoch_secs();
    let held_secs = now_epoch.saturating_sub(metadata.acquired_epoch_secs);

    if held_secs < MAX_SCAN_LOCK_HOLD_DURATION.as_secs() {
        return Ok(None); // Not long enough to declare stuck.
    }

    Ok(Some(ScanLockStuckReceipt {
        schema: SCAN_LOCK_STUCK_RECEIPT_SCHEMA.to_string(),
        stuck_holder_pid: metadata.holder_pid,
        acquired_epoch_secs: metadata.acquired_epoch_secs,
        detected_epoch_secs: now_epoch,
        detector_pid: std::process::id(),
        held_duration_secs: held_secs,
    }))
}

/// Compute a jittered sleep duration for workers that could not acquire
/// the scan lock.
///
/// The jitter prevents thundering-herd retries when multiple workers
/// discover the lock is held simultaneously.
#[must_use]
pub fn scan_lock_jitter_duration(base_interval_secs: u64) -> Duration {
    let jitter_ms = rand::random::<u64>() % (SCAN_LOCK_JITTER_MS + 1);
    Duration::from_secs(base_interval_secs) + Duration::from_millis(jitter_ms)
}

// ============================================================================
// Internal helpers
// ============================================================================

fn open_scan_lock_file(lock_path: &Path) -> Result<File, ScanLockError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).truncate(false).create(true);

    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
        options.mode(0o600);
    }

    options
        .open(lock_path)
        .map_err(|e| ScanLockError::io(format!("opening scan lock {}", lock_path.display()), e))
}

fn try_flock_exclusive(file: &File) -> Result<bool, ScanLockError> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: `fd` is a valid file descriptor from an open `std::fs::File`.
        // `LOCK_EX | LOCK_NB` is a valid `flock` operation that cannot cause
        // undefined behavior. The file handle remains alive for the duration
        // of this call.
        #[allow(unsafe_code)]
        let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            return Ok(false);
        }
        Err(ScanLockError::io("flock(LOCK_EX|LOCK_NB)", err))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        // On non-Unix platforms, always acquire (single-worker assumption).
        Ok(true)
    }
}

fn write_lock_metadata(lock_path: &Path, metadata: &ScanLockMetadata) -> Result<(), ScanLockError> {
    let json = serde_json::to_string_pretty(metadata)
        .map_err(|e| ScanLockError::io("serializing scan lock metadata", io::Error::other(e)))?;

    // Atomic write: write to unpredictable temp file, then rename (INV-SL-004).
    // Uses tempfile::NamedTempFile for unpredictable name + O_EXCL creation +
    // 0600 permissions, preventing symlink attacks on the temp file (CTR-2607).
    let parent = lock_path.parent().unwrap_or(lock_path);

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| ScanLockError::io("creating scan lock temp file", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = tmp.as_file().set_permissions(perms);
    }

    tmp.write_all(json.as_bytes())
        .map_err(|e| ScanLockError::io("writing scan lock metadata", e))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| ScanLockError::io("syncing scan lock metadata", e))?;

    // We write metadata to a separate sidecar file rather than the lock file
    // itself, because replacing the lock file via rename would break the flock
    // association (the flock is on the open fd, which references the original
    // inode).
    let meta_path = lock_path.with_extension("lock.meta");
    tmp.persist(&meta_path)
        .map_err(|e| ScanLockError::io("renaming scan lock metadata", e.error))?;

    Ok(())
}

fn read_lock_metadata(lock_path: &Path) -> Result<ScanLockMetadata, ScanLockError> {
    let meta_path = lock_path.with_extension("lock.meta");

    // Open with O_NOFOLLOW to atomically reject symlinks (INV-SL-001).
    // This eliminates the TOCTOU race between a separate symlink check and
    // the open call. On symlinks, open() returns ELOOP which we translate
    // to SymlinkDetected.
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = match options.open(&meta_path) {
        Ok(f) => f,
        Err(e) => {
            // ELOOP (errno 40) indicates the path is a symlink when O_NOFOLLOW is set.
            #[cfg(unix)]
            if e.raw_os_error() == Some(libc::ELOOP) {
                return Err(ScanLockError::SymlinkDetected {
                    path: meta_path.display().to_string(),
                });
            }
            return Err(ScanLockError::io("opening scan lock metadata", e));
        },
    };

    // Size check on the opened fd (no TOCTOU — we already hold the fd).
    {
        let file_meta = file
            .metadata()
            .map_err(|e| ScanLockError::io("stat scan lock metadata", e))?;
        let size = usize::try_from(file_meta.len()).unwrap_or(usize::MAX);
        if size > MAX_SCAN_LOCK_FILE_SIZE {
            return Err(ScanLockError::MetadataTooLarge {
                size,
                max: MAX_SCAN_LOCK_FILE_SIZE,
            });
        }
    }

    let mut buf = vec![0u8; MAX_SCAN_LOCK_FILE_SIZE];
    let mut total = 0usize;
    loop {
        let n = file
            .read(&mut buf[total..])
            .map_err(|e| ScanLockError::io("reading scan lock metadata", e))?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n);
        if total > MAX_SCAN_LOCK_FILE_SIZE {
            return Err(ScanLockError::MetadataTooLarge {
                size: total,
                max: MAX_SCAN_LOCK_FILE_SIZE,
            });
        }
    }

    let metadata: ScanLockMetadata =
        serde_json::from_slice(&buf[..total]).map_err(|e| ScanLockError::MetadataParseFailed {
            detail: e.to_string(),
        })?;

    // Validate bounded string fields (INV-SL-005).
    if metadata.schema.len() > MAX_SCHEMA_STRING_LENGTH {
        return Err(ScanLockError::MetadataParseFailed {
            detail: format!(
                "schema field too long: {} > {MAX_SCHEMA_STRING_LENGTH}",
                metadata.schema.len()
            ),
        });
    }

    Ok(metadata)
}

/// Returns current epoch seconds using `SystemTime`.
///
/// CTR-2501 deviation: uses `SystemTime::now()` for the persisted epoch
/// timestamp. This is intentional: the timestamp must be meaningful across
/// processes (different `Instant` origins). The stuck detection threshold
/// is 30s, which is large enough to tolerate NTP drift. Elapsed time is
/// computed as `saturating_sub` on epoch seconds, so backwards clock jumps
/// produce zero (safe).
#[allow(clippy::disallowed_methods)]
fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Send signal 0 to check if the process exists.
        // SAFETY: `kill(pid, 0)` is a standard POSIX call that checks process
        // existence without sending a signal. It cannot cause undefined
        // behavior. The `pid as libc::pid_t` cast is safe because `libc::pid_t`
        // is `i32` and valid PIDs on Linux are in [1, 2^22], well within range.
        #[allow(unsafe_code, clippy::cast_possible_wrap)]
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if result == 0 {
            return true;
        }
        // EPERM means the process exists but we lack permission to signal it.
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        errno == libc::EPERM
    }
    #[cfg(not(unix))]
    {
        // Conservatively assume alive on non-Unix (fail-closed for stuck
        // detection: won't falsely declare stuck).
        let _ = pid;
        true
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn test_acquire_scan_lock_on_missing_queue_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nonexistent = tmp.path().join("nonexistent");
        let result = try_acquire_scan_lock(&nonexistent).expect("should not error");
        assert!(matches!(result, ScanLockResult::Unavailable));
    }

    #[test]
    fn test_acquire_scan_lock_success() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create queue dir");

        let result = try_acquire_scan_lock(&queue_root).expect("should not error");
        assert!(
            matches!(result, ScanLockResult::Acquired(_)),
            "expected Acquired, got {result:?}"
        );
    }

    #[test]
    fn test_acquire_scan_lock_writes_metadata() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create queue dir");

        // Acquire the lock.
        let _guard = try_acquire_scan_lock(&queue_root).expect("should not error");

        // Verify metadata was written.
        let meta_path = queue_root.join("scan.lock.meta");
        assert!(
            meta_path.exists(),
            "metadata file should exist after acquisition"
        );

        let metadata =
            read_lock_metadata(&queue_root.join(SCAN_LOCK_FILENAME)).expect("should read metadata");
        assert_eq!(metadata.holder_pid, std::process::id());
        assert_eq!(metadata.schema, SCAN_LOCK_METADATA_SCHEMA);
    }

    #[test]
    fn test_scan_lock_metadata_roundtrip() {
        let metadata = ScanLockMetadata {
            schema: SCAN_LOCK_METADATA_SCHEMA.to_string(),
            holder_pid: 12345,
            acquired_epoch_secs: 1_700_000_000,
        };
        let json = serde_json::to_string_pretty(&metadata).expect("serialize");
        let parsed: ScanLockMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.holder_pid, 12345);
        assert_eq!(parsed.acquired_epoch_secs, 1_700_000_000);
        assert_eq!(parsed.schema, SCAN_LOCK_METADATA_SCHEMA);
    }

    #[test]
    fn test_stuck_receipt_roundtrip() {
        let receipt = ScanLockStuckReceipt {
            schema: SCAN_LOCK_STUCK_RECEIPT_SCHEMA.to_string(),
            stuck_holder_pid: 99999,
            acquired_epoch_secs: 1_700_000_000,
            detected_epoch_secs: 1_700_000_060,
            detector_pid: 11111,
            held_duration_secs: 60,
        };
        let json = serde_json::to_string_pretty(&receipt).expect("serialize");
        let parsed: ScanLockStuckReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.stuck_holder_pid, 99999);
        assert_eq!(parsed.held_duration_secs, 60);
    }

    #[test]
    fn test_check_stuck_no_lock_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create dir");

        let result = check_stuck_scan_lock(&queue_root).expect("should not error");
        assert!(result.is_none(), "no lock file should mean not stuck");
    }

    #[test]
    fn test_scan_lock_jitter_bounded() {
        for _ in 0..100 {
            let dur = scan_lock_jitter_duration(5);
            assert!(dur >= Duration::from_secs(5));
            assert!(dur <= Duration::from_secs(5) + Duration::from_millis(SCAN_LOCK_JITTER_MS));
        }
    }

    #[test]
    fn test_metadata_too_large() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let meta_path = tmp.path().join("scan.lock.meta");
        let large_data = vec![b'x'; MAX_SCAN_LOCK_FILE_SIZE + 100];
        fs::write(&meta_path, &large_data).expect("write");

        let lock_path = tmp.path().join(SCAN_LOCK_FILENAME);
        let result = read_lock_metadata(&lock_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScanLockError::MetadataTooLarge { size, max } => {
                assert!(size > MAX_SCAN_LOCK_FILE_SIZE);
                assert_eq!(max, MAX_SCAN_LOCK_FILE_SIZE);
            },
            other => panic!("expected MetadataTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn test_metadata_parse_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let meta_path = tmp.path().join("scan.lock.meta");
        fs::write(&meta_path, b"not json").expect("write");

        let lock_path = tmp.path().join(SCAN_LOCK_FILENAME);
        let result = read_lock_metadata(&lock_path);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScanLockError::MetadataParseFailed { .. }
        ));
    }

    #[test]
    fn test_schema_field_too_long() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let meta_path = tmp.path().join("scan.lock.meta");
        let metadata = ScanLockMetadata {
            schema: "x".repeat(MAX_SCHEMA_STRING_LENGTH + 1),
            holder_pid: 1,
            acquired_epoch_secs: 0,
        };
        let json = serde_json::to_string(&metadata).expect("serialize");
        fs::write(&meta_path, json.as_bytes()).expect("write");

        let lock_path = tmp.path().join(SCAN_LOCK_FILENAME);
        let result = read_lock_metadata(&lock_path);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScanLockError::MetadataParseFailed { .. }
        ));
    }

    #[test]
    fn test_symlink_detection_lock_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create dir");

        // Create a target file and a symlink to it.
        let target = tmp.path().join("real_lock");
        fs::write(&target, b"").expect("write target");
        let lock_path = queue_root.join(SCAN_LOCK_FILENAME);

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &lock_path).expect("symlink");
            let result = try_acquire_scan_lock(&queue_root);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ScanLockError::SymlinkDetected { .. }
            ));
        }
    }

    #[test]
    fn test_current_pid_is_alive() {
        assert!(is_pid_alive(std::process::id()));
    }

    #[test]
    fn test_dead_pid_is_not_alive() {
        // PID 4000000 is almost certainly not a real process.
        // On some systems this may be true if PIDs wrap, but it is
        // overwhelmingly unlikely in test environments.
        assert!(!is_pid_alive(4_000_000));
    }

    #[test]
    fn test_guard_drops_cleanly() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create dir");

        {
            let result = try_acquire_scan_lock(&queue_root).expect("acquire");
            assert!(matches!(result, ScanLockResult::Acquired(_)));
            // Guard drops here.
        }

        // After drop, we should be able to acquire again.
        let result = try_acquire_scan_lock(&queue_root).expect("re-acquire");
        assert!(
            matches!(result, ScanLockResult::Acquired(_)),
            "expected Acquired after guard drop, got {result:?}"
        );
    }

    #[test]
    fn test_deny_unknown_fields_metadata() {
        let json = r#"{"schema":"test","holder_pid":1,"acquired_epoch_secs":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<ScanLockMetadata>(json);
        assert!(result.is_err(), "deny_unknown_fields should reject extra");
    }

    #[test]
    fn test_deny_unknown_fields_receipt() {
        let json = r#"{"schema":"test","stuck_holder_pid":1,"acquired_epoch_secs":0,"detected_epoch_secs":0,"detector_pid":1,"held_duration_secs":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<ScanLockStuckReceipt>(json);
        assert!(result.is_err(), "deny_unknown_fields should reject extra");
    }

    // ========================================================================
    // Regression tests for security findings (TCK-00586 fix round)
    // ========================================================================

    /// Regression: `read_lock_metadata` must reject symlinks via `O_NOFOLLOW`
    /// (BLOCKER: TOCTOU symlink attack fix).
    #[cfg(unix)]
    #[test]
    fn test_read_lock_metadata_rejects_symlink_atomically() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create dir");

        // Write a legitimate metadata file at a different location.
        let real_meta = tmp.path().join("real.meta");
        let metadata = ScanLockMetadata {
            schema: SCAN_LOCK_METADATA_SCHEMA.to_string(),
            holder_pid: 1,
            acquired_epoch_secs: 1_700_000_000,
        };
        let json = serde_json::to_string_pretty(&metadata).expect("serialize");
        fs::write(&real_meta, json.as_bytes()).expect("write real meta");

        // Create a symlink at the metadata path pointing to the real file.
        let meta_path = queue_root.join("scan.lock.meta");
        std::os::unix::fs::symlink(&real_meta, &meta_path).expect("symlink");

        let lock_path = queue_root.join(SCAN_LOCK_FILENAME);
        let result = read_lock_metadata(&lock_path);
        assert!(result.is_err(), "symlink metadata should be rejected");
        assert!(
            matches!(result.unwrap_err(), ScanLockError::SymlinkDetected { .. }),
            "expected SymlinkDetected error for symlinked metadata"
        );
    }

    /// Regression: `write_lock_metadata` uses unpredictable temp file name
    /// (MAJOR: predictable temp file name fix).
    #[test]
    fn test_write_lock_metadata_no_predictable_temp() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create dir");

        let lock_path = queue_root.join(SCAN_LOCK_FILENAME);
        let metadata = ScanLockMetadata {
            schema: SCAN_LOCK_METADATA_SCHEMA.to_string(),
            holder_pid: std::process::id(),
            acquired_epoch_secs: current_epoch_secs(),
        };

        write_lock_metadata(&lock_path, &metadata).expect("write metadata");

        // Verify the predictable temp file `.scan.lock.tmp` does NOT exist
        // (the old code would have left it or used it; the new code uses
        // NamedTempFile which creates a random name and persist() renames it).
        let old_temp_path = queue_root.join(".scan.lock.tmp");
        assert!(
            !old_temp_path.exists(),
            "predictable temp file should not exist after write_lock_metadata"
        );

        // Verify the metadata sidecar was written correctly.
        let meta_path = lock_path.with_extension("lock.meta");
        assert!(meta_path.exists(), "metadata sidecar should exist");
        let read_back = read_lock_metadata(&lock_path).expect("read back metadata");
        assert_eq!(read_back.holder_pid, std::process::id());
    }

    /// Regression: `write_lock_metadata` sets 0600 permissions on metadata
    /// file.
    #[cfg(unix)]
    #[test]
    fn test_write_lock_metadata_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create dir");

        let lock_path = queue_root.join(SCAN_LOCK_FILENAME);
        let metadata = ScanLockMetadata {
            schema: SCAN_LOCK_METADATA_SCHEMA.to_string(),
            holder_pid: std::process::id(),
            acquired_epoch_secs: current_epoch_secs(),
        };

        write_lock_metadata(&lock_path, &metadata).expect("write metadata");

        let meta_path = lock_path.with_extension("lock.meta");
        let perms = fs::metadata(&meta_path).expect("stat").permissions();
        // tempfile creates with 0600 by default on Unix; verify no group/other bits.
        let mode = perms.mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "metadata file should have no group/other permissions, got {mode:#o}"
        );
    }
}
