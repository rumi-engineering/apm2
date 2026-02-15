// AGENT-AUTHORED (TCK-00600)
//! Worker heartbeat file for liveness monitoring.
//!
//! The FAC worker writes a small JSON heartbeat file after each poll cycle.
//! `apm2 fac services status` reads this file to determine worker health
//! beyond what systemd unit state alone can tell (e.g., a worker that is
//! `active (running)` but stuck in a long job or deadlocked).
//!
//! # File Format
//!
//! ```json
//! {
//!   "schema": "apm2.fac_worker_heartbeat.v1",
//!   "pid": 12345,
//!   "timestamp_epoch_secs": 1707000000,
//!   "cycle_count": 42,
//!   "jobs_completed": 10,
//!   "jobs_denied": 2,
//!   "jobs_quarantined": 1,
//!   "health_status": "healthy"
//! }
//! ```
//!
//! # Security Invariants
//!
//! - [INV-WHB-001] Heartbeat files are bounded to `MAX_HEARTBEAT_FILE_SIZE` (4
//!   KiB) when read, preventing OOM from crafted files.
//! - [INV-WHB-002] Heartbeat file reads use bounded I/O with symlink refusal
//!   (where available).
//! - [INV-WHB-003] Stale heartbeat detection uses a wall-clock threshold
//!   (`MAX_HEARTBEAT_AGE_SECS`). Heartbeats older than this are reported as
//!   `stale`.
//! - [INV-WHB-004] Heartbeat writes use atomic write (temp + rename) to prevent
//!   partial reads.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema identifier for worker heartbeat files.
pub const HEARTBEAT_SCHEMA: &str = "apm2.fac_worker_heartbeat.v1";

/// Maximum heartbeat file size for bounded reads (4 KiB).
///
/// The read buffer is allocated at `MAX_HEARTBEAT_FILE_SIZE + 1` bytes so
/// that an oversized file is detected *during* the read (before parsing),
/// rather than after loading the entire file into memory.
pub const MAX_HEARTBEAT_FILE_SIZE: usize = 4096;

/// Maximum age of a heartbeat before it is considered stale (120 seconds).
///
/// This should be comfortably larger than the worker's poll interval to
/// avoid false stale reports during normal operation with a 10-second poll.
pub const MAX_HEARTBEAT_AGE_SECS: u64 = 120;

/// Heartbeat file name.
pub const HEARTBEAT_FILENAME: &str = "worker_heartbeat.json";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Worker heartbeat written after each poll cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHeartbeatV1 {
    /// Schema identifier.
    pub schema: String,
    /// Worker process ID.
    pub pid: u32,
    /// Epoch timestamp (seconds) when this heartbeat was written.
    pub timestamp_epoch_secs: u64,
    /// Number of poll cycles completed.
    pub cycle_count: u64,
    /// Cumulative jobs completed.
    pub jobs_completed: u64,
    /// Cumulative jobs denied.
    pub jobs_denied: u64,
    /// Cumulative jobs quarantined.
    pub jobs_quarantined: u64,
    /// Self-assessed health status.
    pub health_status: String,
}

/// Result of reading and evaluating a worker heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatStatus {
    /// Whether a heartbeat file was found.
    pub found: bool,
    /// Whether the heartbeat is fresh (not stale).
    pub fresh: bool,
    /// Worker PID from the heartbeat.
    pub pid: u32,
    /// Age of the heartbeat in seconds.
    pub age_secs: u64,
    /// Cycle count from the heartbeat.
    pub cycle_count: u64,
    /// Worker self-assessed health.
    pub health_status: String,
    /// Error message if heartbeat could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HeartbeatStatus {
    /// Create a status indicating no heartbeat file found.
    #[must_use]
    pub fn not_found() -> Self {
        Self {
            found: false,
            fresh: false,
            pid: 0,
            age_secs: 0,
            cycle_count: 0,
            health_status: "unknown".to_string(),
            error: Some("heartbeat file not found".to_string()),
        }
    }

    /// Create a status indicating a read error.
    #[must_use]
    pub fn read_error(msg: String) -> Self {
        Self {
            found: false,
            fresh: false,
            pid: 0,
            age_secs: 0,
            cycle_count: 0,
            health_status: "unknown".to_string(),
            error: Some(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// Write API (used by worker)
// ---------------------------------------------------------------------------

/// Write a worker heartbeat file atomically.
///
/// The file is written to `<fac_root>/worker_heartbeat.json` using
/// atomic write (temp + rename) per INV-WHB-004.
///
/// # Errors
///
/// Returns an error string if the write fails.
pub fn write_heartbeat(
    fac_root: &std::path::Path,
    cycle_count: u64,
    jobs_completed: u64,
    jobs_denied: u64,
    jobs_quarantined: u64,
    health_status: &str,
) -> Result<(), String> {
    let heartbeat = WorkerHeartbeatV1 {
        schema: HEARTBEAT_SCHEMA.to_string(),
        pid: std::process::id(),
        timestamp_epoch_secs: current_epoch_secs(),
        cycle_count,
        jobs_completed,
        jobs_denied,
        jobs_quarantined,
        health_status: health_status.to_string(),
    };

    let json = serde_json::to_vec_pretty(&heartbeat)
        .map_err(|e| format!("heartbeat serialization failed: {e}"))?;

    let heartbeat_path = fac_root.join(HEARTBEAT_FILENAME);

    // Atomic write: temp file + rename.
    // We use a simple approach: write to .tmp then rename.
    let tmp_path = fac_root.join(format!(".{HEARTBEAT_FILENAME}.tmp"));
    std::fs::write(&tmp_path, &json).map_err(|e| format!("heartbeat tmp write failed: {e}"))?;
    std::fs::rename(&tmp_path, &heartbeat_path)
        .map_err(|e| format!("heartbeat rename failed: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Read API (used by `services status`)
// ---------------------------------------------------------------------------

/// Read and evaluate a worker heartbeat file.
///
/// Returns a `HeartbeatStatus` with freshness evaluation. The heartbeat
/// is considered stale if older than `MAX_HEARTBEAT_AGE_SECS`.
///
/// # Security (INV-WHB-001, INV-WHB-002, CTR-1603)
///
/// - Opens the file with `O_NOFOLLOW` (Linux) to refuse symlinks at the kernel
///   level. On non-Linux platforms, falls back to `symlink_metadata` check
///   before open (theoretical TOCTOU window, best-effort).
/// - Verifies via `fstat` on the opened handle that the file is a regular file
///   (not a device, pipe, FIFO, or socket).
/// - Reads into a bounded buffer of `MAX_HEARTBEAT_FILE_SIZE + 1` bytes. If the
///   read fills the buffer completely, the file is rejected as oversized
///   *before* parsing. No unbounded allocation occurs.
#[must_use]
pub fn read_heartbeat(fac_root: &std::path::Path) -> HeartbeatStatus {
    let heartbeat_path = fac_root.join(HEARTBEAT_FILENAME);

    // INV-WHB-002: Open with O_NOFOLLOW + regular-file verification.
    let data = match read_heartbeat_bounded(&heartbeat_path) {
        Ok(data) => data,
        Err(HeartbeatReadError::NotFound) => return HeartbeatStatus::not_found(),
        Err(HeartbeatReadError::Other(msg)) => return HeartbeatStatus::read_error(msg),
    };

    let heartbeat: WorkerHeartbeatV1 = match serde_json::from_slice(&data) {
        Ok(hb) => hb,
        Err(e) => {
            return HeartbeatStatus::read_error(format!("heartbeat parse failed: {e}"));
        },
    };

    // Validate schema.
    if heartbeat.schema != HEARTBEAT_SCHEMA {
        return HeartbeatStatus::read_error(format!(
            "heartbeat schema mismatch: expected {HEARTBEAT_SCHEMA}, got {}",
            heartbeat.schema
        ));
    }

    let now = current_epoch_secs();
    let age_secs = now.saturating_sub(heartbeat.timestamp_epoch_secs);
    let fresh = age_secs <= MAX_HEARTBEAT_AGE_SECS;

    HeartbeatStatus {
        found: true,
        fresh,
        pid: heartbeat.pid,
        age_secs,
        cycle_count: heartbeat.cycle_count,
        health_status: if fresh {
            heartbeat.health_status
        } else {
            "stale".to_string()
        },
        error: None,
    }
}

/// Internal error type to distinguish "not found" from other read errors.
#[derive(Debug)]
enum HeartbeatReadError {
    NotFound,
    Other(String),
}

/// Open the heartbeat file with `O_NOFOLLOW` and read up to
/// `MAX_HEARTBEAT_FILE_SIZE + 1` bytes. If the read returns more than
/// `MAX_HEARTBEAT_FILE_SIZE` bytes, the file is rejected as oversized.
///
/// This ensures:
/// 1. Symlinks are refused at the kernel level (Linux `O_NOFOLLOW`).
/// 2. No unbounded allocation — the buffer is fixed-size.
/// 3. Special files (devices, pipes) are rejected via `fstat`.
fn read_heartbeat_bounded(path: &std::path::Path) -> Result<Vec<u8>, HeartbeatReadError> {
    use std::io::Read;

    let file = open_heartbeat_nofollow(path)?;

    // Post-open metadata verification on the file handle (not the path).
    let metadata = file
        .metadata()
        .map_err(|e| HeartbeatReadError::Other(format!("heartbeat fstat failed: {e}")))?;

    if !metadata.is_file() {
        return Err(HeartbeatReadError::Other(
            "heartbeat path is not a regular file".to_string(),
        ));
    }

    // INV-WHB-001: Bounded read. Read up to MAX + 1 bytes. If we get
    // MAX + 1 bytes, the file is too large.
    let cap = MAX_HEARTBEAT_FILE_SIZE + 1;
    let file_len = usize::try_from(metadata.len()).unwrap_or(cap);
    let mut buf = Vec::with_capacity(std::cmp::min(file_len, cap));
    // Use Read::take to enforce the kernel-level read bound.
    let bytes_read = file
        .take(cap as u64)
        .read_to_end(&mut buf)
        .map_err(|e| HeartbeatReadError::Other(format!("heartbeat read failed: {e}")))?;

    if bytes_read > MAX_HEARTBEAT_FILE_SIZE {
        return Err(HeartbeatReadError::Other(format!(
            "heartbeat file too large: read {bytes_read} bytes > {MAX_HEARTBEAT_FILE_SIZE}",
        )));
    }

    Ok(buf)
}

/// Open a file with `O_NOFOLLOW | O_NONBLOCK` on Linux to prevent symlink
/// traversal and avoid blocking on FIFOs/pipes.
///
/// On non-Linux platforms, falls back to a `symlink_metadata` check before
/// open (best-effort TOCTOU mitigation).
fn open_heartbeat_nofollow(path: &std::path::Path) -> Result<std::fs::File, HeartbeatReadError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    HeartbeatReadError::NotFound
                } else if e.raw_os_error() == Some(libc::ELOOP) {
                    HeartbeatReadError::Other(
                        "heartbeat path is a symlink (O_NOFOLLOW refused)".to_string(),
                    )
                } else {
                    HeartbeatReadError::Other(format!("heartbeat open failed: {e}"))
                }
            })
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Best-effort symlink check on non-Linux platforms.
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(HeartbeatReadError::Other(
                        "heartbeat path is a symlink".to_string(),
                    ));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(HeartbeatReadError::NotFound);
            },
            Err(e) => {
                return Err(HeartbeatReadError::Other(format!(
                    "heartbeat symlink_metadata failed: {e}"
                )));
            },
        }
        std::fs::File::open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                HeartbeatReadError::NotFound
            } else {
                HeartbeatReadError::Other(format!("heartbeat open failed: {e}"))
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// CTR-2501 deviation: Uses `SystemTime` for epoch timestamps (wall-clock
/// anchored). This is intentional for cross-process heartbeat age
/// calculation — both writer (worker) and reader (CLI) must agree on a
/// shared time reference, which requires wall-clock time.
#[allow(clippy::disallowed_methods)]
fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let status = read_heartbeat(tmp.path());
        assert!(!status.found);
        assert!(!status.fresh);
        assert!(status.error.is_some());
    }

    #[test]
    fn test_heartbeat_write_and_read() {
        let tmp = tempfile::tempdir().unwrap();
        write_heartbeat(tmp.path(), 5, 3, 1, 0, "healthy").unwrap();

        let status = read_heartbeat(tmp.path());
        assert!(status.found);
        assert!(status.fresh);
        assert_eq!(status.cycle_count, 5);
        assert_eq!(status.health_status, "healthy");
        assert!(status.error.is_none());
        assert!(status.pid > 0);
    }

    #[test]
    fn test_heartbeat_stale_detection() {
        let tmp = tempfile::tempdir().unwrap();

        // Write a heartbeat with a very old timestamp.
        let heartbeat = WorkerHeartbeatV1 {
            schema: HEARTBEAT_SCHEMA.to_string(),
            pid: 1234,
            timestamp_epoch_secs: 1000, // Ancient timestamp.
            cycle_count: 1,
            jobs_completed: 0,
            jobs_denied: 0,
            jobs_quarantined: 0,
            health_status: "healthy".to_string(),
        };
        let json = serde_json::to_vec_pretty(&heartbeat).unwrap();
        let path = tmp.path().join(HEARTBEAT_FILENAME);
        std::fs::write(&path, &json).unwrap();

        let status = read_heartbeat(tmp.path());
        assert!(status.found);
        assert!(!status.fresh);
        assert_eq!(status.health_status, "stale");
    }

    #[test]
    fn test_heartbeat_schema_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let heartbeat = WorkerHeartbeatV1 {
            schema: "wrong.schema".to_string(),
            pid: 1234,
            timestamp_epoch_secs: current_epoch_secs(),
            cycle_count: 1,
            jobs_completed: 0,
            jobs_denied: 0,
            jobs_quarantined: 0,
            health_status: "healthy".to_string(),
        };
        let json = serde_json::to_vec_pretty(&heartbeat).unwrap();
        let path = tmp.path().join(HEARTBEAT_FILENAME);
        std::fs::write(&path, &json).unwrap();

        let status = read_heartbeat(tmp.path());
        assert!(!status.found);
        assert!(status.error.is_some());
        assert!(status.error.unwrap().contains("schema mismatch"));
    }

    #[test]
    fn test_heartbeat_oversized_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(HEARTBEAT_FILENAME);
        let data = vec![b'x'; MAX_HEARTBEAT_FILE_SIZE + 1];
        std::fs::write(&path, &data).unwrap();

        let status = read_heartbeat(tmp.path());
        assert!(!status.found);
        assert!(status.error.is_some());
        assert!(status.error.unwrap().contains("too large"));
    }

    /// INV-WHB-002: Symlinks are refused on Linux via `O_NOFOLLOW`.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_heartbeat_symlink_refused() {
        let tmp = tempfile::tempdir().unwrap();

        // Write a real heartbeat to a different name.
        let real_path = tmp.path().join("real_heartbeat.json");
        let heartbeat = WorkerHeartbeatV1 {
            schema: HEARTBEAT_SCHEMA.to_string(),
            pid: 1234,
            timestamp_epoch_secs: current_epoch_secs(),
            cycle_count: 1,
            jobs_completed: 0,
            jobs_denied: 0,
            jobs_quarantined: 0,
            health_status: "healthy".to_string(),
        };
        let json = serde_json::to_vec_pretty(&heartbeat).unwrap();
        std::fs::write(&real_path, &json).unwrap();

        // Create a symlink at the heartbeat filename pointing to the real file.
        let symlink_path = tmp.path().join(HEARTBEAT_FILENAME);
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        // read_heartbeat should refuse the symlink.
        let status = read_heartbeat(tmp.path());
        assert!(!status.found);
        assert!(status.error.is_some());
        let err = status.error.unwrap();
        assert!(
            err.contains("symlink") || err.contains("ELOOP") || err.contains("open failed"),
            "expected symlink refusal, got: {err}"
        );
    }

    /// INV-WHB-001: Bounded read rejects files at exactly MAX + 1 bytes
    /// without loading the entire file into memory first.
    #[test]
    fn test_heartbeat_bounded_read_rejects_at_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(HEARTBEAT_FILENAME);

        // Exactly at the boundary: MAX_HEARTBEAT_FILE_SIZE bytes should pass.
        let ok_data = vec![b'{'; MAX_HEARTBEAT_FILE_SIZE];
        std::fs::write(&path, &ok_data).unwrap();
        let result = read_heartbeat_bounded(&path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), MAX_HEARTBEAT_FILE_SIZE);

        // One byte over: should be rejected.
        let bad_data = vec![b'{'; MAX_HEARTBEAT_FILE_SIZE + 1];
        std::fs::write(&path, &bad_data).unwrap();
        let result = read_heartbeat_bounded(&path);
        assert!(result.is_err());
    }

    /// INV-WHB-002: Non-regular files (if somehow created) are rejected.
    #[cfg(unix)]
    #[test]
    fn test_heartbeat_fifo_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo_path = tmp.path().join(HEARTBEAT_FILENAME);

        // Create a FIFO at the heartbeat path.
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU).unwrap();

        let status = read_heartbeat(tmp.path());
        assert!(!status.found);
        assert!(status.error.is_some());
        let err = status.error.unwrap();
        assert!(
            err.contains("not a regular file") || err.contains("open failed"),
            "expected non-regular-file rejection, got: {err}"
        );
    }
}
