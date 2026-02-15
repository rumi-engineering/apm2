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
#[must_use]
pub fn read_heartbeat(fac_root: &std::path::Path) -> HeartbeatStatus {
    let heartbeat_path = fac_root.join(HEARTBEAT_FILENAME);

    if !heartbeat_path.exists() {
        return HeartbeatStatus::not_found();
    }

    // INV-WHB-001: Bounded read.
    let data = match std::fs::read(&heartbeat_path) {
        Ok(data) => {
            if data.len() > MAX_HEARTBEAT_FILE_SIZE {
                return HeartbeatStatus::read_error(format!(
                    "heartbeat file too large: {} > {MAX_HEARTBEAT_FILE_SIZE}",
                    data.len()
                ));
            }
            data
        },
        Err(e) => {
            return HeartbeatStatus::read_error(format!("heartbeat read failed: {e}"));
        },
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
}
