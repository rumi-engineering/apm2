// AGENT-AUTHORED (TCK-00600)
//! Broker health IPC endpoint: file-based health + version + readiness status.
//!
//! The daemon writes a JSON health status file after each main-loop tick.
//! `apm2 fac services status` reads this file to determine broker health
//! beyond what systemd unit state alone reveals (e.g., a daemon that is
//! `active (running)` but has failed internal health checks).
//!
//! # File Format
//!
//! ```json
//! {
//!   "schema": "apm2.fac_broker_health_ipc.v1",
//!   "version": "0.1.0",
//!   "ready": true,
//!   "pid": 12345,
//!   "timestamp_epoch_secs": 1707000000,
//!   "uptime_secs": 300,
//!   "health_status": "healthy",
//!   "reason": null
//! }
//! ```
//!
//! # Security Invariants
//!
//! - [INV-BHI-001] Health status files are bounded to
//!   `MAX_BROKER_HEALTH_FILE_SIZE` (4 KiB) when read, preventing OOM from
//!   crafted files.
//! - [INV-BHI-002] Health status file reads use bounded I/O with `O_NOFOLLOW`
//!   symlink refusal (Linux) per CTR-1603 and RS-31.
//! - [INV-BHI-003] Health status writes use atomic write (temp + rename) to
//!   prevent partial reads.
//! - [INV-BHI-004] Health status is not authoritative for admission or security
//!   decisions. It is an observability signal only. The authoritative broker
//!   health gate is in `broker_health.rs`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema identifier for broker health IPC files.
pub const BROKER_HEALTH_SCHEMA: &str = "apm2.fac_broker_health_ipc.v1";

/// Maximum broker health file size for bounded reads (4 KiB).
pub const MAX_BROKER_HEALTH_FILE_SIZE: usize = 4096;

/// Maximum age of a broker health status before it is considered stale (180
/// seconds).
///
/// Slightly longer than heartbeat staleness because the daemon loop may
/// have longer tick intervals during heavy work.
pub const MAX_BROKER_HEALTH_AGE_SECS: u64 = 180;

/// Broker health file name.
pub const BROKER_HEALTH_FILENAME: &str = "broker_health.json";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Broker health status written by the daemon after each main-loop tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerHealthIpcV1 {
    /// Schema identifier.
    pub schema: String,
    /// Daemon version string (from `env!("CARGO_PKG_VERSION")`).
    pub version: String,
    /// Whether the broker is ready to accept work.
    pub ready: bool,
    /// Daemon process ID.
    pub pid: u32,
    /// Epoch timestamp (seconds) when this status was written.
    pub timestamp_epoch_secs: u64,
    /// Daemon uptime in seconds (wall-clock).
    pub uptime_secs: u64,
    /// Health status: "healthy", "degraded", or "unhealthy".
    pub health_status: String,
    /// Optional reason for non-healthy status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Result of reading and evaluating a broker health IPC file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerHealthIpcStatus {
    /// Whether a broker health file was found.
    pub found: bool,
    /// Whether the status is fresh (not stale).
    pub fresh: bool,
    /// Whether the broker reports as ready.
    pub ready: bool,
    /// Daemon version string.
    pub version: String,
    /// Daemon PID from the status.
    pub pid: u32,
    /// Age of the status in seconds.
    pub age_secs: u64,
    /// Daemon uptime in seconds.
    pub uptime_secs: u64,
    /// Health status string.
    pub health_status: String,
    /// Error message if status could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BrokerHealthIpcStatus {
    /// Create a status indicating no broker health file found.
    #[must_use]
    pub fn not_found() -> Self {
        Self {
            found: false,
            fresh: false,
            ready: false,
            version: String::new(),
            pid: 0,
            age_secs: 0,
            uptime_secs: 0,
            health_status: "unknown".to_string(),
            error: Some("broker health file not found".to_string()),
        }
    }

    /// Create a status indicating a read error.
    #[must_use]
    pub fn read_error(msg: String) -> Self {
        Self {
            found: false,
            fresh: false,
            ready: false,
            version: String::new(),
            pid: 0,
            age_secs: 0,
            uptime_secs: 0,
            health_status: "unknown".to_string(),
            error: Some(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// Write API (used by daemon)
// ---------------------------------------------------------------------------

/// Write a broker health IPC file atomically.
///
/// The file is written to `<fac_root>/broker_health.json` using
/// atomic write (temp + rename) per INV-BHI-003.
///
/// # Errors
///
/// Returns an error string if the write fails.
pub fn write_broker_health(
    fac_root: &std::path::Path,
    version: &str,
    ready: bool,
    uptime_secs: u64,
    health_status: &str,
    reason: Option<&str>,
) -> Result<(), String> {
    let status = BrokerHealthIpcV1 {
        schema: BROKER_HEALTH_SCHEMA.to_string(),
        version: version.to_string(),
        ready,
        pid: std::process::id(),
        timestamp_epoch_secs: current_epoch_secs(),
        uptime_secs,
        health_status: health_status.to_string(),
        reason: reason.map(ToString::to_string),
    };

    let json = serde_json::to_vec_pretty(&status)
        .map_err(|e| format!("broker health serialization failed: {e}"))?;

    let health_path = fac_root.join(BROKER_HEALTH_FILENAME);
    let tmp_path = fac_root.join(format!(".{BROKER_HEALTH_FILENAME}.tmp"));
    std::fs::write(&tmp_path, &json).map_err(|e| format!("broker health tmp write failed: {e}"))?;
    std::fs::rename(&tmp_path, &health_path)
        .map_err(|e| format!("broker health rename failed: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Read API (used by `services status`)
// ---------------------------------------------------------------------------

/// Read and evaluate a broker health IPC file.
///
/// Returns a `BrokerHealthIpcStatus` with freshness evaluation. The status
/// is considered stale if older than `MAX_BROKER_HEALTH_AGE_SECS`.
///
/// # Security (INV-BHI-001, INV-BHI-002, CTR-1603)
///
/// - Opens the file with `O_NOFOLLOW` (Linux) to refuse symlinks.
/// - Verifies regular file via `fstat` on the opened handle.
/// - Reads into a bounded buffer of `MAX_BROKER_HEALTH_FILE_SIZE + 1` bytes.
#[must_use]
pub fn read_broker_health(fac_root: &std::path::Path) -> BrokerHealthIpcStatus {
    let health_path = fac_root.join(BROKER_HEALTH_FILENAME);

    let data = match read_broker_health_bounded(&health_path) {
        Ok(data) => data,
        Err(BrokerHealthReadError::NotFound) => return BrokerHealthIpcStatus::not_found(),
        Err(BrokerHealthReadError::Other(msg)) => return BrokerHealthIpcStatus::read_error(msg),
    };

    let status: BrokerHealthIpcV1 = match serde_json::from_slice(&data) {
        Ok(s) => s,
        Err(e) => {
            return BrokerHealthIpcStatus::read_error(format!("broker health parse failed: {e}"));
        },
    };

    if status.schema != BROKER_HEALTH_SCHEMA {
        return BrokerHealthIpcStatus::read_error(format!(
            "broker health schema mismatch: expected {BROKER_HEALTH_SCHEMA}, got {}",
            status.schema
        ));
    }

    let now = current_epoch_secs();
    let age_secs = now.saturating_sub(status.timestamp_epoch_secs);
    let fresh = age_secs <= MAX_BROKER_HEALTH_AGE_SECS;

    BrokerHealthIpcStatus {
        found: true,
        fresh,
        ready: status.ready && fresh,
        version: status.version,
        pid: status.pid,
        age_secs,
        uptime_secs: status.uptime_secs,
        health_status: if fresh {
            status.health_status
        } else {
            "stale".to_string()
        },
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Internal bounded read (mirrors worker_heartbeat pattern)
// ---------------------------------------------------------------------------

enum BrokerHealthReadError {
    NotFound,
    Other(String),
}

fn read_broker_health_bounded(path: &std::path::Path) -> Result<Vec<u8>, BrokerHealthReadError> {
    use std::io::Read;

    let file = open_nofollow(path)?;

    let metadata = file
        .metadata()
        .map_err(|e| BrokerHealthReadError::Other(format!("broker health fstat failed: {e}")))?;

    if !metadata.is_file() {
        return Err(BrokerHealthReadError::Other(
            "broker health path is not a regular file".to_string(),
        ));
    }

    let cap = MAX_BROKER_HEALTH_FILE_SIZE + 1;
    let file_len = usize::try_from(metadata.len()).unwrap_or(cap);
    let mut buf = Vec::with_capacity(std::cmp::min(file_len, cap));
    let bytes_read = file
        .take(cap as u64)
        .read_to_end(&mut buf)
        .map_err(|e| BrokerHealthReadError::Other(format!("broker health read failed: {e}")))?;

    if bytes_read > MAX_BROKER_HEALTH_FILE_SIZE {
        return Err(BrokerHealthReadError::Other(format!(
            "broker health file too large: read {bytes_read} bytes > {MAX_BROKER_HEALTH_FILE_SIZE}",
        )));
    }

    Ok(buf)
}

fn open_nofollow(path: &std::path::Path) -> Result<std::fs::File, BrokerHealthReadError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    BrokerHealthReadError::NotFound
                } else if e.raw_os_error() == Some(libc::ELOOP) {
                    BrokerHealthReadError::Other(
                        "broker health path is a symlink (O_NOFOLLOW refused)".to_string(),
                    )
                } else {
                    BrokerHealthReadError::Other(format!("broker health open failed: {e}"))
                }
            })
    }

    #[cfg(not(target_os = "linux"))]
    {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(BrokerHealthReadError::Other(
                        "broker health path is a symlink".to_string(),
                    ));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BrokerHealthReadError::NotFound);
            },
            Err(e) => {
                return Err(BrokerHealthReadError::Other(format!(
                    "broker health symlink_metadata failed: {e}"
                )));
            },
        }
        std::fs::File::open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BrokerHealthReadError::NotFound
            } else {
                BrokerHealthReadError::Other(format!("broker health open failed: {e}"))
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// CTR-2501 deviation: Uses `SystemTime` for epoch timestamps (wall-clock
/// anchored). Intentional for cross-process age calculation.
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
    fn test_broker_health_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let status = read_broker_health(tmp.path());
        assert!(!status.found);
        assert!(!status.fresh);
        assert!(!status.ready);
        assert!(status.error.is_some());
        assert!(status.error.unwrap().contains("not found"));
    }

    #[test]
    fn test_broker_health_write_and_read() {
        let tmp = tempfile::tempdir().unwrap();
        write_broker_health(tmp.path(), "0.1.0-test", true, 300, "healthy", None).unwrap();

        let status = read_broker_health(tmp.path());
        assert!(status.found);
        assert!(status.fresh);
        assert!(status.ready);
        assert_eq!(status.version, "0.1.0-test");
        assert_eq!(status.health_status, "healthy");
        assert!(status.error.is_none());
        assert!(status.pid > 0);
        assert_eq!(status.uptime_secs, 300);
    }

    #[test]
    fn test_broker_health_stale_detection() {
        let tmp = tempfile::tempdir().unwrap();
        let status_data = BrokerHealthIpcV1 {
            schema: BROKER_HEALTH_SCHEMA.to_string(),
            version: "0.1.0".to_string(),
            ready: true,
            pid: 1234,
            timestamp_epoch_secs: 1000, // Ancient timestamp.
            uptime_secs: 500,
            health_status: "healthy".to_string(),
            reason: None,
        };
        let json = serde_json::to_vec_pretty(&status_data).unwrap();
        let path = tmp.path().join(BROKER_HEALTH_FILENAME);
        std::fs::write(&path, &json).unwrap();

        let status = read_broker_health(tmp.path());
        assert!(status.found);
        assert!(!status.fresh);
        assert!(!status.ready); // Stale means not ready.
        assert_eq!(status.health_status, "stale");
    }

    #[test]
    fn test_broker_health_schema_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let status_data = BrokerHealthIpcV1 {
            schema: "wrong.schema".to_string(),
            version: "0.1.0".to_string(),
            ready: true,
            pid: 1234,
            timestamp_epoch_secs: current_epoch_secs(),
            uptime_secs: 100,
            health_status: "healthy".to_string(),
            reason: None,
        };
        let json = serde_json::to_vec_pretty(&status_data).unwrap();
        let path = tmp.path().join(BROKER_HEALTH_FILENAME);
        std::fs::write(&path, &json).unwrap();

        let status = read_broker_health(tmp.path());
        assert!(!status.found);
        assert!(status.error.is_some());
        assert!(status.error.unwrap().contains("schema mismatch"));
    }

    #[test]
    fn test_broker_health_oversized_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(BROKER_HEALTH_FILENAME);
        let data = vec![b'x'; MAX_BROKER_HEALTH_FILE_SIZE + 1];
        std::fs::write(&path, &data).unwrap();

        let status = read_broker_health(tmp.path());
        assert!(!status.found);
        assert!(status.error.is_some());
        assert!(status.error.unwrap().contains("too large"));
    }

    #[test]
    fn test_broker_health_degraded_with_reason() {
        let tmp = tempfile::tempdir().unwrap();
        write_broker_health(
            tmp.path(),
            "0.1.0",
            false,
            60,
            "degraded",
            Some("health check failed: TP001 envelope expired"),
        )
        .unwrap();

        let status = read_broker_health(tmp.path());
        assert!(status.found);
        assert!(status.fresh);
        assert!(!status.ready);
        assert_eq!(status.health_status, "degraded");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_broker_health_symlink_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let real_path = tmp.path().join("real_health.json");
        write_broker_health(tmp.path(), "0.1.0", true, 100, "healthy", None).unwrap();
        std::fs::rename(tmp.path().join(BROKER_HEALTH_FILENAME), &real_path).unwrap();

        // Create symlink at the expected path.
        let symlink_path = tmp.path().join(BROKER_HEALTH_FILENAME);
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        let status = read_broker_health(tmp.path());
        assert!(!status.found);
        assert!(status.error.is_some());
        let err = status.error.unwrap();
        assert!(
            err.contains("symlink") || err.contains("open failed"),
            "expected symlink refusal, got: {err}"
        );
    }
}
