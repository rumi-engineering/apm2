//! Reviewer agent health monitoring state management.
//!
//! This module provides state tracking for AI reviewer agents (Gemini
//! processes) spawned during `cargo xtask push` and `cargo xtask review`. It
//! enables the `cargo xtask check` command to monitor agent health and
//! auto-remediate stale or dead agents.
//!
//! # State File
//!
//! State is persisted in `~/.apm2/reviewer_state.json` using atomic writes
//! (temp file + rename) to prevent corruption. The file contains a JSON object
//! with reviewer entries keyed by review type (e.g., "security", "quality").
//!
//! # Health Detection
//!
//! Health is determined by two factors:
//! 1. Process alive check using `kill(pid, None)` (signal 0)
//! 2. Log file modification time (mtime) for activity detection
//!
//! A reviewer is considered:
//! - `Healthy`: Process alive AND log file mtime < 60s ago
//! - `Stale`: Process alive BUT log file mtime >= 60s ago
//! - `Dead`: Process not alive (killed, crashed, or PID reused by unrelated
//!   process)

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use nix::libc;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

/// Stale threshold in seconds. A reviewer is considered stale if its log file
/// has not been modified for this many seconds.
pub const STALE_THRESHOLD_SECS: u64 = 60;

/// Timeout for SIGTERM before escalating to SIGKILL.
pub const SIGTERM_TIMEOUT_SECS: u64 = 5;

/// Poll interval when waiting for process to exit after SIGTERM.
pub const POLL_INTERVAL_MS: u64 = 100;

/// Health status of a reviewer agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Process is alive and has recent activity (log file mtime < 60s ago).
    Healthy,
    /// Process is alive but no recent activity (log file mtime >= 60s ago).
    Stale,
    /// Process is not alive or PID was reused by an unrelated process.
    Dead,
}

impl HealthStatus {
    /// Returns the display string for this health status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Stale => "STALE",
            Self::Dead => "DEAD",
        }
    }
}

/// Entry for a single reviewer agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewerEntry {
    /// Process ID of the reviewer agent.
    pub pid: u32,
    /// Timestamp when the reviewer was started.
    pub started_at: DateTime<Utc>,
    /// Path to the log file capturing the reviewer's output.
    pub log_file: PathBuf,
    /// The PR URL being reviewed.
    pub pr_url: String,
    /// The HEAD SHA being reviewed.
    pub head_sha: String,
}

impl ReviewerEntry {
    /// Check the health status of this reviewer.
    ///
    /// Checks:
    /// 1. Whether the process is still alive using `kill(pid, None)`
    /// 2. Whether the PID is still our process (not reused) by checking
    ///    `/proc/<pid>/cmdline` 3. Whether the log file has recent activity
    ///    (mtime < 60s ago)
    ///
    /// Returns:
    /// - `Dead` if process is not alive or PID was reused
    /// - `Stale` if process is alive but no recent activity
    /// - `Healthy` if process is alive and has recent activity
    #[allow(clippy::cast_possible_wrap)]
    pub fn check_health(&self) -> HealthStatus {
        let pid = Pid::from_raw(self.pid as i32);

        // Check if process is alive using kill with signal 0
        let process_alive = kill(pid, None).is_ok();

        if !process_alive {
            return HealthStatus::Dead;
        }

        // Check for PID reuse by verifying cmdline contains expected process
        if !self.is_our_process() {
            return HealthStatus::Dead;
        }

        // Check log file mtime for activity
        // Both None (log file missing) and Some(_) with elapsed >= threshold are stale
        match self.get_log_mtime_elapsed() {
            Some(elapsed_secs) if elapsed_secs < STALE_THRESHOLD_SECS => HealthStatus::Healthy,
            // Log file doesn't exist, can't be read, or stale - treat as stale
            Some(_) | None => HealthStatus::Stale,
        }
    }

    /// Get the elapsed time in seconds since the log file was last modified.
    ///
    /// Returns `None` if the log file doesn't exist or can't be read.
    pub fn get_log_mtime_elapsed(&self) -> Option<u64> {
        let metadata = fs::metadata(&self.log_file).ok()?;
        let mtime = metadata.modified().ok()?;
        let elapsed = SystemTime::now().duration_since(mtime).ok()?;
        Some(elapsed.as_secs())
    }

    /// Check if the PID is still our process (not reused by an unrelated
    /// process).
    ///
    /// Checks `/proc/<pid>/cmdline` for "gemini" or "script" to verify
    /// the process is still our reviewer agent.
    fn is_our_process(&self) -> bool {
        let cmdline_path = format!("/proc/{}/cmdline", self.pid);
        let Ok(mut file) = File::open(&cmdline_path) else {
            return false;
        };

        let mut cmdline = String::new();
        if file.read_to_string(&mut cmdline).is_err() {
            return false;
        }

        // cmdline uses null bytes as separators
        let cmdline_lower = cmdline.to_lowercase();
        cmdline_lower.contains("gemini") || cmdline_lower.contains("script")
    }
}

/// State file containing all active reviewer entries.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ReviewerStateFile {
    /// Map from reviewer type (e.g., "security", "quality") to entry.
    pub reviewers: HashMap<String, ReviewerEntry>,
}

impl ReviewerStateFile {
    /// Get the path to the state file (`~/.apm2/reviewer_state.json`).
    ///
    /// Returns `None` if the home directory cannot be determined.
    pub fn path() -> Option<PathBuf> {
        directories::BaseDirs::new()
            .map(|dirs| dirs.home_dir().join(".apm2").join("reviewer_state.json"))
    }

    /// Load the state file from disk.
    ///
    /// Returns a default (empty) state if:
    /// - The file doesn't exist (not an error, just means no active reviewers)
    /// - The file is corrupt (logs a warning, deletes the file, returns
    ///   default)
    ///
    /// # Errors
    ///
    /// Returns an error only if the state file path cannot be determined.
    pub fn load() -> Result<Self> {
        let path = Self::path().context("Could not determine home directory")?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!(
                    "Warning: Failed to read reviewer state file: {e}. Starting with empty state."
                );
                return Ok(Self::default());
            },
        };

        match serde_json::from_str(&content) {
            Ok(state) => Ok(state),
            Err(e) => {
                eprintln!(
                    "Warning: Corrupt reviewer state file: {e}. Deleting and starting fresh."
                );
                // Delete the corrupt file
                let _ = fs::remove_file(&path);
                Ok(Self::default())
            },
        }
    }

    /// Save the state file to disk using atomic write (temp file + rename).
    ///
    /// Creates the parent directory (~/.apm2) with 0700 permissions if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The state file path cannot be determined
    /// - The parent directory cannot be created
    /// - The file cannot be written
    pub fn save(&self) -> Result<()> {
        let path = Self::path().context("Could not determine home directory")?;

        // Create parent directory with 0700 permissions
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).context("Failed to create ~/.apm2 directory")?;
                // Set directory permissions to 0700
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                    .context("Failed to set ~/.apm2 directory permissions")?;
            }
        }

        // Serialize to JSON
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize reviewer state")?;

        // Write to temp file first
        let temp_path = path.with_extension("json.tmp");
        let mut file = File::create(&temp_path).context("Failed to create temp state file")?;
        file.write_all(content.as_bytes())
            .context("Failed to write temp state file")?;
        file.sync_all().context("Failed to sync temp state file")?;

        // Atomic rename
        fs::rename(&temp_path, &path).context("Failed to rename temp state file")?;

        Ok(())
    }

    /// Add or update a reviewer entry.
    pub fn set_reviewer(&mut self, reviewer_type: &str, entry: ReviewerEntry) {
        self.reviewers.insert(reviewer_type.to_string(), entry);
    }

    /// Remove a reviewer entry.
    pub fn remove_reviewer(&mut self, reviewer_type: &str) {
        self.reviewers.remove(reviewer_type);
    }

    /// Get a reviewer entry by type.
    pub fn get_reviewer(&self, reviewer_type: &str) -> Option<&ReviewerEntry> {
        self.reviewers.get(reviewer_type)
    }
}

/// Kill a process with SIGTERM, wait up to 5s, then SIGKILL if needed.
///
/// # Arguments
///
/// * `pid` - The process ID to kill
///
/// # Returns
///
/// Returns `true` if the process was successfully killed, `false` otherwise.
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
pub fn kill_process(pid: u32) -> bool {
    let nix_pid = Pid::from_raw(pid as i32);

    // First, check if process is even alive
    if kill(nix_pid, None).is_err() {
        return true; // Already dead
    }

    // Send SIGTERM
    if kill(nix_pid, Signal::SIGTERM).is_err() {
        return true; // Failed to send signal, assume dead
    }

    // Poll for exit with 100ms intervals up to 5s
    // max_polls = 5000 / 100 = 50, which fits in u32
    let max_polls = (SIGTERM_TIMEOUT_SECS * 1000 / POLL_INTERVAL_MS) as u32;
    for _ in 0..max_polls {
        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
        if kill(nix_pid, None).is_err() {
            return true; // Process exited
        }
    }

    // Still alive after 5s, send SIGKILL
    let _ = kill(nix_pid, Signal::SIGKILL);

    // Brief wait to let SIGKILL take effect
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Check if finally dead
    kill(nix_pid, None).is_err()
}

/// Acquire an exclusive file lock for remediation.
///
/// Uses flock to prevent concurrent remediation attempts.
///
/// # Returns
///
/// Returns a file handle that holds the lock. The lock is released when
/// the handle is dropped.
///
/// # Safety
///
/// Uses unsafe `libc::flock` to acquire an exclusive file lock. This is safe
/// because:
/// - The file descriptor is obtained from a valid `File` object
/// - The flock flags (`LOCK_EX | LOCK_NB`) are valid constants
/// - The result is checked before returning
#[allow(unsafe_code)]
pub fn acquire_remediation_lock() -> Result<File> {
    use std::os::unix::io::AsRawFd;

    let path = ReviewerStateFile::path()
        .context("Could not determine home directory")?
        .with_extension("lock");

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).context("Failed to create ~/.apm2 directory")?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .context("Failed to set ~/.apm2 directory permissions")?;
        }
    }

    let file = File::create(&path).context("Failed to create lock file")?;

    // Try to acquire exclusive lock (non-blocking)
    // SAFETY: fd is a valid file descriptor from File::as_raw_fd(),
    // and LOCK_EX | LOCK_NB are valid flock flags.
    let fd = file.as_raw_fd();
    let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

    if result != 0 {
        anyhow::bail!("Another remediation is in progress");
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.as_str(), "HEALTHY");
        assert_eq!(HealthStatus::Stale.as_str(), "STALE");
        assert_eq!(HealthStatus::Dead.as_str(), "DEAD");
    }

    #[test]
    fn test_reviewer_state_file_path() {
        let path = ReviewerStateFile::path();
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.ends_with(".apm2/reviewer_state.json"));
    }

    #[test]
    fn test_reviewer_state_file_default() {
        let state = ReviewerStateFile::default();
        assert!(state.reviewers.is_empty());
    }

    #[test]
    fn test_reviewer_state_file_set_get_remove() {
        let mut state = ReviewerStateFile::default();

        let entry = ReviewerEntry {
            pid: 12345,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/test.log"),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
        };

        state.set_reviewer("security", entry);
        assert!(state.get_reviewer("security").is_some());
        assert_eq!(state.get_reviewer("security").unwrap().pid, 12345);

        state.remove_reviewer("security");
        assert!(state.get_reviewer("security").is_none());
    }

    #[test]
    fn test_reviewer_entry_serialization() {
        let entry = ReviewerEntry {
            pid: 12345,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/test.log"),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: ReviewerEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.pid, deserialized.pid);
        assert_eq!(entry.pr_url, deserialized.pr_url);
        assert_eq!(entry.head_sha, deserialized.head_sha);
    }

    #[test]
    fn test_reviewer_state_file_serialization() {
        let mut state = ReviewerStateFile::default();

        state.set_reviewer(
            "security",
            ReviewerEntry {
                pid: 12345,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/security.log"),
                pr_url: "https://github.com/owner/repo/pull/123".to_string(),
                head_sha: "abc123".to_string(),
            },
        );

        state.set_reviewer(
            "quality",
            ReviewerEntry {
                pid: 12346,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/quality.log"),
                pr_url: "https://github.com/owner/repo/pull/123".to_string(),
                head_sha: "abc123".to_string(),
            },
        );

        let json = serde_json::to_string_pretty(&state).unwrap();
        let deserialized: ReviewerStateFile = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.reviewers.len(), 2);
        assert!(deserialized.reviewers.contains_key("security"));
        assert!(deserialized.reviewers.contains_key("quality"));
    }

    #[test]
    fn test_load_missing_file() {
        // This test is tricky because it depends on the home directory
        // We can at least verify it doesn't panic
        let result = ReviewerStateFile::load();
        // Should succeed with either empty state or existing state
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_health_dead_process() {
        // Use PID 1 which exists but we can't signal, or a very high PID that
        // doesn't exist
        let entry = ReviewerEntry {
            pid: 999_999_999, // Very unlikely to exist
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/nonexistent.log"),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
        };

        assert_eq!(entry.check_health(), HealthStatus::Dead);
    }

    #[test]
    fn test_get_log_mtime_elapsed_missing_file() {
        let entry = ReviewerEntry {
            pid: 12345,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/definitely_does_not_exist_12345.log"),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
        };

        assert!(entry.get_log_mtime_elapsed().is_none());
    }

    #[test]
    fn test_get_log_mtime_elapsed_existing_file() {
        // Create a temp file
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let entry = ReviewerEntry {
            pid: 12345,
            started_at: Utc::now(),
            log_file: path,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
        };

        let elapsed = entry.get_log_mtime_elapsed();
        assert!(elapsed.is_some());
        // File was just created, so elapsed should be very small
        assert!(elapsed.unwrap() < 5);
    }
}
