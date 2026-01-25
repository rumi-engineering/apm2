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
//! 1. Process alive check using `sysinfo` crate (cross-platform)
//! 2. Log file modification time (mtime) for activity detection
//!
//! A reviewer is considered:
//! - `Healthy`: Process alive AND log file mtime < 60s ago
//! - `Stale`: Process alive BUT log file mtime >= 60s ago
//! - `Dead`: Process not alive (killed, crashed, or PID reused by unrelated
//!   process)
//!
//! # Platform Support
//!
//! This module uses `sysinfo` crate for cross-platform process introspection.
//! Signal handling (SIGTERM, SIGKILL) is only available on Unix platforms.
//! On non-Unix platforms, process termination returns an error.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
#[cfg(unix)]
use nix::libc;
#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use sysinfo::{Pid as SysPid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tempfile::NamedTempFile;

/// Stale threshold in seconds.
///
/// A reviewer is considered stale if its log file has not been modified for
/// this many seconds. 300s (5 minutes) allows for AI tool startup, large PR
/// analysis, and network latency.
pub const STALE_THRESHOLD_SECS: u64 = 300;

/// Maximum number of restart attempts before giving up on a reviewer.
pub const MAX_RESTART_ATTEMPTS: u32 = 3;

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
#[serde(deny_unknown_fields)]
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
    /// Number of times this reviewer has been restarted.
    #[serde(default)]
    pub restart_count: u32,
}

impl ReviewerEntry {
    /// Check the health status of this reviewer.
    ///
    /// Checks:
    /// 1. Whether the process is still alive using `sysinfo` crate
    ///    (cross-platform)
    /// 2. Whether the PID is still our process (not reused) by checking the
    ///    command line via `sysinfo`
    /// 3. Whether the log file has recent activity (mtime < 60s ago)
    ///
    /// Returns:
    /// - `Dead` if process is not alive or PID was reused
    /// - `Stale` if process is alive but no recent activity
    /// - `Healthy` if process is alive and has recent activity
    pub fn check_health(&self) -> HealthStatus {
        // Validate PID is within safe range
        // sysinfo uses usize for PIDs, but we store as u32
        if self.pid == 0 {
            // PID must be positive
            return HealthStatus::Dead;
        }

        // Check for PID reuse by verifying cmdline contains expected process
        // This also serves as the process-alive check since it returns false
        // if the process doesn't exist
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
    /// Uses `sysinfo` crate for cross-platform process introspection.
    /// We check for:
    /// - "gemini" binary in the process name or command line (the AI tool)
    /// - "script" binary (the PTY wrapper we use)
    ///
    /// We specifically avoid matching editor processes like "vim script.rs"
    /// by checking if the cmdline starts with a known wrapper pattern.
    fn is_our_process(&self) -> bool {
        let pid = SysPid::from_u32(self.pid);
        let mut system = System::new();

        // Refresh only the specific process with command line info
        let refresh_kind = ProcessRefreshKind::new().with_cmd(UpdateKind::Always);
        system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), refresh_kind);

        let Some(process) = system.process(pid) else {
            // Process doesn't exist
            return false;
        };

        // Get command line arguments
        let cmd = process.cmd();
        if cmd.is_empty() {
            // No command line info available, check process name as fallback
            let name = process.name().to_string_lossy().to_lowercase();
            return name.contains("gemini") || name == "script";
        }

        // Join command line arguments for pattern matching
        let cmdline: String = cmd
            .iter()
            .map(|s| s.to_string_lossy().to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        // Get argv[0] for precise matching
        let argv0 = cmd
            .first()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // Check for our known patterns:
        // - Contains "gemini" (the AI tool binary or script)
        // - Equals "script" or ends with "/script" (the PTY wrapper)
        // - Contains "bash" or "sh" and subsequent args contain "gemini" (shell
        //   wrapper)
        let is_gemini_binary = argv0.contains("gemini");
        let is_script_binary = argv0 == "script" || argv0.ends_with("/script");
        let is_shell_wrapper =
            (argv0.contains("bash") || argv0.contains("sh")) && cmdline.contains("gemini");

        is_gemini_binary || is_script_binary || is_shell_wrapper
    }
}

/// State file containing all active reviewer entries.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Returns an error if:
    /// - The state file path cannot be determined
    /// - The file exists but cannot be read (permission denied, etc.)
    pub fn load() -> Result<Self> {
        let path = Self::path().context("Could not determine home directory")?;

        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // File doesn't exist - this is fine, just means no active reviewers
                return Ok(Self::default());
            },
            Err(e) => {
                // Other errors (permission denied, etc.) should fail closed
                return Err(e).context("Failed to read reviewer state file");
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
    /// Creates the parent directory (~/.apm2) with 0700 permissions if needed
    /// (Unix only). Uses `tempfile::NamedTempFile` for secure temporary file
    /// creation with automatic cleanup on panic.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The state file path cannot be determined
    /// - The parent directory cannot be created
    /// - The file cannot be written
    pub fn save(&self) -> Result<()> {
        let path = Self::path().context("Could not determine home directory")?;

        // Create parent directory with 0700 permissions (Unix only)
        let parent = path.parent().context("State file path has no parent")?;
        if !parent.exists() {
            fs::create_dir_all(parent).context("Failed to create ~/.apm2 directory")?;
            // Set directory permissions to 0700 (Unix only)
            #[cfg(unix)]
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .context("Failed to set ~/.apm2 directory permissions")?;
        }

        // Serialize to JSON
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize reviewer state")?;

        // Create temp file in the same directory as the target for atomic rename
        // NamedTempFile ensures cleanup on panic and uses unique random names
        let mut temp_file =
            NamedTempFile::new_in(parent).context("Failed to create temp state file")?;
        temp_file
            .write_all(content.as_bytes())
            .context("Failed to write temp state file")?;
        temp_file
            .as_file()
            .sync_all()
            .context("Failed to sync temp state file")?;

        // Persist and rename atomically
        temp_file
            .persist(&path)
            .context("Failed to persist temp state file")?;

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
///
/// # Platform Support
///
/// This function is only available on Unix platforms. On non-Unix platforms,
/// it always returns `false`.
#[cfg(unix)]
#[allow(clippy::cast_possible_truncation)]
pub fn kill_process(pid: u32) -> bool {
    // Validate PID is within safe range to prevent kill(-1) which would kill all
    // processes
    let Ok(pid_i32) = i32::try_from(pid) else {
        return false; // Invalid PID
    };
    if pid_i32 <= 0 {
        return false; // PID must be positive
    }
    let nix_pid = Pid::from_raw(pid_i32);

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

/// Kill a process (non-Unix stub).
///
/// # Platform Support
///
/// Process termination is not supported on non-Unix platforms.
/// This function always returns `false`.
#[cfg(not(unix))]
pub fn kill_process(_pid: u32) -> bool {
    // Process termination not supported on this platform
    false
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
///
/// # Platform Support
///
/// This function uses Unix-specific file locking (flock). On non-Unix
/// platforms, this function still creates the lock file but does not acquire an
/// exclusive lock (no-op for concurrency control).
#[cfg(unix)]
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

/// Acquire an exclusive file lock for remediation (non-Unix stub).
///
/// # Platform Support
///
/// On non-Unix platforms, this function creates the lock file but does not
/// acquire an exclusive lock. Concurrent remediation may occur.
#[cfg(not(unix))]
pub fn acquire_remediation_lock() -> Result<File> {
    let path = ReviewerStateFile::path()
        .context("Could not determine home directory")?
        .with_extension("lock");

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).context("Failed to create ~/.apm2 directory")?;
            // Note: Setting 0700 permissions is Unix-specific and skipped here
        }
    }

    let file = File::create(&path).context("Failed to create lock file")?;

    // Note: File locking is not implemented for non-Unix platforms
    // Concurrent remediation may occur
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
            restart_count: 0,
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
            restart_count: 0,
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
                restart_count: 0,
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
                restart_count: 0,
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
            restart_count: 0,
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
            restart_count: 0,
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
            restart_count: 0,
        };

        let elapsed = entry.get_log_mtime_elapsed();
        assert!(elapsed.is_some());
        // File was just created, so elapsed should be very small
        assert!(elapsed.unwrap() < 5);
    }

    #[test]
    fn test_check_health_max_pid_returns_dead() {
        // u32::MAX would become -1 when cast to i32, which would kill all processes
        // This test verifies we handle this safely
        let entry = ReviewerEntry {
            pid: u32::MAX,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/test.log"),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
        };

        // Should return Dead without attempting to signal PID -1
        assert_eq!(entry.check_health(), HealthStatus::Dead);
    }

    #[test]
    #[cfg(unix)]
    fn test_kill_process_max_pid_returns_false() {
        // u32::MAX would become -1 when cast to i32, which would kill all processes
        // This test verifies we handle this safely
        let result = kill_process(u32::MAX);
        // Should return false without attempting to signal PID -1
        assert!(!result);
    }

    #[test]
    #[cfg(unix)]
    fn test_kill_process_zero_pid_returns_false() {
        // PID 0 is special (process group) and should not be signaled
        let result = kill_process(0);
        assert!(!result);
    }

    #[test]
    #[cfg(not(unix))]
    fn test_kill_process_returns_false_on_non_unix() {
        // On non-Unix platforms, kill_process always returns false
        assert!(!kill_process(12345));
        assert!(!kill_process(0));
        assert!(!kill_process(u32::MAX));
    }

    /// Test that process checking works for the current process.
    ///
    /// This test verifies that the cross-platform sysinfo API can correctly
    /// detect and inspect the current process. Note that the current test
    /// process is not a "gemini" or "script" process, so `is_our_process()`
    /// should return false for it. This test verifies the sysinfo API works.
    #[test]
    fn test_process_check_current_process_exists() {
        // Get the current process's PID
        let current_pid = std::process::id();

        // Verify we can inspect the current process using sysinfo
        let pid = SysPid::from_u32(current_pid);
        let mut system = System::new();
        let refresh_kind = ProcessRefreshKind::new().with_cmd(UpdateKind::Always);
        system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), refresh_kind);

        // The current process should exist
        let process = system.process(pid);
        assert!(
            process.is_some(),
            "Current process (PID {current_pid}) should exist"
        );

        // We should be able to get the process name
        let process = process.unwrap();
        let name = process.name();
        assert!(
            !name.is_empty(),
            "Process name should not be empty for current process"
        );
    }

    /// Test that a non-existent PID returns None from sysinfo.
    #[test]
    fn test_process_check_nonexistent_pid() {
        // Use a very high PID that is unlikely to exist
        let pid = SysPid::from_u32(999_999_999);
        let mut system = System::new();
        let refresh_kind = ProcessRefreshKind::new().with_cmd(UpdateKind::Always);
        system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), refresh_kind);

        // Should return None for non-existent process
        let process = system.process(pid);
        assert!(process.is_none(), "Non-existent PID should return None");
    }

    /// Test the `is_our_process` detection for a non-reviewer process.
    ///
    /// The current test process is not a "gemini" or "script" process,
    /// so `is_our_process` should return false.
    #[test]
    fn test_is_our_process_returns_false_for_non_reviewer() {
        let current_pid = std::process::id();

        let entry = ReviewerEntry {
            pid: current_pid,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/test.log"),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
        };

        // The current process is a test process, not gemini/script
        // So is_our_process should return false
        assert!(
            !entry.is_our_process(),
            "Test process should not be detected as a reviewer process"
        );
    }

    /// Test that `check_health` returns Dead for a process that exists but is
    /// not ours.
    #[test]
    fn test_check_health_returns_dead_for_non_reviewer_process() {
        let current_pid = std::process::id();

        let entry = ReviewerEntry {
            pid: current_pid,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/nonexistent.log"),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
        };

        // Even though the process exists, it's not a reviewer process
        // So check_health should return Dead (PID reuse detection)
        assert_eq!(
            entry.check_health(),
            HealthStatus::Dead,
            "Process that exists but is not a reviewer should be treated as Dead"
        );
    }

    /// Test that `check_health` returns Dead for PID 0.
    #[test]
    fn test_check_health_zero_pid_returns_dead() {
        let entry = ReviewerEntry {
            pid: 0,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/test.log"),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
        };

        // PID 0 is invalid and should return Dead
        assert_eq!(entry.check_health(), HealthStatus::Dead);
    }
}
