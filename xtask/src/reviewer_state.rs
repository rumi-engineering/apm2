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
//!
//! # Reviewer Spawning
//!
//! The [`ReviewerSpawner`] struct provides centralized spawn logic for all
//! reviewer invocations. It handles:
//! - Prompt variable interpolation (`$PR_URL`, `$HEAD_SHA`)
//! - Secure temp file creation for prompts and logs
//! - Script command construction with proper shell escaping
//! - State persistence to the state file
//! - Process spawning (background or synchronous)

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
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
    /// Path to the prompt file used for this review.
    #[serde(default)]
    pub prompt_file: Option<PathBuf>,
    /// The PR URL being reviewed.
    pub pr_url: String,
    /// The HEAD SHA being reviewed.
    pub head_sha: String,
    /// Number of times this reviewer has been restarted.
    #[serde(default)]
    pub restart_count: u32,
    /// Temporary files created for this review (for cleanup tracking).
    #[serde(default)]
    pub temp_files: Vec<PathBuf>,
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

    /// Clean up orphaned temp files from dead reviewers older than the
    /// threshold.
    ///
    /// This function removes temp files for reviewers that:
    /// 1. Have a `Dead` health status (process is no longer running)
    /// 2. Were started more than `age_threshold_secs` ago
    ///
    /// After cleanup, the dead entries are also removed from the state file.
    ///
    /// # Arguments
    ///
    /// * `age_threshold_secs` - Only clean up entries older than this many
    ///   seconds
    ///
    /// # Returns
    ///
    /// Returns a `Vec` of paths that were successfully cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file cannot be saved.
    pub fn cleanup_orphaned_temp_files(&mut self, age_threshold_secs: u64) -> Result<Vec<PathBuf>> {
        let mut cleaned = Vec::new();
        let now = Utc::now();
        let threshold =
            chrono::Duration::seconds(i64::try_from(age_threshold_secs).unwrap_or(i64::MAX));

        // Collect entries to clean up (dead and old enough)
        let entries_to_cleanup: Vec<(String, Vec<PathBuf>)> = self
            .reviewers
            .iter()
            .filter_map(|(name, entry)| {
                // Skip if reviewer is still alive
                if entry.check_health() != HealthStatus::Dead {
                    return None;
                }

                // Skip if not old enough
                let age = now.signed_duration_since(entry.started_at);
                if age < threshold {
                    return None;
                }

                // Collect all temp files to clean up
                let mut files = entry.temp_files.clone();
                // Also include log_file and prompt_file
                files.push(entry.log_file.clone());
                if let Some(prompt) = &entry.prompt_file {
                    files.push(prompt.clone());
                }

                Some((name.clone(), files))
            })
            .collect();

        // Clean up files and remove entries
        for (name, files) in &entries_to_cleanup {
            for path in files {
                if path.exists() && std::fs::remove_file(path).is_ok() {
                    cleaned.push(path.clone());
                }
            }
            self.reviewers.remove(name);
        }

        // Save the updated state
        if !entries_to_cleanup.is_empty() {
            self.save()?;
        }

        Ok(cleaned)
    }
}

/// Result of a reviewer spawn operation.
#[derive(Debug)]
pub struct SpawnResult {
    /// The reviewer entry that was created.
    pub entry: ReviewerEntry,
    /// The child process (if spawned in background mode).
    /// For synchronous mode, this is `None` since we wait for completion.
    pub child: Option<Child>,
}

/// Result of a synchronous reviewer execution.
#[derive(Debug)]
pub struct SyncResult {
    /// The exit status of the reviewer process.
    pub status: ExitStatus,
    /// Path to the log file (cleaned up automatically if successful).
    pub log_path: PathBuf,
}

/// Centralized reviewer spawning logic.
///
/// This struct encapsulates all the logic for spawning AI reviewer processes,
/// eliminating code duplication across `push.rs`, `check.rs`, and `review.rs`.
///
/// # Usage
///
/// ```ignore
/// use xtask::reviewer_state::ReviewerSpawner;
///
/// // For background spawning (push.rs, check.rs restart)
/// let spawner = ReviewerSpawner::new("security", pr_url, head_sha)
///     .with_prompt_content(&prompt_content);
/// let result = spawner.spawn_background()?;
///
/// // For synchronous execution (review.rs)
/// let spawner = ReviewerSpawner::new("quality", pr_url, head_sha)
///     .with_prompt_content(&prompt_content);
/// let result = spawner.spawn_sync()?;
/// ```
///
/// # Spawn Lifecycle
///
/// 1. Create temp file for prompt content (secure, 0600 permissions)
/// 2. Create temp file for log capture (for mtime-based health monitoring)
/// 3. Construct script command using `shell_escape` utilities
/// 4. Spawn process via `Command::new("sh")`
/// 5. Record entry in `ReviewerStateFile`
/// 6. Return child PID for tracking
pub struct ReviewerSpawner<'a> {
    /// The type of reviewer (e.g., "security", "quality").
    review_type: &'a str,
    /// The PR URL being reviewed.
    pr_url: &'a str,
    /// The HEAD SHA being reviewed.
    head_sha: &'a str,
    /// The prompt content (already interpolated with variables).
    prompt_content: Option<String>,
    /// The AI model to use (e.g., "gemini-3-flash-preview").
    model: Option<String>,
    /// Number of times this reviewer has been restarted (for remediation).
    restart_count: u32,
}

impl<'a> ReviewerSpawner<'a> {
    /// Create a new `ReviewerSpawner`.
    ///
    /// # Arguments
    ///
    /// * `review_type` - The type of reviewer (e.g., "security", "quality")
    /// * `pr_url` - The PR URL being reviewed
    /// * `head_sha` - The HEAD SHA being reviewed
    #[must_use]
    pub const fn new(review_type: &'a str, pr_url: &'a str, head_sha: &'a str) -> Self {
        Self {
            review_type,
            pr_url,
            head_sha,
            prompt_content: None,
            model: None,
            restart_count: 0,
        }
    }

    /// Set the prompt content (already interpolated).
    ///
    /// The prompt should have `$PR_URL` and `$HEAD_SHA` already substituted.
    #[must_use]
    pub fn with_prompt_content(mut self, content: &str) -> Self {
        self.prompt_content = Some(content.to_string());
        self
    }

    /// Set the AI model to use.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Load and interpolate prompt from a file path.
    ///
    /// Reads the prompt file and substitutes `$PR_URL` and `$HEAD_SHA`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn with_prompt_file(mut self, path: &Path) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read prompt file: {}", path.display()))?;

        let interpolated = content
            .replace("$PR_URL", self.pr_url)
            .replace("$HEAD_SHA", self.head_sha);

        self.prompt_content = Some(interpolated);
        Ok(self)
    }

    /// Set the restart count (for remediation restarts).
    #[must_use]
    pub const fn with_restart_count(mut self, count: u32) -> Self {
        self.restart_count = count;
        self
    }

    /// Spawn the reviewer in the background.
    ///
    /// This method:
    /// 1. Creates secure temp files for prompt and log
    /// 2. Constructs the script command with proper shell escaping
    /// 3. Spawns the process asynchronously
    /// 4. Records the entry in the state file
    ///
    /// The prompt temp file is cleaned up after execution via the command
    /// itself. The log file remains for health monitoring and is cleaned up
    /// by the check command when the reviewer completes.
    ///
    /// # Returns
    ///
    /// Returns `Some(SpawnResult)` on success, or `None` if spawning fails.
    ///
    /// # Errors
    ///
    /// Returns `None` if:
    /// - No prompt content was set
    /// - Temp file creation fails
    /// - Process spawning fails
    pub fn spawn_background(self) -> Option<SpawnResult> {
        let prompt = self.prompt_content.as_ref()?;

        // Create log file for output capture (mtime tracking)
        let log_file = tempfile::Builder::new()
            .prefix(&format!("apm2_review_{}_", self.review_type))
            .suffix(".log")
            .tempfile()
            .ok()?;

        // Keep the log file (don't delete on drop) - cleanup happens on completion
        let (_, log_path) = log_file.keep().ok()?;

        // Create prompt temp file
        let mut prompt_temp = NamedTempFile::new().ok()?;
        prompt_temp.write_all(prompt.as_bytes()).ok()?;

        // Persist the prompt file - cleanup happens via state tracking
        let (_, prompt_path) = prompt_temp.keep().ok()?;

        // Build the script command with cleanup
        let shell_cmd = crate::shell_escape::build_script_command_with_cleanup(
            &prompt_path,
            &log_path,
            self.model.as_deref(),
        );

        // Spawn the process
        let child = std::process::Command::new("sh")
            .args(["-c", &shell_cmd])
            .spawn()
            .ok()?;

        let pid = child.id();

        let entry = ReviewerEntry {
            pid,
            started_at: Utc::now(),
            log_file: log_path,
            prompt_file: Some(prompt_path),
            pr_url: self.pr_url.to_string(),
            head_sha: self.head_sha.to_string(),
            restart_count: self.restart_count,
            temp_files: Vec::new(),
        };

        // Save to state file
        let mut state = ReviewerStateFile::load().unwrap_or_default();
        state.set_reviewer(self.review_type, entry.clone());
        let _ = state.save();

        Some(SpawnResult {
            entry,
            child: Some(child),
        })
    }

    /// Spawn the reviewer synchronously and wait for completion.
    ///
    /// This method is used by `review.rs` for manual review invocation where
    /// we want to wait for the result.
    ///
    /// # Returns
    ///
    /// Returns `Ok(SyncResult)` with the exit status and log path.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No prompt content was set
    /// - Temp file creation fails
    /// - Process spawning or waiting fails
    pub fn spawn_sync(self) -> anyhow::Result<SyncResult> {
        let prompt = self
            .prompt_content
            .as_ref()
            .context("No prompt content set")?;

        // Create log file for output capture
        let log_file = tempfile::Builder::new()
            .prefix(&format!("apm2_review_{}_", self.review_type))
            .suffix(".log")
            .tempfile()
            .context("Failed to create log file")?;

        let (_, log_path) = log_file.keep().context("Failed to persist log file")?;

        // Create prompt temp file
        let mut prompt_temp = NamedTempFile::new().context("Failed to create prompt temp file")?;
        prompt_temp.write_all(prompt.as_bytes())?;
        let (_, prompt_temp_path) = prompt_temp
            .keep()
            .context("Failed to persist prompt file")?;

        // Record entry in state file before starting
        let entry = ReviewerEntry {
            pid: std::process::id(), // Use current process as placeholder
            started_at: Utc::now(),
            log_file: log_path.clone(),
            prompt_file: Some(prompt_temp_path.clone()),
            pr_url: self.pr_url.to_string(),
            head_sha: self.head_sha.to_string(),
            restart_count: self.restart_count,
            temp_files: Vec::new(),
        };

        let mut state = ReviewerStateFile::load().unwrap_or_default();
        state.set_reviewer(self.review_type, entry);
        let _ = state.save();

        // Build command with log capture (no cleanup - we handle it)
        let shell_cmd = crate::shell_escape::build_script_command(
            &prompt_temp_path,
            Some(&log_path),
            self.model.as_deref(),
        );

        // Run synchronously and wait
        let status = std::process::Command::new("sh")
            .args(["-c", &shell_cmd])
            .status()
            .context("Failed to run reviewer process")?;

        // Clean up: remove from state and temp files
        let mut state = ReviewerStateFile::load().unwrap_or_default();
        let _ = cleanup_reviewer_temp_files(&mut state, self.review_type);
        let _ = state.save();

        Ok(SyncResult { status, log_path })
    }
}

/// Clean up temp files associated with a reviewer entry.
///
/// This removes the log file, prompt file, and any tracked temp files.
/// It also removes the entry from the state file.
///
/// # Arguments
///
/// * `state` - The mutable state file reference
/// * `reviewer_type` - The key for the reviewer entry (e.g., "security",
///   "quality")
///
/// # Returns
///
/// Returns a `Vec` of paths that were successfully cleaned up.
pub fn cleanup_reviewer_temp_files(
    state: &mut ReviewerStateFile,
    reviewer_type: &str,
) -> Vec<PathBuf> {
    let mut cleaned = Vec::new();

    if let Some(entry) = state.get_reviewer(reviewer_type) {
        // Clean up all tracked temp files
        for path in &entry.temp_files {
            if path.exists() && std::fs::remove_file(path).is_ok() {
                cleaned.push(path.clone());
            }
        }

        // Clean up log file
        if entry.log_file.exists() && std::fs::remove_file(&entry.log_file).is_ok() {
            cleaned.push(entry.log_file.clone());
        }

        // Clean up prompt file
        if let Some(prompt) = &entry.prompt_file {
            if prompt.exists() && std::fs::remove_file(prompt).is_ok() {
                cleaned.push(prompt.clone());
            }
        }
    }

    // Remove the entry from state
    state.remove_reviewer(reviewer_type);

    cleaned
}

/// One hour in seconds, used as the default age threshold for orphan cleanup.
pub const ORPHAN_CLEANUP_AGE_THRESHOLD_SECS: u64 = 3600;
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
            prompt_file: Some(PathBuf::from("/tmp/test_prompt.txt")),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: Vec::new(),
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
            prompt_file: Some(PathBuf::from("/tmp/test_prompt.txt")),
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: vec![PathBuf::from("/tmp/extra.txt")],
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: ReviewerEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.pid, deserialized.pid);
        assert_eq!(entry.pr_url, deserialized.pr_url);
        assert_eq!(entry.head_sha, deserialized.head_sha);
        assert_eq!(entry.prompt_file, deserialized.prompt_file);
        assert_eq!(entry.temp_files, deserialized.temp_files);
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
                prompt_file: None,
                pr_url: "https://github.com/owner/repo/pull/123".to_string(),
                head_sha: "abc123".to_string(),
                restart_count: 0,
                temp_files: Vec::new(),
            },
        );

        state.set_reviewer(
            "quality",
            ReviewerEntry {
                pid: 12346,
                started_at: Utc::now(),
                log_file: PathBuf::from("/tmp/quality.log"),
                prompt_file: None,
                pr_url: "https://github.com/owner/repo/pull/123".to_string(),
                head_sha: "abc123".to_string(),
                restart_count: 0,
                temp_files: Vec::new(),
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
            prompt_file: None,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: Vec::new(),
        };

        assert_eq!(entry.check_health(), HealthStatus::Dead);
    }

    #[test]
    fn test_get_log_mtime_elapsed_missing_file() {
        let entry = ReviewerEntry {
            pid: 12345,
            started_at: Utc::now(),
            log_file: PathBuf::from("/tmp/definitely_does_not_exist_12345.log"),
            prompt_file: None,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: Vec::new(),
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
            prompt_file: None,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: Vec::new(),
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
            prompt_file: None,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: Vec::new(),
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
            prompt_file: None,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: Vec::new(),
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
            prompt_file: None,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: Vec::new(),
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
            prompt_file: None,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
            head_sha: "abc123".to_string(),
            restart_count: 0,
            temp_files: Vec::new(),
        };

        // PID 0 is invalid and should return Dead
        assert_eq!(entry.check_health(), HealthStatus::Dead);
    }

    /// Test cleanup of orphaned temp files.
    #[test]
    fn test_cleanup_orphaned_temp_files() {
        // Create temp files that we'll track
        let temp_log = tempfile::NamedTempFile::new().unwrap();
        let temp_prompt = tempfile::NamedTempFile::new().unwrap();
        let temp_extra = tempfile::NamedTempFile::new().unwrap();

        // Keep the files (don't auto-delete)
        let (_, log_path) = temp_log.keep().unwrap();
        let (_, prompt_path) = temp_prompt.keep().unwrap();
        let (_, extra_path) = temp_extra.keep().unwrap();

        // Create a state with a dead reviewer (non-existent PID, old enough)
        let mut state = ReviewerStateFile::default();
        state.set_reviewer(
            "security",
            ReviewerEntry {
                pid: 999_999_999,                                    // Very unlikely to exist
                started_at: Utc::now() - chrono::Duration::hours(2), // Old enough
                log_file: log_path.clone(),
                prompt_file: Some(prompt_path.clone()),
                pr_url: "https://github.com/owner/repo/pull/123".to_string(),
                head_sha: "abc123".to_string(),
                restart_count: 0,
                temp_files: vec![extra_path.clone()],
            },
        );

        // Verify files exist before cleanup
        assert!(log_path.exists());
        assert!(prompt_path.exists());
        assert!(extra_path.exists());

        // Run cleanup with 1 hour threshold
        let cleaned = state.cleanup_orphaned_temp_files(3600).unwrap();

        // Should have cleaned up 3 files
        assert_eq!(cleaned.len(), 3);
        assert!(!log_path.exists());
        assert!(!prompt_path.exists());
        assert!(!extra_path.exists());

        // Entry should be removed from state
        assert!(state.get_reviewer("security").is_none());
    }

    /// Test that cleanup does not remove files from healthy reviewers.
    #[test]
    fn test_cleanup_orphaned_temp_files_skips_alive() {
        // Create temp files
        let temp_log = tempfile::NamedTempFile::new().unwrap();
        let (_, log_path) = temp_log.keep().unwrap();

        // Create a state with a reviewer using current process PID
        // Note: This won't be considered "our process" but we're testing the
        // age threshold
        let mut state = ReviewerStateFile::default();
        state.set_reviewer(
            "security",
            ReviewerEntry {
                pid: 999_999_999,       // Dead process
                started_at: Utc::now(), // Not old enough (just started)
                log_file: log_path.clone(),
                prompt_file: None,
                pr_url: "https://github.com/owner/repo/pull/123".to_string(),
                head_sha: "abc123".to_string(),
                restart_count: 0,
                temp_files: Vec::new(),
            },
        );

        // Run cleanup with 1 hour threshold - entry is not old enough
        let cleaned = state.cleanup_orphaned_temp_files(3600).unwrap();

        // Should not have cleaned up anything (not old enough)
        assert!(cleaned.is_empty());
        assert!(log_path.exists());

        // Entry should still exist
        assert!(state.get_reviewer("security").is_some());

        // Clean up the file manually
        let _ = std::fs::remove_file(&log_path);
    }

    /// Test `cleanup_reviewer_temp_files` helper function.
    #[test]
    fn test_cleanup_reviewer_temp_files() {
        // Create temp files and persist them (keep() returns paths)
        let temp_log = tempfile::NamedTempFile::new().unwrap();
        let temp_prompt = tempfile::NamedTempFile::new().unwrap();

        let (_, log_path) = temp_log.keep().unwrap();
        let (_, prompt_path) = temp_prompt.keep().unwrap();

        let mut state = ReviewerStateFile::default();
        state.set_reviewer(
            "quality",
            ReviewerEntry {
                pid: 12345,
                started_at: Utc::now(),
                log_file: log_path.clone(),
                prompt_file: Some(prompt_path.clone()),
                pr_url: "https://github.com/owner/repo/pull/123".to_string(),
                head_sha: "abc123".to_string(),
                restart_count: 0,
                temp_files: Vec::new(),
            },
        );

        // Verify files exist
        assert!(log_path.exists());
        assert!(prompt_path.exists());

        // Clean up
        let cleaned = cleanup_reviewer_temp_files(&mut state, "quality");

        // Should have cleaned up 2 files
        assert_eq!(cleaned.len(), 2);
        assert!(!log_path.exists());
        assert!(!prompt_path.exists());

        // Entry should be removed
        assert!(state.get_reviewer("quality").is_none());
    }
}
