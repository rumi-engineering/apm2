// AGENT-AUTHORED (TCK-00515)
//! FAC execution lane management: lane directories, profiles, leases, and
//! status.
//!
//! This module implements the `FESv1` "execution lane" primitives defined in
//! RFC-0019 Amendment A1 (§4.2–§5.3.2). Lanes are the sole concurrency
//! primitive for FAC execution; each lane is a bounded, cullable execution
//! context with deterministic identity and a fixed resource profile.
//!
//! # Directory Layout
//!
//! ```text
//! $APM2_HOME/private/fac/lanes/<lane_id>/workspace/
//! $APM2_HOME/private/fac/lanes/<lane_id>/target/
//! $APM2_HOME/private/fac/lanes/<lane_id>/logs/
//! $APM2_HOME/private/fac/lanes/<lane_id>/profile.v1.json
//! $APM2_HOME/private/fac/lanes/<lane_id>/lease.v1.json
//! $APM2_HOME/private/fac/locks/lanes/<lane_id>.lock
//! ```
//!
//! # Security Model
//!
//! - Lock acquisition is atomic and exclusive via `flock(LOCK_EX | LOCK_NB)`.
//! - Lease records are persisted via atomic write (temp → rename).
//! - Stale lease detection uses PID liveness checks (fail-closed).
//! - Directories are created with mode 0o700 in operator mode and 0o770 in
//!   system-mode (CTR-2611).
//!
//! # Invariants
//!
//! - [INV-LANE-001] At most one job executes in a lane at a time.
//! - [INV-LANE-002] Lane profile hash is computed via BLAKE3 over canonical
//!   JSON.
//! - [INV-LANE-003] Lock acquisition uses file-lock pattern (RAII + jitter).
//! - [INV-LANE-004] Stale lease detection is fail-closed: ambiguous PID state →
//!   CORRUPT.
//! - [INV-LANE-005] All in-memory collections are bounded by hard MAX_*
//!   constants.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::execution_backend::{ExecutionBackend, select_backend};
use super::safe_rmtree::{MAX_LOG_DIR_ENTRIES, safe_rmtree_v1, safe_rmtree_v1_with_entry_limit};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Schema identifier for lane profile v1.
pub const LANE_PROFILE_V1_SCHEMA: &str = "apm2.fac.lane_profile.v1";

/// Schema identifier for lane lease v1.
pub const LANE_LEASE_V1_SCHEMA: &str = "apm2.fac.lane_lease.v1";

/// Schema identifier for lane init receipt v1 (TCK-00539).
pub const LANE_INIT_RECEIPT_SCHEMA: &str = "apm2.fac.lane_init_receipt.v1";

/// Schema identifier for lane reconcile receipt v1 (TCK-00539).
pub const LANE_RECONCILE_RECEIPT_SCHEMA: &str = "apm2.fac.lane_reconcile_receipt.v1";

/// Schema identifier for corrupt marker files.
pub const LANE_CORRUPT_MARKER_SCHEMA: &str = "apm2.fac.lane_corrupt.v1";

const CLEANUP_STEP_GIT_RESET: &str = "git_reset";
const CLEANUP_STEP_GIT_CLEAN: &str = "git_clean";
const CLEANUP_STEP_TEMP_PRUNE: &str = "temp_prune";
const CLEANUP_STEP_ENV_DIR_PRUNE: &str = "env_dir_prune";
const CLEANUP_STEP_LOG_QUOTA: &str = "log_quota";
const CLEANUP_STEP_WORKSPACE_VALIDATION: &str = "workspace_path_validation";

/// Maximum log directory size in bytes (100 MB).
///
/// Used by the legacy `enforce_log_quota` (test-only). Production cleanup
/// now uses `enforce_log_retention` with policy-derived `LogRetentionConfig`.
#[cfg(test)]
const MAX_LOG_QUOTA_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum number of collected log entries during quota enforcement.
const MAX_LOG_ENTRIES: usize = 10_000;

/// Maximum directory recursion depth while enforcing log quota.
#[cfg(test)]
const MAX_LOG_QUOTA_DIR_DEPTH: usize = 8;

/// Maximum number of directory entries read per directory during log quota
/// enforcement. Prevents directory-flood `DoS` where an attacker creates
/// millions of subdirectories. Matches INV-RMTREE-009 from `safe_rmtree_v1`.
#[cfg(test)]
const MAX_DIR_ENTRIES: usize = 10_000;

/// Default lane count when not configured via environment.
pub const DEFAULT_LANE_COUNT: usize = 3;

/// Maximum allowed lane count (prevents unbounded resource allocation).
pub const MAX_LANE_COUNT: usize = 32;

/// Maximum lane ID length.
pub const MAX_LANE_ID_LENGTH: usize = 64;

/// Maximum string field length in lane records.
pub const MAX_STRING_LENGTH: usize = 512;

/// Maximum lease file size to read (1 MiB, CTR-1603).
pub const MAX_LEASE_FILE_SIZE: u64 = 1024 * 1024;

/// Maximum profile file size to read (1 MiB, CTR-1603).
pub const MAX_PROFILE_FILE_SIZE: u64 = 1024 * 1024;

/// Maximum allowed test timeout in seconds for FAC execution paths.
pub const MAX_TEST_TIMEOUT_SECONDS: u64 = 600;

/// Maximum allowed memory cap in bytes for FAC execution paths (48 GiB).
pub const MAX_MEMORY_MAX_BYTES: u64 = 51_539_607_552;

/// Poll interval for lane lock acquisition.
pub const LANE_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Maximum jitter added to lock poll interval (milliseconds).
pub const LANE_LOCK_POLL_JITTER_MS: u64 = 100;

/// Maximum time to wait for lane lock acquisition before failing.
pub const LANE_LOCK_TIMEOUT: Duration = Duration::from_secs(120);

/// Environment variable for configuring lane count.
pub const LANE_COUNT_ENV_VAR: &str = "APM2_FAC_LANE_COUNT";

/// Lane ID prefix for generated lane IDs.
pub const LANE_ID_PREFIX: &str = "lane-";

/// Cleanup outcome for lane cleanup execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneCleanupOutcome {
    /// Cleanup completed successfully.
    Success,
    /// Cleanup failed and lane is marked corrupt.
    Failed,
}

/// Errors that can occur while executing lane cleanup.
#[derive(Debug, Error)]
pub enum LaneCleanupError {
    /// A git command failed to execute or returned a non-zero status.
    #[error("git command failed in workspace during {step}: {reason}")]
    GitCommandFailed {
        /// Name of the cleanup step that failed.
        step: &'static str,
        /// Human-readable failure detail.
        reason: String,
        /// Ordered list of completed steps before failure.
        steps_completed: Vec<String>,
        /// The step that caused the failure.
        failure_step: Option<String>,
    },

    /// Temporary directory prune failed.
    #[error("temp directory prune failed during {step}: {reason}")]
    TempPruneFailed {
        /// Name of the cleanup step that failed.
        step: &'static str,
        /// Human-readable failure detail.
        reason: String,
        /// Ordered list of completed steps before failure.
        steps_completed: Vec<String>,
        /// The step that caused the failure.
        failure_step: Option<String>,
    },

    /// Per-lane environment directory prune failed (TCK-00575).
    #[error("env directory prune failed during {step}: {reason}")]
    EnvDirPruneFailed {
        /// Name of the cleanup step that failed.
        step: &'static str,
        /// Human-readable failure detail.
        reason: String,
        /// Ordered list of completed steps before failure.
        steps_completed: Vec<String>,
        /// The step that caused the failure.
        failure_step: Option<String>,
    },

    /// Log quota enforcement failed.
    #[error("log quota enforcement failed during {step}: {reason}")]
    LogQuotaFailed {
        /// Name of the cleanup step that failed.
        step: &'static str,
        /// Human-readable failure detail.
        reason: String,
        /// Ordered list of completed steps before failure.
        steps_completed: Vec<String>,
        /// The step that caused the failure.
        failure_step: Option<String>,
    },

    /// Filesystem error while running cleanup.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Current lane state is invalid for cleanup.
    #[error("invalid cleanup state: {0}")]
    InvalidState(String),
}

impl LaneCleanupError {
    /// Failed step identifier for receipt emission.
    #[must_use]
    pub fn failure_step(&self) -> Option<&str> {
        match self {
            Self::GitCommandFailed { failure_step, .. }
            | Self::TempPruneFailed { failure_step, .. }
            | Self::EnvDirPruneFailed { failure_step, .. }
            | Self::LogQuotaFailed { failure_step, .. } => failure_step.as_deref(),
            Self::Io(_) | Self::InvalidState(_) => None,
        }
    }

    /// Completed steps before the failure (for receipt evidence).
    #[must_use]
    pub fn steps_completed(&self) -> &[String] {
        match self {
            Self::GitCommandFailed {
                steps_completed, ..
            }
            | Self::TempPruneFailed {
                steps_completed, ..
            }
            | Self::EnvDirPruneFailed {
                steps_completed, ..
            }
            | Self::LogQuotaFailed {
                steps_completed, ..
            } => steps_completed.as_slice(),
            Self::Io(_) | Self::InvalidState(_) => &[],
        }
    }
}

/// Build a `Command` for git with config isolation to prevent LPE via
/// malicious `.git/config` entries (e.g., `core.fsmonitor`, `core.pager`).
///
/// SEC-CTRL-LANE-CLEANUP-001: Git config isolation for lane cleanup.
///
/// A malicious job can modify `.git/config` in the workspace. When the worker
/// executes `git reset` or `git clean` during cleanup, configs like
/// `core.fsmonitor` can trigger arbitrary code execution with worker
/// privileges. This function isolates the git environment by:
///
/// 1. Setting `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_SYSTEM=/dev/null`
///    to prevent loading global/system config files.
/// 2. Passing `-c` overrides for dangerous config keys that could trigger
///    arbitrary code execution (`core.fsmonitor`, `core.pager`, `core.editor`).
/// 3. Setting `GIT_TERMINAL_PROMPT=0` to prevent interactive prompts.
///
/// The caller is responsible for appending the subcommand args (e.g.,
/// `["reset", "--hard", "HEAD"]`) and for adding `--no-optional-locks`
/// where appropriate.
fn build_isolated_git_command(workspace_path: &Path) -> Command {
    let mut cmd = Command::new("git");
    // Disable global and system config files to prevent loading attacker-
    // planted config from outside the workspace.
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    // Override dangerous config keys that can execute arbitrary commands.
    // These -c flags override any per-repo .git/config values.
    // --no-optional-locks is a top-level git flag that reduces surface area
    // by preventing git from taking optional locks (e.g., for gc).
    cmd.args([
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=",
        "-c",
        "core.pager=cat",
        "-c",
        "core.editor=:",
    ]);
    cmd.current_dir(workspace_path);
    cmd
}

/// Execute a lane cleanup run using only a FAC root path.
///
/// This is the canonical cleanup runner that performs state transitions.
///
/// Steps:
/// 1. `Running` -> `Cleanup`
/// 2. `git reset --hard HEAD`
/// 3. `git clean -ffdxq`
/// 4. prune `tmp/`
/// 5. enforce log quota
/// 6. `Cleanup` -> idle (remove lease) on success
///
/// On failure, the lease remains `Cleanup`; the worker is expected to persist
/// the corrupt marker as durable evidence of failed cleanup.
///
/// # Errors
///
/// Returns:
/// - `Err(LaneCleanupError::InvalidState)` if lane management context cannot be
///   constructed from `fac_root`.
/// - `Err(LaneCleanupError::Io)` on filesystem errors.
/// - Cleanup-step specific variants when `git`/`tmp` cleanup or log quota
///   enforcement fails.
pub fn run_lane_cleanup(
    lane_id: &str,
    fac_root: &Path,
    workspace_path: &Path,
) -> Result<LaneCleanupOutcome, LaneCleanupError> {
    let manager = LaneManager::new(fac_root.to_path_buf())
        .map_err(|e| LaneCleanupError::InvalidState(e.to_string()))?;
    manager.run_lane_cleanup(lane_id, workspace_path)?;
    Ok(LaneCleanupOutcome::Success)
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during lane operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LaneError {
    /// Failed to resolve APM2 home directory.
    #[error("cannot resolve APM2 home directory: {0}")]
    HomeResolution(String),

    /// I/O error during lane operations.
    #[error("lane I/O error: {context}: {source}")]
    Io {
        /// Description of what was being attempted.
        context: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// Lane lock acquisition timed out.
    #[error("lane lock acquisition timed out for lane {lane_id} after {elapsed_secs}s")]
    LockTimeout {
        /// Lane that could not be locked.
        lane_id: String,
        /// How long we waited.
        elapsed_secs: u64,
    },

    /// Lane lock acquisition failed with unexpected error.
    #[error("lane lock acquisition failed for lane {lane_id}: {source}")]
    LockFailed {
        /// Lane that could not be locked.
        lane_id: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Name of the field.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Invalid lane ID.
    #[error("invalid lane ID: {0}")]
    InvalidLaneId(String),

    /// Invalid lane count configuration.
    #[error("invalid lane count: {0}")]
    InvalidLaneCount(String),

    /// Lease record is corrupt or invalid.
    #[error("invalid lease record for lane {lane_id}: {reason}")]
    InvalidLease {
        /// Lane with invalid lease.
        lane_id: String,
        /// What is wrong.
        reason: String,
    },

    /// Lane is in a corrupt state.
    #[error("lane {lane_id} is corrupt: {reason}")]
    Corrupt {
        /// Corrupted lane.
        lane_id: String,
        /// Why it is corrupt.
        reason: String,
    },

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Lane profile hash computation failed.
    #[error("profile hash computation failed: {0}")]
    HashComputation(String),

    /// Invalid lane profile or lease record.
    #[error("invalid lane record for lane {lane_id}: {reason}")]
    InvalidRecord {
        /// Affected lane.
        lane_id: String,
        /// Why the record is invalid.
        reason: String,
    },

    /// Invalid digest format (expected `b3-256:<64 lowercase hex chars>`).
    #[error("invalid digest format for field {field}: {reason}")]
    InvalidDigestFormat {
        /// Name of the field containing the malformed digest.
        field: &'static str,
        /// What is wrong with the digest.
        reason: String,
    },
}

impl LaneError {
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane State
// ─────────────────────────────────────────────────────────────────────────────

/// State of an execution lane.
///
/// Lifecycle: `IDLE → LEASED → RUNNING → CLEANUP → IDLE`
/// Exceptional: `* → CORRUPT → RESET → IDLE`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LaneState {
    /// Lane is available for new jobs.
    Idle,
    /// Lane has been leased to a job but execution has not started.
    Leased,
    /// Lane is executing a job.
    Running,
    /// Lane is cleaning up after a job.
    Cleanup,
    /// Lane is in a corrupt state and requires reset.
    Corrupt,
}

impl fmt::Display for LaneState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "IDLE"),
            Self::Leased => write!(f, "LEASED"),
            Self::Running => write!(f, "RUNNING"),
            Self::Cleanup => write!(f, "CLEANUP"),
            Self::Corrupt => write!(f, "CORRUPT"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource Profile
// ─────────────────────────────────────────────────────────────────────────────

/// Resource limits for a lane (systemd/cgroup enforcement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProfile {
    /// CPU quota as percentage (e.g., 200 = 2 full cores).
    pub cpu_quota_percent: u32,
    /// Memory ceiling in bytes.
    pub memory_max_bytes: u64,
    /// Maximum number of PIDs/tasks.
    pub pids_max: u32,
    /// I/O weight (1-10000, default 100).
    pub io_weight: u32,
}

impl Default for ResourceProfile {
    fn default() -> Self {
        Self {
            cpu_quota_percent: 200,
            memory_max_bytes: 51_539_607_552, // 48 GiB
            pids_max: 1536,
            io_weight: 100,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane Timeouts
// ─────────────────────────────────────────────────────────────────────────────

/// Timeout configuration for a lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneTimeouts {
    /// Test gate timeout in seconds.
    pub test_timeout_seconds: u64,
    /// Maximum total job runtime in seconds.
    pub job_runtime_max_seconds: u64,
}

impl Default for LaneTimeouts {
    fn default() -> Self {
        Self {
            test_timeout_seconds: 600,
            job_runtime_max_seconds: 1800,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy knobs for a lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanePolicy {
    /// Hash of the FAC policy object (b3-256 hex).
    pub fac_policy_hash: String,
    /// Nextest profile to use.
    pub nextest_profile: String,
    /// Whether to deny ambient `CARGO_HOME`.
    pub deny_ambient_cargo_home: bool,
}

impl Default for LanePolicy {
    fn default() -> Self {
        Self {
            fac_policy_hash: String::new(),
            nextest_profile: "ci".to_string(),
            deny_ambient_cargo_home: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LaneProfileV1
// ─────────────────────────────────────────────────────────────────────────────

/// Lane profile v1: static configuration for a lane.
///
/// Stored at `$APM2_HOME/private/fac/lanes/<lane_id>/profile.v1.json`.
/// The profile hash is `b3-256(canonical_json(LaneProfileV1))`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneProfileV1 {
    /// Schema identifier (always `apm2.fac.lane_profile.v1`).
    pub schema: String,
    /// Lane identifier.
    pub lane_id: String,
    /// Node fingerprint (b3-256 hex).
    pub node_fingerprint: String,
    /// Boundary identifier for evaluation context routing.
    #[serde(default)]
    pub boundary_id: String,
    /// Resource limits.
    pub resource_profile: ResourceProfile,
    /// Timeout configuration.
    pub timeouts: LaneTimeouts,
    /// Policy knobs.
    pub policy: LanePolicy,
}

impl LaneProfileV1 {
    /// Create a new lane profile with defaults.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::StringTooLong` if `lane_id` exceeds
    /// `MAX_LANE_ID_LENGTH`, and `boundary_id` exceeds its allowed length.
    pub fn new(
        lane_id: &str,
        node_fingerprint: &str,
        boundary_id: &str,
    ) -> Result<Self, LaneError> {
        validate_lane_id(lane_id)?;
        validate_string_field("node_fingerprint", node_fingerprint, MAX_STRING_LENGTH)?;
        validate_boundary_id(lane_id, boundary_id)?;
        let profile = Self {
            schema: LANE_PROFILE_V1_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            node_fingerprint: node_fingerprint.to_string(),
            boundary_id: boundary_id.to_string(),
            resource_profile: ResourceProfile::default(),
            timeouts: LaneTimeouts::default(),
            policy: LanePolicy::default(),
        };
        profile.validate_fac_test_caps(false)?;
        Ok(profile)
    }

    /// Validate FAC default caps for test command construction.
    ///
    /// # Errors
    ///
    /// Returns [`LaneError::InvalidRecord`] if either timeout or memory cap
    /// exceeds FAC caps and `allow_unsafe` is false.
    pub fn validate_fac_test_caps(&self, allow_unsafe: bool) -> Result<(), LaneError> {
        if !allow_unsafe && self.timeouts.test_timeout_seconds > MAX_TEST_TIMEOUT_SECONDS {
            return Err(LaneError::InvalidRecord {
                lane_id: self.lane_id.clone(),
                reason: format!(
                    "test_timeout_seconds {} exceeds FAC cap {}",
                    self.timeouts.test_timeout_seconds, MAX_TEST_TIMEOUT_SECONDS
                ),
            });
        }

        if !allow_unsafe && self.resource_profile.memory_max_bytes > MAX_MEMORY_MAX_BYTES {
            return Err(LaneError::InvalidRecord {
                lane_id: self.lane_id.clone(),
                reason: format!(
                    "memory_max_bytes {} exceeds FAC cap {}",
                    self.resource_profile.memory_max_bytes, MAX_MEMORY_MAX_BYTES
                ),
            });
        }

        Ok(())
    }

    /// Compute the BLAKE3-256 hash of this profile (canonical JSON).
    ///
    /// Returns the hash as a `b3-256:<hex>` string.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Serialization` if JSON serialization fails.
    pub fn compute_hash(&self) -> Result<String, LaneError> {
        let json_bytes =
            serde_json::to_vec(self).map_err(|e| LaneError::Serialization(e.to_string()))?;

        // Domain-separated hash: schema_id || NUL || canonical_json_bytes
        let mut hasher = blake3::Hasher::new();
        hasher.update(LANE_PROFILE_V1_SCHEMA.as_bytes());
        hasher.update(b"\0");
        hasher.update(&json_bytes);
        let digest = hasher.finalize();
        Ok(format!("b3-256:{}", hex::encode(digest.as_bytes())))
    }

    /// Persist this profile to the lane directory.
    ///
    /// Uses atomic write (temp → rename) per CTR-2607.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors.
    /// Returns `LaneError::Serialization` if JSON serialization fails.
    pub fn persist(&self, lane_dir: &Path) -> Result<(), LaneError> {
        let profile_path = lane_dir.join("profile.v1.json");
        let json_bytes =
            serde_json::to_vec_pretty(self).map_err(|e| LaneError::Serialization(e.to_string()))?;
        atomic_write(&profile_path, &json_bytes)
    }

    /// Load a lane profile from the lane directory.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors.
    /// Returns `LaneError::Serialization` on parse errors.
    pub fn load(lane_dir: &Path) -> Result<Self, LaneError> {
        let profile_path = lane_dir.join("profile.v1.json");
        let bytes = bounded_read_file(&profile_path, MAX_PROFILE_FILE_SIZE)?;
        let mut profile: Self = serde_json::from_slice(&bytes).map_err(|e| {
            LaneError::Serialization(format!(
                "failed to parse profile at {}: {e}",
                profile_path.display()
            ))
        })?;
        let expected_lane_id = lane_dir_lane_id(lane_dir)?;
        if profile.boundary_id.is_empty() {
            profile.boundary_id = legacy_boundary_id_fallback(&profile.node_fingerprint);
        }
        if profile.schema != LANE_PROFILE_V1_SCHEMA {
            return Err(LaneError::InvalidRecord {
                lane_id: expected_lane_id.to_string(),
                reason: format!(
                    "schema mismatch: expected '{LANE_PROFILE_V1_SCHEMA}', got '{}'",
                    profile.schema
                ),
            });
        }
        if profile.lane_id != expected_lane_id {
            return Err(LaneError::InvalidRecord {
                lane_id: expected_lane_id.to_string(),
                reason: format!(
                    "lane_id mismatch: expected '{expected_lane_id}', got '{}'",
                    profile.lane_id
                ),
            });
        }
        validate_string_field(
            "node_fingerprint",
            &profile.node_fingerprint,
            MAX_STRING_LENGTH,
        )?;
        if profile.node_fingerprint.is_empty() {
            return Err(LaneError::InvalidRecord {
                lane_id: expected_lane_id.to_string(),
                reason: "node_fingerprint must not be empty".to_string(),
            });
        }
        validate_boundary_id(expected_lane_id, &profile.boundary_id)?;
        validate_lane_id(&profile.lane_id)?;
        profile.validate_fac_test_caps(false)?;
        Ok(profile)
    }
}

/// Resolve host-parallelism default for FAC test/build execution.
#[must_use]
pub fn resolve_host_test_parallelism() -> u32 {
    std::thread::available_parallelism()
        .ok()
        .and_then(|n| u32::try_from(n.get()).ok())
        .map_or(1, |n| n.max(1))
}

/// Build test environment variables from an explicit parallelism value.
#[must_use]
pub fn compute_test_env_for_parallelism(parallelism: u32) -> Vec<(String, String)> {
    let cpu_count = parallelism.max(1);
    vec![
        ("NEXTEST_TEST_THREADS".to_string(), cpu_count.to_string()),
        ("CARGO_BUILD_JOBS".to_string(), cpu_count.to_string()),
    ]
}

fn legacy_boundary_id_fallback(node_fingerprint: &str) -> String {
    if node_fingerprint.is_empty() {
        "unknown".to_string()
    } else {
        node_fingerprint.to_string()
    }
}

fn validate_boundary_id(lane_id: &str, boundary_id: &str) -> Result<(), LaneError> {
    if boundary_id.is_empty() {
        return Err(LaneError::InvalidRecord {
            lane_id: lane_id.to_string(),
            reason: "boundary_id must not be empty".to_string(),
        });
    }
    if !boundary_id.is_ascii() {
        return Err(LaneError::InvalidRecord {
            lane_id: lane_id.to_string(),
            reason: "boundary_id must be ASCII".to_string(),
        });
    }
    if boundary_id.len() > super::node_identity::MAX_BOUNDARY_ID_LENGTH {
        return Err(LaneError::InvalidRecord {
            lane_id: lane_id.to_string(),
            reason: format!(
                "boundary_id length {} exceeds max {}",
                boundary_id.len(),
                super::node_identity::MAX_BOUNDARY_ID_LENGTH
            ),
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// LaneLeaseV1
// ─────────────────────────────────────────────────────────────────────────────

/// Lane lease v1: durable record of lane occupancy.
///
/// Stored at `$APM2_HOME/private/fac/lanes/<lane_id>/lease.v1.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneLeaseV1 {
    /// Schema identifier (always `apm2.fac.lane_lease.v1`).
    pub schema: String,
    /// Lane identifier.
    pub lane_id: String,
    /// Job identifier occupying this lane.
    pub job_id: String,
    /// OS process ID of the job executor.
    pub pid: u32,
    /// Current lane state.
    pub state: LaneState,
    /// RFC3339 UTC timestamp when lease was acquired.
    pub started_at: String,
    /// Lane profile hash at lease time (b3-256 hex).
    pub lane_profile_hash: String,
    /// Toolchain fingerprint at lease time (b3-256 hex).
    pub toolchain_fingerprint: String,
}

impl LaneLeaseV1 {
    /// Create a new lease record.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::StringTooLong` if any field exceeds its limit.
    /// Returns `LaneError::InvalidLease` if `started_at` is not RFC3339.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        job_id: &str,
        pid: u32,
        state: LaneState,
        started_at: &str,
        lane_profile_hash: &str,
        toolchain_fingerprint: &str,
    ) -> Result<Self, LaneError> {
        validate_lane_id(lane_id)?;
        validate_string_field("job_id", job_id, MAX_STRING_LENGTH)?;
        validate_string_field("started_at", started_at, MAX_STRING_LENGTH)?;
        validate_string_field("lane_profile_hash", lane_profile_hash, MAX_STRING_LENGTH)?;
        validate_string_field(
            "toolchain_fingerprint",
            toolchain_fingerprint,
            MAX_STRING_LENGTH,
        )?;
        let normalized_started_at =
            Self::normalize_rfc3339_utc(started_at).ok_or_else(|| LaneError::InvalidLease {
                lane_id: lane_id.to_string(),
                reason: "started_at must be RFC3339".to_string(),
            })?;
        Ok(Self {
            schema: LANE_LEASE_V1_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            job_id: job_id.to_string(),
            pid,
            state,
            started_at: normalized_started_at,
            lane_profile_hash: lane_profile_hash.to_string(),
            toolchain_fingerprint: toolchain_fingerprint.to_string(),
        })
    }

    /// Return `started_at` normalized to canonical RFC3339 UTC (`...Z`).
    ///
    /// This accepts native RFC3339 values and legacy epoch-second strings.
    /// Returns `None` if the value is not parseable.
    #[must_use]
    pub fn started_at_rfc3339(&self) -> Option<String> {
        if let Some(normalized) = Self::normalize_rfc3339_utc(&self.started_at) {
            return Some(normalized);
        }
        let legacy_epoch_secs = Self::parse_legacy_epoch_secs(&self.started_at)?;
        Self::epoch_secs_to_rfc3339(legacy_epoch_secs)
    }

    /// Return `started_at` as epoch seconds.
    ///
    /// This accepts native RFC3339 values and legacy epoch-second strings.
    /// Returns `None` if the value is not parseable or is pre-epoch.
    #[must_use]
    pub fn started_at_epoch_secs(&self) -> Option<u64> {
        if let Some(parsed) = Self::parse_rfc3339_utc(&self.started_at) {
            return u64::try_from(parsed.timestamp()).ok();
        }
        Self::parse_legacy_epoch_secs(&self.started_at)
    }

    /// Compute lease age relative to `now_epoch_secs`.
    ///
    /// Returns `None` if `started_at` cannot be parsed or if `started_at` is
    /// in the future relative to `now_epoch_secs`.
    #[must_use]
    pub fn age_secs(&self, now_epoch_secs: u64) -> Option<u64> {
        let started_epoch_secs = self.started_at_epoch_secs()?;
        now_epoch_secs.checked_sub(started_epoch_secs)
    }

    fn parse_rfc3339_utc(started_at: &str) -> Option<chrono::DateTime<Utc>> {
        chrono::DateTime::parse_from_rfc3339(started_at)
            .ok()
            .map(|parsed| parsed.with_timezone(&Utc))
    }

    fn normalize_rfc3339_utc(started_at: &str) -> Option<String> {
        let parsed = Self::parse_rfc3339_utc(started_at)?;
        Some(parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    }

    fn parse_legacy_epoch_secs(started_at: &str) -> Option<u64> {
        let epoch_secs = started_at.parse::<u64>().ok()?;
        let epoch_i64 = i64::try_from(epoch_secs).ok()?;
        Utc.timestamp_opt(epoch_i64, 0).single().map(|_| epoch_secs)
    }

    fn epoch_secs_to_rfc3339(epoch_secs: u64) -> Option<String> {
        let epoch_i64 = i64::try_from(epoch_secs).ok()?;
        let parsed = Utc.timestamp_opt(epoch_i64, 0).single()?;
        Some(parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    }

    /// Persist this lease to the lane directory.
    ///
    /// Uses atomic write (temp → rename) per CTR-2607.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors.
    /// Returns `LaneError::Serialization` if JSON serialization fails.
    pub fn persist(&self, lane_dir: &Path) -> Result<(), LaneError> {
        let lease_path = lane_dir.join("lease.v1.json");
        let json_bytes =
            serde_json::to_vec_pretty(self).map_err(|e| LaneError::Serialization(e.to_string()))?;
        atomic_write(&lease_path, &json_bytes)
    }

    /// Load a lease record from the lane directory.
    ///
    /// Returns `None` if the lease file does not exist.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors (other than not-found).
    /// Returns `LaneError::Serialization` on parse errors.
    pub fn load(lane_dir: &Path) -> Result<Option<Self>, LaneError> {
        let lease_path = lane_dir.join("lease.v1.json");
        if !lease_path.exists() {
            return Ok(None);
        }
        let bytes = bounded_read_file(&lease_path, MAX_LEASE_FILE_SIZE)?;
        let lease: Self = serde_json::from_slice(&bytes).map_err(|e| {
            LaneError::Serialization(format!(
                "failed to parse lease at {}: {e}",
                lease_path.display()
            ))
        })?;
        let expected_lane_id = lane_dir_lane_id(lane_dir)?;
        if lease.schema != LANE_LEASE_V1_SCHEMA {
            return Err(LaneError::InvalidRecord {
                lane_id: expected_lane_id.to_string(),
                reason: format!(
                    "schema mismatch: expected '{LANE_LEASE_V1_SCHEMA}', got '{}'",
                    lease.schema
                ),
            });
        }
        if lease.lane_id != expected_lane_id {
            return Err(LaneError::InvalidRecord {
                lane_id: expected_lane_id.to_string(),
                reason: format!(
                    "lane_id mismatch: expected '{expected_lane_id}', got '{}'",
                    lease.lane_id
                ),
            });
        }
        validate_lane_id(&lease.lane_id)?;
        validate_string_field("job_id", &lease.job_id, MAX_STRING_LENGTH)?;
        validate_string_field("started_at", &lease.started_at, MAX_STRING_LENGTH)?;
        validate_string_field(
            "lane_profile_hash",
            &lease.lane_profile_hash,
            MAX_STRING_LENGTH,
        )?;
        validate_string_field(
            "toolchain_fingerprint",
            &lease.toolchain_fingerprint,
            MAX_STRING_LENGTH,
        )?;
        Ok(Some(lease))
    }

    /// Remove the lease file from the lane directory.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors (ignores not-found).
    pub fn remove(lane_dir: &Path) -> Result<(), LaneError> {
        let lease_path = lane_dir.join("lease.v1.json");
        match fs::remove_file(&lease_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LaneError::io(
                format!("removing lease at {}", lease_path.display()),
                e,
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane Status (derived)
// ─────────────────────────────────────────────────────────────────────────────

/// Derived lane status for CLI display and JSON output.
///
/// This is computed from lock state + lease record + PID liveness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneStatusV1 {
    /// Lane identifier.
    pub lane_id: String,
    /// Derived lane state.
    pub state: LaneState,
    /// Job ID (if leased/running).
    pub job_id: Option<String>,
    /// PID of executor (if leased/running).
    pub pid: Option<u32>,
    /// When lease was acquired (if leased/running).
    ///
    /// Exposed as canonical RFC3339 UTC when parseable (including legacy
    /// epoch-seconds lease values).
    pub started_at: Option<String>,
    /// Toolchain fingerprint (if leased/running).
    pub toolchain_fingerprint: Option<String>,
    /// Lane profile hash.
    pub lane_profile_hash: Option<String>,
    /// Corrupt reason if lane is in CORRUPT state.
    pub corrupt_reason: Option<String>,
    /// Whether the lock file is currently held.
    pub lock_held: bool,
    /// Whether the PID in the lease is still alive.
    pub pid_alive: Option<bool>,
}

/// Persistent marker indicating a lane is corrupt and cannot accept new jobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneCorruptMarkerV1 {
    /// Schema identifier.
    pub schema: String,
    /// Lane identifier.
    pub lane_id: String,
    /// Human-readable reason for corruption.
    pub reason: String,
    /// Optional digest of the cleanup receipt that marked this lane corrupt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_receipt_digest: Option<String>,
    /// ISO-8601 UTC timestamp recording when the lane became corrupt.
    pub detected_at: String,
}

impl LaneCorruptMarkerV1 {
    fn marker_path(fac_root: &Path, lane_id: &str) -> PathBuf {
        fac_root.join("lanes").join(lane_id).join("corrupt.v1.json")
    }

    /// Persist this marker to the lane directory.
    ///
    /// Performs defense-in-depth validation before writing to ensure no
    /// invalid marker is ever persisted, even if constructed directly
    /// (bypassing `LaneManager::mark_corrupt`).
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` for serialization or write failures,
    /// `LaneError::StringTooLong` for oversized fields,
    /// `LaneError::InvalidDigestFormat` for malformed digests, or
    /// `LaneError::InvalidRecord` if the marker schema is invalid.
    pub fn persist(&self, fac_root: &Path) -> Result<(), LaneError> {
        // Defense-in-depth: validate fields before writing to disk.
        if self.schema != LANE_CORRUPT_MARKER_SCHEMA {
            return Err(LaneError::InvalidRecord {
                lane_id: self.lane_id.clone(),
                reason: format!(
                    "schema mismatch: expected '{LANE_CORRUPT_MARKER_SCHEMA}', got '{}'",
                    self.schema
                ),
            });
        }
        validate_lane_id(&self.lane_id)?;
        validate_string_field("reason", &self.reason, MAX_STRING_LENGTH)?;
        validate_string_field("detected_at", &self.detected_at, MAX_STRING_LENGTH)?;
        if let Some(ref digest) = self.cleanup_receipt_digest {
            validate_string_field("cleanup_receipt_digest", digest, MAX_STRING_LENGTH)?;
            validate_b3_256_digest("cleanup_receipt_digest", digest)?;
        }

        let path = Self::marker_path(fac_root, &self.lane_id);
        let bytes =
            serde_json::to_vec_pretty(self).map_err(|e| LaneError::Serialization(e.to_string()))?;
        atomic_write(&path, &bytes)
    }

    /// Load the marker for a lane, if present.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` for filesystem read failures and
    /// `LaneError::InvalidRecord` for malformed marker data.
    pub fn load(fac_root: &Path, lane_id: &str) -> Result<Option<Self>, LaneError> {
        let path = Self::marker_path(fac_root, lane_id);
        if !path.exists() {
            return Ok(None);
        }

        let bytes = bounded_read_file(&path, MAX_LEASE_FILE_SIZE)?;
        let marker: Self = serde_json::from_slice(&bytes).map_err(|e| {
            LaneError::Serialization(format!("failed to parse corrupt marker: {e}"))
        })?;

        if marker.schema != LANE_CORRUPT_MARKER_SCHEMA {
            return Err(LaneError::InvalidRecord {
                lane_id: lane_id.to_string(),
                reason: format!(
                    "schema mismatch: expected '{LANE_CORRUPT_MARKER_SCHEMA}', got '{}'",
                    marker.schema
                ),
            });
        }

        validate_lane_id(lane_id)?;
        if marker.lane_id != lane_id {
            return Err(LaneError::InvalidRecord {
                lane_id: lane_id.to_string(),
                reason: format!(
                    "lane_id mismatch: expected '{lane_id}', got '{}'",
                    marker.lane_id
                ),
            });
        }
        validate_string_field("reason", &marker.reason, MAX_STRING_LENGTH)?;
        validate_string_field("detected_at", &marker.detected_at, MAX_STRING_LENGTH)?;
        if let Some(ref digest) = marker.cleanup_receipt_digest {
            validate_string_field("cleanup_receipt_digest", digest, MAX_STRING_LENGTH)?;
            validate_b3_256_digest("cleanup_receipt_digest", digest)?;
        }

        Ok(Some(marker))
    }

    /// Remove the marker for a lane.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` if removal fails for reasons other than
    /// `NotFound`.
    pub fn remove(fac_root: &Path, lane_id: &str) -> Result<(), LaneError> {
        let path = Self::marker_path(fac_root, lane_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LaneError::io(
                format!("removing corrupt marker at {}", path.display()),
                e,
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane Init / Reconcile Receipt Types (TCK-00539)
// ─────────────────────────────────────────────────────────────────────────────

/// Receipt for `apm2 fac lane init` (TCK-00539).
///
/// Records the lanes that were created vs already existed, profile hashes,
/// and node identity used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneInitReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Total number of lanes configured.
    pub lane_count: usize,
    /// Lane IDs that were newly created (profile written).
    pub lanes_created: Vec<String>,
    /// Lane IDs that already existed (profile untouched).
    pub lanes_existing: Vec<String>,
    /// Per-lane profile hash information.
    pub profiles: Vec<LaneInitProfileEntry>,
    /// Node fingerprint used for profile generation.
    pub node_fingerprint: String,
    /// Boundary ID used for profile generation.
    pub boundary_id: String,
}

/// Per-lane profile entry in the init receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneInitProfileEntry {
    /// Lane identifier.
    pub lane_id: String,
    /// `b3-256:<hex>` profile hash.
    pub profile_hash: String,
    /// Whether the profile was newly created (`true`) or already existed
    /// (`false`).
    pub created: bool,
}

/// Receipt for `apm2 fac lane reconcile` (TCK-00539).
///
/// Records all reconciliation actions taken, lanes inspected, and outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneReconcileReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Total lanes inspected.
    pub lanes_inspected: usize,
    /// Lanes that were already healthy.
    pub lanes_ok: usize,
    /// Lanes that had missing dirs/profiles repaired.
    pub lanes_repaired: usize,
    /// Lanes marked CORRUPT because repair failed.
    pub lanes_marked_corrupt: usize,
    /// Lanes where repair actions failed.
    pub lanes_failed: usize,
    /// Infrastructure-level failures (e.g., lock-dir creation) that are not
    /// attributable to any specific lane but indicate a broken control plane.
    /// Any non-zero value here means the reconcile run should be treated as
    /// failed.
    #[serde(default)]
    pub infrastructure_failures: usize,
    /// Individual reconciliation actions taken.
    pub actions: Vec<LaneReconcileAction>,
}

/// A single reconciliation action for a lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneReconcileAction {
    /// Lane identifier affected.
    pub lane_id: String,
    /// Action taken (e.g., `create_dir_workspace`, `write_default_profile`).
    pub action: String,
    /// Outcome of the action.
    pub outcome: LaneReconcileOutcome,
    /// Optional detail (e.g., error message on failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Outcome of a single reconciliation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneReconcileOutcome {
    /// Lane was already healthy; no action needed.
    Ok,
    /// Missing resource was successfully repaired.
    Repaired,
    /// Repair failed; lane marked CORRUPT.
    MarkedCorrupt,
    /// Repair failed and corrupt marker also could not be written.
    Failed,
    /// Action was skipped (e.g., existing corrupt marker).
    Skipped,
}

impl fmt::Display for LaneStatusV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<12} {:<10}", self.lane_id, self.state)?;
        if self.state == LaneState::Corrupt {
            if let Some(reason) = &self.corrupt_reason {
                write!(f, " corrupt_reason={reason}")?;
            }
        }
        if let Some(ref job_id) = self.job_id {
            // Truncate job_id for display using Unicode-safe boundaries.
            let display_id = job_id.chars().take(30).collect::<String>();
            write!(f, " {display_id:<32}")?;
        } else {
            write!(f, " {:<32}", "-")?;
        }
        if let Some(ref started) = self.started_at {
            write!(f, " {started}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane Lock (RAII guard)
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard for an exclusively-held lane lock.
///
/// The lock is released when this guard is dropped. The underlying file lock
/// is automatically released by the OS when the file descriptor is closed.
///
/// # Synchronization Protocol
///
/// The lock file at `$APM2_HOME/private/fac/locks/lanes/<lane_id>.lock` uses
/// `flock(LOCK_EX)` for mutual exclusion. The happens-before relationship is:
/// - Writer acquires `flock(LOCK_EX)` → writes lease → releases lock
/// - Reader acquires `flock(LOCK_EX)` → reads lease → releases lock
/// - `flock` release synchronizes-with next successful `flock` acquisition
pub struct LaneLockGuard {
    /// The lock file (held open for the lifetime of the guard).
    _lock_file: File,
    /// Lane ID for diagnostics.
    lane_id: String,
}

impl fmt::Debug for LaneLockGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaneLockGuard")
            .field("lane_id", &self.lane_id)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane Directory Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages lane directories and lock files under `$APM2_HOME/private/fac/`.
#[derive(Debug, Clone)]
pub struct LaneManager {
    /// Root of the FAC private directory (`$APM2_HOME/private/fac`).
    fac_root: PathBuf,
}

impl LaneManager {
    /// Create a new lane manager rooted at the given FAC directory.
    ///
    /// The `fac_root` path must be an absolute path to
    /// `$APM2_HOME/private/fac`.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::InvalidLaneId` if `fac_root` is not absolute.
    pub fn new(fac_root: PathBuf) -> Result<Self, LaneError> {
        if !fac_root.is_absolute() {
            return Err(LaneError::InvalidLaneId(
                "fac_root must be an absolute path".to_string(),
            ));
        }
        Ok(Self { fac_root })
    }

    /// Create a lane manager using the default APM2 home directory.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::HomeResolution` if the home directory cannot be
    /// resolved.
    pub fn from_default_home() -> Result<Self, LaneError> {
        let home = apm2_home_dir().map_err(LaneError::HomeResolution)?;
        Self::new(home.join("private").join("fac"))
    }

    /// Get the configured lane count from environment or default.
    #[must_use]
    pub fn lane_count() -> usize {
        std::env::var(LANE_COUNT_ENV_VAR)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0 && n <= MAX_LANE_COUNT)
            .unwrap_or(DEFAULT_LANE_COUNT)
    }

    /// Generate the default set of lane IDs.
    #[must_use]
    pub fn default_lane_ids() -> Vec<String> {
        let count = Self::lane_count();
        (0..count)
            .map(|i| format!("{LANE_ID_PREFIX}{i:02}"))
            .collect()
    }

    /// Get the path to a lane's directory.
    #[must_use]
    pub fn lane_dir(&self, lane_id: &str) -> PathBuf {
        self.fac_root.join("lanes").join(lane_id)
    }

    /// Return the FAC root directory used by this manager.
    #[must_use]
    pub fn fac_root(&self) -> &Path {
        &self.fac_root
    }

    /// Get the path to a lane's lock file.
    #[must_use]
    pub fn lock_path(&self, lane_id: &str) -> PathBuf {
        self.fac_root
            .join("locks")
            .join("lanes")
            .join(format!("{lane_id}.lock"))
    }

    /// Ensure all lane directories and lock parent directories exist with
    /// restrictive permissions (0o700 in operator mode, 0o770 in system-mode)
    /// (CTR-2611).
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors.
    pub fn ensure_directories(&self) -> Result<(), LaneError> {
        let lane_ids = Self::default_lane_ids();
        for lane_id in &lane_ids {
            let lane_dir = self.lane_dir(lane_id);
            create_dir_restricted(&lane_dir.join("workspace"))?;
            create_dir_restricted(&lane_dir.join("target"))?;
            create_dir_restricted(&lane_dir.join("logs"))?;
            // TCK-00575: Create per-lane env isolation directories.
            for env_subdir in super::policy::LANE_ENV_DIRS {
                create_dir_restricted(&lane_dir.join(env_subdir))?;
            }
        }
        // Ensure lock directory exists
        let lock_dir = self.fac_root.join("locks").join("lanes");
        create_dir_restricted(&lock_dir)?;
        Ok(())
    }

    /// Initialize all lanes: create directories, write default profiles, and
    /// emit an init receipt.
    ///
    /// This is the operator-friendly bootstrap command for `apm2 fac lane
    /// init`. After this returns successfully, a fresh `$APM2_HOME` has a
    /// ready lane pool.
    ///
    /// If a profile already exists for a lane, it is left untouched
    /// (idempotent).
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors, or
    /// `LaneError::Serialization` if profile serialization fails.
    pub fn init_lanes(&self) -> Result<LaneInitReceiptV1, LaneError> {
        let apm2_home = self
            .fac_root
            .parent()
            .and_then(|p| p.parent())
            .ok_or_else(|| {
                LaneError::HomeResolution("fac_root must be $APM2_HOME/private/fac".to_string())
            })?;
        let node_fingerprint = super::node_identity::load_or_derive_node_fingerprint(apm2_home)
            .map_err(|e| {
                LaneError::HomeResolution(format!("node fingerprint derivation failed: {e}"))
            })?;
        let boundary_id =
            super::node_identity::load_or_default_boundary_id(apm2_home).map_err(|e| {
                LaneError::HomeResolution(format!("boundary ID resolution failed: {e}"))
            })?;

        // Ensure all directories exist first.
        self.ensure_directories()?;

        let lane_ids = Self::default_lane_ids();
        let mut lanes_created: Vec<String> = Vec::with_capacity(lane_ids.len());
        let mut lanes_existing: Vec<String> = Vec::with_capacity(lane_ids.len());
        let mut profile_hashes: Vec<LaneInitProfileEntry> = Vec::with_capacity(lane_ids.len());

        for lane_id in &lane_ids {
            let lane_dir = self.lane_dir(lane_id);
            let profile_path = lane_dir.join("profile.v1.json");

            if profile_path.exists() {
                // Profile already exists -- leave it.
                let existing = LaneProfileV1::load(&lane_dir)?;
                let hash = existing
                    .compute_hash()
                    .unwrap_or_else(|_| "unknown".to_string());
                profile_hashes.push(LaneInitProfileEntry {
                    lane_id: lane_id.clone(),
                    profile_hash: hash,
                    created: false,
                });
                lanes_existing.push(lane_id.clone());
            } else {
                let profile = LaneProfileV1::new(lane_id, &node_fingerprint, &boundary_id)?;
                profile.persist(&lane_dir)?;
                let hash = profile
                    .compute_hash()
                    .unwrap_or_else(|_| "unknown".to_string());
                profile_hashes.push(LaneInitProfileEntry {
                    lane_id: lane_id.clone(),
                    profile_hash: hash,
                    created: true,
                });
                lanes_created.push(lane_id.clone());
            }
        }

        let receipt = LaneInitReceiptV1 {
            schema: LANE_INIT_RECEIPT_SCHEMA.to_string(),
            lane_count: lane_ids.len(),
            lanes_created,
            lanes_existing,
            profiles: profile_hashes,
            node_fingerprint,
            boundary_id,
        };

        // TCK-00589: Persist receipt under receipts directory (not legacy evidence/).
        let receipt_dir = self.fac_root.join("receipts");
        create_dir_restricted(&receipt_dir)?;
        let receipt_bytes = serde_json::to_vec_pretty(&receipt)
            .map_err(|e| LaneError::Serialization(e.to_string()))?;
        let receipt_hash = blake3::hash(&receipt_bytes);
        let receipt_filename = format!("lane_init_{}.json", &receipt_hash.to_hex()[..16]);
        let receipt_path = receipt_dir.join(&receipt_filename);
        atomic_write(&receipt_path, &receipt_bytes)?;

        Ok(receipt)
    }

    /// Reconcile lane state: repair missing directories and profiles, mark
    /// lanes CORRUPT if unrecoverable.
    ///
    /// This is the operator recovery command for `apm2 fac lane reconcile`.
    /// It inspects each configured lane and repairs what it can:
    ///
    /// - Missing lane directories are recreated with `0o700` permissions.
    /// - Missing profiles are regenerated with defaults.
    /// - Lanes with corrupt markers are reported but not cleared.
    /// - Lanes that cannot be repaired (e.g., permissions errors) are marked
    ///   CORRUPT.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors, or
    /// `LaneError::HomeResolution` if identity resolution fails.
    pub fn reconcile_lanes(&self) -> Result<LaneReconcileReceiptV1, LaneError> {
        let apm2_home = self
            .fac_root
            .parent()
            .and_then(|p| p.parent())
            .ok_or_else(|| {
                LaneError::HomeResolution("fac_root must be $APM2_HOME/private/fac".to_string())
            })?;
        let node_fingerprint = super::node_identity::load_or_derive_node_fingerprint(apm2_home)
            .map_err(|e| {
                LaneError::HomeResolution(format!("node fingerprint derivation failed: {e}"))
            })?;
        let boundary_id =
            super::node_identity::load_or_default_boundary_id(apm2_home).map_err(|e| {
                LaneError::HomeResolution(format!("boundary ID resolution failed: {e}"))
            })?;

        let lane_ids = Self::default_lane_ids();
        let mut actions: Vec<LaneReconcileAction> = Vec::with_capacity(lane_ids.len());

        // Ensure lock directory exists.
        let lock_dir = self.fac_root.join("locks").join("lanes");
        if let Err(e) = create_dir_restricted(&lock_dir) {
            actions.push(LaneReconcileAction {
                lane_id: "locks/lanes".to_string(),
                action: "create_lock_dir".to_string(),
                outcome: LaneReconcileOutcome::Failed,
                detail: Some(format!("failed to create lock directory: {e}")),
            });
        }

        for lane_id in &lane_ids {
            self.reconcile_orphan_lease(lane_id, &mut actions);
            Self::reconcile_single_lane(
                &self.fac_root,
                &self.lane_dir(lane_id),
                lane_id,
                &node_fingerprint,
                &boundary_id,
                &mut actions,
            );
        }

        let receipt = Self::build_reconcile_receipt(&lane_ids, actions);

        // TCK-00589: Persist receipt under receipts directory (not legacy evidence/).
        let receipt_dir = self.fac_root.join("receipts");
        create_dir_restricted(&receipt_dir)?;
        let receipt_bytes = serde_json::to_vec_pretty(&receipt)
            .map_err(|e| LaneError::Serialization(e.to_string()))?;
        let receipt_hash = blake3::hash(&receipt_bytes);
        let receipt_filename = format!("lane_reconcile_{}.json", &receipt_hash.to_hex()[..16]);
        let receipt_path = receipt_dir.join(&receipt_filename);
        atomic_write(&receipt_path, &receipt_bytes)?;

        Ok(receipt)
    }

    /// Reconcile orphan lease state for a lane before directory/profile repair.
    ///
    /// S10: Detect `LEASED` lanes with missing/dead PID and proactively remove
    /// stale lease metadata when the lane lock can be acquired.
    fn reconcile_orphan_lease(&self, lane_id: &str, actions: &mut Vec<LaneReconcileAction>) {
        let lane_dir = self.lane_dir(lane_id);
        let orphan_detail = match LaneLeaseV1::load(&lane_dir) {
            Ok(Some(lease)) => {
                if lease.state == LaneState::Leased && !is_pid_alive(lease.pid) {
                    Some(format!(
                        "lease state=LEASED with dead pid {} (stale lease)",
                        lease.pid
                    ))
                } else {
                    return;
                }
            },
            Ok(None) => {
                // Production-reported orphan: derived LEASED with pid/job_id null
                // (lock held, no lease metadata). Flag this as orphaned even
                // though there is no lease file to remove.
                let status = match self.lane_status(lane_id) {
                    Ok(status) => status,
                    Err(err) => {
                        actions.push(LaneReconcileAction {
                            lane_id: lane_id.to_string(),
                            action: "inspect_orphan_lease".to_string(),
                            outcome: LaneReconcileOutcome::Failed,
                            detail: Some(format!(
                                "failed to read lane status for orphan-lease check: {err}"
                            )),
                        });
                        return;
                    },
                };
                if status.state == LaneState::Leased && status.pid.is_none() {
                    Some("derived LEASED with missing lease metadata (pid/job_id null)".to_string())
                } else {
                    return;
                }
            },
            Err(err) => {
                actions.push(LaneReconcileAction {
                    lane_id: lane_id.to_string(),
                    action: "inspect_orphan_lease".to_string(),
                    outcome: LaneReconcileOutcome::Failed,
                    detail: Some(format!(
                        "failed to load lease for orphan-lease check: {err}"
                    )),
                });
                return;
            },
        };

        let Some(orphan_detail) = orphan_detail else {
            return;
        };
        match self.try_lock(lane_id) {
            Ok(Some(_guard)) => match LaneLeaseV1::remove(&lane_dir) {
                Ok(()) => {
                    actions.push(LaneReconcileAction {
                        lane_id: lane_id.to_string(),
                        action: "reap_orphan_lease".to_string(),
                        outcome: LaneReconcileOutcome::Repaired,
                        detail: Some(format!("released orphaned leased state: {orphan_detail}")),
                    });
                },
                Err(err) => {
                    actions.push(LaneReconcileAction {
                        lane_id: lane_id.to_string(),
                        action: "reap_orphan_lease".to_string(),
                        outcome: LaneReconcileOutcome::Failed,
                        detail: Some(format!("failed to remove orphaned lease: {err}")),
                    });
                },
            },
            Ok(None) => {
                actions.push(LaneReconcileAction {
                    lane_id: lane_id.to_string(),
                    action: "reap_orphan_lease".to_string(),
                    outcome: LaneReconcileOutcome::Failed,
                    detail: Some(
                        "lane lock is held; cannot reap orphaned leased state safely".to_string(),
                    ),
                });
            },
            Err(err) => {
                actions.push(LaneReconcileAction {
                    lane_id: lane_id.to_string(),
                    action: "reap_orphan_lease".to_string(),
                    outcome: LaneReconcileOutcome::Failed,
                    detail: Some(format!(
                        "failed to acquire lane lock for orphan-lease reap: {err}"
                    )),
                });
            },
        }
    }

    /// Reconcile a single lane: repair missing directories/profiles and mark
    /// CORRUPT on unrecoverable failures.
    ///
    /// Corrupt-marked lanes are skipped immediately — no repair attempts are
    /// made. This preserves the quarantine contract: operators must explicitly
    /// clear the corrupt marker via `apm2 fac lane reset` before the lane is
    /// eligible for repair.
    fn reconcile_single_lane(
        fac_root: &Path,
        lane_dir: &Path,
        lane_id: &str,
        node_fingerprint: &str,
        boundary_id: &str,
        actions: &mut Vec<LaneReconcileAction>,
    ) {
        // Check for existing corrupt marker FIRST — corrupt-marked lanes are
        // quarantined and must not be repaired until the marker is cleared.
        let corrupt_marker_path = lane_dir.join("corrupt.v1.json");
        if corrupt_marker_path.exists() {
            actions.push(LaneReconcileAction {
                lane_id: lane_id.to_string(),
                action: "existing_corrupt_marker".to_string(),
                outcome: LaneReconcileOutcome::Skipped,
                detail: Some(
                    "corrupt marker present; use `apm2 fac lane reset` to clear".to_string(),
                ),
            });
            return;
        }

        let mut lane_repaired = false;
        let mut lane_failed = false;

        // Check and repair lane subdirectories.
        for subdir in &["workspace", "target", "logs"] {
            Self::reconcile_dir(
                lane_dir,
                lane_id,
                subdir,
                &format!("create_dir_{subdir}"),
                &mut lane_repaired,
                &mut lane_failed,
                actions,
            );
        }

        // Check and repair per-lane env dirs.
        for env_subdir in super::policy::LANE_ENV_DIRS {
            Self::reconcile_dir(
                lane_dir,
                lane_id,
                env_subdir,
                &format!("create_env_{env_subdir}"),
                &mut lane_repaired,
                &mut lane_failed,
                actions,
            );
        }

        // Check and repair missing profile.
        let profile_path = lane_dir.join("profile.v1.json");
        if !profile_path.exists() {
            Self::reconcile_profile(
                lane_dir,
                lane_id,
                node_fingerprint,
                boundary_id,
                &mut lane_repaired,
                &mut lane_failed,
                actions,
            );
        }

        // Mark CORRUPT if any repair failed.
        if lane_failed {
            Self::mark_lane_corrupt(fac_root, lane_id, actions);
        }

        // If no repairs were needed and no failures occurred, note OK.
        if !lane_failed && !lane_repaired {
            actions.push(LaneReconcileAction {
                lane_id: lane_id.to_string(),
                action: "inspect".to_string(),
                outcome: LaneReconcileOutcome::Ok,
                detail: None,
            });
        }
    }

    /// Check and repair a single subdirectory during reconciliation.
    ///
    /// Validates existing paths using `symlink_metadata` to ensure they are
    /// real directories. Files, symlinks, and other non-directory entries are
    /// treated as failures that mark the lane corrupt (Finding 2, PR #719).
    fn reconcile_dir(
        lane_dir: &Path,
        lane_id: &str,
        subdir: &str,
        action_name: &str,
        lane_repaired: &mut bool,
        lane_failed: &mut bool,
        actions: &mut Vec<LaneReconcileAction>,
    ) {
        let subdir_path = lane_dir.join(subdir);

        // Use symlink_metadata to detect the true entry type without
        // following symlinks. This catches files, symlinks, and other
        // non-directory entries that `.exists()` alone would treat as
        // valid (common-review-findings.md § 9: use symlink_metadata).
        match std::fs::symlink_metadata(&subdir_path) {
            Ok(meta) => {
                if !meta.file_type().is_dir() {
                    // Path exists but is NOT a real directory (file, symlink,
                    // FIFO, etc.). This is an invalid lane state.
                    let kind = if meta.file_type().is_symlink() {
                        "symlink"
                    } else if meta.file_type().is_file() {
                        "regular file"
                    } else {
                        "non-directory entry"
                    };
                    actions.push(LaneReconcileAction {
                        lane_id: lane_id.to_string(),
                        action: action_name.to_string(),
                        outcome: LaneReconcileOutcome::Failed,
                        detail: Some(format!(
                            "expected directory but found {kind} at {}",
                            subdir_path.display()
                        )),
                    });
                    *lane_failed = true;
                }
                // If it is a directory, it is healthy — no action needed.
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Path does not exist — attempt to create it.
                match create_dir_restricted(&subdir_path) {
                    Ok(()) => {
                        actions.push(LaneReconcileAction {
                            lane_id: lane_id.to_string(),
                            action: action_name.to_string(),
                            outcome: LaneReconcileOutcome::Repaired,
                            detail: None,
                        });
                        *lane_repaired = true;
                    },
                    Err(e) => {
                        actions.push(LaneReconcileAction {
                            lane_id: lane_id.to_string(),
                            action: action_name.to_string(),
                            outcome: LaneReconcileOutcome::Failed,
                            detail: Some(e.to_string()),
                        });
                        *lane_failed = true;
                    },
                }
            },
            Err(e) => {
                // Other I/O errors (e.g., permission denied).
                actions.push(LaneReconcileAction {
                    lane_id: lane_id.to_string(),
                    action: action_name.to_string(),
                    outcome: LaneReconcileOutcome::Failed,
                    detail: Some(format!("failed to stat {}: {e}", subdir_path.display())),
                });
                *lane_failed = true;
            },
        }
    }

    /// Attempt to write a default profile during reconciliation.
    fn reconcile_profile(
        lane_dir: &Path,
        lane_id: &str,
        node_fingerprint: &str,
        boundary_id: &str,
        lane_repaired: &mut bool,
        lane_failed: &mut bool,
        actions: &mut Vec<LaneReconcileAction>,
    ) {
        match LaneProfileV1::new(lane_id, node_fingerprint, boundary_id) {
            Ok(profile) => match profile.persist(lane_dir) {
                Ok(()) => {
                    actions.push(LaneReconcileAction {
                        lane_id: lane_id.to_string(),
                        action: "write_default_profile".to_string(),
                        outcome: LaneReconcileOutcome::Repaired,
                        detail: None,
                    });
                    *lane_repaired = true;
                },
                Err(e) => {
                    actions.push(LaneReconcileAction {
                        lane_id: lane_id.to_string(),
                        action: "write_default_profile".to_string(),
                        outcome: LaneReconcileOutcome::Failed,
                        detail: Some(e.to_string()),
                    });
                    *lane_failed = true;
                },
            },
            Err(e) => {
                actions.push(LaneReconcileAction {
                    lane_id: lane_id.to_string(),
                    action: "write_default_profile".to_string(),
                    outcome: LaneReconcileOutcome::Failed,
                    detail: Some(e.to_string()),
                });
                *lane_failed = true;
            },
        }
    }

    /// Write a CORRUPT marker for a lane that could not be repaired.
    // SECURITY JUSTIFICATION (CTR-2501): Lane reconciliation corrupt-marker
    // Timestamps use wall-clock time because reconciliation is an operational
    // recovery task, not a coordinated consensus operation. The timestamp is
    // used only for corrupt marker labelling (CTR-2501).
    fn mark_lane_corrupt(fac_root: &Path, lane_id: &str, actions: &mut Vec<LaneReconcileAction>) {
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: "lane reconcile failed to repair missing directories/profile".to_string(),
            cleanup_receipt_digest: None,
            detected_at: current_time_iso8601(),
        };
        if let Err(e) = marker.persist(fac_root) {
            actions.push(LaneReconcileAction {
                lane_id: lane_id.to_string(),
                action: "mark_corrupt".to_string(),
                outcome: LaneReconcileOutcome::Failed,
                detail: Some(format!("failed to persist corrupt marker: {e}")),
            });
        } else {
            actions.push(LaneReconcileAction {
                lane_id: lane_id.to_string(),
                action: "mark_corrupt".to_string(),
                outcome: LaneReconcileOutcome::MarkedCorrupt,
                detail: None,
            });
        }
    }

    /// Build the reconcile receipt from accumulated actions.
    ///
    /// Aggregates outcomes **per lane** rather than per action, so that
    /// `lanes_repaired` etc. never exceed `lanes_inspected`. Each lane
    /// contributes to exactly one counter based on its worst action outcome:
    ///   `Failed` > `MarkedCorrupt` > `Repaired` > `Ok` > `Skipped`
    ///
    /// Actions whose `lane_id` is not in the configured `lane_ids` set are
    /// counted as infrastructure failures (e.g., lock-dir creation). These
    /// are tracked separately in `infrastructure_failures` to ensure the
    /// receipt (and exit code) reflects non-lane control-plane failures.
    fn build_reconcile_receipt(
        lane_ids: &[String],
        actions: Vec<LaneReconcileAction>,
    ) -> LaneReconcileReceiptV1 {
        use std::collections::{HashMap, HashSet};

        let lane_id_set: HashSet<&str> = lane_ids.iter().map(String::as_str).collect();

        // Count infrastructure failures: actions with lane_id NOT in the
        // configured lane set that have a Failed outcome.
        let infrastructure_failures = actions
            .iter()
            .filter(|a| !lane_id_set.contains(a.lane_id.as_str()))
            .filter(|a| a.outcome == LaneReconcileOutcome::Failed)
            .count();

        // Determine per-lane summary outcome.
        // Priority (worst wins): Failed > MarkedCorrupt > Repaired > Ok > Skipped
        let mut lane_outcomes: HashMap<&str, LaneReconcileOutcome> =
            HashMap::with_capacity(lane_ids.len());

        for action in &actions {
            // Only aggregate actions that belong to configured lanes.
            if !lane_id_set.contains(action.lane_id.as_str()) {
                continue;
            }
            let entry = lane_outcomes
                .entry(action.lane_id.as_str())
                .or_insert(action.outcome);
            // Promote to worse outcome when applicable.
            *entry = worse_outcome(*entry, action.outcome);
        }

        let mut lanes_ok: usize = 0;
        let mut lanes_repaired: usize = 0;
        let mut lanes_marked_corrupt: usize = 0;
        let mut lanes_failed: usize = 0;

        for lane_id in lane_ids {
            match lane_outcomes.get(lane_id.as_str()) {
                Some(LaneReconcileOutcome::Ok) => lanes_ok += 1,
                Some(LaneReconcileOutcome::Repaired) => lanes_repaired += 1,
                Some(LaneReconcileOutcome::MarkedCorrupt) => lanes_marked_corrupt += 1,
                Some(LaneReconcileOutcome::Failed) => lanes_failed += 1,
                // Skipped lanes (corrupt-marked) are not counted in ok/repaired/failed.
                Some(LaneReconcileOutcome::Skipped) | None => {},
            }
        }

        LaneReconcileReceiptV1 {
            schema: LANE_RECONCILE_RECEIPT_SCHEMA.to_string(),
            lanes_inspected: lane_ids.len(),
            lanes_ok,
            lanes_repaired,
            lanes_marked_corrupt,
            lanes_failed,
            infrastructure_failures,
            actions,
        }
    }

    /// Try to acquire an exclusive lock on a lane (non-blocking).
    ///
    /// Returns `Ok(Some(guard))` if the lock was acquired, `Ok(None)` if the
    /// lane is currently held by another process.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on unexpected filesystem errors.
    pub fn try_lock(&self, lane_id: &str) -> Result<Option<LaneLockGuard>, LaneError> {
        validate_lane_id(lane_id)?;
        let lock_path = self.lock_path(lane_id);
        ensure_parent_dir(&lock_path)?;

        let lock_file = open_lock_file(&lock_path, true)?;

        // Set restrictive permissions on the lock file (CTR-2611)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            if let Err(e) = fs::set_permissions(&lock_path, perms) {
                tracing::warn!(path = %lock_path.display(), err = %e, "failed to set lock file permissions");
            }
        }

        match try_flock_exclusive(&lock_file) {
            Ok(true) => Ok(Some(LaneLockGuard {
                _lock_file: lock_file,
                lane_id: lane_id.to_string(),
            })),
            Ok(false) => Ok(None),
            Err(e) => Err(LaneError::LockFailed {
                lane_id: lane_id.to_string(),
                source: e,
            }),
        }
    }

    /// Acquire an exclusive lock on a lane, polling with jitter until success
    /// or timeout.
    ///
    /// Uses the proven RAII + jitter pattern from `model_pool.rs`.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::LockTimeout` if the lock is not acquired within
    /// `LANE_LOCK_TIMEOUT`.
    pub fn acquire_lock(&self, lane_id: &str) -> Result<LaneLockGuard, LaneError> {
        let start = Instant::now();
        loop {
            if let Some(guard) = self.try_lock(lane_id)? {
                return Ok(guard);
            }
            let elapsed = start.elapsed();
            if elapsed >= LANE_LOCK_TIMEOUT {
                return Err(LaneError::LockTimeout {
                    lane_id: lane_id.to_string(),
                    elapsed_secs: elapsed.as_secs(),
                });
            }
            let jitter_ms = rand::random::<u64>() % (LANE_LOCK_POLL_JITTER_MS + 1);
            std::thread::sleep(LANE_LOCK_POLL_INTERVAL + Duration::from_millis(jitter_ms));
        }
    }

    /// Check whether a lane's lock is currently held by another process.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on unexpected filesystem errors.
    pub fn is_lock_held(&self, lane_id: &str) -> Result<bool, LaneError> {
        let lock_path = self.lock_path(lane_id);
        if !lock_path.exists() {
            return Ok(false);
        }
        let lock_file = open_lock_file(&lock_path, false)?;
        match try_flock_exclusive(&lock_file) {
            Ok(true) => {
                // We acquired it — release immediately by dropping.
                // The file close in drop releases the lock.
                Ok(false)
            },
            Ok(false) => Ok(true),
            Err(e) => Err(LaneError::LockFailed {
                lane_id: lane_id.to_string(),
                source: e,
            }),
        }
    }

    /// Derive the status of a lane from lock state, lease record, PID
    /// liveness, and corrupt marker.
    ///
    /// # Stale Lease Detection Rules (RFC-0019 §4.4)
    ///
    /// - Lock held + corrupt marker → CORRUPT
    /// - Lock free + corrupt marker (even with no lease) → CORRUPT until marker
    ///   is cleared explicitly via `LaneCorruptMarkerV1::remove()`
    /// - Lock held + lease missing/invalid → LEASED
    /// - Lock free + lease missing/invalid → IDLE
    /// - Lock free + lease RUNNING + PID alive → CORRUPT (INV-LANE-004)
    /// - Lock free + PID dead → stale lease (IDLE)
    /// - Lock held + lease RUNNING + PID alive → RUNNING
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors.
    pub fn lane_status(&self, lane_id: &str) -> Result<LaneStatusV1, LaneError> {
        validate_lane_id(lane_id)?;
        let lane_dir = self.lane_dir(lane_id);
        let corrupt_marker = LaneCorruptMarkerV1::load(&self.fac_root, lane_id)?;
        let corrupt_reason = corrupt_marker.as_ref().map(|marker| marker.reason.clone());
        let lock_held = self.is_lock_held(lane_id)?;

        let lease = match LaneLeaseV1::load(&lane_dir) {
            Ok(lease) => lease,
            Err(_err) if lock_held => None,
            Err(err) => return Err(err),
        };
        let is_corrupt = corrupt_marker.is_some();
        let pid_alive = lease.as_ref().map(|lease| is_pid_alive(lease.pid));
        let state = derive_lane_state(
            lock_held,
            lease.as_ref(),
            pid_alive.unwrap_or(false),
            is_corrupt,
        );
        let (job_id, pid, started_at, lane_profile_hash, toolchain_fingerprint) = lease
            .as_ref()
            .map_or((None, None, None, None, None), |lease| {
                (
                    Some(lease.job_id.clone()),
                    Some(lease.pid),
                    lease
                        .started_at_rfc3339()
                        .or_else(|| Some(lease.started_at.clone())),
                    Some(lease.lane_profile_hash.clone()),
                    Some(lease.toolchain_fingerprint.clone()),
                )
            });

        Ok(LaneStatusV1 {
            lane_id: lane_id.to_string(),
            state,
            job_id,
            pid,
            started_at,
            toolchain_fingerprint,
            lane_profile_hash,
            lock_held,
            pid_alive,
            corrupt_reason,
        })
    }

    /// Clear a corrupt marker for a lane.
    ///
    /// This is used by operator recovery workflows when a marker is known to
    /// have been resolved externally.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::InvalidLaneId` for malformed lane IDs, or
    /// `LaneError::Io` for filesystem errors.
    pub fn clear_corrupt_marker(&self, lane_id: &str) -> Result<(), LaneError> {
        validate_lane_id(lane_id)?;
        LaneCorruptMarkerV1::remove(&self.fac_root, lane_id)
    }

    /// Mark a lane as CORRUPT with a reason and optional receipt digest.
    ///
    /// This is the canonical operator-facing API for marking a lane as
    /// corrupt (TCK-00570). The caller MUST hold the lane lock before
    /// calling this method to prevent TOCTOU between status check and
    /// marker write.
    ///
    /// # Arguments
    ///
    /// * `lane_id` - Lane to mark (validated).
    /// * `reason` - Human-readable reason (validated against
    ///   `MAX_STRING_LENGTH`).
    /// * `receipt_digest` - Optional `b3-256:<hex>` digest binding the marker
    ///   to an evidence artifact.
    ///
    /// The `detected_at` timestamp is generated internally as an ISO-8601
    /// UTC string (CTR-2501) to ensure consistent format across all code
    /// paths that create corrupt markers.  On success the generated
    /// `detected_at` value is returned so callers can surface it in
    /// command output without a fragile load-back round-trip.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::InvalidLaneId` for malformed lane IDs,
    /// `LaneError::StringTooLong` for oversized fields, or
    /// `LaneError::Io` / `LaneError::Serialization` for persistence
    /// failures.
    pub fn mark_corrupt(
        &self,
        lane_id: &str,
        reason: &str,
        receipt_digest: Option<&str>,
    ) -> Result<String, LaneError> {
        validate_lane_id(lane_id)?;
        validate_string_field("reason", reason, MAX_STRING_LENGTH)?;
        if let Some(digest) = receipt_digest {
            validate_string_field("cleanup_receipt_digest", digest, MAX_STRING_LENGTH)?;
            validate_b3_256_digest("cleanup_receipt_digest", digest)?;
        }

        let detected_at = current_time_iso8601();
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: reason.to_string(),
            cleanup_receipt_digest: receipt_digest.map(String::from),
            detected_at: detected_at.clone(),
        };
        marker.persist(&self.fac_root)?;
        Ok(detected_at)
    }

    /// Get the status of all lanes.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors.
    pub fn all_lane_statuses(&self) -> Result<Vec<LaneStatusV1>, LaneError> {
        let lane_ids = Self::default_lane_ids();
        let mut statuses = Vec::with_capacity(lane_ids.len());
        for lane_id in &lane_ids {
            statuses.push(self.lane_status(lane_id)?);
        }
        Ok(statuses)
    }

    /// Run lane cleanup with default log retention config.
    ///
    /// Delegates to [`Self::run_lane_cleanup_with_retention`] using
    /// [`LogRetentionConfig::default()`](super::gc::LogRetentionConfig).
    ///
    /// # Errors
    ///
    /// Returns `LaneCleanupError::GitCommandFailed` on git failures, and
    /// `LaneCleanupError::TempPruneFailed` or
    /// `LaneCleanupError::LogQuotaFailed` for cleanup actions.
    pub fn run_lane_cleanup(
        &self,
        lane_id: &str,
        workspace_path: &Path,
    ) -> Result<Vec<String>, LaneCleanupError> {
        self.run_lane_cleanup_with_retention(
            lane_id,
            workspace_path,
            &super::gc::LogRetentionConfig::default(),
        )
    }

    /// Run lane cleanup with explicit log retention policy (TCK-00571).
    ///
    /// Steps:
    /// 1. Reset workspace (`git reset --hard HEAD`)
    /// 2. Remove untracked files (`git clean -ffdxq`)
    /// 3. Remove temporary directory (`tmp`) via safe deletion
    /// 4. Prune per-lane env dirs from `LANE_ENV_DIRS` (excluding `tmp`):
    ///    (`home/`, `xdg_cache/`, `xdg_config/`, `xdg_data/`, `xdg_state/`,
    ///    `xdg_runtime/`)
    /// 5. Enforce log retention policy using the provided
    ///    [`LogRetentionConfig`](super::gc::LogRetentionConfig), ensuring
    ///    cleanup and GC enforce the same retention contract.
    ///
    /// # Errors
    ///
    /// Returns `LaneCleanupError::GitCommandFailed` on git failures, and
    /// `LaneCleanupError::TempPruneFailed` or
    /// `LaneCleanupError::LogQuotaFailed` for cleanup actions.
    #[allow(clippy::too_many_lines)]
    pub fn run_lane_cleanup_with_retention(
        &self,
        lane_id: &str,
        workspace_path: &Path,
        log_retention: &super::gc::LogRetentionConfig,
    ) -> Result<Vec<String>, LaneCleanupError> {
        validate_lane_id(lane_id).map_err(|e| {
            LaneCleanupError::Io(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
        })?;
        let mut steps_completed = Vec::new();
        let lanes_dir = self.fac_root.join("lanes").join(lane_id);

        let lease = LaneLeaseV1::load(&lanes_dir).map_err(|e| {
            LaneCleanupError::Io(io::Error::other(format!(
                "failed to load lane lease for cleanup: {e}"
            )))
        })?;
        let mut lease = lease.ok_or_else(|| {
            LaneCleanupError::InvalidState("cleanup requires a RUNNING lease".to_string())
        })?;
        if lease.state != LaneState::Running {
            return Err(LaneCleanupError::InvalidState(format!(
                "cleanup requires lane {lane_id} in RUNNING state, found {}",
                lease.state
            )));
        }

        let persist_lease_state = |lease: &mut LaneLeaseV1, state: LaneState| {
            lease.state = state;
            lease.persist(&lanes_dir).map_err(|e| {
                LaneCleanupError::Io(io::Error::other(format!(
                    "failed to persist lane lease state to {state} for {lane_id}: {e}"
                )))
            })
        };

        persist_lease_state(&mut lease, LaneState::Cleanup)?;

        let workspace_path = match Self::validate_workspace_path(
            &lanes_dir,
            workspace_path,
            &steps_completed,
            CLEANUP_STEP_WORKSPACE_VALIDATION,
        ) {
            Ok(path) => path,
            Err(err) => {
                persist_lease_state(&mut lease, LaneState::Corrupt)?;
                return Err(err);
            },
        };

        // Step 1: git reset (restore workspace to HEAD).
        //
        // SEC-CTRL-LANE-CLEANUP-001: Git config isolation.
        // A malicious job can modify .git/config (e.g., core.fsmonitor,
        // core.pager) in the workspace. We isolate the git environment by:
        // 1. Setting GIT_CONFIG_GLOBAL=/dev/null and GIT_CONFIG_SYSTEM=/dev/null to
        //    prevent loading global/system config files.
        // 2. Passing -c overrides for dangerous config keys that could trigger
        //    arbitrary code execution (core.fsmonitor, core.pager, core.editor).
        // 3. Using --no-optional-locks to reduce surface area.
        let reset_output = build_isolated_git_command(&workspace_path)
            .args(["reset", "--hard", "HEAD"])
            .output();
        let reset_output = match reset_output {
            Ok(reset_output) => reset_output,
            Err(err) => {
                persist_lease_state(&mut lease, LaneState::Corrupt)?;
                return Err(LaneCleanupError::GitCommandFailed {
                    step: CLEANUP_STEP_GIT_RESET,
                    reason: format!("git reset spawn: {err}"),
                    steps_completed: steps_completed.clone(),
                    failure_step: Some(CLEANUP_STEP_GIT_RESET.to_string()),
                });
            },
        };
        if !reset_output.status.success() {
            persist_lease_state(&mut lease, LaneState::Corrupt)?;
            return Err(LaneCleanupError::GitCommandFailed {
                step: CLEANUP_STEP_GIT_RESET,
                reason: format!(
                    "git reset: {}",
                    String::from_utf8_lossy(&reset_output.stderr)
                ),
                steps_completed: steps_completed.clone(),
                failure_step: Some(CLEANUP_STEP_GIT_RESET.to_string()),
            });
        }
        steps_completed.push(CLEANUP_STEP_GIT_RESET.to_string());

        // Step 2: git clean -ffdxq (remove untracked files).
        //
        // SEC-CTRL-LANE-CLEANUP-001: Same git config isolation as Step 1.
        let clean_output = build_isolated_git_command(&workspace_path)
            .args(["clean", "-ffdxq"])
            .output();
        let clean_output = match clean_output {
            Ok(clean_output) => clean_output,
            Err(err) => {
                persist_lease_state(&mut lease, LaneState::Corrupt)?;
                return Err(LaneCleanupError::GitCommandFailed {
                    step: CLEANUP_STEP_GIT_CLEAN,
                    reason: format!("git clean spawn: {err}"),
                    steps_completed: steps_completed.clone(),
                    failure_step: Some(CLEANUP_STEP_GIT_CLEAN.to_string()),
                });
            },
        };
        if !clean_output.status.success() {
            persist_lease_state(&mut lease, LaneState::Corrupt)?;
            return Err(LaneCleanupError::GitCommandFailed {
                step: CLEANUP_STEP_GIT_CLEAN,
                reason: format!(
                    "git clean: {}",
                    String::from_utf8_lossy(&clean_output.stderr)
                ),
                steps_completed: steps_completed.clone(),
                failure_step: Some(CLEANUP_STEP_GIT_CLEAN.to_string()),
            });
        }
        steps_completed.push(CLEANUP_STEP_GIT_CLEAN.to_string());

        // Step 3: Prune temp directory.
        let tmp_dir = lanes_dir.join("tmp");
        if tmp_dir.exists() {
            if let Err(err) = safe_rmtree_v1(&tmp_dir, &lanes_dir) {
                persist_lease_state(&mut lease, LaneState::Corrupt)?;
                return Err(LaneCleanupError::TempPruneFailed {
                    step: CLEANUP_STEP_TEMP_PRUNE,
                    reason: format!("{err}"),
                    steps_completed: steps_completed.clone(),
                    failure_step: Some(CLEANUP_STEP_TEMP_PRUNE.to_string()),
                });
            }
        }
        steps_completed.push(CLEANUP_STEP_TEMP_PRUNE.to_string());

        // Step 3b (TCK-00575): Prune per-lane environment directories from
        // `LANE_ENV_DIRS`. The `tmp` dir is already handled above in
        // step 3.
        for &env_subdir in super::policy::LANE_ENV_DIRS {
            if env_subdir == super::policy::LANE_ENV_DIR_TMP {
                continue;
            }

            let env_dir = lanes_dir.join(env_subdir);
            if env_dir.exists() {
                if let Err(err) = safe_rmtree_v1(&env_dir, &lanes_dir) {
                    persist_lease_state(&mut lease, LaneState::Corrupt)?;
                    return Err(LaneCleanupError::EnvDirPruneFailed {
                        step: CLEANUP_STEP_ENV_DIR_PRUNE,
                        reason: format!("failed to prune env dir {}: {err}", env_dir.display()),
                        steps_completed: steps_completed.clone(),
                        failure_step: Some(CLEANUP_STEP_ENV_DIR_PRUNE.to_string()),
                    });
                }
            }
        }
        steps_completed.push(CLEANUP_STEP_ENV_DIR_PRUNE.to_string());

        // Step 4: Enforce log retention policy (TCK-00571).
        //
        // CQ-BLOCKER-1 fix: Uses the caller-provided LogRetentionConfig
        // (derived from FacPolicyV1 fields per_job_log_ttl_days,
        // keep_last_n_jobs_per_lane, per_lane_log_max_bytes) instead of a
        // hardcoded 100 MiB file-level quota. This ensures post-job cleanup
        // and GC enforce the same retention contract.
        if let Err(err) =
            Self::enforce_log_retention(&lanes_dir.join("logs"), log_retention, &steps_completed)
        {
            persist_lease_state(&mut lease, LaneState::Corrupt)?;
            return Err(err);
        }
        steps_completed.push(CLEANUP_STEP_LOG_QUOTA.to_string());
        if let Err(e) = LaneLeaseV1::remove(&lanes_dir) {
            persist_lease_state(&mut lease, LaneState::Corrupt)?;
            return Err(LaneCleanupError::Io(io::Error::other(format!(
                "failed to remove lane lease after cleanup: {e}"
            ))));
        }

        Ok(steps_completed)
    }

    /// Legacy log quota enforcement (file-level, hardcoded 100 MiB).
    ///
    /// Retained for existing test coverage. Production cleanup now uses
    /// `enforce_log_retention` with policy-derived `LogRetentionConfig`.
    #[cfg(test)]
    fn enforce_log_quota(
        logs_dir: &Path,
        steps_completed: &[String],
    ) -> Result<(), LaneCleanupError> {
        if !logs_dir.exists() {
            return Ok(());
        }

        let mut entries: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
        let mut total_size: u64 = 0;
        Self::collect_log_entries(logs_dir, &mut entries, &mut total_size, 0, steps_completed)?;

        if total_size <= MAX_LOG_QUOTA_BYTES {
            return Ok(());
        }

        entries.sort_by(|a, b| {
            let time_ord = a.2.cmp(&b.2);
            if time_ord.is_eq() {
                a.0.cmp(&b.0)
            } else {
                time_ord
            }
        });

        for (path, size, _) in entries {
            if total_size <= MAX_LOG_QUOTA_BYTES {
                break;
            }
            match fs::remove_file(&path) {
                Ok(()) => {
                    total_size = total_size.saturating_sub(size);
                },
                Err(err) if err.kind() == io::ErrorKind::NotFound => {},
                Err(err) => {
                    return Err(LaneCleanupError::LogQuotaFailed {
                        step: CLEANUP_STEP_LOG_QUOTA,
                        reason: format!("cannot remove log file {}: {err}", path.display()),
                        steps_completed: steps_completed.to_vec(),
                        failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                    });
                },
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn collect_log_entries(
        base: &Path,
        entries: &mut Vec<(PathBuf, u64, SystemTime)>,
        total_size: &mut u64,
        depth: usize,
        steps_completed: &[String],
    ) -> Result<(), LaneCleanupError> {
        if depth > MAX_LOG_QUOTA_DIR_DEPTH {
            return Err(LaneCleanupError::LogQuotaFailed {
                step: CLEANUP_STEP_LOG_QUOTA,
                reason: format!(
                    "log directory recursion depth exceeded at {} (max {})",
                    base.display(),
                    MAX_LOG_QUOTA_DIR_DEPTH
                ),
                steps_completed: steps_completed.to_vec(),
                failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
            });
        }

        // Bound per-directory breadth to prevent directory-flood DoS
        // (INV-RMTREE-009). An attacker can create millions of entries in the
        // logs directory; without this cap the worker would spin reading all of
        // them and starve.
        let mut dir_entry_count: usize = 0;

        for entry in fs::read_dir(base).map_err(|e| LaneCleanupError::LogQuotaFailed {
            step: CLEANUP_STEP_LOG_QUOTA,
            reason: format!("cannot read logs directory {}: {e}", base.display()),
            steps_completed: steps_completed.to_vec(),
            failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
        })? {
            dir_entry_count += 1;
            if dir_entry_count > MAX_DIR_ENTRIES {
                return Err(LaneCleanupError::LogQuotaFailed {
                    step: CLEANUP_STEP_LOG_QUOTA,
                    reason: format!(
                        "log directory {} contains more than {MAX_DIR_ENTRIES} entries \
                         (directory-flood DoS prevention)",
                        base.display()
                    ),
                    steps_completed: steps_completed.to_vec(),
                    failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                });
            }

            let entry = entry.map_err(|e| LaneCleanupError::LogQuotaFailed {
                step: CLEANUP_STEP_LOG_QUOTA,
                reason: format!("cannot read log directory entry: {e}"),
                steps_completed: steps_completed.to_vec(),
                failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
            })?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|e| LaneCleanupError::LogQuotaFailed {
                    step: CLEANUP_STEP_LOG_QUOTA,
                    reason: format!("cannot stat log entry {}: {e}", path.display()),
                    steps_completed: steps_completed.to_vec(),
                    failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                })?;

            if metadata.is_dir() {
                Self::collect_log_entries(&path, entries, total_size, depth + 1, steps_completed)?;
                continue;
            }

            if !(metadata.is_file() || metadata.file_type().is_symlink()) {
                return Err(LaneCleanupError::LogQuotaFailed {
                    step: CLEANUP_STEP_LOG_QUOTA,
                    reason: format!("unsupported log entry type in {}", path.display()),
                    steps_completed: steps_completed.to_vec(),
                    failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                });
            }

            if entries.len() + 1 > MAX_LOG_ENTRIES {
                return Err(LaneCleanupError::LogQuotaFailed {
                    step: CLEANUP_STEP_LOG_QUOTA,
                    reason: format!("log directory contains more than {MAX_LOG_ENTRIES} entries"),
                    steps_completed: steps_completed.to_vec(),
                    failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                });
            }

            let size = metadata.len();
            let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            entries.push((path, size, mtime));
            *total_size = total_size.saturating_add(size);
        }

        Ok(())
    }

    /// Enforce log retention policy on a lane's `logs/` directory (TCK-00571).
    ///
    /// This is the post-job cleanup counterpart to the GC planner's
    /// `collect_lane_log_retention_targets`. It applies the same three
    /// retention criteria (TTL, keep-last-N, byte quota) to ensure cleanup
    /// and GC enforce an identical retention contract (CQ-BLOCKER-1 fix).
    ///
    /// Unlike the old `enforce_log_quota` (which operated on individual files),
    /// this method operates at the job-log-directory level: each immediate
    /// subdirectory of `logs/` is treated as a single pruning unit.
    #[allow(clippy::too_many_lines, clippy::items_after_statements)]
    fn enforce_log_retention(
        logs_dir: &Path,
        config: &super::gc::LogRetentionConfig,
        steps_completed: &[String],
    ) -> Result<(), LaneCleanupError> {
        // SECURITY: Validate that logs_dir itself is not a symlink before any
        // read_dir/remove operations. A symlinked logs/ directory would cause
        // all subsequent path operations to resolve outside the lane root,
        // enabling arbitrary-file-deletion attacks (BLOCKER finding).
        // Use symlink_metadata (lstat) to inspect without following.
        match fs::symlink_metadata(logs_dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(LaneCleanupError::LogQuotaFailed {
                        step: CLEANUP_STEP_LOG_QUOTA,
                        reason: format!(
                            "logs directory {} is a symlink — refusing to follow \
                             (fail-closed: symlinked logs/ enables arbitrary-file-deletion \
                             attacks outside the lane root)",
                            logs_dir.display()
                        ),
                        steps_completed: steps_completed.to_vec(),
                        failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                    });
                }
                if !meta.is_dir() {
                    return Err(LaneCleanupError::LogQuotaFailed {
                        step: CLEANUP_STEP_LOG_QUOTA,
                        reason: format!(
                            "logs path {} exists but is not a directory \
                             (fail-closed: unexpected file type at logs path)",
                            logs_dir.display()
                        ),
                        steps_completed: steps_completed.to_vec(),
                        failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                    });
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(());
            },
            Err(e) => {
                return Err(LaneCleanupError::LogQuotaFailed {
                    step: CLEANUP_STEP_LOG_QUOTA,
                    reason: format!(
                        "cannot stat logs directory {}: {e} \
                         (fail-closed: unreadable logs path)",
                        logs_dir.display()
                    ),
                    steps_completed: steps_completed.to_vec(),
                    failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                });
            },
        }

        let effective_ttl = config.effective_ttl_secs();
        let now_secs = {
            // SECURITY JUSTIFICATION (CTR-2501): Log retention staleness
            // uses wall-clock time because it is an operational maintenance
            // task, not a coordinated consensus operation.
            #[allow(clippy::disallowed_methods)]
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        };

        // Collect immediate subdirectories (job log dirs) with metadata.
        let entries = fs::read_dir(logs_dir).map_err(|e| LaneCleanupError::LogQuotaFailed {
            step: CLEANUP_STEP_LOG_QUOTA,
            reason: format!("cannot read logs directory {}: {e}", logs_dir.display()),
            steps_completed: steps_completed.to_vec(),
            failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
        })?;

        struct JobLogDirEntry {
            path: PathBuf,
            modified_secs: u64,
            estimated_bytes: u64,
            pruned: bool,
        }

        let mut job_dirs: Vec<JobLogDirEntry> = Vec::new();
        let mut scan_count = 0usize;
        let mut lane_visited_count = 0usize;
        // Accumulator for bytes consumed by invalid top-level entries
        // (non-directory files) that survived deletion attempts.  These
        // bytes MUST be included in quota calculations so that undeletable
        // stray files cannot bypass per-lane retention limits (fail-closed
        // accounting, security finding f-759-security-*-0).
        let mut stray_surviving_bytes: u64 = 0;
        for entry_result in entries {
            scan_count += 1;
            if scan_count > MAX_LOG_ENTRIES {
                return Err(LaneCleanupError::LogQuotaFailed {
                    step: CLEANUP_STEP_LOG_QUOTA,
                    reason: format!(
                        "log directory {} contains more than {MAX_LOG_ENTRIES} entries \
                         (directory-flood DoS prevention)",
                        logs_dir.display()
                    ),
                    steps_completed: steps_completed.to_vec(),
                    failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                });
            }

            let entry = entry_result.map_err(|e| LaneCleanupError::LogQuotaFailed {
                step: CLEANUP_STEP_LOG_QUOTA,
                reason: format!("cannot read log directory entry: {e}"),
                steps_completed: steps_completed.to_vec(),
                failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
            })?;

            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|e| LaneCleanupError::LogQuotaFailed {
                    step: CLEANUP_STEP_LOG_QUOTA,
                    reason: format!("cannot stat log entry {}: {e}", path.display()),
                    steps_completed: steps_completed.to_vec(),
                    failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                })?;

            // Fail-closed: symlinks under logs/ are never valid — remove
            // them unconditionally to prevent symlink-following attacks.
            // If removal fails, propagate the error (fail-closed): a
            // surviving symlink is a security risk that must not be
            // silently ignored.
            if metadata.file_type().is_symlink() {
                if let Err(e) = fs::remove_file(&path) {
                    // NotFound is benign (concurrent deletion race).
                    if e.kind() != io::ErrorKind::NotFound {
                        return Err(LaneCleanupError::LogQuotaFailed {
                            step: CLEANUP_STEP_LOG_QUOTA,
                            reason: format!(
                                "cannot remove invalid symlink {}: {e} \
                                 (fail-closed: surviving symlinks under logs/ \
                                 are a symlink-following attack vector)",
                                path.display()
                            ),
                            steps_completed: steps_completed.to_vec(),
                            failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                        });
                    }
                }
                continue;
            }

            // Regular files under logs/ are invalid (only job-log
            // subdirectories belong here). Remove them and account for
            // their bytes toward the quota so that stray files cannot
            // bypass per-lane log-retention controls.
            if !metadata.is_dir() {
                let file_bytes = metadata.len();
                match fs::remove_file(&path) {
                    Ok(()) => {
                        // Successfully removed — no byte accounting needed.
                    },
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        // Benign race: file was concurrently deleted.
                    },
                    Err(_) => {
                        // Deletion failed and file still exists — include
                        // its bytes in quota accounting so the surviving
                        // entry cannot bypass retention limits (fail-closed
                        // accounting, security finding f-759-security-*-0).
                        stray_surviving_bytes = stray_surviving_bytes.saturating_add(file_bytes);
                    },
                }
                continue;
            }

            let modified_secs = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());

            // S-BLOCKER-1 fix: Use bounded recursive estimator (DoS protection
            // via lane_visited_count).
            let estimated_bytes =
                super::gc::estimate_job_log_dir_size_recursive(&path, &mut lane_visited_count);

            job_dirs.push(JobLogDirEntry {
                path,
                modified_secs,
                estimated_bytes,
                pruned: false,
            });
        }

        if job_dirs.is_empty() {
            // If invalid top-level files survived deletion and there are no
            // job directories to evict, report failure so the lane is marked
            // Corrupt rather than silently accumulating undeletable entries.
            if stray_surviving_bytes > 0 {
                return Err(LaneCleanupError::LogQuotaFailed {
                    step: CLEANUP_STEP_LOG_QUOTA,
                    reason: format!(
                        "cannot delete {stray_surviving_bytes} bytes of invalid \
                         top-level files under {} and no job directories exist \
                         to evict (fail-closed: undeletable stray entries \
                         must not silently accumulate)",
                        logs_dir.display()
                    ),
                    steps_completed: steps_completed.to_vec(),
                    failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                });
            }
            return Ok(());
        }

        // Sort by mtime ascending (oldest first), then by path.
        job_dirs.sort_by(|a, b| {
            a.modified_secs
                .cmp(&b.modified_secs)
                .then_with(|| a.path.cmp(&b.path))
        });

        let keep_last_n = config.keep_last_n_jobs_per_lane as usize;
        let total_count = job_dirs.len();
        let protected_start = total_count.saturating_sub(keep_last_n);

        // Phase 1: TTL-based pruning outside keep-last-N window.
        for (idx, entry) in job_dirs.iter_mut().enumerate() {
            if idx >= protected_start {
                break;
            }
            if effective_ttl > 0 && entry.modified_secs.saturating_add(effective_ttl) <= now_secs {
                entry.pruned = true;
            }
        }

        // SENTINEL GUARD (MAJOR finding fix): If any entry has
        // `estimated_bytes == u64::MAX`, the recursive size estimator
        // encountered a traversal failure (depth overflow, scan-entry
        // overflow, or unreadable subtree via read_dir failure) and the
        // returned value is a fail-closed sentinel, NOT a real byte count.
        //
        // Fail-closed: mark the lane CORRUPT. Without accurate sizes,
        // retention decisions are unsound — an apparently small directory
        // may actually be enormous, so both TTL and byte-quota pruning
        // could make incorrect decisions. The lane must be repaired
        // (unreadable subtree fixed) before retention can resume.
        let has_size_overflow = job_dirs.iter().any(|e| e.estimated_bytes == u64::MAX);
        if has_size_overflow {
            // Collect paths of entries that triggered the sentinel for
            // diagnostic reporting.
            let sentinel_paths: Vec<String> = job_dirs
                .iter()
                .filter(|e| e.estimated_bytes == u64::MAX)
                .map(|e| e.path.display().to_string())
                .collect();
            return Err(LaneCleanupError::LogQuotaFailed {
                step: CLEANUP_STEP_LOG_QUOTA,
                reason: format!(
                    "size estimation returned u64::MAX sentinel for {} job log dir(s) \
                     under {} — indicates unreadable subtree, depth overflow, or \
                     scan-entry overflow (fail-closed: lane must be marked CORRUPT \
                     until obstruction is resolved). Affected paths: {:?}",
                    sentinel_paths.len(),
                    logs_dir.display(),
                    sentinel_paths,
                ),
                steps_completed: steps_completed.to_vec(),
                failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
            });
        }

        // Phase 2: Byte quota enforcement.
        if config.per_lane_log_max_bytes > 0 {
            let mut total_bytes: u64 = job_dirs
                .iter()
                .map(|e| e.estimated_bytes)
                .fold(0u64, u64::saturating_add);

            // Include bytes from invalid top-level files that survived
            // deletion so they count against the per-lane quota
            // (fail-closed: undeletable stray files are not invisible).
            total_bytes = total_bytes.saturating_add(stray_surviving_bytes);

            // Subtract bytes already marked for TTL pruning.
            for entry in &job_dirs {
                if entry.pruned {
                    total_bytes = total_bytes.saturating_sub(entry.estimated_bytes);
                }
            }

            if total_bytes > config.per_lane_log_max_bytes {
                for (idx, entry) in job_dirs.iter_mut().enumerate() {
                    if total_bytes <= config.per_lane_log_max_bytes {
                        break;
                    }
                    if idx >= protected_start {
                        break;
                    }
                    if entry.pruned {
                        continue;
                    }
                    entry.pruned = true;
                    total_bytes = total_bytes.saturating_sub(entry.estimated_bytes);
                }
            }
        }

        // Execute pruning via safe_rmtree for each marked directory.
        // Use elevated entry limit (MAX_LOG_DIR_ENTRIES) because job log
        // directories may legitimately exceed the default MAX_DIR_ENTRIES
        // (10,000). Without this, oversized log dirs become permanently
        // unprunable, causing the lane to be marked Corrupt on every
        // cleanup attempt (MAJOR-4 fix).
        for entry in &job_dirs {
            if !entry.pruned {
                continue;
            }
            match safe_rmtree_v1_with_entry_limit(&entry.path, logs_dir, MAX_LOG_DIR_ENTRIES) {
                Ok(_) => {},
                Err(err) => {
                    return Err(LaneCleanupError::LogQuotaFailed {
                        step: CLEANUP_STEP_LOG_QUOTA,
                        reason: format!(
                            "cannot prune log directory {}: {err}",
                            entry.path.display()
                        ),
                        steps_completed: steps_completed.to_vec(),
                        failure_step: Some(CLEANUP_STEP_LOG_QUOTA.to_string()),
                    });
                },
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_workspace_path(
        lanes_dir: &Path,
        workspace_path: &Path,
        steps_completed: &[String],
        step: &'static str,
    ) -> Result<PathBuf, LaneCleanupError> {
        let invalid_workspace_path = |reason: String| LaneCleanupError::GitCommandFailed {
            step,
            reason,
            steps_completed: steps_completed.to_vec(),
            failure_step: Some(step.to_string()),
        };

        let metadata = workspace_path.symlink_metadata().map_err(|e| {
            invalid_workspace_path(format!(
                "cannot stat workspace path {}: {e}",
                workspace_path.display()
            ))
        })?;

        if metadata.file_type().is_symlink() {
            return Err(invalid_workspace_path(format!(
                "workspace path {} is a symlink, which is not allowed",
                workspace_path.display()
            )));
        }

        if !metadata.is_dir() {
            return Err(invalid_workspace_path(format!(
                "workspace path {} is not a directory",
                workspace_path.display()
            )));
        }

        let git_path = workspace_path.join(".git");
        let git_metadata = git_path.symlink_metadata().map_err(|e| {
            invalid_workspace_path(format!(
                "workspace path {} must contain .git metadata: {e}",
                workspace_path.display()
            ))
        })?;

        if git_metadata.file_type().is_symlink() {
            return Err(invalid_workspace_path(format!(
                "workspace path {} has a symlink .git entry, which is not allowed",
                workspace_path.display()
            )));
        }

        let canonical_workspace = workspace_path.canonicalize().map_err(|e| {
            invalid_workspace_path(format!(
                "workspace path {} must canonicalize successfully: {e}",
                workspace_path.display()
            ))
        })?;

        let canonical_lanes_dir = lanes_dir.canonicalize().map_err(|e| {
            invalid_workspace_path(format!(
                "lane directory {} must canonicalize successfully: {e}",
                lanes_dir.display()
            ))
        })?;

        let canonical_git_dir = if git_metadata.is_file() {
            // NIT FIX: .git as a file is the standard git worktree pattern
            // (contains a `gitdir: <path>` pointer). Lane workspaces must use
            // a full .git directory, not a worktree .git file, because the
            // referenced gitdir may reside outside the lane boundary and the
            // cleanup state machine cannot safely validate or control it.
            return Err(invalid_workspace_path(
                "workspace .git is a file (git worktree), not a directory; \
                 lane workspaces require a full .git directory — \
                 git worktree .git files are not supported"
                    .to_string(),
            ));
        } else if git_metadata.is_dir() {
            let git_dir_metadata = git_path.symlink_metadata().map_err(|e| {
                invalid_workspace_path(format!(
                    "workspace path {} resolved gitdir could not be statted: {e}",
                    workspace_path.display()
                ))
            })?;

            if git_dir_metadata.file_type().is_symlink() {
                return Err(invalid_workspace_path(format!(
                    "workspace path {} has a symlink gitdir entry, which is not allowed",
                    workspace_path.display()
                )));
            }

            if !git_dir_metadata.is_dir() {
                return Err(invalid_workspace_path(format!(
                    "workspace path {} resolved gitdir is not a directory",
                    workspace_path.display()
                )));
            }

            git_path.canonicalize().map_err(|e| {
                invalid_workspace_path(format!(
                    "workspace path {} resolved gitdir could not be canonicalized: {e}",
                    workspace_path.display()
                ))
            })?
        } else {
            return Err(invalid_workspace_path(format!(
                "workspace path {} has invalid .git metadata",
                workspace_path.display()
            )));
        };

        if !canonical_git_dir.starts_with(&canonical_lanes_dir) {
            return Err(invalid_workspace_path(format!(
                "workspace path {} has gitdir outside lane directory {}",
                canonical_git_dir.display(),
                canonical_lanes_dir.display()
            )));
        }

        if !canonical_workspace.starts_with(&canonical_lanes_dir) {
            return Err(invalid_workspace_path(format!(
                "workspace path {} is outside lane directory {}",
                canonical_workspace.display(),
                lanes_dir.display()
            )));
        }

        Ok(canonical_workspace)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane State Derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive the effective lane state from lock state, lease record, and PID
/// liveness.
///
/// Stale lease detection rules (RFC-0019 §4.4, fail-closed):
/// - Lock free + lease RUNNING + PID alive → CORRUPT
/// - Lock free + corrupt marker (including missing lease) → CORRUPT until
///   marker is cleared explicitly via `LaneCorruptMarkerV1::remove()`
/// - Lock free + lease RUNNING + PID dead → IDLE (stale lease)
/// - Lock held + lease RUNNING → RUNNING
/// - Lock held + lease state other → use lease state
/// - Lock free + lease state != RUNNING → use lease state (or IDLE if terminal)
fn derive_lane_state(
    lock_held: bool,
    lease: Option<&LaneLeaseV1>,
    pid_alive: bool,
    has_corrupt_marker: bool,
) -> LaneState {
    if has_corrupt_marker {
        return LaneState::Corrupt;
    }

    match (lock_held, lease) {
        // Locked lane with no (or failed) lease state is still in LEASED
        // transitional state until lease metadata is refreshed.
        (true, None) => LaneState::Leased,

        // Lock free + active state (RUNNING/LEASED/CLEANUP) + PID alive →
        // ambiguous ownership → CORRUPT (fail-closed, INV-LANE-004).
        // Lock free + CORRUPT → remains CORRUPT regardless of PID.
        (false, Some(lease))
            if matches!(
                lease.state,
                LaneState::Running | LaneState::Leased | LaneState::Cleanup
            ) && pid_alive =>
        {
            LaneState::Corrupt
        },
        (false, Some(lease)) if lease.state == LaneState::Corrupt => LaneState::Corrupt,

        // Lock free + active state + PID dead → stale lease → IDLE.
        // Lock free + IDLE → IDLE.
        (false, Some(lease))
            if matches!(
                lease.state,
                LaneState::Running | LaneState::Leased | LaneState::Cleanup
            ) =>
        {
            LaneState::Idle
        },

        // For lease-present cases not handled above, use lease state. Lock-held
        // lanes use this path when lease state is available.
        (true | false, Some(lease)) => lease.state,

        // Lock free + no lease: idle.
        (false, None) => LaneState::Idle,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PID Liveness
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether a given PID is alive.
///
/// Uses `kill(pid, 0)` which checks for process existence without sending a
/// signal.
pub(crate) fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let Ok(pid_i32) = i32::try_from(pid) else {
        return false;
    };
    #[cfg(unix)]
    {
        // SAFETY: kill with signal 0 only checks for process existence.
        // This is a standard POSIX pattern. PID casting is validated against
        // platform bounds before invocation.
        #[allow(unsafe_code)]
        let result = unsafe { libc::kill(pid_i32, 0) };
        if result == 0 {
            return true;
        }
        // EPERM means the process exists but we don't have permission to
        // signal it. Treat as alive (fail-closed for stale detection).
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        errno == libc::EPERM
    }
    #[cfg(not(unix))]
    {
        // On non-Unix platforms, conservatively assume alive (fail-closed).
        let _ = pid;
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// File Lock Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Try to acquire an exclusive flock on a file (non-blocking).
///
/// Returns `Ok(true)` if the lock was acquired, `Ok(false)` if the file is
/// already locked by another process.
fn try_flock_exclusive(file: &File) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: flock is a standard POSIX call. fd is a valid file descriptor
        // owned by `file`. LOCK_EX | LOCK_NB is non-blocking exclusive lock.
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
        Err(err)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(true)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filesystem Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the APM2 home directory.
///
/// Checks `$APM2_HOME` first, then falls back to `~/.apm2`.
fn apm2_home_dir() -> Result<PathBuf, String> {
    if let Some(override_dir) = std::env::var_os("APM2_HOME") {
        let path = PathBuf::from(override_dir);
        if !path.as_os_str().is_empty() {
            return Ok(path);
        }
    }
    let base_dirs = directories::BaseDirs::new()
        .ok_or_else(|| "could not resolve home directory".to_string())?;
    Ok(base_dirs.home_dir().join(".apm2"))
}

/// Create a directory with restricted permissions (0o700) per CTR-2611.
/// In system-mode, shared-group execution contexts require 0o770.
///
/// Uses `DirBuilder` with mode set at create-time to avoid TOCTOU window.
/// Recursive: creates missing intermediate directories, each with the
/// restricted mode. Symlink paths are rejected via `ensure_safe_path`.
///
/// # Errors
///
/// Returns `LaneError::Io` on filesystem errors, or if the path contains
/// symlinks, or if an ancestor exists but is not a directory.
pub fn create_dir_restricted(path: &Path) -> Result<(), LaneError> {
    ensure_safe_path(path, "create_dir_restricted")?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.is_dir() {
            return Ok(());
        }
        return Err(LaneError::io(
            format!("expected directory at {}", path.display()),
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "path exists but is not a directory",
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mode = if matches!(select_backend(), Ok(ExecutionBackend::SystemMode)) {
            0o770
        } else {
            0o700
        };

        // CTR-2611: When `DirBuilder::recursive(true)` is used, the mode
        // only applies to the **leaf** directory; intermediate directories
        // are created with default permissions influenced by the process
        // umask. To ensure every newly created component has the restricted
        // mode, walk up from `path` to find the first existing ancestor,
        // then create each missing component individually with the desired
        // mode.
        let mut components_to_create: Vec<&std::path::Path> = Vec::new();
        let mut current = path;
        loop {
            match fs::symlink_metadata(current) {
                Ok(meta) if meta.is_dir() => break,
                Ok(_) => {
                    return Err(LaneError::io(
                        format!(
                            "ancestor path {} exists but is not a directory",
                            current.display()
                        ),
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "ancestor exists but is not a directory",
                        ),
                    ));
                },
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    components_to_create.push(current);
                    match current.parent() {
                        Some(parent) if parent != current => current = parent,
                        _ => break,
                    }
                },
                Err(e) => {
                    return Err(LaneError::io(
                        format!("stat ancestor {}", current.display()),
                        e,
                    ));
                },
            }
        }

        // Create missing components from outermost to innermost, each with
        // the restricted mode. Using `recursive(false)` so the mode is
        // applied to the single directory being created.
        for component in components_to_create.into_iter().rev() {
            match fs::DirBuilder::new()
                .recursive(false)
                .mode(mode)
                .create(component)
            {
                Ok(()) => {},
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // CTR-2611 TOCTOU mitigation: An attacker may plant a
                    // symlink between the initial `symlink_metadata` check
                    // (which returned NotFound) and this `DirBuilder::create`
                    // call.  Re-stat the path and fail-closed if it is not a
                    // real directory.
                    let meta = fs::symlink_metadata(component).map_err(|e2| {
                        LaneError::io(
                            format!("re-stat after AlreadyExists for {}", component.display()),
                            e2,
                        )
                    })?;
                    if !meta.is_dir() {
                        return Err(LaneError::io(
                            format!(
                                "path {} exists but is not a directory (possible symlink attack)",
                                component.display()
                            ),
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "existing path is not a directory",
                            ),
                        ));
                    }
                    // It is a genuine directory — tolerate the race.
                },
                Err(e) => {
                    return Err(LaneError::io(
                        format!("creating directory {}", component.display()),
                        e,
                    ));
                },
            }
        }

        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
            .map_err(|e| LaneError::io(format!("creating directory {}", path.display()), e))
    }
}

/// Ensure the parent directory of a path exists.
fn ensure_parent_dir(path: &Path) -> Result<(), LaneError> {
    if let Some(parent) = path.parent() {
        create_dir_restricted(parent)?;
    }
    Ok(())
}

/// Atomic write: write to temp file then rename (CTR-2607).
pub(crate) fn atomic_write(target: &Path, data: &[u8]) -> Result<(), LaneError> {
    ensure_safe_path(target, "atomic_write")?;
    ensure_parent_dir(target)?;
    if let Ok(metadata) = fs::symlink_metadata(target) {
        if metadata.is_dir() {
            return Err(LaneError::io(
                format!("target path is a directory: {}", target.display()),
                io::Error::new(io::ErrorKind::InvalidInput, "target must be a file"),
            ));
        }
    }
    let parent = target.parent().ok_or_else(|| {
        LaneError::io(
            format!("path has no parent: {}", target.display()),
            io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"),
        )
    })?;

    let temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| LaneError::io(format!("creating temp file in {}", parent.display()), e))?;

    // Set restrictive permissions on the temp file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        if let Err(e) = fs::set_permissions(temp.path(), perms) {
            tracing::warn!(path = %temp.path().display(), err = %e, "failed to set temp file permissions");
        }
    }

    let mut file = temp.as_file();
    file.write_all(data)
        .map_err(|e| LaneError::io(format!("writing temp file for {}", target.display()), e))?;
    file.sync_all()
        .map_err(|e| LaneError::io(format!("syncing temp file for {}", target.display()), e))?;

    temp.persist(target).map_err(|e| {
        LaneError::io(
            format!("renaming temp file to {}", target.display()),
            e.error,
        )
    })?;
    Ok(())
}

/// Read a file with a size bound (CTR-1603).
///
/// Streams into a bounded buffer to prevent memory exhaustion from crafted
/// files.
pub(crate) fn bounded_read_file(path: &Path, max_size: u64) -> Result<Vec<u8>, LaneError> {
    ensure_safe_path(path, "bounded_read_file")?;
    let mut file = open_file_no_follow(path)?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        let remaining = max_size.saturating_sub(buf.len() as u64);
        let read_len = if remaining == 0 {
            1u64
        } else {
            remaining.min(chunk.len() as u64)
        };
        let Ok(read_len) = usize::try_from(read_len) else {
            return Err(LaneError::io(
                format!(
                    "file {} exceeds maximum size {max_size} bytes",
                    path.display()
                ),
                io::Error::new(io::ErrorKind::InvalidData, "file too large"),
            ));
        };

        let n = file
            .read(&mut chunk[..read_len])
            .map_err(|e| LaneError::io(format!("reading {}", path.display()), e))?;
        if n == 0 {
            return Ok(buf);
        }

        buf.extend_from_slice(&chunk[..n]);
        if buf.len() as u64 > max_size {
            return Err(LaneError::io(
                format!(
                    "file {} exceeds maximum size {max_size} bytes",
                    path.display()
                ),
                io::Error::new(io::ErrorKind::InvalidData, "file too large"),
            ));
        }
    }
}

/// Open file for read without following symlinks on Unix.
fn open_file_no_follow(path: &Path) -> Result<File, LaneError> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        options
            .open(path)
            .map_err(|e| LaneError::io(format!("opening {}", path.display()), e))
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| LaneError::io(format!("opening {}", path.display()), e))
    }
}

fn open_lock_file(lock_path: &Path, create_if_missing: bool) -> Result<File, LaneError> {
    let is_symlink = match lock_path.symlink_metadata() {
        Ok(metadata) => metadata.file_type().is_symlink(),
        Err(e) if create_if_missing && e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(LaneError::io(
                format!("validating lock file path {}", lock_path.display()),
                e,
            ));
        },
    };

    if is_symlink {
        return Err(LaneError::io(
            format!("opening lock file {}", lock_path.display()),
            io::Error::new(io::ErrorKind::InvalidInput, "lock path is a symlink"),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).truncate(false);
    if create_if_missing {
        options.create(true);
    }

    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }

    options
        .open(lock_path)
        .map_err(|e| LaneError::io(format!("opening lock file {}", lock_path.display()), e))
}

fn lane_dir_lane_id(lane_dir: &Path) -> Result<&str, LaneError> {
    let lane_id = lane_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            LaneError::InvalidLaneId("lane directory name is invalid UTF-8".to_string())
        })?;
    if lane_id.is_empty() {
        return Err(LaneError::InvalidLaneId(
            "lane directory name is empty".to_string(),
        ));
    }

    Ok(lane_id)
}

fn ensure_safe_path(path: &Path, context: &str) -> Result<(), LaneError> {
    for component in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if component.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(component) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(LaneError::io(
                        format!(
                            "{context}: symlink component in path: {}",
                            component.display()
                        ),
                        io::Error::new(io::ErrorKind::InvalidInput, "symlink component detected"),
                    ));
                }
                if component != path && !metadata.is_dir() {
                    return Err(LaneError::io(
                        format!(
                            "{context}: non-directory path component: {}",
                            component.display()
                        ),
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "path component is not a directory",
                        ),
                    ));
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
            Err(e) => {
                return Err(LaneError::io(
                    format!("failed to validate path component: {}", component.display()),
                    e,
                ));
            },
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Validate a lane ID.
///
/// Lane IDs must be non-empty, ASCII alphanumeric with hyphens, and at most
/// `MAX_LANE_ID_LENGTH` bytes.
fn validate_lane_id(lane_id: &str) -> Result<(), LaneError> {
    if lane_id.is_empty() {
        return Err(LaneError::InvalidLaneId("lane ID is empty".to_string()));
    }
    if lane_id.len() > MAX_LANE_ID_LENGTH {
        return Err(LaneError::StringTooLong {
            field: "lane_id",
            actual: lane_id.len(),
            max: MAX_LANE_ID_LENGTH,
        });
    }
    // Only allow ASCII alphanumeric + hyphens + underscores (path safety,
    // CTR-2609).
    if !lane_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(LaneError::InvalidLaneId(format!(
            "lane ID contains invalid characters: {lane_id}"
        )));
    }
    // Prevent path traversal (CTR-2609)
    if lane_id.contains("..") || lane_id.starts_with('.') {
        return Err(LaneError::InvalidLaneId(format!(
            "lane ID contains path traversal: {lane_id}"
        )));
    }
    Ok(())
}

/// Validate a string field length.
const fn validate_string_field(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), LaneError> {
    if value.len() > max {
        return Err(LaneError::StringTooLong {
            field,
            actual: value.len(),
            max,
        });
    }
    Ok(())
}

/// Expected length of the hex portion of a `b3-256` digest (256 bits = 64 hex
/// chars).
const B3_256_HEX_LEN: usize = 64;

/// The canonical prefix for BLAKE3-256 digest strings.
const B3_256_PREFIX: &str = "b3-256:";

/// Validate that a digest string conforms to the canonical `b3-256:<64
/// lowercase hex>` format used for evidence artifact binding throughout FAC.
///
/// Returns `Ok(())` if the digest is valid, or `LaneError::InvalidDigestFormat`
/// with a descriptive reason if not. This is the single canonical validation
/// point so all callers (CLI, core, worker) share the same rules.
///
/// # Errors
///
/// Returns [`LaneError::InvalidDigestFormat`] if the digest does not match
/// the canonical `b3-256:` prefix followed by exactly 64 lowercase hex
/// characters.
pub fn validate_b3_256_digest(field: &'static str, digest: &str) -> Result<(), LaneError> {
    let Some(hex_part) = digest.strip_prefix(B3_256_PREFIX) else {
        return Err(LaneError::InvalidDigestFormat {
            field,
            reason: format!(
                "expected prefix '{B3_256_PREFIX}', got '{}'",
                digest
                    .get(..B3_256_PREFIX.len().min(digest.len()))
                    .unwrap_or(digest)
            ),
        });
    };

    if hex_part.len() != B3_256_HEX_LEN {
        return Err(LaneError::InvalidDigestFormat {
            field,
            reason: format!(
                "expected {B3_256_HEX_LEN} hex characters after prefix, got {}",
                hex_part.len()
            ),
        });
    }

    if !hex_part
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(LaneError::InvalidDigestFormat {
            field,
            reason: "hex portion must contain only lowercase hex characters (0-9, a-f)".to_string(),
        });
    }

    Ok(())
}

/// Return the current wall-clock time as an ISO-8601 string (UTC, second
/// precision).
///
/// # Clock Contract (CTR-2501)
///
/// This function reads wall-clock time (`chrono::Utc::now`) and is intended
/// **only** for human-readable audit labels (e.g., `detected_at` in corrupt
/// markers). It MUST NOT be used for monotonic ordering, timeout logic, or
/// distributed coordination. Callers requiring elapsed-time measurement
/// should use `std::time::Instant`.
#[must_use]
#[allow(clippy::disallowed_methods)]
pub fn current_time_iso8601() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Return the worse (higher-priority) of two reconcile outcomes.
///
/// Priority order: `Failed` > `MarkedCorrupt` > `Repaired` > `Ok` > `Skipped`.
/// Used to aggregate per-action outcomes into a single per-lane summary.
const fn worse_outcome(a: LaneReconcileOutcome, b: LaneReconcileOutcome) -> LaneReconcileOutcome {
    const fn severity(o: LaneReconcileOutcome) -> u8 {
        match o {
            LaneReconcileOutcome::Skipped => 0,
            LaneReconcileOutcome::Ok => 1,
            LaneReconcileOutcome::Repaired => 2,
            LaneReconcileOutcome::MarkedCorrupt => 3,
            LaneReconcileOutcome::Failed => 4,
        }
    }
    if severity(b) > severity(a) { b } else { a }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::policy;

    fn init_git_workspace(path: &Path) {
        if path.exists() {
            let _ = fs::remove_dir_all(path);
        }
        fs::create_dir_all(path).expect("create workspace");

        let init_output = std::process::Command::new("git")
            .args(["init"])
            .current_dir(path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("init git repo");
        assert!(
            init_output.status.success(),
            "git init should succeed, got {}",
            String::from_utf8_lossy(&init_output.stderr)
        );

        let set_name_output = std::process::Command::new("git")
            .args(["config", "user.name", "apm2 test"])
            .current_dir(path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("set git user name");
        assert!(
            set_name_output.status.success(),
            "git config user.name should succeed, got {}",
            String::from_utf8_lossy(&set_name_output.stderr)
        );

        let set_email_output = std::process::Command::new("git")
            .args(["config", "user.email", "test@apm2.local"])
            .current_dir(path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("set git user email");
        assert!(
            set_email_output.status.success(),
            "git config user.email should succeed, got {}",
            String::from_utf8_lossy(&set_email_output.stderr)
        );

        fs::write(path.join("README.md"), b"seed").expect("write seed file");
        let add_output = std::process::Command::new("git")
            .args(["add", "README.md"])
            .current_dir(path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git add");
        assert!(
            add_output.status.success(),
            "git add should succeed, got {}",
            String::from_utf8_lossy(&add_output.stderr)
        );

        let commit_output = std::process::Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git commit");
        assert!(
            commit_output.status.success(),
            "git commit should succeed, got {}",
            String::from_utf8_lossy(&commit_output.stderr)
        );
    }

    fn persist_running_lease(manager: &LaneManager, lane_id: &str) {
        let lane_dir = manager.lane_dir(lane_id);
        let lease = LaneLeaseV1::new(
            lane_id,
            "job_cleanup",
            std::process::id(),
            LaneState::Running,
            "2026-02-12T03:15:00Z",
            "b3-256:ph",
            "b3-256:th",
        )
        .expect("create lease");
        lease.persist(&lane_dir).expect("persist lease");
    }

    // ── Lane ID Validation ─────────────────────────────────────────────

    #[test]
    fn valid_lane_ids() {
        assert!(validate_lane_id("lane-00").is_ok());
        assert!(validate_lane_id("lane-01").is_ok());
        assert!(validate_lane_id("lane_test").is_ok());
        assert!(validate_lane_id("custom-lane-123").is_ok());
    }

    #[test]
    fn invalid_lane_ids() {
        // Empty
        assert!(validate_lane_id("").is_err());
        // Path traversal
        assert!(validate_lane_id("..").is_err());
        assert!(validate_lane_id(".hidden").is_err());
        // Invalid characters
        assert!(validate_lane_id("lane/00").is_err());
        assert!(validate_lane_id("lane 00").is_err());
        assert!(validate_lane_id("lane\x0000").is_err());
        // Too long
        let long_id = "a".repeat(MAX_LANE_ID_LENGTH + 1);
        assert!(validate_lane_id(&long_id).is_err());
    }

    #[test]
    fn max_length_lane_id_accepted() {
        let id = "a".repeat(MAX_LANE_ID_LENGTH);
        assert!(validate_lane_id(&id).is_ok());
    }

    // ── Default Lane IDs ───────────────────────────────────────────────

    #[test]
    fn default_lane_ids_are_valid() {
        let ids = LaneManager::default_lane_ids();
        assert!(!ids.is_empty());
        assert!(ids.len() <= MAX_LANE_COUNT);
        for id in &ids {
            assert!(validate_lane_id(id).is_ok());
            assert!(id.starts_with(LANE_ID_PREFIX));
        }
    }

    // ── LaneState Display ──────────────────────────────────────────────

    #[test]
    fn lane_state_display() {
        assert_eq!(LaneState::Idle.to_string(), "IDLE");
        assert_eq!(LaneState::Running.to_string(), "RUNNING");
        assert_eq!(LaneState::Corrupt.to_string(), "CORRUPT");
        assert_eq!(LaneState::Leased.to_string(), "LEASED");
        assert_eq!(LaneState::Cleanup.to_string(), "CLEANUP");
    }

    // ── LaneState Serialization ────────────────────────────────────────

    #[test]
    fn lane_state_serde_round_trip() {
        let states = [
            LaneState::Idle,
            LaneState::Leased,
            LaneState::Running,
            LaneState::Cleanup,
            LaneState::Corrupt,
        ];
        for state in &states {
            let json = serde_json::to_string(state).expect("serialize");
            let parsed: LaneState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*state, parsed, "round-trip failed for {state}");
        }
    }

    // ── LaneProfileV1 ──────────────────────────────────────────────────

    #[test]
    fn lane_profile_creation_and_hash() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:abc123", "boundary-00").expect("create profile");
        assert_eq!(profile.schema, LANE_PROFILE_V1_SCHEMA);
        assert_eq!(profile.lane_id, "lane-00");
        assert_eq!(profile.boundary_id, "boundary-00");
        let hash = profile.compute_hash().expect("compute hash");
        assert!(
            hash.starts_with("b3-256:"),
            "hash should have b3-256 prefix"
        );
        assert_eq!(hash.len(), 7 + 64, "b3-256 prefix + 64 hex chars");
    }

    #[test]
    fn lane_profile_hash_is_deterministic() {
        let p1 = LaneProfileV1::new("lane-00", "b3-256:abc", "boundary-00").expect("p1");
        let p2 = LaneProfileV1::new("lane-00", "b3-256:abc", "boundary-00").expect("p2");
        assert_eq!(
            p1.compute_hash().expect("h1"),
            p2.compute_hash().expect("h2"),
            "same inputs must produce same hash"
        );
    }

    #[test]
    fn lane_profile_hash_changes_with_input() {
        let p1 = LaneProfileV1::new("lane-00", "b3-256:aaa", "boundary-01").expect("p1");
        let p2 = LaneProfileV1::new("lane-01", "b3-256:aaa", "boundary-01").expect("p2");
        assert_ne!(
            p1.compute_hash().expect("h1"),
            p2.compute_hash().expect("h2"),
            "different lane IDs must produce different hashes"
        );
    }

    #[test]
    fn lane_profile_serde_round_trip() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:abc123", "boundary-00").expect("create profile");
        let json = serde_json::to_string_pretty(&profile).expect("serialize");
        let parsed: LaneProfileV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile, parsed);
    }

    #[test]
    fn lane_profile_rejects_unknown_fields() {
        let json = r#"{"schema":"apm2.fac.lane_profile.v1","lane_id":"lane-00","node_fingerprint":"x","boundary_id":"boundary-00","resource_profile":{"cpu_quota_percent":200,"memory_max_bytes":100,"pids_max":1536,"io_weight":100},"timeouts":{"test_timeout_seconds":600,"job_runtime_max_seconds":1800},"policy":{"fac_policy_hash":"","nextest_profile":"ci","deny_ambient_cargo_home":true},"extra_field":"evil"}"#;
        let result: Result<LaneProfileV1, _> = serde_json::from_str(json);
        assert!(result.is_err(), "must reject unknown fields (CTR-1604)");
    }

    #[test]
    fn lane_profile_persist_and_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:abc123", "boundary-00").expect("create profile");
        profile.persist(&lane_dir).expect("persist");
        let loaded = LaneProfileV1::load(&lane_dir).expect("load");
        assert_eq!(profile, loaded);
    }

    #[test]
    fn lane_profile_load_assigns_legacy_default_boundary_id_when_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");

        let node_fingerprint = "b3-256:legacy-fingerprint";
        let profile =
            LaneProfileV1::new("lane-00", node_fingerprint, "boundary-00").expect("create profile");
        let mut payload = serde_json::to_value(profile).expect("serialize");
        payload
            .as_object_mut()
            .expect("profile object")
            .remove("boundary_id");
        std::fs::write(
            lane_dir.join("profile.v1.json"),
            serde_json::to_vec_pretty(&payload).expect("serialize legacy profile"),
        )
        .expect("write legacy profile");

        let loaded = LaneProfileV1::load(&lane_dir).expect("load");
        assert_eq!(loaded.boundary_id, node_fingerprint);
    }

    #[test]
    fn resolve_host_test_parallelism_is_bounded_and_nonzero() {
        let parallelism = resolve_host_test_parallelism();
        assert!(parallelism >= 1);
    }

    #[test]
    fn compute_test_env_for_parallelism_sets_both_env_vars() {
        let env = compute_test_env_for_parallelism(3);
        assert_eq!(env.len(), 2);
        let threads = env
            .iter()
            .find(|(k, _)| k == "NEXTEST_TEST_THREADS")
            .and_then(|(_, v)| v.parse::<u32>().ok())
            .unwrap_or(0);
        let build_jobs = env
            .iter()
            .find(|(k, _)| k == "CARGO_BUILD_JOBS")
            .and_then(|(_, v)| v.parse::<u32>().ok())
            .unwrap_or(0);
        assert_eq!(threads, 3);
        assert_eq!(threads, build_jobs);
    }

    #[test]
    fn compute_test_env_for_parallelism_clamps_to_one() {
        let env = compute_test_env_for_parallelism(0);
        assert!(
            env.iter()
                .any(|(k, v)| k == "NEXTEST_TEST_THREADS" && v == "1")
        );
        assert!(env.iter().any(|(k, v)| k == "CARGO_BUILD_JOBS" && v == "1"));
    }

    #[test]
    fn lane_profile_enforces_test_timeout_cap_by_default() {
        let mut profile =
            LaneProfileV1::new("lane-00", "b3-256:abc123", "boundary-00").expect("create profile");
        profile.timeouts.test_timeout_seconds = MAX_TEST_TIMEOUT_SECONDS + 1;
        assert!(profile.validate_fac_test_caps(false).is_err());
        assert!(profile.validate_fac_test_caps(true).is_ok());
    }

    #[test]
    fn lane_profile_enforces_memory_cap_by_default() {
        let mut profile =
            LaneProfileV1::new("lane-00", "b3-256:abc123", "boundary-00").expect("create profile");
        profile.resource_profile.memory_max_bytes = MAX_MEMORY_MAX_BYTES + 1;
        assert!(profile.validate_fac_test_caps(false).is_err());
        assert!(profile.validate_fac_test_caps(true).is_ok());
    }

    // ── LaneLeaseV1 ────────────────────────────────────────────────────

    #[test]
    fn lane_lease_creation() {
        let lease = LaneLeaseV1::new(
            "lane-00",
            "job_20260212T031500Z_abc",
            12345,
            LaneState::Running,
            "2026-02-12T03:15:00Z",
            "b3-256:profile_hash",
            "b3-256:toolchain_hash",
        )
        .expect("create lease");
        assert_eq!(lease.schema, LANE_LEASE_V1_SCHEMA);
        assert_eq!(lease.lane_id, "lane-00");
        assert_eq!(lease.pid, 12345);
        assert_eq!(lease.state, LaneState::Running);
    }

    #[test]
    fn lane_lease_serde_round_trip() {
        let lease = LaneLeaseV1::new(
            "lane-00",
            "job_test",
            42,
            LaneState::Running,
            "2026-02-12T03:15:00Z",
            "b3-256:ph",
            "b3-256:th",
        )
        .expect("create lease");
        let json = serde_json::to_string_pretty(&lease).expect("serialize");
        let parsed: LaneLeaseV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(lease, parsed);
    }

    #[test]
    fn lane_lease_rejects_unknown_fields() {
        let json = r#"{"schema":"apm2.fac.lane_lease.v1","lane_id":"lane-00","job_id":"j","pid":1,"state":"RUNNING","started_at":"2026-02-12T03:15:00Z","lane_profile_hash":"h","toolchain_fingerprint":"f","extra":"evil"}"#;
        let result: Result<LaneLeaseV1, _> = serde_json::from_str(json);
        assert!(result.is_err(), "must reject unknown fields (CTR-1604)");
    }

    #[test]
    fn lane_lease_persist_load_remove() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");
        let lease = LaneLeaseV1::new(
            "lane-00",
            "job_test",
            42,
            LaneState::Running,
            "2026-02-12T03:15:00Z",
            "b3-256:ph",
            "b3-256:th",
        )
        .expect("create lease");

        // Persist
        lease.persist(&lane_dir).expect("persist");

        // Load
        let loaded = LaneLeaseV1::load(&lane_dir)
            .expect("load")
            .expect("should exist");
        assert_eq!(lease, loaded);

        // Remove
        LaneLeaseV1::remove(&lane_dir).expect("remove");
        let after_remove = LaneLeaseV1::load(&lane_dir).expect("load after remove");
        assert!(after_remove.is_none());
    }

    #[test]
    fn lane_lease_load_nonexistent_returns_none() {
        let dir = tempfile::tempdir().expect("temp dir");
        let result = LaneLeaseV1::load(dir.path()).expect("load");
        assert!(result.is_none());
    }

    #[test]
    fn lane_lease_remove_nonexistent_is_ok() {
        let dir = tempfile::tempdir().expect("temp dir");
        LaneLeaseV1::remove(dir.path()).expect("remove nonexistent should be OK");
    }

    // ── String Validation ──────────────────────────────────────────────

    #[test]
    fn lane_lease_rejects_oversized_job_id() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let result = LaneLeaseV1::new(
            "lane-00",
            &long_id,
            1,
            LaneState::Idle,
            "2026-01-01T00:00:00Z",
            "h",
            "f",
        );
        assert!(result.is_err());
    }

    #[test]
    fn lane_lease_rejects_non_rfc3339_started_at() {
        let result = LaneLeaseV1::new(
            "lane-00",
            "job-test",
            1,
            LaneState::Idle,
            "1735689600",
            "h",
            "f",
        );
        assert!(matches!(result, Err(LaneError::InvalidLease { .. })));
    }

    #[test]
    fn lane_lease_normalizes_started_at_to_utc_z() {
        let lease = LaneLeaseV1::new(
            "lane-00",
            "job-test",
            1,
            LaneState::Idle,
            "2026-02-12T04:15:00+01:00",
            "h",
            "f",
        )
        .expect("create lease");
        assert_eq!(lease.started_at, "2026-02-12T03:15:00Z");
    }

    #[test]
    fn lane_lease_helpers_parse_legacy_epoch_started_at() {
        let lease = LaneLeaseV1 {
            schema: LANE_LEASE_V1_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            job_id: "job-test".to_string(),
            pid: 1,
            state: LaneState::Leased,
            started_at: "1735689600".to_string(),
            lane_profile_hash: "h".to_string(),
            toolchain_fingerprint: "f".to_string(),
        };
        assert_eq!(lease.started_at_epoch_secs(), Some(1_735_689_600));
        assert_eq!(
            lease.started_at_rfc3339().as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
        assert_eq!(lease.age_secs(1_735_689_660), Some(60));
    }

    #[test]
    fn lane_lease_helpers_return_none_for_unparseable_started_at() {
        let lease = LaneLeaseV1 {
            schema: LANE_LEASE_V1_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            job_id: "job-test".to_string(),
            pid: 1,
            state: LaneState::Leased,
            started_at: "not-a-timestamp".to_string(),
            lane_profile_hash: "h".to_string(),
            toolchain_fingerprint: "f".to_string(),
        };
        assert!(lease.started_at_epoch_secs().is_none());
        assert!(lease.started_at_rfc3339().is_none());
        assert!(lease.age_secs(100).is_none());
    }

    #[test]
    fn lane_profile_load_rejects_schema_mismatch() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");

        let profile = LaneProfileV1::new("lane-00", "fp", "boundary-00").expect("create profile");
        let mut value = serde_json::to_value(profile).expect("to value");
        value["schema"] = serde_json::Value::String("apm2.fac.lane_profile.wrong".to_string());
        fs::write(
            lane_dir.join("profile.v1.json"),
            serde_json::to_vec_pretty(&value).expect("to json"),
        )
        .expect("write bad profile");

        let err = LaneProfileV1::load(&lane_dir).expect_err("schema mismatch should fail");
        match err {
            LaneError::InvalidRecord { lane_id, reason } => {
                assert_eq!(lane_id, "lane-00");
                assert!(
                    reason.contains("schema mismatch"),
                    "unexpected reason: {reason}"
                );
            },
            other => panic!("expected invalid record, got {other}"),
        }
    }

    #[test]
    fn lane_profile_load_rejects_lane_id_mismatch() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");

        let profile = LaneProfileV1::new("lane-00", "fp", "boundary-00").expect("create profile");
        let mut value = serde_json::to_value(profile).expect("to value");
        value["lane_id"] = serde_json::Value::String("lane-99".to_string());
        fs::write(
            lane_dir.join("profile.v1.json"),
            serde_json::to_vec_pretty(&value).expect("to json"),
        )
        .expect("write bad profile");

        let err = LaneProfileV1::load(&lane_dir).expect_err("lane_id mismatch should fail");
        match err {
            LaneError::InvalidRecord { lane_id, reason } => {
                assert_eq!(lane_id, "lane-00");
                assert!(
                    reason.contains("lane_id mismatch"),
                    "unexpected reason: {reason}"
                );
            },
            other => panic!("expected invalid record, got {other}"),
        }
    }

    #[test]
    fn lane_lease_load_rejects_schema_mismatch() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");

        let lease = LaneLeaseV1::new(
            "lane-00",
            "job_20260213T000000Z",
            123,
            LaneState::Running,
            "2026-02-13T00:00:00Z",
            "b3-256:ph",
            "b3-256:tf",
        )
        .expect("create lease");
        let mut value = serde_json::to_value(lease).expect("to value");
        value["schema"] = serde_json::Value::String("apm2.fac.lane_lease.wrong".to_string());
        fs::write(
            lane_dir.join("lease.v1.json"),
            serde_json::to_vec_pretty(&value).expect("to json"),
        )
        .expect("write bad lease");

        let err = LaneLeaseV1::load(&lane_dir).expect_err("schema mismatch should fail");
        match err {
            LaneError::InvalidRecord { lane_id, reason } => {
                assert_eq!(lane_id, "lane-00");
                assert!(
                    reason.contains("schema mismatch"),
                    "unexpected reason: {reason}"
                );
            },
            other => panic!("expected invalid record, got {other}"),
        }
    }

    #[test]
    fn lane_lease_load_rejects_lane_id_mismatch() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");

        let lease = LaneLeaseV1::new(
            "lane-00",
            "job_20260213T000000Z",
            123,
            LaneState::Running,
            "2026-02-13T00:00:00Z",
            "b3-256:ph",
            "b3-256:tf",
        )
        .expect("create lease");
        let mut value = serde_json::to_value(lease).expect("to value");
        value["lane_id"] = serde_json::Value::String("lane-99".to_string());
        fs::write(
            lane_dir.join("lease.v1.json"),
            serde_json::to_vec_pretty(&value).expect("to json"),
        )
        .expect("write bad lease");

        let err = LaneLeaseV1::load(&lane_dir).expect_err("lane_id mismatch should fail");
        match err {
            LaneError::InvalidRecord { lane_id, reason } => {
                assert_eq!(lane_id, "lane-00");
                assert!(
                    reason.contains("lane_id mismatch"),
                    "unexpected reason: {reason}"
                );
            },
            other => panic!("expected invalid record, got {other}"),
        }
    }

    #[test]
    fn lane_lease_load_rejects_oversized_started_at() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");

        let lease = LaneLeaseV1::new(
            "lane-00",
            "job_20260213T000000Z",
            123,
            LaneState::Running,
            "2026-02-13T00:00:00Z",
            "b3-256:ph",
            "b3-256:tf",
        )
        .expect("create lease");
        let mut value = serde_json::to_value(lease).expect("to value");
        value["started_at"] = serde_json::Value::String("x".repeat(MAX_STRING_LENGTH + 1));
        fs::write(
            lane_dir.join("lease.v1.json"),
            serde_json::to_vec_pretty(&value).expect("to json"),
        )
        .expect("write bad lease");

        let err = LaneLeaseV1::load(&lane_dir).expect_err("oversized started_at should fail");
        assert!(
            matches!(
                err,
                LaneError::StringTooLong {
                    field: "started_at",
                    ..
                }
            ),
            "expected started_at length failure, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_restricted_rejects_symlink_paths() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp dir");
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");

        let target = workspace.join("target_dir");
        fs::create_dir_all(&target).expect("create target");
        let symlink_path = workspace.join("symlink_dir");
        symlink(&target, &symlink_path).expect("create symlink dir");

        assert!(create_dir_restricted(&symlink_path.join("child")).is_err());
    }

    /// Regression test for TOCTOU symlink planting in `create_dir_restricted`.
    ///
    /// Simulates the race: a symlink exists at a path where
    /// `DirBuilder::create` returns `AlreadyExists`. The function must
    /// re-stat and reject the symlink (fail-closed) rather than silently
    /// accepting it.
    #[cfg(unix)]
    #[test]
    fn create_dir_restricted_rejects_symlink_on_already_exists() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path().join("base");
        fs::create_dir_all(&base).expect("create base");

        // Create a real target directory that the symlink will point to.
        let real_target = dir.path().join("real_target");
        fs::create_dir_all(&real_target).expect("create real target");

        // Plant a symlink at the path where create_dir_restricted will try to
        // create a directory.  DirBuilder::create will return AlreadyExists
        // because the symlink path already exists on the filesystem.
        let symlink_component = base.join("planted");
        symlink(&real_target, &symlink_component).expect("create symlink");

        // create_dir_restricted must fail-closed: the existing entry is a
        // symlink, not a real directory.
        let result = create_dir_restricted(&symlink_component);
        assert!(
            result.is_err(),
            "create_dir_restricted must reject a symlink that triggers AlreadyExists"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("not a directory") || err_msg.contains("symlink"),
            "error should mention symlink or not-a-directory: {err_msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_restricted_sets_mode_on_intermediates() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path().join("existing_base");
        fs::create_dir_all(&base).expect("create base");
        // Set base to 0o700 to match expected environment.
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("set base perms");

        // Create a deeply nested path where intermediate dirs don't exist.
        let deep_path = base.join("a").join("b").join("c");
        create_dir_restricted(&deep_path).expect("create deep path");

        // Verify all intermediate directories have the restricted mode
        // (0o700 in user-mode, which is the default).
        for component_name in &["a", "b", "c"] {
            let component_path = base.join(if *component_name == "a" {
                "a".to_string()
            } else if *component_name == "b" {
                "a/b".to_string()
            } else {
                "a/b/c".to_string()
            });
            let meta = fs::symlink_metadata(&component_path)
                .unwrap_or_else(|_| panic!("stat {}", component_path.display()));
            let mode = meta.permissions().mode() & 0o777;
            // In user-mode (default), the mode should be 0o700.
            assert_eq!(
                mode,
                0o700,
                "directory {} should have mode 0o700, got {mode:#o}",
                component_path.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp dir");
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");

        let target = workspace.join("target.txt");
        fs::write(&target, b"target").expect("write target");

        let symlink_path = workspace.join("target_link.json");
        symlink(&target, &symlink_path).expect("create symlink target");

        assert!(atomic_write(&symlink_path, b"payload").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_file_rejects_symlink_path() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp dir");
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");

        let target = workspace.join("target.json");
        fs::write(&target, b"{}").expect("write target");

        let link = workspace.join("target_link.json");
        symlink(&target, &link).expect("create symlink");

        let result = bounded_read_file(&link, 1024);
        assert!(result.is_err());
    }

    #[test]
    fn pid_above_i32_max_is_not_alive() {
        let pid = (i32::MAX as u32) + 1;
        assert!(!is_pid_alive(pid));
    }

    #[test]
    fn lane_profile_rejects_oversized_lane_id() {
        let long_id = "x".repeat(MAX_LANE_ID_LENGTH + 1);
        let result = LaneProfileV1::new(&long_id, "fp", "boundary-long");
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupt_marker_persist_load_remove() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");

        let lane_id = "lane-00";
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: "cleanup failed unexpectedly".to_string(),
            cleanup_receipt_digest: Some(
                "b3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            ),
            detected_at: "2026-02-15T00:00:00Z".to_string(),
        };

        marker.persist(&fac_root).expect("persist marker");
        let loaded = LaneCorruptMarkerV1::load(&fac_root, lane_id).expect("load marker");
        assert_eq!(loaded, Some(marker));

        LaneCorruptMarkerV1::remove(&fac_root, lane_id).expect("remove marker");
        assert!(
            LaneCorruptMarkerV1::load(&fac_root, lane_id)
                .expect("load after remove")
                .is_none()
        );
    }

    /// Helper: write a raw corrupt marker JSON to disk, bypassing `persist()`
    /// validation, so we can test that `load()` independently rejects
    /// malformed data.
    fn write_raw_corrupt_marker(fac_root: &Path, lane_id: &str, json: &[u8]) {
        let lane_dir = fac_root.join("lanes").join(lane_id);
        fs::create_dir_all(&lane_dir).expect("create lane dir");
        fs::write(lane_dir.join("corrupt.v1.json"), json).expect("write raw marker");
    }

    #[test]
    fn corrupt_marker_load_rejects_wrong_prefix_digest() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        let lane_id = "lane-00";

        // sha256: prefix instead of b3-256:
        let raw = serde_json::json!({
            "schema": LANE_CORRUPT_MARKER_SCHEMA,
            "lane_id": lane_id,
            "reason": "test",
            "cleanup_receipt_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "detected_at": "2026-02-15T00:00:00Z"
        });
        write_raw_corrupt_marker(&fac_root, lane_id, raw.to_string().as_bytes());

        let err = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect_err("load must reject digest with wrong prefix");
        assert!(
            matches!(err, LaneError::InvalidDigestFormat { .. }),
            "expected InvalidDigestFormat, got: {err:?}"
        );
    }

    #[test]
    fn corrupt_marker_load_rejects_too_short_digest() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        let lane_id = "lane-00";

        let raw = serde_json::json!({
            "schema": LANE_CORRUPT_MARKER_SCHEMA,
            "lane_id": lane_id,
            "reason": "test",
            "cleanup_receipt_digest": "b3-256:deadbeef",
            "detected_at": "2026-02-15T00:00:00Z"
        });
        write_raw_corrupt_marker(&fac_root, lane_id, raw.to_string().as_bytes());

        let err = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect_err("load must reject digest with too few hex chars");
        assert!(
            matches!(err, LaneError::InvalidDigestFormat { .. }),
            "expected InvalidDigestFormat, got: {err:?}"
        );
    }

    #[test]
    fn corrupt_marker_load_rejects_uppercase_hex_digest() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        let lane_id = "lane-00";

        let raw = serde_json::json!({
            "schema": LANE_CORRUPT_MARKER_SCHEMA,
            "lane_id": lane_id,
            "reason": "test",
            "cleanup_receipt_digest": "b3-256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "detected_at": "2026-02-15T00:00:00Z"
        });
        write_raw_corrupt_marker(&fac_root, lane_id, raw.to_string().as_bytes());

        let err = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect_err("load must reject digest with uppercase hex");
        assert!(
            matches!(err, LaneError::InvalidDigestFormat { .. }),
            "expected InvalidDigestFormat, got: {err:?}"
        );
    }

    #[test]
    fn corrupt_marker_load_rejects_non_hex_digest() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        let lane_id = "lane-00";

        let raw = serde_json::json!({
            "schema": LANE_CORRUPT_MARKER_SCHEMA,
            "lane_id": lane_id,
            "reason": "test",
            "cleanup_receipt_digest": "b3-256:not-a-digest-string-at-all-nope-not-valid-hex-chars-at-all!",
            "detected_at": "2026-02-15T00:00:00Z"
        });
        write_raw_corrupt_marker(&fac_root, lane_id, raw.to_string().as_bytes());

        let err = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect_err("load must reject digest with non-hex characters");
        assert!(
            matches!(err, LaneError::InvalidDigestFormat { .. }),
            "expected InvalidDigestFormat, got: {err:?}"
        );
    }

    #[test]
    fn corrupt_marker_load_rejects_missing_prefix_digest() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        let lane_id = "lane-00";

        // Bare hex without any prefix
        let raw = serde_json::json!({
            "schema": LANE_CORRUPT_MARKER_SCHEMA,
            "lane_id": lane_id,
            "reason": "test",
            "cleanup_receipt_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "detected_at": "2026-02-15T00:00:00Z"
        });
        write_raw_corrupt_marker(&fac_root, lane_id, raw.to_string().as_bytes());

        let err = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect_err("load must reject digest without b3-256: prefix");
        assert!(
            matches!(err, LaneError::InvalidDigestFormat { .. }),
            "expected InvalidDigestFormat, got: {err:?}"
        );
    }

    #[test]
    fn corrupt_marker_load_accepts_valid_digest() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        let lane_id = "lane-00";

        let valid_digest =
            "b3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let raw = serde_json::json!({
            "schema": LANE_CORRUPT_MARKER_SCHEMA,
            "lane_id": lane_id,
            "reason": "test",
            "cleanup_receipt_digest": valid_digest,
            "detected_at": "2026-02-15T00:00:00Z"
        });
        write_raw_corrupt_marker(&fac_root, lane_id, raw.to_string().as_bytes());

        let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect("load must succeed")
            .expect("marker must be present");
        assert_eq!(marker.cleanup_receipt_digest.as_deref(), Some(valid_digest));
    }

    #[test]
    fn corrupt_marker_load_accepts_none_digest() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        let lane_id = "lane-00";

        let raw = serde_json::json!({
            "schema": LANE_CORRUPT_MARKER_SCHEMA,
            "lane_id": lane_id,
            "reason": "test",
            "detected_at": "2026-02-15T00:00:00Z"
        });
        write_raw_corrupt_marker(&fac_root, lane_id, raw.to_string().as_bytes());

        let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
            .expect("load must succeed")
            .expect("marker must be present");
        assert_eq!(marker.cleanup_receipt_digest, None);
    }

    #[test]
    fn corrupt_marker_persist_rejects_invalid_schema() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");

        let marker = LaneCorruptMarkerV1 {
            schema: "bogus.schema.v99".to_string(),
            lane_id: "lane-00".to_string(),
            reason: "cleanup failed".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-02-15T00:00:00Z".to_string(),
        };

        let err = marker
            .persist(&fac_root)
            .expect_err("persist with wrong schema must fail");
        match &err {
            LaneError::InvalidRecord { lane_id, reason } => {
                assert_eq!(lane_id, "lane-00");
                assert!(
                    reason.contains("schema mismatch"),
                    "expected schema mismatch message, got: {reason}"
                );
            },
            other => panic!("expected InvalidRecord, got: {other:?}"),
        }

        // Verify no file was written to disk.
        let marker_path = fac_root
            .join("lanes")
            .join("lane-00")
            .join("corrupt.v1.json");
        assert!(
            !marker_path.exists(),
            "marker file must NOT exist after rejected persist"
        );
    }

    #[test]
    fn lane_manager_clear_corrupt_marker() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        let lane_id = "lane-00";
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: "test recovery".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-02-15T00:00:00Z".to_string(),
        };
        marker.persist(manager.fac_root()).expect("persist marker");

        manager.clear_corrupt_marker(lane_id).expect("clear marker");

        assert!(
            LaneCorruptMarkerV1::load(manager.fac_root(), lane_id)
                .expect("load marker")
                .is_none()
        );
    }

    #[test]
    fn lane_manager_mark_corrupt() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");

        let valid_digest =
            "b3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        manager
            .mark_corrupt("lane-00", "operator maintenance", Some(valid_digest))
            .expect("mark_corrupt should succeed");

        let marker = LaneCorruptMarkerV1::load(&fac_root, "lane-00")
            .expect("load marker")
            .expect("marker must be present");
        assert_eq!(marker.lane_id, "lane-00");
        assert_eq!(marker.reason, "operator maintenance");
        assert_eq!(marker.cleanup_receipt_digest.as_deref(), Some(valid_digest));
        // detected_at is now generated internally as ISO-8601; verify it is non-empty.
        assert!(!marker.detected_at.is_empty(), "detected_at must be set");
    }

    #[test]
    fn lane_manager_mark_corrupt_rejects_oversized_reason() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root).expect("create manager");

        let long_reason = "x".repeat(MAX_STRING_LENGTH + 1);
        let result = manager.mark_corrupt("lane-00", &long_reason, None);
        assert!(result.is_err(), "oversized reason must be rejected");
    }

    #[test]
    fn mark_corrupt_rejects_digest_missing_prefix() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root).expect("create manager");

        let result = manager.mark_corrupt(
            "lane-00",
            "test",
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        );
        assert!(
            matches!(result, Err(LaneError::InvalidDigestFormat { .. })),
            "digest without b3-256: prefix must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn mark_corrupt_rejects_digest_wrong_prefix() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root).expect("create manager");

        let result = manager.mark_corrupt(
            "lane-00",
            "test",
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        );
        assert!(
            matches!(result, Err(LaneError::InvalidDigestFormat { .. })),
            "digest with wrong prefix must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn mark_corrupt_rejects_digest_too_short() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root).expect("create manager");

        let result = manager.mark_corrupt("lane-00", "test", Some("b3-256:deadbeef"));
        assert!(
            matches!(result, Err(LaneError::InvalidDigestFormat { .. })),
            "digest with too few hex chars must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn mark_corrupt_rejects_digest_too_long() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root).expect("create manager");

        // 65 hex chars instead of 64
        let result = manager.mark_corrupt(
            "lane-00",
            "test",
            Some("b3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"),
        );
        assert!(
            matches!(result, Err(LaneError::InvalidDigestFormat { .. })),
            "digest with too many hex chars must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn mark_corrupt_rejects_digest_uppercase_hex() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root).expect("create manager");

        let result = manager.mark_corrupt(
            "lane-00",
            "test",
            Some("b3-256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"),
        );
        assert!(
            matches!(result, Err(LaneError::InvalidDigestFormat { .. })),
            "digest with uppercase hex must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn mark_corrupt_rejects_digest_non_hex_chars() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root).expect("create manager");

        let result = manager.mark_corrupt(
            "lane-00",
            "test",
            Some("b3-256:not-a-digest-string-at-all-nope-not-valid-hex-chars-at-all!"),
        );
        assert!(
            matches!(result, Err(LaneError::InvalidDigestFormat { .. })),
            "digest with non-hex chars must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn mark_corrupt_accepts_none_digest() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-00")).expect("create lane dir");
        let manager = LaneManager::new(fac_root).expect("create manager");

        manager
            .mark_corrupt("lane-00", "test reason", None)
            .expect("None digest must be accepted");
    }

    #[test]
    fn validate_b3_256_digest_accepts_valid() {
        validate_b3_256_digest(
            "test",
            "b3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid digest must be accepted");
    }

    #[test]
    fn validate_b3_256_digest_rejects_empty() {
        assert!(
            matches!(
                validate_b3_256_digest("test", ""),
                Err(LaneError::InvalidDigestFormat { .. })
            ),
            "empty string must be rejected"
        );
    }

    #[test]
    fn lane_manager_mark_corrupt_then_clear() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(fac_root.join("lanes").join("lane-01")).expect("create lane dir");
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");

        manager
            .mark_corrupt("lane-01", "test", None)
            .expect("mark_corrupt should succeed");

        // Marker should exist.
        assert!(
            LaneCorruptMarkerV1::load(&fac_root, "lane-01")
                .expect("load")
                .is_some()
        );

        // Clear it.
        manager.clear_corrupt_marker("lane-01").expect("clear");

        // Marker should be gone.
        assert!(
            LaneCorruptMarkerV1::load(&fac_root, "lane-01")
                .expect("load")
                .is_none()
        );
    }

    // ── Lane State Derivation ──────────────────────────────────────────

    fn make_lease(state: LaneState) -> LaneLeaseV1 {
        LaneLeaseV1 {
            schema: LANE_LEASE_V1_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            job_id: "job_test".to_string(),
            pid: 1,
            state,
            started_at: "2026-02-12T03:15:00Z".to_string(),
            lane_profile_hash: "h".to_string(),
            toolchain_fingerprint: "f".to_string(),
        }
    }

    #[test]
    fn derive_state_lock_held_running() {
        let lease = make_lease(LaneState::Running);
        assert_eq!(
            derive_lane_state(true, Some(&lease), true, false),
            LaneState::Running
        );
        assert_eq!(
            derive_lane_state(true, Some(&lease), false, false),
            LaneState::Running
        );
    }

    #[test]
    fn derive_state_lock_held_no_lease_is_leased() {
        assert_eq!(
            derive_lane_state(true, None, false, false),
            LaneState::Leased,
            "locked lane without lease should remain LEASED"
        );
    }

    #[test]
    fn derive_state_lock_free_no_lease_is_idle() {
        assert_eq!(
            derive_lane_state(false, None, false, false),
            LaneState::Idle,
            "unlocked lane without lease should be IDLE"
        );
    }

    #[test]
    fn enforce_log_quota_rejects_deep_directory_traversal() {
        let root = tempfile::tempdir().expect("temp dir");
        let logs_dir = root.path().join("logs");

        let mut depth_dir = logs_dir.clone();
        for level in 0..(MAX_LOG_QUOTA_DIR_DEPTH + 2) {
            depth_dir = depth_dir.join(format!("level_{level}"));
        }
        fs::create_dir_all(&depth_dir).expect("create deep logs directory");
        fs::write(depth_dir.join("deep.log"), b"payload").expect("write deep log file");

        let err = LaneManager::enforce_log_quota(&logs_dir, &[]).unwrap_err();
        assert!(matches!(err, LaneCleanupError::LogQuotaFailed { .. }));
        assert!(
            format!("{err}").contains("recursion depth exceeded"),
            "expected recursion-depth guard failure, got {err}"
        );
    }

    #[test]
    fn derive_state_lock_free_running_pid_alive_is_corrupt() {
        let lease = make_lease(LaneState::Running);
        assert_eq!(
            derive_lane_state(false, Some(&lease), true, false),
            LaneState::Corrupt,
            "lock free + RUNNING + PID alive → CORRUPT (fail-closed)"
        );
    }

    #[test]
    fn derive_state_lock_free_running_pid_dead_is_idle() {
        let lease = make_lease(LaneState::Running);
        assert_eq!(
            derive_lane_state(false, Some(&lease), false, false),
            LaneState::Idle,
            "lock free + RUNNING + PID dead → IDLE (stale lease)"
        );
    }

    #[test]
    fn derive_state_lock_free_corrupt_stays_corrupt() {
        let lease = make_lease(LaneState::Corrupt);
        assert_eq!(
            derive_lane_state(false, Some(&lease), false, false),
            LaneState::Corrupt
        );
        assert_eq!(
            derive_lane_state(false, Some(&lease), true, false),
            LaneState::Corrupt
        );
    }

    #[test]
    fn test_derive_lane_state_corrupt_marker() {
        let lease = make_lease(LaneState::Running);
        assert_eq!(
            derive_lane_state(false, Some(&lease), false, true),
            LaneState::Corrupt
        );
        assert_eq!(
            derive_lane_state(true, Some(&lease), false, true),
            LaneState::Corrupt
        );
        assert_eq!(
            derive_lane_state(false, None, false, true),
            LaneState::Corrupt,
            "corrupt marker remains authoritative when lease is absent"
        );
    }

    #[test]
    fn derive_state_lock_free_leased_pid_alive_is_corrupt() {
        let lease = make_lease(LaneState::Leased);
        assert_eq!(
            derive_lane_state(false, Some(&lease), true, false),
            LaneState::Corrupt,
            "lock free + LEASED + PID alive → CORRUPT (fail-closed)"
        );
    }

    #[test]
    fn derive_state_lock_free_leased_pid_dead_is_idle() {
        let lease = make_lease(LaneState::Leased);
        assert_eq!(
            derive_lane_state(false, Some(&lease), false, false),
            LaneState::Idle
        );
    }

    #[test]
    fn derive_state_lock_free_idle_is_idle() {
        let lease = make_lease(LaneState::Idle);
        assert_eq!(
            derive_lane_state(false, Some(&lease), false, false),
            LaneState::Idle
        );
        assert_eq!(
            derive_lane_state(false, Some(&lease), true, false),
            LaneState::Idle
        );
    }

    #[test]
    fn test_lane_status_shows_corrupt_reason() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: "cleanup failed".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-02-15T00:00:00Z".to_string(),
        };
        marker.persist(manager.fac_root()).expect("persist marker");

        let status = manager.lane_status(lane_id).expect("lane status");
        assert_eq!(status.state, LaneState::Corrupt);
        assert_eq!(status.corrupt_reason.as_deref(), Some("cleanup failed"));
    }

    #[test]
    fn run_lane_cleanup_transitions_to_corrupt_on_failure() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let workspace = manager.lane_dir(lane_id).join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");
        let guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("acquire lock");

        persist_running_lease(&manager, lane_id);

        let err = manager
            .run_lane_cleanup(lane_id, &workspace)
            .expect_err("cleanup fails when workspace is not a repo");
        assert!(matches!(err, LaneCleanupError::GitCommandFailed { .. }));
        assert_eq!(
            err.failure_step().expect("failure step"),
            CLEANUP_STEP_WORKSPACE_VALIDATION,
        );

        let status_during = manager.lane_status(lane_id).expect("status during failure");
        assert_eq!(status_during.state, LaneState::Corrupt);

        drop(guard);
        let status_after = manager.lane_status(lane_id).expect("status after release");
        assert_eq!(status_after.state, LaneState::Corrupt);
    }

    #[test]
    fn run_lane_cleanup_transitions_to_idle_on_success() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        let steps_completed = manager
            .run_lane_cleanup(lane_id, &workspace)
            .expect("lane cleanup should succeed");
        assert_eq!(
            steps_completed,
            vec![
                CLEANUP_STEP_GIT_RESET.to_string(),
                CLEANUP_STEP_GIT_CLEAN.to_string(),
                CLEANUP_STEP_TEMP_PRUNE.to_string(),
                CLEANUP_STEP_ENV_DIR_PRUNE.to_string(),
                CLEANUP_STEP_LOG_QUOTA.to_string(),
            ],
            "all steps should be reported",
        );

        for &env_subdir in policy::LANE_ENV_DIRS {
            assert!(
                !lane_dir.join(env_subdir).exists(),
                "{env_subdir} should be removed during lane cleanup"
            );
        }

        let status = manager.lane_status(lane_id).expect("status");
        assert_eq!(status.state, LaneState::Idle);
        assert!(LaneLeaseV1::load(&lane_dir).expect("load lease").is_none());
    }

    #[test]
    fn run_lane_cleanup_removes_all_env_dirs() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        for &env_subdir in policy::LANE_ENV_DIRS {
            let env_dir = lane_dir.join(env_subdir);
            fs::create_dir_all(&env_dir).expect("create env dir");
            fs::write(env_dir.join("stale-state"), b"stale").expect("write stale env state");
        }

        manager
            .run_lane_cleanup(lane_id, &workspace)
            .expect("lane cleanup should succeed");

        for &env_subdir in policy::LANE_ENV_DIRS {
            assert!(
                !lane_dir.join(env_subdir).exists(),
                "{env_subdir} should be deleted during cleanup"
            );
        }
    }

    #[test]
    fn run_lane_cleanup_deeply_nested_logs_succeeds() {
        // With enforce_log_retention (TCK-00571), cleanup operates at the
        // job-log-directory level (immediate children of logs/). Deep
        // nesting inside a job log directory is not a failure condition
        // because the scanner does not recurse into job dirs — it only
        // examines top-level entries. This test verifies that deeply
        // nested content inside a single job log dir does NOT cause a
        // cleanup failure.
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        let logs_dir = lane_dir.join("logs");
        // Create a single job-log directory with deeply nested content.
        let mut depth_dir = logs_dir.join("job-deep");
        for level in 0..20 {
            depth_dir = depth_dir.join(format!("level_{level}"));
        }
        fs::create_dir_all(&depth_dir).expect("create deep logs directory");
        fs::write(depth_dir.join("deep.log"), b"payload").expect("write deep log file");

        let steps = manager
            .run_lane_cleanup(lane_id, &workspace)
            .expect("cleanup should succeed — deep nesting is inside a job dir");
        assert!(
            steps.contains(&CLEANUP_STEP_LOG_QUOTA.to_string()),
            "log quota step should have completed"
        );
    }

    /// Regression test: top-level regular files and symlinks under logs/ are
    /// removed by `enforce_log_retention` (fail-closed). Stray files cannot
    /// bypass per-lane log-retention controls, and symlinks are never valid
    /// under logs/.
    #[test]
    fn run_lane_cleanup_removes_top_level_files_and_symlinks_in_logs() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        let logs_dir = lane_dir.join("logs");

        // Create a stray regular file directly under logs/.
        let stray_file = logs_dir.join("stray-file.log");
        fs::write(&stray_file, vec![0u8; 1024]).expect("write stray file");

        // Create a legitimate job log directory alongside the stray file.
        let job_dir = logs_dir.join("job-001");
        fs::create_dir_all(&job_dir).expect("create job dir");
        fs::write(job_dir.join("output.log"), b"job output").expect("write job log");

        // Create a symlink directly under logs/ (unix only).
        #[cfg(unix)]
        {
            let symlink_path = logs_dir.join("symlink-escape");
            let _ = std::os::unix::fs::symlink("/tmp", &symlink_path);
            assert!(
                symlink_path.symlink_metadata().is_ok(),
                "symlink should exist before cleanup"
            );
        }

        let steps = manager
            .run_lane_cleanup(lane_id, &workspace)
            .expect("cleanup should succeed");
        assert!(
            steps.contains(&CLEANUP_STEP_LOG_QUOTA.to_string()),
            "log quota step should have completed"
        );

        // Stray file must be removed (fail-closed: files under logs/
        // are never valid job-log directories).
        assert!(
            !stray_file.exists(),
            "stray regular file under logs/ must be removed by cleanup"
        );

        // Symlink must be removed (fail-closed: symlinks under logs/
        // are never valid).
        #[cfg(unix)]
        {
            let symlink_path = logs_dir.join("symlink-escape");
            assert!(
                symlink_path.symlink_metadata().is_err(),
                "symlink under logs/ must be removed by cleanup"
            );
        }
    }

    /// Regression (security finding f-759-security-*-0): when a symlink under
    /// logs/ cannot be deleted (e.g., parent directory made read-only), cleanup
    /// MUST return an error rather than silently ignoring the surviving
    /// symlink.
    #[cfg(unix)]
    #[test]
    fn cleanup_errors_on_undeletable_symlink_in_logs() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        let logs_dir = lane_dir.join("logs");

        // Create a symlink directly under logs/.
        let symlink_path = logs_dir.join("symlink-escape");
        std::os::unix::fs::symlink("/tmp", &symlink_path).expect("create symlink");
        assert!(
            symlink_path.symlink_metadata().is_ok(),
            "symlink should exist before cleanup"
        );

        // Make the logs directory read-only so remove_file will fail
        // with PermissionDenied.
        let original_perms = fs::metadata(&logs_dir).expect("metadata").permissions();
        let mut readonly = original_perms.clone();
        readonly.set_mode(0o555);
        fs::set_permissions(&logs_dir, readonly).expect("set readonly");

        // Cleanup must fail because the symlink cannot be deleted.
        let result = manager.run_lane_cleanup(lane_id, &workspace);

        // Restore permissions before assertions so tempdir cleanup works.
        fs::set_permissions(&logs_dir, original_perms).expect("restore perms");

        let err = result.expect_err(
            "cleanup must fail when symlink under logs/ cannot be deleted (fail-closed)",
        );
        assert!(
            matches!(err, LaneCleanupError::LogQuotaFailed { .. }),
            "expected LogQuotaFailed, got: {err:?}"
        );
        let reason = match &err {
            LaneCleanupError::LogQuotaFailed { reason, .. } => reason.clone(),
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(
            reason.contains("symlink"),
            "error reason should mention symlink, got: {reason}"
        );
    }

    /// Regression (security finding f-759-security-*-0): when an invalid
    /// top-level file under logs/ cannot be deleted (e.g., parent directory
    /// made read-only), the file's bytes MUST be included in quota
    /// calculations so the surviving entry counts against the lane's byte
    /// limit.  When stray surviving bytes push total usage above the quota,
    /// the function attempts to prune job directories; if pruning also fails
    /// (read-only directory), the function returns an error rather than
    /// silently accepting the over-quota state.
    #[cfg(unix)]
    #[test]
    fn cleanup_accounts_bytes_for_undeletable_stray_file_in_logs() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        let logs_dir = lane_dir.join("logs");

        // Create a large stray file (50 KiB) directly under logs/.
        let stray_file = logs_dir.join("stray-undeletable.bin");
        fs::write(&stray_file, vec![0u8; 50 * 1024]).expect("write stray file");

        // Create a legitimate job log directory (~1 KiB).
        let job_dir = logs_dir.join("job-001");
        fs::create_dir_all(&job_dir).expect("create job dir");
        fs::write(job_dir.join("output.log"), vec![0u8; 1024]).expect("write job log");

        // Use a byte quota small enough that stray_surviving_bytes (50 KiB)
        // alone exceeds it. Without fail-closed byte accounting, total would
        // be ~1 KiB (job dir only) which is under quota. WITH stray byte
        // accounting, total is ~51 KiB which exceeds the 10 KiB quota,
        // triggering eviction of the job dir. Since logs/ is read-only,
        // the eviction via safe_rmtree fails, producing an error.
        let retention = crate::fac::gc::LogRetentionConfig {
            per_lane_log_max_bytes: 10 * 1024, // 10 KiB — less than the stray file
            per_job_log_ttl_secs: 0,
            keep_last_n_jobs_per_lane: 0,
        };

        // Make the logs directory read-only so that:
        // 1. remove_file on the stray file fails → bytes go to stray_surviving_bytes
        // 2. safe_rmtree on job-001 also fails → error returned
        let original_perms = fs::metadata(&logs_dir).expect("metadata").permissions();
        let mut readonly = original_perms.clone();
        readonly.set_mode(0o555);
        fs::set_permissions(&logs_dir, readonly).expect("set readonly on logs");

        // Run cleanup with retention config.
        let result = manager.run_lane_cleanup_with_retention(lane_id, &workspace, &retention);

        // Restore permissions before assertions so tempdir cleanup works.
        fs::set_permissions(&logs_dir, original_perms).expect("restore perms");

        // The cleanup must fail: stray bytes push total over quota, job dir
        // pruning is attempted but fails on the read-only directory.
        let err = result.expect_err(
            "cleanup must fail when stray surviving bytes push usage above quota \
             and subsequent pruning cannot proceed (fail-closed byte accounting)",
        );
        assert!(
            matches!(err, LaneCleanupError::LogQuotaFailed { .. }),
            "expected LogQuotaFailed, got: {err:?}"
        );
    }

    /// Regression (security finding f-759-security-*-0): when an invalid
    /// top-level file under logs/ cannot be deleted and no job directories
    /// exist, the function MUST return an error rather than Ok(()).
    #[cfg(unix)]
    #[test]
    fn cleanup_errors_on_undeletable_stray_file_with_no_job_dirs() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        let logs_dir = lane_dir.join("logs");

        // Create only a stray file (no job directories).
        let stray_file = logs_dir.join("stray-orphan.bin");
        fs::write(&stray_file, vec![0u8; 4096]).expect("write stray file");

        // Make logs/ unwritable so remove_file will fail.
        let original_perms = fs::metadata(&logs_dir).expect("metadata").permissions();
        let mut readonly = original_perms.clone();
        readonly.set_mode(0o555);
        fs::set_permissions(&logs_dir, readonly).expect("set readonly on logs");

        let result = manager.run_lane_cleanup_with_retention(
            lane_id,
            &workspace,
            &crate::fac::gc::LogRetentionConfig::default(),
        );

        // Restore permissions for tempdir cleanup.
        fs::set_permissions(&logs_dir, original_perms).expect("restore perms");

        let err = result.expect_err(
            "cleanup must fail when undeletable stray files exist and no job \
             directories are present (fail-closed: no silent accumulation)",
        );
        assert!(
            matches!(err, LaneCleanupError::LogQuotaFailed { .. }),
            "expected LogQuotaFailed, got: {err:?}"
        );
        let reason = match &err {
            LaneCleanupError::LogQuotaFailed { reason, .. } => reason.clone(),
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(
            reason.contains("undeletable") || reason.contains("cannot delete"),
            "error reason should mention undeletable stray entries, got: {reason}"
        );
    }

    #[test]
    fn run_lane_cleanup_rejects_workspace_outside_lane_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let foreign_workspace = root.path().join("foreign_workspace");
        init_git_workspace(&foreign_workspace);
        persist_running_lease(&manager, lane_id);

        let err = manager
            .run_lane_cleanup(lane_id, &foreign_workspace)
            .expect_err("workspace outside lane directory should be rejected");
        assert!(matches!(err, LaneCleanupError::GitCommandFailed { .. }));
        assert_eq!(
            err.failure_step().expect("failure step"),
            CLEANUP_STEP_WORKSPACE_VALIDATION,
        );
        let status = manager.lane_status(lane_id).expect("lane status");
        assert_eq!(status.state, LaneState::Corrupt);
    }

    #[test]
    fn run_lane_cleanup_rejects_gitdir_indirection_outside_lane_directory() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");

        let foreign_git_dir = root.path().join("foreign_git");
        fs::create_dir_all(&foreign_git_dir).expect("create foreign git dir");
        fs::write(
            workspace.join(".git"),
            format!("gitdir: {}\n", foreign_git_dir.display()),
        )
        .expect("write gitdir file");

        persist_running_lease(&manager, lane_id);

        let err = manager
            .run_lane_cleanup(lane_id, &workspace)
            .expect_err("gitdir indirection outside lane directory should be rejected");
        assert!(matches!(err, LaneCleanupError::GitCommandFailed { .. }));
        assert_eq!(
            err.failure_step().expect("failure step"),
            CLEANUP_STEP_WORKSPACE_VALIDATION,
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_lane_cleanup_rejects_workspace_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        let workspace_link = lane_dir.join("workspace_link");
        symlink(&workspace, &workspace_link).expect("create workspace symlink");

        persist_running_lease(&manager, lane_id);

        let err = manager
            .run_lane_cleanup(lane_id, &workspace_link)
            .expect_err("symlink workspace path should be rejected");
        assert!(matches!(err, LaneCleanupError::GitCommandFailed { .. }));
        assert_eq!(
            err.failure_step().expect("failure step"),
            CLEANUP_STEP_WORKSPACE_VALIDATION,
        );
    }

    #[test]
    fn collect_log_entries_rejects_too_many_entries() {
        let logs_dir = tempfile::tempdir().expect("tempdir");
        for idx in 0..=MAX_LOG_ENTRIES {
            fs::write(logs_dir.path().join(format!("log_{idx}")), b"entry").expect("write log");
        }

        let mut entries = Vec::new();
        let mut total_size = 0;
        let steps_completed = Vec::new();
        let err = LaneManager::collect_log_entries(
            logs_dir.path(),
            &mut entries,
            &mut total_size,
            0,
            &steps_completed,
        )
        .expect_err("collecting too many log entries should fail");
        assert!(matches!(err, LaneCleanupError::LogQuotaFailed { .. }));
        assert_eq!(entries.len(), MAX_LOG_ENTRIES);
        assert!(total_size > 0);
    }

    #[test]
    fn collect_log_entries_rejects_dir_entry_flood() {
        // Regression test for directory-flood DoS prevention
        // (f-685-security-1771184894734689-0). The read_dir iteration must
        // be bounded by MAX_DIR_ENTRIES, including subdirectories.
        let logs_dir = tempfile::tempdir().expect("tempdir");
        // Create MAX_DIR_ENTRIES + 1 subdirectories (all count toward the
        // per-directory breadth limit).
        for idx in 0..=MAX_DIR_ENTRIES {
            fs::create_dir(logs_dir.path().join(format!("subdir_{idx}"))).expect("create subdir");
        }

        let mut entries = Vec::new();
        let mut total_size = 0;
        let steps_completed = Vec::new();
        let err = LaneManager::collect_log_entries(
            logs_dir.path(),
            &mut entries,
            &mut total_size,
            0,
            &steps_completed,
        )
        .expect_err("directory-flood should be rejected");
        assert!(matches!(err, LaneCleanupError::LogQuotaFailed { .. }));
        let reason = match &err {
            LaneCleanupError::LogQuotaFailed { reason, .. } => reason.clone(),
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(
            reason.contains("directory-flood DoS prevention"),
            "error reason should mention DoS prevention, got: {reason}"
        );
    }

    #[test]
    fn lane_status_with_unreadable_lease_and_lock_held_is_leased() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let lease_path = lane_dir.join("lease.v1.json");
        fs::write(&lease_path, b"{invalid lease json").expect("write corrupted lease");

        let guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("acquire lock");

        let status = manager.lane_status(lane_id).expect("lane status");
        assert_eq!(status.state, LaneState::Leased);
        drop(guard);
    }

    // ── PID Liveness ───────────────────────────────────────────────────

    #[test]
    fn pid_zero_is_not_alive() {
        assert!(!is_pid_alive(0));
    }

    #[test]
    fn current_pid_is_alive() {
        let pid = std::process::id();
        assert!(is_pid_alive(pid), "current process should be alive");
    }

    #[test]
    fn nonexistent_pid_is_not_alive() {
        // PID 4_000_000 is extremely unlikely to exist
        assert!(!is_pid_alive(4_000_000));
    }

    // ── LaneManager ────────────────────────────────────────────────────

    #[test]
    fn lane_manager_directory_structure() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        // Manually create to make it absolute
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        manager.ensure_directories().expect("ensure dirs");

        let lane_ids = LaneManager::default_lane_ids();
        for lane_id in &lane_ids {
            let lane_dir = manager.lane_dir(lane_id);
            assert!(
                lane_dir.join("workspace").exists(),
                "workspace dir should exist for {lane_id}"
            );
            assert!(
                lane_dir.join("target").exists(),
                "target dir should exist for {lane_id}"
            );
            assert!(
                lane_dir.join("logs").exists(),
                "logs dir should exist for {lane_id}"
            );
        }
        assert!(
            manager.fac_root().join("locks").join("lanes").exists(),
            "lock dir should exist"
        );
    }

    #[test]
    fn lane_manager_lock_acquire_and_release() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";

        // Acquire lock
        let guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("should acquire");
        assert!(
            manager.is_lock_held(lane_id).expect("check held"),
            "lock should be held"
        );

        // Drop guard → lock released
        drop(guard);
        assert!(
            !manager.is_lock_held(lane_id).expect("check released"),
            "lock should be released after drop"
        );
    }

    #[test]
    fn lane_manager_try_lock_returns_none_when_held() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("acquire");

        // Second attempt should return None
        let second = manager.try_lock(lane_id).expect("second try_lock");
        assert!(
            second.is_none(),
            "should not acquire lock when already held"
        );
        drop(guard);
    }

    #[test]
    fn lane_manager_status_idle_no_lease() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let status = manager.lane_status("lane-00").expect("status");
        assert_eq!(status.state, LaneState::Idle);
        assert!(status.job_id.is_none());
        assert!(!status.lock_held);
    }

    #[test]
    fn lane_manager_status_with_lease_and_lock() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);

        // Write a lease with current PID
        let pid = std::process::id();
        let lease = LaneLeaseV1::new(
            lane_id,
            "job_test",
            pid,
            LaneState::Running,
            "2026-02-12T03:15:00Z",
            "b3-256:ph",
            "b3-256:th",
        )
        .expect("create lease");
        lease.persist(&lane_dir).expect("persist lease");

        // Acquire lock
        let guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("acquire");

        let status = manager.lane_status(lane_id).expect("status");
        assert_eq!(status.state, LaneState::Running);
        assert_eq!(status.job_id.as_deref(), Some("job_test"));
        assert_eq!(status.pid, Some(pid));
        assert!(status.lock_held);
        assert_eq!(status.pid_alive, Some(true));
        drop(guard);
    }

    #[test]
    fn lane_manager_status_normalizes_legacy_epoch_started_at() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let lease = LaneLeaseV1::new(
            lane_id,
            "job_test",
            std::process::id(),
            LaneState::Running,
            "2026-02-12T03:15:00Z",
            "b3-256:ph",
            "b3-256:th",
        )
        .expect("create lease");
        let mut value = serde_json::to_value(lease).expect("to value");
        value["started_at"] = serde_json::Value::String("1735689600".to_string());
        fs::write(
            lane_dir.join("lease.v1.json"),
            serde_json::to_vec_pretty(&value).expect("to json"),
        )
        .expect("write legacy lease");

        let guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("acquire");
        let status = manager.lane_status(lane_id).expect("status");
        assert_eq!(
            status.started_at.as_deref(),
            Some("2025-01-01T00:00:00Z"),
            "legacy epoch lease should be exposed as canonical RFC3339"
        );
        drop(guard);
    }

    #[test]
    fn lane_manager_status_stale_lease_pid_dead() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);

        // Write a lease with a dead PID
        let lease = LaneLeaseV1::new(
            lane_id,
            "job_stale",
            4_000_000, // extremely unlikely to exist
            LaneState::Running,
            "2026-02-12T03:15:00Z",
            "b3-256:ph",
            "b3-256:th",
        )
        .expect("create lease");
        lease.persist(&lane_dir).expect("persist lease");

        // No lock held + RUNNING + PID dead → IDLE
        let status = manager.lane_status(lane_id).expect("status");
        assert_eq!(
            status.state,
            LaneState::Idle,
            "stale lease with dead PID should be IDLE"
        );
        assert!(!status.lock_held);
        assert_eq!(status.pid_alive, Some(false));
    }

    #[test]
    fn lane_manager_all_statuses() {
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let statuses = manager.all_lane_statuses().expect("all statuses");
        let expected_count = LaneManager::lane_count();
        assert_eq!(
            statuses.len(),
            expected_count,
            "should have one status per lane"
        );
        for status in &statuses {
            assert_eq!(status.state, LaneState::Idle);
        }
    }

    // ── Bounded Read ───────────────────────────────────────────────────

    #[test]
    fn bounded_read_file_enforces_cap() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("big.json");
        let data = vec![b'x'; 1024];
        fs::write(&path, &data).expect("write");

        // Should succeed with large cap
        let result = bounded_read_file(&path, 2048);
        assert!(result.is_ok());

        // Should fail with small cap
        let result = bounded_read_file(&path, 512);
        assert!(result.is_err());
    }

    // ── Atomic Write ───────────────────────────────────────────────────

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("test.json");
        atomic_write(&path, b"hello").expect("write");
        let contents = fs::read_to_string(&path).expect("read");
        assert_eq!(contents, "hello");
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("test.json");
        atomic_write(&path, b"first").expect("write 1");
        atomic_write(&path, b"second").expect("write 2");
        let contents = fs::read_to_string(&path).expect("read");
        assert_eq!(contents, "second");
    }

    #[cfg(unix)]
    #[test]
    fn lane_manager_try_lock_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lock_path = manager.lock_path(lane_id);
        let target = root.path().join("real_lock_target");
        fs::write(&target, b"target").expect("write target");
        symlink(&target, &lock_path).expect("create symlink lock path");

        let err = manager
            .try_lock(lane_id)
            .expect_err("try_lock should reject symlinked lock path");
        match err {
            LaneError::Io { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
            },
            other => panic!("expected io error, got {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn lane_manager_is_lock_held_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lock_path = manager.lock_path(lane_id);
        let target = root.path().join("real_lock_target_for_status");
        fs::write(&target, b"target").expect("write target");
        symlink(&target, &lock_path).expect("create symlink lock path");

        let err = manager
            .is_lock_held(lane_id)
            .expect_err("is_lock_held should reject symlinked lock path");
        match err {
            LaneError::Io { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
            },
            other => panic!("expected io error, got {other}"),
        }
    }

    // ── Concurrency Test ───────────────────────────────────────────────

    #[test]
    fn concurrent_lock_acquisition_is_exclusive() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = Arc::new(LaneManager::new(fac_root).expect("create manager"));
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let barrier = Arc::new(Barrier::new(4));
        let acquired_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let m = Arc::clone(&manager);
            let b = Arc::clone(&barrier);
            let count = Arc::clone(&acquired_count);
            let lid = lane_id.to_string();
            handles.push(std::thread::spawn(move || {
                b.wait();
                if let Ok(Some(guard)) = m.try_lock(&lid) {
                    count.fetch_add(1, Ordering::SeqCst);
                    // Hold the lock briefly
                    std::thread::sleep(Duration::from_millis(50));
                    drop(guard);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread join");
        }

        assert_eq!(
            acquired_count.load(Ordering::SeqCst),
            1,
            "exactly one thread should have acquired the lock"
        );
    }

    #[test]
    fn build_isolated_git_command_sets_config_isolation() {
        // SEC-CTRL-LANE-CLEANUP-001: Verify that the isolated git command
        // sets the expected environment variables and config overrides to
        // prevent LPE via malicious .git/config entries.
        let workspace = PathBuf::from("/tmp/test-workspace");
        let cmd = build_isolated_git_command(&workspace);
        let envs: Vec<(String, String)> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().to_string(),
                    v?.to_string_lossy().to_string(),
                ))
            })
            .collect();

        // Verify GIT_CONFIG_GLOBAL=/dev/null
        assert!(
            envs.iter()
                .any(|(k, v)| k == "GIT_CONFIG_GLOBAL" && v == "/dev/null"),
            "GIT_CONFIG_GLOBAL must be set to /dev/null, got: {envs:?}"
        );
        // Verify GIT_CONFIG_SYSTEM=/dev/null
        assert!(
            envs.iter()
                .any(|(k, v)| k == "GIT_CONFIG_SYSTEM" && v == "/dev/null"),
            "GIT_CONFIG_SYSTEM must be set to /dev/null, got: {envs:?}"
        );
        // Verify GIT_TERMINAL_PROMPT=0
        assert!(
            envs.iter()
                .any(|(k, v)| k == "GIT_TERMINAL_PROMPT" && v == "0"),
            "GIT_TERMINAL_PROMPT must be set to 0, got: {envs:?}"
        );

        // Verify -c config overrides and --no-optional-locks in the args.
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let args_str = args.join(" ");
        assert!(
            args_str.contains("core.fsmonitor="),
            "must override core.fsmonitor, got args: {args_str}"
        );
        assert!(
            args_str.contains("core.pager=cat"),
            "must override core.pager, got args: {args_str}"
        );
        assert!(
            args_str.contains("core.editor=:"),
            "must override core.editor, got args: {args_str}"
        );
        assert!(
            args_str.contains("--no-optional-locks"),
            "must include --no-optional-locks, got args: {args_str}"
        );
    }

    #[test]
    fn run_lane_cleanup_uses_config_isolated_git_commands() {
        // SEC-CTRL-LANE-CLEANUP-001: End-to-end test that lane cleanup
        // succeeds even when the workspace has a malicious core.fsmonitor
        // config. If config isolation were not applied, git reset/clean
        // would try to execute the malicious command and fail (since the
        // configured command does not exist).
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        // Plant a malicious core.fsmonitor in the workspace's .git/config.
        // Without config isolation, git reset would try to execute this
        // nonexistent command and fail.
        let git_config_path = workspace.join(".git").join("config");
        let mut config_content = fs::read_to_string(&git_config_path).unwrap_or_default();
        config_content.push_str("\n[core]\n\tfsmonitor = /nonexistent/malicious-command\n");
        fs::write(&git_config_path, &config_content).expect("plant malicious git config");

        // Cleanup should succeed because config isolation overrides the
        // malicious core.fsmonitor with an empty value.
        let steps = manager
            .run_lane_cleanup(lane_id, &workspace)
            .expect("lane cleanup should succeed despite malicious git config");
        assert!(
            steps.contains(&CLEANUP_STEP_GIT_RESET.to_string()),
            "git reset should have completed"
        );
        assert!(
            steps.contains(&CLEANUP_STEP_GIT_CLEAN.to_string()),
            "git clean should have completed"
        );
    }

    // ── TCK-00571: Log retention cleanup tests ──────────────────────────

    #[test]
    fn run_lane_cleanup_with_retention_prunes_stale_job_dirs() {
        // CQ-BLOCKER-1 regression: run_lane_cleanup_with_retention must use
        // the provided LogRetentionConfig, not a hardcoded 100 MiB quota.
        let root = tempfile::tempdir().expect("temp dir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = &lane_ids[0];
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        let logs_dir = lane_dir.join("logs");

        // Initialize a git repo in the workspace.
        let out = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&workspace)
            .output()
            .expect("git init");
        assert!(out.status.success(), "git init must succeed");
        let out = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@test.com",
                "commit",
                "--allow-empty",
                "-m",
                "init",
            ])
            .current_dir(&workspace)
            .output()
            .expect("git commit");
        assert!(out.status.success(), "git commit must succeed");

        // Create a lease so run_lane_cleanup_with_retention can proceed.
        let lease = LaneLeaseV1 {
            schema: LANE_LEASE_V1_SCHEMA.to_string(),
            lane_id: lane_id.clone(),
            state: LaneState::Running,
            job_id: "test-job".to_string(),
            pid: std::process::id(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            toolchain_fingerprint: "test-fp".to_string(),
            lane_profile_hash:
                "b3-256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
        };
        lease.persist(&lane_dir).expect("persist lease");

        // Create job log directories — one stale (will be pruned), one fresh.
        let stale_dir = logs_dir.join("job-stale");
        fs::create_dir_all(&stale_dir).expect("create stale dir");
        let stale_file = stale_dir.join("output.log");
        let file = std::fs::File::create(&stale_file).expect("create file");
        file.set_len(100).expect("set len");
        // Backdate the directory mtime to 30 days ago.
        // SECURITY JUSTIFICATION (CTR-2501): Test-only wall-clock usage for
        // backdating file mtime; not a coordination or consensus path.
        #[allow(clippy::disallowed_methods)]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        #[allow(clippy::cast_possible_wrap)]
        let stale_time = filetime::FileTime::from_unix_time((now - 30 * 86400) as i64, 0);
        filetime::set_file_mtime(&stale_dir, stale_time).expect("set mtime");

        let fresh_dir = logs_dir.join("job-fresh");
        fs::create_dir_all(&fresh_dir).expect("create fresh dir");
        let fresh_file = fresh_dir.join("output.log");
        let file = std::fs::File::create(&fresh_file).expect("create file");
        file.set_len(100).expect("set len");

        // Use a short TTL to demonstrate that the config is actually used.
        let retention = crate::fac::gc::LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: 86400, // 1 day
            keep_last_n_jobs_per_lane: 0,
        };

        let steps = manager
            .run_lane_cleanup_with_retention(lane_id, &workspace, &retention)
            .expect("cleanup should succeed");

        assert!(
            steps.contains(&CLEANUP_STEP_LOG_QUOTA.to_string()),
            "log quota step should have completed"
        );
        // The stale directory should have been pruned.
        assert!(
            !stale_dir.exists(),
            "stale job log dir must be pruned by retention policy"
        );
        // The fresh directory should still exist.
        assert!(fresh_dir.exists(), "fresh job log dir must be retained");
    }

    // ── Init and Reconcile Tests (TCK-00539) ────────────────────────────

    #[test]
    fn init_lanes_creates_profiles_and_directories() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");

        let receipt = manager.init_lanes().expect("init_lanes");

        // Verify receipt structure.
        assert_eq!(receipt.schema, LANE_INIT_RECEIPT_SCHEMA);
        assert_eq!(receipt.lane_count, LaneManager::lane_count());
        assert!(!receipt.lanes_created.is_empty());
        assert!(receipt.lanes_existing.is_empty());
        assert_eq!(receipt.profiles.len(), receipt.lane_count);

        // Verify all profiles were created.
        for entry in &receipt.profiles {
            assert!(entry.created);
            assert!(entry.profile_hash.starts_with("b3-256:"));
        }

        // Verify directories exist on disk.
        let lane_ids = LaneManager::default_lane_ids();
        for lane_id in &lane_ids {
            let lane_dir = manager.lane_dir(lane_id);
            assert!(lane_dir.join("workspace").is_dir());
            assert!(lane_dir.join("target").is_dir());
            assert!(lane_dir.join("logs").is_dir());
            assert!(lane_dir.join("profile.v1.json").is_file());
        }

        // TCK-00589: Verify receipt was persisted under receipts/ (not legacy
        // evidence/).
        let receipts_dir = fac_root.join("receipts");
        assert!(receipts_dir.is_dir());
        let entry_count = fs::read_dir(&receipts_dir)
            .expect("read receipts dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("lane_init_"))
            .count();
        assert_eq!(entry_count, 1, "exactly one init receipt should exist");

        // TCK-00589: Verify legacy evidence/ directory is NOT created.
        let legacy_evidence_dir = fac_root.join("evidence");
        assert!(
            !legacy_evidence_dir.exists(),
            "legacy evidence/ directory must not be created by init_lanes"
        );
    }

    #[test]
    fn init_lanes_is_idempotent() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        let first = manager.init_lanes().expect("first init");
        let second = manager.init_lanes().expect("second init");

        // Second run should find all lanes existing, none created.
        assert!(second.lanes_created.is_empty());
        assert_eq!(second.lanes_existing.len(), first.lane_count);

        // Profile hashes should match.
        for (a, b) in first.profiles.iter().zip(second.profiles.iter()) {
            assert_eq!(a.lane_id, b.lane_id);
            assert_eq!(a.profile_hash, b.profile_hash);
        }
    }

    #[test]
    fn reconcile_lanes_reports_ok_for_healthy_pool() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        // Init first to create a healthy pool.
        manager.init_lanes().expect("init_lanes");

        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        assert_eq!(receipt.schema, LANE_RECONCILE_RECEIPT_SCHEMA);
        assert_eq!(receipt.lanes_inspected, LaneManager::lane_count());
        assert_eq!(receipt.lanes_ok, LaneManager::lane_count());
        assert_eq!(receipt.lanes_repaired, 0);
        assert_eq!(receipt.lanes_marked_corrupt, 0);
        assert_eq!(receipt.lanes_failed, 0);
    }

    #[test]
    fn reconcile_repairs_missing_profile() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        // Init first.
        manager.init_lanes().expect("init_lanes");

        // Delete one profile.
        let lane_id = &LaneManager::default_lane_ids()[0];
        let profile_path = manager.lane_dir(lane_id).join("profile.v1.json");
        fs::remove_file(&profile_path).expect("remove profile");

        // Reconcile should repair it.
        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        assert!(receipt.lanes_repaired > 0);
        assert!(profile_path.is_file(), "profile should be recreated");
    }

    #[test]
    fn reconcile_repairs_missing_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        // Init first.
        manager.init_lanes().expect("init_lanes");

        // Delete the workspace dir of the first lane.
        let lane_id = &LaneManager::default_lane_ids()[0];
        let workspace = manager.lane_dir(lane_id).join("workspace");
        fs::remove_dir_all(&workspace).expect("remove workspace");

        // Reconcile should repair it.
        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        assert!(receipt.lanes_repaired > 0);
        assert!(workspace.is_dir(), "workspace should be recreated");
    }

    #[test]
    fn reconcile_reports_existing_corrupt_markers() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");

        // Init first.
        manager.init_lanes().expect("init_lanes");

        // Create a corrupt marker on lane-00.
        let lane_id = "lane-00";
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: "test corruption".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "1234567890".to_string(),
        };
        marker.persist(&fac_root).expect("persist corrupt marker");

        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        // Should report the corrupt marker as skipped.
        let skip_count = receipt
            .actions
            .iter()
            .filter(|a| {
                a.lane_id == lane_id
                    && a.action == "existing_corrupt_marker"
                    && a.outcome == LaneReconcileOutcome::Skipped
            })
            .count();
        assert_eq!(skip_count, 1, "should report existing corrupt marker");
    }

    #[test]
    fn reconcile_reaps_orphan_leased_lane_with_dead_pid() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        manager.init_lanes().expect("init_lanes");
        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);

        // Simulate orphaned lease: LEASED state with dead pid.
        let lease = LaneLeaseV1::new(
            lane_id,
            "job-orphan",
            4_000_000,
            LaneState::Leased,
            "2026-01-01T00:00:00Z",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "b3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect("lease");
        lease.persist(&lane_dir).expect("persist lease");

        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        assert!(
            receipt.actions.iter().any(|action| {
                action.lane_id == lane_id
                    && action.action == "reap_orphan_lease"
                    && action.outcome == LaneReconcileOutcome::Repaired
            }),
            "expected reap_orphan_lease repaired action, got: {:?}",
            receipt.actions
        );
        assert!(
            LaneLeaseV1::load(&lane_dir)
                .expect("load lane lease")
                .is_none(),
            "orphaned lease should be removed"
        );
        let status = manager.lane_status(lane_id).expect("lane status");
        assert_eq!(status.state, LaneState::Idle, "lane should return to IDLE");
    }

    #[test]
    fn reconcile_detects_orphan_leased_lane_without_pid_when_lock_held() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        manager.init_lanes().expect("init_lanes");
        let lane_id = "lane-00";

        // Hold the lock without writing a lease: lane_status derives LEASED with
        // pid=None, matching the observed orphaned state from production.
        let _guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("acquire lock");

        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");
        assert!(
            receipt.actions.iter().any(|action| {
                action.lane_id == lane_id
                    && action.action == "reap_orphan_lease"
                    && action.outcome == LaneReconcileOutcome::Failed
                    && action
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("lock is held"))
            }),
            "expected failed orphan-lease reap action for lock-held lane, got: {:?}",
            receipt.actions
        );
    }

    #[test]
    fn init_receipt_roundtrips_through_json() {
        let receipt = LaneInitReceiptV1 {
            schema: LANE_INIT_RECEIPT_SCHEMA.to_string(),
            lane_count: 3,
            lanes_created: vec!["lane-00".to_string()],
            lanes_existing: vec!["lane-01".to_string(), "lane-02".to_string()],
            profiles: vec![
                LaneInitProfileEntry {
                    lane_id: "lane-00".to_string(),
                    profile_hash: "b3-256:abcd".to_string(),
                    created: true,
                },
                LaneInitProfileEntry {
                    lane_id: "lane-01".to_string(),
                    profile_hash: "b3-256:ef01".to_string(),
                    created: false,
                },
            ],
            node_fingerprint:
                "b3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            boundary_id: "apm2.fac.local".to_string(),
        };

        let json = serde_json::to_string(&receipt).expect("serialize");
        let deserialized: LaneInitReceiptV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, deserialized);
    }

    #[test]
    fn reconcile_receipt_roundtrips_through_json() {
        let receipt = LaneReconcileReceiptV1 {
            schema: LANE_RECONCILE_RECEIPT_SCHEMA.to_string(),
            lanes_inspected: 3,
            lanes_ok: 2,
            lanes_repaired: 1,
            lanes_marked_corrupt: 0,
            lanes_failed: 0,
            infrastructure_failures: 0,
            actions: vec![LaneReconcileAction {
                lane_id: "lane-00".to_string(),
                action: "create_dir_workspace".to_string(),
                outcome: LaneReconcileOutcome::Repaired,
                detail: None,
            }],
        };

        let json = serde_json::to_string(&receipt).expect("serialize");
        let deserialized: LaneReconcileReceiptV1 =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, deserialized);
    }

    // ── Regression tests for review findings (PR #719 code-quality round) ───

    /// Regression: corrupt-marked lane with missing workspace/profile must NOT
    /// be repaired. Only a single Skipped action should be emitted and no
    /// directories or profiles should be recreated.
    #[test]
    fn reconcile_skips_corrupt_lane_no_repair_even_with_missing_dirs() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");

        // Init first to create a healthy pool.
        manager.init_lanes().expect("init_lanes");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);

        // Place a corrupt marker.
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            reason: "test corruption".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "1234567890".to_string(),
        };
        marker.persist(&fac_root).expect("persist corrupt marker");

        // Delete the workspace dir AND the profile to simulate missing state.
        let workspace = lane_dir.join("workspace");
        let profile = lane_dir.join("profile.v1.json");
        fs::remove_dir_all(&workspace).expect("remove workspace");
        fs::remove_file(&profile).expect("remove profile");

        // Reconcile.
        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        // Only a single Skipped action for this lane, no repair actions.
        let lane_actions: Vec<_> = receipt
            .actions
            .iter()
            .filter(|a| a.lane_id == lane_id)
            .collect();
        assert_eq!(
            lane_actions.len(),
            1,
            "corrupt-marked lane must emit exactly one action, got: {lane_actions:?}"
        );
        assert_eq!(lane_actions[0].outcome, LaneReconcileOutcome::Skipped);
        assert_eq!(lane_actions[0].action, "existing_corrupt_marker");

        // Verify no files were recreated.
        assert!(
            !workspace.exists(),
            "workspace must NOT be recreated for corrupt-marked lane"
        );
        assert!(
            !profile.exists(),
            "profile must NOT be recreated for corrupt-marked lane"
        );
    }

    /// Regression: lane counters are lane-level, not action-level. A single
    /// lane with multiple repairs (e.g., missing workspace + missing profile)
    /// must report exactly 1 repaired lane, and counters must never exceed
    /// `lanes_inspected`.
    #[test]
    fn reconcile_receipt_counts_lanes_not_actions() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        // Init first.
        manager.init_lanes().expect("init_lanes");

        let lane_id = &LaneManager::default_lane_ids()[0];
        let lane_dir = manager.lane_dir(lane_id);

        // Delete BOTH workspace dir AND profile to trigger multiple repairs on
        // a single lane.
        let workspace = lane_dir.join("workspace");
        let profile = lane_dir.join("profile.v1.json");
        fs::remove_dir_all(&workspace).expect("remove workspace");
        fs::remove_file(&profile).expect("remove profile");

        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        // Verify lane-level counters.
        let total = receipt.lanes_ok
            + receipt.lanes_repaired
            + receipt.lanes_marked_corrupt
            + receipt.lanes_failed;
        assert!(
            total <= receipt.lanes_inspected,
            "lane counters ({total}) must not exceed lanes_inspected ({})",
            receipt.lanes_inspected
        );

        // The single lane with multiple repairs should count as exactly 1
        // repaired lane.
        assert_eq!(
            receipt.lanes_repaired, 1,
            "one lane with multiple repairs should count as exactly 1 repaired lane"
        );

        // Remaining lanes are OK (no damage).
        let expected_ok = LaneManager::lane_count() - 1;
        assert_eq!(
            receipt.lanes_ok, expected_ok,
            "remaining lanes should be OK"
        );

        // Per-action detail should still record both individual repairs.
        let repair_actions: Vec<_> = receipt
            .actions
            .iter()
            .filter(|a| a.lane_id == *lane_id && a.outcome == LaneReconcileOutcome::Repaired)
            .collect();
        assert!(
            repair_actions.len() >= 2,
            "per-action detail should record at least 2 repair actions for the lane, got {}",
            repair_actions.len()
        );
    }

    /// Regression: verify `build_reconcile_receipt` aggregates per-lane with
    /// the `worse_outcome` priority (`Failed` > `MarkedCorrupt` >
    /// `Repaired` > `Ok` > `Skipped`).
    #[test]
    fn build_receipt_aggregates_per_lane_worst_outcome() {
        let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
        let actions = vec![
            // lane-00: two Repaired actions → should count as 1 repaired lane.
            LaneReconcileAction {
                lane_id: "lane-00".to_string(),
                action: "create_dir_workspace".to_string(),
                outcome: LaneReconcileOutcome::Repaired,
                detail: None,
            },
            LaneReconcileAction {
                lane_id: "lane-00".to_string(),
                action: "write_default_profile".to_string(),
                outcome: LaneReconcileOutcome::Repaired,
                detail: None,
            },
            // lane-01: one Ok action → should count as 1 ok lane.
            LaneReconcileAction {
                lane_id: "lane-01".to_string(),
                action: "inspect".to_string(),
                outcome: LaneReconcileOutcome::Ok,
                detail: None,
            },
        ];

        let receipt = LaneManager::build_reconcile_receipt(&lane_ids, actions);

        assert_eq!(receipt.lanes_inspected, 2);
        assert_eq!(receipt.lanes_ok, 1);
        assert_eq!(receipt.lanes_repaired, 1);
        assert_eq!(receipt.lanes_marked_corrupt, 0);
        assert_eq!(receipt.lanes_failed, 0);

        // Counters never exceed lanes_inspected.
        let total = receipt.lanes_ok
            + receipt.lanes_repaired
            + receipt.lanes_marked_corrupt
            + receipt.lanes_failed;
        assert!(total <= receipt.lanes_inspected);
    }

    /// Regression: verify `worse_outcome` escalation ordering.
    #[test]
    fn worse_outcome_priority_ordering() {
        // Failed dominates everything.
        assert_eq!(
            worse_outcome(LaneReconcileOutcome::Repaired, LaneReconcileOutcome::Failed),
            LaneReconcileOutcome::Failed
        );
        assert_eq!(
            worse_outcome(LaneReconcileOutcome::Failed, LaneReconcileOutcome::Ok),
            LaneReconcileOutcome::Failed
        );

        // MarkedCorrupt dominates Repaired/Ok/Skipped.
        assert_eq!(
            worse_outcome(
                LaneReconcileOutcome::Repaired,
                LaneReconcileOutcome::MarkedCorrupt
            ),
            LaneReconcileOutcome::MarkedCorrupt
        );

        // Repaired dominates Ok.
        assert_eq!(
            worse_outcome(LaneReconcileOutcome::Ok, LaneReconcileOutcome::Repaired),
            LaneReconcileOutcome::Repaired
        );

        // Ok dominates Skipped.
        assert_eq!(
            worse_outcome(LaneReconcileOutcome::Skipped, LaneReconcileOutcome::Ok),
            LaneReconcileOutcome::Ok
        );

        // Same outcome is idempotent.
        assert_eq!(
            worse_outcome(
                LaneReconcileOutcome::Repaired,
                LaneReconcileOutcome::Repaired
            ),
            LaneReconcileOutcome::Repaired
        );
    }

    // ── Regression tests for PR #719 round 2 findings ─────────────────────

    /// Regression (Finding 1 & 3): lock-dir creation failure must be counted
    /// as an infrastructure failure and cause the reconcile receipt to report
    /// non-zero `infrastructure_failures`. Simulated by placing a regular file
    /// at the lock-dir path so `create_dir_restricted` fails.
    #[test]
    fn reconcile_lock_dir_failure_counts_infrastructure_failure() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");

        // Init first so lanes exist and are healthy.
        manager.init_lanes().expect("init_lanes");

        // Place a regular file at `locks/lanes` so that the lock-dir
        // creation path fails (cannot create a directory where a file
        // exists).
        let lock_dir = fac_root.join("locks").join("lanes");
        // Remove the existing directory first.
        fs::remove_dir_all(&lock_dir).expect("remove lock dir");
        // Create the parent if needed.
        fs::create_dir_all(lock_dir.parent().unwrap()).expect("create locks dir");
        // Place a file where the directory should be.
        fs::write(&lock_dir, b"blocking file").expect("write blocking file");

        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        // Infrastructure failures must be > 0.
        assert!(
            receipt.infrastructure_failures > 0,
            "infrastructure_failures must be non-zero when lock-dir creation fails, \
             got: {}",
            receipt.infrastructure_failures
        );

        // There must be a create_lock_dir action with Failed outcome.
        let lock_action = receipt
            .actions
            .iter()
            .find(|a| a.action == "create_lock_dir");
        assert!(
            lock_action.is_some(),
            "receipt must contain a create_lock_dir action"
        );
        assert_eq!(
            lock_action.unwrap().outcome,
            LaneReconcileOutcome::Failed,
            "create_lock_dir action must have Failed outcome"
        );

        // Lane-level counters should still report lanes as OK (the lock
        // failure is infrastructure, not lane-level).
        assert_eq!(
            receipt.lanes_failed, 0,
            "lane-level failures should be 0 when only infrastructure failed"
        );
    }

    /// Regression (Finding 1): `build_reconcile_receipt` must count
    /// infrastructure failures from actions with non-lane IDs.
    #[test]
    fn build_receipt_counts_infrastructure_failures() {
        let lane_ids = vec!["lane-00".to_string()];
        let actions = vec![
            // Infrastructure failure: lane_id is NOT a configured lane.
            LaneReconcileAction {
                lane_id: "locks/lanes".to_string(),
                action: "create_lock_dir".to_string(),
                outcome: LaneReconcileOutcome::Failed,
                detail: Some("test failure".to_string()),
            },
            // Normal lane action.
            LaneReconcileAction {
                lane_id: "lane-00".to_string(),
                action: "inspect".to_string(),
                outcome: LaneReconcileOutcome::Ok,
                detail: None,
            },
        ];

        let receipt = LaneManager::build_reconcile_receipt(&lane_ids, actions);

        assert_eq!(receipt.infrastructure_failures, 1);
        assert_eq!(receipt.lanes_ok, 1);
        assert_eq!(receipt.lanes_failed, 0);
    }

    /// Regression (Finding 2): reconcile must detect a regular file at a
    /// lane workspace path and mark the lane as failed/corrupt.
    #[test]
    fn reconcile_detects_file_at_workspace_path() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        // Init first.
        manager.init_lanes().expect("init_lanes");

        let lane_id = &LaneManager::default_lane_ids()[0];
        let lane_dir = manager.lane_dir(lane_id);

        // Replace the workspace directory with a regular file.
        let workspace = lane_dir.join("workspace");
        fs::remove_dir_all(&workspace).expect("remove workspace dir");
        fs::write(&workspace, b"not a directory").expect("write file at workspace");

        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        // The lane must be counted as failed or marked corrupt.
        assert!(
            receipt.lanes_failed > 0 || receipt.lanes_marked_corrupt > 0,
            "lane with file-at-workspace must be reported as failed or corrupt, \
             got lanes_failed={}, lanes_marked_corrupt={}",
            receipt.lanes_failed,
            receipt.lanes_marked_corrupt,
        );

        // There must be a failed action mentioning the workspace.
        let failed_action = receipt.actions.iter().find(|a| {
            a.lane_id == *lane_id
                && a.outcome == LaneReconcileOutcome::Failed
                && a.action.contains("workspace")
        });
        assert!(
            failed_action.is_some(),
            "must have a failed action for workspace, actions: {:?}",
            receipt.actions
        );
        let detail = failed_action.unwrap().detail.as_deref().unwrap_or("");
        assert!(
            detail.contains("regular file"),
            "detail must mention 'regular file', got: {detail}"
        );
    }

    /// Regression (Finding 2): reconcile must detect a symlink at a lane
    /// workspace path and mark the lane as failed/corrupt.
    #[test]
    fn reconcile_detects_symlink_at_workspace_path() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");

        // Init first.
        manager.init_lanes().expect("init_lanes");

        let lane_id = &LaneManager::default_lane_ids()[0];
        let lane_dir = manager.lane_dir(lane_id);

        // Replace the workspace directory with a symlink.
        let workspace = lane_dir.join("workspace");
        fs::remove_dir_all(&workspace).expect("remove workspace dir");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/tmp", &workspace).expect("create symlink at workspace");
        }

        // On non-Unix this test is effectively a no-op — the symlink_metadata
        // validation still applies.
        #[cfg(not(unix))]
        {
            // Create a file instead of symlink on non-Unix for test coverage.
            fs::write(&workspace, b"not a directory").expect("write file");
        }

        let receipt = manager.reconcile_lanes().expect("reconcile_lanes");

        // The lane must be counted as failed or marked corrupt.
        assert!(
            receipt.lanes_failed > 0 || receipt.lanes_marked_corrupt > 0,
            "lane with symlink-at-workspace must be reported as failed or corrupt, \
             got lanes_failed={}, lanes_marked_corrupt={}",
            receipt.lanes_failed,
            receipt.lanes_marked_corrupt,
        );

        // There must be a failed action for the workspace.
        let failed_action = receipt.actions.iter().find(|a| {
            a.lane_id == *lane_id
                && a.outcome == LaneReconcileOutcome::Failed
                && a.action.contains("workspace")
        });
        assert!(
            failed_action.is_some(),
            "must have a failed action for workspace, actions: {:?}",
            receipt.actions
        );

        #[cfg(unix)]
        {
            let detail = failed_action.unwrap().detail.as_deref().unwrap_or("");
            assert!(
                detail.contains("symlink"),
                "detail must mention 'symlink', got: {detail}"
            );
        }
    }

    /// Regression (Finding 3): `infrastructure_failures` field round-trips
    /// through JSON serialization/deserialization.
    #[test]
    fn reconcile_receipt_infrastructure_failures_roundtrip() {
        let receipt = LaneReconcileReceiptV1 {
            schema: LANE_RECONCILE_RECEIPT_SCHEMA.to_string(),
            lanes_inspected: 3,
            lanes_ok: 3,
            lanes_repaired: 0,
            lanes_marked_corrupt: 0,
            lanes_failed: 0,
            infrastructure_failures: 2,
            actions: vec![LaneReconcileAction {
                lane_id: "locks/lanes".to_string(),
                action: "create_lock_dir".to_string(),
                outcome: LaneReconcileOutcome::Failed,
                detail: Some("test failure".to_string()),
            }],
        };

        let json = serde_json::to_string(&receipt).expect("serialize");
        let deserialized: LaneReconcileReceiptV1 =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, deserialized);
        assert_eq!(deserialized.infrastructure_failures, 2);
    }

    /// Regression (Finding 3): backward-compatible deserialization — receipts
    /// without the `infrastructure_failures` field default to 0.
    #[test]
    fn reconcile_receipt_missing_infrastructure_failures_defaults_to_zero() {
        let json = r#"{
            "schema": "apm2.fac.lane_reconcile_receipt.v1",
            "lanes_inspected": 3,
            "lanes_ok": 3,
            "lanes_repaired": 0,
            "lanes_marked_corrupt": 0,
            "lanes_failed": 0,
            "actions": []
        }"#;
        let receipt: LaneReconcileReceiptV1 = serde_json::from_str(json).expect("deserialize");
        assert_eq!(receipt.infrastructure_failures, 0);
    }

    // =========================================================================
    // Regression tests for round-N review findings (PR #759)
    // =========================================================================

    /// BLOCKER regression: `enforce_log_retention` MUST reject a symlinked
    /// `logs/` directory at entry and MUST NOT follow the symlink or delete
    /// files outside the lane root. This prevents an attacker-controlled job
    /// from replacing `lanes/{lane_id}/logs` with a symlink to an arbitrary
    /// directory, which would cause `read_dir`/`remove_file` operations to
    /// resolve outside FAC boundaries.
    #[cfg(unix)]
    #[test]
    fn enforce_log_retention_rejects_symlinked_logs_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        // Create a directory that a symlink will point to.
        // Place a canary file inside to verify it is NOT deleted.
        let target_dir = root.path().join("attacker-controlled");
        fs::create_dir_all(&target_dir).expect("create target dir");
        let canary = target_dir.join("canary.txt");
        fs::write(&canary, b"must survive").expect("write canary");

        // Remove the real logs/ directory and replace it with a symlink
        // to the attacker-controlled directory.
        let logs_dir = lane_dir.join("logs");
        if logs_dir.exists() {
            fs::remove_dir_all(&logs_dir).expect("remove real logs dir");
        }
        std::os::unix::fs::symlink(&target_dir, &logs_dir).expect("create symlink at logs/");

        // Verify the symlink exists.
        let meta = fs::symlink_metadata(&logs_dir).expect("symlink metadata");
        assert!(
            meta.file_type().is_symlink(),
            "logs/ must be a symlink for this test"
        );

        // Run cleanup — must fail at log retention entry due to symlink.
        let result = manager.run_lane_cleanup(lane_id, &workspace);
        let err = result.expect_err(
            "cleanup must fail when logs/ is a symlink (fail-closed: \
             symlinked logs/ enables arbitrary-file-deletion attacks)",
        );

        // Verify it is a LogQuotaFailed error mentioning the symlink.
        assert!(
            matches!(err, LaneCleanupError::LogQuotaFailed { .. }),
            "expected LogQuotaFailed, got: {err:?}"
        );
        let reason = match &err {
            LaneCleanupError::LogQuotaFailed { reason, .. } => reason.clone(),
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(
            reason.contains("symlink"),
            "error reason must mention symlink, got: {reason}"
        );

        // Canary file outside the lane MUST survive — the symlink was
        // never followed.
        assert!(
            canary.exists(),
            "canary file outside lane root must not be deleted — \
             symlink following was correctly prevented"
        );
    }

    /// MAJOR regression: when `estimate_job_log_dir_size_recursive` returns
    /// `u64::MAX` (traversal overflow sentinel), `enforce_log_retention` MUST
    /// return an error (fail-closed) which causes the lane to be marked
    /// CORRUPT. Silently continuing with zero-byte or sentinel accounting
    /// would let unreadable/overflow subtrees bypass quota enforcement.
    #[test]
    fn enforce_log_retention_marks_corrupt_on_size_overflow_sentinel() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        let logs_dir = lane_dir.join("logs");

        // Clean up and re-create logs_dir.
        fs::remove_dir_all(&logs_dir).expect("remove logs dir");
        fs::create_dir_all(&logs_dir).expect("recreate logs dir");

        // Create two job dirs. First one small, second one with
        // wide+deep nesting to hit the MAX_LANE_SCAN_ENTRIES limit
        // in the recursive estimator.
        let job_a = logs_dir.join("job-a-small");
        fs::create_dir_all(&job_a).expect("create job-a");
        fs::write(job_a.join("output.log"), vec![0u8; 100]).expect("write");

        let job_b = logs_dir.join("job-b-overflow");
        fs::create_dir_all(&job_b).expect("create job-b");
        // Create 200 subdirs, each with 501 files = 100,400 entries
        // which exceeds MAX_LANE_SCAN_ENTRIES (100,000).
        for dir_idx in 0..200 {
            let subdir = job_b.join(format!("d{dir_idx:04}"));
            fs::create_dir_all(&subdir).expect("create subdir");
            for file_idx in 0..501 {
                fs::write(subdir.join(format!("f{file_idx:04}.log")), vec![0u8; 10])
                    .expect("write nested file");
            }
        }

        let retention = crate::fac::gc::LogRetentionConfig {
            per_lane_log_max_bytes: 50,
            per_job_log_ttl_secs: 0,
            keep_last_n_jobs_per_lane: 0,
        };

        // Run cleanup — MUST fail because the sentinel triggers
        // fail-closed, marking the lane CORRUPT.
        let result = manager.run_lane_cleanup_with_retention(lane_id, &workspace, &retention);
        let err = result.expect_err(
            "cleanup must fail when size estimator returns u64::MAX sentinel \
             (fail-closed: lane must be marked CORRUPT)",
        );

        assert!(
            matches!(err, LaneCleanupError::LogQuotaFailed { .. }),
            "expected LogQuotaFailed, got: {err:?}"
        );
        let reason = match &err {
            LaneCleanupError::LogQuotaFailed { reason, .. } => reason.clone(),
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(
            reason.contains("u64::MAX sentinel"),
            "error reason must mention u64::MAX sentinel, got: {reason}"
        );

        // Both job dirs must survive — cleanup was aborted before pruning.
        assert!(
            job_a.exists(),
            "job-a must survive: cleanup aborted on sentinel detection"
        );
        assert!(
            job_b.exists(),
            "job-b must survive: cleanup aborted on sentinel detection"
        );

        // Verify lane transitioned to Corrupt.
        let lease = LaneLeaseV1::load(&manager.lane_dir(lane_id))
            .expect("load lease")
            .expect("lease exists");
        assert_eq!(
            lease.state,
            LaneState::Corrupt,
            "lane must be CORRUPT after sentinel-triggered cleanup failure"
        );
    }

    /// CQ-MAJOR regression: `enforce_log_retention` MUST return an error
    /// (causing the lane to be marked CORRUPT) when an unreadable nested
    /// subdirectory causes `estimate_job_log_dir_size_recursive` to return
    /// the `u64::MAX` sentinel. Silently continuing with zero-byte
    /// accounting would let unreadable subtrees bypass quota enforcement.
    #[cfg(unix)]
    #[test]
    fn enforce_log_retention_marks_corrupt_on_unreadable_nested_dir() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let workspace = lane_dir.join("workspace");
        init_git_workspace(&workspace);
        persist_running_lease(&manager, lane_id);

        let logs_dir = lane_dir.join("logs");

        // Create a normal job log directory.
        let job_a = logs_dir.join("job-a-normal");
        fs::create_dir_all(&job_a).expect("create job-a");
        fs::write(job_a.join("output.log"), vec![0u8; 100]).expect("write");

        // Create a job log directory with an unreadable nested subdirectory.
        let job_b = logs_dir.join("job-b-unreadable");
        fs::create_dir_all(&job_b).expect("create job-b");
        fs::write(job_b.join("output.log"), vec![0u8; 200]).expect("write");
        let nested = job_b.join("nested-secret");
        fs::create_dir_all(&nested).expect("mkdir nested");
        fs::write(nested.join("large.bin"), vec![0u8; 10_000_000]).expect("write large file");
        // Make the nested subdirectory unreadable (mode 000).
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o000))
            .expect("chmod 000 nested dir");

        // Use a retention config with byte quota. The unreadable dir should
        // trigger the u64::MAX sentinel and fail-closed.
        let retention = crate::fac::gc::LogRetentionConfig {
            per_lane_log_max_bytes: 500,
            per_job_log_ttl_secs: 0,
            keep_last_n_jobs_per_lane: 0,
        };

        let result = manager.run_lane_cleanup_with_retention(lane_id, &workspace, &retention);

        // Restore permissions for cleanup (tempdir Drop will fail otherwise).
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755))
            .expect("chmod 755 (cleanup)");

        // Cleanup MUST fail — the error propagation marks the lane CORRUPT.
        let err = result.expect_err(
            "cleanup must fail when a job log dir has an unreadable nested \
             subdirectory (fail-closed: u64::MAX sentinel triggers CORRUPT)",
        );

        // Verify it is a LogQuotaFailed error mentioning the sentinel.
        assert!(
            matches!(err, LaneCleanupError::LogQuotaFailed { .. }),
            "expected LogQuotaFailed, got: {err:?}"
        );
        let reason = match &err {
            LaneCleanupError::LogQuotaFailed { reason, .. } => reason.clone(),
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(
            reason.contains("u64::MAX sentinel"),
            "error reason must mention u64::MAX sentinel, got: {reason}"
        );
        assert!(
            reason.contains("CORRUPT"),
            "error reason must mention CORRUPT, got: {reason}"
        );

        // Verify the lane was transitioned to Corrupt state.
        let lane_dir_for_lease = manager.lane_dir(lane_id);
        let lease = LaneLeaseV1::load(&lane_dir_for_lease)
            .expect("load lease")
            .expect("lease exists");
        assert_eq!(
            lease.state,
            LaneState::Corrupt,
            "lane must be in CORRUPT state after unreadable nested dir \
             triggers u64::MAX sentinel in enforce_log_retention"
        );
    }
}
