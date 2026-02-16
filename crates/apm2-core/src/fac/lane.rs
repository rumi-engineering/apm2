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

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::execution_backend::{ExecutionBackend, select_backend};
use super::safe_rmtree::safe_rmtree_v1;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Schema identifier for lane profile v1.
pub const LANE_PROFILE_V1_SCHEMA: &str = "apm2.fac.lane_profile.v1";

/// Schema identifier for lane lease v1.
pub const LANE_LEASE_V1_SCHEMA: &str = "apm2.fac.lane_lease.v1";

/// Schema identifier for corrupt marker files.
pub const LANE_CORRUPT_MARKER_SCHEMA: &str = "apm2.fac.lane_corrupt.v1";

const CLEANUP_STEP_GIT_RESET: &str = "git_reset";
const CLEANUP_STEP_GIT_CLEAN: &str = "git_clean";
const CLEANUP_STEP_TEMP_PRUNE: &str = "temp_prune";
const CLEANUP_STEP_ENV_DIR_PRUNE: &str = "env_dir_prune";
const CLEANUP_STEP_LOG_QUOTA: &str = "log_quota";
const CLEANUP_STEP_WORKSPACE_VALIDATION: &str = "workspace_path_validation";

/// Maximum log directory size in bytes (100 MB).
const MAX_LOG_QUOTA_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum number of collected log entries during quota enforcement.
const MAX_LOG_ENTRIES: usize = 10_000;

/// Maximum directory recursion depth while enforcing log quota.
const MAX_LOG_QUOTA_DIR_DEPTH: usize = 8;

/// Maximum number of directory entries read per directory during log quota
/// enforcement. Prevents directory-flood `DoS` where an attacker creates
/// millions of subdirectories. Matches INV-RMTREE-009 from `safe_rmtree_v1`.
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
    /// ISO 8601 timestamp when lease was acquired.
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
        Ok(Self {
            schema: LANE_LEASE_V1_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            job_id: job_id.to_string(),
            pid,
            state,
            started_at: started_at.to_string(),
            lane_profile_hash: lane_profile_hash.to_string(),
            toolchain_fingerprint: toolchain_fingerprint.to_string(),
        })
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
    /// ISO-8601 / epoch marker used to record when the lane became corrupt.
    pub detected_at: String,
}

impl LaneCorruptMarkerV1 {
    fn marker_path(fac_root: &Path, lane_id: &str) -> PathBuf {
        fac_root.join("lanes").join(lane_id).join("corrupt.v1.json")
    }

    /// Persist this marker to the lane directory.
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` for serialization or write failures, or
    /// `LaneError::InvalidRecord` if the marker schema is invalid.
    pub fn persist(&self, fac_root: &Path) -> Result<(), LaneError> {
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
                    Some(lease.started_at.clone()),
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

    /// Run lane cleanup:
    /// 1. Reset workspace (`git reset --hard HEAD`)
    /// 2. Remove untracked files (`git clean -ffdxq`)
    /// 3. Remove temporary directory (`tmp`) via safe deletion
    /// 4. Prune per-lane env dirs from `LANE_ENV_DIRS` (excluding `tmp`):
    ///    (`home/`, `xdg_cache/`, `xdg_config/`, `xdg_data/`, `xdg_state/`,
    ///    `xdg_runtime/`)
    /// 5. Enforce log quota by pruning oldest logs to 100 MiB
    ///
    /// # Errors
    ///
    /// Returns `LaneCleanupError::GitCommandFailed` on git failures, and
    /// `LaneCleanupError::TempPruneFailed` or
    /// `LaneCleanupError::LogQuotaFailed` for cleanup actions.
    #[allow(clippy::too_many_lines)]
    pub fn run_lane_cleanup(
        &self,
        lane_id: &str,
        workspace_path: &Path,
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

        // Step 4: Enforce log quota.
        if let Err(err) = Self::enforce_log_quota(&lanes_dir.join("logs"), &steps_completed) {
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
pub(crate) fn create_dir_restricted(path: &Path) -> Result<(), LaneError> {
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
            fs::DirBuilder::new()
                .recursive(false)
                .mode(mode)
                .create(component)
                .or_else(|e| {
                    // Tolerate AlreadyExists (concurrent creation race)
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .map_err(|e| {
                    LaneError::io(format!("creating directory {}", component.display()), e)
                })?;
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
        let json = r#"{"schema":"apm2.fac.lane_lease.v1","lane_id":"lane-00","job_id":"j","pid":1,"state":"RUNNING","started_at":"t","lane_profile_hash":"h","toolchain_fingerprint":"f","extra":"evil"}"#;
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
        let result = LaneLeaseV1::new("lane-00", &long_id, 1, LaneState::Idle, "t", "h", "f");
        assert!(result.is_err());
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
    fn run_lane_cleanup_preserves_steps_for_log_quota_failure() {
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
        let mut depth_dir = logs_dir;
        for level in 0..(MAX_LOG_QUOTA_DIR_DEPTH + 2) {
            depth_dir = depth_dir.join(format!("level_{level}"));
        }
        fs::create_dir_all(&depth_dir).expect("create deep logs directory");
        fs::write(depth_dir.join("deep.log"), b"payload").expect("write deep log file");

        let err = manager
            .run_lane_cleanup(lane_id, &workspace)
            .expect_err("cleanup should fail from log quota traversal depth check");
        assert!(matches!(err, LaneCleanupError::LogQuotaFailed { .. }));
        assert_eq!(
            err.steps_completed(),
            [
                CLEANUP_STEP_GIT_RESET.to_string(),
                CLEANUP_STEP_GIT_CLEAN.to_string(),
                CLEANUP_STEP_TEMP_PRUNE.to_string(),
                CLEANUP_STEP_ENV_DIR_PRUNE.to_string(),
            ]
            .as_slice()
        );
        assert_eq!(err.failure_step(), Some(CLEANUP_STEP_LOG_QUOTA));
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
}
