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
//! - Directories are created with mode 0o700 (CTR-2611).
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
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Schema identifier for lane profile v1.
pub const LANE_PROFILE_V1_SCHEMA: &str = "apm2.fac.lane_profile.v1";

/// Schema identifier for lane lease v1.
pub const LANE_LEASE_V1_SCHEMA: &str = "apm2.fac.lane_lease.v1";

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
            memory_max_bytes: 25_769_803_776, // 24 GiB
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
            test_timeout_seconds: 240,
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
    /// `MAX_LANE_ID_LENGTH`.
    pub fn new(lane_id: &str, node_fingerprint: &str) -> Result<Self, LaneError> {
        validate_lane_id(lane_id)?;
        validate_string_field("node_fingerprint", node_fingerprint, MAX_STRING_LENGTH)?;
        Ok(Self {
            schema: LANE_PROFILE_V1_SCHEMA.to_string(),
            lane_id: lane_id.to_string(),
            node_fingerprint: node_fingerprint.to_string(),
            resource_profile: ResourceProfile::default(),
            timeouts: LaneTimeouts::default(),
            policy: LanePolicy::default(),
        })
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
        let profile: Self = serde_json::from_slice(&bytes).map_err(|e| {
            LaneError::Serialization(format!(
                "failed to parse profile at {}: {e}",
                profile_path.display()
            ))
        })?;
        let expected_lane_id = lane_dir_lane_id(lane_dir)?;
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
        validate_lane_id(&profile.lane_id)?;
        Ok(profile)
    }
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
    /// Whether the lock file is currently held.
    pub lock_held: bool,
    /// Whether the PID in the lease is still alive.
    pub pid_alive: Option<bool>,
}

impl fmt::Display for LaneStatusV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<12} {:<10}", self.lane_id, self.state)?;
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

    /// Get the path to a lane's lock file.
    #[must_use]
    pub fn lock_path(&self, lane_id: &str) -> PathBuf {
        self.fac_root
            .join("locks")
            .join("lanes")
            .join(format!("{lane_id}.lock"))
    }

    /// Ensure all lane directories and lock parent directories exist with
    /// mode 0o700 (CTR-2611).
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

        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| LaneError::io(format!("opening lock file {}", lock_path.display()), e))?;

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
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| LaneError::io(format!("opening lock file {}", lock_path.display()), e))?;
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

    /// Derive the status of a lane from lock state, lease record, and PID
    /// liveness.
    ///
    /// # Stale Lease Detection Rules (RFC-0019 §4.4)
    ///
    /// - Lock free + lease RUNNING + PID alive → CORRUPT (INV-LANE-004)
    /// - Lock free + PID dead → stale lease (IDLE)
    /// - Lock held + lease RUNNING + PID alive → RUNNING
    /// - No lease → IDLE
    ///
    /// # Errors
    ///
    /// Returns `LaneError::Io` on filesystem errors.
    pub fn lane_status(&self, lane_id: &str) -> Result<LaneStatusV1, LaneError> {
        validate_lane_id(lane_id)?;
        let lane_dir = self.lane_dir(lane_id);
        let lock_held = self.is_lock_held(lane_id)?;

        let lease = LaneLeaseV1::load(&lane_dir)?;

        match lease {
            None => Ok(LaneStatusV1 {
                lane_id: lane_id.to_string(),
                state: LaneState::Idle,
                job_id: None,
                pid: None,
                started_at: None,
                toolchain_fingerprint: None,
                lane_profile_hash: None,
                lock_held,
                pid_alive: None,
            }),
            Some(lease) => {
                let pid_alive = is_pid_alive(lease.pid);
                let state = derive_lane_state(lock_held, &lease, pid_alive);
                Ok(LaneStatusV1 {
                    lane_id: lane_id.to_string(),
                    state,
                    job_id: Some(lease.job_id),
                    pid: Some(lease.pid),
                    started_at: Some(lease.started_at),
                    toolchain_fingerprint: Some(lease.toolchain_fingerprint),
                    lane_profile_hash: Some(lease.lane_profile_hash),
                    lock_held,
                    pid_alive: Some(pid_alive),
                })
            },
        }
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane State Derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive the effective lane state from lock state, lease record, and PID
/// liveness.
///
/// Stale lease detection rules (RFC-0019 §4.4, fail-closed):
/// - Lock free + lease RUNNING + PID alive → CORRUPT
/// - Lock free + lease RUNNING + PID dead → IDLE (stale lease)
/// - Lock held + lease RUNNING → RUNNING
/// - Lock held + lease state other → use lease state
/// - Lock free + lease state != RUNNING → use lease state (or IDLE if terminal)
const fn derive_lane_state(lock_held: bool, lease: &LaneLeaseV1, pid_alive: bool) -> LaneState {
    match (lock_held, lease.state, pid_alive) {
        // Lock held: trust the lease state unconditionally
        (true, state, _) => state,

        // Lock free + active state (RUNNING/LEASED/CLEANUP) + PID alive →
        // ambiguous ownership → CORRUPT (fail-closed, INV-LANE-004).
        // Lock free + CORRUPT → remains CORRUPT regardless of PID.
        (false, LaneState::Running | LaneState::Leased | LaneState::Cleanup, true)
        | (false, LaneState::Corrupt, _) => LaneState::Corrupt,

        // Lock free + active state + PID dead → stale lease → IDLE.
        // Lock free + IDLE → IDLE.
        (false, LaneState::Running | LaneState::Leased | LaneState::Cleanup, false)
        | (false, LaneState::Idle, _) => LaneState::Idle,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PID Liveness
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether a given PID is alive.
///
/// Uses `kill(pid, 0)` which checks for process existence without sending a
/// signal.
fn is_pid_alive(pid: u32) -> bool {
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
///
/// Uses `DirBuilder` with mode set at create-time to avoid TOCTOU window.
fn create_dir_restricted(path: &Path) -> Result<(), LaneError> {
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
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| LaneError::io(format!("creating directory {}", path.display()), e))
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
fn atomic_write(target: &Path, data: &[u8]) -> Result<(), LaneError> {
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
fn bounded_read_file(path: &Path, max_size: u64) -> Result<Vec<u8>, LaneError> {
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
        let profile = LaneProfileV1::new("lane-00", "b3-256:abc123").expect("create profile");
        assert_eq!(profile.schema, LANE_PROFILE_V1_SCHEMA);
        assert_eq!(profile.lane_id, "lane-00");
        let hash = profile.compute_hash().expect("compute hash");
        assert!(
            hash.starts_with("b3-256:"),
            "hash should have b3-256 prefix"
        );
        assert_eq!(hash.len(), 7 + 64, "b3-256 prefix + 64 hex chars");
    }

    #[test]
    fn lane_profile_hash_is_deterministic() {
        let p1 = LaneProfileV1::new("lane-00", "b3-256:abc").expect("p1");
        let p2 = LaneProfileV1::new("lane-00", "b3-256:abc").expect("p2");
        assert_eq!(
            p1.compute_hash().expect("h1"),
            p2.compute_hash().expect("h2"),
            "same inputs must produce same hash"
        );
    }

    #[test]
    fn lane_profile_hash_changes_with_input() {
        let p1 = LaneProfileV1::new("lane-00", "b3-256:aaa").expect("p1");
        let p2 = LaneProfileV1::new("lane-01", "b3-256:aaa").expect("p2");
        assert_ne!(
            p1.compute_hash().expect("h1"),
            p2.compute_hash().expect("h2"),
            "different lane IDs must produce different hashes"
        );
    }

    #[test]
    fn lane_profile_serde_round_trip() {
        let profile = LaneProfileV1::new("lane-00", "b3-256:abc123").expect("create profile");
        let json = serde_json::to_string_pretty(&profile).expect("serialize");
        let parsed: LaneProfileV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile, parsed);
    }

    #[test]
    fn lane_profile_rejects_unknown_fields() {
        let json = r#"{"schema":"apm2.fac.lane_profile.v1","lane_id":"lane-00","node_fingerprint":"x","resource_profile":{"cpu_quota_percent":200,"memory_max_bytes":100,"pids_max":1536,"io_weight":100},"timeouts":{"test_timeout_seconds":240,"job_runtime_max_seconds":1800},"policy":{"fac_policy_hash":"","nextest_profile":"ci","deny_ambient_cargo_home":true},"extra_field":"evil"}"#;
        let result: Result<LaneProfileV1, _> = serde_json::from_str(json);
        assert!(result.is_err(), "must reject unknown fields (CTR-1604)");
    }

    #[test]
    fn lane_profile_persist_and_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        let lane_dir = dir.path().join("lane-00");
        fs::create_dir_all(&lane_dir).expect("create lane dir");
        let profile = LaneProfileV1::new("lane-00", "b3-256:abc123").expect("create profile");
        profile.persist(&lane_dir).expect("persist");
        let loaded = LaneProfileV1::load(&lane_dir).expect("load");
        assert_eq!(profile, loaded);
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

        let profile = LaneProfileV1::new("lane-00", "fp").expect("create profile");
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

        let profile = LaneProfileV1::new("lane-00", "fp").expect("create profile");
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
        let result = LaneProfileV1::new(&long_id, "fp");
        assert!(result.is_err());
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
        assert_eq!(derive_lane_state(true, &lease, true), LaneState::Running);
        assert_eq!(derive_lane_state(true, &lease, false), LaneState::Running);
    }

    #[test]
    fn derive_state_lock_free_running_pid_alive_is_corrupt() {
        let lease = make_lease(LaneState::Running);
        assert_eq!(
            derive_lane_state(false, &lease, true),
            LaneState::Corrupt,
            "lock free + RUNNING + PID alive → CORRUPT (fail-closed)"
        );
    }

    #[test]
    fn derive_state_lock_free_running_pid_dead_is_idle() {
        let lease = make_lease(LaneState::Running);
        assert_eq!(
            derive_lane_state(false, &lease, false),
            LaneState::Idle,
            "lock free + RUNNING + PID dead → IDLE (stale lease)"
        );
    }

    #[test]
    fn derive_state_lock_free_corrupt_stays_corrupt() {
        let lease = make_lease(LaneState::Corrupt);
        assert_eq!(derive_lane_state(false, &lease, false), LaneState::Corrupt);
        assert_eq!(derive_lane_state(false, &lease, true), LaneState::Corrupt);
    }

    #[test]
    fn derive_state_lock_free_leased_pid_alive_is_corrupt() {
        let lease = make_lease(LaneState::Leased);
        assert_eq!(
            derive_lane_state(false, &lease, true),
            LaneState::Corrupt,
            "lock free + LEASED + PID alive → CORRUPT (fail-closed)"
        );
    }

    #[test]
    fn derive_state_lock_free_leased_pid_dead_is_idle() {
        let lease = make_lease(LaneState::Leased);
        assert_eq!(derive_lane_state(false, &lease, false), LaneState::Idle);
    }

    #[test]
    fn derive_state_lock_free_idle_is_idle() {
        let lease = make_lease(LaneState::Idle);
        assert_eq!(derive_lane_state(false, &lease, false), LaneState::Idle);
        assert_eq!(derive_lane_state(false, &lease, true), LaneState::Idle);
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
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");

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
            fac_root.join("locks").join("lanes").exists(),
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
        let _guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("acquire");

        // Second attempt should return None
        let second = manager.try_lock(lane_id).expect("second try_lock");
        assert!(
            second.is_none(),
            "should not acquire lock when already held"
        );
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
        let _guard = manager
            .try_lock(lane_id)
            .expect("try_lock")
            .expect("acquire");

        let status = manager.lane_status(lane_id).expect("status");
        assert_eq!(status.state, LaneState::Running);
        assert_eq!(status.job_id.as_deref(), Some("job_test"));
        assert_eq!(status.pid, Some(pid));
        assert!(status.lock_held);
        assert_eq!(status.pid_alive, Some(true));
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
                if let Ok(Some(_guard)) = m.try_lock(&lid) {
                    count.fetch_add(1, Ordering::SeqCst);
                    // Hold the lock briefly
                    std::thread::sleep(Duration::from_millis(50));
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
}
