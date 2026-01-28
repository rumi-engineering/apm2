//! Cgroups v2 reader for episode resource metrics.
//!
//! This module implements the `CgroupReader` for collecting CPU, memory, and
//! I/O statistics from Linux cgroups v2 hierarchy per AD-TEL-001 and
//! AD-CGROUP-001.
//!
//! # Architecture
//!
//! Per AD-CGROUP-001, each episode executes in an isolated cgroup scope:
//!
//! ```text
//! /sys/fs/cgroup/apm2.slice/
//! +-- daemon.service/           # Daemon process
//! +-- episode-<uuid>.scope/     # Per-episode isolation
//!     +-- cpu.stat
//!     +-- memory.current
//!     +-- memory.peak
//!     +-- memory.stat
//!     +-- io.stat
//! ```
//!
//! # Cgroup v2 File Formats
//!
//! - `cpu.stat`: `usage_usec <value>\nuser_usec <value>\nsystem_usec <value>\n`
//! - `memory.current`: `<bytes>\n`
//! - `memory.peak`: `<bytes>\n`
//! - `memory.stat`: `key value\n` pairs including `pgfault`, `pgmajfault`
//! - `io.stat`: `<major>:<minor> rbytes=<n> wbytes=<n> rios=<n> wios=<n> ...\n`
//!
//! # Creation Strategy
//!
//! Per AD-CGROUP-001:
//! 1. Primary: systemd transient API (`DBus`: `org.freedesktop.systemd1`) via
//!    `zbus`
//! 2. Fallback: Direct cgroup v2 writes
//!
//! The "freeze trick" is used for safe creation: create frozen cgroup, assign
//! PID, then unfreeze to prevent escape/race conditions.
//!
//! # Contract References
//!
//! - AD-TEL-001: Telemetry collection via cgroups v2
//! - AD-CGROUP-001: Per-episode cgroup hierarchy with systemd transient API

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use nix::unistd::Pid;
use thiserror::Error;
use tracing::{debug, warn};

use super::proc_fallback::ProcReader;
use super::stats::{CpuStats, IoStats, MemoryStats, MetricSource, ResourceStats};

/// Default cgroup v2 mount point.
pub const CGROUP_V2_MOUNT: &str = "/sys/fs/cgroup";

/// APM2 slice name for episode isolation.
pub const APM2_SLICE: &str = "apm2.slice";

/// Maximum path length for cgroup paths.
pub const MAX_CGROUP_PATH_LEN: usize = 4096;

/// Maximum episode ID length for cgroup scope names.
pub const MAX_EPISODE_ID_LEN: usize = 128;

/// Maximum size for telemetry file reads (64 KiB).
///
/// This prevents denial-of-service via unbounded file reads on paths derived
/// from external IDs. Cgroup stat files are typically a few hundred bytes;
/// 64 KiB is generous.
pub const MAX_TELEMETRY_FILE_SIZE: u64 = 64 * 1024;

/// Cgroup reader errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CgroupError {
    /// Cgroups v2 not available on this system.
    #[error("cgroups v2 not available: {reason}")]
    NotAvailable {
        /// Reason why cgroups v2 is not available.
        reason: String,
    },

    /// Cgroup path not found.
    #[error("cgroup path not found: {path}")]
    PathNotFound {
        /// The path that was not found.
        path: String,
    },

    /// Failed to read cgroup file.
    #[error("failed to read cgroup file '{file}': {source}")]
    ReadFailed {
        /// The file that failed to read.
        file: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse cgroup file content.
    #[error("failed to parse cgroup file '{file}': {reason}")]
    ParseFailed {
        /// The file that failed to parse.
        file: String,
        /// Reason for parse failure.
        reason: String,
    },

    /// Invalid episode ID for cgroup scope name.
    #[error("invalid episode ID for cgroup: {reason}")]
    InvalidEpisodeId {
        /// Reason for rejection.
        reason: String,
    },

    /// Failed to create cgroup scope.
    #[error("failed to create cgroup scope: {reason}")]
    CreateFailed {
        /// Reason for creation failure.
        reason: String,
    },

    /// Cgroup controller not enabled.
    #[error("cgroup controller '{controller}' not enabled")]
    ControllerNotEnabled {
        /// The controller that is not enabled.
        controller: String,
    },
}

/// Result type for cgroup operations.
pub type CgroupResult<T> = Result<T, CgroupError>;

/// Cgroup reader for episode resource metrics.
///
/// Reads CPU, memory, and I/O statistics from the cgroups v2 hierarchy.
/// Falls back to `/proc/{pid}/` when cgroup isolation is unavailable.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::telemetry::cgroup::CgroupReader;
///
/// // Create reader for an episode cgroup
/// let reader = CgroupReader::for_episode("ep-abc123")?;
///
/// // Read CPU stats
/// let cpu = reader.read_cpu()?;
/// println!("CPU usage: {} ms", cpu.usage_ms());
///
/// // Read all stats at once
/// let stats = reader.read_all()?;
/// ```
#[derive(Debug)]
pub struct CgroupReader {
    /// Path to the episode cgroup directory.
    cgroup_path: PathBuf,
    /// Fallback PID for `/proc` reading when cgroup is unavailable.
    fallback_pid: Option<Pid>,
    /// Cached availability of cgroup controllers.
    controllers_available: ControllerAvailability,
}

/// Availability of cgroup controllers.
#[derive(Debug, Clone, Copy, Default)]
struct ControllerAvailability {
    /// CPU controller available.
    cpu: bool,
    /// Memory controller available.
    memory: bool,
    /// I/O controller available.
    io: bool,
}

impl CgroupReader {
    /// Creates a cgroup reader for an episode.
    ///
    /// The episode cgroup is expected at:
    /// `/sys/fs/cgroup/apm2.slice/episode-{episode_id}.scope/`
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode identifier (used in scope name)
    ///
    /// # Errors
    ///
    /// Returns `CgroupError::InvalidEpisodeId` if the episode ID contains
    /// forbidden characters or is too long.
    ///
    /// Returns `CgroupError::PathNotFound` if the cgroup path doesn't exist.
    pub fn for_episode(episode_id: &str) -> CgroupResult<Self> {
        Self::for_episode_with_root(episode_id, CGROUP_V2_MOUNT)
    }

    /// Creates a cgroup reader for an episode with a custom cgroup root.
    ///
    /// This is primarily for testing with mock cgroup hierarchies.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode identifier
    /// * `cgroup_root` - Custom cgroup root path (e.g., for testing)
    pub fn for_episode_with_root(episode_id: &str, cgroup_root: &str) -> CgroupResult<Self> {
        validate_episode_id(episode_id)?;

        let scope_name = format!("episode-{episode_id}.scope");
        let cgroup_path = PathBuf::from(cgroup_root)
            .join(APM2_SLICE)
            .join(&scope_name);

        if !cgroup_path.exists() {
            return Err(CgroupError::PathNotFound {
                path: cgroup_path.display().to_string(),
            });
        }

        let controllers_available = check_controllers(&cgroup_path);

        Ok(Self {
            cgroup_path,
            fallback_pid: None,
            controllers_available,
        })
    }

    /// Creates a cgroup reader from a direct path.
    ///
    /// This is useful when the cgroup path is already known.
    ///
    /// # Arguments
    ///
    /// * `cgroup_path` - Direct path to the cgroup directory
    pub fn from_path(cgroup_path: impl Into<PathBuf>) -> CgroupResult<Self> {
        let cgroup_path = cgroup_path.into();

        if !cgroup_path.exists() {
            return Err(CgroupError::PathNotFound {
                path: cgroup_path.display().to_string(),
            });
        }

        let controllers_available = check_controllers(&cgroup_path);

        Ok(Self {
            cgroup_path,
            fallback_pid: None,
            controllers_available,
        })
    }

    /// Sets the fallback PID for `/proc` reading.
    ///
    /// When cgroup files are unavailable, the reader will attempt to read
    /// metrics from `/proc/{pid}/` instead (degraded mode).
    #[must_use]
    pub const fn with_fallback_pid(mut self, pid: Pid) -> Self {
        self.fallback_pid = Some(pid);
        self
    }

    /// Returns the cgroup path.
    #[must_use]
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    /// Returns the fallback PID.
    #[must_use]
    pub const fn fallback_pid(&self) -> Option<Pid> {
        self.fallback_pid
    }

    /// Reads CPU statistics from the cgroup.
    ///
    /// Reads from `cpu.stat` which contains:
    /// ```text
    /// usage_usec <value>
    /// user_usec <value>
    /// system_usec <value>
    /// ```
    ///
    /// Falls back to `/proc/{pid}/stat` if cgroup CPU controller is
    /// unavailable.
    pub fn read_cpu(&self) -> CpuStats {
        if self.controllers_available.cpu {
            match self.read_cpu_from_cgroup() {
                Ok(stats) => return stats,
                Err(e) => {
                    debug!("cgroup CPU read failed, trying fallback: {}", e);
                },
            }
        }

        // Fallback to /proc
        if let Some(pid) = self.fallback_pid {
            match ProcReader::new(pid).read_cpu() {
                Ok(stats) => return stats,
                Err(e) => {
                    warn!("proc CPU read failed: {}", e);
                },
            }
        }

        CpuStats::unavailable()
    }

    /// Reads memory statistics from the cgroup.
    ///
    /// Reads from:
    /// - `memory.current`: Current RSS in bytes
    /// - `memory.peak`: Peak memory usage in bytes
    /// - `memory.stat`: Page fault counters (pgfault, pgmajfault)
    ///
    /// Falls back to `/proc/{pid}/statm` if cgroup memory controller is
    /// unavailable.
    pub fn read_memory(&self) -> MemoryStats {
        if self.controllers_available.memory {
            match self.read_memory_from_cgroup() {
                Ok(stats) => return stats,
                Err(e) => {
                    debug!("cgroup memory read failed, trying fallback: {}", e);
                },
            }
        }

        // Fallback to /proc
        if let Some(pid) = self.fallback_pid {
            match ProcReader::new(pid).read_memory() {
                Ok(stats) => return stats,
                Err(e) => {
                    warn!("proc memory read failed: {}", e);
                },
            }
        }

        MemoryStats::unavailable()
    }

    /// Reads I/O statistics from the cgroup.
    ///
    /// Reads from `io.stat` which contains per-device statistics:
    /// ```text
    /// <major>:<minor> rbytes=<n> wbytes=<n> rios=<n> wios=<n> ...
    /// ```
    ///
    /// Falls back to `/proc/{pid}/io` if cgroup I/O controller is unavailable.
    pub fn read_io(&self) -> IoStats {
        if self.controllers_available.io {
            match self.read_io_from_cgroup() {
                Ok(stats) => return stats,
                Err(e) => {
                    debug!("cgroup I/O read failed, trying fallback: {}", e);
                },
            }
        }

        // Fallback to /proc
        if let Some(pid) = self.fallback_pid {
            match ProcReader::new(pid).read_io() {
                Ok(stats) => return stats,
                Err(e) => {
                    warn!("proc I/O read failed: {}", e);
                },
            }
        }

        IoStats::unavailable()
    }

    /// Reads all resource statistics at once.
    ///
    /// This is more efficient than calling individual methods when all
    /// metrics are needed.
    #[must_use]
    pub fn read_all(&self) -> ResourceStats {
        ResourceStats::new(self.read_cpu(), self.read_memory(), self.read_io())
    }

    /// Reads CPU stats from cgroup files.
    fn read_cpu_from_cgroup(&self) -> CgroupResult<CpuStats> {
        let cpu_stat_path = self.cgroup_path.join("cpu.stat");
        let content = read_cgroup_file(&cpu_stat_path)?;

        let mut usage_usec: u64 = 0;
        let mut user_usec: u64 = 0;
        let mut system_usec: u64 = 0;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "usage_usec" => {
                        usage_usec = parse_u64(parts[1], "cpu.stat", "usage_usec")?;
                    },
                    "user_usec" => {
                        user_usec = parse_u64(parts[1], "cpu.stat", "user_usec")?;
                    },
                    "system_usec" => {
                        system_usec = parse_u64(parts[1], "cpu.stat", "system_usec")?;
                    },
                    _ => {},
                }
            }
        }

        // Convert microseconds to nanoseconds
        Ok(CpuStats::new(
            usage_usec.saturating_mul(1000),
            user_usec.saturating_mul(1000),
            system_usec.saturating_mul(1000),
            MetricSource::Cgroup,
        ))
    }

    /// Reads memory stats from cgroup files.
    ///
    /// Fails closed on parse errors per security review - returns error
    /// rather than using default values that could mask issues.
    fn read_memory_from_cgroup(&self) -> CgroupResult<MemoryStats> {
        // Read memory.current (required)
        let current_path = self.cgroup_path.join("memory.current");
        let current_content = read_cgroup_file(&current_path)?;
        let rss_bytes = parse_u64(current_content.trim(), "memory.current", "value")?;

        // Read memory.peak (required for proper invariant validation)
        let peak_path = self.cgroup_path.join("memory.peak");
        let peak_bytes = match read_cgroup_file(&peak_path) {
            Ok(content) => parse_u64(content.trim(), "memory.peak", "value")?,
            Err(CgroupError::ReadFailed { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                // memory.peak doesn't exist on older kernels - use rss as fallback
                debug!("memory.peak not available, using memory.current as peak");
                rss_bytes
            },
            Err(e) => return Err(e),
        };

        // Read memory.stat for page faults (required)
        let memory_stat_path = self.cgroup_path.join("memory.stat");
        let memory_stat_content = read_cgroup_file(&memory_stat_path)?;
        let (page_faults_major, page_faults_minor) = parse_memory_stat(&memory_stat_content)?;

        // Validate and construct stats
        MemoryStats::try_new(
            rss_bytes,
            peak_bytes,
            page_faults_major,
            page_faults_minor,
            MetricSource::Cgroup,
        )
        .map_err(|reason| CgroupError::ParseFailed {
            file: "memory.*".to_string(),
            reason,
        })
    }

    /// Reads I/O stats from cgroup files.
    ///
    /// Fails closed on parse errors per security review.
    fn read_io_from_cgroup(&self) -> CgroupResult<IoStats> {
        let io_stat_path = self.cgroup_path.join("io.stat");
        let content = read_cgroup_file(&io_stat_path)?;

        let mut total_read_bytes: u64 = 0;
        let mut total_write_bytes: u64 = 0;
        let mut total_read_ops: u64 = 0;
        let mut total_write_ops: u64 = 0;

        // io.stat format: <major>:<minor> rbytes=<n> wbytes=<n> rios=<n> wios=<n> ...
        for line in content.lines() {
            let stats = parse_io_stat_line(line)?;
            // Use 0 as default for missing keys (device may not have all metrics)
            // but fail on malformed values (handled by parse_io_stat_line)
            total_read_bytes =
                total_read_bytes.saturating_add(stats.get("rbytes").copied().unwrap_or(0));
            total_write_bytes =
                total_write_bytes.saturating_add(stats.get("wbytes").copied().unwrap_or(0));
            total_read_ops = total_read_ops.saturating_add(stats.get("rios").copied().unwrap_or(0));
            total_write_ops =
                total_write_ops.saturating_add(stats.get("wios").copied().unwrap_or(0));
        }

        Ok(IoStats::new(
            total_read_bytes,
            total_write_bytes,
            total_read_ops,
            total_write_ops,
            MetricSource::Cgroup,
        ))
    }
}

/// Checks if cgroups v2 is available on this system.
///
/// Returns `true` if `/sys/fs/cgroup/cgroup.controllers` exists,
/// indicating a cgroups v2 unified hierarchy.
#[must_use]
pub fn is_cgroup_v2_available() -> bool {
    is_cgroup_v2_available_at(CGROUP_V2_MOUNT)
}

/// Checks if cgroups v2 is available at a specific mount point.
#[must_use]
pub fn is_cgroup_v2_available_at(mount_point: &str) -> bool {
    let controllers_path = PathBuf::from(mount_point).join("cgroup.controllers");
    controllers_path.exists()
}

/// Gets the episode cgroup path for a given episode ID.
///
/// Returns the expected path at:
/// `/sys/fs/cgroup/apm2.slice/episode-{episode_id}.scope/`
pub fn episode_cgroup_path(episode_id: &str) -> CgroupResult<PathBuf> {
    episode_cgroup_path_with_root(episode_id, CGROUP_V2_MOUNT)
}

/// Gets the episode cgroup path with a custom root.
pub fn episode_cgroup_path_with_root(episode_id: &str, cgroup_root: &str) -> CgroupResult<PathBuf> {
    validate_episode_id(episode_id)?;
    let scope_name = format!("episode-{episode_id}.scope");
    Ok(PathBuf::from(cgroup_root).join(APM2_SLICE).join(scope_name))
}

/// Validates an episode ID for use in cgroup scope names and D-Bus paths.
///
/// Per security review, this validation is strengthened to prevent:
/// - Path injection via `/`, `\0`, `..`
/// - D-Bus path injection via special characters
/// - Systemd unit name violations
///
/// Allowed characters: alphanumeric (a-z, A-Z, 0-9), hyphen (-), underscore (_)
/// This is the intersection of safe characters for:
/// - Cgroup paths (no `/`, `\0`)
/// - D-Bus object paths (alphanumeric + `_`)
/// - Systemd unit names (alphanumeric + `-:_.@`)
fn validate_episode_id(episode_id: &str) -> CgroupResult<()> {
    if episode_id.is_empty() {
        return Err(CgroupError::InvalidEpisodeId {
            reason: "episode ID cannot be empty".to_string(),
        });
    }

    if episode_id.len() > MAX_EPISODE_ID_LEN {
        return Err(CgroupError::InvalidEpisodeId {
            reason: format!("episode ID exceeds maximum length of {MAX_EPISODE_ID_LEN} characters"),
        });
    }

    // systemd scope names cannot start with '.'
    if episode_id.starts_with('.') {
        return Err(CgroupError::InvalidEpisodeId {
            reason: "episode ID cannot start with '.'".to_string(),
        });
    }

    // Check for path traversal patterns
    if episode_id.contains("..") {
        return Err(CgroupError::InvalidEpisodeId {
            reason: "episode ID cannot contain '..' (path traversal)".to_string(),
        });
    }

    // Validate all characters are safe for cgroups, D-Bus, and systemd
    // Allow: a-z, A-Z, 0-9, -, _
    // This is intentionally restrictive to be safe across all contexts
    for (idx, ch) in episode_id.chars().enumerate() {
        let is_safe = ch.is_ascii_alphanumeric() || ch == '-' || ch == '_';
        if !is_safe {
            return Err(CgroupError::InvalidEpisodeId {
                reason: format!(
                    "episode ID contains invalid character '{}' at position {} \
                     (allowed: alphanumeric, hyphen, underscore)",
                    ch.escape_debug(),
                    idx
                ),
            });
        }
    }

    Ok(())
}

/// Checks which cgroup controllers are available at a path.
fn check_controllers(cgroup_path: &Path) -> ControllerAvailability {
    ControllerAvailability {
        cpu: cgroup_path.join("cpu.stat").exists(),
        memory: cgroup_path.join("memory.current").exists(),
        io: cgroup_path.join("io.stat").exists(),
    }
}

// ============================================================================
// Cgroup Scope Creation (per AD-CGROUP-001)
// ============================================================================

/// OS-level resource limits for an episode cgroup scope.
///
/// Specifies the resource constraints to apply when creating a cgroup scope.
/// This type represents OS-level cgroup limits, distinct from the application-
/// level `EpisodeBudget` type used for work tracking.
///
/// # Note
///
/// Named `OsResourceLimits` to avoid collision with the central `EpisodeBudget`
/// type in the episode module, which tracks application-level resource budgets.
#[derive(Debug, Clone, Default)]
pub struct OsResourceLimits {
    /// Memory limit in bytes (maps to `memory.max`).
    pub memory_bytes: Option<u64>,
    /// CPU time limit in microseconds per period (maps to `cpu.max`).
    /// Format: `(quota_usec, period_usec)`. E.g., `(100000, 100000)` = 100% of
    /// one CPU.
    pub cpu_quota: Option<(u64, u64)>,
}

/// Strategy used to create a cgroup scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeCreationStrategy {
    /// Created via systemd transient API (D-Bus).
    SystemdTransient,
    /// Created via direct cgroup v2 writes (fallback).
    DirectWrite,
}

/// Result of scope creation.
#[derive(Debug)]
pub struct ScopeCreationResult {
    /// Path to the created cgroup.
    pub cgroup_path: PathBuf,
    /// Strategy used to create the scope.
    pub strategy: ScopeCreationStrategy,
}

/// Creates an episode cgroup scope for process isolation.
///
/// Per AD-CGROUP-001, this function:
/// 1. **Primary**: Uses systemd transient API via zbus (D-Bus)
/// 2. **Fallback**: Uses direct cgroup v2 writes
///
/// The "freeze trick" is used for direct writes: create the cgroup frozen,
/// assign the PID, then unfreeze to prevent race conditions.
///
/// # Arguments
///
/// * `episode_id` - The episode identifier (used in scope name)
/// * `pid` - The process ID to place in the cgroup
/// * `budget` - Optional resource limits to apply
///
/// # Returns
///
/// The path to the created cgroup and the strategy used.
///
/// # Errors
///
/// Returns `CgroupError::CreateFailed` if scope creation fails via both
/// strategies.
pub async fn create_episode_scope(
    episode_id: &str,
    pid: Pid,
    budget: Option<&OsResourceLimits>,
) -> CgroupResult<ScopeCreationResult> {
    create_episode_scope_with_root(episode_id, pid, budget, CGROUP_V2_MOUNT).await
}

/// Creates an episode cgroup scope with a custom cgroup root.
///
/// This is primarily for testing with mock cgroup hierarchies.
pub async fn create_episode_scope_with_root(
    episode_id: &str,
    pid: Pid,
    budget: Option<&OsResourceLimits>,
    cgroup_root: &str,
) -> CgroupResult<ScopeCreationResult> {
    validate_episode_id(episode_id)?;

    // Validate PID
    if pid.as_raw() <= 0 {
        return Err(CgroupError::CreateFailed {
            reason: format!("invalid PID: {}", pid.as_raw()),
        });
    }

    let scope_name = format!("episode-{episode_id}.scope");

    // Try systemd transient API first
    match create_scope_via_systemd(&scope_name, pid, budget).await {
        Ok(cgroup_path) => {
            debug!(
                episode_id,
                pid = %pid,
                path = %cgroup_path.display(),
                "created episode scope via systemd"
            );
            return Ok(ScopeCreationResult {
                cgroup_path,
                strategy: ScopeCreationStrategy::SystemdTransient,
            });
        },
        Err(e) => {
            debug!(
                episode_id,
                error = %e,
                "systemd transient API failed, trying direct write fallback"
            );
        },
    }

    // Fallback to direct cgroup v2 writes
    let cgroup_path = create_scope_via_direct_write(&scope_name, pid, budget, cgroup_root)?;

    debug!(
        episode_id,
        pid = %pid,
        path = %cgroup_path.display(),
        "created episode scope via direct write"
    );

    Ok(ScopeCreationResult {
        cgroup_path,
        strategy: ScopeCreationStrategy::DirectWrite,
    })
}

/// Creates a scope via systemd transient API.
///
/// Uses D-Bus to call `org.freedesktop.systemd1.Manager.StartTransientUnit`.
///
/// Note: Systemd unit names cannot contain slashes. The scope is placed in
/// the APM2 slice using the `Slice=` property rather than embedding the
/// slice name in the unit name.
async fn create_scope_via_systemd(
    scope_name: &str,
    pid: Pid,
    budget: Option<&OsResourceLimits>,
) -> CgroupResult<PathBuf> {
    use zbus::Connection;

    // Connect to the system bus
    let connection = Connection::system()
        .await
        .map_err(|e| CgroupError::CreateFailed {
            reason: format!("failed to connect to system bus: {e}"),
        })?;

    // Build properties for the scope
    // Safety: We validate PID is positive before calling this function
    let pid_u32 = u32::try_from(pid.as_raw()).map_err(|_| CgroupError::CreateFailed {
        reason: format!("PID {} cannot be converted to u32", pid.as_raw()),
    })?;
    let mut properties: Vec<(&str, zbus::zvariant::Value<'_>)> = vec![
        // PIDs to place in the scope
        ("PIDs", zbus::zvariant::Value::new(vec![pid_u32])),
        // Delegate controllers to allow nested cgroup management
        ("Delegate", zbus::zvariant::Value::new(true)),
        // Place the scope in the APM2 slice (systemd unit names cannot contain slashes)
        ("Slice", zbus::zvariant::Value::new(APM2_SLICE)),
    ];

    // Add resource limits if specified
    if let Some(limits) = budget {
        if let Some(memory_bytes) = limits.memory_bytes {
            properties.push(("MemoryMax", zbus::zvariant::Value::new(memory_bytes)));
        }
        if let Some((quota_usec, period_usec)) = limits.cpu_quota {
            // CPUQuotaPerSecUSec expects microseconds of CPU time allowed per second.
            // Given a quota in microseconds and a period in microseconds, we need to
            // scale to per-second: (quota_usec / period_usec) * 1_000_000 usec/sec
            // This simplifies to: (quota_usec * 1_000_000) / period_usec
            //
            // Example: quota=100000us, period=100000us means 100% of one CPU
            //          -> (100000 * 1_000_000) / 100000 = 1_000_000 usec/sec
            let quota_per_sec_usec = quota_usec
                .saturating_mul(1_000_000)
                .checked_div(period_usec)
                .unwrap_or(0);
            properties.push((
                "CPUQuotaPerSecUSec",
                zbus::zvariant::Value::new(quota_per_sec_usec),
            ));
        }
    }

    // Get the systemd manager proxy
    let proxy = zbus::fdo::ObjectManagerProxy::builder(&connection)
        .destination("org.freedesktop.systemd1")
        .map_err(|e| CgroupError::CreateFailed {
            reason: format!("failed to create proxy builder: {e}"),
        })?
        .path("/org/freedesktop/systemd1")
        .map_err(|e| CgroupError::CreateFailed {
            reason: format!("failed to set proxy path: {e}"),
        })?
        .build()
        .await
        .map_err(|e| CgroupError::CreateFailed {
            reason: format!("failed to build proxy: {e}"),
        })?;

    // Use low-level call to StartTransientUnit
    // Note: Unit name is just the scope name (e.g., "episode-abc123.scope"),
    // NOT "{slice}/{scope}" which would contain a forbidden slash character.
    let reply: zbus::Message = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "StartTransientUnit",
            // Arguments: name, mode, properties, aux
            &(
                scope_name.to_string(),
                "fail", // mode: fail if exists
                properties,
                Vec::<(String, Vec<(String, zbus::zvariant::Value<'_>)>)>::new(), // aux units
            ),
        )
        .await
        .map_err(|e| CgroupError::CreateFailed {
            reason: format!("StartTransientUnit failed: {e}"),
        })?;

    // Extract the job path from the reply (we don't need it, but verify success)
    let _: zbus::zvariant::OwnedObjectPath =
        reply
            .body()
            .deserialize()
            .map_err(|e| CgroupError::CreateFailed {
                reason: format!("failed to parse StartTransientUnit response: {e}"),
            })?;

    // The proxy is just for validation, actual path comes from cgroup root
    let _ = proxy;

    // Return the expected cgroup path
    Ok(PathBuf::from(CGROUP_V2_MOUNT)
        .join(APM2_SLICE)
        .join(scope_name))
}

/// Creates a scope via direct cgroup v2 writes (fallback).
///
/// Uses the "freeze trick" per AD-CGROUP-001:
/// 1. Create the cgroup directory frozen
/// 2. Assign the PID
/// 3. Unfreeze
///
/// This prevents race conditions where the process could escape before
/// being properly contained.
fn create_scope_via_direct_write(
    scope_name: &str,
    pid: Pid,
    budget: Option<&OsResourceLimits>,
    cgroup_root: &str,
) -> CgroupResult<PathBuf> {
    let slice_path = PathBuf::from(cgroup_root).join(APM2_SLICE);
    let scope_path = slice_path.join(scope_name);

    // Ensure the APM2 slice exists
    if !slice_path.exists() {
        fs::create_dir_all(&slice_path).map_err(|e| CgroupError::CreateFailed {
            reason: format!("failed to create slice directory: {e}"),
        })?;

        // Enable controllers in the slice
        enable_controllers(&slice_path);
    }

    // Create the scope directory
    fs::create_dir(&scope_path).map_err(|e| CgroupError::CreateFailed {
        reason: format!("failed to create scope directory: {e}"),
    })?;

    // Enable controllers in the scope
    enable_controllers(&scope_path);

    // Step 1: Freeze the cgroup (if freezer is available)
    let freeze_path = scope_path.join("cgroup.freeze");
    let had_freezer = if freeze_path.exists() {
        fs::write(&freeze_path, "1").map_err(|e| CgroupError::CreateFailed {
            reason: format!("failed to freeze cgroup: {e}"),
        })?;
        true
    } else {
        debug!("cgroup.freeze not available, skipping freeze trick");
        false
    };

    // Step 2: Assign the PID to the cgroup
    let procs_path = scope_path.join("cgroup.procs");
    fs::write(&procs_path, format!("{}\n", pid.as_raw())).map_err(|e| {
        CgroupError::CreateFailed {
            reason: format!("failed to assign PID to cgroup: {e}"),
        }
    })?;

    // Step 3: Apply resource limits
    if let Some(budget) = budget {
        if let Some(memory_bytes) = budget.memory_bytes {
            let memory_max_path = scope_path.join("memory.max");
            if memory_max_path.exists() {
                fs::write(&memory_max_path, format!("{memory_bytes}\n")).map_err(|e| {
                    CgroupError::CreateFailed {
                        reason: format!("failed to set memory.max: {e}"),
                    }
                })?;
            }
        }

        if let Some((quota, period)) = budget.cpu_quota {
            let cpu_max_path = scope_path.join("cpu.max");
            if cpu_max_path.exists() {
                fs::write(&cpu_max_path, format!("{quota} {period}\n")).map_err(|e| {
                    CgroupError::CreateFailed {
                        reason: format!("failed to set cpu.max: {e}"),
                    }
                })?;
            }
        }
    }

    // Step 4: Unfreeze the cgroup
    if had_freezer {
        fs::write(&freeze_path, "0").map_err(|e| CgroupError::CreateFailed {
            reason: format!("failed to unfreeze cgroup: {e}"),
        })?;
    }

    Ok(scope_path)
}

/// Enables cgroup controllers in a directory.
///
/// Writes to `cgroup.subtree_control` to enable cpu, memory, and io
/// controllers.
fn enable_controllers(path: &Path) {
    let subtree_control = path.join("cgroup.subtree_control");
    if subtree_control.exists() {
        // Enable common controllers
        // Note: This may fail if controllers are not available, which is OK
        let _ = fs::write(&subtree_control, "+cpu +memory +io");
    }
}

/// Removes an episode cgroup scope.
///
/// This should be called after the process has terminated to clean up
/// the cgroup hierarchy.
///
/// # Arguments
///
/// * `episode_id` - The episode identifier
///
/// # Errors
///
/// Returns `CgroupError::PathNotFound` if the scope doesn't exist.
pub fn remove_episode_scope(episode_id: &str) -> CgroupResult<()> {
    remove_episode_scope_with_root(episode_id, CGROUP_V2_MOUNT)
}

/// Removes an episode cgroup scope with a custom root.
pub fn remove_episode_scope_with_root(episode_id: &str, cgroup_root: &str) -> CgroupResult<()> {
    validate_episode_id(episode_id)?;

    let scope_name = format!("episode-{episode_id}.scope");
    let scope_path = PathBuf::from(cgroup_root).join(APM2_SLICE).join(scope_name);

    if !scope_path.exists() {
        return Err(CgroupError::PathNotFound {
            path: scope_path.display().to_string(),
        });
    }

    // Remove the scope directory
    // Note: This will fail if there are still processes in the cgroup
    fs::remove_dir(&scope_path).map_err(|e| CgroupError::CreateFailed {
        reason: format!("failed to remove scope directory: {e}"),
    })?;

    Ok(())
}

/// Reads a cgroup file as a string with bounded size.
///
/// Uses `Read::take()` to limit reads to `MAX_TELEMETRY_FILE_SIZE` bytes,
/// preventing denial-of-service via unbounded file reads on paths derived
/// from external IDs.
fn read_cgroup_file(path: &Path) -> CgroupResult<String> {
    let file = File::open(path).map_err(|e| CgroupError::ReadFailed {
        file: path.display().to_string(),
        source: e,
    })?;

    let mut reader = BufReader::new(file).take(MAX_TELEMETRY_FILE_SIZE);
    let mut content = String::new();

    reader
        .read_to_string(&mut content)
        .map_err(|e| CgroupError::ReadFailed {
            file: path.display().to_string(),
            source: e,
        })?;

    Ok(content)
}

/// Parses a u64 value from a string.
fn parse_u64(s: &str, file: &str, field: &str) -> CgroupResult<u64> {
    s.parse::<u64>().map_err(|_| CgroupError::ParseFailed {
        file: file.to_string(),
        reason: format!("invalid {field} value: '{s}'"),
    })
}

/// Parses memory.stat for page fault counters.
///
/// Returns `Ok((major, minor))` on success, or `Err` if required fields
/// cannot be parsed. This is fail-closed behavior per security review.
fn parse_memory_stat(content: &str) -> CgroupResult<(u64, u64)> {
    let mut pgmajfault: Option<u64> = None;
    let mut pgfault: Option<u64> = None;

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "pgmajfault" => {
                    pgmajfault = Some(parts[1].parse().map_err(|_| CgroupError::ParseFailed {
                        file: "memory.stat".to_string(),
                        reason: format!("invalid pgmajfault value: '{}'", parts[1]),
                    })?);
                },
                "pgfault" => {
                    pgfault = Some(parts[1].parse().map_err(|_| CgroupError::ParseFailed {
                        file: "memory.stat".to_string(),
                        reason: format!("invalid pgfault value: '{}'", parts[1]),
                    })?);
                },
                _ => {},
            }
        }
    }

    // Both fields are required for accurate metrics
    let pgmajfault = pgmajfault.ok_or_else(|| CgroupError::ParseFailed {
        file: "memory.stat".to_string(),
        reason: "missing pgmajfault field".to_string(),
    })?;

    let pgfault = pgfault.ok_or_else(|| CgroupError::ParseFailed {
        file: "memory.stat".to_string(),
        reason: "missing pgfault field".to_string(),
    })?;

    // pgfault is total, pgmajfault is major; minor = total - major
    let pgminorfault = pgfault.saturating_sub(pgmajfault);
    Ok((pgmajfault, pgminorfault))
}

/// Parses a single line from io.stat.
///
/// Returns `Ok(HashMap)` on success, or `Err` if the line format is invalid.
/// This is fail-closed behavior per security review.
fn parse_io_stat_line(line: &str) -> CgroupResult<HashMap<&str, u64>> {
    let mut stats = HashMap::new();

    // Empty lines are valid (no I/O recorded)
    if line.trim().is_empty() {
        return Ok(stats);
    }

    // Skip the device identifier (first field)
    for part in line.split_whitespace().skip(1) {
        if let Some((key, value)) = part.split_once('=') {
            let v = value.parse::<u64>().map_err(|_| CgroupError::ParseFailed {
                file: "io.stat".to_string(),
                reason: format!("invalid value for key '{key}': '{value}'"),
            })?;
            stats.insert(key, v);
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // UT-00168-01: cgroup_read tests
    // ========================================================================

    #[test]
    fn test_validate_episode_id_valid() {
        assert!(validate_episode_id("ep-abc123").is_ok());
        assert!(validate_episode_id("test-episode-1").is_ok());
        assert!(validate_episode_id("a").is_ok());
    }

    #[test]
    fn test_validate_episode_id_empty() {
        let result = validate_episode_id("");
        assert!(matches!(
            result,
            Err(CgroupError::InvalidEpisodeId { reason }) if reason.contains("empty")
        ));
    }

    #[test]
    fn test_validate_episode_id_too_long() {
        let long_id = "x".repeat(MAX_EPISODE_ID_LEN + 1);
        let result = validate_episode_id(&long_id);
        assert!(matches!(
            result,
            Err(CgroupError::InvalidEpisodeId { reason }) if reason.contains("maximum length")
        ));
    }

    #[test]
    fn test_validate_episode_id_slash() {
        let result = validate_episode_id("ep/123");
        assert!(matches!(
            result,
            Err(CgroupError::InvalidEpisodeId { reason }) if reason.contains("invalid character")
        ));
    }

    #[test]
    fn test_validate_episode_id_null() {
        let result = validate_episode_id("ep\x00123");
        assert!(matches!(
            result,
            Err(CgroupError::InvalidEpisodeId { reason }) if reason.contains("invalid character")
        ));
    }

    #[test]
    fn test_validate_episode_id_path_traversal() {
        let result = validate_episode_id("ep..123");
        assert!(matches!(
            result,
            Err(CgroupError::InvalidEpisodeId { reason }) if reason.contains("path traversal")
        ));
    }

    #[test]
    fn test_validate_episode_id_special_chars() {
        // Test various special characters that should be rejected
        for bad_char in ['@', ':', '.', '!', ' ', '\t', '\n', '\\', '`', '$', '%'] {
            let id = format!("ep{bad_char}123");
            let result = validate_episode_id(&id);
            assert!(
                matches!(result, Err(CgroupError::InvalidEpisodeId { .. })),
                "expected rejection for character '{bad_char}'"
            );
        }
    }

    #[test]
    fn test_validate_episode_id_underscore_allowed() {
        assert!(validate_episode_id("ep_abc_123").is_ok());
    }

    #[test]
    fn test_validate_episode_id_dot_prefix() {
        let result = validate_episode_id(".hidden");
        assert!(matches!(
            result,
            Err(CgroupError::InvalidEpisodeId { reason }) if reason.contains("'.'")
        ));
    }

    #[test]
    fn test_episode_cgroup_path() {
        let path = episode_cgroup_path_with_root("test-ep", "/cgroup").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/cgroup/apm2.slice/episode-test-ep.scope")
        );
    }

    #[test]
    fn test_parse_memory_stat() {
        let content = "pgfault 1000\npgmajfault 10\nother 123\n";
        let (major, minor) = parse_memory_stat(content).unwrap();
        assert_eq!(major, 10);
        assert_eq!(minor, 990); // 1000 - 10
    }

    #[test]
    fn test_parse_memory_stat_missing_pgfault() {
        let content = "pgmajfault 10\nother 123\n";
        let result = parse_memory_stat(content);
        assert!(matches!(
            result,
            Err(CgroupError::ParseFailed { reason, .. }) if reason.contains("pgfault")
        ));
    }

    #[test]
    fn test_parse_memory_stat_invalid_value() {
        let content = "pgfault notanumber\npgmajfault 10\n";
        let result = parse_memory_stat(content);
        assert!(matches!(result, Err(CgroupError::ParseFailed { .. })));
    }

    #[test]
    fn test_parse_io_stat_line() {
        let line = "8:0 rbytes=12345 wbytes=67890 rios=100 wios=50";
        let stats = parse_io_stat_line(line).unwrap();
        assert_eq!(stats.get("rbytes"), Some(&12345));
        assert_eq!(stats.get("wbytes"), Some(&67890));
        assert_eq!(stats.get("rios"), Some(&100));
        assert_eq!(stats.get("wios"), Some(&50));
    }

    #[test]
    fn test_parse_io_stat_line_empty() {
        let line = "";
        let stats = parse_io_stat_line(line).unwrap();
        assert!(stats.is_empty());
    }

    #[test]
    fn test_parse_io_stat_line_invalid_value() {
        let line = "8:0 rbytes=notanumber";
        let result = parse_io_stat_line(line);
        assert!(matches!(result, Err(CgroupError::ParseFailed { .. })));
    }

    #[test]
    fn test_is_cgroup_v2_available_at() {
        // Test with a path that definitely doesn't exist
        assert!(!is_cgroup_v2_available_at("/nonexistent/cgroup/path"));
    }

    #[test]
    fn test_cgroup_error_display() {
        let err = CgroupError::NotAvailable {
            reason: "test".to_string(),
        };
        assert!(err.to_string().contains("test"));

        let err = CgroupError::PathNotFound {
            path: "/test/path".to_string(),
        };
        assert!(err.to_string().contains("/test/path"));

        let err = CgroupError::ControllerNotEnabled {
            controller: "cpu".to_string(),
        };
        assert!(err.to_string().contains("cpu"));
    }

    #[test]
    fn test_controller_availability_default() {
        let avail = ControllerAvailability::default();
        assert!(!avail.cpu);
        assert!(!avail.memory);
        assert!(!avail.io);
    }

    // Integration test that requires actual cgroup access
    #[test]
    #[ignore = "requires cgroup v2 access"]
    fn test_cgroup_reader_real() {
        // This test requires setting up a real cgroup scope
        // Skip in CI environments without cgroup access
    }
}
