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
use std::fs;
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
    fn read_memory_from_cgroup(&self) -> CgroupResult<MemoryStats> {
        // Read memory.current
        let current_path = self.cgroup_path.join("memory.current");
        let current_content = read_cgroup_file(&current_path)?;
        let rss_bytes = parse_u64(current_content.trim(), "memory.current", "value")?;

        // Read memory.peak (may not exist on older kernels)
        let peak_bytes = read_cgroup_file(&self.cgroup_path.join("memory.peak"))
            .map_or(rss_bytes, |content| {
                parse_u64(content.trim(), "memory.peak", "value").unwrap_or(rss_bytes)
            });

        // Read memory.stat for page faults
        let (page_faults_major, page_faults_minor) =
            read_cgroup_file(&self.cgroup_path.join("memory.stat"))
                .map_or((0, 0), |content| parse_memory_stat(&content));

        Ok(MemoryStats::new(
            rss_bytes,
            peak_bytes,
            page_faults_major,
            page_faults_minor,
            MetricSource::Cgroup,
        ))
    }

    /// Reads I/O stats from cgroup files.
    fn read_io_from_cgroup(&self) -> CgroupResult<IoStats> {
        let io_stat_path = self.cgroup_path.join("io.stat");
        let content = read_cgroup_file(&io_stat_path)?;

        let mut total_read_bytes: u64 = 0;
        let mut total_write_bytes: u64 = 0;
        let mut total_read_ops: u64 = 0;
        let mut total_write_ops: u64 = 0;

        // io.stat format: <major>:<minor> rbytes=<n> wbytes=<n> rios=<n> wios=<n> ...
        for line in content.lines() {
            let stats = parse_io_stat_line(line);
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

/// Validates an episode ID for use in cgroup scope names.
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

    // Forbidden characters in cgroup names
    if episode_id.contains('/') {
        return Err(CgroupError::InvalidEpisodeId {
            reason: "episode ID cannot contain '/'".to_string(),
        });
    }

    if episode_id.contains('\0') {
        return Err(CgroupError::InvalidEpisodeId {
            reason: "episode ID cannot contain null bytes".to_string(),
        });
    }

    // systemd scope names have additional restrictions
    if episode_id.starts_with('.') {
        return Err(CgroupError::InvalidEpisodeId {
            reason: "episode ID cannot start with '.'".to_string(),
        });
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

/// Reads a cgroup file as a string.
fn read_cgroup_file(path: &Path) -> CgroupResult<String> {
    fs::read_to_string(path).map_err(|e| CgroupError::ReadFailed {
        file: path.display().to_string(),
        source: e,
    })
}

/// Parses a u64 value from a string.
fn parse_u64(s: &str, file: &str, field: &str) -> CgroupResult<u64> {
    s.parse::<u64>().map_err(|_| CgroupError::ParseFailed {
        file: file.to_string(),
        reason: format!("invalid {field} value: '{s}'"),
    })
}

/// Parses memory.stat for page fault counters.
fn parse_memory_stat(content: &str) -> (u64, u64) {
    let mut pgmajfault: u64 = 0;
    let mut pgfault: u64 = 0;

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "pgmajfault" => {
                    pgmajfault = parts[1].parse().unwrap_or(0);
                },
                "pgfault" => {
                    pgfault = parts[1].parse().unwrap_or(0);
                },
                _ => {},
            }
        }
    }

    // pgfault is total, pgmajfault is major; minor = total - major
    let pgminorfault = pgfault.saturating_sub(pgmajfault);
    (pgmajfault, pgminorfault)
}

/// Parses a single line from io.stat.
fn parse_io_stat_line(line: &str) -> HashMap<&str, u64> {
    let mut stats = HashMap::new();

    // Skip the device identifier (first field)
    for part in line.split_whitespace().skip(1) {
        if let Some((key, value)) = part.split_once('=') {
            if let Ok(v) = value.parse::<u64>() {
                stats.insert(key, v);
            }
        }
    }

    stats
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
            Err(CgroupError::InvalidEpisodeId { reason }) if reason.contains("'/'")
        ));
    }

    #[test]
    fn test_validate_episode_id_null() {
        let result = validate_episode_id("ep\x00123");
        assert!(matches!(
            result,
            Err(CgroupError::InvalidEpisodeId { reason }) if reason.contains("null")
        ));
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
        let (major, minor) = parse_memory_stat(content);
        assert_eq!(major, 10);
        assert_eq!(minor, 990); // 1000 - 10
    }

    #[test]
    fn test_parse_io_stat_line() {
        let line = "8:0 rbytes=12345 wbytes=67890 rios=100 wios=50";
        let stats = parse_io_stat_line(line);
        assert_eq!(stats.get("rbytes"), Some(&12345));
        assert_eq!(stats.get("wbytes"), Some(&67890));
        assert_eq!(stats.get("rios"), Some(&100));
        assert_eq!(stats.get("wios"), Some(&50));
    }

    #[test]
    fn test_parse_io_stat_line_empty() {
        let line = "";
        let stats = parse_io_stat_line(line);
        assert!(stats.is_empty());
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
