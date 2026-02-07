//! Telemetry statistics types for resource metrics.
//!
//! This module defines the core metric types for episode resource consumption
//! per AD-TEL-001. These types represent CPU, memory, and I/O statistics
//! collected from cgroups v2 or `/proc` fallback sources.
//!
//! # Architecture
//!
//! Statistics are collected from two possible sources:
//! - **Primary**: cgroups v2 hierarchy
//!   (`/sys/fs/cgroup/apm2.slice/episode-{uuid}.scope/`)
//! - **Fallback**: `/proc/{pid}/` when cgroup isolation is unavailable
//!
//! The `MetricSource` field on each stat type indicates the collection source,
//! enabling callers to assess telemetry accuracy for enforcement decisions.
//!
//! # Contract References
//!
//! - AD-TEL-001: Telemetry collection via cgroups v2
//! - AD-CGROUP-001: Per-episode cgroup hierarchy

use serde::{Deserialize, Serialize};

/// Maximum nanoseconds value (prevents overflow in calculations).
pub const MAX_NS: u64 = u64::MAX / 2;

/// Maximum bytes value (prevents overflow in calculations).
pub const MAX_BYTES: u64 = u64::MAX / 2;

/// Maximum operations count (prevents overflow in calculations).
pub const MAX_OPS: u64 = u64::MAX / 2;

/// Maximum page fault count (prevents overflow in calculations).
pub const MAX_PAGE_FAULTS: u64 = u64::MAX / 2;

/// Source of metric collection.
///
/// Indicates where telemetry data was collected from, enabling callers
/// to assess accuracy for enforcement decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricSource {
    /// Metrics collected from cgroups v2 hierarchy (high accuracy).
    Cgroup,
    /// Metrics collected from `/proc/{pid}/` (degraded accuracy).
    Proc,
    /// Metrics unavailable or collection failed.
    #[default]
    Unavailable,
}

impl MetricSource {
    /// Returns `true` if metrics are from the authoritative cgroup source.
    #[must_use]
    pub const fn is_cgroup(&self) -> bool {
        matches!(self, Self::Cgroup)
    }

    /// Returns `true` if metrics are from the degraded `/proc` source.
    #[must_use]
    pub const fn is_proc(&self) -> bool {
        matches!(self, Self::Proc)
    }

    /// Returns `true` if metrics are unavailable.
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

/// CPU usage statistics.
///
/// Represents CPU time consumption for an episode, collected from either
/// cgroups v2 `cpu.stat` or `/proc/{pid}/stat`.
///
/// # Fields
///
/// Per AD-TEL-001:
/// - `usage_ns`: Total CPU time in nanoseconds
/// - `user_ns`: User-mode CPU time in nanoseconds
/// - `system_ns`: Kernel-mode CPU time in nanoseconds
///
/// # Invariants
///
/// - [INV-CPU001] `usage_ns >= user_ns + system_ns` (may include wait time)
/// - [INV-CPU002] All values are bounded by `MAX_NS` to prevent overflow
///
/// # Example
///
/// ```rust
/// use apm2_daemon::telemetry::{CpuStats, MetricSource};
///
/// let stats = CpuStats::new(
///     1_000_000_000,
///     600_000_000,
///     400_000_000,
///     MetricSource::Cgroup,
/// );
/// assert_eq!(stats.usage_ns(), 1_000_000_000);
/// assert!(stats.source().is_cgroup());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuStats {
    /// Total CPU time in nanoseconds.
    usage_ns: u64,
    /// User-mode CPU time in nanoseconds.
    user_ns: u64,
    /// Kernel-mode CPU time in nanoseconds.
    system_ns: u64,
    /// Source of the metrics.
    source: MetricSource,
}

impl CpuStats {
    /// Creates new CPU statistics.
    ///
    /// Values are clamped to `MAX_NS` to prevent overflow.
    ///
    /// # Note
    ///
    /// This constructor does not enforce the invariant `usage >= user +
    /// system`. Use [`try_new`](Self::try_new) for strict validation.
    #[must_use]
    pub const fn new(usage_ns: u64, user_ns: u64, system_ns: u64, source: MetricSource) -> Self {
        Self {
            usage_ns: if usage_ns > MAX_NS { MAX_NS } else { usage_ns },
            user_ns: if user_ns > MAX_NS { MAX_NS } else { user_ns },
            system_ns: if system_ns > MAX_NS {
                MAX_NS
            } else {
                system_ns
            },
            source,
        }
    }

    /// Creates new CPU statistics with invariant validation.
    ///
    /// # Errors
    ///
    /// Returns an error string if `usage_ns < user_ns + system_ns`.
    pub fn try_new(
        usage_ns: u64,
        user_ns: u64,
        system_ns: u64,
        source: MetricSource,
    ) -> Result<Self, String> {
        let stats = Self::new(usage_ns, user_ns, system_ns, source);
        stats.validate()?;
        Ok(stats)
    }

    /// Validates the CPU stats invariants.
    ///
    /// # Invariants
    ///
    /// - [INV-CPU001] `usage_ns >= user_ns + system_ns` (may include wait time)
    ///
    /// # Errors
    ///
    /// Returns an error string describing the violated invariant.
    pub fn validate(&self) -> Result<(), String> {
        let user_plus_system = self.user_ns.saturating_add(self.system_ns);
        if self.usage_ns < user_plus_system {
            return Err(format!(
                "INV-CPU001 violated: usage_ns ({}) < user_ns ({}) + system_ns ({})",
                self.usage_ns, self.user_ns, self.system_ns
            ));
        }
        Ok(())
    }

    /// Creates CPU statistics indicating unavailable metrics.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            usage_ns: 0,
            user_ns: 0,
            system_ns: 0,
            source: MetricSource::Unavailable,
        }
    }

    /// Returns the total CPU time in nanoseconds.
    #[must_use]
    pub const fn usage_ns(&self) -> u64 {
        self.usage_ns
    }

    /// Returns the user-mode CPU time in nanoseconds.
    #[must_use]
    pub const fn user_ns(&self) -> u64 {
        self.user_ns
    }

    /// Returns the kernel-mode CPU time in nanoseconds.
    #[must_use]
    pub const fn system_ns(&self) -> u64 {
        self.system_ns
    }

    /// Returns the metric source.
    #[must_use]
    pub const fn source(&self) -> MetricSource {
        self.source
    }

    /// Returns `true` if metrics are available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        !self.source.is_unavailable()
    }

    /// Returns the total CPU time in milliseconds.
    #[must_use]
    pub const fn usage_ms(&self) -> u64 {
        self.usage_ns / 1_000_000
    }
}

impl Default for CpuStats {
    fn default() -> Self {
        Self::unavailable()
    }
}

/// Memory usage statistics.
///
/// Represents memory consumption for an episode, collected from either
/// cgroups v2 `memory.current`/`memory.peak`/`memory.stat` or
/// `/proc/{pid}/statm`.
///
/// # Fields
///
/// Per AD-TEL-001:
/// - `rss_bytes`: Resident set size (physical memory used)
/// - `peak_bytes`: Peak memory usage during episode
/// - `page_faults_major`: Major page faults (required disk I/O)
/// - `page_faults_minor`: Minor page faults (no disk I/O)
///
/// # Invariants
///
/// - [INV-MEM001] `peak_bytes >= rss_bytes` at collection time
/// - [INV-MEM002] All values are bounded to prevent overflow
///
/// # Example
///
/// ```rust
/// use apm2_daemon::telemetry::{MemoryStats, MetricSource};
///
/// let stats = MemoryStats::new(
///     1024 * 1024 * 100, // 100 MiB RSS
///     1024 * 1024 * 150, // 150 MiB peak
///     10,                // major faults
///     1000,              // minor faults
///     MetricSource::Cgroup,
/// );
/// assert_eq!(stats.rss_bytes(), 104_857_600);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryStats {
    /// Resident set size in bytes (physical memory used).
    rss_bytes: u64,
    /// Peak memory usage in bytes.
    peak_bytes: u64,
    /// Major page faults (required disk I/O).
    page_faults_major: u64,
    /// Minor page faults (no disk I/O).
    page_faults_minor: u64,
    /// Source of the metrics.
    source: MetricSource,
}

impl MemoryStats {
    /// Creates new memory statistics.
    ///
    /// Values are clamped to their respective maximums to prevent overflow.
    ///
    /// # Note
    ///
    /// This constructor does not enforce the invariant `peak >= rss`.
    /// Use [`try_new`](Self::try_new) for strict validation.
    #[must_use]
    pub const fn new(
        rss_bytes: u64,
        peak_bytes: u64,
        page_faults_major: u64,
        page_faults_minor: u64,
        source: MetricSource,
    ) -> Self {
        Self {
            rss_bytes: if rss_bytes > MAX_BYTES {
                MAX_BYTES
            } else {
                rss_bytes
            },
            peak_bytes: if peak_bytes > MAX_BYTES {
                MAX_BYTES
            } else {
                peak_bytes
            },
            page_faults_major: if page_faults_major > MAX_PAGE_FAULTS {
                MAX_PAGE_FAULTS
            } else {
                page_faults_major
            },
            page_faults_minor: if page_faults_minor > MAX_PAGE_FAULTS {
                MAX_PAGE_FAULTS
            } else {
                page_faults_minor
            },
            source,
        }
    }

    /// Creates new memory statistics with invariant validation.
    ///
    /// # Errors
    ///
    /// Returns an error string if `peak_bytes < rss_bytes`.
    pub fn try_new(
        rss_bytes: u64,
        peak_bytes: u64,
        page_faults_major: u64,
        page_faults_minor: u64,
        source: MetricSource,
    ) -> Result<Self, String> {
        let stats = Self::new(
            rss_bytes,
            peak_bytes,
            page_faults_major,
            page_faults_minor,
            source,
        );
        stats.validate()?;
        Ok(stats)
    }

    /// Validates the memory stats invariants.
    ///
    /// # Invariants
    ///
    /// - [INV-MEM001] `peak_bytes >= rss_bytes` at collection time
    ///
    /// # Errors
    ///
    /// Returns an error string describing the violated invariant.
    pub fn validate(&self) -> Result<(), String> {
        if self.peak_bytes < self.rss_bytes {
            return Err(format!(
                "INV-MEM001 violated: peak_bytes ({}) < rss_bytes ({})",
                self.peak_bytes, self.rss_bytes
            ));
        }
        Ok(())
    }

    /// Creates memory statistics indicating unavailable metrics.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            rss_bytes: 0,
            peak_bytes: 0,
            page_faults_major: 0,
            page_faults_minor: 0,
            source: MetricSource::Unavailable,
        }
    }

    /// Returns the resident set size in bytes.
    #[must_use]
    pub const fn rss_bytes(&self) -> u64 {
        self.rss_bytes
    }

    /// Returns the peak memory usage in bytes.
    #[must_use]
    pub const fn peak_bytes(&self) -> u64 {
        self.peak_bytes
    }

    /// Returns the major page fault count.
    #[must_use]
    pub const fn page_faults_major(&self) -> u64 {
        self.page_faults_major
    }

    /// Returns the minor page fault count.
    #[must_use]
    pub const fn page_faults_minor(&self) -> u64 {
        self.page_faults_minor
    }

    /// Returns the total page fault count.
    #[must_use]
    pub const fn page_faults(&self) -> u64 {
        self.page_faults_major
            .saturating_add(self.page_faults_minor)
    }

    /// Returns the metric source.
    #[must_use]
    pub const fn source(&self) -> MetricSource {
        self.source
    }

    /// Returns `true` if metrics are available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        !self.source.is_unavailable()
    }

    /// Returns the RSS in mebibytes (MiB).
    #[must_use]
    pub const fn rss_mib(&self) -> u64 {
        self.rss_bytes / (1024 * 1024)
    }
}

impl Default for MemoryStats {
    fn default() -> Self {
        Self::unavailable()
    }
}

/// I/O usage statistics.
///
/// Represents I/O consumption for an episode, collected from either
/// cgroups v2 `io.stat` or `/proc/{pid}/io`.
///
/// # Fields
///
/// Per AD-TEL-001:
/// - `read_bytes`: Total bytes read
/// - `write_bytes`: Total bytes written
/// - `read_ops`: Number of read operations
/// - `write_ops`: Number of write operations
///
/// # Invariants
///
/// - [INV-IO001] All values are bounded to prevent overflow
///
/// # Example
///
/// ```rust
/// use apm2_daemon::telemetry::{IoStats, MetricSource};
///
/// let stats = IoStats::new(
///     1024 * 1024 * 50, // 50 MiB read
///     1024 * 1024 * 10, // 10 MiB written
///     1000,             // read ops
///     200,              // write ops
///     MetricSource::Cgroup,
/// );
/// assert_eq!(stats.total_bytes(), 62_914_560);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoStats {
    /// Total bytes read.
    read_bytes: u64,
    /// Total bytes written.
    write_bytes: u64,
    /// Number of read operations.
    read_ops: u64,
    /// Number of write operations.
    write_ops: u64,
    /// Source of the metrics.
    source: MetricSource,
}

impl IoStats {
    /// Creates new I/O statistics.
    ///
    /// Values are clamped to their respective maximums to prevent overflow.
    #[must_use]
    pub const fn new(
        read_bytes: u64,
        write_bytes: u64,
        read_ops: u64,
        write_ops: u64,
        source: MetricSource,
    ) -> Self {
        Self {
            read_bytes: if read_bytes > MAX_BYTES {
                MAX_BYTES
            } else {
                read_bytes
            },
            write_bytes: if write_bytes > MAX_BYTES {
                MAX_BYTES
            } else {
                write_bytes
            },
            read_ops: if read_ops > MAX_OPS {
                MAX_OPS
            } else {
                read_ops
            },
            write_ops: if write_ops > MAX_OPS {
                MAX_OPS
            } else {
                write_ops
            },
            source,
        }
    }

    /// Creates I/O statistics indicating unavailable metrics.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            read_bytes: 0,
            write_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            source: MetricSource::Unavailable,
        }
    }

    /// Returns the total bytes read.
    #[must_use]
    pub const fn read_bytes(&self) -> u64 {
        self.read_bytes
    }

    /// Returns the total bytes written.
    #[must_use]
    pub const fn write_bytes(&self) -> u64 {
        self.write_bytes
    }

    /// Returns the number of read operations.
    #[must_use]
    pub const fn read_ops(&self) -> u64 {
        self.read_ops
    }

    /// Returns the number of write operations.
    #[must_use]
    pub const fn write_ops(&self) -> u64 {
        self.write_ops
    }

    /// Returns the total bytes (read + write).
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.read_bytes.saturating_add(self.write_bytes)
    }

    /// Returns the total operations (read + write).
    #[must_use]
    pub const fn total_ops(&self) -> u64 {
        self.read_ops.saturating_add(self.write_ops)
    }

    /// Returns the metric source.
    #[must_use]
    pub const fn source(&self) -> MetricSource {
        self.source
    }

    /// Returns `true` if metrics are available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        !self.source.is_unavailable()
    }
}

impl Default for IoStats {
    fn default() -> Self {
        Self::unavailable()
    }
}

/// Combined resource statistics snapshot.
///
/// Aggregates CPU, memory, and I/O statistics for a single telemetry
/// collection point. This is the primary type for telemetry frames.
///
/// # Example
///
/// ```rust
/// use apm2_daemon::telemetry::{CpuStats, IoStats, MemoryStats, MetricSource, ResourceStats};
///
/// let stats = ResourceStats::new(
///     CpuStats::new(
///         1_000_000_000,
///         600_000_000,
///         400_000_000,
///         MetricSource::Cgroup,
///     ),
///     MemoryStats::new(104_857_600, 157_286_400, 10, 1000, MetricSource::Cgroup),
///     IoStats::new(52_428_800, 10_485_760, 1000, 200, MetricSource::Cgroup),
/// );
/// assert!(stats.all_available());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResourceStats {
    /// CPU statistics.
    pub cpu: CpuStats,
    /// Memory statistics.
    pub memory: MemoryStats,
    /// I/O statistics.
    pub io: IoStats,
}

impl ResourceStats {
    /// Creates a new resource statistics snapshot.
    #[must_use]
    pub const fn new(cpu: CpuStats, memory: MemoryStats, io: IoStats) -> Self {
        Self { cpu, memory, io }
    }

    /// Creates resource statistics indicating all metrics unavailable.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            cpu: CpuStats::unavailable(),
            memory: MemoryStats::unavailable(),
            io: IoStats::unavailable(),
        }
    }

    /// Returns `true` if all metric categories are available.
    #[must_use]
    pub const fn all_available(&self) -> bool {
        self.cpu.is_available() && self.memory.is_available() && self.io.is_available()
    }

    /// Returns `true` if any metric category is from the degraded `/proc`
    /// source.
    #[must_use]
    pub const fn has_degraded_source(&self) -> bool {
        self.cpu.source().is_proc() || self.memory.source().is_proc() || self.io.source().is_proc()
    }

    /// Returns `true` if all available metrics are from cgroup source.
    #[must_use]
    pub const fn all_from_cgroup(&self) -> bool {
        (self.cpu.source().is_cgroup() || self.cpu.source().is_unavailable())
            && (self.memory.source().is_cgroup() || self.memory.source().is_unavailable())
            && (self.io.source().is_cgroup() || self.io.source().is_unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // CpuStats tests
    // ========================================================================

    #[test]
    fn test_cpu_stats_new() {
        let stats = CpuStats::new(
            1_000_000_000,
            600_000_000,
            400_000_000,
            MetricSource::Cgroup,
        );
        assert_eq!(stats.usage_ns(), 1_000_000_000);
        assert_eq!(stats.user_ns(), 600_000_000);
        assert_eq!(stats.system_ns(), 400_000_000);
        assert!(stats.source().is_cgroup());
        assert!(stats.is_available());
    }

    #[test]
    fn test_cpu_stats_unavailable() {
        let stats = CpuStats::unavailable();
        assert_eq!(stats.usage_ns(), 0);
        assert!(!stats.is_available());
        assert!(stats.source().is_unavailable());
    }

    #[test]
    fn test_cpu_stats_clamping() {
        let stats = CpuStats::new(u64::MAX, u64::MAX, u64::MAX, MetricSource::Cgroup);
        assert_eq!(stats.usage_ns(), MAX_NS);
        assert_eq!(stats.user_ns(), MAX_NS);
        assert_eq!(stats.system_ns(), MAX_NS);
    }

    #[test]
    fn test_cpu_stats_usage_ms() {
        let stats = CpuStats::new(1_500_000_000, 0, 0, MetricSource::Cgroup);
        assert_eq!(stats.usage_ms(), 1500);
    }

    #[test]
    fn test_cpu_stats_validate_ok() {
        // usage >= user + system
        let stats = CpuStats::new(
            1_000_000_000,
            600_000_000,
            400_000_000,
            MetricSource::Cgroup,
        );
        assert!(stats.validate().is_ok());
    }

    #[test]
    fn test_cpu_stats_validate_fail() {
        // usage < user + system violates invariant
        let stats = CpuStats::new(500_000_000, 600_000_000, 400_000_000, MetricSource::Cgroup);
        let result = stats.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("INV-CPU001"));
    }

    #[test]
    fn test_cpu_stats_try_new_ok() {
        let result = CpuStats::try_new(
            1_000_000_000,
            600_000_000,
            400_000_000,
            MetricSource::Cgroup,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cpu_stats_try_new_fail() {
        let result = CpuStats::try_new(500_000_000, 600_000_000, 400_000_000, MetricSource::Cgroup);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpu_stats_serialize() {
        let stats = CpuStats::new(
            1_000_000_000,
            600_000_000,
            400_000_000,
            MetricSource::Cgroup,
        );
        let json = serde_json::to_string(&stats).expect("serialize failed");
        let decoded: CpuStats = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(stats, decoded);
    }

    // ========================================================================
    // MemoryStats tests
    // ========================================================================

    #[test]
    fn test_memory_stats_new() {
        let stats = MemoryStats::new(104_857_600, 157_286_400, 10, 1000, MetricSource::Cgroup);
        assert_eq!(stats.rss_bytes(), 104_857_600);
        assert_eq!(stats.peak_bytes(), 157_286_400);
        assert_eq!(stats.page_faults_major(), 10);
        assert_eq!(stats.page_faults_minor(), 1000);
        assert_eq!(stats.page_faults(), 1010);
        assert!(stats.source().is_cgroup());
    }

    #[test]
    fn test_memory_stats_unavailable() {
        let stats = MemoryStats::unavailable();
        assert_eq!(stats.rss_bytes(), 0);
        assert!(!stats.is_available());
    }

    #[test]
    fn test_memory_stats_clamping() {
        let stats = MemoryStats::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX, MetricSource::Proc);
        assert_eq!(stats.rss_bytes(), MAX_BYTES);
        assert_eq!(stats.peak_bytes(), MAX_BYTES);
        assert_eq!(stats.page_faults_major(), MAX_PAGE_FAULTS);
        assert_eq!(stats.page_faults_minor(), MAX_PAGE_FAULTS);
    }

    #[test]
    fn test_memory_stats_rss_mib() {
        let stats = MemoryStats::new(104_857_600, 104_857_600, 0, 0, MetricSource::Cgroup);
        assert_eq!(stats.rss_mib(), 100);
    }

    #[test]
    fn test_memory_stats_validate_ok() {
        // peak >= rss
        let stats = MemoryStats::new(104_857_600, 157_286_400, 10, 1000, MetricSource::Cgroup);
        assert!(stats.validate().is_ok());
    }

    #[test]
    fn test_memory_stats_validate_fail() {
        // peak < rss violates invariant
        let stats = MemoryStats::new(157_286_400, 104_857_600, 10, 1000, MetricSource::Cgroup);
        let result = stats.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("INV-MEM001"));
    }

    #[test]
    fn test_memory_stats_try_new_ok() {
        let result = MemoryStats::try_new(104_857_600, 157_286_400, 10, 1000, MetricSource::Cgroup);
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_stats_try_new_fail() {
        let result = MemoryStats::try_new(157_286_400, 104_857_600, 10, 1000, MetricSource::Cgroup);
        assert!(result.is_err());
    }

    // ========================================================================
    // IoStats tests
    // ========================================================================

    #[test]
    fn test_io_stats_new() {
        let stats = IoStats::new(52_428_800, 10_485_760, 1000, 200, MetricSource::Cgroup);
        assert_eq!(stats.read_bytes(), 52_428_800);
        assert_eq!(stats.write_bytes(), 10_485_760);
        assert_eq!(stats.read_ops(), 1000);
        assert_eq!(stats.write_ops(), 200);
        assert_eq!(stats.total_bytes(), 62_914_560);
        assert_eq!(stats.total_ops(), 1200);
    }

    #[test]
    fn test_io_stats_unavailable() {
        let stats = IoStats::unavailable();
        assert_eq!(stats.total_bytes(), 0);
        assert!(!stats.is_available());
    }

    #[test]
    fn test_io_stats_clamping() {
        let stats = IoStats::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX, MetricSource::Cgroup);
        assert_eq!(stats.read_bytes(), MAX_BYTES);
        assert_eq!(stats.write_bytes(), MAX_BYTES);
        assert_eq!(stats.read_ops(), MAX_OPS);
        assert_eq!(stats.write_ops(), MAX_OPS);
    }

    // ========================================================================
    // ResourceStats tests
    // ========================================================================

    #[test]
    fn test_resource_stats_new() {
        let cpu = CpuStats::new(
            1_000_000_000,
            600_000_000,
            400_000_000,
            MetricSource::Cgroup,
        );
        let memory = MemoryStats::new(104_857_600, 157_286_400, 10, 1000, MetricSource::Cgroup);
        let io = IoStats::new(52_428_800, 10_485_760, 1000, 200, MetricSource::Cgroup);

        let stats = ResourceStats::new(cpu, memory, io);
        assert!(stats.all_available());
        assert!(stats.all_from_cgroup());
        assert!(!stats.has_degraded_source());
    }

    #[test]
    fn test_resource_stats_mixed_sources() {
        let cpu = CpuStats::new(
            1_000_000_000,
            600_000_000,
            400_000_000,
            MetricSource::Cgroup,
        );
        let memory = MemoryStats::new(104_857_600, 157_286_400, 10, 1000, MetricSource::Proc);
        let io = IoStats::unavailable();

        let stats = ResourceStats::new(cpu, memory, io);
        assert!(!stats.all_available());
        assert!(!stats.all_from_cgroup());
        assert!(stats.has_degraded_source());
    }

    #[test]
    fn test_resource_stats_unavailable() {
        let stats = ResourceStats::unavailable();
        assert!(!stats.all_available());
        assert!(stats.all_from_cgroup()); // Unavailable counts as "not degraded"
    }

    // ========================================================================
    // MetricSource tests
    // ========================================================================

    #[test]
    fn test_metric_source() {
        assert!(MetricSource::Cgroup.is_cgroup());
        assert!(!MetricSource::Cgroup.is_proc());
        assert!(!MetricSource::Cgroup.is_unavailable());

        assert!(!MetricSource::Proc.is_cgroup());
        assert!(MetricSource::Proc.is_proc());
        assert!(!MetricSource::Proc.is_unavailable());

        assert!(!MetricSource::Unavailable.is_cgroup());
        assert!(!MetricSource::Unavailable.is_proc());
        assert!(MetricSource::Unavailable.is_unavailable());
    }

    #[test]
    fn test_metric_source_default() {
        assert_eq!(MetricSource::default(), MetricSource::Unavailable);
    }
}
