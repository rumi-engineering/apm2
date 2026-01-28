//! Telemetry collection module.
//!
//! This module provides cgroup-based resource telemetry collection,
//! including memory, CPU, and I/O metrics from Linux cgroups v2.
//!
//! # Architecture
//!
//! Per AD-TEL-001, telemetry is collected from two possible sources:
//!
//! - **Primary**: cgroups v2 hierarchy
//!   (`/sys/fs/cgroup/apm2.slice/episode-{uuid}.scope/`)
//! - **Fallback**: `/proc/{pid}/` when cgroup isolation is unavailable
//!
//! The collection architecture follows a layered design:
//!
//! ```text
//! +-------------------+
//! |   CgroupReader    |  <-- Primary reader for per-episode cgroups
//! +-------------------+
//!          |
//!          v
//! +-------------------+
//! |    ProcReader     |  <-- Fallback for degraded mode
//! +-------------------+
//!          |
//!          v
//! +-------------------+
//! |  ResourceStats    |  <-- Unified stats with source tracking
//! +-------------------+
//! ```
//!
//! # Modules
//!
//! - [`cgroup`]: Cgroups v2 reader and cgroup path resolution
//! - [`stats`]: CPU, memory, and I/O statistics types
//! - [`proc_fallback`]: `/proc` fallback for degraded mode
//!
//! # Usage
//!
//! ```rust,ignore
//! use apm2_daemon::telemetry::{CgroupReader, ResourceStats};
//!
//! // Create reader for an episode cgroup
//! let reader = CgroupReader::for_episode("ep-abc123")?;
//!
//! // Read all resource stats
//! let stats: ResourceStats = reader.read_all();
//!
//! // Check if we're in degraded mode
//! if stats.has_degraded_source() {
//!     warn!("Telemetry accuracy reduced - using /proc fallback");
//! }
//! ```
//!
//! # Contract References
//!
//! - AD-TEL-001: Telemetry collection via cgroups v2
//! - AD-CGROUP-001: Per-episode cgroup hierarchy

pub mod cgroup;
pub mod proc_fallback;
pub mod stats;

// Re-export primary types
pub use cgroup::{
    APM2_SLICE, CGROUP_V2_MOUNT, CgroupError, CgroupReader, CgroupResult, MAX_CGROUP_PATH_LEN,
    MAX_EPISODE_ID_LEN, episode_cgroup_path, episode_cgroup_path_with_root, is_cgroup_v2_available,
    is_cgroup_v2_available_at,
};
pub use proc_fallback::{ProcError, ProcReader, ProcResult};
pub use stats::{
    CpuStats, IoStats, MAX_BYTES, MAX_NS, MAX_OPS, MAX_PAGE_FAULTS, MemoryStats, MetricSource,
    ResourceStats,
};
