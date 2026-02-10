//! Telemetry collection module.
//!
//! This module provides cgroup-based resource telemetry collection,
//! including memory, CPU, and I/O metrics from Linux cgroups v2.
//!
//! # Architecture
//!
//! Per AD-TEL-001 and CTR-DAEMON-005, telemetry is collected from two
//! possible sources:
//!
//! - **Primary**: cgroups v2 hierarchy
//!   (`/sys/fs/cgroup/apm2.slice/episode-{uuid}.scope/`)
//! - **Fallback**: `/proc/{pid}/` when cgroup isolation is unavailable
//!
//! The collection architecture follows a layered design:
//!
//! ```text
//! +-------------------+
//! |TelemetryCollector |  <-- Main collector with policy and ring buffer
//! +-------------------+
//!          |
//!          v
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
//! |  TelemetryFrame   |  <-- Captured metrics with timestamps
//! +-------------------+
//! ```
//!
//! # Modules
//!
//! - [`cgroup`]: Cgroups v2 reader and cgroup path resolution
//! - [`stats`]: CPU, memory, and I/O statistics types
//! - [`proc_fallback`]: `/proc` fallback for degraded mode
//! - [`frame`]: `TelemetryFrame` type for captured metrics
//! - [`policy`]: `TelemetryPolicy` configuration
//! - [`handle`]: `TelemetryHandle` for active collection sessions
//! - [`collector`]: `TelemetryCollector` implementation
//!
//! # Usage
//!
//! ```rust,ignore
//! use apm2_daemon::telemetry::{
//!     CgroupReader, TelemetryCollector, TelemetryPolicy, TelemetryFrame
//! };
//! use apm2_daemon::episode::EpisodeId;
//! use nix::unistd::Pid;
//!
//! // Create collector with policy
//! let policy = TelemetryPolicy::default();
//! let collector = TelemetryCollector::new(policy);
//!
//! // Start collection for an episode
//! let handle = collector.start(
//!     EpisodeId::new("ep-abc123")?,
//!     Pid::from_raw(1234),
//! );
//!
//! // Create reader for the episode cgroup
//! let reader = CgroupReader::for_episode("ep-abc123")?;
//!
//! // Collect a frame
//! let frame = collector.collect(&handle, &reader, O11yFlags::new())?;
//!
//! // Check if we're in degraded mode
//! if frame.is_degraded() {
//!     warn!("Telemetry accuracy reduced - using /proc fallback");
//! }
//!
//! // Stop collection and get final frames
//! let frames = handle.stop();
//! ```
//!
//! # Contract References
//!
//! - AD-TEL-001: Telemetry collection via cgroups v2
//! - AD-CGROUP-001: Per-episode cgroup hierarchy
//! - CTR-DAEMON-005: `TelemetryCollector` and frame streaming

pub mod cgroup;
pub mod collector;
pub mod frame;
pub mod handle;
pub mod policy;
pub mod proc_fallback;
pub mod reviewer;
pub mod stats;

// Re-export cgroup types
pub use cgroup::{
    APM2_SLICE, CGROUP_V2_MOUNT, CgroupError, CgroupReader, CgroupResult, MAX_CGROUP_PATH_LEN,
    MAX_EPISODE_ID_LEN, MAX_TELEMETRY_FILE_SIZE, OsResourceLimits, ScopeCreationResult,
    ScopeCreationStrategy, create_episode_scope, create_episode_scope_with_root,
    episode_cgroup_path, episode_cgroup_path_with_root, is_cgroup_v2_available,
    is_cgroup_v2_available_at, remove_episode_scope, remove_episode_scope_with_root,
};
// Re-export collector types (TCK-00169)
pub use collector::{TelemetryCollector, TelemetryError, TelemetryResult, new_shared_collector};
pub use frame::{MAX_FRAME_BYTES, MAX_FRAME_NS, O11yFlags, TelemetryFrame, TelemetryFrameBuilder};
pub use handle::{MAX_SEQUENCE, TelemetryHandle, TelemetryHandleSnapshot};
pub use policy::{
    DEFAULT_HIGH_FREQ_THRESHOLD_PERCENT, DEFAULT_RING_BUFFER_CAPACITY, DEFAULT_SAMPLE_PERIOD_MS,
    HIGH_FREQ_MULTIPLIER, MAX_RING_BUFFER_CAPACITY, MAX_SAMPLE_PERIOD_MS, MIN_RING_BUFFER_CAPACITY,
    MIN_SAMPLE_PERIOD_MS, PromoteTriggers, TelemetryPolicy, TelemetryPolicyBuilder,
};
// Re-export proc fallback types
pub use proc_fallback::{MAX_PROC_FILE_SIZE, ProcError, ProcReader, ProcResult};
pub use reviewer::{
    DEFAULT_PROJECTION_SUMMARY_INTERVAL, DEFAULT_REVIEWER_ROTATE_BYTES, ProjectionSummary,
    ProjectionSummaryEmitter, REVIEWER_TELEMETRY_SCHEMA, REVIEWER_TELEMETRY_SCHEMA_VERSION,
    ReviewerLifecycleEvent, ReviewerLifecycleEventKind, ReviewerProjectionEvent,
    ReviewerProjectionFilter, ReviewerProjectionRead, ReviewerTelemetryError,
    ReviewerTelemetryHealth, ReviewerTelemetryWriter, append_reviewer_event_ndjson,
    canonicalize_reviewer_event_value, read_reviewer_projection_events, reviewer_events_lock_path,
    reviewer_events_rotated_path,
};
// Re-export stats types
pub use stats::{
    CpuStats, IoStats, MAX_BYTES, MAX_NS, MAX_OPS, MAX_PAGE_FAULTS, MemoryStats, MetricSource,
    ResourceStats,
};
