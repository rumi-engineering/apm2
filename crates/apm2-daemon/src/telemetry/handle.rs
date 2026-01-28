//! Telemetry handle for active collection sessions.
//!
//! This module provides the `TelemetryHandle` type per CTR-DAEMON-005,
//! representing an active telemetry collection session for an episode.
//!
//! # Architecture
//!
//! ```text
//! TelemetryCollector::start()
//!         |
//!         v
//! TelemetryHandle
//!     |
//!     +-- episode_id: identifies the episode
//!     +-- pid: process to monitor
//!     +-- seq_gen: sequence number generator
//!     +-- ring_buffer: recent frames
//!     +-- start_mono_ns: collection start time
//!     +-- prev_stats: for computing deltas
//! ```
//!
//! # Thread Safety
//!
//! `TelemetryHandle` uses interior mutability for thread-safe access:
//! - Sequence number uses `AtomicU64`
//! - Ring buffer and stats use `Mutex` (short-held)
//! - All methods are safe to call from multiple threads
//!
//! # Contract References
//!
//! - CTR-DAEMON-005: `TelemetryCollector` and frame streaming

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use nix::unistd::Pid;

use super::frame::{O11yFlags, TelemetryFrame};
use super::stats::ResourceStats;
use crate::episode::{EpisodeId, RingBuffer};

/// Maximum sequence number before wrapping.
///
/// We use a large but not maximal value to detect overflow conditions.
pub const MAX_SEQUENCE: u64 = u64::MAX / 2;

/// Telemetry handle for an active collection session.
///
/// Returned by `TelemetryCollector::start()`, this handle tracks the
/// state of telemetry collection for a single episode.
///
/// # Invariants
///
/// - [INV-TH001] Sequence numbers are monotonically increasing
/// - [INV-TH002] Ring buffer capacity is bounded by policy
/// - [INV-TH003] Handle is invalidated after `stop()` is called
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::telemetry::{TelemetryCollector, TelemetryPolicy};
/// use apm2_daemon::episode::EpisodeId;
/// use nix::unistd::Pid;
///
/// let collector = TelemetryCollector::new(TelemetryPolicy::default());
/// let handle = collector.start(
///     EpisodeId::new("ep-001")?,
///     Pid::from_raw(1234),
/// );
///
/// // Collect frames
/// let frame = handle.next_frame(stats, mono_ns, o11y_flags);
///
/// // Stop collection
/// let frames = handle.stop();
/// ```
#[derive(Debug)]
pub struct TelemetryHandle {
    /// Episode identifier.
    episode_id: EpisodeId,

    /// Process ID being monitored.
    pid: Pid,

    /// Monotonically increasing sequence number.
    seq: AtomicU64,

    /// Ring buffer of recent frames.
    ring_buffer: Mutex<RingBuffer<TelemetryFrame>>,

    /// Start time (monotonic) for relative timestamps.
    start_mono: Instant,

    /// Previous stats for computing deltas.
    prev_stats: Mutex<Option<ResourceStats>>,

    /// Whether collection has been stopped.
    stopped: AtomicBool,

    /// Whether high-frequency mode is active.
    high_freq_active: AtomicBool,

    /// Total frames collected.
    frames_collected: AtomicU64,

    /// Total frames promoted to persistent storage.
    frames_promoted: AtomicU64,
}

impl TelemetryHandle {
    /// Creates a new telemetry handle.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode identifier
    /// * `pid` - Process ID to monitor
    /// * `ring_buffer_capacity` - Maximum frames to retain
    #[must_use]
    pub fn new(episode_id: EpisodeId, pid: Pid, ring_buffer_capacity: usize) -> Self {
        Self {
            episode_id,
            pid,
            seq: AtomicU64::new(0),
            ring_buffer: Mutex::new(RingBuffer::new(ring_buffer_capacity.max(1))),
            start_mono: Instant::now(),
            prev_stats: Mutex::new(None),
            stopped: AtomicBool::new(false),
            high_freq_active: AtomicBool::new(false),
            frames_collected: AtomicU64::new(0),
            frames_promoted: AtomicU64::new(0),
        }
    }

    /// Returns the episode ID.
    #[must_use]
    pub const fn episode_id(&self) -> &EpisodeId {
        &self.episode_id
    }

    /// Returns the process ID.
    #[must_use]
    pub const fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns the current sequence number.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// Returns the start time.
    #[must_use]
    pub const fn start_mono(&self) -> Instant {
        self.start_mono
    }

    /// Returns `true` if collection has been stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// Returns `true` if high-frequency mode is active.
    #[must_use]
    pub fn is_high_freq_active(&self) -> bool {
        self.high_freq_active.load(Ordering::Relaxed)
    }

    /// Sets the high-frequency mode state.
    pub fn set_high_freq_active(&self, active: bool) {
        self.high_freq_active.store(active, Ordering::Relaxed);
    }

    /// Returns the total frames collected.
    #[must_use]
    pub fn frames_collected(&self) -> u64 {
        self.frames_collected.load(Ordering::Relaxed)
    }

    /// Returns the total frames promoted.
    #[must_use]
    pub fn frames_promoted(&self) -> u64 {
        self.frames_promoted.load(Ordering::Relaxed)
    }

    /// Returns the elapsed time since collection started.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_mono.elapsed()
    }

    /// Returns the elapsed time in nanoseconds.
    #[must_use]
    pub fn elapsed_ns(&self) -> u64 {
        self.elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(super::frame::MAX_FRAME_NS)
    }

    /// Returns the number of frames in the ring buffer.
    #[must_use]
    pub fn buffer_len(&self) -> usize {
        self.ring_buffer.lock().map(|buf| buf.len()).unwrap_or(0)
    }

    /// Returns the ring buffer capacity.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        self.ring_buffer
            .lock()
            .map(|buf| buf.capacity())
            .unwrap_or(0)
    }

    /// Gets the next sequence number (atomically incremented).
    ///
    /// # Returns
    ///
    /// Returns `Some(seq)` if sequence is valid, `None` if overflow would
    /// occur.
    fn next_seq(&self) -> Option<u64> {
        loop {
            let current = self.seq.load(Ordering::Relaxed);
            if current >= MAX_SEQUENCE {
                return None;
            }
            let next = current + 1;
            if self
                .seq
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Some(current);
            }
        }
    }

    /// Creates a new telemetry frame from the given stats.
    ///
    /// # Arguments
    ///
    /// * `stats` - Current resource stats
    /// * `o11y_flags` - Observability flags for this frame
    ///
    /// # Returns
    ///
    /// Returns `Some(frame)` if created successfully, `None` if:
    /// - Collection is stopped
    /// - Sequence number overflow
    pub fn next_frame(
        &self,
        stats: ResourceStats,
        o11y_flags: O11yFlags,
    ) -> Option<TelemetryFrame> {
        if self.is_stopped() {
            return None;
        }

        let seq = self.next_seq()?;
        let ts_mono = self.elapsed_ns();

        // Determine source from stats
        let source = if stats.cpu.source().is_cgroup() {
            super::stats::MetricSource::Cgroup
        } else if stats.cpu.source().is_proc() {
            super::stats::MetricSource::Proc
        } else {
            super::stats::MetricSource::Unavailable
        };

        // Build the frame
        let frame = TelemetryFrame::builder(self.episode_id.clone(), seq)
            .ts_mono(ts_mono)
            .cpu_ns(stats.cpu.usage_ns())
            .cpu_user_ns(stats.cpu.user_ns())
            .cpu_system_ns(stats.cpu.system_ns())
            .mem_rss_bytes(stats.memory.rss_bytes())
            .mem_peak_bytes(stats.memory.peak_bytes())
            .io_read_bytes(stats.io.read_bytes())
            .io_write_bytes(stats.io.write_bytes())
            .source(source)
            .o11y_flags(o11y_flags)
            .build();

        // Store in ring buffer
        if let Ok(mut buffer) = self.ring_buffer.lock() {
            buffer.push(frame.clone());
        }

        // Update stats
        self.frames_collected.fetch_add(1, Ordering::Relaxed);

        // Store previous stats for delta computation
        if let Ok(mut prev) = self.prev_stats.lock() {
            *prev = Some(stats);
        }

        Some(frame)
    }

    /// Returns the previous stats for delta computation.
    #[must_use]
    pub fn prev_stats(&self) -> Option<ResourceStats> {
        self.prev_stats.lock().map(|guard| *guard).unwrap_or(None)
    }

    /// Computes the delta between current and previous stats.
    ///
    /// Returns `(cpu_delta_ns, io_delta_bytes)` representing the resources
    /// consumed since the last frame.
    #[must_use]
    pub fn compute_delta(&self, current: &ResourceStats) -> (u64, u64) {
        let prev = self.prev_stats();

        let cpu_delta = prev.map_or_else(
            || current.cpu.usage_ns(),
            |p| current.cpu.usage_ns().saturating_sub(p.cpu.usage_ns()),
        );

        let io_delta = prev.map_or_else(
            || current.io.total_bytes(),
            |p| current.io.total_bytes().saturating_sub(p.io.total_bytes()),
        );

        (cpu_delta, io_delta)
    }

    /// Drains all frames from the ring buffer.
    ///
    /// This is typically called when promoting frames to persistent storage.
    pub fn drain_frames(&self) -> Vec<TelemetryFrame> {
        let mut frames = Vec::new();
        if let Ok(mut buffer) = self.ring_buffer.lock() {
            frames.extend(buffer.drain());
        }
        let count = frames.len() as u64;
        self.frames_promoted.fetch_add(count, Ordering::Relaxed);
        frames
    }

    /// Returns an iterator over frames in the ring buffer (oldest first).
    ///
    /// Note: This clones the frames to avoid holding the lock.
    pub fn iter_frames(&self) -> Vec<TelemetryFrame> {
        self.ring_buffer
            .lock()
            .map(|buffer| buffer.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Stops telemetry collection.
    ///
    /// After calling this, `next_frame()` will return `None`.
    /// Returns the final frames from the ring buffer.
    pub fn stop(&self) -> Vec<TelemetryFrame> {
        self.stopped.store(true, Ordering::Relaxed);
        self.drain_frames()
    }

    /// Creates a snapshot of the handle's statistics.
    #[must_use]
    pub fn snapshot(&self) -> TelemetryHandleSnapshot {
        TelemetryHandleSnapshot {
            episode_id: self.episode_id.clone(),
            pid: self.pid,
            seq: self.seq(),
            elapsed_ns: self.elapsed_ns(),
            frames_collected: self.frames_collected(),
            frames_promoted: self.frames_promoted(),
            buffer_len: self.buffer_len(),
            buffer_capacity: self.buffer_capacity(),
            stopped: self.is_stopped(),
            high_freq_active: self.is_high_freq_active(),
        }
    }
}

/// Snapshot of a telemetry handle's state.
#[derive(Debug, Clone)]
pub struct TelemetryHandleSnapshot {
    /// Episode identifier.
    pub episode_id: EpisodeId,

    /// Process ID being monitored.
    pub pid: Pid,

    /// Current sequence number.
    pub seq: u64,

    /// Elapsed time in nanoseconds.
    pub elapsed_ns: u64,

    /// Total frames collected.
    pub frames_collected: u64,

    /// Total frames promoted.
    pub frames_promoted: u64,

    /// Current buffer length.
    pub buffer_len: usize,

    /// Buffer capacity.
    pub buffer_capacity: usize,

    /// Whether collection is stopped.
    pub stopped: bool,

    /// Whether high-frequency mode is active.
    pub high_freq_active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::stats::{CpuStats, IoStats, MemoryStats, MetricSource};

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("test-episode-001").expect("valid episode ID")
    }

    fn test_stats() -> ResourceStats {
        ResourceStats::new(
            CpuStats::new(
                1_000_000_000,
                600_000_000,
                400_000_000,
                MetricSource::Cgroup,
            ),
            MemoryStats::new(104_857_600, 157_286_400, 10, 1000, MetricSource::Cgroup),
            IoStats::new(1_048_576, 524_288, 100, 50, MetricSource::Cgroup),
        )
    }

    // =========================================================================
    // UT-00169-01: Frame collection tests
    // =========================================================================

    #[test]
    fn test_telemetry_handle_new() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        assert_eq!(handle.episode_id().as_str(), "test-episode-001");
        assert_eq!(handle.pid().as_raw(), 1234);
        assert_eq!(handle.seq(), 0);
        assert!(!handle.is_stopped());
        assert!(!handle.is_high_freq_active());
        assert_eq!(handle.buffer_capacity(), 100);
    }

    #[test]
    fn test_telemetry_handle_next_frame() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        let frame = handle
            .next_frame(test_stats(), O11yFlags::new().with_initial())
            .expect("frame should be created");

        assert_eq!(frame.seq(), 0);
        assert!(frame.o11y_flags().initial);
        assert_eq!(handle.seq(), 1);
        assert_eq!(handle.frames_collected(), 1);
        assert_eq!(handle.buffer_len(), 1);
    }

    #[test]
    fn test_telemetry_handle_multiple_frames() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        for i in 0..10 {
            let frame = handle
                .next_frame(test_stats(), O11yFlags::new())
                .expect("frame should be created");
            assert_eq!(frame.seq(), i);
        }

        assert_eq!(handle.seq(), 10);
        assert_eq!(handle.frames_collected(), 10);
        assert_eq!(handle.buffer_len(), 10);
    }

    #[test]
    fn test_telemetry_handle_ring_buffer_overflow() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 5);

        // Fill beyond capacity
        for _ in 0..10 {
            handle.next_frame(test_stats(), O11yFlags::new());
        }

        assert_eq!(handle.frames_collected(), 10);
        assert_eq!(handle.buffer_len(), 5); // Capped at capacity

        // Check that we have the most recent frames
        let frames = handle.iter_frames();
        assert_eq!(frames.len(), 5);
        assert_eq!(frames[0].seq(), 5); // Oldest remaining
        assert_eq!(frames[4].seq(), 9); // Newest
    }

    #[test]
    fn test_telemetry_handle_stop() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        handle.next_frame(test_stats(), O11yFlags::new());
        handle.next_frame(test_stats(), O11yFlags::new());
        handle.next_frame(test_stats(), O11yFlags::new());

        let frames = handle.stop();
        assert_eq!(frames.len(), 3);
        assert!(handle.is_stopped());

        // Further frames should fail
        assert!(handle.next_frame(test_stats(), O11yFlags::new()).is_none());
    }

    #[test]
    fn test_telemetry_handle_drain_frames() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        for _ in 0..5 {
            handle.next_frame(test_stats(), O11yFlags::new());
        }

        let frames = handle.drain_frames();
        assert_eq!(frames.len(), 5);
        assert_eq!(handle.buffer_len(), 0);
        assert_eq!(handle.frames_promoted(), 5);
    }

    #[test]
    fn test_telemetry_handle_high_freq_mode() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        assert!(!handle.is_high_freq_active());

        handle.set_high_freq_active(true);
        assert!(handle.is_high_freq_active());

        handle.set_high_freq_active(false);
        assert!(!handle.is_high_freq_active());
    }

    #[test]
    fn test_telemetry_handle_compute_delta() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        let stats1 = ResourceStats::new(
            CpuStats::new(
                1_000_000_000,
                600_000_000,
                400_000_000,
                MetricSource::Cgroup,
            ),
            MemoryStats::new(104_857_600, 157_286_400, 10, 1000, MetricSource::Cgroup),
            IoStats::new(1_000_000, 500_000, 100, 50, MetricSource::Cgroup),
        );

        // First frame - no previous
        let (cpu_delta, io_delta) = handle.compute_delta(&stats1);
        assert_eq!(cpu_delta, 1_000_000_000);
        assert_eq!(io_delta, 1_500_000);

        // Record the first stats
        handle.next_frame(stats1, O11yFlags::new());

        // Second frame - compute delta from previous
        let stats2 = ResourceStats::new(
            CpuStats::new(
                1_500_000_000,
                900_000_000,
                600_000_000,
                MetricSource::Cgroup,
            ),
            MemoryStats::new(104_857_600, 157_286_400, 10, 1000, MetricSource::Cgroup),
            IoStats::new(2_000_000, 1_000_000, 200, 100, MetricSource::Cgroup),
        );

        let (cpu_delta, io_delta) = handle.compute_delta(&stats2);
        assert_eq!(cpu_delta, 500_000_000);
        assert_eq!(io_delta, 1_500_000);
    }

    #[test]
    fn test_telemetry_handle_snapshot() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        handle.next_frame(test_stats(), O11yFlags::new());
        handle.next_frame(test_stats(), O11yFlags::new());
        handle.set_high_freq_active(true);

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.episode_id.as_str(), "test-episode-001");
        assert_eq!(snapshot.pid.as_raw(), 1234);
        assert_eq!(snapshot.seq, 2);
        assert_eq!(snapshot.frames_collected, 2);
        assert_eq!(snapshot.buffer_len, 2);
        assert_eq!(snapshot.buffer_capacity, 100);
        assert!(!snapshot.stopped);
        assert!(snapshot.high_freq_active);
    }

    #[test]
    fn test_telemetry_handle_iter_frames() {
        let handle = TelemetryHandle::new(test_episode_id(), Pid::from_raw(1234), 100);

        for _ in 0..5 {
            handle.next_frame(test_stats(), O11yFlags::new());
        }

        let frames = handle.iter_frames();
        assert_eq!(frames.len(), 5);

        // iter_frames should not drain
        assert_eq!(handle.buffer_len(), 5);
    }
}
