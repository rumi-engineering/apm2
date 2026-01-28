//! Telemetry frame type for resource metrics.
//!
//! This module defines the `TelemetryFrame` type per CTR-DAEMON-005,
//! representing a single telemetry sample collected during episode execution.
//!
//! # Architecture
//!
//! ```text
//! TelemetryCollector
//!       |
//!       +-- collect() --> TelemetryFrame
//!                             |
//!                             +-- episode_id, seq, ts_mono
//!                             +-- cpu_ns, cpu_user_ns, cpu_system_ns
//!                             +-- mem_rss_bytes, mem_peak_bytes
//!                             +-- io_read_bytes, io_write_bytes
//!                             +-- o11y_flags
//! ```
//!
//! # Invariants
//!
//! - [INV-TF001] Sequence numbers are monotonically increasing per episode
//! - [INV-TF002] All values are bounded to prevent overflow
//! - [INV-TF003] Timestamps are monotonic (from `CLOCK_MONOTONIC`)
//!
//! # Contract References
//!
//! - CTR-DAEMON-005: `TelemetryCollector` and frame streaming

use serde::{Deserialize, Serialize};

use super::stats::MetricSource;
use crate::episode::EpisodeId;

/// Maximum nanoseconds value (prevents overflow in calculations).
pub const MAX_FRAME_NS: u64 = u64::MAX / 2;

/// Maximum bytes value (prevents overflow in calculations).
pub const MAX_FRAME_BYTES: u64 = u64::MAX / 2;

/// Observability flags for telemetry sampling mode.
///
/// These flags indicate the collection mode and any special conditions
/// during frame capture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Flags struct intentionally uses bools
pub struct O11yFlags {
    /// Frame was collected during high-frequency sampling (e.g., budget nearing
    /// exhaustion).
    pub high_frequency: bool,

    /// Frame was promoted from ring buffer to persistent storage.
    pub promoted: bool,

    /// Frame was collected during degraded mode (proc fallback).
    pub degraded: bool,

    /// Frame was the first sample after episode start.
    pub initial: bool,

    /// Frame was the final sample before episode termination.
    pub terminal: bool,
}

impl O11yFlags {
    /// Creates a new empty flags instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            high_frequency: false,
            promoted: false,
            degraded: false,
            initial: false,
            terminal: false,
        }
    }

    /// Sets the initial flag.
    #[must_use]
    pub const fn with_initial(mut self) -> Self {
        self.initial = true;
        self
    }

    /// Sets the terminal flag.
    #[must_use]
    pub const fn with_terminal(mut self) -> Self {
        self.terminal = true;
        self
    }

    /// Sets the degraded flag.
    #[must_use]
    pub const fn with_degraded(mut self) -> Self {
        self.degraded = true;
        self
    }

    /// Sets the high-frequency flag.
    #[must_use]
    pub const fn with_high_frequency(mut self) -> Self {
        self.high_frequency = true;
        self
    }

    /// Sets the promoted flag.
    #[must_use]
    pub const fn with_promoted(mut self) -> Self {
        self.promoted = true;
        self
    }

    /// Returns `true` if any special flag is set.
    #[must_use]
    pub const fn has_any(&self) -> bool {
        self.high_frequency || self.promoted || self.degraded || self.initial || self.terminal
    }
}

/// A single telemetry frame capturing resource metrics at a point in time.
///
/// Per CTR-DAEMON-005, each frame contains:
/// - Episode identity and sequence
/// - CPU time (total, user, system)
/// - Memory usage (RSS, peak)
/// - I/O metrics (read/write bytes)
/// - Observability flags
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::telemetry::TelemetryFrame;
/// use apm2_daemon::episode::EpisodeId;
///
/// let frame = TelemetryFrame::builder(EpisodeId::new("ep-001")?, 0)
///     .ts_mono(1234567890)
///     .cpu_ns(1_000_000)
///     .mem_rss_bytes(1024 * 1024)
///     .build();
///
/// assert_eq!(frame.seq(), 0);
/// assert_eq!(frame.cpu_ns(), 1_000_000);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryFrame {
    /// Episode identifier.
    episode_id: EpisodeId,

    /// Sequence number (monotonically increasing per episode).
    seq: u64,

    /// Monotonic timestamp in nanoseconds (from `CLOCK_MONOTONIC`).
    ts_mono: u64,

    /// Total CPU time in nanoseconds.
    cpu_ns: u64,

    /// User-mode CPU time in nanoseconds.
    cpu_user_ns: u64,

    /// Kernel-mode CPU time in nanoseconds.
    cpu_system_ns: u64,

    /// Resident set size in bytes.
    mem_rss_bytes: u64,

    /// Peak memory usage in bytes.
    mem_peak_bytes: u64,

    /// I/O bytes read.
    io_read_bytes: u64,

    /// I/O bytes written.
    io_write_bytes: u64,

    /// Metric source (cgroup vs proc fallback).
    source: MetricSource,

    /// Observability flags.
    o11y_flags: O11yFlags,
}

impl TelemetryFrame {
    /// Creates a new frame builder.
    #[must_use]
    pub const fn builder(episode_id: EpisodeId, seq: u64) -> TelemetryFrameBuilder {
        TelemetryFrameBuilder::new(episode_id, seq)
    }

    /// Creates a frame with invariant validation.
    ///
    /// # Errors
    ///
    /// Returns an error string if any invariant is violated.
    #[allow(clippy::too_many_arguments)] // Frame has many metrics by design
    pub fn try_new(
        episode_id: EpisodeId,
        seq: u64,
        ts_mono: u64,
        cpu_ns: u64,
        cpu_user_ns: u64,
        cpu_system_ns: u64,
        mem_rss_bytes: u64,
        mem_peak_bytes: u64,
        io_read_bytes: u64,
        io_write_bytes: u64,
        source: MetricSource,
        o11y_flags: O11yFlags,
    ) -> Result<Self, String> {
        let frame = Self {
            episode_id,
            seq,
            ts_mono: clamp_ns(ts_mono),
            cpu_ns: clamp_ns(cpu_ns),
            cpu_user_ns: clamp_ns(cpu_user_ns),
            cpu_system_ns: clamp_ns(cpu_system_ns),
            mem_rss_bytes: clamp_bytes(mem_rss_bytes),
            mem_peak_bytes: clamp_bytes(mem_peak_bytes),
            io_read_bytes: clamp_bytes(io_read_bytes),
            io_write_bytes: clamp_bytes(io_write_bytes),
            source,
            o11y_flags,
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Validates frame invariants.
    ///
    /// # Invariants
    ///
    /// - [INV-TF002] All values are bounded by MAX_* constants
    ///
    /// # Errors
    ///
    /// Returns an error string describing the violated invariant.
    pub fn validate(&self) -> Result<(), String> {
        // INV-TF002: Validate bounded values
        if self.ts_mono > MAX_FRAME_NS {
            return Err(format!(
                "INV-TF002 violated: ts_mono ({}) exceeds MAX_FRAME_NS",
                self.ts_mono
            ));
        }
        if self.cpu_ns > MAX_FRAME_NS {
            return Err(format!(
                "INV-TF002 violated: cpu_ns ({}) exceeds MAX_FRAME_NS",
                self.cpu_ns
            ));
        }
        if self.mem_rss_bytes > MAX_FRAME_BYTES {
            return Err(format!(
                "INV-TF002 violated: mem_rss_bytes ({}) exceeds MAX_FRAME_BYTES",
                self.mem_rss_bytes
            ));
        }
        if self.mem_peak_bytes > MAX_FRAME_BYTES {
            return Err(format!(
                "INV-TF002 violated: mem_peak_bytes ({}) exceeds MAX_FRAME_BYTES",
                self.mem_peak_bytes
            ));
        }
        Ok(())
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Returns the episode ID.
    #[must_use]
    pub const fn episode_id(&self) -> &EpisodeId {
        &self.episode_id
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the monotonic timestamp in nanoseconds.
    #[must_use]
    pub const fn ts_mono(&self) -> u64 {
        self.ts_mono
    }

    /// Returns the total CPU time in nanoseconds.
    #[must_use]
    pub const fn cpu_ns(&self) -> u64 {
        self.cpu_ns
    }

    /// Returns the user-mode CPU time in nanoseconds.
    #[must_use]
    pub const fn cpu_user_ns(&self) -> u64 {
        self.cpu_user_ns
    }

    /// Returns the kernel-mode CPU time in nanoseconds.
    #[must_use]
    pub const fn cpu_system_ns(&self) -> u64 {
        self.cpu_system_ns
    }

    /// Returns the resident set size in bytes.
    #[must_use]
    pub const fn mem_rss_bytes(&self) -> u64 {
        self.mem_rss_bytes
    }

    /// Returns the peak memory usage in bytes.
    #[must_use]
    pub const fn mem_peak_bytes(&self) -> u64 {
        self.mem_peak_bytes
    }

    /// Returns the I/O bytes read.
    #[must_use]
    pub const fn io_read_bytes(&self) -> u64 {
        self.io_read_bytes
    }

    /// Returns the I/O bytes written.
    #[must_use]
    pub const fn io_write_bytes(&self) -> u64 {
        self.io_write_bytes
    }

    /// Returns the total I/O bytes (read + write).
    #[must_use]
    pub const fn io_total_bytes(&self) -> u64 {
        self.io_read_bytes.saturating_add(self.io_write_bytes)
    }

    /// Returns the metric source.
    #[must_use]
    pub const fn source(&self) -> MetricSource {
        self.source
    }

    /// Returns the observability flags.
    #[must_use]
    pub const fn o11y_flags(&self) -> &O11yFlags {
        &self.o11y_flags
    }

    /// Returns the CPU time in milliseconds.
    #[must_use]
    pub const fn cpu_ms(&self) -> u64 {
        self.cpu_ns / 1_000_000
    }

    /// Returns `true` if metrics are from the cgroup source.
    #[must_use]
    pub const fn is_from_cgroup(&self) -> bool {
        self.source.is_cgroup()
    }

    /// Returns `true` if metrics are from the degraded proc source.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.source.is_proc()
    }
}

/// Builder for [`TelemetryFrame`].
#[derive(Debug, Clone)]
pub struct TelemetryFrameBuilder {
    episode_id: EpisodeId,
    seq: u64,
    ts_mono: u64,
    cpu_ns: u64,
    cpu_user_ns: u64,
    cpu_system_ns: u64,
    mem_rss_bytes: u64,
    mem_peak_bytes: u64,
    io_read_bytes: u64,
    io_write_bytes: u64,
    source: MetricSource,
    o11y_flags: O11yFlags,
}

impl TelemetryFrameBuilder {
    /// Creates a new builder with required fields.
    #[must_use]
    pub const fn new(episode_id: EpisodeId, seq: u64) -> Self {
        Self {
            episode_id,
            seq,
            ts_mono: 0,
            cpu_ns: 0,
            cpu_user_ns: 0,
            cpu_system_ns: 0,
            mem_rss_bytes: 0,
            mem_peak_bytes: 0,
            io_read_bytes: 0,
            io_write_bytes: 0,
            source: MetricSource::Unavailable,
            o11y_flags: O11yFlags::new(),
        }
    }

    /// Sets the monotonic timestamp.
    #[must_use]
    pub const fn ts_mono(mut self, ts_mono: u64) -> Self {
        self.ts_mono = ts_mono;
        self
    }

    /// Sets the total CPU time in nanoseconds.
    #[must_use]
    pub const fn cpu_ns(mut self, cpu_ns: u64) -> Self {
        self.cpu_ns = cpu_ns;
        self
    }

    /// Sets the user-mode CPU time in nanoseconds.
    #[must_use]
    pub const fn cpu_user_ns(mut self, cpu_user_ns: u64) -> Self {
        self.cpu_user_ns = cpu_user_ns;
        self
    }

    /// Sets the kernel-mode CPU time in nanoseconds.
    #[must_use]
    pub const fn cpu_system_ns(mut self, cpu_system_ns: u64) -> Self {
        self.cpu_system_ns = cpu_system_ns;
        self
    }

    /// Sets the resident set size in bytes.
    #[must_use]
    pub const fn mem_rss_bytes(mut self, mem_rss_bytes: u64) -> Self {
        self.mem_rss_bytes = mem_rss_bytes;
        self
    }

    /// Sets the peak memory usage in bytes.
    #[must_use]
    pub const fn mem_peak_bytes(mut self, mem_peak_bytes: u64) -> Self {
        self.mem_peak_bytes = mem_peak_bytes;
        self
    }

    /// Sets the I/O bytes read.
    #[must_use]
    pub const fn io_read_bytes(mut self, io_read_bytes: u64) -> Self {
        self.io_read_bytes = io_read_bytes;
        self
    }

    /// Sets the I/O bytes written.
    #[must_use]
    pub const fn io_write_bytes(mut self, io_write_bytes: u64) -> Self {
        self.io_write_bytes = io_write_bytes;
        self
    }

    /// Sets the metric source.
    #[must_use]
    pub const fn source(mut self, source: MetricSource) -> Self {
        self.source = source;
        self
    }

    /// Sets the observability flags.
    #[must_use]
    pub const fn o11y_flags(mut self, o11y_flags: O11yFlags) -> Self {
        self.o11y_flags = o11y_flags;
        self
    }

    /// Builds the frame.
    #[must_use]
    pub fn build(self) -> TelemetryFrame {
        TelemetryFrame {
            episode_id: self.episode_id,
            seq: self.seq,
            ts_mono: clamp_ns(self.ts_mono),
            cpu_ns: clamp_ns(self.cpu_ns),
            cpu_user_ns: clamp_ns(self.cpu_user_ns),
            cpu_system_ns: clamp_ns(self.cpu_system_ns),
            mem_rss_bytes: clamp_bytes(self.mem_rss_bytes),
            mem_peak_bytes: clamp_bytes(self.mem_peak_bytes),
            io_read_bytes: clamp_bytes(self.io_read_bytes),
            io_write_bytes: clamp_bytes(self.io_write_bytes),
            source: self.source,
            o11y_flags: self.o11y_flags,
        }
    }

    /// Builds the frame with validation.
    ///
    /// # Errors
    ///
    /// Returns an error string if any invariant is violated.
    pub fn try_build(self) -> Result<TelemetryFrame, String> {
        let frame = self.build();
        frame.validate()?;
        Ok(frame)
    }
}

/// Clamps a nanosecond value to `MAX_FRAME_NS`.
const fn clamp_ns(value: u64) -> u64 {
    if value > MAX_FRAME_NS {
        MAX_FRAME_NS
    } else {
        value
    }
}

/// Clamps a byte value to `MAX_FRAME_BYTES`.
const fn clamp_bytes(value: u64) -> u64 {
    if value > MAX_FRAME_BYTES {
        MAX_FRAME_BYTES
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("test-episode-001").expect("valid episode ID")
    }

    // =========================================================================
    // UT-00169-01: Frame collection tests
    // =========================================================================

    #[test]
    fn test_telemetry_frame_builder() {
        let frame = TelemetryFrame::builder(test_episode_id(), 0)
            .ts_mono(1_000_000_000)
            .cpu_ns(500_000_000)
            .cpu_user_ns(300_000_000)
            .cpu_system_ns(200_000_000)
            .mem_rss_bytes(1024 * 1024 * 100)
            .mem_peak_bytes(1024 * 1024 * 150)
            .io_read_bytes(1024 * 1024)
            .io_write_bytes(512 * 1024)
            .source(MetricSource::Cgroup)
            .build();

        assert_eq!(frame.seq(), 0);
        assert_eq!(frame.ts_mono(), 1_000_000_000);
        assert_eq!(frame.cpu_ns(), 500_000_000);
        assert_eq!(frame.cpu_user_ns(), 300_000_000);
        assert_eq!(frame.cpu_system_ns(), 200_000_000);
        assert_eq!(frame.mem_rss_bytes(), 104_857_600);
        assert_eq!(frame.mem_peak_bytes(), 157_286_400);
        assert_eq!(frame.io_read_bytes(), 1_048_576);
        assert_eq!(frame.io_write_bytes(), 524_288);
        assert!(frame.is_from_cgroup());
    }

    #[test]
    fn test_telemetry_frame_try_new() {
        let result = TelemetryFrame::try_new(
            test_episode_id(),
            1,
            1_000_000_000,
            500_000_000,
            300_000_000,
            200_000_000,
            104_857_600,
            157_286_400,
            1_048_576,
            524_288,
            MetricSource::Cgroup,
            O11yFlags::new(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_telemetry_frame_clamping() {
        let frame = TelemetryFrame::builder(test_episode_id(), 0)
            .ts_mono(u64::MAX)
            .cpu_ns(u64::MAX)
            .mem_rss_bytes(u64::MAX)
            .build();

        assert_eq!(frame.ts_mono(), MAX_FRAME_NS);
        assert_eq!(frame.cpu_ns(), MAX_FRAME_NS);
        assert_eq!(frame.mem_rss_bytes(), MAX_FRAME_BYTES);
    }

    #[test]
    fn test_telemetry_frame_validate() {
        let frame = TelemetryFrame::builder(test_episode_id(), 0)
            .cpu_ns(1_000_000)
            .build();
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn test_telemetry_frame_io_total() {
        let frame = TelemetryFrame::builder(test_episode_id(), 0)
            .io_read_bytes(100)
            .io_write_bytes(200)
            .build();
        assert_eq!(frame.io_total_bytes(), 300);
    }

    #[test]
    fn test_telemetry_frame_cpu_ms() {
        let frame = TelemetryFrame::builder(test_episode_id(), 0)
            .cpu_ns(1_500_000_000)
            .build();
        assert_eq!(frame.cpu_ms(), 1500);
    }

    #[test]
    fn test_telemetry_frame_degraded() {
        let frame = TelemetryFrame::builder(test_episode_id(), 0)
            .source(MetricSource::Proc)
            .build();
        assert!(frame.is_degraded());
        assert!(!frame.is_from_cgroup());
    }

    // =========================================================================
    // O11yFlags tests
    // =========================================================================

    #[test]
    fn test_o11y_flags_new() {
        let flags = O11yFlags::new();
        assert!(!flags.high_frequency);
        assert!(!flags.promoted);
        assert!(!flags.degraded);
        assert!(!flags.initial);
        assert!(!flags.terminal);
        assert!(!flags.has_any());
    }

    #[test]
    fn test_o11y_flags_with_initial() {
        let flags = O11yFlags::new().with_initial();
        assert!(flags.initial);
        assert!(flags.has_any());
    }

    #[test]
    fn test_o11y_flags_with_terminal() {
        let flags = O11yFlags::new().with_terminal();
        assert!(flags.terminal);
        assert!(flags.has_any());
    }

    #[test]
    fn test_o11y_flags_with_degraded() {
        let flags = O11yFlags::new().with_degraded();
        assert!(flags.degraded);
        assert!(flags.has_any());
    }

    #[test]
    fn test_o11y_flags_with_high_frequency() {
        let flags = O11yFlags::new().with_high_frequency();
        assert!(flags.high_frequency);
        assert!(flags.has_any());
    }

    #[test]
    fn test_o11y_flags_with_promoted() {
        let flags = O11yFlags::new().with_promoted();
        assert!(flags.promoted);
        assert!(flags.has_any());
    }

    #[test]
    fn test_o11y_flags_chained() {
        let flags = O11yFlags::new()
            .with_initial()
            .with_degraded()
            .with_high_frequency();
        assert!(flags.initial);
        assert!(flags.degraded);
        assert!(flags.high_frequency);
        assert!(!flags.terminal);
        assert!(!flags.promoted);
    }

    // =========================================================================
    // Serialization tests
    // =========================================================================

    #[test]
    fn test_telemetry_frame_serialize() {
        let frame = TelemetryFrame::builder(test_episode_id(), 42)
            .ts_mono(1_000_000_000)
            .cpu_ns(500_000_000)
            .source(MetricSource::Cgroup)
            .o11y_flags(O11yFlags::new().with_initial())
            .build();

        let json = serde_json::to_string(&frame).expect("serialize failed");
        let decoded: TelemetryFrame = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_o11y_flags_serialize() {
        let flags = O11yFlags::new().with_initial().with_degraded();
        let json = serde_json::to_string(&flags).expect("serialize failed");
        let decoded: O11yFlags = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(flags, decoded);
    }
}
