// AGENT-AUTHORED
//! Core time types for the Hierarchical Time Framework (HTF).
//!
//! This module defines the fundamental time representations used throughout
//! the system, as specified in RFC-0016:
//!
//! - [`LedgerTime`]: Authoritative ordering tuple from consensus ledgers
//! - [`HtfTick`]: Node-local monotonic tick counter
//! - [`TimeEnvelopeRef`]: Content hash reference to time envelopes
//! - [`BoundedWallInterval`]: Wall time with explicit uncertainty bounds
//!
//! # Resource Limits
//!
//! All string fields are bounded by [`MAX_STRING_LENGTH`] to prevent
//! denial-of-service attacks via oversized payloads.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length of any string field in HTF types.
/// This prevents denial-of-service attacks via oversized strings.
pub const MAX_STRING_LENGTH: usize = 4096;

// =============================================================================
// LedgerTime
// =============================================================================

/// Authoritative time tuple from a consensus-backed ledger.
///
/// `LedgerTime` represents a point in a ledger's timeline, identified by:
/// - `ledger_id`: Stable identifier for a ledger namespace
/// - `epoch`: Increments on authority or configuration changes
/// - `seq`: Monotonically increasing sequence within (`ledger_id`, `epoch`)
///
/// # Ordering
///
/// `LedgerTime` implements total ordering lexicographically:
/// 1. First by `ledger_id` (lexicographic string comparison)
/// 2. Then by `epoch` (numeric comparison)
/// 3. Finally by `seq` (numeric comparison)
///
/// This ordering is authoritative for truth decisions across the system.
///
/// # Security
///
/// The `ledger_id` field is bounded by [`MAX_STRING_LENGTH`] to prevent
/// denial-of-service attacks.
///
/// # Example
///
/// ```rust
/// use apm2_core::htf::LedgerTime;
///
/// let t1 = LedgerTime::new("ledger-a", 1, 100);
/// let t2 = LedgerTime::new("ledger-a", 1, 101);
/// let t3 = LedgerTime::new("ledger-a", 2, 1);
/// let t4 = LedgerTime::new("ledger-b", 1, 1);
///
/// // Same ledger, same epoch: compare by seq
/// assert!(t1 < t2);
///
/// // Same ledger, different epoch: epoch takes precedence
/// assert!(t2 < t3);
///
/// // Different ledgers: compare by ledger_id
/// assert!(t3 < t4);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct LedgerTime {
    /// Stable identifier for a ledger namespace.
    ledger_id: String,

    /// Epoch number, increments on authority/configuration changes.
    epoch: u64,

    /// Sequence number, monotonically increasing within (`ledger_id`, `epoch`).
    seq: u64,
}

impl LedgerTime {
    /// Creates a new `LedgerTime` with the given components.
    ///
    /// # Arguments
    ///
    /// * `ledger_id` - Stable identifier for the ledger namespace
    /// * `epoch` - Epoch number (changes on authority/config changes)
    /// * `seq` - Sequence number within the epoch
    ///
    /// # Panics
    ///
    /// Panics if `ledger_id` exceeds [`MAX_STRING_LENGTH`]. Use
    /// [`LedgerTime::try_new`] for fallible construction.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::LedgerTime;
    ///
    /// let time = LedgerTime::new("main-ledger", 1, 42);
    /// assert_eq!(time.ledger_id(), "main-ledger");
    /// assert_eq!(time.epoch(), 1);
    /// assert_eq!(time.seq(), 42);
    /// ```
    #[must_use]
    pub fn new(ledger_id: impl Into<String>, epoch: u64, seq: u64) -> Self {
        Self::try_new(ledger_id, epoch, seq).expect("ledger_id must not exceed MAX_STRING_LENGTH")
    }

    /// Attempts to create a new `LedgerTime` with validation.
    ///
    /// # Arguments
    ///
    /// * `ledger_id` - Stable identifier for the ledger namespace
    /// * `epoch` - Epoch number (changes on authority/config changes)
    /// * `seq` - Sequence number within the epoch
    ///
    /// # Errors
    ///
    /// Returns [`LedgerTimeError::LedgerIdTooLong`] if `ledger_id` exceeds
    /// [`MAX_STRING_LENGTH`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::{LedgerTime, LedgerTimeError, MAX_STRING_LENGTH};
    ///
    /// // Valid ledger ID
    /// let time = LedgerTime::try_new("valid-id", 1, 1).unwrap();
    ///
    /// // Oversized ledger ID
    /// let long_id = "x".repeat(MAX_STRING_LENGTH + 1);
    /// let result = LedgerTime::try_new(long_id, 1, 1);
    /// assert!(matches!(
    ///     result,
    ///     Err(LedgerTimeError::LedgerIdTooLong { .. })
    /// ));
    /// ```
    pub fn try_new(
        ledger_id: impl Into<String>,
        epoch: u64,
        seq: u64,
    ) -> Result<Self, LedgerTimeError> {
        let ledger_id = ledger_id.into();
        if ledger_id.len() > MAX_STRING_LENGTH {
            return Err(LedgerTimeError::LedgerIdTooLong {
                length: ledger_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        Ok(Self {
            ledger_id,
            epoch,
            seq,
        })
    }

    /// Returns the ledger namespace identifier.
    #[must_use]
    pub fn ledger_id(&self) -> &str {
        &self.ledger_id
    }

    /// Returns the epoch number.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the sequence number within the epoch.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns a new `LedgerTime` with the sequence incremented by one.
    ///
    /// # Panics
    ///
    /// Panics on sequence overflow. Use [`LedgerTime::checked_next_seq`] for
    /// fallible increment.
    #[must_use]
    pub fn next_seq(&self) -> Self {
        self.checked_next_seq()
            .expect("sequence overflow in LedgerTime::next_seq")
    }

    /// Returns a new `LedgerTime` with the sequence incremented by one,
    /// or `None` if the sequence would overflow.
    #[must_use]
    pub fn checked_next_seq(&self) -> Option<Self> {
        self.seq.checked_add(1).map(|seq| Self {
            ledger_id: self.ledger_id.clone(),
            epoch: self.epoch,
            seq,
        })
    }

    /// Returns a new `LedgerTime` with the epoch incremented and sequence
    /// reset to zero.
    ///
    /// # Panics
    ///
    /// Panics on epoch overflow. Use [`LedgerTime::checked_next_epoch`] for
    /// fallible increment.
    #[must_use]
    pub fn next_epoch(&self) -> Self {
        self.checked_next_epoch()
            .expect("epoch overflow in LedgerTime::next_epoch")
    }

    /// Returns a new `LedgerTime` with the epoch incremented and sequence
    /// reset to zero, or `None` if the epoch would overflow.
    #[must_use]
    pub fn checked_next_epoch(&self) -> Option<Self> {
        self.epoch.checked_add(1).map(|epoch| Self {
            ledger_id: self.ledger_id.clone(),
            epoch,
            seq: 0,
        })
    }
}

impl PartialOrd for LedgerTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LedgerTime {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lexicographic ordering: ledger_id, then epoch, then seq
        match self.ledger_id.cmp(&other.ledger_id) {
            Ordering::Equal => match self.epoch.cmp(&other.epoch) {
                Ordering::Equal => self.seq.cmp(&other.seq),
                other => other,
            },
            other => other,
        }
    }
}

impl std::fmt::Display for LedgerTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.ledger_id, self.epoch, self.seq)
    }
}

/// Custom deserialization that enforces resource limits.
impl<'de> Deserialize<'de> for LedgerTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct LedgerTimeHelper {
            ledger_id: String,
            epoch: u64,
            seq: u64,
        }

        let helper = LedgerTimeHelper::deserialize(deserializer)?;

        if helper.ledger_id.len() > MAX_STRING_LENGTH {
            return Err(D::Error::custom(format!(
                "ledger_id exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                helper.ledger_id.len(),
            )));
        }

        Ok(Self {
            ledger_id: helper.ledger_id,
            epoch: helper.epoch,
            seq: helper.seq,
        })
    }
}

/// Errors that can occur when working with [`LedgerTime`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerTimeError {
    /// The ledger ID exceeds the maximum allowed length.
    #[error("ledger_id too long: {length} > {max}")]
    LedgerIdTooLong {
        /// The actual length.
        length: usize,
        /// The maximum allowed length.
        max: usize,
    },
}

// =============================================================================
// HtfTick
// =============================================================================

/// Node-local monotonic tick counter for deadlines and durations.
///
/// `HtfTick` wraps a `u64` tick value along with the tick rate in Hz for
/// context. Tick values are node-local and MUST NOT be compared across
/// different nodes.
///
/// # Authority
///
/// Tick arithmetic is authoritative for:
/// - Deadline calculations within a single node
/// - Duration measurements within a single node
/// - Timeout enforcement
///
/// # Non-Authority
///
/// Tick values are NOT authoritative for:
/// - Cross-node time comparison (use [`LedgerTime`])
/// - Wall clock correlation (use [`BoundedWallInterval`])
///
/// # Example
///
/// ```rust
/// use apm2_core::htf::HtfTick;
///
/// // Create a tick at 1MHz (1 tick = 1 microsecond)
/// let start = HtfTick::new(1000, 1_000_000);
///
/// // Add 5000 ticks (5ms at 1MHz)
/// let deadline = start.saturating_add(5000);
/// assert_eq!(deadline.value(), 6000);
///
/// // Calculate elapsed ticks
/// let elapsed = deadline.saturating_sub(&start);
/// assert_eq!(elapsed, 5000);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HtfTick {
    /// The tick value.
    value: u64,

    /// The tick rate in Hz (ticks per second).
    tick_rate_hz: u64,
}

impl HtfTick {
    /// Creates a new `HtfTick` with the given value and tick rate.
    ///
    /// # Arguments
    ///
    /// * `value` - The tick counter value
    /// * `tick_rate_hz` - The tick rate in Hz (ticks per second)
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::HtfTick;
    ///
    /// // 1MHz tick rate (1 tick = 1 microsecond)
    /// let tick = HtfTick::new(42, 1_000_000);
    /// assert_eq!(tick.value(), 42);
    /// assert_eq!(tick.tick_rate_hz(), 1_000_000);
    /// ```
    #[must_use]
    pub const fn new(value: u64, tick_rate_hz: u64) -> Self {
        Self {
            value,
            tick_rate_hz,
        }
    }

    /// Returns the tick counter value.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Returns the tick rate in Hz.
    #[must_use]
    pub const fn tick_rate_hz(&self) -> u64 {
        self.tick_rate_hz
    }

    /// Returns a new `HtfTick` with the given delta added, saturating at
    /// `u64::MAX`.
    ///
    /// # Arguments
    ///
    /// * `delta` - The number of ticks to add
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::HtfTick;
    ///
    /// let tick = HtfTick::new(100, 1_000_000);
    /// let later = tick.saturating_add(50);
    /// assert_eq!(later.value(), 150);
    ///
    /// // Saturates at u64::MAX
    /// let max_tick = HtfTick::new(u64::MAX - 10, 1_000_000);
    /// let saturated = max_tick.saturating_add(20);
    /// assert_eq!(saturated.value(), u64::MAX);
    /// ```
    #[must_use]
    pub const fn saturating_add(&self, delta: u64) -> Self {
        Self {
            value: self.value.saturating_add(delta),
            tick_rate_hz: self.tick_rate_hz,
        }
    }

    /// Returns the difference between this tick and another tick, saturating
    /// at zero.
    ///
    /// Note: This returns a raw `u64` delta, not an `HtfTick`, since the
    /// result represents a duration rather than a point in time.
    ///
    /// # Arguments
    ///
    /// * `earlier` - The earlier tick to subtract
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::HtfTick;
    ///
    /// let start = HtfTick::new(100, 1_000_000);
    /// let end = HtfTick::new(150, 1_000_000);
    ///
    /// assert_eq!(end.saturating_sub(&start), 50);
    /// assert_eq!(start.saturating_sub(&end), 0); // Saturates at 0
    /// ```
    #[must_use]
    pub const fn saturating_sub(&self, earlier: &Self) -> u64 {
        self.value.saturating_sub(earlier.value)
    }

    /// Returns a new `HtfTick` with the given delta added, or `None` on
    /// overflow.
    ///
    /// # Arguments
    ///
    /// * `delta` - The number of ticks to add
    #[must_use]
    pub const fn checked_add(&self, delta: u64) -> Option<Self> {
        match self.value.checked_add(delta) {
            Some(value) => Some(Self {
                value,
                tick_rate_hz: self.tick_rate_hz,
            }),
            None => None,
        }
    }

    /// Returns the difference between this tick and another tick, or `None`
    /// if the result would be negative.
    ///
    /// # Arguments
    ///
    /// * `earlier` - The earlier tick to subtract
    #[must_use]
    pub const fn checked_sub(&self, earlier: &Self) -> Option<u64> {
        self.value.checked_sub(earlier.value)
    }

    /// Converts a duration in nanoseconds to ticks at this tick rate.
    ///
    /// # Arguments
    ///
    /// * `nanos` - Duration in nanoseconds
    ///
    /// # Returns
    ///
    /// The number of ticks, or `None` if the calculation would overflow.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::HtfTick;
    ///
    /// let tick = HtfTick::new(0, 1_000_000); // 1MHz
    ///
    /// // 1 millisecond = 1,000,000 nanoseconds = 1000 ticks at 1MHz
    /// assert_eq!(tick.nanos_to_ticks(1_000_000), Some(1000));
    /// ```
    #[must_use]
    pub const fn nanos_to_ticks(&self, nanos: u64) -> Option<u64> {
        // ticks = nanos * tick_rate_hz / 1_000_000_000
        // To avoid overflow, we use: (nanos / 1_000_000_000) * tick_rate_hz +
        //                            (nanos % 1_000_000_000) * tick_rate_hz /
        // 1_000_000_000
        let whole_seconds = nanos / 1_000_000_000;
        let remainder_nanos = nanos % 1_000_000_000;

        let Some(whole_ticks) = whole_seconds.checked_mul(self.tick_rate_hz) else {
            return None;
        };

        let frac_ticks = match remainder_nanos.checked_mul(self.tick_rate_hz) {
            Some(t) => t / 1_000_000_000,
            None => return None,
        };

        whole_ticks.checked_add(frac_ticks)
    }

    /// Converts ticks to nanoseconds at this tick rate.
    ///
    /// # Arguments
    ///
    /// * `ticks` - Number of ticks
    ///
    /// # Returns
    ///
    /// The duration in nanoseconds, or `None` if the calculation would
    /// overflow.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::HtfTick;
    ///
    /// let tick = HtfTick::new(0, 1_000_000); // 1MHz
    ///
    /// // 1000 ticks at 1MHz = 1 millisecond = 1,000,000 nanoseconds
    /// assert_eq!(tick.ticks_to_nanos(1000), Some(1_000_000));
    /// ```
    #[must_use]
    pub const fn ticks_to_nanos(&self, ticks: u64) -> Option<u64> {
        // nanos = ticks * 1_000_000_000 / tick_rate_hz
        if self.tick_rate_hz == 0 {
            return None;
        }

        if let Some(nanos) = ticks.checked_mul(1_000_000_000) {
            Some(nanos / self.tick_rate_hz)
        } else {
            // Overflow in multiplication, use alternative calculation
            // ticks / tick_rate_hz * 1_000_000_000 + (ticks % tick_rate_hz) *
            // 1_000_000_000 / tick_rate_hz
            let whole_seconds = ticks / self.tick_rate_hz;
            let remainder_ticks = ticks % self.tick_rate_hz;

            match whole_seconds.checked_mul(1_000_000_000) {
                Some(whole_nanos) => {
                    let frac_nanos = match remainder_ticks.checked_mul(1_000_000_000) {
                        Some(n) => n / self.tick_rate_hz,
                        None => 0,
                    };
                    whole_nanos.checked_add(frac_nanos)
                },
                None => None,
            }
        }
    }
}

impl std::fmt::Display for HtfTick {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}Hz", self.value, self.tick_rate_hz)
    }
}

// =============================================================================
// TimeEnvelopeRef
// =============================================================================

/// Content hash reference to a full `TimeEnvelope`.
///
/// `TimeEnvelopeRef` is a lightweight 32-byte reference used in hot-path
/// events to avoid embedding full time envelopes. The actual envelope can
/// be retrieved from content-addressed storage using this hash.
///
/// # Zero-Copy Serialization
///
/// The type is designed for zero-copy serde operations where possible,
/// using a fixed-size byte array internally.
///
/// # Example
///
/// ```rust
/// use apm2_core::htf::TimeEnvelopeRef;
///
/// // Create from a content hash
/// let hash = [0x42u8; 32];
/// let envelope_ref = TimeEnvelopeRef::new(hash);
///
/// // Access the raw bytes
/// assert_eq!(envelope_ref.as_bytes(), &hash);
///
/// // Compare references
/// let same_ref = TimeEnvelopeRef::new([0x42u8; 32]);
/// assert_eq!(envelope_ref, same_ref);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimeEnvelopeRef {
    /// The content hash (SHA-256).
    hash: [u8; 32],
}

impl TimeEnvelopeRef {
    /// Creates a new `TimeEnvelopeRef` from a content hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte content hash (typically SHA-256)
    #[must_use]
    pub const fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Returns the content hash as a byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Returns the content hash as a mutable byte slice.
    #[must_use]
    pub const fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.hash
    }

    /// Creates a `TimeEnvelopeRef` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte slice
    ///
    /// # Returns
    ///
    /// `Some(TimeEnvelopeRef)` if the slice is exactly 32 bytes, `None`
    /// otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::TimeEnvelopeRef;
    ///
    /// let bytes = [0x42u8; 32];
    /// let envelope_ref = TimeEnvelopeRef::from_slice(&bytes).unwrap();
    ///
    /// // Wrong size returns None
    /// let short = [0u8; 16];
    /// assert!(TimeEnvelopeRef::from_slice(&short).is_none());
    /// ```
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(bytes);
            Some(Self { hash })
        } else {
            None
        }
    }

    /// Returns the zero reference (all bytes are zero).
    ///
    /// This can be used as a sentinel value.
    #[must_use]
    pub const fn zero() -> Self {
        Self { hash: [0u8; 32] }
    }

    /// Returns `true` if this is the zero reference.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < 32 {
            if self.hash[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl std::fmt::Display for TimeEnvelopeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display first 8 bytes in hex for brevity
        write!(f, "htf:{}...", hex::encode(&self.hash[..8]))
    }
}

impl From<[u8; 32]> for TimeEnvelopeRef {
    fn from(hash: [u8; 32]) -> Self {
        Self::new(hash)
    }
}

impl From<TimeEnvelopeRef> for [u8; 32] {
    fn from(envelope_ref: TimeEnvelopeRef) -> Self {
        envelope_ref.hash
    }
}

impl AsRef<[u8; 32]> for TimeEnvelopeRef {
    fn as_ref(&self) -> &[u8; 32] {
        &self.hash
    }
}

// =============================================================================
// MonotonicSource
// =============================================================================

/// Source of monotonic time readings.
///
/// This enum identifies the kernel/system monotonic clock source used for
/// tick generation.
///
/// # Variants
///
/// - `ClockMonotonicRaw`: Linux `CLOCK_MONOTONIC_RAW`, not subject to NTP
///   adjustments
/// - `ClockMonotonic`: Standard `CLOCK_MONOTONIC`, may be adjusted by NTP
/// - `Other`: Platform-specific or custom clock source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum MonotonicSource {
    /// Linux `CLOCK_MONOTONIC_RAW`.
    ///
    /// Not subject to NTP adjustments. Preferred for precise duration
    /// measurement.
    ClockMonotonicRaw,

    /// Standard `CLOCK_MONOTONIC`.
    ///
    /// May be subject to NTP rate adjustments (but not step changes).
    ClockMonotonic,

    /// Platform-specific or custom clock source.
    Other,
}

impl std::fmt::Display for MonotonicSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClockMonotonicRaw => write!(f, "CLOCK_MONOTONIC_RAW"),
            Self::ClockMonotonic => write!(f, "CLOCK_MONOTONIC"),
            Self::Other => write!(f, "OTHER"),
        }
    }
}

// =============================================================================
// WallTimeSource
// =============================================================================

/// Source of wall clock time readings.
///
/// This enum identifies how wall clock time bounds were obtained. Different
/// sources have different trust and accuracy characteristics.
///
/// # Security Note
///
/// Wall time is NEVER authoritative for ordering or truth decisions. It is
/// only used for display and external system coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WallTimeSource {
    /// No wall time source available.
    ///
    /// The wall time bounds are meaningless placeholders.
    None,

    /// Best-effort NTP synchronization.
    ///
    /// Standard NTP without authentication. Subject to network-based attacks.
    BestEffortNtp,

    /// Authenticated Network Time Security (NTS).
    ///
    /// NTP with TLS-based authentication. Protects against MITM attacks.
    AuthenticatedNts,

    /// Roughtime protocol.
    ///
    /// Provides cryptographic proof of time from multiple servers.
    Roughtime,

    /// Cloud provider bounded time service.
    ///
    /// Examples: AWS Time Sync Service, Google True Time.
    CloudBounded,

    /// Manual operator-provided time bounds.
    ///
    /// Used when automated time sources are unavailable or untrusted.
    ManualOperator,
}

impl std::fmt::Display for WallTimeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::BestEffortNtp => write!(f, "best-effort-ntp"),
            Self::AuthenticatedNts => write!(f, "authenticated-nts"),
            Self::Roughtime => write!(f, "roughtime"),
            Self::CloudBounded => write!(f, "cloud-bounded"),
            Self::ManualOperator => write!(f, "manual-operator"),
        }
    }
}

// =============================================================================
// BoundedWallInterval
// =============================================================================

/// Wall time interval with explicit uncertainty bounds.
///
/// `BoundedWallInterval` represents a wall clock time range with:
/// - `t_min_utc_ns`: Minimum possible wall time (Unix nanoseconds)
/// - `t_max_utc_ns`: Maximum possible wall time (Unix nanoseconds)
/// - `source`: How the time bounds were obtained
/// - `confidence`: Deployment-defined confidence descriptor
///
/// # Invariant
///
/// `t_max_utc_ns >= t_min_utc_ns` is always enforced.
///
/// # Authority
///
/// Wall time is NEVER authoritative. It is only used for:
/// - Display purposes
/// - External system coordination
/// - Audit logging with explicit uncertainty
///
/// # Example
///
/// ```rust
/// use apm2_core::htf::{BoundedWallInterval, WallTimeSource};
///
/// // 100ms uncertainty window around 2024-01-01 00:00:00 UTC
/// let wall = BoundedWallInterval::new(
///     1704067200_000_000_000, // t_min
///     1704067200_100_000_000, // t_max (+100ms)
///     WallTimeSource::BestEffortNtp,
///     "95%",
/// )
/// .expect("valid interval");
///
/// assert!(wall.contains(1704067200_050_000_000));
/// assert!(!wall.contains(1704067200_200_000_000));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct BoundedWallInterval {
    /// Minimum wall time in Unix nanoseconds (UTC).
    t_min_utc_ns: u64,

    /// Maximum wall time in Unix nanoseconds (UTC).
    t_max_utc_ns: u64,

    /// Source of the wall time reading.
    source: WallTimeSource,

    /// Deployment-defined confidence descriptor.
    confidence: String,
}

impl BoundedWallInterval {
    /// Creates a new `BoundedWallInterval` with validation.
    ///
    /// # Arguments
    ///
    /// * `t_min_utc_ns` - Minimum wall time in Unix nanoseconds
    /// * `t_max_utc_ns` - Maximum wall time in Unix nanoseconds
    /// * `source` - Source of the time reading
    /// * `confidence` - Deployment-defined confidence descriptor
    ///
    /// # Errors
    ///
    /// Returns [`BoundedWallIntervalError`] if:
    /// - `t_max_utc_ns < t_min_utc_ns` (invalid interval)
    /// - `confidence` exceeds [`MAX_STRING_LENGTH`]
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::htf::{
    ///     BoundedWallInterval, BoundedWallIntervalError, WallTimeSource,
    /// };
    ///
    /// // Valid interval
    /// let wall = BoundedWallInterval::new(100, 200, WallTimeSource::None, "test");
    /// assert!(wall.is_ok());
    ///
    /// // Invalid: t_max < t_min
    /// let invalid =
    ///     BoundedWallInterval::new(200, 100, WallTimeSource::None, "test");
    /// assert!(matches!(
    ///     invalid,
    ///     Err(BoundedWallIntervalError::InvalidInterval { .. })
    /// ));
    /// ```
    pub fn new(
        t_min_utc_ns: u64,
        t_max_utc_ns: u64,
        source: WallTimeSource,
        confidence: impl Into<String>,
    ) -> Result<Self, BoundedWallIntervalError> {
        if t_max_utc_ns < t_min_utc_ns {
            return Err(BoundedWallIntervalError::InvalidInterval {
                t_min: t_min_utc_ns,
                t_max: t_max_utc_ns,
            });
        }

        let confidence = confidence.into();
        if confidence.len() > MAX_STRING_LENGTH {
            return Err(BoundedWallIntervalError::ConfidenceTooLong {
                length: confidence.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        Ok(Self {
            t_min_utc_ns,
            t_max_utc_ns,
            source,
            confidence,
        })
    }

    /// Creates a point-in-time interval (zero uncertainty).
    ///
    /// # Arguments
    ///
    /// * `t_utc_ns` - Wall time in Unix nanoseconds
    /// * `source` - Source of the time reading
    /// * `confidence` - Confidence descriptor
    ///
    /// # Errors
    ///
    /// Returns an error if `confidence` exceeds [`MAX_STRING_LENGTH`].
    pub fn point(
        t_utc_ns: u64,
        source: WallTimeSource,
        confidence: impl Into<String>,
    ) -> Result<Self, BoundedWallIntervalError> {
        Self::new(t_utc_ns, t_utc_ns, source, confidence)
    }

    /// Returns the minimum wall time in Unix nanoseconds.
    #[must_use]
    pub const fn t_min_utc_ns(&self) -> u64 {
        self.t_min_utc_ns
    }

    /// Returns the maximum wall time in Unix nanoseconds.
    #[must_use]
    pub const fn t_max_utc_ns(&self) -> u64 {
        self.t_max_utc_ns
    }

    /// Returns the wall time source.
    #[must_use]
    pub const fn source(&self) -> WallTimeSource {
        self.source
    }

    /// Returns the confidence descriptor.
    #[must_use]
    pub fn confidence(&self) -> &str {
        &self.confidence
    }

    /// Returns the uncertainty span in nanoseconds.
    #[must_use]
    pub const fn uncertainty_ns(&self) -> u64 {
        self.t_max_utc_ns - self.t_min_utc_ns
    }

    /// Returns `true` if the given timestamp falls within this interval
    /// (inclusive).
    ///
    /// # Arguments
    ///
    /// * `t_utc_ns` - Timestamp to check in Unix nanoseconds
    #[must_use]
    pub const fn contains(&self, t_utc_ns: u64) -> bool {
        t_utc_ns >= self.t_min_utc_ns && t_utc_ns <= self.t_max_utc_ns
    }

    /// Returns `true` if this interval overlaps with another.
    ///
    /// # Arguments
    ///
    /// * `other` - The other interval to check
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.t_min_utc_ns <= other.t_max_utc_ns && self.t_max_utc_ns >= other.t_min_utc_ns
    }

    /// Returns the midpoint of this interval.
    ///
    /// This can be used as a "best guess" timestamp when a single value is
    /// needed.
    #[must_use]
    pub const fn midpoint_ns(&self) -> u64 {
        self.t_min_utc_ns + (self.t_max_utc_ns - self.t_min_utc_ns) / 2
    }
}

impl std::fmt::Display for BoundedWallInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let uncertainty_ms = self.uncertainty_ns() / 1_000_000;
        write!(
            f,
            "[{}, {}] (+/-{}ms, {}, {})",
            self.t_min_utc_ns, self.t_max_utc_ns, uncertainty_ms, self.source, self.confidence
        )
    }
}

/// Custom deserialization that enforces invariants and resource limits.
impl<'de> Deserialize<'de> for BoundedWallInterval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct BoundedWallIntervalHelper {
            t_min_utc_ns: u64,
            t_max_utc_ns: u64,
            source: WallTimeSource,
            confidence: String,
        }

        let helper = BoundedWallIntervalHelper::deserialize(deserializer)?;

        if helper.t_max_utc_ns < helper.t_min_utc_ns {
            return Err(D::Error::custom(format!(
                "invalid interval: t_max ({}) < t_min ({})",
                helper.t_max_utc_ns, helper.t_min_utc_ns,
            )));
        }

        if helper.confidence.len() > MAX_STRING_LENGTH {
            return Err(D::Error::custom(format!(
                "confidence exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                helper.confidence.len(),
            )));
        }

        Ok(Self {
            t_min_utc_ns: helper.t_min_utc_ns,
            t_max_utc_ns: helper.t_max_utc_ns,
            source: helper.source,
            confidence: helper.confidence,
        })
    }
}

/// Errors that can occur when working with [`BoundedWallInterval`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BoundedWallIntervalError {
    /// Invalid interval where `t_max` < `t_min`.
    #[error("invalid interval: t_max ({t_max}) < t_min ({t_min})")]
    InvalidInterval {
        /// The minimum time value.
        t_min: u64,
        /// The maximum time value.
        t_max: u64,
    },

    /// Confidence string exceeds maximum length.
    #[error("confidence too long: {length} > {max}")]
    ConfidenceTooLong {
        /// The actual length.
        length: usize,
        /// The maximum allowed length.
        max: usize,
    },
}

// =============================================================================
// ClockProfile
// =============================================================================

/// Configuration for a node's clock behavior.
///
/// `ClockProfile` defines the parameters for monotonic and wall time sources,
/// tick rates, and uncertainty bounds. It is a CAC artifact that must be
/// canonicalized and signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClockProfile {
    /// Optional attestation data (Phase 2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<serde_json::Value>,

    /// Daemon version + platform hash.
    pub build_fingerprint: String,

    /// Whether hybrid logical clock is enabled.
    pub hlc_enabled: bool,

    /// Maximum wall time uncertainty in nanoseconds.
    pub max_wall_uncertainty_ns: u64,

    /// Source of monotonic clock.
    pub monotonic_source: MonotonicSource,

    /// Stable identifier for policy grouping.
    pub profile_policy_id: String,

    /// Tick rate in Hz (must match envelopes).
    pub tick_rate_hz: u64,

    /// Source of wall time synchronization.
    pub wall_time_source: WallTimeSource,
}

impl<'de> Deserialize<'de> for ClockProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct Helper {
            attestation: Option<serde_json::Value>,
            build_fingerprint: String,
            hlc_enabled: bool,
            max_wall_uncertainty_ns: u64,
            monotonic_source: MonotonicSource,
            profile_policy_id: String,
            tick_rate_hz: u64,
            wall_time_source: WallTimeSource,
        }

        let helper = Helper::deserialize(deserializer)?;

        if helper.build_fingerprint.len() > MAX_STRING_LENGTH {
            return Err(D::Error::custom(format!(
                "build_fingerprint exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                helper.build_fingerprint.len()
            )));
        }
        if helper.profile_policy_id.len() > MAX_STRING_LENGTH {
            return Err(D::Error::custom(format!(
                "profile_policy_id exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                helper.profile_policy_id.len()
            )));
        }

        Ok(Self {
            attestation: helper.attestation,
            build_fingerprint: helper.build_fingerprint,
            hlc_enabled: helper.hlc_enabled,
            max_wall_uncertainty_ns: helper.max_wall_uncertainty_ns,
            monotonic_source: helper.monotonic_source,
            profile_policy_id: helper.profile_policy_id,
            tick_rate_hz: helper.tick_rate_hz,
            wall_time_source: helper.wall_time_source,
        })
    }
}

// =============================================================================
// TimeEnvelope
// =============================================================================

/// A verifiable time assertion envelope.
///
/// `TimeEnvelope` binds a monotonic tick reading, wall time bounds, and
/// logical clock state to a specific ledger anchor and clock profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimeEnvelope {
    /// Content hash of the `ClockProfileV1`.
    pub clock_profile_hash: String,

    /// Hybrid logical clock timestamp.
    pub hlc: Hlc,

    /// Reference to ledger position.
    pub ledger_anchor: LedgerTime,

    /// Monotonic clock reading.
    pub mono: MonotonicReading,

    /// Optional notes about the time envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    /// Wall clock time bounds.
    pub wall: BoundedWallInterval,
}

impl<'de> Deserialize<'de> for TimeEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct Helper {
            clock_profile_hash: String,
            hlc: Hlc,
            ledger_anchor: LedgerTime,
            mono: MonotonicReading,
            notes: Option<String>,
            wall: BoundedWallInterval,
        }

        let helper = Helper::deserialize(deserializer)?;

        if helper.clock_profile_hash.len() > MAX_STRING_LENGTH {
            return Err(D::Error::custom(format!(
                "clock_profile_hash exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                helper.clock_profile_hash.len()
            )));
        }
        if let Some(notes) = &helper.notes {
            if notes.len() > MAX_STRING_LENGTH {
                return Err(D::Error::custom(format!(
                    "notes exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                    notes.len()
                )));
            }
        }

        Ok(Self {
            clock_profile_hash: helper.clock_profile_hash,
            hlc: helper.hlc,
            ledger_anchor: helper.ledger_anchor,
            mono: helper.mono,
            notes: helper.notes,
            wall: helper.wall,
        })
    }
}

/// Hybrid Logical Clock timestamp components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hlc {
    /// Logical counter component.
    pub logical: u64,

    /// Wall time in nanoseconds.
    pub wall_ns: u64,
}

/// Monotonic clock reading components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MonotonicReading {
    /// End tick (must be >= `start_tick` when present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_tick: Option<u64>,

    /// Monotonic clock source.
    pub source: MonotonicSource,

    /// Start tick value.
    pub start_tick: u64,

    /// Tick rate in Hz.
    pub tick_rate_hz: u64,
}

// =============================================================================
// TimeSyncObservation
// =============================================================================

/// A record of time synchronization observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimeSyncObservation {
    /// Array of time sync observation records.
    pub observations: Vec<ObservationRecord>,

    /// `TimeEnvelopeRef` hash reference.
    pub observed_at_envelope_ref: String,
}

impl<'de> Deserialize<'de> for TimeSyncObservation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct Helper {
            observations: Vec<ObservationRecord>,
            observed_at_envelope_ref: String,
        }

        let helper = Helper::deserialize(deserializer)?;

        if helper.observed_at_envelope_ref.len() > MAX_STRING_LENGTH {
            return Err(D::Error::custom(format!(
                "observed_at_envelope_ref exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                helper.observed_at_envelope_ref.len()
            )));
        }

        Ok(Self {
            observations: helper.observations,
            observed_at_envelope_ref: helper.observed_at_envelope_ref,
        })
    }
}

/// Individual observation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationRecord {
    /// Monotonic tick at observation time.
    pub observed_at_mono_tick: u64,

    /// Observed clock offset in nanoseconds.
    pub observed_offset_ns: i64,

    /// Source of the observation.
    pub source: String,

    /// Uncertainty of the observation in nanoseconds.
    pub uncertainty_ns: u64,
}

impl<'de> Deserialize<'de> for ObservationRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct Helper {
            observed_at_mono_tick: u64,
            observed_offset_ns: i64,
            source: String,
            uncertainty_ns: u64,
        }

        let helper = Helper::deserialize(deserializer)?;

        if helper.source.len() > MAX_STRING_LENGTH {
            return Err(D::Error::custom(format!(
                "source exceeds maximum length: {} > {MAX_STRING_LENGTH}",
                helper.source.len()
            )));
        }

        Ok(Self {
            observed_at_mono_tick: helper.observed_at_mono_tick,
            observed_offset_ns: helper.observed_offset_ns,
            source: helper.source,
            uncertainty_ns: helper.uncertainty_ns,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // LedgerTime Tests
    // =========================================================================

    mod ledger_time {
        use super::*;

        #[test]
        fn test_new_and_accessors() {
            let time = LedgerTime::new("test-ledger", 5, 100);
            assert_eq!(time.ledger_id(), "test-ledger");
            assert_eq!(time.epoch(), 5);
            assert_eq!(time.seq(), 100);
        }

        #[test]
        fn test_try_new_valid() {
            let time = LedgerTime::try_new("valid-id", 1, 2).unwrap();
            assert_eq!(time.ledger_id(), "valid-id");
        }

        #[test]
        fn test_try_new_oversized_ledger_id() {
            let long_id = "x".repeat(MAX_STRING_LENGTH + 1);
            let result = LedgerTime::try_new(long_id, 1, 1);
            assert!(matches!(
                result,
                Err(LedgerTimeError::LedgerIdTooLong { .. })
            ));
        }

        #[test]
        fn test_ordering_same_ledger_same_epoch() {
            let t1 = LedgerTime::new("ledger", 1, 100);
            let t2 = LedgerTime::new("ledger", 1, 101);
            let t3 = LedgerTime::new("ledger", 1, 100);

            assert!(t1 < t2);
            assert!(t2 > t1);
            assert_eq!(t1, t3);
        }

        #[test]
        fn test_ordering_same_ledger_different_epoch() {
            let t1 = LedgerTime::new("ledger", 1, 999);
            let t2 = LedgerTime::new("ledger", 2, 1);

            // Epoch takes precedence over seq
            assert!(t1 < t2);
        }

        #[test]
        fn test_ordering_different_ledger() {
            let t1 = LedgerTime::new("aaa", 999, 999);
            let t2 = LedgerTime::new("bbb", 1, 1);

            // Ledger ID takes precedence
            assert!(t1 < t2);
        }

        #[test]
        fn test_ordering_comprehensive() {
            let mut times = [
                LedgerTime::new("ledger-b", 1, 1),
                LedgerTime::new("ledger-a", 2, 1),
                LedgerTime::new("ledger-a", 1, 100),
                LedgerTime::new("ledger-a", 1, 1),
            ];

            times.sort();

            assert_eq!(times[0], LedgerTime::new("ledger-a", 1, 1));
            assert_eq!(times[1], LedgerTime::new("ledger-a", 1, 100));
            assert_eq!(times[2], LedgerTime::new("ledger-a", 2, 1));
            assert_eq!(times[3], LedgerTime::new("ledger-b", 1, 1));
        }

        #[test]
        fn test_next_seq() {
            let t1 = LedgerTime::new("ledger", 1, 100);
            let t2 = t1.next_seq();
            assert_eq!(t2.seq(), 101);
            assert_eq!(t2.epoch(), 1);
            assert_eq!(t2.ledger_id(), "ledger");
        }

        #[test]
        fn test_checked_next_seq_overflow() {
            let max_seq = LedgerTime::new("ledger", 1, u64::MAX);
            assert!(max_seq.checked_next_seq().is_none());
        }

        #[test]
        fn test_next_epoch() {
            let t1 = LedgerTime::new("ledger", 5, 999);
            let t2 = t1.next_epoch();
            assert_eq!(t2.epoch(), 6);
            assert_eq!(t2.seq(), 0);
            assert_eq!(t2.ledger_id(), "ledger");
        }

        #[test]
        fn test_checked_next_epoch_overflow() {
            let max_epoch = LedgerTime::new("ledger", u64::MAX, 100);
            assert!(max_epoch.checked_next_epoch().is_none());
        }

        #[test]
        fn test_display() {
            let time = LedgerTime::new("main", 2, 42);
            assert_eq!(time.to_string(), "main:2:42");
        }

        #[test]
        fn test_serde_roundtrip() {
            let time = LedgerTime::new("test-ledger", 5, 100);
            let json = serde_json::to_string(&time).unwrap();
            let deserialized: LedgerTime = serde_json::from_str(&json).unwrap();
            assert_eq!(time, deserialized);
        }

        #[test]
        fn test_deserialize_rejects_oversized_ledger_id() {
            let long_id = "x".repeat(MAX_STRING_LENGTH + 1);
            let json = format!(r#"{{"ledger_id": "{long_id}", "epoch": 1, "seq": 1}}"#);
            let result: Result<LedgerTime, _> = serde_json::from_str(&json);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("ledger_id exceeds maximum length"));
        }

        #[test]
        fn test_hash_equality() {
            use std::collections::HashSet;

            let t1 = LedgerTime::new("ledger", 1, 100);
            let t2 = LedgerTime::new("ledger", 1, 100);
            let t3 = LedgerTime::new("ledger", 1, 101);

            let mut set = HashSet::new();
            set.insert(t1.clone());
            set.insert(t2);
            set.insert(t3.clone());

            assert_eq!(set.len(), 2); // t1 and t2 are equal
            assert!(set.contains(&t1));
            assert!(set.contains(&t3));
        }
    }

    // =========================================================================
    // HtfTick Tests
    // =========================================================================

    mod htf_tick {
        use super::*;

        #[test]
        fn test_new_and_accessors() {
            let tick = HtfTick::new(1000, 1_000_000);
            assert_eq!(tick.value(), 1000);
            assert_eq!(tick.tick_rate_hz(), 1_000_000);
        }

        #[test]
        fn test_saturating_add() {
            let tick = HtfTick::new(100, 1_000_000);
            let result = tick.saturating_add(50);
            assert_eq!(result.value(), 150);
            assert_eq!(result.tick_rate_hz(), 1_000_000);
        }

        #[test]
        fn test_saturating_add_overflow() {
            let tick = HtfTick::new(u64::MAX - 10, 1_000_000);
            let result = tick.saturating_add(20);
            assert_eq!(result.value(), u64::MAX);
        }

        #[test]
        fn test_saturating_sub() {
            let start = HtfTick::new(100, 1_000_000);
            let end = HtfTick::new(150, 1_000_000);
            assert_eq!(end.saturating_sub(&start), 50);
        }

        #[test]
        fn test_saturating_sub_underflow() {
            let start = HtfTick::new(150, 1_000_000);
            let end = HtfTick::new(100, 1_000_000);
            assert_eq!(end.saturating_sub(&start), 0);
        }

        #[test]
        fn test_checked_add() {
            let tick = HtfTick::new(100, 1_000_000);
            assert_eq!(tick.checked_add(50).map(|t| t.value()), Some(150));
            assert!(HtfTick::new(u64::MAX, 1_000_000).checked_add(1).is_none());
        }

        #[test]
        fn test_checked_sub() {
            let start = HtfTick::new(100, 1_000_000);
            let end = HtfTick::new(150, 1_000_000);
            assert_eq!(end.checked_sub(&start), Some(50));
            assert_eq!(start.checked_sub(&end), None);
        }

        #[test]
        fn test_nanos_to_ticks() {
            let tick = HtfTick::new(0, 1_000_000); // 1MHz

            // 1ms = 1,000,000ns = 1000 ticks at 1MHz
            assert_eq!(tick.nanos_to_ticks(1_000_000), Some(1000));

            // 1 second = 1,000,000,000ns = 1,000,000 ticks at 1MHz
            assert_eq!(tick.nanos_to_ticks(1_000_000_000), Some(1_000_000));
        }

        #[test]
        fn test_ticks_to_nanos() {
            let tick = HtfTick::new(0, 1_000_000); // 1MHz

            // 1000 ticks at 1MHz = 1ms = 1,000,000ns
            assert_eq!(tick.ticks_to_nanos(1000), Some(1_000_000));

            // 1,000,000 ticks at 1MHz = 1s = 1,000,000,000ns
            assert_eq!(tick.ticks_to_nanos(1_000_000), Some(1_000_000_000));
        }

        #[test]
        fn test_ticks_to_nanos_zero_rate() {
            let tick = HtfTick::new(0, 0);
            assert_eq!(tick.ticks_to_nanos(1000), None);
        }

        #[test]
        fn test_display() {
            let tick = HtfTick::new(1000, 1_000_000);
            assert_eq!(tick.to_string(), "1000@1000000Hz");
        }

        #[test]
        fn test_serde_roundtrip() {
            let tick = HtfTick::new(12345, 1_000_000);
            let json = serde_json::to_string(&tick).unwrap();
            let deserialized: HtfTick = serde_json::from_str(&json).unwrap();
            assert_eq!(tick, deserialized);
        }

        #[test]
        fn test_equality_and_hash() {
            use std::collections::HashSet;

            let t1 = HtfTick::new(100, 1_000_000);
            let t2 = HtfTick::new(100, 1_000_000);
            let t3 = HtfTick::new(100, 2_000_000); // Different rate

            assert_eq!(t1, t2);
            assert_ne!(t1, t3);

            let mut set = HashSet::new();
            set.insert(t1);
            set.insert(t2);
            set.insert(t3);
            assert_eq!(set.len(), 2);
        }
    }

    // =========================================================================
    // TimeEnvelopeRef Tests
    // =========================================================================

    mod time_envelope_ref {
        use super::*;

        #[test]
        fn test_new_and_accessors() {
            let hash = [0x42u8; 32];
            let envelope_ref = TimeEnvelopeRef::new(hash);
            assert_eq!(envelope_ref.as_bytes(), &hash);
        }

        #[test]
        fn test_from_slice() {
            let bytes = [0x42u8; 32];
            let envelope_ref = TimeEnvelopeRef::from_slice(&bytes).unwrap();
            assert_eq!(envelope_ref.as_bytes(), &bytes);

            // Wrong size
            let short = [0u8; 16];
            assert!(TimeEnvelopeRef::from_slice(&short).is_none());

            let long = [0u8; 64];
            assert!(TimeEnvelopeRef::from_slice(&long).is_none());
        }

        #[test]
        fn test_zero() {
            let zero = TimeEnvelopeRef::zero();
            assert!(zero.is_zero());
            assert_eq!(zero.as_bytes(), &[0u8; 32]);

            let non_zero = TimeEnvelopeRef::new([0x01; 32]);
            assert!(!non_zero.is_zero());
        }

        #[test]
        fn test_from_into_array() {
            let hash = [0x42u8; 32];
            let envelope_ref: TimeEnvelopeRef = hash.into();
            let back: [u8; 32] = envelope_ref.into();
            assert_eq!(hash, back);
        }

        #[test]
        fn test_as_ref() {
            let hash = [0x42u8; 32];
            let envelope_ref = TimeEnvelopeRef::new(hash);
            let reference: &[u8; 32] = envelope_ref.as_ref();
            assert_eq!(reference, &hash);
        }

        #[test]
        fn test_display() {
            let hash = [0x42u8; 32];
            let envelope_ref = TimeEnvelopeRef::new(hash);
            let display = envelope_ref.to_string();
            assert!(display.starts_with("htf:"));
            assert!(display.ends_with("..."));
        }

        #[test]
        fn test_equality_and_comparison() {
            let ref1 = TimeEnvelopeRef::new([0x42u8; 32]);
            let ref2 = TimeEnvelopeRef::new([0x42u8; 32]);
            let ref3 = TimeEnvelopeRef::new([0x43u8; 32]);

            assert_eq!(ref1, ref2);
            assert_ne!(ref1, ref3);
        }

        #[test]
        fn test_serde_roundtrip() {
            let hash = [0x42u8; 32];
            let envelope_ref = TimeEnvelopeRef::new(hash);
            let json = serde_json::to_string(&envelope_ref).unwrap();
            let deserialized: TimeEnvelopeRef = serde_json::from_str(&json).unwrap();
            assert_eq!(envelope_ref, deserialized);
        }

        #[test]
        fn test_hash_set() {
            use std::collections::HashSet;

            let ref1 = TimeEnvelopeRef::new([0x42u8; 32]);
            let ref2 = TimeEnvelopeRef::new([0x42u8; 32]);
            let ref3 = TimeEnvelopeRef::new([0x43u8; 32]);

            let mut set = HashSet::new();
            set.insert(ref1);
            set.insert(ref2);
            set.insert(ref3);

            assert_eq!(set.len(), 2);
        }
    }

    // =========================================================================
    // MonotonicSource Tests
    // =========================================================================

    mod monotonic_source {
        use super::*;

        #[test]
        fn test_display() {
            assert_eq!(
                MonotonicSource::ClockMonotonicRaw.to_string(),
                "CLOCK_MONOTONIC_RAW"
            );
            assert_eq!(
                MonotonicSource::ClockMonotonic.to_string(),
                "CLOCK_MONOTONIC"
            );
            assert_eq!(MonotonicSource::Other.to_string(), "OTHER");
        }

        #[test]
        fn test_serde_roundtrip() {
            let sources = [
                MonotonicSource::ClockMonotonicRaw,
                MonotonicSource::ClockMonotonic,
                MonotonicSource::Other,
            ];

            for source in sources {
                let json = serde_json::to_string(&source).unwrap();
                let deserialized: MonotonicSource = serde_json::from_str(&json).unwrap();
                assert_eq!(source, deserialized);
            }
        }

        #[test]
        fn test_serde_format() {
            assert_eq!(
                serde_json::to_string(&MonotonicSource::ClockMonotonicRaw).unwrap(),
                "\"CLOCK_MONOTONIC_RAW\""
            );
            assert_eq!(
                serde_json::to_string(&MonotonicSource::ClockMonotonic).unwrap(),
                "\"CLOCK_MONOTONIC\""
            );
            assert_eq!(
                serde_json::to_string(&MonotonicSource::Other).unwrap(),
                "\"OTHER\""
            );
        }
    }

    // =========================================================================
    // WallTimeSource Tests
    // =========================================================================

    mod wall_time_source {
        use super::*;

        #[test]
        fn test_display() {
            assert_eq!(WallTimeSource::None.to_string(), "none");
            assert_eq!(WallTimeSource::BestEffortNtp.to_string(), "best-effort-ntp");
            assert_eq!(
                WallTimeSource::AuthenticatedNts.to_string(),
                "authenticated-nts"
            );
            assert_eq!(WallTimeSource::Roughtime.to_string(), "roughtime");
            assert_eq!(WallTimeSource::CloudBounded.to_string(), "cloud-bounded");
            assert_eq!(
                WallTimeSource::ManualOperator.to_string(),
                "manual-operator"
            );
        }

        #[test]
        fn test_serde_roundtrip() {
            let sources = [
                WallTimeSource::None,
                WallTimeSource::BestEffortNtp,
                WallTimeSource::AuthenticatedNts,
                WallTimeSource::Roughtime,
                WallTimeSource::CloudBounded,
                WallTimeSource::ManualOperator,
            ];

            for source in sources {
                let json = serde_json::to_string(&source).unwrap();
                let deserialized: WallTimeSource = serde_json::from_str(&json).unwrap();
                assert_eq!(source, deserialized);
            }
        }

        #[test]
        fn test_serde_format() {
            assert_eq!(
                serde_json::to_string(&WallTimeSource::None).unwrap(),
                "\"NONE\""
            );
            assert_eq!(
                serde_json::to_string(&WallTimeSource::BestEffortNtp).unwrap(),
                "\"BEST_EFFORT_NTP\""
            );
            assert_eq!(
                serde_json::to_string(&WallTimeSource::AuthenticatedNts).unwrap(),
                "\"AUTHENTICATED_NTS\""
            );
        }
    }

    // =========================================================================
    // BoundedWallInterval Tests
    // =========================================================================

    mod bounded_wall_interval {
        use super::*;

        #[test]
        fn test_new_valid() {
            let wall = BoundedWallInterval::new(100, 200, WallTimeSource::None, "95%").unwrap();
            assert_eq!(wall.t_min_utc_ns(), 100);
            assert_eq!(wall.t_max_utc_ns(), 200);
            assert_eq!(wall.source(), WallTimeSource::None);
            assert_eq!(wall.confidence(), "95%");
        }

        #[test]
        fn test_new_invalid_interval() {
            let result = BoundedWallInterval::new(200, 100, WallTimeSource::None, "test");
            assert!(matches!(
                result,
                Err(BoundedWallIntervalError::InvalidInterval {
                    t_min: 200,
                    t_max: 100
                })
            ));
        }

        #[test]
        fn test_new_confidence_too_long() {
            let long_confidence = "x".repeat(MAX_STRING_LENGTH + 1);
            let result = BoundedWallInterval::new(100, 200, WallTimeSource::None, long_confidence);
            assert!(matches!(
                result,
                Err(BoundedWallIntervalError::ConfidenceTooLong { .. })
            ));
        }

        #[test]
        fn test_point() {
            let wall = BoundedWallInterval::point(150, WallTimeSource::None, "100%").unwrap();
            assert_eq!(wall.t_min_utc_ns(), 150);
            assert_eq!(wall.t_max_utc_ns(), 150);
            assert_eq!(wall.uncertainty_ns(), 0);
        }

        #[test]
        fn test_uncertainty_ns() {
            let wall = BoundedWallInterval::new(100, 200, WallTimeSource::None, "test").unwrap();
            assert_eq!(wall.uncertainty_ns(), 100);
        }

        #[test]
        fn test_contains() {
            let wall = BoundedWallInterval::new(100, 200, WallTimeSource::None, "test").unwrap();

            assert!(wall.contains(100)); // Min boundary
            assert!(wall.contains(150)); // Middle
            assert!(wall.contains(200)); // Max boundary

            assert!(!wall.contains(99)); // Below min
            assert!(!wall.contains(201)); // Above max
        }

        #[test]
        fn test_overlaps() {
            let wall1 = BoundedWallInterval::new(100, 200, WallTimeSource::None, "test").unwrap();
            let wall2 = BoundedWallInterval::new(150, 250, WallTimeSource::None, "test").unwrap();
            let wall3 = BoundedWallInterval::new(201, 300, WallTimeSource::None, "test").unwrap();
            let wall4 = BoundedWallInterval::new(0, 99, WallTimeSource::None, "test").unwrap();

            assert!(wall1.overlaps(&wall2)); // Overlapping
            assert!(!wall1.overlaps(&wall3)); // wall3 starts after wall1 ends
            assert!(!wall1.overlaps(&wall4)); // wall4 ends before wall1 starts

            // Edge case: adjacent intervals
            let wall5 = BoundedWallInterval::new(200, 300, WallTimeSource::None, "test").unwrap();
            assert!(wall1.overlaps(&wall5)); // Touching at boundary
        }

        #[test]
        fn test_midpoint() {
            let wall = BoundedWallInterval::new(100, 200, WallTimeSource::None, "test").unwrap();
            assert_eq!(wall.midpoint_ns(), 150);

            let asymmetric =
                BoundedWallInterval::new(100, 201, WallTimeSource::None, "test").unwrap();
            assert_eq!(asymmetric.midpoint_ns(), 150); // Integer division
        }

        #[test]
        fn test_display() {
            let wall = BoundedWallInterval::new(
                1_000_000_000, // 1s in ns
                1_100_000_000, // 1.1s in ns (100ms uncertainty)
                WallTimeSource::BestEffortNtp,
                "95%",
            )
            .unwrap();

            let display = wall.to_string();
            assert!(display.contains("1000000000"));
            assert!(display.contains("1100000000"));
            assert!(display.contains("100ms")); // Uncertainty
            assert!(display.contains("best-effort-ntp"));
            assert!(display.contains("95%"));
        }

        #[test]
        fn test_serde_roundtrip() {
            let wall = BoundedWallInterval::new(
                1_704_067_200_000_000_000,
                1_704_067_200_100_000_000,
                WallTimeSource::BestEffortNtp,
                "95%",
            )
            .unwrap();

            let json = serde_json::to_string(&wall).unwrap();
            let deserialized: BoundedWallInterval = serde_json::from_str(&json).unwrap();
            assert_eq!(wall, deserialized);
        }

        #[test]
        fn test_deserialize_rejects_invalid_interval() {
            let json = r#"{"t_min_utc_ns": 200, "t_max_utc_ns": 100, "source": "NONE", "confidence": "test"}"#;
            let result: Result<BoundedWallInterval, _> = serde_json::from_str(json);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("invalid interval"));
        }

        #[test]
        fn test_deserialize_rejects_oversized_confidence() {
            let long_confidence = "x".repeat(MAX_STRING_LENGTH + 1);
            let json = format!(
                r#"{{"t_min_utc_ns": 100, "t_max_utc_ns": 200, "source": "NONE", "confidence": "{long_confidence}"}}"#
            );
            let result: Result<BoundedWallInterval, _> = serde_json::from_str(&json);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("confidence exceeds maximum length"));
        }

        #[test]
        fn test_all_wall_time_sources() {
            let sources = [
                WallTimeSource::None,
                WallTimeSource::BestEffortNtp,
                WallTimeSource::AuthenticatedNts,
                WallTimeSource::Roughtime,
                WallTimeSource::CloudBounded,
                WallTimeSource::ManualOperator,
            ];

            for source in sources {
                let wall = BoundedWallInterval::new(100, 200, source, "test").unwrap();
                assert_eq!(wall.source(), source);

                // Verify serde roundtrip
                let json = serde_json::to_string(&wall).unwrap();
                let deserialized: BoundedWallInterval = serde_json::from_str(&json).unwrap();
                assert_eq!(wall.source(), deserialized.source());
            }
        }
    }
}
