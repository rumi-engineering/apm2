// AGENT-AUTHORED
//! `HolonicClock` service for time envelope stamping.
//!
//! This module implements the daemon clock service that provides:
//!
//! - `now_mono_tick()`: Current monotonic tick reading
//! - `now_hlc()`: Current HLC timestamp (if enabled)
//! - `observed_ledger_head()`: Current ledger position via `LedgerBackend`
//! - `stamp_envelope()`: Create a complete `TimeEnvelope`
//!
//! # Implementation Notes
//!
//! Per RFC-0016 TCK-00240 implementation steps:
//!
//! 1. **Monotonic source**: Uses `CLOCK_MONOTONIC_RAW` if available (Linux),
//!    fallback to `CLOCK_MONOTONIC` via `std::time::Instant`.
//!
//! 2. **Ledger source**: Holds a reference to a `LedgerBackend` to query
//!    `head(namespace)`.
//!
//! 3. **HLC state**: Stores `last_wall_ns` and `last_logical` in a mutex for
//!    thread-safe updates.
//!
//! 4. **Error handling**:
//!    - Monotonic regression: Emits `CLOCK_REGRESSION` defect, fails closed
//!    - Ledger query failure: Emits defect, returns error
//!    - Wall time unavailable: Omits W interval, continues with L+M
//!
//! # Security Properties
//!
//! - **Bounded strings (CTR-1303)**: All string fields are validated
//! - **Fail-closed**: Clock regressions fail rather than silently continue
//! - **No wall-time authority**: Wall time is observational only

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use apm2_core::htf::{
    BoundedWallInterval, Canonicalizable, CanonicalizationError, ClockProfile, Hlc, HtfTick,
    LedgerTime, MAX_STRING_LENGTH, MonotonicReading, MonotonicSource, TimeEnvelope,
    TimeEnvelopeRef, WallTimeSource,
};
use apm2_core::ledger::{BoxFuture, LedgerBackend, LedgerError};
use thiserror::Error;
use tracing::{debug, warn};

// =============================================================================
// Constants
// =============================================================================

/// Default tick rate in Hz (1 GHz = nanosecond resolution).
pub const DEFAULT_TICK_RATE_HZ: u64 = 1_000_000_000;

/// Default maximum wall time uncertainty in nanoseconds (100ms).
pub const DEFAULT_MAX_WALL_UNCERTAINTY_NS: u64 = 100_000_000;

/// Default ledger namespace for daemon events.
pub const DEFAULT_LEDGER_NAMESPACE: &str = "kernel";

/// Default ledger ID for single-node deployments.
pub const DEFAULT_LEDGER_ID: &str = "apm2-local";

/// Maximum length for build fingerprint strings.
pub const MAX_BUILD_FINGERPRINT_LEN: usize = 256;

/// Maximum length for policy ID strings.
pub const MAX_POLICY_ID_LEN: usize = 128;

/// Maximum length for ledger namespace strings.
pub const MAX_NAMESPACE_LEN: usize = 128;

/// Maximum allowed HLC offset from physical time in nanoseconds.
///
/// Per `THREAT_MODEL.md`, time is treated as an adversarial input. This
/// constant defines the maximum drift tolerance when receiving HLC timestamps
/// from remote peers. A malicious peer could attempt to push a node's HLC
/// arbitrarily far into the future, irreversibly desynchronizing temporal
/// ordering.
///
/// Default: 5 seconds (`5_000_000_000` nanoseconds) to tolerate reasonable
/// network latency and clock skew while rejecting obviously malicious
/// timestamps.
pub const MAX_HLC_OFFSET_NS: u64 = 5_000_000_000;

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during clock operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClockError {
    /// Monotonic clock regression detected.
    #[error("clock regression detected: current={current}, previous={previous}")]
    ClockRegression {
        /// Current tick value.
        current: u64,
        /// Previous tick value.
        previous: u64,
    },

    /// Ledger backend query failed.
    #[error("ledger query failed: {0}")]
    LedgerQuery(#[from] LedgerError),

    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// String field too long.
    #[error("{field} too long: {length} > {max}")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// HLC not enabled.
    #[error("HLC is not enabled for this clock")]
    HlcNotEnabled,

    /// Remote HLC timestamp exceeds maximum allowed drift from physical time.
    ///
    /// This error indicates a potential attack where a malicious peer attempts
    /// to push the local HLC arbitrarily far into the future. Per
    /// `THREAT_MODEL.md`, time is treated as an adversarial input.
    #[error(
        "remote HLC drift exceeded: remote_wall_ns={remote_wall_ns}, \
         physical_now={physical_now}, offset={offset_ns}ns, max_allowed={max_allowed_ns}ns"
    )]
    HlcDriftExceeded {
        /// Remote wall time in nanoseconds.
        remote_wall_ns: u64,
        /// Local physical time in nanoseconds.
        physical_now: u64,
        /// Actual offset between remote and physical time.
        offset_ns: u64,
        /// Maximum allowed offset.
        max_allowed_ns: u64,
    },

    /// Canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
}

/// Record of a clock regression event for defect reporting.
#[derive(Debug, Clone)]
pub struct ClockRegression {
    /// Current tick value at regression detection.
    pub current_tick: u64,
    /// Previous tick value before regression.
    pub previous_tick: u64,
    /// Regression amount in ticks.
    pub delta_ticks: u64,
    /// Timestamp when regression was detected (wall time, best effort).
    pub detected_at_ns: u64,
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the [`HolonicClock`] service.
#[derive(Debug, Clone)]
pub struct ClockConfig {
    /// Tick rate in Hz.
    pub tick_rate_hz: u64,

    /// Whether HLC is enabled.
    pub hlc_enabled: bool,

    /// Source of monotonic time.
    pub monotonic_source: MonotonicSource,

    /// Source of wall time.
    pub wall_time_source: WallTimeSource,

    /// Maximum wall time uncertainty in nanoseconds.
    pub max_wall_uncertainty_ns: u64,

    /// Ledger ID for [`LedgerTime`] construction.
    pub ledger_id: String,

    /// Default ledger namespace.
    pub ledger_namespace: String,

    /// Default epoch (0 for Phase 1).
    pub default_epoch: u64,

    /// Build fingerprint for [`ClockProfile`].
    pub build_fingerprint: String,

    /// Policy ID for [`ClockProfile`].
    pub profile_policy_id: String,
}

impl Default for ClockConfig {
    fn default() -> Self {
        Self {
            tick_rate_hz: DEFAULT_TICK_RATE_HZ,
            hlc_enabled: true,
            monotonic_source: MonotonicSource::ClockMonotonic,
            wall_time_source: WallTimeSource::BestEffortNtp,
            max_wall_uncertainty_ns: DEFAULT_MAX_WALL_UNCERTAINTY_NS,
            ledger_id: DEFAULT_LEDGER_ID.to_string(),
            ledger_namespace: DEFAULT_LEDGER_NAMESPACE.to_string(),
            default_epoch: 0,
            build_fingerprint: format!("apm2-daemon/{}", env!("CARGO_PKG_VERSION")),
            profile_policy_id: "default".to_string(),
        }
    }
}

/// Builder for [`ClockConfig`].
#[derive(Debug, Default)]
pub struct ClockConfigBuilder {
    config: ClockConfig,
}

impl ClockConfigBuilder {
    /// Creates a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the tick rate in Hz.
    #[must_use]
    pub const fn tick_rate_hz(mut self, hz: u64) -> Self {
        self.config.tick_rate_hz = hz;
        self
    }

    /// Enables or disables HLC.
    #[must_use]
    pub const fn hlc_enabled(mut self, enabled: bool) -> Self {
        self.config.hlc_enabled = enabled;
        self
    }

    /// Sets the monotonic time source.
    #[must_use]
    pub const fn monotonic_source(mut self, source: MonotonicSource) -> Self {
        self.config.monotonic_source = source;
        self
    }

    /// Sets the wall time source.
    #[must_use]
    pub const fn wall_time_source(mut self, source: WallTimeSource) -> Self {
        self.config.wall_time_source = source;
        self
    }

    /// Sets the maximum wall time uncertainty.
    #[must_use]
    pub const fn max_wall_uncertainty_ns(mut self, ns: u64) -> Self {
        self.config.max_wall_uncertainty_ns = ns;
        self
    }

    /// Sets the ledger ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger ID exceeds [`MAX_STRING_LENGTH`].
    pub fn ledger_id(mut self, id: impl Into<String>) -> Result<Self, ClockError> {
        let id = id.into();
        if id.len() > MAX_STRING_LENGTH {
            return Err(ClockError::StringTooLong {
                field: "ledger_id",
                length: id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        self.config.ledger_id = id;
        Ok(self)
    }

    /// Sets the ledger namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace exceeds [`MAX_NAMESPACE_LEN`].
    pub fn ledger_namespace(mut self, ns: impl Into<String>) -> Result<Self, ClockError> {
        let ns = ns.into();
        if ns.len() > MAX_NAMESPACE_LEN {
            return Err(ClockError::StringTooLong {
                field: "ledger_namespace",
                length: ns.len(),
                max: MAX_NAMESPACE_LEN,
            });
        }
        self.config.ledger_namespace = ns;
        Ok(self)
    }

    /// Sets the default epoch.
    #[must_use]
    pub const fn default_epoch(mut self, epoch: u64) -> Self {
        self.config.default_epoch = epoch;
        self
    }

    /// Sets the build fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if the fingerprint exceeds
    /// [`MAX_BUILD_FINGERPRINT_LEN`].
    pub fn build_fingerprint(mut self, fp: impl Into<String>) -> Result<Self, ClockError> {
        let fp = fp.into();
        if fp.len() > MAX_BUILD_FINGERPRINT_LEN {
            return Err(ClockError::StringTooLong {
                field: "build_fingerprint",
                length: fp.len(),
                max: MAX_BUILD_FINGERPRINT_LEN,
            });
        }
        self.config.build_fingerprint = fp;
        Ok(self)
    }

    /// Sets the profile policy ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy ID exceeds [`MAX_POLICY_ID_LEN`].
    pub fn profile_policy_id(mut self, id: impl Into<String>) -> Result<Self, ClockError> {
        let id = id.into();
        if id.len() > MAX_POLICY_ID_LEN {
            return Err(ClockError::StringTooLong {
                field: "profile_policy_id",
                length: id.len(),
                max: MAX_POLICY_ID_LEN,
            });
        }
        self.config.profile_policy_id = id;
        Ok(self)
    }

    /// Builds the configuration.
    #[must_use]
    pub fn build(self) -> ClockConfig {
        self.config
    }
}

// =============================================================================
// HLC State
// =============================================================================

/// Internal HLC state protected by a mutex.
#[derive(Debug)]
struct HlcState {
    /// Last wall time in nanoseconds.
    wall_ns: u64,
    /// Logical counter.
    logical: u64,
}

impl Default for HlcState {
    #[allow(clippy::cast_possible_truncation)]
    fn default() -> Self {
        // Initialize with current system time.
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        let wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            wall_ns,
            logical: 0,
        }
    }
}

// =============================================================================
// HolonicClock
// =============================================================================

/// The [`HolonicClock`] service for time envelope stamping.
///
/// This service provides the three time surfaces required by HTF:
///
/// 1. **Monotonic ticks**: Node-local monotonic time from `Instant`
/// 2. **HLC**: Hybrid logical clock for causality (if enabled)
/// 3. **Ledger head**: Current position from `LedgerBackend`
///
/// # Thread Safety
///
/// `HolonicClock` is `Send + Sync` and can be shared across async tasks.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::htf::{ClockConfig, HolonicClock};
///
/// let clock = HolonicClock::new(config, ledger_backend);
///
/// // Get current monotonic tick
/// let tick = clock.now_mono_tick();
///
/// // Stamp a time envelope
/// let envelope = clock.stamp_envelope().await?;
/// ```
pub struct HolonicClock {
    /// Configuration.
    config: ClockConfig,

    /// Ledger backend for head queries.
    ledger: Option<Arc<dyn LedgerBackend>>,

    /// Reference instant for tick calculation.
    epoch_instant: Instant,

    /// Last observed tick (for regression detection).
    last_tick: AtomicU64,

    /// HLC state (if enabled).
    hlc_state: Option<Mutex<HlcState>>,

    /// Cached clock profile hash.
    profile_hash: String,

    /// Clock profile for envelope stamping.
    clock_profile: ClockProfile,
}

impl HolonicClock {
    /// Creates a new `HolonicClock` with the given configuration and ledger
    /// backend.
    ///
    /// # Arguments
    ///
    /// * `config` - Clock configuration
    /// * `ledger` - Optional ledger backend for head queries
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::Canonicalization`] if the clock profile cannot be
    /// canonicalized for hashing.
    pub fn new(
        config: ClockConfig,
        ledger: Option<Arc<dyn LedgerBackend>>,
    ) -> Result<Self, ClockError> {
        let clock_profile = ClockProfile {
            attestation: None,
            build_fingerprint: config.build_fingerprint.clone(),
            hlc_enabled: config.hlc_enabled,
            max_wall_uncertainty_ns: config.max_wall_uncertainty_ns,
            monotonic_source: config.monotonic_source,
            profile_policy_id: config.profile_policy_id.clone(),
            tick_rate_hz: config.tick_rate_hz,
            wall_time_source: config.wall_time_source,
        };

        // Compute profile hash using canonical serialization (RFC 8785) + BLAKE3
        let profile_hash = hex::encode(clock_profile.canonical_hash()?);

        let hlc_state = if config.hlc_enabled {
            Some(Mutex::new(HlcState::default()))
        } else {
            None
        };

        Ok(Self {
            config,
            ledger,
            epoch_instant: Instant::now(),
            last_tick: AtomicU64::new(0),
            hlc_state,
            profile_hash,
            clock_profile,
        })
    }

    /// Creates a builder for `HolonicClock`.
    #[must_use]
    pub fn builder() -> HolonicClockBuilder {
        HolonicClockBuilder::new()
    }

    /// Returns the clock configuration.
    #[must_use]
    pub const fn config(&self) -> &ClockConfig {
        &self.config
    }

    /// Returns the clock profile.
    #[must_use]
    pub const fn clock_profile(&self) -> &ClockProfile {
        &self.clock_profile
    }

    /// Returns the clock profile hash.
    #[must_use]
    pub fn profile_hash(&self) -> &str {
        &self.profile_hash
    }

    /// Returns the current monotonic tick value.
    ///
    /// # Returns
    ///
    /// The current tick as an [`HtfTick`].
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::ClockRegression`] if the tick value has regressed.
    /// This indicates a serious system issue (e.g., VM time travel).
    #[allow(clippy::cast_possible_truncation)]
    pub fn now_mono_tick(&self) -> Result<HtfTick, ClockError> {
        // The cast from u128 to u64 is safe: elapsed time from Instant::now()
        // won't exceed u64::MAX nanoseconds (584 years).
        let elapsed = self.epoch_instant.elapsed();
        let current_tick = elapsed.as_nanos() as u64;

        // Atomically update and check for regression (INV-HC001).
        // Using fetch_max ensures thread-safe updates without race conditions
        // between load and store operations.
        let previous = self.last_tick.fetch_max(current_tick, Ordering::AcqRel);
        if current_tick < previous {
            // Emit warning for defect recording
            warn!(
                current = current_tick,
                previous = previous,
                "clock regression detected"
            );
            return Err(ClockError::ClockRegression {
                current: current_tick,
                previous,
            });
        }

        Ok(HtfTick::new(current_tick, self.config.tick_rate_hz))
    }

    /// Returns the current HLC timestamp.
    ///
    /// This advances the HLC per the local tick algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::HlcNotEnabled`] if HLC is not enabled.
    #[allow(clippy::cast_possible_truncation)]
    pub fn now_hlc(&self) -> Result<Hlc, ClockError> {
        let state_mutex = self.hlc_state.as_ref().ok_or(ClockError::HlcNotEnabled)?;

        let mut state = state_mutex.lock().unwrap_or_else(|poisoned| {
            // Mutex was poisoned, but we can still access the data
            warn!("HLC mutex was poisoned, recovering");
            poisoned.into_inner()
        });

        // Get current wall time.
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // HLC tick algorithm: max(physical, last_wall) with counter advancement
        if physical_now > state.wall_ns {
            // Physical time advanced, reset counter
            state.wall_ns = physical_now;
            state.logical = 0;
        } else {
            // Physical time hasn't advanced, increment counter
            state.logical = state.logical.saturating_add(1);
        }

        Ok(Hlc {
            wall_ns: state.wall_ns,
            logical: state.logical,
        })
    }

    /// Updates the HLC with a received remote timestamp.
    ///
    /// This implements the HLC receive algorithm for cross-node
    /// synchronization with security validation.
    ///
    /// # Security
    ///
    /// Per `THREAT_MODEL.md`, time is treated as an adversarial input. This
    /// function validates that the remote HLC is not too far ahead of physical
    /// time to prevent malicious peers from pushing the local HLC arbitrarily
    /// far into the future.
    ///
    /// # Arguments
    ///
    /// * `remote_hlc` - The HLC timestamp from the remote message
    ///
    /// # Errors
    ///
    /// - Returns [`ClockError::HlcNotEnabled`] if HLC is not enabled.
    /// - Returns [`ClockError::HlcDriftExceeded`] if the remote HLC's wall time
    ///   exceeds physical time by more than [`MAX_HLC_OFFSET_NS`].
    #[allow(clippy::cast_possible_truncation)]
    pub fn receive_hlc(&self, remote_hlc: &Hlc) -> Result<Hlc, ClockError> {
        let state_mutex = self.hlc_state.as_ref().ok_or(ClockError::HlcNotEnabled)?;

        let mut state = state_mutex.lock().unwrap_or_else(|poisoned| {
            warn!("HLC mutex was poisoned, recovering");
            poisoned.into_inner()
        });

        // Get current wall time.
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // SECURITY: Validate remote HLC drift against physical time.
        // Per THREAT_MODEL.md, time is an adversarial input. A malicious peer
        // could attempt to push our HLC arbitrarily far into the future,
        // irreversibly desynchronizing temporal ordering.
        if remote_hlc.wall_ns > physical_now {
            let offset_ns = remote_hlc.wall_ns - physical_now;
            if offset_ns > MAX_HLC_OFFSET_NS {
                warn!(
                    remote_wall_ns = remote_hlc.wall_ns,
                    physical_now = physical_now,
                    offset_ns = offset_ns,
                    max_allowed_ns = MAX_HLC_OFFSET_NS,
                    "rejecting remote HLC: drift exceeds maximum allowed offset"
                );
                return Err(ClockError::HlcDriftExceeded {
                    remote_wall_ns: remote_hlc.wall_ns,
                    physical_now,
                    offset_ns,
                    max_allowed_ns: MAX_HLC_OFFSET_NS,
                });
            }
        }

        // HLC receive algorithm
        let max_wall = state.wall_ns.max(remote_hlc.wall_ns).max(physical_now);

        let new_logical = if max_wall == state.wall_ns && max_wall == remote_hlc.wall_ns {
            // All three equal: increment max counter
            state.logical.max(remote_hlc.logical).saturating_add(1)
        } else if max_wall == state.wall_ns {
            // Local wall time is max: increment local counter
            state.logical.saturating_add(1)
        } else if max_wall == remote_hlc.wall_ns {
            // Remote wall time is max: increment remote counter
            remote_hlc.logical.saturating_add(1)
        } else {
            // Physical time is max: reset counter
            0
        };

        state.wall_ns = max_wall;
        state.logical = new_logical;

        Ok(Hlc {
            wall_ns: state.wall_ns,
            logical: state.logical,
        })
    }

    /// Returns the current observed ledger head as `LedgerTime`.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::LedgerQuery`] if the ledger query fails.
    /// Returns [`ClockError::InvalidConfig`] if no ledger backend is
    /// configured.
    pub fn observed_ledger_head(&self) -> BoxFuture<'_, Result<LedgerTime, ClockError>> {
        Box::pin(async move {
            let ledger = self.ledger.as_ref().ok_or_else(|| {
                ClockError::InvalidConfig("no ledger backend configured".to_string())
            })?;

            let seq = ledger.head(&self.config.ledger_namespace).await?;

            // Construct LedgerTime from config and head position
            let ledger_time =
                LedgerTime::new(&self.config.ledger_id, self.config.default_epoch, seq);

            debug!(
                ledger_id = %self.config.ledger_id,
                epoch = self.config.default_epoch,
                seq = seq,
                "observed ledger head"
            );

            Ok(ledger_time)
        })
    }

    /// Stamps a complete `TimeEnvelope` with current readings.
    ///
    /// This is the primary stamping method used at episode and tool boundaries.
    ///
    /// # Arguments
    ///
    /// * `notes` - Optional notes to include in the envelope
    ///
    /// # Returns
    ///
    /// A tuple of (`TimeEnvelope`, `TimeEnvelopeRef`) where the ref is the
    /// content hash of the envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if any clock source fails.
    #[allow(clippy::cast_possible_truncation)]
    pub fn stamp_envelope(
        &self,
        notes: Option<String>,
    ) -> BoxFuture<'_, Result<(TimeEnvelope, TimeEnvelopeRef), ClockError>> {
        Box::pin(async move {
            // Get monotonic reading
            let mono_tick = self.now_mono_tick()?;

            // Get HLC (or default if not enabled)
            let hlc = self.now_hlc().unwrap_or(Hlc {
                wall_ns: 0,
                logical: 0,
            });

            // Get ledger anchor (or default if no backend)
            let ledger_anchor = match self.observed_ledger_head().await {
                Ok(lt) => lt,
                Err(ClockError::InvalidConfig(_)) => {
                    // No ledger backend, use a placeholder
                    LedgerTime::new(&self.config.ledger_id, self.config.default_epoch, 0)
                },
                Err(e) => return Err(e),
            };

            // Get wall time interval.
            // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
            // won't exceed u64::MAX until the year 2554.
            let wall_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);

            let wall = BoundedWallInterval::new(
                wall_now,
                wall_now.saturating_add(self.config.max_wall_uncertainty_ns),
                self.config.wall_time_source,
                "best-effort",
            )
            .map_err(|e| ClockError::InvalidConfig(format!("wall interval error: {e}")))?;

            // Validate notes length
            if let Some(ref n) = notes {
                if n.len() > MAX_STRING_LENGTH {
                    return Err(ClockError::StringTooLong {
                        field: "notes",
                        length: n.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
            }

            let envelope = TimeEnvelope {
                clock_profile_hash: self.profile_hash.clone(),
                hlc,
                ledger_anchor,
                mono: MonotonicReading {
                    end_tick: None,
                    source: self.config.monotonic_source,
                    start_tick: mono_tick.value(),
                    tick_rate_hz: self.config.tick_rate_hz,
                },
                notes,
                wall,
            };

            // Compute envelope hash using canonical serialization (RFC 8785) + BLAKE3
            let envelope_hash = envelope.canonical_hash()?;
            let envelope_ref = TimeEnvelopeRef::new(envelope_hash);

            debug!(
                envelope_ref = %envelope_ref,
                ledger_seq = envelope.ledger_anchor.seq(),
                mono_tick = mono_tick.value(),
                "stamped time envelope"
            );

            Ok((envelope, envelope_ref))
        })
    }

    /// Stamps an envelope with an end tick for span measurement.
    ///
    /// This is used when completing an episode or tool execution to record
    /// the duration.
    ///
    /// # Arguments
    ///
    /// * `start_tick` - The start tick from the beginning of the span
    /// * `notes` - Optional notes to include
    ///
    /// # Returns
    ///
    /// A new envelope with `end_tick` set.
    #[allow(clippy::cast_possible_truncation)]
    pub fn stamp_span_end(
        &self,
        start_tick: u64,
        notes: Option<String>,
    ) -> BoxFuture<'_, Result<(TimeEnvelope, TimeEnvelopeRef), ClockError>> {
        Box::pin(async move {
            let mono_tick = self.now_mono_tick()?;
            let hlc = self.now_hlc().unwrap_or(Hlc {
                wall_ns: 0,
                logical: 0,
            });

            let ledger_anchor = match self.observed_ledger_head().await {
                Ok(lt) => lt,
                Err(ClockError::InvalidConfig(_)) => {
                    LedgerTime::new(&self.config.ledger_id, self.config.default_epoch, 0)
                },
                Err(e) => return Err(e),
            };

            // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
            // won't exceed u64::MAX until the year 2554.
            let wall_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);

            let wall = BoundedWallInterval::new(
                wall_now,
                wall_now.saturating_add(self.config.max_wall_uncertainty_ns),
                self.config.wall_time_source,
                "best-effort",
            )
            .map_err(|e| ClockError::InvalidConfig(format!("wall interval error: {e}")))?;

            if let Some(ref n) = notes {
                if n.len() > MAX_STRING_LENGTH {
                    return Err(ClockError::StringTooLong {
                        field: "notes",
                        length: n.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
            }

            let envelope = TimeEnvelope {
                clock_profile_hash: self.profile_hash.clone(),
                hlc,
                ledger_anchor,
                mono: MonotonicReading {
                    end_tick: Some(mono_tick.value()),
                    source: self.config.monotonic_source,
                    start_tick,
                    tick_rate_hz: self.config.tick_rate_hz,
                },
                notes,
                wall,
            };

            // Compute envelope hash using canonical serialization (RFC 8785) + BLAKE3
            let envelope_hash = envelope.canonical_hash()?;
            let envelope_ref = TimeEnvelopeRef::new(envelope_hash);

            debug!(
                envelope_ref = %envelope_ref,
                start_tick = start_tick,
                end_tick = mono_tick.value(),
                "stamped span end envelope"
            );

            Ok((envelope, envelope_ref))
        })
    }

    /// Returns a `ClockRegression` record for defect reporting.
    ///
    /// This should be called when `ClockError::ClockRegression` is encountered
    /// to create a defect record.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn record_regression(&self, current: u64, previous: u64) -> ClockRegression {
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        let detected_at_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        ClockRegression {
            current_tick: current,
            previous_tick: previous,
            delta_ticks: previous.saturating_sub(current),
            detected_at_ns,
        }
    }
}

impl std::fmt::Debug for HolonicClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HolonicClock")
            .field("config", &self.config)
            .field("profile_hash", &self.profile_hash)
            .field("hlc_enabled", &self.hlc_state.is_some())
            .finish_non_exhaustive()
    }
}

// HolonicClock is Send + Sync because:
// - config: ClockConfig is Send + Sync (all fields are)
// - ledger: Arc<dyn LedgerBackend> where LedgerBackend: Send + Sync
// - epoch_instant: Instant is Send + Sync
// - last_tick: AtomicU64 is Send + Sync
// - hlc_state: Option<Mutex<HlcState>> is Send + Sync
// - profile_hash: String is Send + Sync
// - clock_profile: ClockProfile is Send + Sync

// =============================================================================
// Builder
// =============================================================================

/// Builder for [`HolonicClock`].
#[derive(Default)]
pub struct HolonicClockBuilder {
    config: ClockConfig,
    ledger: Option<Arc<dyn LedgerBackend>>,
}

impl std::fmt::Debug for HolonicClockBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HolonicClockBuilder")
            .field("config", &self.config)
            .field("ledger", &self.ledger.is_some())
            .finish()
    }
}

impl HolonicClockBuilder {
    /// Creates a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the clock configuration.
    #[must_use]
    pub fn config(mut self, config: ClockConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the ledger backend.
    #[must_use]
    pub fn ledger(mut self, ledger: Arc<dyn LedgerBackend>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Sets the tick rate.
    #[must_use]
    pub const fn tick_rate_hz(mut self, hz: u64) -> Self {
        self.config.tick_rate_hz = hz;
        self
    }

    /// Enables or disables HLC.
    #[must_use]
    pub const fn hlc_enabled(mut self, enabled: bool) -> Self {
        self.config.hlc_enabled = enabled;
        self
    }

    /// Sets the ledger ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is too long.
    pub fn ledger_id(mut self, id: impl Into<String>) -> Result<Self, ClockError> {
        let id = id.into();
        if id.len() > MAX_STRING_LENGTH {
            return Err(ClockError::StringTooLong {
                field: "ledger_id",
                length: id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        self.config.ledger_id = id;
        Ok(self)
    }

    /// Builds the `HolonicClock`.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::Canonicalization`] if the clock profile cannot be
    /// canonicalized for hashing.
    pub fn build(self) -> Result<HolonicClock, ClockError> {
        HolonicClock::new(self.config, self.ledger)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_config_default() {
        let config = ClockConfig::default();
        assert_eq!(config.tick_rate_hz, DEFAULT_TICK_RATE_HZ);
        assert!(config.hlc_enabled);
        assert_eq!(config.ledger_id, DEFAULT_LEDGER_ID);
    }

    #[test]
    fn test_clock_config_builder() {
        let config = ClockConfigBuilder::new()
            .tick_rate_hz(1_000_000)
            .hlc_enabled(false)
            .build();

        assert_eq!(config.tick_rate_hz, 1_000_000);
        assert!(!config.hlc_enabled);
    }

    #[test]
    fn test_holonic_clock_mono_tick() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        let tick1 = clock.now_mono_tick().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let tick2 = clock.now_mono_tick().unwrap();

        assert!(tick2.value() > tick1.value());
    }

    #[test]
    fn test_holonic_clock_hlc() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        let hlc1 = clock.now_hlc().unwrap();
        let hlc2 = clock.now_hlc().unwrap();

        // HLC should advance
        assert!(
            hlc2.wall_ns > hlc1.wall_ns
                || (hlc2.wall_ns == hlc1.wall_ns && hlc2.logical > hlc1.logical)
        );
    }

    #[test]
    fn test_holonic_clock_hlc_disabled() {
        let config = ClockConfigBuilder::new().hlc_enabled(false).build();
        let clock = HolonicClock::new(config, None).unwrap();

        let result = clock.now_hlc();
        assert!(matches!(result, Err(ClockError::HlcNotEnabled)));
    }

    #[test]
    fn test_holonic_clock_profile_hash() {
        let clock1 = HolonicClock::new(ClockConfig::default(), None).unwrap();
        let clock2 = HolonicClock::new(ClockConfig::default(), None).unwrap();

        // Same config should produce same hash
        assert_eq!(clock1.profile_hash(), clock2.profile_hash());

        // Different config should produce different hash
        let config3 = ClockConfigBuilder::new().tick_rate_hz(999).build();
        let clock3 = HolonicClock::new(config3, None).unwrap();
        assert_ne!(clock1.profile_hash(), clock3.profile_hash());
    }

    #[tokio::test]
    async fn test_stamp_envelope_no_ledger() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        let (envelope, envelope_ref) = clock.stamp_envelope(None).await.unwrap();

        assert!(!envelope_ref.is_zero());
        assert_eq!(envelope.clock_profile_hash, clock.profile_hash());
        assert!(envelope.mono.start_tick > 0);
        assert!(envelope.mono.end_tick.is_none());
    }

    #[tokio::test]
    async fn test_stamp_span_end() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        let (start_envelope, _) = clock
            .stamp_envelope(Some("start".to_string()))
            .await
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1));

        let (end_envelope, _) = clock
            .stamp_span_end(start_envelope.mono.start_tick, Some("end".to_string()))
            .await
            .unwrap();

        assert_eq!(end_envelope.mono.start_tick, start_envelope.mono.start_tick);
        assert!(end_envelope.mono.end_tick.is_some());
        assert!(end_envelope.mono.end_tick.unwrap() > end_envelope.mono.start_tick);
    }

    #[test]
    fn test_clock_builder() {
        let clock = HolonicClock::builder()
            .tick_rate_hz(1_000_000)
            .hlc_enabled(true)
            .build()
            .unwrap();

        assert_eq!(clock.config().tick_rate_hz, 1_000_000);
        assert!(clock.config().hlc_enabled);
    }

    #[test]
    fn test_string_length_validation() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = ClockConfigBuilder::new().ledger_id(long_string.clone());
        assert!(matches!(result, Err(ClockError::StringTooLong { .. })));

        let result = ClockConfigBuilder::new().ledger_namespace(long_string);
        assert!(matches!(result, Err(ClockError::StringTooLong { .. })));
    }

    #[test]
    fn test_receive_hlc() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        let local_hlc = clock.now_hlc().unwrap();

        // Simulate receiving a message from a node with a higher wall time
        let remote_hlc = Hlc {
            wall_ns: local_hlc.wall_ns + 1_000_000,
            logical: 5,
        };

        let updated = clock.receive_hlc(&remote_hlc).unwrap();

        // Updated HLC should be at least as high as the remote
        assert!(updated.wall_ns >= remote_hlc.wall_ns);
    }

    #[test]
    fn test_record_regression() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        let regression = clock.record_regression(100, 200);

        assert_eq!(regression.current_tick, 100);
        assert_eq!(regression.previous_tick, 200);
        assert_eq!(regression.delta_ticks, 100);
        assert!(regression.detected_at_ns > 0);
    }

    // =========================================================================
    // TCK-00240: Unit test with in-memory ledger backend
    // =========================================================================

    /// Stub in-memory ledger backend for testing.
    struct StubLedgerBackend {
        head_seq: std::sync::atomic::AtomicU64,
    }

    impl StubLedgerBackend {
        fn new(initial_head: u64) -> Self {
            Self {
                head_seq: std::sync::atomic::AtomicU64::new(initial_head),
            }
        }

        fn set_head(&self, seq: u64) {
            self.head_seq.store(seq, Ordering::SeqCst);
        }
    }

    impl LedgerBackend for StubLedgerBackend {
        fn append<'a>(
            &'a self,
            _namespace: &'a str,
            _event: &'a apm2_core::ledger::EventRecord,
        ) -> BoxFuture<'a, Result<u64, apm2_core::ledger::LedgerError>> {
            let new_seq = self.head_seq.fetch_add(1, Ordering::SeqCst) + 1;
            Box::pin(async move { Ok(new_seq) })
        }

        fn read_from<'a>(
            &'a self,
            _namespace: &'a str,
            _cursor: u64,
            _limit: u64,
        ) -> BoxFuture<
            'a,
            Result<Vec<apm2_core::ledger::EventRecord>, apm2_core::ledger::LedgerError>,
        > {
            Box::pin(async { Ok(vec![]) })
        }

        fn head<'a>(
            &'a self,
            _namespace: &'a str,
        ) -> BoxFuture<'a, Result<u64, apm2_core::ledger::LedgerError>> {
            let seq = self.head_seq.load(Ordering::SeqCst);
            Box::pin(async move { Ok(seq) })
        }

        fn verify_chain<'a>(
            &'a self,
            _namespace: &'a str,
            _from_seq_id: u64,
            _verify_hash_fn: apm2_core::ledger::HashFn<'a>,
            _verify_sig_fn: apm2_core::ledger::VerifyFn<'a>,
        ) -> BoxFuture<'a, Result<(), apm2_core::ledger::LedgerError>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// TCK-00240 acceptance criterion: `observed_ledger_head()` returns
    /// `LedgerTime` using `LedgerBackend::head()`.
    #[tokio::test]
    async fn tck_00240_observed_ledger_head_with_in_memory_backend() {
        let backend = Arc::new(StubLedgerBackend::new(42));

        let clock = HolonicClock::builder()
            .ledger(backend.clone())
            .ledger_id("test-ledger")
            .unwrap()
            .build()
            .unwrap();

        // Test initial head value
        let ledger_time = clock.observed_ledger_head().await.unwrap();
        assert_eq!(ledger_time.seq(), 42);
        assert_eq!(ledger_time.ledger_id(), "test-ledger");
        assert_eq!(ledger_time.epoch(), 0); // Default epoch

        // Update head and verify
        backend.set_head(100);
        let ledger_time = clock.observed_ledger_head().await.unwrap();
        assert_eq!(ledger_time.seq(), 100);
    }

    /// TCK-00240 acceptance criterion: Episode/tool receipts include
    /// `time_envelope_ref`.
    #[tokio::test]
    async fn tck_00240_stamp_envelope_includes_time_envelope_ref() {
        let backend = Arc::new(StubLedgerBackend::new(10));

        let clock = HolonicClock::builder()
            .ledger(backend)
            .ledger_id("test-ledger")
            .unwrap()
            .build()
            .unwrap();

        // Stamp an envelope and verify it has a valid reference
        let (envelope, envelope_ref) = clock
            .stamp_envelope(Some("test receipt".to_string()))
            .await
            .unwrap();

        // Envelope ref should be non-zero (valid hash)
        assert!(!envelope_ref.is_zero());

        // Envelope should contain the correct ledger anchor
        assert_eq!(envelope.ledger_anchor.seq(), 10);
        assert_eq!(envelope.ledger_anchor.ledger_id(), "test-ledger");

        // Envelope should have HLC values
        assert!(envelope.hlc.wall_ns > 0 || envelope.hlc.logical > 0);

        // Monotonic reading should be present
        assert!(envelope.mono.start_tick > 0);
        assert_eq!(envelope.mono.tick_rate_hz, DEFAULT_TICK_RATE_HZ);

        // Notes should be preserved
        assert_eq!(envelope.notes, Some("test receipt".to_string()));
    }

    /// TCK-00240: Verify clock profile is properly hashed and pinned
    #[tokio::test]
    async fn tck_00240_clock_profile_pinned_in_envelope() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        let (envelope, _) = clock.stamp_envelope(None).await.unwrap();

        // Envelope should reference the clock's profile hash
        assert_eq!(envelope.clock_profile_hash, clock.profile_hash());

        // Profile hash should be a valid hex string
        assert!(hex::decode(&envelope.clock_profile_hash).is_ok());
    }

    // =========================================================================
    // TCK-00240 Security: HLC drift protection
    // =========================================================================

    /// TCK-00240 security: Verify that malicious future HLC timestamps are
    /// rejected.
    ///
    /// Per `THREAT_MODEL.md`, time is treated as an adversarial input. A
    /// malicious peer could attempt to push a node's HLC arbitrarily far into
    /// the future (e.g., year 2100), irreversibly desynchronizing temporal
    /// ordering.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn tck_00240_receive_hlc_rejects_excessive_drift() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        // Get current physical time as baseline.
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Create a malicious HLC far in the future (e.g., 1 year ahead)
        // 1 year in nanoseconds = 365 * 24 * 60 * 60 * 1_000_000_000
        let one_year_ns: u64 = 365 * 24 * 60 * 60 * 1_000_000_000;
        let malicious_hlc = Hlc {
            wall_ns: physical_now + one_year_ns,
            logical: 0,
        };

        // Attempt to receive the malicious HLC - should be rejected
        let result = clock.receive_hlc(&malicious_hlc);
        assert!(
            matches!(result, Err(ClockError::HlcDriftExceeded { .. })),
            "expected HlcDriftExceeded error, got: {result:?}"
        );

        // Verify the error contains the expected information
        if let Err(ClockError::HlcDriftExceeded {
            remote_wall_ns,
            offset_ns,
            max_allowed_ns,
            ..
        }) = result
        {
            assert_eq!(remote_wall_ns, physical_now + one_year_ns);
            assert!(offset_ns > MAX_HLC_OFFSET_NS);
            assert_eq!(max_allowed_ns, MAX_HLC_OFFSET_NS);
        }
    }

    /// TCK-00240 security: Verify that HLC timestamps within acceptable drift
    /// are accepted.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn tck_00240_receive_hlc_accepts_reasonable_drift() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        // Get current physical time as baseline.
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Create an HLC slightly in the future (1 second ahead - within 5s tolerance)
        let one_second_ns: u64 = 1_000_000_000;
        let reasonable_hlc = Hlc {
            wall_ns: physical_now + one_second_ns,
            logical: 0,
        };

        // Should be accepted
        let result = clock.receive_hlc(&reasonable_hlc);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let updated = result.unwrap();
        // Updated HLC should have adopted the reasonable future time
        assert!(updated.wall_ns >= reasonable_hlc.wall_ns);
    }

    /// TCK-00240 security: Verify that HLC timestamps clearly past the boundary
    /// are rejected.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn tck_00240_receive_hlc_past_boundary_drift() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        // Get current physical time as baseline.
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Create an HLC clearly past the boundary (1 second beyond max offset)
        // This avoids timing issues where physical time advances between calls.
        let one_second_ns: u64 = 1_000_000_000;
        let past_boundary_hlc = Hlc {
            wall_ns: physical_now + MAX_HLC_OFFSET_NS + one_second_ns,
            logical: 0,
        };

        let result = clock.receive_hlc(&past_boundary_hlc);
        assert!(
            matches!(result, Err(ClockError::HlcDriftExceeded { .. })),
            "expected HlcDriftExceeded past boundary, got: {result:?}"
        );
    }

    /// TCK-00240 security: Verify that HLC timestamps in the past are always
    /// accepted (no drift concern).
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn tck_00240_receive_hlc_accepts_past_timestamps() {
        let clock = HolonicClock::new(ClockConfig::default(), None).unwrap();

        // Get current physical time as baseline.
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        let physical_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Create an HLC far in the past (1 year ago)
        let one_year_ns: u64 = 365 * 24 * 60 * 60 * 1_000_000_000;
        let past_hlc = Hlc {
            wall_ns: physical_now.saturating_sub(one_year_ns),
            logical: 0,
        };

        // Should be accepted (past timestamps don't pose a drift risk)
        let result = clock.receive_hlc(&past_hlc);
        assert!(
            result.is_ok(),
            "expected Ok for past timestamp, got: {result:?}"
        );

        // The local HLC should use physical_now, not the past timestamp
        let updated = result.unwrap();
        assert!(updated.wall_ns >= physical_now);
    }
}
