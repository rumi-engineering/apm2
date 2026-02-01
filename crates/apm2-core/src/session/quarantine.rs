//! Quarantine mechanism for sessions.
//!
//! This module implements the quarantine mechanism for sessions that exhibit
//! problematic behavior (excessive violations, entropy exceeded, etc.).
//!
//! # Design
//!
//! Quarantine is a protective mechanism that prevents a session from being
//! restarted for a configurable duration. This helps prevent:
//! - Runaway sessions that keep failing and consuming resources
//! - Sessions that repeatedly violate policies
//! - Sessions in a crash loop that might cause system instability
//!
//! # Triggers
//!
//! A session can be quarantined for:
//! - **Entropy exceeded**: Budget exhausted due to errors/violations
//! - **Excessive violations**: Too many policy violations in a time window
//! - **Crash loop**: Too many restarts in a short period
//! - **Non-restartable crash**: Crashes due to bugs (SIGSEGV, etc.)
//!
//! # Duration
//!
//! Quarantine duration uses exponential backoff based on how many times
//! the session has been quarantined. This prevents sessions from constantly
//! cycling through quarantine and retry.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::htf::HtfTick;

/// Configuration for quarantine behavior.
///
/// # Time Model (RFC-0016 HTF)
///
/// Quarantine uses tick-based durations for immunity to wall-clock
/// manipulation:
///
/// - `base_duration_ticks` / `max_duration_ticks` / `tick_rate_hz`:
///   Authoritative for quarantine duration calculations when present
/// - `base_duration` / `max_duration`: Retained for backwards compatibility
///
/// When tick-based fields are present, they are authoritative. Duration
/// calculations MUST use tick arithmetic, not wall time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineConfig {
    /// Base duration for the first quarantine.
    /// Retained for backwards compatibility; use tick-based fields when
    /// available.
    pub base_duration: Duration,

    /// Maximum quarantine duration.
    /// Retained for backwards compatibility; use tick-based fields when
    /// available.
    pub max_duration: Duration,

    /// Multiplier for exponential backoff on repeated quarantines.
    /// Duration = `base_duration` * (multiplier ^ `quarantine_count`).
    pub multiplier: f64,

    /// Threshold for policy violations to trigger quarantine.
    /// If a session accumulates this many violations, it is quarantined.
    pub violation_threshold: u64,

    /// Threshold for restart attempts before quarantine.
    /// If a session is restarted this many times without success, it is
    /// quarantined.
    pub restart_threshold: u32,

    /// Whether to quarantine on entropy exceeded.
    pub quarantine_on_entropy_exceeded: bool,

    /// Whether to quarantine on non-restartable crashes (SIGSEGV, etc.).
    pub quarantine_on_non_restartable: bool,

    /// HTF: Base duration in ticks for the first quarantine.
    /// When present, this is authoritative over `base_duration`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_duration_ticks: Option<u64>,

    /// HTF: Maximum duration in ticks.
    /// When present, this is authoritative over `max_duration`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_ticks: Option<u64>,

    /// HTF: Tick rate in Hz for tick-based durations.
    /// Required when using tick-based durations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_rate_hz: Option<u64>,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            base_duration: Duration::from_secs(300),  // 5 minutes
            max_duration: Duration::from_secs(86400), // 24 hours
            multiplier: 2.0,
            violation_threshold: 5,
            restart_threshold: 5,
            quarantine_on_entropy_exceeded: true,
            quarantine_on_non_restartable: true,
            base_duration_ticks: None,
            max_duration_ticks: None,
            tick_rate_hz: None,
        }
    }
}

impl QuarantineConfig {
    /// Creates a configuration with a custom base duration.
    #[must_use]
    pub const fn with_base_duration(base_duration: Duration) -> Self {
        Self {
            base_duration,
            max_duration: Duration::from_secs(86400),
            multiplier: 2.0,
            violation_threshold: 5,
            restart_threshold: 5,
            quarantine_on_entropy_exceeded: true,
            quarantine_on_non_restartable: true,
            base_duration_ticks: None,
            max_duration_ticks: None,
            tick_rate_hz: None,
        }
    }

    /// Creates a lenient configuration with longer thresholds.
    #[must_use]
    pub const fn lenient() -> Self {
        Self {
            base_duration: Duration::from_secs(60),
            max_duration: Duration::from_secs(3600),
            multiplier: 1.5,
            violation_threshold: 10,
            restart_threshold: 10,
            quarantine_on_entropy_exceeded: false,
            quarantine_on_non_restartable: true,
            base_duration_ticks: None,
            max_duration_ticks: None,
            tick_rate_hz: None,
        }
    }

    /// Creates a strict configuration with shorter thresholds.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            base_duration: Duration::from_secs(600),
            max_duration: Duration::from_secs(86400 * 7), // 1 week
            multiplier: 3.0,
            violation_threshold: 3,
            restart_threshold: 3,
            quarantine_on_entropy_exceeded: true,
            quarantine_on_non_restartable: true,
            base_duration_ticks: None,
            max_duration_ticks: None,
            tick_rate_hz: None,
        }
    }

    /// Creates a tick-based configuration (RFC-0016 HTF compliant).
    ///
    /// This is the preferred constructor for new code. Tick-based durations
    /// are authoritative for quarantine calculations, immune to wall-clock
    /// manipulation.
    ///
    /// # Arguments
    ///
    /// * `base_duration_ticks` - Base quarantine duration in ticks
    /// * `max_duration_ticks` - Maximum quarantine duration in ticks
    /// * `tick_rate_hz` - Tick rate in Hz (ticks per second)
    /// * `multiplier` - Exponential backoff multiplier
    #[must_use]
    pub const fn with_ticks(
        base_duration_ticks: u64,
        max_duration_ticks: u64,
        tick_rate_hz: u64,
        multiplier: f64,
    ) -> Self {
        // Calculate wall-clock equivalents for backwards compatibility
        // These are observational only; tick values are authoritative
        let base_secs = base_duration_ticks / tick_rate_hz;
        let max_secs = max_duration_ticks / tick_rate_hz;

        Self {
            base_duration: Duration::from_secs(base_secs),
            max_duration: Duration::from_secs(max_secs),
            multiplier,
            violation_threshold: 5,
            restart_threshold: 5,
            quarantine_on_entropy_exceeded: true,
            quarantine_on_non_restartable: true,
            base_duration_ticks: Some(base_duration_ticks),
            max_duration_ticks: Some(max_duration_ticks),
            tick_rate_hz: Some(tick_rate_hz),
        }
    }

    /// Returns true if this configuration uses tick-based timing.
    #[must_use]
    pub const fn is_tick_based(&self) -> bool {
        self.base_duration_ticks.is_some()
            && self.max_duration_ticks.is_some()
            && self.tick_rate_hz.is_some()
    }
}

/// Reason why a session was quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineReason {
    /// Session exceeded its entropy budget.
    EntropyExceeded {
        /// Total budget that was exceeded.
        budget: u64,
        /// Amount consumed when quarantine triggered.
        consumed: u64,
    },
    /// Session had too many policy violations.
    ExcessiveViolations {
        /// Number of violations that triggered quarantine.
        violation_count: u64,
        /// Threshold that was exceeded.
        threshold: u64,
    },
    /// Session was in a crash loop (too many restarts).
    CrashLoop {
        /// Number of restart attempts.
        restart_count: u32,
        /// Threshold that was exceeded.
        threshold: u32,
    },
    /// Session crashed with a non-restartable error (bug indicator).
    NonRestartableCrash {
        /// The signal that caused the crash.
        signal: i32,
        /// Human-readable signal name.
        signal_name: String,
    },
    /// Manual quarantine by operator.
    Manual {
        /// Reason provided by operator.
        reason: String,
    },
}

impl QuarantineReason {
    /// Returns a short code for this reason.
    #[must_use]
    pub const fn as_code(&self) -> &'static str {
        match self {
            Self::EntropyExceeded { .. } => "ENTROPY_EXCEEDED",
            Self::ExcessiveViolations { .. } => "EXCESSIVE_VIOLATIONS",
            Self::CrashLoop { .. } => "CRASH_LOOP",
            Self::NonRestartableCrash { .. } => "NON_RESTARTABLE_CRASH",
            Self::Manual { .. } => "MANUAL",
        }
    }
}

impl std::fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntropyExceeded { budget, consumed } => {
                write!(
                    f,
                    "entropy budget exceeded (consumed {consumed} of {budget})"
                )
            },
            Self::ExcessiveViolations {
                violation_count,
                threshold,
            } => {
                write!(
                    f,
                    "excessive policy violations ({violation_count} >= threshold {threshold})"
                )
            },
            Self::CrashLoop {
                restart_count,
                threshold,
            } => {
                write!(
                    f,
                    "crash loop detected ({restart_count} restarts >= threshold {threshold})"
                )
            },
            Self::NonRestartableCrash {
                signal,
                signal_name,
            } => {
                write!(f, "non-restartable crash (signal {signal} {signal_name})")
            },
            Self::Manual { reason } => {
                write!(f, "manual quarantine: {reason}")
            },
        }
    }
}

/// Manages quarantine decisions for sessions.
///
/// This component evaluates session state and determines whether a session
/// should be quarantined based on configured thresholds.
#[derive(Debug)]
pub struct QuarantineManager {
    /// Configuration for quarantine behavior.
    config: QuarantineConfig,
}

impl QuarantineManager {
    /// Creates a new quarantine manager with the given configuration.
    #[must_use]
    pub const fn new(config: QuarantineConfig) -> Self {
        Self { config }
    }

    /// Creates a quarantine manager with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(QuarantineConfig::default())
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &QuarantineConfig {
        &self.config
    }

    /// Evaluates whether a session should be quarantined based on its state.
    ///
    /// Returns `Some(reason)` if the session should be quarantined, or `None`
    /// if it should not.
    #[must_use]
    pub fn should_quarantine(&self, state: &QuarantineEvaluation) -> Option<QuarantineReason> {
        // Check entropy exceeded
        if self.config.quarantine_on_entropy_exceeded && state.entropy_exceeded {
            return Some(QuarantineReason::EntropyExceeded {
                budget: state.entropy_budget,
                consumed: state.entropy_consumed,
            });
        }

        // Check excessive violations
        if state.violation_count >= self.config.violation_threshold {
            return Some(QuarantineReason::ExcessiveViolations {
                violation_count: state.violation_count,
                threshold: self.config.violation_threshold,
            });
        }

        // Check crash loop
        if state.restart_count >= self.config.restart_threshold {
            return Some(QuarantineReason::CrashLoop {
                restart_count: state.restart_count,
                threshold: self.config.restart_threshold,
            });
        }

        // Check non-restartable crash
        if self.config.quarantine_on_non_restartable {
            if let Some((signal, ref name)) = state.non_restartable_signal {
                return Some(QuarantineReason::NonRestartableCrash {
                    signal,
                    signal_name: name.clone(),
                });
            }
        }

        None
    }

    /// Calculates the quarantine duration based on how many times the session
    /// has been quarantined previously.
    ///
    /// Uses exponential backoff: `base_duration * (multiplier ^
    /// previous_quarantines)`
    #[must_use]
    #[expect(
        clippy::cast_sign_loss,
        reason = "multiplier and base_millis are always positive"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "clamped to max_duration which fits in u64"
    )]
    #[expect(
        clippy::cast_precision_loss,
        reason = "precision loss acceptable for duration calculation"
    )]
    pub fn calculate_duration(&self, previous_quarantines: u32) -> Duration {
        let base_millis = self.config.base_duration.as_millis() as f64;
        let factor = self
            .config
            .multiplier
            .powi(i32::try_from(previous_quarantines).unwrap_or(0));
        let duration_millis = base_millis * factor;

        // Clamp to max_duration milliseconds to avoid overflow
        let max_millis = self.config.max_duration.as_millis() as f64;
        let clamped_millis = duration_millis.min(max_millis);
        let duration = Duration::from_millis(clamped_millis as u64);

        // Cap at max duration
        if duration > self.config.max_duration {
            self.config.max_duration
        } else {
            duration
        }
    }

    /// Calculates the quarantine duration in ticks (RFC-0016 HTF compliant).
    ///
    /// Uses exponential backoff: `base_duration_ticks * (multiplier ^
    /// previous_quarantines)`, clamped to `max_duration_ticks`.
    ///
    /// # Returns
    ///
    /// The duration in ticks, or `None` if the config is not tick-based.
    #[must_use]
    #[expect(
        clippy::cast_sign_loss,
        reason = "multiplier and base_ticks are always positive"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "clamped to max_duration_ticks which fits in u64"
    )]
    #[expect(
        clippy::cast_precision_loss,
        reason = "precision loss acceptable for duration calculation"
    )]
    pub fn calculate_duration_ticks(&self, previous_quarantines: u32) -> Option<u64> {
        let base_ticks = self.config.base_duration_ticks? as f64;
        let max_ticks = self.config.max_duration_ticks? as f64;

        let factor = self
            .config
            .multiplier
            .powi(i32::try_from(previous_quarantines).unwrap_or(0));
        let duration_ticks = base_ticks * factor;

        // Clamp to max_duration_ticks
        let clamped_ticks = duration_ticks.min(max_ticks) as u64;
        Some(clamped_ticks)
    }

    /// Checks if a quarantine has expired based on current time.
    ///
    /// **DEPRECATED**: Use [`QuarantineManager::is_quarantine_expired_at_tick`]
    /// for RFC-0016 HTF compliant expiry checks.
    ///
    /// # Arguments
    /// * `quarantine_until` - Unix timestamp (nanoseconds) when quarantine
    ///   expires
    /// * `current_time_ns` - Current Unix timestamp (nanoseconds)
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use is_quarantine_expired_at_tick for tick-based expiry (RFC-0016 HTF)"
    )]
    pub const fn is_quarantine_expired(quarantine_until: u64, current_time_ns: u64) -> bool {
        current_time_ns >= quarantine_until
    }

    /// Checks if a quarantine has expired based on current tick (RFC-0016 HTF).
    ///
    /// # SEC-HTF-003: Tick Rate Validation
    ///
    /// Ticks are node-local and their rates can vary. Comparing raw values
    /// without rate-equality enforcement is dangerous. This method enforces
    /// that `current_tick.tick_rate_hz() ==
    /// quarantine_until_tick.tick_rate_hz()`. If rates differ, returns
    /// `true` (fail-closed) to prevent incorrect expiry decisions.
    ///
    /// # Arguments
    /// * `quarantine_until_tick` - Tick when quarantine expires
    /// * `current_tick` - Current tick
    #[must_use]
    pub fn is_quarantine_expired_at_tick(
        quarantine_until_tick: &HtfTick,
        current_tick: &HtfTick,
    ) -> bool {
        // SEC-HTF-003: Enforce tick rate equality. If rates differ, fail-closed.
        if current_tick.tick_rate_hz() != quarantine_until_tick.tick_rate_hz() {
            return true; // Fail-closed: treat as expired
        }
        current_tick.value() >= quarantine_until_tick.value()
    }

    /// Calculates the `quarantine_until` timestamp.
    ///
    /// **DEPRECATED**: Use [`QuarantineManager::quarantine_until_tick`]
    /// for RFC-0016 HTF compliant calculations.
    ///
    /// # Arguments
    /// * `current_time_ns` - Current Unix timestamp (nanoseconds)
    /// * `duration` - Quarantine duration
    ///
    /// # Note
    /// The `duration.as_nanos()` returns `u128`, but we truncate to `u64`.
    /// This is safe because max quarantine duration is 7 days, which is
    /// approximately 604 trillion ns, well within `u64::MAX`.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "duration < 7 days fits in u64 nanos"
    )]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "as_nanos() is not const in stable Rust"
    )]
    #[deprecated(
        since = "0.4.0",
        note = "use quarantine_until_tick for tick-based timing (RFC-0016 HTF)"
    )]
    pub fn quarantine_until(current_time_ns: u64, duration: Duration) -> u64 {
        let duration_ns = duration.as_nanos() as u64;
        current_time_ns.saturating_add(duration_ns)
    }

    /// Calculates the quarantine expiry tick (RFC-0016 HTF compliant).
    ///
    /// # Arguments
    /// * `current_tick` - Current tick when quarantine starts
    /// * `duration_ticks` - Quarantine duration in ticks
    #[must_use]
    pub fn quarantine_until_tick(current_tick: &HtfTick, duration_ticks: u64) -> HtfTick {
        current_tick.saturating_add(duration_ticks)
    }
}

/// State needed to evaluate quarantine decisions.
///
/// This is extracted from session state to allow evaluation without
/// requiring full session state access.
#[derive(Debug, Clone, Default)]
pub struct QuarantineEvaluation {
    /// Session ID being evaluated.
    pub session_id: String,

    /// Whether entropy budget was exceeded.
    pub entropy_exceeded: bool,

    /// Total entropy budget.
    pub entropy_budget: u64,

    /// Entropy consumed.
    pub entropy_consumed: u64,

    /// Number of policy violations.
    pub violation_count: u64,

    /// Number of restart attempts.
    pub restart_count: u32,

    /// If the session crashed with a non-restartable signal, the signal number
    /// and name.
    pub non_restartable_signal: Option<(i32, String)>,
}

impl QuarantineEvaluation {
    /// Creates a new evaluation for a session.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            ..Default::default()
        }
    }

    /// Sets the entropy state.
    #[must_use]
    pub const fn with_entropy(mut self, budget: u64, consumed: u64) -> Self {
        self.entropy_budget = budget;
        self.entropy_consumed = consumed;
        self.entropy_exceeded = consumed >= budget;
        self
    }

    /// Sets the violation count.
    #[must_use]
    pub const fn with_violations(mut self, count: u64) -> Self {
        self.violation_count = count;
        self
    }

    /// Sets the restart count.
    #[must_use]
    pub const fn with_restarts(mut self, count: u32) -> Self {
        self.restart_count = count;
        self
    }

    /// Sets the non-restartable signal.
    #[must_use]
    pub fn with_non_restartable_signal(mut self, signal: i32, name: impl Into<String>) -> Self {
        self.non_restartable_signal = Some((signal, name.into()));
        self
    }
}

/// Information about a quarantined session.
///
/// # Time Model (RFC-0016 HTF)
///
/// Quarantine info uses tick-based expiry for immunity to wall-clock
/// manipulation:
///
/// - `quarantined_at_tick` / `quarantine_until_tick`: Authoritative for expiry
///   checks when present
/// - `quarantined_at` / `quarantine_until`: Retained for backwards
///   compatibility and audit
///
/// When tick-based fields are present, they are authoritative. Expiry decisions
/// MUST use tick comparison, not wall time comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineInfo {
    /// Session ID.
    pub session_id: String,

    /// Reason for quarantine.
    pub reason: QuarantineReason,

    /// Timestamp when quarantine started (nanoseconds since epoch).
    /// Retained for backwards compatibility; not authoritative for expiry.
    pub quarantined_at: u64,

    /// Timestamp when quarantine expires (nanoseconds since epoch).
    /// Retained for backwards compatibility; not authoritative for expiry.
    pub quarantine_until: u64,

    /// How many times this session has been quarantined.
    pub quarantine_count: u32,

    /// Monotonic tick when quarantine started (RFC-0016 HTF).
    /// Authoritative for timing decisions when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_at_tick: Option<HtfTick>,

    /// Monotonic tick when quarantine expires (RFC-0016 HTF).
    /// Authoritative for expiry checks when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine_until_tick: Option<HtfTick>,
}

impl QuarantineInfo {
    /// Creates a new quarantine info.
    ///
    /// This constructor creates a quarantine without tick-based timing.
    /// Use [`QuarantineInfo::new_with_ticks`] for full RFC-0016 HTF compliance.
    #[must_use]
    #[allow(deprecated)] // We intentionally use quarantine_until for legacy compat
    pub fn new(
        session_id: impl Into<String>,
        reason: QuarantineReason,
        quarantined_at: u64,
        duration: Duration,
        quarantine_count: u32,
    ) -> Self {
        #[allow(deprecated)]
        let quarantine_until = QuarantineManager::quarantine_until(quarantined_at, duration);
        Self {
            session_id: session_id.into(),
            reason,
            quarantined_at,
            quarantine_until,
            quarantine_count,
            quarantined_at_tick: None,
            quarantine_until_tick: None,
        }
    }

    /// Creates a new quarantine info with tick-based timing (RFC-0016 HTF
    /// compliant).
    ///
    /// This is the preferred constructor for new code. The tick-based fields
    /// are authoritative for expiry decisions, immune to wall-clock changes.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session being quarantined
    /// * `reason` - Reason for quarantine
    /// * `quarantined_at` - Wall time when quarantine started (for
    ///   audit/display only)
    /// * `quarantine_until` - Wall time when quarantine expires (for
    ///   audit/display only)
    /// * `quarantined_at_tick` - Monotonic tick when quarantine started
    ///   (authoritative)
    /// * `quarantine_until_tick` - Monotonic tick when quarantine expires
    ///   (authoritative)
    /// * `quarantine_count` - Number of times this session has been quarantined
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ticks(
        session_id: impl Into<String>,
        reason: QuarantineReason,
        quarantined_at: u64,
        quarantine_until: u64,
        quarantined_at_tick: HtfTick,
        quarantine_until_tick: HtfTick,
        quarantine_count: u32,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            reason,
            quarantined_at,
            quarantine_until,
            quarantine_count,
            quarantined_at_tick: Some(quarantined_at_tick),
            quarantine_until_tick: Some(quarantine_until_tick),
        }
    }

    /// Returns true if this is a legacy quarantine without tick-based timing.
    ///
    /// Legacy quarantines should use wall-clock fallback for expiry checks.
    #[must_use]
    pub const fn is_legacy(&self) -> bool {
        self.quarantine_until_tick.is_none()
    }

    /// Checks if this quarantine has expired based on the given current tick.
    ///
    /// This is the RFC-0016 HTF compliant expiry check using monotonic ticks.
    /// Returns true if the current tick is past the quarantine's expiration
    /// tick.
    ///
    /// # SEC-HTF-003: Tick Rate Validation
    ///
    /// Ticks are node-local and their rates can vary. Comparing raw values
    /// without rate-equality enforcement is dangerous. This method enforces
    /// that `current_tick.tick_rate_hz() ==
    /// quarantine_until_tick.tick_rate_hz()`. If rates differ, returns
    /// `true` (fail-closed) to prevent incorrect expiry decisions.
    ///
    /// # SEC-CTRL-FAC-0015: Legacy Fallback
    ///
    /// For quarantines WITHOUT tick data (legacy), this method returns `false`
    /// to indicate "not expired via tick logic" - the caller should use the
    /// wall-clock fallback via [`QuarantineInfo::is_expired`] for such
    /// quarantines. Use [`QuarantineInfo::is_expired_at_tick_or_wall`] for
    /// automatic fallback handling.
    #[must_use]
    pub fn is_expired_at_tick(&self, current_tick: &HtfTick) -> bool {
        // SEC-CTRL-FAC-0015: For legacy quarantines without tick data, return false.
        let Some(quarantine_until_tick) = &self.quarantine_until_tick else {
            return false;
        };

        QuarantineManager::is_quarantine_expired_at_tick(quarantine_until_tick, current_tick)
    }

    /// Checks if this quarantine has expired, using tick-based comparison with
    /// wall-clock fallback for legacy quarantines.
    ///
    /// # SEC-CTRL-FAC-0015: Migration Path for Legacy Quarantines
    ///
    /// This method provides a migration path for pre-existing quarantines that
    /// lack tick data:
    ///
    /// - For quarantines WITH tick data: Uses tick-based comparison (RFC-0016
    ///   HTF)
    /// - For quarantines WITHOUT tick data: Falls back to wall-clock comparison
    ///
    /// This prevents all legacy quarantines from expiring simultaneously upon
    /// deployment while maintaining security for new tick-based quarantines.
    ///
    /// # SEC-HTF-003: Tick Rate Validation
    ///
    /// When tick data is present, tick rates must match. Mismatched rates
    /// result in fail-closed behavior (returns `true`).
    #[must_use]
    #[allow(deprecated)] // We intentionally use is_expired for legacy fallback
    pub fn is_expired_at_tick_or_wall(&self, current_tick: &HtfTick, current_wall_ns: u64) -> bool {
        if let Some(quarantine_until_tick) = &self.quarantine_until_tick {
            // Tick data present: use tick comparison
            QuarantineManager::is_quarantine_expired_at_tick(quarantine_until_tick, current_tick)
        } else {
            // SEC-CTRL-FAC-0015: Legacy quarantine without tick data.
            // Fall back to wall-clock comparison for migration compatibility.
            current_wall_ns >= self.quarantine_until
        }
    }

    /// Returns the remaining ticks until quarantine expires, or 0 if expired.
    ///
    /// This is the RFC-0016 HTF compliant method using monotonic ticks.
    /// Only meaningful for quarantines with tick-based timing.
    ///
    /// # SEC-HTF-003: Tick Rate Validation
    ///
    /// Returns 0 if tick rates differ, as comparing ticks across different
    /// rates is invalid.
    ///
    /// # SEC-CTRL-FAC-0015: Legacy Fallback
    ///
    /// Returns 0 if tick-based timing is not available. For legacy quarantines,
    /// use wall-clock remaining time calculation instead.
    #[must_use]
    pub fn ticks_remaining(&self, current_tick: &HtfTick) -> u64 {
        // SEC-CTRL-FAC-0015: Return 0 if tick data is missing (legacy quarantine)
        let Some(quarantine_until_tick) = &self.quarantine_until_tick else {
            return 0;
        };

        // SEC-HTF-003: Return 0 if tick rates differ (fail-closed)
        if current_tick.tick_rate_hz() != quarantine_until_tick.tick_rate_hz() {
            return 0;
        }

        quarantine_until_tick
            .value()
            .saturating_sub(current_tick.value())
    }

    /// Checks if this quarantine has expired (wall clock).
    ///
    /// **DEPRECATED**: This method uses wall time which can be manipulated.
    /// Use [`QuarantineInfo::is_expired_at_tick`] for RFC-0016 HTF compliant
    /// expiry checks.
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use is_expired_at_tick for tick-based expiry (RFC-0016 HTF)"
    )]
    pub const fn is_expired(&self, current_time_ns: u64) -> bool {
        current_time_ns >= self.quarantine_until
    }

    /// Returns the remaining quarantine duration (wall clock).
    ///
    /// **DEPRECATED**: This method uses wall time which can be manipulated.
    /// Use [`QuarantineInfo::ticks_remaining`] for RFC-0016 HTF compliant
    /// timing.
    ///
    /// Returns `None` if quarantine has expired.
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use ticks_remaining for tick-based timing (RFC-0016 HTF)"
    )]
    pub const fn remaining(&self, current_time_ns: u64) -> Option<Duration> {
        if current_time_ns >= self.quarantine_until {
            None
        } else {
            let remaining_ns = self.quarantine_until - current_time_ns;
            Some(Duration::from_nanos(remaining_ns))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = QuarantineConfig::default();
        assert_eq!(config.base_duration, Duration::from_secs(300));
        assert_eq!(config.max_duration, Duration::from_secs(86400));
        assert!((config.multiplier - 2.0).abs() < f64::EPSILON);
        assert_eq!(config.violation_threshold, 5);
        assert_eq!(config.restart_threshold, 5);
        assert!(config.quarantine_on_entropy_exceeded);
        assert!(config.quarantine_on_non_restartable);
    }

    #[test]
    fn test_config_lenient() {
        let config = QuarantineConfig::lenient();
        assert_eq!(config.violation_threshold, 10);
        assert_eq!(config.restart_threshold, 10);
        assert!(!config.quarantine_on_entropy_exceeded);
    }

    #[test]
    fn test_config_strict() {
        let config = QuarantineConfig::strict();
        assert_eq!(config.violation_threshold, 3);
        assert_eq!(config.restart_threshold, 3);
        assert!(config.quarantine_on_entropy_exceeded);
    }

    #[test]
    fn test_should_quarantine_entropy_exceeded() {
        let manager = QuarantineManager::with_defaults();
        let eval = QuarantineEvaluation::new("session-1").with_entropy(1000, 1500);

        let reason = manager.should_quarantine(&eval);
        assert!(reason.is_some());
        assert!(matches!(
            reason.unwrap(),
            QuarantineReason::EntropyExceeded {
                budget: 1000,
                consumed: 1500
            }
        ));
    }

    #[test]
    fn test_should_quarantine_entropy_disabled() {
        let config = QuarantineConfig {
            quarantine_on_entropy_exceeded: false,
            ..Default::default()
        };
        let manager = QuarantineManager::new(config);
        let eval = QuarantineEvaluation::new("session-1").with_entropy(1000, 1500);

        let reason = manager.should_quarantine(&eval);
        assert!(reason.is_none());
    }

    #[test]
    fn test_should_quarantine_excessive_violations() {
        let manager = QuarantineManager::with_defaults();
        let eval = QuarantineEvaluation::new("session-1").with_violations(5);

        let reason = manager.should_quarantine(&eval);
        assert!(reason.is_some());
        assert!(matches!(
            reason.unwrap(),
            QuarantineReason::ExcessiveViolations {
                violation_count: 5,
                threshold: 5
            }
        ));
    }

    #[test]
    fn test_should_quarantine_below_violation_threshold() {
        let manager = QuarantineManager::with_defaults();
        let eval = QuarantineEvaluation::new("session-1").with_violations(4);

        let reason = manager.should_quarantine(&eval);
        assert!(reason.is_none());
    }

    #[test]
    fn test_should_quarantine_crash_loop() {
        let manager = QuarantineManager::with_defaults();
        let eval = QuarantineEvaluation::new("session-1").with_restarts(5);

        let reason = manager.should_quarantine(&eval);
        assert!(reason.is_some());
        assert!(matches!(
            reason.unwrap(),
            QuarantineReason::CrashLoop {
                restart_count: 5,
                threshold: 5
            }
        ));
    }

    #[test]
    fn test_should_quarantine_non_restartable() {
        let manager = QuarantineManager::with_defaults();
        let eval =
            QuarantineEvaluation::new("session-1").with_non_restartable_signal(11, "SIGSEGV");

        let reason = manager.should_quarantine(&eval);
        assert!(reason.is_some());
        assert!(matches!(
            reason.unwrap(),
            QuarantineReason::NonRestartableCrash { signal: 11, .. }
        ));
    }

    #[test]
    fn test_should_quarantine_non_restartable_disabled() {
        let config = QuarantineConfig {
            quarantine_on_non_restartable: false,
            ..Default::default()
        };
        let manager = QuarantineManager::new(config);
        let eval =
            QuarantineEvaluation::new("session-1").with_non_restartable_signal(11, "SIGSEGV");

        let reason = manager.should_quarantine(&eval);
        assert!(reason.is_none());
    }

    #[test]
    fn test_should_not_quarantine_healthy_session() {
        let manager = QuarantineManager::with_defaults();
        let eval = QuarantineEvaluation::new("session-1")
            .with_entropy(1000, 500)
            .with_violations(2)
            .with_restarts(2);

        let reason = manager.should_quarantine(&eval);
        assert!(reason.is_none());
    }

    #[test]
    fn test_calculate_duration_first_quarantine() {
        let manager = QuarantineManager::with_defaults();
        let duration = manager.calculate_duration(0);
        assert_eq!(duration, Duration::from_secs(300));
    }

    #[test]
    fn test_calculate_duration_exponential_backoff() {
        let manager = QuarantineManager::with_defaults();

        // First: 300s
        assert_eq!(manager.calculate_duration(0), Duration::from_secs(300));

        // Second: 300 * 2 = 600s
        assert_eq!(manager.calculate_duration(1), Duration::from_secs(600));

        // Third: 300 * 4 = 1200s
        assert_eq!(manager.calculate_duration(2), Duration::from_secs(1200));

        // Fourth: 300 * 8 = 2400s
        assert_eq!(manager.calculate_duration(3), Duration::from_secs(2400));
    }

    #[test]
    fn test_calculate_duration_capped_at_max() {
        let manager = QuarantineManager::with_defaults();

        // After many quarantines, should be capped at max
        let duration = manager.calculate_duration(20);
        assert_eq!(duration, Duration::from_secs(86400));
    }

    #[test]
    #[allow(deprecated)]
    fn test_is_quarantine_expired() {
        // Not expired
        assert!(!QuarantineManager::is_quarantine_expired(
            2_000_000_000,
            1_000_000_000
        ));

        // Exactly at expiry
        assert!(QuarantineManager::is_quarantine_expired(
            1_000_000_000,
            1_000_000_000
        ));

        // Past expiry
        assert!(QuarantineManager::is_quarantine_expired(
            1_000_000_000,
            2_000_000_000
        ));
    }

    #[test]
    #[allow(deprecated)]
    fn test_quarantine_until() {
        let current = 1_000_000_000_000_000_000u64; // 1 second in nanos
        let duration = Duration::from_secs(300);
        let until = QuarantineManager::quarantine_until(current, duration);
        assert_eq!(until, current + 300_000_000_000);
    }

    #[test]
    #[allow(deprecated)]
    fn test_quarantine_info_is_expired() {
        let info = QuarantineInfo::new(
            "session-1",
            QuarantineReason::EntropyExceeded {
                budget: 1000,
                consumed: 1500,
            },
            1_000_000_000_000_000_000,
            Duration::from_secs(300),
            1,
        );

        // Not expired
        assert!(!info.is_expired(1_000_000_000_000_000_000));

        // Expired
        assert!(info.is_expired(1_000_000_000_000_000_000 + 300_000_000_001));
    }

    #[test]
    #[allow(deprecated)]
    fn test_quarantine_info_remaining() {
        let current = 1_000_000_000_000_000_000u64;
        let info = QuarantineInfo::new(
            "session-1",
            QuarantineReason::EntropyExceeded {
                budget: 1000,
                consumed: 1500,
            },
            current,
            Duration::from_secs(300),
            1,
        );

        // Full duration remaining
        let remaining = info.remaining(current);
        assert_eq!(remaining, Some(Duration::from_secs(300)));

        // Half remaining
        let remaining = info.remaining(current + 150_000_000_000);
        assert_eq!(remaining, Some(Duration::from_secs(150)));

        // Expired
        let remaining = info.remaining(current + 400_000_000_000);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_quarantine_reason_display() {
        let entropy = QuarantineReason::EntropyExceeded {
            budget: 1000,
            consumed: 1500,
        };
        assert!(entropy.to_string().contains("1500"));
        assert!(entropy.to_string().contains("1000"));

        let violations = QuarantineReason::ExcessiveViolations {
            violation_count: 10,
            threshold: 5,
        };
        assert!(violations.to_string().contains("10"));
        assert!(violations.to_string().contains('5'));

        let crash = QuarantineReason::CrashLoop {
            restart_count: 5,
            threshold: 3,
        };
        assert!(crash.to_string().contains('5'));
        assert!(crash.to_string().contains('3'));

        let signal = QuarantineReason::NonRestartableCrash {
            signal: 11,
            signal_name: "SIGSEGV".to_string(),
        };
        assert!(signal.to_string().contains("11"));
        assert!(signal.to_string().contains("SIGSEGV"));

        let manual = QuarantineReason::Manual {
            reason: "test reason".to_string(),
        };
        assert!(manual.to_string().contains("test reason"));
    }

    #[test]
    fn test_quarantine_reason_code() {
        assert_eq!(
            QuarantineReason::EntropyExceeded {
                budget: 1000,
                consumed: 1500
            }
            .as_code(),
            "ENTROPY_EXCEEDED"
        );
        assert_eq!(
            QuarantineReason::ExcessiveViolations {
                violation_count: 10,
                threshold: 5
            }
            .as_code(),
            "EXCESSIVE_VIOLATIONS"
        );
        assert_eq!(
            QuarantineReason::CrashLoop {
                restart_count: 5,
                threshold: 3
            }
            .as_code(),
            "CRASH_LOOP"
        );
        assert_eq!(
            QuarantineReason::NonRestartableCrash {
                signal: 11,
                signal_name: "SIGSEGV".to_string()
            }
            .as_code(),
            "NON_RESTARTABLE_CRASH"
        );
        assert_eq!(
            QuarantineReason::Manual {
                reason: "test".to_string()
            }
            .as_code(),
            "MANUAL"
        );
    }

    #[test]
    fn test_evaluation_builder() {
        let eval = QuarantineEvaluation::new("session-1")
            .with_entropy(1000, 500)
            .with_violations(3)
            .with_restarts(2);

        assert_eq!(eval.session_id, "session-1");
        assert_eq!(eval.entropy_budget, 1000);
        assert_eq!(eval.entropy_consumed, 500);
        assert!(!eval.entropy_exceeded);
        assert_eq!(eval.violation_count, 3);
        assert_eq!(eval.restart_count, 2);
        assert!(eval.non_restartable_signal.is_none());
    }

    #[test]
    fn test_evaluation_entropy_exceeded_flag() {
        let under = QuarantineEvaluation::new("session-1").with_entropy(1000, 500);
        assert!(!under.entropy_exceeded);

        let at = QuarantineEvaluation::new("session-2").with_entropy(1000, 1000);
        assert!(at.entropy_exceeded);

        let over = QuarantineEvaluation::new("session-3").with_entropy(1000, 1500);
        assert!(over.entropy_exceeded);
    }

    /// Tests priority ordering of quarantine reasons.
    /// Entropy exceeded should be checked first, then violations, then crash
    /// loop.
    #[test]
    fn test_quarantine_reason_priority() {
        let manager = QuarantineManager::with_defaults();

        // Session with multiple issues - entropy exceeded takes priority
        let eval = QuarantineEvaluation::new("session-1")
            .with_entropy(1000, 1500)
            .with_violations(10)
            .with_restarts(10);

        let reason = manager.should_quarantine(&eval);
        assert!(matches!(
            reason,
            Some(QuarantineReason::EntropyExceeded { .. })
        ));
    }

    /// Tests that quarantine count affects duration exponentially.
    #[test]
    fn test_quarantine_count_escalation() {
        let manager = QuarantineManager::with_defaults();

        let info1 = QuarantineInfo::new(
            "session-1",
            QuarantineReason::ExcessiveViolations {
                violation_count: 5,
                threshold: 5,
            },
            0,
            manager.calculate_duration(0),
            1,
        );
        assert_eq!(info1.quarantine_until, 300_000_000_000); // 300s in nanos

        let info2 = QuarantineInfo::new(
            "session-1",
            QuarantineReason::ExcessiveViolations {
                violation_count: 5,
                threshold: 5,
            },
            0,
            manager.calculate_duration(1),
            2,
        );
        assert_eq!(info2.quarantine_until, 600_000_000_000); // 600s in nanos

        let info3 = QuarantineInfo::new(
            "session-1",
            QuarantineReason::ExcessiveViolations {
                violation_count: 5,
                threshold: 5,
            },
            0,
            manager.calculate_duration(2),
            3,
        );
        assert_eq!(info3.quarantine_until, 1_200_000_000_000); // 1200s in nanos
    }
}

/// TCK-00243: Tick-based quarantine expiry tests (RFC-0016 HTF).
///
/// These tests verify that quarantine validity is determined by monotonic
/// ticks, not wall time, and that wall time changes do not affect quarantine
/// validity.
#[cfg(test)]
mod tck_00243 {
    use super::*;

    const TICK_RATE_HZ: u64 = 1_000_000; // 1MHz = 1 tick per microsecond

    /// Helper to create a tick at a given value with standard tick rate.
    fn tick(value: u64) -> HtfTick {
        HtfTick::new(value, TICK_RATE_HZ)
    }

    /// TCK-00243: Tick-based config constructor sets all fields correctly.
    #[test]
    fn tick_based_config_constructor() {
        // 5 minutes base = 300_000_000 ticks at 1MHz
        // 24 hours max = 86_400_000_000 ticks at 1MHz
        let config = QuarantineConfig::with_ticks(
            300_000_000,    // base duration ticks (5 min)
            86_400_000_000, // max duration ticks (24 hr)
            TICK_RATE_HZ,   // tick rate
            2.0,            // multiplier
        );

        assert!(config.is_tick_based());
        assert_eq!(config.base_duration_ticks, Some(300_000_000));
        assert_eq!(config.max_duration_ticks, Some(86_400_000_000));
        assert_eq!(config.tick_rate_hz, Some(TICK_RATE_HZ));
        assert!((config.multiplier - 2.0).abs() < f64::EPSILON);

        // Wall-clock fallback values should be set for backwards compat
        assert_eq!(config.base_duration, Duration::from_secs(300));
        assert_eq!(config.max_duration, Duration::from_secs(86400));
    }

    /// TCK-00243: Legacy config is not tick-based.
    #[test]
    fn legacy_config_is_not_tick_based() {
        let config = QuarantineConfig::default();
        assert!(!config.is_tick_based());
        assert!(config.base_duration_ticks.is_none());
        assert!(config.max_duration_ticks.is_none());
        assert!(config.tick_rate_hz.is_none());
    }

    /// TCK-00243: Tick-based duration calculation with exponential backoff.
    #[test]
    fn tick_based_duration_calculation() {
        let config = QuarantineConfig::with_ticks(
            1000,    // base: 1000 ticks
            100_000, // max: 100_000 ticks
            TICK_RATE_HZ,
            2.0,
        );
        let manager = QuarantineManager::new(config);

        // First quarantine: base ticks
        assert_eq!(manager.calculate_duration_ticks(0), Some(1000));

        // Second quarantine: 1000 * 2 = 2000
        assert_eq!(manager.calculate_duration_ticks(1), Some(2000));

        // Third quarantine: 1000 * 4 = 4000
        assert_eq!(manager.calculate_duration_ticks(2), Some(4000));

        // Fourth quarantine: 1000 * 8 = 8000
        assert_eq!(manager.calculate_duration_ticks(3), Some(8000));

        // Many quarantines: capped at max
        assert_eq!(manager.calculate_duration_ticks(20), Some(100_000));
    }

    /// TCK-00243: Legacy config returns None for tick duration.
    #[test]
    fn legacy_config_duration_ticks_returns_none() {
        let manager = QuarantineManager::with_defaults();
        assert!(manager.calculate_duration_ticks(0).is_none());
    }

    /// TCK-00243: Tick-based expiry is independent of wall time.
    ///
    /// Verifies that changing wall time values does not affect quarantine
    /// validity when tick-based timing is used.
    #[test]
    fn wall_time_changes_do_not_affect_tick_expiry() {
        // Create quarantine with tick-based timing
        let info = QuarantineInfo::new_with_ticks(
            "session-1",
            QuarantineReason::EntropyExceeded {
                budget: 1000,
                consumed: 1500,
            },
            1_000_000_000, // wall quarantined_at (irrelevant)
            2_000_000_000, // wall quarantine_until (irrelevant)
            tick(1000),    // quarantined_at_tick
            tick(2000),    // quarantine_until_tick
            1,
        );

        // Test: At tick 1500, quarantine should NOT be expired
        assert!(!info.is_expired_at_tick(&tick(1500)));
        assert_eq!(info.ticks_remaining(&tick(1500)), 500);

        // Test: At tick 2500, quarantine SHOULD be expired
        assert!(info.is_expired_at_tick(&tick(2500)));
        assert_eq!(info.ticks_remaining(&tick(2500)), 0);
    }

    /// TCK-00243: Tick-based expiry at exact boundary.
    #[test]
    fn tick_expiry_at_exact_boundary() {
        let info = QuarantineInfo::new_with_ticks(
            "session-1",
            QuarantineReason::CrashLoop {
                restart_count: 5,
                threshold: 5,
            },
            0,
            0,
            tick(1000),
            tick(2000),
            1,
        );

        // One tick before expiration
        assert!(!info.is_expired_at_tick(&tick(1999)));
        assert_eq!(info.ticks_remaining(&tick(1999)), 1);

        // Exactly at expiration (tick >= quarantine_until_tick)
        assert!(info.is_expired_at_tick(&tick(2000)));
        assert_eq!(info.ticks_remaining(&tick(2000)), 0);

        // One tick after expiration
        assert!(info.is_expired_at_tick(&tick(2001)));
        assert_eq!(info.ticks_remaining(&tick(2001)), 0);
    }

    /// TCK-00243: SEC-CTRL-FAC-0015 legacy quarantine handling.
    ///
    /// Legacy quarantines without tick data should NOT be treated as expired
    /// by tick-only methods. Instead, callers should use the wall-clock
    /// fallback method `is_expired_at_tick_or_wall`.
    #[test]
    fn legacy_quarantine_tick_methods_return_false_or_zero() {
        // Create quarantine WITHOUT tick data (using legacy constructor)
        let info = QuarantineInfo::new(
            "session-1",
            QuarantineReason::EntropyExceeded {
                budget: 1000,
                consumed: 1500,
            },
            1_000_000_000,
            Duration::from_secs(300),
            1,
        );

        // Verify tick fields are None
        assert!(info.quarantined_at_tick.is_none());
        assert!(info.quarantine_until_tick.is_none());
        assert!(info.is_legacy());

        // is_expired_at_tick returns false for legacy quarantines
        assert!(!info.is_expired_at_tick(&tick(1500)));
        assert_eq!(info.ticks_remaining(&tick(1500)), 0);
    }

    /// TCK-00243: SEC-CTRL-FAC-0015 wall-clock fallback for legacy quarantines.
    ///
    /// Legacy quarantines should use wall-clock comparison when tick data is
    /// not available. This provides a migration path for existing quarantines.
    #[test]
    fn legacy_quarantine_uses_wall_clock_fallback() {
        // Create quarantine WITHOUT tick data (using legacy constructor)
        let info = QuarantineInfo::new(
            "session-1",
            QuarantineReason::ExcessiveViolations {
                violation_count: 5,
                threshold: 5,
            },
            1_000_000_000,          // quarantined at 1s
            Duration::from_secs(1), // 1 second duration
            1,
        );

        // quarantine_until should be 2_000_000_000 (2s in nanos)
        assert_eq!(info.quarantine_until, 2_000_000_000);

        // Before wall time expiration
        assert!(!info.is_expired_at_tick_or_wall(&tick(1000), 1_500_000_000));

        // At wall time expiration boundary
        assert!(info.is_expired_at_tick_or_wall(&tick(1000), 2_000_000_000));

        // After wall time expiration
        assert!(info.is_expired_at_tick_or_wall(&tick(1000), 3_000_000_000));
    }

    /// TCK-00243: SEC-HTF-003 Tick rate mismatch fails closed.
    ///
    /// When tick rates differ between current tick and quarantine expiry tick,
    /// the comparison is invalid. The method fails closed (returns true for
    /// expired) to prevent incorrect expiry decisions.
    #[test]
    fn tick_rate_mismatch_fails_closed() {
        // Quarantine with 1MHz tick rate
        let info = QuarantineInfo::new_with_ticks(
            "session-1",
            QuarantineReason::Manual {
                reason: "test".to_string(),
            },
            0,
            0,
            HtfTick::new(1000, 1_000_000), // 1MHz
            HtfTick::new(2000, 1_000_000), // expires at tick 2000
            1,
        );

        // Same rate: normal comparison works
        let current_same_rate = HtfTick::new(1500, 1_000_000);
        assert!(!info.is_expired_at_tick(&current_same_rate));
        assert_eq!(info.ticks_remaining(&current_same_rate), 500);

        // Different rate: SEC-HTF-003 fail-closed (treated as expired)
        let current_diff_rate = HtfTick::new(1500, 10_000_000);
        assert!(info.is_expired_at_tick(&current_diff_rate)); // Fail-closed!
        assert_eq!(info.ticks_remaining(&current_diff_rate), 0); // Also fails closed
    }

    /// TCK-00243: Injected ticks work correctly for testing.
    ///
    /// Demonstrates that tests can use arbitrary tick values without
    /// needing real time sources.
    #[test]
    fn injected_ticks_for_testing() {
        let info = QuarantineInfo::new_with_ticks(
            "session-1",
            QuarantineReason::CrashLoop {
                restart_count: 3,
                threshold: 3,
            },
            0, // Wall time irrelevant
            0, // Wall time irrelevant
            tick(0),
            tick(5000), // Expires at tick 5000
            1,
        );

        // Test with various injected tick values
        let test_cases = [
            (0, false, 5000),    // Start: not expired, 5000 remaining
            (2500, false, 2500), // Midpoint: not expired, 2500 remaining
            (4999, false, 1),    // Just before: not expired, 1 remaining
            (5000, true, 0),     // At expiry: expired, 0 remaining
            (10000, true, 0),    // Well after: expired, 0 remaining
        ];

        for (tick_value, expected_expired, expected_remaining) in test_cases {
            let current = tick(tick_value);
            assert_eq!(
                info.is_expired_at_tick(&current),
                expected_expired,
                "tick {tick_value} should be expired={expected_expired}"
            );
            assert_eq!(
                info.ticks_remaining(&current),
                expected_remaining,
                "tick {tick_value} should have {expected_remaining} remaining"
            );
        }
    }

    /// TCK-00243: `QuarantineInfo::new_with_ticks` sets all fields correctly.
    #[test]
    fn new_with_ticks_sets_all_fields() {
        let quarantined = tick(1000);
        let until = tick(5000);

        let info = QuarantineInfo::new_with_ticks(
            "session-id",
            QuarantineReason::NonRestartableCrash {
                signal: 11,
                signal_name: "SIGSEGV".to_string(),
            },
            100_000_000,
            500_000_000,
            quarantined,
            until,
            3,
        );

        // Verify all fields
        assert_eq!(info.session_id, "session-id");
        assert!(matches!(
            info.reason,
            QuarantineReason::NonRestartableCrash { signal: 11, .. }
        ));
        assert_eq!(info.quarantined_at, 100_000_000);
        assert_eq!(info.quarantine_until, 500_000_000);
        assert_eq!(info.quarantine_count, 3);
        assert_eq!(info.quarantined_at_tick, Some(quarantined));
        assert_eq!(info.quarantine_until_tick, Some(until));
        assert!(!info.is_legacy());
    }

    /// TCK-00243: Tick-based quarantine uses tick comparison, ignores wall
    /// time.
    ///
    /// When tick data is present, `is_expired_at_tick_or_wall` uses tick
    /// comparison and ignores the wall time parameter.
    #[test]
    fn tick_based_quarantine_ignores_wall_time_in_combined_method() {
        let info = QuarantineInfo::new_with_ticks(
            "session-1",
            QuarantineReason::EntropyExceeded {
                budget: 100,
                consumed: 200,
            },
            1_000_000_000, // wall quarantined at 1s
            2_000_000_000, // wall expires at 2s
            tick(1000),
            tick(2000), // tick expires at 2000
            1,
        );

        // Not expired by tick (1500 < 2000), even if wall time says expired
        assert!(!info.is_expired_at_tick_or_wall(&tick(1500), 3_000_000_000));

        // Expired by tick (2500 >= 2000), even if wall time says not expired
        assert!(info.is_expired_at_tick_or_wall(&tick(2500), 1_500_000_000));
    }

    /// TCK-00243: SEC-HTF-003 tick rate mismatch in combined method.
    ///
    /// When tick rates mismatch, the combined method also fails closed.
    #[test]
    fn tick_rate_mismatch_in_combined_method_fails_closed() {
        let info = QuarantineInfo::new_with_ticks(
            "session-1",
            QuarantineReason::ExcessiveViolations {
                violation_count: 10,
                threshold: 5,
            },
            1_000_000_000,
            2_000_000_000,
            HtfTick::new(1000, 1_000_000), // 1MHz
            HtfTick::new(2000, 1_000_000), // expires at tick 2000
            1,
        );

        // Different rate: fails closed even though tick value 1500 < 2000
        let mismatched_tick = HtfTick::new(1500, 10_000_000); // 10MHz
        assert!(info.is_expired_at_tick_or_wall(&mismatched_tick, 1_500_000_000));
    }

    /// TCK-00243: Quarantine until tick calculation.
    #[test]
    fn quarantine_until_tick_calculation() {
        let current = tick(1000);
        let duration_ticks = 5000;

        let until = QuarantineManager::quarantine_until_tick(&current, duration_ticks);

        assert_eq!(until.value(), 6000);
        assert_eq!(until.tick_rate_hz(), TICK_RATE_HZ);
    }

    /// TCK-00243: Static tick-based expiry check.
    #[test]
    fn static_tick_expiry_check() {
        let until = tick(2000);

        // Not expired
        assert!(!QuarantineManager::is_quarantine_expired_at_tick(
            &until,
            &tick(1999)
        ));

        // At expiry
        assert!(QuarantineManager::is_quarantine_expired_at_tick(
            &until,
            &tick(2000)
        ));

        // After expiry
        assert!(QuarantineManager::is_quarantine_expired_at_tick(
            &until,
            &tick(2001)
        ));

        // Rate mismatch: fail-closed
        let mismatched = HtfTick::new(1500, 10_000_000);
        assert!(QuarantineManager::is_quarantine_expired_at_tick(
            &until,
            &mismatched
        ));
    }

    /// TCK-00243: Serde roundtrip for tick-based quarantine info.
    #[test]
    fn tick_based_quarantine_info_serde_roundtrip() {
        let info = QuarantineInfo::new_with_ticks(
            "session-1",
            QuarantineReason::CrashLoop {
                restart_count: 5,
                threshold: 3,
            },
            1_000_000_000,
            2_000_000_000,
            tick(1000),
            tick(2000),
            2,
        );

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: QuarantineInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(info, deserialized);
        assert_eq!(deserialized.quarantined_at_tick, Some(tick(1000)));
        assert_eq!(deserialized.quarantine_until_tick, Some(tick(2000)));
        assert!(!deserialized.is_legacy());
    }

    /// TCK-00243: Legacy quarantine info serializes without tick fields.
    #[test]
    fn legacy_quarantine_info_serde_omits_tick_fields() {
        let info = QuarantineInfo::new(
            "session-1",
            QuarantineReason::Manual {
                reason: "test".to_string(),
            },
            1_000_000_000,
            Duration::from_secs(300),
            1,
        );

        let json = serde_json::to_string(&info).unwrap();

        // Tick fields should not be present in JSON
        assert!(!json.contains("quarantined_at_tick"));
        assert!(!json.contains("quarantine_until_tick"));

        let deserialized: QuarantineInfo = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_legacy());
        assert!(deserialized.quarantined_at_tick.is_none());
        assert!(deserialized.quarantine_until_tick.is_none());
    }

    /// TCK-00243: Tick-based config serializes tick fields.
    #[test]
    fn tick_based_config_serde_roundtrip() {
        let config = QuarantineConfig::with_ticks(1000, 100_000, TICK_RATE_HZ, 2.5);

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: QuarantineConfig = serde_json::from_str(&json).unwrap();

        assert!(deserialized.is_tick_based());
        assert_eq!(deserialized.base_duration_ticks, Some(1000));
        assert_eq!(deserialized.max_duration_ticks, Some(100_000));
        assert_eq!(deserialized.tick_rate_hz, Some(TICK_RATE_HZ));
    }
}
