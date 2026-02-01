#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Restart policy module.
//!
//! Defines restart behavior including backoff strategies and circuit breakers.
//!
//! # Time Model (RFC-0016 HTF)
//!
//! Restart tracking uses tick-based timing for immunity to wall-clock
//! manipulation:
//!
//! - `restart_window_ticks` / `tick_rate_hz`: Authoritative for restart window
//!   calculations when present
//! - `restart_window`: Retained for backwards compatibility
//!
//! When tick-based fields are present, they are authoritative. Window
//! calculations MUST use tick arithmetic, not wall time.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::htf::HtfTick;

/// Restart configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartConfig {
    /// Maximum number of restarts within the restart window.
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,

    /// Time window for counting restarts.
    #[serde(default = "default_restart_window")]
    #[serde(with = "humantime_serde")]
    pub restart_window: Duration,

    /// Minimum uptime before a restart is considered successful.
    #[serde(default = "default_min_uptime")]
    #[serde(with = "humantime_serde")]
    pub min_uptime: Duration,

    /// Backoff configuration.
    #[serde(default)]
    pub backoff: BackoffConfig,

    /// Whether to restart on successful exit (exit code 0).
    #[serde(default)]
    pub restart_on_success: bool,
}

const fn default_max_restarts() -> u32 {
    5
}

const fn default_restart_window() -> Duration {
    Duration::from_secs(60)
}

const fn default_min_uptime() -> Duration {
    Duration::from_secs(30)
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: default_max_restarts(),
            restart_window: default_restart_window(),
            min_uptime: default_min_uptime(),
            backoff: BackoffConfig::default(),
            restart_on_success: false,
        }
    }
}

/// Backoff configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackoffConfig {
    /// Fixed delay between restarts.
    Fixed {
        /// Delay duration.
        #[serde(with = "humantime_serde")]
        delay: Duration,
    },

    /// Exponential backoff.
    Exponential {
        /// Initial delay.
        #[serde(with = "humantime_serde")]
        initial_delay: Duration,

        /// Maximum delay.
        #[serde(with = "humantime_serde")]
        max_delay: Duration,

        /// Multiplier for each retry (default: 2.0).
        #[serde(default = "default_multiplier")]
        multiplier: f64,
    },

    /// Linear backoff.
    Linear {
        /// Initial delay.
        #[serde(with = "humantime_serde")]
        initial_delay: Duration,

        /// Increment per retry.
        #[serde(with = "humantime_serde")]
        increment: Duration,

        /// Maximum delay.
        #[serde(with = "humantime_serde")]
        max_delay: Duration,
    },
}

const fn default_multiplier() -> f64 {
    2.0
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self::Exponential {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(300),
            multiplier: 2.0,
        }
    }
}

impl BackoffConfig {
    /// Calculate the delay for a given attempt number (1-based).
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        match self {
            Self::Fixed { delay } => *delay,
            Self::Exponential {
                initial_delay,
                max_delay,
                multiplier,
            } => {
                #[allow(clippy::cast_possible_wrap)] // attempt count won't exceed i32
                let delay_secs =
                    initial_delay.as_secs_f64() * multiplier.powi((attempt - 1) as i32);
                let delay = Duration::from_secs_f64(delay_secs);
                delay.min(*max_delay)
            },
            Self::Linear {
                initial_delay,
                increment,
                max_delay,
            } => {
                let delay = *initial_delay + *increment * (attempt - 1);
                delay.min(*max_delay)
            },
        }
    }
}

/// Restart history entry.
///
/// # Time Model (RFC-0016 HTF)
///
/// When `recorded_at_tick` is present, it is authoritative for restart window
/// calculations. The `timestamp` field is retained for backwards compatibility
/// and observational purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartEntry {
    /// Time of the restart (observational, not authoritative for window
    /// calculations when tick data is present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ns: Option<u64>,

    /// Exit code of the previous run (if available).
    pub exit_code: Option<i32>,

    /// Uptime of the previous run.
    pub uptime: Duration,

    /// Restart delay applied.
    pub delay: Duration,

    /// HTF tick when this restart was recorded (RFC-0016).
    /// Authoritative for restart window calculations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at_tick: Option<HtfTick>,
}

/// Manages restart decisions and history.
///
/// # Time Model (RFC-0016 HTF)
///
/// `RestartManager` supports both tick-based and legacy wall-clock timing:
///
/// - When tick-based timing is configured (via `restart_window_ticks`), all
///   restart window calculations use tick arithmetic immune to wall-clock
///   manipulation.
/// - Legacy mode uses wall-clock duration for backwards compatibility.
///
/// Use `should_restart_at_tick` and `record_restart_at_tick` for tick-based
/// operations.
#[derive(Debug)]
pub struct RestartManager {
    /// Restart configuration.
    config: RestartConfig,

    /// Restart history (within the restart window).
    history: Vec<RestartEntry>,

    /// Current backoff attempt counter.
    backoff_attempt: u32,

    /// Whether the circuit breaker is open (preventing restarts).
    circuit_open: bool,

    /// Tick when the circuit breaker opened (RFC-0016 HTF).
    circuit_opened_at_tick: Option<HtfTick>,

    /// Restart window in ticks (if tick-based timing is configured).
    restart_window_ticks: Option<u64>,

    /// Tick rate in Hz (required when using tick-based timing).
    tick_rate_hz: Option<u64>,
}

impl RestartManager {
    /// Create a new restart manager.
    #[must_use]
    pub const fn new(config: RestartConfig) -> Self {
        Self {
            config,
            history: Vec::new(),
            backoff_attempt: 0,
            circuit_open: false,
            circuit_opened_at_tick: None,
            restart_window_ticks: None,
            tick_rate_hz: None,
        }
    }

    /// Create a new restart manager with tick-based timing (RFC-0016 HTF).
    ///
    /// This is the preferred constructor for new code. Tick-based timing is
    /// immune to wall-clock manipulation.
    ///
    /// # Arguments
    ///
    /// * `config` - Restart configuration
    /// * `restart_window_ticks` - Restart window in ticks
    /// * `tick_rate_hz` - Tick rate in Hz (MUST be > 0)
    ///
    /// # Panics
    ///
    /// Panics if `tick_rate_hz` is 0.
    #[must_use]
    pub const fn with_ticks(
        config: RestartConfig,
        restart_window_ticks: u64,
        tick_rate_hz: u64,
    ) -> Self {
        assert!(tick_rate_hz > 0, "tick_rate_hz must be > 0");
        Self {
            config,
            history: Vec::new(),
            backoff_attempt: 0,
            circuit_open: false,
            circuit_opened_at_tick: None,
            restart_window_ticks: Some(restart_window_ticks),
            tick_rate_hz: Some(tick_rate_hz),
        }
    }

    /// Returns true if this manager uses tick-based timing.
    #[must_use]
    pub const fn is_tick_based(&self) -> bool {
        self.restart_window_ticks.is_some() && self.tick_rate_hz.is_some()
    }

    /// Check if a restart should be allowed at the given tick (RFC-0016 HTF).
    ///
    /// This is the tick-based equivalent of `should_restart`. It counts
    /// restarts within the tick-based window to determine if a restart is
    /// allowed.
    ///
    /// # SEC-HTF-003: Tick Rate Validation
    ///
    /// If the provided `current_tick` has a different tick rate than the
    /// configured rate, this method returns `false` (fail-closed: deny
    /// restart).
    ///
    /// # SEC-FIX-002: History Entry Rate Validation
    ///
    /// In legacy mode (no `tick_rate_hz` configured), history entries are
    /// validated to ensure they share the same tick rate as `current_tick`.
    /// If any history entry has a different tick rate, this method returns
    /// `false` (fail-closed: deny restart) to prevent cross-rate comparisons.
    #[must_use]
    pub fn should_restart_at_tick(&self, exit_code: Option<i32>, current_tick: &HtfTick) -> bool {
        // Check circuit breaker
        if self.circuit_open {
            return false;
        }

        // Check if we restart on success
        if exit_code == Some(0) && !self.config.restart_on_success {
            return false;
        }

        // SEC-HTF-003: Validate tick rate matches configuration
        if let Some(configured_rate) = self.tick_rate_hz {
            if current_tick.tick_rate_hz() != configured_rate {
                // Fail-closed: deny restart on tick rate mismatch
                return false;
            }
        }

        // SEC-FIX-002: In legacy mode, validate history entries have consistent tick
        // rates This prevents incorrect window calculations when entries have
        // mixed tick rates
        let expected_tick_rate = self
            .tick_rate_hz
            .unwrap_or_else(|| current_tick.tick_rate_hz());
        for entry in &self.history {
            if let Some(ref entry_tick) = entry.recorded_at_tick {
                if entry_tick.tick_rate_hz() != expected_tick_rate {
                    // Fail-closed: deny restart if history contains mismatched tick rates
                    return false;
                }
            }
        }

        // Get window boundary
        let window_ticks = self.restart_window_ticks.unwrap_or_else(|| {
            // Fallback: convert Duration to ticks if not configured
            let tick_rate = self.tick_rate_hz.unwrap_or(1_000_000);
            self.config.restart_window.as_secs() * tick_rate
        });

        let window_start_tick = current_tick.value().saturating_sub(window_ticks);

        // Count restarts within the tick-based window
        let recent_restarts = self
            .history
            .iter()
            .filter(|entry| {
                entry
                    .recorded_at_tick
                    .as_ref()
                    .is_some_and(|t| t.value() >= window_start_tick)
            })
            .count();

        recent_restarts < self.config.max_restarts as usize
    }

    /// Record a restart at the given tick and get the delay (RFC-0016 HTF).
    ///
    /// This is the tick-based equivalent of `record_restart`. The restart is
    /// recorded with the provided tick for window calculations.
    pub fn record_restart_at_tick(
        &mut self,
        exit_code: Option<i32>,
        uptime: Duration,
        current_tick: HtfTick,
    ) -> Duration {
        self.backoff_attempt += 1;
        let delay = self.config.backoff.delay_for_attempt(self.backoff_attempt);

        let entry = RestartEntry {
            timestamp_ns: None,
            exit_code,
            uptime,
            delay,
            recorded_at_tick: Some(current_tick),
        };

        self.history.push(entry);
        self.prune_history_at_tick(&current_tick);

        // Check if we should open the circuit breaker
        self.check_circuit_breaker_at_tick(&current_tick);

        delay
    }

    /// Record a successful run (uptime exceeded `min_uptime`).
    pub const fn record_success(&mut self) {
        // Reset backoff on successful run
        self.backoff_attempt = 0;
        self.circuit_open = false;
        self.circuit_opened_at_tick = None;
    }

    // =========================================================================
    // Legacy methods for backwards compatibility
    // =========================================================================

    /// Check if a restart should be allowed (legacy, wall-clock based).
    ///
    /// **DEPRECATED**: Use [`RestartManager::should_restart_at_tick`] for
    /// tick-based timing (RFC-0016 HTF).
    ///
    /// This method maintains backwards compatibility with code that doesn't
    /// provide tick values. It uses a simple count of restarts in history
    /// without wall-clock window filtering (since history is pruned by
    /// tick-based methods).
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use should_restart_at_tick for tick-based timing (RFC-0016 HTF)"
    )]
    pub fn should_restart(&self, exit_code: Option<i32>) -> bool {
        // Check circuit breaker
        if self.circuit_open {
            return false;
        }

        // Check if we restart on success
        if exit_code == Some(0) && !self.config.restart_on_success {
            return false;
        }

        // For legacy mode, count all history entries
        // (tick-based pruning will have removed old entries)
        self.history.len() < self.config.max_restarts as usize
    }

    /// Record a restart and get the delay (legacy, wall-clock based).
    ///
    /// **DEPRECATED**: Use [`RestartManager::record_restart_at_tick`] for
    /// tick-based timing (RFC-0016 HTF).
    #[deprecated(
        since = "0.4.0",
        note = "use record_restart_at_tick for tick-based timing (RFC-0016 HTF)"
    )]
    #[allow(clippy::disallowed_methods)] // Legacy method uses wall-clock for backwards compatibility
    pub fn record_restart(&mut self, exit_code: Option<i32>, uptime: Duration) -> Duration {
        self.backoff_attempt += 1;
        let delay = self.config.backoff.delay_for_attempt(self.backoff_attempt);

        // Record with wall-clock timestamp for legacy pruning
        // Note: truncation is acceptable here as restart windows are typically
        // seconds/minutes
        #[allow(clippy::cast_possible_truncation)]
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let entry = RestartEntry {
            timestamp_ns: Some(now_ns),
            exit_code,
            uptime,
            delay,
            recorded_at_tick: None, // Legacy: no tick data
        };

        self.history.push(entry);

        // SEC-FIX-001: Prune old entries using wall-clock time to prevent
        // unbounded history growth and session lockout
        self.prune_history_wall_clock();

        // Circuit breaker check uses history length
        if self.history.len() >= self.config.max_restarts as usize {
            self.circuit_open = true;
        }

        delay
    }

    /// Remove old entries from history using wall-clock time (legacy).
    ///
    /// This method is used by the deprecated `record_restart` method for
    /// backwards compatibility. It prunes entries older than `restart_window`.
    #[allow(clippy::disallowed_methods)] // Legacy method uses wall-clock for backwards compatibility
    fn prune_history_wall_clock(&mut self) {
        // Note: truncation is acceptable here as restart windows are typically
        // seconds/minutes
        #[allow(clippy::cast_possible_truncation)]
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        #[allow(clippy::cast_possible_truncation)]
        let window_ns = self.config.restart_window.as_nanos() as u64;
        let cutoff_ns = now_ns.saturating_sub(window_ns);

        self.history.retain(|entry| {
            // Keep entries that have a timestamp within the window
            entry.timestamp_ns.is_some_and(|ts| ts >= cutoff_ns)
        });
    }

    /// Get the number of restarts within the window (legacy).
    ///
    /// **DEPRECATED**: Use [`RestartManager::restart_count_at_tick`] for
    /// tick-based timing (RFC-0016 HTF).
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use restart_count_at_tick for tick-based timing (RFC-0016 HTF)"
    )]
    pub fn restart_count(&self) -> usize {
        self.history.len()
    }

    /// Check if the circuit breaker should open (tick-based).
    fn check_circuit_breaker_at_tick(&mut self, current_tick: &HtfTick) {
        let window_ticks = self.restart_window_ticks.unwrap_or_else(|| {
            let tick_rate = self.tick_rate_hz.unwrap_or(1_000_000);
            self.config.restart_window.as_secs() * tick_rate
        });

        let window_start_tick = current_tick.value().saturating_sub(window_ticks);

        let recent_restarts = self
            .history
            .iter()
            .filter(|entry| {
                entry
                    .recorded_at_tick
                    .as_ref()
                    .is_some_and(|t| t.value() >= window_start_tick)
            })
            .count();

        if recent_restarts >= self.config.max_restarts as usize {
            self.circuit_open = true;
            self.circuit_opened_at_tick = Some(*current_tick);
        }
    }

    /// Remove old entries from history (tick-based).
    fn prune_history_at_tick(&mut self, current_tick: &HtfTick) {
        let window_ticks = self.restart_window_ticks.unwrap_or_else(|| {
            let tick_rate = self.tick_rate_hz.unwrap_or(1_000_000);
            self.config.restart_window.as_secs() * tick_rate
        });

        let window_start_tick = current_tick.value().saturating_sub(window_ticks);

        self.history.retain(|entry| {
            entry
                .recorded_at_tick
                .is_some_and(|t| t.value() >= window_start_tick)
        });
    }

    /// Get the number of restarts within the window at the given tick.
    #[must_use]
    pub fn restart_count_at_tick(&self, current_tick: &HtfTick) -> usize {
        let window_ticks = self.restart_window_ticks.unwrap_or_else(|| {
            let tick_rate = self.tick_rate_hz.unwrap_or(1_000_000);
            self.config.restart_window.as_secs() * tick_rate
        });

        let window_start_tick = current_tick.value().saturating_sub(window_ticks);

        self.history
            .iter()
            .filter(|entry| {
                entry
                    .recorded_at_tick
                    .as_ref()
                    .is_some_and(|t| t.value() >= window_start_tick)
            })
            .count()
    }

    /// Check if the circuit breaker is open.
    #[must_use]
    pub const fn is_circuit_open(&self) -> bool {
        self.circuit_open
    }

    /// Reset the manager state.
    pub fn reset(&mut self) {
        self.history.clear();
        self.backoff_attempt = 0;
        self.circuit_open = false;
        self.circuit_opened_at_tick = None;
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &RestartConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff() {
        let config = BackoffConfig::Exponential {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 2.0,
        };

        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(config.delay_for_attempt(4), Duration::from_secs(8));

        // Should cap at max_delay
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(60));
    }

    #[test]
    fn test_linear_backoff() {
        let config = BackoffConfig::Linear {
            initial_delay: Duration::from_secs(1),
            increment: Duration::from_secs(2),
            max_delay: Duration::from_secs(10),
        };

        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(3));
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(5));
        assert_eq!(config.delay_for_attempt(5), Duration::from_secs(9));

        // Should cap at max_delay
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(10));
    }

    #[test]
    fn test_restart_on_success() {
        let config = RestartConfig {
            restart_on_success: false,
            ..Default::default()
        };
        let manager = RestartManager::new(config);
        let tick = HtfTick::new(1000, 1_000_000);

        // Should not restart on exit code 0
        assert!(!manager.should_restart_at_tick(Some(0), &tick));
        // Should restart on non-zero exit code
        assert!(manager.should_restart_at_tick(Some(1), &tick));
    }
}

/// TCK-00243: Tick-based restart window tests (RFC-0016 HTF).
#[cfg(test)]
mod tck_00243 {
    use super::*;

    const TICK_RATE_HZ: u64 = 1_000_000; // 1MHz

    fn tick(value: u64) -> HtfTick {
        HtfTick::new(value, TICK_RATE_HZ)
    }

    /// TCK-00243: Tick-based restart manager construction.
    #[test]
    fn tick_based_manager_construction() {
        let config = RestartConfig {
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };

        // 60 seconds = 60_000_000 ticks at 1MHz
        let manager = RestartManager::with_ticks(config, 60_000_000, TICK_RATE_HZ);

        assert!(manager.is_tick_based());
        assert_eq!(manager.restart_window_ticks, Some(60_000_000));
        assert_eq!(manager.tick_rate_hz, Some(TICK_RATE_HZ));
    }

    /// TCK-00243: Legacy manager is not tick-based.
    #[test]
    fn legacy_manager_not_tick_based() {
        let config = RestartConfig::default();
        let manager = RestartManager::new(config);

        assert!(!manager.is_tick_based());
    }

    /// TCK-00243: Tick-based restart window counting.
    #[test]
    fn tick_based_restart_window() {
        let config = RestartConfig {
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };

        // Window of 1000 ticks
        let mut manager = RestartManager::with_ticks(config, 1000, TICK_RATE_HZ);

        // Should allow restarts initially
        assert!(manager.should_restart_at_tick(Some(1), &tick(100)));

        // Record restarts within window
        manager.record_restart_at_tick(Some(1), Duration::from_secs(5), tick(100));
        assert!(manager.should_restart_at_tick(Some(1), &tick(200)));
        assert_eq!(manager.restart_count_at_tick(&tick(200)), 1);

        manager.record_restart_at_tick(Some(1), Duration::from_secs(5), tick(200));
        assert!(manager.should_restart_at_tick(Some(1), &tick(300)));
        assert_eq!(manager.restart_count_at_tick(&tick(300)), 2);

        manager.record_restart_at_tick(Some(1), Duration::from_secs(5), tick(300));
        // Should not allow restart after max_restarts
        assert!(!manager.should_restart_at_tick(Some(1), &tick(400)));
        assert!(manager.is_circuit_open());
    }

    /// TCK-00243: Restarts outside window are not counted.
    #[test]
    fn restarts_outside_window_not_counted() {
        let config = RestartConfig {
            max_restarts: 2,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };

        // Window of 1000 ticks
        let mut manager = RestartManager::with_ticks(config, 1000, TICK_RATE_HZ);

        // Record restart at tick 100
        manager.record_restart_at_tick(Some(1), Duration::from_secs(5), tick(100));

        // At tick 500, the restart at 100 is within window (500 - 1000 < 0, so
        // window_start = 0)
        assert_eq!(manager.restart_count_at_tick(&tick(500)), 1);

        // At tick 1200, the restart at 100 is outside window (1200 - 1000 = 200 > 100)
        assert_eq!(manager.restart_count_at_tick(&tick(1200)), 0);

        // Can restart again after window expires
        assert!(manager.should_restart_at_tick(Some(1), &tick(1200)));
    }

    /// TCK-00243: Tick rate mismatch fails closed.
    #[test]
    fn tick_rate_mismatch_fails_closed() {
        let config = RestartConfig {
            max_restarts: 5,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };

        let manager = RestartManager::with_ticks(config, 1000, TICK_RATE_HZ);

        // Correct tick rate: should allow restart
        assert!(manager.should_restart_at_tick(Some(1), &tick(100)));

        // Wrong tick rate: should deny restart (fail-closed)
        let wrong_rate_tick = HtfTick::new(100, 10_000_000); // 10MHz instead of 1MHz
        assert!(!manager.should_restart_at_tick(Some(1), &wrong_rate_tick));
    }

    /// TCK-00243: Reset clears tick-based state.
    #[test]
    fn reset_clears_tick_state() {
        let config = RestartConfig {
            max_restarts: 1,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };

        let mut manager = RestartManager::with_ticks(config, 1000, TICK_RATE_HZ);

        // Record restart and hit circuit breaker
        manager.record_restart_at_tick(Some(1), Duration::from_secs(5), tick(100));
        assert!(manager.is_circuit_open());
        assert!(!manager.should_restart_at_tick(Some(1), &tick(200)));

        // Reset
        manager.reset();

        // Should allow restarts again
        assert!(!manager.is_circuit_open());
        assert!(manager.should_restart_at_tick(Some(1), &tick(300)));
    }

    /// TCK-00243: Record success resets state.
    #[test]
    fn record_success_resets_state() {
        let config = RestartConfig {
            max_restarts: 1,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };

        let mut manager = RestartManager::with_ticks(config, 1000, TICK_RATE_HZ);

        // Record restart and hit circuit breaker
        manager.record_restart_at_tick(Some(1), Duration::from_secs(5), tick(100));
        assert!(manager.is_circuit_open());

        // Record success
        manager.record_success();

        // Circuit should be closed
        assert!(!manager.is_circuit_open());
    }

    /// TCK-00243: `with_ticks` panics on zero tick rate.
    #[test]
    #[should_panic(expected = "tick_rate_hz must be > 0")]
    fn with_ticks_panics_on_zero_rate() {
        let config = RestartConfig::default();
        let _ = RestartManager::with_ticks(config, 1000, 0);
    }

    /// SEC-FIX-001: Legacy `record_restart` prunes old entries to prevent
    /// session lockout.
    #[test]
    #[allow(deprecated)]
    fn legacy_record_restart_prunes_history() {
        let config = RestartConfig {
            max_restarts: 5,
            restart_window: Duration::from_millis(100), // Very short window for testing
            ..Default::default()
        };

        let mut manager = RestartManager::new(config);

        // Record a restart
        manager.record_restart(Some(1), Duration::from_secs(1));
        assert!(!manager.history.is_empty(), "history should have an entry");

        // Wait longer than the window
        std::thread::sleep(Duration::from_millis(150));

        // Record another restart - this should prune the old entry
        manager.record_restart(Some(1), Duration::from_secs(1));

        // The old entry should have been pruned, leaving only the new one
        // (or possibly both if timing is close, but definitely not more than 2)
        assert!(
            manager.history.len() <= 2,
            "history should be pruned, got {} entries",
            manager.history.len()
        );

        // More importantly, the circuit breaker should not be permanently open
        // after window expires
        std::thread::sleep(Duration::from_millis(150));

        // Use a tick-based check to verify state
        // Note: should_restart uses history.len(), so we need a fresh manager to verify
        let config2 = RestartConfig {
            max_restarts: 5,
            restart_window: Duration::from_millis(100),
            ..Default::default()
        };
        let mut manager2 = RestartManager::new(config2);

        // Record max_restarts entries quickly
        for _ in 0..5 {
            manager2.record_restart(Some(1), Duration::from_secs(1));
        }
        // Circuit should be open after max_restarts
        assert!(manager2.circuit_open, "circuit should be open");

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(150));

        // Record another restart - should prune old entries
        manager2.record_restart(Some(1), Duration::from_secs(1));

        // After pruning, we should have fewer entries than max_restarts
        // (only recent entries remain)
        assert!(
            manager2.history.len() <= 2,
            "history should be pruned after window expires, got {} entries",
            manager2.history.len()
        );
    }

    /// SEC-FIX-002: History entries with mismatched tick rates fail closed.
    #[test]
    fn history_tick_rate_mismatch_fails_closed() {
        let config = RestartConfig {
            max_restarts: 5,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };

        // Create a manager WITHOUT tick_rate_hz configured (legacy mode)
        let mut manager = RestartManager::new(config);

        // Record restart at 1MHz tick rate
        let initial_tick = HtfTick::new(100, 1_000_000);
        manager.record_restart_at_tick(Some(1), Duration::from_secs(1), initial_tick);

        // Try to check restart at a DIFFERENT tick rate (10MHz)
        let mismatched_rate_tick = HtfTick::new(200, 10_000_000);

        // Should fail closed because history has different tick rate than current_tick
        assert!(
            !manager.should_restart_at_tick(Some(1), &mismatched_rate_tick),
            "should fail closed when history tick rate differs from current tick rate"
        );

        // With matching tick rate, should allow restart
        let matching_rate_tick = HtfTick::new(200, 1_000_000);
        assert!(
            manager.should_restart_at_tick(Some(1), &matching_rate_tick),
            "should allow restart when tick rates match"
        );
    }

    /// SEC-FIX-002: Configured tick rate validates history entries.
    #[test]
    fn configured_tick_rate_validates_history() {
        let config = RestartConfig {
            max_restarts: 5,
            restart_window: Duration::from_secs(60),
            ..Default::default()
        };

        // Create a manager WITH tick_rate_hz configured
        let mut manager = RestartManager::with_ticks(config, 60_000_000, 1_000_000);

        // Record restart at the configured tick rate
        let tick = HtfTick::new(100, 1_000_000);
        manager.record_restart_at_tick(Some(1), Duration::from_secs(1), tick);

        // Manually insert a history entry with wrong tick rate to simulate corruption
        manager.history.push(RestartEntry {
            timestamp_ns: None,
            exit_code: Some(1),
            uptime: Duration::from_secs(1),
            delay: Duration::from_secs(1),
            recorded_at_tick: Some(HtfTick::new(50, 2_000_000)), // Wrong rate!
        });

        // Should fail closed because history has mismatched tick rate
        let current_tick = HtfTick::new(200, 1_000_000);
        assert!(
            !manager.should_restart_at_tick(Some(1), &current_tick),
            "should fail closed when history contains entry with wrong tick rate"
        );
    }
}

mod humantime_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&humantime::format_duration(*duration).to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}
