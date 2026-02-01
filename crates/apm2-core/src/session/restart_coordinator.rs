//! Restart coordination for crashed sessions.
//!
//! This module provides the `RestartCoordinator` which wraps the low-level
//! `RestartManager` and integrates with entropy tracking and quarantine
//! management to make restart decisions.
//!
//! # Migration Note
//!
//! This module currently uses legacy (wall-clock based) restart manager methods
//! for backwards compatibility. These will be migrated to tick-based methods
//! when the calling code is updated to provide HTF tick values.

// Allow deprecated methods during migration period
#![allow(deprecated)]

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::crash::{CrashEvent, CrashType};
use super::entropy::EntropyTrackerSummary;
use super::quarantine::{ClockRegressionDefect, QuarantineEvaluation, QuarantineManager};
use crate::htf::HtfTick;
use crate::restart::{BackoffConfig, RestartConfig, RestartManager};

/// Coordinates restart decisions for a session.
///
/// This combines the restart manager's backoff/circuit-breaker logic with
/// entropy budget awareness and crash type classification.
pub struct RestartCoordinator {
    /// The underlying restart manager.
    restart_manager: RestartManager,
    /// Session ID this coordinator manages.
    session_id: String,
    /// Work ID associated with this session.
    work_id: String,
}

impl RestartCoordinator {
    /// Creates a new restart coordinator.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        work_id: impl Into<String>,
        config: RestartConfig,
    ) -> Self {
        Self {
            restart_manager: RestartManager::new(config),
            session_id: session_id.into(),
            work_id: work_id.into(),
        }
    }

    /// Creates a restart coordinator with default configuration.
    #[must_use]
    pub fn with_defaults(session_id: impl Into<String>, work_id: impl Into<String>) -> Self {
        Self::new(session_id, work_id, RestartConfig::default())
    }

    /// Returns the session ID.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the restart configuration.
    #[must_use]
    pub const fn config(&self) -> &RestartConfig {
        self.restart_manager.config()
    }

    /// Returns the current restart count within the window.
    ///
    /// **DEPRECATED**: Use [`RestartCoordinator::restart_count_at_tick`] for
    /// tick-based timing (RFC-0016 HTF).
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use restart_count_at_tick for tick-based timing (RFC-0016 HTF)"
    )]
    pub fn restart_count(&self) -> usize {
        self.restart_manager.restart_count()
    }

    /// Returns the current restart count within the tick-based window
    /// (RFC-0016 HTF compliant).
    ///
    /// This is the preferred method for getting restart counts. Tick-based
    /// timing is immune to wall-clock manipulation.
    #[must_use]
    pub fn restart_count_at_tick(&self, current_tick: &HtfTick) -> usize {
        self.restart_manager.restart_count_at_tick(current_tick)
    }

    /// Returns whether the circuit breaker is open.
    #[must_use]
    pub const fn is_circuit_open(&self) -> bool {
        self.restart_manager.is_circuit_open()
    }

    /// Determines whether a crashed session should be restarted.
    ///
    /// **DEPRECATED**: Use [`RestartCoordinator::should_restart_at_tick`] for
    /// tick-based timing (RFC-0016 HTF).
    ///
    /// Takes into account:
    /// - The crash type (some crashes shouldn't trigger restart)
    /// - The entropy budget (exhausted budget means no restart)
    /// - The restart manager's circuit breaker and limits
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use should_restart_at_tick for tick-based timing (RFC-0016 HTF)"
    )]
    pub fn should_restart(
        &self,
        crash_event: &CrashEvent,
        entropy_summary: Option<&EntropyTrackerSummary>,
    ) -> RestartDecision {
        // Check crash type first
        if !crash_event.crash_type.is_restartable() {
            return match &crash_event.crash_type {
                CrashType::CleanExit => RestartDecision::Terminate {
                    reason: TerminateReason::CleanExit,
                },
                CrashType::EntropyExceeded => RestartDecision::Terminate {
                    reason: TerminateReason::EntropyExhausted,
                },
                CrashType::Signal { signal, .. } => RestartDecision::Terminate {
                    reason: TerminateReason::NonRestartableSignal(*signal),
                },
                _ => RestartDecision::Terminate {
                    reason: TerminateReason::RestartLimitExceeded,
                },
            };
        }

        // Check entropy budget
        if let Some(summary) = entropy_summary {
            if summary.is_exceeded {
                return RestartDecision::Terminate {
                    reason: TerminateReason::EntropyExhausted,
                };
            }
        }

        // Check circuit breaker
        if self.restart_manager.is_circuit_open() {
            return RestartDecision::Terminate {
                reason: TerminateReason::CircuitBreakerOpen,
            };
        }

        // Check restart count limit
        let exit_code = crash_event.crash_type.exit_code();
        if !self.restart_manager.should_restart(exit_code) {
            return RestartDecision::Terminate {
                reason: TerminateReason::RestartLimitExceeded,
            };
        }

        // Calculate delay based on attempt number
        let attempt_number = crash_event.restart_count + 1;
        let delay = self
            .restart_manager
            .config()
            .backoff
            .delay_for_attempt(attempt_number);

        RestartDecision::Restart {
            delay,
            resume_cursor: crash_event.last_ledger_cursor,
            attempt_number,
        }
    }

    /// Determines whether a crashed session should be restarted using
    /// tick-based timing (RFC-0016 HTF compliant).
    ///
    /// This is the preferred method for making restart decisions. Tick-based
    /// timing is immune to wall-clock manipulation.
    ///
    /// Takes into account:
    /// - The crash type (some crashes shouldn't trigger restart)
    /// - The entropy budget (exhausted budget means no restart)
    /// - The restart manager's circuit breaker and limits
    ///
    /// # Arguments
    ///
    /// * `crash_event` - The crash event details
    /// * `entropy_summary` - Optional entropy tracker summary
    /// * `current_tick` - The current monotonic tick
    #[must_use]
    pub fn should_restart_at_tick(
        &self,
        crash_event: &CrashEvent,
        entropy_summary: Option<&EntropyTrackerSummary>,
        current_tick: &HtfTick,
    ) -> RestartDecision {
        // Check crash type first
        if !crash_event.crash_type.is_restartable() {
            return match &crash_event.crash_type {
                CrashType::CleanExit => RestartDecision::Terminate {
                    reason: TerminateReason::CleanExit,
                },
                CrashType::EntropyExceeded => RestartDecision::Terminate {
                    reason: TerminateReason::EntropyExhausted,
                },
                CrashType::Signal { signal, .. } => RestartDecision::Terminate {
                    reason: TerminateReason::NonRestartableSignal(*signal),
                },
                _ => RestartDecision::Terminate {
                    reason: TerminateReason::RestartLimitExceeded,
                },
            };
        }

        // Check entropy budget
        if let Some(summary) = entropy_summary {
            if summary.is_exceeded {
                return RestartDecision::Terminate {
                    reason: TerminateReason::EntropyExhausted,
                };
            }
        }

        // Check circuit breaker
        if self.restart_manager.is_circuit_open() {
            return RestartDecision::Terminate {
                reason: TerminateReason::CircuitBreakerOpen,
            };
        }

        // Check restart count limit using tick-based window
        let exit_code = crash_event.crash_type.exit_code();
        if !self
            .restart_manager
            .should_restart_at_tick(exit_code, current_tick)
        {
            return RestartDecision::Terminate {
                reason: TerminateReason::RestartLimitExceeded,
            };
        }

        // Calculate delay based on attempt number
        let attempt_number = crash_event.restart_count + 1;
        let delay = self
            .restart_manager
            .config()
            .backoff
            .delay_for_attempt(attempt_number);

        RestartDecision::Restart {
            delay,
            resume_cursor: crash_event.last_ledger_cursor,
            attempt_number,
        }
    }

    /// Records a restart and returns the backoff delay.
    ///
    /// **DEPRECATED**: Use [`RestartCoordinator::record_restart_at_tick`] for
    /// tick-based timing (RFC-0016 HTF).
    ///
    /// This should be called when a restart is actually performed.
    #[deprecated(
        since = "0.4.0",
        note = "use record_restart_at_tick for tick-based timing (RFC-0016 HTF)"
    )]
    pub fn record_restart(&mut self, uptime: Duration) -> Duration {
        let exit_code = None; // We don't track specific exit code at this level
        self.restart_manager.record_restart(exit_code, uptime)
    }

    /// Records a restart at the given tick and returns the backoff delay
    /// (RFC-0016 HTF compliant).
    ///
    /// This is the preferred method for recording restarts. Tick-based timing
    /// is immune to wall-clock manipulation.
    ///
    /// # Arguments
    ///
    /// * `uptime` - How long the session ran before crashing
    /// * `current_tick` - The current monotonic tick
    pub fn record_restart_at_tick(&mut self, uptime: Duration, current_tick: HtfTick) -> Duration {
        let exit_code = None; // We don't track specific exit code at this level
        self.restart_manager
            .record_restart_at_tick(exit_code, uptime, current_tick)
    }

    /// Records a successful run (uptime exceeded minimum).
    ///
    /// This resets the backoff counter and closes the circuit breaker.
    pub const fn record_success(&mut self) {
        self.restart_manager.record_success();
    }

    /// Resets the coordinator state.
    pub fn reset(&mut self) {
        self.restart_manager.reset();
    }

    /// Returns the backoff type as a string for protobuf encoding.
    #[must_use]
    pub const fn backoff_type_str(&self) -> &'static str {
        match self.restart_manager.config().backoff {
            BackoffConfig::Fixed { .. } => "FIXED",
            BackoffConfig::Exponential { .. } => "EXPONENTIAL",
            BackoffConfig::Linear { .. } => "LINEAR",
        }
    }

    /// Checks if a quarantine has expired, returning a defect on tick rate
    /// mismatch (RFC-0016 HTF, DD-HTF-0001).
    ///
    /// This method wraps
    /// [`QuarantineManager::check_quarantine_expired_at_tick`] to provide
    /// quarantine expiry checks with proper defect emission for
    /// observability.
    ///
    /// # SEC-HTF-003: Tick Rate Validation (FAIL-CLOSED)
    ///
    /// If tick rates differ between `current_tick` and `quarantine_until_tick`,
    /// returns `(false, Some(defect))` where:
    /// - `false` = quarantine NOT expired (fail-closed behavior)
    /// - `defect` = `ClockRegressionDefect` for emission to ledger/logs
    ///
    /// # Arguments
    ///
    /// * `quarantine_until_tick` - Tick when quarantine expires
    /// * `current_tick` - Current tick
    ///
    /// # Returns
    ///
    /// A tuple of `(is_expired, Option<ClockRegressionDefect>)`.
    #[must_use]
    pub fn check_quarantine_expired_at_tick(
        quarantine_until_tick: &HtfTick,
        current_tick: &HtfTick,
    ) -> (bool, Option<ClockRegressionDefect>) {
        QuarantineManager::check_quarantine_expired_at_tick(quarantine_until_tick, current_tick)
    }

    /// Determines whether a crashed session should be restarted, with
    /// quarantine support.
    ///
    /// **DEPRECATED**: Use
    /// [`RestartCoordinator::should_restart_with_quarantine_tick`]
    /// for RFC-0016 HTF compliant quarantine timing.
    ///
    /// This method uses wall-clock timestamps which can be manipulated.
    /// The tick-based variant is immune to wall-clock manipulation.
    ///
    /// Takes into account:
    /// - The crash type (some crashes shouldn't trigger restart)
    /// - The entropy budget (exhausted budget means no restart)
    /// - The restart manager's circuit breaker and limits
    /// - Quarantine thresholds (excessive violations, crash loops, etc.)
    ///
    /// # Arguments
    /// * `crash_event` - The crash event details
    /// * `entropy_summary` - Optional entropy tracker summary
    /// * `quarantine_manager` - The quarantine manager to evaluate thresholds
    /// * `current_time_ns` - Current timestamp in nanoseconds (for quarantine
    ///   duration)
    /// * `previous_quarantines` - How many times this session has been
    ///   quarantined
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use should_restart_with_quarantine_tick for tick-based timing (RFC-0016 HTF)"
    )]
    #[allow(deprecated)]
    pub fn should_restart_with_quarantine(
        &self,
        crash_event: &CrashEvent,
        entropy_summary: Option<&EntropyTrackerSummary>,
        quarantine_manager: &QuarantineManager,
        current_time_ns: u64,
        previous_quarantines: u32,
    ) -> RestartDecision {
        // Build quarantine evaluation from available state
        let mut eval = QuarantineEvaluation::new(&crash_event.session_id)
            .with_restarts(crash_event.restart_count);

        if let Some(summary) = entropy_summary {
            eval = eval
                .with_entropy(summary.budget, summary.consumed)
                .with_violations(summary.violation_count);
        }

        // Check for non-restartable signal
        if let CrashType::Signal {
            signal,
            signal_name,
        } = &crash_event.crash_type
        {
            if !super::crash::is_signal_restartable(*signal) {
                eval = eval.with_non_restartable_signal(*signal, signal_name);
            }
        }

        // Check if session should be quarantined
        if let Some(reason) = quarantine_manager.should_quarantine(&eval) {
            let duration = quarantine_manager.calculate_duration(previous_quarantines);
            let until = QuarantineManager::quarantine_until(current_time_ns, duration);
            return RestartDecision::Quarantine {
                reason: reason.to_string(),
                until,
                until_tick: None,
            };
        }

        // Fall back to regular restart decision
        self.should_restart(crash_event, entropy_summary)
    }

    /// Determines whether a crashed session should be restarted, with
    /// quarantine support using tick-based timing (RFC-0016 HTF compliant).
    ///
    /// This is the preferred method for making restart decisions as it
    /// integrates with the quarantine system and uses monotonic ticks
    /// that are immune to wall-clock manipulation.
    ///
    /// Takes into account:
    /// - The crash type (some crashes shouldn't trigger restart)
    /// - The entropy budget (exhausted budget means no restart)
    /// - The restart manager's circuit breaker and limits
    /// - Quarantine thresholds (excessive violations, crash loops, etc.)
    ///
    /// # Arguments
    /// * `crash_event` - The crash event details
    /// * `entropy_summary` - Optional entropy tracker summary
    /// * `quarantine_manager` - The quarantine manager to evaluate thresholds
    /// * `current_tick` - Current monotonic tick
    /// * `current_time_ns` - Current wall-clock timestamp (observational only)
    /// * `previous_quarantines` - How many times this session has been
    ///   quarantined
    ///
    /// # Returns
    ///
    /// A [`RestartDecision`] with tick-based quarantine timing when applicable.
    /// For quarantine decisions, both `until` (wall-clock, observational) and
    /// `until_tick` (authoritative) are populated.
    #[must_use]
    #[allow(deprecated)]
    pub fn should_restart_with_quarantine_tick(
        &self,
        crash_event: &CrashEvent,
        entropy_summary: Option<&EntropyTrackerSummary>,
        quarantine_manager: &QuarantineManager,
        current_tick: &HtfTick,
        current_time_ns: u64,
        previous_quarantines: u32,
    ) -> RestartDecision {
        // Build quarantine evaluation from available state
        let mut eval = QuarantineEvaluation::new(&crash_event.session_id)
            .with_restarts(crash_event.restart_count);

        if let Some(summary) = entropy_summary {
            eval = eval
                .with_entropy(summary.budget, summary.consumed)
                .with_violations(summary.violation_count);
        }

        // Check for non-restartable signal
        if let CrashType::Signal {
            signal,
            signal_name,
        } = &crash_event.crash_type
        {
            if !super::crash::is_signal_restartable(*signal) {
                eval = eval.with_non_restartable_signal(*signal, signal_name);
            }
        }

        // Check if session should be quarantined
        if let Some(reason) = quarantine_manager.should_quarantine(&eval) {
            // Calculate tick-based duration if config supports it, otherwise fall back
            let (until, until_tick) = quarantine_manager
                .calculate_duration_ticks(previous_quarantines)
                .map_or_else(
                    || {
                        // Legacy: wall-clock only
                        let duration = quarantine_manager.calculate_duration(previous_quarantines);
                        let until = QuarantineManager::quarantine_until(current_time_ns, duration);
                        (until, None)
                    },
                    |duration_ticks| {
                        // Tick-based: authoritative
                        let until_tick =
                            QuarantineManager::quarantine_until_tick(current_tick, duration_ticks);
                        // Wall-clock: observational only
                        let duration = quarantine_manager.calculate_duration(previous_quarantines);
                        let until = QuarantineManager::quarantine_until(current_time_ns, duration);
                        (until, Some(until_tick))
                    },
                );

            return RestartDecision::Quarantine {
                reason: reason.to_string(),
                until,
                until_tick,
            };
        }

        // Fall back to regular restart decision using tick-based method
        // SEC-HTF-003: Use tick-based restart decision to avoid mixed clock domains
        self.should_restart_at_tick(crash_event, entropy_summary, current_tick)
    }
}

/// The decision made by the restart coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartDecision {
    /// The session should be restarted.
    Restart {
        /// Delay before restarting.
        delay: Duration,
        /// Ledger cursor to resume from.
        resume_cursor: u64,
        /// Which restart attempt this is (1-based).
        attempt_number: u32,
    },
    /// The session should be terminated (no restart).
    Terminate {
        /// Reason for not restarting.
        reason: TerminateReason,
    },
    /// The session should be quarantined.
    Quarantine {
        /// Reason for quarantine.
        reason: String,
        /// OBSERVATIONAL - see RFC-0016 HTF; not authoritative for expiry.
        /// Unix timestamp (nanoseconds) until when quarantined.
        /// Retained for backwards compatibility and display purposes.
        until: u64,
        /// HTF: Monotonic tick until when quarantined (RFC-0016).
        /// Authoritative for expiry checks when present.
        /// If `None`, use wall-clock `until` for legacy quarantines.
        until_tick: Option<HtfTick>,
    },
}

impl RestartDecision {
    /// Returns whether this is a restart decision.
    #[must_use]
    pub const fn is_restart(&self) -> bool {
        matches!(self, Self::Restart { .. })
    }

    /// Returns whether this is a terminate decision.
    #[must_use]
    pub const fn is_terminate(&self) -> bool {
        matches!(self, Self::Terminate { .. })
    }

    /// Returns whether this is a quarantine decision.
    #[must_use]
    pub const fn is_quarantine(&self) -> bool {
        matches!(self, Self::Quarantine { .. })
    }
}

/// Reason for terminating a session without restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminateReason {
    /// Maximum restart attempts exceeded.
    RestartLimitExceeded,
    /// Circuit breaker is open due to too many restarts.
    CircuitBreakerOpen,
    /// Session entropy budget was exhausted.
    EntropyExhausted,
    /// Session exited cleanly (code 0).
    CleanExit,
    /// Session was killed by a non-restartable signal.
    NonRestartableSignal(i32),
}

impl TerminateReason {
    /// Returns a string code for this reason.
    #[must_use]
    pub const fn as_code(&self) -> &'static str {
        match self {
            Self::RestartLimitExceeded => "RESTART_LIMIT_EXCEEDED",
            Self::CircuitBreakerOpen => "CIRCUIT_BREAKER_OPEN",
            Self::EntropyExhausted => "ENTROPY_EXHAUSTED",
            Self::CleanExit => "CLEAN_EXIT",
            Self::NonRestartableSignal(_) => "NON_RESTARTABLE_SIGNAL",
        }
    }
}

impl std::fmt::Display for TerminateReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RestartLimitExceeded => write!(f, "restart limit exceeded"),
            Self::CircuitBreakerOpen => write!(f, "circuit breaker open"),
            Self::EntropyExhausted => write!(f, "entropy budget exhausted"),
            Self::CleanExit => write!(f, "clean exit"),
            Self::NonRestartableSignal(sig) => write!(f, "non-restartable signal {sig}"),
        }
    }
}

/// Finds the last ledger cursor for a session.
///
/// This scans the ledger for the most recent event from this session
/// and returns its cursor position.
#[must_use]
pub fn find_last_session_cursor(
    session_events: &[(u64, String)], // (cursor, session_id)
    session_id: &str,
) -> Option<u64> {
    session_events
        .iter()
        .filter(|(_, sid)| sid == session_id)
        .map(|(cursor, _)| *cursor)
        .max()
}

/// Gets the resume cursor for a session restart.
///
/// Returns the cursor of the last event for the session, or 0 if no events
/// exist.
#[must_use]
pub fn get_resume_cursor(
    session_events: &[(u64, String)], // (cursor, session_id)
    session_id: &str,
) -> u64 {
    find_last_session_cursor(session_events, session_id).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use nix::libc;

    use super::*;

    fn make_crash_event(crash_type: CrashType, restart_count: u32) -> CrashEvent {
        CrashEvent {
            session_id: "test-session".to_string(),
            work_id: "test-work".to_string(),
            crash_type,
            timestamp_ns: 1_000_000_000,
            last_ledger_cursor: 42,
            restart_count,
            uptime_ms: 5000,
        }
    }

    fn make_entropy_summary(is_exceeded: bool) -> EntropyTrackerSummary {
        EntropyTrackerSummary {
            session_id: "test-session".to_string(),
            budget: 1000,
            consumed: if is_exceeded { 1000 } else { 500 },
            remaining: if is_exceeded { 0 } else { 500 },
            is_exceeded,
            error_count: 0,
            violation_count: 0,
            stall_count: 0,
            timeout_count: 0,
        }
    }

    #[test]
    fn test_should_restart_error_exit() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        let entropy = make_entropy_summary(false);

        let decision = coordinator.should_restart(&crash, Some(&entropy));
        assert!(decision.is_restart());
        if let RestartDecision::Restart {
            attempt_number,
            resume_cursor,
            ..
        } = decision
        {
            assert_eq!(attempt_number, 1);
            assert_eq!(resume_cursor, 42);
        }
    }

    #[test]
    fn test_should_not_restart_clean_exit() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(CrashType::CleanExit, 0);

        let decision = coordinator.should_restart(&crash, None);
        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::CleanExit);
        }
    }

    #[test]
    fn test_should_not_restart_entropy_exceeded() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(CrashType::EntropyExceeded, 0);

        let decision = coordinator.should_restart(&crash, None);
        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::EntropyExhausted);
        }
    }

    #[test]
    fn test_should_not_restart_when_entropy_summary_exceeded() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        let entropy = make_entropy_summary(true);

        let decision = coordinator.should_restart(&crash, Some(&entropy));
        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::EntropyExhausted);
        }
    }

    #[test]
    fn test_should_not_restart_non_restartable_signal() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(
            CrashType::Signal {
                signal: libc::SIGSEGV,
                signal_name: "SIGSEGV".to_string(),
            },
            0,
        );

        let decision = coordinator.should_restart(&crash, None);
        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::NonRestartableSignal(libc::SIGSEGV));
        }
    }

    #[test]
    fn test_should_restart_restartable_signal() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(
            CrashType::Signal {
                signal: libc::SIGTERM,
                signal_name: "SIGTERM".to_string(),
            },
            0,
        );

        let decision = coordinator.should_restart(&crash, None);
        assert!(decision.is_restart());
    }

    #[test]
    fn test_should_restart_timeout() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(CrashType::Timeout, 0);

        let decision = coordinator.should_restart(&crash, None);
        assert!(decision.is_restart());
    }

    #[test]
    fn test_restart_limit_exceeded() {
        let config = RestartConfig {
            max_restarts: 2,
            ..Default::default()
        };
        let mut coordinator = RestartCoordinator::new("session-1", "work-1", config);

        // Record 2 restarts
        coordinator.record_restart(Duration::from_secs(1));
        coordinator.record_restart(Duration::from_secs(1));

        // Circuit should be open now
        assert!(coordinator.is_circuit_open());

        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 2);
        let decision = coordinator.should_restart(&crash, None);

        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::CircuitBreakerOpen);
        }
    }

    #[test]
    fn test_exponential_backoff_delay() {
        let config = RestartConfig {
            backoff: BackoffConfig::Exponential {
                initial_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(60),
                multiplier: 2.0,
            },
            ..Default::default()
        };
        let coordinator = RestartCoordinator::new("session-1", "work-1", config);

        // First restart (attempt 1)
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        if let RestartDecision::Restart { delay, .. } = coordinator.should_restart(&crash, None) {
            assert_eq!(delay, Duration::from_secs(1));
        }

        // Second restart (attempt 2)
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 1);
        if let RestartDecision::Restart { delay, .. } = coordinator.should_restart(&crash, None) {
            assert_eq!(delay, Duration::from_secs(2));
        }

        // Third restart (attempt 3)
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 2);
        if let RestartDecision::Restart { delay, .. } = coordinator.should_restart(&crash, None) {
            assert_eq!(delay, Duration::from_secs(4));
        }
    }

    #[test]
    fn test_backoff_type_str() {
        let fixed_config = RestartConfig {
            backoff: BackoffConfig::Fixed {
                delay: Duration::from_secs(5),
            },
            ..Default::default()
        };
        let fixed_coord = RestartCoordinator::new("s1", "w1", fixed_config);
        assert_eq!(fixed_coord.backoff_type_str(), "FIXED");

        let exp_config = RestartConfig {
            backoff: BackoffConfig::Exponential {
                initial_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(60),
                multiplier: 2.0,
            },
            ..Default::default()
        };
        let exp_coord = RestartCoordinator::new("s2", "w2", exp_config);
        assert_eq!(exp_coord.backoff_type_str(), "EXPONENTIAL");

        let linear_config = RestartConfig {
            backoff: BackoffConfig::Linear {
                initial_delay: Duration::from_secs(1),
                increment: Duration::from_secs(1),
                max_delay: Duration::from_secs(60),
            },
            ..Default::default()
        };
        let linear_coord = RestartCoordinator::new("s3", "w3", linear_config);
        assert_eq!(linear_coord.backoff_type_str(), "LINEAR");
    }

    #[test]
    fn test_find_last_session_cursor() {
        let events = vec![
            (1, "session-1".to_string()),
            (2, "session-2".to_string()),
            (3, "session-1".to_string()),
            (4, "session-2".to_string()),
            (5, "session-1".to_string()),
        ];

        assert_eq!(find_last_session_cursor(&events, "session-1"), Some(5));
        assert_eq!(find_last_session_cursor(&events, "session-2"), Some(4));
        assert_eq!(find_last_session_cursor(&events, "session-3"), None);
    }

    #[test]
    fn test_get_resume_cursor() {
        let events = vec![(10, "session-1".to_string()), (20, "session-1".to_string())];

        assert_eq!(get_resume_cursor(&events, "session-1"), 20);
        assert_eq!(get_resume_cursor(&events, "session-2"), 0);
    }

    #[test]
    fn test_terminate_reason_display() {
        assert_eq!(
            TerminateReason::RestartLimitExceeded.to_string(),
            "restart limit exceeded"
        );
        assert_eq!(
            TerminateReason::CircuitBreakerOpen.to_string(),
            "circuit breaker open"
        );
        assert_eq!(
            TerminateReason::EntropyExhausted.to_string(),
            "entropy budget exhausted"
        );
        assert_eq!(TerminateReason::CleanExit.to_string(), "clean exit");
        assert_eq!(
            TerminateReason::NonRestartableSignal(11).to_string(),
            "non-restartable signal 11"
        );
    }

    #[test]
    fn test_restart_decision_predicates() {
        let restart = RestartDecision::Restart {
            delay: Duration::from_secs(1),
            resume_cursor: 42,
            attempt_number: 1,
        };
        assert!(restart.is_restart());
        assert!(!restart.is_terminate());
        assert!(!restart.is_quarantine());

        let terminate = RestartDecision::Terminate {
            reason: TerminateReason::CleanExit,
        };
        assert!(!terminate.is_restart());
        assert!(terminate.is_terminate());
        assert!(!terminate.is_quarantine());

        let quarantine = RestartDecision::Quarantine {
            reason: "test".to_string(),
            until: 1000,
            until_tick: None,
        };
        assert!(!quarantine.is_restart());
        assert!(!quarantine.is_terminate());
        assert!(quarantine.is_quarantine());
    }

    #[test]
    fn test_record_success_resets_state() {
        let config = RestartConfig {
            max_restarts: 3,
            ..Default::default()
        };
        let mut coordinator = RestartCoordinator::new("session-1", "work-1", config);

        // Record some restarts
        coordinator.record_restart(Duration::from_secs(1));
        coordinator.record_restart(Duration::from_secs(1));
        assert_eq!(coordinator.restart_count(), 2);

        // Record success - should reset
        coordinator.record_success();
        // Note: restart_count may not reset immediately depending on implementation
        // but circuit breaker should be closed
        assert!(!coordinator.is_circuit_open());
    }

    // ========================================================================
    // Quarantine Integration Tests
    // ========================================================================

    #[test]
    #[allow(deprecated)]
    fn test_should_restart_with_quarantine_healthy_session() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let quarantine_manager = QuarantineManager::with_defaults();
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        let entropy = make_entropy_summary(false);

        let decision = coordinator.should_restart_with_quarantine(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            1_000_000_000,
            0,
        );

        // Should restart, not quarantine
        assert!(decision.is_restart());
    }

    #[test]
    #[allow(deprecated)]
    fn test_should_restart_with_quarantine_excessive_violations() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let quarantine_manager = QuarantineManager::with_defaults();
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);

        // Create entropy summary with violations at threshold
        let entropy = EntropyTrackerSummary {
            session_id: "test-session".to_string(),
            budget: 1000,
            consumed: 250,
            remaining: 750,
            is_exceeded: false,
            error_count: 0,
            violation_count: 5, // At threshold
            stall_count: 0,
            timeout_count: 0,
        };

        let decision = coordinator.should_restart_with_quarantine(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            1_000_000_000,
            0,
        );

        // Should quarantine due to excessive violations
        assert!(decision.is_quarantine());
        if let RestartDecision::Quarantine { reason, until, .. } = decision {
            assert!(reason.contains("violation"));
            assert!(until > 1_000_000_000);
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_should_restart_with_quarantine_crash_loop() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let quarantine_manager = QuarantineManager::with_defaults();
        // Crash with 5 restarts (at threshold)
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 5);
        let entropy = make_entropy_summary(false);

        let decision = coordinator.should_restart_with_quarantine(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            1_000_000_000,
            0,
        );

        // Should quarantine due to crash loop
        assert!(decision.is_quarantine());
        if let RestartDecision::Quarantine { reason, .. } = decision {
            assert!(reason.contains("crash loop"));
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_should_restart_with_quarantine_non_restartable_signal() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let quarantine_manager = QuarantineManager::with_defaults();
        let crash = make_crash_event(
            CrashType::Signal {
                signal: libc::SIGSEGV,
                signal_name: "SIGSEGV".to_string(),
            },
            0,
        );

        let decision = coordinator.should_restart_with_quarantine(
            &crash,
            None,
            &quarantine_manager,
            1_000_000_000,
            0,
        );

        // Should quarantine due to non-restartable signal
        assert!(decision.is_quarantine());
        if let RestartDecision::Quarantine { reason, .. } = decision {
            assert!(reason.contains("SIGSEGV"));
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_should_restart_with_quarantine_entropy_exceeded() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let quarantine_manager = QuarantineManager::with_defaults();
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        let entropy = make_entropy_summary(true); // Entropy exceeded

        let decision = coordinator.should_restart_with_quarantine(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            1_000_000_000,
            0,
        );

        // Should quarantine due to entropy exceeded
        assert!(decision.is_quarantine());
        if let RestartDecision::Quarantine { reason, .. } = decision {
            assert!(reason.contains("entropy"));
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_quarantine_duration_escalates() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let quarantine_manager = QuarantineManager::with_defaults();
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 5);
        let entropy = make_entropy_summary(false);
        let current_time = 1_000_000_000_000_000_000u64;

        // First quarantine (previous_quarantines = 0)
        let decision1 = coordinator.should_restart_with_quarantine(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            current_time,
            0,
        );
        let RestartDecision::Quarantine { until: until1, .. } = decision1 else {
            panic!("Expected quarantine");
        };

        // Second quarantine (previous_quarantines = 1)
        let decision2 = coordinator.should_restart_with_quarantine(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            current_time,
            1,
        );
        let RestartDecision::Quarantine { until: until2, .. } = decision2 else {
            panic!("Expected quarantine");
        };

        // Duration should double (exponential backoff with multiplier 2.0)
        let duration1 = until1 - current_time;
        let duration2 = until2 - current_time;
        assert_eq!(duration2, duration1 * 2);
    }

    #[test]
    #[allow(deprecated)]
    fn test_quarantine_disabled_for_entropy() {
        use super::super::quarantine::QuarantineConfig;

        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let config = QuarantineConfig {
            quarantine_on_entropy_exceeded: false,
            ..Default::default()
        };
        let quarantine_manager = QuarantineManager::new(config);
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        let entropy = make_entropy_summary(true);

        let decision = coordinator.should_restart_with_quarantine(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            1_000_000_000,
            0,
        );

        // Should NOT quarantine (disabled), but should terminate instead
        // because regular should_restart checks entropy
        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::EntropyExhausted);
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_quarantine_clean_exit_not_quarantined() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let quarantine_manager = QuarantineManager::with_defaults();
        let crash = make_crash_event(CrashType::CleanExit, 0);

        let decision = coordinator.should_restart_with_quarantine(
            &crash,
            None,
            &quarantine_manager,
            1_000_000_000,
            0,
        );

        // Clean exit should terminate, not quarantine
        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::CleanExit);
        }
    }

    // ========================================================================
    // Tick-based Quarantine Tests (TCK-00243)
    // ========================================================================

    #[test]
    fn tck_00243_tick_based_quarantine_returns_until_tick() {
        use super::super::quarantine::QuarantineConfig;

        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        // Create quarantine manager with tick-based config
        // with_ticks(base_duration_ticks, max_duration_ticks, tick_rate_hz, multiplier)
        let config = QuarantineConfig::with_ticks(
            60,   // base_duration_ticks
            3600, // max_duration_ticks
            1,    // tick_rate_hz (1 Hz for easy calculation)
            2.0,  // backoff_multiplier
        );
        let quarantine_manager = QuarantineManager::new(config);
        // Crash with 5 restarts to trigger crash loop quarantine
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 5);
        let entropy = make_entropy_summary(false);
        // HtfTick::new(value, tick_rate_hz)
        let current_tick = HtfTick::new(1000, 1);
        let current_time = 1_000_000_000_000_000_000u64;

        let decision = coordinator.should_restart_with_quarantine_tick(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            &current_tick,
            current_time,
            0,
        );

        // Should quarantine with tick-based until
        assert!(decision.is_quarantine());
        if let RestartDecision::Quarantine {
            reason,
            until,
            until_tick,
        } = decision
        {
            assert!(reason.contains("crash loop"));
            // Wall-clock until should be populated (observational)
            assert!(until > current_time);
            // Tick-based until should be populated (authoritative)
            assert!(until_tick.is_some());
            let tick = until_tick.unwrap();
            // Should be current_tick + base_duration_ticks (60)
            assert_eq!(tick.value(), 1000 + 60);
        }
    }

    #[test]
    fn tck_00243_tick_based_quarantine_escalates() {
        use super::super::quarantine::QuarantineConfig;

        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let config = QuarantineConfig::with_ticks(
            60,   // base_duration_ticks
            3600, // max_duration_ticks
            1,    // tick_rate_hz
            2.0,  // backoff_multiplier
        );
        let quarantine_manager = QuarantineManager::new(config);
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 5);
        let entropy = make_entropy_summary(false);
        let current_tick = HtfTick::new(1000, 1);
        let current_time = 1_000_000_000_000_000_000u64;

        // First quarantine (previous_quarantines = 0)
        let decision1 = coordinator.should_restart_with_quarantine_tick(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            &current_tick,
            current_time,
            0,
        );
        let RestartDecision::Quarantine {
            until_tick: until_tick1,
            ..
        } = decision1
        else {
            panic!("Expected quarantine");
        };
        let tick1 = until_tick1.expect("Expected until_tick");
        // Duration should be base (60 ticks)
        assert_eq!(tick1.value() - current_tick.value(), 60);

        // Second quarantine (previous_quarantines = 1)
        let decision2 = coordinator.should_restart_with_quarantine_tick(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            &current_tick,
            current_time,
            1,
        );
        let RestartDecision::Quarantine {
            until_tick: until_tick2,
            ..
        } = decision2
        else {
            panic!("Expected quarantine");
        };
        let tick2 = until_tick2.expect("Expected until_tick");
        // Duration should be doubled (120 ticks)
        assert_eq!(tick2.value() - current_tick.value(), 120);

        // Third quarantine (previous_quarantines = 2)
        let decision3 = coordinator.should_restart_with_quarantine_tick(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            &current_tick,
            current_time,
            2,
        );
        let RestartDecision::Quarantine {
            until_tick: until_tick3,
            ..
        } = decision3
        else {
            panic!("Expected quarantine");
        };
        let tick3 = until_tick3.expect("Expected until_tick");
        // Duration should be quadrupled (240 ticks)
        assert_eq!(tick3.value() - current_tick.value(), 240);
    }

    #[test]
    fn tck_00243_legacy_config_returns_none_until_tick() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        // Default quarantine manager has no tick config
        let quarantine_manager = QuarantineManager::with_defaults();
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 5);
        let entropy = make_entropy_summary(false);
        let current_tick = HtfTick::new(1000, 1);
        let current_time = 1_000_000_000_000_000_000u64;

        let decision = coordinator.should_restart_with_quarantine_tick(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            &current_tick,
            current_time,
            0,
        );

        // Should quarantine but with no tick (legacy mode)
        assert!(decision.is_quarantine());
        if let RestartDecision::Quarantine { until_tick, .. } = decision {
            // Legacy config has no tick-based duration
            assert!(until_tick.is_none());
        }
    }

    #[test]
    fn tck_00243_tick_quarantine_no_wall_time_dependence() {
        use super::super::quarantine::QuarantineConfig;

        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let config = QuarantineConfig::with_ticks(
            60,   // base_duration_ticks
            3600, // max_duration_ticks
            1,    // tick_rate_hz
            2.0,  // backoff_multiplier
        );
        let quarantine_manager = QuarantineManager::new(config);
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 5);
        let entropy = make_entropy_summary(false);
        let current_tick = HtfTick::new(1000, 1);

        // Call with different wall clock times
        let decision1 = coordinator.should_restart_with_quarantine_tick(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            &current_tick,
            1_000_000_000_000_000_000u64, // Time A
            0,
        );

        let decision2 = coordinator.should_restart_with_quarantine_tick(
            &crash,
            Some(&entropy),
            &quarantine_manager,
            &current_tick,
            9_000_000_000_000_000_000u64, // Time B (very different)
            0,
        );

        // Both should have the same until_tick (tick-based is deterministic)
        let RestartDecision::Quarantine {
            until_tick: tick1, ..
        } = decision1
        else {
            panic!("Expected quarantine");
        };
        let RestartDecision::Quarantine {
            until_tick: tick2, ..
        } = decision2
        else {
            panic!("Expected quarantine");
        };

        // Tick values should be identical regardless of wall time
        assert_eq!(tick1, tick2);
        assert_eq!(tick1.unwrap().value(), 1060); // current_tick + 60
    }

    // ========================================================================
    // Tick-based RestartCoordinator Methods (TCK-00243 Security Fixes)
    // ========================================================================

    #[test]
    fn tck_00243_should_restart_at_tick_allows_restart() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        let entropy = make_entropy_summary(false);
        let current_tick = HtfTick::new(1000, 1_000_000);

        let decision = coordinator.should_restart_at_tick(&crash, Some(&entropy), &current_tick);

        assert!(decision.is_restart());
        if let RestartDecision::Restart {
            attempt_number,
            resume_cursor,
            ..
        } = decision
        {
            assert_eq!(attempt_number, 1);
            assert_eq!(resume_cursor, 42);
        }
    }

    #[test]
    fn tck_00243_should_restart_at_tick_denies_clean_exit() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(CrashType::CleanExit, 0);
        let current_tick = HtfTick::new(1000, 1_000_000);

        let decision = coordinator.should_restart_at_tick(&crash, None, &current_tick);

        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::CleanExit);
        }
    }

    #[test]
    fn tck_00243_should_restart_at_tick_denies_entropy_exceeded() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        let entropy = make_entropy_summary(true); // Exceeded
        let current_tick = HtfTick::new(1000, 1_000_000);

        let decision = coordinator.should_restart_at_tick(&crash, Some(&entropy), &current_tick);

        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::EntropyExhausted);
        }
    }

    #[test]
    fn tck_00243_should_restart_at_tick_uses_tick_based_window() {
        use crate::restart::RestartConfig;

        let config = RestartConfig {
            max_restarts: 2,
            ..Default::default()
        };
        let mut coordinator = RestartCoordinator::new("session-1", "work-1", config);
        let crash = make_crash_event(CrashType::ErrorExit { exit_code: 1 }, 0);
        let tick1 = HtfTick::new(1000, 1_000_000);
        let tick2 = HtfTick::new(2000, 1_000_000);

        // Record 2 restarts using tick-based method
        coordinator.record_restart_at_tick(Duration::from_secs(1), tick1);
        coordinator.record_restart_at_tick(Duration::from_secs(1), tick2);

        // Circuit should be open now
        assert!(coordinator.is_circuit_open());

        let current_tick = HtfTick::new(3000, 1_000_000);
        let decision = coordinator.should_restart_at_tick(&crash, None, &current_tick);

        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::CircuitBreakerOpen);
        }
    }

    #[test]
    fn tck_00243_record_restart_at_tick_returns_delay() {
        let mut coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let current_tick = HtfTick::new(1000, 1_000_000);

        let delay = coordinator.record_restart_at_tick(Duration::from_secs(5), current_tick);

        // Default exponential backoff: first attempt should be 1 second
        assert_eq!(delay, Duration::from_secs(1));
    }

    #[test]
    fn tck_00243_restart_count_at_tick_returns_correct_count() {
        let mut coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let tick1 = HtfTick::new(1000, 1_000_000);
        let tick2 = HtfTick::new(2000, 1_000_000);

        assert_eq!(coordinator.restart_count_at_tick(&tick1), 0);

        coordinator.record_restart_at_tick(Duration::from_secs(1), tick1);
        assert_eq!(coordinator.restart_count_at_tick(&tick2), 1);

        coordinator.record_restart_at_tick(Duration::from_secs(1), tick2);
        let tick3 = HtfTick::new(3000, 1_000_000);
        assert_eq!(coordinator.restart_count_at_tick(&tick3), 2);
    }

    #[test]
    fn tck_00243_check_quarantine_expired_at_tick_no_defect() {
        let quarantine_until = HtfTick::new(2000, 1_000_000);
        let current_tick = HtfTick::new(1500, 1_000_000);

        let (is_expired, defect) =
            RestartCoordinator::check_quarantine_expired_at_tick(&quarantine_until, &current_tick);

        assert!(!is_expired);
        assert!(defect.is_none());
    }

    #[test]
    fn tck_00243_check_quarantine_expired_at_tick_expired() {
        let quarantine_until = HtfTick::new(2000, 1_000_000);
        let current_tick = HtfTick::new(2500, 1_000_000);

        let (is_expired, defect) =
            RestartCoordinator::check_quarantine_expired_at_tick(&quarantine_until, &current_tick);

        assert!(is_expired);
        assert!(defect.is_none());
    }

    #[test]
    fn tck_00243_check_quarantine_expired_at_tick_rate_mismatch_emits_defect() {
        let quarantine_until = HtfTick::new(2000, 1_000_000); // 1MHz
        let current_tick = HtfTick::new(1500, 10_000_000); // 10MHz (mismatch!)

        let (is_expired, defect) =
            RestartCoordinator::check_quarantine_expired_at_tick(&quarantine_until, &current_tick);

        // Fail-closed: quarantine should NOT be expired
        assert!(!is_expired);

        // Defect should be present
        assert!(defect.is_some());
        let defect = defect.unwrap();
        assert_eq!(defect.code, "CLOCK_REGRESSION");
        assert_eq!(defect.current_tick_rate_hz, 10_000_000);
        assert_eq!(defect.expected_tick_rate_hz, 1_000_000);
        assert!(defect.fail_closed_applied);
    }

    #[test]
    fn tck_00243_should_restart_at_tick_denies_non_restartable_signal() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(
            CrashType::Signal {
                signal: libc::SIGSEGV,
                signal_name: "SIGSEGV".to_string(),
            },
            0,
        );
        let current_tick = HtfTick::new(1000, 1_000_000);

        let decision = coordinator.should_restart_at_tick(&crash, None, &current_tick);

        assert!(decision.is_terminate());
        if let RestartDecision::Terminate { reason } = decision {
            assert_eq!(reason, TerminateReason::NonRestartableSignal(libc::SIGSEGV));
        }
    }

    #[test]
    fn tck_00243_should_restart_at_tick_allows_restartable_signal() {
        let coordinator = RestartCoordinator::with_defaults("session-1", "work-1");
        let crash = make_crash_event(
            CrashType::Signal {
                signal: libc::SIGTERM,
                signal_name: "SIGTERM".to_string(),
            },
            0,
        );
        let current_tick = HtfTick::new(1000, 1_000_000);

        let decision = coordinator.should_restart_at_tick(&crash, None, &current_tick);

        assert!(decision.is_restart());
    }
}
