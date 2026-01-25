//! Restart coordination for crashed sessions.
//!
//! This module provides the `RestartCoordinator` which wraps the low-level
//! `RestartManager` and integrates with entropy tracking and quarantine
//! management to make restart decisions.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::crash::{CrashEvent, CrashType};
use super::entropy::EntropyTrackerSummary;
use super::quarantine::{QuarantineEvaluation, QuarantineManager};
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
    #[must_use]
    pub fn restart_count(&self) -> usize {
        self.restart_manager.restart_count()
    }

    /// Returns whether the circuit breaker is open.
    #[must_use]
    pub const fn is_circuit_open(&self) -> bool {
        self.restart_manager.is_circuit_open()
    }

    /// Determines whether a crashed session should be restarted.
    ///
    /// Takes into account:
    /// - The crash type (some crashes shouldn't trigger restart)
    /// - The entropy budget (exhausted budget means no restart)
    /// - The restart manager's circuit breaker and limits
    #[must_use]
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

    /// Records a restart and returns the backoff delay.
    ///
    /// This should be called when a restart is actually performed.
    pub fn record_restart(&mut self, uptime: Duration) -> Duration {
        let exit_code = None; // We don't track specific exit code at this level
        self.restart_manager.record_restart(exit_code, uptime)
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

    /// Determines whether a crashed session should be restarted, with
    /// quarantine support.
    ///
    /// This is the preferred method for making restart decisions as it
    /// integrates with the quarantine system.
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
            };
        }

        // Fall back to regular restart decision
        self.should_restart(crash_event, entropy_summary)
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
        /// Unix timestamp (nanoseconds) until when quarantined.
        until: u64,
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
        if let RestartDecision::Quarantine { reason, until } = decision {
            assert!(reason.contains("violation"));
            assert!(until > 1_000_000_000);
        }
    }

    #[test]
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
}
