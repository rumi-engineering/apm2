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

/// Configuration for quarantine behavior.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineConfig {
    /// Base duration for the first quarantine.
    pub base_duration: Duration,

    /// Maximum quarantine duration.
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
        }
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

    /// Checks if a quarantine has expired based on current time.
    ///
    /// # Arguments
    /// * `quarantine_until` - Unix timestamp (nanoseconds) when quarantine
    ///   expires
    /// * `current_time_ns` - Current Unix timestamp (nanoseconds)
    #[must_use]
    pub const fn is_quarantine_expired(quarantine_until: u64, current_time_ns: u64) -> bool {
        current_time_ns >= quarantine_until
    }

    /// Calculates the `quarantine_until` timestamp.
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
    pub fn quarantine_until(current_time_ns: u64, duration: Duration) -> u64 {
        let duration_ns = duration.as_nanos() as u64;
        current_time_ns.saturating_add(duration_ns)
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineInfo {
    /// Session ID.
    pub session_id: String,

    /// Reason for quarantine.
    pub reason: QuarantineReason,

    /// Timestamp when quarantine started (nanoseconds since epoch).
    pub quarantined_at: u64,

    /// Timestamp when quarantine expires (nanoseconds since epoch).
    pub quarantine_until: u64,

    /// How many times this session has been quarantined.
    pub quarantine_count: u32,
}

impl QuarantineInfo {
    /// Creates a new quarantine info.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        reason: QuarantineReason,
        quarantined_at: u64,
        duration: Duration,
        quarantine_count: u32,
    ) -> Self {
        let quarantine_until = QuarantineManager::quarantine_until(quarantined_at, duration);
        Self {
            session_id: session_id.into(),
            reason,
            quarantined_at,
            quarantine_until,
            quarantine_count,
        }
    }

    /// Checks if this quarantine has expired.
    #[must_use]
    pub const fn is_expired(&self, current_time_ns: u64) -> bool {
        QuarantineManager::is_quarantine_expired(self.quarantine_until, current_time_ns)
    }

    /// Returns the remaining quarantine duration.
    ///
    /// Returns `None` if quarantine has expired.
    #[must_use]
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
    fn test_quarantine_until() {
        let current = 1_000_000_000_000_000_000u64; // 1 second in nanos
        let duration = Duration::from_secs(300);
        let until = QuarantineManager::quarantine_until(current, duration);
        assert_eq!(until, current + 300_000_000_000);
    }

    #[test]
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
