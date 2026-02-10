//! Bounded restart policy with reason-coded transitions.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum allowed restart attempts in [`RestartPolicyConfig::max_restarts`].
pub const MAX_RESTARTS_LIMIT: u32 = 1000;

/// Maximum allowed circuit breaker failures.
pub const MAX_CIRCUIT_BREAKER_FAILURES: u32 = 100;

/// Validation error for [`RestartPolicyConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RestartPolicyConfigError {
    /// `max_restarts` exceeds the configured hard limit.
    #[error("max_restarts exceeds allowed limit: {actual} > {limit}")]
    MaxRestartsExceedsLimit {
        /// Requested `max_restarts` value.
        actual: u32,
        /// Maximum allowed value.
        limit: u32,
    },
    /// `circuit_breaker_max_failures` exceeds the configured hard limit.
    #[error("circuit_breaker_max_failures exceeds allowed limit: {actual} > {limit}")]
    CircuitBreakerFailuresExceedsLimit {
        /// Requested `circuit_breaker_max_failures` value.
        actual: u32,
        /// Maximum allowed value.
        limit: u32,
    },
}

/// Terminal reason taxonomy for launch lifecycle outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalReason {
    /// Clean exit (exit code 0).
    CleanExit,
    /// Maximum restart attempts exceeded within window.
    RestartLimitExceeded,
    /// Circuit breaker opened due to crash loop.
    CircuitBreakerOpen,
    /// Stall timeout exceeded without recovery.
    StallTimeout,
    /// Operator-initiated shutdown.
    OperatorShutdown,
    /// Unrecoverable error (non-restartable signal).
    UnrecoverableError,
}

/// Restart decision from the bounded restart controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartDecision {
    /// Allow restart with the given attempt number.
    Allow {
        /// 1-based restart attempt number in the current window.
        attempt: u32,
    },
    /// Deny restart — terminal reason given.
    Deny {
        /// Terminal reason for denying further restarts.
        reason: TerminalReason,
    },
}

/// Configuration for the bounded restart policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicyConfig {
    /// Maximum restart attempts within the window.
    pub max_restarts: u32,
    /// Window size in HTF ticks.
    pub window_ticks: u64,
    /// Circuit breaker threshold (rapid failures within this many ticks).
    pub circuit_breaker_threshold_ticks: u64,
    /// Circuit breaker max rapid failures.
    pub circuit_breaker_max_failures: u32,
    /// Stall timeout in HTF ticks.
    pub stall_timeout_ticks: u64,
}

impl RestartPolicyConfig {
    /// Validates policy bounds at configuration admission time.
    ///
    /// # Errors
    ///
    /// Returns [`RestartPolicyConfigError`] when a field exceeds the allowed
    /// guardrail limits.
    pub const fn validate(&self) -> Result<(), RestartPolicyConfigError> {
        if self.max_restarts > MAX_RESTARTS_LIMIT {
            return Err(RestartPolicyConfigError::MaxRestartsExceedsLimit {
                actual: self.max_restarts,
                limit: MAX_RESTARTS_LIMIT,
            });
        }

        if self.circuit_breaker_max_failures > MAX_CIRCUIT_BREAKER_FAILURES {
            return Err(
                RestartPolicyConfigError::CircuitBreakerFailuresExceedsLimit {
                    actual: self.circuit_breaker_max_failures,
                    limit: MAX_CIRCUIT_BREAKER_FAILURES,
                },
            );
        }

        Ok(())
    }
}

/// Bounded restart controller state.
#[derive(Debug, Clone)]
pub struct RestartController {
    config: RestartPolicyConfig,
    /// Restart timestamps (HTF ticks).
    restart_ticks: Vec<u64>,
    /// Current circuit breaker state.
    circuit_breaker_open: bool,
    /// Terminal reason when the controller transitions to stop.
    terminal_reason: Option<TerminalReason>,
}

impl RestartController {
    /// Creates a new restart controller for the provided policy configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RestartPolicyConfigError`] when `config` violates admission
    /// limits.
    pub fn new(config: RestartPolicyConfig) -> Result<Self, RestartPolicyConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            restart_ticks: Vec::new(),
            circuit_breaker_open: false,
            terminal_reason: None,
        })
    }

    /// Record a restart and return the decision.
    ///
    /// Fail-closed: if state is ambiguous, deny.
    #[must_use]
    pub fn record_restart(&mut self, current_tick: u64) -> RestartDecision {
        if let Some(reason) = self.terminal_reason {
            return RestartDecision::Deny { reason };
        }

        self.prune_window(current_tick);

        if self.would_open_circuit_breaker(current_tick) {
            self.circuit_breaker_open = true;
            self.terminal_reason = Some(TerminalReason::CircuitBreakerOpen);
            return RestartDecision::Deny {
                reason: TerminalReason::CircuitBreakerOpen,
            };
        }

        let next_attempt = self.next_attempt_number();
        if next_attempt > self.config.max_restarts {
            self.terminal_reason = Some(TerminalReason::RestartLimitExceeded);
            return RestartDecision::Deny {
                reason: TerminalReason::RestartLimitExceeded,
            };
        }

        self.restart_ticks.push(current_tick);
        RestartDecision::Allow {
            attempt: next_attempt,
        }
    }

    /// Marks the lifecycle as terminal with a reason-coded transition.
    ///
    /// This is used for non-restart transitions such as clean exit or
    /// operator shutdown.
    #[must_use]
    pub const fn record_terminal(&mut self, reason: TerminalReason) -> RestartDecision {
        self.terminal_reason = Some(reason);
        RestartDecision::Deny { reason }
    }

    /// Check if stall timeout has been exceeded.
    #[must_use]
    pub const fn check_stall(&self, last_heartbeat_tick: u64, current_tick: u64) -> bool {
        current_tick.saturating_sub(last_heartbeat_tick) >= self.config.stall_timeout_ticks
    }

    /// Get the terminal reason if the controller has decided to stop.
    #[must_use]
    pub const fn terminal_reason(&self) -> Option<TerminalReason> {
        self.terminal_reason
    }

    fn prune_window(&mut self, current_tick: u64) {
        let window_start = current_tick.saturating_sub(self.config.window_ticks);
        self.restart_ticks.retain(|tick| *tick >= window_start);
    }

    fn would_open_circuit_breaker(&self, current_tick: u64) -> bool {
        if self.circuit_breaker_open {
            return true;
        }

        if self.config.circuit_breaker_max_failures == 0 {
            return true;
        }

        let threshold_start =
            current_tick.saturating_sub(self.config.circuit_breaker_threshold_ticks);
        let rapid_failures = self
            .restart_ticks
            .iter()
            .filter(|&&tick| tick >= threshold_start)
            .count();
        let projected_failures = u32::try_from(rapid_failures)
            .unwrap_or(u32::MAX)
            .saturating_add(1);

        projected_failures >= self.config.circuit_breaker_max_failures
    }

    fn next_attempt_number(&self) -> u32 {
        u32::try_from(self.restart_ticks.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> RestartPolicyConfig {
        RestartPolicyConfig {
            max_restarts: 3,
            window_ticks: 50,
            circuit_breaker_threshold_ticks: 5,
            circuit_breaker_max_failures: 3,
            stall_timeout_ticks: 10,
        }
    }

    #[test]
    fn test_too_many_restarts_rejected() {
        let config = RestartPolicyConfig {
            max_restarts: MAX_RESTARTS_LIMIT + 1,
            ..valid_config()
        };

        let error =
            RestartController::new(config).expect_err("config above max_restarts must fail");
        assert_eq!(
            error,
            RestartPolicyConfigError::MaxRestartsExceedsLimit {
                actual: MAX_RESTARTS_LIMIT + 1,
                limit: MAX_RESTARTS_LIMIT
            }
        );
    }
}
