//! Launch liveness heartbeat and bounded restart policy primitives (RFC-0020).
//!
//! This module defines deterministic heartbeat receipts, bounded restart
//! decisions, and fail-closed authoritative gate checks.

use serde::{Deserialize, Deserializer, Serialize, de};

pub mod heartbeat;
pub mod restart_policy;

pub use heartbeat::{
    HealthVerdict, LivenessHeartbeatReceiptV1, MAX_HEARTBEAT_DETAIL_LENGTH, MAX_RUN_ID_LENGTH,
};
pub use restart_policy::{
    MAX_CIRCUIT_BREAKER_FAILURES, MAX_RESTARTS_LIMIT, RestartController, RestartDecision,
    RestartPolicyConfig, RestartPolicyConfigError, TerminalReason,
};

/// Maximum length for liveness gate denial detail.
pub const MAX_LIVENESS_DENIAL_DETAIL_LENGTH: usize = MAX_HEARTBEAT_DETAIL_LENGTH;

/// Check if liveness state allows authoritative progression.
///
/// Fail-closed: `Ambiguous`/`Stalled`/`Crashed` verdicts, stale heartbeats, and
/// restart-limit violations deny progression.
///
/// # Errors
///
/// Returns [`LivenessGateDenial`] when progression must be denied.
pub fn check_liveness_for_progression(
    latest_heartbeat: &LivenessHeartbeatReceiptV1,
    current_tick: u64,
    max_heartbeat_age_ticks: u64,
) -> Result<(), LivenessGateDenial> {
    if !latest_heartbeat.has_valid_bounds() {
        return Err(LivenessGateDenial::new(
            LivenessDenialReason::AmbiguousState,
            "liveness heartbeat contains out-of-bounds string fields",
        ));
    }

    match latest_heartbeat.health_verdict {
        HealthVerdict::Healthy => {},
        HealthVerdict::Stalled => {
            return Err(LivenessGateDenial::new(
                LivenessDenialReason::UnhealthyVerdict,
                "health verdict is stalled",
            ));
        },
        HealthVerdict::Crashed => {
            return Err(LivenessGateDenial::new(
                LivenessDenialReason::UnhealthyVerdict,
                "health verdict is crashed",
            ));
        },
        HealthVerdict::Ambiguous => {
            return Err(LivenessGateDenial::new(
                LivenessDenialReason::AmbiguousState,
                "health verdict is ambiguous",
            ));
        },
    }

    let heartbeat_age = current_tick.saturating_sub(latest_heartbeat.emitted_at_tick);
    if heartbeat_age > max_heartbeat_age_ticks {
        return Err(LivenessGateDenial::new(
            LivenessDenialReason::StaleHeartbeat,
            format!(
                "heartbeat age {heartbeat_age} exceeds max age {max_heartbeat_age_ticks} ticks"
            ),
        ));
    }

    if latest_heartbeat.restart_count > latest_heartbeat.max_restarts {
        return Err(LivenessGateDenial::new(
            LivenessDenialReason::RestartLimitExceeded,
            format!(
                "restart count {} exceeds max restarts {}",
                latest_heartbeat.restart_count, latest_heartbeat.max_restarts
            ),
        ));
    }

    Ok(())
}

/// Structured denial output for liveness gate failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivenessGateDenial {
    /// Reason code for the denial.
    pub reason: LivenessDenialReason,
    /// Human-readable denial detail (bounded).
    #[serde(deserialize_with = "deserialize_denial_detail")]
    pub detail: String,
}

impl LivenessGateDenial {
    /// Creates a bounded denial payload.
    #[must_use]
    pub fn new(reason: LivenessDenialReason, detail: impl Into<String>) -> Self {
        let mut detail = detail.into();
        if detail.len() > MAX_LIVENESS_DENIAL_DETAIL_LENGTH {
            let mut truncation_index = MAX_LIVENESS_DENIAL_DETAIL_LENGTH;
            while !detail.is_char_boundary(truncation_index) {
                truncation_index = truncation_index.saturating_sub(1);
            }
            detail.truncate(truncation_index);
        }
        Self { reason, detail }
    }
}

/// Liveness-based denial taxonomy for authoritative gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivenessDenialReason {
    /// Health verdict is not `Healthy`.
    UnhealthyVerdict,
    /// Heartbeat is too old (exceeds `max_heartbeat_age_ticks`).
    StaleHeartbeat,
    /// Restart limit exceeded.
    RestartLimitExceeded,
    /// Ambiguous state — cannot determine liveness.
    AmbiguousState,
}

fn deserialize_denial_detail<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let detail = String::deserialize(deserializer)?;
    if detail.len() > MAX_LIVENESS_DENIAL_DETAIL_LENGTH {
        return Err(de::Error::custom(format!(
            "detail exceeds maximum length ({} > {MAX_LIVENESS_DENIAL_DETAIL_LENGTH})",
            detail.len()
        )));
    }
    Ok(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_heartbeat(health_verdict: HealthVerdict) -> LivenessHeartbeatReceiptV1 {
        LivenessHeartbeatReceiptV1 {
            run_id: "run-123".to_string(),
            episode_id: [1; 32],
            emitted_at_tick: 100,
            time_envelope_ref: [2; 32],
            health_verdict,
            restart_count: 0,
            max_restarts: 3,
            uptime_ms: 42_000,
            detail: Some("heartbeat ok".to_string()),
        }
    }

    fn sample_restart_config() -> RestartPolicyConfig {
        RestartPolicyConfig {
            max_restarts: 3,
            window_ticks: 20,
            circuit_breaker_threshold_ticks: 5,
            circuit_breaker_max_failures: 4,
            stall_timeout_ticks: 8,
        }
    }

    #[test]
    fn test_healthy_heartbeat_allows_progression() {
        let heartbeat = sample_heartbeat(HealthVerdict::Healthy);
        let result = check_liveness_for_progression(&heartbeat, 105, 10);
        assert!(result.is_ok());
    }

    #[test]
    fn test_stalled_verdict_denies_progression() {
        let heartbeat = sample_heartbeat(HealthVerdict::Stalled);
        let denial = check_liveness_for_progression(&heartbeat, 105, 10)
            .expect_err("stalled verdict must deny progression");
        assert_eq!(denial.reason, LivenessDenialReason::UnhealthyVerdict);
    }

    #[test]
    fn test_crashed_verdict_denies_progression() {
        let heartbeat = sample_heartbeat(HealthVerdict::Crashed);
        let denial = check_liveness_for_progression(&heartbeat, 105, 10)
            .expect_err("crashed verdict must deny progression");
        assert_eq!(denial.reason, LivenessDenialReason::UnhealthyVerdict);
    }

    #[test]
    fn test_ambiguous_verdict_denies_progression() {
        let heartbeat = sample_heartbeat(HealthVerdict::Ambiguous);
        let denial = check_liveness_for_progression(&heartbeat, 105, 10)
            .expect_err("ambiguous verdict must deny progression");
        assert_eq!(denial.reason, LivenessDenialReason::AmbiguousState);
    }

    #[test]
    fn test_stale_heartbeat_denies_progression() {
        let mut heartbeat = sample_heartbeat(HealthVerdict::Healthy);
        heartbeat.emitted_at_tick = 10;

        let denial = check_liveness_for_progression(&heartbeat, 30, 5)
            .expect_err("stale heartbeat must deny progression");
        assert_eq!(denial.reason, LivenessDenialReason::StaleHeartbeat);
    }

    #[test]
    fn test_restart_within_limits_allowed() {
        let mut controller =
            RestartController::new(sample_restart_config()).expect("valid config should succeed");
        let decision = controller.record_restart(100);
        assert_eq!(decision, RestartDecision::Allow { attempt: 1 });
    }

    #[test]
    fn test_restart_limit_exceeded_denied() {
        let config = RestartPolicyConfig {
            max_restarts: 1,
            window_ticks: 20,
            circuit_breaker_threshold_ticks: 10,
            circuit_breaker_max_failures: 10,
            stall_timeout_ticks: 8,
        };
        let mut controller = RestartController::new(config).expect("valid config should succeed");

        assert_eq!(
            controller.record_restart(100),
            RestartDecision::Allow { attempt: 1 }
        );
        assert_eq!(
            controller.record_restart(101),
            RestartDecision::Deny {
                reason: TerminalReason::RestartLimitExceeded
            }
        );
        assert_eq!(
            controller.terminal_reason(),
            Some(TerminalReason::RestartLimitExceeded)
        );
    }

    #[test]
    fn test_circuit_breaker_opens_on_rapid_failures() {
        let config = RestartPolicyConfig {
            max_restarts: 10,
            window_ticks: 50,
            circuit_breaker_threshold_ticks: 2,
            circuit_breaker_max_failures: 3,
            stall_timeout_ticks: 8,
        };
        let mut controller = RestartController::new(config).expect("valid config should succeed");

        assert_eq!(
            controller.record_restart(100),
            RestartDecision::Allow { attempt: 1 }
        );
        assert_eq!(
            controller.record_restart(101),
            RestartDecision::Allow { attempt: 2 }
        );
        assert_eq!(
            controller.record_restart(102),
            RestartDecision::Deny {
                reason: TerminalReason::CircuitBreakerOpen
            }
        );
        assert_eq!(
            controller.record_restart(103),
            RestartDecision::Deny {
                reason: TerminalReason::CircuitBreakerOpen
            }
        );
    }

    #[test]
    fn test_stall_timeout_detection() {
        let controller =
            RestartController::new(sample_restart_config()).expect("valid config should succeed");
        assert!(controller.check_stall(10, 18));
    }

    #[test]
    fn test_clean_exit_is_terminal() {
        let mut controller =
            RestartController::new(sample_restart_config()).expect("valid config should succeed");
        assert_eq!(
            controller.record_terminal(TerminalReason::CleanExit),
            RestartDecision::Deny {
                reason: TerminalReason::CleanExit
            }
        );
        assert_eq!(
            controller.terminal_reason(),
            Some(TerminalReason::CleanExit)
        );
        assert_eq!(
            controller.record_restart(200),
            RestartDecision::Deny {
                reason: TerminalReason::CleanExit
            }
        );
    }

    #[test]
    fn test_heartbeat_receipt_serialization() {
        let heartbeat = sample_heartbeat(HealthVerdict::Healthy);
        let encoded = serde_json::to_string(&heartbeat).expect("heartbeat should serialize");
        let decoded: LivenessHeartbeatReceiptV1 =
            serde_json::from_str(&encoded).expect("heartbeat should deserialize");
        assert_eq!(heartbeat, decoded);
    }

    #[test]
    fn test_restart_decision_serialization() {
        let decision = RestartDecision::Allow { attempt: 2 };
        let encoded = serde_json::to_string(&decision).expect("decision should serialize");
        let decoded: RestartDecision =
            serde_json::from_str(&encoded).expect("decision should deserialize");
        assert_eq!(decision, decoded);
    }

    #[test]
    fn test_liveness_denial_includes_detail() {
        let mut heartbeat = sample_heartbeat(HealthVerdict::Healthy);
        heartbeat.emitted_at_tick = 1;

        let denial = check_liveness_for_progression(&heartbeat, 15, 3)
            .expect_err("stale heartbeat should deny with detail");
        assert_eq!(denial.reason, LivenessDenialReason::StaleHeartbeat);
        assert!(denial.detail.contains("heartbeat age"));
        assert!(!denial.detail.trim().is_empty());
    }
}
