//! Bounded timeout policy for FAC test execution.
//!
//! FAC uses one uniform timeout for bounded test execution regardless of
//! workspace cache temperature.

use std::path::Path;

pub const DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS: u64 = 600;
pub const MAX_MANUAL_TIMEOUT_SECONDS: u64 = 600;
pub const TEST_TIMEOUT_SLA_MESSAGE: &str =
    "Bounded FAC test timeout is fixed at 600s for all runs.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutDecision {
    pub requested_seconds: u64,
    pub effective_seconds: u64,
}

#[must_use]
pub fn resolve_bounded_test_timeout(
    _workspace_root: &Path,
    requested_seconds: u64,
) -> TimeoutDecision {
    TimeoutDecision {
        requested_seconds,
        effective_seconds: requested_seconds.min(MAX_MANUAL_TIMEOUT_SECONDS),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_MANUAL_TIMEOUT_SECONDS, resolve_bounded_test_timeout};

    #[test]
    fn timeout_policy_uses_requested_value_when_within_limit() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let decision = resolve_bounded_test_timeout(temp_dir.path(), 480);
        assert_eq!(decision.requested_seconds, 480);
        assert_eq!(decision.effective_seconds, 480);
    }

    #[test]
    fn timeout_policy_clamps_values_above_manual_limit() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let decision =
            resolve_bounded_test_timeout(temp_dir.path(), MAX_MANUAL_TIMEOUT_SECONDS + 1);
        assert_eq!(decision.effective_seconds, MAX_MANUAL_TIMEOUT_SECONDS);
    }
}
