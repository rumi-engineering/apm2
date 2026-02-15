//! Bounded timeout policy for FAC test execution.
//!
//! FAC uses one uniform timeout for bounded test execution regardless of
//! workspace cache temperature.

use std::path::Path;

use apm2_core::fac::MAX_MEMORY_MAX_BYTES;

pub const DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS: u64 = 600;
pub const MAX_MANUAL_TIMEOUT_SECONDS: u64 = 600;
pub const TEST_TIMEOUT_SLA_MESSAGE: &str =
    "Bounded FAC test timeout is fixed at 600s for all runs.";
pub const DEFAULT_TEST_MEMORY_MAX: &str = "48G";

#[must_use]
pub const fn max_memory_bytes() -> u64 {
    MAX_MEMORY_MAX_BYTES
}

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

pub fn parse_memory_limit(memory_max: &str) -> Result<u64, String> {
    let trimmed = memory_max.trim();
    if trimmed.is_empty() {
        return Err("--memory-max cannot be empty".to_string());
    }

    let (number_part, multiplier) = match trimmed.chars().last() {
        Some('K' | 'k') => (&trimmed[..trimmed.len() - 1], 1024_u64),
        Some('M' | 'm') => (&trimmed[..trimmed.len() - 1], 1024_u64.pow(2)),
        Some('G' | 'g') => (&trimmed[..trimmed.len() - 1], 1024_u64.pow(3)),
        Some('T' | 't') => (&trimmed[..trimmed.len() - 1], 1024_u64.pow(4)),
        Some(_) => (trimmed, 1),
        None => return Err("--memory-max cannot be empty".to_string()),
    };

    if number_part.is_empty() {
        return Err(format!("--memory-max must be numeric: `{memory_max}`"));
    }

    let quantity: u64 = number_part
        .parse()
        .map_err(|_| format!("--memory-max is not a valid integer: `{memory_max}`"))?;
    if quantity == 0 {
        return Err("--memory-max must be > 0".to_string());
    }

    quantity
        .checked_mul(multiplier)
        .ok_or_else(|| format!("--memory-max is too large: `{memory_max}`"))
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS, DEFAULT_TEST_MEMORY_MAX, MAX_MANUAL_TIMEOUT_SECONDS,
        max_memory_bytes, parse_memory_limit, resolve_bounded_test_timeout,
    };

    #[test]
    fn timeout_policy_uses_requested_value_when_within_limit() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let decision = resolve_bounded_test_timeout(temp_dir.path(), 180);
        assert_eq!(decision.requested_seconds, 180);
        assert_eq!(decision.effective_seconds, 180);
    }

    #[test]
    fn timeout_policy_clamps_values_above_manual_limit() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let decision =
            resolve_bounded_test_timeout(temp_dir.path(), MAX_MANUAL_TIMEOUT_SECONDS + 1);
        assert_eq!(decision.effective_seconds, MAX_MANUAL_TIMEOUT_SECONDS);
    }

    #[test]
    fn timeout_policy_has_default_600_seconds() {
        assert_eq!(DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS, 600);
    }

    #[test]
    fn parse_memory_limit_handles_binary_gibibyte_input() {
        assert_eq!(
            parse_memory_limit(DEFAULT_TEST_MEMORY_MAX).expect("parse"),
            max_memory_bytes()
        );
    }

    #[test]
    fn parse_memory_limit_rejects_invalid_values() {
        assert!(parse_memory_limit("abc").is_err());
        assert!(parse_memory_limit("0").is_err());
        assert!(parse_memory_limit("").is_err());
    }
}
