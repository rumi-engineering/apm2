// AGENT-AUTHORED
//! Bounded retry manager for FAC gates.
//!
//! This module implements the `RetryManager` which enforces strict limits on
//! the number of retries for gate execution. This prevents infinite loops
//! and resource exhaustion (FAC-REQ-0021).
//!
//! # Resource Limits
//!
//! - **Per-Gate Limit**: Maximum 3 attempts per gate.
//! - **Global Limit**: Maximum 50 total episodes across all gates.
//!
//! # Security
//!
//! - Prevents infinite recursion in agent control loops.
//! - Bounded state size via `MAX_STRING_LENGTH` checks on gate IDs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::policy_resolution::MAX_STRING_LENGTH;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of attempts allowed per gate.
pub const MAX_GATE_ATTEMPTS: u32 = 3;

/// Maximum number of global episodes allowed across all gates.
pub const MAX_GLOBAL_EPISODES: u32 = 50;

/// Maximum number of gates tracked.
/// Prevents DoS via memory exhaustion.
pub const MAX_TRACKED_GATES: usize = 128;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during retry management.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RetryError {
    /// Per-gate retry limit exceeded.
    #[error("gate '{gate_id}' exceeded max attempts ({current} >= {max})")]
    GateLimitExceeded {
        /// The gate ID.
        gate_id: String,
        /// Current attempt count.
        current: u32,
        /// Maximum allowed attempts.
        max: u32,
    },

    /// Global episode limit exceeded.
    #[error("global episode limit exceeded ({current} >= {max})")]
    GlobalLimitExceeded {
        /// Current global episode count.
        current: u32,
        /// Maximum allowed global episodes.
        max: u32,
    },

    /// Too many gates tracked (DoS protection).
    #[error("too many gates tracked ({current} >= {max})")]
    TooManyGates {
        /// Current number of tracked gates.
        current: usize,
        /// Maximum allowed tracked gates.
        max: usize,
    },

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
}

// =============================================================================
// RetryManager
// =============================================================================

/// Manages retry budgets for FAC gates.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RetryManager {
    /// Map of gate ID to attempt count.
    gate_attempts: HashMap<String, u32>,

    /// Total number of episodes executed globally.
    global_episodes: u32,
}

impl RetryManager {
    /// Creates a new `RetryManager`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if a retry is allowed for the given gate.
    ///
    /// # Arguments
    ///
    /// * `gate_id` - The ID of the gate to check.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if retry is allowed.
    /// `Ok(false)` if retry is NOT allowed (limits reached).
    /// `Err(RetryError)` for validation errors (e.g. string too long).
    pub fn can_retry(&self, gate_id: &str) -> Result<bool, RetryError> {
        if gate_id.len() > MAX_STRING_LENGTH {
            return Err(RetryError::StringTooLong {
                field: "gate_id",
                len: gate_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        if self.global_episodes >= MAX_GLOBAL_EPISODES {
            return Ok(false);
        }

        let attempts = self.gate_attempts.get(gate_id).copied().unwrap_or(0);
        if attempts >= MAX_GATE_ATTEMPTS {
            return Ok(false);
        }

        Ok(true)
    }

    /// Records an attempt for the given gate, incrementing counters.
    ///
    /// # Arguments
    ///
    /// * `gate_id` - The ID of the gate to record.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the attempt was successfully recorded.
    /// `Err(RetryError)` if limits would be exceeded or validation fails.
    pub fn record_attempt(&mut self, gate_id: impl Into<String>) -> Result<(), RetryError> {
        let gate_id = gate_id.into();

        // Validation
        if gate_id.len() > MAX_STRING_LENGTH {
            return Err(RetryError::StringTooLong {
                field: "gate_id",
                len: gate_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Check global limit
        if self.global_episodes >= MAX_GLOBAL_EPISODES {
            return Err(RetryError::GlobalLimitExceeded {
                current: self.global_episodes,
                max: MAX_GLOBAL_EPISODES,
            });
        }

        // Check/Update per-gate limit
        if let Some(attempts) = self.gate_attempts.get_mut(&gate_id) {
            if *attempts >= MAX_GATE_ATTEMPTS {
                return Err(RetryError::GateLimitExceeded {
                    gate_id,
                    current: *attempts,
                    max: MAX_GATE_ATTEMPTS,
                });
            }
            *attempts += 1;
        } else {
            // New gate - check map size limit
            if self.gate_attempts.len() >= MAX_TRACKED_GATES {
                return Err(RetryError::TooManyGates {
                    current: self.gate_attempts.len(),
                    max: MAX_TRACKED_GATES,
                });
            }
            self.gate_attempts.insert(gate_id, 1);
        }

        self.global_episodes += 1;

        Ok(())
    }

    /// Returns the current attempt count for a gate.
    #[must_use]
    pub fn attempts_for(&self, gate_id: &str) -> u32 {
        self.gate_attempts.get(gate_id).copied().unwrap_or(0)
    }

    /// Returns the global episode count.
    #[must_use]
    pub const fn global_episodes(&self) -> u32 {
        self.global_episodes
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_limits() {
        let mut manager = RetryManager::new();
        let gate = "test-gate";

        // Attempt 1
        assert!(manager.can_retry(gate).unwrap());
        manager.record_attempt(gate).unwrap();
        assert_eq!(manager.attempts_for(gate), 1);
        assert_eq!(manager.global_episodes(), 1);

        // Attempt 2
        assert!(manager.can_retry(gate).unwrap());
        manager.record_attempt(gate).unwrap();
        assert_eq!(manager.attempts_for(gate), 2);

        // Attempt 3
        assert!(manager.can_retry(gate).unwrap());
        manager.record_attempt(gate).unwrap();
        assert_eq!(manager.attempts_for(gate), 3);

        // Attempt 4 (Should fail)
        assert!(!manager.can_retry(gate).unwrap());
        let result = manager.record_attempt(gate);
        assert!(matches!(result, Err(RetryError::GateLimitExceeded { .. })));

        // Counts should stay at max
        assert_eq!(manager.attempts_for(gate), 3);
        assert_eq!(manager.global_episodes(), 3);
    }

    #[test]
    fn test_global_limit() {
        let mut manager = RetryManager::new();

        // Fill up global episodes with unique gates
        for i in 0..MAX_GLOBAL_EPISODES {
            let gate = format!("gate-{}", i);
            manager.record_attempt(&gate).unwrap();
        }

        assert_eq!(manager.global_episodes(), MAX_GLOBAL_EPISODES);

        // Next attempt should fail globally
        let gate = "overflow-gate";
        assert!(!manager.can_retry(gate).unwrap());

        let result = manager.record_attempt(gate);
        assert!(matches!(
            result,
            Err(RetryError::GlobalLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_string_too_long() {
        let manager = RetryManager::new();
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = manager.can_retry(&long_id);
        assert!(matches!(result, Err(RetryError::StringTooLong { .. })));
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut manager = RetryManager::new();
        manager.record_attempt("gate-1").unwrap();
        manager.record_attempt("gate-2").unwrap();

        let json = serde_json::to_string(&manager).unwrap();
        let recovered: RetryManager = serde_json::from_str(&json).unwrap();

        assert_eq!(manager, recovered);
    }
}
