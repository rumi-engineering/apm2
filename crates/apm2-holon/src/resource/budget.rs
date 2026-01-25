//! Budget types for resource tracking in holonic execution.
//!
//! This module defines the [`Budget`] type that tracks multiple resource
//! dimensions consumed during holon execution. Budgets are monotonically
//! decreasing - once resources are consumed, they cannot be restored.
//!
//! # Resource Dimensions
//!
//! Budgets track four resource dimensions (per REQ-3004):
//! - **Episodes**: The number of episode iterations allowed
//! - **Tool Calls**: The number of tool invocations allowed
//! - **Tokens**: The number of LLM tokens that can be consumed
//! - **Duration**: The wall-clock time allowed (in milliseconds)
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::resource::Budget;
//!
//! let mut budget = Budget::new(10, 100, 10_000, 60_000);
//!
//! // Deduct resources
//! budget.deduct_episodes(1).unwrap();
//! budget.deduct_tool_calls(5).unwrap();
//! budget.deduct_tokens(500).unwrap();
//! budget.deduct_duration_ms(1000).unwrap();
//!
//! assert_eq!(budget.remaining_episodes(), 9);
//! assert!(!budget.is_exhausted());
//! ```

use serde::{Deserialize, Serialize};

use super::error::ResourceError;

/// A budget for resource consumption during holon execution.
///
/// Budgets track multiple resource dimensions and enforce monotonic
/// consumption. Once any dimension is exhausted, the budget is considered
/// exhausted.
///
/// # Invariants
///
/// - All remaining values are monotonically decreasing
/// - Remaining values never exceed initial values
/// - Exhaustion is permanent once any dimension reaches zero
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Initial episode count.
    initial_episodes: u64,
    /// Remaining episode count.
    remaining_episodes: u64,

    /// Initial tool call count.
    initial_tool_calls: u64,
    /// Remaining tool call count.
    remaining_tool_calls: u64,

    /// Initial token count.
    initial_tokens: u64,
    /// Remaining token count.
    remaining_tokens: u64,

    /// Initial duration in milliseconds.
    initial_duration_ms: u64,
    /// Remaining duration in milliseconds.
    remaining_duration_ms: u64,
}

impl Budget {
    /// Creates a new budget with the specified limits.
    ///
    /// # Arguments
    ///
    /// * `episodes` - Maximum number of episodes allowed
    /// * `tool_calls` - Maximum number of tool calls allowed
    /// * `tokens` - Maximum number of tokens allowed
    /// * `duration_ms` - Maximum duration in milliseconds
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_holon::resource::Budget;
    ///
    /// let budget = Budget::new(10, 100, 10_000, 60_000);
    /// assert_eq!(budget.remaining_episodes(), 10);
    /// ```
    #[must_use]
    pub const fn new(episodes: u64, tool_calls: u64, tokens: u64, duration_ms: u64) -> Self {
        Self {
            initial_episodes: episodes,
            remaining_episodes: episodes,
            initial_tool_calls: tool_calls,
            remaining_tool_calls: tool_calls,
            initial_tokens: tokens,
            remaining_tokens: tokens,
            initial_duration_ms: duration_ms,
            remaining_duration_ms: duration_ms,
        }
    }

    /// Creates an unlimited budget.
    ///
    /// An unlimited budget uses `u64::MAX` for all dimensions.
    /// This should only be used in testing or for root-level holons
    /// with explicit authorization.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_holon::resource::Budget;
    ///
    /// let budget = Budget::unlimited();
    /// assert!(!budget.is_exhausted());
    /// ```
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX)
    }

    /// Returns the initial episode count.
    #[must_use]
    pub const fn initial_episodes(&self) -> u64 {
        self.initial_episodes
    }

    /// Returns the remaining episode count.
    #[must_use]
    pub const fn remaining_episodes(&self) -> u64 {
        self.remaining_episodes
    }

    /// Returns the initial tool call count.
    #[must_use]
    pub const fn initial_tool_calls(&self) -> u64 {
        self.initial_tool_calls
    }

    /// Returns the remaining tool call count.
    #[must_use]
    pub const fn remaining_tool_calls(&self) -> u64 {
        self.remaining_tool_calls
    }

    /// Returns the initial token count.
    #[must_use]
    pub const fn initial_tokens(&self) -> u64 {
        self.initial_tokens
    }

    /// Returns the remaining token count.
    #[must_use]
    pub const fn remaining_tokens(&self) -> u64 {
        self.remaining_tokens
    }

    /// Returns the initial duration in milliseconds.
    #[must_use]
    pub const fn initial_duration_ms(&self) -> u64 {
        self.initial_duration_ms
    }

    /// Returns the remaining duration in milliseconds.
    #[must_use]
    pub const fn remaining_duration_ms(&self) -> u64 {
        self.remaining_duration_ms
    }

    /// Returns the number of episodes consumed.
    #[must_use]
    pub const fn consumed_episodes(&self) -> u64 {
        self.initial_episodes - self.remaining_episodes
    }

    /// Returns the number of tool calls consumed.
    #[must_use]
    pub const fn consumed_tool_calls(&self) -> u64 {
        self.initial_tool_calls - self.remaining_tool_calls
    }

    /// Returns the number of tokens consumed.
    #[must_use]
    pub const fn consumed_tokens(&self) -> u64 {
        self.initial_tokens - self.remaining_tokens
    }

    /// Returns the duration consumed in milliseconds.
    #[must_use]
    pub const fn consumed_duration_ms(&self) -> u64 {
        self.initial_duration_ms - self.remaining_duration_ms
    }

    /// Returns `true` if any resource dimension is exhausted.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_holon::resource::Budget;
    ///
    /// let mut budget = Budget::new(1, 100, 10_000, 60_000);
    /// assert!(!budget.is_exhausted());
    ///
    /// budget.deduct_episodes(1).unwrap();
    /// assert!(budget.is_exhausted());
    /// ```
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.remaining_episodes == 0
            || self.remaining_tool_calls == 0
            || self.remaining_tokens == 0
            || self.remaining_duration_ms == 0
    }

    /// Returns `true` if episodes are exhausted.
    #[must_use]
    pub const fn episodes_exhausted(&self) -> bool {
        self.remaining_episodes == 0
    }

    /// Returns `true` if tool calls are exhausted.
    #[must_use]
    pub const fn tool_calls_exhausted(&self) -> bool {
        self.remaining_tool_calls == 0
    }

    /// Returns `true` if tokens are exhausted.
    #[must_use]
    pub const fn tokens_exhausted(&self) -> bool {
        self.remaining_tokens == 0
    }

    /// Returns `true` if duration is exhausted.
    #[must_use]
    pub const fn duration_exhausted(&self) -> bool {
        self.remaining_duration_ms == 0
    }

    /// Returns the name of the first exhausted resource, if any.
    #[must_use]
    pub const fn exhausted_resource(&self) -> Option<&'static str> {
        if self.remaining_episodes == 0 {
            Some("episodes")
        } else if self.remaining_tool_calls == 0 {
            Some("tool_calls")
        } else if self.remaining_tokens == 0 {
            Some("tokens")
        } else if self.remaining_duration_ms == 0 {
            Some("duration")
        } else {
            None
        }
    }

    /// Deducts episodes from the budget.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::BudgetExhausted` if there are insufficient
    /// episodes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_holon::resource::Budget;
    ///
    /// let mut budget = Budget::new(5, 100, 10_000, 60_000);
    /// budget.deduct_episodes(3).unwrap();
    /// assert_eq!(budget.remaining_episodes(), 2);
    ///
    /// // Attempting to deduct more than remaining fails
    /// assert!(budget.deduct_episodes(5).is_err());
    /// ```
    pub fn deduct_episodes(&mut self, amount: u64) -> Result<(), ResourceError> {
        if amount > self.remaining_episodes {
            return Err(ResourceError::BudgetExhausted {
                resource: "episodes".to_string(),
                requested: amount,
                remaining: self.remaining_episodes,
            });
        }
        self.remaining_episodes -= amount;
        Ok(())
    }

    /// Deducts tool calls from the budget.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::BudgetExhausted` if there are insufficient tool
    /// calls.
    pub fn deduct_tool_calls(&mut self, amount: u64) -> Result<(), ResourceError> {
        if amount > self.remaining_tool_calls {
            return Err(ResourceError::BudgetExhausted {
                resource: "tool_calls".to_string(),
                requested: amount,
                remaining: self.remaining_tool_calls,
            });
        }
        self.remaining_tool_calls -= amount;
        Ok(())
    }

    /// Deducts tokens from the budget.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::BudgetExhausted` if there are insufficient
    /// tokens.
    pub fn deduct_tokens(&mut self, amount: u64) -> Result<(), ResourceError> {
        if amount > self.remaining_tokens {
            return Err(ResourceError::BudgetExhausted {
                resource: "tokens".to_string(),
                requested: amount,
                remaining: self.remaining_tokens,
            });
        }
        self.remaining_tokens -= amount;
        Ok(())
    }

    /// Deducts duration from the budget.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::BudgetExhausted` if there is insufficient
    /// duration.
    pub fn deduct_duration_ms(&mut self, amount: u64) -> Result<(), ResourceError> {
        if amount > self.remaining_duration_ms {
            return Err(ResourceError::BudgetExhausted {
                resource: "duration".to_string(),
                requested: amount,
                remaining: self.remaining_duration_ms,
            });
        }
        self.remaining_duration_ms -= amount;
        Ok(())
    }

    /// Deducts multiple resources at once.
    ///
    /// This is atomic - if any deduction would fail, none are applied.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::BudgetExhausted` if any resource is
    /// insufficient.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_holon::resource::Budget;
    ///
    /// let mut budget = Budget::new(10, 100, 10_000, 60_000);
    /// budget.deduct(1, 5, 500, 1000).unwrap();
    ///
    /// assert_eq!(budget.remaining_episodes(), 9);
    /// assert_eq!(budget.remaining_tool_calls(), 95);
    /// assert_eq!(budget.remaining_tokens(), 9_500);
    /// assert_eq!(budget.remaining_duration_ms(), 59_000);
    /// ```
    pub fn deduct(
        &mut self,
        episodes: u64,
        tool_calls: u64,
        tokens: u64,
        duration_ms: u64,
    ) -> Result<(), ResourceError> {
        // Check all resources first for atomicity
        if episodes > self.remaining_episodes {
            return Err(ResourceError::BudgetExhausted {
                resource: "episodes".to_string(),
                requested: episodes,
                remaining: self.remaining_episodes,
            });
        }
        if tool_calls > self.remaining_tool_calls {
            return Err(ResourceError::BudgetExhausted {
                resource: "tool_calls".to_string(),
                requested: tool_calls,
                remaining: self.remaining_tool_calls,
            });
        }
        if tokens > self.remaining_tokens {
            return Err(ResourceError::BudgetExhausted {
                resource: "tokens".to_string(),
                requested: tokens,
                remaining: self.remaining_tokens,
            });
        }
        if duration_ms > self.remaining_duration_ms {
            return Err(ResourceError::BudgetExhausted {
                resource: "duration".to_string(),
                requested: duration_ms,
                remaining: self.remaining_duration_ms,
            });
        }

        // Apply all deductions
        self.remaining_episodes -= episodes;
        self.remaining_tool_calls -= tool_calls;
        self.remaining_tokens -= tokens;
        self.remaining_duration_ms -= duration_ms;
        Ok(())
    }

    /// Creates a sub-budget that is bounded by this budget.
    ///
    /// The sub-budget's limits are capped at the remaining values of this
    /// budget. This is used for lease derivation to ensure sub-holons
    /// cannot exceed their parent's remaining resources.
    ///
    /// # Arguments
    ///
    /// * `requested` - The requested budget for the sub-holon
    ///
    /// # Returns
    ///
    /// A new budget with limits that are the minimum of the requested values
    /// and this budget's remaining values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_holon::resource::Budget;
    ///
    /// let parent = Budget::new(10, 100, 10_000, 60_000);
    /// let requested = Budget::new(5, 200, 5_000, 30_000);
    ///
    /// let sub = parent.derive_sub_budget(&requested);
    ///
    /// // Capped at parent's remaining (100 < 200)
    /// assert_eq!(sub.remaining_tool_calls(), 100);
    /// // Uses requested (5 < 10)
    /// assert_eq!(sub.remaining_episodes(), 5);
    /// ```
    #[must_use]
    pub fn derive_sub_budget(&self, requested: &Self) -> Self {
        Self::new(
            self.remaining_episodes.min(requested.initial_episodes),
            self.remaining_tool_calls.min(requested.initial_tool_calls),
            self.remaining_tokens.min(requested.initial_tokens),
            self.remaining_duration_ms
                .min(requested.initial_duration_ms),
        )
    }

    /// Checks if this budget can accommodate the requested sub-budget.
    ///
    /// # Returns
    ///
    /// `true` if all dimensions of the requested budget are less than or equal
    /// to the remaining values of this budget.
    #[must_use]
    pub const fn can_accommodate(&self, requested: &Self) -> bool {
        requested.initial_episodes <= self.remaining_episodes
            && requested.initial_tool_calls <= self.remaining_tool_calls
            && requested.initial_tokens <= self.remaining_tokens
            && requested.initial_duration_ms <= self.remaining_duration_ms
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_creation() {
        let budget = Budget::new(10, 100, 10_000, 60_000);

        assert_eq!(budget.initial_episodes(), 10);
        assert_eq!(budget.remaining_episodes(), 10);
        assert_eq!(budget.initial_tool_calls(), 100);
        assert_eq!(budget.remaining_tool_calls(), 100);
        assert_eq!(budget.initial_tokens(), 10_000);
        assert_eq!(budget.remaining_tokens(), 10_000);
        assert_eq!(budget.initial_duration_ms(), 60_000);
        assert_eq!(budget.remaining_duration_ms(), 60_000);
    }

    #[test]
    fn test_budget_unlimited() {
        let budget = Budget::unlimited();

        assert_eq!(budget.remaining_episodes(), u64::MAX);
        assert_eq!(budget.remaining_tool_calls(), u64::MAX);
        assert_eq!(budget.remaining_tokens(), u64::MAX);
        assert_eq!(budget.remaining_duration_ms(), u64::MAX);
        assert!(!budget.is_exhausted());
    }

    #[test]
    fn test_budget_default() {
        let budget = Budget::default();

        assert_eq!(budget.remaining_episodes(), 0);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_deduct_episodes() {
        let mut budget = Budget::new(10, 100, 10_000, 60_000);

        budget.deduct_episodes(3).unwrap();
        assert_eq!(budget.remaining_episodes(), 7);
        assert_eq!(budget.consumed_episodes(), 3);
        assert!(!budget.is_exhausted());

        budget.deduct_episodes(7).unwrap();
        assert_eq!(budget.remaining_episodes(), 0);
        assert!(budget.episodes_exhausted());
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_deduct_episodes_insufficient() {
        let mut budget = Budget::new(5, 100, 10_000, 60_000);

        let result = budget.deduct_episodes(10);
        assert!(result.is_err());

        match result {
            Err(ResourceError::BudgetExhausted {
                resource,
                requested,
                remaining,
            }) => {
                assert_eq!(resource, "episodes");
                assert_eq!(requested, 10);
                assert_eq!(remaining, 5);
            },
            _ => panic!("Expected BudgetExhausted error"),
        }

        // Budget should be unchanged
        assert_eq!(budget.remaining_episodes(), 5);
    }

    #[test]
    fn test_deduct_tool_calls() {
        let mut budget = Budget::new(10, 100, 10_000, 60_000);

        budget.deduct_tool_calls(25).unwrap();
        assert_eq!(budget.remaining_tool_calls(), 75);
        assert_eq!(budget.consumed_tool_calls(), 25);
    }

    #[test]
    fn test_deduct_tokens() {
        let mut budget = Budget::new(10, 100, 10_000, 60_000);

        budget.deduct_tokens(2500).unwrap();
        assert_eq!(budget.remaining_tokens(), 7_500);
        assert_eq!(budget.consumed_tokens(), 2_500);
    }

    #[test]
    fn test_deduct_duration() {
        let mut budget = Budget::new(10, 100, 10_000, 60_000);

        budget.deduct_duration_ms(15_000).unwrap();
        assert_eq!(budget.remaining_duration_ms(), 45_000);
        assert_eq!(budget.consumed_duration_ms(), 15_000);
    }

    #[test]
    fn test_deduct_multiple() {
        let mut budget = Budget::new(10, 100, 10_000, 60_000);

        budget.deduct(1, 5, 500, 1000).unwrap();

        assert_eq!(budget.remaining_episodes(), 9);
        assert_eq!(budget.remaining_tool_calls(), 95);
        assert_eq!(budget.remaining_tokens(), 9_500);
        assert_eq!(budget.remaining_duration_ms(), 59_000);
    }

    #[test]
    fn test_deduct_multiple_atomic() {
        let mut budget = Budget::new(10, 100, 10_000, 60_000);

        // This should fail because tokens requested > remaining
        let result = budget.deduct(1, 5, 20_000, 1000);
        assert!(result.is_err());

        // All values should be unchanged due to atomicity
        assert_eq!(budget.remaining_episodes(), 10);
        assert_eq!(budget.remaining_tool_calls(), 100);
        assert_eq!(budget.remaining_tokens(), 10_000);
        assert_eq!(budget.remaining_duration_ms(), 60_000);
    }

    #[test]
    fn test_exhausted_resource() {
        let mut budget = Budget::new(1, 1, 1, 1);

        assert!(budget.exhausted_resource().is_none());

        budget.deduct_tokens(1).unwrap();
        assert_eq!(budget.exhausted_resource(), Some("tokens"));
    }

    #[test]
    fn test_exhaustion_priority() {
        // Test that exhausted_resource returns resources in priority order
        let mut budget = Budget::new(0, 0, 0, 0);
        assert_eq!(budget.exhausted_resource(), Some("episodes"));

        budget = Budget::new(1, 0, 0, 0);
        assert_eq!(budget.exhausted_resource(), Some("tool_calls"));

        budget = Budget::new(1, 1, 0, 0);
        assert_eq!(budget.exhausted_resource(), Some("tokens"));

        budget = Budget::new(1, 1, 1, 0);
        assert_eq!(budget.exhausted_resource(), Some("duration"));
    }

    #[test]
    fn test_derive_sub_budget() {
        let parent = Budget::new(10, 100, 10_000, 60_000);
        let requested = Budget::new(5, 200, 5_000, 30_000);

        let sub = parent.derive_sub_budget(&requested);

        // Should use minimum of parent remaining and requested
        assert_eq!(sub.remaining_episodes(), 5); // min(10, 5) = 5
        assert_eq!(sub.remaining_tool_calls(), 100); // min(100, 200) = 100
        assert_eq!(sub.remaining_tokens(), 5_000); // min(10_000, 5_000) = 5_000
        assert_eq!(sub.remaining_duration_ms(), 30_000); // min(60_000, 30_000) = 30_000
    }

    #[test]
    fn test_derive_sub_budget_from_depleted() {
        let mut parent = Budget::new(10, 100, 10_000, 60_000);
        parent.deduct(5, 50, 5_000, 30_000).unwrap();

        let requested = Budget::new(10, 100, 10_000, 60_000);
        let sub = parent.derive_sub_budget(&requested);

        // Should be capped at parent's remaining
        assert_eq!(sub.remaining_episodes(), 5);
        assert_eq!(sub.remaining_tool_calls(), 50);
        assert_eq!(sub.remaining_tokens(), 5_000);
        assert_eq!(sub.remaining_duration_ms(), 30_000);
    }

    #[test]
    fn test_can_accommodate() {
        let parent = Budget::new(10, 100, 10_000, 60_000);

        // Can accommodate smaller budget
        let small = Budget::new(5, 50, 5_000, 30_000);
        assert!(parent.can_accommodate(&small));

        // Can accommodate equal budget
        let equal = Budget::new(10, 100, 10_000, 60_000);
        assert!(parent.can_accommodate(&equal));

        // Cannot accommodate larger budget
        let large = Budget::new(20, 100, 10_000, 60_000);
        assert!(!parent.can_accommodate(&large));
    }

    #[test]
    fn test_serialization() {
        let budget = Budget::new(10, 100, 10_000, 60_000);
        let json = serde_json::to_string(&budget).unwrap();
        let deserialized: Budget = serde_json::from_str(&json).unwrap();

        assert_eq!(budget, deserialized);
    }

    #[test]
    fn test_budget_monotonicity() {
        // Property: remaining values can only decrease
        let mut budget = Budget::new(10, 100, 10_000, 60_000);

        let initial_episodes = budget.remaining_episodes();
        budget.deduct_episodes(1).unwrap();
        assert!(budget.remaining_episodes() < initial_episodes);

        // Multiple deductions continue to decrease
        budget.deduct_episodes(1).unwrap();
        assert!(budget.remaining_episodes() < initial_episodes - 1);
    }

    #[test]
    fn test_consumed_never_exceeds_initial() {
        let mut budget = Budget::new(10, 100, 10_000, 60_000);

        // Consume everything
        budget.deduct_episodes(10).unwrap();
        budget.deduct_tool_calls(100).unwrap();
        budget.deduct_tokens(10_000).unwrap();
        budget.deduct_duration_ms(60_000).unwrap();

        // Consumed should equal initial
        assert_eq!(budget.consumed_episodes(), budget.initial_episodes());
        assert_eq!(budget.consumed_tool_calls(), budget.initial_tool_calls());
        assert_eq!(budget.consumed_tokens(), budget.initial_tokens());
        assert_eq!(budget.consumed_duration_ms(), budget.initial_duration_ms());
    }
}
