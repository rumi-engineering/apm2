//! Property-based tests for budget monotonicity.
//!
//! These tests verify the key invariants of the Budget type using
//! property-based testing with proptest.

use proptest::prelude::*;

use super::budget::Budget;

/// Strategy for generating valid budget values (avoiding overflow issues).
fn budget_value() -> impl Strategy<Value = u64> {
    // Use reasonable bounds to avoid overflow in tests
    0u64..1_000_000_000
}

/// Strategy for generating a Budget with random values.
fn budget_strategy() -> impl Strategy<Value = Budget> {
    (
        budget_value(),
        budget_value(),
        budget_value(),
        budget_value(),
    )
        .prop_map(|(episodes, tool_calls, tokens, duration_ms)| {
            Budget::new(episodes, tool_calls, tokens, duration_ms)
        })
}

/// Strategy for generating a deduction amount that may or may not exceed
/// remaining.
fn deduction_amount() -> impl Strategy<Value = u64> {
    0u64..100_000_000
}

proptest! {
    /// Property: After any sequence of deductions, remaining <= initial.
    #[test]
    fn prop_remaining_never_exceeds_initial(
        initial_episodes in budget_value(),
        initial_tool_calls in budget_value(),
        initial_tokens in budget_value(),
        initial_duration in budget_value(),
        deduct_episodes in prop::collection::vec(deduction_amount(), 0..10),
        deduct_tool_calls in prop::collection::vec(deduction_amount(), 0..10),
        deduct_tokens in prop::collection::vec(deduction_amount(), 0..10),
        deduct_duration in prop::collection::vec(deduction_amount(), 0..10),
    ) {
        let mut budget = Budget::new(
            initial_episodes,
            initial_tool_calls,
            initial_tokens,
            initial_duration,
        );

        // Apply deductions (ignore errors)
        for amount in deduct_episodes {
            let _ = budget.deduct_episodes(amount);
        }
        for amount in deduct_tool_calls {
            let _ = budget.deduct_tool_calls(amount);
        }
        for amount in deduct_tokens {
            let _ = budget.deduct_tokens(amount);
        }
        for amount in deduct_duration {
            let _ = budget.deduct_duration_ms(amount);
        }

        // Verify invariants
        prop_assert!(budget.remaining_episodes() <= budget.initial_episodes());
        prop_assert!(budget.remaining_tool_calls() <= budget.initial_tool_calls());
        prop_assert!(budget.remaining_tokens() <= budget.initial_tokens());
        prop_assert!(budget.remaining_duration_ms() <= budget.initial_duration_ms());
    }

    /// Property: Consumed + remaining always equals initial.
    #[test]
    fn prop_consumed_plus_remaining_equals_initial(
        initial_episodes in budget_value(),
        initial_tool_calls in budget_value(),
        initial_tokens in budget_value(),
        initial_duration in budget_value(),
        deduct_episodes in prop::collection::vec(deduction_amount(), 0..10),
    ) {
        let mut budget = Budget::new(
            initial_episodes,
            initial_tool_calls,
            initial_tokens,
            initial_duration,
        );

        // Apply deductions (ignore errors)
        for amount in deduct_episodes {
            let _ = budget.deduct_episodes(amount);
        }

        // Verify conservation law
        prop_assert_eq!(
            budget.consumed_episodes() + budget.remaining_episodes(),
            budget.initial_episodes()
        );
        prop_assert_eq!(
            budget.consumed_tool_calls() + budget.remaining_tool_calls(),
            budget.initial_tool_calls()
        );
        prop_assert_eq!(
            budget.consumed_tokens() + budget.remaining_tokens(),
            budget.initial_tokens()
        );
        prop_assert_eq!(
            budget.consumed_duration_ms() + budget.remaining_duration_ms(),
            budget.initial_duration_ms()
        );
    }

    /// Property: Budget is exhausted if and only if some remaining is zero.
    #[test]
    fn prop_exhausted_iff_zero_remaining(budget in budget_strategy()) {
        let is_exhausted = budget.is_exhausted();
        let has_zero = budget.remaining_episodes() == 0
            || budget.remaining_tool_calls() == 0
            || budget.remaining_tokens() == 0
            || budget.remaining_duration_ms() == 0;

        prop_assert_eq!(is_exhausted, has_zero);
    }

    /// Property: Successful deduction decreases remaining by exactly the amount.
    #[test]
    fn prop_successful_deduction_decreases_exactly(
        initial in 1u64..1_000_000_000,
        deduct in 1u64..1_000_000_000,
    ) {
        let mut budget = Budget::new(initial, initial, initial, initial);

        if deduct <= initial {
            let before = budget.remaining_episodes();
            budget.deduct_episodes(deduct).unwrap();
            prop_assert_eq!(budget.remaining_episodes(), before - deduct);
        }
    }

    /// Property: Failed deduction leaves budget unchanged.
    #[test]
    fn prop_failed_deduction_unchanged(
        initial in 0u64..1_000_000,
        deduct in 1u64..1_000_000_000,
    ) {
        let mut budget = Budget::new(initial, initial, initial, initial);

        if deduct > initial {
            let before_episodes = budget.remaining_episodes();
            let before_tool_calls = budget.remaining_tool_calls();
            let before_tokens = budget.remaining_tokens();
            let before_duration = budget.remaining_duration_ms();

            let result = budget.deduct_episodes(deduct);
            prop_assert!(result.is_err());

            prop_assert_eq!(budget.remaining_episodes(), before_episodes);
            prop_assert_eq!(budget.remaining_tool_calls(), before_tool_calls);
            prop_assert_eq!(budget.remaining_tokens(), before_tokens);
            prop_assert_eq!(budget.remaining_duration_ms(), before_duration);
        }
    }

    /// Property: Atomic deduction is all-or-nothing.
    #[test]
    fn prop_atomic_deduction_all_or_nothing(
        initial in 1u64..1_000_000,
        d_episodes in 0u64..100_000,
        d_tool_calls in 0u64..100_000,
        d_tokens in 0u64..100_000,
        d_duration in 0u64..100_000,
    ) {
        let mut budget = Budget::new(initial, initial, initial, initial);
        let before = budget.clone();

        let result = budget.deduct(d_episodes, d_tool_calls, d_tokens, d_duration);

        if result.is_ok() {
            // All values should have decreased
            prop_assert_eq!(budget.remaining_episodes(), initial - d_episodes);
            prop_assert_eq!(budget.remaining_tool_calls(), initial - d_tool_calls);
            prop_assert_eq!(budget.remaining_tokens(), initial - d_tokens);
            prop_assert_eq!(budget.remaining_duration_ms(), initial - d_duration);
        } else {
            // Budget should be unchanged
            prop_assert_eq!(budget, before);
        }
    }

    /// Property: Derived sub-budget is always bounded by parent.
    #[test]
    fn prop_derived_budget_bounded(
        parent in budget_strategy(),
        requested in budget_strategy(),
    ) {
        let derived = parent.derive_sub_budget(&requested);

        prop_assert!(derived.remaining_episodes() <= parent.remaining_episodes());
        prop_assert!(derived.remaining_tool_calls() <= parent.remaining_tool_calls());
        prop_assert!(derived.remaining_tokens() <= parent.remaining_tokens());
        prop_assert!(derived.remaining_duration_ms() <= parent.remaining_duration_ms());
    }

    /// Property: can_accommodate is consistent with derive_sub_budget.
    #[test]
    fn prop_can_accommodate_consistency(
        parent in budget_strategy(),
        requested in budget_strategy(),
    ) {
        let can_accommodate = parent.can_accommodate(&requested);
        let derived = parent.derive_sub_budget(&requested);

        if can_accommodate {
            // If we can accommodate, derived should equal requested
            prop_assert_eq!(derived.remaining_episodes(), requested.initial_episodes());
            prop_assert_eq!(derived.remaining_tool_calls(), requested.initial_tool_calls());
            prop_assert_eq!(derived.remaining_tokens(), requested.initial_tokens());
            prop_assert_eq!(derived.remaining_duration_ms(), requested.initial_duration_ms());
        }
    }
}
