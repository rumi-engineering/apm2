#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Budget enforcement for session resource limits.
//!
//! This module implements budget tracking and enforcement for the APM2 kernel.
//! Sessions operate under explicit budgets for:
//! - **Tokens**: Maximum inference tokens consumed
//! - **Tool calls**: Maximum number of tool invocations
//! - **Time**: Maximum active execution time for the session
//!
//! # Security Model
//!
//! Budget enforcement is a **fail-closed** security mechanism:
//! - Requests are denied when any budget is exceeded
//! - Budget checks occur before tool execution
//! - Exceeding a budget results in a `BudgetExceeded` event
//!
//! # Time Budget Semantics
//!
//! **IMPORTANT**: The time budget tracks **active execution time**, not
//! wall-clock session duration. This means:
//!
//! - Time is measured using `std::time::Instant::elapsed()` from process start
//! - For restored sessions, `time_offset_ms` is added to account for previous
//!   execution time
//! - System suspends, process restarts, or network delays do NOT count against
//!   the time budget unless explicitly restored
//!
//! If you need wall-clock session expiry (e.g., "session must end within 1 hour
//! of creation regardless of activity"), use `started_at_ns` with external
//! `SystemTime` comparisons instead of the built-in time budget enforcement.
//!
//! # Design
//!
//! The budget system integrates with the policy layer (TCK-00010) to:
//! 1. Check budgets before allowing tool requests
//! 2. Charge consumption after successful operations
//! 3. Emit events when budgets are exceeded
//!
//! # Example
//!
//! ```rust
//! use apm2_core::budget::{BudgetConfig, BudgetTracker, BudgetType};
//!
//! // Configure budgets for a session
//! let config = BudgetConfig::builder()
//!     .token_budget(100_000)      // 100k tokens
//!     .tool_call_budget(500)      // 500 tool calls
//!     .time_budget_ms(3_600_000)  // 1 hour
//!     .build();
//!
//! // Create a tracker for the session
//! let mut tracker = BudgetTracker::new("session-123", config);
//!
//! // Check if a tool call can proceed
//! if tracker.can_charge(BudgetType::ToolCalls, 1) {
//!     // Execute the tool...
//!     tracker.charge(BudgetType::ToolCalls, 1).unwrap();
//! }
//!
//! // Check for budget exceeded
//! for &budget_type in BudgetType::all() {
//!     if tracker.is_exceeded(budget_type) {
//!         // Handle budget exceeded for this type
//!     }
//! }
//! ```

use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Types of resource budgets that can be tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BudgetType {
    /// Token budget for inference calls.
    Token,
    /// Tool call budget (number of tool invocations).
    ToolCalls,
    /// Time budget in milliseconds.
    Time,
}

impl BudgetType {
    /// Returns all budget types.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Token, Self::ToolCalls, Self::Time]
    }

    /// Returns the string representation for protocol events.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Token => "TOKEN",
            Self::ToolCalls => "TOOL_CALLS",
            Self::Time => "TIME",
        }
    }
}

impl std::fmt::Display for BudgetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Configuration for session budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum tokens that can be consumed (0 = unlimited).
    pub token_budget: u64,
    /// Maximum tool calls that can be made (0 = unlimited).
    pub tool_call_budget: u64,
    /// Maximum time in milliseconds (0 = unlimited).
    pub time_budget_ms: u64,
}

impl BudgetConfig {
    /// Creates a new budget configuration builder.
    #[must_use]
    pub const fn builder() -> BudgetConfigBuilder {
        BudgetConfigBuilder::new()
    }

    /// Creates a configuration with all budgets unlimited.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            token_budget: 0,
            tool_call_budget: 0,
            time_budget_ms: 0,
        }
    }

    /// Returns the limit for a given budget type.
    #[must_use]
    pub const fn limit(&self, budget_type: BudgetType) -> u64 {
        match budget_type {
            BudgetType::Token => self.token_budget,
            BudgetType::ToolCalls => self.tool_call_budget,
            BudgetType::Time => self.time_budget_ms,
        }
    }

    /// Returns `true` if the given budget type has a limit (not unlimited).
    #[must_use]
    pub const fn has_limit(&self, budget_type: BudgetType) -> bool {
        self.limit(budget_type) > 0
    }
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            // Default budgets provide reasonable limits for typical sessions
            token_budget: 1_000_000,   // 1M tokens
            tool_call_budget: 10_000,  // 10k tool calls
            time_budget_ms: 3_600_000, // 1 hour
        }
    }
}

/// Builder for [`BudgetConfig`].
#[derive(Debug, Clone)]
pub struct BudgetConfigBuilder {
    token_budget: u64,
    tool_call_budget: u64,
    time_budget_ms: u64,
}

impl BudgetConfigBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            token_budget: 1_000_000,
            tool_call_budget: 10_000,
            time_budget_ms: 3_600_000,
        }
    }

    /// Sets the token budget.
    #[must_use]
    pub const fn token_budget(mut self, budget: u64) -> Self {
        self.token_budget = budget;
        self
    }

    /// Sets the tool call budget.
    #[must_use]
    pub const fn tool_call_budget(mut self, budget: u64) -> Self {
        self.tool_call_budget = budget;
        self
    }

    /// Sets the time budget in milliseconds.
    #[must_use]
    pub const fn time_budget_ms(mut self, budget: u64) -> Self {
        self.time_budget_ms = budget;
        self
    }

    /// Builds the configuration.
    #[must_use]
    pub const fn build(self) -> BudgetConfig {
        BudgetConfig {
            token_budget: self.token_budget,
            tool_call_budget: self.tool_call_budget,
            time_budget_ms: self.time_budget_ms,
        }
    }
}

impl Default for BudgetConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a budget check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetCheckResult {
    /// The operation is allowed within budget.
    Allowed {
        /// The budget type that was checked.
        budget_type: BudgetType,
        /// Current consumption before the charge.
        current: u64,
        /// The limit for this budget.
        limit: u64,
        /// The amount that would be charged.
        charge: u64,
    },
    /// The operation would exceed the budget.
    Exceeded {
        /// The budget type that was exceeded.
        budget_type: BudgetType,
        /// Current consumption.
        consumed: u64,
        /// The limit for this budget.
        limit: u64,
        /// The amount that was requested.
        requested: u64,
    },
    /// The budget type is unlimited (no check needed).
    Unlimited {
        /// The budget type that is unlimited.
        budget_type: BudgetType,
    },
}

impl BudgetCheckResult {
    /// Returns `true` if the operation is allowed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. } | Self::Unlimited { .. })
    }

    /// Returns `true` if the budget was exceeded.
    #[must_use]
    pub const fn is_exceeded(&self) -> bool {
        matches!(self, Self::Exceeded { .. })
    }
}

/// Tracks budget consumption for a session.
#[derive(Debug, Clone)]
pub struct BudgetTracker {
    /// Session ID being tracked.
    session_id: String,
    /// Budget configuration.
    config: BudgetConfig,
    /// Tokens consumed.
    tokens_consumed: u64,
    /// Tool calls made.
    tool_calls_consumed: u64,
    /// Session start time for time budget tracking.
    started_at: Instant,
    /// Start timestamp in nanoseconds (for serialization/events).
    started_at_ns: u64,
    /// Time offset in milliseconds (for restored sessions).
    time_offset_ms: u64,
}

impl BudgetTracker {
    /// Creates a new budget tracker for a session.
    #[must_use]
    pub fn new(session_id: impl Into<String>, config: BudgetConfig) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            tokens_consumed: 0,
            tool_calls_consumed: 0,
            started_at: Instant::now(),
            started_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
                .unwrap_or(0),
            time_offset_ms: 0,
        }
    }

    /// Creates a new budget tracker with restored state.
    ///
    /// This is used when resuming a session to restore its budget consumption.
    #[must_use]
    pub fn restore(
        session_id: impl Into<String>,
        config: BudgetConfig,
        started_at_ns: u64,
        tokens_consumed: u64,
        tool_calls_consumed: u64,
        time_offset_ms: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            tokens_consumed,
            tool_calls_consumed,
            started_at: Instant::now(),
            started_at_ns,
            time_offset_ms,
        }
    }

    /// Creates a new budget tracker with a specific start timestamp.
    ///
    /// This is useful for testing and for restoring state from checkpoints.
    #[must_use]
    pub fn with_start_time(
        session_id: impl Into<String>,
        config: BudgetConfig,
        started_at_ns: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            tokens_consumed: 0,
            tool_calls_consumed: 0,
            started_at: Instant::now(),
            started_at_ns,
            time_offset_ms: 0,
        }
    }

    /// Returns the session ID.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the session start timestamp in nanoseconds since Unix epoch.
    #[must_use]
    pub const fn started_at_ns(&self) -> u64 {
        self.started_at_ns
    }

    /// Returns the budget configuration.
    #[must_use]
    pub const fn config(&self) -> &BudgetConfig {
        &self.config
    }

    /// Returns the limit for a budget type.
    #[must_use]
    pub const fn limit(&self, budget_type: BudgetType) -> u64 {
        self.config.limit(budget_type)
    }

    /// Returns the current consumption for a budget type.
    #[must_use]
    pub fn consumed(&self, budget_type: BudgetType) -> u64 {
        match budget_type {
            BudgetType::Token => self.tokens_consumed,
            BudgetType::ToolCalls => self.tool_calls_consumed,
            BudgetType::Time => self.elapsed_ms(),
        }
    }

    /// Returns the remaining budget for a budget type.
    ///
    /// Returns `u64::MAX` for unlimited budgets.
    #[must_use]
    pub fn remaining(&self, budget_type: BudgetType) -> u64 {
        let limit = self.limit(budget_type);
        if limit == 0 {
            return u64::MAX; // Unlimited
        }
        limit.saturating_sub(self.consumed(budget_type))
    }

    /// Returns the elapsed time in milliseconds since the session started.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        // Saturate at u64::MAX for extremely long sessions (unlikely in practice)
        let current_run_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.time_offset_ms.saturating_add(current_run_ms)
    }

    /// Returns `true` if the given budget type is exceeded.
    #[must_use]
    pub fn is_exceeded(&self, budget_type: BudgetType) -> bool {
        let limit = self.limit(budget_type);
        if limit == 0 {
            return false; // Unlimited
        }
        self.consumed(budget_type) >= limit
    }

    /// Returns `true` if any budget is exceeded.
    #[must_use]
    pub fn is_any_exceeded(&self) -> bool {
        BudgetType::all().iter().any(|&bt| self.is_exceeded(bt))
    }

    /// Returns the first exceeded budget type, if any.
    #[must_use]
    pub fn first_exceeded(&self) -> Option<BudgetType> {
        BudgetType::all()
            .iter()
            .copied()
            .find(|&bt| self.is_exceeded(bt))
    }

    /// Checks if an amount can be charged without exceeding the budget.
    #[must_use]
    pub fn check(&self, budget_type: BudgetType, amount: u64) -> BudgetCheckResult {
        let limit = self.limit(budget_type);

        // Check for unlimited budget
        if limit == 0 {
            return BudgetCheckResult::Unlimited { budget_type };
        }

        let current = self.consumed(budget_type);
        let would_consume = current.saturating_add(amount);

        if would_consume > limit {
            BudgetCheckResult::Exceeded {
                budget_type,
                consumed: current,
                limit,
                requested: amount,
            }
        } else {
            BudgetCheckResult::Allowed {
                budget_type,
                current,
                limit,
                charge: amount,
            }
        }
    }

    /// Returns `true` if the amount can be charged without exceeding budget.
    #[must_use]
    pub fn can_charge(&self, budget_type: BudgetType, amount: u64) -> bool {
        self.check(budget_type, amount).is_allowed()
    }

    /// Charges an amount against the budget.
    ///
    /// # Errors
    ///
    /// Returns `BudgetChargeError::TimeCannotBeCharged` if the budget type
    /// is `Time` (time is tracked automatically).
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::budget::{BudgetChargeError, BudgetConfig, BudgetTracker, BudgetType};
    ///
    /// let mut tracker = BudgetTracker::new("session-1", BudgetConfig::default());
    ///
    /// // Token and ToolCalls can be charged
    /// assert!(tracker.charge(BudgetType::Token, 100).is_ok());
    /// assert!(tracker.charge(BudgetType::ToolCalls, 1).is_ok());
    ///
    /// // Time cannot be charged (tracked automatically)
    /// assert_eq!(
    ///     tracker.charge(BudgetType::Time, 100),
    ///     Err(BudgetChargeError::TimeCannotBeCharged)
    /// );
    /// ```
    #[allow(clippy::missing_const_for_fn)] // Uses saturating_add which is not const
    pub fn charge(
        &mut self,
        budget_type: BudgetType,
        amount: u64,
    ) -> Result<(), BudgetChargeError> {
        match budget_type {
            BudgetType::Token => {
                self.tokens_consumed = self.tokens_consumed.saturating_add(amount);
                Ok(())
            },
            BudgetType::ToolCalls => {
                self.tool_calls_consumed = self.tool_calls_consumed.saturating_add(amount);
                Ok(())
            },
            BudgetType::Time => Err(BudgetChargeError::TimeCannotBeCharged),
        }
    }

    /// Tries to charge an amount, returning an error if the budget would be
    /// exceeded.
    ///
    /// # Errors
    ///
    /// Returns `BudgetCheckResult::Exceeded` if the charge would exceed the
    /// budget.
    ///
    /// # Note
    ///
    /// This method silently ignores attempts to charge `BudgetType::Time`
    /// (since time is tracked automatically). The check result is still
    /// returned, but no charge is made.
    pub fn try_charge(&mut self, budget_type: BudgetType, amount: u64) -> BudgetCheckResult {
        let result = self.check(budget_type, amount);
        if result.is_allowed() && !matches!(budget_type, BudgetType::Time) {
            // SAFETY: charge() only fails for Time, which we explicitly exclude
            let _ = self.charge(budget_type, amount);
        }
        result
    }

    /// Increments the tool call counter by 1.
    ///
    /// # Panics
    ///
    /// This method will never panic in practice. The internal `expect` call
    /// guards against an impossible case (charging `ToolCalls` always
    /// succeeds).
    pub fn record_tool_call(&mut self) {
        // SAFETY: ToolCalls is always a valid charge type
        self.charge(BudgetType::ToolCalls, 1)
            .expect("ToolCalls charge should never fail");
    }

    /// Records token consumption from an inference call.
    ///
    /// # Panics
    ///
    /// This method will never panic in practice. The internal `expect` call
    /// guards against an impossible case (charging `Token` always succeeds).
    pub fn record_tokens(&mut self, tokens: u64) {
        // SAFETY: Token is always a valid charge type
        self.charge(BudgetType::Token, tokens)
            .expect("Token charge should never fail");
    }

    /// Creates a summary of the current budget state.
    #[must_use]
    pub fn summary(&self) -> BudgetSummary {
        BudgetSummary {
            session_id: self.session_id.clone(),
            token_limit: self.config.token_budget,
            token_consumed: self.tokens_consumed,
            tool_call_limit: self.config.tool_call_budget,
            tool_calls_consumed: self.tool_calls_consumed,
            time_limit_ms: self.config.time_budget_ms,
            time_elapsed_ms: self.elapsed_ms(),
            is_token_exceeded: self.is_exceeded(BudgetType::Token),
            is_tool_calls_exceeded: self.is_exceeded(BudgetType::ToolCalls),
            is_time_exceeded: self.is_exceeded(BudgetType::Time),
        }
    }
}

/// Summary of a budget tracker's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSummary {
    /// Session ID.
    pub session_id: String,
    /// Token budget limit (0 = unlimited).
    pub token_limit: u64,
    /// Tokens consumed.
    pub token_consumed: u64,
    /// Tool call budget limit (0 = unlimited).
    pub tool_call_limit: u64,
    /// Tool calls consumed.
    pub tool_calls_consumed: u64,
    /// Time budget limit in ms (0 = unlimited).
    pub time_limit_ms: u64,
    /// Time elapsed in ms.
    pub time_elapsed_ms: u64,
    /// Whether token budget is exceeded.
    pub is_token_exceeded: bool,
    /// Whether tool call budget is exceeded.
    pub is_tool_calls_exceeded: bool,
    /// Whether time budget is exceeded.
    pub is_time_exceeded: bool,
}

impl BudgetSummary {
    /// Returns `true` if any budget is exceeded.
    #[must_use]
    pub const fn is_any_exceeded(&self) -> bool {
        self.is_token_exceeded || self.is_tool_calls_exceeded || self.is_time_exceeded
    }
}

/// Error returned when a budget is exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetExceededError {
    /// Session ID.
    pub session_id: String,
    /// The budget type that was exceeded.
    pub budget_type: BudgetType,
    /// The limit for this budget.
    pub limit: u64,
    /// The amount consumed.
    pub consumed: u64,
}

impl std::fmt::Display for BudgetExceededError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session {} exceeded {} budget: consumed {} of {} limit",
            self.session_id, self.budget_type, self.consumed, self.limit
        )
    }
}

impl std::error::Error for BudgetExceededError {}

/// Error returned when attempting to charge an invalid budget type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetChargeError {
    /// Attempted to charge the time budget directly.
    ///
    /// Time budget is tracked automatically via elapsed wall-clock time
    /// and cannot be charged manually.
    TimeCannotBeCharged,
}

impl std::fmt::Display for BudgetChargeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeCannotBeCharged => {
                write!(
                    f,
                    "Time budget cannot be charged directly; it is tracked automatically"
                )
            },
        }
    }
}

impl std::error::Error for BudgetChargeError {}

// ============================================================================
// Event Integration
// ============================================================================

use crate::events::{self, PolicyEvent, policy_event};

/// Creates a `BudgetExceeded` policy event from a budget check result.
///
/// This should be called when a budget is exceeded to emit an event to the
/// ledger.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_core::budget::{BudgetTracker, BudgetType, create_budget_exceeded_event};
///
/// let tracker = BudgetTracker::new("session-123", BudgetConfig::default());
/// // ... after budget exceeded ...
/// if let Some(exceeded) = tracker.first_exceeded() {
///     let event = create_budget_exceeded_event(&tracker, exceeded);
///     // Emit event to ledger...
/// }
/// ```
#[must_use]
pub fn create_budget_exceeded_event(
    tracker: &BudgetTracker,
    budget_type: BudgetType,
) -> PolicyEvent {
    PolicyEvent {
        event: Some(policy_event::Event::BudgetExceeded(
            events::BudgetExceeded {
                session_id: tracker.session_id().to_string(),
                budget_type: budget_type.as_str().to_string(),
                limit: tracker.limit(budget_type),
                consumed: tracker.consumed(budget_type),
            },
        )),
    }
}

/// Creates a `BudgetExceeded` policy event from components.
///
/// This is useful when you have the individual components rather than a
/// tracker.
#[must_use]
#[allow(clippy::missing_const_for_fn)] // Cannot be const due to heap allocations
pub fn create_budget_exceeded_event_from_parts(
    session_id: String,
    budget_type: BudgetType,
    limit: u64,
    consumed: u64,
) -> PolicyEvent {
    PolicyEvent {
        event: Some(policy_event::Event::BudgetExceeded(
            events::BudgetExceeded {
                session_id,
                budget_type: budget_type.as_str().to_string(),
                limit,
                consumed,
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_type_all() {
        let all = BudgetType::all();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&BudgetType::Token));
        assert!(all.contains(&BudgetType::ToolCalls));
        assert!(all.contains(&BudgetType::Time));
    }

    #[test]
    fn test_budget_type_as_str() {
        assert_eq!(BudgetType::Token.as_str(), "TOKEN");
        assert_eq!(BudgetType::ToolCalls.as_str(), "TOOL_CALLS");
        assert_eq!(BudgetType::Time.as_str(), "TIME");
    }

    #[test]
    fn test_budget_config_default() {
        let config = BudgetConfig::default();
        assert_eq!(config.token_budget, 1_000_000);
        assert_eq!(config.tool_call_budget, 10_000);
        assert_eq!(config.time_budget_ms, 3_600_000);
    }

    #[test]
    fn test_budget_config_unlimited() {
        let config = BudgetConfig::unlimited();
        assert_eq!(config.token_budget, 0);
        assert_eq!(config.tool_call_budget, 0);
        assert_eq!(config.time_budget_ms, 0);
        assert!(!config.has_limit(BudgetType::Token));
        assert!(!config.has_limit(BudgetType::ToolCalls));
        assert!(!config.has_limit(BudgetType::Time));
    }

    #[test]
    fn test_budget_config_builder() {
        let config = BudgetConfig::builder()
            .token_budget(50_000)
            .tool_call_budget(100)
            .time_budget_ms(60_000)
            .build();

        assert_eq!(config.token_budget, 50_000);
        assert_eq!(config.tool_call_budget, 100);
        assert_eq!(config.time_budget_ms, 60_000);
    }

    #[test]
    fn test_budget_tracker_new() {
        let config = BudgetConfig::default();
        let tracker = BudgetTracker::new("session-1", config);

        assert_eq!(tracker.session_id(), "session-1");
        assert_eq!(tracker.consumed(BudgetType::Token), 0);
        assert_eq!(tracker.consumed(BudgetType::ToolCalls), 0);
        assert!(!tracker.is_exceeded(BudgetType::Token));
        assert!(!tracker.is_exceeded(BudgetType::ToolCalls));
    }

    #[test]
    fn test_budget_tracker_charge_tokens() {
        let config = BudgetConfig::builder().token_budget(1000).build();
        let mut tracker = BudgetTracker::new("session-1", config);

        tracker.charge(BudgetType::Token, 100).unwrap();
        assert_eq!(tracker.consumed(BudgetType::Token), 100);
        assert_eq!(tracker.remaining(BudgetType::Token), 900);
        assert!(!tracker.is_exceeded(BudgetType::Token));

        tracker.charge(BudgetType::Token, 900).unwrap();
        assert_eq!(tracker.consumed(BudgetType::Token), 1000);
        assert_eq!(tracker.remaining(BudgetType::Token), 0);
        assert!(tracker.is_exceeded(BudgetType::Token));
    }

    #[test]
    fn test_budget_tracker_charge_tool_calls() {
        let config = BudgetConfig::builder().tool_call_budget(10).build();
        let mut tracker = BudgetTracker::new("session-1", config);

        for _ in 0..10 {
            tracker.record_tool_call();
        }

        assert_eq!(tracker.consumed(BudgetType::ToolCalls), 10);
        assert!(tracker.is_exceeded(BudgetType::ToolCalls));
    }

    #[test]
    fn test_budget_tracker_check() {
        let config = BudgetConfig::builder().token_budget(100).build();
        let tracker = BudgetTracker::new("session-1", config);

        // Check within budget
        let result = tracker.check(BudgetType::Token, 50);
        assert!(result.is_allowed());
        assert!(!result.is_exceeded());

        // Check would exceed
        let result = tracker.check(BudgetType::Token, 150);
        assert!(!result.is_allowed());
        assert!(result.is_exceeded());
    }

    #[test]
    fn test_budget_tracker_check_unlimited() {
        let config = BudgetConfig::unlimited();
        let tracker = BudgetTracker::new("session-1", config);

        let result = tracker.check(BudgetType::Token, u64::MAX);
        assert!(matches!(result, BudgetCheckResult::Unlimited { .. }));
        assert!(result.is_allowed());
    }

    #[test]
    fn test_budget_tracker_try_charge() {
        let config = BudgetConfig::builder().token_budget(100).build();
        let mut tracker = BudgetTracker::new("session-1", config);

        // Successful charge
        let result = tracker.try_charge(BudgetType::Token, 50);
        assert!(result.is_allowed());
        assert_eq!(tracker.consumed(BudgetType::Token), 50);

        // Exceeding charge
        let result = tracker.try_charge(BudgetType::Token, 100);
        assert!(result.is_exceeded());
        // Should not have charged
        assert_eq!(tracker.consumed(BudgetType::Token), 50);
    }

    #[test]
    fn test_budget_tracker_first_exceeded() {
        let config = BudgetConfig::builder()
            .token_budget(100)
            .tool_call_budget(10)
            .build();
        let mut tracker = BudgetTracker::new("session-1", config);

        assert!(tracker.first_exceeded().is_none());

        tracker.charge(BudgetType::Token, 100).unwrap();
        assert_eq!(tracker.first_exceeded(), Some(BudgetType::Token));
    }

    #[test]
    fn test_budget_tracker_summary() {
        let config = BudgetConfig::builder()
            .token_budget(1000)
            .tool_call_budget(100)
            .time_budget_ms(60_000)
            .build();
        let mut tracker = BudgetTracker::new("session-1", config);

        tracker.charge(BudgetType::Token, 500).unwrap();
        tracker.charge(BudgetType::ToolCalls, 50).unwrap();

        let summary = tracker.summary();
        assert_eq!(summary.session_id, "session-1");
        assert_eq!(summary.token_limit, 1000);
        assert_eq!(summary.token_consumed, 500);
        assert_eq!(summary.tool_call_limit, 100);
        assert_eq!(summary.tool_calls_consumed, 50);
        assert!(!summary.is_token_exceeded);
        assert!(!summary.is_tool_calls_exceeded);
        assert!(!summary.is_any_exceeded());
    }

    #[test]
    fn test_budget_exceeded_error() {
        let error = BudgetExceededError {
            session_id: "session-1".to_string(),
            budget_type: BudgetType::Token,
            limit: 1000,
            consumed: 1500,
        };

        let msg = error.to_string();
        assert!(msg.contains("session-1"));
        assert!(msg.contains("TOKEN"));
        assert!(msg.contains("1500"));
        assert!(msg.contains("1000"));
    }

    #[test]
    fn test_saturating_add() {
        let config = BudgetConfig::builder().token_budget(u64::MAX).build();
        let mut tracker = BudgetTracker::new("session-1", config);

        tracker.charge(BudgetType::Token, u64::MAX - 10).unwrap();
        tracker.charge(BudgetType::Token, 100).unwrap();

        // Should saturate at MAX, not overflow
        assert_eq!(tracker.consumed(BudgetType::Token), u64::MAX);
    }

    #[test]
    fn test_remaining_unlimited() {
        let config = BudgetConfig::unlimited();
        let tracker = BudgetTracker::new("session-1", config);

        assert_eq!(tracker.remaining(BudgetType::Token), u64::MAX);
        assert_eq!(tracker.remaining(BudgetType::ToolCalls), u64::MAX);
        assert_eq!(tracker.remaining(BudgetType::Time), u64::MAX);
    }

    #[test]
    fn test_charge_time_returns_error() {
        let config = BudgetConfig::default();
        let mut tracker = BudgetTracker::new("session-1", config);

        // Time budget cannot be charged directly
        let result = tracker.charge(BudgetType::Time, 100);
        assert_eq!(result, Err(BudgetChargeError::TimeCannotBeCharged));

        // Token and ToolCalls can be charged
        assert!(tracker.charge(BudgetType::Token, 100).is_ok());
        assert!(tracker.charge(BudgetType::ToolCalls, 1).is_ok());

        // Verify consumption was recorded for valid types
        assert_eq!(tracker.consumed(BudgetType::Token), 100);
        assert_eq!(tracker.consumed(BudgetType::ToolCalls), 1);
    }

    // ========================================================================
    // Event Integration Tests
    // ========================================================================

    #[test]
    fn test_create_budget_exceeded_event() {
        use crate::events::policy_event;

        let config = BudgetConfig::builder()
            .token_budget(1000)
            .tool_call_budget(100)
            .build();
        let mut tracker = BudgetTracker::new("session-123", config);

        // Exceed the token budget
        tracker.charge(BudgetType::Token, 1500).unwrap();

        let event = super::create_budget_exceeded_event(&tracker, BudgetType::Token);

        match event.event {
            Some(policy_event::Event::BudgetExceeded(exceeded)) => {
                assert_eq!(exceeded.session_id, "session-123");
                assert_eq!(exceeded.budget_type, "TOKEN");
                assert_eq!(exceeded.limit, 1000);
                assert_eq!(exceeded.consumed, 1500);
            },
            _ => panic!("Expected BudgetExceeded event"),
        }
    }

    #[test]
    fn test_create_budget_exceeded_event_from_parts() {
        use crate::events::policy_event;

        let event = super::create_budget_exceeded_event_from_parts(
            "session-456".to_string(),
            BudgetType::ToolCalls,
            500,
            750,
        );

        match event.event {
            Some(policy_event::Event::BudgetExceeded(exceeded)) => {
                assert_eq!(exceeded.session_id, "session-456");
                assert_eq!(exceeded.budget_type, "TOOL_CALLS");
                assert_eq!(exceeded.limit, 500);
                assert_eq!(exceeded.consumed, 750);
            },
            _ => panic!("Expected BudgetExceeded event"),
        }
    }

    #[test]
    fn test_create_budget_exceeded_event_time() {
        use crate::events::policy_event;

        // Create a tracker with a very short time budget
        let config = BudgetConfig::builder()
            .time_budget_ms(1) // 1ms
            .build();
        let tracker = BudgetTracker::new("session-789", config);

        // Wait briefly to exceed
        std::thread::sleep(std::time::Duration::from_millis(5));

        let event = super::create_budget_exceeded_event(&tracker, BudgetType::Time);

        match event.event {
            Some(policy_event::Event::BudgetExceeded(exceeded)) => {
                assert_eq!(exceeded.session_id, "session-789");
                assert_eq!(exceeded.budget_type, "TIME");
                assert_eq!(exceeded.limit, 1);
                assert!(exceeded.consumed >= 1); // Should have elapsed at least 1ms
            },
            _ => panic!("Expected BudgetExceeded event"),
        }
    }

    #[test]
    fn test_budget_tracker_restore() {
        let config = BudgetConfig::default();
        let tracker = BudgetTracker::restore(
            "session-restored",
            config,
            123_456_789, // started_at_ns
            1000,        // tokens
            50,          // tool_calls
            300_000,     // time_offset_ms (5 minutes)
        );

        assert_eq!(tracker.consumed(BudgetType::Token), 1000);
        assert_eq!(tracker.consumed(BudgetType::ToolCalls), 50);
        assert!(tracker.consumed(BudgetType::Time) >= 300_000);
        assert_eq!(tracker.started_at_ns(), 123_456_789);
    }
}
