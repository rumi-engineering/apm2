//! Entropy budget tracking for sessions.
//!
//! This module implements entropy budget tracking for the crash-only session
//! design. Entropy represents the accumulated "chaos" in a session (errors,
//! stalls, violations) and when it exceeds the budget, the session must be
//! terminated.
//!
//! # Design
//!
//! The entropy budget tracker:
//! - Tracks entropy consumption from errors, violations, and stalls
//! - Emits events when the budget is exceeded
//! - Integrates with the session lifecycle for termination
//!
//! # Entropy Sources
//!
//! - **Errors**: Tool failures, execution errors (weight: configurable)
//! - **Violations**: Policy violations (weight: higher, as they indicate
//!   misbehavior)
//! - **Stalls**: Detected lack of progress (weight: configurable)
//!
//! # Example
//!
//! ```rust
//! use apm2_core::session::entropy::{EntropyBudgetConfig, EntropyTracker};
//!
//! let config = EntropyBudgetConfig::default();
//! let mut tracker = EntropyTracker::new("session-123", config);
//!
//! // Record errors
//! tracker.record_error("tool_failure");
//! tracker.record_error("tool_failure");
//!
//! // Check if budget exceeded
//! if tracker.is_exceeded() {
//!     // Session should be terminated
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Configuration for entropy budget tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntropyBudgetConfig {
    /// Total entropy budget for the session.
    pub budget: u64,

    /// Entropy cost per error event.
    pub error_weight: u64,

    /// Entropy cost per policy violation.
    pub violation_weight: u64,

    /// Entropy cost per stall detection.
    pub stall_weight: u64,

    /// Entropy cost per tool timeout.
    pub timeout_weight: u64,
}

impl EntropyBudgetConfig {
    /// Creates a new configuration with the specified budget.
    #[must_use]
    pub const fn with_budget(budget: u64) -> Self {
        Self {
            budget,
            error_weight: 10,
            violation_weight: 50,
            stall_weight: 25,
            timeout_weight: 15,
        }
    }

    /// Creates a strict configuration with higher weights.
    #[must_use]
    pub const fn strict(budget: u64) -> Self {
        Self {
            budget,
            error_weight: 25,
            violation_weight: 100,
            stall_weight: 50,
            timeout_weight: 30,
        }
    }

    /// Creates a lenient configuration with lower weights.
    #[must_use]
    pub const fn lenient(budget: u64) -> Self {
        Self {
            budget,
            error_weight: 5,
            violation_weight: 25,
            stall_weight: 10,
            timeout_weight: 8,
        }
    }
}

impl Default for EntropyBudgetConfig {
    fn default() -> Self {
        Self::with_budget(1000)
    }
}

/// Types of entropy-inducing events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropySource {
    /// An error occurred (tool failure, execution error).
    Error,
    /// A policy violation was detected.
    Violation,
    /// A stall was detected (no progress).
    Stall,
    /// A tool execution timed out.
    Timeout,
}

impl EntropySource {
    /// Returns the budget type string for protocol events.
    #[must_use]
    pub const fn as_budget_type(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Violation => "VIOLATION",
            Self::Stall => "STALL",
            Self::Timeout => "TIMEOUT",
        }
    }
}

impl std::fmt::Display for EntropySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_budget_type())
    }
}

/// Record of an entropy-contributing event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntropyEvent {
    /// The source of the entropy.
    pub source: EntropySource,
    /// Details about the event.
    pub details: String,
    /// The entropy cost charged.
    pub cost: u64,
    /// Timestamp when the event occurred (nanoseconds since epoch).
    pub timestamp_ns: u64,
}

/// Tracks entropy consumption for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyTracker {
    /// Session ID being tracked.
    session_id: String,

    /// Configuration for entropy weights and budget.
    config: EntropyBudgetConfig,

    /// Total entropy consumed so far.
    consumed: u64,

    /// Count of errors recorded.
    error_count: u64,

    /// Count of violations recorded.
    violation_count: u64,

    /// Count of stalls recorded.
    stall_count: u64,

    /// Count of timeouts recorded.
    timeout_count: u64,

    /// History of entropy events.
    events: Vec<EntropyEvent>,
}

impl EntropyTracker {
    /// Creates a new entropy tracker for a session.
    #[must_use]
    pub fn new(session_id: impl Into<String>, config: EntropyBudgetConfig) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            consumed: 0,
            error_count: 0,
            violation_count: 0,
            stall_count: 0,
            timeout_count: 0,
            events: Vec::new(),
        }
    }

    /// Returns the session ID.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &EntropyBudgetConfig {
        &self.config
    }

    /// Returns the total budget.
    #[must_use]
    pub const fn budget(&self) -> u64 {
        self.config.budget
    }

    /// Returns the total entropy consumed.
    #[must_use]
    pub const fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Returns the remaining budget.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.config.budget.saturating_sub(self.consumed)
    }

    /// Returns `true` if the budget has been exceeded.
    #[must_use]
    pub const fn is_exceeded(&self) -> bool {
        self.consumed >= self.config.budget
    }

    /// Returns the count of errors recorded.
    #[must_use]
    pub const fn error_count(&self) -> u64 {
        self.error_count
    }

    /// Returns the count of violations recorded.
    #[must_use]
    pub const fn violation_count(&self) -> u64 {
        self.violation_count
    }

    /// Returns the count of stalls recorded.
    #[must_use]
    pub const fn stall_count(&self) -> u64 {
        self.stall_count
    }

    /// Returns the count of timeouts recorded.
    #[must_use]
    pub const fn timeout_count(&self) -> u64 {
        self.timeout_count
    }

    /// Returns the history of entropy events.
    #[must_use]
    pub fn events(&self) -> &[EntropyEvent] {
        &self.events
    }

    /// Records an error and returns the entropy cost.
    pub fn record_error(&mut self, details: impl Into<String>) -> u64 {
        self.record_event(EntropySource::Error, details, 0)
    }

    /// Records a policy violation and returns the entropy cost.
    pub fn record_violation(&mut self, details: impl Into<String>) -> u64 {
        self.record_event(EntropySource::Violation, details, 0)
    }

    /// Records a stall detection and returns the entropy cost.
    pub fn record_stall(&mut self, details: impl Into<String>) -> u64 {
        self.record_event(EntropySource::Stall, details, 0)
    }

    /// Records a timeout and returns the entropy cost.
    pub fn record_timeout(&mut self, details: impl Into<String>) -> u64 {
        self.record_event(EntropySource::Timeout, details, 0)
    }

    /// Records an entropy event with a timestamp.
    pub fn record_error_at(&mut self, details: impl Into<String>, timestamp_ns: u64) -> u64 {
        self.record_event(EntropySource::Error, details, timestamp_ns)
    }

    /// Records a violation with a timestamp.
    pub fn record_violation_at(&mut self, details: impl Into<String>, timestamp_ns: u64) -> u64 {
        self.record_event(EntropySource::Violation, details, timestamp_ns)
    }

    /// Records a stall with a timestamp.
    pub fn record_stall_at(&mut self, details: impl Into<String>, timestamp_ns: u64) -> u64 {
        self.record_event(EntropySource::Stall, details, timestamp_ns)
    }

    /// Records a timeout with a timestamp.
    pub fn record_timeout_at(&mut self, details: impl Into<String>, timestamp_ns: u64) -> u64 {
        self.record_event(EntropySource::Timeout, details, timestamp_ns)
    }

    /// Records a generic entropy event.
    fn record_event(
        &mut self,
        source: EntropySource,
        details: impl Into<String>,
        timestamp_ns: u64,
    ) -> u64 {
        let cost = self.weight_for_source(source);

        // Update counters
        match source {
            EntropySource::Error => self.error_count += 1,
            EntropySource::Violation => self.violation_count += 1,
            EntropySource::Stall => self.stall_count += 1,
            EntropySource::Timeout => self.timeout_count += 1,
        }

        // Add to consumed (saturating to prevent overflow)
        self.consumed = self.consumed.saturating_add(cost);

        // Record the event
        self.events.push(EntropyEvent {
            source,
            details: details.into(),
            cost,
            timestamp_ns,
        });

        cost
    }

    /// Returns the weight for a given entropy source.
    #[must_use]
    const fn weight_for_source(&self, source: EntropySource) -> u64 {
        match source {
            EntropySource::Error => self.config.error_weight,
            EntropySource::Violation => self.config.violation_weight,
            EntropySource::Stall => self.config.stall_weight,
            EntropySource::Timeout => self.config.timeout_weight,
        }
    }

    /// Resets the tracker to initial state.
    pub fn reset(&mut self) {
        self.consumed = 0;
        self.error_count = 0;
        self.violation_count = 0;
        self.stall_count = 0;
        self.timeout_count = 0;
        self.events.clear();
    }

    /// Creates a summary of the tracker state.
    #[must_use]
    pub fn summary(&self) -> EntropyTrackerSummary {
        EntropyTrackerSummary {
            session_id: self.session_id.clone(),
            budget: self.config.budget,
            consumed: self.consumed,
            remaining: self.remaining(),
            is_exceeded: self.is_exceeded(),
            error_count: self.error_count,
            violation_count: self.violation_count,
            stall_count: self.stall_count,
            timeout_count: self.timeout_count,
        }
    }
}

/// Summary of an entropy tracker's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntropyTrackerSummary {
    /// Session ID.
    pub session_id: String,
    /// Total budget.
    pub budget: u64,
    /// Total consumed.
    pub consumed: u64,
    /// Remaining budget.
    pub remaining: u64,
    /// Whether the budget is exceeded.
    pub is_exceeded: bool,
    /// Count of errors.
    pub error_count: u64,
    /// Count of violations.
    pub violation_count: u64,
    /// Count of stalls.
    pub stall_count: u64,
    /// Count of timeouts.
    pub timeout_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = EntropyBudgetConfig::default();
        assert_eq!(config.budget, 1000);
        assert_eq!(config.error_weight, 10);
        assert_eq!(config.violation_weight, 50);
        assert_eq!(config.stall_weight, 25);
        assert_eq!(config.timeout_weight, 15);
    }

    #[test]
    fn test_config_with_budget() {
        let config = EntropyBudgetConfig::with_budget(500);
        assert_eq!(config.budget, 500);
    }

    #[test]
    fn test_config_strict() {
        let config = EntropyBudgetConfig::strict(1000);
        assert_eq!(config.error_weight, 25);
        assert_eq!(config.violation_weight, 100);
    }

    #[test]
    fn test_config_lenient() {
        let config = EntropyBudgetConfig::lenient(1000);
        assert_eq!(config.error_weight, 5);
        assert_eq!(config.violation_weight, 25);
    }

    #[test]
    fn test_tracker_new() {
        let tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());
        assert_eq!(tracker.session_id(), "session-1");
        assert_eq!(tracker.consumed(), 0);
        assert_eq!(tracker.remaining(), 1000);
        assert!(!tracker.is_exceeded());
    }

    #[test]
    fn test_record_error() {
        let mut tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());
        let cost = tracker.record_error("tool_failure");

        assert_eq!(cost, 10);
        assert_eq!(tracker.consumed(), 10);
        assert_eq!(tracker.error_count(), 1);
        assert_eq!(tracker.remaining(), 990);
    }

    #[test]
    fn test_record_violation() {
        let mut tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());
        let cost = tracker.record_violation("policy_breach");

        assert_eq!(cost, 50);
        assert_eq!(tracker.consumed(), 50);
        assert_eq!(tracker.violation_count(), 1);
    }

    #[test]
    fn test_record_stall() {
        let mut tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());
        let cost = tracker.record_stall("no_progress");

        assert_eq!(cost, 25);
        assert_eq!(tracker.consumed(), 25);
        assert_eq!(tracker.stall_count(), 1);
    }

    #[test]
    fn test_record_timeout() {
        let mut tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());
        let cost = tracker.record_timeout("tool_timeout");

        assert_eq!(cost, 15);
        assert_eq!(tracker.consumed(), 15);
        assert_eq!(tracker.timeout_count(), 1);
    }

    #[test]
    fn test_multiple_events() {
        let mut tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());

        tracker.record_error("error1");
        tracker.record_error("error2");
        tracker.record_violation("violation1");

        assert_eq!(tracker.consumed(), 10 + 10 + 50); // 70
        assert_eq!(tracker.error_count(), 2);
        assert_eq!(tracker.violation_count(), 1);
        assert_eq!(tracker.events().len(), 3);
    }

    #[test]
    fn test_budget_exceeded() {
        let config = EntropyBudgetConfig::with_budget(100);
        let mut tracker = EntropyTracker::new("session-1", config);

        // 10 errors = 100 consumed
        for i in 0..10 {
            tracker.record_error(format!("error_{i}"));
        }

        assert_eq!(tracker.consumed(), 100);
        assert!(tracker.is_exceeded());
        assert_eq!(tracker.remaining(), 0);
    }

    #[test]
    fn test_budget_exceeded_with_violation() {
        let config = EntropyBudgetConfig::with_budget(100);
        let mut tracker = EntropyTracker::new("session-1", config);

        // 2 violations = 100 consumed
        tracker.record_violation("violation1");
        tracker.record_violation("violation2");

        assert_eq!(tracker.consumed(), 100);
        assert!(tracker.is_exceeded());
    }

    #[test]
    fn test_saturating_add() {
        let config = EntropyBudgetConfig::with_budget(u64::MAX);
        let mut tracker = EntropyTracker::new("session-1", config);

        // Set consumed to near max
        tracker.consumed = u64::MAX - 5;

        // This should saturate, not overflow
        tracker.record_error("error");

        assert_eq!(tracker.consumed(), u64::MAX);
    }

    #[test]
    fn test_event_history() {
        let mut tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());

        tracker.record_error_at("error1", 1_000_000);
        tracker.record_violation_at("violation1", 2_000_000);

        let events = tracker.events();
        assert_eq!(events.len(), 2);

        assert_eq!(events[0].source, EntropySource::Error);
        assert_eq!(events[0].details, "error1");
        assert_eq!(events[0].cost, 10);
        assert_eq!(events[0].timestamp_ns, 1_000_000);

        assert_eq!(events[1].source, EntropySource::Violation);
        assert_eq!(events[1].details, "violation1");
        assert_eq!(events[1].cost, 50);
        assert_eq!(events[1].timestamp_ns, 2_000_000);
    }

    #[test]
    fn test_reset() {
        let mut tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());

        tracker.record_error("error1");
        tracker.record_violation("violation1");

        assert_eq!(tracker.consumed(), 60);
        assert_eq!(tracker.events().len(), 2);

        tracker.reset();

        assert_eq!(tracker.consumed(), 0);
        assert_eq!(tracker.error_count(), 0);
        assert_eq!(tracker.violation_count(), 0);
        assert_eq!(tracker.events().len(), 0);
        assert!(!tracker.is_exceeded());
    }

    #[test]
    fn test_summary() {
        let mut tracker = EntropyTracker::new("session-1", EntropyBudgetConfig::default());

        tracker.record_error("error1");
        tracker.record_violation("violation1");
        tracker.record_stall("stall1");
        tracker.record_timeout("timeout1");

        let summary = tracker.summary();

        assert_eq!(summary.session_id, "session-1");
        assert_eq!(summary.budget, 1000);
        assert_eq!(summary.consumed, 100); // 10 + 50 + 25 + 15
        assert_eq!(summary.remaining, 900);
        assert!(!summary.is_exceeded);
        assert_eq!(summary.error_count, 1);
        assert_eq!(summary.violation_count, 1);
        assert_eq!(summary.stall_count, 1);
        assert_eq!(summary.timeout_count, 1);
    }

    #[test]
    fn test_entropy_source_display() {
        assert_eq!(EntropySource::Error.as_budget_type(), "ERROR");
        assert_eq!(EntropySource::Violation.as_budget_type(), "VIOLATION");
        assert_eq!(EntropySource::Stall.as_budget_type(), "STALL");
        assert_eq!(EntropySource::Timeout.as_budget_type(), "TIMEOUT");
    }

    #[test]
    fn test_entropy_source_to_string() {
        assert_eq!(EntropySource::Error.to_string(), "ERROR");
        assert_eq!(EntropySource::Violation.to_string(), "VIOLATION");
    }
}
