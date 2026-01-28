//! Telemetry policy configuration.
//!
//! This module defines the `TelemetryPolicy` type per CTR-DAEMON-005,
//! configuring how telemetry is collected and persisted.
//!
//! # Architecture
//!
//! ```text
//! TelemetryPolicy
//!     |
//!     +-- sample_period_ms: collection interval
//!     +-- promote_triggers: when to persist full buffer
//!     +-- ring_buffer_capacity: size of frame buffer
//!     +-- high_frequency_threshold: when to switch to high-freq mode
//! ```
//!
//! # Security Considerations
//!
//! - All limits are bounded to prevent resource exhaustion
//! - Minimum sample period prevents denial-of-service via excessive collection
//! - Maximum buffer capacity prevents memory exhaustion
//!
//! # Contract References
//!
//! - CTR-DAEMON-005: `TelemetryCollector` and frame streaming

use serde::{Deserialize, Serialize};

use crate::episode::RiskTier;

/// Minimum sample period in milliseconds (100ms = 10 Hz max).
///
/// This prevents denial-of-service via excessive collection frequency.
pub const MIN_SAMPLE_PERIOD_MS: u64 = 100;

/// Maximum sample period in milliseconds (1 hour).
pub const MAX_SAMPLE_PERIOD_MS: u64 = 3_600_000;

/// Default sample period in milliseconds (1 second).
pub const DEFAULT_SAMPLE_PERIOD_MS: u64 = 1_000;

/// Minimum ring buffer capacity (must hold at least 1 frame).
pub const MIN_RING_BUFFER_CAPACITY: usize = 1;

/// Maximum ring buffer capacity (prevents memory exhaustion).
pub const MAX_RING_BUFFER_CAPACITY: usize = 10_000;

/// Default ring buffer capacity (1024 frames).
pub const DEFAULT_RING_BUFFER_CAPACITY: usize = 1024;

/// Default high-frequency threshold (80% of budget consumed).
pub const DEFAULT_HIGH_FREQ_THRESHOLD_PERCENT: u8 = 80;

/// High-frequency sample period multiplier (4x faster).
pub const HIGH_FREQ_MULTIPLIER: u64 = 4;

/// Triggers that cause the ring buffer to be promoted to persistent storage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteTriggers {
    /// Promote on episode termination.
    pub on_termination: bool,

    /// Promote on quarantine (abnormal termination).
    pub on_quarantine: bool,

    /// Promote when budget threshold is exceeded.
    pub on_budget_threshold: bool,

    /// Promote periodically (every N frames).
    pub periodic_frames: Option<u64>,
}

impl PromoteTriggers {
    /// Creates default triggers (promote on termination and quarantine).
    #[must_use]
    pub const fn default_triggers() -> Self {
        Self {
            on_termination: true,
            on_quarantine: true,
            on_budget_threshold: false,
            periodic_frames: None,
        }
    }

    /// Creates triggers that promote on all events.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            on_termination: true,
            on_quarantine: true,
            on_budget_threshold: true,
            periodic_frames: Some(100),
        }
    }

    /// Creates triggers that never promote.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            on_termination: false,
            on_quarantine: false,
            on_budget_threshold: false,
            periodic_frames: None,
        }
    }

    /// Sets the `on_termination` flag.
    #[must_use]
    pub const fn with_on_termination(mut self, value: bool) -> Self {
        self.on_termination = value;
        self
    }

    /// Sets the `on_quarantine` flag.
    #[must_use]
    pub const fn with_on_quarantine(mut self, value: bool) -> Self {
        self.on_quarantine = value;
        self
    }

    /// Sets the `on_budget_threshold` flag.
    #[must_use]
    pub const fn with_on_budget_threshold(mut self, value: bool) -> Self {
        self.on_budget_threshold = value;
        self
    }

    /// Sets the periodic frame count.
    #[must_use]
    pub const fn with_periodic_frames(mut self, frames: u64) -> Self {
        self.periodic_frames = Some(frames);
        self
    }

    /// Returns `true` if any trigger is enabled.
    #[must_use]
    pub const fn has_any(&self) -> bool {
        self.on_termination
            || self.on_quarantine
            || self.on_budget_threshold
            || self.periodic_frames.is_some()
    }
}

/// Telemetry collection policy configuration.
///
/// Per CTR-DAEMON-005, this configures:
/// - Sample period (how often to collect)
/// - Ring buffer capacity (how many frames to retain)
/// - Promote triggers (when to persist to storage)
/// - High-frequency mode threshold (when to speed up collection)
///
/// # Example
///
/// ```rust
/// use apm2_daemon::telemetry::{PromoteTriggers, TelemetryPolicy};
///
/// let policy = TelemetryPolicy::builder()
///     .sample_period_ms(500)
///     .ring_buffer_capacity(2048)
///     .promote_triggers(PromoteTriggers::default_triggers())
///     .build();
///
/// assert_eq!(policy.sample_period_ms(), 500);
/// assert_eq!(policy.ring_buffer_capacity(), 2048);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryPolicy {
    /// Sample period in milliseconds.
    sample_period_ms: u64,

    /// Ring buffer capacity (number of frames).
    ring_buffer_capacity: usize,

    /// Triggers for promoting buffer to persistent storage.
    promote_triggers: PromoteTriggers,

    /// Threshold (percent of budget consumed) to switch to high-frequency mode.
    high_freq_threshold_percent: u8,

    /// Whether high-frequency mode is enabled.
    high_freq_enabled: bool,
}

impl TelemetryPolicy {
    /// Creates a new policy builder.
    #[must_use]
    pub const fn builder() -> TelemetryPolicyBuilder {
        TelemetryPolicyBuilder::new()
    }

    /// Creates a policy with invariant validation.
    ///
    /// # Errors
    ///
    /// Returns an error string if any value is out of bounds.
    pub fn try_new(
        sample_period_ms: u64,
        ring_buffer_capacity: usize,
        promote_triggers: PromoteTriggers,
        high_freq_threshold_percent: u8,
        high_freq_enabled: bool,
    ) -> Result<Self, String> {
        let policy = Self {
            sample_period_ms: clamp_sample_period(sample_period_ms),
            ring_buffer_capacity: clamp_buffer_capacity(ring_buffer_capacity),
            promote_triggers,
            high_freq_threshold_percent: clamp_threshold(high_freq_threshold_percent),
            high_freq_enabled,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validates policy invariants.
    ///
    /// # Errors
    ///
    /// Returns an error string if any invariant is violated.
    pub fn validate(&self) -> Result<(), String> {
        if self.sample_period_ms < MIN_SAMPLE_PERIOD_MS {
            return Err(format!(
                "sample_period_ms ({}) below minimum ({})",
                self.sample_period_ms, MIN_SAMPLE_PERIOD_MS
            ));
        }
        if self.sample_period_ms > MAX_SAMPLE_PERIOD_MS {
            return Err(format!(
                "sample_period_ms ({}) above maximum ({})",
                self.sample_period_ms, MAX_SAMPLE_PERIOD_MS
            ));
        }
        if self.ring_buffer_capacity < MIN_RING_BUFFER_CAPACITY {
            return Err(format!(
                "ring_buffer_capacity ({}) below minimum ({})",
                self.ring_buffer_capacity, MIN_RING_BUFFER_CAPACITY
            ));
        }
        if self.ring_buffer_capacity > MAX_RING_BUFFER_CAPACITY {
            return Err(format!(
                "ring_buffer_capacity ({}) above maximum ({})",
                self.ring_buffer_capacity, MAX_RING_BUFFER_CAPACITY
            ));
        }
        if self.high_freq_threshold_percent > 100 {
            return Err(format!(
                "high_freq_threshold_percent ({}) above 100",
                self.high_freq_threshold_percent
            ));
        }
        Ok(())
    }

    /// Creates a default policy for a given risk tier.
    ///
    /// Higher risk tiers get more frequent sampling and larger buffers.
    #[must_use]
    pub const fn for_risk_tier(tier: RiskTier) -> Self {
        match tier {
            RiskTier::Tier0 => Self {
                sample_period_ms: 5_000, // 5 seconds
                ring_buffer_capacity: 64,
                promote_triggers: PromoteTriggers::none(),
                high_freq_threshold_percent: 90,
                high_freq_enabled: false,
            },
            RiskTier::Tier1 => Self {
                sample_period_ms: 2_000, // 2 seconds
                ring_buffer_capacity: 256,
                promote_triggers: PromoteTriggers::default_triggers(),
                high_freq_threshold_percent: 85,
                high_freq_enabled: true,
            },
            RiskTier::Tier2 => Self {
                sample_period_ms: 1_000, // 1 second
                ring_buffer_capacity: 512,
                promote_triggers: PromoteTriggers::default_triggers(),
                high_freq_threshold_percent: 80,
                high_freq_enabled: true,
            },
            RiskTier::Tier3 | RiskTier::Tier4 => Self {
                sample_period_ms: 500, // 500ms
                ring_buffer_capacity: 1024,
                promote_triggers: PromoteTriggers::all(),
                high_freq_threshold_percent: 75,
                high_freq_enabled: true,
            },
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Returns the sample period in milliseconds.
    #[must_use]
    pub const fn sample_period_ms(&self) -> u64 {
        self.sample_period_ms
    }

    /// Returns the ring buffer capacity.
    #[must_use]
    pub const fn ring_buffer_capacity(&self) -> usize {
        self.ring_buffer_capacity
    }

    /// Returns the promote triggers.
    #[must_use]
    pub const fn promote_triggers(&self) -> &PromoteTriggers {
        &self.promote_triggers
    }

    /// Returns the high-frequency threshold percent.
    #[must_use]
    pub const fn high_freq_threshold_percent(&self) -> u8 {
        self.high_freq_threshold_percent
    }

    /// Returns whether high-frequency mode is enabled.
    #[must_use]
    pub const fn high_freq_enabled(&self) -> bool {
        self.high_freq_enabled
    }

    /// Returns the high-frequency sample period (faster collection).
    #[must_use]
    pub const fn high_freq_sample_period_ms(&self) -> u64 {
        let period = self.sample_period_ms / HIGH_FREQ_MULTIPLIER;
        if period < MIN_SAMPLE_PERIOD_MS {
            MIN_SAMPLE_PERIOD_MS
        } else {
            period
        }
    }

    /// Returns the effective sample period based on whether high-frequency
    /// mode is active.
    #[must_use]
    pub const fn effective_sample_period_ms(&self, high_freq_active: bool) -> u64 {
        if high_freq_active && self.high_freq_enabled {
            self.high_freq_sample_period_ms()
        } else {
            self.sample_period_ms
        }
    }
}

impl Default for TelemetryPolicy {
    fn default() -> Self {
        Self {
            sample_period_ms: DEFAULT_SAMPLE_PERIOD_MS,
            ring_buffer_capacity: DEFAULT_RING_BUFFER_CAPACITY,
            promote_triggers: PromoteTriggers::default_triggers(),
            high_freq_threshold_percent: DEFAULT_HIGH_FREQ_THRESHOLD_PERCENT,
            high_freq_enabled: true,
        }
    }
}

/// Builder for [`TelemetryPolicy`].
#[derive(Debug, Clone)]
pub struct TelemetryPolicyBuilder {
    sample_period_ms: u64,
    ring_buffer_capacity: usize,
    promote_triggers: PromoteTriggers,
    high_freq_threshold_percent: u8,
    high_freq_enabled: bool,
}

impl TelemetryPolicyBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sample_period_ms: DEFAULT_SAMPLE_PERIOD_MS,
            ring_buffer_capacity: DEFAULT_RING_BUFFER_CAPACITY,
            promote_triggers: PromoteTriggers::default_triggers(),
            high_freq_threshold_percent: DEFAULT_HIGH_FREQ_THRESHOLD_PERCENT,
            high_freq_enabled: true,
        }
    }

    /// Sets the sample period in milliseconds.
    #[must_use]
    pub const fn sample_period_ms(mut self, ms: u64) -> Self {
        self.sample_period_ms = ms;
        self
    }

    /// Sets the ring buffer capacity.
    #[must_use]
    pub const fn ring_buffer_capacity(mut self, capacity: usize) -> Self {
        self.ring_buffer_capacity = capacity;
        self
    }

    /// Sets the promote triggers.
    #[must_use]
    pub const fn promote_triggers(mut self, triggers: PromoteTriggers) -> Self {
        self.promote_triggers = triggers;
        self
    }

    /// Sets the high-frequency threshold percent.
    #[must_use]
    pub const fn high_freq_threshold_percent(mut self, percent: u8) -> Self {
        self.high_freq_threshold_percent = percent;
        self
    }

    /// Sets whether high-frequency mode is enabled.
    #[must_use]
    pub const fn high_freq_enabled(mut self, enabled: bool) -> Self {
        self.high_freq_enabled = enabled;
        self
    }

    /// Builds the policy with clamping.
    #[must_use]
    pub const fn build(self) -> TelemetryPolicy {
        TelemetryPolicy {
            sample_period_ms: clamp_sample_period(self.sample_period_ms),
            ring_buffer_capacity: clamp_buffer_capacity(self.ring_buffer_capacity),
            promote_triggers: self.promote_triggers,
            high_freq_threshold_percent: clamp_threshold(self.high_freq_threshold_percent),
            high_freq_enabled: self.high_freq_enabled,
        }
    }

    /// Builds the policy with validation.
    ///
    /// # Errors
    ///
    /// Returns an error string if any invariant is violated.
    pub fn try_build(self) -> Result<TelemetryPolicy, String> {
        let policy = self.build();
        policy.validate()?;
        Ok(policy)
    }
}

impl Default for TelemetryPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Clamps sample period to valid range.
const fn clamp_sample_period(ms: u64) -> u64 {
    if ms < MIN_SAMPLE_PERIOD_MS {
        MIN_SAMPLE_PERIOD_MS
    } else if ms > MAX_SAMPLE_PERIOD_MS {
        MAX_SAMPLE_PERIOD_MS
    } else {
        ms
    }
}

/// Clamps buffer capacity to valid range.
const fn clamp_buffer_capacity(capacity: usize) -> usize {
    if capacity < MIN_RING_BUFFER_CAPACITY {
        MIN_RING_BUFFER_CAPACITY
    } else if capacity > MAX_RING_BUFFER_CAPACITY {
        MAX_RING_BUFFER_CAPACITY
    } else {
        capacity
    }
}

/// Clamps threshold to 0-100 range.
const fn clamp_threshold(percent: u8) -> u8 {
    if percent > 100 { 100 } else { percent }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TelemetryPolicy tests
    // =========================================================================

    #[test]
    fn test_telemetry_policy_default() {
        let policy = TelemetryPolicy::default();
        assert_eq!(policy.sample_period_ms(), DEFAULT_SAMPLE_PERIOD_MS);
        assert_eq!(policy.ring_buffer_capacity(), DEFAULT_RING_BUFFER_CAPACITY);
        assert!(policy.high_freq_enabled());
    }

    #[test]
    fn test_telemetry_policy_builder() {
        let policy = TelemetryPolicy::builder()
            .sample_period_ms(500)
            .ring_buffer_capacity(2048)
            .high_freq_threshold_percent(75)
            .high_freq_enabled(true)
            .build();

        assert_eq!(policy.sample_period_ms(), 500);
        assert_eq!(policy.ring_buffer_capacity(), 2048);
        assert_eq!(policy.high_freq_threshold_percent(), 75);
        assert!(policy.high_freq_enabled());
    }

    #[test]
    fn test_telemetry_policy_clamping() {
        // Test lower bound clamping
        let policy = TelemetryPolicy::builder()
            .sample_period_ms(10) // Below minimum
            .ring_buffer_capacity(0) // Below minimum
            .high_freq_threshold_percent(150) // Above 100
            .build();

        assert_eq!(policy.sample_period_ms(), MIN_SAMPLE_PERIOD_MS);
        assert_eq!(policy.ring_buffer_capacity(), MIN_RING_BUFFER_CAPACITY);
        assert_eq!(policy.high_freq_threshold_percent(), 100);

        // Test upper bound clamping
        let policy = TelemetryPolicy::builder()
            .sample_period_ms(10_000_000) // Above maximum
            .ring_buffer_capacity(100_000) // Above maximum
            .build();

        assert_eq!(policy.sample_period_ms(), MAX_SAMPLE_PERIOD_MS);
        assert_eq!(policy.ring_buffer_capacity(), MAX_RING_BUFFER_CAPACITY);
    }

    #[test]
    fn test_telemetry_policy_try_new() {
        let result =
            TelemetryPolicy::try_new(1000, 512, PromoteTriggers::default_triggers(), 80, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_telemetry_policy_for_risk_tier() {
        let tier0 = TelemetryPolicy::for_risk_tier(RiskTier::Tier0);
        assert_eq!(tier0.sample_period_ms(), 5_000);
        assert!(!tier0.high_freq_enabled());

        let tier1 = TelemetryPolicy::for_risk_tier(RiskTier::Tier1);
        assert_eq!(tier1.sample_period_ms(), 2_000);
        assert!(tier1.high_freq_enabled());

        let tier2 = TelemetryPolicy::for_risk_tier(RiskTier::Tier2);
        assert_eq!(tier2.sample_period_ms(), 1_000);

        let tier3 = TelemetryPolicy::for_risk_tier(RiskTier::Tier3);
        assert_eq!(tier3.sample_period_ms(), 500);
        assert_eq!(tier3.ring_buffer_capacity(), 1024);
    }

    #[test]
    fn test_telemetry_policy_high_freq_sample_period() {
        let policy = TelemetryPolicy::builder().sample_period_ms(1000).build();

        assert_eq!(policy.high_freq_sample_period_ms(), 250);
    }

    #[test]
    fn test_telemetry_policy_high_freq_sample_period_clamped() {
        let policy = TelemetryPolicy::builder()
            .sample_period_ms(200) // Would be 50ms at high freq, below min
            .build();

        assert_eq!(policy.high_freq_sample_period_ms(), MIN_SAMPLE_PERIOD_MS);
    }

    #[test]
    fn test_telemetry_policy_effective_sample_period() {
        let policy = TelemetryPolicy::builder()
            .sample_period_ms(1000)
            .high_freq_enabled(true)
            .build();

        assert_eq!(policy.effective_sample_period_ms(false), 1000);
        assert_eq!(policy.effective_sample_period_ms(true), 250);
    }

    #[test]
    fn test_telemetry_policy_effective_sample_period_disabled() {
        let policy = TelemetryPolicy::builder()
            .sample_period_ms(1000)
            .high_freq_enabled(false)
            .build();

        assert_eq!(policy.effective_sample_period_ms(false), 1000);
        assert_eq!(policy.effective_sample_period_ms(true), 1000); // Still normal period
    }

    // =========================================================================
    // PromoteTriggers tests
    // =========================================================================

    #[test]
    fn test_promote_triggers_default() {
        let triggers = PromoteTriggers::default_triggers();
        assert!(triggers.on_termination);
        assert!(triggers.on_quarantine);
        assert!(!triggers.on_budget_threshold);
        assert!(triggers.periodic_frames.is_none());
        assert!(triggers.has_any());
    }

    #[test]
    fn test_promote_triggers_all() {
        let triggers = PromoteTriggers::all();
        assert!(triggers.on_termination);
        assert!(triggers.on_quarantine);
        assert!(triggers.on_budget_threshold);
        assert_eq!(triggers.periodic_frames, Some(100));
        assert!(triggers.has_any());
    }

    #[test]
    fn test_promote_triggers_none() {
        let triggers = PromoteTriggers::none();
        assert!(!triggers.on_termination);
        assert!(!triggers.on_quarantine);
        assert!(!triggers.on_budget_threshold);
        assert!(triggers.periodic_frames.is_none());
        assert!(!triggers.has_any());
    }

    #[test]
    fn test_promote_triggers_builder_methods() {
        let triggers = PromoteTriggers::none()
            .with_on_termination(true)
            .with_on_quarantine(true)
            .with_on_budget_threshold(true)
            .with_periodic_frames(50);

        assert!(triggers.on_termination);
        assert!(triggers.on_quarantine);
        assert!(triggers.on_budget_threshold);
        assert_eq!(triggers.periodic_frames, Some(50));
    }

    // =========================================================================
    // Serialization tests
    // =========================================================================

    #[test]
    fn test_telemetry_policy_serialize() {
        let policy = TelemetryPolicy::builder()
            .sample_period_ms(500)
            .ring_buffer_capacity(256)
            .build();

        let json = serde_json::to_string(&policy).expect("serialize failed");
        let decoded: TelemetryPolicy = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(policy, decoded);
    }

    #[test]
    fn test_promote_triggers_serialize() {
        let triggers = PromoteTriggers::all();
        let json = serde_json::to_string(&triggers).expect("serialize failed");
        let decoded: PromoteTriggers = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(triggers, decoded);
    }
}
