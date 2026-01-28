//! Recorder configuration per risk tier.
//!
//! This module defines `RecorderConfig` per AD-EVID-001, providing
//! per-risk-tier buffer sizes for the flight recorder. Buffer sizes
//! are specified in **item counts** (not bytes) because `RingBuffer<T>`
//! operates on item capacity.
//!
//! # Architecture
//!
//! ```text
//! RecorderConfig
//!     |
//!     +-- pty_capacity: usize
//!     +-- tool_capacity: usize
//!     +-- telemetry_capacity: usize
//!     |
//!     +-- from_risk_tier(RiskTier) -> RecorderConfig
//! ```
//!
//! # Buffer Size Rationale (AD-EVID-001)
//!
//! Buffer capacities are derived from byte targets and estimated item sizes:
//!
//! | Tier    | PTY Target | Tool Target | Telemetry Target |
//! |---------|-----------|-------------|------------------|
//! | Tier 1  | ~1MB      | ~512KB      | ~256KB           |
//! | Tier 2  | ~4MB      | ~2MB        | ~1MB             |
//! | Tier 3+ | ~16MB     | ~8MB        | ~4MB             |
//!
//! Estimated average item sizes:
//! - PTY output: ~4KB per chunk (typical terminal output)
//! - Tool event: ~2KB per event (JSON-encoded request/response)
//! - Telemetry frame: ~256 bytes (metrics struct)
//!
//! # Aggregate Memory Bounds
//!
//! With `MAX_CONCURRENT_EPISODES` = 10,000:
//! - Tier 1: ~1.75MB per episode * 10,000 = ~17GB worst case
//! - Tier 2: ~7MB per episode * 10,000 = ~70GB worst case
//! - Tier 3+: ~28MB per episode * 10,000 = ~280GB worst case
//!
//! In practice, episodes are distributed across tiers and memory is reclaimed
//! on normal termination. Only failure cases retain buffers until persistence.
//!
//! # Invariants
//!
//! - [INV-RC001] All capacities are > 0 (enforced by `try_new`)
//! - [INV-RC002] Tier 0 uses minimal capacity (tier 1 values)
//! - [INV-RC003] Higher tiers never have smaller buffers than lower tiers
//!
//! # Contract References
//!
//! - AD-EVID-001: Flight recorder and ring buffers
//! - CTR-1303: Bounded collections with MAX_* constants

use serde::{Deserialize, Serialize};

use crate::episode::envelope::RiskTier;

// =============================================================================
// Capacity Constants (Item Counts)
// =============================================================================

/// Estimated average PTY chunk size (4KB).
pub const ESTIMATED_PTY_CHUNK_SIZE: usize = 4 * 1024;

/// Estimated average tool event size (2KB).
pub const ESTIMATED_TOOL_EVENT_SIZE: usize = 2 * 1024;

/// Estimated average telemetry frame size (256 bytes).
pub const ESTIMATED_TELEMETRY_FRAME_SIZE: usize = 256;

// Tier 1 capacities (derived from byte targets)
// PTY: 1MB / 4KB = 256 items
// Tool: 512KB / 2KB = 256 items
// Telemetry: 256KB / 256B = 1024 items

/// Tier 1 PTY buffer capacity (item count, ~1MB equivalent).
pub const TIER_1_PTY_CAPACITY: usize = 256;

/// Tier 1 tool buffer capacity (item count, ~512KB equivalent).
pub const TIER_1_TOOL_CAPACITY: usize = 256;

/// Tier 1 telemetry buffer capacity (item count, ~256KB equivalent).
pub const TIER_1_TELEMETRY_CAPACITY: usize = 1024;

// Tier 2 capacities (4x Tier 1)
// PTY: 4MB / 4KB = 1024 items
// Tool: 2MB / 2KB = 1024 items
// Telemetry: 1MB / 256B = 4096 items

/// Tier 2 PTY buffer capacity (item count, ~4MB equivalent).
pub const TIER_2_PTY_CAPACITY: usize = 1024;

/// Tier 2 tool buffer capacity (item count, ~2MB equivalent).
pub const TIER_2_TOOL_CAPACITY: usize = 1024;

/// Tier 2 telemetry buffer capacity (item count, ~1MB equivalent).
pub const TIER_2_TELEMETRY_CAPACITY: usize = 4096;

// Tier 3+ capacities (4x Tier 2)
// PTY: 16MB / 4KB = 4096 items
// Tool: 8MB / 2KB = 4096 items
// Telemetry: 4MB / 256B = 16384 items

/// Tier 3+ PTY buffer capacity (item count, ~16MB equivalent).
pub const TIER_3_PLUS_PTY_CAPACITY: usize = 4096;

/// Tier 3+ tool buffer capacity (item count, ~8MB equivalent).
pub const TIER_3_PLUS_TOOL_CAPACITY: usize = 4096;

/// Tier 3+ telemetry buffer capacity (item count, ~4MB equivalent).
pub const TIER_3_PLUS_TELEMETRY_CAPACITY: usize = 16384;

/// Maximum allowed capacity for any buffer (bounds memory growth).
pub const MAX_BUFFER_CAPACITY: usize = 65536;

/// Minimum allowed capacity for any buffer.
pub const MIN_BUFFER_CAPACITY: usize = 1;

// =============================================================================
// RecorderConfig
// =============================================================================

/// Configuration for flight recorder buffer sizes.
///
/// All capacities are in **item counts**, not bytes. The `RingBuffer<T>` uses
/// item-based capacity, and actual memory usage depends on item size.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::config::RecorderConfig;
/// use apm2_daemon::episode::envelope::RiskTier;
///
/// // Get configuration for risk tier 2
/// let config = RecorderConfig::from_risk_tier(RiskTier::Tier2);
///
/// assert_eq!(config.pty_capacity(), 1024);
/// assert_eq!(config.tool_capacity(), 1024);
/// assert_eq!(config.telemetry_capacity(), 4096);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Capacity suffix is intentional for clarity
pub struct RecorderConfig {
    /// PTY output buffer capacity (item count).
    pty_capacity: usize,

    /// Tool event buffer capacity (item count).
    tool_capacity: usize,

    /// Telemetry frame buffer capacity (item count).
    telemetry_capacity: usize,
}

impl RecorderConfig {
    /// Creates a new configuration with validated capacities.
    ///
    /// # Arguments
    ///
    /// * `pty_capacity` - PTY output buffer capacity
    /// * `tool_capacity` - Tool event buffer capacity
    /// * `telemetry_capacity` - Telemetry frame buffer capacity
    ///
    /// # Errors
    ///
    /// Returns an error string if any capacity is 0 or exceeds
    /// `MAX_BUFFER_CAPACITY`.
    pub fn try_new(
        pty_capacity: usize,
        tool_capacity: usize,
        telemetry_capacity: usize,
    ) -> Result<Self, String> {
        // INV-RC001: All capacities must be > 0
        if pty_capacity < MIN_BUFFER_CAPACITY {
            return Err(format!(
                "INV-RC001 violated: pty_capacity ({pty_capacity}) must be >= {MIN_BUFFER_CAPACITY}"
            ));
        }
        if tool_capacity < MIN_BUFFER_CAPACITY {
            return Err(format!(
                "INV-RC001 violated: tool_capacity ({tool_capacity}) must be >= {MIN_BUFFER_CAPACITY}"
            ));
        }
        if telemetry_capacity < MIN_BUFFER_CAPACITY {
            return Err(format!(
                "INV-RC001 violated: telemetry_capacity ({telemetry_capacity}) must be >= {MIN_BUFFER_CAPACITY}"
            ));
        }

        // Bounds check (CTR-1303)
        if pty_capacity > MAX_BUFFER_CAPACITY {
            return Err(format!(
                "pty_capacity ({pty_capacity}) exceeds MAX_BUFFER_CAPACITY ({MAX_BUFFER_CAPACITY})"
            ));
        }
        if tool_capacity > MAX_BUFFER_CAPACITY {
            return Err(format!(
                "tool_capacity ({tool_capacity}) exceeds MAX_BUFFER_CAPACITY ({MAX_BUFFER_CAPACITY})"
            ));
        }
        if telemetry_capacity > MAX_BUFFER_CAPACITY {
            return Err(format!(
                "telemetry_capacity ({telemetry_capacity}) exceeds MAX_BUFFER_CAPACITY ({MAX_BUFFER_CAPACITY})"
            ));
        }

        Ok(Self {
            pty_capacity,
            tool_capacity,
            telemetry_capacity,
        })
    }

    /// Creates a configuration from a risk tier.
    ///
    /// Per AD-EVID-001, buffer sizes scale with risk tier:
    /// - Tier 0-1: Minimal buffers for read-only/local development
    /// - Tier 2: Medium buffers for production-adjacent operations
    /// - Tier 3+: Large buffers for critical operations
    #[must_use]
    pub const fn from_risk_tier(tier: RiskTier) -> Self {
        match tier {
            // INV-RC002: Tier 0 uses tier 1 values (minimal but non-zero)
            RiskTier::Tier0 | RiskTier::Tier1 => Self {
                pty_capacity: TIER_1_PTY_CAPACITY,
                tool_capacity: TIER_1_TOOL_CAPACITY,
                telemetry_capacity: TIER_1_TELEMETRY_CAPACITY,
            },
            RiskTier::Tier2 => Self {
                pty_capacity: TIER_2_PTY_CAPACITY,
                tool_capacity: TIER_2_TOOL_CAPACITY,
                telemetry_capacity: TIER_2_TELEMETRY_CAPACITY,
            },
            // INV-RC003: Tier 3+ gets largest buffers
            RiskTier::Tier3 | RiskTier::Tier4 => Self {
                pty_capacity: TIER_3_PLUS_PTY_CAPACITY,
                tool_capacity: TIER_3_PLUS_TOOL_CAPACITY,
                telemetry_capacity: TIER_3_PLUS_TELEMETRY_CAPACITY,
            },
        }
    }

    /// Returns the PTY output buffer capacity (item count).
    #[must_use]
    pub const fn pty_capacity(&self) -> usize {
        self.pty_capacity
    }

    /// Returns the tool event buffer capacity (item count).
    #[must_use]
    pub const fn tool_capacity(&self) -> usize {
        self.tool_capacity
    }

    /// Returns the telemetry frame buffer capacity (item count).
    #[must_use]
    pub const fn telemetry_capacity(&self) -> usize {
        self.telemetry_capacity
    }

    /// Returns estimated total memory usage in bytes.
    ///
    /// This is an approximation based on estimated item sizes. Actual
    /// memory usage may vary based on actual item contents.
    #[must_use]
    pub const fn estimated_memory_bytes(&self) -> usize {
        self.pty_capacity * ESTIMATED_PTY_CHUNK_SIZE
            + self.tool_capacity * ESTIMATED_TOOL_EVENT_SIZE
            + self.telemetry_capacity * ESTIMATED_TELEMETRY_FRAME_SIZE
    }

    /// Creates a builder for custom configuration.
    #[must_use]
    pub const fn builder() -> RecorderConfigBuilder {
        RecorderConfigBuilder::new()
    }
}

impl Default for RecorderConfig {
    /// Default configuration uses Tier 1 capacities.
    fn default() -> Self {
        Self::from_risk_tier(RiskTier::Tier1)
    }
}

// =============================================================================
// RecorderConfigBuilder
// =============================================================================

/// Builder for `RecorderConfig`.
///
/// All capacities are clamped to valid ranges on build.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)] // Capacity suffix is intentional for clarity
pub struct RecorderConfigBuilder {
    pty_capacity: usize,
    tool_capacity: usize,
    telemetry_capacity: usize,
}

impl RecorderConfigBuilder {
    /// Creates a new builder with Tier 1 defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pty_capacity: TIER_1_PTY_CAPACITY,
            tool_capacity: TIER_1_TOOL_CAPACITY,
            telemetry_capacity: TIER_1_TELEMETRY_CAPACITY,
        }
    }

    /// Sets the PTY buffer capacity.
    #[must_use]
    pub const fn pty_capacity(mut self, capacity: usize) -> Self {
        self.pty_capacity = capacity;
        self
    }

    /// Sets the tool buffer capacity.
    #[must_use]
    pub const fn tool_capacity(mut self, capacity: usize) -> Self {
        self.tool_capacity = capacity;
        self
    }

    /// Sets the telemetry buffer capacity.
    #[must_use]
    pub const fn telemetry_capacity(mut self, capacity: usize) -> Self {
        self.telemetry_capacity = capacity;
        self
    }

    /// Builds the configuration with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if any capacity violates invariants.
    pub fn build(self) -> Result<RecorderConfig, String> {
        RecorderConfig::try_new(
            self.pty_capacity,
            self.tool_capacity,
            self.telemetry_capacity,
        )
    }

    /// Builds the configuration, clamping values to valid ranges.
    ///
    /// This never fails - invalid values are clamped.
    #[must_use]
    pub fn build_clamped(self) -> RecorderConfig {
        RecorderConfig {
            pty_capacity: self
                .pty_capacity
                .clamp(MIN_BUFFER_CAPACITY, MAX_BUFFER_CAPACITY),
            tool_capacity: self
                .tool_capacity
                .clamp(MIN_BUFFER_CAPACITY, MAX_BUFFER_CAPACITY),
            telemetry_capacity: self
                .telemetry_capacity
                .clamp(MIN_BUFFER_CAPACITY, MAX_BUFFER_CAPACITY),
        }
    }
}

impl Default for RecorderConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // UT-00170-03: Tier configuration tests
    // =========================================================================

    #[test]
    fn test_recorder_config_tier_1() {
        let config = RecorderConfig::from_risk_tier(RiskTier::Tier1);

        assert_eq!(config.pty_capacity(), TIER_1_PTY_CAPACITY);
        assert_eq!(config.tool_capacity(), TIER_1_TOOL_CAPACITY);
        assert_eq!(config.telemetry_capacity(), TIER_1_TELEMETRY_CAPACITY);
    }

    #[test]
    fn test_recorder_config_tier_2() {
        let config = RecorderConfig::from_risk_tier(RiskTier::Tier2);

        assert_eq!(config.pty_capacity(), TIER_2_PTY_CAPACITY);
        assert_eq!(config.tool_capacity(), TIER_2_TOOL_CAPACITY);
        assert_eq!(config.telemetry_capacity(), TIER_2_TELEMETRY_CAPACITY);
    }

    #[test]
    fn test_recorder_config_tier_3_plus() {
        let config_t3 = RecorderConfig::from_risk_tier(RiskTier::Tier3);
        let config_t4 = RecorderConfig::from_risk_tier(RiskTier::Tier4);

        // Tier 3 and 4 should have same (largest) buffers
        assert_eq!(config_t3.pty_capacity(), TIER_3_PLUS_PTY_CAPACITY);
        assert_eq!(config_t3.tool_capacity(), TIER_3_PLUS_TOOL_CAPACITY);
        assert_eq!(
            config_t3.telemetry_capacity(),
            TIER_3_PLUS_TELEMETRY_CAPACITY
        );

        assert_eq!(config_t4.pty_capacity(), config_t3.pty_capacity());
        assert_eq!(config_t4.tool_capacity(), config_t3.tool_capacity());
        assert_eq!(
            config_t4.telemetry_capacity(),
            config_t3.telemetry_capacity()
        );
    }

    /// INV-RC002: Tier 0 uses tier 1 values.
    #[test]
    fn test_recorder_config_tier_0_uses_tier_1() {
        let config_t0 = RecorderConfig::from_risk_tier(RiskTier::Tier0);
        let config_t1 = RecorderConfig::from_risk_tier(RiskTier::Tier1);

        assert_eq!(config_t0.pty_capacity(), config_t1.pty_capacity());
        assert_eq!(config_t0.tool_capacity(), config_t1.tool_capacity());
        assert_eq!(
            config_t0.telemetry_capacity(),
            config_t1.telemetry_capacity()
        );
    }

    /// INV-RC003: Higher tiers never have smaller buffers.
    #[test]
    fn test_recorder_config_tier_monotonicity() {
        let t1 = RecorderConfig::from_risk_tier(RiskTier::Tier1);
        let t2 = RecorderConfig::from_risk_tier(RiskTier::Tier2);
        let t3 = RecorderConfig::from_risk_tier(RiskTier::Tier3);

        // Tier 2 >= Tier 1
        assert!(t2.pty_capacity() >= t1.pty_capacity());
        assert!(t2.tool_capacity() >= t1.tool_capacity());
        assert!(t2.telemetry_capacity() >= t1.telemetry_capacity());

        // Tier 3 >= Tier 2
        assert!(t3.pty_capacity() >= t2.pty_capacity());
        assert!(t3.tool_capacity() >= t2.tool_capacity());
        assert!(t3.telemetry_capacity() >= t2.telemetry_capacity());
    }

    #[test]
    fn test_recorder_config_try_new_valid() {
        let result = RecorderConfig::try_new(100, 200, 300);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.pty_capacity(), 100);
        assert_eq!(config.tool_capacity(), 200);
        assert_eq!(config.telemetry_capacity(), 300);
    }

    /// INV-RC001: Zero capacity is rejected.
    #[test]
    fn test_recorder_config_try_new_zero_rejected() {
        assert!(RecorderConfig::try_new(0, 100, 100).is_err());
        assert!(RecorderConfig::try_new(100, 0, 100).is_err());
        assert!(RecorderConfig::try_new(100, 100, 0).is_err());
    }

    #[test]
    fn test_recorder_config_try_new_exceeds_max() {
        let too_large = MAX_BUFFER_CAPACITY + 1;

        assert!(RecorderConfig::try_new(too_large, 100, 100).is_err());
        assert!(RecorderConfig::try_new(100, too_large, 100).is_err());
        assert!(RecorderConfig::try_new(100, 100, too_large).is_err());
    }

    #[test]
    fn test_recorder_config_builder() {
        let config = RecorderConfig::builder()
            .pty_capacity(500)
            .tool_capacity(600)
            .telemetry_capacity(700)
            .build()
            .unwrap();

        assert_eq!(config.pty_capacity(), 500);
        assert_eq!(config.tool_capacity(), 600);
        assert_eq!(config.telemetry_capacity(), 700);
    }

    #[test]
    fn test_recorder_config_builder_clamped() {
        // Zero values should be clamped to MIN_BUFFER_CAPACITY
        let config = RecorderConfig::builder()
            .pty_capacity(0)
            .tool_capacity(0)
            .telemetry_capacity(0)
            .build_clamped();

        assert_eq!(config.pty_capacity(), MIN_BUFFER_CAPACITY);
        assert_eq!(config.tool_capacity(), MIN_BUFFER_CAPACITY);
        assert_eq!(config.telemetry_capacity(), MIN_BUFFER_CAPACITY);

        // Large values should be clamped to MAX_BUFFER_CAPACITY
        let config = RecorderConfig::builder()
            .pty_capacity(MAX_BUFFER_CAPACITY * 2)
            .tool_capacity(MAX_BUFFER_CAPACITY * 2)
            .telemetry_capacity(MAX_BUFFER_CAPACITY * 2)
            .build_clamped();

        assert_eq!(config.pty_capacity(), MAX_BUFFER_CAPACITY);
        assert_eq!(config.tool_capacity(), MAX_BUFFER_CAPACITY);
        assert_eq!(config.telemetry_capacity(), MAX_BUFFER_CAPACITY);
    }

    #[test]
    fn test_recorder_config_default() {
        let config = RecorderConfig::default();
        let tier1 = RecorderConfig::from_risk_tier(RiskTier::Tier1);

        assert_eq!(config, tier1);
    }

    #[test]
    fn test_recorder_config_estimated_memory() {
        let config = RecorderConfig::from_risk_tier(RiskTier::Tier1);
        let estimated = config.estimated_memory_bytes();

        // Tier 1: 256*4KB + 256*2KB + 1024*256B = 1MB + 512KB + 256KB = ~1.75MB
        let expected = TIER_1_PTY_CAPACITY * ESTIMATED_PTY_CHUNK_SIZE
            + TIER_1_TOOL_CAPACITY * ESTIMATED_TOOL_EVENT_SIZE
            + TIER_1_TELEMETRY_CAPACITY * ESTIMATED_TELEMETRY_FRAME_SIZE;

        assert_eq!(estimated, expected);
    }

    #[test]
    fn test_recorder_config_serialization() {
        let config = RecorderConfig::try_new(100, 200, 300).unwrap();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RecorderConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }

    /// SECURITY: Verify unknown fields are rejected.
    #[test]
    fn test_recorder_config_rejects_unknown_fields() {
        let json = r#"{
            "pty_capacity": 100,
            "tool_capacity": 200,
            "telemetry_capacity": 300,
            "malicious": "attack"
        }"#;

        let result: Result<RecorderConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }
}
