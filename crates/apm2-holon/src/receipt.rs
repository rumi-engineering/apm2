//! `RunReceipt` types for episode completion tracking.
//!
//! This module provides the [`RunReceipt`] struct for capturing episode
//! completion metadata including context pack sufficiency and budget
//! consumption.
//!
//! # Design Principles
//!
//! - **Hermetic Consumption Feedback**: Pack misses are tracked to feed back
//!   into pack completeness improvements (per DD-0003)
//! - **Typed Quantities**: Budget deltas use explicit types for safety
//! - **Strict Serde**: All types use `#[serde(deny_unknown_fields)]` (CTR-1604)
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::receipt::{BudgetDelta, RunReceipt, RunReceiptBuilder};
//!
//! // Build a receipt during episode execution
//! let mut builder = RunReceiptBuilder::new("episode-001", [0u8; 32]);
//!
//! // Record a context pack miss
//! builder.record_miss(
//!     "org:doc:missing",
//!     1_000_000_000,
//!     "artifact not found in pack",
//! );
//!
//! // Build the final receipt
//! let receipt = builder
//!     .with_budget_delta(BudgetDelta::new(1000, 5000, 5))
//!     .with_pack_manifest_hash([1u8; 32])
//!     .build()
//!     .unwrap();
//!
//! assert!(!receipt.context_pack_sufficiency());
//! assert_eq!(receipt.context_pack_misses().len(), 1);
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of pack misses that can be recorded in a receipt.
pub const MAX_PACK_MISSES: usize = 1000;

/// Maximum length for stable IDs.
pub const MAX_STABLE_ID_LENGTH: usize = 1024;

/// Maximum length for miss reason strings.
pub const MAX_REASON_LENGTH: usize = 4096;

/// Maximum length for episode IDs.
pub const MAX_EPISODE_ID_LENGTH: usize = 256;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during receipt operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptError {
    /// Episode ID is missing.
    #[error("episode_id is required")]
    MissingEpisodeId,

    /// Episode ID exceeds maximum length.
    #[error("episode_id exceeds maximum length of {max_length} (got {actual_length})")]
    EpisodeIdTooLong {
        /// Maximum allowed length.
        max_length: usize,
        /// Actual length provided.
        actual_length: usize,
    },

    /// Stable ID exceeds maximum length.
    #[error("stable_id exceeds maximum length of {max_length} (got {actual_length})")]
    StableIdTooLong {
        /// Maximum allowed length.
        max_length: usize,
        /// Actual length provided.
        actual_length: usize,
    },

    /// Reason exceeds maximum length.
    #[error("reason exceeds maximum length of {max_length} (got {actual_length})")]
    ReasonTooLong {
        /// Maximum allowed length.
        max_length: usize,
        /// Actual length provided.
        actual_length: usize,
    },

    /// Too many pack misses recorded.
    #[error("too many pack misses: {count} exceeds maximum of {max}")]
    TooManyMisses {
        /// Number of misses attempted.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// ============================================================================
// PackMiss
// ============================================================================

/// Record of a context pack artifact fetch failure.
///
/// A `PackMiss` captures when an agent requests an artifact that was not
/// included in the compiled context pack, indicating a gap in pack
/// completeness.
///
/// # Design
///
/// Per CTR-0703, this struct provides actionable context:
/// - `stable_id`: Which artifact was requested
/// - `fetch_attempt_ns`: When the miss occurred (for timing analysis)
/// - `reason`: Why the fetch failed (for root cause analysis)
///
/// # Example
///
/// ```rust
/// use apm2_holon::receipt::PackMiss;
///
/// let miss = PackMiss::new(
///     "org:doc:missing-readme",
///     1_706_000_000_000,
///     "artifact not present in manifest",
/// );
///
/// assert_eq!(miss.stable_id(), "org:doc:missing-readme");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMiss {
    /// The stable ID of the artifact that was requested but not found.
    stable_id: String,

    /// Timestamp when the fetch was attempted (Unix nanoseconds).
    fetch_attempt_ns: u64,

    /// Human-readable reason for the miss.
    reason: String,
}

impl PackMiss {
    /// Creates a new pack miss record.
    ///
    /// # Arguments
    ///
    /// * `stable_id` - The stable ID of the requested artifact
    /// * `fetch_attempt_ns` - When the fetch was attempted (Unix nanoseconds)
    /// * `reason` - Human-readable reason for the miss
    #[must_use]
    pub fn new(
        stable_id: impl Into<String>,
        fetch_attempt_ns: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            stable_id: stable_id.into(),
            fetch_attempt_ns,
            reason: reason.into(),
        }
    }

    /// Returns the stable ID of the requested artifact.
    #[must_use]
    pub fn stable_id(&self) -> &str {
        &self.stable_id
    }

    /// Returns the timestamp of the fetch attempt in nanoseconds.
    #[must_use]
    pub const fn fetch_attempt_ns(&self) -> u64 {
        self.fetch_attempt_ns
    }

    /// Returns the reason for the miss.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Validates this pack miss record.
    ///
    /// # Errors
    ///
    /// - [`ReceiptError::StableIdTooLong`] if `stable_id` exceeds max length
    /// - [`ReceiptError::ReasonTooLong`] if `reason` exceeds max length
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.stable_id.len() > MAX_STABLE_ID_LENGTH {
            return Err(ReceiptError::StableIdTooLong {
                max_length: MAX_STABLE_ID_LENGTH,
                actual_length: self.stable_id.len(),
            });
        }
        if self.reason.len() > MAX_REASON_LENGTH {
            return Err(ReceiptError::ReasonTooLong {
                max_length: MAX_REASON_LENGTH,
                actual_length: self.reason.len(),
            });
        }
        Ok(())
    }
}

// ============================================================================
// BudgetDelta
// ============================================================================

/// Budget consumption metrics for an episode.
///
/// Captures the resources consumed during episode execution for tracking
/// and billing purposes.
///
/// # Example
///
/// ```rust
/// use apm2_holon::receipt::BudgetDelta;
///
/// let delta = BudgetDelta::new(1500, 3000, 10);
///
/// assert_eq!(delta.tokens_used(), 1500);
/// assert_eq!(delta.time_used_ms(), 3000);
/// assert_eq!(delta.artifacts_accessed(), 10);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetDelta {
    /// Number of tokens consumed during the episode.
    tokens_used: u64,

    /// Time consumed during the episode (milliseconds).
    time_used_ms: u64,

    /// Number of artifacts accessed during the episode.
    artifacts_accessed: u64,
}

impl BudgetDelta {
    /// Creates a new budget delta.
    #[must_use]
    pub const fn new(tokens_used: u64, time_used_ms: u64, artifacts_accessed: u64) -> Self {
        Self {
            tokens_used,
            time_used_ms,
            artifacts_accessed,
        }
    }

    /// Creates an empty budget delta (all zeros).
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            tokens_used: 0,
            time_used_ms: 0,
            artifacts_accessed: 0,
        }
    }

    /// Returns the number of tokens consumed.
    #[must_use]
    pub const fn tokens_used(&self) -> u64 {
        self.tokens_used
    }

    /// Returns the time consumed in milliseconds.
    #[must_use]
    pub const fn time_used_ms(&self) -> u64 {
        self.time_used_ms
    }

    /// Returns the number of artifacts accessed.
    #[must_use]
    pub const fn artifacts_accessed(&self) -> u64 {
        self.artifacts_accessed
    }

    /// Returns true if all consumption metrics are zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.tokens_used == 0 && self.time_used_ms == 0 && self.artifacts_accessed == 0
    }
}

// ============================================================================
// RunReceipt
// ============================================================================

/// Hash type alias (BLAKE3-256, 32 bytes).
pub type Hash = [u8; 32];

/// Receipt capturing episode completion metadata.
///
/// A `RunReceipt` is generated at the end of each episode to capture:
/// - Context pack sufficiency (were all needed artifacts available?)
/// - Pack misses (which artifacts were requested but missing?)
/// - Budget consumption (tokens, time, artifacts used)
/// - Reproducibility data (pack hash, manifest hash)
///
/// # Design
///
/// Per CTR-0704, this struct is marked `#[must_use]` because ignoring a
/// receipt could lead to lost feedback about pack completeness.
///
/// Per CTR-1604, this struct uses `#[serde(deny_unknown_fields)]` to reject
/// unknown fields during deserialization.
///
/// # Sufficiency Computation
///
/// Context pack sufficiency is `true` if and only if `misses.is_empty()`.
/// This follows the hermetic consumption model from DD-0003.
///
/// # Example
///
/// ```rust
/// use apm2_holon::receipt::{BudgetDelta, RunReceipt, RunReceiptBuilder};
///
/// let receipt = RunReceiptBuilder::new("ep-001", [0u8; 32])
///     .with_budget_delta(BudgetDelta::new(100, 500, 2))
///     .build()
///     .unwrap();
///
/// assert!(receipt.context_pack_sufficiency());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[must_use]
pub struct RunReceipt {
    /// Unique identifier for this episode.
    episode_id: String,

    /// BLAKE3-256 hash of the context pack used.
    pack_hash: Hash,

    /// Whether the context pack was sufficient (no misses).
    ///
    /// Computed as `misses.is_empty()` - a pack is sufficient if the agent
    /// never requested an artifact that wasn't in the pack.
    sufficiency: bool,

    /// List of context pack misses (artifacts requested but not found).
    context_pack_misses: Vec<PackMiss>,

    /// Budget consumption metrics for this episode.
    budget_delta: BudgetDelta,

    /// Optional hash of the pack manifest for reproducibility binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pack_manifest_hash: Option<Hash>,
}

impl RunReceipt {
    /// Returns the episode ID.
    #[must_use]
    pub fn episode_id(&self) -> &str {
        &self.episode_id
    }

    /// Returns the pack hash.
    #[must_use]
    pub const fn pack_hash(&self) -> &Hash {
        &self.pack_hash
    }

    /// Returns whether the context pack was sufficient.
    ///
    /// A pack is sufficient if no artifacts were requested that weren't
    /// present in the pack (i.e., `context_pack_misses.is_empty()`).
    #[must_use]
    pub const fn context_pack_sufficiency(&self) -> bool {
        self.sufficiency
    }

    /// Returns a borrowed view of the pack misses.
    ///
    /// Per CTR-1202, this returns a slice for efficient iteration without
    /// cloning.
    #[must_use]
    pub fn context_pack_misses(&self) -> &[PackMiss] {
        &self.context_pack_misses
    }

    /// Returns the budget delta.
    #[must_use]
    pub const fn budget_delta(&self) -> &BudgetDelta {
        &self.budget_delta
    }

    /// Returns the pack manifest hash, if set.
    #[must_use]
    pub const fn pack_manifest_hash(&self) -> Option<&Hash> {
        self.pack_manifest_hash.as_ref()
    }

    /// Returns true if there were any pack misses.
    #[must_use]
    pub fn has_misses(&self) -> bool {
        !self.context_pack_misses.is_empty()
    }

    /// Returns the number of pack misses.
    #[must_use]
    pub fn miss_count(&self) -> usize {
        self.context_pack_misses.len()
    }
}

// ============================================================================
// RunReceiptBuilder
// ============================================================================

/// Builder for constructing [`RunReceipt`] instances.
///
/// The builder accumulates pack misses during episode execution and computes
/// sufficiency automatically when building.
///
/// Per CTR-1205, the builder validates inputs and returns errors on `build()`.
///
/// # Example
///
/// ```rust
/// use apm2_holon::receipt::{BudgetDelta, RunReceiptBuilder};
///
/// let mut builder = RunReceiptBuilder::new("episode-001", [0u8; 32]);
///
/// // Record misses during execution
/// builder.record_miss("org:doc:missing", 1_000_000, "not in pack");
///
/// // Build with budget delta
/// let receipt = builder
///     .with_budget_delta(BudgetDelta::new(500, 1000, 3))
///     .build()
///     .unwrap();
///
/// assert!(!receipt.context_pack_sufficiency());
/// ```
#[derive(Debug, Clone)]
pub struct RunReceiptBuilder {
    episode_id: String,
    pack_hash: Hash,
    misses: Vec<PackMiss>,
    budget_delta: BudgetDelta,
    pack_manifest_hash: Option<Hash>,
    first_miss_recorded: bool,
}

impl RunReceiptBuilder {
    /// Creates a new builder for the given episode.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Unique identifier for this episode
    /// * `pack_hash` - BLAKE3-256 hash of the context pack used
    #[must_use]
    pub fn new(episode_id: impl Into<String>, pack_hash: Hash) -> Self {
        Self {
            episode_id: episode_id.into(),
            pack_hash,
            misses: Vec::new(),
            budget_delta: BudgetDelta::zero(),
            pack_manifest_hash: None,
            first_miss_recorded: false,
        }
    }

    /// Records a context pack miss.
    ///
    /// This method tracks artifacts that were requested but not found in
    /// the context pack. Use this during episode execution when artifact
    /// fetches fail.
    ///
    /// # Arguments
    ///
    /// * `stable_id` - The stable ID of the requested artifact
    /// * `fetch_attempt_ns` - When the fetch was attempted (Unix nanoseconds)
    /// * `reason` - Human-readable reason for the miss
    ///
    /// # Returns
    ///
    /// Returns `true` if this was the first miss recorded (useful for
    /// emitting a `DefectRecord` only on first miss), `false` otherwise.
    pub fn record_miss(
        &mut self,
        stable_id: impl Into<String>,
        fetch_attempt_ns: u64,
        reason: impl Into<String>,
    ) -> bool {
        let miss = PackMiss::new(stable_id, fetch_attempt_ns, reason);
        self.misses.push(miss);

        let was_first = !self.first_miss_recorded;
        self.first_miss_recorded = true;
        was_first
    }

    /// Returns true if this is the first miss being recorded.
    ///
    /// Useful for deciding whether to emit a `DefectRecord`.
    #[must_use]
    pub const fn is_first_miss(&self) -> bool {
        !self.first_miss_recorded
    }

    /// Returns the current number of recorded misses.
    #[must_use]
    pub fn miss_count(&self) -> usize {
        self.misses.len()
    }

    /// Returns true if any misses have been recorded.
    #[must_use]
    pub fn has_misses(&self) -> bool {
        !self.misses.is_empty()
    }

    /// Sets the budget delta.
    #[must_use]
    pub const fn with_budget_delta(mut self, delta: BudgetDelta) -> Self {
        self.budget_delta = delta;
        self
    }

    /// Sets the pack manifest hash.
    #[must_use]
    pub const fn with_pack_manifest_hash(mut self, hash: Hash) -> Self {
        self.pack_manifest_hash = Some(hash);
        self
    }

    /// Builds the `RunReceipt`.
    ///
    /// # Errors
    ///
    /// - [`ReceiptError::MissingEpisodeId`] if `episode_id` is empty
    /// - [`ReceiptError::EpisodeIdTooLong`] if `episode_id` exceeds max length
    /// - [`ReceiptError::TooManyMisses`] if too many misses recorded
    /// - [`ReceiptError::StableIdTooLong`] if any miss has invalid `stable_id`
    /// - [`ReceiptError::ReasonTooLong`] if any miss has invalid `reason`
    pub fn build(self) -> Result<RunReceipt, ReceiptError> {
        // Validate episode_id
        if self.episode_id.is_empty() {
            return Err(ReceiptError::MissingEpisodeId);
        }
        if self.episode_id.len() > MAX_EPISODE_ID_LENGTH {
            return Err(ReceiptError::EpisodeIdTooLong {
                max_length: MAX_EPISODE_ID_LENGTH,
                actual_length: self.episode_id.len(),
            });
        }

        // Validate miss count
        if self.misses.len() > MAX_PACK_MISSES {
            return Err(ReceiptError::TooManyMisses {
                count: self.misses.len(),
                max: MAX_PACK_MISSES,
            });
        }

        // Validate each miss
        for miss in &self.misses {
            miss.validate()?;
        }

        // Compute sufficiency (no misses = sufficient)
        let sufficiency = self.misses.is_empty();

        Ok(RunReceipt {
            episode_id: self.episode_id,
            pack_hash: self.pack_hash,
            sufficiency,
            context_pack_misses: self.misses,
            budget_delta: self.budget_delta,
            pack_manifest_hash: self.pack_manifest_hash,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // PackMiss Tests
    // =========================================================================

    #[test]
    fn test_pack_miss_creation() {
        let miss = PackMiss::new("org:doc:readme", 1_000_000_000, "artifact not found");

        assert_eq!(miss.stable_id(), "org:doc:readme");
        assert_eq!(miss.fetch_attempt_ns(), 1_000_000_000);
        assert_eq!(miss.reason(), "artifact not found");
    }

    #[test]
    fn test_pack_miss_validate_success() {
        let miss = PackMiss::new("org:doc:readme", 1_000_000_000, "not found");
        assert!(miss.validate().is_ok());
    }

    #[test]
    fn test_pack_miss_validate_stable_id_too_long() {
        let long_id = "x".repeat(MAX_STABLE_ID_LENGTH + 1);
        let miss = PackMiss::new(long_id, 1_000_000_000, "not found");

        let result = miss.validate();
        assert!(matches!(result, Err(ReceiptError::StableIdTooLong { .. })));
    }

    #[test]
    fn test_pack_miss_validate_reason_too_long() {
        let long_reason = "x".repeat(MAX_REASON_LENGTH + 1);
        let miss = PackMiss::new("org:doc:readme", 1_000_000_000, long_reason);

        let result = miss.validate();
        assert!(matches!(result, Err(ReceiptError::ReasonTooLong { .. })));
    }

    #[test]
    fn test_pack_miss_serialization() {
        let miss = PackMiss::new("org:doc:readme", 1_000_000_000, "not found");
        let json = serde_json::to_string(&miss).unwrap();

        assert!(json.contains("\"stable_id\":\"org:doc:readme\""));
        assert!(json.contains("\"fetch_attempt_ns\":1000000000"));
        assert!(json.contains("\"reason\":\"not found\""));

        let deserialized: PackMiss = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, miss);
    }

    #[test]
    fn test_pack_miss_rejects_unknown_fields() {
        let json = r#"{
            "stable_id": "org:doc:readme",
            "fetch_attempt_ns": 1000000000,
            "reason": "not found",
            "extra_field": "should fail"
        }"#;

        let result: Result<PackMiss, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // BudgetDelta Tests
    // =========================================================================

    #[test]
    fn test_budget_delta_creation() {
        let delta = BudgetDelta::new(1000, 5000, 10);

        assert_eq!(delta.tokens_used(), 1000);
        assert_eq!(delta.time_used_ms(), 5000);
        assert_eq!(delta.artifacts_accessed(), 10);
        assert!(!delta.is_zero());
    }

    #[test]
    fn test_budget_delta_zero() {
        let delta = BudgetDelta::zero();

        assert_eq!(delta.tokens_used(), 0);
        assert_eq!(delta.time_used_ms(), 0);
        assert_eq!(delta.artifacts_accessed(), 0);
        assert!(delta.is_zero());
    }

    #[test]
    fn test_budget_delta_default() {
        let delta = BudgetDelta::default();
        assert!(delta.is_zero());
    }

    #[test]
    fn test_budget_delta_serialization() {
        let delta = BudgetDelta::new(1000, 5000, 10);
        let json = serde_json::to_string(&delta).unwrap();

        let deserialized: BudgetDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, delta);
    }

    #[test]
    fn test_budget_delta_rejects_unknown_fields() {
        let json = r#"{
            "tokens_used": 1000,
            "time_used_ms": 5000,
            "artifacts_accessed": 10,
            "extra": "should fail"
        }"#;

        let result: Result<BudgetDelta, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // RunReceipt Tests
    // =========================================================================

    #[test]
    fn test_run_receipt_sufficient() {
        let receipt = RunReceiptBuilder::new("ep-001", [0u8; 32])
            .with_budget_delta(BudgetDelta::new(100, 500, 2))
            .build()
            .unwrap();

        assert_eq!(receipt.episode_id(), "ep-001");
        assert_eq!(receipt.pack_hash(), &[0u8; 32]);
        assert!(receipt.context_pack_sufficiency());
        assert!(receipt.context_pack_misses().is_empty());
        assert!(!receipt.has_misses());
        assert_eq!(receipt.miss_count(), 0);
    }

    #[test]
    fn test_run_receipt_with_misses() {
        let mut builder = RunReceiptBuilder::new("ep-002", [1u8; 32]);
        builder.record_miss("org:doc:missing", 1_000_000, "not in pack");
        builder.record_miss("org:lib:utils", 2_000_000, "dependency not resolved");

        let receipt = builder
            .with_budget_delta(BudgetDelta::new(200, 1000, 5))
            .build()
            .unwrap();

        assert!(!receipt.context_pack_sufficiency());
        assert!(receipt.has_misses());
        assert_eq!(receipt.miss_count(), 2);
        assert_eq!(
            receipt.context_pack_misses()[0].stable_id(),
            "org:doc:missing"
        );
        assert_eq!(
            receipt.context_pack_misses()[1].stable_id(),
            "org:lib:utils"
        );
    }

    #[test]
    fn test_run_receipt_with_manifest_hash() {
        let manifest_hash = [42u8; 32];
        let receipt = RunReceiptBuilder::new("ep-003", [0u8; 32])
            .with_pack_manifest_hash(manifest_hash)
            .build()
            .unwrap();

        assert_eq!(receipt.pack_manifest_hash(), Some(&manifest_hash));
    }

    #[test]
    fn test_run_receipt_serialization() {
        let receipt = RunReceiptBuilder::new("ep-001", [0u8; 32])
            .with_budget_delta(BudgetDelta::new(100, 500, 2))
            .build()
            .unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: RunReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.episode_id(), receipt.episode_id());
        assert_eq!(
            deserialized.context_pack_sufficiency(),
            receipt.context_pack_sufficiency()
        );
    }

    #[test]
    fn test_run_receipt_rejects_unknown_fields() {
        let json = r#"{
            "episode_id": "ep-001",
            "pack_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "sufficiency": true,
            "context_pack_misses": [],
            "budget_delta": {"tokens_used": 0, "time_used_ms": 0, "artifacts_accessed": 0},
            "extra_field": "should fail"
        }"#;

        let result: Result<RunReceipt, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // RunReceiptBuilder Tests
    // =========================================================================

    #[test]
    fn test_builder_record_miss_returns_first() {
        let mut builder = RunReceiptBuilder::new("ep-001", [0u8; 32]);

        // First miss should return true
        let first = builder.record_miss("org:doc:a", 1_000_000, "miss 1");
        assert!(first);

        // Subsequent misses should return false
        let second = builder.record_miss("org:doc:b", 2_000_000, "miss 2");
        assert!(!second);

        let third = builder.record_miss("org:doc:c", 3_000_000, "miss 3");
        assert!(!third);
    }

    #[test]
    fn test_builder_is_first_miss() {
        let mut builder = RunReceiptBuilder::new("ep-001", [0u8; 32]);

        assert!(builder.is_first_miss());
        builder.record_miss("org:doc:a", 1_000_000, "miss");
        assert!(!builder.is_first_miss());
    }

    #[test]
    fn test_builder_miss_count() {
        let mut builder = RunReceiptBuilder::new("ep-001", [0u8; 32]);

        assert_eq!(builder.miss_count(), 0);
        assert!(!builder.has_misses());

        builder.record_miss("org:doc:a", 1_000_000, "miss");
        assert_eq!(builder.miss_count(), 1);
        assert!(builder.has_misses());

        builder.record_miss("org:doc:b", 2_000_000, "miss");
        assert_eq!(builder.miss_count(), 2);
    }

    #[test]
    fn test_builder_validation_empty_episode_id() {
        let builder = RunReceiptBuilder::new("", [0u8; 32]);
        let result = builder.build();

        assert!(matches!(result, Err(ReceiptError::MissingEpisodeId)));
    }

    #[test]
    fn test_builder_validation_episode_id_too_long() {
        let long_id = "x".repeat(MAX_EPISODE_ID_LENGTH + 1);
        let builder = RunReceiptBuilder::new(long_id, [0u8; 32]);
        let result = builder.build();

        assert!(matches!(result, Err(ReceiptError::EpisodeIdTooLong { .. })));
    }

    #[test]
    fn test_builder_validation_too_many_misses() {
        let mut builder = RunReceiptBuilder::new("ep-001", [0u8; 32]);

        for i in 0..=MAX_PACK_MISSES {
            builder.record_miss(format!("org:doc:{i}"), i as u64, "miss");
        }

        let result = builder.build();
        assert!(matches!(result, Err(ReceiptError::TooManyMisses { .. })));
    }

    #[test]
    fn test_builder_validation_invalid_miss_propagates() {
        let mut builder = RunReceiptBuilder::new("ep-001", [0u8; 32]);
        let long_id = "x".repeat(MAX_STABLE_ID_LENGTH + 1);
        builder.record_miss(long_id, 1_000_000, "miss");

        let result = builder.build();
        assert!(matches!(result, Err(ReceiptError::StableIdTooLong { .. })));
    }

    // =========================================================================
    // Sufficiency Computation Tests
    // =========================================================================

    #[test]
    fn test_sufficiency_true_when_no_misses() {
        let receipt = RunReceiptBuilder::new("ep-001", [0u8; 32]).build().unwrap();

        assert!(receipt.context_pack_sufficiency());
        assert!(receipt.context_pack_misses().is_empty());
    }

    #[test]
    fn test_sufficiency_false_when_has_misses() {
        let mut builder = RunReceiptBuilder::new("ep-001", [0u8; 32]);
        builder.record_miss("org:doc:missing", 1_000_000, "not found");

        let receipt = builder.build().unwrap();

        assert!(!receipt.context_pack_sufficiency());
        assert!(!receipt.context_pack_misses().is_empty());
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let err = ReceiptError::MissingEpisodeId;
        assert!(err.to_string().contains("episode_id"));

        let err = ReceiptError::EpisodeIdTooLong {
            max_length: 256,
            actual_length: 300,
        };
        assert!(err.to_string().contains("256"));
        assert!(err.to_string().contains("300"));

        let err = ReceiptError::TooManyMisses {
            count: 1001,
            max: 1000,
        };
        assert!(err.to_string().contains("1001"));
        assert!(err.to_string().contains("1000"));
    }
}
