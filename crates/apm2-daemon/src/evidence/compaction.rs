//! Evidence compaction for bounded storage growth.
//!
//! This module implements evidence compaction per AD-EVID-002, enabling
//! storage reduction through summary generation and tombstone tracking.
//! Compaction produces summary receipts referencing dropped artifacts
//! by digest (tombstoned pointers).
//!
//! # Architecture
//!
//! ```text
//! CompactionJob
//!     |-- episode_id: EpisodeId
//!     |-- artifacts: Vec<ArtifactId> (bounded by MAX_COMPACTION_ARTIFACTS)
//!     |-- strategy: CompactionStrategy
//!     `-- threshold_ns: u64 (only compact older than this)
//!
//! CompactionResult
//!     |-- summary_hash: Hash (digest of summary artifact)
//!     |-- tombstones: TombstoneList (dropped artifact references)
//!     |-- compacted_count: usize
//!     `-- retained_count: usize
//! ```
//!
//! # Compaction Strategies
//!
//! - **`CountSummary`**: Retain counts, drop details
//! - **`DigestOnly`**: Retain only content hashes
//! - **`TimeWindow`**: Compact artifacts older than threshold
//!
//! # Security Model
//!
//! - All collections are bounded per CTR-1303
//! - Compaction is idempotent (same input produces same output)
//! - Tombstones provide audit trail for compacted data
//! - Summary hashes enable verification of compaction integrity
//!
//! # Contract References
//!
//! - AD-EVID-002: Evidence TTL and pinning
//! - CTR-1303: Bounded collections with MAX_* constants
//! - CTR-1604: `deny_unknown_fields` for ledger/audit types

use std::time::Duration;

use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::receipt::Hash;
use super::tombstone::{ArtifactKind, Tombstone, TombstoneError, TombstoneList};
use crate::episode::EpisodeId;

// =============================================================================
// Limits (CTR-1303)
// =============================================================================

/// Maximum number of artifacts in a single compaction job.
///
/// This bounds memory usage during compaction operations.
pub const MAX_COMPACTION_ARTIFACTS: usize = 100_000;

/// Maximum length for artifact ID.
pub const MAX_ARTIFACT_ID_LEN: usize = 256;

/// Default compaction threshold: 7 days in nanoseconds.
pub const DEFAULT_COMPACTION_THRESHOLD_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

/// Minimum compaction threshold: 1 hour in nanoseconds.
pub const MIN_COMPACTION_THRESHOLD_NS: u64 = 60 * 60 * 1_000_000_000;

// =============================================================================
// CompactionStrategy
// =============================================================================

/// Strategy for evidence compaction.
///
/// Different strategies trade off between storage reduction and
/// information retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub enum CompactionStrategy {
    /// Retain counts only, drop all details.
    ///
    /// Produces a summary with artifact counts and total sizes.
    /// Most aggressive storage reduction.
    CountSummary,

    /// Retain only content hashes (digests).
    ///
    /// Produces a summary containing only the hashes of compacted
    /// artifacts, enabling existence verification without data.
    #[default]
    DigestOnly,

    /// Compact artifacts older than a time threshold.
    ///
    /// Keeps recent artifacts intact, compacts older ones.
    /// The threshold is specified in the job configuration.
    TimeWindow,
}

impl CompactionStrategy {
    /// Returns the numeric value for protobuf encoding.
    #[must_use]
    pub const fn value(&self) -> u32 {
        match self {
            Self::CountSummary => 1,
            Self::DigestOnly => 2,
            Self::TimeWindow => 3,
        }
    }

    /// Creates a `CompactionStrategy` from its numeric value.
    #[must_use]
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::CountSummary),
            2 => Some(Self::DigestOnly),
            3 => Some(Self::TimeWindow),
            _ => None,
        }
    }
}

impl std::fmt::Display for CompactionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CountSummary => write!(f, "count_summary"),
            Self::DigestOnly => write!(f, "digest_only"),
            Self::TimeWindow => write!(f, "time_window"),
        }
    }
}

// =============================================================================
// ArtifactId
// =============================================================================

/// Unique identifier for an evidence artifact.
///
/// Artifacts are identified by their content hash, which is computed
/// when they are stored in the content-addressed store.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactId {
    /// Content hash of the artifact.
    pub hash: Hash,

    /// Kind of artifact.
    pub kind: ArtifactKind,

    /// Timestamp when artifact was created (nanoseconds).
    pub created_at: u64,

    /// Size of the artifact in bytes.
    pub size_bytes: u64,
}

impl ArtifactId {
    /// Creates a new artifact ID.
    #[must_use]
    pub const fn new(hash: Hash, kind: ArtifactKind, created_at: u64, size_bytes: u64) -> Self {
        Self {
            hash,
            kind,
            created_at,
            size_bytes,
        }
    }

    /// Returns whether this artifact is older than the given threshold.
    ///
    /// # Arguments
    ///
    /// * `current_time_ns` - Current time in nanoseconds
    /// * `threshold` - Age threshold
    ///
    /// # Note
    ///
    /// This truncates the threshold nanosecond value to u64, which is
    /// sufficient for any practical duration (up to ~584 years).
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::missing_const_for_fn)]
    pub fn is_older_than(&self, current_time_ns: u64, threshold: Duration) -> bool {
        let threshold_ns = threshold.as_nanos() as u64;
        current_time_ns.saturating_sub(self.created_at) > threshold_ns
    }
}

// =============================================================================
// CompactionError
// =============================================================================

/// Errors that can occur during compaction operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompactionError {
    /// Too many artifacts in compaction job.
    #[error("too many artifacts in compaction job: {count} (max {max})")]
    TooManyArtifacts {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid episode ID.
    #[error("invalid episode ID: {reason}")]
    InvalidEpisodeId {
        /// Reason for invalidity.
        reason: String,
    },

    /// Invalid compaction threshold.
    #[error("invalid compaction threshold: {reason}")]
    InvalidThreshold {
        /// Reason for invalidity.
        reason: &'static str,
    },

    /// Tombstone error during compaction.
    #[error("tombstone error: {0}")]
    Tombstone(#[from] TombstoneError),

    /// No artifacts to compact.
    #[error("no artifacts to compact")]
    NoArtifacts,

    /// Compaction job validation failed.
    #[error("compaction job validation failed: {reason}")]
    ValidationFailed {
        /// Reason for failure.
        reason: String,
    },
}

// =============================================================================
// CompactionJob
// =============================================================================

/// A job specifying which artifacts to compact and how.
///
/// Compaction jobs are created by the evidence retention system when
/// artifacts exceed their TTL or storage quotas are approached.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::compaction::{CompactionJob, CompactionStrategy};
///
/// let job = CompactionJob::builder()
///     .episode_id("ep-001")
///     .strategy(CompactionStrategy::DigestOnly)
///     .artifacts(artifact_ids)
///     .build()?;
///
/// let result = job.execute(&cas, timestamp_ns)?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionJob {
    /// Episode ID this compaction belongs to.
    pub episode_id: EpisodeId,

    /// Artifacts to compact.
    artifacts: Vec<ArtifactId>,

    /// Compaction strategy to use.
    pub strategy: CompactionStrategy,

    /// For `TimeWindow` strategy: compact artifacts older than this.
    /// Nanoseconds since epoch.
    pub threshold_ns: Option<u64>,
}

impl CompactionJob {
    /// Creates a new compaction job builder.
    #[must_use]
    pub fn builder() -> CompactionJobBuilder {
        CompactionJobBuilder::new()
    }

    /// Returns the artifacts to compact.
    #[must_use]
    pub fn artifacts(&self) -> &[ArtifactId] {
        &self.artifacts
    }

    /// Returns the number of artifacts.
    #[must_use]
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Validates the compaction job.
    ///
    /// # Errors
    ///
    /// Returns an error if the job is invalid.
    pub fn validate(&self) -> Result<(), CompactionError> {
        if self.artifacts.is_empty() {
            return Err(CompactionError::NoArtifacts);
        }

        if self.artifacts.len() > MAX_COMPACTION_ARTIFACTS {
            return Err(CompactionError::TooManyArtifacts {
                count: self.artifacts.len(),
                max: MAX_COMPACTION_ARTIFACTS,
            });
        }

        // TimeWindow strategy requires threshold
        if self.strategy == CompactionStrategy::TimeWindow && self.threshold_ns.is_none() {
            return Err(CompactionError::InvalidThreshold {
                reason: "TimeWindow strategy requires threshold_ns",
            });
        }

        // Validate threshold if present
        if let Some(threshold) = self.threshold_ns {
            if threshold < MIN_COMPACTION_THRESHOLD_NS {
                return Err(CompactionError::InvalidThreshold {
                    reason: "threshold must be at least 1 hour",
                });
            }
        }

        Ok(())
    }

    /// Executes the compaction job, producing a result.
    ///
    /// This method:
    /// 1. Filters artifacts based on strategy
    /// 2. Generates summary artifact
    /// 3. Creates tombstones for compacted artifacts
    /// 4. Returns the compaction result
    ///
    /// # Arguments
    ///
    /// * `current_time_ns` - Current timestamp in nanoseconds
    /// * `summary_hash` - Hash of the generated summary (computed externally)
    ///
    /// # Errors
    ///
    /// Returns an error if compaction fails.
    pub fn execute(
        &self,
        current_time_ns: u64,
        summary_hash: Hash,
    ) -> Result<CompactionResult, CompactionError> {
        self.validate()?;

        let mut tombstones = TombstoneList::with_capacity(self.artifacts.len());
        let mut compacted_count = 0;
        let mut retained_count = 0;
        let mut compacted_bytes = 0u64;

        for artifact in &self.artifacts {
            let should_compact = match self.strategy {
                CompactionStrategy::CountSummary | CompactionStrategy::DigestOnly => true,
                CompactionStrategy::TimeWindow => {
                    let threshold = self.threshold_ns.unwrap_or(DEFAULT_COMPACTION_THRESHOLD_NS);
                    current_time_ns.saturating_sub(artifact.created_at) > threshold
                },
            };

            if should_compact {
                let tombstone =
                    Tombstone::new(artifact.hash, summary_hash, current_time_ns, artifact.kind);
                tombstones.push(tombstone)?;
                compacted_count += 1;
                compacted_bytes = compacted_bytes.saturating_add(artifact.size_bytes);
            } else {
                retained_count += 1;
            }
        }

        Ok(CompactionResult {
            summary_hash,
            tombstones,
            compacted_count,
            retained_count,
            compacted_bytes,
            strategy: self.strategy,
            episode_id: self.episode_id.clone(),
        })
    }

    /// Returns the canonical bytes for this job.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Sort artifacts by hash for determinism
        let mut sorted_hashes: Vec<_> = self.artifacts.iter().map(|a| a.hash).collect();
        sorted_hashes.sort_unstable();

        let proto = CompactionJobProto {
            episode_id: self.episode_id.as_str().to_string(),
            artifact_hashes: sorted_hashes.into_iter().map(|h| h.to_vec()).collect(),
            strategy: Some(self.strategy.value()),
            threshold_ns: self.threshold_ns,
        };
        proto.encode_to_vec()
    }

    /// Computes the BLAKE3 digest of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

/// Internal protobuf representation for `CompactionJob`.
#[derive(Clone, PartialEq, Message)]
struct CompactionJobProto {
    #[prost(string, tag = "1")]
    episode_id: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    artifact_hashes: Vec<Vec<u8>>,
    #[prost(uint32, optional, tag = "3")]
    strategy: Option<u32>,
    #[prost(uint64, optional, tag = "4")]
    threshold_ns: Option<u64>,
}

// =============================================================================
// CompactionJobBuilder
// =============================================================================

/// Builder for `CompactionJob`.
#[derive(Debug, Default)]
pub struct CompactionJobBuilder {
    episode_id: Option<EpisodeId>,
    artifacts: Vec<ArtifactId>,
    strategy: CompactionStrategy,
    threshold_ns: Option<u64>,
}

impl CompactionJobBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the episode ID.
    #[must_use]
    pub fn episode_id(mut self, id: EpisodeId) -> Self {
        self.episode_id = Some(id);
        self
    }

    /// Sets the compaction strategy.
    #[must_use]
    pub const fn strategy(mut self, strategy: CompactionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Adds an artifact to compact.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed `MAX_COMPACTION_ARTIFACTS`.
    pub fn add_artifact(&mut self, artifact: ArtifactId) -> Result<&mut Self, CompactionError> {
        if self.artifacts.len() >= MAX_COMPACTION_ARTIFACTS {
            return Err(CompactionError::TooManyArtifacts {
                count: self.artifacts.len() + 1,
                max: MAX_COMPACTION_ARTIFACTS,
            });
        }
        self.artifacts.push(artifact);
        Ok(self)
    }

    /// Sets the artifacts to compact.
    ///
    /// # Errors
    ///
    /// Returns an error if the list exceeds `MAX_COMPACTION_ARTIFACTS`.
    pub fn artifacts(mut self, artifacts: Vec<ArtifactId>) -> Result<Self, CompactionError> {
        if artifacts.len() > MAX_COMPACTION_ARTIFACTS {
            return Err(CompactionError::TooManyArtifacts {
                count: artifacts.len(),
                max: MAX_COMPACTION_ARTIFACTS,
            });
        }
        self.artifacts = artifacts;
        Ok(self)
    }

    /// Sets the time threshold for `TimeWindow` strategy.
    #[must_use]
    pub const fn threshold_ns(mut self, threshold: u64) -> Self {
        self.threshold_ns = Some(threshold);
        self
    }

    /// Sets the time threshold from a Duration.
    ///
    /// # Note
    ///
    /// This truncates the nanosecond value to u64, which is sufficient for
    /// any practical duration (up to ~584 years).
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::missing_const_for_fn)]
    pub fn threshold(mut self, threshold: Duration) -> Self {
        self.threshold_ns = Some(threshold.as_nanos() as u64);
        self
    }

    /// Builds the compaction job.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or validation fails.
    pub fn build(self) -> Result<CompactionJob, CompactionError> {
        let episode_id = self
            .episode_id
            .ok_or_else(|| CompactionError::ValidationFailed {
                reason: "episode_id is required".to_string(),
            })?;

        let job = CompactionJob {
            episode_id,
            artifacts: self.artifacts,
            strategy: self.strategy,
            threshold_ns: self.threshold_ns,
        };

        job.validate()?;
        Ok(job)
    }
}

// =============================================================================
// CompactionResult
// =============================================================================

/// Result of executing a compaction job.
///
/// Contains the summary hash, tombstones for dropped artifacts,
/// and statistics about the compaction operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionResult {
    /// Hash of the summary artifact.
    pub summary_hash: Hash,

    /// Tombstones for compacted artifacts.
    pub tombstones: TombstoneList,

    /// Number of artifacts compacted.
    pub compacted_count: usize,

    /// Number of artifacts retained (not compacted).
    pub retained_count: usize,

    /// Total bytes of compacted artifacts.
    pub compacted_bytes: u64,

    /// Strategy used for compaction.
    pub strategy: CompactionStrategy,

    /// Episode this compaction belongs to.
    pub episode_id: EpisodeId,
}

impl CompactionResult {
    /// Returns `true` if any artifacts were compacted.
    #[must_use]
    pub const fn has_compacted(&self) -> bool {
        self.compacted_count > 0
    }

    /// Returns the total number of artifacts processed.
    #[must_use]
    pub const fn total_processed(&self) -> usize {
        self.compacted_count + self.retained_count
    }

    /// Returns the compaction ratio (compacted / total).
    ///
    /// Returns 0.0 if no artifacts were processed.
    ///
    /// # Note
    ///
    /// For extremely large values (>2^52), precision may be lost during
    /// the conversion to f64. This is acceptable for a ratio calculation.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn compaction_ratio(&self) -> f64 {
        let total = self.total_processed();
        if total == 0 {
            0.0
        } else {
            self.compacted_count as f64 / total as f64
        }
    }

    /// Returns the canonical bytes for this result.
    ///
    /// Per AD-VERIFY-001, provides deterministic serialization.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = CompactionResultProto {
            summary_hash: self.summary_hash.to_vec(),
            tombstones_hash: self.tombstones.digest().to_vec(),
            compacted_count: Some(self.compacted_count as u64),
            retained_count: Some(self.retained_count as u64),
            compacted_bytes: Some(self.compacted_bytes),
            strategy: Some(self.strategy.value()),
            episode_id: self.episode_id.as_str().to_string(),
        };
        proto.encode_to_vec()
    }

    /// Computes the BLAKE3 digest of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

/// Internal protobuf representation for `CompactionResult`.
#[derive(Clone, PartialEq, Message)]
struct CompactionResultProto {
    #[prost(bytes = "vec", tag = "1")]
    summary_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    tombstones_hash: Vec<u8>,
    #[prost(uint64, optional, tag = "3")]
    compacted_count: Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    retained_count: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    compacted_bytes: Option<u64>,
    #[prost(uint32, optional, tag = "6")]
    strategy: Option<u32>,
    #[prost(string, tag = "7")]
    episode_id: String,
}

// =============================================================================
// CompactionSummary
// =============================================================================

/// Summary of compacted evidence for storage in CAS.
///
/// This is the artifact that replaces the compacted data, containing
/// enough information for audit purposes without the full data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionSummary {
    /// Episode this summary belongs to.
    pub episode_id: EpisodeId,

    /// Hashes of all compacted artifacts.
    pub artifact_hashes: Vec<Hash>,

    /// Total count of compacted artifacts by kind.
    pub counts_by_kind: CompactionCounts,

    /// Total size of compacted data in bytes.
    pub total_size_bytes: u64,

    /// Timestamp when compaction occurred (nanoseconds).
    pub compacted_at: u64,

    /// Strategy used for compaction.
    pub strategy: CompactionStrategy,
}

impl CompactionSummary {
    /// Creates a new compaction summary.
    #[must_use]
    pub const fn new(
        episode_id: EpisodeId,
        artifact_hashes: Vec<Hash>,
        counts_by_kind: CompactionCounts,
        total_size_bytes: u64,
        compacted_at: u64,
        strategy: CompactionStrategy,
    ) -> Self {
        Self {
            episode_id,
            artifact_hashes,
            counts_by_kind,
            total_size_bytes,
            compacted_at,
            strategy,
        }
    }

    /// Returns the total number of compacted artifacts.
    #[must_use]
    pub fn total_artifacts(&self) -> usize {
        self.artifact_hashes.len()
    }

    /// Serializes the summary to JSON bytes for CAS storage.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Computes the BLAKE3 hash of the serialized summary.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn compute_hash(&self) -> Result<Hash, serde_json::Error> {
        let bytes = self.to_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

/// Counts of compacted artifacts by kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionCounts {
    /// Number of PTY transcript artifacts.
    pub pty_transcripts: u64,

    /// Number of tool event artifacts.
    pub tool_events: u64,

    /// Number of telemetry frame artifacts.
    pub telemetry_frames: u64,

    /// Number of evidence bundle artifacts.
    pub evidence_bundles: u64,

    /// Number of generic artifacts.
    pub generic: u64,
}

impl CompactionCounts {
    /// Creates new compaction counts from artifact list.
    #[must_use]
    pub fn from_artifacts(artifacts: &[ArtifactId]) -> Self {
        let mut counts = Self::default();
        for artifact in artifacts {
            match artifact.kind {
                ArtifactKind::PtyTranscript => counts.pty_transcripts += 1,
                ArtifactKind::ToolEvent => counts.tool_events += 1,
                ArtifactKind::TelemetryFrame => counts.telemetry_frames += 1,
                ArtifactKind::EvidenceBundle => counts.evidence_bundles += 1,
                ArtifactKind::Generic => counts.generic += 1,
            }
        }
        counts
    }

    /// Returns the total count of all artifacts.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.pty_transcripts
            + self.tool_events
            + self.telemetry_frames
            + self.evidence_bundles
            + self.generic
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(value: u8) -> Hash {
        [value; 32]
    }

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("ep-test-001").unwrap()
    }

    fn test_artifact(hash_val: u8, created_at: u64) -> ArtifactId {
        ArtifactId::new(
            test_hash(hash_val),
            ArtifactKind::ToolEvent,
            created_at,
            1024,
        )
    }

    // =========================================================================
    // CompactionStrategy tests
    // =========================================================================

    #[test]
    fn test_strategy_value_roundtrip() {
        for strategy in [
            CompactionStrategy::CountSummary,
            CompactionStrategy::DigestOnly,
            CompactionStrategy::TimeWindow,
        ] {
            let value = strategy.value();
            let restored = CompactionStrategy::from_value(value);
            assert_eq!(
                restored,
                Some(strategy),
                "roundtrip failed for {strategy:?}"
            );
        }
    }

    #[test]
    fn test_strategy_from_invalid_value() {
        assert!(CompactionStrategy::from_value(0).is_none());
        assert!(CompactionStrategy::from_value(100).is_none());
    }

    #[test]
    fn test_strategy_default() {
        assert_eq!(
            CompactionStrategy::default(),
            CompactionStrategy::DigestOnly
        );
    }

    #[test]
    fn test_strategy_display() {
        assert_eq!(
            CompactionStrategy::CountSummary.to_string(),
            "count_summary"
        );
        assert_eq!(CompactionStrategy::DigestOnly.to_string(), "digest_only");
        assert_eq!(CompactionStrategy::TimeWindow.to_string(), "time_window");
    }

    // =========================================================================
    // ArtifactId tests
    // =========================================================================

    #[test]
    fn test_artifact_id_is_older_than() {
        let artifact = test_artifact(0xaa, 1_000_000_000);
        let current = 2_000_000_000u64;

        // 1 second old, threshold 0.5 seconds
        assert!(artifact.is_older_than(current, Duration::from_millis(500)));

        // 1 second old, threshold 2 seconds
        assert!(!artifact.is_older_than(current, Duration::from_secs(2)));
    }

    // =========================================================================
    // CompactionJob tests (UT-00172-01: Compaction produces summary)
    // =========================================================================

    #[test]
    fn test_compaction_job_builder() {
        let artifacts = vec![test_artifact(0xaa, 1_000_000_000)];

        let job = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::DigestOnly)
            .artifacts(artifacts)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(job.episode_id, test_episode_id());
        assert_eq!(job.strategy, CompactionStrategy::DigestOnly);
        assert_eq!(job.artifact_count(), 1);
    }

    #[test]
    fn test_compaction_job_validation_no_artifacts() {
        let result = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::DigestOnly)
            .build();

        assert!(matches!(result, Err(CompactionError::NoArtifacts)));
    }

    #[test]
    fn test_compaction_job_validation_time_window_requires_threshold() {
        let artifacts = vec![test_artifact(0xaa, 1_000_000_000)];

        let result = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::TimeWindow)
            .artifacts(artifacts)
            .unwrap()
            .build();

        assert!(matches!(
            result,
            Err(CompactionError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn test_compaction_job_execute_digest_only() {
        let artifacts = vec![
            test_artifact(0xaa, 1_000_000_000),
            test_artifact(0xbb, 1_000_000_000),
        ];

        let job = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::DigestOnly)
            .artifacts(artifacts)
            .unwrap()
            .build()
            .unwrap();

        let summary_hash = test_hash(0xcc);
        let result = job.execute(2_000_000_000, summary_hash).unwrap();

        assert_eq!(result.summary_hash, summary_hash);
        assert_eq!(result.compacted_count, 2);
        assert_eq!(result.retained_count, 0);
        assert_eq!(result.tombstones.len(), 2);
        assert!(result.has_compacted());
    }

    #[test]
    fn test_compaction_job_execute_time_window() {
        // Use timestamps in nanoseconds:
        // - Old artifact: 0 ns
        // - Recent artifact: 1 hour + 30 minutes (5400 seconds)
        // - Current time: 2 hours (7200 seconds)
        // - Threshold: 1 hour (3600 seconds = MIN_COMPACTION_THRESHOLD_NS)
        let artifacts = vec![
            test_artifact(0xaa, 0),                    // Old (2 hours ago)
            test_artifact(0xbb, 5_400_000_000_000u64), // Recent (30 min ago)
        ];

        let job = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::TimeWindow)
            .artifacts(artifacts)
            .unwrap()
            .threshold_ns(MIN_COMPACTION_THRESHOLD_NS) // 1 hour threshold
            .build()
            .unwrap();

        let summary_hash = test_hash(0xcc);
        let current_time = 7_200_000_000_000u64; // 2 hours in ns
        let result = job.execute(current_time, summary_hash).unwrap();

        // Only the old artifact should be compacted (more than 1 hour old)
        // The recent artifact (30 min old) should be retained
        assert_eq!(result.compacted_count, 1);
        assert_eq!(result.retained_count, 1);
    }

    #[test]
    fn test_compaction_job_canonical_bytes_determinism() {
        let artifacts = vec![test_artifact(0xaa, 1_000_000_000)];

        let job1 = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::DigestOnly)
            .artifacts(artifacts.clone())
            .unwrap()
            .build()
            .unwrap();

        let job2 = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::DigestOnly)
            .artifacts(artifacts)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            job1.canonical_bytes(),
            job2.canonical_bytes(),
            "identical jobs must produce identical canonical bytes"
        );
    }

    #[test]
    fn test_compaction_job_too_many_artifacts() {
        #[allow(clippy::cast_possible_truncation)]
        let artifacts: Vec<_> = (0..=MAX_COMPACTION_ARTIFACTS)
            .map(|i| test_artifact((i % 256) as u8, 1_000_000_000))
            .collect();

        let result = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::DigestOnly)
            .artifacts(artifacts);

        assert!(matches!(
            result,
            Err(CompactionError::TooManyArtifacts { .. })
        ));
    }

    // =========================================================================
    // CompactionResult tests
    // =========================================================================

    #[test]
    fn test_compaction_result_compaction_ratio() {
        let artifacts = vec![test_artifact(0xaa, 1_000_000_000)];

        let job = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::DigestOnly)
            .artifacts(artifacts)
            .unwrap()
            .build()
            .unwrap();

        let result = job.execute(2_000_000_000, test_hash(0xcc)).unwrap();

        assert!((result.compaction_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compaction_result_serde_roundtrip() {
        let artifacts = vec![test_artifact(0xaa, 1_000_000_000)];

        let job = CompactionJob::builder()
            .episode_id(test_episode_id())
            .strategy(CompactionStrategy::DigestOnly)
            .artifacts(artifacts)
            .unwrap()
            .build()
            .unwrap();

        let result = job.execute(2_000_000_000, test_hash(0xcc)).unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let restored: CompactionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    /// SECURITY: Verify unknown fields are rejected.
    #[test]
    fn test_compaction_result_rejects_unknown_fields() {
        let json = r#"{
            "summary_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "tombstones": {"tombstones": []},
            "compacted_count": 0,
            "retained_count": 0,
            "compacted_bytes": 0,
            "strategy": "digest_only",
            "episode_id": "ep-001",
            "malicious": "attack"
        }"#;

        let result: Result<CompactionResult, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    // =========================================================================
    // CompactionSummary tests
    // =========================================================================

    #[test]
    fn test_compaction_summary() {
        let summary = CompactionSummary::new(
            test_episode_id(),
            vec![test_hash(0xaa), test_hash(0xbb)],
            CompactionCounts::default(),
            2048,
            1_000_000_000,
            CompactionStrategy::DigestOnly,
        );

        assert_eq!(summary.total_artifacts(), 2);
        assert!(summary.compute_hash().is_ok());
    }

    #[test]
    fn test_compaction_counts_from_artifacts() {
        let artifacts = vec![
            ArtifactId::new(test_hash(0xaa), ArtifactKind::ToolEvent, 1_000_000_000, 100),
            ArtifactId::new(
                test_hash(0xbb),
                ArtifactKind::TelemetryFrame,
                1_000_000_000,
                200,
            ),
            ArtifactId::new(test_hash(0xcc), ArtifactKind::ToolEvent, 1_000_000_000, 100),
        ];

        let counts = CompactionCounts::from_artifacts(&artifacts);

        assert_eq!(counts.tool_events, 2);
        assert_eq!(counts.telemetry_frames, 1);
        assert_eq!(counts.total(), 3);
    }

    #[test]
    fn test_compaction_summary_serde_roundtrip() {
        let summary = CompactionSummary::new(
            test_episode_id(),
            vec![test_hash(0xaa)],
            CompactionCounts::default(),
            1024,
            1_000_000_000,
            CompactionStrategy::DigestOnly,
        );

        let json = serde_json::to_string(&summary).unwrap();
        let restored: CompactionSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }
}
