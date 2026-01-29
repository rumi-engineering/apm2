//! Tombstone tracking for compacted evidence artifacts.
//!
//! This module implements tombstones per AD-EVID-002 for tracking dropped
//! artifacts after compaction. Tombstones provide audit trail references
//! from summary artifacts back to the original compacted data.
//!
//! # Architecture
//!
//! ```text
//! Tombstone
//!     |-- original_hash: Hash (what was compacted)
//!     |-- summary_hash: Hash (where summary lives)
//!     |-- dropped_at: u64 (nanosecond timestamp)
//!     `-- artifact_kind: ArtifactKind (classification)
//! ```
//!
//! # Security Model
//!
//! - Tombstones enable verification that compacted data existed
//! - Original hash provides CAS reference for audit
//! - Summary hash links to retained digest-only summary
//! - All collections are bounded per CTR-1303
//!
//! # Contract References
//!
//! - AD-EVID-002: Evidence TTL and pinning
//! - CTR-1303: Bounded collections with MAX_* constants
//! - CTR-1604: `deny_unknown_fields` for ledger/audit types

use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::receipt::Hash;

// =============================================================================
// Limits (CTR-1303)
// =============================================================================

/// Maximum number of tombstones in a single compaction result.
///
/// This bounds memory usage during compaction operations.
pub const MAX_TOMBSTONES: usize = 10_000;

/// Maximum length for artifact kind description.
pub const MAX_ARTIFACT_KIND_LEN: usize = 64;

// =============================================================================
// ArtifactKind
// =============================================================================

/// Classification of the compacted artifact.
///
/// This indicates what type of evidence was compacted, enabling
/// targeted retrieval from summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArtifactKind {
    /// PTY output transcript.
    PtyTranscript,

    /// Tool execution event.
    ToolEvent,

    /// Telemetry frame.
    TelemetryFrame,

    /// Evidence bundle containing multiple types.
    EvidenceBundle,

    /// Generic artifact (unclassified).
    Generic,
}

impl ArtifactKind {
    /// Returns the numeric value for protobuf encoding.
    #[must_use]
    pub const fn value(&self) -> u32 {
        match self {
            Self::PtyTranscript => 1,
            Self::ToolEvent => 2,
            Self::TelemetryFrame => 3,
            Self::EvidenceBundle => 4,
            Self::Generic => 5,
        }
    }

    /// Creates an `ArtifactKind` from its numeric value.
    #[must_use]
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::PtyTranscript),
            2 => Some(Self::ToolEvent),
            3 => Some(Self::TelemetryFrame),
            4 => Some(Self::EvidenceBundle),
            5 => Some(Self::Generic),
            _ => None,
        }
    }
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PtyTranscript => write!(f, "pty_transcript"),
            Self::ToolEvent => write!(f, "tool_event"),
            Self::TelemetryFrame => write!(f, "telemetry_frame"),
            Self::EvidenceBundle => write!(f, "evidence_bundle"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

// =============================================================================
// TombstoneError
// =============================================================================

/// Errors that can occur during tombstone operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TombstoneError {
    /// Too many tombstones in collection.
    #[error("too many tombstones: {count} (max {max})")]
    TooManyTombstones {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid timestamp.
    #[error("invalid timestamp: {reason}")]
    InvalidTimestamp {
        /// Reason for invalidity.
        reason: &'static str,
    },

    /// Tombstone validation failed.
    #[error("tombstone validation failed: {reason}")]
    ValidationFailed {
        /// Reason for failure.
        reason: String,
    },
}

// =============================================================================
// Tombstone
// =============================================================================

/// A tombstone marking a compacted evidence artifact.
///
/// Tombstones provide an audit trail for compacted data, enabling
/// verification that evidence existed even after the original data
/// has been removed.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::tombstone::{Tombstone, ArtifactKind};
///
/// let tombstone = Tombstone::new(
///     original_hash,
///     summary_hash,
///     timestamp_ns,
///     ArtifactKind::ToolEvent,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tombstone {
    /// Hash of the original artifact that was compacted.
    pub original_hash: Hash,

    /// Hash of the summary artifact that replaced it.
    pub summary_hash: Hash,

    /// Timestamp when the artifact was dropped (nanoseconds since epoch).
    pub dropped_at: u64,

    /// Kind of artifact that was compacted.
    pub artifact_kind: ArtifactKind,
}

impl Tombstone {
    /// Creates a new tombstone.
    ///
    /// # Arguments
    ///
    /// * `original_hash` - Hash of the original artifact
    /// * `summary_hash` - Hash of the summary that replaced it
    /// * `dropped_at` - Timestamp in nanoseconds
    /// * `artifact_kind` - Classification of the artifact
    #[must_use]
    pub const fn new(
        original_hash: Hash,
        summary_hash: Hash,
        dropped_at: u64,
        artifact_kind: ArtifactKind,
    ) -> Self {
        Self {
            original_hash,
            summary_hash,
            dropped_at,
            artifact_kind,
        }
    }

    /// Validates the tombstone.
    ///
    /// # Errors
    ///
    /// Returns an error if the tombstone is invalid.
    pub const fn validate(&self) -> Result<(), TombstoneError> {
        // Timestamp should be non-zero for valid tombstones
        if self.dropped_at == 0 {
            return Err(TombstoneError::InvalidTimestamp {
                reason: "timestamp cannot be zero",
            });
        }
        Ok(())
    }

    /// Returns the canonical bytes for this tombstone.
    ///
    /// Per AD-VERIFY-001, provides deterministic serialization.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = TombstoneProto {
            original_hash: self.original_hash.to_vec(),
            summary_hash: self.summary_hash.to_vec(),
            dropped_at: Some(self.dropped_at),
            artifact_kind: Some(self.artifact_kind.value()),
        };
        proto.encode_to_vec()
    }

    /// Computes the BLAKE3 digest of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

/// Internal protobuf representation for `Tombstone`.
#[derive(Clone, PartialEq, Message)]
struct TombstoneProto {
    #[prost(bytes = "vec", tag = "1")]
    original_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    summary_hash: Vec<u8>,
    #[prost(uint64, optional, tag = "3")]
    dropped_at: Option<u64>,
    #[prost(uint32, optional, tag = "4")]
    artifact_kind: Option<u32>,
}

// =============================================================================
// TombstoneList
// =============================================================================

/// A bounded collection of tombstones.
///
/// This provides a safe wrapper for tombstone collections with
/// enforced size limits per CTR-1303.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TombstoneList {
    /// The tombstones in this list.
    tombstones: Vec<Tombstone>,
}

impl TombstoneList {
    /// Creates a new empty tombstone list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tombstones: Vec::new(),
        }
    }

    /// Creates a tombstone list with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial capacity (capped at `MAX_TOMBSTONES`)
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tombstones: Vec::with_capacity(capacity.min(MAX_TOMBSTONES)),
        }
    }

    /// Adds a tombstone to the list.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed `MAX_TOMBSTONES`.
    pub fn push(&mut self, tombstone: Tombstone) -> Result<(), TombstoneError> {
        if self.tombstones.len() >= MAX_TOMBSTONES {
            return Err(TombstoneError::TooManyTombstones {
                count: self.tombstones.len() + 1,
                max: MAX_TOMBSTONES,
            });
        }
        self.tombstones.push(tombstone);
        Ok(())
    }

    /// Returns the number of tombstones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tombstones.len()
    }

    /// Returns `true` if the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tombstones.is_empty()
    }

    /// Returns an iterator over the tombstones.
    pub fn iter(&self) -> impl Iterator<Item = &Tombstone> {
        self.tombstones.iter()
    }

    /// Returns the tombstones as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[Tombstone] {
        &self.tombstones
    }

    /// Consumes the list and returns the inner vector.
    #[must_use]
    pub fn into_inner(self) -> Vec<Tombstone> {
        self.tombstones
    }

    /// Validates all tombstones in the list.
    ///
    /// # Errors
    ///
    /// Returns an error if any tombstone is invalid.
    pub fn validate(&self) -> Result<(), TombstoneError> {
        for tombstone in &self.tombstones {
            tombstone.validate()?;
        }
        Ok(())
    }

    /// Returns the canonical bytes for the list.
    ///
    /// Tombstones are sorted by `original_hash` for determinism.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Sort tombstones by original_hash for determinism
        let mut sorted: Vec<_> = self.tombstones.clone();
        sorted.sort_unstable_by_key(|t| t.original_hash);

        let proto = TombstoneListProto {
            tombstones: sorted.into_iter().map(|t| t.canonical_bytes()).collect(),
        };
        proto.encode_to_vec()
    }

    /// Computes the BLAKE3 digest of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

impl FromIterator<Tombstone> for TombstoneList {
    fn from_iter<I: IntoIterator<Item = Tombstone>>(iter: I) -> Self {
        let mut list = Self::new();
        for tombstone in iter {
            // Silently truncate if exceeding limit during iteration
            if list.push(tombstone).is_err() {
                break;
            }
        }
        list
    }
}

/// Internal protobuf representation for `TombstoneList`.
#[derive(Clone, PartialEq, Message)]
struct TombstoneListProto {
    #[prost(bytes = "vec", repeated, tag = "1")]
    tombstones: Vec<Vec<u8>>,
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

    fn test_tombstone() -> Tombstone {
        Tombstone::new(
            test_hash(0xaa),
            test_hash(0xbb),
            1_704_067_200_000_000_000, // 2024-01-01 00:00:00 UTC
            ArtifactKind::ToolEvent,
        )
    }

    // =========================================================================
    // ArtifactKind tests
    // =========================================================================

    #[test]
    fn test_artifact_kind_value_roundtrip() {
        for kind in [
            ArtifactKind::PtyTranscript,
            ArtifactKind::ToolEvent,
            ArtifactKind::TelemetryFrame,
            ArtifactKind::EvidenceBundle,
            ArtifactKind::Generic,
        ] {
            let value = kind.value();
            let restored = ArtifactKind::from_value(value);
            assert_eq!(restored, Some(kind), "roundtrip failed for {kind:?}");
        }
    }

    #[test]
    fn test_artifact_kind_from_invalid_value() {
        assert!(ArtifactKind::from_value(0).is_none());
        assert!(ArtifactKind::from_value(100).is_none());
    }

    #[test]
    fn test_artifact_kind_display() {
        assert_eq!(ArtifactKind::PtyTranscript.to_string(), "pty_transcript");
        assert_eq!(ArtifactKind::ToolEvent.to_string(), "tool_event");
        assert_eq!(ArtifactKind::TelemetryFrame.to_string(), "telemetry_frame");
        assert_eq!(ArtifactKind::EvidenceBundle.to_string(), "evidence_bundle");
        assert_eq!(ArtifactKind::Generic.to_string(), "generic");
    }

    // =========================================================================
    // Tombstone tests (UT-00172-02: Tombstone creation)
    // =========================================================================

    #[test]
    fn test_tombstone_creation() {
        let tombstone = test_tombstone();
        assert_eq!(tombstone.original_hash, test_hash(0xaa));
        assert_eq!(tombstone.summary_hash, test_hash(0xbb));
        assert_eq!(tombstone.dropped_at, 1_704_067_200_000_000_000);
        assert_eq!(tombstone.artifact_kind, ArtifactKind::ToolEvent);
    }

    #[test]
    fn test_tombstone_validation_valid() {
        let tombstone = test_tombstone();
        assert!(tombstone.validate().is_ok());
    }

    #[test]
    fn test_tombstone_validation_zero_timestamp() {
        let tombstone = Tombstone::new(
            test_hash(0xaa),
            test_hash(0xbb),
            0, // Invalid: zero timestamp
            ArtifactKind::Generic,
        );
        assert!(matches!(
            tombstone.validate(),
            Err(TombstoneError::InvalidTimestamp { .. })
        ));
    }

    #[test]
    fn test_tombstone_canonical_bytes_determinism() {
        let t1 = test_tombstone();
        let t2 = test_tombstone();

        assert_eq!(
            t1.canonical_bytes(),
            t2.canonical_bytes(),
            "identical tombstones must produce identical canonical bytes"
        );
        assert_eq!(
            t1.digest(),
            t2.digest(),
            "identical tombstones must produce identical digests"
        );
    }

    #[test]
    fn test_tombstone_serde_roundtrip() {
        let tombstone = test_tombstone();
        let json = serde_json::to_string(&tombstone).unwrap();
        let restored: Tombstone = serde_json::from_str(&json).unwrap();
        assert_eq!(tombstone, restored);
    }

    /// SECURITY: Verify unknown fields are rejected.
    #[test]
    fn test_tombstone_rejects_unknown_fields() {
        let json = r#"{
            "original_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "summary_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "dropped_at": 1000000000,
            "artifact_kind": "generic",
            "malicious": "attack"
        }"#;

        let result: Result<Tombstone, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    // =========================================================================
    // TombstoneList tests
    // =========================================================================

    #[test]
    fn test_tombstone_list_new() {
        let list = TombstoneList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_tombstone_list_push() {
        let mut list = TombstoneList::new();
        list.push(test_tombstone()).unwrap();
        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_tombstone_list_bounded() {
        let mut list = TombstoneList::new();

        // Fill to limit
        #[allow(clippy::cast_possible_truncation)]
        for i in 0..MAX_TOMBSTONES {
            let tombstone = Tombstone::new(
                test_hash((i % 256) as u8),
                test_hash(0xbb),
                1_000_000_000,
                ArtifactKind::Generic,
            );
            list.push(tombstone).unwrap();
        }

        // One more should fail
        let result = list.push(test_tombstone());
        assert!(matches!(
            result,
            Err(TombstoneError::TooManyTombstones { .. })
        ));
    }

    #[test]
    fn test_tombstone_list_iter() {
        let mut list = TombstoneList::new();
        list.push(test_tombstone()).unwrap();
        list.push(test_tombstone()).unwrap();

        let count = list.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_tombstone_list_from_iter() {
        let tombstones = vec![test_tombstone(), test_tombstone()];
        let list: TombstoneList = tombstones.into_iter().collect();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_tombstone_list_canonical_bytes_sorts() {
        let mut list1 = TombstoneList::new();
        list1
            .push(Tombstone::new(
                test_hash(0xff),
                test_hash(0xbb),
                1_000_000_000,
                ArtifactKind::Generic,
            ))
            .unwrap();
        list1
            .push(Tombstone::new(
                test_hash(0x00),
                test_hash(0xbb),
                1_000_000_000,
                ArtifactKind::Generic,
            ))
            .unwrap();

        let mut list2 = TombstoneList::new();
        list2
            .push(Tombstone::new(
                test_hash(0x00),
                test_hash(0xbb),
                1_000_000_000,
                ArtifactKind::Generic,
            ))
            .unwrap();
        list2
            .push(Tombstone::new(
                test_hash(0xff),
                test_hash(0xbb),
                1_000_000_000,
                ArtifactKind::Generic,
            ))
            .unwrap();

        // Despite different insertion order, canonical bytes should match
        assert_eq!(
            list1.canonical_bytes(),
            list2.canonical_bytes(),
            "canonical bytes should be sorted for determinism"
        );
    }

    #[test]
    fn test_tombstone_list_validate() {
        let mut list = TombstoneList::new();
        list.push(test_tombstone()).unwrap();
        assert!(list.validate().is_ok());

        // Add invalid tombstone
        list.push(Tombstone::new(
            test_hash(0xaa),
            test_hash(0xbb),
            0, // Invalid
            ArtifactKind::Generic,
        ))
        .unwrap();
        assert!(list.validate().is_err());
    }

    #[test]
    fn test_tombstone_list_serde_roundtrip() {
        let mut list = TombstoneList::new();
        list.push(test_tombstone()).unwrap();

        let json = serde_json::to_string(&list).unwrap();
        let restored: TombstoneList = serde_json::from_str(&json).unwrap();
        assert_eq!(list, restored);
    }

    /// SECURITY: Verify unknown fields are rejected.
    #[test]
    fn test_tombstone_list_rejects_unknown_fields() {
        let json = r#"{
            "tombstones": [],
            "malicious": "attack"
        }"#;

        let result: Result<TombstoneList, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }
}
