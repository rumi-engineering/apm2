//! Compaction receipt generation for audit trail.
//!
//! This module implements compaction receipts per AD-RECEIPT-001, providing
//! cryptographic proof of compaction operations for audit and verification.
//!
//! # Architecture
//!
//! ```text
//! CompactionReceipt
//!     |-- episode_id: EpisodeId
//!     |-- compacted_hashes: Vec<Hash> (what was compacted)
//!     |-- summary_hash: Hash (the replacement summary)
//!     |-- tombstone_list_hash: Hash (hash of all tombstones)
//!     |-- strategy: CompactionStrategy
//!     |-- compacted_at: u64 (timestamp)
//!     |-- canonicalizer_id: CanonicalizerId
//!     |-- canonicalizer_version: u32
//!     |-- unsigned_bytes_hash: Hash
//!     `-- signature: Option<Signature>
//! ```
//!
//! # Security Model
//!
//! Per AD-RECEIPT-001:
//! - Receipts bind all compaction details for audit
//! - `canonical_bytes()` provides deterministic serialization for signing
//! - Compacted hashes are sorted for determinism per AD-VERIFY-001
//! - Signature verification uses constant-time Ed25519 (CTR-1909)
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-VERIFY-001: Deterministic serialization
//! - AD-EVID-002: Evidence TTL and pinning
//! - CTR-1303: Bounded collections with MAX_* constants
//! - CTR-1604: `deny_unknown_fields` for ledger/audit types

use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::compaction::CompactionStrategy;
use super::receipt::{
    CanonicalizerId, Hash, MAX_EVIDENCE_REFS, MAX_SIGNER_IDENTITY_LEN, Signature, SignerIdentity,
};
use crate::episode::EpisodeId;

// =============================================================================
// Limits (CTR-1303)
// =============================================================================

/// Maximum number of compacted artifact hashes in a receipt.
///
/// This bounds memory usage for compaction receipt construction.
pub const MAX_COMPACTED_HASHES: usize = MAX_EVIDENCE_REFS;

// =============================================================================
// CompactionReceiptError
// =============================================================================

/// Errors that can occur during compaction receipt operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompactionReceiptError {
    /// Too many compacted hashes.
    #[error("too many compacted hashes: {count} (max {max})")]
    TooManyCompactedHashes {
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

    /// Invalid timestamp.
    #[error("invalid timestamp: {reason}")]
    InvalidTimestamp {
        /// Reason for invalidity.
        reason: &'static str,
    },

    /// Receipt is not signed.
    #[error("receipt is not signed")]
    NotSigned,

    /// Receipt is already signed.
    #[error("receipt is already signed")]
    AlreadySigned,

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Hash mismatch between stored and computed digest.
    #[error("hash mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch {
        /// Expected hash (computed digest).
        expected: Hash,
        /// Actual hash (stored value).
        actual: Hash,
    },

    /// Signer identity too long.
    #[error("signer identity too long: {len} bytes (max {max})")]
    SignerIdentityTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Canonicalizer ID too long.
    #[error("canonicalizer ID too long: {len} bytes (max {max})")]
    CanonicalizerIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// =============================================================================
// CompactionReceipt
// =============================================================================

/// A receipt providing cryptographic proof of evidence compaction.
///
/// Compaction receipts enable verification that:
/// 1. Specific artifacts were compacted
/// 2. A summary was created to replace them
/// 3. Tombstones were properly generated
/// 4. The compaction was authorized
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::summary::{CompactionReceipt, CompactionReceiptBuilder};
///
/// let receipt = CompactionReceiptBuilder::new()
///     .episode_id(episode_id)
///     .compacted_hashes(hashes)
///     .summary_hash(summary_hash)
///     .tombstone_list_hash(tombstone_hash)
///     .strategy(CompactionStrategy::DigestOnly)
///     .compacted_at(timestamp_ns)
///     .build()?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionReceipt {
    /// Episode ID this compaction belongs to.
    pub episode_id: EpisodeId,

    /// Hashes of compacted artifacts.
    ///
    /// Sorted for deterministic encoding per AD-VERIFY-001.
    compacted_hashes: Vec<Hash>,

    /// Hash of the summary artifact that replaced the compacted data.
    pub summary_hash: Hash,

    /// Hash of the tombstone list.
    pub tombstone_list_hash: Hash,

    /// Compaction strategy used.
    pub strategy: CompactionStrategy,

    /// Timestamp when compaction occurred (nanoseconds since epoch).
    pub compacted_at: u64,

    /// Statistics about the compaction.
    pub stats: CompactionStats,

    /// Canonicalizer identifier.
    pub canonicalizer_id: CanonicalizerId,

    /// Canonicalizer version for determinism tracking.
    pub canonicalizer_version: u32,

    /// BLAKE3 hash of the canonical unsigned bytes.
    pub unsigned_bytes_hash: Hash,

    /// Optional signature (populated after signing).
    #[serde(with = "serde_opt_signature")]
    pub signature: Option<Signature>,

    /// Optional signer identity (populated after signing).
    pub signer_identity: Option<SignerIdentity>,
}

/// Serde helper for optional fixed-size byte arrays.
mod serde_opt_signature {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(opt: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&bytes.as_slice()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(vec) => {
                let arr: [u8; 64] = vec.try_into().map_err(|v: Vec<u8>| {
                    serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
                })?;
                Ok(Some(arr))
            },
            None => Ok(None),
        }
    }
}

impl CompactionReceipt {
    /// Creates a new compaction receipt builder.
    #[must_use]
    pub fn builder() -> CompactionReceiptBuilder {
        CompactionReceiptBuilder::new()
    }

    /// Returns the compacted hashes.
    #[must_use]
    pub fn compacted_hashes(&self) -> &[Hash] {
        &self.compacted_hashes
    }

    /// Returns the number of compacted artifacts.
    #[must_use]
    pub fn compacted_count(&self) -> usize {
        self.compacted_hashes.len()
    }

    /// Returns `true` if this receipt is signed.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Validates the receipt structure.
    ///
    /// # Errors
    ///
    /// Returns an error if any field exceeds its limits or the
    /// `unsigned_bytes_hash` doesn't match the computed digest.
    pub fn validate(&self) -> Result<(), CompactionReceiptError> {
        // Check compacted hashes count
        if self.compacted_hashes.len() > MAX_COMPACTED_HASHES {
            return Err(CompactionReceiptError::TooManyCompactedHashes {
                count: self.compacted_hashes.len(),
                max: MAX_COMPACTED_HASHES,
            });
        }

        // Timestamp should be non-zero
        if self.compacted_at == 0 {
            return Err(CompactionReceiptError::InvalidTimestamp {
                reason: "timestamp cannot be zero",
            });
        }

        // Validate signer identity if present
        if let Some(ref identity) = self.signer_identity {
            if identity.identity.len() > MAX_SIGNER_IDENTITY_LEN {
                return Err(CompactionReceiptError::SignerIdentityTooLong {
                    len: identity.identity.len(),
                    max: MAX_SIGNER_IDENTITY_LEN,
                });
            }
        }

        // Verify unsigned_bytes_hash matches computed digest
        let computed_digest = self.digest();
        if self.unsigned_bytes_hash != computed_digest {
            return Err(CompactionReceiptError::HashMismatch {
                expected: computed_digest,
                actual: self.unsigned_bytes_hash,
            });
        }

        Ok(())
    }

    /// Returns the canonical bytes for signing.
    ///
    /// Per AD-VERIFY-001:
    /// - Fields are serialized in tag order
    /// - Compacted hashes are sorted by hash value
    /// - Signature and `unsigned_bytes_hash` are excluded
    /// - `signer_identity` IS included to cryptographically bind the signer
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Sort compacted hashes for determinism
        let mut sorted_hashes: Vec<_> = self.compacted_hashes.clone();
        sorted_hashes.sort_unstable();

        let proto = CompactionReceiptProto {
            episode_id: self.episode_id.as_str().to_string(),
            compacted_hashes: sorted_hashes.into_iter().map(|h| h.to_vec()).collect(),
            summary_hash: self.summary_hash.to_vec(),
            tombstone_list_hash: self.tombstone_list_hash.to_vec(),
            strategy: Some(self.strategy.value()),
            compacted_at: Some(self.compacted_at),
            compacted_count: Some(self.stats.compacted_count as u64),
            compacted_bytes: Some(self.stats.compacted_bytes),
            canonicalizer_id: self.canonicalizer_id.as_str().to_string(),
            canonicalizer_version: Some(self.canonicalizer_version),
            // signer_identity IS included for cryptographic binding
            signer_identity: self
                .signer_identity
                .as_ref()
                .map(SignerIdentity::canonical_bytes),
        };
        proto.encode_to_vec()
    }

    /// Computes the BLAKE3 digest of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Returns the bytes that should be signed.
    #[must_use]
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

/// Internal protobuf representation for `CompactionReceipt`.
#[derive(Clone, PartialEq, Message)]
struct CompactionReceiptProto {
    #[prost(string, tag = "1")]
    episode_id: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    compacted_hashes: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    summary_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    tombstone_list_hash: Vec<u8>,
    #[prost(uint32, optional, tag = "5")]
    strategy: Option<u32>,
    #[prost(uint64, optional, tag = "6")]
    compacted_at: Option<u64>,
    #[prost(uint64, optional, tag = "7")]
    compacted_count: Option<u64>,
    #[prost(uint64, optional, tag = "8")]
    compacted_bytes: Option<u64>,
    #[prost(string, tag = "9")]
    canonicalizer_id: String,
    #[prost(uint32, optional, tag = "10")]
    canonicalizer_version: Option<u32>,
    // Tag 11: signer_identity - INCLUDED for cryptographic binding
    #[prost(bytes = "vec", optional, tag = "11")]
    signer_identity: Option<Vec<u8>>,
}

// =============================================================================
// CompactionStats
// =============================================================================

/// Statistics about a compaction operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionStats {
    /// Number of artifacts compacted.
    pub compacted_count: usize,

    /// Total bytes of compacted artifacts.
    pub compacted_bytes: u64,

    /// Number of artifacts retained (not compacted).
    pub retained_count: usize,
}

impl CompactionStats {
    /// Creates new compaction statistics.
    #[must_use]
    pub const fn new(compacted_count: usize, compacted_bytes: u64, retained_count: usize) -> Self {
        Self {
            compacted_count,
            compacted_bytes,
            retained_count,
        }
    }
}

// =============================================================================
// CompactionReceiptBuilder
// =============================================================================

/// Builder for `CompactionReceipt`.
#[derive(Debug)]
pub struct CompactionReceiptBuilder {
    episode_id: Option<EpisodeId>,
    compacted_hashes: Vec<Hash>,
    summary_hash: Option<Hash>,
    tombstone_list_hash: Option<Hash>,
    strategy: CompactionStrategy,
    compacted_at: Option<u64>,
    stats: CompactionStats,
    canonicalizer_id: CanonicalizerId,
    canonicalizer_version: u32,
    signer_identity: Option<SignerIdentity>,
}

impl Default for CompactionReceiptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CompactionReceiptBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            episode_id: None,
            compacted_hashes: Vec::new(),
            summary_hash: None,
            tombstone_list_hash: None,
            strategy: CompactionStrategy::default(),
            compacted_at: None,
            stats: CompactionStats::default(),
            canonicalizer_id: CanonicalizerId::apm2_proto_v1(),
            canonicalizer_version: 1,
            signer_identity: None,
        }
    }

    /// Sets the episode ID.
    #[must_use]
    pub fn episode_id(mut self, id: EpisodeId) -> Self {
        self.episode_id = Some(id);
        self
    }

    /// Sets the compacted hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if the list exceeds `MAX_COMPACTED_HASHES`.
    pub fn compacted_hashes(mut self, hashes: Vec<Hash>) -> Result<Self, CompactionReceiptError> {
        if hashes.len() > MAX_COMPACTED_HASHES {
            return Err(CompactionReceiptError::TooManyCompactedHashes {
                count: hashes.len(),
                max: MAX_COMPACTED_HASHES,
            });
        }
        self.compacted_hashes = hashes;
        Ok(self)
    }

    /// Adds a compacted hash.
    ///
    /// # Errors
    ///
    /// Returns an error if adding would exceed `MAX_COMPACTED_HASHES`.
    pub fn add_compacted_hash(&mut self, hash: Hash) -> Result<&mut Self, CompactionReceiptError> {
        if self.compacted_hashes.len() >= MAX_COMPACTED_HASHES {
            return Err(CompactionReceiptError::TooManyCompactedHashes {
                count: self.compacted_hashes.len() + 1,
                max: MAX_COMPACTED_HASHES,
            });
        }
        self.compacted_hashes.push(hash);
        Ok(self)
    }

    /// Sets the summary hash.
    #[must_use]
    pub const fn summary_hash(mut self, hash: Hash) -> Self {
        self.summary_hash = Some(hash);
        self
    }

    /// Sets the tombstone list hash.
    #[must_use]
    pub const fn tombstone_list_hash(mut self, hash: Hash) -> Self {
        self.tombstone_list_hash = Some(hash);
        self
    }

    /// Sets the compaction strategy.
    #[must_use]
    pub const fn strategy(mut self, strategy: CompactionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the compaction timestamp.
    #[must_use]
    pub const fn compacted_at(mut self, timestamp_ns: u64) -> Self {
        self.compacted_at = Some(timestamp_ns);
        self
    }

    /// Sets the compaction statistics.
    #[must_use]
    pub const fn stats(mut self, stats: CompactionStats) -> Self {
        self.stats = stats;
        self
    }

    /// Sets the canonicalizer ID.
    #[must_use]
    pub fn canonicalizer_id(mut self, id: CanonicalizerId) -> Self {
        self.canonicalizer_id = id;
        self
    }

    /// Sets the canonicalizer version.
    #[must_use]
    pub const fn canonicalizer_version(mut self, version: u32) -> Self {
        self.canonicalizer_version = version;
        self
    }

    /// Sets the signer identity.
    #[must_use]
    pub fn signer_identity(mut self, identity: SignerIdentity) -> Self {
        self.signer_identity = Some(identity);
        self
    }

    /// Builds the compaction receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing.
    pub fn build(self) -> Result<CompactionReceipt, CompactionReceiptError> {
        let episode_id =
            self.episode_id
                .ok_or_else(|| CompactionReceiptError::InvalidEpisodeId {
                    reason: "episode_id is required".to_string(),
                })?;

        let summary_hash =
            self.summary_hash
                .ok_or_else(|| CompactionReceiptError::InvalidEpisodeId {
                    reason: "summary_hash is required".to_string(),
                })?;

        let tombstone_list_hash =
            self.tombstone_list_hash
                .ok_or_else(|| CompactionReceiptError::InvalidEpisodeId {
                    reason: "tombstone_list_hash is required".to_string(),
                })?;

        let compacted_at = self
            .compacted_at
            .ok_or(CompactionReceiptError::InvalidTimestamp {
                reason: "compacted_at is required",
            })?;

        // Create receipt without unsigned_bytes_hash first
        let mut receipt = CompactionReceipt {
            episode_id,
            compacted_hashes: self.compacted_hashes,
            summary_hash,
            tombstone_list_hash,
            strategy: self.strategy,
            compacted_at,
            stats: self.stats,
            canonicalizer_id: self.canonicalizer_id,
            canonicalizer_version: self.canonicalizer_version,
            unsigned_bytes_hash: [0; 32], // Placeholder
            signature: None,
            signer_identity: self.signer_identity,
        };

        // Compute and set the unsigned_bytes_hash
        receipt.unsigned_bytes_hash = receipt.digest();

        Ok(receipt)
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

    fn test_receipt() -> CompactionReceipt {
        CompactionReceiptBuilder::new()
            .episode_id(test_episode_id())
            .compacted_hashes(vec![test_hash(0xaa), test_hash(0xbb)])
            .unwrap()
            .summary_hash(test_hash(0xcc))
            .tombstone_list_hash(test_hash(0xdd))
            .strategy(CompactionStrategy::DigestOnly)
            .compacted_at(1_704_067_200_000_000_000)
            .stats(CompactionStats::new(2, 2048, 0))
            .build()
            .unwrap()
    }

    // =========================================================================
    // CompactionReceipt tests (UT-00172-03: Compaction receipt)
    // =========================================================================

    #[test]
    fn test_compaction_receipt_builder() {
        let receipt = test_receipt();

        assert_eq!(receipt.episode_id, test_episode_id());
        assert_eq!(receipt.compacted_count(), 2);
        assert_eq!(receipt.summary_hash, test_hash(0xcc));
        assert_eq!(receipt.tombstone_list_hash, test_hash(0xdd));
        assert_eq!(receipt.strategy, CompactionStrategy::DigestOnly);
        assert!(!receipt.is_signed());
    }

    #[test]
    fn test_compaction_receipt_validation() {
        let receipt = test_receipt();
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn test_compaction_receipt_validation_too_many_hashes() {
        #[allow(clippy::cast_possible_truncation)]
        let hashes: Vec<Hash> = (0..=MAX_COMPACTED_HASHES)
            .map(|i| test_hash((i % 256) as u8))
            .collect();

        let result = CompactionReceiptBuilder::new()
            .episode_id(test_episode_id())
            .compacted_hashes(hashes);

        assert!(matches!(
            result,
            Err(CompactionReceiptError::TooManyCompactedHashes { .. })
        ));
    }

    #[test]
    fn test_compaction_receipt_canonical_bytes_determinism() {
        let receipt1 = test_receipt();
        let receipt2 = test_receipt();

        assert_eq!(
            receipt1.canonical_bytes(),
            receipt2.canonical_bytes(),
            "identical receipts must produce identical canonical bytes"
        );
        assert_eq!(
            receipt1.digest(),
            receipt2.digest(),
            "identical receipts must produce identical digests"
        );
    }

    #[test]
    fn test_compaction_receipt_canonical_bytes_sorts_hashes() {
        let receipt1 = CompactionReceiptBuilder::new()
            .episode_id(test_episode_id())
            .compacted_hashes(vec![test_hash(0xff), test_hash(0x00)])
            .unwrap()
            .summary_hash(test_hash(0xcc))
            .tombstone_list_hash(test_hash(0xdd))
            .compacted_at(1_000_000_000)
            .build()
            .unwrap();

        let receipt2 = CompactionReceiptBuilder::new()
            .episode_id(test_episode_id())
            .compacted_hashes(vec![test_hash(0x00), test_hash(0xff)])
            .unwrap()
            .summary_hash(test_hash(0xcc))
            .tombstone_list_hash(test_hash(0xdd))
            .compacted_at(1_000_000_000)
            .build()
            .unwrap();

        assert_eq!(
            receipt1.canonical_bytes(),
            receipt2.canonical_bytes(),
            "hash order should not affect canonical bytes"
        );
    }

    #[test]
    fn test_compaction_receipt_excludes_signature_includes_signer() {
        let receipt_unsigned = test_receipt();

        // Receipt with signature only
        let mut receipt_with_sig = test_receipt();
        receipt_with_sig.signature = Some([0xab; 64]);

        assert_eq!(
            receipt_unsigned.canonical_bytes(),
            receipt_with_sig.canonical_bytes(),
            "signature must be excluded from canonical bytes"
        );

        // Receipt with signer identity
        let receipt_with_signer = CompactionReceiptBuilder::new()
            .episode_id(test_episode_id())
            .compacted_hashes(vec![test_hash(0xaa), test_hash(0xbb)])
            .unwrap()
            .summary_hash(test_hash(0xcc))
            .tombstone_list_hash(test_hash(0xdd))
            .compacted_at(1_704_067_200_000_000_000)
            .stats(CompactionStats::new(2, 2048, 0))
            .signer_identity(SignerIdentity {
                public_key: [0x12; 32],
                identity: "test-signer".to_string(),
            })
            .build()
            .unwrap();

        assert_ne!(
            receipt_unsigned.canonical_bytes(),
            receipt_with_signer.canonical_bytes(),
            "signer_identity must be INCLUDED in canonical bytes"
        );
    }

    #[test]
    fn test_compaction_receipt_serde_roundtrip() {
        let receipt = test_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: CompactionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    /// SECURITY: Verify unknown fields are rejected.
    #[test]
    fn test_compaction_receipt_rejects_unknown_fields() {
        let json = r#"{
            "episode_id": "ep-001",
            "compacted_hashes": [],
            "summary_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "tombstone_list_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "strategy": "digest_only",
            "compacted_at": 1000000000,
            "stats": {"compacted_count": 0, "compacted_bytes": 0, "retained_count": 0},
            "canonicalizer_id": "apm2-proto-v1",
            "canonicalizer_version": 1,
            "unsigned_bytes_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "signature": null,
            "signer_identity": null,
            "malicious": "attack"
        }"#;

        let result: Result<CompactionReceipt, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn test_compaction_receipt_validation_zero_timestamp() {
        let mut receipt = test_receipt();
        receipt.compacted_at = 0;
        // Need to recompute hash after modification
        receipt.unsigned_bytes_hash = receipt.digest();

        assert!(matches!(
            receipt.validate(),
            Err(CompactionReceiptError::InvalidTimestamp { .. })
        ));
    }

    #[test]
    fn test_compaction_receipt_validation_hash_mismatch() {
        let mut receipt = test_receipt();
        receipt.unsigned_bytes_hash = [0xff; 32]; // Corrupt the hash

        assert!(matches!(
            receipt.validate(),
            Err(CompactionReceiptError::HashMismatch { .. })
        ));
    }

    // =========================================================================
    // CompactionStats tests
    // =========================================================================

    #[test]
    fn test_compaction_stats() {
        let stats = CompactionStats::new(10, 1024, 5);
        assert_eq!(stats.compacted_count, 10);
        assert_eq!(stats.compacted_bytes, 1024);
        assert_eq!(stats.retained_count, 5);
    }

    #[test]
    fn test_compaction_stats_serde_roundtrip() {
        let stats = CompactionStats::new(10, 1024, 5);
        let json = serde_json::to_string(&stats).unwrap();
        let restored: CompactionStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, restored);
    }
}
