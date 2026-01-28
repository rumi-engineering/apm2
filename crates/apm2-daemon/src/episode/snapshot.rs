//! Pinned snapshot types for episode reproducibility.
//!
//! This module defines the `PinnedSnapshot` struct that captures digests
//! of reproducibility-relevant inputs at episode creation time. Per
//! AD-EPISODE-001, these digests enable deterministic replay and audit.
//!
//! # Purpose
//!
//! The pinned snapshot captures the environment state at episode start:
//! - Repository content hash (git tree hash or equivalent)
//! - Lockfile hash (Cargo.lock, package-lock.json, etc.)
//! - Policy document hash
//! - Toolchain version hash
//! - Model profile hash (inference configuration)
//!
//! # Canonicalization
//!
//! Per AD-VERIFY-001, all hash fields are serialized in tag order for
//! deterministic encoding. Empty optional hashes are explicitly serialized
//! as empty bytes (not omitted).
//!
//! # Contract References
//!
//! - AD-EPISODE-001: Pinned snapshot in episode envelope
//! - AD-VERIFY-001: Deterministic serialization rules

use prost::Message;
use serde::{Deserialize, Serialize};

/// Size of a BLAKE3 hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Internal protobuf representation for encoding/decoding.
#[allow(clippy::struct_field_names)]
#[derive(Clone, PartialEq, Message)]
struct PinnedSnapshotProto {
    #[prost(bytes = "vec", tag = "1")]
    repo_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    lockfile_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    policy_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    toolchain_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    model_profile_hash: Vec<u8>,
}

/// Pinned snapshot of reproducibility-relevant inputs.
///
/// This struct captures digests of the environment at episode creation
/// time, enabling deterministic replay and audit per AD-EPISODE-001.
///
/// # Optional Fields
///
/// All fields are optional to support incremental adoption:
/// - A missing hash means that input was not pinned for this episode
/// - An empty hash (`[0u8; 32]`) means the input was explicitly absent
///
/// # Invariants
///
/// - [INV-SNAP-001] Hash fields are either empty or exactly 32 bytes.
/// - [INV-SNAP-002] Once set, snapshot fields are immutable.
/// - [INV-SNAP-003] Serialization order follows protobuf tag numbers.
///
/// # Example
///
/// ```rust
/// use apm2_daemon::episode::PinnedSnapshot;
///
/// let snapshot = PinnedSnapshot::builder()
///     .repo_hash([0xab; 32])
///     .lockfile_hash([0xcd; 32])
///     .policy_hash([0xef; 32])
///     .build();
///
/// assert!(snapshot.has_repo_hash());
/// assert!(snapshot.has_lockfile_hash());
/// assert!(snapshot.has_policy_hash());
/// assert!(!snapshot.has_toolchain_hash());
/// ```
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PinnedSnapshot {
    /// Hash of the repository state (e.g., git tree hash).
    pub(crate) repo_hash: Vec<u8>,

    /// Hash of dependency lockfiles.
    pub(crate) lockfile_hash: Vec<u8>,

    /// Hash of the policy document governing this episode.
    pub(crate) policy_hash: Vec<u8>,

    /// Hash of the toolchain configuration.
    pub(crate) toolchain_hash: Vec<u8>,

    /// Hash of the model/inference profile.
    pub(crate) model_profile_hash: Vec<u8>,
}

impl PinnedSnapshot {
    /// Creates a new snapshot builder.
    #[must_use]
    pub const fn builder() -> PinnedSnapshotBuilder {
        PinnedSnapshotBuilder::new()
    }

    /// Creates an empty snapshot with no pinned values.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            repo_hash: Vec::new(),
            lockfile_hash: Vec::new(),
            policy_hash: Vec::new(),
            toolchain_hash: Vec::new(),
            model_profile_hash: Vec::new(),
        }
    }

    /// Returns the repository hash, if present.
    #[must_use]
    pub fn repo_hash(&self) -> Option<&[u8]> {
        if self.repo_hash.is_empty() {
            None
        } else {
            Some(&self.repo_hash)
        }
    }

    /// Returns the lockfile hash, if present.
    #[must_use]
    pub fn lockfile_hash(&self) -> Option<&[u8]> {
        if self.lockfile_hash.is_empty() {
            None
        } else {
            Some(&self.lockfile_hash)
        }
    }

    /// Returns the policy hash, if present.
    #[must_use]
    pub fn policy_hash(&self) -> Option<&[u8]> {
        if self.policy_hash.is_empty() {
            None
        } else {
            Some(&self.policy_hash)
        }
    }

    /// Returns the toolchain hash, if present.
    #[must_use]
    pub fn toolchain_hash(&self) -> Option<&[u8]> {
        if self.toolchain_hash.is_empty() {
            None
        } else {
            Some(&self.toolchain_hash)
        }
    }

    /// Returns the model profile hash, if present.
    #[must_use]
    pub fn model_profile_hash(&self) -> Option<&[u8]> {
        if self.model_profile_hash.is_empty() {
            None
        } else {
            Some(&self.model_profile_hash)
        }
    }

    /// Returns `true` if a repository hash is pinned.
    #[must_use]
    pub fn has_repo_hash(&self) -> bool {
        !self.repo_hash.is_empty()
    }

    /// Returns `true` if a lockfile hash is pinned.
    #[must_use]
    pub fn has_lockfile_hash(&self) -> bool {
        !self.lockfile_hash.is_empty()
    }

    /// Returns `true` if a policy hash is pinned.
    #[must_use]
    pub fn has_policy_hash(&self) -> bool {
        !self.policy_hash.is_empty()
    }

    /// Returns `true` if a toolchain hash is pinned.
    #[must_use]
    pub fn has_toolchain_hash(&self) -> bool {
        !self.toolchain_hash.is_empty()
    }

    /// Returns `true` if a model profile hash is pinned.
    #[must_use]
    pub fn has_model_profile_hash(&self) -> bool {
        !self.model_profile_hash.is_empty()
    }

    /// Returns `true` if no hashes are pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.repo_hash.is_empty()
            && self.lockfile_hash.is_empty()
            && self.policy_hash.is_empty()
            && self.toolchain_hash.is_empty()
            && self.model_profile_hash.is_empty()
    }

    /// Returns the count of pinned hashes.
    #[must_use]
    pub fn pinned_count(&self) -> usize {
        let mut count = 0;
        if self.has_repo_hash() {
            count += 1;
        }
        if self.has_lockfile_hash() {
            count += 1;
        }
        if self.has_policy_hash() {
            count += 1;
        }
        if self.has_toolchain_hash() {
            count += 1;
        }
        if self.has_model_profile_hash() {
            count += 1;
        }
        count
    }

    /// Returns the canonical bytes for this snapshot.
    ///
    /// Per AD-VERIFY-001, this produces deterministic bytes suitable
    /// for hashing and signing.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = PinnedSnapshotProto {
            repo_hash: self.repo_hash.clone(),
            lockfile_hash: self.lockfile_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            toolchain_hash: self.toolchain_hash.clone(),
            model_profile_hash: self.model_profile_hash.clone(),
        };
        proto.encode_to_vec()
    }

    /// Decodes a snapshot from protobuf bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn decode(buf: &[u8]) -> Result<Self, prost::DecodeError> {
        let proto = PinnedSnapshotProto::decode(buf)?;
        Ok(Self {
            repo_hash: proto.repo_hash,
            lockfile_hash: proto.lockfile_hash,
            policy_hash: proto.policy_hash,
            toolchain_hash: proto.toolchain_hash,
            model_profile_hash: proto.model_profile_hash,
        })
    }

    /// Computes the BLAKE3 digest of this snapshot.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

impl Default for PinnedSnapshot {
    fn default() -> Self {
        Self::empty()
    }
}

/// Builder for [`PinnedSnapshot`].
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Default)]
pub struct PinnedSnapshotBuilder {
    repo_hash: Vec<u8>,
    lockfile_hash: Vec<u8>,
    policy_hash: Vec<u8>,
    toolchain_hash: Vec<u8>,
    model_profile_hash: Vec<u8>,
}

impl PinnedSnapshotBuilder {
    /// Creates a new builder with no pinned values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            repo_hash: Vec::new(),
            lockfile_hash: Vec::new(),
            policy_hash: Vec::new(),
            toolchain_hash: Vec::new(),
            model_profile_hash: Vec::new(),
        }
    }

    /// Sets the repository hash.
    #[must_use]
    pub fn repo_hash(mut self, hash: [u8; HASH_SIZE]) -> Self {
        self.repo_hash = hash.to_vec();
        self
    }

    /// Sets the repository hash from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn repo_hash_from_slice(
        mut self,
        hash: &[u8],
    ) -> Result<Self, crate::episode::EnvelopeError> {
        if hash.len() != HASH_SIZE {
            return Err(crate::episode::EnvelopeError::InvalidHashSize {
                field: "repo_hash",
                expected: HASH_SIZE,
                actual: hash.len(),
            });
        }
        self.repo_hash = hash.to_vec();
        Ok(self)
    }

    /// Sets the lockfile hash.
    #[must_use]
    pub fn lockfile_hash(mut self, hash: [u8; HASH_SIZE]) -> Self {
        self.lockfile_hash = hash.to_vec();
        self
    }

    /// Sets the lockfile hash from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn lockfile_hash_from_slice(
        mut self,
        hash: &[u8],
    ) -> Result<Self, crate::episode::EnvelopeError> {
        if hash.len() != HASH_SIZE {
            return Err(crate::episode::EnvelopeError::InvalidHashSize {
                field: "lockfile_hash",
                expected: HASH_SIZE,
                actual: hash.len(),
            });
        }
        self.lockfile_hash = hash.to_vec();
        Ok(self)
    }

    /// Sets the policy hash.
    #[must_use]
    pub fn policy_hash(mut self, hash: [u8; HASH_SIZE]) -> Self {
        self.policy_hash = hash.to_vec();
        self
    }

    /// Sets the policy hash from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn policy_hash_from_slice(
        mut self,
        hash: &[u8],
    ) -> Result<Self, crate::episode::EnvelopeError> {
        if hash.len() != HASH_SIZE {
            return Err(crate::episode::EnvelopeError::InvalidHashSize {
                field: "policy_hash",
                expected: HASH_SIZE,
                actual: hash.len(),
            });
        }
        self.policy_hash = hash.to_vec();
        Ok(self)
    }

    /// Sets the toolchain hash.
    #[must_use]
    pub fn toolchain_hash(mut self, hash: [u8; HASH_SIZE]) -> Self {
        self.toolchain_hash = hash.to_vec();
        self
    }

    /// Sets the toolchain hash from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn toolchain_hash_from_slice(
        mut self,
        hash: &[u8],
    ) -> Result<Self, crate::episode::EnvelopeError> {
        if hash.len() != HASH_SIZE {
            return Err(crate::episode::EnvelopeError::InvalidHashSize {
                field: "toolchain_hash",
                expected: HASH_SIZE,
                actual: hash.len(),
            });
        }
        self.toolchain_hash = hash.to_vec();
        Ok(self)
    }

    /// Sets the model profile hash.
    #[must_use]
    pub fn model_profile_hash(mut self, hash: [u8; HASH_SIZE]) -> Self {
        self.model_profile_hash = hash.to_vec();
        self
    }

    /// Sets the model profile hash from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn model_profile_hash_from_slice(
        mut self,
        hash: &[u8],
    ) -> Result<Self, crate::episode::EnvelopeError> {
        if hash.len() != HASH_SIZE {
            return Err(crate::episode::EnvelopeError::InvalidHashSize {
                field: "model_profile_hash",
                expected: HASH_SIZE,
                actual: hash.len(),
            });
        }
        self.model_profile_hash = hash.to_vec();
        Ok(self)
    }

    /// Builds the snapshot.
    #[must_use]
    pub fn build(self) -> PinnedSnapshot {
        PinnedSnapshot {
            repo_hash: self.repo_hash,
            lockfile_hash: self.lockfile_hash,
            policy_hash: self.policy_hash,
            toolchain_hash: self.toolchain_hash,
            model_profile_hash: self.model_profile_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_empty() {
        let snapshot = PinnedSnapshot::empty();
        assert!(snapshot.is_empty());
        assert_eq!(snapshot.pinned_count(), 0);
        assert!(!snapshot.has_repo_hash());
        assert!(!snapshot.has_lockfile_hash());
        assert!(!snapshot.has_policy_hash());
        assert!(!snapshot.has_toolchain_hash());
        assert!(!snapshot.has_model_profile_hash());
    }

    #[test]
    fn test_snapshot_builder() {
        let snapshot = PinnedSnapshot::builder()
            .repo_hash([0xab; 32])
            .lockfile_hash([0xcd; 32])
            .policy_hash([0xef; 32])
            .build();

        assert!(!snapshot.is_empty());
        assert_eq!(snapshot.pinned_count(), 3);
        assert!(snapshot.has_repo_hash());
        assert!(snapshot.has_lockfile_hash());
        assert!(snapshot.has_policy_hash());
        assert!(!snapshot.has_toolchain_hash());
        assert!(!snapshot.has_model_profile_hash());

        assert_eq!(snapshot.repo_hash(), Some([0xab; 32].as_slice()));
        assert_eq!(snapshot.lockfile_hash(), Some([0xcd; 32].as_slice()));
        assert_eq!(snapshot.policy_hash(), Some([0xef; 32].as_slice()));
        assert!(snapshot.toolchain_hash().is_none());
        assert!(snapshot.model_profile_hash().is_none());
    }

    #[test]
    fn test_snapshot_all_hashes() {
        let snapshot = PinnedSnapshot::builder()
            .repo_hash([0x11; 32])
            .lockfile_hash([0x22; 32])
            .policy_hash([0x33; 32])
            .toolchain_hash([0x44; 32])
            .model_profile_hash([0x55; 32])
            .build();

        assert_eq!(snapshot.pinned_count(), 5);
        assert_eq!(snapshot.repo_hash(), Some([0x11; 32].as_slice()));
        assert_eq!(snapshot.lockfile_hash(), Some([0x22; 32].as_slice()));
        assert_eq!(snapshot.policy_hash(), Some([0x33; 32].as_slice()));
        assert_eq!(snapshot.toolchain_hash(), Some([0x44; 32].as_slice()));
        assert_eq!(snapshot.model_profile_hash(), Some([0x55; 32].as_slice()));
    }

    #[test]
    fn test_snapshot_from_slice() {
        let hash = [0xab; 32];
        let builder = PinnedSnapshotBuilder::new()
            .repo_hash_from_slice(&hash)
            .expect("valid hash");

        let snapshot = builder.build();
        assert!(snapshot.has_repo_hash());
    }

    #[test]
    fn test_snapshot_from_slice_invalid_length() {
        let short_hash = [0xab; 16];
        let result = PinnedSnapshotBuilder::new().repo_hash_from_slice(&short_hash);
        assert!(result.is_err());

        let long_hash = [0xab; 64];
        let result = PinnedSnapshotBuilder::new().repo_hash_from_slice(&long_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_canonical_bytes_deterministic() {
        let snapshot = PinnedSnapshot::builder()
            .repo_hash([0xab; 32])
            .policy_hash([0xcd; 32])
            .build();

        let bytes1 = snapshot.canonical_bytes();
        let bytes2 = snapshot.canonical_bytes();
        let bytes3 = snapshot.canonical_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }

    #[test]
    fn test_snapshot_roundtrip() {
        let original = PinnedSnapshot::builder()
            .repo_hash([0x11; 32])
            .lockfile_hash([0x22; 32])
            .policy_hash([0x33; 32])
            .toolchain_hash([0x44; 32])
            .model_profile_hash([0x55; 32])
            .build();

        let bytes = original.canonical_bytes();
        let decoded = PinnedSnapshot::decode(&bytes).expect("decode failed");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_snapshot_digest_stable() {
        let snapshot = PinnedSnapshot::builder()
            .repo_hash([0xab; 32])
            .policy_hash([0xcd; 32])
            .build();

        let digest1 = snapshot.digest();
        let digest2 = snapshot.digest();

        assert_eq!(digest1, digest2);
        assert_eq!(digest1.len(), 32);
    }

    #[test]
    fn test_snapshot_different_values_different_digests() {
        let snapshot1 = PinnedSnapshot::builder().repo_hash([0xab; 32]).build();
        let snapshot2 = PinnedSnapshot::builder().repo_hash([0xac; 32]).build();

        assert_ne!(snapshot1.digest(), snapshot2.digest());
    }

    #[test]
    fn test_snapshot_serialize_deserialize() {
        let snapshot = PinnedSnapshot::builder()
            .repo_hash([0xab; 32])
            .policy_hash([0xcd; 32])
            .build();

        let json = serde_json::to_string(&snapshot).expect("serialize failed");
        let decoded: PinnedSnapshot = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(snapshot, decoded);
    }

    #[test]
    fn test_snapshot_default() {
        let snapshot = PinnedSnapshot::default();
        assert!(snapshot.is_empty());
    }
}
