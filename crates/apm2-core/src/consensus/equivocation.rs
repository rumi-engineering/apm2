// AGENT-AUTHORED
//! Byzantine equivocation detection for the consensus layer.
//!
//! This module implements detection of Byzantine behavior in the form of
//! equivocation (double-signing or conflicting proposals). When a validator
//! sends conflicting messages for the same slot, cryptographic evidence
//! is generated that can be verified by any node.
//!
//! # Equivocation Types
//!
//! - **Double-signing**: Same sequence ID with different content/hash
//! - **Conflicting proposals**: Multiple proposals for the same slot from the
//!   same leader
//!
//! # Security Properties
//!
//! - Evidence includes both conflicting proposals with valid signatures
//! - Any node can verify the evidence independently
//! - Byzantine node identity is cryptographically proven
//! - Bounded collection prevents memory exhaustion (CTR-1303)
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00196: Byzantine Equivocation Detection

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::bft::ValidatorId;
use super::replication::ReplicationProposal;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of cached proposals for equivocation detection.
///
/// Bounded to prevent denial-of-service via memory exhaustion (CTR-1303).
/// This provides a window of recent proposals for detecting equivocation.
pub const MAX_CACHED_PROPOSALS: usize = 1024;

/// Maximum age of cached proposals in seconds.
///
/// Proposals older than this are evicted to prevent stale data accumulation.
pub const MAX_PROPOSAL_AGE_SECS: u64 = 3600; // 1 hour

/// Domain separation prefix for equivocation evidence signatures.
pub const DOMAIN_PREFIX_EQUIVOCATION: &[u8] = b"APM2-EQUIVOCATION-EVIDENCE-V1:";

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during equivocation detection.
#[derive(Debug, Error)]
pub enum EquivocationError {
    /// Invalid signature on proposal.
    #[error("invalid signature on proposal from {validator_id}")]
    InvalidSignature {
        /// The validator whose signature was invalid.
        validator_id: String,
    },

    /// Unknown validator.
    #[error("unknown validator: {0}")]
    UnknownValidator(String),

    /// Evidence verification failed.
    #[error("evidence verification failed: {0}")]
    VerificationFailed(String),

    /// Cache is at capacity.
    #[error("proposal cache at capacity: {size} >= {max}")]
    CacheAtCapacity {
        /// Current cache size.
        size: usize,
        /// Maximum cache size.
        max: usize,
    },
}

// =============================================================================
// Types
// =============================================================================

/// Type of equivocation detected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivocationType {
    /// Same sequence ID with different content/hash.
    ///
    /// This is the primary equivocation type: a validator signed two different
    /// proposals for the same slot (namespace, epoch, `sequence_id`).
    DoubleSigning,
    /// Multiple proposals for the same slot from the same leader.
    ///
    /// Reserved for future use. Currently, all detected equivocations are
    /// classified as `DoubleSigning` since evidence is only created when
    /// proposals have different hashes.
    ConflictingProposal,
}

impl EquivocationType {
    /// Returns a human-readable description of the equivocation type.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::DoubleSigning => "Double-signing: same sequence ID with different hash",
            Self::ConflictingProposal => "Conflicting proposals for the same slot",
        }
    }
}

/// Cryptographic evidence of Byzantine equivocation behavior.
///
/// This structure contains all the information needed for any node to
/// independently verify that a validator engaged in Byzantine behavior.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// The type of equivocation detected.
    pub equivocation_type: EquivocationType,

    /// The Byzantine validator's ID (BLAKE3 hash of their public key).
    pub byzantine_validator_id: ValidatorId,

    /// The first conflicting proposal (with signature).
    pub proposal_a: ConflictingProposal,

    /// The second conflicting proposal (with signature).
    pub proposal_b: ConflictingProposal,

    /// Timestamp when the equivocation was detected (Unix epoch nanoseconds).
    pub detected_at_ns: u64,

    /// The namespace where the equivocation occurred.
    pub namespace: String,

    /// The epoch in which the equivocation occurred.
    pub epoch: u64,

    /// The sequence ID where the conflict was detected.
    pub sequence_id: u64,
}

/// A conflicting proposal with its signature.
///
/// This is a subset of `ReplicationProposal` containing the fields needed
/// to prove equivocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictingProposal {
    /// The epoch of this proposal.
    pub epoch: u64,

    /// Sequence ID assigned by the leader.
    pub sequence_id: u64,

    /// The leader's validator ID.
    pub leader_id: ValidatorId,

    /// Namespace for this event.
    pub namespace: String,

    /// BLAKE3 hash of the event data.
    #[serde(with = "base64_arr_32")]
    pub event_hash: [u8; 32],

    /// Ed25519 signature over the proposal.
    #[serde(with = "base64_arr_64")]
    pub signature: [u8; 64],
}

impl From<&ReplicationProposal> for ConflictingProposal {
    fn from(proposal: &ReplicationProposal) -> Self {
        Self {
            epoch: proposal.epoch,
            sequence_id: proposal.sequence_id,
            leader_id: proposal.leader_id,
            namespace: proposal.namespace.clone(),
            event_hash: proposal.event_hash,
            signature: proposal.signature,
        }
    }
}

impl EquivocationEvidence {
    /// Creates new equivocation evidence from two conflicting proposals.
    ///
    /// # Arguments
    ///
    /// * `proposal_a` - The first proposal.
    /// * `proposal_b` - The second proposal (must conflict with first).
    ///
    /// # Panics
    ///
    /// This function does not panic but callers should ensure that both
    /// proposals are indeed conflicting (same `sequence_id`, different hash).
    #[must_use]
    pub fn new(proposal_a: &ReplicationProposal, proposal_b: &ReplicationProposal) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        // Equivocation evidence should only be created when proposals have different
        // hashes. If hashes are equal, the proposals are identical (not equivocation).
        // The check_proposal method already filters out duplicates before calling
        // new().
        debug_assert_ne!(
            proposal_a.event_hash, proposal_b.event_hash,
            "EquivocationEvidence::new called with identical proposals (same hash)"
        );

        // Since we only create evidence when hashes differ, this is always
        // double-signing: the validator signed two different values for the
        // same sequence ID.
        let equivocation_type = EquivocationType::DoubleSigning;

        // Saturating conversion from u128 to u64 - timestamps far in the future
        // are capped to u64::MAX, which is acceptable for evidence purposes
        #[allow(clippy::cast_possible_truncation)]
        let detected_at_ns = if now > u128::from(u64::MAX) {
            u64::MAX
        } else {
            now as u64
        };

        Self {
            equivocation_type,
            byzantine_validator_id: proposal_a.leader_id,
            proposal_a: ConflictingProposal::from(proposal_a),
            proposal_b: ConflictingProposal::from(proposal_b),
            detected_at_ns,
            namespace: proposal_a.namespace.clone(),
            epoch: proposal_a.epoch,
            sequence_id: proposal_a.sequence_id,
        }
    }

    /// Verifies that this evidence is valid.
    ///
    /// This checks that:
    /// 1. Both proposals are for the same sequence ID
    /// 2. Both proposals are from the same leader
    /// 3. The proposals actually conflict (different hashes)
    /// 4. Both signatures are valid
    ///
    /// # Arguments
    ///
    /// * `validator_key` - The public key of the Byzantine validator.
    ///
    /// # Errors
    ///
    /// Returns an error if the evidence is invalid.
    pub fn verify(&self, validator_key: &VerifyingKey) -> Result<(), EquivocationError> {
        // Verify the provided key matches the Byzantine validator ID
        let key_hash: [u8; 32] = blake3::hash(validator_key.as_bytes()).into();
        if key_hash != self.byzantine_validator_id {
            return Err(EquivocationError::VerificationFailed(
                "provided key does not match Byzantine validator ID".to_string(),
            ));
        }

        // Verify proposals are for the same sequence ID
        if self.proposal_a.sequence_id != self.proposal_b.sequence_id {
            return Err(EquivocationError::VerificationFailed(
                "proposals have different sequence IDs".to_string(),
            ));
        }

        // Verify proposals are from the same leader
        if self.proposal_a.leader_id != self.proposal_b.leader_id {
            return Err(EquivocationError::VerificationFailed(
                "proposals are from different leaders".to_string(),
            ));
        }

        // Verify proposals actually conflict (different hashes)
        if self.proposal_a.event_hash == self.proposal_b.event_hash {
            return Err(EquivocationError::VerificationFailed(
                "proposals have identical hashes (no conflict)".to_string(),
            ));
        }

        // Verify the Byzantine validator ID matches the leader ID
        if self.byzantine_validator_id != self.proposal_a.leader_id {
            return Err(EquivocationError::VerificationFailed(
                "Byzantine validator ID does not match leader ID".to_string(),
            ));
        }

        // Verify both signatures
        Self::verify_proposal_signature(&self.proposal_a, validator_key)?;
        Self::verify_proposal_signature(&self.proposal_b, validator_key)?;

        Ok(())
    }

    /// Verifies the signature on a conflicting proposal.
    fn verify_proposal_signature(
        proposal: &ConflictingProposal,
        validator_key: &VerifyingKey,
    ) -> Result<(), EquivocationError> {
        // Reconstruct the signing message using the same format as ReplicationProposal
        let ns_bytes = proposal.namespace.as_bytes();
        let ns_len =
            u32::try_from(ns_bytes.len()).map_err(|_| EquivocationError::InvalidSignature {
                validator_id: hex::encode(proposal.leader_id),
            })?;

        let mut msg = Vec::with_capacity(
            super::replication::DOMAIN_PREFIX_PROPOSAL.len() + 4 + ns_bytes.len() + 32 + 8 + 8 + 32,
        );
        msg.extend_from_slice(super::replication::DOMAIN_PREFIX_PROPOSAL);
        msg.extend_from_slice(&ns_len.to_le_bytes());
        msg.extend_from_slice(ns_bytes);
        msg.extend_from_slice(&proposal.leader_id);
        msg.extend_from_slice(&proposal.epoch.to_le_bytes());
        msg.extend_from_slice(&proposal.sequence_id.to_le_bytes());
        msg.extend_from_slice(&proposal.event_hash);

        let signature = ed25519_dalek::Signature::from_bytes(&proposal.signature);

        validator_key.verify_strict(&msg, &signature).map_err(|_| {
            EquivocationError::InvalidSignature {
                validator_id: hex::encode(proposal.leader_id),
            }
        })
    }

    /// Returns a hex-encoded string of the Byzantine validator's ID.
    #[must_use]
    pub fn byzantine_validator_id_hex(&self) -> String {
        hex::encode(self.byzantine_validator_id)
    }
}

// =============================================================================
// Proposal Cache
// =============================================================================

/// Key for caching proposals by (namespace, epoch, `sequence_id`, `leader_id`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ProposalCacheKey {
    namespace: String,
    epoch: u64,
    sequence_id: u64,
    leader_id: ValidatorId,
}

/// Cached proposal entry with timestamp for eviction.
#[derive(Clone, Debug)]
struct CachedProposal {
    /// The cached proposal data.
    proposal: ConflictingProposal,
    /// Timestamp when the proposal was cached (Unix epoch seconds).
    cached_at: u64,
}

/// Result of checking a proposal for equivocation.
#[derive(Clone, Debug)]
pub enum EquivocationCheckResult {
    /// No equivocation detected; proposal was cached.
    NoConflict,
    /// Equivocation detected; evidence is available.
    ///
    /// The evidence is boxed to reduce the enum size since it's a large struct
    /// and this variant is rarely encountered (only in Byzantine scenarios).
    EquivocationDetected(Box<EquivocationEvidence>),
    /// The proposal is a duplicate of an already-seen proposal (same hash).
    Duplicate,
}

/// Detector for Byzantine equivocation behavior.
///
/// This maintains a bounded cache of recent proposals and detects when
/// a validator sends conflicting proposals for the same slot.
///
/// # Thread Safety
///
/// This type is not internally synchronized. Use external synchronization
/// (e.g., `RwLock`) for concurrent access.
pub struct EquivocationDetector {
    /// Cache of proposals keyed by (namespace, epoch, `sequence_id`,
    /// `leader_id`).
    cache: HashMap<ProposalCacheKey, CachedProposal>,
    /// Insertion order for FIFO eviction (`VecDeque` for O(1) front removal).
    insertion_order: VecDeque<ProposalCacheKey>,
    /// Maximum cache size.
    max_cache_size: usize,
}

impl Default for EquivocationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EquivocationDetector {
    /// Creates a new equivocation detector with the default cache size.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_CACHED_PROPOSALS)
    }

    /// Creates a new equivocation detector with a specified cache size.
    #[must_use]
    pub fn with_capacity(max_cache_size: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(max_cache_size),
            insertion_order: VecDeque::with_capacity(max_cache_size),
            max_cache_size,
        }
    }

    /// Checks a proposal for equivocation and caches it if no conflict found.
    ///
    /// # Arguments
    ///
    /// * `proposal` - The proposal to check.
    ///
    /// # Returns
    ///
    /// - `NoConflict` if this is a new, non-conflicting proposal (now cached).
    /// - `EquivocationDetected` if this proposal conflicts with a cached one.
    /// - `Duplicate` if this is an exact duplicate of a cached proposal.
    pub fn check_proposal(&mut self, proposal: &ReplicationProposal) -> EquivocationCheckResult {
        let key = ProposalCacheKey {
            namespace: proposal.namespace.clone(),
            epoch: proposal.epoch,
            sequence_id: proposal.sequence_id,
            leader_id: proposal.leader_id,
        };

        // Check if we have a cached proposal for this slot
        if let Some(cached) = self.cache.get(&key) {
            // Check if it's an exact duplicate (same hash)
            if cached.proposal.event_hash == proposal.event_hash {
                return EquivocationCheckResult::Duplicate;
            }

            // Conflict detected! Generate evidence
            let evidence =
                EquivocationEvidence::new(&Self::reconstruct_proposal(&cached.proposal), proposal);
            return EquivocationCheckResult::EquivocationDetected(Box::new(evidence));
        }

        // Evict old entries if at capacity
        self.evict_if_needed();

        // Cache this proposal
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.cache.insert(
            key.clone(),
            CachedProposal {
                proposal: ConflictingProposal::from(proposal),
                cached_at: now,
            },
        );
        self.insertion_order.push_back(key);

        EquivocationCheckResult::NoConflict
    }

    /// Evicts old entries if the cache is at capacity.
    fn evict_if_needed(&mut self) {
        // Evict based on age first
        self.evict_stale_entries();

        // If still at capacity, evict oldest entries (FIFO)
        while self.cache.len() >= self.max_cache_size && !self.insertion_order.is_empty() {
            if let Some(oldest_key) = self.insertion_order.pop_front() {
                self.cache.remove(&oldest_key);
            }
        }
    }

    /// Evicts entries older than `MAX_PROPOSAL_AGE_SECS`.
    fn evict_stale_entries(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cutoff = now.saturating_sub(MAX_PROPOSAL_AGE_SECS);

        // Remove stale entries from cache
        self.cache.retain(|_, cached| cached.cached_at > cutoff);

        // Update insertion order to match
        self.insertion_order
            .retain(|key| self.cache.contains_key(key));
    }

    /// Reconstructs a `ReplicationProposal` from a `ConflictingProposal`.
    ///
    /// Note: The `event_data` field is not stored in the cache, so it's set to
    /// the hash bytes for reconstruction purposes.
    fn reconstruct_proposal(cached: &ConflictingProposal) -> ReplicationProposal {
        ReplicationProposal {
            epoch: cached.epoch,
            sequence_id: cached.sequence_id,
            leader_id: cached.leader_id,
            namespace: cached.namespace.clone(),
            // We don't store the full event_data, but for evidence purposes
            // we only need the hash and signature
            event_data: cached.event_hash.to_vec(),
            event_hash: cached.event_hash,
            signature: cached.signature,
        }
    }

    /// Returns the current number of cached proposals.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Clears all cached proposals.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.insertion_order.clear();
    }
}

// =============================================================================
// Serde Helpers
// =============================================================================

/// Base64 serialization for `[u8; 32]` arrays in JSON.
mod base64_arr_32 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// Base64 serialization for `[u8; 64]` arrays in JSON.
mod base64_arr_64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    fn generate_test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn validator_id_from_key(key: &SigningKey) -> ValidatorId {
        blake3::hash(key.verifying_key().as_bytes()).into()
    }

    fn create_signed_proposal(
        key: &SigningKey,
        namespace: &str,
        epoch: u64,
        sequence_id: u64,
        event_data: &[u8],
    ) -> ReplicationProposal {
        let leader_id = validator_id_from_key(key);
        let event_hash = blake3::hash(event_data).into();

        let mut proposal = ReplicationProposal {
            epoch,
            sequence_id,
            leader_id,
            namespace: namespace.to_string(),
            event_data: event_data.to_vec(),
            event_hash,
            signature: [0u8; 64],
        };

        proposal.sign(key).unwrap();
        proposal
    }

    #[test]
    fn test_equivocation_type_description() {
        assert_eq!(
            EquivocationType::DoubleSigning.description(),
            "Double-signing: same sequence ID with different hash"
        );
        assert_eq!(
            EquivocationType::ConflictingProposal.description(),
            "Conflicting proposals for the same slot"
        );
    }

    #[test]
    fn test_detector_no_conflict() {
        let mut detector = EquivocationDetector::new();
        let key = generate_test_key();

        let proposal = create_signed_proposal(&key, "test", 1, 1, b"event1");
        let result = detector.check_proposal(&proposal);

        assert!(matches!(result, EquivocationCheckResult::NoConflict));
        assert_eq!(detector.cache_size(), 1);
    }

    #[test]
    fn test_detector_duplicate() {
        let mut detector = EquivocationDetector::new();
        let key = generate_test_key();

        let proposal = create_signed_proposal(&key, "test", 1, 1, b"event1");

        // First check: no conflict
        let result1 = detector.check_proposal(&proposal);
        assert!(matches!(result1, EquivocationCheckResult::NoConflict));

        // Second check with same proposal: duplicate
        let result2 = detector.check_proposal(&proposal);
        assert!(matches!(result2, EquivocationCheckResult::Duplicate));
    }

    #[test]
    fn test_detector_equivocation_detected() {
        let mut detector = EquivocationDetector::new();
        let key = generate_test_key();

        // First proposal for sequence 1
        let proposal1 = create_signed_proposal(&key, "test", 1, 1, b"event1");
        let result1 = detector.check_proposal(&proposal1);
        assert!(matches!(result1, EquivocationCheckResult::NoConflict));

        // Second proposal for same sequence with different data
        let proposal2 = create_signed_proposal(&key, "test", 1, 1, b"different_event");
        let result2 = detector.check_proposal(&proposal2);

        match result2 {
            EquivocationCheckResult::EquivocationDetected(evidence) => {
                assert_eq!(evidence.epoch, 1);
                assert_eq!(evidence.sequence_id, 1);
                assert_eq!(evidence.byzantine_validator_id, validator_id_from_key(&key));
                assert_eq!(evidence.equivocation_type, EquivocationType::DoubleSigning);
                assert_ne!(
                    evidence.proposal_a.event_hash,
                    evidence.proposal_b.event_hash
                );
            },
            _ => panic!("Expected EquivocationDetected"),
        }
    }

    #[test]
    fn test_evidence_verification() {
        let mut detector = EquivocationDetector::new();
        let key = generate_test_key();

        let proposal1 = create_signed_proposal(&key, "test", 1, 1, b"event1");
        detector.check_proposal(&proposal1);

        let proposal2 = create_signed_proposal(&key, "test", 1, 1, b"different_event");
        let result = detector.check_proposal(&proposal2);

        if let EquivocationCheckResult::EquivocationDetected(evidence) = result {
            // Verification should pass with correct key
            assert!(evidence.verify(&key.verifying_key()).is_ok());

            // Verification should fail with wrong key
            let wrong_key = generate_test_key();
            assert!(evidence.verify(&wrong_key.verifying_key()).is_err());
        } else {
            panic!("Expected EquivocationDetected");
        }
    }

    #[test]
    fn test_different_sequence_ids_no_conflict() {
        let mut detector = EquivocationDetector::new();
        let key = generate_test_key();

        let proposal1 = create_signed_proposal(&key, "test", 1, 1, b"event1");
        let proposal2 = create_signed_proposal(&key, "test", 1, 2, b"event2");

        let result1 = detector.check_proposal(&proposal1);
        let result2 = detector.check_proposal(&proposal2);

        assert!(matches!(result1, EquivocationCheckResult::NoConflict));
        assert!(matches!(result2, EquivocationCheckResult::NoConflict));
        assert_eq!(detector.cache_size(), 2);
    }

    #[test]
    fn test_different_leaders_no_conflict() {
        let mut detector = EquivocationDetector::new();
        let key1 = generate_test_key();
        let key2 = generate_test_key();

        let proposal1 = create_signed_proposal(&key1, "test", 1, 1, b"event1");
        let proposal2 = create_signed_proposal(&key2, "test", 1, 1, b"event2");

        let result1 = detector.check_proposal(&proposal1);
        let result2 = detector.check_proposal(&proposal2);

        // Different leaders can propose different events for the same slot
        // (though in practice only one should be the real leader)
        assert!(matches!(result1, EquivocationCheckResult::NoConflict));
        assert!(matches!(result2, EquivocationCheckResult::NoConflict));
    }

    #[test]
    fn test_bounded_cache_eviction() {
        let max_size = 10;
        let mut detector = EquivocationDetector::with_capacity(max_size);
        let key = generate_test_key();

        // Add proposals up to capacity
        for i in 0..max_size {
            let proposal =
                create_signed_proposal(&key, "test", 1, i as u64, format!("event{i}").as_bytes());
            detector.check_proposal(&proposal);
        }
        assert_eq!(detector.cache_size(), max_size);

        // Add one more - should trigger eviction
        let proposal = create_signed_proposal(&key, "test", 1, max_size as u64, b"overflow");
        detector.check_proposal(&proposal);

        // Cache size should still be at max
        assert!(detector.cache_size() <= max_size);
    }

    #[test]
    fn test_clear_cache() {
        let mut detector = EquivocationDetector::new();
        let key = generate_test_key();

        let proposal = create_signed_proposal(&key, "test", 1, 1, b"event1");
        detector.check_proposal(&proposal);
        assert_eq!(detector.cache_size(), 1);

        detector.clear();
        assert_eq!(detector.cache_size(), 0);
    }

    #[test]
    fn test_evidence_serialization_roundtrip() {
        let mut detector = EquivocationDetector::new();
        let key = generate_test_key();

        let proposal1 = create_signed_proposal(&key, "test", 1, 1, b"event1");
        detector.check_proposal(&proposal1);

        let proposal2 = create_signed_proposal(&key, "test", 1, 1, b"different_event");
        let result = detector.check_proposal(&proposal2);

        if let EquivocationCheckResult::EquivocationDetected(evidence) = result {
            // Serialize to JSON (deref the Box)
            let json = serde_json::to_string(&*evidence).unwrap();

            // Deserialize back
            let restored: EquivocationEvidence = serde_json::from_str(&json).unwrap();

            assert_eq!(restored.equivocation_type, evidence.equivocation_type);
            assert_eq!(
                restored.byzantine_validator_id,
                evidence.byzantine_validator_id
            );
            assert_eq!(restored.epoch, evidence.epoch);
            assert_eq!(restored.sequence_id, evidence.sequence_id);
            assert_eq!(
                restored.proposal_a.event_hash,
                evidence.proposal_a.event_hash
            );
            assert_eq!(
                restored.proposal_b.event_hash,
                evidence.proposal_b.event_hash
            );
        } else {
            panic!("Expected EquivocationDetected");
        }
    }

    #[test]
    fn test_byzantine_validator_id_hex() {
        let key = generate_test_key();
        let validator_id = validator_id_from_key(&key);

        let evidence = EquivocationEvidence {
            equivocation_type: EquivocationType::DoubleSigning,
            byzantine_validator_id: validator_id,
            proposal_a: ConflictingProposal {
                epoch: 1,
                sequence_id: 1,
                leader_id: validator_id,
                namespace: "test".to_string(),
                event_hash: [0u8; 32],
                signature: [0u8; 64],
            },
            proposal_b: ConflictingProposal {
                epoch: 1,
                sequence_id: 1,
                leader_id: validator_id,
                namespace: "test".to_string(),
                event_hash: [1u8; 32],
                signature: [0u8; 64],
            },
            detected_at_ns: 0,
            namespace: "test".to_string(),
            epoch: 1,
            sequence_id: 1,
        };

        let hex_id = evidence.byzantine_validator_id_hex();
        assert_eq!(hex_id.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(hex_id, hex::encode(validator_id));
    }
}

#[cfg(test)]
mod tck_00196_tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    fn generate_test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn validator_id_from_key(key: &SigningKey) -> ValidatorId {
        blake3::hash(key.verifying_key().as_bytes()).into()
    }

    fn create_signed_proposal(
        key: &SigningKey,
        namespace: &str,
        epoch: u64,
        sequence_id: u64,
        event_data: &[u8],
    ) -> ReplicationProposal {
        let leader_id = validator_id_from_key(key);
        let event_hash = blake3::hash(event_data).into();

        let mut proposal = ReplicationProposal {
            epoch,
            sequence_id,
            leader_id,
            namespace: namespace.to_string(),
            event_data: event_data.to_vec(),
            event_hash,
            signature: [0u8; 64],
        };

        proposal.sign(key).unwrap();
        proposal
    }

    /// TCK-00196: Test that equivocation is detected for same `seq_id` with
    /// different hash.
    #[test]
    fn tck_00196_detect_double_signing() {
        let mut detector = EquivocationDetector::new();
        let byzantine_key = generate_test_key();

        // Byzantine validator signs two different proposals for same slot
        let proposal1 = create_signed_proposal(&byzantine_key, "test", 1, 42, b"legitimate_event");
        let proposal2 = create_signed_proposal(&byzantine_key, "test", 1, 42, b"malicious_event");

        // First proposal should be accepted
        let result1 = detector.check_proposal(&proposal1);
        assert!(
            matches!(result1, EquivocationCheckResult::NoConflict),
            "First proposal should not trigger equivocation"
        );

        // Second conflicting proposal should trigger equivocation detection
        let result2 = detector.check_proposal(&proposal2);
        assert!(
            matches!(result2, EquivocationCheckResult::EquivocationDetected(_)),
            "Conflicting proposal should trigger equivocation detection"
        );
    }

    /// TCK-00196: Test that evidence contains all required fields.
    #[test]
    fn tck_00196_evidence_contains_required_fields() {
        let mut detector = EquivocationDetector::new();
        let byzantine_key = generate_test_key();
        let byzantine_id = validator_id_from_key(&byzantine_key);

        let proposal1 = create_signed_proposal(&byzantine_key, "kernel", 5, 100, b"event_a");
        let proposal2 = create_signed_proposal(&byzantine_key, "kernel", 5, 100, b"event_b");

        detector.check_proposal(&proposal1);
        let result = detector.check_proposal(&proposal2);

        match result {
            EquivocationCheckResult::EquivocationDetected(evidence) => {
                // Verify Byzantine node identity is included
                assert_eq!(
                    evidence.byzantine_validator_id, byzantine_id,
                    "Byzantine validator ID should match"
                );

                // Verify both conflicting proposals are included
                assert_ne!(
                    evidence.proposal_a.event_hash, evidence.proposal_b.event_hash,
                    "Proposals should have different hashes"
                );

                // Verify both proposals have valid signatures
                assert!(
                    evidence.verify(&byzantine_key.verifying_key()).is_ok(),
                    "Evidence should be verifiable"
                );

                // Verify timestamp is present
                assert!(
                    evidence.detected_at_ns > 0,
                    "Detection timestamp should be set"
                );

                // Verify namespace is included
                assert_eq!(
                    evidence.namespace, "kernel",
                    "Namespace should be preserved"
                );

                // Verify epoch and sequence_id are included
                assert_eq!(evidence.epoch, 5, "Epoch should be preserved");
                assert_eq!(evidence.sequence_id, 100, "Sequence ID should be preserved");

                // Verify equivocation type is correct
                assert_eq!(
                    evidence.equivocation_type,
                    EquivocationType::DoubleSigning,
                    "Should be double-signing type"
                );
            },
            _ => panic!("Expected EquivocationDetected"),
        }
    }

    /// TCK-00196: Test that valid proposals don't trigger false positives.
    #[test]
    fn tck_00196_no_false_positives() {
        let mut detector = EquivocationDetector::new();
        let key = generate_test_key();

        // Different sequence IDs should not conflict
        let proposal1 = create_signed_proposal(&key, "test", 1, 1, b"event1");
        let proposal2 = create_signed_proposal(&key, "test", 1, 2, b"event2");
        let proposal3 = create_signed_proposal(&key, "test", 1, 3, b"event3");

        assert!(matches!(
            detector.check_proposal(&proposal1),
            EquivocationCheckResult::NoConflict
        ));
        assert!(matches!(
            detector.check_proposal(&proposal2),
            EquivocationCheckResult::NoConflict
        ));
        assert!(matches!(
            detector.check_proposal(&proposal3),
            EquivocationCheckResult::NoConflict
        ));

        // Different epochs should not conflict
        let proposal4 = create_signed_proposal(&key, "test", 2, 1, b"new_epoch_event");
        assert!(matches!(
            detector.check_proposal(&proposal4),
            EquivocationCheckResult::NoConflict
        ));

        // Different namespaces should not conflict
        let proposal5 = create_signed_proposal(&key, "other_ns", 1, 1, b"other_ns_event");
        assert!(matches!(
            detector.check_proposal(&proposal5),
            EquivocationCheckResult::NoConflict
        ));
    }

    /// TCK-00196: Test bounded collection eviction.
    #[test]
    fn tck_00196_bounded_collection_eviction() {
        let max_size = 5;
        let mut detector = EquivocationDetector::with_capacity(max_size);
        let key = generate_test_key();

        // Fill the cache
        for i in 0..max_size {
            let proposal =
                create_signed_proposal(&key, "test", 1, i as u64, format!("event{i}").as_bytes());
            detector.check_proposal(&proposal);
        }
        assert_eq!(detector.cache_size(), max_size);

        // Add more proposals beyond capacity
        for i in max_size..(max_size * 2) {
            let proposal =
                create_signed_proposal(&key, "test", 1, i as u64, format!("event{i}").as_bytes());
            detector.check_proposal(&proposal);
        }

        // Cache should remain bounded
        assert!(
            detector.cache_size() <= max_size,
            "Cache size {} should not exceed max {}",
            detector.cache_size(),
            max_size
        );
    }

    /// TCK-00196: Test that evidence is independently verifiable.
    #[test]
    fn tck_00196_evidence_independently_verifiable() {
        let mut detector = EquivocationDetector::new();
        let byzantine_key = generate_test_key();

        let proposal1 = create_signed_proposal(&byzantine_key, "test", 1, 1, b"event1");
        let proposal2 = create_signed_proposal(&byzantine_key, "test", 1, 1, b"event2");

        detector.check_proposal(&proposal1);
        let result = detector.check_proposal(&proposal2);

        if let EquivocationCheckResult::EquivocationDetected(evidence) = result {
            // Serialize evidence (as would happen when transmitting to another
            // node) - deref the Box
            let serialized = serde_json::to_vec(&*evidence).unwrap();

            // Deserialize on "another node"
            let received: EquivocationEvidence = serde_json::from_slice(&serialized).unwrap();

            // The other node can verify the evidence using only the public key
            assert!(
                received.verify(&byzantine_key.verifying_key()).is_ok(),
                "Evidence should be verifiable by any node with the public key"
            );

            // Verification should fail with wrong public key
            let other_key = generate_test_key();
            assert!(
                received.verify(&other_key.verifying_key()).is_err(),
                "Evidence should fail verification with wrong key"
            );
        } else {
            panic!("Expected EquivocationDetected");
        }
    }

    /// TCK-00196: Test constants are within acceptable bounds.
    ///
    /// This test verifies that the constants are set to appropriate values
    /// at runtime by checking they meet expected bounds.
    #[test]
    fn tck_00196_constants_bounded() {
        // Verify constants have expected values at runtime
        // (compile-time checks are done in const block below)
        let max_cached = MAX_CACHED_PROPOSALS;
        let max_age = MAX_PROPOSAL_AGE_SECS;

        // These checks ensure the constants haven't been set to unexpected values
        assert!(max_cached > 0 && max_cached <= 8192);
        assert!(max_age > 0 && max_age <= 86400);
    }

    // Compile-time bounds verification
    const _: () = {
        assert!(MAX_CACHED_PROPOSALS > 0);
        assert!(MAX_CACHED_PROPOSALS <= 8192);
        assert!(MAX_PROPOSAL_AGE_SECS > 0);
        assert!(MAX_PROPOSAL_AGE_SECS <= 86400);
    };
}
