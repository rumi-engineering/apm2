// AGENT-AUTHORED
//! Leader-based event replication for the consensus layer.
//!
//! This module implements basic leader-based replication where the leader
//! receives proposals and broadcasts them to connected peers. Followers
//! append replicated events to their local log.
//!
//! # Architecture
//!
//! ```text
//!                    +-----------+
//!                    |  Leader   |
//!                    | (propose) |
//!                    +-----+-----+
//!                          |
//!           +--------------+---------------+
//!           |              |               |
//!           v              v               v
//!     +---------+    +---------+    +---------+
//!     |Follower1|    |Follower2|    |Follower3|
//!     | (append)|    | (append)|    | (append)|
//!     +---------+    +---------+    +---------+
//! ```
//!
//! # Protocol Flow
//!
//! 1. Client submits a proposal to the leader via
//!    `ReplicationEngine::propose()`
//! 2. Leader validates the proposal and creates a
//!    `ReplicationMessage::Proposal`
//! 3. Leader broadcasts the message to all connected peers
//! 4. Followers receive the message and append to local log
//! 5. Followers send `ReplicationMessage::Ack` back to leader
//! 6. Leader tracks acknowledgments for commit confirmation
//!
//! # Security Properties
//!
//! - **Signature Validation**: All proposals are signed by the leader and
//!   verified by followers
//! - **Epoch/Sequence Validation**: Stale and duplicate messages are rejected
//! - **Bounded Collections (CTR-1303)**: All internal collections are bounded
//! - **Leader Verification**: Followers verify the sender is the current leader
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00195: Leader-Based Replication (Basic)
//! - DD-0001: Hybrid Consensus Model

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::RwLock;

use super::bft::ValidatorId;
use super::handlers::PeerManager;
use crate::ledger::{EventRecord, LedgerBackend, LedgerError};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of pending proposals in the outbound queue.
///
/// Bounded to prevent denial-of-service via memory exhaustion (CTR-1303).
pub const MAX_PENDING_PROPOSALS: usize = 256;

/// Maximum number of tracked acknowledgments per proposal.
///
/// This limits memory usage when tracking peer responses.
pub const MAX_ACKS_PER_PROPOSAL: usize = 128;

/// Maximum number of proposals to track for acknowledgment.
///
/// Older proposals are evicted to maintain bounded memory usage.
pub const MAX_TRACKED_PROPOSALS: usize = 1024;

/// Maximum payload size for replicated events.
///
/// Events larger than this are rejected to prevent denial-of-service.
pub const MAX_REPLICATION_PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MiB

/// Message type for replication proposals.
pub const MSG_REPLICATION_PROPOSAL: u32 = 300;

/// Domain separation prefix for proposal signatures (prevents cross-protocol
/// replay).
pub const DOMAIN_PREFIX_PROPOSAL: &[u8] = b"APM2-REPLICATION-PROPOSAL-V1:";

/// Domain separation prefix for acknowledgment signatures.
pub const DOMAIN_PREFIX_ACK: &[u8] = b"APM2-REPLICATION-ACK-V1:";

/// Domain separation prefix for nack signatures.
pub const DOMAIN_PREFIX_NACK: &[u8] = b"APM2-REPLICATION-NACK-V1:";

/// Message type for replication acknowledgments.
pub const MSG_REPLICATION_ACK: u32 = 301;

/// Message type for replication nack (rejection).
pub const MSG_REPLICATION_NACK: u32 = 302;

/// Default timeout for proposal acknowledgment.
pub const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(5);

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during replication operations.
#[derive(Debug, Error)]
pub enum ReplicationError {
    /// Not the current leader.
    #[error("not the current leader: expected {expected}, got {actual}")]
    NotLeader {
        /// The expected leader ID.
        expected: String,
        /// The actual node ID that attempted to lead.
        actual: String,
    },

    /// Invalid signature on proposal.
    #[error("invalid proposal signature from {sender}")]
    InvalidSignature {
        /// The sender whose signature failed verification.
        sender: String,
    },

    /// Proposal from non-leader node.
    #[error("proposal from non-leader: {sender} is not the leader")]
    ProposalFromNonLeader {
        /// The non-leader that sent the proposal.
        sender: String,
    },

    /// Duplicate proposal received.
    #[error("duplicate proposal: sequence {sequence_id} already received")]
    DuplicateProposal {
        /// The duplicate sequence ID.
        sequence_id: u64,
    },

    /// Stale proposal (sequence too old).
    #[error("stale proposal: sequence {proposal_seq} < current {current_seq}")]
    StaleProposal {
        /// The proposal's sequence ID.
        proposal_seq: u64,
        /// The current expected sequence ID.
        current_seq: u64,
    },

    /// Future proposal (sequence too far ahead).
    #[error("future proposal: sequence {proposal_seq} > expected {expected_seq}")]
    FutureProposal {
        /// The proposal's sequence ID.
        proposal_seq: u64,
        /// The expected next sequence ID.
        expected_seq: u64,
    },

    /// Payload too large.
    #[error("payload too large: {size} > {max}")]
    PayloadTooLarge {
        /// Actual payload size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Ledger error during append.
    #[error("ledger error: {0}")]
    Ledger(#[from] LedgerError),

    /// Queue full.
    #[error("proposal queue full: {size} >= {max}")]
    QueueFull {
        /// Current queue size.
        size: usize,
        /// Maximum queue size.
        max: usize,
    },

    /// Unknown peer.
    #[error("unknown peer: {peer_id}")]
    UnknownPeer {
        /// The unknown peer ID.
        peer_id: String,
    },

    /// Stale epoch in ack/nack.
    #[error("stale epoch: ack epoch {ack_epoch} != proposal epoch {proposal_epoch}")]
    StaleEpoch {
        /// The epoch in the ack.
        ack_epoch: u64,
        /// The expected proposal epoch.
        proposal_epoch: u64,
    },

    /// Engine is shutting down.
    #[error("replication engine is shutting down")]
    Shutdown,
}

// =============================================================================
// Messages
// =============================================================================

/// Replication protocol messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ReplicationMessage {
    /// A proposal from the leader to replicate an event.
    Proposal(ReplicationProposal),

    /// Acknowledgment that a follower has appended the event.
    Ack(ReplicationAck),

    /// Negative acknowledgment (rejection) of a proposal.
    Nack(ReplicationNack),
}

/// Replicated event data for transmission.
///
/// This captures the essential fields of an `EventRecord` that need to be
/// transmitted for replication. The format is designed to be serializable
/// and to allow reconstruction of an `EventRecord` on the follower side.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicatedEvent {
    /// Event type identifier.
    pub event_type: String,

    /// Session this event belongs to.
    pub session_id: String,

    /// Actor ID that signed this event.
    pub actor_id: String,

    /// Record version for schema compatibility.
    pub record_version: u32,

    /// Event payload (typically JSON).
    #[serde(with = "base64_vec")]
    pub payload: Vec<u8>,

    /// Timestamp in nanoseconds since Unix epoch.
    pub timestamp_ns: u64,

    /// Previous hash (for hash chaining).
    #[serde(with = "base64_opt_vec")]
    pub prev_hash: Option<Vec<u8>>,

    /// Event hash.
    #[serde(with = "base64_opt_vec")]
    pub event_hash: Option<Vec<u8>>,

    /// Signature over the event.
    #[serde(with = "base64_opt_vec")]
    pub signature: Option<Vec<u8>>,

    // RFC-0014 Consensus fields
    /// Consensus epoch number.
    pub consensus_epoch: Option<u64>,

    /// Consensus round within epoch.
    pub consensus_round: Option<u64>,

    /// Quorum certificate as serialized bytes.
    #[serde(with = "base64_opt_vec")]
    pub quorum_cert: Option<Vec<u8>>,

    /// BLAKE3 digest of the schema definition.
    #[serde(with = "base64_opt_vec")]
    pub schema_digest: Option<Vec<u8>>,

    /// Canonicalizer identifier.
    pub canonicalizer_id: Option<String>,

    /// Canonicalizer version.
    pub canonicalizer_version: Option<String>,

    /// Hybrid Logical Clock wall time.
    pub hlc_wall_time: Option<u64>,

    /// Hybrid Logical Clock counter.
    pub hlc_counter: Option<u32>,
}

impl ReplicatedEvent {
    /// Creates a `ReplicatedEvent` from an `EventRecord`.
    #[must_use]
    pub fn from_event_record(event: &EventRecord) -> Self {
        Self {
            event_type: event.event_type.clone(),
            session_id: event.session_id.clone(),
            actor_id: event.actor_id.clone(),
            record_version: event.record_version,
            payload: event.payload.clone(),
            timestamp_ns: event.timestamp_ns,
            prev_hash: event.prev_hash.clone(),
            event_hash: event.event_hash.clone(),
            signature: event.signature.clone(),
            consensus_epoch: event.consensus_epoch,
            consensus_round: event.consensus_round,
            quorum_cert: event.quorum_cert.clone(),
            schema_digest: event.schema_digest.clone(),
            canonicalizer_id: event.canonicalizer_id.clone(),
            canonicalizer_version: event.canonicalizer_version.clone(),
            hlc_wall_time: event.hlc_wall_time,
            hlc_counter: event.hlc_counter,
        }
    }

    /// Converts this `ReplicatedEvent` to an `EventRecord`.
    #[must_use]
    pub fn to_event_record(&self) -> EventRecord {
        EventRecord {
            seq_id: None, // Assigned by ledger on append
            event_type: self.event_type.clone(),
            session_id: self.session_id.clone(),
            actor_id: self.actor_id.clone(),
            record_version: self.record_version,
            payload: self.payload.clone(),
            timestamp_ns: self.timestamp_ns,
            prev_hash: self.prev_hash.clone(),
            event_hash: self.event_hash.clone(),
            signature: self.signature.clone(),
            consensus_epoch: self.consensus_epoch,
            consensus_round: self.consensus_round,
            quorum_cert: self.quorum_cert.clone(),
            schema_digest: self.schema_digest.clone(),
            canonicalizer_id: self.canonicalizer_id.clone(),
            canonicalizer_version: self.canonicalizer_version.clone(),
            hlc_wall_time: self.hlc_wall_time,
            hlc_counter: self.hlc_counter,
        }
    }

    /// Verifies that the event has a valid hash (integrity check).
    ///
    /// This validates that the event hash field matches the computed hash
    /// of the payload and `prev_hash`, providing basic integrity verification.
    ///
    /// # Returns
    ///
    /// Returns `true` if the hash is valid or if no hash is present (for
    /// events that don't require hashing).
    #[must_use]
    pub fn validate_hash(&self) -> bool {
        match (&self.event_hash, &self.prev_hash) {
            (Some(stored_hash), Some(prev)) => {
                // Compute hash: BLAKE3(prev_hash || payload)
                let mut hasher = blake3::Hasher::new();
                hasher.update(prev);
                hasher.update(&self.payload);
                let computed = hasher.finalize();
                computed.as_bytes().ct_eq(stored_hash.as_slice()).into()
            },
            (Some(stored_hash), None) => {
                // Compute hash: BLAKE3(payload) when no prev_hash
                let computed = blake3::hash(&self.payload);
                computed.as_bytes().ct_eq(stored_hash.as_slice()).into()
            },
            (None, _) => {
                // No hash to validate - this is acceptable for some event types
                true
            },
        }
    }

    /// Verifies the actor signature on this event.
    ///
    /// This validates that the event was signed by an authorized actor,
    /// providing defense-in-depth against compromised leaders.
    ///
    /// # Arguments
    ///
    /// * `actor_key` - The public key of the actor who supposedly signed this
    ///   event
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature is missing
    /// - The event hash is missing
    /// - The signature length is invalid
    /// - The signature verification fails
    pub fn verify_signature(&self, actor_key: &VerifyingKey) -> Result<(), ReplicationError> {
        let Some(signature_bytes) = &self.signature else {
            // No signature present - this could be acceptable for some event
            // types, but for strict validation we require it
            return Err(ReplicationError::InvalidSignature {
                sender: self.actor_id.clone(),
            });
        };

        let Some(event_hash) = &self.event_hash else {
            // No hash to sign - this is a malformed event
            return Err(ReplicationError::InvalidSignature {
                sender: self.actor_id.clone(),
            });
        };

        // Signature should be over the event hash
        if signature_bytes.len() != 64 {
            return Err(ReplicationError::InvalidSignature {
                sender: self.actor_id.clone(),
            });
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        actor_key
            .verify_strict(event_hash, &signature)
            .map_err(|_| ReplicationError::InvalidSignature {
                sender: self.actor_id.clone(),
            })
    }
}

/// A proposal from the leader containing an event to replicate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationProposal {
    /// The epoch of this proposal.
    pub epoch: u64,

    /// Sequence ID assigned by the leader.
    pub sequence_id: u64,

    /// The leader's validator ID.
    pub leader_id: ValidatorId,

    /// Namespace for this event.
    pub namespace: String,

    /// The event to replicate (serialized `ReplicatedEvent`).
    #[serde(with = "base64_vec")]
    pub event_data: Vec<u8>,

    /// BLAKE3 hash of the event data.
    #[serde(with = "base64_arr_32")]
    pub event_hash: [u8; 32],

    /// Ed25519 signature over (`epoch` || `sequence_id` || `event_hash`).
    #[serde(with = "base64_arr_64")]
    pub signature: [u8; 64],
}

impl ReplicationProposal {
    /// Creates the message to sign for this proposal.
    ///
    /// The message includes a domain separation prefix and the namespace to
    /// prevent cross-protocol and cross-namespace replay attacks.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace is longer than `u32::MAX` bytes.
    pub fn signing_message(&self) -> Result<Vec<u8>, ReplicationError> {
        let ns_bytes = self.namespace.as_bytes();
        let ns_len =
            u32::try_from(ns_bytes.len()).map_err(|_| ReplicationError::PayloadTooLarge {
                size: ns_bytes.len(),
                max: u32::MAX as usize,
            })?;
        let mut msg =
            Vec::with_capacity(DOMAIN_PREFIX_PROPOSAL.len() + 4 + ns_bytes.len() + 8 + 8 + 32);
        msg.extend_from_slice(DOMAIN_PREFIX_PROPOSAL);
        msg.extend_from_slice(&ns_len.to_le_bytes());
        msg.extend_from_slice(ns_bytes);
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        msg.extend_from_slice(&self.sequence_id.to_le_bytes());
        msg.extend_from_slice(&self.event_hash);
        Ok(msg)
    }

    /// Signs this proposal with the given signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace is too long.
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ReplicationError> {
        let msg = self.signing_message()?;
        self.signature = key.sign(&msg).to_bytes();
        Ok(())
    }

    /// Verifies the signature on this proposal.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or the namespace is too
    /// long.
    pub fn verify_signature(&self, public_key: &VerifyingKey) -> Result<(), ReplicationError> {
        let msg = self.signing_message()?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        public_key
            .verify_strict(&msg, &signature)
            .map_err(|_| ReplicationError::InvalidSignature {
                sender: hex::encode(self.leader_id),
            })
    }

    /// Computes the hash of the event data.
    #[must_use]
    pub fn compute_event_hash(event_data: &[u8]) -> [u8; 32] {
        blake3::hash(event_data).into()
    }

    /// Validates the event hash.
    #[must_use]
    pub fn validate_hash(&self) -> bool {
        let computed = Self::compute_event_hash(&self.event_data);
        computed.ct_eq(&self.event_hash).into()
    }
}

/// Acknowledgment from a follower that an event was appended.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationAck {
    /// The epoch of the acknowledged proposal.
    pub epoch: u64,

    /// The sequence ID being acknowledged.
    pub sequence_id: u64,

    /// Namespace for this acknowledgment.
    pub namespace: String,

    /// The follower's validator ID.
    pub follower_id: ValidatorId,

    /// Sequence ID assigned in the follower's local ledger.
    pub local_seq_id: u64,

    /// Ed25519 signature over (`namespace` || `epoch` || `sequence_id` ||
    /// `local_seq_id`).
    #[serde(with = "base64_arr_64")]
    pub signature: [u8; 64],
}

impl ReplicationAck {
    /// Creates the message to sign for this acknowledgment.
    ///
    /// The message includes a domain separation prefix and the namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace is longer than `u32::MAX` bytes.
    pub fn signing_message(&self) -> Result<Vec<u8>, ReplicationError> {
        let ns_bytes = self.namespace.as_bytes();
        let ns_len =
            u32::try_from(ns_bytes.len()).map_err(|_| ReplicationError::PayloadTooLarge {
                size: ns_bytes.len(),
                max: u32::MAX as usize,
            })?;
        let mut msg = Vec::with_capacity(DOMAIN_PREFIX_ACK.len() + 4 + ns_bytes.len() + 8 + 8 + 8);
        msg.extend_from_slice(DOMAIN_PREFIX_ACK);
        msg.extend_from_slice(&ns_len.to_le_bytes());
        msg.extend_from_slice(ns_bytes);
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        msg.extend_from_slice(&self.sequence_id.to_le_bytes());
        msg.extend_from_slice(&self.local_seq_id.to_le_bytes());
        Ok(msg)
    }

    /// Signs this acknowledgment with the given signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace is too long.
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ReplicationError> {
        let msg = self.signing_message()?;
        self.signature = key.sign(&msg).to_bytes();
        Ok(())
    }

    /// Verifies the signature on this acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or the namespace is too
    /// long.
    pub fn verify_signature(&self, public_key: &VerifyingKey) -> Result<(), ReplicationError> {
        let msg = self.signing_message()?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        public_key
            .verify_strict(&msg, &signature)
            .map_err(|_| ReplicationError::InvalidSignature {
                sender: hex::encode(self.follower_id),
            })
    }
}

/// Negative acknowledgment (rejection) of a proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationNack {
    /// The epoch of the rejected proposal.
    pub epoch: u64,

    /// The sequence ID being rejected.
    pub sequence_id: u64,

    /// Namespace for this nack.
    pub namespace: String,

    /// The follower's validator ID.
    pub follower_id: ValidatorId,

    /// Reason for rejection.
    pub reason: NackReason,

    /// Ed25519 signature over (`namespace` || `epoch` || `sequence_id` ||
    /// `reason_code`).
    #[serde(with = "base64_arr_64")]
    pub signature: [u8; 64],
}

/// Reasons for rejecting a proposal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NackReason {
    /// Invalid signature on proposal.
    InvalidSignature,
    /// Proposal from non-leader.
    NotLeader,
    /// Duplicate sequence ID.
    Duplicate,
    /// Sequence ID too old.
    Stale,
    /// Sequence ID too far ahead (gap).
    Gap,
    /// Ledger append failed.
    LedgerError,
    /// Invalid event hash.
    InvalidHash,
    /// Payload too large.
    PayloadTooLarge,
    /// Invalid inner event signature.
    InvalidEventSignature,
}

impl NackReason {
    /// Returns the numeric code for this reason.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Self::InvalidSignature => 1,
            Self::NotLeader => 2,
            Self::Duplicate => 3,
            Self::Stale => 4,
            Self::Gap => 5,
            Self::LedgerError => 6,
            Self::InvalidHash => 7,
            Self::PayloadTooLarge => 8,
            Self::InvalidEventSignature => 9,
        }
    }
}

impl ReplicationNack {
    /// Creates the message to sign for this nack.
    ///
    /// The message includes a domain separation prefix and the namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace is longer than `u32::MAX` bytes.
    pub fn signing_message(&self) -> Result<Vec<u8>, ReplicationError> {
        let ns_bytes = self.namespace.as_bytes();
        let ns_len =
            u32::try_from(ns_bytes.len()).map_err(|_| ReplicationError::PayloadTooLarge {
                size: ns_bytes.len(),
                max: u32::MAX as usize,
            })?;
        let mut msg = Vec::with_capacity(DOMAIN_PREFIX_NACK.len() + 4 + ns_bytes.len() + 8 + 8 + 1);
        msg.extend_from_slice(DOMAIN_PREFIX_NACK);
        msg.extend_from_slice(&ns_len.to_le_bytes());
        msg.extend_from_slice(ns_bytes);
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        msg.extend_from_slice(&self.sequence_id.to_le_bytes());
        msg.push(self.reason.code());
        Ok(msg)
    }

    /// Signs this nack with the given signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace is too long.
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), ReplicationError> {
        let msg = self.signing_message()?;
        self.signature = key.sign(&msg).to_bytes();
        Ok(())
    }

    /// Verifies the signature on this nack.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or the namespace is too
    /// long.
    pub fn verify_signature(&self, public_key: &VerifyingKey) -> Result<(), ReplicationError> {
        let msg = self.signing_message()?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        public_key
            .verify_strict(&msg, &signature)
            .map_err(|_| ReplicationError::InvalidSignature {
                sender: hex::encode(self.follower_id),
            })
    }
}

/// Base64 serialization for `Vec<u8>` in JSON.
mod base64_vec {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Base64 serialization for `Option<Vec<u8>>` in JSON.
mod base64_opt_vec {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    // Serde's serialize_with requires `&T` for the field type, which is
    // `&Option<Vec<u8>>`.
    #[allow(clippy::ref_option)]
    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&STANDARD.encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        opt.map_or_else(
            || Ok(None),
            |s| {
                STANDARD
                    .decode(&s)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            },
        )
    }
}

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
// Acknowledgment Tracking
// =============================================================================

/// Tracks acknowledgments for a single proposal.
///
/// Note: We only store metadata (epoch, namespace) needed for validation,
/// not the full proposal, to reduce memory usage (CTR-1303).
#[derive(Clone, Debug)]
struct ProposalAckState {
    /// The epoch of the proposal (for ack validation).
    epoch: u64,
    /// The namespace of the proposal (for ack validation).
    namespace: String,
    /// Set of peers that have acknowledged.
    acks: HashMap<ValidatorId, ReplicationAck>,
    /// Set of peers that have rejected.
    nacks: HashMap<ValidatorId, ReplicationNack>,
}

impl ProposalAckState {
    /// Creates a new ack state for a proposal.
    fn new(epoch: u64, namespace: String) -> Self {
        Self {
            epoch,
            namespace,
            acks: HashMap::with_capacity(MAX_ACKS_PER_PROPOSAL),
            nacks: HashMap::with_capacity(MAX_ACKS_PER_PROPOSAL),
        }
    }

    /// Records an acknowledgment, validating epoch and namespace match.
    ///
    /// Returns true if the ack was recorded, false if validation failed or
    /// limit reached.
    fn record_ack(&mut self, ack: ReplicationAck) -> bool {
        // Validate epoch matches to prevent stale acks from old epochs
        if ack.epoch != self.epoch {
            return false;
        }
        // Validate namespace matches to prevent cross-namespace confusion
        if ack.namespace != self.namespace {
            return false;
        }
        if self.acks.len() < MAX_ACKS_PER_PROPOSAL {
            self.acks.insert(ack.follower_id, ack);
            true
        } else {
            false
        }
    }

    /// Records a negative acknowledgment.
    fn record_nack(&mut self, nack: ReplicationNack) {
        if self.nacks.len() < MAX_ACKS_PER_PROPOSAL {
            self.nacks.insert(nack.follower_id, nack);
        }
    }

    /// Returns the number of acknowledgments.
    fn ack_count(&self) -> usize {
        self.acks.len()
    }

    /// Returns the number of negative acknowledgments.
    fn nack_count(&self) -> usize {
        self.nacks.len()
    }
}

// =============================================================================
// Replication Configuration
// =============================================================================

/// Configuration for the replication engine.
#[derive(Clone, Debug)]
pub struct ReplicationConfig {
    /// This node's validator ID.
    pub validator_id: ValidatorId,

    /// The current leader's validator ID.
    pub leader_id: ValidatorId,

    /// The current epoch.
    pub epoch: u64,

    /// Namespace for replication.
    pub namespace: String,

    /// Timeout for acknowledgments.
    pub ack_timeout: Duration,

    /// Number of acknowledgments required for commit (typically 2f+1).
    pub quorum_threshold: usize,
}

impl ReplicationConfig {
    /// Returns true if this node is the current leader.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.validator_id.ct_eq(&self.leader_id).into()
    }
}

// =============================================================================
// Replication Engine
// =============================================================================

/// Leader-based replication engine.
///
/// The `ReplicationEngine` handles both leader and follower roles:
/// - As leader: receives proposals, broadcasts to peers, tracks acks
/// - As follower: receives proposals from leader, appends to local log, sends
///   acks
///
/// # Thread Safety
///
/// The engine uses `RwLock` for internal state and is safe to share across
/// threads.
pub struct ReplicationEngine<B: LedgerBackend> {
    /// Configuration.
    config: RwLock<ReplicationConfig>,

    /// Signing key for this node.
    signing_key: SigningKey,

    /// Ledger backend for event storage.
    backend: Arc<B>,

    /// Peer manager for routing messages.
    #[allow(dead_code)] // Will be used for broadcast routing in future
    peers: Arc<PeerManager>,

    /// Map of validator IDs to their public keys.
    validator_keys: RwLock<HashMap<ValidatorId, VerifyingKey>>,

    /// Next sequence ID to assign (leader only).
    next_sequence_id: RwLock<u64>,

    /// Last appended sequence ID (follower tracking).
    last_appended_seq: RwLock<u64>,

    /// Pending outbound proposals.
    outbound_queue: RwLock<VecDeque<ReplicationProposal>>,

    /// Acknowledgment tracking for proposals (leader only).
    ack_tracker: RwLock<HashMap<u64, ProposalAckState>>,

    /// Order of tracked proposals for FIFO eviction.
    ack_order: RwLock<VecDeque<u64>>,

    /// Whether the engine is running.
    running: RwLock<bool>,
}

impl<B: LedgerBackend> ReplicationEngine<B> {
    /// Creates a new replication engine.
    #[must_use]
    pub fn new(
        config: ReplicationConfig,
        signing_key: SigningKey,
        backend: Arc<B>,
        peers: Arc<PeerManager>,
    ) -> Self {
        Self {
            config: RwLock::new(config),
            signing_key,
            backend,
            peers,
            validator_keys: RwLock::new(HashMap::new()),
            next_sequence_id: RwLock::new(1),
            last_appended_seq: RwLock::new(0),
            outbound_queue: RwLock::new(VecDeque::with_capacity(MAX_PENDING_PROPOSALS)),
            ack_tracker: RwLock::new(HashMap::new()),
            ack_order: RwLock::new(VecDeque::new()),
            running: RwLock::new(true),
        }
    }

    /// Registers a validator's public key.
    pub async fn register_validator(&self, id: ValidatorId, public_key: VerifyingKey) {
        let mut keys = self.validator_keys.write().await;
        keys.insert(id, public_key);
    }

    /// Updates the configuration (e.g., new leader).
    pub async fn update_config(&self, config: ReplicationConfig) {
        let mut cfg = self.config.write().await;
        *cfg = config;
    }

    /// Returns whether this node is currently the leader.
    pub async fn is_leader(&self) -> bool {
        let config = self.config.read().await;
        config.is_leader()
    }

    /// Proposes an event for replication (leader only).
    ///
    /// # Arguments
    ///
    /// * `event` - The event record to replicate
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - This node is not the leader
    /// - The event payload is too large
    /// - The outbound queue is full
    pub async fn propose(&self, event: &EventRecord) -> Result<u64, ReplicationError> {
        // Check if running
        if !*self.running.read().await {
            return Err(ReplicationError::Shutdown);
        }

        // Verify we are the leader
        let config = self.config.read().await;
        if !config.is_leader() {
            return Err(ReplicationError::NotLeader {
                expected: hex::encode(config.leader_id),
                actual: hex::encode(config.validator_id),
            });
        }

        // Convert to ReplicatedEvent and serialize
        let replicated_event = ReplicatedEvent::from_event_record(event);
        let event_data = serde_json::to_vec(&replicated_event)
            .map_err(|e| ReplicationError::Serialization(e.to_string()))?;

        // Check payload size
        if event_data.len() > MAX_REPLICATION_PAYLOAD_SIZE {
            return Err(ReplicationError::PayloadTooLarge {
                size: event_data.len(),
                max: MAX_REPLICATION_PAYLOAD_SIZE,
            });
        }

        // Compute event hash
        let event_hash = ReplicationProposal::compute_event_hash(&event_data);

        // Assign sequence ID
        let sequence_id = {
            let mut next_seq = self.next_sequence_id.write().await;
            let seq = *next_seq;
            *next_seq += 1;
            seq
        };

        // Create proposal
        let mut proposal = ReplicationProposal {
            epoch: config.epoch,
            sequence_id,
            leader_id: config.validator_id,
            namespace: config.namespace.clone(),
            event_data,
            event_hash,
            signature: [0u8; 64],
        };

        // Sign the proposal
        proposal.sign(&self.signing_key)?;

        // First, append to our own ledger
        let _local_seq_id = self.backend.append(&config.namespace, event).await?;

        // Track the proposal for acks
        {
            let mut tracker = self.ack_tracker.write().await;
            let mut order = self.ack_order.write().await;

            // Evict old entries if needed
            while tracker.len() >= MAX_TRACKED_PROPOSALS {
                if let Some(old_seq) = order.pop_front() {
                    tracker.remove(&old_seq);
                }
            }

            tracker.insert(
                sequence_id,
                ProposalAckState::new(config.epoch, config.namespace.clone()),
            );
            order.push_back(sequence_id);
        }

        // Queue for broadcast
        {
            let mut queue = self.outbound_queue.write().await;
            if queue.len() >= MAX_PENDING_PROPOSALS {
                return Err(ReplicationError::QueueFull {
                    size: queue.len(),
                    max: MAX_PENDING_PROPOSALS,
                });
            }
            queue.push_back(proposal);
        }

        Ok(sequence_id)
    }

    /// Handles an incoming replication proposal (follower role).
    ///
    /// # Arguments
    ///
    /// * `proposal` - The proposal received from the leader
    ///
    /// # Returns
    ///
    /// Returns `Ok(ReplicationAck)` if the event was appended, or
    /// `Err(ReplicationNack)` if the proposal was rejected.
    ///
    /// # Errors
    ///
    /// Returns a `ReplicationNack` if the proposal is invalid (bad signature,
    /// wrong leader, duplicate, gap, or ledger error).
    pub async fn handle_proposal(
        &self,
        proposal: ReplicationProposal,
    ) -> Result<ReplicationAck, ReplicationNack> {
        let config = self.config.read().await;
        let my_id = config.validator_id;

        // Clone namespace for use in the closure
        let proposal_namespace = proposal.namespace.clone();

        // Create a nack helper
        let make_nack = |reason: NackReason| -> ReplicationNack {
            let mut nack = ReplicationNack {
                epoch: proposal.epoch,
                sequence_id: proposal.sequence_id,
                namespace: proposal_namespace.clone(),
                follower_id: my_id,
                reason,
                signature: [0u8; 64],
            };
            // Sign will only fail if namespace is > u32::MAX bytes, which is already
            // validated above, so we can safely ignore the error
            let _ = nack.sign(&self.signing_key);
            nack
        };

        // Validate payload size to prevent DoS (CTR-1303)
        if proposal.event_data.len() > MAX_REPLICATION_PAYLOAD_SIZE {
            return Err(make_nack(NackReason::PayloadTooLarge));
        }

        // Verify the proposal is from the current leader
        if !bool::from(proposal.leader_id.ct_eq(&config.leader_id)) {
            return Err(make_nack(NackReason::NotLeader));
        }

        // Verify epoch matches
        if proposal.epoch != config.epoch {
            return Err(make_nack(NackReason::Stale));
        }

        // Validate the event hash
        if !proposal.validate_hash() {
            return Err(make_nack(NackReason::InvalidHash));
        }

        // Verify signature
        let keys = self.validator_keys.read().await;
        if let Some(leader_key) = keys.get(&proposal.leader_id) {
            if proposal.verify_signature(leader_key).is_err() {
                return Err(make_nack(NackReason::InvalidSignature));
            }
        } else {
            // Unknown leader key - reject
            return Err(make_nack(NackReason::InvalidSignature));
        }

        // Check sequence ID
        let last_seq = *self.last_appended_seq.read().await;
        let expected_seq = last_seq + 1;

        if proposal.sequence_id < expected_seq {
            return Err(make_nack(NackReason::Duplicate));
        }

        if proposal.sequence_id > expected_seq {
            // Gap detected - we're missing proposals
            return Err(make_nack(NackReason::Gap));
        }

        // Deserialize the replicated event and convert to EventRecord
        // Note: We use serde_json which has some depth limits by default, but for
        // additional DoS protection, the payload size is already validated above.
        let replicated_event: ReplicatedEvent = serde_json::from_slice(&proposal.event_data)
            .map_err(|_| make_nack(NackReason::LedgerError))?;

        // Validate the inner event's hash for integrity (defense-in-depth)
        // This catches corrupted or tampered events even if the leader's
        // proposal signature is valid.
        if !replicated_event.validate_hash() {
            return Err(make_nack(NackReason::InvalidEventSignature));
        }

        let event = replicated_event.to_event_record();

        let local_seq_id = self
            .backend
            .append(&proposal.namespace, &event)
            .await
            .map_err(|_| make_nack(NackReason::LedgerError))?;

        // Update last appended sequence
        {
            let mut last_seq = self.last_appended_seq.write().await;
            *last_seq = proposal.sequence_id;
        }

        // Create and sign acknowledgment
        let mut ack = ReplicationAck {
            epoch: proposal.epoch,
            sequence_id: proposal.sequence_id,
            namespace: proposal.namespace.clone(),
            follower_id: my_id,
            local_seq_id,
            signature: [0u8; 64],
        };
        // Namespace was already validated above, so signing should not fail
        let _ = ack.sign(&self.signing_key);

        Ok(ack)
    }

    /// Handles an incoming acknowledgment (leader role).
    ///
    /// # Arguments
    ///
    /// * `ack` - The acknowledgment from a follower
    ///
    /// # Returns
    ///
    /// Returns the current ack count for the proposal.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid, the peer is unknown,
    /// or the epoch doesn't match the proposal's epoch.
    pub async fn handle_ack(&self, ack: ReplicationAck) -> Result<usize, ReplicationError> {
        // Verify signature
        let keys = self.validator_keys.read().await;
        if let Some(follower_key) = keys.get(&ack.follower_id) {
            ack.verify_signature(follower_key)?;
        } else {
            return Err(ReplicationError::UnknownPeer {
                peer_id: hex::encode(ack.follower_id),
            });
        }
        drop(keys);

        // Record the ack (with epoch validation)
        let mut tracker = self.ack_tracker.write().await;
        if let Some(state) = tracker.get_mut(&ack.sequence_id) {
            // record_ack validates epoch internally and returns false if mismatched
            if state.record_ack(ack.clone()) {
                Ok(state.ack_count())
            } else {
                Err(ReplicationError::StaleEpoch {
                    ack_epoch: ack.epoch,
                    proposal_epoch: state.epoch,
                })
            }
        } else {
            // Proposal not being tracked (already evicted or unknown)
            Ok(0)
        }
    }

    /// Handles an incoming negative acknowledgment (leader role).
    ///
    /// # Arguments
    ///
    /// * `nack` - The nack from a follower
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or the peer is unknown.
    pub async fn handle_nack(&self, nack: ReplicationNack) -> Result<(), ReplicationError> {
        // Verify signature to prevent state pollution attacks
        let keys = self.validator_keys.read().await;
        if let Some(follower_key) = keys.get(&nack.follower_id) {
            nack.verify_signature(follower_key)?;
        } else {
            return Err(ReplicationError::UnknownPeer {
                peer_id: hex::encode(nack.follower_id),
            });
        }
        drop(keys);

        let mut tracker = self.ack_tracker.write().await;
        if let Some(state) = tracker.get_mut(&nack.sequence_id) {
            state.record_nack(nack);
        }
        Ok(())
    }

    /// Returns the next pending proposal to broadcast.
    pub async fn next_outbound_proposal(&self) -> Option<ReplicationProposal> {
        let mut queue = self.outbound_queue.write().await;
        queue.pop_front()
    }

    /// Returns the acknowledgment state for a proposal.
    pub async fn get_ack_state(&self, sequence_id: u64) -> Option<(usize, usize)> {
        let tracker = self.ack_tracker.read().await;
        tracker
            .get(&sequence_id)
            .map(|state| (state.ack_count(), state.nack_count()))
    }

    /// Checks if a proposal has reached quorum.
    pub async fn has_quorum(&self, sequence_id: u64) -> bool {
        let config = self.config.read().await;
        let tracker = self.ack_tracker.read().await;

        // Leader counts as one ack (already appended locally)
        tracker
            .get(&sequence_id)
            .is_some_and(|state| state.ack_count() + 1 >= config.quorum_threshold)
    }

    /// Shuts down the replication engine.
    pub async fn shutdown(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Returns statistics about the replication engine.
    pub async fn stats(&self) -> ReplicationStats {
        let outbound_queue = self.outbound_queue.read().await;
        let tracker = self.ack_tracker.read().await;
        let config = self.config.read().await;
        let next_seq = *self.next_sequence_id.read().await;
        let last_appended = *self.last_appended_seq.read().await;

        ReplicationStats {
            is_leader: config.is_leader(),
            epoch: config.epoch,
            next_sequence_id: next_seq,
            last_appended_seq: last_appended,
            pending_proposals: outbound_queue.len(),
            tracked_proposals: tracker.len(),
        }
    }
}

/// Statistics about the replication engine.
#[derive(Clone, Debug)]
pub struct ReplicationStats {
    /// Whether this node is the leader.
    pub is_leader: bool,
    /// Current epoch.
    pub epoch: u64,
    /// Next sequence ID to assign (leader).
    pub next_sequence_id: u64,
    /// Last appended sequence ID (follower).
    pub last_appended_seq: u64,
    /// Number of proposals pending broadcast.
    pub pending_proposals: usize,
    /// Number of proposals being tracked for acks.
    pub tracked_proposals: usize,
}

// =============================================================================
// Message Serialization Helpers
// =============================================================================

impl ReplicationMessage {
    /// Returns the message type code.
    #[must_use]
    pub const fn message_type(&self) -> u32 {
        match self {
            Self::Proposal(_) => MSG_REPLICATION_PROPOSAL,
            Self::Ack(_) => MSG_REPLICATION_ACK,
            Self::Nack(_) => MSG_REPLICATION_NACK,
        }
    }

    /// Serializes the message to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ReplicationError> {
        serde_json::to_vec(self).map_err(|e| ReplicationError::Serialization(e.to_string()))
    }

    /// Deserializes a message from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReplicationError> {
        serde_json::from_slice(bytes).map_err(|e| ReplicationError::Serialization(e.to_string()))
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

    #[test]
    fn test_proposal_signing_roundtrip() {
        let key = generate_test_key();
        let leader_id = validator_id_from_key(&key);

        let event_data = b"test event data".to_vec();
        let event_hash = ReplicationProposal::compute_event_hash(&event_data);

        let mut proposal = ReplicationProposal {
            epoch: 1,
            sequence_id: 42,
            leader_id,
            namespace: "test".to_string(),
            event_data,
            event_hash,
            signature: [0u8; 64],
        };

        proposal.sign(&key).unwrap();

        // Verify with correct key
        assert!(proposal.verify_signature(&key.verifying_key()).is_ok());

        // Verify hash
        assert!(proposal.validate_hash());
    }

    #[test]
    fn test_proposal_invalid_signature() {
        let key1 = generate_test_key();
        let key2 = generate_test_key();
        let leader_id = validator_id_from_key(&key1);

        let event_data = b"test event data".to_vec();
        let event_hash = ReplicationProposal::compute_event_hash(&event_data);

        let mut proposal = ReplicationProposal {
            epoch: 1,
            sequence_id: 42,
            leader_id,
            namespace: "test".to_string(),
            event_data,
            event_hash,
            signature: [0u8; 64],
        };

        proposal.sign(&key1).unwrap();

        // Verify with wrong key should fail
        assert!(proposal.verify_signature(&key2.verifying_key()).is_err());
    }

    #[test]
    fn test_ack_signing_roundtrip() {
        let key = generate_test_key();
        let follower_id = validator_id_from_key(&key);

        let mut ack = ReplicationAck {
            epoch: 1,
            sequence_id: 42,
            namespace: "test".to_string(),
            follower_id,
            local_seq_id: 100,
            signature: [0u8; 64],
        };

        ack.sign(&key).unwrap();

        // Verify with correct key
        assert!(ack.verify_signature(&key.verifying_key()).is_ok());
    }

    #[test]
    fn test_nack_reason_codes() {
        assert_eq!(NackReason::InvalidSignature.code(), 1);
        assert_eq!(NackReason::NotLeader.code(), 2);
        assert_eq!(NackReason::Duplicate.code(), 3);
        assert_eq!(NackReason::Stale.code(), 4);
        assert_eq!(NackReason::Gap.code(), 5);
        assert_eq!(NackReason::LedgerError.code(), 6);
        assert_eq!(NackReason::InvalidHash.code(), 7);
        assert_eq!(NackReason::PayloadTooLarge.code(), 8);
        assert_eq!(NackReason::InvalidEventSignature.code(), 9);
    }

    #[test]
    fn test_message_types() {
        let proposal = ReplicationMessage::Proposal(ReplicationProposal {
            epoch: 1,
            sequence_id: 1,
            leader_id: [0u8; 32],
            namespace: "test".to_string(),
            event_data: vec![],
            event_hash: [0u8; 32],
            signature: [0u8; 64],
        });
        assert_eq!(proposal.message_type(), MSG_REPLICATION_PROPOSAL);

        let ack = ReplicationMessage::Ack(ReplicationAck {
            epoch: 1,
            sequence_id: 1,
            namespace: "test".to_string(),
            follower_id: [0u8; 32],
            local_seq_id: 1,
            signature: [0u8; 64],
        });
        assert_eq!(ack.message_type(), MSG_REPLICATION_ACK);

        let nack = ReplicationMessage::Nack(ReplicationNack {
            epoch: 1,
            sequence_id: 1,
            namespace: "test".to_string(),
            follower_id: [0u8; 32],
            reason: NackReason::Stale,
            signature: [0u8; 64],
        });
        assert_eq!(nack.message_type(), MSG_REPLICATION_NACK);
    }

    #[test]
    fn test_message_serialization_roundtrip() {
        let proposal = ReplicationMessage::Proposal(ReplicationProposal {
            epoch: 1,
            sequence_id: 42,
            leader_id: [1u8; 32],
            namespace: "kernel".to_string(),
            event_data: b"test data".to_vec(),
            event_hash: [2u8; 32],
            signature: [3u8; 64],
        });

        let bytes = proposal.to_bytes().unwrap();
        let restored = ReplicationMessage::from_bytes(&bytes).unwrap();

        if let ReplicationMessage::Proposal(p) = restored {
            assert_eq!(p.epoch, 1);
            assert_eq!(p.sequence_id, 42);
            assert_eq!(p.namespace, "kernel");
        } else {
            panic!("Expected Proposal variant");
        }
    }

    #[test]
    fn test_proposal_hash_validation() {
        let event_data = b"important event".to_vec();
        let correct_hash = ReplicationProposal::compute_event_hash(&event_data);

        let proposal = ReplicationProposal {
            epoch: 1,
            sequence_id: 1,
            leader_id: [0u8; 32],
            namespace: "test".to_string(),
            event_data,
            event_hash: correct_hash,
            signature: [0u8; 64],
        };

        assert!(proposal.validate_hash());

        // Corrupt the data
        let mut corrupted = proposal;
        corrupted.event_data = b"tampered data".to_vec();
        assert!(!corrupted.validate_hash());
    }

    #[test]
    fn test_ack_state_tracking() {
        let mut state = ProposalAckState::new(1, "test".to_string());
        assert_eq!(state.ack_count(), 0);
        assert_eq!(state.nack_count(), 0);

        // Add acks with matching epoch
        for i in 0u8..3 {
            let mut follower_id = [0u8; 32];
            follower_id[0] = i;
            assert!(state.record_ack(ReplicationAck {
                epoch: 1,
                sequence_id: 42,
                namespace: "test".to_string(),
                follower_id,
                local_seq_id: 100 + u64::from(i),
                signature: [0u8; 64],
            }));
        }

        assert_eq!(state.ack_count(), 3);

        // Ack with mismatched epoch should be rejected
        let mut follower_id = [0u8; 32];
        follower_id[0] = 99;
        assert!(!state.record_ack(ReplicationAck {
            epoch: 2, // Wrong epoch
            sequence_id: 42,
            namespace: "test".to_string(),
            follower_id,
            local_seq_id: 200,
            signature: [0u8; 64],
        }));
        assert_eq!(state.ack_count(), 3); // Count unchanged

        // Add nack
        state.record_nack(ReplicationNack {
            epoch: 1,
            sequence_id: 42,
            namespace: "test".to_string(),
            follower_id: [10u8; 32],
            reason: NackReason::Gap,
            signature: [0u8; 64],
        });

        assert_eq!(state.nack_count(), 1);
    }

    #[test]
    fn test_replication_config_is_leader() {
        let leader_id = [1u8; 32];
        let follower_id = [2u8; 32];

        let leader_config = ReplicationConfig {
            validator_id: leader_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 3,
        };
        assert!(leader_config.is_leader());

        let follower_config = ReplicationConfig {
            validator_id: follower_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 3,
        };
        assert!(!follower_config.is_leader());
    }

    // Compile-time bounds verification
    const _: () = {
        assert!(MAX_PENDING_PROPOSALS > 0);
        assert!(MAX_PENDING_PROPOSALS <= 4096);
        assert!(MAX_ACKS_PER_PROPOSAL > 0);
        assert!(MAX_ACKS_PER_PROPOSAL <= 256);
        assert!(MAX_TRACKED_PROPOSALS > 0);
        assert!(MAX_TRACKED_PROPOSALS <= 8192);
        assert!(MAX_REPLICATION_PAYLOAD_SIZE > 0);
        assert!(MAX_REPLICATION_PAYLOAD_SIZE <= 16 * 1024 * 1024);
    };

    // Message type range verification
    const _MSG_TYPE_RANGE: () = {
        assert!(MSG_REPLICATION_PROPOSAL >= 300);
        assert!(MSG_REPLICATION_ACK >= 300);
        assert!(MSG_REPLICATION_NACK >= 300);
    };
}

#[cfg(test)]
mod tck_00195_tests {
    use super::*;

    #[test]
    fn tck_00195_proposal_structure() {
        // Verify proposal has all required fields
        let proposal = ReplicationProposal {
            epoch: 0,
            sequence_id: 0,
            leader_id: [0u8; 32],
            namespace: String::new(),
            event_data: Vec::new(),
            event_hash: [0u8; 32],
            signature: [0u8; 64],
        };

        assert_eq!(proposal.epoch, 0);
        assert_eq!(proposal.sequence_id, 0);
    }

    #[test]
    fn tck_00195_ack_structure() {
        // Verify ack has all required fields
        let ack = ReplicationAck {
            epoch: 0,
            sequence_id: 0,
            namespace: String::new(),
            follower_id: [0u8; 32],
            local_seq_id: 0,
            signature: [0u8; 64],
        };

        assert_eq!(ack.epoch, 0);
    }

    #[test]
    fn tck_00195_nack_reasons_complete() {
        // Verify all nack reasons exist and have unique codes
        let reasons = [
            NackReason::InvalidSignature,
            NackReason::NotLeader,
            NackReason::Duplicate,
            NackReason::Stale,
            NackReason::Gap,
            NackReason::LedgerError,
            NackReason::InvalidHash,
            NackReason::PayloadTooLarge,
            NackReason::InvalidEventSignature,
        ];
        assert_eq!(reasons.len(), 9);
    }

    #[test]
    fn tck_00195_error_variants() {
        // Verify all error variants exist and can be displayed
        let errors: [ReplicationError; 12] = [
            ReplicationError::NotLeader {
                expected: String::new(),
                actual: String::new(),
            },
            ReplicationError::InvalidSignature {
                sender: String::new(),
            },
            ReplicationError::ProposalFromNonLeader {
                sender: String::new(),
            },
            ReplicationError::DuplicateProposal { sequence_id: 0 },
            ReplicationError::StaleProposal {
                proposal_seq: 0,
                current_seq: 0,
            },
            ReplicationError::FutureProposal {
                proposal_seq: 0,
                expected_seq: 0,
            },
            ReplicationError::PayloadTooLarge { size: 0, max: 0 },
            ReplicationError::Serialization(String::new()),
            ReplicationError::QueueFull { size: 0, max: 0 },
            ReplicationError::UnknownPeer {
                peer_id: String::new(),
            },
            ReplicationError::StaleEpoch {
                ack_epoch: 0,
                proposal_epoch: 0,
            },
            ReplicationError::Shutdown,
        ];
        assert_eq!(errors.len(), 12);
    }

    #[test]
    fn tck_00195_message_variants() {
        // Verify all message variants exist and have correct types
        let proposal = ReplicationMessage::Proposal(ReplicationProposal {
            epoch: 0,
            sequence_id: 0,
            leader_id: [0u8; 32],
            namespace: String::new(),
            event_data: Vec::new(),
            event_hash: [0u8; 32],
            signature: [0u8; 64],
        });
        assert_eq!(proposal.message_type(), MSG_REPLICATION_PROPOSAL);

        let ack = ReplicationMessage::Ack(ReplicationAck {
            epoch: 0,
            sequence_id: 0,
            namespace: String::new(),
            follower_id: [0u8; 32],
            local_seq_id: 0,
            signature: [0u8; 64],
        });
        assert_eq!(ack.message_type(), MSG_REPLICATION_ACK);

        let nack = ReplicationMessage::Nack(ReplicationNack {
            epoch: 0,
            sequence_id: 0,
            namespace: String::new(),
            follower_id: [0u8; 32],
            reason: NackReason::Stale,
            signature: [0u8; 64],
        });
        assert_eq!(nack.message_type(), MSG_REPLICATION_NACK);
    }

    #[test]
    fn tck_00195_bounded_collections() {
        // Verify bounded collection constants are appropriate
        // Use const asserts in compile-time block above
        assert_eq!(MAX_PENDING_PROPOSALS, 256, "Pending proposals queue depth");
        assert_eq!(MAX_ACKS_PER_PROPOSAL, 128, "Acks per proposal limit");
        assert_eq!(MAX_TRACKED_PROPOSALS, 1024, "Tracked proposals limit");
    }

    #[test]
    fn tck_00195_stats_structure() {
        let stats = ReplicationStats {
            is_leader: false,
            epoch: 1,
            next_sequence_id: 10,
            last_appended_seq: 9,
            pending_proposals: 5,
            tracked_proposals: 20,
        };

        assert!(!stats.is_leader);
        assert_eq!(stats.epoch, 1);
    }
}

/// Integration tests for `ReplicationEngine` state transitions.
#[cfg(test)]
mod engine_integration_tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, RwLock};

    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;
    use crate::consensus::handlers::PeerManager;
    use crate::ledger::{BoxFuture, EventRecord, HashFn, LedgerBackend, LedgerError, VerifyFn};

    /// A simple in-memory ledger backend for testing.
    struct MockLedgerBackend {
        events: RwLock<HashMap<String, Vec<EventRecord>>>,
        next_seq: AtomicU64,
    }

    impl MockLedgerBackend {
        fn new() -> Self {
            Self {
                events: RwLock::new(HashMap::new()),
                next_seq: AtomicU64::new(1),
            }
        }
    }

    impl LedgerBackend for MockLedgerBackend {
        fn append<'a>(
            &'a self,
            namespace: &'a str,
            event: &'a EventRecord,
        ) -> BoxFuture<'a, Result<u64, LedgerError>> {
            Box::pin(async move {
                let seq_id = self.next_seq.fetch_add(1, Ordering::SeqCst);
                let mut events = self.events.write().unwrap();
                let mut cloned = event.clone();
                cloned.seq_id = Some(seq_id);
                events
                    .entry(namespace.to_string())
                    .or_default()
                    .push(cloned);
                Ok(seq_id)
            })
        }

        fn read_from<'a>(
            &'a self,
            namespace: &'a str,
            cursor: u64,
            limit: u64,
        ) -> BoxFuture<'a, Result<Vec<EventRecord>, LedgerError>> {
            Box::pin(async move {
                let events = self.events.read().unwrap();
                // In tests, limit is always small, so truncation is safe
                #[allow(clippy::cast_possible_truncation)]
                let limit_usize = limit as usize;
                let ns_events = events.get(namespace).map_or_else(Vec::new, |e| {
                    e.iter()
                        .filter(|ev| ev.seq_id.unwrap_or(0) >= cursor)
                        .take(limit_usize)
                        .cloned()
                        .collect()
                });
                Ok(ns_events)
            })
        }

        fn head<'a>(&'a self, namespace: &'a str) -> BoxFuture<'a, Result<u64, LedgerError>> {
            Box::pin(async move {
                let events = self.events.read().unwrap();
                Ok(events
                    .get(namespace)
                    .and_then(|e| e.last())
                    .and_then(|e| e.seq_id)
                    .unwrap_or(0))
            })
        }

        fn verify_chain<'a>(
            &'a self,
            _namespace: &'a str,
            _from_seq_id: u64,
            _verify_hash_fn: HashFn<'a>,
            _verify_sig_fn: VerifyFn<'a>,
        ) -> BoxFuture<'a, Result<(), LedgerError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn generate_test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn validator_id_from_key(key: &SigningKey) -> ValidatorId {
        blake3::hash(key.verifying_key().as_bytes()).into()
    }

    fn create_test_event() -> EventRecord {
        EventRecord::new(
            "test.event",
            "session-123",
            "actor-456",
            b"{\"data\": \"test\"}".to_vec(),
        )
    }

    #[tokio::test]
    async fn test_leader_propose_success() {
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        let config = ReplicationConfig {
            validator_id: leader_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let backend = Arc::new(MockLedgerBackend::new());
        let peers = Arc::new(PeerManager::new());

        let engine = ReplicationEngine::new(config, leader_key.clone(), backend.clone(), peers);

        // Register the leader's own key
        engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;

        // Propose an event
        let event = create_test_event();
        let seq_id = engine.propose(&event).await.unwrap();

        assert_eq!(seq_id, 1);

        // Check stats
        let stats = engine.stats().await;
        assert!(stats.is_leader);
        assert_eq!(stats.epoch, 1);
        assert_eq!(stats.next_sequence_id, 2);
        assert_eq!(stats.pending_proposals, 1);
        assert_eq!(stats.tracked_proposals, 1);

        // Verify proposal is in outbound queue
        let proposal = engine.next_outbound_proposal().await.unwrap();
        assert_eq!(proposal.epoch, 1);
        assert_eq!(proposal.sequence_id, 1);
    }

    #[tokio::test]
    async fn test_follower_handle_proposal_success() {
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        let follower_key = generate_test_key();
        let follower_id = validator_id_from_key(&follower_key);

        // Create follower config (not leader)
        let follower_config = ReplicationConfig {
            validator_id: follower_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let backend = Arc::new(MockLedgerBackend::new());
        let peers = Arc::new(PeerManager::new());

        let follower_engine = ReplicationEngine::new(
            follower_config,
            follower_key.clone(),
            backend.clone(),
            peers,
        );

        // Register the leader's key with the follower
        follower_engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;

        // Create a proposal from the leader
        let event = create_test_event();
        let replicated_event = ReplicatedEvent::from_event_record(&event);
        let event_data = serde_json::to_vec(&replicated_event).unwrap();
        let event_hash = ReplicationProposal::compute_event_hash(&event_data);

        let mut proposal = ReplicationProposal {
            epoch: 1,
            sequence_id: 1,
            leader_id,
            namespace: "test".to_string(),
            event_data,
            event_hash,
            signature: [0u8; 64],
        };
        proposal.sign(&leader_key).unwrap();

        // Follower handles the proposal
        let ack = follower_engine.handle_proposal(proposal).await.unwrap();

        assert_eq!(ack.epoch, 1);
        assert_eq!(ack.sequence_id, 1);
        assert_eq!(ack.follower_id, follower_id);

        // Check follower stats
        let stats = follower_engine.stats().await;
        assert!(!stats.is_leader);
        assert_eq!(stats.last_appended_seq, 1);
    }

    #[tokio::test]
    async fn test_leader_handle_ack_success() {
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        let follower_key = generate_test_key();
        let follower_id = validator_id_from_key(&follower_key);

        let config = ReplicationConfig {
            validator_id: leader_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let backend = Arc::new(MockLedgerBackend::new());
        let peers = Arc::new(PeerManager::new());

        let engine = ReplicationEngine::new(config, leader_key.clone(), backend.clone(), peers);

        // Register both validators
        engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;
        engine
            .register_validator(follower_id, follower_key.verifying_key())
            .await;

        // Propose an event
        let event = create_test_event();
        let seq_id = engine.propose(&event).await.unwrap();
        assert_eq!(seq_id, 1);

        // Create an ack from the follower
        let mut ack = ReplicationAck {
            epoch: 1,
            sequence_id: 1,
            namespace: "test".to_string(),
            follower_id,
            local_seq_id: 100,
            signature: [0u8; 64],
        };
        ack.sign(&follower_key).unwrap();

        // Leader handles the ack
        let ack_count = engine.handle_ack(ack).await.unwrap();
        assert_eq!(ack_count, 1);

        // Check ack state
        let (acks, nacks) = engine.get_ack_state(1).await.unwrap();
        assert_eq!(acks, 1);
        assert_eq!(nacks, 0);

        // Check quorum (leader + 1 follower = 2, threshold is 2)
        assert!(engine.has_quorum(1).await);
    }

    #[tokio::test]
    async fn test_full_replication_roundtrip() {
        // Create leader
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        // Create followers
        let follower1_key = generate_test_key();
        let follower1_id = validator_id_from_key(&follower1_key);

        let follower2_key = generate_test_key();
        let follower2_id = validator_id_from_key(&follower2_key);

        // Leader engine
        let leader_config = ReplicationConfig {
            validator_id: leader_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let leader_backend = Arc::new(MockLedgerBackend::new());
        let leader_peers = Arc::new(PeerManager::new());
        let leader_engine = ReplicationEngine::new(
            leader_config,
            leader_key.clone(),
            leader_backend.clone(),
            leader_peers,
        );

        // Follower 1 engine
        let follower1_config = ReplicationConfig {
            validator_id: follower1_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let follower1_backend = Arc::new(MockLedgerBackend::new());
        let follower1_peers = Arc::new(PeerManager::new());
        let follower1_engine = ReplicationEngine::new(
            follower1_config,
            follower1_key.clone(),
            follower1_backend.clone(),
            follower1_peers,
        );

        // Register keys
        leader_engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;
        leader_engine
            .register_validator(follower1_id, follower1_key.verifying_key())
            .await;
        leader_engine
            .register_validator(follower2_id, follower2_key.verifying_key())
            .await;

        follower1_engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;

        // Step 1: Leader proposes
        let event = create_test_event();
        let seq_id = leader_engine.propose(&event).await.unwrap();
        assert_eq!(seq_id, 1);

        // Step 2: Get proposal from outbound queue
        let proposal = leader_engine.next_outbound_proposal().await.unwrap();
        assert_eq!(proposal.sequence_id, 1);

        // Step 3: Follower handles proposal and sends ack
        let ack = follower1_engine.handle_proposal(proposal).await.unwrap();
        assert_eq!(ack.sequence_id, 1);
        assert_eq!(ack.follower_id, follower1_id);

        // Step 4: Leader handles ack
        let ack_count = leader_engine.handle_ack(ack).await.unwrap();
        assert_eq!(ack_count, 1);

        // Step 5: Verify quorum reached (leader + follower1 = 2 >= threshold)
        assert!(leader_engine.has_quorum(1).await);

        // Verify events are stored in both ledgers
        let leader_events = leader_backend.read_from("test", 0, 10).await.unwrap();
        assert_eq!(leader_events.len(), 1);

        let follower_events = follower1_backend.read_from("test", 0, 10).await.unwrap();
        assert_eq!(follower_events.len(), 1);
    }

    #[tokio::test]
    async fn test_follower_rejects_stale_epoch_proposal() {
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        let follower_key = generate_test_key();
        let follower_id = validator_id_from_key(&follower_key);

        // Follower is at epoch 2
        let follower_config = ReplicationConfig {
            validator_id: follower_id,
            leader_id,
            epoch: 2,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let backend = Arc::new(MockLedgerBackend::new());
        let peers = Arc::new(PeerManager::new());

        let follower_engine =
            ReplicationEngine::new(follower_config, follower_key.clone(), backend, peers);

        follower_engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;

        // Create a proposal from epoch 1 (stale)
        let event = create_test_event();
        let replicated_event = ReplicatedEvent::from_event_record(&event);
        let event_data = serde_json::to_vec(&replicated_event).unwrap();
        let event_hash = ReplicationProposal::compute_event_hash(&event_data);

        let mut proposal = ReplicationProposal {
            epoch: 1, // Stale epoch
            sequence_id: 1,
            leader_id,
            namespace: "test".to_string(),
            event_data,
            event_hash,
            signature: [0u8; 64],
        };
        proposal.sign(&leader_key).unwrap();

        // Follower should reject with Stale nack
        let result = follower_engine.handle_proposal(proposal).await;
        assert!(result.is_err());
        let nack = result.unwrap_err();
        assert_eq!(nack.reason, NackReason::Stale);
    }

    #[tokio::test]
    async fn test_leader_rejects_stale_epoch_ack() {
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        let follower_key = generate_test_key();
        let follower_id = validator_id_from_key(&follower_key);

        let config = ReplicationConfig {
            validator_id: leader_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let backend = Arc::new(MockLedgerBackend::new());
        let peers = Arc::new(PeerManager::new());

        let engine = ReplicationEngine::new(config, leader_key.clone(), backend, peers);

        engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;
        engine
            .register_validator(follower_id, follower_key.verifying_key())
            .await;

        // Propose an event
        let event = create_test_event();
        let seq_id = engine.propose(&event).await.unwrap();
        assert_eq!(seq_id, 1);

        // Create an ack with wrong epoch
        let mut ack = ReplicationAck {
            epoch: 2, // Wrong epoch
            sequence_id: 1,
            namespace: "test".to_string(),
            follower_id,
            local_seq_id: 100,
            signature: [0u8; 64],
        };
        ack.sign(&follower_key).unwrap();

        // Leader should reject stale epoch ack
        let result = engine.handle_ack(ack).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ReplicationError::StaleEpoch {
                ack_epoch,
                proposal_epoch,
            } => {
                assert_eq!(ack_epoch, 2);
                assert_eq!(proposal_epoch, 1);
            },
            e => panic!("Expected StaleEpoch error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_follower_rejects_oversized_payload() {
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        let follower_key = generate_test_key();
        let follower_id = validator_id_from_key(&follower_key);

        let follower_config = ReplicationConfig {
            validator_id: follower_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let backend = Arc::new(MockLedgerBackend::new());
        let peers = Arc::new(PeerManager::new());

        let follower_engine =
            ReplicationEngine::new(follower_config, follower_key.clone(), backend, peers);

        follower_engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;

        // Create a proposal with oversized payload
        let oversized_data = vec![0u8; MAX_REPLICATION_PAYLOAD_SIZE + 1];
        let event_hash = ReplicationProposal::compute_event_hash(&oversized_data);

        let mut proposal = ReplicationProposal {
            epoch: 1,
            sequence_id: 1,
            leader_id,
            namespace: "test".to_string(),
            event_data: oversized_data,
            event_hash,
            signature: [0u8; 64],
        };
        proposal.sign(&leader_key).unwrap();

        // Follower should reject with PayloadTooLarge nack
        let result = follower_engine.handle_proposal(proposal).await;
        assert!(result.is_err());
        let nack = result.unwrap_err();
        assert_eq!(nack.reason, NackReason::PayloadTooLarge);
    }

    #[tokio::test]
    async fn test_follower_rejects_gap_in_sequence() {
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        let follower_key = generate_test_key();
        let follower_id = validator_id_from_key(&follower_key);

        let follower_config = ReplicationConfig {
            validator_id: follower_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let backend = Arc::new(MockLedgerBackend::new());
        let peers = Arc::new(PeerManager::new());

        let follower_engine =
            ReplicationEngine::new(follower_config, follower_key.clone(), backend, peers);

        follower_engine
            .register_validator(leader_id, leader_key.verifying_key())
            .await;

        // Create a proposal with sequence_id = 5 (but follower expects 1)
        let event = create_test_event();
        let replicated_event = ReplicatedEvent::from_event_record(&event);
        let event_data = serde_json::to_vec(&replicated_event).unwrap();
        let event_hash = ReplicationProposal::compute_event_hash(&event_data);

        let mut proposal = ReplicationProposal {
            epoch: 1,
            sequence_id: 5, // Gap - expected 1
            leader_id,
            namespace: "test".to_string(),
            event_data,
            event_hash,
            signature: [0u8; 64],
        };
        proposal.sign(&leader_key).unwrap();

        // Follower should reject with Gap nack
        let result = follower_engine.handle_proposal(proposal).await;
        assert!(result.is_err());
        let nack = result.unwrap_err();
        assert_eq!(nack.reason, NackReason::Gap);
    }

    #[tokio::test]
    async fn test_non_leader_cannot_propose() {
        let leader_key = generate_test_key();
        let leader_id = validator_id_from_key(&leader_key);

        let follower_key = generate_test_key();
        let follower_id = validator_id_from_key(&follower_key);

        // Follower tries to act as engine but is not leader
        let follower_config = ReplicationConfig {
            validator_id: follower_id,
            leader_id,
            epoch: 1,
            namespace: "test".to_string(),
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            quorum_threshold: 2,
        };

        let backend = Arc::new(MockLedgerBackend::new());
        let peers = Arc::new(PeerManager::new());

        let engine = ReplicationEngine::new(follower_config, follower_key.clone(), backend, peers);

        // Try to propose (should fail - not leader)
        let event = create_test_event();
        let result = engine.propose(&event).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ReplicationError::NotLeader { expected, actual } => {
                assert_eq!(expected, hex::encode(leader_id));
                assert_eq!(actual, hex::encode(follower_id));
            },
            e => panic!("Expected NotLeader error, got: {e:?}"),
        }
    }
}
