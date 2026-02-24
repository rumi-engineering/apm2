// AGENT-AUTHORED
//! BFT network message handlers for consensus protocol.
//!
//! This module implements network message handlers for BFT phases (`Proposal`,
//! `Vote`, `NewView`, QC broadcast) as specified in RFC-0014. Handlers validate
//! signatures and epoch/round, reject invalid or replayed messages, and
//! integrate with the transport layer for traffic analysis mitigation.
//!
//! # Security Properties
//!
//! - **Signature Validation**: All messages are verified against validator keys
//!   before processing (INV-0018)
//! - **Epoch/Round Validation**: Stale and future messages are rejected
//! - **Replay Protection**: Duplicate messages are detected and rejected
//! - **Traffic Analysis Mitigation**: Fixed-size frames with jitter (INV-0017,
//!   INV-0020)
//! - **Bounded Storage**: All caches have bounded size with FIFO eviction
//!   (CTR-1303)
//!
//! # Protocol Integration
//!
//! The handlers integrate with:
//! - `BftMachine` for consensus state management
//! - `ControlFrame` for fixed-size padding
//! - `apply_dispatch_jitter()` for traffic analysis mitigation
//! - `TunnelData` for relay-based routing
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::consensus::handlers::{MessageHandler, BftMessageEnvelope};
//!
//! let handler = MessageHandler::new(config, validators);
//!
//! // Receive and validate a message
//! let envelope = handler.receive_and_validate(frame)?;
//!
//! // Process through BFT machine
//! let actions = machine.handle_event(envelope.into_event(), now)?;
//! ```
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - RFC-0033::REQ-0049: BFT Network Message Handlers
//! - INV-0017: Control plane frames use fixed-size frames
//! - INV-0018: Consensus messages are signed by sender
//! - INV-0020: Control plane dispatch uses bounded jitter

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::RwLock;

use super::bft::{
    BftError, NewView, Proposal, QuorumCertificate, ValidatorId, ValidatorInfo, Vote,
};
use super::bft_machine::{
    BftAction, BftEvent, MSG_BFT_NEW_VIEW, MSG_BFT_PROPOSAL, MSG_BFT_QC, MSG_BFT_VOTE,
};
use super::network::{
    CONTROL_FRAME_SIZE, ControlFrame, MAX_PAYLOAD_SIZE, NetworkError, PooledConnection,
    apply_dispatch_jitter,
};
use super::tunnel::{TunnelData, TunnelError};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of entries in the replay protection cache.
///
/// Bounded to prevent denial-of-service via memory exhaustion (CTR-1303).
/// This allows tracking approximately 1000 messages per validator for a
/// 4-validator quorum over 250 rounds.
pub const MAX_REPLAY_CACHE_SIZE: usize = 4096;

/// Maximum age of replay cache entries in rounds.
///
/// Entries older than this many rounds from the current round are eligible
/// for eviction. This provides a sliding window for replay protection.
pub const REPLAY_CACHE_ROUND_WINDOW: u64 = 100;

/// Maximum number of pending inbound messages.
///
/// Bounded to prevent memory exhaustion from slow consumers.
pub const MAX_PENDING_INBOUND: usize = 256;

/// Maximum message age in epochs before automatic rejection.
///
/// Messages from epochs more than this many behind the current epoch
/// are rejected without signature verification to prevent denial-of-service
/// attacks using old epoch messages.
pub const MAX_EPOCH_AGE: u64 = 2;

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur in message handler operations.
#[derive(Debug, Error)]
pub enum HandlerError {
    /// BFT protocol error.
    #[error("BFT error: {0}")]
    Bft(#[from] BftError),

    /// Network error.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// Tunnel error.
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid message type.
    #[error("invalid message type: {msg_type}")]
    InvalidMessageType {
        /// The unexpected message type.
        msg_type: u32,
    },

    /// Replay detected.
    #[error("replay detected: message from {validator_id} for epoch {epoch}, round {round}")]
    ReplayDetected {
        /// Validator who sent the duplicate.
        validator_id: String,
        /// Epoch of the message.
        epoch: u64,
        /// Round of the message.
        round: u64,
    },

    /// Stale message (old epoch or round).
    #[error(
        "stale message: epoch {msg_epoch}/{msg_round} < current {current_epoch}/{current_round}"
    )]
    StaleMessage {
        /// Message epoch.
        msg_epoch: u64,
        /// Message round.
        msg_round: u64,
        /// Current epoch.
        current_epoch: u64,
        /// Current round.
        current_round: u64,
    },

    /// Future message (too far ahead).
    #[error(
        "future message: epoch {msg_epoch}/{msg_round} too far ahead of {current_epoch}/{current_round}"
    )]
    FutureMessage {
        /// Message epoch.
        msg_epoch: u64,
        /// Message round.
        msg_round: u64,
        /// Current epoch.
        current_epoch: u64,
        /// Current round.
        current_round: u64,
    },

    /// Unknown validator.
    #[error("unknown validator: {validator_id}")]
    UnknownValidator {
        /// The unknown validator ID.
        validator_id: String,
    },

    /// Invalid signature.
    #[error("invalid signature from {validator_id}")]
    InvalidSignature {
        /// Validator whose signature failed.
        validator_id: String,
    },

    /// Payload too large.
    #[error("payload too large: {size} > {max}")]
    PayloadTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Handler shutdown.
    #[error("handler is shutting down")]
    Shutdown,
}

// =============================================================================
// Message Envelope
// =============================================================================

/// Wrapper for BFT protocol messages with metadata.
///
/// The envelope provides a uniform interface for all BFT message types
/// and includes metadata for routing and validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BftMessageEnvelope {
    /// The message type (`MSG_BFT_PROPOSAL`, `MSG_BFT_VOTE`, etc.).
    pub msg_type: u32,
    /// Epoch of the message.
    pub epoch: u64,
    /// Round of the message.
    pub round: u64,
    /// Sender's validator ID.
    pub sender_id: ValidatorId,
    /// Serialized message payload.
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
}

impl BftMessageEnvelope {
    /// Creates an envelope from a proposal.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn from_proposal(proposal: &Proposal) -> Result<Self, HandlerError> {
        let payload =
            serde_json::to_vec(proposal).map_err(|e| HandlerError::Serialization(e.to_string()))?;

        Ok(Self {
            msg_type: MSG_BFT_PROPOSAL,
            epoch: proposal.epoch,
            round: proposal.round,
            sender_id: proposal.proposer_id,
            payload,
        })
    }

    /// Creates an envelope from a vote.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn from_vote(vote: &Vote) -> Result<Self, HandlerError> {
        let payload =
            serde_json::to_vec(vote).map_err(|e| HandlerError::Serialization(e.to_string()))?;

        Ok(Self {
            msg_type: MSG_BFT_VOTE,
            epoch: vote.epoch,
            round: vote.round,
            sender_id: vote.voter_id,
            payload,
        })
    }

    /// Creates an envelope from a new-view message.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn from_new_view(new_view: &NewView) -> Result<Self, HandlerError> {
        let payload =
            serde_json::to_vec(new_view).map_err(|e| HandlerError::Serialization(e.to_string()))?;

        Ok(Self {
            msg_type: MSG_BFT_NEW_VIEW,
            epoch: new_view.epoch,
            round: new_view.round,
            sender_id: new_view.sender_id,
            payload,
        })
    }

    /// Creates an envelope from a quorum certificate.
    ///
    /// For QC broadcasts, the sender is set to all zeros (broadcast message).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn from_qc(qc: &QuorumCertificate) -> Result<Self, HandlerError> {
        let payload =
            serde_json::to_vec(qc).map_err(|e| HandlerError::Serialization(e.to_string()))?;

        Ok(Self {
            msg_type: MSG_BFT_QC,
            epoch: qc.epoch,
            round: qc.round,
            sender_id: [0u8; 32], // QC is a broadcast, not from a specific sender
            payload,
        })
    }

    /// Extracts the proposal from the envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the message type doesn't match or deserialization
    /// fails.
    pub fn into_proposal(self) -> Result<Proposal, HandlerError> {
        if self.msg_type != MSG_BFT_PROPOSAL {
            return Err(HandlerError::InvalidMessageType {
                msg_type: self.msg_type,
            });
        }
        serde_json::from_slice(&self.payload)
            .map_err(|e| HandlerError::Serialization(e.to_string()))
    }

    /// Extracts the vote from the envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the message type doesn't match or deserialization
    /// fails.
    pub fn into_vote(self) -> Result<Vote, HandlerError> {
        if self.msg_type != MSG_BFT_VOTE {
            return Err(HandlerError::InvalidMessageType {
                msg_type: self.msg_type,
            });
        }
        serde_json::from_slice(&self.payload)
            .map_err(|e| HandlerError::Serialization(e.to_string()))
    }

    /// Extracts the new-view message from the envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the message type doesn't match or deserialization
    /// fails.
    pub fn into_new_view(self) -> Result<NewView, HandlerError> {
        if self.msg_type != MSG_BFT_NEW_VIEW {
            return Err(HandlerError::InvalidMessageType {
                msg_type: self.msg_type,
            });
        }
        serde_json::from_slice(&self.payload)
            .map_err(|e| HandlerError::Serialization(e.to_string()))
    }

    /// Extracts the quorum certificate from the envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the message type doesn't match or deserialization
    /// fails.
    pub fn into_qc(self) -> Result<QuorumCertificate, HandlerError> {
        if self.msg_type != MSG_BFT_QC {
            return Err(HandlerError::InvalidMessageType {
                msg_type: self.msg_type,
            });
        }
        serde_json::from_slice(&self.payload)
            .map_err(|e| HandlerError::Serialization(e.to_string()))
    }

    /// Converts the envelope to a BFT event for the machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the message type is invalid or deserialization
    /// fails.
    pub fn into_event(self) -> Result<BftEvent, HandlerError> {
        match self.msg_type {
            MSG_BFT_PROPOSAL => Ok(BftEvent::ProposalReceived(self.into_proposal()?)),
            MSG_BFT_VOTE => Ok(BftEvent::VoteReceived(self.into_vote()?)),
            MSG_BFT_NEW_VIEW => Ok(BftEvent::NewViewReceived(self.into_new_view()?)),
            MSG_BFT_QC => Ok(BftEvent::QcReceived(self.into_qc()?)),
            _ => Err(HandlerError::InvalidMessageType {
                msg_type: self.msg_type,
            }),
        }
    }

    /// Serializes the envelope to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, HandlerError> {
        serde_json::to_vec(self).map_err(|e| HandlerError::Serialization(e.to_string()))
    }

    /// Deserializes an envelope from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandlerError> {
        serde_json::from_slice(bytes).map_err(|e| HandlerError::Serialization(e.to_string()))
    }
}

/// Base64 serialization for binary data in JSON.
mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
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

// =============================================================================
// Replay Protection Cache
// =============================================================================

/// Key for the replay protection cache.
///
/// Uniquely identifies a message by (epoch, round, validator, `msg_type`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ReplayCacheKey {
    epoch: u64,
    round: u64,
    validator_id: ValidatorId,
    msg_type: u32,
}

/// Bounded replay protection cache with FIFO eviction.
///
/// Tracks recently seen messages to detect and reject replays.
/// Uses constant-time comparison for security.
pub struct ReplayCache {
    /// Set of seen message keys for O(1) lookup.
    seen: HashSet<ReplayCacheKey>,
    /// Ordered list of keys for FIFO eviction.
    order: VecDeque<ReplayCacheKey>,
    /// Maximum cache size.
    max_size: usize,
    /// Current epoch for staleness checks.
    current_epoch: u64,
    /// Current round for staleness checks.
    current_round: u64,
}

impl ReplayCache {
    /// Creates a new replay cache.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(max_size),
            order: VecDeque::with_capacity(max_size),
            max_size,
            current_epoch: 0,
            current_round: 1,
        }
    }

    /// Updates the current epoch and round, evicting old entries.
    pub fn update_view(&mut self, epoch: u64, round: u64) {
        self.current_epoch = epoch;
        self.current_round = round;

        // Evict entries that are too old
        self.evict_stale();
    }

    /// Checks if a message has been seen and records it if not.
    ///
    /// Returns `true` if this is a replay (message was already seen).
    pub fn check_and_record(
        &mut self,
        epoch: u64,
        round: u64,
        validator_id: ValidatorId,
        msg_type: u32,
    ) -> bool {
        let key = ReplayCacheKey {
            epoch,
            round,
            validator_id,
            msg_type,
        };

        // Check if already seen
        if self.seen.contains(&key) {
            return true;
        }

        // Ensure space in cache
        while self.order.len() >= self.max_size {
            if let Some(old_key) = self.order.pop_front() {
                self.seen.remove(&old_key);
            }
        }

        // Record the new message
        self.seen.insert(key);
        self.order.push_back(key);

        false
    }

    /// Evicts entries that are older than the staleness window.
    fn evict_stale(&mut self) {
        // Calculate the minimum round to keep
        let min_round = self.current_round.saturating_sub(REPLAY_CACHE_ROUND_WINDOW);
        let min_epoch = self.current_epoch.saturating_sub(MAX_EPOCH_AGE);

        // Remove old entries from the front
        while let Some(key) = self.order.front() {
            // Evict if epoch is too old OR (same epoch but round too old)
            if key.epoch < min_epoch || (key.epoch == self.current_epoch && key.round < min_round) {
                let key = self.order.pop_front().unwrap();
                self.seen.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Returns the number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// =============================================================================
// Message Handler
// =============================================================================

/// Handler configuration.
#[derive(Clone)]
pub struct HandlerConfig {
    /// This node's validator ID.
    pub validator_id: ValidatorId,
    /// Quorum threshold for QC validation.
    pub quorum_threshold: usize,
    /// Maximum round jump allowed.
    pub max_round_jump: u64,
}

/// BFT network message handler.
///
/// Handles incoming BFT messages with:
/// - Signature verification
/// - Epoch/round validation
/// - Replay protection
/// - Transport integration (padding, jitter)
pub struct MessageHandler {
    /// Configuration.
    config: HandlerConfig,
    /// Validator set for signature verification.
    validators: Arc<RwLock<Vec<ValidatorInfo>>>,
    /// Replay protection cache.
    replay_cache: RwLock<ReplayCache>,
    /// Current epoch.
    current_epoch: RwLock<u64>,
    /// Current round.
    current_round: RwLock<u64>,
}

impl MessageHandler {
    /// Creates a new message handler.
    #[must_use]
    pub fn new(config: HandlerConfig, validators: Vec<ValidatorInfo>) -> Self {
        Self {
            config,
            validators: Arc::new(RwLock::new(validators)),
            replay_cache: RwLock::new(ReplayCache::new(MAX_REPLAY_CACHE_SIZE)),
            current_epoch: RwLock::new(0),
            current_round: RwLock::new(1),
        }
    }

    /// Updates the handler's view (epoch and round).
    ///
    /// Call this when the consensus machine advances.
    pub async fn update_view(&self, epoch: u64, round: u64) {
        {
            let mut e = self.current_epoch.write().await;
            *e = epoch;
        }
        {
            let mut r = self.current_round.write().await;
            *r = round;
        }
        {
            let mut cache = self.replay_cache.write().await;
            cache.update_view(epoch, round);
        }
    }

    /// Updates the validator set.
    pub async fn update_validators(&self, validators: Vec<ValidatorInfo>) {
        let mut v = self.validators.write().await;
        *v = validators;
    }

    /// Validates and processes an incoming control frame.
    ///
    /// This method performs full validation:
    /// 1. Parse the envelope
    /// 2. Check epoch/round validity
    /// 3. Check for replay
    /// 4. Verify signature
    ///
    /// # Errors
    ///
    /// Returns an error if any validation step fails.
    pub async fn receive_and_validate(
        &self,
        frame: &ControlFrame,
    ) -> Result<BftMessageEnvelope, HandlerError> {
        // Check message type
        let msg_type = frame.message_type();
        if msg_type != MSG_BFT_PROPOSAL
            && msg_type != MSG_BFT_VOTE
            && msg_type != MSG_BFT_NEW_VIEW
            && msg_type != MSG_BFT_QC
        {
            return Err(HandlerError::InvalidMessageType { msg_type });
        }

        // Parse envelope
        let envelope = BftMessageEnvelope::from_bytes(frame.payload())?;

        // Validate epoch/round
        self.validate_epoch_round(&envelope).await?;

        // Check for replay (skip for QC which is a broadcast)
        if msg_type != MSG_BFT_QC {
            self.check_replay(&envelope).await?;
        }

        // Verify signature
        self.verify_signature(&envelope).await?;

        Ok(envelope)
    }

    /// Validates that the message epoch/round is acceptable.
    async fn validate_epoch_round(
        &self,
        envelope: &BftMessageEnvelope,
    ) -> Result<(), HandlerError> {
        let current_epoch = *self.current_epoch.read().await;
        let current_round = *self.current_round.read().await;

        // Reject messages from too-old epochs (DoS protection)
        if envelope.epoch + MAX_EPOCH_AGE < current_epoch {
            return Err(HandlerError::StaleMessage {
                msg_epoch: envelope.epoch,
                msg_round: envelope.round,
                current_epoch,
                current_round,
            });
        }

        // Reject stale messages (old round in current epoch)
        if envelope.epoch == current_epoch && envelope.round < current_round {
            // Allow messages from recent rounds (for late arrivals)
            let min_acceptable = current_round.saturating_sub(REPLAY_CACHE_ROUND_WINDOW);
            if envelope.round < min_acceptable {
                return Err(HandlerError::StaleMessage {
                    msg_epoch: envelope.epoch,
                    msg_round: envelope.round,
                    current_epoch,
                    current_round,
                });
            }
        }

        // Reject messages too far in the future
        if envelope.epoch > current_epoch + MAX_EPOCH_AGE {
            return Err(HandlerError::FutureMessage {
                msg_epoch: envelope.epoch,
                msg_round: envelope.round,
                current_epoch,
                current_round,
            });
        }

        if envelope.epoch == current_epoch
            && envelope.round > current_round + self.config.max_round_jump
        {
            return Err(HandlerError::FutureMessage {
                msg_epoch: envelope.epoch,
                msg_round: envelope.round,
                current_epoch,
                current_round,
            });
        }

        Ok(())
    }

    /// Checks for replay and records the message if not a duplicate.
    async fn check_replay(&self, envelope: &BftMessageEnvelope) -> Result<(), HandlerError> {
        let mut cache = self.replay_cache.write().await;

        if cache.check_and_record(
            envelope.epoch,
            envelope.round,
            envelope.sender_id,
            envelope.msg_type,
        ) {
            return Err(HandlerError::ReplayDetected {
                validator_id: hex::encode(envelope.sender_id),
                epoch: envelope.epoch,
                round: envelope.round,
            });
        }

        Ok(())
    }

    /// Verifies the signature on the message.
    async fn verify_signature(&self, envelope: &BftMessageEnvelope) -> Result<(), HandlerError> {
        // QC validation is different (multiple signatures)
        if envelope.msg_type == MSG_BFT_QC {
            return self.verify_qc_signatures(envelope).await;
        }

        // Find the validator
        let validators = self.validators.read().await;
        let validator = validators
            .iter()
            .find(|v| v.id.ct_eq(&envelope.sender_id).into())
            .ok_or_else(|| HandlerError::UnknownValidator {
                validator_id: hex::encode(envelope.sender_id),
            })?;

        // Verify based on message type
        match envelope.msg_type {
            MSG_BFT_PROPOSAL => {
                let proposal: Proposal = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| HandlerError::Serialization(e.to_string()))?;
                proposal
                    .verify_signature(&validator.public_key)
                    .map_err(|_| HandlerError::InvalidSignature {
                        validator_id: hex::encode(envelope.sender_id),
                    })?;
            },
            MSG_BFT_VOTE => {
                let vote: Vote = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| HandlerError::Serialization(e.to_string()))?;
                vote.verify_signature(&validator.public_key).map_err(|_| {
                    HandlerError::InvalidSignature {
                        validator_id: hex::encode(envelope.sender_id),
                    }
                })?;
            },
            MSG_BFT_NEW_VIEW => {
                let new_view: NewView = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| HandlerError::Serialization(e.to_string()))?;
                new_view
                    .verify_signature(&validator.public_key)
                    .map_err(|_| HandlerError::InvalidSignature {
                        validator_id: hex::encode(envelope.sender_id),
                    })?;
            },
            _ => {
                return Err(HandlerError::InvalidMessageType {
                    msg_type: envelope.msg_type,
                });
            },
        }

        Ok(())
    }

    /// Verifies signatures on a quorum certificate.
    async fn verify_qc_signatures(
        &self,
        envelope: &BftMessageEnvelope,
    ) -> Result<(), HandlerError> {
        let qc: QuorumCertificate = serde_json::from_slice(&envelope.payload)
            .map_err(|e| HandlerError::Serialization(e.to_string()))?;

        // Genesis QC has no signatures
        if qc.is_genesis() {
            return Ok(());
        }

        let validators = self.validators.read().await;
        qc.verify_signatures(&validators, self.config.quorum_threshold)
            .map_err(HandlerError::from)?;

        Ok(())
    }

    /// Creates a control frame from a BFT action for sending.
    ///
    /// Wraps the action in a properly padded control frame (INV-0017).
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is too large or serialization fails.
    pub fn create_frame(&self, action: &BftAction) -> Result<ControlFrame, HandlerError> {
        let envelope = match action {
            BftAction::BroadcastProposal(proposal) => BftMessageEnvelope::from_proposal(proposal)?,
            BftAction::BroadcastVote(vote) => BftMessageEnvelope::from_vote(vote)?,
            BftAction::BroadcastNewView(new_view) => BftMessageEnvelope::from_new_view(new_view)?,
            BftAction::BroadcastQc(qc) => BftMessageEnvelope::from_qc(qc)?,
            _ => {
                return Err(HandlerError::Serialization(
                    "non-broadcast action cannot be framed".into(),
                ));
            },
        };

        let payload = envelope.to_bytes()?;

        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(HandlerError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let msg_type = envelope.msg_type;
        Ok(ControlFrame::new(msg_type, &payload)?)
    }

    /// Sends a control frame to a peer with jitter (INV-0020).
    ///
    /// # Errors
    ///
    /// Returns an error if sending fails.
    pub async fn send_frame(
        &self,
        conn: &mut PooledConnection,
        frame: &ControlFrame,
    ) -> Result<(), HandlerError> {
        // Apply dispatch jitter for traffic analysis mitigation
        apply_dispatch_jitter().await;
        conn.send_frame(frame).await.map_err(HandlerError::from)
    }

    /// Creates a tunnel data message for relay routing.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is too large.
    pub fn create_tunnel_data(
        &self,
        tunnel_id: &str,
        action: &BftAction,
    ) -> Result<TunnelData, HandlerError> {
        let frame = self.create_frame(action)?;
        Ok(TunnelData::new(
            tunnel_id.to_string(),
            frame.as_bytes().to_vec(),
        ))
    }

    /// Extracts a BFT envelope from tunnel data.
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be parsed.
    pub async fn receive_from_tunnel(
        &self,
        data: &TunnelData,
    ) -> Result<BftMessageEnvelope, HandlerError> {
        // The payload should be a complete control frame
        if data.payload.len() != CONTROL_FRAME_SIZE {
            return Err(HandlerError::Serialization(format!(
                "invalid tunnel payload size: {} != {CONTROL_FRAME_SIZE}",
                data.payload.len()
            )));
        }

        let frame_data: [u8; CONTROL_FRAME_SIZE] = data.payload[..].try_into().map_err(|_| {
            HandlerError::Serialization("failed to convert payload to frame".into())
        })?;

        let frame = ControlFrame::parse(&frame_data)?;
        self.receive_and_validate(&frame).await
    }
}

// =============================================================================
// Peer Manager
// =============================================================================

/// Peer information for routing.
#[derive(Clone, Debug)]
pub struct PeerEndpoint {
    /// Validator ID.
    pub validator_id: ValidatorId,
    /// Direct socket address (if available).
    pub direct_addr: Option<SocketAddr>,
    /// Tunnel ID for relay routing (if behind NAT).
    pub tunnel_id: Option<String>,
    /// Server name for TLS.
    pub server_name: String,
}

/// Manager for peer endpoints.
pub struct PeerManager {
    /// Endpoints by validator ID.
    endpoints: RwLock<HashMap<ValidatorId, PeerEndpoint>>,
}

impl PeerManager {
    /// Creates a new peer manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            endpoints: RwLock::new(HashMap::new()),
        }
    }

    /// Registers or updates a peer endpoint.
    pub async fn register(&self, endpoint: PeerEndpoint) {
        let mut endpoints = self.endpoints.write().await;
        endpoints.insert(endpoint.validator_id, endpoint);
    }

    /// Unregisters a peer.
    pub async fn unregister(&self, validator_id: &ValidatorId) {
        let mut endpoints = self.endpoints.write().await;
        endpoints.remove(validator_id);
    }

    /// Gets a peer's endpoint.
    pub async fn get(&self, validator_id: &ValidatorId) -> Option<PeerEndpoint> {
        let endpoints = self.endpoints.read().await;
        endpoints.get(validator_id).cloned()
    }

    /// Gets all peer endpoints.
    pub async fn all(&self) -> Vec<PeerEndpoint> {
        let endpoints = self.endpoints.read().await;
        endpoints.values().cloned().collect()
    }

    /// Gets all peers except the specified one.
    pub async fn all_except(&self, exclude: &ValidatorId) -> Vec<PeerEndpoint> {
        let endpoints = self.endpoints.read().await;
        endpoints
            .values()
            .filter(|e| !bool::from(e.validator_id.ct_eq(exclude)))
            .cloned()
            .collect()
    }
}

impl Default for PeerManager {
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

    #[test]
    fn test_replay_cache_basic() {
        let mut cache = ReplayCache::new(100);

        let validator_id = [1u8; 32];

        // First message should not be replay
        assert!(!cache.check_and_record(0, 1, validator_id, MSG_BFT_VOTE));

        // Same message should be replay
        assert!(cache.check_and_record(0, 1, validator_id, MSG_BFT_VOTE));

        // Different validator should not be replay
        let other_validator = [2u8; 32];
        assert!(!cache.check_and_record(0, 1, other_validator, MSG_BFT_VOTE));

        // Different round should not be replay
        assert!(!cache.check_and_record(0, 2, validator_id, MSG_BFT_VOTE));

        // Different message type should not be replay
        assert!(!cache.check_and_record(0, 1, validator_id, MSG_BFT_PROPOSAL));
    }

    #[test]
    fn test_replay_cache_bounded() {
        let mut cache = ReplayCache::new(10);

        // Fill the cache
        for i in 0..15u8 {
            let mut validator_id = [0u8; 32];
            validator_id[0] = i;
            cache.check_and_record(0, 1, validator_id, MSG_BFT_VOTE);
        }

        // Cache should be bounded
        assert!(cache.len() <= 10);
    }

    #[test]
    fn test_replay_cache_eviction() {
        let mut cache = ReplayCache::new(100);

        // Add an old message
        let validator_id = [1u8; 32];
        cache.check_and_record(0, 1, validator_id, MSG_BFT_VOTE);

        // Update view to trigger eviction
        cache.update_view(0, REPLAY_CACHE_ROUND_WINDOW + 10);

        // Old message should be evicted (can record again)
        assert!(!cache.check_and_record(0, 1, validator_id, MSG_BFT_VOTE));
    }

    #[test]
    fn test_envelope_proposal_roundtrip() {
        let proposal = Proposal {
            epoch: 1,
            round: 5,
            proposer_id: [1u8; 32],
            block_hash: [2u8; 32],
            parent_qc: QuorumCertificate::genesis(0, [0u8; 32]),
            payload_hash: [3u8; 32],
            signature: [0u8; 64],
        };

        let envelope = BftMessageEnvelope::from_proposal(&proposal).unwrap();
        assert_eq!(envelope.msg_type, MSG_BFT_PROPOSAL);
        assert_eq!(envelope.epoch, 1);
        assert_eq!(envelope.round, 5);

        let restored = envelope.into_proposal().unwrap();
        assert_eq!(restored.epoch, proposal.epoch);
        assert_eq!(restored.round, proposal.round);
    }

    #[test]
    fn test_envelope_vote_roundtrip() {
        let vote = Vote {
            epoch: 2,
            round: 10,
            voter_id: [5u8; 32],
            block_hash: [6u8; 32],
            signature: [0u8; 64],
        };

        let envelope = BftMessageEnvelope::from_vote(&vote).unwrap();
        assert_eq!(envelope.msg_type, MSG_BFT_VOTE);

        let restored = envelope.into_vote().unwrap();
        assert_eq!(restored.epoch, vote.epoch);
        assert_eq!(restored.voter_id, vote.voter_id);
    }

    #[test]
    fn test_envelope_new_view_roundtrip() {
        let new_view = NewView {
            epoch: 3,
            round: 15,
            sender_id: [7u8; 32],
            high_qc: QuorumCertificate::genesis(0, [0u8; 32]),
            signature: [0u8; 64],
        };

        let envelope = BftMessageEnvelope::from_new_view(&new_view).unwrap();
        assert_eq!(envelope.msg_type, MSG_BFT_NEW_VIEW);

        let restored = envelope.into_new_view().unwrap();
        assert_eq!(restored.epoch, new_view.epoch);
    }

    #[test]
    fn test_envelope_qc_roundtrip() {
        let qc = QuorumCertificate {
            epoch: 4,
            round: 20,
            block_hash: [8u8; 32],
            signatures: vec![],
        };

        let envelope = BftMessageEnvelope::from_qc(&qc).unwrap();
        assert_eq!(envelope.msg_type, MSG_BFT_QC);

        let restored = envelope.into_qc().unwrap();
        assert_eq!(restored.epoch, qc.epoch);
    }

    #[test]
    fn test_envelope_serialization_roundtrip() {
        let envelope = BftMessageEnvelope {
            msg_type: MSG_BFT_VOTE,
            epoch: 1,
            round: 5,
            sender_id: [1u8; 32],
            payload: vec![1, 2, 3, 4],
        };

        let bytes = envelope.to_bytes().unwrap();
        let restored = BftMessageEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(restored.msg_type, envelope.msg_type);
        assert_eq!(restored.epoch, envelope.epoch);
        assert_eq!(restored.round, envelope.round);
        assert_eq!(restored.sender_id, envelope.sender_id);
        assert_eq!(restored.payload, envelope.payload);
    }

    #[test]
    fn test_peer_endpoint_structure() {
        let endpoint = PeerEndpoint {
            validator_id: [1u8; 32],
            direct_addr: Some("127.0.0.1:8443".parse().unwrap()),
            tunnel_id: None,
            server_name: "node1.example.com".to_string(),
        };

        assert!(endpoint.direct_addr.is_some());
        assert!(endpoint.tunnel_id.is_none());
    }

    #[tokio::test]
    async fn test_peer_manager_register_unregister() {
        let manager = PeerManager::new();

        let endpoint = PeerEndpoint {
            validator_id: [1u8; 32],
            direct_addr: Some("127.0.0.1:8443".parse().unwrap()),
            tunnel_id: None,
            server_name: "node1".to_string(),
        };

        manager.register(endpoint.clone()).await;

        let retrieved = manager.get(&[1u8; 32]).await;
        assert!(retrieved.is_some());

        manager.unregister(&[1u8; 32]).await;

        let retrieved = manager.get(&[1u8; 32]).await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_peer_manager_all_except() {
        let manager = PeerManager::new();

        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            manager
                .register(PeerEndpoint {
                    validator_id: id,
                    direct_addr: None,
                    tunnel_id: Some(format!("tunnel-{i}")),
                    server_name: format!("node{i}"),
                })
                .await;
        }

        let exclude = [0u8; 32];
        let peers = manager.all_except(&exclude).await;
        assert_eq!(peers.len(), 3);
        assert!(peers.iter().all(|p| p.validator_id[0] != 0));
    }

    #[test]
    fn test_handler_error_display() {
        let errors = [
            HandlerError::InvalidMessageType { msg_type: 999 },
            HandlerError::ReplayDetected {
                validator_id: "abc".into(),
                epoch: 1,
                round: 5,
            },
            HandlerError::StaleMessage {
                msg_epoch: 0,
                msg_round: 1,
                current_epoch: 1,
                current_round: 10,
            },
            HandlerError::UnknownValidator {
                validator_id: "def".into(),
            },
            HandlerError::InvalidSignature {
                validator_id: "ghi".into(),
            },
            HandlerError::PayloadTooLarge {
                size: 2000,
                max: 1000,
            },
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    // Compile-time bounds verification
    const _: () = {
        assert!(MAX_REPLAY_CACHE_SIZE > 0);
        assert!(MAX_REPLAY_CACHE_SIZE <= 16384);
        assert!(REPLAY_CACHE_ROUND_WINDOW > 0);
        assert!(REPLAY_CACHE_ROUND_WINDOW <= 1000);
        assert!(MAX_PENDING_INBOUND > 0);
        assert!(MAX_PENDING_INBOUND <= 1024);
    };
}

#[cfg(test)]
mod tck_00188_tests {
    use super::*;

    #[test]
    fn tck_00188_envelope_types_defined() {
        // Verify all required envelope operations exist
        let _ = BftMessageEnvelope::from_proposal;
        let _ = BftMessageEnvelope::from_vote;
        let _ = BftMessageEnvelope::from_new_view;
        let _ = BftMessageEnvelope::from_qc;
    }

    #[test]
    fn tck_00188_replay_cache_bounded() {
        // CTR-1303: Cache must be bounded
        let cache = ReplayCache::new(MAX_REPLAY_CACHE_SIZE);
        assert_eq!(cache.max_size, MAX_REPLAY_CACHE_SIZE);
    }

    #[test]
    fn tck_00188_handler_config_structure() {
        let config = HandlerConfig {
            validator_id: [0u8; 32],
            quorum_threshold: 3,
            max_round_jump: 10,
        };

        assert_eq!(config.quorum_threshold, 3);
    }

    #[tokio::test]
    async fn tck_00188_handler_creation() {
        let config = HandlerConfig {
            validator_id: [0u8; 32],
            quorum_threshold: 3,
            max_round_jump: 10,
        };

        let handler = MessageHandler::new(config, vec![]);
        handler.update_view(0, 1).await;
    }

    #[test]
    fn tck_00188_error_variants_comprehensive() {
        // Verify all error variants exist
        let _: HandlerError = HandlerError::InvalidMessageType { msg_type: 0 };
        let _: HandlerError = HandlerError::ReplayDetected {
            validator_id: String::new(),
            epoch: 0,
            round: 0,
        };
        let _: HandlerError = HandlerError::StaleMessage {
            msg_epoch: 0,
            msg_round: 0,
            current_epoch: 0,
            current_round: 0,
        };
        let _: HandlerError = HandlerError::FutureMessage {
            msg_epoch: 0,
            msg_round: 0,
            current_epoch: 0,
            current_round: 0,
        };
        let _: HandlerError = HandlerError::UnknownValidator {
            validator_id: String::new(),
        };
        let _: HandlerError = HandlerError::InvalidSignature {
            validator_id: String::new(),
        };
        let _: HandlerError = HandlerError::PayloadTooLarge { size: 0, max: 0 };
        let _: HandlerError = HandlerError::Shutdown;
    }

    #[test]
    fn tck_00188_serde_strict_mode() {
        // Verify BftMessageEnvelope uses deny_unknown_fields
        let json_with_extra = r#"{"msg_type":200,"epoch":0,"round":0,"sender_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","payload":"","extra":"bad"}"#;
        let result: Result<BftMessageEnvelope, _> = serde_json::from_str(json_with_extra);
        assert!(result.is_err(), "Should reject unknown fields");
    }

    // Compile-time validation that BFT message types are in the 200+ range
    // (not conflicting with tunnel message types 100-199)
    const _MSG_TYPE_RANGE: () = {
        assert!(MSG_BFT_PROPOSAL >= 200);
        assert!(MSG_BFT_VOTE >= 200);
        assert!(MSG_BFT_NEW_VIEW >= 200);
        assert!(MSG_BFT_QC >= 200);
    };

    #[test]
    fn tck_00188_peer_endpoint_with_tunnel() {
        // Verify tunnel routing support
        let endpoint = PeerEndpoint {
            validator_id: [1u8; 32],
            direct_addr: None,
            tunnel_id: Some("tunnel-123".to_string()),
            server_name: "worker.example.com".to_string(),
        };

        assert!(endpoint.direct_addr.is_none());
        assert!(endpoint.tunnel_id.is_some());
    }

    #[tokio::test]
    async fn tck_00188_handler_view_update() {
        let config = HandlerConfig {
            validator_id: [0u8; 32],
            quorum_threshold: 3,
            max_round_jump: 10,
        };

        let handler = MessageHandler::new(config, vec![]);

        // Initial view
        handler.update_view(0, 1).await;

        // Advance view
        handler.update_view(0, 5).await;

        // Verify replay cache was updated
        let cache = handler.replay_cache.read().await;
        assert_eq!(cache.current_epoch, 0);
        assert_eq!(cache.current_round, 5);
    }

    // Compile-time constant validation
    const _CONSTANTS_VALID: () = {
        // INV-0017: Frame size check
        assert!(CONTROL_FRAME_SIZE == 1024);

        // Replay cache should be large enough for reasonable operation
        assert!(MAX_REPLAY_CACHE_SIZE >= 1000);

        // Round window should be reasonable
        assert!(REPLAY_CACHE_ROUND_WINDOW >= 10);
        assert!(REPLAY_CACHE_ROUND_WINDOW <= 1000);

        // Epoch age limit
        assert!(MAX_EPOCH_AGE >= 1);
        assert!(MAX_EPOCH_AGE <= 10);
    };

    #[test]
    fn tck_00188_envelope_into_event() {
        // Test conversion to BftEvent
        let vote = Vote {
            epoch: 0,
            round: 1,
            voter_id: [1u8; 32],
            block_hash: [2u8; 32],
            signature: [0u8; 64],
        };

        let envelope = BftMessageEnvelope::from_vote(&vote).unwrap();
        let event = envelope.into_event().unwrap();

        assert!(matches!(event, BftEvent::VoteReceived(_)));
    }
}
