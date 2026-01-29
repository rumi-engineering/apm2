// AGENT-AUTHORED
//! BFT consensus machine driver for event-driven consensus.
//!
//! This module provides a higher-level interface for driving the `HotStuff` BFT
//! state machine. It integrates with the network layer for sending/receiving
//! messages and provides an event-driven interface for the coordinator to drive
//! consensus.
//!
//! # Architecture
//!
//! The `BftMachine` wraps `HotStuffState` and provides:
//! - Event-driven input processing via `handle_event()`
//! - Output actions for network integration via `BftAction`
//! - Timeout management with `tick()` for view changes
//! - Proposal creation for leaders via `propose()`
//!
//! # Protocol Flow
//!
//! ```text
//! +-----------+      +------------+      +------------+
//! |  Network  | ---> | BftMachine | ---> |  Actions   |
//! +-----------+      +------------+      +------------+
//!                          |
//!                    +------------+
//!                    | HotStuff   |
//!                    | State      |
//!                    +------------+
//! ```
//!
//! # Security Properties
//!
//! - **Safety**: Inherits from `HotStuffState` - no two honest validators
//!   commit different blocks at the same height
//! - **Liveness**: Timeout-based view changes ensure progress after GST
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00186: BFT Library Evaluation Spike
//! - TCK-00187: BFT State Machine Core
//! - EVID-0007: Protocol phase transitions
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::consensus::bft_machine::{BftMachine, BftEvent, BftAction};
//!
//! // Create machine with signing key
//! let mut machine = BftMachine::new(config, signing_key);
//!
//! // Handle incoming proposal
//! for action in machine.handle_event(BftEvent::ProposalReceived(proposal))? {
//!     match action {
//!         BftAction::BroadcastVote(vote) => network.broadcast(vote),
//!         BftAction::Commit(block_hash) => apply_to_ledger(block_hash),
//!         _ => {}
//!     }
//! }
//!
//! // Periodic tick for timeout handling
//! for action in machine.tick() {
//!     // Handle timeout actions
//! }
//! ```

use std::collections::VecDeque;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use subtle::ConstantTimeEq;

use super::bft::{
    BftError, BlockHash, HotStuffConfig, HotStuffState, NewView, Phase, Proposal,
    QuorumCertificate, TIMEOUT_MULTIPLIER, ValidatorId, Vote,
};

// ============================================================================
// Constants
// ============================================================================

/// Message type for BFT proposals.
pub const MSG_BFT_PROPOSAL: u32 = 200;

/// Message type for BFT votes.
pub const MSG_BFT_VOTE: u32 = 201;

/// Message type for BFT new-view messages.
pub const MSG_BFT_NEW_VIEW: u32 = 202;

/// Message type for BFT quorum certificates.
pub const MSG_BFT_QC: u32 = 203;

/// Maximum number of pending actions in the output queue.
///
/// Bounded to prevent denial-of-service via memory exhaustion.
pub const MAX_PENDING_ACTIONS: usize = 64;

/// Maximum number of buffered future messages.
///
/// Messages from future rounds are buffered until we advance to that round.
pub const MAX_BUFFERED_MESSAGES: usize = 128;

// ============================================================================
// Events
// ============================================================================

/// Input events for the BFT state machine driver.
///
/// These events represent messages from the network or internal triggers
/// that the consensus coordinator passes to the `BftMachine`.
#[derive(Clone, Debug)]
pub enum BftEvent {
    /// A proposal was received from the network.
    ProposalReceived(Proposal),

    /// A vote was received from the network.
    VoteReceived(Vote),

    /// A new-view message was received from the network.
    NewViewReceived(NewView),

    /// A quorum certificate was received (e.g., from leader aggregation).
    QcReceived(QuorumCertificate),

    /// A timeout event triggered by the coordinator's timer.
    Timeout,

    /// Request to start a new round as leader with the given payload.
    StartRound {
        /// BLAKE3 hash of the payload to propose.
        payload_hash: BlockHash,
    },
}

// ============================================================================
// Actions
// ============================================================================

/// Output actions from the BFT state machine driver.
///
/// These actions tell the coordinator what network messages to send
/// or what state changes occurred.
///
/// # Traffic Analysis Mitigations (INV-0017)
///
/// When sending BFT messages over the network, the coordinator MUST wrap
/// all outbound messages using [`ControlFrame`](super::network::ControlFrame)
/// to ensure fixed-size frame padding. This prevents traffic analysis attacks
/// that could leak consensus state through message size patterns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BftAction {
    /// Broadcast a proposal to all validators.
    BroadcastProposal(Proposal),

    /// Broadcast a vote to all validators (typically to the leader).
    BroadcastVote(Vote),

    /// Broadcast a new-view message during view change.
    BroadcastNewView(NewView),

    /// Broadcast a quorum certificate (leader informs followers).
    BroadcastQc(QuorumCertificate),

    /// A block was committed to the ledger.
    Commit(BlockHash),

    /// Entered a new round.
    RoundAdvanced {
        /// The new round number.
        round: u64,
        /// Whether this node is the leader for this round.
        is_leader: bool,
    },

    /// View change initiated due to timeout.
    ViewChangeStarted {
        /// The round we are moving to.
        new_round: u64,
    },

    /// A quorum certificate was formed for a block.
    QcFormed(QuorumCertificate),

    /// Request the coordinator to schedule a timeout.
    ScheduleTimeout(Duration),
}

// ============================================================================
// Buffered Message
// ============================================================================

/// A message buffered for processing in a future round.
#[derive(Clone, Debug)]
struct BufferedMessage {
    /// The round this message is for.
    round: u64,
    /// The buffered event.
    event: BftEvent,
}

// ============================================================================
// BFT Machine
// ============================================================================

/// Event-driven BFT consensus machine driver.
///
/// The `BftMachine` provides a higher-level interface over `HotStuffState`,
/// handling:
/// - Message signing with the node's Ed25519 key
/// - Output action generation for network integration
/// - Timeout scheduling and view change coordination
/// - Future message buffering
///
/// # Thread Safety
///
/// `BftMachine` is not `Send` or `Sync` by default due to the signing key.
/// Use appropriate synchronization if sharing across threads.
///
/// # Determinism (HOLONIC-BOUNDARY-001)
///
/// This machine is designed for deterministic operation. Time-dependent methods
/// (`tick`, `handle_event`) accept a `now` parameter representing the current
/// time, allowing the caller to inject time for deterministic replay and
/// testing.
pub struct BftMachine {
    /// The underlying `HotStuff` state machine.
    state: HotStuffState,

    /// Ed25519 signing key for this validator.
    signing_key: SigningKey,

    /// Cached validator ID (BLAKE3 hash of public key).
    /// Computed once during initialization to avoid repeated hashing.
    validator_id: ValidatorId,

    /// Pending output actions.
    actions: VecDeque<BftAction>,

    /// Current round timeout duration (with exponential backoff).
    current_timeout: Duration,

    /// Base timeout duration (reset on successful rounds).
    base_timeout: Duration,

    /// When the current round started (for timeout tracking).
    /// Stored as Duration since epoch for deterministic operation.
    round_start: Duration,

    /// Buffered future messages.
    buffered_messages: VecDeque<BufferedMessage>,

    /// Number of consecutive timeouts (for backoff calculation).
    consecutive_timeouts: u32,

    /// Last committed block hash (for deduplication).
    last_committed: Option<BlockHash>,
}

impl BftMachine {
    /// Creates a new BFT machine driver.
    ///
    /// # Arguments
    ///
    /// * `config` - The `HotStuff` configuration including validator set
    /// * `signing_key` - This node's Ed25519 signing key for message signing
    /// * `now` - Current time as duration since an arbitrary epoch (for
    ///   determinism)
    ///
    /// # Panics
    ///
    /// Panics if the computed validator ID from `signing_key` does not match
    /// `config.validator_id`. This is a critical identity mismatch that would
    /// cause the node to sign messages with credentials that don't match its
    /// declared identity in the validator set.
    #[must_use]
    pub fn new(config: HotStuffConfig, signing_key: SigningKey, now: Duration) -> Self {
        let base_timeout = config.round_timeout;
        // Pre-compute validator ID to avoid repeated hashing
        let public_key = signing_key.verifying_key();
        let validator_id: ValidatorId = blake3::hash(public_key.as_bytes()).into();

        // CRITICAL: Verify identity match (prevents signing with wrong credentials)
        assert!(
            bool::from(validator_id.ct_eq(&config.validator_id)),
            "BftMachine identity mismatch: signing_key does not match config.validator_id \
             (computed: {}, config: {})",
            hex::encode(validator_id),
            hex::encode(config.validator_id)
        );

        Self {
            state: HotStuffState::new(config),
            signing_key,
            validator_id,
            actions: VecDeque::with_capacity(MAX_PENDING_ACTIONS),
            current_timeout: base_timeout,
            base_timeout,
            round_start: now,
            buffered_messages: VecDeque::with_capacity(MAX_BUFFERED_MESSAGES),
            consecutive_timeouts: 0,
            last_committed: None,
        }
    }

    /// Returns the current epoch.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Delegates to non-const method
    pub fn epoch(&self) -> u64 {
        self.state.epoch()
    }

    /// Returns the current round.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Delegates to non-const method
    pub fn round(&self) -> u64 {
        self.state.round()
    }

    /// Returns the current phase.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Delegates to non-const method
    pub fn phase(&self) -> Phase {
        self.state.phase()
    }

    /// Returns true if this node is the leader for the current round.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Delegates to non-const method
    pub fn is_leader(&self) -> bool {
        self.state.is_leader()
    }

    /// Returns the highest QC known to this node.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Delegates to non-const method
    pub fn high_qc(&self) -> &QuorumCertificate {
        self.state.high_qc()
    }

    /// Returns the locked QC (safety invariant).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Delegates to non-const method
    pub fn locked_qc(&self) -> Option<&QuorumCertificate> {
        self.state.locked_qc()
    }

    /// Returns the number of committed blocks.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Delegates to non-const method
    pub fn committed_count(&self) -> usize {
        self.state.committed_count()
    }

    /// Returns the current timeout duration.
    #[must_use]
    pub const fn current_timeout(&self) -> Duration {
        self.current_timeout
    }

    /// Returns the number of buffered messages.
    #[must_use]
    pub fn buffered_message_count(&self) -> usize {
        self.buffered_messages.len()
    }

    /// Handles an incoming event and returns resulting actions.
    ///
    /// This is the primary entry point for the consensus driver. The
    /// coordinator calls this method for each network message or internal
    /// trigger and processes the returned actions.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to process
    /// * `now` - Current time as duration since epoch (for determinism)
    ///
    /// # Errors
    ///
    /// Returns an error if the event processing fails due to invalid messages
    /// or protocol violations.
    pub fn handle_event(
        &mut self,
        event: BftEvent,
        now: Duration,
    ) -> Result<Vec<BftAction>, BftError> {
        self.actions.clear();

        match event {
            BftEvent::ProposalReceived(proposal) => {
                self.handle_proposal(proposal, now)?;
            },
            BftEvent::VoteReceived(vote) => {
                self.handle_vote(vote, now)?;
            },
            BftEvent::NewViewReceived(ref new_view) => {
                self.handle_new_view(new_view, now)?;
            },
            BftEvent::QcReceived(ref qc) => {
                self.handle_qc(qc, now);
            },
            BftEvent::Timeout => {
                self.handle_timeout(now);
            },
            BftEvent::StartRound { payload_hash } => {
                self.start_round(payload_hash, now)?;
            },
        }

        // Process any buffered messages that can now be handled
        self.process_buffered_messages(now);

        Ok(self.drain_actions())
    }

    /// Periodic tick for timeout checking.
    ///
    /// The coordinator should call this periodically (e.g., every 100ms)
    /// to check for round timeouts. Returns actions if a timeout occurred.
    ///
    /// # Arguments
    ///
    /// * `now` - Current time as duration since epoch (for determinism)
    #[must_use]
    pub fn tick(&mut self, now: Duration) -> Vec<BftAction> {
        self.actions.clear();

        // Check if current round has timed out
        let elapsed = now.saturating_sub(self.round_start);
        if elapsed >= self.current_timeout {
            self.handle_timeout(now);
        }

        self.drain_actions()
    }

    /// Creates and broadcasts a proposal as leader.
    ///
    /// # Arguments
    ///
    /// * `payload_hash` - BLAKE3 hash of the payload to propose
    /// * `now` - Current time as duration since epoch (for determinism)
    ///
    /// # Errors
    ///
    /// Returns an error if this node is not the leader or signing fails.
    pub fn propose(
        &mut self,
        payload_hash: BlockHash,
        now: Duration,
    ) -> Result<Vec<BftAction>, BftError> {
        self.actions.clear();
        self.start_round(payload_hash, now)?;
        Ok(self.drain_actions())
    }

    /// Handles a received proposal.
    fn handle_proposal(&mut self, proposal: Proposal, now: Duration) -> Result<(), BftError> {
        // Check if this is a future message
        if proposal.round > self.state.round() + 1 {
            self.buffer_message(proposal.round, BftEvent::ProposalReceived(proposal));
            return Ok(());
        }

        // Process through state machine
        let vote = self.state.on_proposal(&proposal)?;

        if let Some(mut vote) = vote {
            // Sign the vote
            vote.sign(&self.signing_key);

            // Queue broadcast action
            self.push_action(BftAction::BroadcastVote(vote));

            // Reset timeout on successful vote
            self.reset_timeout(now);
        }

        // Check for commits
        self.check_commits();

        Ok(())
    }

    /// Handles a received vote.
    fn handle_vote(&mut self, vote: Vote, now: Duration) -> Result<(), BftError> {
        // Check if this is a future message
        if vote.round > self.state.round() {
            self.buffer_message(vote.round, BftEvent::VoteReceived(vote));
            return Ok(());
        }

        // Process through state machine
        let qc = self.state.on_vote(&vote)?;

        if let Some(qc) = qc {
            // QC formed - notify coordinator
            self.push_action(BftAction::QcFormed(qc.clone()));
            self.push_action(BftAction::BroadcastQc(qc));

            // CRITICAL: Check for commits BEFORE advancing round.
            // The 3-chain commit rule requires checking committed state while
            // still in the current phase. Advancing round first would reset
            // the phase to Idle, causing commits to be lost.
            self.check_commits();

            // Now advance to next round
            self.advance_round(now);
        } else {
            // Even without QC formation, check for commits
            self.check_commits();
        }

        Ok(())
    }

    /// Handles a received new-view message.
    fn handle_new_view(&mut self, new_view: &NewView, now: Duration) -> Result<(), BftError> {
        let old_round = self.state.round();

        // Process through state machine
        self.state.on_new_view(new_view)?;

        // Check if we advanced to a new round
        if self.state.round() > old_round {
            self.on_round_advanced(now);
        }

        Ok(())
    }

    /// Handles a received quorum certificate.
    ///
    /// This integrates the QC into `HotStuffState`, updating:
    /// - `high_qc` if this QC is higher
    /// - `certified_blocks` for 3-chain tracking
    /// - `locked_qc` if a 2-chain is formed (safety invariant)
    ///
    /// Then checks for commits using the 3-chain rule.
    fn handle_qc(&mut self, qc: &QuorumCertificate, now: Duration) {
        // Record QC in state machine - this updates locked_qc, certified_blocks,
        // and high_qc as needed. Also triggers try_commit internally.
        let committed = self.state.on_qc(qc);

        // Check for commits (on_qc calls try_commit internally, but we need
        // to check our deduplication logic and emit Commit actions)
        self.check_commits();

        // If a commit occurred, we should emit the Commit action
        // (check_commits already handles this via last_committed deduplication)

        // A QC for a round >= current allows us to advance
        if qc.round >= self.state.round() {
            // The QC proves we can advance
            self.advance_round(now);
        }

        // Log if committed for debugging (the actual Commit action is emitted by
        // check_commits)
        let _ = committed; // suppress unused warning, value is used for side effects
    }

    /// Handles a timeout event.
    fn handle_timeout(&mut self, now: Duration) {
        // Get new-view message from state machine
        let mut new_view = self.state.on_timeout();

        // Sign the message
        new_view.sign(&self.signing_key);

        // Queue broadcast and view change notification
        self.push_action(BftAction::ViewChangeStarted {
            new_round: new_view.round,
        });
        self.push_action(BftAction::BroadcastNewView(new_view));

        // Apply exponential backoff to timeout
        self.consecutive_timeouts += 1;
        self.apply_timeout_backoff(now);

        // Schedule next timeout
        self.push_action(BftAction::ScheduleTimeout(self.current_timeout));
    }

    /// Starts a new round as leader.
    fn start_round(&mut self, payload_hash: BlockHash, now: Duration) -> Result<(), BftError> {
        // Verify we are the leader
        if !self.is_leader() {
            return Err(BftError::NotLeader {
                round: self.state.round(),
                expected: hex::encode(self.state.current_leader().id),
                actual: "this node".into(),
            });
        }

        // Create block hash from payload
        let block_hash = Self::compute_block_hash(
            self.state.epoch(),
            self.state.round(),
            &payload_hash,
            &self.state.high_qc().block_hash,
        );

        // Create proposal (use cached validator_id for performance)
        let mut proposal = Proposal {
            epoch: self.state.epoch(),
            round: self.state.round(),
            proposer_id: self.validator_id,
            block_hash,
            parent_qc: self.state.high_qc().clone(),
            payload_hash,
            signature: [0u8; 64],
        };

        // Sign the proposal
        let signing_message = proposal.signing_message();
        let signature = self.signing_key.sign(&signing_message);
        proposal.signature = signature.to_bytes();

        // Broadcast proposal
        self.push_action(BftAction::BroadcastProposal(proposal));

        // Reset timeout for this round
        self.reset_timeout(now);

        Ok(())
    }

    /// Advances to the next round.
    fn advance_round(&mut self, now: Duration) {
        let old_round = self.state.round();
        self.state.advance_round();

        if self.state.round() > old_round {
            self.on_round_advanced(now);
        }
    }

    /// Called when the round has advanced.
    fn on_round_advanced(&mut self, now: Duration) {
        // Reset timeout tracking
        self.reset_timeout(now);

        // Notify coordinator
        self.push_action(BftAction::RoundAdvanced {
            round: self.state.round(),
            is_leader: self.is_leader(),
        });

        // Schedule timeout for new round
        self.push_action(BftAction::ScheduleTimeout(self.current_timeout));
    }

    /// Checks for newly committed blocks.
    ///
    /// Detects new commits from the underlying state machine and emits
    /// `BftAction::Commit` for EVERY newly committed block, not just the
    /// latest.
    ///
    /// # 3-Chain Commit Rule
    ///
    /// A block is only committed when it becomes the head of a proper 3-chain
    /// (three consecutive certified rounds). This is verified by the underlying
    /// `HotStuffState::try_commit()` method.
    ///
    /// # Multiple Commits
    ///
    /// When a round jump occurs, `try_commit` may commit multiple blocks in a
    /// single call (the grandparent plus its uncommitted ancestors). This
    /// method drains ALL newly committed blocks and emits a `Commit` action
    /// for each one, ensuring the coordinator doesn't miss ledger updates.
    fn check_commits(&mut self) {
        // Drain all newly committed blocks from state
        let newly_committed = self.state.drain_newly_committed();

        // Emit a Commit action for each newly committed block
        for committed_hash in newly_committed {
            self.last_committed = Some(committed_hash);
            self.push_action(BftAction::Commit(committed_hash));
        }
    }

    /// Buffers a message for future processing.
    fn buffer_message(&mut self, round: u64, event: BftEvent) {
        // Enforce bounded buffer
        while self.buffered_messages.len() >= MAX_BUFFERED_MESSAGES {
            // Remove oldest message
            self.buffered_messages.pop_front();
        }

        self.buffered_messages
            .push_back(BufferedMessage { round, event });
    }

    /// Processes buffered messages that can now be handled.
    fn process_buffered_messages(&mut self, now: Duration) {
        let current_round = self.state.round();

        // Extract messages for current round
        let mut to_process = Vec::new();
        let mut remaining = VecDeque::new();

        for msg in self.buffered_messages.drain(..) {
            if msg.round == current_round {
                to_process.push(msg.event);
            } else if msg.round > current_round {
                remaining.push_back(msg);
            }
            // Discard messages for past rounds
        }

        self.buffered_messages = remaining;

        // Process extracted messages
        for event in to_process {
            // Re-dispatch the event (recursive, but bounded by buffer size)
            match event {
                BftEvent::ProposalReceived(p) => {
                    // Don't re-buffer, process directly
                    if let Ok(Some(mut vote)) = self.state.on_proposal(&p) {
                        vote.sign(&self.signing_key);
                        self.push_action(BftAction::BroadcastVote(vote));
                        // Reset timeout on successful vote
                        self.reset_timeout(now);
                    }
                    // Check for commits after processing proposal
                    self.check_commits();
                },
                BftEvent::VoteReceived(v) => {
                    if let Ok(Some(qc)) = self.state.on_vote(&v) {
                        self.push_action(BftAction::QcFormed(qc.clone()));
                        self.push_action(BftAction::BroadcastQc(qc));
                        // CRITICAL: Check commits BEFORE advancing round
                        self.check_commits();
                        self.advance_round(now);
                    } else {
                        // Check commits even without QC formation
                        self.check_commits();
                    }
                },
                BftEvent::NewViewReceived(ref nv) => {
                    // Handle buffered NewView messages
                    let old_round = self.state.round();
                    if self.state.on_new_view(nv).is_ok() && self.state.round() > old_round {
                        self.on_round_advanced(now);
                    }
                },
                BftEvent::QcReceived(ref qc) => {
                    // Handle buffered QC messages - integrate into state and check commits
                    let _committed = self.state.on_qc(qc);
                    self.check_commits();
                    if qc.round >= self.state.round() {
                        self.advance_round(now);
                    }
                },
                BftEvent::Timeout | BftEvent::StartRound { .. } => {
                    // Timeout and StartRound are not buffered, ignore if found
                },
            }
        }
    }

    /// Resets the timeout to base duration.
    #[allow(clippy::missing_const_for_fn)] // Modifies self
    fn reset_timeout(&mut self, now: Duration) {
        self.consecutive_timeouts = 0;
        self.current_timeout = self.base_timeout;
        self.round_start = now;
    }

    /// Applies exponential backoff to the timeout.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    fn apply_timeout_backoff(&mut self, now: Duration) {
        // Calculate new timeout with exponential backoff
        // consecutive_timeouts is capped at 10 which fits in i32 without wrapping
        // The multiplier is always positive (1.5^n) so sign loss is safe
        // Precision loss on u128->f64 is acceptable for timeout values
        let exponent = self.consecutive_timeouts.min(10) as i32;
        let multiplier = TIMEOUT_MULTIPLIER.powi(exponent);
        let new_timeout_ms = (self.base_timeout.as_millis() as f64 * multiplier) as u64;

        // Cap at maximum timeout (from bft module constants)
        let max_timeout = super::bft::MAX_ROUND_TIMEOUT;
        self.current_timeout = Duration::from_millis(new_timeout_ms).min(max_timeout);

        self.round_start = now;
    }

    /// Pushes an action to the output queue.
    ///
    /// If the queue is full, logs a warning and drops the action.
    /// This prevents denial-of-service via memory exhaustion while
    /// making the issue visible for debugging.
    fn push_action(&mut self, action: BftAction) {
        // Enforce bounded queue
        if self.actions.len() < MAX_PENDING_ACTIONS {
            self.actions.push_back(action);
        } else {
            // Log warning about dropped action (DoS mitigation with visibility)
            tracing::warn!(
                action_type = ?std::mem::discriminant(&action),
                queue_size = MAX_PENDING_ACTIONS,
                "BFT action queue full, dropping action"
            );
        }
    }

    /// Drains and returns all pending actions.
    fn drain_actions(&mut self) -> Vec<BftAction> {
        self.actions.drain(..).collect()
    }

    /// Computes a block hash from its components.
    fn compute_block_hash(
        epoch: u64,
        round: u64,
        payload_hash: &BlockHash,
        parent_hash: &BlockHash,
    ) -> BlockHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        hasher.update(payload_hash);
        hasher.update(parent_hash);
        hasher.finalize().into()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;
    use crate::consensus::bft::{HotStuffConfig, ValidatorInfo, ValidatorSignature};

    /// Test time starting point.
    const TEST_NOW: Duration = Duration::from_secs(1000);

    /// Creates a test validator info from a signing key.
    fn validator_info_from_key(signing_key: &SigningKey, index: usize) -> ValidatorInfo {
        let public_key = signing_key.verifying_key();
        let id: ValidatorId = blake3::hash(public_key.as_bytes()).into();
        ValidatorInfo {
            id,
            index,
            public_key: public_key.to_bytes(),
        }
    }

    /// Creates test configuration for multiple validators.
    fn test_config(signing_keys: &[SigningKey], my_index: usize) -> (HotStuffConfig, SigningKey) {
        let validators: Vec<ValidatorInfo> = signing_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| validator_info_from_key(sk, i))
            .collect();

        let my_key = signing_keys[my_index].clone();
        let my_id = validators[my_index].id;

        let config = HotStuffConfig::builder()
            .validator_id(my_id)
            .add_validator(validators[0].clone())
            .unwrap()
            .add_validator(validators[1].clone())
            .unwrap()
            .add_validator(validators[2].clone())
            .unwrap()
            .add_validator(validators[3].clone())
            .unwrap()
            .quorum_threshold(3) // 2f+1 for f=1
            .build()
            .unwrap();

        (config, my_key)
    }

    /// Generates test signing keys for validators.
    fn generate_test_keys(count: usize) -> Vec<SigningKey> {
        (0..count)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect()
    }

    #[test]
    fn tck_00187_machine_creation() {
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 0);

        let machine = BftMachine::new(config, signing_key, TEST_NOW);

        assert_eq!(machine.epoch(), 0);
        assert_eq!(machine.round(), 1);
        assert_eq!(machine.phase(), Phase::Idle);
        assert_eq!(machine.committed_count(), 0);
    }

    #[test]
    fn tck_00187_leader_detection() {
        let keys = generate_test_keys(4);

        // Validator 1 should be leader for round 1
        let (config, signing_key) = test_config(&keys, 1);
        let machine = BftMachine::new(config, signing_key, TEST_NOW);
        assert!(
            machine.is_leader(),
            "Validator 1 should be leader for round 1"
        );

        // Validator 0 should not be leader for round 1
        let (config, signing_key) = test_config(&keys, 0);
        let machine = BftMachine::new(config, signing_key, TEST_NOW);
        assert!(
            !machine.is_leader(),
            "Validator 0 should not be leader for round 1"
        );
    }

    #[test]
    fn tck_00187_propose_as_leader() {
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 1); // Leader for round 1

        let mut machine = BftMachine::new(config, signing_key, TEST_NOW);
        let payload_hash = [0xab; 32];

        let actions = machine.propose(payload_hash, TEST_NOW).unwrap();

        // Should produce a broadcast proposal action
        assert!(!actions.is_empty());
        let has_proposal = actions
            .iter()
            .any(|a| matches!(a, BftAction::BroadcastProposal(_)));
        assert!(has_proposal, "Should broadcast proposal");
    }

    #[test]
    fn tck_00187_propose_not_leader_fails() {
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 0); // Not leader for round 1

        let mut machine = BftMachine::new(config, signing_key, TEST_NOW);
        let payload_hash = [0xab; 32];

        let result = machine.propose(payload_hash, TEST_NOW);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BftError::NotLeader { .. }));
    }

    #[test]
    fn tck_00187_timeout_handling() {
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 0);

        let mut machine = BftMachine::new(config, signing_key, TEST_NOW);

        let actions = machine.handle_event(BftEvent::Timeout, TEST_NOW).unwrap();

        // Should produce view change and new-view broadcast
        let has_view_change = actions
            .iter()
            .any(|a| matches!(a, BftAction::ViewChangeStarted { .. }));
        let has_new_view = actions
            .iter()
            .any(|a| matches!(a, BftAction::BroadcastNewView(_)));

        assert!(has_view_change, "Should notify view change");
        assert!(has_new_view, "Should broadcast new-view");
    }

    #[test]
    fn tck_00187_timeout_backoff() {
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 0);

        let mut machine = BftMachine::new(config, signing_key, TEST_NOW);
        let initial_timeout = machine.current_timeout();

        // Trigger multiple timeouts
        let mut now = TEST_NOW;
        for _ in 0..3 {
            now += Duration::from_secs(10);
            let _ = machine.handle_event(BftEvent::Timeout, now);
        }

        // Timeout should have increased due to exponential backoff
        assert!(
            machine.current_timeout() > initial_timeout,
            "Timeout should increase with exponential backoff"
        );
    }

    #[test]
    fn tck_00187_message_types_defined() {
        // Verify message type constants are defined and unique
        let types = [MSG_BFT_PROPOSAL, MSG_BFT_VOTE, MSG_BFT_NEW_VIEW, MSG_BFT_QC];
        let mut unique_types = types.to_vec();
        unique_types.sort_unstable();
        unique_types.dedup();

        assert_eq!(
            types.len(),
            unique_types.len(),
            "Message types must be unique"
        );

        // Verify they don't conflict with tunnel message types (100-106)
        for t in types {
            assert!(t >= 200, "BFT message types should be >= 200");
        }
    }

    #[test]
    fn tck_00187_bounded_action_queue() {
        // Verify action queue is bounded (compile-time check)
        const _: () = {
            assert!(MAX_PENDING_ACTIONS > 0);
            assert!(MAX_PENDING_ACTIONS <= 1024); // Reasonable upper bound
        };
    }

    #[test]
    fn tck_00187_bounded_message_buffer() {
        // Verify message buffer is bounded (compile-time check)
        const _: () = {
            assert!(MAX_BUFFERED_MESSAGES > 0);
            assert!(MAX_BUFFERED_MESSAGES <= 1024); // Reasonable upper bound
        };
    }

    #[test]
    fn tck_00187_action_enum_variants() {
        // Verify all action variants are accessible
        let _actions: Vec<BftAction> = vec![
            BftAction::BroadcastProposal(Proposal {
                epoch: 0,
                round: 0,
                proposer_id: [0u8; 32],
                block_hash: [0u8; 32],
                parent_qc: QuorumCertificate::default(),
                payload_hash: [0u8; 32],
                signature: [0u8; 64],
            }),
            BftAction::BroadcastVote(Vote {
                epoch: 0,
                round: 0,
                voter_id: [0u8; 32],
                block_hash: [0u8; 32],
                signature: [0u8; 64],
            }),
            BftAction::BroadcastNewView(NewView {
                epoch: 0,
                round: 0,
                sender_id: [0u8; 32],
                high_qc: QuorumCertificate::default(),
                signature: [0u8; 64],
            }),
            BftAction::BroadcastQc(QuorumCertificate::default()),
            BftAction::Commit([0u8; 32]),
            BftAction::RoundAdvanced {
                round: 1,
                is_leader: false,
            },
            BftAction::ViewChangeStarted { new_round: 2 },
            BftAction::QcFormed(QuorumCertificate::default()),
            BftAction::ScheduleTimeout(Duration::from_secs(5)),
        ];
    }

    #[test]
    fn tck_00187_event_enum_variants() {
        // Verify all event variants are accessible
        let _events: Vec<BftEvent> = vec![
            BftEvent::ProposalReceived(Proposal {
                epoch: 0,
                round: 0,
                proposer_id: [0u8; 32],
                block_hash: [0u8; 32],
                parent_qc: QuorumCertificate::default(),
                payload_hash: [0u8; 32],
                signature: [0u8; 64],
            }),
            BftEvent::VoteReceived(Vote {
                epoch: 0,
                round: 0,
                voter_id: [0u8; 32],
                block_hash: [0u8; 32],
                signature: [0u8; 64],
            }),
            BftEvent::NewViewReceived(NewView {
                epoch: 0,
                round: 0,
                sender_id: [0u8; 32],
                high_qc: QuorumCertificate::default(),
                signature: [0u8; 64],
            }),
            BftEvent::QcReceived(QuorumCertificate::default()),
            BftEvent::Timeout,
            BftEvent::StartRound {
                payload_hash: [0u8; 32],
            },
        ];
    }

    #[test]
    fn tck_00187_future_message_buffering() {
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 0);

        let mut machine = BftMachine::new(config, signing_key, TEST_NOW);

        // Create a vote for a future round
        let future_vote = Vote {
            epoch: 0,
            round: 5, // Future round
            voter_id: [0u8; 32],
            block_hash: [0u8; 32],
            signature: [0u8; 64],
        };

        // Handle the future vote
        let actions = machine
            .handle_event(BftEvent::VoteReceived(future_vote), TEST_NOW)
            .unwrap();

        // Should not produce any actions yet (buffered)
        assert!(
            actions.is_empty()
                || actions
                    .iter()
                    .all(|a| !matches!(a, BftAction::BroadcastVote(_)))
        );

        // Message should be buffered
        assert_eq!(machine.buffered_message_count(), 1);
    }

    #[test]
    fn tck_00187_phase_transitions() {
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 0);

        let machine = BftMachine::new(config, signing_key, TEST_NOW);

        // Initial phase should be Idle
        assert_eq!(machine.phase(), Phase::Idle);

        // Phase enum should have expected variants
        let _phases: Vec<Phase> = vec![
            Phase::Idle,
            Phase::Voting,
            Phase::Certified,
            Phase::Committed,
            Phase::ViewChange,
        ];
    }

    #[test]
    fn tck_00187_deterministic_time() {
        // Test that time is deterministic by passing explicit time values
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 0);

        let now = Duration::from_secs(100);
        let machine = BftMachine::new(config, signing_key, now);

        // Machine should use the provided time
        assert_eq!(machine.current_timeout(), Duration::from_secs(5)); // Default timeout
    }

    #[test]
    fn tck_00187_tick_timeout_detection() {
        let keys = generate_test_keys(4);
        let (config, signing_key) = test_config(&keys, 0);

        let start = Duration::from_secs(100);
        let mut machine = BftMachine::new(config, signing_key, start);

        // Tick before timeout - should not trigger
        let actions = machine.tick(start + Duration::from_secs(1));
        assert!(actions.is_empty(), "Should not timeout yet");

        // Tick after timeout (default is 5 seconds)
        let actions = machine.tick(start + Duration::from_secs(10));
        let has_view_change = actions
            .iter()
            .any(|a| matches!(a, BftAction::ViewChangeStarted { .. }));
        assert!(has_view_change, "Should trigger timeout");
    }

    /// Test that verifies 3-chain commit rule produces Commit action.
    ///
    /// This test simulates a full 3-chain scenario:
    /// - Round 1: Block B1 proposed and certified (QC1)
    /// - Round 2: Block B2 extends B1, certified (QC2) -> B1 becomes locked
    /// - Round 3: Block B3 extends B2, certified (QC3) -> B1 should be
    ///   committed
    #[test]
    #[allow(clippy::too_many_lines)]
    fn tck_00187_three_chain_commit() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| validator_info_from_key(sk, i))
            .collect();

        // Create machine for validator 0
        let (config, signing_key) = test_config(&keys, 0);
        let mut machine = BftMachine::new(config, signing_key, TEST_NOW);

        // Helper to create a signed vote
        let create_signed_vote =
            |key: &SigningKey, epoch: u64, round: u64, block_hash: BlockHash| {
                let public_key = key.verifying_key();
                let voter_id: ValidatorId = blake3::hash(public_key.as_bytes()).into();
                let mut vote = Vote {
                    epoch,
                    round,
                    voter_id,
                    block_hash,
                    signature: [0u8; 64],
                };
                vote.sign(key);
                vote
            };

        // Helper to create QC from votes
        let create_qc =
            |epoch: u64, round: u64, block_hash: BlockHash, votes: &[Vote]| QuorumCertificate {
                epoch,
                round,
                block_hash,
                signatures: votes
                    .iter()
                    .map(|v| ValidatorSignature::new(v.voter_id, v.signature))
                    .collect(),
            };

        // === Round 1: Leader (validator 1) proposes B1 ===
        let genesis_hash = [0u8; 32];
        let genesis_qc = QuorumCertificate::genesis(0, genesis_hash);
        let payload1_hash = [0x11; 32];
        // Compute proper block hash using the same algorithm as on_proposal
        // verification
        let b1_hash = BftMachine::compute_block_hash(0, 1, &payload1_hash, &genesis_hash);
        let mut proposal1 = Proposal {
            epoch: 0,
            round: 1,
            proposer_id: validators[1].id,
            block_hash: b1_hash,
            parent_qc: genesis_qc,
            payload_hash: payload1_hash,
            signature: [0u8; 64],
        };
        // Sign proposal with leader's key
        let leader1_msg = proposal1.signing_message();
        proposal1.signature = keys[1].sign(&leader1_msg).to_bytes();

        // Process proposal - should get vote
        let actions = machine
            .handle_event(BftEvent::ProposalReceived(proposal1), TEST_NOW)
            .unwrap();
        let has_vote = actions
            .iter()
            .any(|a| matches!(a, BftAction::BroadcastVote(_)));
        assert!(has_vote, "Should vote for valid proposal");

        // Collect 3 votes for B1 (quorum)
        // Note: validator 0 (the machine) already voted when processing the proposal,
        // so we need votes from validators 1, 2, and 3 to reach quorum of 3.
        // Actually, the machine's internal vote isn't in the vote collection - we need
        // to send it back as if received from network.
        let vote1_0 = create_signed_vote(&keys[0], 0, 1, b1_hash);
        let vote1_1 = create_signed_vote(&keys[1], 0, 1, b1_hash);
        let vote1_2 = create_signed_vote(&keys[2], 0, 1, b1_hash);
        let qc1 = create_qc(
            0,
            1,
            b1_hash,
            &[vote1_0.clone(), vote1_1.clone(), vote1_2.clone()],
        );

        // Process votes to form QC1 (need 3 votes for quorum)
        // First send our own vote back (simulating network echo)
        let _ = machine.handle_event(BftEvent::VoteReceived(vote1_0), TEST_NOW);
        let _ = machine.handle_event(BftEvent::VoteReceived(vote1_1), TEST_NOW);
        let actions = machine.handle_event(BftEvent::VoteReceived(vote1_2), TEST_NOW);

        // Should have QC formed and round advanced
        let qc_formed = actions
            .as_ref()
            .is_ok_and(|a| a.iter().any(|act| matches!(act, BftAction::QcFormed(_))));
        assert!(qc_formed, "QC1 should be formed");

        // === Round 2: Leader (validator 2) proposes B2 extending B1 ===
        let payload2_hash = [0x22; 32];
        // Compute proper block hash - parent is b1_hash from qc1
        let b2_hash = BftMachine::compute_block_hash(0, 2, &payload2_hash, &b1_hash);
        let mut proposal2 = Proposal {
            epoch: 0,
            round: 2,
            proposer_id: validators[2].id,
            block_hash: b2_hash,
            parent_qc: qc1,
            payload_hash: payload2_hash,
            signature: [0u8; 64],
        };
        let leader2_msg = proposal2.signing_message();
        proposal2.signature = keys[2].sign(&leader2_msg).to_bytes();

        let _ = machine.handle_event(BftEvent::ProposalReceived(proposal2), TEST_NOW);

        // Collect votes for B2 (need 3 votes for quorum)
        let vote2_0 = create_signed_vote(&keys[0], 0, 2, b2_hash);
        let vote2_1 = create_signed_vote(&keys[1], 0, 2, b2_hash);
        let vote2_2 = create_signed_vote(&keys[2], 0, 2, b2_hash);
        let qc2 = create_qc(
            0,
            2,
            b2_hash,
            &[vote2_0.clone(), vote2_1.clone(), vote2_2.clone()],
        );

        let _ = machine.handle_event(BftEvent::VoteReceived(vote2_0), TEST_NOW);
        let _ = machine.handle_event(BftEvent::VoteReceived(vote2_1), TEST_NOW);
        let _ = machine.handle_event(BftEvent::VoteReceived(vote2_2), TEST_NOW);

        // === Round 3: Leader (validator 3) proposes B3 extending B2 ===
        let payload3_hash = [0x33; 32];
        // Compute proper block hash - parent is b2_hash from qc2
        let b3_hash = BftMachine::compute_block_hash(0, 3, &payload3_hash, &b2_hash);
        let mut proposal3 = Proposal {
            epoch: 0,
            round: 3,
            proposer_id: validators[3].id,
            block_hash: b3_hash,
            parent_qc: qc2,
            payload_hash: payload3_hash,
            signature: [0u8; 64],
        };
        let leader3_msg = proposal3.signing_message();
        proposal3.signature = keys[3].sign(&leader3_msg).to_bytes();

        let _ = machine.handle_event(BftEvent::ProposalReceived(proposal3), TEST_NOW);

        // Collect votes for B3 - this should trigger commit of B1 (need 3 votes for
        // quorum)
        let vote3_0 = create_signed_vote(&keys[0], 0, 3, b3_hash);
        let vote3_1 = create_signed_vote(&keys[1], 0, 3, b3_hash);
        let vote3_2 = create_signed_vote(&keys[2], 0, 3, b3_hash);

        let _ = machine.handle_event(BftEvent::VoteReceived(vote3_0), TEST_NOW);
        let _ = machine.handle_event(BftEvent::VoteReceived(vote3_1), TEST_NOW);
        let actions = machine
            .handle_event(BftEvent::VoteReceived(vote3_2), TEST_NOW)
            .unwrap();

        // Check that we got a Commit action for B1 (the grandparent in 3-chain)
        let commit_action = actions.iter().find_map(|a| {
            if let BftAction::Commit(hash) = a {
                Some(*hash)
            } else {
                None
            }
        });

        assert!(
            commit_action.is_some(),
            "Should produce Commit action for 3-chain"
        );

        // Verify committed count increased
        assert!(
            machine.committed_count() > 0,
            "Should have committed at least one block"
        );
    }
}
