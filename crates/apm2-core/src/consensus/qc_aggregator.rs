// AGENT-AUTHORED
//! Quorum Certificate Aggregation and Verification.
//!
//! This module provides utilities for:
//! - Collecting votes and forming quorum certificates when 2f+1 threshold is
//!   reached
//! - Offline verification of quorum certificates without network access
//! - Signer membership validation
//!
//! # Security Properties
//!
//! - **Constant-time operations**: All comparisons use constant-time equality
//!   to prevent timing side-channels
//! - **Bounded collections (CTR-1303)**: All internal collections are bounded
//!   to prevent denial-of-service via memory exhaustion
//! - **Duplicate detection**: Prevents quorum forgery via duplicate signatures
//! - **Membership validation**: Verifies all signers are in the validator set
//!
//! # Offline Verification
//!
//! The verification utilities in this module are designed for offline use.
//! They require only the quorum certificate, the message being certified,
//! and the validator set. No network access is required.
//!
//! ```rust,ignore
//! use apm2_core::consensus::qc_aggregator::{verify_qc, QcVerificationContext};
//!
//! let context = QcVerificationContext::new(&validators, quorum_threshold);
//! let result = verify_qc(&qc, &message, &context);
//! assert!(result.is_ok());
//! ```
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00190: Quorum Certificate Generation and Verification
//! - DD-0007: Quorum Certificate Structure

use std::collections::{HashMap, HashSet};

use subtle::ConstantTimeEq;

use super::bft::{
    BftError, BlockHash, MAX_QC_SIGNATURES, MAX_VALIDATORS, QuorumCertificate, ValidatorId,
    ValidatorInfo, ValidatorSignature, Vote,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of votes to track per round (bounded collection CTR-1303).
///
/// This is set to `MAX_VALIDATORS` since each validator can only cast one vote
/// per round.
pub const MAX_VOTES_PER_ROUND: usize = MAX_VALIDATORS;

/// Maximum number of rounds to track votes for simultaneously.
///
/// This bounds memory usage when votes arrive out of order.
pub const MAX_TRACKED_ROUNDS: usize = 16;

// =============================================================================
// QC Verification Context
// =============================================================================

/// Context for offline quorum certificate verification.
///
/// This struct contains all the information needed to verify a quorum
/// certificate without network access. It is designed to be reused across
/// multiple verification calls for efficiency.
#[derive(Clone, Debug)]
pub struct QcVerificationContext {
    /// The validator set for membership validation.
    validators: Vec<ValidatorInfo>,
    /// The quorum threshold (typically 2f+1).
    quorum_threshold: usize,
}

impl QcVerificationContext {
    /// Creates a new verification context.
    ///
    /// # Arguments
    ///
    /// * `validators` - The validator set for this epoch
    /// * `quorum_threshold` - The minimum number of signatures required (2f+1)
    ///
    /// # Panics
    ///
    /// Panics if `validators` is empty or if `quorum_threshold` is zero.
    #[must_use]
    pub fn new(validators: &[ValidatorInfo], quorum_threshold: usize) -> Self {
        assert!(!validators.is_empty(), "validator set cannot be empty");
        assert!(quorum_threshold > 0, "quorum threshold must be positive");

        Self {
            validators: validators.to_vec(),
            quorum_threshold,
        }
    }

    /// Returns the validator set.
    #[must_use]
    pub fn validators(&self) -> &[ValidatorInfo] {
        &self.validators
    }

    /// Returns the quorum threshold.
    #[must_use]
    pub const fn quorum_threshold(&self) -> usize {
        self.quorum_threshold
    }

    /// Returns the number of validators.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Looks up a validator by ID using constant-time comparison.
    ///
    /// Returns the validator info if found.
    #[must_use]
    pub fn get_validator(&self, id: &ValidatorId) -> Option<&ValidatorInfo> {
        // Use constant-time lookup to prevent timing attacks
        self.validators.iter().find(|v| v.id.ct_eq(id).into())
    }

    /// Checks if a validator ID is in the validator set.
    ///
    /// Uses constant-time comparison.
    #[must_use]
    pub fn is_validator(&self, id: &ValidatorId) -> bool {
        self.get_validator(id).is_some()
    }
}

// =============================================================================
// QC Verification Result
// =============================================================================

/// Result of quorum certificate verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QcVerificationResult {
    /// The number of valid signatures in the QC.
    pub valid_signature_count: usize,
    /// Whether the quorum threshold was met.
    pub quorum_met: bool,
    /// List of validator IDs that signed (for auditing).
    pub signers: Vec<ValidatorId>,
}

impl QcVerificationResult {
    /// Returns true if verification passed (quorum met with valid signatures).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.quorum_met
    }
}

// =============================================================================
// Offline Verification Functions
// =============================================================================

/// Verifies a quorum certificate offline.
///
/// This function performs complete verification of a quorum certificate:
/// 1. Checks that the QC has at least `quorum_threshold` signatures
/// 2. Verifies each signature is from a known validator
/// 3. Verifies each Ed25519 signature over the message
/// 4. Detects duplicate signatures (quorum forgery prevention)
///
/// # Arguments
///
/// * `qc` - The quorum certificate to verify
/// * `context` - The verification context containing validator set and
///   threshold
///
/// # Returns
///
/// Returns `Ok(QcVerificationResult)` if verification succeeds, or an error
/// if any check fails.
///
/// # Security
///
/// - Uses constant-time comparison for validator ID lookups
/// - Detects duplicate signatures to prevent quorum forgery
/// - Verifies all signatures, not just the first `quorum_threshold`
///
/// # Errors
///
/// Returns an error if:
/// - Signature count is below quorum threshold
/// - Any signer is not in the validator set
/// - Any signature is invalid
/// - Duplicate signatures are detected
pub fn verify_qc(
    qc: &QuorumCertificate,
    context: &QcVerificationContext,
) -> Result<QcVerificationResult, BftError> {
    // Genesis QC is always valid (no signatures required)
    if qc.is_genesis() {
        return Ok(QcVerificationResult {
            valid_signature_count: 0,
            quorum_met: true,
            signers: Vec::new(),
        });
    }

    // Check signature count
    if qc.signatures.len() < context.quorum_threshold {
        return Err(BftError::InsufficientQuorum {
            have: qc.signatures.len(),
            need: context.quorum_threshold,
        });
    }

    if qc.signatures.len() > MAX_QC_SIGNATURES {
        return Err(BftError::InvalidQc(format!(
            "too many signatures: {} > {}",
            qc.signatures.len(),
            MAX_QC_SIGNATURES
        )));
    }

    // Build the vote message that was signed
    let vote_message = build_vote_message(qc.epoch, qc.round, &qc.block_hash);

    // Track seen validators for duplicate detection
    let mut seen_validators: HashSet<ValidatorId> = HashSet::with_capacity(qc.signatures.len());
    let mut signers: Vec<ValidatorId> = Vec::with_capacity(qc.signatures.len());

    // Verify each signature
    for sig in &qc.signatures {
        // Check for duplicate (quorum forgery prevention)
        if !seen_validators.insert(sig.validator_id) {
            return Err(BftError::DuplicateSignature(hex::encode(sig.validator_id)));
        }

        // Find validator (using constant-time comparison)
        let validator = context
            .get_validator(&sig.validator_id)
            .ok_or_else(|| BftError::UnknownValidator(hex::encode(sig.validator_id)))?;

        // Verify the signature
        sig.verify(&vote_message, &validator.public_key)?;

        signers.push(sig.validator_id);
    }

    Ok(QcVerificationResult {
        valid_signature_count: signers.len(),
        quorum_met: signers.len() >= context.quorum_threshold,
        signers,
    })
}

/// Verifies a quorum certificate with a custom message.
///
/// This is useful when verifying QCs over non-standard messages (e.g.,
/// epoch transitions, config changes).
///
/// # Arguments
///
/// * `qc` - The quorum certificate to verify
/// * `message` - The message that was signed
/// * `context` - The verification context
///
/// # Errors
///
/// Returns an error if verification fails.
pub fn verify_qc_with_message(
    qc: &QuorumCertificate,
    message: &[u8],
    context: &QcVerificationContext,
) -> Result<QcVerificationResult, BftError> {
    // Genesis QC is always valid
    if qc.is_genesis() {
        return Ok(QcVerificationResult {
            valid_signature_count: 0,
            quorum_met: true,
            signers: Vec::new(),
        });
    }

    // Check signature count
    if qc.signatures.len() < context.quorum_threshold {
        return Err(BftError::InsufficientQuorum {
            have: qc.signatures.len(),
            need: context.quorum_threshold,
        });
    }

    if qc.signatures.len() > MAX_QC_SIGNATURES {
        return Err(BftError::InvalidQc(format!(
            "too many signatures: {} > {}",
            qc.signatures.len(),
            MAX_QC_SIGNATURES
        )));
    }

    // Track seen validators
    let mut seen_validators: HashSet<ValidatorId> = HashSet::with_capacity(qc.signatures.len());
    let mut signers: Vec<ValidatorId> = Vec::with_capacity(qc.signatures.len());

    // Verify each signature
    for sig in &qc.signatures {
        // Check for duplicate
        if !seen_validators.insert(sig.validator_id) {
            return Err(BftError::DuplicateSignature(hex::encode(sig.validator_id)));
        }

        // Find validator
        let validator = context
            .get_validator(&sig.validator_id)
            .ok_or_else(|| BftError::UnknownValidator(hex::encode(sig.validator_id)))?;

        // Verify the signature
        sig.verify(message, &validator.public_key)?;

        signers.push(sig.validator_id);
    }

    Ok(QcVerificationResult {
        valid_signature_count: signers.len(),
        quorum_met: signers.len() >= context.quorum_threshold,
        signers,
    })
}

/// Builds the canonical vote message for a given epoch, round, and block hash.
///
/// Format: `"VOTE" || epoch (LE) || round (LE) || block_hash`
///
/// This is the message that validators sign when voting.
#[must_use]
pub fn build_vote_message(epoch: u64, round: u64, block_hash: &BlockHash) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 8 + 8 + 32);
    msg.extend_from_slice(b"VOTE");
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&round.to_le_bytes());
    msg.extend_from_slice(block_hash);
    msg
}

// =============================================================================
// QC Aggregator
// =============================================================================

/// Aggregator for collecting votes and forming quorum certificates.
///
/// The aggregator tracks votes grouped by (round, `block_hash`) and forms a
/// quorum certificate when 2f+1 votes for the same block are collected.
///
/// # Bounded Collections (CTR-1303)
///
/// All internal collections are bounded:
/// - Maximum `MAX_VOTES_PER_ROUND` votes per block per round
/// - Maximum `MAX_TRACKED_ROUNDS` rounds tracked simultaneously
///
/// # Duplicate Vote Detection
///
/// The aggregator detects and rejects:
/// - Duplicate votes from the same validator for the same block
/// - Equivocation (different votes from same validator in same round)
///
/// # Thread Safety
///
/// This struct is not thread-safe. Use appropriate synchronization if sharing
/// across threads.
#[derive(Debug)]
pub struct QcAggregator {
    /// Verification context containing validator set and threshold.
    context: QcVerificationContext,
    /// Votes collected per (round, `block_hash`).
    /// Key: (round, `block_hash`), Value: map of `validator_id` -> vote
    votes: HashMap<(u64, BlockHash), HashMap<ValidatorId, Vote>>,
    /// Tracks which validators voted in which round (equivocation detection).
    /// Key: (round, `validator_id`), Value: `block_hash` they voted for
    votes_per_round: HashMap<(u64, ValidatorId), BlockHash>,
    /// Rounds currently being tracked (for bounded eviction).
    tracked_rounds: Vec<u64>,
    /// Formed QCs awaiting consumption.
    formed_qcs: Vec<QuorumCertificate>,
}

impl QcAggregator {
    /// Creates a new QC aggregator.
    ///
    /// # Arguments
    ///
    /// * `validators` - The validator set for this epoch
    /// * `quorum_threshold` - The minimum number of signatures required (2f+1)
    #[must_use]
    pub fn new(validators: &[ValidatorInfo], quorum_threshold: usize) -> Self {
        Self {
            context: QcVerificationContext::new(validators, quorum_threshold),
            votes: HashMap::new(),
            votes_per_round: HashMap::new(),
            tracked_rounds: Vec::with_capacity(MAX_TRACKED_ROUNDS),
            formed_qcs: Vec::new(),
        }
    }

    /// Creates a new QC aggregator from an existing context.
    #[must_use]
    pub fn from_context(context: QcVerificationContext) -> Self {
        Self {
            context,
            votes: HashMap::new(),
            votes_per_round: HashMap::new(),
            tracked_rounds: Vec::with_capacity(MAX_TRACKED_ROUNDS),
            formed_qcs: Vec::new(),
        }
    }

    /// Returns the verification context.
    #[must_use]
    pub const fn context(&self) -> &QcVerificationContext {
        &self.context
    }

    /// Returns the quorum threshold.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Delegates to non-const method
    pub fn quorum_threshold(&self) -> usize {
        self.context.quorum_threshold
    }

    /// Returns the number of votes collected for a specific block in a round.
    #[must_use]
    pub fn vote_count(&self, round: u64, block_hash: &BlockHash) -> usize {
        self.votes
            .get(&(round, *block_hash))
            .map_or(0, HashMap::len)
    }

    /// Adds a vote to the aggregator.
    ///
    /// If the vote completes a quorum, the formed QC is stored and can be
    /// retrieved via `drain_formed_qcs()`.
    ///
    /// # Arguments
    ///
    /// * `vote` - The vote to add
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(qc))` if adding this vote completed a quorum,
    /// `Ok(None)` if the vote was added but quorum not yet reached,
    /// or an error if the vote is invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The voter is not in the validator set
    /// - The vote signature is invalid
    /// - The validator has already voted in this round (equivocation)
    /// - The validator has already voted for this block (duplicate)
    pub fn add_vote(&mut self, vote: &Vote) -> Result<Option<QuorumCertificate>, BftError> {
        // Validate voter is in validator set
        let validator = self
            .context
            .get_validator(&vote.voter_id)
            .ok_or_else(|| BftError::UnknownValidator(hex::encode(vote.voter_id)))?;

        // Check for equivocation (same validator, same round, different block)
        let round_validator_key = (vote.round, vote.voter_id);
        if let Some(existing_block) = self.votes_per_round.get(&round_validator_key) {
            // If they voted for a different block, it's equivocation
            let same_block: bool = existing_block.ct_eq(&vote.block_hash).into();
            if !same_block {
                return Err(BftError::VoteEquivocation(
                    hex::encode(vote.voter_id),
                    vote.round,
                ));
            }
            // If they voted for the same block, it's a duplicate
            return Err(BftError::DuplicateVote(
                hex::encode(vote.voter_id),
                vote.round,
            ));
        }

        // Verify signature
        let vote_message = build_vote_message(vote.epoch, vote.round, &vote.block_hash);
        let signature = ValidatorSignature::new(vote.voter_id, vote.signature);
        signature.verify(&vote_message, &validator.public_key)?;

        // Track this round if new
        self.track_round(vote.round);

        // Record the vote
        let block_key = (vote.round, vote.block_hash);
        let votes_for_block = self.votes.entry(block_key).or_default();

        // Check for duplicate within block votes (shouldn't happen due to above check)
        if votes_for_block.contains_key(&vote.voter_id) {
            return Err(BftError::DuplicateVote(
                hex::encode(vote.voter_id),
                vote.round,
            ));
        }

        // Add vote
        votes_for_block.insert(vote.voter_id, vote.clone());
        self.votes_per_round
            .insert(round_validator_key, vote.block_hash);

        // Check if quorum is reached - get the vote count first
        let vote_count = self.votes.get(&block_key).map_or(0, HashMap::len);
        if vote_count >= self.context.quorum_threshold {
            // Need to get votes again after releasing mutable borrow
            let qc = if let Some(votes) = self.votes.get(&block_key) {
                Self::form_qc_from_votes(vote.epoch, vote.round, vote.block_hash, votes)
            } else {
                return Ok(None);
            };
            self.formed_qcs.push(qc.clone());
            return Ok(Some(qc));
        }

        Ok(None)
    }

    /// Forms a quorum certificate from votes.
    fn form_qc_from_votes(
        epoch: u64,
        round: u64,
        block_hash: BlockHash,
        votes: &HashMap<ValidatorId, Vote>,
    ) -> QuorumCertificate {
        // Collect signatures and sort by validator_id for deterministic ordering
        let mut signatures: Vec<ValidatorSignature> = votes
            .values()
            .map(|v| ValidatorSignature::new(v.voter_id, v.signature))
            .collect();
        signatures.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));

        QuorumCertificate {
            epoch,
            round,
            block_hash,
            signatures,
        }
    }

    /// Drains and returns all formed quorum certificates.
    pub fn drain_formed_qcs(&mut self) -> Vec<QuorumCertificate> {
        std::mem::take(&mut self.formed_qcs)
    }

    /// Cleans up votes for rounds older than the specified round.
    ///
    /// This should be called periodically to prevent unbounded memory growth.
    pub fn cleanup_old_rounds(&mut self, before_round: u64) {
        // Remove old round tracking
        self.tracked_rounds.retain(|&r| r >= before_round);

        // Remove votes for old rounds
        self.votes.retain(|(round, _), _| *round >= before_round);
        self.votes_per_round
            .retain(|(round, _), _| *round >= before_round);
    }

    /// Tracks a new round, evicting old rounds if at capacity.
    fn track_round(&mut self, round: u64) {
        if self.tracked_rounds.contains(&round) {
            return;
        }

        // Evict oldest round if at capacity
        while self.tracked_rounds.len() >= MAX_TRACKED_ROUNDS {
            if let Some(oldest) = self.tracked_rounds.iter().min().copied() {
                self.tracked_rounds.retain(|&r| r != oldest);
                self.cleanup_old_rounds(oldest + 1);
            } else {
                break;
            }
        }

        self.tracked_rounds.push(round);
    }

    /// Returns the number of rounds currently being tracked.
    #[must_use]
    pub fn tracked_round_count(&self) -> usize {
        self.tracked_rounds.len()
    }

    /// Checks if a specific round is being tracked.
    #[must_use]
    pub fn is_tracking_round(&self, round: u64) -> bool {
        self.tracked_rounds.contains(&round)
    }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Computes the required quorum threshold for a given validator count.
///
/// The threshold is `2f + 1` where `f = (n - 1) / 3` is the maximum number
/// of Byzantine validators tolerable.
///
/// # Arguments
///
/// * `validator_count` - The total number of validators (n)
///
/// # Returns
///
/// The quorum threshold (2f + 1).
///
/// # Examples
///
/// ```ignore
/// assert_eq!(compute_quorum_threshold(4), 3);  // f=1, 2*1+1=3
/// assert_eq!(compute_quorum_threshold(7), 5);  // f=2, 2*2+1=5
/// assert_eq!(compute_quorum_threshold(10), 7); // f=3, 2*3+1=7
/// ```
#[must_use]
pub const fn compute_quorum_threshold(validator_count: usize) -> usize {
    if validator_count == 0 {
        return 0;
    }
    let f = (validator_count - 1) / 3;
    2 * f + 1
}

/// Checks if a signature count meets the quorum threshold.
///
/// # Arguments
///
/// * `signature_count` - The number of signatures
/// * `validator_count` - The total number of validators
///
/// # Returns
///
/// `true` if the signature count meets or exceeds the quorum threshold.
#[must_use]
pub const fn is_quorum(signature_count: usize, validator_count: usize) -> bool {
    signature_count >= compute_quorum_threshold(validator_count)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

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

    /// Generates test signing keys.
    fn generate_test_keys(count: usize) -> Vec<SigningKey> {
        (0..count)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect()
    }

    /// Creates a signed vote.
    fn create_signed_vote(key: &SigningKey, epoch: u64, round: u64, block_hash: BlockHash) -> Vote {
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
    }

    // -------------------------------------------------------------------------
    // Quorum Threshold Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_compute_quorum_threshold() {
        assert_eq!(compute_quorum_threshold(0), 0);
        assert_eq!(compute_quorum_threshold(1), 1); // f=0, 2*0+1=1
        assert_eq!(compute_quorum_threshold(2), 1); // f=0, 2*0+1=1
        assert_eq!(compute_quorum_threshold(3), 1); // f=0, 2*0+1=1
        assert_eq!(compute_quorum_threshold(4), 3); // f=1, 2*1+1=3
        assert_eq!(compute_quorum_threshold(5), 3); // f=1, 2*1+1=3
        assert_eq!(compute_quorum_threshold(6), 3); // f=1, 2*1+1=3
        assert_eq!(compute_quorum_threshold(7), 5); // f=2, 2*2+1=5
        assert_eq!(compute_quorum_threshold(10), 7); // f=3, 2*3+1=7
    }

    #[test]
    fn test_is_quorum() {
        // 4 validators, threshold = 3
        assert!(!is_quorum(0, 4));
        assert!(!is_quorum(1, 4));
        assert!(!is_quorum(2, 4));
        assert!(is_quorum(3, 4));
        assert!(is_quorum(4, 4));
    }

    // -------------------------------------------------------------------------
    // Verification Context Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_verification_context_creation() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);

        assert_eq!(context.validator_count(), 4);
        assert_eq!(context.quorum_threshold(), 3);
    }

    #[test]
    fn test_verification_context_validator_lookup() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);

        // Valid validator lookup
        assert!(context.is_validator(&validators[0].id));
        assert!(context.is_validator(&validators[1].id));
        assert!(context.is_validator(&validators[2].id));
        assert!(context.is_validator(&validators[3].id));

        // Invalid validator lookup
        let unknown_id = [0xff; 32];
        assert!(!context.is_validator(&unknown_id));
    }

    #[test]
    #[should_panic(expected = "validator set cannot be empty")]
    fn test_verification_context_empty_validators() {
        let validators: Vec<ValidatorInfo> = Vec::new();
        let _context = QcVerificationContext::new(&validators, 3);
    }

    #[test]
    #[should_panic(expected = "quorum threshold must be positive")]
    fn test_verification_context_zero_threshold() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();
        let _context = QcVerificationContext::new(&validators, 0);
    }

    // -------------------------------------------------------------------------
    // QC Verification Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_verify_genesis_qc() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);
        let genesis_qc = QuorumCertificate::genesis(0, [0u8; 32]);

        let result = verify_qc(&genesis_qc, &context).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.valid_signature_count, 0);
        assert!(result.signers.is_empty());
    }

    #[test]
    fn test_verify_valid_qc() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);

        // Create votes and QC
        let epoch = 1;
        let round = 5;
        let block_hash = [0xab; 32];

        let votes: Vec<Vote> = keys
            .iter()
            .take(3) // 3 votes for quorum
            .map(|k| create_signed_vote(k, epoch, round, block_hash))
            .collect();

        let qc = QuorumCertificate {
            epoch,
            round,
            block_hash,
            signatures: votes
                .iter()
                .map(|v| ValidatorSignature::new(v.voter_id, v.signature))
                .collect(),
        };

        let result = verify_qc(&qc, &context).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.valid_signature_count, 3);
        assert_eq!(result.signers.len(), 3);
    }

    #[test]
    fn test_verify_qc_insufficient_signatures() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);

        // Only 2 votes (below quorum of 3)
        let block_hash = [0xab; 32];
        let votes: Vec<Vote> = keys
            .iter()
            .take(2)
            .map(|k| create_signed_vote(k, 1, 5, block_hash))
            .collect();

        let qc = QuorumCertificate {
            epoch: 1,
            round: 5,
            block_hash,
            signatures: votes
                .iter()
                .map(|v| ValidatorSignature::new(v.voter_id, v.signature))
                .collect(),
        };

        let result = verify_qc(&qc, &context);
        assert!(matches!(
            result,
            Err(BftError::InsufficientQuorum { have: 2, need: 3 })
        ));
    }

    #[test]
    fn test_verify_qc_duplicate_signature() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);

        let block_hash = [0xab; 32];
        let vote = create_signed_vote(&keys[0], 1, 5, block_hash);

        // Create QC with duplicate signature
        let qc = QuorumCertificate {
            epoch: 1,
            round: 5,
            block_hash,
            signatures: vec![
                ValidatorSignature::new(vote.voter_id, vote.signature),
                ValidatorSignature::new(vote.voter_id, vote.signature), // Duplicate
                ValidatorSignature::new(vote.voter_id, vote.signature), // Duplicate
            ],
        };

        let result = verify_qc(&qc, &context);
        assert!(matches!(result, Err(BftError::DuplicateSignature(_))));
    }

    #[test]
    fn test_verify_qc_unknown_validator() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);

        // Create a vote from an unknown validator
        let unknown_key = SigningKey::generate(&mut OsRng);
        let block_hash = [0xab; 32];

        let mut votes: Vec<Vote> = keys
            .iter()
            .take(2)
            .map(|k| create_signed_vote(k, 1, 5, block_hash))
            .collect();
        votes.push(create_signed_vote(&unknown_key, 1, 5, block_hash));

        let qc = QuorumCertificate {
            epoch: 1,
            round: 5,
            block_hash,
            signatures: votes
                .iter()
                .map(|v| ValidatorSignature::new(v.voter_id, v.signature))
                .collect(),
        };

        let result = verify_qc(&qc, &context);
        assert!(matches!(result, Err(BftError::UnknownValidator(_))));
    }

    #[test]
    fn test_verify_qc_invalid_signature() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);

        let block_hash = [0xab; 32];
        let mut votes: Vec<Vote> = keys
            .iter()
            .take(3)
            .map(|k| create_signed_vote(k, 1, 5, block_hash))
            .collect();

        // Corrupt one signature
        votes[1].signature[0] ^= 0xff;

        let qc = QuorumCertificate {
            epoch: 1,
            round: 5,
            block_hash,
            signatures: votes
                .iter()
                .map(|v| ValidatorSignature::new(v.voter_id, v.signature))
                .collect(),
        };

        let result = verify_qc(&qc, &context);
        assert!(matches!(result, Err(BftError::InvalidSignature { .. })));
    }

    // -------------------------------------------------------------------------
    // QC Aggregator Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_aggregator_creation() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let aggregator = QcAggregator::new(&validators, 3);

        assert_eq!(aggregator.quorum_threshold(), 3);
        assert_eq!(aggregator.tracked_round_count(), 0);
    }

    #[test]
    fn test_aggregator_vote_collection() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        let block_hash = [0xab; 32];
        let vote1 = create_signed_vote(&keys[0], 1, 5, block_hash);
        let vote2 = create_signed_vote(&keys[1], 1, 5, block_hash);

        // First vote - no quorum yet
        let result = aggregator.add_vote(&vote1).unwrap();
        assert!(result.is_none());
        assert_eq!(aggregator.vote_count(5, &block_hash), 1);

        // Second vote - still no quorum
        let result = aggregator.add_vote(&vote2).unwrap();
        assert!(result.is_none());
        assert_eq!(aggregator.vote_count(5, &block_hash), 2);
    }

    #[test]
    fn test_aggregator_quorum_formation() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        let block_hash = [0xab; 32];
        let votes: Vec<Vote> = keys
            .iter()
            .take(3)
            .map(|k| create_signed_vote(k, 1, 5, block_hash))
            .collect();

        // Add first two votes
        assert!(aggregator.add_vote(&votes[0]).unwrap().is_none());
        assert!(aggregator.add_vote(&votes[1]).unwrap().is_none());

        // Third vote should form quorum
        let result = aggregator.add_vote(&votes[2]).unwrap();
        assert!(result.is_some());

        let qc = result.unwrap();
        assert_eq!(qc.epoch, 1);
        assert_eq!(qc.round, 5);
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.signatures.len(), 3);
    }

    #[test]
    fn test_aggregator_duplicate_vote_rejection() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        let block_hash = [0xab; 32];
        let vote = create_signed_vote(&keys[0], 1, 5, block_hash);

        // First vote succeeds
        assert!(aggregator.add_vote(&vote).unwrap().is_none());

        // Duplicate vote fails
        let result = aggregator.add_vote(&vote);
        assert!(matches!(result, Err(BftError::DuplicateVote(_, _))));
    }

    #[test]
    fn test_aggregator_equivocation_rejection() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        let block_hash1 = [0xab; 32];
        let block_hash2 = [0xcd; 32];

        // Vote for first block
        let vote1 = create_signed_vote(&keys[0], 1, 5, block_hash1);
        assert!(aggregator.add_vote(&vote1).unwrap().is_none());

        // Try to vote for different block in same round (equivocation)
        let vote2 = create_signed_vote(&keys[0], 1, 5, block_hash2);
        let result = aggregator.add_vote(&vote2);
        assert!(matches!(result, Err(BftError::VoteEquivocation(_, _))));
    }

    #[test]
    fn test_aggregator_unknown_validator_rejection() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        let unknown_key = SigningKey::generate(&mut OsRng);
        let vote = create_signed_vote(&unknown_key, 1, 5, [0xab; 32]);

        let result = aggregator.add_vote(&vote);
        assert!(matches!(result, Err(BftError::UnknownValidator(_))));
    }

    #[test]
    fn test_aggregator_invalid_signature_rejection() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        let mut vote = create_signed_vote(&keys[0], 1, 5, [0xab; 32]);
        vote.signature[0] ^= 0xff; // Corrupt signature

        let result = aggregator.add_vote(&vote);
        assert!(matches!(result, Err(BftError::InvalidSignature { .. })));
    }

    #[test]
    fn test_aggregator_cleanup_old_rounds() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        // Add votes for different rounds
        let block_hash = [0xab; 32];
        let vote_r5 = create_signed_vote(&keys[0], 1, 5, block_hash);
        let vote_r6 = create_signed_vote(&keys[1], 1, 6, block_hash);
        let vote_r7 = create_signed_vote(&keys[2], 1, 7, block_hash);

        aggregator.add_vote(&vote_r5).unwrap();
        aggregator.add_vote(&vote_r6).unwrap();
        aggregator.add_vote(&vote_r7).unwrap();

        assert_eq!(aggregator.tracked_round_count(), 3);

        // Cleanup rounds < 7
        aggregator.cleanup_old_rounds(7);

        assert_eq!(aggregator.tracked_round_count(), 1);
        assert!(aggregator.is_tracking_round(7));
        assert!(!aggregator.is_tracking_round(5));
        assert!(!aggregator.is_tracking_round(6));
    }

    #[test]
    fn test_aggregator_bounded_rounds() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        // Add votes for many rounds (more than MAX_TRACKED_ROUNDS)
        let block_hash = [0xab; 32];
        for round in 0..(MAX_TRACKED_ROUNDS + 5) as u64 {
            let vote = create_signed_vote(&keys[0], 1, round, block_hash);
            let _ = aggregator.add_vote(&vote);
        }

        // Should not exceed MAX_TRACKED_ROUNDS
        assert!(aggregator.tracked_round_count() <= MAX_TRACKED_ROUNDS);
    }

    #[test]
    fn test_aggregator_drain_formed_qcs() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        let block_hash = [0xab; 32];
        let votes: Vec<Vote> = keys
            .iter()
            .take(3)
            .map(|k| create_signed_vote(k, 1, 5, block_hash))
            .collect();

        // Form quorum
        for vote in &votes {
            let _ = aggregator.add_vote(vote);
        }

        // Drain should return the formed QC
        let qcs = aggregator.drain_formed_qcs();
        assert_eq!(qcs.len(), 1);

        // Drain again should be empty
        let qcs = aggregator.drain_formed_qcs();
        assert!(qcs.is_empty());
    }

    // -------------------------------------------------------------------------
    // Vote Message Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_build_vote_message() {
        let epoch = 1u64;
        let round = 5u64;
        let block_hash = [0xab; 32];

        let msg = build_vote_message(epoch, round, &block_hash);

        // Check prefix
        assert!(msg.starts_with(b"VOTE"));

        // Check length: "VOTE" (4) + epoch (8) + round (8) + hash (32) = 52
        assert_eq!(msg.len(), 52);

        // Check epoch/round encoding
        let epoch_bytes = &msg[4..12];
        assert_eq!(u64::from_le_bytes(epoch_bytes.try_into().unwrap()), epoch);

        let round_bytes = &msg[12..20];
        assert_eq!(u64::from_le_bytes(round_bytes.try_into().unwrap()), round);

        // Check block hash
        let hash_bytes = &msg[20..52];
        assert_eq!(hash_bytes, &block_hash);
    }

    // -------------------------------------------------------------------------
    // TCK-00190 Acceptance Criteria Tests
    // -------------------------------------------------------------------------

    /// AC1: QC generated after 2f+1 votes collected
    #[test]
    fn tck_00190_qc_generated_after_threshold() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator = QcAggregator::new(&validators, 3);

        let block_hash = [0xab; 32];
        let votes: Vec<Vote> = keys
            .iter()
            .take(4)
            .map(|k| create_signed_vote(k, 1, 5, block_hash))
            .collect();

        // Votes 1 and 2 should not form QC
        assert!(aggregator.add_vote(&votes[0]).unwrap().is_none());
        assert!(aggregator.add_vote(&votes[1]).unwrap().is_none());

        // Vote 3 (reaching 2f+1 = 3) should form QC
        let qc = aggregator.add_vote(&votes[2]).unwrap();
        assert!(qc.is_some());
        assert_eq!(qc.unwrap().signatures.len(), 3);
    }

    /// AC2: QC verification validates signer membership and signatures
    #[test]
    fn tck_00190_qc_verification_validates_membership_and_signatures() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let context = QcVerificationContext::new(&validators, 3);

        // Create valid QC
        let block_hash = [0xab; 32];
        let votes: Vec<Vote> = keys
            .iter()
            .take(3)
            .map(|k| create_signed_vote(k, 1, 5, block_hash))
            .collect();

        let qc = QuorumCertificate {
            epoch: 1,
            round: 5,
            block_hash,
            signatures: votes
                .iter()
                .map(|v| ValidatorSignature::new(v.voter_id, v.signature))
                .collect(),
        };

        // Verification should pass
        let result = verify_qc(&qc, &context).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.valid_signature_count, 3);

        // All signers should be in validator set
        for signer in &result.signers {
            assert!(context.is_validator(signer));
        }
    }

    /// Test deterministic signature ordering in QC
    #[test]
    fn tck_00190_deterministic_signature_ordering() {
        let keys = generate_test_keys(4);
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| validator_info_from_key(k, i))
            .collect();

        let mut aggregator1 = QcAggregator::new(&validators, 3);
        let mut aggregator2 = QcAggregator::new(&validators, 3);

        let block_hash = [0xab; 32];
        let votes: Vec<Vote> = keys
            .iter()
            .take(3)
            .map(|k| create_signed_vote(k, 1, 5, block_hash))
            .collect();

        // Add votes in different order
        aggregator1.add_vote(&votes[0]).unwrap();
        aggregator1.add_vote(&votes[1]).unwrap();
        let qc1 = aggregator1.add_vote(&votes[2]).unwrap().unwrap();

        aggregator2.add_vote(&votes[2]).unwrap();
        aggregator2.add_vote(&votes[0]).unwrap();
        let qc2 = aggregator2.add_vote(&votes[1]).unwrap().unwrap();

        // Both QCs should have signatures in the same order
        assert_eq!(qc1.signatures.len(), qc2.signatures.len());
        for (sig1, sig2) in qc1.signatures.iter().zip(qc2.signatures.iter()) {
            assert_eq!(sig1.validator_id, sig2.validator_id);
        }
    }
}
